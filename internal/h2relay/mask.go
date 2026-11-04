package h2relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/mask"
)

// Response masking.
//
// With masking on, the relay decodes every response header block with its
// own decoder and encodes it again for the client with its own encoder, so it
// can mask header values and drop the headers a masked body no longer
// matches. The client's HPACK table then belongs to the relay's encoder; the
// server's encoder and the request direction are unchanged.
//
// A response whose head arrives while the principal has values on record is
// masked: its DATA go through a pipeline (decoding, then a mask.Writer) whose
// output can be longer or shorter than its input, so the relay is the
// flow-control endpoint for that stream on both sides. It credits the server
// for what the pipeline consumed, and sends the client what the client's
// windows allow. The client's WINDOW_UPDATEs for such a stream are not
// forwarded.
//
// Other responses are passed on frame by frame as before, but within the
// client's windows as the relay counts them: masked output shares the
// client's connection window, so a passthrough frame that no longer fits
// waits in its stream's queue. To keep the server from sending more than the
// client accepts, the relay owes the server the difference between what it
// sent the client and what it received for masked streams (debt): a positive
// debt is withheld from the client's next connection WINDOW_UPDATEs, a
// negative one is added to them, or returned at once when it is large. The
// client's first WINDOW_UPDATE, sent before any response, is forwarded
// unchanged.

const (
	// maskOutputQueue bounds the masked output a stream holds before its
	// pipeline waits for the client to take it.
	maskOutputQueue = 64 << 10
	// creditBatch is how much consumed input a masked stream accumulates
	// before crediting the server, unless its input runs dry first.
	creditBatch = 16 << 10
	// debtReturn is the negative debt returned to the server at once.
	debtReturn = 32 << 10
)

// errUnmaskable is a response that cannot be masked and is refused.
var errUnmaskable = errors.New("response cannot be masked")

// respState is the response side of a stream in masking mode.
type respState struct {
	clientID, serverID uint32
	method             string
	window             int64 // what the client lets the relay send on the stream
	queue              []respItem
	queued             int64 // data bytes in queue
	// For a masked stream: DATA bytes received from the server (padding
	// included) and masked bytes sent to the client, settled with the
	// server's connection window when the stream ends.
	maskIn, maskOut int64
	listed          bool // in relay.respList
	sending         bool // a frame of this stream is being written
	final           bool // the final (non-1xx) response head arrived
	bodiless        bool // masked, and its head says it has no content
	done            bool // the stream ended toward the client
	pipe            *maskPipe
	// masker is the one chosen at the final head, for the body and the
	// trailers: nil if nothing was on record then.
	masker *mask.Masker
}

// respItem is one thing waiting to go to the client on a stream, in order.
type respItem struct {
	data   []byte              // masked output (split as windows allow)
	frame  *Frame              // a passthrough DATA frame, sent whole
	fields []hpack.HeaderField // a header block, encoded when sent
	end    bool                // END_STREAM after this item
}

// maskPipe is the input side of a masked response body.
type maskPipe struct {
	in          bytes.Buffer
	inEnded     bool
	serverEnded bool
	failed      bool
	uncredited  int // consumed or padding bytes not yet credited to the server
	trailers    []hpack.HeaderField
}

// respPlan says how a masked response's body is handled.
type respPlan struct {
	body     bool
	bodiless bool // HEAD, 204 or 304: content in DATA makes it malformed
	decode   mask.Encoding
	context  mask.Context // of the body, from its content-type
}

// newRespLocked creates the response state of a new client stream.
func (r *relay) newRespLocked(clientID uint32, method string) {
	r.resp[clientID] = &respState{clientID: clientID, method: method, window: r.clientRespInitial}
}

// enqueueRespLocked appends an item to a stream's queue for clientSendLoop.
func (r *relay) enqueueRespLocked(rs *respState, item respItem) {
	rs.queue = append(rs.queue, item)
	n := int64(len(item.data))
	if item.frame != nil {
		n = int64(len(item.frame.Payload))
	}
	rs.queued += n
	r.respHeld += n
	if !rs.listed {
		rs.listed = true
		r.respList = append(r.respList, rs)
	}
	r.cond.Broadcast()
}

// endRespLocked forgets a stream's response side once it ended toward the
// client, releasing what it held.
func (r *relay) endRespLocked(rs *respState) {
	if rs.done {
		return
	}
	rs.done = true
	// Connection credit the server is owed now that the client will never
	// receive (and so never credit) these bytes: queued passthrough frames,
	// which debt does not count, and what a masked stream received beyond
	// what it sent. The latter is part of a negative debt, which other
	// paths may already have paid back in part (an eager return, or a
	// client WINDOW_UPDATE forwarded with more): only what the debt still
	// owes is returned, so no credit is given twice. A masked stream that
	// sent more than it received leaves that in debt, withheld later.
	var due int64
	for _, item := range rs.queue {
		if item.frame != nil {
			due += int64(len(item.frame.Payload))
		}
	}
	if rs.pipe != nil {
		if balance := rs.maskIn - rs.maskOut; balance > 0 && r.debt < 0 {
			owed := min(balance, -r.debt)
			due += owed
			r.debt += owed
		}
		rs.maskIn, rs.maskOut = 0, 0
	}
	r.serverCreditDue += due
	r.respHeld -= rs.queued
	rs.queue, rs.queued = nil, 0
	if rs.pipe != nil {
		r.respHeld -= int64(rs.pipe.in.Len())
		rs.pipe.in = bytes.Buffer{}
		rs.pipe.failed = true
	}
	if r.resp[rs.clientID] == rs {
		delete(r.resp, rs.clientID)
	}
	r.cond.Broadcast()
}

// onClientSettings applies the client's SETTINGS to what the relay sends it:
// the initial stream window and the header table size its decoder accepts.
func (r *relay) onClientSettings(payload []byte) error {
	settings, err := ParseSettings(payload)
	if err != nil {
		return err
	}
	for _, s := range settings {
		switch s.ID {
		case SettingInitialWindowSize:
			if s.Value > maxWindow {
				return errors.New("client sent an invalid initial window size")
			}
			r.mu.Lock()
			delta := int64(s.Value) - r.clientRespInitial
			r.clientRespInitial = int64(s.Value)
			for _, rs := range r.resp {
				rs.window += delta
			}
			r.cond.Broadcast()
			r.mu.Unlock()
		case SettingHeaderTableSize:
			r.clientMu.Lock()
			r.cenc.SetMaxDynamicTableSizeLimit(s.Value)
			r.clientMu.Unlock()
			// The server's encoder may use up to this size once it has the
			// SETTINGS: the relay's decoder accepts the largest value sent.
			for {
				old := r.serverTableSize.Load()
				if s.Value <= old || r.serverTableSize.CompareAndSwap(old, s.Value) {
					break
				}
			}
		}
	}
	return nil
}

// onClientConnWindow takes the client's connection WINDOW_UPDATE and
// forwards it adjusted by the debt.
func (r *relay) onClientConnWindow(f Frame) error {
	if len(f.Payload) != 4 {
		return errors.New("client sent a bad WINDOW_UPDATE")
	}
	inc := int64(binary.BigEndian.Uint32(f.Payload) & 0x7fffffff)
	r.mu.Lock()
	r.cliConn += inc
	forward := inc
	if r.debt > 0 {
		withheld := min(inc, r.debt)
		r.debt -= withheld
		forward -= withheld
	} else if r.debt < 0 {
		forward -= r.debt
		r.debt = 0
	}
	r.cond.Broadcast()
	r.mu.Unlock()
	if forward <= 0 {
		return nil
	}
	return r.writeServer(windowUpdate(0, int(min(forward, maxWindow))))
}

// onClientStreamFrame handles a client WINDOW_UPDATE or RST_STREAM on the
// response side. It reports whether the frame must not be forwarded: a
// WINDOW_UPDATE for a masked stream, whose server-side window the relay
// manages.
func (r *relay) onClientStreamFrame(f Frame) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rs := r.resp[f.Stream]
	if rs == nil {
		return false, nil
	}
	if f.Type == FrameRSTStream {
		r.endRespLocked(rs)
		return false, nil
	}
	if len(f.Payload) != 4 {
		return false, errors.New("client sent a bad WINDOW_UPDATE")
	}
	rs.window += int64(binary.BigEndian.Uint32(f.Payload) & 0x7fffffff)
	r.cond.Broadcast()
	return rs.pipe != nil, nil
}

// serverLoopMasked is serverLoop with response masking.
func (r *relay) serverLoopMasked() error {
	var block []byte
	var blockStream uint32
	blockEnds, inBlock, sawPreface := false, false, false
	appendFragment := func(fragment []byte) error {
		if len(block)+len(fragment) > r.opts.MaxHeaderBytes {
			return fmt.Errorf("server header block is larger than %d bytes", r.opts.MaxHeaderBytes)
		}
		block = append(block, fragment...)
		return nil
	}
	for {
		f, err := r.readServerFrame()
		if err != nil {
			return err
		}
		if inBlock && f.Type != FrameContinuation {
			return errors.New("server interrupted a header block")
		}
		if !sawPreface && (f.Type != FrameSettings || f.Flags&FlagAck != 0) {
			return fmt.Errorf("server's first frame has type %d, not SETTINGS", f.Type)
		}
		switch f.Type {
		case FrameSettings:
			if f.Flags&FlagAck == 0 {
				if err := r.onServerSettings(f.Payload); err != nil {
					return err
				}
				f.Payload = clientSettings(f.Payload)
			} else {
				r.serverFrames.ack()
			}
			if !sawPreface {
				sawPreface = true
				err = r.writeServerPreface(f)
			} else {
				err = r.writeClient(f)
			}
		case FrameWindowUpdate:
			if len(f.Payload) != 4 {
				return errors.New("server sent a bad WINDOW_UPDATE")
			}
			n := int64(binary.BigEndian.Uint32(f.Payload) & 0x7fffffff)
			r.mu.Lock()
			if f.Stream == 0 {
				r.connWindow += n
			} else if s := r.byServer[f.Stream]; s != nil {
				s.window += n
			}
			r.cond.Broadcast()
			r.mu.Unlock()
		case FrameHeaders:
			_, fragment, err := HeadersPayload(f.Flags, f.Payload)
			if err != nil {
				return err
			}
			block, blockStream, blockEnds, inBlock = block[:0], f.Stream, f.Flags&FlagEndStream != 0, true
			if err := appendFragment(fragment); err != nil {
				return err
			}
		case FrameContinuation:
			if !inBlock || f.Stream != blockStream {
				return errors.New("server sent CONTINUATION outside a header block")
			}
			if err := appendFragment(f.Payload); err != nil {
				return err
			}
		case FrameData:
			err = r.onServerDataMasked(f)
		case FrameRSTStream, FramePriority:
			r.mu.Lock()
			s := r.serverStreamLocked(f.Stream)
			if s != nil && f.Type == FrameRSTStream {
				if rs := r.resp[s.clientID]; rs != nil {
					r.endRespLocked(rs)
				}
			}
			r.mu.Unlock()
			if s == nil {
				break
			}
			f.Stream = s.clientID
			err = r.writeClient(f)
			if f.Type == FrameRSTStream {
				r.serverEnded(s, true)
			}
		case FramePushPromise:
			return errors.New("server sent PUSH_PROMISE, which this proxy does not support")
		case FrameGoAway:
			err = r.onServerGoAway(f)
		case FramePing:
			err = r.onServerPing(f)
		default:
			// An extension or unknown frame type (control.go): dropped.
		}
		if err != nil {
			return err
		}
		if inBlock && f.Flags&FlagEndHeaders != 0 && (f.Type == FrameHeaders || f.Type == FrameContinuation) {
			inBlock = false
			if err := r.onServerHeadersMasked(blockStream, blockEnds, block); err != nil {
				return err
			}
		}
	}
}

// decodeServer decodes a server header block with the relay's decoder,
// refusing one whose decoded size passes MaxHeaderBytes.
func (r *relay) decodeServer(block []byte) ([]hpack.HeaderField, error) {
	if allowed := r.serverTableSize.Load(); allowed != r.sdecAllowed {
		r.sdecAllowed = allowed
		r.sdec.SetAllowedMaxDynamicTableSize(allowed)
	}
	var fields []hpack.HeaderField
	size := 0
	r.sdec.SetEmitFunc(func(f hpack.HeaderField) {
		size += len(f.Name) + len(f.Value) + 32
		if size <= r.opts.MaxHeaderBytes {
			fields = append(fields, f)
		}
	})
	if _, err := r.sdec.Write(block); err != nil {
		return nil, fmt.Errorf("decode server header block: %w", err)
	}
	if err := r.sdec.Close(); err != nil {
		return nil, fmt.Errorf("decode server header block: %w", err)
	}
	if size > r.opts.MaxHeaderBytes {
		return nil, fmt.Errorf("server header list is larger than %d bytes", r.opts.MaxHeaderBytes)
	}
	return fields, nil
}

func (r *relay) onServerHeadersMasked(serverID uint32, ends bool, block []byte) error {
	// Every block is decoded, to keep the relay's table in step with the
	// server's encoder.
	fields, err := r.decodeServer(block)
	if err != nil {
		return err
	}
	r.mu.Lock()
	s := r.serverStreamLocked(serverID)
	var rs *respState
	if s != nil {
		rs = r.resp[s.clientID]
	}
	gone := rs == nil || rs.done
	r.mu.Unlock()
	if s == nil {
		return fmt.Errorf("server sent headers on unknown stream %d", serverID)
	}
	if gone {
		// Reset by the client, or refused: the client's table does not need
		// this block.
		if ends {
			r.serverEnded(s, false)
		}
		return nil
	}
	status := ""
	for _, f := range fields {
		if f.Name == ":status" {
			status = f.Value
		}
	}
	// Which values are masked is decided at the final head: the trailers
	// are masked with its masker, as the body is, even if a value left the
	// record since. A block before it, or after a head that had nothing on
	// record, gets the current one, which can only add masking.
	masker := rs.masker
	if masker == nil {
		masker = r.opts.Session.Masker()
	}
	interim := strings.HasPrefix(status, "1") && len(status) == 3
	var startMask *respPlan
	switch {
	case !rs.final && !interim:
		r.mu.Lock()
		rs.final, rs.masker = true, masker
		r.mu.Unlock()
		if masker != nil {
			var plan respPlan
			fields, plan, err = maskResponseHead(fields, status, rs.method, ends, masker)
			if err != nil {
				return r.refuseResponse(s, rs, ends, err)
			}
			r.mu.Lock()
			rs.bodiless = plan.bodiless
			if plan.body {
				rs.pipe = &maskPipe{}
				startMask = &plan
			}
			r.mu.Unlock()
		}
	case masker != nil:
		if fields, err = maskFields(fields, masker); err != nil {
			return r.refuseResponse(s, rs, ends, err)
		}
	}
	if rs.pipe != nil && ends {
		// Trailers of a masked response: sent once its body is out.
		r.mu.Lock()
		rs.pipe.trailers = fields
		rs.pipe.inEnded = true
		rs.pipe.serverEnded = true
		r.cond.Broadcast()
		r.mu.Unlock()
		r.serverEnded(s, false)
		return nil
	}
	if err := r.sendHeaders(rs, fields, ends); err != nil {
		return err
	}
	if startMask != nil {
		// Started once the head is out, so no body item can precede it.
		go r.runMask(rs, *startMask, masker)
	}
	if ends {
		r.serverEnded(s, false)
	}
	return nil
}

// sendHeaders sends a response header block to the client at once, or after
// what its stream already has queued.
func (r *relay) sendHeaders(rs *respState, fields []hpack.HeaderField, end bool) error {
	r.mu.Lock()
	if rs.done {
		r.mu.Unlock()
		return nil
	}
	if len(rs.queue) > 0 || rs.sending {
		r.enqueueRespLocked(rs, respItem{fields: fields, end: end})
		r.mu.Unlock()
		return nil
	}
	rs.sending = true
	r.mu.Unlock()
	err := r.writeClientHeaders(rs.clientID, fields, end)
	r.mu.Lock()
	rs.sending = false
	if end {
		r.endRespLocked(rs)
	}
	r.cond.Broadcast()
	r.mu.Unlock()
	return err
}

// writeClientHeaders encodes a header block with the relay's encoder and
// writes it, split into HEADERS and CONTINUATION frames, under clientMu so
// blocks reach the client in the order they were encoded.
func (r *relay) writeClientHeaders(clientID uint32, fields []hpack.HeaderField, end bool) error {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	r.cencBuf.Reset()
	for _, f := range fields {
		_ = r.cenc.WriteField(f)
	}
	block := r.cencBuf.Bytes()
	var frames []Frame
	flags := uint8(0)
	if end {
		flags |= FlagEndStream
	}
	typ := FrameHeaders
	for first := true; first || len(block) > 0; first = false {
		n := min(len(block), defaultMaxFrame)
		f := Frame{Type: typ, Stream: clientID, Payload: append([]byte(nil), block[:n]...)}
		if first {
			f.Flags = flags
		}
		block = block[n:]
		if len(block) == 0 {
			f.Flags |= FlagEndHeaders
		}
		frames = append(frames, f)
		typ = FrameContinuation
	}
	if !r.prefaceSent.Load() {
		return r.holdLocked(frames)
	}
	_, err := r.client.Write(encodeFrames(frames))
	return err
}

// refuseResponse answers a response that cannot be masked with a 502 of the
// relay's own and resets the server's stream.
func (r *relay) refuseResponse(s *stream, rs *respState, serverDone bool, cause error) error {
	r.opts.Logger.Warn("refusing a response that cannot be masked", "stream", s.clientID, "reason", cause.Error())
	r.mu.Lock()
	r.endRespLocked(rs)
	if !serverDone {
		if r.streams[s.clientID] == s {
			r.dropLocked(s)
		}
		r.forgetResetLocked(s)
	}
	r.mu.Unlock()
	if err := r.writeClient(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: s.clientID, Payload: badGatewayBlock}); err != nil {
		return err
	}
	if serverDone {
		r.serverEnded(s, false)
		return nil
	}
	return r.writeServer(Frame{Type: FrameRSTStream, Stream: s.serverID, Payload: binary.BigEndian.AppendUint32(nil, errCodeCancel)})
}

// maskResponseHead masks a response head's values and drops the headers a
// masked body no longer matches: a decodable content-encoding (the body is
// sent decoded) and a content-length the body may no longer have. It returns
// errUnmaskable for a body that cannot be masked: an unknown or stacked
// content-coding, a partial response (206), or a field name with an
// upper-case letter.
func maskResponseHead(fields []hpack.HeaderField, status, method string, ends bool, m *mask.Masker) ([]hpack.HeaderField, respPlan, error) {
	// Ranges are masked one by one, so a client that asks for ranges that
	// split a value (bytes=0-7, then bytes=8-15) would get each piece as is
	// and could put the value back together.
	if status == "206" {
		return nil, respPlan{}, fmt.Errorf("%w: a partial response", errUnmaskable)
	}
	var encodings []string
	for _, f := range fields {
		// Field names are lower case in HTTP/2, so one with an upper-case
		// letter is malformed (RFC 9113 8.2.1), and would escape the
		// lookups below: a Content-Encoding body would pass undecoded.
		if strings.ToLower(f.Name) != f.Name {
			return nil, respPlan{}, fmt.Errorf("%w: an upper-case field name", errUnmaskable)
		}
		switch f.Name {
		case "content-encoding":
			encodings = append(encodings, f.Value)
		case "transfer-encoding":
			// Connection-specific, so malformed in HTTP/2 (RFC 9113 8.2.2),
			// and a coding the masker would not see: refused.
			return nil, respPlan{}, fmt.Errorf("%w: a transfer-encoding field", errUnmaskable)
		}
	}
	contentType := ""
	for _, f := range fields {
		if f.Name == "content-type" {
			contentType = f.Value
		}
	}
	// No response is a tunnel whose DATA passes through unmasked: requestHead
	// refuses every CONNECT, and if one reached the server anyway, a 2xx to
	// it would be masked as a body here, not passed on raw.
	bodiless := method == "HEAD" || status == "204" || status == "304"
	plan := respPlan{
		body:     !ends && !bodiless,
		bodiless: bodiless,
		context:  mask.ContextOf(contentType),
	}
	enc, err := mask.ParseEncoding(encodings)
	if err != nil {
		if plan.body {
			return nil, plan, fmt.Errorf("%w: %w", errUnmaskable, err)
		}
		enc = "" // no body to decode: the header stays as it is
	}
	if plan.body {
		plan.decode = enc
	}
	dropLength := plan.body && (enc != "" || !m.SameLength(plan.context)) || method == "HEAD" && enc != ""
	out := make([]hpack.HeaderField, 0, len(fields))
	for _, f := range fields {
		switch {
		case f.Name == "content-encoding" && enc != "":
			continue
		case f.Name == "content-length" && dropLength:
			continue
		}
		out = append(out, f)
	}
	masked, err := maskFields(out, m)
	if err != nil {
		return nil, plan, err
	}
	return masked, plan, nil
}

// maskFields masks the values of every field but pseudo-headers and
// content-length. It returns errUnmaskable when a stand-in would put a line
// break or NUL into a value, or for a real value in content-length, which
// frames the message and is kept as it is, as HTTP/1.1 does.
func maskFields(fields []hpack.HeaderField, m *mask.Masker) ([]hpack.HeaderField, error) {
	for i := range fields {
		f := &fields[i]
		if strings.HasPrefix(f.Name, ":") {
			continue
		}
		masked := m.String(mask.HeaderContext(f.Name), f.Value)
		switch {
		case masked == f.Value:
			continue
		case f.Name == "content-length":
			return nil, fmt.Errorf("%w: a real value in content-length", errUnmaskable)
		case strings.ContainsAny(masked, "\r\n\x00"):
			return nil, fmt.Errorf("%w: a stand-in cannot go into a header", errUnmaskable)
		}
		f.Value = masked
	}
	return fields, nil
}

// onServerDataMasked takes a response DATA frame: into the pipeline of a
// masked stream, else on to the client within its windows.
func (r *relay) onServerDataMasked(f Frame) error {
	end := f.Flags&FlagEndStream != 0
	r.mu.Lock()
	s := r.serverStreamLocked(f.Stream)
	var rs *respState
	if s != nil {
		rs = r.resp[s.clientID]
	}
	if rs == nil || rs.done {
		r.mu.Unlock()
		if len(f.Payload) > 0 {
			// Nobody takes these bytes: keep the server's connection window.
			if err := r.writeServer(windowUpdate(0, len(f.Payload))); err != nil {
				return err
			}
		}
		if s != nil && end {
			r.serverEnded(s, false)
		}
		return nil
	}
	if !rs.final {
		// DATA before the final head (none yet, or only a 1xx): malformed
		// (RFC 9113 8.1), and there is no masking pipeline for it yet.
		r.mu.Unlock()
		return r.resetMalformed(s, rs, len(f.Payload), end)
	}
	if rs.bodiless {
		data, err := unpad(f.Flags, f.Payload)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		if len(data) > 0 {
			r.mu.Unlock()
			return r.resetMalformed(s, rs, len(f.Payload), end)
		}
		// An empty DATA (often the END_STREAM of a HEAD) is passed on.
	}
	if rs.pipe != nil {
		data, err := unpad(f.Flags, f.Payload)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		r.debt -= int64(len(f.Payload))
		rs.maskIn += int64(len(f.Payload))
		rs.pipe.in.Write(data)
		r.respHeld += int64(len(data))
		rs.pipe.uncredited += len(f.Payload) - len(data) // padding
		if end {
			rs.pipe.inEnded, rs.pipe.serverEnded = true, true
		}
		over := r.respHeld > int64(r.opts.MaxBuffered)
		r.cond.Broadcast()
		owed := r.takeDebtReturnLocked()
		r.mu.Unlock()
		if over {
			r.failMasked(rs, errors.New("masked responses hold more than the connection buffer limit"))
		}
		if owed > 0 {
			if err := r.writeServer(windowUpdate(0, int(owed))); err != nil {
				return err
			}
		}
		if end {
			r.serverEnded(s, false)
		}
		return nil
	}
	n := int64(len(f.Payload))
	f.Stream = s.clientID
	if len(rs.queue) == 0 && !rs.sending && r.cliConn >= n && rs.window >= n {
		r.cliConn -= n
		rs.window -= n
		rs.sending = true
		r.mu.Unlock()
		err := r.writeClient(f)
		r.mu.Lock()
		rs.sending = false
		if end {
			r.endRespLocked(rs)
		}
		r.cond.Broadcast()
		r.mu.Unlock()
		if end {
			r.serverEnded(s, false)
		}
		return err
	}
	r.enqueueRespLocked(rs, respItem{frame: &f, end: end})
	over := r.respHeld > int64(r.opts.MaxBuffered)
	r.mu.Unlock()
	if over {
		return errors.New("responses waiting for the client's flow control pass the connection buffer limit")
	}
	if end {
		r.serverEnded(s, false)
	}
	return nil
}

// resetMalformed ends a stream whose response has DATA before its final head
// (RFC 9113 8.1), or content in DATA though its head says it has none (a
// HEAD, 204 or 304, RFC 9113 8.1.1): malformed, and never masked, so its
// content is not passed on. Both sides get RST_STREAM; the server is
// credited the n bytes the relay dropped. The client stops sending once
// reset, so the request ends here too, even when the server already ended
// the stream: one still uploading would otherwise keep its stream slot, and
// the server's stream is reset as well.
func (r *relay) resetMalformed(s *stream, rs *respState, n int, serverDone bool) error {
	r.opts.Logger.Warn("resetting a malformed response", "stream", s.clientID)
	r.mu.Lock()
	r.endRespLocked(rs)
	uploading := !s.sentEnd
	if !serverDone {
		if r.streams[s.clientID] == s {
			r.dropLocked(s)
		}
		r.forgetResetLocked(s)
	}
	r.mu.Unlock()
	if n > 0 {
		if err := r.writeServer(windowUpdate(0, n)); err != nil {
			return err
		}
	}
	if err := r.writeClient(Frame{Type: FrameRSTStream, Stream: s.clientID, Payload: binary.BigEndian.AppendUint32(nil, errCodeInternal)}); err != nil {
		return err
	}
	if serverDone {
		r.serverEnded(s, true)
		if !uploading {
			return nil // both sides ended: the stream is closed
		}
	}
	return r.writeServer(Frame{Type: FrameRSTStream, Stream: s.serverID, Payload: binary.BigEndian.AppendUint32(nil, errCodeProtocol)})
}

// takeDebtReturnLocked returns how much credit to give the server at once
// for a large negative debt.
func (r *relay) takeDebtReturnLocked() int64 {
	if r.debt > -debtReturn {
		return 0
	}
	owed := min(-r.debt, maxWindow)
	r.debt += owed
	return owed
}

// runMask runs a masked response body through decoding and masking into the
// stream's queue, then queues its end.
func (r *relay) runMask(rs *respState, plan respPlan, m *mask.Masker) {
	in := &pipeReader{r: r, rs: rs}
	src, err := mask.Decoder(plan.decode, in, r.opts.MaxDecoded)
	if err != nil {
		r.failMasked(rs, err)
		return
	}
	defer src.Close()
	var body io.Reader = src
	if plan.decode == "" {
		body = in // identity bodies are not capped: they are streamed as they come
	}
	w := m.NewWriter(&pipeWriter{r: r, rs: rs}, plan.context)
	buf := make([]byte, 32<<10)
	if _, err = io.CopyBuffer(w, body, buf); err == nil {
		err = w.Close()
	}
	if err == nil {
		// A compressed stream can end before the HTTP/2 stream does: the
		// response ends with the server's END_STREAM (and its trailers),
		// never with the decoder. Bytes after the end of the compressed
		// stream are not content and are dropped.
		_, err = io.CopyBuffer(io.Discard, in, buf)
	}
	if err != nil {
		r.failMasked(rs, err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs.done {
		return
	}
	if trailers := rs.pipe.trailers; trailers != nil {
		r.enqueueRespLocked(rs, respItem{fields: trailers, end: true})
	} else {
		r.enqueueRespLocked(rs, respItem{end: true})
	}
}

// failMasked ends a masked stream that cannot be completed: the client gets
// RST_STREAM (it never got an unmasked byte), and the server CANCEL unless
// it already ended the stream.
func (r *relay) failMasked(rs *respState, cause error) {
	r.mu.Lock()
	if rs.done {
		r.mu.Unlock()
		return
	}
	serverDone := rs.pipe.serverEnded
	r.endRespLocked(rs)
	s := r.byServer[rs.serverID]
	if !serverDone && s != nil {
		if r.streams[s.clientID] == s {
			r.dropLocked(s)
		}
		r.forgetResetLocked(s)
	}
	r.mu.Unlock()
	if errors.Is(cause, net.ErrClosed) {
		return
	}
	r.opts.Logger.Warn("resetting a response that could not be masked", "stream", rs.clientID, "reason", cause.Error())
	_ = r.writeClient(Frame{Type: FrameRSTStream, Stream: rs.clientID, Payload: binary.BigEndian.AppendUint32(nil, errCodeInternal)})
	if !serverDone {
		_ = r.writeServer(Frame{Type: FrameRSTStream, Stream: rs.serverID, Payload: binary.BigEndian.AppendUint32(nil, errCodeCancel)})
	}
}

// pipeReader reads a masked stream's input, crediting the server for what
// it consumed.
type pipeReader struct {
	r  *relay
	rs *respState
}

func (p *pipeReader) Read(b []byte) (int, error) {
	r, rs := p.r, p.rs
	r.mu.Lock()
	for rs.pipe.in.Len() == 0 && !rs.pipe.inEnded && !rs.pipe.failed && !r.closed {
		r.cond.Wait()
	}
	if rs.pipe.failed || r.closed {
		r.mu.Unlock()
		return 0, net.ErrClosed
	}
	if rs.pipe.in.Len() == 0 {
		r.mu.Unlock()
		return 0, io.EOF
	}
	n, _ := rs.pipe.in.Read(b)
	r.respHeld -= int64(n)
	rs.pipe.uncredited += n
	credit := 0
	if !rs.pipe.serverEnded && (rs.pipe.uncredited >= creditBatch || rs.pipe.in.Len() == 0) {
		credit, rs.pipe.uncredited = rs.pipe.uncredited, 0
	}
	serverID := rs.serverID
	r.mu.Unlock()
	if credit > 0 {
		if err := r.writeServer(windowUpdate(serverID, credit)); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// pipeWriter queues masked output, waiting while the stream holds more than
// maskOutputQueue for the client.
type pipeWriter struct {
	r  *relay
	rs *respState
}

func (p *pipeWriter) Write(b []byte) (int, error) {
	r, rs := p.r, p.rs
	r.mu.Lock()
	defer r.mu.Unlock()
	for rs.queued > maskOutputQueue && !rs.done && !r.closed {
		r.cond.Wait()
	}
	if rs.done || r.closed {
		return 0, net.ErrClosed
	}
	written := len(b)
	for len(b) > 0 {
		n := min(len(b), defaultMaxFrame)
		r.enqueueRespLocked(rs, respItem{data: b[:n:n]})
		b = b[n:]
	}
	return written, nil
}

// clientSendLoop sends queued response frames within the client's windows.
func (r *relay) clientSendLoop() error {
	for {
		r.mu.Lock()
		var rs *respState
		var item respItem
		for rs == nil {
			if r.closed {
				r.mu.Unlock()
				return net.ErrClosed
			}
			if due := r.serverCreditDue; due > 0 {
				r.serverCreditDue = 0
				r.mu.Unlock()
				if err := r.writeServer(windowUpdate(0, int(min(due, maxWindow)))); err != nil {
					return err
				}
				r.mu.Lock()
				continue
			}
			kept := r.respList[:0]
			for _, c := range r.respList {
				if c.done || len(c.queue) == 0 {
					c.listed = false
					continue
				}
				kept = append(kept, c)
			}
			r.respList = kept
			for i, c := range r.respList {
				if c.sending {
					continue
				}
				head := c.queue[0]
				var n int64
				switch {
				case head.fields != nil:
				case head.frame != nil:
					need := int64(len(head.frame.Payload))
					if need > 0 && (r.cliConn < need || c.window < need) {
						continue
					}
					n = need
				case len(head.data) > 0:
					n = min(int64(len(head.data)), r.cliConn, c.window)
					if n <= 0 {
						continue
					}
				}
				rs = c
				r.respList = append(append(r.respList[:i:i], r.respList[i+1:]...), c) // round robin
				item = head
				switch {
				case head.frame != nil:
					c.queue = c.queue[1:]
				case head.fields != nil:
					c.queue = c.queue[1:]
				case int64(len(head.data)) == n:
					c.queue = c.queue[1:]
				default:
					item = respItem{data: head.data[:n:n]}
					c.queue[0].data = head.data[n:]
				}
				c.queued -= n
				r.respHeld -= n
				r.cliConn -= n
				c.window -= n
				if head.frame == nil {
					r.debt += n // masked output the server did not send
					c.maskOut += n
				}
				break
			}
			if rs == nil {
				r.cond.Wait()
			}
		}
		rs.sending = true
		clientID := rs.clientID
		r.cond.Broadcast() // the pipeline may queue more
		r.mu.Unlock()

		var err error
		switch {
		case item.fields != nil:
			err = r.writeClientHeaders(clientID, item.fields, item.end)
		case item.frame != nil:
			err = r.writeClient(*item.frame)
		default:
			flags := uint8(0)
			if item.end {
				flags = FlagEndStream
			}
			err = r.writeClient(Frame{Type: FrameData, Flags: flags, Stream: clientID, Payload: item.data})
		}
		r.mu.Lock()
		rs.sending = false
		if item.end {
			r.endRespLocked(rs)
		}
		r.cond.Broadcast()
		r.mu.Unlock()
		if err != nil {
			return err
		}
	}
}
