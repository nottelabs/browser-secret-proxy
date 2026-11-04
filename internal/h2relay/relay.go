// Package h2relay relays one HTTP/2 connection between a client and an
// upstream server, frame by frame, so the upstream sees the client's own
// connection: the same SETTINGS (values and order), WINDOW_UPDATE, PRIORITY
// and PING frames in the order the client sent them, the same pseudo-header
// and header order, and the same priority on each request.
//
// The response direction is forwarded byte for byte, flow control included.
// In the request direction the relay decodes each header block, swaps
// stand-ins on allowlisted authorities and encodes it again for the upstream.
// A request whose stand-ins cannot be swapped (see package scope) is answered
// 502 by the relay and never sent upstream.
// A request body that may hold a stand-in is buffered until the client ends
// it, swapped, and sent with a corrected content-length; the relay is the
// flow-control endpoint for request bodies on both sides. Upstream stream IDs
// are assigned when a request is sent upstream, so a buffered request does
// not block the ones after it.
//
// With masking on (see mask.go), responses are masked too: real values
// resolved for the connection's principal are replaced by their stand-ins in
// response headers, bodies and trailers.
//
// Memory is bounded per connection: header blocks (encoded and decoded),
// each buffered body, all held request bytes together, and the number of open
// streams. A stream over a limit is refused with REFUSED_STREAM, which tells
// the client it never reached the server and may be retried.
package h2relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// Options configures a relay. Zero limits take the defaults.
type Options struct {
	Hosts *hostmatch.List // stand-ins are swapped only for these authorities
	// Session resolves the stand-ins of each request on an allowlisted
	// authority.
	Session *scope.Session
	// MaxBody caps one buffered request body (default 32 MiB).
	MaxBody int
	// MaxBuffered caps the request bytes the relay holds for the whole
	// connection: buffered bodies and data waiting for the server's flow
	// control (default 64 MiB).
	MaxBuffered int
	// MaxStreams caps the client streams open at once (default 256).
	// Streams waiting for a lookup count toward it.
	MaxStreams int
	// MaxLookups caps the resolver lookups running at once on the
	// connection, each on a goroutine (default DefaultMaxLookups); more wait
	// in a queue, without a goroutine, for a free one.
	MaxLookups int
	// MaxHeaderBytes caps a client header block, encoded and decoded
	// (default 1 MiB).
	MaxHeaderBytes int
	// PrefaceTimeout bounds the wait for the server's first SETTINGS frame
	// (default 30 s); past it the client gets a connection error.
	PrefaceTimeout time.Duration
	// MaxDecoded caps the decoded size of one compressed response that is
	// masked (default mask.DefaultMaxDecoded); past it the stream is reset.
	MaxDecoded int64
	Logger     *slog.Logger
}

// continueBlock is ":status: 100" as a literal without indexing on the static
// ":status" name (index 8), so it leaves the client's dynamic table, which
// belongs to the server's encoder, untouched. badGatewayBlock is ":status:
// 502" the same way.
var (
	continueBlock   = []byte{0x08, 0x03, '1', '0', '0'}
	badGatewayBlock = []byte{0x08, 0x03, '5', '0', '2'}
)

const (
	errCodeNoError       = 0x0
	errCodeProtocol      = 0x1
	errCodeStreamClosed  = 0x5
	errCodeInternal      = 0x2
	errCodeFlowControl   = 0x3
	errCodeFrameSize     = 0x6
	errCodeRefusedStream = 0x7
	errCodeCancel        = 0x8
	errCodeCalm          = 0xb // ENHANCE_YOUR_CALM
	decoderTableSize     = 1 << 16
	maxWindow            = 1<<31 - 1
	// maxResetStreams bounds how many client-reset streams are remembered
	// so late server frames on them can still be passed on.
	maxResetStreams = 1024
	// maxUnackedSettings bounds server SETTINGS frames awaiting the client's ACK.
	maxUnackedSettings = 64
	// maxPriorityValue caps the Priority Field Value of a PRIORITY_UPDATE
	// frame. RFC 9218 values are a few bytes ("u=3, i").
	maxPriorityValue = 1024
)

type relay struct {
	opts           Options
	client, server net.Conn
	// ctx ends with the relay, canceling every resolver lookup in progress.
	ctx    context.Context
	cancel context.CancelFunc
	// Resolver lookups run off clientLoop (lookup.go): lookups tracks their
	// goroutines so the relay ends only after they did, lookupsRunning and
	// lookupQueue (guarded by mu) are the running and waiting ones, and
	// asyncErrs carries an I/O error one of them met to run, which ends the
	// connection.
	lookups        sync.WaitGroup
	lookupsRunning int
	lookupQueue    []pendingLookup
	asyncErrs      chan error
	// streamErrors counts the client's stream errors (frames on a stream it
	// ended); past maxStreamErrors they end the connection. clientLoop only.
	streamErrors int
	// The largest frame each side may send: the client, what the server's
	// SETTINGS told it; the server, what the client's told it. A longer one
	// ends the connection with FRAME_SIZE_ERROR.
	clientFrames, serverFrames frameLimit

	clientMu sync.Mutex // serializes writes to the client
	// The server's first SETTINGS must be the first frame the client gets
	// (RFC 9113 3.4). Until it has been forwarded (prefaceSent), frames the
	// relay itself writes (WINDOW_UPDATE credit, RST_STREAM, GOAWAY, a local
	// 100) wait in early, bounded by MaxBuffered bytes; guarded by clientMu.
	prefaceSent atomic.Bool // written under clientMu; read without it by shutdown and the timer
	early       []Frame
	earlyBytes  int
	serverMu    sync.Mutex // serializes writes to the server and owns enc
	enc         *hpack.Encoder
	encBuf      bytes.Buffer
	dec         *hpack.Decoder // used by the client reader only

	mu           sync.Mutex
	cond         *sync.Cond
	closed       bool
	goaway       bool               // the server sent GOAWAY: no new requests go upstream
	streams      map[uint32]*stream // open client streams, by client stream ID
	byServer     map[uint32]*stream // streams the server may still send on, by server stream ID
	maxClientID  uint32             // highest client stream ID seen
	nextServerID uint32
	connWindow   int64 // what the server lets us send on the connection
	// What the relay lets the client send: its connection window, and the
	// initial stream window the client was told (the server's, forwarded).
	recvConn      int64
	clientInitial int64 // enforced: the largest value the client may be using
	// ackedInitial is the client's initial window as of its last SETTINGS
	// ACK. unackedInitial holds the initial window of each server SETTINGS
	// frame forwarded since, oldest first (-1: frame without one). The
	// client may have applied any prefix of them.
	ackedInitial   int64
	unackedInitial []int64
	// settingsOverflow is set once unackedInitial overflowed: from then on
	// the largest value ever sent is enforced.
	settingsOverflow bool
	maxInitialSent   int64
	initialWindow    int64
	maxFrame         int
	held             int64 // request bytes held: buffered bodies plus unsent data
	// creditOwed is connection credit owed to the client for streamed bytes
	// the relay discarded unsent; sendLoop returns it.
	creditOwed int64
	// maxConcurrent is the server's SETTINGS_MAX_CONCURRENT_STREAMS (-1:
	// none). Streams the server still counts are those in byServer; a
	// request that would pass the limit waits in openQueue, in order.
	maxConcurrent int64
	openQueue     []*stream
	queue         []*stream
	// Client-reset streams the server may still send on (frames in flight),
	// by server stream ID, oldest first in resetOrder. Bounded.
	resetIDs   map[uint32]uint32
	resetOrder []uint32
	// afterOpen, when set (tests only), runs in finish after a buffered
	// request's headers went upstream and before its body is queued.
	afterOpen func(*stream)

	// Response masking (mask.go), when masking is on.
	masking bool
	sdec    *hpack.Decoder // server header blocks; serverLoop only
	// sdecAllowed is the table size sdec accepts (serverLoop only), and
	// serverTableSize the largest the client allowed the server.
	sdecAllowed     uint32
	serverTableSize atomic.Uint32
	cenc            *hpack.Encoder // client header blocks; guarded by clientMu
	cencBuf         bytes.Buffer
	// Guarded by mu: the client's connection window and initial stream
	// window as the relay counts them for what it sends, the response side
	// of each client stream, the streams with queued items, the bytes held
	// for responses, and the connection credit owed to the server (negative)
	// or to withhold from it (positive).
	cliConn           int64
	clientRespInitial int64
	resp              map[uint32]*respState
	respList          []*respState
	respHeld          int64
	debt              int64
	// serverCreditDue is connection credit to give the server at once for
	// response bytes the client will never receive; clientSendLoop sends it.
	serverCreditDue int64
}

type stream struct {
	clientID, serverID uint32
	// lookupCtx is the context of the stream's resolver lookups, canceled
	// when the stream is dropped (guarded by relay.mu).
	lookupCtx    context.Context
	lookupCancel context.CancelFunc
	// finishing is set once finish took the buffered request to swap and
	// send it (guarded by relay.mu).
	finishing bool
	swap      bool
	authority string
	method    string
	buffering bool
	headers   []hpack.HeaderField
	priority  *Priority
	body      bytes.Buffer
	trailers  []hpack.HeaderField
	// Control frames for a stream that has no server ID yet, combined so a
	// client cannot grow them: the summed WINDOW_UPDATE increment and the
	// latest PRIORITY_UPDATE.
	pendingWindow   int64
	pendingPriority *Frame
	// pendingPriorityFrame is the latest PRIORITY frame for the stream,
	// sent (translated) once it has a server ID.
	pendingPriorityFrame *Priority
	// A request waiting for a slot under the server's concurrency limit.
	waitingOpen  bool
	openFields   []hpack.HeaderField
	openPriority *Priority
	openEnd      bool
	clientEnded  bool
	serverEnded  bool  // the server ended or reset the stream
	recvWindow   int64 // what the client may still send on this stream

	// Sending side, guarded by relay.mu.
	window    int64
	out       []byte
	outEnd    bool
	sentEnd   bool // the request side is done: END_STREAM sent, or the stream was dropped
	queued    bool
	streaming bool // window updates to the client follow what reached the server
}

// Serve relays until either side closes. It closes both connections.
func Serve(client, server net.Conn, opts Options) error {
	return newRelay(client, server, opts).run()
}

func newRelay(client, server net.Conn, opts Options) *relay {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 32 << 20
	}
	if opts.MaxBuffered <= 0 {
		opts.MaxBuffered = 64 << 20
	}
	if opts.MaxStreams <= 0 {
		opts.MaxStreams = 256
	}
	if opts.MaxLookups <= 0 {
		opts.MaxLookups = DefaultMaxLookups
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = 1 << 20
	}
	if opts.PrefaceTimeout <= 0 {
		opts.PrefaceTimeout = 30 * time.Second
	}
	if opts.MaxDecoded <= 0 {
		opts.MaxDecoded = mask.DefaultMaxDecoded
	}
	r := &relay{
		opts: opts, client: client, server: server,
		dec:      hpack.NewDecoder(decoderTableSize, nil),
		streams:  map[uint32]*stream{},
		byServer: map[uint32]*stream{},
		resetIDs: map[uint32]uint32{},

		nextServerID: 1, connWindow: defaultWindow, initialWindow: defaultWindow, maxFrame: defaultMaxFrame,
		recvConn: defaultWindow, clientInitial: defaultWindow, maxConcurrent: -1, ackedInitial: defaultWindow, maxInitialSent: defaultWindow,
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.asyncErrs = make(chan error, 1)
	r.dec.SetMaxStringLength(opts.MaxHeaderBytes)
	r.enc = hpack.NewEncoder(&r.encBuf)
	r.cond = sync.NewCond(&r.mu)
	if opts.Session != nil && opts.Session.Masking() {
		r.masking = true
		r.sdecAllowed = 4096
		r.serverTableSize.Store(4096)
		r.sdec = hpack.NewDecoder(4096, nil)
		r.sdec.SetMaxStringLength(opts.MaxHeaderBytes)
		r.cenc = hpack.NewEncoder(&r.cencBuf)
		r.cliConn, r.clientRespInitial = defaultWindow, defaultWindow
		r.resp = map[uint32]*respState{}
	}
	return r
}

// errNoServerPreface is a server that sent no SETTINGS in time.
var errNoServerPreface = errors.New("server sent no SETTINGS frame in time")

// errHeldFrames is more relay frames waiting for the server's SETTINGS
// than the buffer budget allows.
var errHeldFrames = errors.New("too many frames waiting for the server's SETTINGS")

func (r *relay) run() error {
	errs := make(chan error, 3)
	timeout := make(chan error, 1)
	timer := time.AfterFunc(r.opts.PrefaceTimeout, func() {
		// No clientMu here: a writer stuck on a client that stopped reading
		// may hold it.
		if !r.prefaceSent.Load() {
			timeout <- errNoServerPreface
		}
	})
	defer timer.Stop()
	pending := 3
	if r.masking {
		errs = make(chan error, 4)
		pending = 4
		go func() { errs <- r.serverLoopMasked() }()
		go func() { errs <- r.clientSendLoop() }()
	} else {
		go func() { errs <- r.serverLoop() }()
	}
	go func() { errs <- r.clientLoop() }()
	go func() { errs <- r.sendLoop() }()
	var first error
	select {
	case first = <-errs:
		pending--
	case first = <-timeout:
	case first = <-r.asyncErrs:
	}
	r.shutdown()
	for ; pending > 0; pending-- {
		<-errs //nolint:errcheck // waits for the other loops; first is the cause
	}
	// shutdown canceled every lookup; none outlives the relay.
	r.lookups.Wait()
	if errors.Is(first, io.EOF) || errors.Is(first, net.ErrClosed) {
		return nil
	}
	return first
}

// shutdown ends the relay. It must not wait on a goroutine stuck in I/O
// while holding clientMu: client writes block when the client stops reading,
// and serverLoop holds clientMu while it reads the rest of a response header
// block from the server. So the server socket closes first (ending those
// reads and any blocked server write), and clientMu is taken only before
// the server's SETTINGS were forwarded, after a client write deadline that
// also ends a write in progress. After them, the client socket closes
// without the lock, which ends any client write.
func (r *relay) shutdown() {
	r.cancel()
	r.mu.Lock()
	r.closed = true
	r.cond.Broadcast()
	r.mu.Unlock()
	_ = r.server.Close()
	if !r.prefaceSent.Load() {
		_ = r.client.SetWriteDeadline(time.Now().Add(failureWriteTimeout))
		r.failBeforePreface()
	}
	_ = r.client.Close()
}

// failureWriteTimeout bounds the connection error written to a client
// before the server's SETTINGS, and any write in progress then.
const failureWriteTimeout = 5 * time.Second

// failBeforePreface gives the client a connection error when the relay ends
// before the server's SETTINGS were forwarded (the server closed or failed
// early, or never answered): a SETTINGS frame of the relay's own as the
// server preface, the frames held so far, then a GOAWAY unless one of those
// already is. Without it the client would only see the connection close, or
// wait. The write is bounded in time in case the client does not read.
func (r *relay) failBeforePreface() {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	if r.prefaceSent.Load() {
		return
	}
	r.prefaceSent.Store(true)
	frames := append([]Frame{{Type: FrameSettings}}, r.early...)
	goaway := false
	for _, f := range r.early {
		goaway = goaway || f.Type == FrameGoAway
	}
	if !goaway {
		// Last stream 0: the server processed nothing, so the client may retry.
		payload := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), errCodeInternal)
		frames = append(frames, Frame{Type: FrameGoAway, Payload: payload})
	}
	r.early, r.earlyBytes = nil, 0
	_, _ = r.client.Write(encodeFrames(frames)) // bounded by shutdown's write deadline
}

func encodeFrames(frames []Frame) []byte {
	var b []byte
	for _, f := range frames {
		b = AppendFrame(b, f.Type, f.Flags, f.Stream, f.Payload)
	}
	return b
}

func (r *relay) writeClient(frames ...Frame) error {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	if !r.prefaceSent.Load() {
		return r.holdLocked(frames)
	}
	_, err := r.client.Write(encodeFrames(frames))
	return err
}

// holdLocked keeps relay frames until the server's SETTINGS go out.
func (r *relay) holdLocked(frames []Frame) error {
	for _, f := range frames {
		r.earlyBytes += frameHeaderLength + len(f.Payload)
	}
	if r.earlyBytes > r.opts.MaxBuffered {
		return errHeldFrames
	}
	r.early = append(r.early, frames...)
	return nil
}

// writeServerPreface forwards the server's first SETTINGS frame, then the
// relay frames that waited for it, in order.
func (r *relay) writeServerPreface(settings Frame) error {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	if r.prefaceSent.Load() {
		return errors.New("server SETTINGS arrived after the relay ended the connection")
	}
	r.prefaceSent.Store(true)
	frames := append([]Frame{settings}, r.early...)
	r.early, r.earlyBytes = nil, 0
	_, err := r.client.Write(encodeFrames(frames))
	return err
}

func (r *relay) writeServer(frames ...Frame) error {
	b := encodeFrames(frames)
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	_, err := r.server.Write(b)
	return err
}

func windowUpdate(stream uint32, n int) Frame {
	return Frame{Type: FrameWindowUpdate, Stream: stream, Payload: binary.BigEndian.AppendUint32(nil, uint32(n))}
}

func refusal(clientID uint32) Frame {
	return Frame{Type: FrameRSTStream, Stream: clientID, Payload: binary.BigEndian.AppendUint32(nil, errCodeRefusedStream)}
}

// creditClient returns flow-control credit to the client for request bytes.
func (r *relay) creditClient(clientID uint32, n int, streamToo bool) error {
	if n <= 0 {
		return nil
	}
	frames := []Frame{windowUpdate(0, n)}
	r.mu.Lock()
	r.recvConn += int64(n)
	if streamToo {
		frames = append(frames, windowUpdate(clientID, n))
		if s := r.streams[clientID]; s != nil {
			s.recvWindow += int64(n)
		}
	}
	r.mu.Unlock()
	return r.writeClient(frames...)
}

// errFlowControl is a client that sent more DATA than its windows allowed.
var errFlowControl = errors.New("client exceeded its flow-control window")

// flowControlError ends the connection after a window violation.
func (r *relay) flowControlError() error {
	return r.connectionError(errCodeFlowControl, errFlowControl)
}

// connectionError tells the client with GOAWAY that the connection ends for
// code, and returns cause, which ends the relay.
func (r *relay) connectionError(code uint32, cause error) error {
	r.mu.Lock()
	last := r.maxClientID
	r.mu.Unlock()
	payload := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, last), code)
	_ = r.writeClient(Frame{Type: FrameGoAway, Payload: payload})
	return cause
}

// clientLoop reads the client's frames and sends them on.
func (r *relay) clientLoop() error {
	preface := make([]byte, len(Preface))
	if _, err := io.ReadFull(r.client, preface); err != nil {
		return fmt.Errorf("read client preface: %w", err)
	}
	if string(preface) != Preface {
		return errors.New("client did not send the HTTP/2 preface")
	}
	r.serverMu.Lock()
	_, err := r.server.Write(preface)
	r.serverMu.Unlock()
	if err != nil {
		return err
	}

	var block []byte
	inBlock := false
	var blockStream uint32
	var blockFlags uint8
	var blockPriority *Priority
	appendFragment := func(fragment []byte) error {
		if len(block)+len(fragment) > r.opts.MaxHeaderBytes {
			return fmt.Errorf("client header block is larger than %d bytes", r.opts.MaxHeaderBytes)
		}
		block = append(block, fragment...)
		return nil
	}
	for {
		f, err := readFrame(r.client, r.clientFrames.size)
		if errors.Is(err, ErrFrameSize) {
			return r.connectionError(errCodeFrameSize, fmt.Errorf("client: %w", err))
		}
		if err != nil {
			return err
		}
		if inBlock && (f.Type != FrameContinuation || f.Stream != blockStream) {
			return errors.New("client interrupted a header block")
		}
		switch f.Type {
		case FrameHeaders:
			priority, fragment, err := HeadersPayload(f.Flags, f.Payload)
			if err != nil {
				return err
			}
			block, inBlock, blockStream, blockFlags, blockPriority = block[:0], true, f.Stream, f.Flags, priority
			if err := appendFragment(fragment); err != nil {
				return err
			}
		case FrameContinuation:
			if !inBlock {
				return errors.New("CONTINUATION without HEADERS")
			}
			if err := appendFragment(f.Payload); err != nil {
				return err
			}
		case FrameData:
			err = r.onData(f)
		case FrameWindowUpdate, FrameRSTStream:
			switch {
			case f.Stream == 0 && r.masking && f.Type == FrameWindowUpdate:
				err = r.onClientConnWindow(f)
			case f.Stream == 0:
				err = r.writeServer(f)
			default:
				err = r.forStream(f)
			}
		case FramePriority:
			err = r.onPriority(f)
		case FramePriorityUpdate:
			err = r.onPriorityUpdate(f)
		case FramePushPromise:
			return errors.New("client sent PUSH_PROMISE")
		default:
			// SETTINGS (and their ACKs), PING, GOAWAY and unknown frame
			// types go upstream exactly as the client sent them.
			if f.Type == FrameSettings && f.Flags&FlagAck != 0 {
				r.clientFrames.ack()
				if err := r.applyClientAck(); err != nil {
					return err
				}
			}
			if f.Type == FrameSettings && f.Flags&FlagAck == 0 {
				if r.masking {
					if err := r.onClientSettings(f.Payload); err != nil {
						return err
					}
				}
				r.serverFrames.sent(f.Payload)
			}
			err = r.writeServer(f)
		}
		if err != nil {
			return err
		}
		if inBlock && f.Flags&FlagEndHeaders != 0 && (f.Type == FrameHeaders || f.Type == FrameContinuation) {
			inBlock = false
			if err := r.onHeaders(blockStream, blockFlags, blockPriority, block); err != nil {
				return err
			}
		}
	}
}

// decode decodes a client header block, refusing one whose decoded size
// (RFC 9113 accounting: name, value and 32 bytes per field) passes the limit.
// HPACK can expand a small block into a large list through table references.
func (r *relay) decode(block []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	size, overflow := 0, false
	r.dec.SetEmitFunc(func(f hpack.HeaderField) {
		size += len(f.Name) + len(f.Value) + 32
		if size > r.opts.MaxHeaderBytes {
			overflow = true
		}
		if !overflow {
			fields = append(fields, f)
		}
	})
	if _, err := r.dec.Write(block); err != nil {
		return nil, fmt.Errorf("decode client header block: %w", err)
	}
	if err := r.dec.Close(); err != nil {
		return nil, fmt.Errorf("decode client header block: %w", err)
	}
	if overflow {
		return nil, fmt.Errorf("client header list is larger than %d bytes", r.opts.MaxHeaderBytes)
	}
	return fields, nil
}

// forStream forwards a WINDOW_UPDATE or RST_STREAM the client sent for a
// request stream.
func (r *relay) forStream(f Frame) error {
	if r.masking {
		keep, err := r.onClientStreamFrame(f)
		if err != nil || keep {
			return err
		}
	}
	r.mu.Lock()
	s := r.streams[f.Stream]
	if s == nil {
		r.mu.Unlock()
		return nil
	}
	if f.Type == FrameRSTStream {
		r.dropLocked(s)
		if s.serverID != 0 {
			r.forgetResetLocked(s)
		}
	}
	if s.serverID == 0 {
		if f.Type == FrameWindowUpdate {
			if len(f.Payload) != 4 {
				r.mu.Unlock()
				return errors.New("client sent a bad WINDOW_UPDATE")
			}
			s.pendingWindow += int64(binary.BigEndian.Uint32(f.Payload) & 0x7fffffff)
			if s.pendingWindow > maxWindow {
				// RFC 9113 6.9.1: a window above 2^31-1 is an error for the stream.
				r.dropLocked(s)
				r.mu.Unlock()
				return r.writeClient(refusal(s.clientID))
			}
		}
		r.mu.Unlock()
		return nil
	}
	f.Stream = s.serverID
	r.mu.Unlock()
	return r.writeServer(f)
}

// openStreamsLocked counts the client streams the relay holds state for:
// open requests, and, with masking, responses still waiting to reach the
// client after the server ended them.
func (r *relay) openStreamsLocked() int {
	n := len(r.streams)
	for id := range r.resp {
		if r.streams[id] == nil {
			n++
		}
	}
	return n
}

// dropLocked forgets the request side of a stream and releases what it held.
// Every caller ends the stream toward the client (a refusal or a reset). The
// server mapping stays until the server ends the stream: without masking,
// its remaining frames still go to the client, which ignores them after
// decoding any header block; with masking, the response side ends here
// (endRespLocked) and the server's remaining frames are absorbed.
func (r *relay) dropLocked(s *stream) {
	r.held -= int64(s.body.Len() + len(s.out))
	if s.streaming && len(s.out) > 0 {
		// Streamed bytes are credited once sent upstream; these never will
		// be, so their connection credit is returned here. Buffered bodies
		// were credited on arrival.
		r.creditOwed += int64(len(s.out))
		r.cond.Broadcast()
	}
	s.body = bytes.Buffer{}
	s.out = nil
	s.buffering = false
	if s.waitingOpen {
		s.waitingOpen = false
		for i, q := range r.openQueue {
			if q == s {
				r.openQueue = append(r.openQueue[:i], r.openQueue[i+1:]...)
				break
			}
		}
	}
	r.dequeue(s)
	delete(r.streams, s.clientID)
	if s.lookupCancel != nil {
		s.lookupCancel() // a lookup still in flight is no longer wanted
		r.dropLookupsLocked(s)
	}
	if r.masking {
		// The stream ends toward the client too (it was refused or reset):
		// its response, queued or still to come, is released with its
		// queued bytes and masking worker, and nothing more of it reaches
		// the client.
		if rs := r.resp[s.clientID]; rs != nil {
			r.endRespLocked(rs)
		}
	}
}

// forgetResetLocked drops the server mapping of a stream the client reset.
// The server may not answer the reset at all, so the mapping is not kept
// until it does; a bounded record lets frames already in flight reach the
// client (a response header block must, to keep the client's HPACK table in
// step). A header block for a reset stream older than the record ends the
// connection.
func (r *relay) forgetResetLocked(s *stream) {
	r.forgetServerLocked(s)
	if s.serverEnded {
		return
	}
	r.resetIDs[s.serverID] = s.clientID
	r.resetOrder = append(r.resetOrder, s.serverID)
	for len(r.resetOrder) > maxResetStreams {
		delete(r.resetIDs, r.resetOrder[0])
		r.resetOrder = r.resetOrder[1:]
	}
}

// forgetIfDoneLocked removes a stream once both sides have ended.
func (r *relay) forgetIfDoneLocked(s *stream) {
	if s.sentEnd && s.serverEnded {
		if r.streams[s.clientID] == s {
			delete(r.streams, s.clientID)
		}
		r.forgetServerLocked(s)
	}
}

func (r *relay) serverIDLocked(clientID uint32) (uint32, bool) {
	if s := r.streams[clientID]; s != nil && s.serverID != 0 {
		return s.serverID, true
	}
	return 0, false
}

// dependencyLocked translates a priority dependency on a client stream for
// the server. A stream already upstream gets its server ID. A stream with
// none (still buffering, refused, or closed and forgotten) becomes the root:
// no upstream stream stands for it, and its client ID could be another
// stream's server ID. An idle stream the client has not opened yet keeps
// its ID, as every server ID in use is below it (idle-stream priority
// trees, which Chromium does not send, are kept that way).
func (r *relay) dependencyLocked(dep uint32) uint32 {
	if dep == 0 {
		return 0
	}
	if id, ok := r.serverIDLocked(dep); ok {
		return id
	}
	if dep > r.maxClientID {
		return dep
	}
	return 0
}

func (r *relay) onPriority(f Frame) error {
	if len(f.Payload) != 5 {
		return errors.New("PRIORITY frame with a bad length")
	}
	p := parsePriority(f.Payload)
	r.mu.Lock()
	s := r.streams[f.Stream]
	switch {
	case s != nil && s.serverID == 0:
		// Sent once the stream goes upstream, under its server ID.
		s.pendingPriorityFrame = &p
		r.mu.Unlock()
		return nil
	case s != nil:
		f.Stream = s.serverID
	case f.Stream <= r.maxClientID:
		r.mu.Unlock()
		return nil // a closed or refused stream: nothing upstream stands for it
	}
	p.DependsOn = r.dependencyLocked(p.DependsOn)
	if p.DependsOn == f.Stream {
		p.DependsOn = 0
	}
	r.mu.Unlock()
	f.Payload = p.bytes()
	return r.writeServer(f)
}

func (r *relay) onPriorityUpdate(f Frame) error {
	if len(f.Payload) < 4 {
		return errors.New("PRIORITY_UPDATE frame too short")
	}
	if len(f.Payload)-4 > maxPriorityValue {
		// The latest value is kept for each stream not upstream yet, outside
		// the buffer budget, so it must stay small.
		return r.connectionError(errCodeProtocol, fmt.Errorf("client sent a PRIORITY_UPDATE value over %d bytes", maxPriorityValue))
	}
	target := binary.BigEndian.Uint32(f.Payload) & 0x7fffffff
	r.mu.Lock()
	if s := r.streams[target]; s != nil {
		if s.serverID == 0 {
			latest := f
			s.pendingPriority = &latest
			r.mu.Unlock()
			return nil
		}
		payload := binary.BigEndian.AppendUint32(nil, s.serverID)
		f.Payload = append(payload, f.Payload[4:]...)
	} else if target <= r.maxClientID {
		r.mu.Unlock()
		return nil // a closed or refused stream: nothing upstream stands for it
	}
	r.mu.Unlock()
	return r.writeServer(f)
}

func (r *relay) onHeaders(clientID uint32, flags uint8, priority *Priority, block []byte) error {
	// Every block is decoded, even for refused or closed streams, to keep the
	// HPACK table in step with the client's encoder.
	fields, err := r.decode(block)
	if err != nil {
		return err
	}
	endStream := flags&FlagEndStream != 0

	r.mu.Lock()
	s := r.streams[clientID]
	newStream := s == nil && clientID > r.maxClientID
	if newStream {
		r.maxClientID = clientID
	}
	goingAway := r.goaway
	refuse := newStream && (goingAway || r.openStreamsLocked() >= r.opts.MaxStreams)
	r.mu.Unlock()

	if s == nil && !newStream {
		return nil // trailers for a stream that was reset or refused
	}
	if refuse {
		r.opts.Logger.Warn("refusing a client stream", "stream", clientID, "server_going_away", goingAway, "stream_limit", r.opts.MaxStreams)
		return r.writeClient(refusal(clientID))
	}

	if s == nil {
		method, authorities, err := requestHead(fields)
		authority := ""
		if len(authorities) > 0 {
			authority = authorities[0]
		}
		// Every request goes to the CONNECT host: one naming another host is
		// refused, so no value scoped to that host goes with it.
		if err == nil {
			err = r.opts.Session.CheckAuthority(authorities...)
		}
		if err != nil {
			return r.badGateway(clientID, authority, endStream, err)
		}
		s = &stream{clientID: clientID, swap: r.opts.Hosts.Match(authority), authority: authority, method: method, clientEnded: endStream}
		// A request with a body is swapped once the body is complete
		// (finish), with a single lookup for its headers, body and trailers.
		// Any other request on an allowlisted authority is prepared here;
		// one that needs a lookup waits for it off this loop (lookup.go).
		buffered := !endStream && s.swap && method != "CONNECT"
		var lookup *scope.Lookup
		if s.swap && !buffered {
			if lookup, err = r.opts.Session.Prepare(fieldText(fields)...); err != nil {
				return r.badGateway(clientID, authority, endStream, err)
			}
		}
		// Every field other goroutines read is set before the stream is
		// published in r.streams; serverLoop scans buffering streams when
		// the server's SETTINGS arrive, sendLoop and dropLocked read
		// streaming.
		if buffered {
			s.buffering, s.headers, s.priority = true, fields, priority
		} else {
			s.streaming = !endStream
		}
		r.mu.Lock()
		s.recvWindow = r.clientInitial
		r.streams[clientID] = s
		if r.masking {
			r.newRespLocked(clientID, method)
		}
		var topUp []Frame
		if buffered {
			topUp = r.topUpBufferingLocked()
		}
		r.mu.Unlock()
		if lookup != nil {
			return r.resolveLookup(s, lookup, func(swapper *swap.Swapper, err error) error {
				return r.openResolved(s, fields, priority, endStream, swapper, err)
			})
		}
		if !buffered {
			return r.open(s, fields, priority, endStream)
		}
		if len(topUp) > 0 {
			if err := r.writeClient(topUp...); err != nil {
				return err
			}
		}
		for _, f := range fields {
			if f.Name == "expect" && strings.EqualFold(f.Value, "100-continue") {
				// The body is needed before the request can go upstream, so
				// approve it here. A second 100 from the server is harmless.
				return r.writeClient(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: clientID, Payload: continueBlock})
			}
		}
		return nil
	}

	// Trailers. A buffered request's are swapped with its body in finish;
	// a streamed request (extended CONNECT) on an allowlisted authority gets
	// a lookup of its own. A header block after the client ended the stream
	// is a stream error.
	r.mu.Lock()
	buffering, ended := s.buffering, s.clientEnded
	r.mu.Unlock()
	if ended {
		return r.endedStream(s, 0)
	}
	if s.swap && !buffering {
		lookup, err := r.opts.Session.Prepare(fieldText(fields)...)
		if err != nil {
			r.opts.Logger.Error("resetting a request whose trailers cannot be sent", "stream", clientID, "error", err)
			return r.abort(s, errCodeCalm)
		}
		if lookup != nil {
			r.mu.Lock()
			s.clientEnded = s.clientEnded || endStream
			r.mu.Unlock()
			return r.resolveLookup(s, lookup, func(swapper *swap.Swapper, err error) error {
				if err == nil {
					err = r.swapFields(swapper, fields, s.authority)
				}
				if err != nil {
					r.opts.Logger.Error("resetting a request whose trailers cannot be sent", "stream", s.clientID, "error", err)
					return r.abort(s, errCodeCalm)
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				s.trailers = fields
				s.outEnd = s.outEnd || endStream
				r.enqueueLocked(s)
				return nil
			})
		}
	}
	r.mu.Lock()
	s.clientEnded = s.clientEnded || endStream
	if s.buffering {
		s.trailers = fields
		r.mu.Unlock()
		if endStream {
			return r.finish(s)
		}
		return nil
	}
	s.trailers = fields
	s.outEnd = s.outEnd || endStream
	r.enqueueLocked(s)
	r.mu.Unlock()
	return nil
}

// requestHead returns a request's :method and the authorities it names
// (:authority, host), refusing a malformed request (RFC 9113 8.2.1, 8.3.1)
// that a server could read differently from the relay: a field name with an
// uppercase character, which the relay would not take for the framing field
// it is ("Content-Length" would keep its length after a body swap), or more
// than one :authority or host, of which a server may use another than the
// one checked. Session.CheckAuthority refuses a host that disagrees with
// :authority.
func requestHead(fields []hpack.HeaderField) (method string, authorities []string, err error) {
	authorityFields, hostFields, uppercase := 0, 0, ""
	for _, f := range fields {
		if uppercase == "" && strings.ContainsFunc(f.Name, unicode.IsUpper) {
			uppercase = f.Name
		}
		switch f.Name {
		case ":method":
			method = f.Value
		case ":authority":
			authorities = append(authorities, f.Value)
			authorityFields++
		case "host":
			authorities = append(authorities, f.Value)
			hostFields++
		}
	}
	switch {
	case uppercase != "":
		err = fmt.Errorf("%w: field name %q has uppercase characters", scope.ErrRefused, uppercase)
	case authorityFields > 1 || hostFields > 1:
		err = fmt.Errorf("%w: more than one :authority or host field", scope.ErrRefused)
	}
	return method, authorities, err
}

// fieldText is the text of a header list that stand-ins are swapped in: the
// query part of :path and the values of fields that are neither
// pseudo-headers nor framing headers.
func fieldText(fields []hpack.HeaderField) []swap.Part {
	parts := make([]swap.Part, 0, len(fields))
	for _, f := range fields {
		switch {
		case f.Name == ":path":
			if _, query, ok := strings.Cut(f.Value, "?"); ok {
				query, _, _ = strings.Cut(query, "#")
				parts = append(parts, swap.Part{Place: swap.Query, Text: query})
			}
		case strings.HasPrefix(f.Name, ":"), framingHeaders[f.Name]:
		default:
			parts = append(parts, swap.Part{Place: swap.Literal, Text: f.Value})
		}
	}
	return parts
}

// badGateway answers a request that must not be sent with a 502 of the
// relay's own, ending the stream. A client still sending its body is told to
// stop with RST_STREAM NO_ERROR (RFC 9113 8.1).
func (r *relay) badGateway(clientID uint32, authority string, clientEnded bool, cause error) error {
	r.opts.Logger.Warn("refusing a request", "stream", clientID, "authority", authority,
		"principal", r.opts.Session.Principal().ID, "reason", cause.Error())
	frames := []Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: clientID, Payload: badGatewayBlock}}
	if !clientEnded {
		frames = append(frames, Frame{Type: FrameRSTStream, Stream: clientID, Payload: binary.BigEndian.AppendUint32(nil, errCodeNoError)})
	}
	return r.writeClient(frames...)
}

// swapFields swaps stand-ins in header values and in the query string of
// :path; other pseudo-headers are left alone. The swapped list stays within
// MaxHeaderBytes (decoded size), and a real value that would put a line
// break into a header is refused. Errors name the header, never a value.
func (r *relay) swapFields(swapper *swap.Swapper, fields []hpack.HeaderField, authority string) error {
	size := 0
	for _, f := range fields {
		size += len(f.Name) + len(f.Value) + 32
	}
	swapped := 0
	for i := range fields {
		f := &fields[i]
		room := r.opts.MaxHeaderBytes - size + len(f.Value) // the most this value may grow to
		var value string
		var changed bool
		var err error
		switch {
		case f.Name == ":path":
			value, changed, err = swapper.Target(f.Value, room)
		case strings.HasPrefix(f.Name, ":"), framingHeaders[f.Name]:
			continue
		default:
			value, changed, err = swapper.Header(f.Value, room)
		}
		if err != nil {
			return fmt.Errorf("header %s: %w", f.Name, err)
		}
		if changed {
			size += len(value) - len(f.Value)
			f.Value = value
			swapped++
		}
	}
	if swapped > 0 {
		r.opts.Logger.Info("swapped stand-ins in request headers", "authority", authority, "fields", swapped)
	}
	return nil
}

// framingHeaders describe the message, not its content: a stand-in that
// happens to match their value ("123" in content-length: 123) is not one.
// content-length is set from the body that is actually sent.
var framingHeaders = map[string]bool{"content-length": true, "te": true, "trailer": true}

// abort ends a client stream the relay cannot carry on: refused
// (REFUSED_STREAM) when nothing went upstream yet, else reset on both sides,
// the client getting clientCode.
func (r *relay) abort(s *stream, clientCode uint32) error {
	r.mu.Lock()
	if r.streams[s.clientID] != s {
		r.mu.Unlock()
		return nil // already gone
	}
	serverID := s.serverID
	r.dropLocked(s)
	if serverID != 0 {
		r.forgetResetLocked(s)
	}
	r.mu.Unlock()
	if serverID == 0 {
		return r.writeClient(refusal(s.clientID))
	}
	if err := r.writeServer(Frame{Type: FrameRSTStream, Stream: serverID, Payload: binary.BigEndian.AppendUint32(nil, errCodeCancel)}); err != nil {
		return err
	}
	return r.writeClient(Frame{Type: FrameRSTStream, Stream: s.clientID, Payload: binary.BigEndian.AppendUint32(nil, clientCode)})
}

// open sends a request's HEADERS upstream under a new server stream ID,
// unless the stream was dropped meanwhile or the server is going away. A
// request that would pass the server's SETTINGS_MAX_CONCURRENT_STREAMS
// waits in openQueue; sendLoop opens it when a slot frees (fromQueue).
//
// serverMu is held from the ID assignment to the write, so server stream IDs
// reach the server in increasing order whichever goroutine opens.
func (r *relay) open(s *stream, fields []hpack.HeaderField, priority *Priority, endStream bool) error {
	return r.openStream(s, fields, priority, endStream, false)
}

func (r *relay) openStream(s *stream, fields []hpack.HeaderField, priority *Priority, endStream, fromQueue bool) error {
	r.serverMu.Lock()
	r.mu.Lock()
	if r.streams[s.clientID] != s {
		r.mu.Unlock()
		r.serverMu.Unlock()
		return nil
	}
	if r.goaway {
		r.dropLocked(s)
		r.mu.Unlock()
		r.serverMu.Unlock()
		return r.writeClient(refusal(s.clientID))
	}
	if !fromQueue && (len(r.openQueue) > 0 || !r.slotLocked()) {
		s.waitingOpen, s.openFields, s.openPriority, s.openEnd = true, fields, priority, endStream
		r.openQueue = append(r.openQueue, s)
		r.mu.Unlock()
		r.serverMu.Unlock()
		return nil
	}
	s.serverID = r.nextServerID
	r.nextServerID += 2
	r.byServer[s.serverID] = s
	if rs := r.resp[s.clientID]; rs != nil {
		rs.serverID = s.serverID
	}
	s.window = r.initialWindow
	if endStream {
		s.sentEnd = true
	}
	maxFrame := r.maxFrame
	if priority != nil {
		p := *priority
		p.DependsOn = r.dependencyLocked(p.DependsOn)
		if p.DependsOn == s.serverID {
			p.DependsOn = 0 // never on itself
		}
		priority = &p
	}
	var priorityFrame *Priority
	if pf := s.pendingPriorityFrame; pf != nil {
		p := *pf
		p.DependsOn = r.dependencyLocked(p.DependsOn)
		if p.DependsOn == s.serverID {
			p.DependsOn = 0
		}
		priorityFrame = &p
	}
	pendingWindow, pendingPriority := s.pendingWindow, s.pendingPriority
	s.pendingWindow, s.pendingPriority, s.pendingPriorityFrame = 0, nil, nil
	r.cond.Broadcast() // queued data for this stream may go now
	r.mu.Unlock()

	defer r.serverMu.Unlock()
	frames := r.headerFramesLocked(s.serverID, fields, priority, endStream, maxFrame)
	if priorityFrame != nil {
		frames = append(frames, Frame{Type: FramePriority, Stream: s.serverID, Payload: priorityFrame.bytes()})
	}
	if pendingWindow > 0 {
		frames = append(frames, windowUpdate(s.serverID, int(pendingWindow)))
	}
	if pendingPriority != nil {
		f := *pendingPriority
		f.Payload = append(binary.BigEndian.AppendUint32(nil, s.serverID), f.Payload[4:]...)
		frames = append(frames, f)
	}
	_, err := r.server.Write(encodeFrames(frames))
	return err
}

// slotLocked reports whether the server's concurrency limit allows one more
// stream.
func (r *relay) slotLocked() bool {
	return r.maxConcurrent < 0 || int64(len(r.byServer)) < r.maxConcurrent
}

// forgetServerLocked removes a server mapping, freeing a concurrency slot.
func (r *relay) forgetServerLocked(s *stream) {
	if r.byServer[s.serverID] == s {
		delete(r.byServer, s.serverID)
		r.cond.Broadcast()
	}
}

// headerFramesLocked encodes a header block and splits it into HEADERS and
// CONTINUATION frames. The caller holds serverMu, so blocks reach the server
// in the order they were encoded.
func (r *relay) headerFramesLocked(serverID uint32, fields []hpack.HeaderField, priority *Priority, endStream bool, maxFrame int) []Frame {
	r.encBuf.Reset()
	for _, f := range fields {
		_ = r.enc.WriteField(f)
	}
	block := append([]byte{}, r.encBuf.Bytes()...)
	var prefix []byte
	flags := uint8(0)
	if endStream {
		flags |= FlagEndStream
	}
	if priority != nil {
		prefix = priority.bytes()
		flags |= FlagPriority
	}
	first := min(len(block), maxFrame-len(prefix))
	if first == len(block) {
		flags |= FlagEndHeaders
	}
	frames := []Frame{{Type: FrameHeaders, Flags: flags, Stream: serverID, Payload: append(prefix, block[:first]...)}}
	for rest := block[first:]; len(rest) > 0; {
		n := min(len(rest), maxFrame)
		f := Frame{Type: FrameContinuation, Stream: serverID, Payload: rest[:n]}
		if n == len(rest) {
			f.Flags = FlagEndHeaders
		}
		frames = append(frames, f)
		rest = rest[n:]
	}
	return frames
}

func (r *relay) onData(f Frame) error {
	data, err := unpad(f.Flags, f.Payload)
	if err != nil {
		return err
	}
	end := f.Flags&FlagEndStream != 0
	r.mu.Lock()
	// Every DATA frame counts against the connection window, padding
	// included, whatever stream it is on.
	r.recvConn -= int64(len(f.Payload))
	if r.recvConn < 0 {
		r.mu.Unlock()
		return r.flowControlError()
	}
	s := r.streams[f.Stream]
	if s == nil {
		r.mu.Unlock()
		return r.creditClient(0, len(f.Payload), false)
	}
	s.recvWindow -= int64(len(f.Payload))
	if s.recvWindow < 0 {
		r.mu.Unlock()
		return r.flowControlError()
	}
	if s.clientEnded {
		// DATA after the client ended the stream.
		r.mu.Unlock()
		return r.endedStream(s, len(f.Payload))
	}
	s.clientEnded = s.clientEnded || end
	if s.buffering {
		overBody := s.body.Len()+len(data) > r.opts.MaxBody
		overConn := r.held+int64(len(data)) > int64(r.opts.MaxBuffered)
		if overBody || overConn {
			r.dropLocked(s)
			r.mu.Unlock()
			r.opts.Logger.Error("refusing a request body over the buffer limit",
				"stream", f.Stream, "body_limit_bytes", r.opts.MaxBody, "connection_limit_bytes", r.opts.MaxBuffered, "connection_limit_reached", overConn)
			if err := r.writeClient(refusal(f.Stream)); err != nil {
				return err
			}
			return r.creditClient(0, len(f.Payload), false)
		}
		s.body.Write(data)
		r.held += int64(len(data))
		r.mu.Unlock()
		if err := r.creditClient(s.clientID, len(f.Payload), !end); err != nil {
			return err
		}
		if end {
			return r.finish(s)
		}
		return nil
	}
	if r.held+int64(len(data)) > int64(r.opts.MaxBuffered) {
		r.mu.Unlock()
		r.opts.Logger.Error("resetting a streamed upload over the connection buffer limit", "stream", f.Stream, "connection_limit_bytes", r.opts.MaxBuffered)
		if err := r.abort(s, errCodeCalm); err != nil {
			return err
		}
		return r.creditClient(0, len(f.Payload), false)
	}
	s.out = append(s.out, data...)
	r.held += int64(len(data))
	s.outEnd = s.outEnd || end
	r.enqueueLocked(s)
	r.mu.Unlock()
	// Padding never reaches the server, so credit it now.
	return r.creditClient(s.clientID, len(f.Payload)-len(data), !end)
}

// finish swaps a buffered request body and sends the request upstream.
//
// The swapped body may be at most MaxBody and what the connection budget
// has left beside this stream's original; the swap stops at that limit
// rather than allocating past it, and the request is refused. The swapped
// body takes the original's place in held, still under the lock, before the
// headers go upstream; a reset or GOAWAY that drops the stream afterwards
// releases it through dropLocked.
func (r *relay) finish(s *stream) error {
	r.mu.Lock()
	if r.streams[s.clientID] != s || !s.buffering || s.finishing {
		r.mu.Unlock()
		return nil // dropped meanwhile (reset, refused, server going away), or already finishing
	}
	// Finishing from here on, so nothing the client sends starts it again
	// while the lookup runs.
	s.finishing = true
	// s.body is not written again: the client ended the stream, and so its
	// trailers are final too.
	original := s.body.Bytes()
	headers, priority, trailers := s.headers, s.priority, s.trailers
	s.headers = nil
	r.mu.Unlock()

	contentType := ""
	for _, h := range headers {
		if h.Name == "content-type" {
			contentType = h.Value
		}
	}
	parts := append(fieldText(headers), fieldText(trailers)...)
	parts = append(parts, swap.Part{Place: swap.BodyPlace(contentType), Text: string(original)})
	lookup, err := r.opts.Session.Prepare(parts...)
	if err != nil {
		return r.refuseLookup(s, err)
	}
	if lookup == nil {
		return r.finishSwapped(s, nil, headers, priority, trailers, original, contentType)
	}
	// The body stays buffered (and counted) while a lookup runs off
	// clientLoop.
	return r.resolveLookup(s, lookup, func(swapper *swap.Swapper, err error) error {
		if err != nil {
			return r.refuseLookup(s, err)
		}
		return r.finishSwapped(s, swapper, headers, priority, trailers, original, contentType)
	})
}

// finishSwapped swaps a buffered request's headers, trailers and body with
// swapper (nil: nothing to swap) and sends the request upstream.
func (r *relay) finishSwapped(s *stream, swapper *swap.Swapper, headers []hpack.HeaderField, priority *Priority, trailers []hpack.HeaderField, original []byte, contentType string) error {
	r.mu.Lock()
	limit := min(int64(r.opts.MaxBody), int64(r.opts.MaxBuffered)-(r.held-int64(len(original))))
	r.mu.Unlock()
	var err error
	body, changed := original, false
	if swapper != nil {
		for _, list := range [][]hpack.HeaderField{headers, trailers} {
			if err := r.swapFields(swapper, list, s.authority); err != nil {
				r.opts.Logger.Error("refusing a request whose swapped headers cannot be sent", "stream", s.clientID, "error", err)
				return r.abort(s, errCodeRefusedStream)
			}
		}
		body, changed, err = swapper.Body(contentType, original, int(max(limit, 0)))
	}
	if err != nil {
		r.opts.Logger.Error("refusing a request whose swapped body passes the buffer limits",
			"stream", s.clientID, "body_limit_bytes", r.opts.MaxBody, "connection_limit_bytes", r.opts.MaxBuffered)
		return r.abort(s, errCodeRefusedStream)
	}
	// content-length always describes the body that is sent.
	for i := range headers {
		if headers[i].Name == "content-length" {
			headers[i].Value = strconv.Itoa(len(body))
		}
	}
	if changed {
		// No sizes: with the stand-ins known, the change in length gives
		// away the real values' lengths.
		r.opts.Logger.Info("swapped stand-ins in a request body", "authority", s.authority)
	}

	r.mu.Lock()
	if r.streams[s.clientID] != s || !s.buffering {
		r.mu.Unlock()
		return nil
	}
	grow := int64(len(body)) - int64(s.body.Len())
	if r.held+grow > int64(r.opts.MaxBuffered) {
		r.mu.Unlock()
		r.opts.Logger.Error("refusing a request whose swapped body passes the connection buffer limit", "stream", s.clientID, "connection_limit_bytes", r.opts.MaxBuffered)
		return r.abort(s, errCodeRefusedStream)
	}
	r.held += grow
	s.body = bytes.Buffer{}
	s.buffering = false
	s.out = body // not queued before its headers are sent
	r.mu.Unlock()

	if err := r.open(s, headers, priority, false); err != nil {
		return err
	}
	if r.afterOpen != nil {
		r.afterOpen(s)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams[s.clientID] != s {
		return nil // dropped after its headers went upstream; dropLocked released the body
	}
	s.outEnd = true
	r.enqueueLocked(s)
	return nil
}

func (r *relay) enqueueLocked(s *stream) {
	if !s.queued && !s.sentEnd {
		s.queued = true
		r.queue = append(r.queue, s)
	}
	r.cond.Broadcast()
}

func (r *relay) dequeue(s *stream) {
	s.sentEnd = true
	for i, q := range r.queue {
		if q == s {
			r.queue = append(r.queue[:i], r.queue[i+1:]...)
			break
		}
	}
	s.queued = false
}

// sendLoop sends request bodies and trailers upstream within the server's
// flow-control windows.
func (r *relay) sendLoop() error {
	for {
		r.mu.Lock()
		var s *stream
		for s == nil {
			if r.closed {
				r.mu.Unlock()
				return net.ErrClosed
			}
			if owed := r.creditOwed; owed > 0 {
				r.creditOwed = 0
				r.mu.Unlock()
				if err := r.creditClient(0, int(owed), false); err != nil {
					return err
				}
				r.mu.Lock()
				continue
			}
			if len(r.openQueue) > 0 && r.slotLocked() {
				next := r.openQueue[0]
				r.openQueue = r.openQueue[1:]
				next.waitingOpen = false
				fields, priority, end := next.openFields, next.openPriority, next.openEnd
				next.openFields, next.openPriority = nil, nil
				r.mu.Unlock()
				if err := r.openStream(next, fields, priority, end, true); err != nil {
					return err
				}
				r.mu.Lock()
				continue
			}
			kept := r.queue[:0]
			for _, q := range r.queue {
				if len(q.out) == 0 && !q.outEnd {
					q.queued = false // nothing to send until the client sends more
					continue
				}
				kept = append(kept, q)
			}
			r.queue = kept
			for i, q := range r.queue {
				if q.serverID == 0 {
					continue // waiting for a slot under the server's concurrency limit
				}
				if len(q.out) > 0 && q.window > 0 && r.connWindow > 0 || len(q.out) == 0 && q.outEnd {
					s = q
					r.queue = append(append(r.queue[:i:i], r.queue[i+1:]...), q) // round robin
					break
				}
			}
			if s == nil {
				r.cond.Wait()
			}
		}
		var chunk []byte
		var trailers []hpack.HeaderField
		if len(s.out) > 0 {
			n := min(int64(len(s.out)), s.window, r.connWindow, int64(r.maxFrame))
			chunk, s.out = s.out[:n:n], s.out[n:]
			s.window -= n
			r.connWindow -= n
			r.held -= n
		}
		end := len(s.out) == 0 && s.outEnd
		if end {
			trailers = s.trailers
			r.dequeue(s)
			r.forgetIfDoneLocked(s)
		}
		serverID, clientID, streaming, clientEnded, maxFrame := s.serverID, s.clientID, s.streaming, s.clientEnded, r.maxFrame
		r.mu.Unlock()

		r.serverMu.Lock()
		var b []byte
		if len(chunk) > 0 || trailers == nil {
			flags := uint8(0)
			if end && trailers == nil {
				flags = FlagEndStream
			}
			b = AppendFrame(b, FrameData, flags, serverID, chunk)
		}
		if trailers != nil {
			b = append(b, encodeFrames(r.headerFramesLocked(serverID, trailers, nil, true, maxFrame))...)
		}
		_, err := r.server.Write(b)
		r.serverMu.Unlock()
		if err != nil {
			return err
		}
		if streaming {
			if err := r.creditClient(clientID, len(chunk), !clientEnded); err != nil {
				return err
			}
		}
	}
}

// serverLoop reads the server's frames and sends them on to the client.
func (r *relay) serverLoop() error {
	// While a response header block is incomplete, the client write lock is
	// held so no other frame (a WINDOW_UPDATE, say) lands inside it.
	holding := false
	defer func() {
		if holding {
			r.clientMu.Unlock()
		}
	}()
	var block *stream // stream of the response header block in progress
	blockEnds := false
	sawPreface := false
	for {
		f, err := r.readServerFrame()
		if err != nil {
			return err
		}
		if block != nil && f.Type != FrameContinuation {
			return errors.New("server interrupted a header block")
		}
		if !sawPreface && (f.Type != FrameSettings || f.Flags&FlagAck != 0) {
			// RFC 9113 3.4: the server preface is a SETTINGS frame.
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
			// Credit for request bodies, which the relay sends itself.
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
		case FrameHeaders, FrameContinuation:
			var s *stream
			if f.Type == FrameContinuation {
				if block == nil || f.Stream != block.serverID {
					return errors.New("server sent CONTINUATION outside a header block")
				}
				s = block
			} else {
				r.mu.Lock()
				s = r.serverStreamLocked(f.Stream)
				r.mu.Unlock()
				if s == nil {
					return fmt.Errorf("server sent headers on unknown stream %d", f.Stream)
				}
				blockEnds = f.Flags&FlagEndStream != 0
			}
			f.Stream = s.clientID
			if !holding {
				r.clientMu.Lock()
				holding = true
			}
			_, err = r.client.Write(encodeFrames([]Frame{f}))
			if f.Flags&FlagEndHeaders == 0 {
				block = s
				break
			}
			block = nil
			r.clientMu.Unlock()
			holding = false
			if blockEnds {
				r.serverEnded(s, false)
			}
		case FrameData, FrameRSTStream, FramePriority:
			r.mu.Lock()
			s := r.serverStreamLocked(f.Stream)
			r.mu.Unlock()
			if s == nil {
				if f.Type == FrameData && len(f.Payload) > 0 {
					// Keep the server's connection window intact.
					err = r.writeServer(windowUpdate(0, len(f.Payload)))
				}
				break
			}
			f.Stream = s.clientID
			err = r.writeClient(f)
			if f.Type == FrameRSTStream {
				r.serverEnded(s, true)
			} else if f.Type == FrameData && f.Flags&FlagEndStream != 0 {
				r.serverEnded(s, false)
			}
		case FramePushPromise:
			return errors.New("server sent PUSH_PROMISE, which this proxy does not support")
		case FrameGoAway:
			err = r.onServerGoAway(f)
		default:
			err = r.writeClient(f)
		}
		if err != nil {
			return err
		}
	}
}

// readServerFrame reads the server's next frame. One longer than the client
// allowed is a connection error: the server gets GOAWAY with
// FRAME_SIZE_ERROR when it can, and the relay ends.
func (r *relay) readServerFrame() (Frame, error) {
	f, err := readFrame(r.server, r.serverFrames.size)
	if errors.Is(err, ErrFrameSize) {
		r.goAwayServer(errCodeFrameSize)
		return Frame{}, fmt.Errorf("server: %w", err)
	}
	return f, err
}

// goAwayWait bounds how long the relay waits to tell the server with GOAWAY
// that the connection ends, lock and write included.
const goAwayWait = time.Second

// goAwayServer tells the server with GOAWAY that the connection ends for
// code, waiting at most goAwayWait: a write to a server that stopped reading
// (an upload) may hold serverMu, and must not keep the relay from ending.
// Other writes hold serverMu only briefly, so the GOAWAY still goes out
// after them. The relay closes the connection either way, which ends a
// write still waiting.
func (r *relay) goAwayServer(code uint32) {
	// Last stream 0: the relay accepts no stream the server opens.
	payload := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), code)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.serverMu.Lock()
		defer r.serverMu.Unlock()
		_ = r.server.SetWriteDeadline(time.Now().Add(goAwayWait))
		_, _ = r.server.Write(encodeFrames([]Frame{{Type: FrameGoAway, Payload: payload}}))
	}()
	select {
	case <-done:
	case <-time.After(goAwayWait):
	}
}

// serverStreamLocked finds the stream for a server stream ID: an open one,
// or one the client reset recently, whose late frames still go to the client
// (which ignores them, after decoding any header block).
func (r *relay) serverStreamLocked(serverID uint32) *stream {
	if s := r.byServer[serverID]; s != nil {
		return s
	}
	if clientID, ok := r.resetIDs[serverID]; ok {
		return &stream{clientID: clientID, serverID: serverID, sentEnd: true}
	}
	return nil
}

// serverEnded records that the server will send nothing more on a stream.
//
// A response can end while the request is still uploading (RFC 9113 8.1):
// the mapping then stays until the upload ends too, so the server's
// WINDOW_UPDATEs keep reaching it. A reset ends both directions at once.
func (r *relay) serverEnded(s *stream, reset bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.serverEnded = true
	delete(r.resetIDs, s.serverID)
	if reset {
		r.forgetServerLocked(s)
		if r.streams[s.clientID] == s {
			r.dropLocked(s)
		}
		return
	}
	r.forgetIfDoneLocked(s)
}

// onServerGoAway passes the server's GOAWAY on. Requests the server will not
// process (still buffering here, or above its last stream ID) are refused
// with REFUSED_STREAM so the client can retry them elsewhere, and the
// relay sends no new request upstream afterwards.
func (r *relay) onServerGoAway(f Frame) error {
	if len(f.Payload) < 8 {
		return errors.New("server sent a bad GOAWAY")
	}
	last := binary.BigEndian.Uint32(f.Payload) & 0x7fffffff
	var refused []Frame
	translated := uint32(0)
	r.mu.Lock()
	r.goaway = true
	for _, s := range r.streams {
		if s.serverID == 0 || s.serverID > last {
			refused = append(refused, refusal(s.clientID))
			r.dropLocked(s)
			if s.serverID != 0 {
				r.forgetServerLocked(s)
			}
			continue
		}
		translated = max(translated, s.clientID)
	}
	r.mu.Unlock()
	if len(refused) > 0 {
		r.opts.Logger.Warn("server is going away, refusing requests it will not process", "streams", len(refused))
	}
	f.Payload = append(binary.BigEndian.AppendUint32(nil, translated), f.Payload[4:]...)
	return r.writeClient(append(refused, f)...)
}

// bufferWindow is the receive window a buffered upload gets from the relay,
// which holds its body until the client ends it: it cannot be the server's,
// which may be 0 and which the server cannot raise before it has the
// request's headers. Each buffered byte is credited back on arrival, and the
// connection budget (MaxBuffered) still bounds what is held.
func (r *relay) bufferWindow() int64 {
	return min(int64(defaultWindow), int64(r.opts.MaxBody))
}

// topUpBufferingLocked raises every buffering stream's window to
// bufferWindow and returns the WINDOW_UPDATE frames to send the client.
func (r *relay) topUpBufferingLocked() []Frame {
	var frames []Frame
	want := r.bufferWindow()
	for _, st := range r.streams {
		if st.buffering && !st.clientEnded && st.recvWindow < want {
			grant := want - st.recvWindow
			st.recvWindow += grant
			frames = append(frames, windowUpdate(st.clientID, int(grant)))
		}
	}
	return frames
}

// setClientInitialLocked changes the initial stream window the client uses,
// adjusting every open stream by the difference (RFC 9113 6.9.2).
func (r *relay) setClientInitialLocked(v int64) {
	delta := v - r.clientInitial
	r.clientInitial = v
	for _, st := range r.streams {
		st.recvWindow += delta
	}
}

// possibleInitialLocked is the largest initial window the client may be
// using: its acknowledged value, or the value after any prefix of the
// SETTINGS frames it has not acknowledged yet.
func (r *relay) possibleInitialLocked() int64 {
	if r.settingsOverflow {
		return r.maxInitialSent
	}
	state, largest := r.ackedInitial, r.ackedInitial
	for _, v := range r.unackedInitial {
		if v >= 0 {
			state = v
		}
		largest = max(largest, state)
	}
	return largest
}

// applyClientAck records that the client acknowledged the oldest server
// SETTINGS it was sent: it now uses that frame's initial window, up or down.
// Buffering streams a decrease leaves short are topped up again.
func (r *relay) applyClientAck() error {
	r.mu.Lock()
	if len(r.unackedInitial) == 0 {
		r.mu.Unlock()
		return nil
	}
	if v := r.unackedInitial[0]; v >= 0 {
		r.ackedInitial = v
	}
	r.unackedInitial = r.unackedInitial[1:]
	r.setClientInitialLocked(r.possibleInitialLocked())
	topUp := r.topUpBufferingLocked()
	r.mu.Unlock()
	if len(topUp) == 0 {
		return nil
	}
	return r.writeClient(topUp...)
}

// clientSettings is the server's SETTINGS payload as the client receives it:
// unchanged except that SETTINGS_HEADER_TABLE_SIZE is lowered to what the
// relay's request decoder accepts. That value only bounds the client's own
// HPACK encoder, whose output the relay decodes and encodes again, so the
// server sees no difference.
func clientSettings(payload []byte) []byte {
	out := append([]byte{}, payload...)
	for i := 0; i+6 <= len(out); i += 6 {
		if binary.BigEndian.Uint16(out[i:]) == SettingHeaderTableSize && binary.BigEndian.Uint32(out[i+2:]) > decoderTableSize {
			binary.BigEndian.PutUint32(out[i+2:], decoderTableSize)
		}
	}
	return out
}

func (r *relay) onServerSettings(payload []byte) error {
	settings, err := ParseSettings(payload)
	if err != nil {
		return err
	}
	// Before the client can read the frame, so its frames sized to the new
	// value are let through.
	r.clientFrames.sent(payload)
	initial := int64(-1)
	for _, s := range settings {
		if s.ID == SettingInitialWindowSize {
			initial = int64(s.Value)
		}
	}
	r.mu.Lock()
	r.unackedInitial = append(r.unackedInitial, initial)
	r.maxInitialSent = max(r.maxInitialSent, initial)
	if len(r.unackedInitial) > maxUnackedSettings {
		r.unackedInitial = r.unackedInitial[1:]
		r.settingsOverflow = true
	}
	r.setClientInitialLocked(r.possibleInitialLocked())
	topUp := r.topUpBufferingLocked()
	r.mu.Unlock()
	if len(topUp) > 0 {
		if err := r.writeClient(topUp...); err != nil {
			return err
		}
	}
	for _, s := range settings {
		switch s.ID {
		case SettingHeaderTableSize:
			r.serverMu.Lock()
			r.enc.SetMaxDynamicTableSizeLimit(s.Value)
			r.serverMu.Unlock()
		case SettingInitialWindowSize:
			if s.Value > 1<<31-1 {
				return errors.New("server sent an invalid initial window size")
			}
			r.mu.Lock()
			delta := int64(s.Value) - r.initialWindow
			r.initialWindow = int64(s.Value)
			for _, st := range r.byServer {
				st.window += delta
			}

			r.cond.Broadcast()
			r.mu.Unlock()
		case SettingMaxConcurrentStreams:
			r.mu.Lock()
			r.maxConcurrent = int64(s.Value)
			r.cond.Broadcast()
			r.mu.Unlock()
		case SettingMaxFrameSize:
			if s.Value < defaultMaxFrame || s.Value > maxFrameLength {
				return errors.New("server sent an invalid max frame size")
			}
			r.mu.Lock()
			r.maxFrame = int(s.Value)
			r.mu.Unlock()
		}
	}
	return nil
}
