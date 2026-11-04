package h2relay

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

const (
	realCard  = "4111111111111111"
	cardSIn   = "4242424242424242" // same length
	realToken = "sk_live_real_secret_value"
	tokenSIn  = "tok_standin" // shorter
)

// masking turns masking on with values on record: the card only, whose
// stand-in keeps its length, or the card and the token.
func masking(t *testing.T, sameLength bool) func(*Options) {
	return func(o *Options) {
		values := map[string]string{cardSIn: realCard}
		if !sameLength {
			values[tokenSIn] = realToken
		}
		r, err := resolve.NewStatic(values)
		if err != nil {
			t.Fatal(err)
		}
		known := ""
		for k := range values {
			known += k + " "
		}
		o.Session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{ID: "alice"}, "allowed.test", known)
	}
}

// clientView decodes what the client receives, as a client would: one HPACK
// decoder for the connection, and flow-control windows it enforces.
type clientView struct {
	h          *harness
	dec        *hpack.Decoder
	connWindow int64
	windows    map[uint32]int64
	streams    map[uint32]*response // responses being received, by stream
	block      []byte               // header block in progress
	blockEnds  bool
}

func newClientView(h *harness) *clientView {
	return &clientView{h: h, dec: hpack.NewDecoder(4096, nil), connWindow: defaultWindow, windows: map[uint32]int64{}, streams: map[uint32]*response{}}
}

// response is one stream's response as the client saw it.
type response struct {
	head, trailers map[string]string
	headNames      []string
	body           []byte
	reset          uint32 // RST_STREAM error code, or 0
	resetSeen      bool
	ended          bool
}

// readHead returns the next response head on stream.
func (c *clientView) readHead(stream uint32) map[string]string {
	c.h.t.Helper()
	for {
		f := c.h.next(c.h.toClient, "client")
		if f.Type != FrameHeaders {
			continue
		}
		fields, err := c.dec.DecodeFull(f.Payload)
		if err != nil {
			c.h.t.Fatal(err)
		}
		if f.Stream == stream {
			m := map[string]string{}
			for _, field := range fields {
				m[field.Name] = field.Value
			}
			return m
		}
	}
}

// read collects the response on stream until it ends, crediting the relay
// for what it consumed when credit is true, and failing if the relay sends
// more than the windows allow.
func (c *clientView) read(stream uint32, credit bool) *response {
	c.h.t.Helper()
	for {
		if r := c.streams[stream]; r != nil && r.ended {
			delete(c.streams, stream)
			return r
		}
		c.step(credit)
	}
}

// step takes one frame the client receives and adds it to its stream's
// response, crediting DATA when credit is true and failing if the relay
// sends past the client's windows.
func (c *clientView) step(credit bool) {
	c.h.t.Helper()
	f := c.h.next(c.h.toClient, "client")
	resp := c.streams[f.Stream]
	if resp == nil && f.Stream != 0 {
		resp = &response{}
		c.streams[f.Stream] = resp
	}
	switch f.Type {
	case FrameHeaders, FrameContinuation:
		if f.Type == FrameHeaders {
			_, fragment, err := HeadersPayload(f.Flags, f.Payload)
			if err != nil {
				c.h.t.Fatal(err)
			}
			c.block = append(c.block[:0], fragment...)
			c.blockEnds = f.Flags&FlagEndStream != 0
		} else {
			c.block = append(c.block, f.Payload...)
		}
		if f.Flags&FlagEndHeaders == 0 {
			return
		}
		fields, err := c.dec.DecodeFull(c.block)
		if err != nil {
			c.h.t.Fatalf("client cannot decode a header block: %v", err)
		}
		m := map[string]string{}
		var names []string
		for _, field := range fields {
			m[field.Name] = field.Value
			names = append(names, field.Name)
		}
		if resp.head == nil && !strings.HasPrefix(m[":status"], "1") {
			resp.head, resp.headNames = m, names
		} else if resp.head != nil {
			resp.trailers = m
		}
		resp.ended = resp.ended || c.blockEnds
	case FrameData:
		if _, ok := c.windows[f.Stream]; !ok {
			c.windows[f.Stream] = defaultWindow
		}
		n := int64(len(f.Payload))
		c.connWindow -= n
		c.windows[f.Stream] -= n
		if c.connWindow < 0 || c.windows[f.Stream] < 0 {
			c.h.t.Fatalf("relay sent past the client's window: connection %d, stream %d", c.connWindow, c.windows[f.Stream])
		}
		resp.body = append(resp.body, f.Payload...)
		if credit && n > 0 {
			c.connWindow += n
			c.windows[f.Stream] += n
			c.h.clientSend(windowUpdate(0, int(n)), windowUpdate(f.Stream, int(n)))
		}
		resp.ended = resp.ended || f.Flags&FlagEndStream != 0
	case FrameRSTStream:
		resp.reset, resp.resetSeen, resp.ended = binary.BigEndian.Uint32(f.Payload), true, true
	}
}

func get(h *harness, stream uint32) uint32 {
	h.t.Helper()
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: stream, Payload: h.clientBlock(request("GET")...)})
	return h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
}

func status(h *harness, serverID uint32, end bool, fields ...hpack.HeaderField) Frame {
	flags := FlagEndHeaders
	if end {
		flags |= FlagEndStream
	}
	return Frame{Type: FrameHeaders, Flags: flags, Stream: serverID, Payload: h.serverBlock(fields...)}
}

func field(name, value string) hpack.HeaderField { return hpack.HeaderField{Name: name, Value: value} }

func data(stream uint32, payload string, end bool) Frame {
	f := Frame{Type: FrameData, Stream: stream, Payload: []byte(payload)}
	if end {
		f.Flags = FlagEndStream
	}
	return f
}

// Header values, a body split across DATA frames anywhere, and trailers are
// masked; a stand-in of the same length keeps the content-length.
func TestResponsesAreMasked(t *testing.T) {
	text := `{"card":"` + realCard + `","shown":"4111 1111 1111 1111"}`
	want := `{"card":"` + cardSIn + `","shown":"4242 4242 4242 4242"}`
	for split := 1; split < len(text); split += 3 {
		h := newHarness(t, masking(t, true))
		c := newClientView(h)
		id := get(h, 1)
		h.serverSend(
			status(h, id, false, field(":status", "302"), field("location", "/done?c="+realCard),
				field("set-cookie", "c="+realCard), field("content-length", strconv.Itoa(len(text)))),
			data(id, text[:split], false), data(id, text[split:], false),
			status(h, id, true, field("x-sum", realCard)),
		)
		resp := c.read(1, false)
		if string(resp.body) != want {
			t.Fatalf("split %d: body %q", split, resp.body)
		}
		if resp.head["location"] != "/done?c="+cardSIn || resp.head["set-cookie"] != "c="+cardSIn || resp.head["content-length"] != strconv.Itoa(len(text)) {
			t.Fatalf("head %v", resp.head)
		}
		if resp.trailers["x-sum"] != cardSIn {
			t.Fatalf("trailers %v", resp.trailers)
		}
	}
}

// A stand-in of another length drops the content-length.
func TestLengthChangingMaskDropsContentLength(t *testing.T) {
	h := newHarness(t, masking(t, false))
	c := newClientView(h)
	id := get(h, 1)
	body := "t=" + realToken
	h.serverSend(status(h, id, false, field(":status", "200"), field("content-length", strconv.Itoa(len(body)))), data(id, body, true))
	resp := c.read(1, false)
	if string(resp.body) != "t="+tokenSIn || resp.head["content-length"] != "" {
		t.Fatalf("head %v, body %q", resp.head, resp.body)
	}
}

func compressed(t *testing.T, coding string, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "deflate":
		w = zlib.NewWriter(&b)
	case "br":
		w = brotli.NewWriter(&b)
	case "zstd":
		w, _ = zstd.NewWriter(&b)
	}
	_, _ = w.Write(plain)
	_ = w.Close()
	return b.Bytes()
}

// A compressed body is decoded, masked and sent without its coding, within
// the client's windows although it is much larger than what the server sent;
// the client's stream WINDOW_UPDATEs stay with the relay (which credits the
// server for what it consumed), and the server gets back exactly the
// connection credit for what it sent.
func TestCompressedResponsesAreDecodedWithinTheClientsWindows(t *testing.T) {
	plain := bytes.Repeat([]byte("row "+realCard+" "+realToken+"\n"), 20000) // about 900 KB
	want := strings.Repeat("row "+cardSIn+" "+tokenSIn+"\n", 20000)
	for _, coding := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(coding, func(t *testing.T) {
			h := newHarness(t, masking(t, false))
			c := newClientView(h)
			id := get(h, 1)
			body := compressed(t, coding, plain)
			if len(body) > 30000 {
				t.Fatalf("compressed body of %d bytes is too large for this test", len(body))
			}
			half := len(body) / 2
			h.serverSend(
				status(h, id, false, field(":status", "200"), field("content-encoding", coding), field("content-length", strconv.Itoa(len(body))), field("vary", "accept-encoding")),
				data(id, string(body[:half]), false), data(id, string(body[half:]), true),
			)
			resp := c.read(1, true)
			if string(resp.body) != want {
				t.Fatalf("client got %d bytes, want the %d masked ones", len(resp.body), len(want))
			}
			if resp.head["content-encoding"] != "" || resp.head["content-length"] != "" || resp.head["vary"] != "accept-encoding" {
				t.Fatalf("head %v", resp.head)
			}
			var forwarded, streamCredit int64
			deadline := time.After(300 * time.Millisecond)
			for done := false; !done; {
				select {
				case f := <-h.toServer:
					if f.Type == FrameWindowUpdate && f.Stream == 1 {
						// The relay's own credit for input it consumed.
						streamCredit += int64(binary.BigEndian.Uint32(f.Payload))
					}
					if f.Type == FrameWindowUpdate && f.Stream == 0 {
						forwarded += int64(binary.BigEndian.Uint32(f.Payload))
					}
				case <-deadline:
					done = true
				}
			}
			if streamCredit > int64(len(body)) {
				t.Fatalf("server got %d bytes of stream credit for %d sent: the client's WINDOW_UPDATEs reached it", streamCredit, len(body))
			}
			if forwarded != int64(len(body)) {
				t.Fatalf("server got %d bytes of connection credit, it sent %d", forwarded, len(body))
			}
		})
	}
}

// A passthrough response sharing the connection with a masked one never
// gets past the client's connection window either: masked output used it, so
// the passthrough frame waits for the client's next WINDOW_UPDATE.
func TestPassthroughWaitsForTheWindowMaskingUsed(t *testing.T) {
	var session *scope.Session
	h := newHarness(t, func(o *Options) {
		r, _ := resolve.NewStatic(map[string]string{tokenSIn: realToken})
		session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{}, "allowed.test")
		o.Session = session
	})
	c := newClientView(h)
	// Stream 3's head arrives before any value is on record: passthrough.
	passthrough := get(h, 3)
	h.serverSend(status(h, passthrough, false, field(":status", "200")))
	if resp := c.readHead(3); resp[":status"] != "200" {
		t.Fatalf("head %v", resp)
	}
	if _, err := session.Swapper(context.Background(), swap.Part{Text: tokenSIn}); err != nil {
		t.Fatal(err)
	}
	masked := get(h, 5)                                                       // client stream IDs only grow
	body := compressed(t, "gzip", bytes.Repeat([]byte(realToken+"\n"), 6000)) // 156 KB decoded
	h.serverSend(status(h, masked, false, field(":status", "200"), field("content-encoding", "gzip")), data(masked, string(body), true))
	got := 0
	for got < defaultWindow {
		f := h.next(h.toClient, "client")
		switch f.Type {
		case FrameData:
			got += len(f.Payload)
		case FrameHeaders:
			if _, err := c.dec.DecodeFull(f.Payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got != defaultWindow {
		t.Fatalf("relay sent %d bytes on a window of %d", got, defaultWindow)
	}
	h.serverSend(data(passthrough, "hello", true))
	h.quiet(h.toClient, 100*time.Millisecond, func(f Frame) bool { return f.Type == FrameData })
	h.clientSend(windowUpdate(0, 1<<20))
	c.connWindow = 1 << 20
	c.windows[5] = 0
	resp := c.read(3, false)
	if string(resp.body) != "hello" {
		t.Fatalf("passthrough stream got %q", resp.body)
	}
}

// Responses that cannot be masked get a 502 from the relay, and the server
// a CANCEL.
func TestUnmaskableResponsesAreRefused(t *testing.T) {
	cases := map[string][]hpack.HeaderField{
		"unknown coding":  {field(":status", "200"), field("content-encoding", "compress")},
		"stacked codings": {field(":status", "200"), field("content-encoding", "gzip, br")},
		"partial":         {field(":status", "206"), field("content-range", "bytes 0-3/9")},
		// Malformed in HTTP/2 (RFC 9113 8.2.1), and not recognized as the
		// content-encoding, so the body would pass undecoded.
		"upper-case name": {field(":status", "200"), field("Content-Encoding", "gzip")},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, masking(t, false))
			id := get(h, 1)
			h.serverSend(status(h, id, false, fields...))
			h.expect(h.toClient, "client", isBadGateway(1))
			f := h.expect(h.toServer, "server", isType(FrameRSTStream))
			if f.Stream != id || binary.BigEndian.Uint32(f.Payload) != errCodeCancel {
				t.Fatalf("server got RST_STREAM %d on %d", binary.BigEndian.Uint32(f.Payload), f.Stream)
			}
			// Frames in flight for the refused stream are absorbed.
			h.serverSend(data(id, "abcd", true))
			h.quiet(h.toClient, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameData })
		})
	}
}

// Partial responses are refused even when masking keeps every length:
// ranges masked one by one would let a client ask for the pieces of a value
// (bytes=0-7, then bytes=8-15) and put it back together.
func TestSameLengthPartialResponseIsRefused(t *testing.T) {
	h := newHarness(t, masking(t, true))
	id := get(h, 1)
	h.serverSend(status(h, id, false, field(":status", "206"), field("content-range", "bytes 0-7/16"), field("content-length", "8")))
	h.expect(h.toClient, "client", isBadGateway(1))
	h.serverSend(data(id, realCard[:8], true))
	h.quiet(h.toClient, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameData })
}

// Content on a response that cannot have any (HEAD, 204, 304) is malformed
// (RFC 9113 8.1.1): the stream is reset and the content not passed on. An
// empty DATA that ends such a stream is passed on.
func TestContentOnABodilessResponseIsReset(t *testing.T) {
	for _, c := range []struct{ method, status string }{{"HEAD", "200"}, {"GET", "204"}, {"GET", "304"}} {
		t.Run(c.method+" "+c.status, func(t *testing.T) {
			h := newHarness(t, masking(t, true))
			view := newClientView(h)
			h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request(c.method)...)})
			id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
			h.serverSend(status(h, id, false, field(":status", c.status)), data(id, "card "+realCard, false))
			resp := view.read(1, true)
			if !resp.resetSeen || bytes.Contains(resp.body, []byte(realCard)) {
				t.Fatalf("reset %v, body %q", resp.resetSeen, resp.body)
			}
			f := h.expect(h.toServer, "server", isType(FrameRSTStream))
			if f.Stream != id || binary.BigEndian.Uint32(f.Payload) != errCodeProtocol {
				t.Fatalf("server got RST_STREAM %d on %d", binary.BigEndian.Uint32(f.Payload), f.Stream)
			}
		})
	}
	h := newHarness(t, masking(t, true))
	view := newClientView(h)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("HEAD")...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(status(h, id, false, field(":status", "200"), field("content-length", "16")), data(id, "", true))
	if resp := view.read(1, true); resp.resetSeen || resp.head[":status"] != "200" {
		t.Fatalf("reset %v, head %v", resp.resetSeen, resp.head)
	}
}

// A compressed body decoding past the cap is reset; the client never sees a
// real value.
func TestOversizedDecodedResponseIsReset(t *testing.T) {
	h := newHarness(t, func(o *Options) { masking(t, false)(o); o.MaxDecoded = 32 << 10 })
	c := newClientView(h)
	id := get(h, 1)
	body := compressed(t, "gzip", bytes.Repeat([]byte(realToken+" "), 20000))
	h.serverSend(status(h, id, false, field(":status", "200"), field("content-encoding", "gzip")), data(id, string(body), true))
	resp := c.read(1, true)
	if !resp.resetSeen || resp.reset != errCodeInternal || bytes.Contains(resp.body, []byte(realToken)) {
		t.Fatalf("reset %v (%d), %d bytes", resp.resetSeen, resp.reset, len(resp.body))
	}
}

// With masking on and nothing on record, bodies pass unchanged and header
// blocks, re-encoded by the relay, decode to what the server sent, response
// after response.
func TestNothingOnRecordPassesThrough(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		r, _ := resolve.NewStatic(map[string]string{cardSIn: realCard})
		o.Session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{}, "allowed.test")
	})
	c := newClientView(h)
	for i := uint32(0); i < 5; i++ {
		id := get(h, 2*i+1)
		h.serverSend(
			status(h, id, false, field(":status", "200"), field("content-encoding", "gzip"), field("x-repeat", "same value"), field("content-length", "4")),
			data(id, realCard[:4], true),
		)
		resp := c.read(2*i+1, true)
		if string(resp.body) != realCard[:4] || resp.head["content-encoding"] != "gzip" || resp.head["x-repeat"] != "same value" {
			t.Fatalf("response %d: head %v, body %q", i, resp.head, resp.body)
		}
		if strings.Join(resp.headNames, ",") != ":status,content-encoding,x-repeat,content-length" {
			t.Fatalf("header order %v", resp.headNames)
		}
	}
}

// The client's first connection WINDOW_UPDATE, part of its fingerprint,
// reaches the server unchanged.
func TestFirstWindowUpdateIsForwardedUnchanged(t *testing.T) {
	h := newHarness(t, masking(t, false))
	h.clientSend(windowUpdate(0, 15663105))
	f := h.expect(h.toServer, "server", isType(FrameWindowUpdate))
	if f.Stream != 0 || binary.BigEndian.Uint32(f.Payload) != 15663105 {
		t.Fatalf("server got WINDOW_UPDATE %d on %d", binary.BigEndian.Uint32(f.Payload), f.Stream)
	}
}
