package h2relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// connCredit sums the connection WINDOW_UPDATEs the server gets within d.
func (h *harness) connCredit(d time.Duration) int {
	h.t.Helper()
	total := 0
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-h.toServer:
			if !ok {
				return total
			}
			if f.Type == FrameWindowUpdate && f.Stream == 0 {
				total += int(binary.BigEndian.Uint32(f.Payload))
			}
		case <-deadline:
			return total
		}
	}
}

// A passthrough response waiting behind masked output that the client
// cancels gives its connection credit back to the server at once: the
// client never gets those bytes, so it never credits them, and other
// streams would stall.
func TestCancelledWaitingResponseReturnsCredit(t *testing.T) {
	var session *scope.Session
	h := newHarness(t, func(o *Options) {
		r, _ := resolve.NewStatic(map[string]string{tokenSIn: realToken})
		session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{}, "allowed.test")
		o.Session = session
	})
	c := newClientView(h)
	passthrough := get(h, 3)
	h.serverSend(status(h, passthrough, false, field(":status", "200")))
	c.readHead(3)
	if _, err := session.Swapper(context.Background(), swap.Part{Text: tokenSIn}); err != nil {
		t.Fatal(err)
	}
	masked := get(h, 5)
	body := compressed(t, "gzip", bytes.Repeat([]byte(realToken+"\n"), 6000))
	h.serverSend(status(h, masked, false, field(":status", "200"), field("content-encoding", "gzip")), data(masked, string(body), true))
	for got := 0; got < defaultWindow; {
		if f := h.next(h.toClient, "client"); f.Type == FrameData {
			got += len(f.Payload)
		} else if f.Type == FrameHeaders {
			_, _ = c.dec.DecodeFull(f.Payload)
		}
	}
	// The passthrough DATA has to wait: the client's window is used up.
	waiting := bytes.Repeat([]byte("p"), 5000)
	h.serverSend(data(passthrough, string(waiting), false))
	h.quiet(h.toClient, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameData })
	h.connCredit(50 * time.Millisecond) // drop earlier credit (masked input)
	h.clientSend(rstStream(3, errCodeCancel))
	if got := h.connCredit(300 * time.Millisecond); got < len(waiting) {
		t.Fatalf("server got %d bytes of connection credit back, want at least %d", got, len(waiting))
	}
}

// An accepted extended CONNECT (a WebSocket) carries frames, not a body: they
// pass through untouched even with a value on record in them.
func TestExtendedConnectTunnelIsNotMasked(t *testing.T) {
	h := newHarness(t, masking(t, false))
	c := newClientView(h)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1,
		Payload: h.clientBlock(request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(status(h, id, false, field(":status", "200")))
	if head := c.readHead(1); head[":status"] != "200" {
		t.Fatalf("head %v", head)
	}
	frame := "\x81\x19" + realToken // a WebSocket text frame holding the value
	h.serverSend(data(id, frame, false))
	f := h.expect(h.toClient, "client", isType(FrameData))
	if string(f.Payload) != frame {
		t.Fatalf("client got %q, want the frame untouched", f.Payload)
	}
}

// Responses whose output still waits for the client count toward
// MaxStreams after the server ended them: a client withholding its window
// cannot pile them up.
func TestWaitingResponsesCountTowardTheStreamLimit(t *testing.T) {
	h := newHarness(t, func(o *Options) { masking(t, false)(o); o.MaxStreams = 2 })
	// The client allows no response data on new streams.
	h.clientSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}))
	h.expect(h.toServer, "server", isType(FrameSettings))
	c := newClientView(h)
	for _, stream := range []uint32{1, 3} {
		id := get(h, stream)
		h.serverSend(status(h, id, false, field(":status", "200")), data(id, "t="+realToken, true))
		c.readHead(stream)
	}
	// Both ended upstream; their masked bodies wait for a window that never
	// comes. A third stream is over the limit.
	time.Sleep(50 * time.Millisecond)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 5, Payload: h.clientBlock(request("GET")...)})
	h.expect(h.toClient, "client", isRefusal(5))
	// Once the client takes them, new streams are accepted again.
	h.clientSend(windowUpdate(1, 1<<16), windowUpdate(3, 1<<16))
	c.windows[1], c.windows[3] = 1<<16, 1<<16
	c.read(1, false)
	c.read(3, false)
	time.Sleep(50 * time.Millisecond)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 7, Payload: h.clientBlock(request("GET")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
}

// A masked response that shrinks (long real values, short stand-ins) and
// crosses debtReturn, completing alongside another stream: the server gets
// back exactly the connection credit for what it sent, never twice, so the
// relay owes nothing afterwards and the other stream is not held back.
func TestShrinkingResponseCreditsTheServerOnce(t *testing.T) {
	h := newHarness(t, masking(t, false))
	c := newClientView(h)
	credit := 0
	count := func(f Frame) {
		if f.Type == FrameWindowUpdate && f.Stream == 0 {
			credit += int(binary.BigEndian.Uint32(f.Payload))
		}
	}
	expectHeaders := func() Frame {
		for {
			f := h.next(h.toServer, "server")
			count(f)
			if f.Type == FrameHeaders {
				return f
			}
		}
	}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)})
	first := expectHeaders().Stream
	sent := 0
	chunk := bytes.Repeat([]byte(realToken+"\n"), 600) // 15,600 bytes, masked to 7,200
	h.serverSend(status(h, first, false, field(":status", "200")))
	for i := 0; i < 4; i++ {
		h.serverSend(data(first, string(chunk), i == 3))
		sent += len(chunk)
	}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(request("GET")...)})
	second := expectHeaders().Stream
	h.serverSend(status(h, second, false, field(":status", "200")), data(second, "hello, nothing to mask", true))
	sent += len("hello, nothing to mask")
	if got := c.read(1, true); len(got.body) != 4*600*(len(tokenSIn)+1) {
		t.Fatalf("first stream got %d bytes", len(got.body))
	}
	if got := c.read(3, true); string(got.body) != "hello, nothing to mask" {
		t.Fatalf("second stream got %q", got.body)
	}
	deadline := time.After(300 * time.Millisecond)
	for done := false; !done; {
		select {
		case f := <-h.toServer:
			count(f)
		case <-deadline:
			done = true
		}
	}
	if credit != sent {
		t.Fatalf("the server got %d bytes of connection credit for %d sent", credit, sent)
	}
	h.r.mu.Lock()
	debt := h.r.debt
	h.r.mu.Unlock()
	if debt != 0 {
		t.Fatalf("the relay still withholds %d bytes", debt)
	}
}

// A refused extended CONNECT (a WebSocket handshake answered 403) has an
// ordinary body: an echoed value in it is masked.
func TestRefusedConnectBodyIsMasked(t *testing.T) {
	h := newHarness(t, masking(t, false))
	c := newClientView(h)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1,
		Payload: h.clientBlock(request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(status(h, id, false, field(":status", "403"), field("content-type", "text/plain")), data(id, "denied for "+realToken, true))
	resp := c.read(1, true)
	if string(resp.body) != "denied for "+tokenSIn {
		t.Fatalf("client got %q", resp.body)
	}
}

// A refused extended CONNECT's compressed body is decoded and masked like any
// other body, and its content-encoding dropped only because it was decoded.
func TestRefusedConnectCompressedBodyIsDecodedAndMasked(t *testing.T) {
	h := newHarness(t, masking(t, false))
	c := newClientView(h)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1,
		Payload: h.clientBlock(request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	body := compressed(t, "gzip", []byte("denied for "+realToken))
	h.serverSend(status(h, id, false, field(":status", "403"), field("content-encoding", "gzip")), data(id, string(body), true))
	resp := c.read(1, true)
	if string(resp.body) != "denied for "+tokenSIn || resp.head["content-encoding"] != "" {
		t.Fatalf("client got %v %q", resp.head, resp.body)
	}
}

// transfer-encoding is malformed in HTTP/2 and a coding the masker would not
// see: a response carrying it is refused.
func TestTransferEncodingFieldIsRefused(t *testing.T) {
	h := newHarness(t, masking(t, false))
	id := get(h, 1)
	h.serverSend(status(h, id, false, field(":status", "200"), field("transfer-encoding", "gzip")))
	h.expect(h.toClient, "client", isBadGateway(1))
}
