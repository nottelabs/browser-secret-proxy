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
// pass through untouched even with a value on record in them. Any 2xx
// accepts it, 204 included, which elsewhere has no content.
func TestExtendedConnectTunnelIsNotMasked(t *testing.T) {
	for _, code := range []string{"200", "204"} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t, masking(t, false))
			c := newClientView(h)
			h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1,
				Payload: h.clientBlock(request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})...)})
			id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
			h.serverSend(status(h, id, false, field(":status", code)))
			if head := c.readHead(1); head[":status"] != code {
				t.Fatalf("head %v", head)
			}
			frame := "\x81\x19" + realToken // a WebSocket text frame holding the value
			h.serverSend(data(id, frame, false))
			f := h.expect(h.toClient, "client", isType(FrameData))
			if string(f.Payload) != frame {
				t.Fatalf("client got %q, want the frame untouched", f.Payload)
			}
		})
	}
}

// Content on a bodiless response is reset even when it ends the server's
// stream while the request is still open (an extended CONNECT answered
// 304): the client stops sending once reset, so the request ends too, the
// server's stream is reset, and the stream gives back its slot.
func TestBodilessResetEndsARequestStillOpen(t *testing.T) {
	h := newHarness(t, masking(t, true))
	c := newClientView(h)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1,
		Payload: h.clientBlock(request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(status(h, id, false, field(":status", "304")), data(id, "card "+realCard, true))
	if resp := c.read(1, true); !resp.resetSeen || bytes.Contains(resp.body, []byte(realCard)) {
		t.Fatalf("reset %v, body %q", resp.resetSeen, resp.body)
	}
	if f := h.expect(h.toServer, "server", isType(FrameRSTStream)); f.Stream != id {
		t.Fatalf("server got RST_STREAM on %d, want %d", f.Stream, id)
	}
	if streams, byServer, _ := h.state(); streams != 0 || byServer != 0 {
		t.Fatalf("%d streams, %d server mappings left", streams, byServer)
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

// respReleased waits until the relay keeps no response state for stream and
// holds no response bytes.
func (h *harness) respReleased(stream uint32) {
	h.t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		h.r.mu.Lock()
		_, kept := h.r.resp[stream]
		held := h.r.respHeld
		h.r.mu.Unlock()
		if !kept && held == 0 {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("stream %d: response state kept %v, %d response bytes held", stream, kept, held)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// openMaskedResponse opens a masked response on stream 1 whose output waits
// for a client that granted no window, and returns its server stream ID.
func openMaskedResponse(t *testing.T, h *harness, method string, extra ...hpack.HeaderField) uint32 {
	t.Helper()
	h.clientSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}))
	h.expect(h.toServer, "server", isType(FrameSettings))
	flags := FlagEndHeaders | FlagEndStream
	if method == "CONNECT" {
		flags = FlagEndHeaders
	}
	h.clientSend(Frame{Type: FrameHeaders, Flags: flags, Stream: 1, Payload: h.clientBlock(request(method, extra...)...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(status(h, id, false, field(":status", "200")), data(id, "t="+realToken, false))
	c := newClientView(h)
	c.readHead(1)
	deadline := time.Now().Add(waitFor)
	for {
		h.r.mu.Lock()
		held := h.r.respHeld
		h.r.mu.Unlock()
		if held > 0 {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatal("no response output waits for the client")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// noMoreData grants the client window and checks no response DATA for
// stream reaches the client, even with more from the server.
func noMoreData(h *harness, stream, serverID uint32) {
	h.t.Helper()
	h.clientSend(windowUpdate(stream, 1<<16), windowUpdate(0, 1<<16))
	h.serverSend(data(serverID, "more "+realToken, true))
	h.quiet(h.toClient, 100*time.Millisecond, func(f Frame) bool { return f.Type == FrameData && f.Stream == stream })
}

// A stream the client resets by sending on it after its END_STREAM, while
// its masked response waits, releases that response: no more of it reaches
// the client, and its queued bytes and masking worker are released.
func TestEndedStreamReleasesItsResponse(t *testing.T) {
	h := newHarness(t, masking(t, false))
	id := openMaskedResponse(t, h, "GET")
	h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1})
	h.expect(h.toClient, "client", func(f Frame) bool {
		return f.Type == FrameRSTStream && f.Stream == 1 && binary.BigEndian.Uint32(f.Payload) == errCodeStreamClosed
	})
	h.expect(h.toServer, "server", func(f Frame) bool { return f.Type == FrameRSTStream && f.Stream == id })
	h.respReleased(1)
	noMoreData(h, 1, id)
}

// The server's GOAWAY refusing a stream it was sent releases that stream's
// waiting response too.
func TestGoAwayReleasesARefusedStreamsResponse(t *testing.T) {
	h := newHarness(t, masking(t, false))
	id := openMaskedResponse(t, h, "GET")
	h.serverSend(Frame{Type: FrameGoAway, Payload: make([]byte, 8)}) // last stream 0
	h.expect(h.toClient, "client", isRefusal(1))
	h.respReleased(1)
	noMoreData(h, 1, id)
}

// A stream reset by the relay (abort: a streamed upload over the buffer
// limit) releases its waiting response.
func TestAbortReleasesItsResponse(t *testing.T) {
	h := newHarness(t, func(o *Options) { masking(t, false)(o); o.MaxBuffered = 1000 })
	id := openMaskedResponse(t, h, "CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"})
	h.clientSend(Frame{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("u"), 2000)})
	h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameRSTStream && f.Stream == 1 })
	h.respReleased(1)
	noMoreData(h, 1, id)
}
