package h2relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/secret-proxy/internal/hostmatch"
	"github.com/nottelabs/secret-proxy/internal/swap"
)

const waitFor = 5 * time.Second

// harness runs a relay between a scripted client and a scripted server.
type harness struct {
	t              *testing.T
	r              *relay
	client, server net.Conn       // the test's ends
	toClient       chan Frame     // frames the relay sent the client
	toServer       chan Frame     // frames the relay sent the server
	done           chan error     // the relay's result
	clientEnc      *hpack.Encoder // the client's HPACK encoder
	clientEncBuf   *bytes.Buffer
	serverEnc      *hpack.Encoder // the server's HPACK encoder
	serverEncBuf   *bytes.Buffer
}

func newHarness(t *testing.T, mutate func(*Options)) *harness {
	return newHarnessWith(t, mutate, nil)
}

// newHarnessWith also lets setup adjust the relay before it starts.
func newHarnessWith(t *testing.T, mutate func(*Options), setup func(*relay)) *harness {
	t.Helper()
	hosts, err := hostmatch.New([]string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	swapper, err := swap.New(map[string]string{"tok_standin": "real_value"})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Hosts: hosts, Swapper: swapper}
	if mutate != nil {
		mutate(&opts)
	}
	clientTest, clientRelay := net.Pipe()
	serverRelay, serverTest := net.Pipe()
	h := &harness{
		t: t, client: clientTest, server: serverTest,
		toClient: make(chan Frame, 4096), toServer: make(chan Frame, 4096), done: make(chan error, 1),
		clientEncBuf: &bytes.Buffer{}, serverEncBuf: &bytes.Buffer{},
	}
	h.clientEnc = hpack.NewEncoder(h.clientEncBuf)
	h.serverEnc = hpack.NewEncoder(h.serverEncBuf)
	h.r = newRelay(clientRelay, serverRelay, opts)
	if setup != nil {
		setup(h.r)
	}
	go func() { h.done <- h.r.run() }()
	go func() {
		defer close(h.toServer)
		preface := make([]byte, len(Preface))
		if _, err := io.ReadFull(serverTest, preface); err != nil {
			return
		}
		for {
			f, err := ReadFrame(serverTest)
			if err != nil {
				return
			}
			h.toServer <- f
		}
	}()
	go func() {
		defer close(h.toClient)
		for {
			f, err := ReadFrame(clientTest)
			if err != nil {
				return
			}
			h.toClient <- f
		}
	}()
	t.Cleanup(func() {
		_ = clientTest.Close()
		_ = serverTest.Close()
		select {
		case <-h.done:
		case <-time.After(waitFor):
			t.Error("relay did not stop")
		}
	})
	h.write(h.client, []byte(Preface))
	return h
}

func (h *harness) write(conn net.Conn, b []byte) {
	h.t.Helper()
	_ = conn.SetWriteDeadline(time.Now().Add(waitFor))
	if _, err := conn.Write(b); err != nil {
		h.t.Fatalf("write: %v", err)
	}
}

func (h *harness) clientSend(frames ...Frame) { h.t.Helper(); h.write(h.client, encodeFrames(frames)) }
func (h *harness) serverSend(frames ...Frame) { h.t.Helper(); h.write(h.server, encodeFrames(frames)) }

func (h *harness) clientBlock(fields ...hpack.HeaderField) []byte {
	h.clientEncBuf.Reset()
	for _, f := range fields {
		_ = h.clientEnc.WriteField(f)
	}
	return append([]byte{}, h.clientEncBuf.Bytes()...)
}

func (h *harness) serverBlock(fields ...hpack.HeaderField) []byte {
	h.serverEncBuf.Reset()
	for _, f := range fields {
		_ = h.serverEnc.WriteField(f)
	}
	return append([]byte{}, h.serverEncBuf.Bytes()...)
}

func request(method string, extra ...hpack.HeaderField) []hpack.HeaderField {
	return append([]hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":authority", Value: "allowed.test"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
	}, extra...)
}

// next returns the next frame on ch, failing after a timeout.
func (h *harness) next(ch chan Frame, side string) Frame {
	h.t.Helper()
	select {
	case f, ok := <-ch:
		if !ok {
			h.t.Fatalf("%s connection closed", side)
		}
		return f
	case <-time.After(waitFor):
		h.t.Fatalf("no frame for the %s", side)
		return Frame{}
	}
}

// expect returns the first frame on ch that matches, dropping others.
func (h *harness) expect(ch chan Frame, side string, match func(Frame) bool) Frame {
	h.t.Helper()
	for {
		if f := h.next(ch, side); match(f) {
			return f
		}
	}
}

// quiet fails if a matching frame arrives on ch within d.
func (h *harness) quiet(ch chan Frame, d time.Duration, match func(Frame) bool) {
	h.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-ch:
			if ok && match(f) {
				h.t.Fatalf("unexpected frame type %d on stream %d", f.Type, f.Stream)
			}
		case <-deadline:
			return
		}
	}
}

func isType(t uint8) func(Frame) bool { return func(f Frame) bool { return f.Type == t } }
func isRefusal(stream uint32) func(Frame) bool {
	return func(f Frame) bool { return isRefused(f, stream) }
}

func isRefused(f Frame, stream uint32) bool {
	return f.Type == FrameRSTStream && f.Stream == stream && binary.BigEndian.Uint32(f.Payload) == errCodeRefusedStream
}

func (h *harness) result() error {
	h.t.Helper()
	select {
	case err := <-h.done:
		h.done <- err
		return err
	case <-time.After(waitFor):
		h.t.Fatal("relay did not stop")
		return nil
	}
}

func (h *harness) state() (streams, byServer int, held int64) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	return len(h.r.streams), len(h.r.byServer), h.r.held
}

// settle waits until the relay holds no stream, mapping or byte.
func (h *harness) settle(what string) {
	h.t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		streams, byServer, held := h.state()
		if streams == 0 && byServer == 0 && held == 0 {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("after %s the relay keeps %d streams, %d server mappings, %d bytes", what, streams, byServer, held)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func rstStream(stream uint32, code uint32) Frame {
	return Frame{Type: FrameRSTStream, Stream: stream, Payload: binary.BigEndian.AppendUint32(nil, code)}
}

// A header block that keeps growing through CONTINUATION frames is refused
// once it passes the limit, before the relay buffers more of it.
func TestClientHeaderBlockIsCapped(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxHeaderBytes = 4096 })
	chunk := bytes.Repeat([]byte{0x80}, 1000)
	h.clientSend(Frame{Type: FrameHeaders, Stream: 1, Payload: chunk})
	for i := 0; i < 3; i++ {
		h.clientSend(Frame{Type: FrameContinuation, Stream: 1, Payload: chunk})
	}
	// The fifth fragment passes 4096 bytes; the relay stops reading.
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = h.client.Write(encodeFrames([]Frame{{Type: FrameContinuation, Stream: 1, Payload: chunk}}))
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "header block is larger than 4096") {
		t.Fatalf("relay error %v", err)
	}
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
}

// A small block that expands through HPACK table references is refused by
// its decoded size.
func TestDecodedHeaderListIsCapped(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxHeaderBytes = 4096 })
	big := hpack.HeaderField{Name: "x-big", Value: strings.Repeat("v", 3000)}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET", big)...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	block := h.clientBlock(request("GET", big, big, big)...)
	if len(block) > 100 {
		t.Fatalf("the second block is %d bytes, the test needs table references", len(block))
	}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: block})
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "header list is larger than 4096") {
		t.Fatalf("relay error %v", err)
	}
}

// Streams past the limit are refused, not sent upstream.
func TestStreamLimitRefusesNewStreams(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxStreams = 2 })
	for _, id := range []uint32{1, 3, 5} {
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)})
	}
	h.expect(h.toClient, "client", isRefusal(5))
	for _, want := range []uint32{1, 3} {
		if f := h.expect(h.toServer, "server", isType(FrameHeaders)); f.Stream != want {
			t.Fatalf("server stream %d, want %d", f.Stream, want)
		}
	}
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
}

// Buffered bodies share one budget per connection: the stream that would
// pass it is refused, the others carry on, and nothing stays held.
func TestBufferedBodiesShareABudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 1000 })
	post := request("POST", hpack.HeaderField{Name: "content-type", Value: "application/json"})
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(post...)},
		Frame{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("a"), 600)},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(post...)},
		Frame{Type: FrameData, Stream: 3, Payload: bytes.Repeat([]byte("b"), 600)},
	)
	h.expect(h.toClient, "client", isRefusal(3))
	if _, _, held := h.state(); held != 600 {
		t.Fatalf("relay holds %d bytes, want the 600 of stream 1", held)
	}
	h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("tok_standin")})
	headers := h.expect(h.toServer, "server", isType(FrameHeaders))
	if headers.Stream != 1 {
		t.Fatalf("server got headers on stream %d", headers.Stream)
	}
	var body []byte
	for {
		f := h.expect(h.toServer, "server", isType(FrameData))
		body = append(body, f.Payload...)
		if f.Flags&FlagEndStream != 0 {
			break
		}
	}
	if want := strings.Repeat("a", 600) + "real_value"; string(body) != want {
		t.Fatalf("server body %q", body)
	}
	if _, _, held := h.state(); held != 0 {
		t.Fatalf("relay still holds %d bytes", held)
	}
}

// A response header block that ends the stream and continues in
// CONTINUATION frames is passed on whole, nothing lands inside it, and the
// connection stays usable.
func TestResponseHeaderBlockWithContinuation(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(request("POST")...)},
	)
	h.expect(h.toServer, "server", isType(FrameHeaders))

	block := h.serverBlock(hpack.HeaderField{Name: ":status", Value: "204"}, hpack.HeaderField{Name: "x-large", Value: strings.Repeat("z", 200)})
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndStream, Stream: 1, Payload: block[:50]})
	if f := h.next(h.toClient, "client"); f.Type != FrameHeaders || f.Stream != 1 {
		t.Fatalf("client got frame type %d on stream %d", f.Type, f.Stream)
	}
	// Upload data the relay wants to credit while the block is open.
	h.clientSend(Frame{Type: FrameData, Stream: 3, Payload: bytes.Repeat([]byte("u"), 500)})
	time.Sleep(100 * time.Millisecond)
	h.serverSend(Frame{Type: FrameContinuation, Flags: FlagEndHeaders, Stream: 1, Payload: block[50:]})
	if f := h.next(h.toClient, "client"); f.Type != FrameContinuation || f.Stream != 1 || f.Flags&FlagEndHeaders == 0 {
		t.Fatalf("after HEADERS the client got frame type %d on stream %d, want its CONTINUATION", f.Type, f.Stream)
	}
	h.expect(h.toClient, "client", isType(FrameWindowUpdate))

	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 5, Payload: h.clientBlock(request("GET")...)})
	if f := h.expect(h.toServer, "server", isType(FrameHeaders)); f.Stream != 3 {
		t.Fatalf("next request reached the server on stream %d, want 3", f.Stream)
	}
}

// After the server's GOAWAY, requests it will not process are refused so the
// client can retry them, and none is sent upstream afterwards.
func TestGoAwayRefusesUnsentRequests(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Stream: 1, Payload: []byte("partial")},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(request("GET")...)},
	)
	if f := h.expect(h.toServer, "server", isType(FrameHeaders)); f.Stream != 1 {
		t.Fatalf("GET went upstream on stream %d", f.Stream)
	}
	goaway := append(binary.BigEndian.AppendUint32(nil, 1), 0, 0, 0, 0)
	h.serverSend(Frame{Type: FrameGoAway, Payload: goaway})

	h.expect(h.toClient, "client", isRefusal(1))
	f := h.expect(h.toClient, "client", isType(FrameGoAway))
	if last := binary.BigEndian.Uint32(f.Payload); last != 3 {
		t.Fatalf("client GOAWAY last stream %d, want 3", last)
	}
	h.clientSend(
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("rest")},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 5, Payload: h.clientBlock(request("GET")...)},
	)
	h.expect(h.toClient, "client", isRefusal(5))
	h.quiet(h.toServer, 100*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
}

// Finished requests leave no state behind on a long-lived connection.
func TestCompletedStreamsAreForgotten(t *testing.T) {
	h := newHarness(t, nil)
	const requests = 200
	for i := 0; i < requests; i++ {
		id := uint32(2*i + 1)
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)})
		f := h.expect(h.toServer, "server", isType(FrameHeaders))
		h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: f.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
		if got := h.expect(h.toClient, "client", isType(FrameHeaders)); got.Stream != id {
			t.Fatalf("response on stream %d, want %d", got.Stream, id)
		}
	}
	// One POST with a body, finished on both sides.
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 2*requests + 1, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 2*requests + 1, Payload: []byte("body")},
	)
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	h.expect(h.toServer, "server", func(f Frame) bool { return f.Type == FrameData && f.Flags&FlagEndStream != 0 })
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: f.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	h.expect(h.toClient, "client", isType(FrameHeaders))

	h.settle("finished requests")

	// Requests the client resets and the server never answers.
	const resets = maxResetStreams + 100
	first := uint32(2*requests + 3)
	var lastServerID uint32
	for i := uint32(0); i < resets; i++ {
		id := first + 2*i
		h.clientSend(
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)},
			rstStream(id, 0x8), // CANCEL
		)
		lastServerID = h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
		h.expect(h.toServer, "server", isType(FrameRSTStream))
	}
	h.settle("client resets with no reply")
	h.r.mu.Lock()
	remembered := len(h.r.resetIDs)
	h.r.mu.Unlock()
	if remembered > maxResetStreams {
		t.Fatalf("relay remembers %d reset streams, limit %d", remembered, maxResetStreams)
	}
	// A late response on the newest reset stream still reaches its client
	// stream (keeping HPACK in step), and the connection keeps working.
	lastClientID := first + 2*(resets-1)
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: lastServerID, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	if got := h.expect(h.toClient, "client", isType(FrameHeaders)); got.Stream != lastClientID {
		t.Fatalf("late response on stream %d, want %d", got.Stream, lastClientID)
	}
	next := lastClientID + 2
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: next, Payload: h.clientBlock(request("GET")...)})
	f = h.expect(h.toServer, "server", isType(FrameHeaders))
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: f.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	if got := h.expect(h.toClient, "client", isType(FrameHeaders)); got.Stream != next {
		t.Fatalf("response on stream %d, want %d", got.Stream, next)
	}
	h.settle("the last request")
}

// Control frames for a stream still buffering are combined, not stored one
// by one: the server gets one summed WINDOW_UPDATE and the latest
// PRIORITY_UPDATE once the request goes upstream.
func TestPendingControlFramesAreCombined(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)})
	const updates = 3000
	var frames []Frame
	for i := 1; i <= updates; i++ {
		frames = append(frames, windowUpdate(1, 1))
		frames = append(frames, Frame{Type: FramePriorityUpdate, Payload: append(binary.BigEndian.AppendUint32(nil, 1), []byte("u="+string(rune('0'+i%8)))...)})
	}
	h.clientSend(frames...)
	h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("body")})

	windowUpdates, priorityUpdates := 0, 0
	var increment uint32
	var priority []byte
	h.expect(h.toServer, "server", isType(FrameHeaders))
	for {
		f := h.next(h.toServer, "server")
		switch f.Type {
		case FrameWindowUpdate:
			windowUpdates++
			increment = binary.BigEndian.Uint32(f.Payload)
		case FramePriorityUpdate:
			priorityUpdates++
			priority = f.Payload
		}
		if f.Type == FrameData && f.Flags&FlagEndStream != 0 {
			break
		}
	}
	if windowUpdates != 1 || increment != updates {
		t.Fatalf("server got %d WINDOW_UPDATE frames (last increment %d), want one of %d", windowUpdates, increment, updates)
	}
	if want := "u=" + string(rune('0'+updates%8)); priorityUpdates != 1 || string(priority[4:]) != want || binary.BigEndian.Uint32(priority) != 1 {
		t.Fatalf("server got %d PRIORITY_UPDATE frames, last %q, want one %q", priorityUpdates, priority, want)
	}
}

// The server resets a buffered request right after its headers went
// upstream, before its body is queued: the relay releases the body and keeps
// no state.
func TestUpstreamResetWhileFinishing(t *testing.T) {
	var h *harness
	h = newHarnessWith(t, nil, func(r *relay) {
		r.afterOpen = func(s *stream) {
			_ = h.server.SetWriteDeadline(time.Now().Add(waitFor))
			if _, err := h.server.Write(encodeFrames([]Frame{rstStream(s.serverID, 0x8)})); err != nil {
				t.Errorf("server reset: %v", err)
				return
			}
			deadline := time.Now().Add(waitFor)
			for {
				r.mu.Lock()
				gone := r.streams[s.clientID] != s
				r.mu.Unlock()
				if gone || time.Now().After(deadline) {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	})
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST", hpack.HeaderField{Name: "content-type", Value: "application/json"})...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte(`{"token":"tok_standin"}`)},
	)
	h.expect(h.toServer, "server", isType(FrameHeaders))
	h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameRSTStream && f.Stream == 1 })
	h.settle("an upstream reset while finishing")
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameData))
}

// An HTTP/2 upload with expect: 100-continue is approved by the relay before
// its body, and the injected 100 leaves the client's HPACK table intact.
func TestExpectContinueOverHTTP2(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST",
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
		hpack.HeaderField{Name: "expect", Value: "100-continue"})...)})

	clientDec := hpack.NewDecoder(4096, nil)
	f := h.expect(h.toClient, "client", isType(FrameHeaders))
	fields, err := clientDec.DecodeFull(f.Payload)
	if err != nil || f.Stream != 1 || len(fields) != 1 || fields[0].Name != ":status" || fields[0].Value != "100" || f.Flags&FlagEndStream != 0 {
		t.Fatalf("client got %v on stream %d (flags %#x), %v; want :status 100", fields, f.Stream, f.Flags, err)
	}
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))

	h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte(`{"token":"tok_standin"}`)})
	headers := h.expect(h.toServer, "server", isType(FrameHeaders))
	var body []byte
	for {
		d := h.expect(h.toServer, "server", isType(FrameData))
		body = append(body, d.Payload...)
		if d.Flags&FlagEndStream != 0 {
			break
		}
	}
	if string(body) != `{"token":"real_value"}` {
		t.Fatalf("server body %q", body)
	}
	// Two responses whose second one references the server encoder's table.
	custom := hpack.HeaderField{Name: "x-trace", Value: "abc"}
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: headers.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"}, custom)})
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(request("GET")...)})
	second := h.expect(h.toServer, "server", isType(FrameHeaders))
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: second.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"}, custom)})
	for _, stream := range []uint32{1, 3} {
		f := h.expect(h.toClient, "client", isType(FrameHeaders))
		fields, err := clientDec.DecodeFull(f.Payload)
		if err != nil || f.Stream != stream || len(fields) != 2 || fields[1] != custom {
			t.Fatalf("response on stream %d decoded to %v, %v", f.Stream, fields, err)
		}
	}
}

func settingsFrame(settings ...Setting) Frame {
	var payload []byte
	for _, s := range settings {
		payload = binary.BigEndian.AppendUint16(payload, s.ID)
		payload = binary.BigEndian.AppendUint32(payload, s.Value)
	}
	return Frame{Type: FrameSettings, Payload: payload}
}

// otherRequest is a request for a host that is not allowlisted: its body is
// streamed upstream, not buffered.
func otherRequest(method string) []hpack.HeaderField {
	fields := request(method)
	fields[1].Value = "other.test"
	return fields
}

func isGoAway(code uint32) func(Frame) bool {
	return func(f Frame) bool {
		return f.Type == FrameGoAway && len(f.Payload) >= 8 && binary.BigEndian.Uint32(f.Payload[4:]) == code
	}
}

// A client that sends more on a stream than its window allows ends the
// connection with FLOW_CONTROL_ERROR instead of growing the relay's queue.
func TestStreamWindowViolationClosesTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 100}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}) // the client now uses 100
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = h.client.Write(encodeFrames([]Frame{{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("x"), 200)}}))
	h.expect(h.toClient, "client", isGoAway(errCodeFlowControl))
	if err := h.result(); err != errFlowControl {
		t.Fatalf("relay error %v, want %v", err, errFlowControl)
	}
}

// The same for the connection window, which is 65,535 bytes until the relay
// grants more.
func TestConnectionWindowViolationClosesTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 1 << 20}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = h.client.Write(encodeFrames([]Frame{{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("x"), 70000)}}))
	h.expect(h.toClient, "client", isGoAway(errCodeFlowControl))
	if err := h.result(); err != errFlowControl {
		t.Fatalf("relay error %v, want %v", err, errFlowControl)
	}
}

// A streamed upload that would pass the connection's buffer budget while the
// server withholds credit is reset on both sides, and nothing stays held.
func TestStreamedUploadsShareTheBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 70000 })
	// Stream 1 uses up the server's 65,535 byte connection window.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	for sent := 0; sent < defaultWindow; {
		n := min(defaultMaxFrame, defaultWindow-sent)
		h.clientSend(Frame{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("c"), n)})
		sent += n
	}
	for received := 0; received < defaultWindow; {
		if f := h.next(h.toServer, "server"); f.Type == FrameData {
			received += len(f.Payload)
		}
	}
	// Stream 3 buffers 10,000 bytes (credited at once); stream 5 streams
	// within its windows but cannot be sent on, so its bytes queue up.
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Stream: 3, Payload: bytes.Repeat([]byte("b"), 10000)},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 5, Payload: h.clientBlock(otherRequest("POST")...)},
	)
	streamHeaders := h.expect(h.toServer, "server", isType(FrameHeaders))
	for sent := 0; sent < 4*defaultMaxFrame-1; {
		n := min(defaultMaxFrame, 4*defaultMaxFrame-1-sent)
		h.clientSend(Frame{Type: FrameData, Stream: 5, Payload: bytes.Repeat([]byte("s"), n)})
		sent += n
	}
	h.expect(h.toClient, "client", func(f Frame) bool {
		return f.Type == FrameRSTStream && f.Stream == 5 && binary.BigEndian.Uint32(f.Payload) == errCodeCalm
	})
	h.expect(h.toServer, "server", func(f Frame) bool {
		return f.Type == FrameRSTStream && f.Stream == streamHeaders.Stream && binary.BigEndian.Uint32(f.Payload) == errCodeCancel
	})
	if _, _, held := h.state(); held != 10000 {
		t.Fatalf("relay holds %d bytes, want stream 3's 10000", held)
	}
}

// A server table size above the relay's decoder limit reaches the client
// lowered to that limit, and a client that uses all of what it was told
// keeps working. The other settings arrive unchanged and in order.
func TestLargeServerHeaderTableSize(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(
		Setting{ID: 3, Value: 100},
		Setting{ID: SettingHeaderTableSize, Value: 131072},
		Setting{ID: SettingInitialWindowSize, Value: 1 << 20},
	))
	f := h.expect(h.toClient, "client", isType(FrameSettings))
	got, err := ParseSettings(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != (Setting{ID: 3, Value: 100}) || got[1].ID != SettingHeaderTableSize || got[2] != (Setting{ID: SettingInitialWindowSize, Value: 1 << 20}) {
		t.Fatalf("client settings %v", got)
	}
	// The client follows what it received: a table size update to it,
	// then a header large enough to need a table above 4096 bytes.
	h.clientEnc.SetMaxDynamicTableSizeLimit(got[1].Value)
	h.clientEnc.SetMaxDynamicTableSize(got[1].Value)
	big := hpack.HeaderField{Name: "x-big", Value: strings.Repeat("v", 20000)}
	for _, id := range []uint32{1, 3} {
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET", big)...)})
		if f := h.expect(h.toServer, "server", isType(FrameHeaders)); f.Stream != id {
			t.Fatalf("request reached the server on stream %d, want %d", f.Stream, id)
		}
	}
}

// Two SETTINGS frames sent before either is acknowledged: a window of 0,
// then back to 65,535. After both ACKs the client uses 65,535, so a DATA
// frame within it is legal.
func TestSettingsAcksApplyEachFrameInOrder(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(
		settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}),
		settingsFrame(Setting{ID: SettingInitialWindowSize, Value: defaultWindow}),
	)
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}, Frame{Type: FrameSettings, Flags: FlagAck})
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: bytes.Repeat([]byte("d"), 1000)},
	)
	h.expect(h.toServer, "server", isType(FrameHeaders))
	got := 0
	for {
		f := h.expect(h.toServer, "server", isType(FrameData))
		got += len(f.Payload)
		if f.Flags&FlagEndStream != 0 {
			break
		}
	}
	if got != 1000 {
		t.Fatalf("server got %d bytes", got)
	}
	h.quiet(h.toClient, 50*time.Millisecond, isType(FrameGoAway))
}

// The decrease itself is enforced once acknowledged, also when an increase
// follows it later.
func TestSettingsDecreaseTakesEffectOnItsAck(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: defaultWindow}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}) // the client uses 0 now, maybe 65,535 already
	h.r.mu.Lock()
	possible := h.r.clientInitial
	h.r.mu.Unlock()
	if possible != defaultWindow {
		t.Fatalf("enforced initial window %d while the client may already use %d", possible, defaultWindow)
	}
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 10}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}, Frame{Type: FrameSettings, Flags: FlagAck}) // now 10
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = h.client.Write(encodeFrames([]Frame{{Type: FrameData, Stream: 1, Payload: bytes.Repeat([]byte("x"), 11)}}))
	h.expect(h.toClient, "client", isGoAway(errCodeFlowControl))
}

func expandingSwapper(t *testing.T) *swap.Swapper {
	t.Helper()
	s, err := swap.New(map[string]string{"t1": strings.Repeat("R", 200)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A body within MaxBody whose swap would pass it (a short stand-in repeated)
// is refused before anything goes upstream, and nothing stays held.
func TestBodyExpansionIsBoundedByMaxBody(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBody = 1000; o.Swapper = expandingSwapper(t) })
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte(strings.Repeat("t1", 400))}, // 800 bytes, 80,000 swapped
	)
	h.expect(h.toClient, "client", isRefusal(1))
	h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
	h.settle("a refused expansion")
}

// The same against the connection budget, with MaxBody out of the way.
func TestBodyExpansionIsBoundedByTheConnectionBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 5000; o.Swapper = expandingSwapper(t) })
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte(strings.Repeat("t1", 400))},
	)
	h.expect(h.toClient, "client", isRefusal(1))
	h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
	h.settle("a refused expansion")
	// A body whose swap fits still goes through.
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 3, Payload: []byte("t1t1")},
	)
	h.expect(h.toServer, "server", isType(FrameHeaders))
	if f := h.expect(h.toServer, "server", isType(FrameData)); len(f.Payload) != 400 {
		t.Fatalf("server got %d bytes, want 400", len(f.Payload))
	}
}

// Header values and the query string are bounded the same way, and a real
// value with a line break never reaches a header.
func TestHeaderSwapsAreBoundedAndSafe(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxHeaderBytes = 16384; o.Swapper = expandingSwapper(t) })
	repeated := strings.Repeat("t1", 1000) // 2,000 bytes, 200,000 swapped
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1,
		Payload: h.clientBlock(request("GET", hpack.HeaderField{Name: "x-token", Value: repeated})...)})
	h.expect(h.toClient, "client", isRefusal(1))
	query := request("GET")
	query[3].Value = "/?q=" + repeated
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(query...)})
	h.expect(h.toClient, "client", isRefusal(3))
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))

	unsafe, err := swap.New(map[string]string{"tok": "a\r\nX-Injected: 1"})
	if err != nil {
		t.Fatal(err)
	}
	h2 := newHarness(t, func(o *Options) { o.Swapper = unsafe })
	h2.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1,
		Payload: h2.clientBlock(request("GET", hpack.HeaderField{Name: "authorization", Value: "Bearer tok"})...)})
	h2.expect(h2.toClient, "client", isRefusal(1))
	h2.quiet(h2.toServer, 50*time.Millisecond, isType(FrameHeaders))
}

// sendData sends n bytes on a stream in frames of at most 16,384 bytes.
func (h *harness) sendData(stream uint32, n int, end bool) {
	h.t.Helper()
	for sent := 0; sent < n; {
		size := min(defaultMaxFrame, n-sent)
		f := Frame{Type: FrameData, Stream: stream, Payload: bytes.Repeat([]byte("u"), size)}
		sent += size
		if end && sent == n {
			f.Flags = FlagEndStream
		}
		h.clientSend(f)
	}
}

// receiveData waits until the server got n bytes on a stream, and returns
// whether the last frame ended it.
func (h *harness) receiveData(stream uint32, n int) bool {
	h.t.Helper()
	got, ended := 0, false
	for got < n {
		f := h.expect(h.toServer, "server", func(f Frame) bool { return f.Type == FrameData && f.Stream == stream })
		got += len(f.Payload)
		ended = f.Flags&FlagEndStream != 0
	}
	if got != n {
		h.t.Fatalf("server got %d bytes on stream %d, want %d", got, stream, n)
	}
	return ended
}

// credit waits until the client got connection WINDOW_UPDATEs summing n.
func (h *harness) credit(n int) {
	h.t.Helper()
	for got := 0; got < n; {
		f := h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameWindowUpdate && f.Stream == 0 })
		got += int(binary.BigEndian.Uint32(f.Payload))
	}
}

// A streamed upload the client resets while its bytes wait for the server's
// credit gives their connection credit back, so other streams keep flowing.
func TestResetUploadReturnsConnectionCredit(t *testing.T) {
	h := newHarness(t, nil)
	// Stream 1 uses up the server's connection window; the relay credits
	// the client as the bytes reach the server.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	h.sendData(1, defaultWindow, false)
	h.receiveData(1, defaultWindow)
	h.credit(defaultWindow)
	// Stream 3's 60,000 bytes queue: the server grants no more yet.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(otherRequest("POST")...)})
	h.sendData(3, 60000, false)
	h.clientSend(rstStream(3, errCodeCancel))
	h.credit(60000) // the discarded bytes' credit comes back
	// The server opens its window again; stream 5 sends within the
	// connection window the client now has.
	h.serverSend(windowUpdate(0, defaultWindow))
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 5, Payload: h.clientBlock(otherRequest("POST")...)})
	h.sendData(5, 50000, true)
	if !h.receiveData(5, 50000) {
		t.Fatal("stream 5 did not end")
	}
	h.quiet(h.toClient, 50*time.Millisecond, isType(FrameGoAway))
	if _, _, held := h.state(); held != 0 {
		t.Fatalf("relay still holds %d bytes", held)
	}
}

// The server answers before the upload is done and keeps reading: its later
// WINDOW_UPDATEs still reach the upload, which completes.
func TestEarlyResponseKeepsTheUploadGoing(t *testing.T) {
	h := newHarness(t, nil)
	const total = 100000
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(otherRequest("POST")...)})
	serverID := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.sendData(1, defaultWindow, false)
	h.receiveData(1, defaultWindow) // the server's stream window is now 0
	h.credit(defaultWindow)
	// The response ends first; then the server grants more of its window.
	h.serverSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: serverID, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})},
		windowUpdate(serverID, defaultWindow),
		windowUpdate(0, defaultWindow),
	)
	h.expect(h.toClient, "client", isType(FrameHeaders))
	h.sendData(1, total-defaultWindow, true)
	if !h.receiveData(1, total-defaultWindow) {
		t.Fatal("the upload did not end")
	}
	h.settle("an upload that outlived its response")
}

// A request depending on a stream that is still buffering here (so has no
// server ID yet) must not end up depending on itself once it takes the
// first server ID; and a PRIORITY frame for the buffering stream waits for
// that stream's own server ID instead of landing on another stream.
func TestPriorityNeverPointsAtTheWrongStream(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)}) // buffering
	dependent := Priority{Exclusive: false, DependsOn: 1, Weight: 100}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream | FlagPriority, Stream: 3,
		Payload: append(dependent.bytes(), h.clientBlock(request("GET")...)...)})
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	priority, _, err := HeadersPayload(f.Flags, f.Payload)
	if err != nil || priority == nil {
		t.Fatalf("server HEADERS on %d lost their priority: %v", f.Stream, err)
	}
	if f.Stream != 1 || priority.DependsOn == f.Stream || priority.DependsOn != 0 || priority.Weight != 100 {
		t.Fatalf("server stream %d depends on %d (weight %d), want the root", f.Stream, priority.DependsOn, priority.Weight)
	}

	// Reprioritize the buffering stream 1: upstream stream 1 is client 3.
	h.clientSend(Frame{Type: FramePriority, Stream: 1, Payload: Priority{DependsOn: 0, Weight: 50}.bytes()})
	h.quiet(h.toServer, 50*time.Millisecond, isType(FramePriority))
	h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("body")})
	headers := h.expect(h.toServer, "server", isType(FrameHeaders))
	if headers.Stream != 3 {
		t.Fatalf("buffered request went upstream on %d, want 3", headers.Stream)
	}
	pf := h.expect(h.toServer, "server", isType(FramePriority))
	if p := parsePriority(pf.Payload); pf.Stream != 3 || p.Weight != 50 || p.DependsOn != 0 {
		t.Fatalf("PRIORITY reached server stream %d as %+v, want stream 3, weight 50", pf.Stream, p)
	}
}

// With a server limit of one concurrent stream, an upload that got its final
// response early still counts upstream while its last bytes wait for credit;
// the client's next request waits for that slot instead of passing the limit.
func TestServerConcurrencyLimitIsKept(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 1}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	const total = defaultWindow + 4465
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)}) // buffered
	h.sendData(1, defaultWindow, false)
	h.credit(defaultWindow)
	h.sendData(1, total-defaultWindow, true)
	serverID := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	if ended := h.receiveData(serverID, defaultWindow); ended {
		t.Fatal("the upload ended before its last bytes")
	}
	// The response ends early; 4,465 bytes still wait for the server's credit.
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: serverID,
		Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	h.expect(h.toClient, "client", isType(FrameHeaders))
	// For the client stream 1 is closed, so it may open another.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(request("GET")...)})
	h.quiet(h.toServer, 100*time.Millisecond, isType(FrameHeaders))
	// Credit lets the upload finish; only then does stream 3 go upstream.
	h.serverSend(windowUpdate(serverID, defaultWindow), windowUpdate(0, defaultWindow))
	var order []string
	for len(order) < 2 {
		f := h.next(h.toServer, "server")
		switch {
		case f.Type == FrameData && f.Flags&FlagEndStream != 0:
			order = append(order, "upload end")
		case f.Type == FrameHeaders:
			order = append(order, "next request")
		}
	}
	if order[0] != "upload end" || order[1] != "next request" {
		t.Fatalf("server saw %v, want the upload to end before the next request", order)
	}
}

// After the client acknowledged a server initial window of 0, an
// allowlisted upload (held here until its body ends, so the server cannot
// grant it credit yet) gets the relay's own window and completes.
func TestBufferedUploadAfterZeroInitialWindow(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)})
	// The client's stream window is 0: it may send only once credited.
	f := h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameWindowUpdate && f.Stream == 1 })
	window := int(binary.BigEndian.Uint32(f.Payload))
	if window < 1000 {
		t.Fatalf("relay granted the buffered upload %d bytes", window)
	}
	h.sendData(1, 1000, true)
	serverID := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	// The server now has the headers and grants credit for the body.
	h.serverSend(windowUpdate(serverID, 1000))
	if !h.receiveData(serverID, 1000) {
		t.Fatal("the upload did not end")
	}
	h.quiet(h.toClient, 50*time.Millisecond, isType(FrameGoAway))
}

// Framing headers are not swapped: a stand-in equal to the content-length
// leaves it alone, and the content-length matches the body that is sent.
func TestFramingHeadersAreNotSwapped(t *testing.T) {
	numeric, err := swap.New(map[string]string{"123": "456"})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(o *Options) { o.Swapper = numeric })
	body := bytes.Repeat([]byte("x"), 123)
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST",
			hpack.HeaderField{Name: "content-length", Value: "123"},
			hpack.HeaderField{Name: "x-code", Value: "123"})...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: body},
	)
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	_, fragment, err := HeadersPayload(f.Flags, f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(fragment)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, field := range fields {
		got[field.Name] = field.Value
	}
	if got["content-length"] != "123" || got["x-code"] != "456" {
		t.Fatalf("server got content-length %q and x-code %q, want 123 and 456", got["content-length"], got["x-code"])
	}
	if !h.receiveData(f.Stream, 123) {
		t.Fatal("the body did not end")
	}
}

// A buffering upload already open when the client acknowledges a drop to a
// zero initial window gets its window back from the relay.
func TestBufferedUploadKeepsItsWindowAfterADecrease(t *testing.T) {
	h := newHarness(t, nil)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)})
	h.serverSend(settingsFrame(Setting{ID: SettingInitialWindowSize, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}) // stream 1's window is now 0
	f := h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameWindowUpdate && f.Stream == 1 })
	if granted := int(binary.BigEndian.Uint32(f.Payload)); granted != defaultWindow {
		t.Fatalf("relay granted %d bytes, want %d", granted, defaultWindow)
	}
	h.sendData(1, 1000, true)
	serverID := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(windowUpdate(serverID, 1000))
	if !h.receiveData(serverID, 1000) {
		t.Fatal("the upload did not end")
	}
}

// Server SETTINGS (which make the relay scan buffering streams) arriving
// while the client opens uploads: the race detector must find no stream
// field written after the stream became visible to the other goroutines.
func TestSettingsWhileUploadsOpen(t *testing.T) {
	h := newHarness(t, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			value := uint32(defaultWindow)
			if i%2 == 1 {
				value = 1 << 20
			}
			_ = h.server.SetWriteDeadline(time.Now().Add(waitFor))
			if _, err := h.server.Write(encodeFrames([]Frame{settingsFrame(Setting{ID: SettingInitialWindowSize, Value: value})})); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		id := uint32(2*i + 1)
		fields := request("POST") // allowlisted: buffered
		if i%4 == 3 {
			fields = otherRequest("POST") // streamed
		}
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: id, Payload: h.clientBlock(fields...)})
	}
	<-done
	// The connection still works.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 201, Payload: h.clientBlock(otherRequest("GET")...)})
	h.expect(h.toServer, "server", func(f Frame) bool {
		if f.Type != FrameHeaders {
			return false
		}
		_, fragment, err := HeadersPayload(f.Flags, f.Payload)
		return err == nil && len(fragment) > 0 && f.Flags&FlagEndStream != 0
	})
}
