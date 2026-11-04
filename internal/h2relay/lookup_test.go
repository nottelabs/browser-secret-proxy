package h2relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// gatedResolver answers tok_<name> with real_<name>, but only once the test
// releases <name>: a slow resolver, like an http one. It is not
// resolve.Local, so its lookups run off the client loop.
type gatedResolver struct {
	mu       sync.Mutex
	gates    map[string]chan struct{}
	started  chan string // the stand-in of each lookup that reached the resolver
	canceled chan string // the stand-in of each lookup canceled before its answer
}

func newGatedResolver(names ...string) *gatedResolver {
	g := &gatedResolver{gates: map[string]chan struct{}{}, started: make(chan string, 64), canceled: make(chan string, 64)}
	for _, n := range names {
		g.gates["tok_"+n] = make(chan struct{})
	}
	return g
}

func (g *gatedResolver) StandIns(resolve.Principal) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for k := range g.gates {
		out = append(out, k)
	}
	return out
}

func (g *gatedResolver) release(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	close(g.gates["tok_"+name])
}

func (g *gatedResolver) Resolve(ctx context.Context, req resolve.Request) (resolve.Result, error) {
	standIn := req.StandIns[0]
	g.mu.Lock()
	gate := g.gates[standIn]
	g.mu.Unlock()
	g.started <- standIn
	select {
	case <-gate:
	case <-ctx.Done():
		g.canceled <- standIn
		return resolve.Result{}, ctx.Err()
	}
	out := resolve.Result{Values: map[string]resolve.Value{}}
	for _, s := range req.StandIns {
		out.Values[s] = resolve.Value{Real: "real_" + strings.TrimPrefix(s, "tok_")}
	}
	return out, nil
}

func gated(t *testing.T, g *gatedResolver, maxLookups int) func(*Options) {
	return func(o *Options) {
		o.Session = scopetest.Session(t, o.Hosts, g, resolve.Principal{ID: "alice"})
		o.MaxLookups = maxLookups
	}
}

func getPath(h *harness, stream uint32, path string) {
	h.t.Helper()
	fields := request("GET")
	fields[3].Value = path
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: stream, Payload: h.clientBlock(fields...)})
}

func (g *gatedResolver) waitStarted(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-g.started:
		if got != want {
			t.Fatalf("lookup for %s started, want %s", got, want)
		}
	case <-time.After(waitFor):
		t.Fatalf("lookup for %s did not start", want)
	}
}

// waitStartedSet waits for lookups of want to start, in any order.
func (g *gatedResolver) waitStartedSet(t *testing.T, want ...string) {
	t.Helper()
	left := map[string]bool{}
	for _, w := range want {
		left[w] = true
	}
	for len(left) > 0 {
		select {
		case got := <-g.started:
			if !left[got] {
				t.Fatalf("unexpected lookup for %s", got)
			}
			delete(left, got)
		case <-time.After(waitFor):
			t.Fatalf("lookups for %v did not start", left)
		}
	}
}

func (g *gatedResolver) waitCanceled(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-g.canceled:
		if got != want {
			t.Fatalf("lookup for %s canceled, want %s", got, want)
		}
	case <-time.After(waitFor):
		t.Fatalf("lookup for %s was not canceled", want)
	}
}

// serverPath decodes the :path of a request HEADERS frame the server got.
func serverPath(t *testing.T, dec *hpack.Decoder, f Frame) string {
	t.Helper()
	_, fragment, err := HeadersPayload(f.Flags, f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := dec.DecodeFull(fragment)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if field.Name == ":path" {
			return field.Value
		}
	}
	return ""
}

// A slow lookup for one stream does not hold back another on the same
// connection: stream 3, which needs no lookup, reaches the server and gets
// its response while stream 1's lookup is still blocked.
func TestSlowLookupDoesNotDelayOtherStreams(t *testing.T) {
	g := newGatedResolver("a")
	h := newHarness(t, gated(t, g, 0))
	dec := hpack.NewDecoder(4096, nil)
	getPath(h, 1, "/?k=tok_a")
	g.waitStarted(t, "tok_a")
	getPath(h, 3, "/plain")
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	if p := serverPath(t, dec, f); p != "/plain" {
		t.Fatalf("server got %s first, want /plain", p)
	}
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: f.Stream, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	if got := h.expect(h.toClient, "client", isType(FrameHeaders)); got.Stream != 3 {
		t.Fatalf("response on stream %d, want 3", got.Stream)
	}
	// The slow stream goes upstream, swapped, once its lookup answers.
	g.release("a")
	f2 := h.expect(h.toServer, "server", isType(FrameHeaders))
	if p := serverPath(t, dec, f2); p != "/?k=real_a" || f2.Stream <= f.Stream {
		t.Fatalf("server got %s on stream %d after stream %d", p, f2.Stream, f.Stream)
	}
}

// Upstream stream IDs increase in the order streams are opened, which for
// streams that waited on a lookup is the order their lookups answered.
func TestUpstreamIDsFollowOpeningOrder(t *testing.T) {
	g := newGatedResolver("a", "b")
	h := newHarness(t, gated(t, g, 0))
	dec := hpack.NewDecoder(4096, nil)
	// Each lookup is seen to start before the next request is sent: the
	// order lookup goroutines run in is not the client's.
	getPath(h, 1, "/?k=tok_a")
	g.waitStarted(t, "tok_a")
	getPath(h, 3, "/?k=tok_b")
	g.waitStarted(t, "tok_b")
	getPath(h, 5, "/plain")
	g.release("b")
	time.Sleep(20 * time.Millisecond)
	g.release("a")
	var paths []string
	last := uint32(0)
	for i := 0; i < 3; i++ {
		f := h.expect(h.toServer, "server", isType(FrameHeaders))
		if f.Stream <= last {
			t.Fatalf("upstream stream %d after %d", f.Stream, last)
		}
		last = f.Stream
		paths = append(paths, serverPath(t, dec, f))
	}
	if strings.Join(paths, " ") != "/plain /?k=real_b /?k=real_a" {
		t.Fatalf("server got %q", paths)
	}
}

// The client's RST_STREAM during a lookup cancels it; nothing goes upstream
// and the relay keeps nothing for the stream.
func TestResetCancelsTheLookup(t *testing.T) {
	g := newGatedResolver("a")
	h := newHarness(t, gated(t, g, 0))
	getPath(h, 1, "/?k=tok_a")
	g.waitStarted(t, "tok_a")
	h.clientSend(rstStream(1, errCodeCancel))
	g.waitCanceled(t, "tok_a")
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
	h.settle("a reset during its lookup")
}

// A request whose lookup refuses it gets the relay's 502, as when the lookup
// ran in line.
func TestRefusedLookupIsAnswered502(t *testing.T) {
	g := newGatedResolver("a")
	h := newHarness(t, func(o *Options) {
		r := refusing{g}
		o.Session = scopetest.Session(t, o.Hosts, r, resolve.Principal{ID: "alice"})
	})
	getPath(h, 1, "/?k=tok_a")
	h.expect(h.toClient, "client", isBadGateway(1))
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
	h.settle("a refused lookup")
}

// refusing answers every lookup, after a while, with a value for another
// host.
type refusing struct{ *gatedResolver }

func (r refusing) Resolve(context.Context, resolve.Request) (resolve.Result, error) {
	time.Sleep(10 * time.Millisecond)
	return resolve.Result{Values: map[string]resolve.Value{"tok_a": {Real: "real_a", Hosts: []string{"elsewhere.test"}}}}, nil
}

// A buffered upload waiting for its lookup does not hold back a request
// sent after it.
func TestBufferedUploadLookupDoesNotDelayOthers(t *testing.T) {
	g := newGatedResolver("a")
	h := newHarness(t, gated(t, g, 0))
	dec := hpack.NewDecoder(4096, nil)
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("card=tok_a")},
	)
	g.waitStarted(t, "tok_a")
	getPath(h, 3, "/plain")
	if p := serverPath(t, dec, h.expect(h.toServer, "server", isType(FrameHeaders))); p != "/plain" {
		t.Fatalf("server got %s first", p)
	}
	g.release("a")
	h.expect(h.toServer, "server", isType(FrameHeaders))
	if f := h.expect(h.toServer, "server", isType(FrameData)); string(f.Payload) != "card=real_a" {
		t.Fatalf("server got body %q", f.Payload)
	}
}

// The server's GOAWAY during a lookup refuses the stream (it never went
// upstream, so the client may retry it) and cancels the lookup.
func TestGoAwayDuringALookup(t *testing.T) {
	g := newGatedResolver("a")
	h := newHarness(t, gated(t, g, 0))
	getPath(h, 1, "/?k=tok_a")
	g.waitStarted(t, "tok_a")
	h.serverSend(Frame{Type: FrameGoAway, Payload: make([]byte, 8)})
	h.expect(h.toClient, "client", isRefusal(1))
	g.waitCanceled(t, "tok_a")
	h.settle("GOAWAY during a lookup")
}

// The end of the connection cancels every lookup in flight, and the relay
// returns only once their goroutines did.
func TestShutdownCancelsLookups(t *testing.T) {
	g := newGatedResolver("a", "b")
	h := newHarness(t, gated(t, g, 0))
	getPath(h, 1, "/?k=tok_a")
	getPath(h, 3, "/?k=tok_b")
	g.waitStartedSet(t, "tok_a", "tok_b")
	_ = h.client.Close()
	_ = h.result()
	canceled := map[string]bool{}
	for len(canceled) < 2 {
		select {
		case s := <-g.canceled:
			canceled[s] = true
		default:
			t.Fatalf("the relay returned before canceling its lookups: %v", canceled)
		}
	}
}

// At most MaxLookups lookups are in flight on a connection; the next starts
// when one ends.
func TestLookupsInFlightAreBounded(t *testing.T) {
	g := newGatedResolver("a", "b", "c")
	h := newHarness(t, gated(t, g, 2))
	getPath(h, 1, "/?k=tok_a")
	getPath(h, 3, "/?k=tok_b")
	getPath(h, 5, "/?k=tok_c")
	started := map[string]bool{}
	for len(started) < 2 {
		select {
		case s := <-g.started:
			started[s] = true
		case <-time.After(waitFor):
			t.Fatal("two lookups did not start")
		}
	}
	select {
	case s := <-g.started:
		t.Fatalf("a third lookup (%s) started past the limit of 2", s)
	case <-time.After(100 * time.Millisecond):
	}
	first := ""
	for s := range started {
		first = s
	}
	g.release(strings.TrimPrefix(first, "tok_"))
	select {
	case <-g.started:
	case <-time.After(waitFor):
		t.Fatal("the third lookup did not start once one ended")
	}
}

// Lookups answered from memory (resolve.Local) still run in line: requests
// reach the server in the client's order.
func TestLocalLookupsKeepTheClientsOrder(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Session = scopetest.Static(t, o.Hosts, map[string]string{"tok_standin": "real_value"})
	})
	dec := hpack.NewDecoder(4096, nil)
	getPath(h, 1, "/?k=tok_standin")
	getPath(h, 3, "/plain")
	for _, want := range []string{"/?k=real_value", "/plain"} {
		if p := serverPath(t, dec, h.expect(h.toServer, "server", isType(FrameHeaders))); p != want {
			t.Fatalf("server got %s, want %s", p, want)
		}
	}
}

// A client ending a stream again while its lookup runs (DATA or HEADERS
// with END_STREAM after the first) gets RST_STREAM STREAM_CLOSED: no second
// lookup starts, the stream's lookup is canceled, and nothing goes upstream.
func TestFramesAfterTheEndAreAStreamError(t *testing.T) {
	for name, extra := range map[string]func(h *harness) Frame{
		"data": func(*harness) Frame { return Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1} },
		"headers": func(h *harness) Frame {
			return Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(hpack.HeaderField{Name: "x-t", Value: "1"})}
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGatedResolver("a")
			h := newHarness(t, gated(t, g, 0))
			h.clientSend(
				Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
				Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("card=tok_a")},
			)
			g.waitStarted(t, "tok_a")
			for i := 0; i < 20; i++ {
				h.clientSend(extra(h))
			}
			f := h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameRSTStream && f.Stream == 1 })
			if code := binary.BigEndian.Uint32(f.Payload); code != errCodeStreamClosed {
				t.Fatalf("RST_STREAM code %d, want STREAM_CLOSED", code)
			}
			g.waitCanceled(t, "tok_a")
			select {
			case s := <-g.started:
				t.Fatalf("another lookup (%s) started", s)
			case <-time.After(50 * time.Millisecond):
			}
			h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
			h.settle("frames after the end")
		})
	}
}

// Stream errors past maxStreamErrors end the connection with PROTOCOL_ERROR.
func TestRepeatedStreamErrorsEndTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i <= maxStreamErrors; i++ {
		id := uint32(2*i + 1)
		h.clientSend(
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)},
			Frame{Type: FrameData, Flags: FlagEndStream, Stream: id},
		)
	}
	h.expect(h.toClient, "client", isGoAway(errCodeProtocol))
	if err := h.result(); !errors.Is(err, errTooManyStreamErrors) {
		t.Fatalf("relay error %v", err)
	}
}

// Lookups waiting for a slot have no goroutine: many streams waiting on a
// slow resolver cost MaxLookups goroutines, not one each.
func TestWaitingLookupsHaveNoGoroutine(t *testing.T) {
	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("n%d", i)
	}
	g := newGatedResolver(names...)
	h := newHarness(t, gated(t, g, 2))
	before := runtime.NumGoroutine()
	for i, n := range names {
		getPath(h, uint32(2*i+1), "/?k=tok_"+n)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-g.started:
		case <-time.After(waitFor):
			t.Fatal("lookups did not start")
		}
	}
	time.Sleep(50 * time.Millisecond)
	if grown := runtime.NumGoroutine() - before; grown > 5 {
		t.Fatalf("%d goroutines for 40 waiting lookups with 2 slots", grown)
	}
	h.r.mu.Lock()
	running, waiting := h.r.lookupsRunning, len(h.r.lookupQueue)
	h.r.mu.Unlock()
	if running != 2 || waiting != 38 {
		t.Fatalf("%d running, %d waiting; want 2 and 38", running, waiting)
	}
	// A stream reset while waiting leaves the queue.
	h.clientSend(rstStream(39, errCodeCancel))
	time.Sleep(50 * time.Millisecond)
	h.r.mu.Lock()
	waiting = len(h.r.lookupQueue)
	h.r.mu.Unlock()
	if waiting != 37 {
		t.Fatalf("%d waiting after a reset, want 37", waiting)
	}
}
