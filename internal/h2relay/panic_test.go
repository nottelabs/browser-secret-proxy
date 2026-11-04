package h2relay

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/panics"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// panicValue is what the test panics with. It stands for a real value, so
// it must never reach a log.
const panicValue = "real_value_in_a_panic"

// panicConn panics once in Read or Write once armed: a bug hit once.
type panicConn struct {
	net.Conn
	onRead, onWrite atomic.Bool
}

func (c *panicConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.onRead.CompareAndSwap(true, false) {
		panic(panicValue)
	}
	return n, err
}

func (c *panicConn) Write(b []byte) (int, error) {
	if c.onWrite.CompareAndSwap(true, false) {
		panic(panicValue)
	}
	return c.Conn.Write(b)
}

// panicHandler is a log handler that panics on one message and writes the
// others to buf.
type panicHandler struct {
	slog.Handler
	message string
}

func (h panicHandler) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Message == h.message {
		panic(panicValue)
	}
	return h.Handler.Handle(ctx, rec)
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// panicking is a harness whose relay connections can be made to panic, and
// whose log the test reads.
type panicking struct {
	*harness
	client, server *panicConn
	logs           *logBuffer
}

func newPanicking(t *testing.T, mutate func(*Options), setup func(*relay)) *panicking {
	t.Helper()
	p := &panicking{logs: &logBuffer{}}
	p.harness = newHarnessWith(t, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(p.logs, nil))
		if mutate != nil {
			mutate(o)
		}
	}, func(r *relay) {
		p.client, p.server = &panicConn{Conn: r.client}, &panicConn{Conn: r.server}
		r.client, r.server = p.client, p.server
		if setup != nil {
			setup(r)
		}
	})
	return p
}

// ended checks that the relay stopped and closed both connections, and
// that the log names the panic and where it happened, without its value.
func (p *panicking) ended(site string) {
	t := p.t
	t.Helper()
	var pe *panics.Error
	if err := p.result(); !errors.As(err, &pe) {
		t.Fatalf("the relay returned %v, not the panic", err)
	}
	p.closed()
	got := p.logs.String()
	if !strings.Contains(got, "HTTP/2 relay panicked") || !strings.Contains(got, "panic_type=string") || !strings.Contains(got, site) {
		t.Fatalf("no log line names the panic in %s:\n%s", site, got)
	}
	if strings.Contains(got, panicValue) {
		t.Fatalf("the log carries the panic value:\n%s", got)
	}
}

// closed checks that both of the relay's connections are closed: the
// harness stops reading each once it is.
func (p *panicking) closed() {
	p.t.Helper()
	for _, side := range []chan Frame{p.toClient, p.toServer} {
		for open := true; open; {
			select {
			case _, open = <-side:
			case <-time.After(waitFor):
				p.t.Fatal("a connection stayed open")
			}
		}
	}
}

// otherConnectionWorks checks that a relay started after the panic relays
// a request and its response.
func otherConnectionWorks(t *testing.T) {
	t.Helper()
	h := newHarness(t, nil)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)})
	id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
	h.serverSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
	if f := h.expect(h.toClient, "client", isType(FrameHeaders)); f.Stream != 1 {
		t.Fatalf("response on stream %d", f.Stream)
	}
}

var ping = Frame{Type: FramePing, Payload: make([]byte, 8)}

// A panic on any goroutine the relay starts ends that connection only.
func TestGoroutinePanicEndsOnlyItsConnection(t *testing.T) {
	maskedGzip := func(o *Options) {
		masking(t, true)(o)
		o.Logger = slog.New(panicHandler{Handler: o.Logger.Handler(), message: "resetting a response that could not be masked"})
	}
	panickingResolver := func(o *Options) {
		o.Session = scopetest.Session(t, o.Hosts, scopetest.Resolver{
			Known: []string{"tok_panic"},
			Fn:    func(resolve.Request) (resolve.Result, error) { panic(panicValue) },
		}, resolve.Principal{})
	}
	cases := []struct {
		name    string
		mutate  func(*Options)
		trigger func(p *panicking)
		site    string
	}{
		{"server loop", nil, func(p *panicking) {
			p.server.onRead.Store(true)
			writeAsync(p.harness.server, ping)
		}, "(*relay).serverLoop"},
		{"client loop", nil, func(p *panicking) {
			p.client.onRead.Store(true)
			writeAsync(p.harness.client, ping)
		}, "(*relay).clientLoop"},
		{"send loop", nil, func(p *panicking) {
			// A streamed request goes out at once; its body from sendLoop.
			p.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: p.clientBlock(otherRequest("POST")...)})
			p.expect(p.toServer, "server", isType(FrameHeaders))
			p.server.onWrite.Store(true)
			writeAsync(p.harness.client, data(1, "body", true))
		}, "(*relay).sendLoop"},
		{"masked server loop", masking(t, true), func(p *panicking) {
			p.server.onRead.Store(true)
			writeAsync(p.harness.server, ping)
		}, "(*relay).serverLoopMasked"},
		{"client send loop", masking(t, true), func(p *panicking) {
			// A masked body reaches the client from clientSendLoop.
			id := get(p.harness, 1)
			p.serverSend(status(p.harness, id, false, field(":status", "200")))
			p.expect(p.toClient, "client", isType(FrameHeaders))
			p.client.onWrite.Store(true)
			writeAsync(p.harness.server, data(id, "body", true))
		}, "(*relay).clientSendLoop"},
		{"lookup", panickingResolver, func(p *panicking) {
			writeAsync(p.harness.client, Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1,
				Payload: p.clientBlock(request("GET", hpack.HeaderField{Name: "authorization", Value: "Bearer tok_panic"})...)})
		}, "(*relay).runLookup"},
		{"mask", maskedGzip, func(p *panicking) {
			id := get(p.harness, 1)
			writeAsync(p.harness.server, status(p.harness, id, false, field(":status", "200"), field("content-encoding", "gzip")),
				data(id, "not gzip at all", true))
		}, "(*relay).runMask"},
		{"GOAWAY to the server", nil, func(p *panicking) {
			p.server.onWrite.Store(true)
			// A DATA frame over the client's 16,384-byte limit.
			writeAsync(p.harness.server, Frame{Type: FrameData, Stream: 1, Payload: make([]byte, defaultMaxFrame+1)})
		}, "(*relay).goAwayServer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPanicking(t, c.mutate, nil)
			c.trigger(p)
			p.ended(c.site)
			otherConnectionWorks(t)
		})
	}
}

// A panic that leaves the relay's lock held keeps the goroutines waiting on
// it from ending, but not the relay: it stops waiting for them after
// panicWait, with both connections closed.
func TestPanicWithTheLockHeldStillEndsTheRelay(t *testing.T) {
	p := newPanicking(t, nil, func(r *relay) { r.panicWait = 100 * time.Millisecond })
	p.r.mu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			p.r.mu.Unlock()
		}
	}()
	p.server.onRead.Store(true)
	writeAsync(p.harness.server, ping)
	select {
	case <-p.done: //nolint:errcheck // only waits for the relay to stop
	case <-time.After(waitFor):
		t.Fatal("the relay kept waiting on goroutines stuck on its lock")
	}
	p.done <- nil
	p.closed()
	if got := p.logs.String(); !strings.Contains(got, "stopped waiting") {
		t.Fatalf("no log line says the relay stopped waiting:\n%s", got)
	}
	p.r.mu.Unlock()
	unlocked = true
}

// A panic is what the relay returns, even when another goroutine's error
// reached run first: here the client closed, then writing the connection
// error to it during shutdown panicked.
func TestRelayReturnsAPanicThatFollowsAnotherError(t *testing.T) {
	var client *panicConn
	h := newRawHarness(t, nil, func(r *relay) {
		client = &panicConn{Conn: r.client}
		r.client = client
	})
	client.onWrite.Store(true)
	_ = h.client.Close()
	var p *panics.Error
	if err := h.result(); !errors.As(err, &p) {
		t.Fatalf("the relay returned %v, not the panic", err)
	}
}
