package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// relayPanicValue is what a panicking destination connection panics with.
// It stands for a real value, so it must never reach a log.
const relayPanicValue = "sk_live_real_secret_value_in_a_panic"

// idlePanicHandler injects a failure on the idle timer's goroutine.
type idlePanicHandler struct{ slog.Handler }

func (h idlePanicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return idlePanicHandler{h.Handler.WithAttrs(attrs)}
}

func (h idlePanicHandler) WithGroup(name string) slog.Handler {
	return idlePanicHandler{h.Handler.WithGroup(name)}
}

func (h idlePanicHandler) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Message == "closing an idle connection" {
		panic(relayPanicValue)
	}
	return h.Handler.Handle(ctx, rec)
}

func TestIdleTimerPanicClosesOnlyItsConnection(t *testing.T) {
	destinationClosed := make(chan struct{}, 1)
	plain := startTCPDestination(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
		destinationClosed <- struct{}{}
	})
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": plain, allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		c.IdleTimeout = 300 * time.Millisecond
		c.Logger = slog.New(idlePanicHandler{c.Logger.Handler()})
	})
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	expectClosed(t, conn, 5*time.Second)
	select {
	case <-destinationClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("destination connection not closed")
	}
	waitForLog(t, p, "idle timer panicked", "panic_type=string", "proxy.idlePanicHandler.Handle")
	conn2, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	getOK(t, chromeClient(t, conn2, allowedHost, p.ca), allowedHost)
}

// panicConn panics once in Read or Write once armed: a bug hit once.
type panicConn struct {
	net.Conn
	onRead, onWrite atomic.Bool
}

func (c *panicConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.onRead.CompareAndSwap(true, false) {
		panic(relayPanicValue)
	}
	return n, err
}

func (c *panicConn) Write(b []byte) (int, error) {
	if c.onWrite.CompareAndSwap(true, false) {
		panic(relayPanicValue)
	}
	return c.Conn.Write(b)
}

// panicConnDialer dials like mapDialer, wraps each connection to target in
// a panicConn, and hands it to the test on conns.
type panicConnDialer struct {
	mapDialer
	target string
	conns  chan *panicConn
}

func (d panicConnDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.mapDialer.DialContext(ctx, network, addr)
	if err != nil || addr != d.target {
		return conn, err
	}
	pc := &panicConn{Conn: conn}
	d.conns <- pc
	return pc, nil
}

// waitForLog waits for a log line holding want, and checks the log never
// carries the panic value.
func waitForLog(t *testing.T, p *testProxy, want ...string) {
	t.Helper()
	var logs string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		logs = p.logs.String()
		found := true
		for _, w := range want {
			found = found && strings.Contains(logs, w)
		}
		if found {
			break
		}
	}
	for _, w := range want {
		if !strings.Contains(logs, w) {
			t.Fatalf("no log line holds %q:\n%s", w, logs)
		}
	}
	if strings.Contains(logs, relayPanicValue) {
		t.Fatalf("the log carries the panic value:\n%s", logs)
	}
}

// A panic in one of a tunnel's copies closes both of its connections, and
// the proxy goes on serving others.
func TestTunnelPanicClosesOnlyItsConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	armed, destinationClosed := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-armed
		_, _ = io.WriteString(conn, "hello from the destination")
		_, _ = io.Copy(io.Discard, conn)
		close(destinationClosed)
	}()
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	dialer := panicConnDialer{
		mapDialer: mapDialer{otherHost + ":443": ln.Addr().String(), allowedHost + ":443": dest.addr},
		target:    otherHost + ":443", conns: make(chan *panicConn, 1),
	}
	p := startProxy(t, nil, dest.ca, func(c *Config) { c.Dialer = dialer })

	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	// Armed before the destination sends anything: the copy toward the
	// client panics on its first bytes.
	(<-dialer.conns).onRead.Store(true)
	close(armed)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("client connection not closed: %v", err)
	}
	select {
	case <-destinationClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("destination connection not closed")
	}
	waitForLog(t, p, "tunnel panicked", "panic_type=string", "proxy.(*panicConn).Read")

	conn2, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	getOK(t, chromeClient(t, conn2, allowedHost, p.ca), allowedHost)
}

// A panic in a relay goroutine of an intercepted connection closes that
// connection, and the proxy goes on serving others.
func TestRelayPanicClosesOnlyItsConnection(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			dest := startDestination(t, allowedHost, []string{protocol}, respondOK)
			dialer := panicConnDialer{mapDialer: mapDialer{allowedHost + ":443": dest.addr}, target: allowedHost + ":443", conns: make(chan *panicConn, 2)}
			p := startProxy(t, nil, dest.ca, func(c *Config) { c.Dialer = dialer })

			conn, resp := connect(t, p.addr, allowedHost+":443", "")
			_ = resp.Body.Close()
			client := chromeClient(t, conn, allowedHost, p.ca)
			// The handshakes are done: the next write to the destination
			// is the relay's.
			(<-dialer.conns).onWrite.Store(true)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			request := "GET / HTTP/1.1\r\nHost: " + allowedHost + "\r\n\r\n"
			if protocol == "h2" {
				request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"
			}
			_, _ = io.WriteString(client, request)
			if _, err := io.ReadAll(client); err != nil && !strings.Contains(err.Error(), "closed") {
				t.Fatalf("client connection not closed: %v", err)
			}
			waitForLog(t, p, "relay panicked", "panic_type=string", "proxy.(*panicConn).Write")

			// A new connection dials a new, unarmed destination connection.
			conn2, resp := connect(t, p.addr, allowedHost+":443", "")
			_ = resp.Body.Close()
			client2 := chromeClient(t, conn2, allowedHost, p.ca)
			<-dialer.conns
			if protocol == "http/1.1" {
				getOK(t, client2, allowedHost)
			}
		})
	}
}
