package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startTCPDestination serves handle on plain TCP connections, for tunnels.
func startTCPDestination(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func echo(c net.Conn) { _, _ = io.Copy(c, c) }

// expectClosed fails unless the proxy closes conn within wait.
func expectClosed(t *testing.T, conn net.Conn, wait time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := io.Copy(io.Discard, conn)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the proxy kept the connection open for %s", wait)
	}
}

// A tunnel that carries nothing either way for IdleTimeout is closed.
func TestIdleTunnelIsClosed(t *testing.T) {
	dest := startTCPDestination(t, echo)
	p := startProxy(t, mapDialer{otherHost + ":443": dest}, nil, func(c *Config) {
		c.IdleTimeout = 300 * time.Millisecond
	})
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	send(t, conn, "ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q, %v", got, err)
	}
	expectClosed(t, conn, 3*time.Second)
	if !strings.Contains(p.logs.String(), "closing an idle connection") {
		t.Fatalf("no log line:\n%s", p.logs.String())
	}
}

// Traffic in one direction only, such as a server pushing events, keeps a
// connection open past IdleTimeout.
func TestOneWayTrafficKeepsATunnelOpen(t *testing.T) {
	dest := startTCPDestination(t, func(c net.Conn) {
		if _, err := c.Read(make([]byte, 1)); err != nil {
			return
		}
		for i := 0; i < 20; i++ {
			if _, err := c.Write([]byte{'e'}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	p := startProxy(t, mapDialer{otherHost + ":443": dest}, nil, func(c *Config) {
		c.IdleTimeout = 300 * time.Millisecond
	})
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	send(t, conn, "s") // the only byte the client sends
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || len(got) != 20 {
		t.Fatalf("client got %d of 20 events (%v)", len(got), err)
	}
}

// An intercepted connection that goes silent is closed too, over HTTP/1.1
// and HTTP/2.
func TestIdleInterceptedConnectionIsClosed(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			dest := startDestination(t, allowedHost, []string{protocol}, func(c *tls.Conn) { _, _ = io.Copy(io.Discard, c) })
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
				c.IdleTimeout = 300 * time.Millisecond
			})
			conn, resp := connect(t, p.addr, allowedHost+":443", "")
			_ = resp.Body.Close()
			u := chromeClient(t, conn, allowedHost, p.ca)
			if got := u.ConnectionState().NegotiatedProtocol; got != protocol {
				t.Fatalf("negotiated %q", got)
			}
			expectClosed(t, u, 3*time.Second)
		})
	}
}

// A large write that a slow reader keeps draining counts as traffic while
// it goes on, though the whole write takes longer than IdleTimeout.
func TestSlowlyDrainedWriteIsNotIdle(t *testing.T) {
	ours, peer := net.Pipe()
	defer peer.Close()
	idle := newIdleTimer(200 * time.Millisecond)
	conn := idle.wrap(ours)
	idle.start(slog.New(slog.DiscardHandler), conn)
	defer idle.stop()
	go func() {
		buf := make([]byte, 4<<10)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	// 128 reads of 4 KiB, 10ms apart, take over a second.
	if _, err := conn.Write(make([]byte, 512<<10)); err != nil {
		t.Fatalf("a write that was being drained ended with %v", err)
	}
}

// The CONNECT head must arrive within HeaderTimeout, however long the
// handshake may take.
func TestSlowConnectHeadIsClosed(t *testing.T) {
	p := startProxy(t, mapDialer{}, nil, func(c *Config) {
		c.HeaderTimeout = 200 * time.Millisecond
		c.HandshakeTimeout = 10 * time.Second
	})
	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	send(t, conn, "CONNECT allowed.test:443 HTTP/1.1\r\n")
	expectClosed(t, conn, 3*time.Second)
}

// A request head dripped inside an intercepted HTTP/1.1 connection ends it
// after HeaderTimeout, even though bytes keep arriving.
func TestSlowRequestHeadIsClosed(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		c.HeaderTimeout = 300 * time.Millisecond
	})
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	getOK(t, tlsConn, allowedHost)
	go func() {
		for _, c := range "GET / HTTP/1.1\r\nHost: " + allowedHost + "\r\nX-Slow: " + strings.Repeat("s", 100) {
			if _, err := io.WriteString(tlsConn, string(c)); err != nil {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()
	expectClosed(t, tlsConn, 3*time.Second)
}

// dripConn writes one byte at a time once drip is set, so a TLS record
// reaches the proxy in many pieces.
type dripConn struct {
	net.Conn
	drip atomic.Bool
}

func (c *dripConn) Write(p []byte) (int, error) {
	if !c.drip.Load() {
		return c.Conn.Write(p)
	}
	for i := range p {
		if _, err := c.Conn.Write(p[i : i+1]); err != nil {
			return i, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return len(p), nil
}

// HeaderTimeout counts from the first byte of the TLS record that carries a
// request head, so a client cannot put the deadline off by dripping that
// record's encrypted bytes, each of which keeps IdleTimeout from firing.
// Waiting between requests is still not counted.
func TestDrippedTLSRecordIsClosed(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		c.HeaderTimeout = 300 * time.Millisecond
		c.IdleTimeout = time.Second
	})
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	dripping := &dripConn{Conn: conn}
	tlsConn := tls.Client(dripping, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	getOK(t, tlsConn, allowedHost)
	time.Sleep(2 * 300 * time.Millisecond)
	getOK(t, tlsConn, allowedHost)

	// One record of about 270 bytes takes over 5s to arrive.
	dripping.drip.Store(true)
	go func() {
		_, _ = io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: "+allowedHost+"\r\nX-Pad: "+strings.Repeat("p", 200)+"\r\n\r\n")
	}()
	expectClosed(t, tlsConn, 3*time.Second)
}

// Past MaxConns, a new connection is answered 503 and closed; once one
// ends, a new one is served again.
func TestConnectionLimit(t *testing.T) {
	dest := startTCPDestination(t, echo)
	p := startProxy(t, mapDialer{otherHost + ":443": dest}, nil, func(c *Config) {
		c.MaxConns = 2
	})
	first, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	_, resp = connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	over, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, _ := io.ReadAll(over)
	if !strings.HasPrefix(string(reply), "HTTP/1.1 503 ") {
		t.Fatalf("connection over the limit got %q", reply)
	}
	if !strings.Contains(p.logs.String(), "refusing connections over the limit") {
		t.Fatalf("no log line:\n%s", p.logs.String())
	}

	_ = first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial("tcp", p.addr)
		if err != nil {
			t.Fatal(err)
		}
		send(t, conn, "CONNECT "+otherHost+":443 HTTP/1.1\r\nHost: "+otherHost+":443\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		status := make([]byte, 12)
		_, err = io.ReadFull(conn, status)
		_ = conn.Close()
		if err == nil && string(status) == "HTTP/1.1 200" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection was served after one ended: %q, %v", status, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func send(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
}
