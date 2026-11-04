package h1relay

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/panics"
)

// panicValue is what a panicking connection panics with. It stands for a
// real value, so it must never reach a log.
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

// A panic on either of the relay's goroutines ends that connection only:
// Serve returns, both sides are closed, the log names where it happened but
// not the panic value, and another connection is relayed as before.
func TestGoroutinePanicEndsOnlyItsConnection(t *testing.T) {
	cases := []struct {
		name string
		arm  func(client, server *panicConn)
	}{
		// The response side reads the server.
		{"responses", func(_, server *panicConn) { server.onRead.Store(true) }},
		// The request side reads the client.
		{"requests", func(client, _ *panicConn) { client.onRead.Store(true) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logs := &logBuffer{}
			opts := options(t)
			opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
			clientSide, relayClient := net.Pipe()
			relayServer, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			client, server := &panicConn{Conn: relayClient}, &panicConn{Conn: relayServer}
			result := make(chan error, 1)
			go func() { result <- Serve(client, server, opts) }()

			// One exchange first, so the panic comes in the middle of a
			// connection.
			getThrough(t, clientSide, serverSide)
			c.arm(client, server)
			go func() {
				_, _ = io.WriteString(clientSide, "GET /2 HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
			}()
			go func() {
				// The server answers whatever it receives, so the response
				// side has something to read.
				br := bufio.NewReader(serverSide)
				if _, err := http.ReadRequest(br); err == nil {
					_, _ = io.WriteString(serverSide, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
				_, _ = io.Copy(io.Discard, br)
			}()

			select {
			case err := <-result:
				var p *panics.Error
				if !errors.As(err, &p) {
					t.Fatalf("relay returned %v, want a panic", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay did not stop after a panic")
			}
			_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(clientSide); err != nil {
				t.Fatalf("client side not closed: %v", err)
			}
			got := logs.String()
			if !strings.Contains(got, "panic_type=string") || !strings.Contains(got, "h1relay.(*panicConn).Read") {
				t.Fatalf("no log line names the panic and where it happened:\n%s", got)
			}
			if strings.Contains(got, panicValue) {
				t.Fatalf("the log carries the panic value:\n%s", got)
			}

			// Another connection works.
			other, otherServer := net.Pipe()
			otherRelayServer, otherServerSide := net.Pipe()
			defer other.Close()
			defer otherServerSide.Close()
			go func() { _ = Serve(otherServer, otherRelayServer, options(t)) }()
			getThrough(t, other, otherServerSide)
		})
	}
}

// getThrough sends one GET through a relay and answers it.
func getThrough(t *testing.T, client, server net.Conn) {
	t.Helper()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() {
		_ = client.SetDeadline(time.Time{})
		_ = server.SetDeadline(time.Time{})
	}()
	go func() { _, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n") }()
	sbr := bufio.NewReader(server)
	if _, err := http.ReadRequest(sbr); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") }()
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
}
