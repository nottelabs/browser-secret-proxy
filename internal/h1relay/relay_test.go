package h1relay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

func options(t *testing.T) Options {
	t.Helper()
	hosts, err := hostmatch.New([]string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	return Options{Hosts: hosts, Session: scopetest.Static(t, hosts, map[string]string{"tok_standin": "real"})}
}

// serve runs a relay between pipes, sends request from a client goroutine and
// returns how many bytes the client got to write and the relay's error.
func serve(t *testing.T, request func(w io.Writer) error) (int64, error) {
	t.Helper()
	clientSide, relayClient := net.Pipe()
	relayServer, serverSide := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, serverSide) }()
	var written atomic.Int64
	go func() {
		_ = request(writerFunc(func(p []byte) (int, error) {
			n, err := clientSide.Write(p)
			written.Add(int64(n))
			return n, err
		}))
	}()
	go func() { _, _ = io.Copy(io.Discard, clientSide) }()
	result := make(chan error, 1)
	go func() { result <- Serve(relayClient, relayServer, options(t)) }()
	select {
	case err := <-result:
		_ = clientSide.Close()
		_ = serverSide.Close()
		return written.Load(), err
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not stop")
		return 0, nil
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A line that never ends is refused once it passes the head limit, without
// the relay reading (and holding) the rest of it.
func TestEndlessLineIsRefusedAtTheLimit(t *testing.T) {
	const total = 8 * maxHeadBytes
	written, err := serve(t, func(w io.Writer) error {
		chunk := []byte(strings.Repeat("a", 32<<10))
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, errLineTooLong) {
		t.Fatalf("relay error %v, want a line-too-long error", err)
	}
	if written >= total || written > maxHeadBytes+(64<<10) {
		t.Fatalf("relay read %d bytes of an endless line (limit %d)", written, maxHeadBytes)
	}
}

func TestEndlessHeaderIsRefused(t *testing.T) {
	_, err := serve(t, func(w io.Writer) error {
		if _, err := io.WriteString(w, "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-Long: "); err != nil {
			return err
		}
		chunk := strings.Repeat("b", 32<<10)
		for i := 0; i < 64; i++ {
			if _, err := io.WriteString(w, chunk); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "request head too large") {
		t.Fatalf("relay error %v", err)
	}
}

func TestChunkedTrailersAreCapped(t *testing.T) {
	_, err := serve(t, func(w io.Writer) error {
		if _, err := io.WriteString(w, "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"); err != nil {
			return err
		}
		line := "X-Trailer: " + strings.Repeat("c", 1000) + "\r\n"
		for i := 0; i < 100; i++ {
			if _, err := io.WriteString(w, line); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "chunked trailers too large") {
		t.Fatalf("relay error %v", err)
	}
}

// pipes runs a relay and returns the test's client and server ends.
func pipes(t *testing.T) (client net.Conn, clientReader *bufio.Reader, server net.Conn, serverReader *bufio.Reader) {
	t.Helper()
	client, clientReader, server, serverReader, _ = pipesWith(t, options(t))
	return client, clientReader, server, serverReader
}

// pipesWith also returns the relay's result.
func pipesWith(t *testing.T, opts Options) (client net.Conn, clientReader *bufio.Reader, server net.Conn, serverReader *bufio.Reader, result <-chan error) {
	t.Helper()
	clientSide, relayClient := net.Pipe()
	relayServer, serverSide := net.Pipe()
	done := make(chan error, 1)
	results := make(chan error, 1)
	go func() {
		err := Serve(relayClient, relayServer, opts)
		results <- err
		done <- err
	}()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		select {
		case <-done: //nolint:errcheck // only waits for the relay to stop
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	for _, c := range []net.Conn{clientSide, serverSide} {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	return clientSide, bufio.NewReader(clientSide), serverSide, bufio.NewReader(serverSide), results
}

func readHead(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var head strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read head: %v (so far %q)", err, head.String())
		}
		head.WriteString(line)
		if line == "\r\n" {
			return head.String()
		}
	}
}

func send(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
}

// A refused upgrade leaves the connection in HTTP: the next request is still
// parsed and its stand-ins swapped.
func TestRefusedUpgradeKeepsSwapping(t *testing.T) {
	client, clientReader, server, serverReader := pipes(t)
	send(t, client, "GET /socket HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if head := readHead(t, serverReader); !strings.HasPrefix(head, "GET /socket ") {
		t.Fatalf("server got %q", head)
	}
	send(t, server, "HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad")
	if head := readHead(t, clientReader); !strings.HasPrefix(head, "HTTP/1.1 400 ") {
		t.Fatalf("client got %q", head)
	}
	body := make([]byte, 3)
	if _, err := io.ReadFull(clientReader, body); err != nil || string(body) != "bad" {
		t.Fatalf("client body %q, %v", body, err)
	}
	send(t, client, "GET /next?key=tok_standin HTTP/1.1\r\nHost: allowed.test\r\nAuthorization: Bearer tok_standin\r\n\r\n")
	want := "GET /next?key=real HTTP/1.1\r\nHost: allowed.test\r\nAuthorization: Bearer real\r\n\r\n"
	if head := readHead(t, serverReader); head != want {
		t.Fatalf("server got %q, want %q", head, want)
	}
}

// An accepted upgrade turns the connection into a raw stream both ways.
func TestAcceptedUpgradeBecomesRaw(t *testing.T) {
	client, clientReader, server, serverReader := pipes(t)
	send(t, client, "GET /socket HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	readHead(t, serverReader)
	send(t, server, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if head := readHead(t, clientReader); !strings.HasPrefix(head, "HTTP/1.1 101 ") {
		t.Fatalf("client got %q", head)
	}
	frame := "\x81\x0btok_standin" // not HTTP: copied as is
	send(t, client, frame)
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(serverReader, got); err != nil || string(got) != frame {
		t.Fatalf("server got %q, %v", got, err)
	}
	send(t, server, "\x81\x02ok")
	back := make([]byte, 4)
	if _, err := io.ReadFull(clientReader, back); err != nil || string(back) != "\x81\x02ok" {
		t.Fatalf("client got %q, %v", back, err)
	}
}

// A request that could open a tunnel other than a WebSocket is answered 502
// before any swap and never sent: the server's answer to it, and the rest of
// the connection, would reach the client neither swapped nor masked. A
// CONNECT answered 200 by any catch-all handler would do it, and so would an
// h2c upgrade, after which the server answers the swapped request itself as
// HTTP/2.
func TestTunnelRequestsAreAnswered502(t *testing.T) {
	for name, request := range map[string]string{
		"CONNECT":                    "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\nX-Token: tok_standin\r\n\r\n",
		"CONNECT in origin-form":     "CONNECT /echo?q=tok_standin HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"lower-case connect":         "connect allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n",
		"upgrade to h2c":             "GET /echo?q=tok_standin HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
		"websocket or h2c":           "GET /socket HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: websocket, h2c\r\n\r\n",
		"websocket, then another":    "GET /socket HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: TLS/1.2\r\n\r\n",
		"upgrade naming no protocol": "GET /socket HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: ,\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client, clientReader, _, serverReader, result := pipesWith(t, options(t))
			go func() { _, _ = io.WriteString(client, request) }()
			refused, err := http.ReadResponse(clientReader, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(refused.Body)
			_ = refused.Body.Close()
			if refused.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "request refused") {
				t.Fatalf("refusal %d %q", refused.StatusCode, body)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("relay error %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay kept the connection open")
			}
			if b, err := serverReader.ReadByte(); err == nil {
				t.Fatalf("server received data starting with %q", b)
			}
		})
	}
}

// A WebSocket upgrade is recognized whatever the case of its token, and its
// handshake is swapped like any request.
func TestWebSocketUpgradeIsSwapped(t *testing.T) {
	client, _, _, serverReader := pipes(t)
	send(t, client, "GET /socket?key=tok_standin HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n")
	if head := readHead(t, serverReader); !strings.HasPrefix(head, "GET /socket?key=real ") {
		t.Fatalf("server got %q", head)
	}
}

// Responses are passed on byte for byte whatever their framing, and each
// is matched to its request (a HEAD response has no body).
func TestResponsesAreFramedAndCopiedExactly(t *testing.T) {
	client, clientReader, server, serverReader := pipes(t)
	exchanges := []struct{ request, response string }{
		{"HEAD /a HTTP/1.1\r\nHost: allowed.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"},
		{"GET /b HTTP/1.1\r\nHost: allowed.test\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nabcd\r\n0\r\nX-Trailer: t\r\n\r\n"},
		{"GET /c HTTP/1.1\r\nHost: allowed.test\r\n\r\n", "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"},
		{"GET /d HTTP/1.1\r\nHost: allowed.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
	}
	for _, ex := range exchanges {
		send(t, client, ex.request)
		readHead(t, serverReader)
		send(t, server, ex.response)
		got := make([]byte, len(ex.response))
		if _, err := io.ReadFull(clientReader, got); err != nil || string(got) != ex.response {
			t.Fatalf("client got %q, %v; want %q", got, err, ex.response)
		}
	}
}

// The relay's own 100 Continue for an upload pipelined behind another
// request goes out after that request's response, never inside it.
func TestLocalContinueWaitsForEarlierResponses(t *testing.T) {
	client, clientReader, server, serverReader := pipes(t)
	send(t, client, "GET /a HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	readHead(t, serverReader)
	send(t, server, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234")
	readHead(t, clientReader)
	first := make([]byte, 5)
	if _, err := io.ReadFull(clientReader, first); err != nil || string(first) != "01234" {
		t.Fatalf("first half %q, %v", first, err)
	}
	// Pipelined upload while the rest of /a is still on its way.
	send(t, client, "POST /b HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 11\r\nExpect: 100-continue\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	send(t, server, "56789")
	rest := make([]byte, 5)
	if _, err := io.ReadFull(clientReader, rest); err != nil || string(rest) != "56789" {
		t.Fatalf("the rest of the first response arrived as %q (%v): the 100 Continue landed inside it", rest, err)
	}
	if head := readHead(t, clientReader); head != "HTTP/1.1 100 Continue\r\n\r\n" {
		t.Fatalf("after the first response the client got %q", head)
	}
	send(t, client, "tok_standin")
	if head := readHead(t, serverReader); !strings.HasPrefix(head, "POST /b ") {
		t.Fatalf("server got %q", head)
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(serverReader, body); err != nil || string(body) != "real" {
		t.Fatalf("server body %q, %v", body, err)
	}
}

func expandingOptions(t *testing.T, real string) Options {
	t.Helper()
	o := options(t)
	o.Session, o.MaxBody = scopetest.Static(t, o.Hosts, map[string]string{"t1": real}), 1000
	return o
}

// Swaps that would grow a request past its limits, or put a line break in a
// header, end the connection before anything reaches the server.
func TestSwapLimitsEndTheConnection(t *testing.T) {
	long := strings.Repeat("R", 200)
	cases := []struct {
		name, real, request string
		want                error
	}{
		{"body", long, "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 800\r\n\r\n" + strings.Repeat("t1", 400), swap.ErrTooLarge},
		{"header", strings.Repeat("R", 2000), "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-Token: " + strings.Repeat("t1", 1000) + "\r\n\r\n", swap.ErrTooLarge},
		{"target", strings.Repeat("R", 2000), "GET /?q=" + strings.Repeat("t1", 1000) + " HTTP/1.1\r\nHost: allowed.test\r\n\r\n", swap.ErrTooLarge},
		{"line break", "a\r\nX-Injected: 1", "GET / HTTP/1.1\r\nHost: allowed.test\r\nAuthorization: Bearer t1\r\n\r\n", swap.ErrUnsafeHeader},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, _, _, serverReader, result := pipesWith(t, expandingOptions(t, c.real))
			go func() { _, _ = io.WriteString(client, c.request) }()
			select {
			case err := <-result:
				if !errors.Is(err, c.want) {
					t.Fatalf("relay error %v, want %v", err, c.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay kept going")
			}
			if b, err := serverReader.ReadByte(); err == nil {
				t.Fatalf("server received data starting with %q", b)
			}
		})
	}
}

// Framing headers are not swapped: a stand-in equal to the Content-Length
// leaves it alone, so the body and the next request keep their boundaries.
func TestFramingHeadersAreNotSwapped(t *testing.T) {
	o := options(t)
	o.Session = scopetest.Static(t, o.Hosts, map[string]string{"123": "456"})
	client, _, _, serverReader, _ := pipesWith(t, o)
	body := strings.Repeat("x", 123)
	go func() {
		_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 123\r\nX-Code: 123\r\n\r\n"+body)
	}()
	want := "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 123\r\nX-Code: 456\r\n\r\n"
	if head := readHead(t, serverReader); head != want {
		t.Fatalf("server got %q, want %q", head, want)
	}
	got := make([]byte, 123)
	if _, err := io.ReadFull(serverReader, got); err != nil || string(got) != body {
		t.Fatalf("server body %q, %v", got, err)
	}
}
