package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// methodEcho answers every method, CONNECT included, with 200 and what the
// request carried, as a catch-all net/http handler does.
var methodEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, "method "+r.Method+" token "+r.Header.Get("X-Token")+" q "+r.URL.Query().Get("q"))
})

// interceptedConn opens an HTTP/1.1 connection through the proxy to
// allowedHost.
func interceptedConn(t *testing.T, p *testProxy) *tls.Conn {
	t.Helper()
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	return tlsConn
}

// A CONNECT inside an intercepted HTTP/1.1 connection is answered 502 and
// never reaches the destination. Before, a destination that answered it 200,
// as any catch-all handler does, had its answer and the rest of the
// connection passed to the client raw: the swapped real value came back
// unmasked.
func TestConnectInsideAnInterceptedConnectionIsRefused(t *testing.T) {
	for name, request := range map[string]string{
		"authority-form": "CONNECT " + allowedHost + ":443 HTTP/1.1\r\nHost: " + allowedHost + ":443\r\nX-Token: tok_alice\r\n\r\n",
		"origin-form":    "CONNECT /echo?q=tok_alice HTTP/1.1\r\nHost: " + allowedHost + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			received := &echoed{}
			p := maskingSetup(t, "http/1.1", serveWith(received, methodEcho), map[string]string{"tok_alice": "real_alice_secret"})
			tlsConn := interceptedConn(t, p)
			if _, err := io.WriteString(tlsConn, request); err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(tlsConn)
			if !strings.HasPrefix(string(got), "HTTP/1.1 502 ") || strings.Contains(string(got), "real_alice_secret") {
				t.Fatalf("client got %q", got)
			}
			if r := received.all(); r != "" {
				t.Fatalf("destination received %q", r)
			}
		})
	}
}

// Over HTTP/2 a plain CONNECT is refused the same way; an ordinary request
// on the connection still goes through, its echo masked.
func TestPlainH2ConnectIsRefused(t *testing.T) {
	received := &echoed{}
	p := maskingSetup(t, "h2", serveWith(received, methodEcho), map[string]string{"tok_alice": "real_alice_secret"})
	c := clientTo(t, p, "h2", allowedHost)
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		req, err := http.NewRequest(method, "https://"+allowedHost+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodConnect {
			req.URL.Path = "" // a plain CONNECT: :method and :authority only
		}
		req.Header.Set("X-Token", "tok_alice")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(body), "real_alice_secret") {
			t.Fatalf("%s: client got %d %q", method, resp.StatusCode, body)
		}
		want := http.StatusOK
		if method == http.MethodConnect {
			want = http.StatusBadGateway
		}
		if resp.StatusCode != want {
			t.Fatalf("%s: client got %d %q, want %d", method, resp.StatusCode, body, want)
		}
	}
	if r := received.all(); r == "" || strings.Contains(r, "\n") {
		t.Fatalf("destination received %q, want the GET only", r)
	}
}

// An HTTP/1.1 upgrade to anything but a WebSocket is answered 502 and never
// reaches the destination. Before, a destination that accepts h2c over TLS
// (Go's h2c handler does) answered the swapped upgrade request itself after
// its 101, as HTTP/2 the client read raw: the real value came back unmasked,
// and the client then had a whole HTTP/2 connection to the destination
// without masking. The destination here stands in for one: after its 101 it
// echoes the request's query in plain bytes.
func TestH2CUpgradeIsRefused(t *testing.T) {
	received := &echoed{}
	p := maskingSetup(t, "http/1.1", func(c *tls.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		received.mu.Lock()
		received.requests = append(received.requests, req.URL.RequestURI())
		received.mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"+
			"you sent "+req.URL.Query().Get("q"))
	}, map[string]string{"tok_alice": "real_alice_secret"})
	tlsConn := interceptedConn(t, p)
	request := "GET /echo?q=tok_alice HTTP/1.1\r\nHost: " + allowedHost + "\r\n" +
		"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(tlsConn)
	if !strings.HasPrefix(string(got), "HTTP/1.1 502 ") || strings.Contains(string(got), "real_alice_secret") {
		t.Fatalf("client got %q", got)
	}
	if r := received.all(); r != "" {
		t.Fatalf("destination received %q", r)
	}
}
