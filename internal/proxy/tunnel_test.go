package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/h2relay"
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
	return interceptedConnWith(t, p, "http/1.1")
}

// interceptedConnWith opens a connection through the proxy to allowedHost
// that negotiates proto.
func interceptedConnWith(t *testing.T, p *testProxy, proto string) *tls.Conn {
	t.Helper()
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{proto}})
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

// h2Echo is an HTTP/2 destination that supports extended CONNECT (it sends
// SETTINGS_ENABLE_CONNECT_PROTOCOL = 1) and answers every request, an
// extended CONNECT for a WebSocket included, with 200 and its :path, as a
// catch-all handler does. It records each :path it gets.
func h2Echo(received *echoed) func(*tls.Conn) {
	return func(c *tls.Conn) {
		if _, err := io.ReadFull(c, make([]byte, len(h2relay.Preface))); err != nil {
			return
		}
		enable := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint16(nil, h2relay.SettingEnableConnectProtocol), 1)
		if _, err := c.Write(h2relay.AppendFrame(nil, h2relay.FrameSettings, 0, 0, enable)); err != nil {
			return
		}
		dec := hpack.NewDecoder(4096, nil)
		var block bytes.Buffer
		enc := hpack.NewEncoder(&block)
		for {
			f, err := h2relay.ReadFrame(c)
			if err != nil {
				return
			}
			var out []byte
			switch {
			case f.Type == h2relay.FrameSettings && f.Flags&h2relay.FlagAck == 0:
				out = h2relay.AppendFrame(nil, h2relay.FrameSettings, h2relay.FlagAck, 0, nil)
			case f.Type == h2relay.FrameHeaders:
				_, fragment, err := h2relay.HeadersPayload(f.Flags, f.Payload)
				if err != nil {
					return
				}
				fields, err := dec.DecodeFull(fragment)
				if err != nil {
					return
				}
				path := ""
				for _, field := range fields {
					if field.Name == ":path" {
						path = field.Value
					}
				}
				received.mu.Lock()
				received.requests = append(received.requests, path)
				received.mu.Unlock()
				block.Reset()
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				out = h2relay.AppendFrame(nil, h2relay.FrameHeaders, h2relay.FlagEndHeaders, f.Stream, block.Bytes())
				out = h2relay.AppendFrame(out, h2relay.FrameData, h2relay.FlagEndStream, f.Stream, []byte("you sent "+path))
			}
			if _, err := c.Write(out); err != nil {
				return
			}
		}
	}
}

// Over HTTP/2 the proxy opens no WebSocket. The client never learns that the
// destination supports extended CONNECT, so a browser opens its WebSockets
// over HTTP/1.1 (RFC 8441 section 3: no extended CONNECT without the
// setting), where only a 101 opens one. An extended CONNECT for a WebSocket
// sent anyway is answered 502 and never reaches the destination. Before, the
// relay swapped it, and the destination's 200, which any catch-all handler
// sends, opened a stream whose DATA passed through unmasked: the echoed real
// value reached the client.
func TestH2WebSocketConnectIsRefused(t *testing.T) {
	received := &echoed{}
	p := maskingSetup(t, "h2", h2Echo(received), map[string]string{"tok_alice": "real_alice_secret"})
	c := interceptedConnWith(t, p, "h2")
	var out bytes.Buffer
	enc := hpack.NewEncoder(&out)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":protocol", Value: "websocket"}, {Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/chat?q=tok_alice"}, {Name: ":authority", Value: allowedHost}, {Name: "sec-websocket-version", Value: "13"},
	} {
		_ = enc.WriteField(f)
	}
	request := append([]byte(h2relay.Preface), h2relay.AppendFrame(nil, h2relay.FrameSettings, 0, 0, nil)...)
	request = h2relay.AppendFrame(request, h2relay.FrameHeaders, h2relay.FlagEndHeaders, 1, out.Bytes())
	if _, err := c.Write(request); err != nil {
		t.Fatal(err)
	}
	dec := hpack.NewDecoder(4096, nil)
	sawSettings := false
	for {
		f, err := h2relay.ReadFrame(c)
		if err != nil {
			t.Fatalf("no response to the extended CONNECT: %v", err)
		}
		if bytes.Contains(f.Payload, []byte("real_alice_secret")) {
			t.Fatalf("client got the real value in a frame of type %d", f.Type)
		}
		if f.Type == h2relay.FrameSettings && f.Flags&h2relay.FlagAck == 0 {
			settings, err := h2relay.ParseSettings(f.Payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range settings {
				if s.ID == h2relay.SettingEnableConnectProtocol {
					t.Fatalf("client got SETTINGS_ENABLE_CONNECT_PROTOCOL = %d", s.Value)
				}
			}
			sawSettings = true
		}
		if f.Type != h2relay.FrameHeaders || f.Stream != 1 {
			continue
		}
		_, fragment, err := h2relay.HeadersPayload(f.Flags, f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := dec.DecodeFull(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if !sawSettings || len(fields) == 0 || fields[0].Name != ":status" || fields[0].Value != "502" {
			t.Fatalf("client got %v, SETTINGS first %v; want 502 after the destination's SETTINGS", fields, sawSettings)
		}
		break
	}
	if r := received.all(); r != "" {
		t.Fatalf("destination received %q", r)
	}
}
