package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// maskingSetup is a proxy with masking on whose principal alice has the
// value of standIn on record once a request carried it.
func maskingSetup(t *testing.T, proto string, handler func(*tls.Conn), values map[string]string, configure ...func(*Config)) *testProxy {
	t.Helper()
	dest := startDestination(t, allowedHost, []string{proto}, handler)
	return startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		r, err := resolve.NewStatic(values)
		if err != nil {
			t.Fatal(err)
		}
		d, err := resolve.NewDetector(r, resolve.Patterns{})
		if err != nil {
			t.Fatal(err)
		}
		c.Resolver, c.Detector, c.MaskResponses = r, d, true
		for _, f := range configure {
			f(c)
		}
	})
}

func deflate(t *testing.T, plain string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = io.WriteString(w, plain)
	_ = w.Close()
	return b.Bytes()
}

// A compressed body ends with its HTTP framing, not with the decoder: the
// trailers sent after it, late, still arrive (masked), and the next
// response on the connection is intact.
func TestCompressedResponsesEndWithTheirFraming(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		received := &echoed{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if r.URL.Path == "/next" {
				_, _ = io.WriteString(w, "next "+string(body))
				return
			}
			w.Header().Set("Trailer", "X-Sum")
			w.Header().Set("Content-Encoding", "deflate")
			_, _ = w.Write(deflate(t, "echo "+string(body)))
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("X-Sum", string(body))
		})
		p := maskingSetup(t, proto, serveWith(received, handler), map[string]string{"tok_alice": "real_alice"})
		c := clientTo(t, p, proto, allowedHost)
		c.Transport.(*http.Transport).DisableCompression = true
		c.Transport.(*http.Transport).DisableKeepAlives = false
		for _, path := range []string{"/z", "/next"} {
			resp, err := c.Post("https://"+allowedHost+path, "text/plain", strings.NewReader("tok_alice"))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			switch path {
			case "/z":
				if string(body) != "echo tok_alice" || resp.Trailer.Get("X-Sum") != "tok_alice" {
					t.Fatalf("body %q, trailer %q", body, resp.Trailer.Get("X-Sum"))
				}
			default:
				if string(body) != "next tok_alice" {
					t.Fatalf("next response %q", body)
				}
			}
		}
		if !strings.Contains(received.all(), "real_alice") {
			t.Fatalf("destination did not get the real value: %s", received.all())
		}
	})
}

// A stand-in that needs escaping is escaped for where the echoed value sits:
// the JSON body stays valid JSON, the redirect keeps its parameters.
func TestMaskedReplacementsAreEscapedForTheirContext(t *testing.T) {
	const standIn = `tok_"q&x=1`
	protos(t, func(t *testing.T, proto string) {
		received := &echoed{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			w.Header().Set("Location", "/done?token="+in["token"]+"&n=1")
			w.Header().Set("Content-Type", "application/json")
			out, _ := json.Marshal(map[string]string{"echo": in["token"]})
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write(out)
		})
		p := maskingSetup(t, proto, serveWith(received, handler), map[string]string{standIn: "abcdefgh12"})
		c := clientTo(t, p, proto, allowedHost)
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		// Without HTML escaping: the request side swaps the stand-in's
		// plain JSON form.
		var reqBody bytes.Buffer
		enc := json.NewEncoder(&reqBody)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{"token": standIn})
		resp, err := c.Post("https://"+allowedHost+"/j", "application/json", &reqBody)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var out map[string]string
		if err := json.Unmarshal(body, &out); err != nil || out["echo"] != standIn {
			t.Fatalf("masked body %q is not the JSON of the stand-in: %v", body, err)
		}
		loc := resp.Header.Get("Location")
		if loc != "/done?token=tok_%22q%26x%3D1&n=1" {
			t.Fatalf("Location %q", loc)
		}
		if !strings.Contains(received.all(), "abcdefgh12") {
			t.Fatalf("destination did not get the real value: %s", received.all())
		}
	})
}

// Several content-codings, in one list or in repeated headers, cannot be
// decoded: the response is refused, never passed through compressed.
func TestStackedCodingsAreRefused(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if r.URL.Path == "/list" {
				w.Header().Set("Content-Encoding", "identity, gzip, gzip")
			} else {
				w.Header()["Content-Encoding"] = []string{"gzip", "gzip"}
			}
			var b bytes.Buffer
			z := gzip.NewWriter(&b)
			_, _ = io.WriteString(z, "real_alice")
			_ = z.Close()
			_, _ = w.Write(b.Bytes())
		})
		p := maskingSetup(t, proto, serveWith(&echoed{}, handler), map[string]string{"tok_alice": "real_alice"})
		c := clientTo(t, p, proto, allowedHost)
		c.Transport.(*http.Transport).DisableCompression = true
		for _, path := range []string{"/list", "/repeated"} {
			if got := do(t, c, http.MethodPost, "https://"+allowedHost+path, "c=tok_alice"); got != http.StatusBadGateway {
				t.Fatalf("%s: %d, want 502", path, got)
			}
		}
	})
}

// rawDestination answers the first request on each connection with
// response, after reading the request head and body.
func rawDestination(response func(head string) string, after func(c *tls.Conn)) func(*tls.Conn) {
	return func(c *tls.Conn) {
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		if _, err := io.WriteString(c, response(string(body))); err != nil {
			return
		}
		if after != nil {
			after(c)
		}
	}
}

// A folded Content-Encoding (obs-fold), which a client may unfold into a
// coding the proxy did not see, is refused: the compressed real value never
// reaches the client.
func TestFoldedHeadersAreRefused(t *testing.T) {
	var gz bytes.Buffer
	z := gzip.NewWriter(&gz)
	_, _ = io.WriteString(z, "secret real_alice")
	_ = z.Close()
	p := maskingSetup(t, "http/1.1", rawDestination(func(string) string {
		return "HTTP/1.1 200 OK\r\nContent-Encoding:\r\n gzip\r\nContent-Length: " + strconv.Itoa(gz.Len()) + "\r\n\r\n" + gz.String()
	}, nil), map[string]string{"tok_alice": "real_alice"})
	c := clientTo(t, p, "http/1.1", allowedHost)
	c.Transport.(*http.Transport).DisableCompression = true
	if got := do(t, c, http.MethodPost, "https://"+allowedHost+"/f", "c=tok_alice"); got != http.StatusBadGateway {
		t.Fatalf("folded coding: %d, want 502", got)
	}
}

// An accepted HTTP/1.1 upgrade carries WebSocket frames, passed through
// byte for byte both ways, even with a value on record in them.
func TestWebSocketFramesPassThroughUntouched(t *testing.T) {
	frame := "\x81\x0areal_alice" // a text frame holding the real value
	p := maskingSetup(t, "http/1.1", rawDestination(func(string) string {
		return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + frame
	}, func(c *tls.Conn) {
		_, _ = io.Copy(c, c) // echo what the client sends
	}), map[string]string{"tok_alice": "real_alice"})
	// The upgrade request carries the stand-in, so its value is on record
	// before the 101 arrives.
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConn, "GET /ws HTTP/1.1\r\nHost: "+allowedHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 9\r\n\r\ntok_alice"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tlsConn)
	head, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = head.Body.Close() // a 101 has no body: the frames follow on br
	if head.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", head.StatusCode)
	}
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != frame {
		t.Fatalf("client got frame %q, %v; want it untouched", got, err)
	}
	if _, err := io.WriteString(tlsConn, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(br, got); err != nil || string(got) != frame {
		t.Fatalf("echoed frame %q, %v", got, err)
	}
}

// A refused upgrade (a WebSocket handshake answered 403) is an ordinary
// response: a value its body echoes is masked.
func TestRefusedUpgradeBodyIsMasked(t *testing.T) {
	p := maskingSetup(t, "http/1.1", func(c *tls.Conn) {
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body := "denied for " + req.Header.Get("X-Token")
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}, map[string]string{"tok_alice": "real_alice"})
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tlsConn, "GET /ws HTTP/1.1\r\nHost: "+allowedHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Token: tok_alice\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	got, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if got.StatusCode != http.StatusForbidden || string(body) != "denied for tok_alice" {
		t.Fatalf("client got %d %q", got.StatusCode, body)
	}
}

// Transfer-codings are read from every Transfer-Encoding header: gzip in one
// header and chunked in another is not plain chunked, and is refused, never
// passed on with a gzip-coded real value.
func TestRepeatedTransferEncodingsAreRefused(t *testing.T) {
	var gz bytes.Buffer
	z := gzip.NewWriter(&gz)
	_, _ = io.WriteString(z, "secret real_alice")
	_ = z.Close()
	for name, headers := range map[string]string{
		"repeated":      "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
		"list":          "Transfer-Encoding: gzip, chunked\r\n",
		"chunked twice": "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := maskingSetup(t, "http/1.1", rawDestination(func(string) string {
				return "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + strconv.FormatInt(int64(gz.Len()), 16) + "\r\n" + gz.String() + "\r\n0\r\n\r\n"
			}, nil), map[string]string{"tok_alice": "real_alice"})
			conn, resp := connect(t, p.addr, allowedHost+":443", "")
			_ = resp.Body.Close()
			tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"http/1.1"}})
			if err := tlsConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(tlsConn, "POST /t HTTP/1.1\r\nHost: "+allowedHost+"\r\nContent-Length: 11\r\n\r\nc=tok_alice"); err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(tlsConn)
			if !bytes.HasPrefix(got, []byte("HTTP/1.1 502 ")) || bytes.Contains(got, gz.Bytes()[:10]) {
				t.Fatalf("client got %q", got)
			}
		})
	}
}
