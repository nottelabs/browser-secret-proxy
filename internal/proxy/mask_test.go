package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// echoingDestination answers each request with what it received, in its
// body, a Location header and a cookie, compressed with the coding named by
// the "enc" query parameter.
func echoingDestination() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		echo := "you sent " + string(body) + " " + strings.Repeat("padding ", 5000)
		w.Header().Set("Location", "/receipt?"+string(body))
		w.Header().Set("Set-Cookie", "last="+string(body))
		var b bytes.Buffer
		var enc io.WriteCloser
		switch coding := r.URL.Query().Get("enc"); coding {
		case "gzip":
			enc = gzip.NewWriter(&b)
		case "br":
			enc = brotli.NewWriter(&b)
		case "zstd":
			enc, _ = zstd.NewWriter(&b)
		}
		if enc == nil {
			_, _ = io.WriteString(w, echo)
			return
		}
		_, _ = io.WriteString(enc, echo)
		_ = enc.Close()
		w.Header().Set("Content-Encoding", r.URL.Query().Get("enc"))
		_, _ = w.Write(b.Bytes())
	})
}

// A destination echoing the real value back returns it to the client as its
// stand-in, in the body and headers, compressed or not, over HTTP/1.1 and
// HTTP/2; with masking off the real value comes back.
func TestEchoedValuesAreMasked(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		for _, masking := range []bool{true, false} {
			name := proto
			if !masking {
				name += " masking off"
			}
			t.Run(name, func(t *testing.T) {
				received := &echoed{}
				dest := startDestination(t, allowedHost, []string{proto}, serveWith(received, echoingDestination()))
				p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
					r := scopedAccounts()
					d, err := resolve.NewDetector(r, resolve.Patterns{})
					if err != nil {
						t.Fatal(err)
					}
					c.Resolver, c.Detector, c.MaskResponses = r, d, masking
				})
				client := proxiedClient(t, p, "alice", "alice-pw", proto)
				client.Transport.(*http.Transport).DisableCompression = true
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				for _, coding := range []string{"", "gzip", "br", "zstd"} {
					req, err := http.NewRequest(http.MethodPost, "https://"+allowedHost+"/echo?enc="+coding, strings.NewReader("card=tok_alice"))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if !masking {
						if coding == "" && !strings.Contains(string(body), "real_alice") {
							t.Fatalf("with masking off the echo is unchanged: %.80q", body)
						}
						continue
					}
					if !strings.HasPrefix(string(body), "you sent card=tok_alice ") || bytes.Contains(body, []byte("real_alice")) {
						t.Fatalf("%q: body %.80q", coding, body)
					}
					if resp.Header.Get("Content-Encoding") != "" {
						t.Fatalf("%q: content-encoding %q kept on a decoded body", coding, resp.Header.Get("Content-Encoding"))
					}
					if resp.Header.Get("Location") != "/receipt?card=tok_alice" || resp.Header.Get("Set-Cookie") != "last=card=tok_alice" {
						t.Fatalf("%q: headers %v", coding, resp.Header)
					}
				}
				if !strings.Contains(received.all(), "card=real_alice") {
					t.Fatalf("destination did not get the real value: %s", received.all())
				}
			})
		}
	}
}
