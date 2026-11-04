package h1relay

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// A request whose body a server could frame differently from the relay, or
// whose head a server could split into other lines, is answered 502 and
// nothing of it reaches the server (RFC 9112 2.2, 5, 6.1, 6.3). Otherwise the
// bytes the relay swapped as body could reach the server as another request,
// one whose Host was never checked.
func TestAmbiguousFramingIsAnswered502(t *testing.T) {
	for name, request := range map[string]string{
		"Transfer-Encoding and Content-Length":         "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\nd\r\nx=tok_standin\r\n0\r\n\r\n",
		"Content-Length and Transfer-Encoding":         "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"two Transfer-Encoding headers":                "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n",
		"chunked twice":                                "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"a coding containing chunked":                  "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: xchunked\r\n\r\n1\r\na\r\n0\r\n\r\n",
		"a list of codings":                            "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"chunked, not last":                            "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
		"another coding":                               "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: identity\r\nContent-Length: 4\r\n\r\nabcd",
		"Transfer-Encoding over HTTP/1.0":              "POST / HTTP/1.0\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"Transfer-Encoding over HTTP/1.0 with a space": "POST / HTTP/1.0 \r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"chunked followed by a VT":                     "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\x0b\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"chunked after a FF":                           "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding:\x0cchunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"chunked after a VT":                           "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding:\x0bchunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"chunked followed by a NEL":                    "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\u0085\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"chunked followed by a NBSP":                   "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\u00a0\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"chunked with a Kelvin sign":                   "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chun\u212aed\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"two differing Content-Length":                 "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nContent-Length: 4\r\n\r\nabcd",
		"two Content-Length, the first zero":           "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\nabcd",
		"two Content-Length that agree":                "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd",
		"a Content-Length list":                        "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4, 4\r\n\r\nabcd",
		"a signed Content-Length":                      "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: +4\r\n\r\nabcd",
		"an empty Content-Length":                      "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length:\r\n\r\n",
		"a Content-Length followed by a VT":            "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\x0b\r\n\r\nabcd",
		"a Content-Length after a FF":                  "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length:\x0c4\r\n\r\nabcd",
		"a folded header line":                         "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\r\n b\r\n\r\n",
		"a folded line with a tab":                     "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\r\n\tHost: evil.test\r\n\r\n",
		"space before the colon":                       "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
		"an empty header name":                         "GET / HTTP/1.1\r\nHost: allowed.test\r\n: a\r\n\r\n",
		"a line without a colon":                       "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A\r\n\r\n",
		"a bare CR in a header value":                  "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\rHost: evil.test\r\n\r\n",
		"a bare CR in a header name":                   "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A\r: a\r\n\r\n",
		"a NUL in a header value":                      "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: tok_standin\x00\r\n\r\n",
		"a bare CR in the request line":                "GET /\rHost: evil.test HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"a NUL in the request line":                    "GET /\x00 HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"a VT after the Host":                          "GET / HTTP/1.1\r\nHost: allowed.test\x0b\r\n\r\n",
		"a FF before the Host":                         "GET / HTTP/1.1\r\nHost:\x0callowed.test\r\n\r\n",
		"a NBSP after the Host":                        "GET / HTTP/1.1\r\nHost: allowed.test\u00a0\r\n\r\n",
		"a NEL after the Host":                         "GET / HTTP/1.1\r\nHost: allowed.test\u0085\r\n\r\n",
		"a control character in a header value":        "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\x01b\r\n\r\n",
		"an ESC in a header value":                     "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: \x1b[0m\r\n\r\n",
		"a DEL in a header value":                      "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\x7f\r\n\r\n",
		"a header name that is not a token":            "GET / HTTP/1.1\r\nHost: allowed.test\r\nX(A): a\r\n\r\n",
		"a non-ASCII header name":                      "GET / HTTP/1.1\r\nHost: allowed.test\r\nHost\u00a0: evil.test\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, options(t), request)
		})
	}
}

// A bare CR or NUL that the client put in a header cannot open the way for
// a real value holding a line break: the request is refused before any
// swap.
func TestControlCharactersDoNotLetALineBreakIntoAHeader(t *testing.T) {
	o := options(t)
	o.Session = scopetest.Static(t, o.Hosts, map[string]string{"tok_standin": "line1\r\nInjected: yes"})
	for name, request := range map[string]string{
		"bare CR": "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: \rtok_standin\r\n\r\n",
		"NUL":     "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: \x00tok_standin\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			assertRefused(t, o, request)
		})
	}
}

// assertRefused sends request and checks that it is answered 502, that the
// relay ends the connection, and that nothing reaches the server.
func assertRefused(t *testing.T, o Options, request string) {
	t.Helper()
	client, clientReader, _, serverReader, result := pipesWith(t, o)
	go func() { _, _ = io.WriteString(client, request) }()
	refused, err := http.ReadResponse(clientReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(refused.Body)
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "request refused") || strings.Contains(string(body), "line1") {
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
}

// A trailer line a server could split or unfold ends the connection before
// anything of its request is sent.
func TestMalformedTrailersEndTheConnection(t *testing.T) {
	for name, trailer := range map[string]string{
		"bare CR":                "X-T: a\rX-U: b\r\n",
		"NUL":                    "X-T: a\x00\r\n",
		"folded line":            "X-T: a\r\n b\r\n",
		"no colon":               "X-T\r\n",
		"space before the colon": "X-T : a\r\n",
		"VT in a value":          "X-T: a\x0b\r\n",
		"DEL in a value":         "X-T: a\x7f\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client, _, _, serverReader, result := pipesWith(t, options(t))
			go func() {
				_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"+trailer+"\r\n")
			}()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "malformed trailer line") {
					t.Fatalf("relay error %v", err)
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

// A chunked request is still swapped and sent chunked, with its trailers;
// the coding name is case-insensitive (RFC 9112 7).
func TestChunkedRequestIsSwapped(t *testing.T) {
	client, _, _, serverReader := pipes(t)
	send(t, client, "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: Chunked\r\n\r\n"+
		"4\r\nx=to\r\n9\r\nk_standin\r\n0\r\nX-Trailer: t\r\n\r\n")
	want := "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: Chunked\r\n\r\n"
	if head := readHead(t, serverReader); head != want {
		t.Fatalf("server got %q, want %q", head, want)
	}
	wantBody := "6\r\nx=real\r\n0\r\nX-Trailer: t\r\n\r\n"
	body := make([]byte, len(wantBody))
	if _, err := io.ReadFull(serverReader, body); err != nil || string(body) != wantBody {
		t.Fatalf("server body %q, %v; want %q", body, err, wantBody)
	}
}

// SP and HTAB around a Transfer-Encoding or Content-Length value are
// whitespace (RFC 9110 5.6.3), so the request is sent as it came.
func TestWhitespaceAroundFramingValuesIsAccepted(t *testing.T) {
	for name, request := range map[string]string{
		"Transfer-Encoding": "POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding:\t chunked \t\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"Content-Length":    "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length:\t 3 \t\r\n\r\nabc",
	} {
		t.Run(name, func(t *testing.T) {
			client, _, _, serverReader := pipes(t)
			send(t, client, request)
			got := make([]byte, len(request))
			if _, err := io.ReadFull(serverReader, got); err != nil || string(got) != request {
				t.Fatalf("server got %q, %v; want %q", got, err, request)
			}
		})
	}
}

// Tabs and text that is not ASCII stay allowed inside a header value (RFC
// 9110 5.5), so such a request is sent as it came.
func TestTabsAndNonASCIIInHeaderValuesAreAccepted(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: a\tb caf\u00e9\r\n\r\n"
	client, _, _, serverReader := pipes(t)
	send(t, client, request)
	if head := readHead(t, serverReader); head != request {
		t.Fatalf("server got %q, want %q", head, request)
	}
}

// A response head that a client could split or unfold into other lines
// than the relay reads, or whose framing it could read differently, is
// answered 502, masked or not: the relay follows each response's framing to
// know where the next one, which it may have to mask, begins (RFC 9112 5,
// 6.3).
func TestUnclearResponseHeadsAreAnswered502(t *testing.T) {
	for name, head := range map[string]string{
		"a folded header line":                 "HTTP/1.1 200 OK\r\nX-A: a\r\n Content-Length: 2\r\n",
		"a folded line with a tab":             "HTTP/1.1 200 OK\r\nX-A: a\r\n\tContent-Length: 2\r\n",
		"space before the colon":               "HTTP/1.1 200 OK\r\nContent-Length : 2\r\n",
		"a tab before the colon":               "HTTP/1.1 200 OK\r\nContent-Length\t: 2\r\n",
		"a header name that is not a token":    "HTTP/1.1 200 OK\r\nX(A): a\r\nContent-Length: 2\r\n",
		"an empty header name":                 "HTTP/1.1 200 OK\r\n: a\r\nContent-Length: 2\r\n",
		"a line without a colon":               "HTTP/1.1 200 OK\r\nX-A\r\nContent-Length: 2\r\n",
		"a bare CR in a header line":           "HTTP/1.1 200 OK\r\nX-A: a\rContent-Length: 2\r\n",
		"a NUL in a header line":               "HTTP/1.1 200 OK\r\nX-A: a\x00\r\nContent-Length: 2\r\n",
		"a signed Content-Length":              "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n",
		"a Content-Length followed by a VT":    "HTTP/1.1 200 OK\r\nContent-Length: 2\x0b\r\n",
		"a Content-Length followed by a NBSP":  "HTTP/1.1 200 OK\r\nContent-Length: 2\u00a0\r\n",
		"a folded line in an interim response": "HTTP/1.1 100 Continue\r\nX-A: a\r\n b\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n",
		"a CR before the empty line":           "HTTP/1.1 200 OK\r\nX-A: a\r\nContent-Length: 2\r\n\r",
		"a bare CR in the status line":         "HTTP/1.1 200 OK\rTransfer-Encoding: chunked\r\nContent-Length: 2\r\nX-A: a\r\n",
		"a NUL in the status line":             "HTTP/1.1 200 OK\x00\r\nX-A: a\r\nContent-Length: 2\r\n",
	} {
		for _, masked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, masked %t", name, masked), func(t *testing.T) {
				o := options(t)
				if masked {
					o = maskedOptions(t, true)
				}
				got := rawRoundTrip(t, o, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n", head+"\r\nok")
				if !strings.HasPrefix(got, "HTTP/1.1 502 ") || strings.Contains(got, "X-A") || strings.Contains(got, "ok") {
					t.Fatalf("client got %q", got)
				}
			})
		}
	}
}

// Only SP and HTAB surround a response's framing values, and the coding
// name chunked is matched in ASCII only, as a client matches it.
func TestResponseFramingValues(t *testing.T) {
	for name, tc := range map[string]struct {
		head    string
		length  int64
		chunked bool
	}{
		"Content-Length with tabs":       {"Content-Length:\t 2 \t", 2, false},
		"chunked with tabs":              {"Transfer-Encoding:\t chunked \t", -1, true},
		"chunked last in a list":         {"Transfer-Encoding: gzip, Chunked", -1, true},
		"chunked with a Kelvin sign":     {"Transfer-Encoding: chun\u212aed", -1, false},
		"chunked followed by a NBSP":     {"Transfer-Encoding: chunked\u00a0", -1, false},
		"chunked followed by a VT":       {"Transfer-Encoding: chunked\x0b", -1, false},
		"chunked after a FF in the list": {"Transfer-Encoding: gzip,\x0cchunked", -1, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, length, chunked, err := readResponseHead(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\n" + tc.head + "\r\n\r\n")))
			if err != nil || length != tc.length || chunked != tc.chunked {
				t.Fatalf("length %d, chunked %t, %v; want %d, %t", length, chunked, err, tc.length, tc.chunked)
			}
		})
	}
}

// A response trailer line that a client could read differently ends the
// connection, masked or not, before it is passed on: the response is left
// unfinished.
func TestUnclearResponseTrailersEndTheConnection(t *testing.T) {
	for name, trailer := range map[string]string{
		"space before the colon":     "X-T : a\r\n",
		"bare CR":                    "X-T: a\rX-U: b\r\n",
		"NUL":                        "X-T: a\x00\r\n",
		"folded line":                "X-T: a\r\n b\r\n",
		"no colon":                   "X-T\r\n",
		"a CR before the empty line": "\r",
	} {
		for _, masked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, masked %t", name, masked), func(t *testing.T) {
				o := options(t)
				if masked {
					o = maskedOptions(t, false)
				}
				got := rawRoundTrip(t, o, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
					"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"+trailer+"\r\n")
				// Nothing after the last chunk's size line.
				_, rest, _ := strings.Cut(got, "\r\nok\r\n")
				if !strings.HasPrefix(got, "HTTP/1.1 200 ") || rest != "" && rest != "0\r\n" {
					t.Fatalf("client got %q", got)
				}
			})
		}
	}
}
