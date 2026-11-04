package h1relay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

const (
	realCard  = "4111111111111111"
	cardSIn   = "4242424242424242" // same length: masking keeps lengths
	realToken = "sk_live_real_secret_value"
	tokenSIn  = "tok_standin" // shorter: masking changes lengths
)

// maskedOptions has both values on record for masking; with sameLength only
// the card, whose stand-in keeps its length.
func maskedOptions(t *testing.T, sameLength bool) Options {
	t.Helper()
	o := options(t)
	values := map[string]string{cardSIn: realCard}
	if !sameLength {
		values[tokenSIn] = realToken
	}
	r, err := resolve.NewStatic(values)
	if err != nil {
		t.Fatal(err)
	}
	var known []string
	for k := range values {
		known = append(known, k)
	}
	o.Session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{ID: "alice"}, "allowed.test", strings.Join(known, " "))
	return o
}

// received is a response as the client parsed it.
type received struct {
	StatusCode       int
	Header, Trailer  http.Header
	ContentLength    int64
	TransferEncoding []string
}

// roundTrip sends one request and the server's raw response, and returns
// what the client got, parsed.
func roundTrip(t *testing.T, o Options, method, response string) (received, string) {
	t.Helper()
	client, clientReader, server, serverReader, _ := pipesWith(t, o)
	send(t, client, method+" / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	readHead(t, serverReader)
	go func() { _, _ = io.WriteString(server, response) }()
	resp, err := http.ReadResponse(bufio.NewReader(clientReader), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v (got %q)", err, body)
	}
	return received{resp.StatusCode, resp.Header, resp.Trailer, resp.ContentLength, resp.TransferEncoding}, string(body)
}

func TestSameLengthMaskingKeepsContentLength(t *testing.T) {
	body := `{"card":"` + realCard + `","shown":"4111 1111 1111 1111"}`
	resp, got := roundTrip(t, maskedOptions(t, true), "GET",
		"HTTP/1.1 302 Found\r\nLocation: /done?card="+realCard+"\r\nSet-Cookie: c="+realCard+"; Secure\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	if want := `{"card":"` + cardSIn + `","shown":"4242 4242 4242 4242"}`; got != want {
		t.Fatalf("body %q, want %q", got, want)
	}
	if resp.ContentLength != int64(len(body)) || len(resp.TransferEncoding) != 0 {
		t.Fatalf("framing changed: length %d, transfer-encoding %v", resp.ContentLength, resp.TransferEncoding)
	}
	if resp.Header.Get("Location") != "/done?card="+cardSIn || resp.Header.Get("Set-Cookie") != "c="+cardSIn+"; Secure" {
		t.Fatalf("headers %v", resp.Header)
	}
}

func TestLengthChangingMaskingSendsChunked(t *testing.T) {
	body := "token=" + realToken + "&card=" + realCard
	resp, got := roundTrip(t, maskedOptions(t, false), "GET",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	if want := "token=" + tokenSIn + "&card=" + cardSIn; got != want {
		t.Fatalf("body %q, want %q", got, want)
	}
	if resp.ContentLength != -1 || len(resp.TransferEncoding) != 1 || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("framing: length %d, transfer-encoding %v", resp.ContentLength, resp.TransferEncoding)
	}
}

// A value split across chunks, in every place, is masked, and so are the
// trailers.
func TestValueSplitAcrossChunks(t *testing.T) {
	text := "a=" + realToken + "&b=" + realCard
	for split := 1; split < len(text); split++ {
		raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n" +
			chunk(text[:split]) + chunk(text[split:]) + "0\r\nX-Sum: " + realToken + "\r\n\r\n"
		resp, got := roundTrip(t, maskedOptions(t, false), "GET", raw)
		if want := "a=" + tokenSIn + "&b=" + cardSIn; got != want {
			t.Fatalf("split %d: body %q, want %q", split, got, want)
		}
		if resp.Trailer.Get("X-Sum") != tokenSIn {
			t.Fatalf("split %d: trailer %q", split, resp.Trailer.Get("X-Sum"))
		}
	}
}

func chunk(s string) string { return strings.ToUpper(itoaBase(len(s), 16)) + "\r\n" + s + "\r\n" }

func compress(t *testing.T, coding string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "deflate":
		w = zlib.NewWriter(&b)
	case "br":
		w = brotli.NewWriter(&b)
	case "zstd":
		w, _ = zstd.NewWriter(&b)
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// A compressed body is decoded, masked and sent without its coding, never
// passed through compressed.
func TestCompressedBodiesAreDecodedAndMasked(t *testing.T) {
	plain := bytes.Repeat([]byte("row "+realCard+" "+realToken+"\n"), 2000)
	want := strings.Repeat("row "+cardSIn+" "+tokenSIn+"\n", 2000)
	for _, coding := range []string{"gzip", "deflate", "br", "zstd"} {
		for _, chunked := range []bool{false, true} {
			name := coding
			if chunked {
				name += " chunked"
			}
			t.Run(name, func(t *testing.T) {
				data := compress(t, coding, plain)
				raw := "HTTP/1.1 200 OK\r\nContent-Encoding: " + coding + "\r\nVary: Accept-Encoding\r\n"
				if chunked {
					half := len(data) / 2
					raw += "Transfer-Encoding: chunked\r\n\r\n" + chunk(string(data[:half])) + chunk(string(data[half:])) + "0\r\n\r\n"
				} else {
					raw += "Content-Length: " + itoa(len(data)) + "\r\n\r\n" + string(data)
				}
				resp, got := roundTrip(t, maskedOptions(t, false), "GET", raw)
				if got != want {
					t.Fatalf("body of %d bytes differs from the masked text (%d bytes)", len(got), len(want))
				}
				if resp.Header.Get("Content-Encoding") != "" {
					t.Fatalf("content-encoding %q kept", resp.Header.Get("Content-Encoding"))
				}
				if resp.Header.Get("Vary") != "Accept-Encoding" {
					t.Fatal("other headers must stay")
				}
			})
		}
	}
}

// Bodiless responses lose a coding the body would lose, so a cached decoded
// copy keeps describing itself; HEAD also loses its length.
func TestBodilessResponsesDropTheCoding(t *testing.T) {
	resp, _ := roundTrip(t, maskedOptions(t, true), "HEAD", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1234\r\n\r\n")
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("headers %v", resp.Header)
	}
	resp, _ = roundTrip(t, maskedOptions(t, true), "GET", "HTTP/1.1 304 Not Modified\r\nContent-Encoding: br\r\nETag: \"x\"\r\n\r\n")
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("ETag") != `"x"` {
		t.Fatalf("headers %v", resp.Header)
	}
}

func TestCloseDelimitedBodyIsMasked(t *testing.T) {
	client, clientReader, server, serverReader, _ := pipesWith(t, maskedOptions(t, false))
	send(t, client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	readHead(t, serverReader)
	go func() {
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\nx "+realToken[:5])
		time.Sleep(10 * time.Millisecond)
		_, _ = io.WriteString(server, realToken[5:]+" y")
		_ = server.Close()
	}()
	got, _ := io.ReadAll(clientReader)
	if !strings.HasSuffix(string(got), "\r\n\r\nx "+tokenSIn+" y") {
		t.Fatalf("client got %q", got)
	}
}

// Responses that cannot be masked are answered 502 and the connection ends.
func TestUnmaskableResponsesAreRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown coding":          "HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\nContent-Length: 4\r\n\r\nabcd",
		"stacked codings":         "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\nContent-Length: 4\r\n\r\nabcd",
		"partial, length changes": "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/10\r\nContent-Length: 4\r\n\r\nabcd",
		"transfer coding":         "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := roundTrip(t, maskedOptions(t, false), "GET", raw)
			if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "abcd") {
				t.Fatalf("got %d %q", resp.StatusCode, body)
			}
		})
	}
	// A partial response whose masking keeps every length goes through.
	resp, body := roundTrip(t, maskedOptions(t, true), "GET",
		"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-15/99\r\nContent-Length: 16\r\n\r\n"+realCard)
	if resp.StatusCode != http.StatusPartialContent || body != cardSIn {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
}

// A compressed body that decodes past the cap is cut off: the client gets a
// truncated response, and no real value.
func TestOversizedDecodedBodyIsCutOff(t *testing.T) {
	o := maskedOptions(t, false)
	o.MaxDecoded = 64 << 10
	plain := bytes.Repeat([]byte(realToken+" "), 20000) // about 520 KB
	data := compress(t, "gzip", plain)
	client, clientReader, server, serverReader, result := pipesWith(t, o)
	send(t, client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	readHead(t, serverReader)
	go func() {
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "+itoa(len(data))+"\r\n\r\n"+string(data))
	}()
	got, _ := io.ReadAll(clientReader)
	if strings.Contains(string(got), realToken) || strings.HasSuffix(string(got), "0\r\n\r\n") || len(got) > 80<<10 {
		t.Fatalf("client got %d bytes, complete or unmasked", len(got))
	}
	select {
	case <-result: //nolint:errcheck // only waits for the relay to stop
	case <-time.After(5 * time.Second):
		t.Fatal("relay kept going")
	}
}

// With masking on and nothing on record, responses are copied byte for byte.
func TestNothingToMaskCopiesExactly(t *testing.T) {
	o := options(t)
	r, _ := resolve.NewStatic(map[string]string{cardSIn: realCard})
	o.Session = scopetest.Masked(t, o.Hosts, r, resolve.Principal{}, "allowed.test")
	raw := "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nabcd\r\n0\r\n\r\n"
	client, clientReader, server, serverReader, _ := pipesWith(t, o)
	send(t, client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	readHead(t, serverReader)
	send(t, server, raw)
	got := make([]byte, len(raw))
	if _, err := io.ReadFull(clientReader, got); err != nil || string(got) != raw {
		t.Fatalf("got %q, %v", got, err)
	}
}

// Pipelined responses keep their order and boundaries around a masked one.
func TestMaskedResponsesKeepTheirBoundaries(t *testing.T) {
	client, clientReader, server, serverReader, _ := pipesWith(t, maskedOptions(t, false))
	br := bufio.NewReader(clientReader)
	for i, raw := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(realToken)) + "\r\n\r\n" + realToken,
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	} {
		send(t, client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
		readHead(t, serverReader)
		send(t, server, raw)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		want := []string{tokenSIn, "", "ok"}[i]
		if string(body) != want {
			t.Fatalf("response %d: %q, want %q", i, body, want)
		}
	}
}

func itoa(n int) string { return itoaBase(n, 10) }

func itoaBase(n, base int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= base {
		b = append([]byte{digits[n%base]}, b...)
	}
	return string(b)
}
