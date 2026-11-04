package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/h2relay"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
)

// A destination that reflects a client's input and flushes after it does
// not let the client rebuild a real value from the framing of the masked
// response (critic-1). The masker used to hold back only bytes that could
// begin a value, and each piece it passed on became one HTTP/1.1 chunk or
// one HTTP/2 DATA frame: a client could reflect "s", "sk", "sk_", ... and
// see from the size of the first piece whether its guess was held back,
// recovering the value byte by byte without ever receiving it. Each guess
// that extends the value must now get the same framing as one that does
// not.
func TestMaskingFramingDoesNotRevealPrefixes(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		if leaked, of := framingLeaks(t, proto, mask.Fixed); leaked > 0 {
			t.Fatalf("the framing told a matching guess from a wrong one at %d of %d bytes", leaked, of)
		}
	})
}

// -mask-stream-window=minimal holds back only bytes that could begin a
// value, as the masker used to, and so gives the oracle back: this is the
// trade-off an operator accepts with it.
func TestMinimalMaskWindowRevealsPrefixes(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		if leaked, _ := framingLeaks(t, proto, mask.Minimal); leaked == 0 {
			t.Fatal("the framing of a matching guess was the same as of a wrong one at every byte")
		}
	})
}

// framingLeaks has a streaming destination reflect a guess at each prefix of
// a real value, and one with a wrong last byte, through a proxy that masks
// streams with window. It returns at how many of the prefixes the framing
// of the two responses differed, of how many.
func framingLeaks(t *testing.T, proto string, window mask.Window) (leaked, of int) {
	t.Helper()
	const real = "sk_live_real_secret_value"
	page := strings.Repeat("<p>results</p>\n", 40) + "results for "
	// The client signals once it has the first piece of a search response,
	// so the rest is written only after the proxy masked and passed on the
	// first write: the two writes never reach the masker as one, whatever
	// the scheduling.
	seen := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		// A streaming server: the reflected part is flushed, more follows
		// once the client got some of it.
		_, _ = io.WriteString(w, page+r.URL.Query().Get("q"))
		w.(http.Flusher).Flush()
		select {
		case <-seen:
		case <-time.After(10 * time.Second):
			t.Errorf("the client got nothing of a flushed %d bytes", len(page)+len(r.URL.Query().Get("q")))
		}
		_, _ = io.WriteString(w, " end")
	})
	p := maskingSetup(t, proto, serveWith(&echoed{}, handler), map[string]string{"tok_standin": real},
		func(c *Config) { c.MaskStreamWindow = window })
	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{proto}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	pieces := h1Pieces(t, tc)
	if proto == "h2" {
		pieces = h2Pieces(t, tc)
	}
	// A request with the stand-in puts the real value on record.
	pieces(http.MethodPost, "/login", "pw=tok_standin", nil)
	for n := 1; n < len(real); n++ {
		miss := byte('z')
		if real[n-1] == miss {
			miss = 'y'
		}
		hit := pieces(http.MethodGet, "/search?q="+real[:n], "", seen)
		other := pieces(http.MethodGet, "/search?q="+real[:n-1]+string(miss), "", seen)
		if !slices.Equal(hit, other) {
			leaked++
			t.Logf("%d bytes of the value: pieces %v, %v for a wrong last byte", n, hit, other)
		}
	}
	return leaked, len(real) - 1
}

// h1Pieces returns a function that sends a request over c and returns the
// sizes of the chunks of its response. Once it has the first chunk, it
// signals on seen, if not nil.
func h1Pieces(t *testing.T, c *tls.Conn) func(method, path, body string, seen chan<- struct{}) []int {
	br := bufio.NewReader(c)
	return func(method, path, body string, seen chan<- struct{}) []int {
		t.Helper()
		request := method + " " + path + " HTTP/1.1\r\nHost: " + allowedHost + "\r\n"
		if body != "" {
			request += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
		}
		if _, err := io.WriteString(c, request+"\r\n"+body); err != nil {
			t.Fatal(err)
		}
		chunked := false
		length := 0
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
			name, value, _ := strings.Cut(strings.TrimSpace(line), ":")
			switch strings.ToLower(name) {
			case "transfer-encoding":
				chunked = strings.TrimSpace(value) == "chunked"
			case "content-length":
				length, _ = strconv.Atoi(strings.TrimSpace(value))
			}
		}
		if !chunked {
			if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
				t.Fatal(err)
			}
			return []int{length}
		}
		var sizes []int
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			n, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
			if err != nil {
				t.Fatalf("chunk size %q", line)
			}
			if n == 0 {
				if _, err := br.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
				return sizes
			}
			if _, err := io.CopyN(io.Discard, br, n+2); err != nil {
				t.Fatal(err)
			}
			sizes = append(sizes, int(n))
			if len(sizes) == 1 && seen != nil {
				seen <- struct{}{}
			}
		}
	}
}

// h2Pieces returns a function that sends a request over c, on a new HTTP/2
// stream, and returns the sizes of the DATA frames of its response. Once it
// has the first non-empty DATA frame, it signals on seen, if not nil.
func h2Pieces(t *testing.T, c *tls.Conn) func(method, path, body string, seen chan<- struct{}) []int {
	if _, err := c.Write(h2relay.AppendFrame([]byte(h2relay.Preface), h2relay.FrameSettings, 0, 0, nil)); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	stream := uint32(1)
	return func(method, path, body string, seen chan<- struct{}) []int {
		t.Helper()
		block.Reset()
		for _, f := range [][2]string{{":method", method}, {":scheme", "https"}, {":authority", allowedHost}, {":path", path}} {
			_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
		}
		id := stream
		stream += 2
		var out []byte
		if body == "" {
			out = h2relay.AppendFrame(out, h2relay.FrameHeaders, h2relay.FlagEndHeaders|h2relay.FlagEndStream, id, block.Bytes())
		} else {
			out = h2relay.AppendFrame(out, h2relay.FrameHeaders, h2relay.FlagEndHeaders, id, block.Bytes())
			out = h2relay.AppendFrame(out, h2relay.FrameData, h2relay.FlagEndStream, id, []byte(body))
		}
		if _, err := c.Write(out); err != nil {
			t.Fatal(err)
		}
		var sizes []int
		for {
			f, err := h2relay.ReadFrame(c)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case f.Type == h2relay.FrameSettings && f.Flags&h2relay.FlagAck == 0:
				if _, err := c.Write(h2relay.AppendFrame(nil, h2relay.FrameSettings, h2relay.FlagAck, 0, nil)); err != nil {
					t.Fatal(err)
				}
			case f.Type == h2relay.FrameRSTStream && f.Stream == id:
				t.Fatal("stream reset")
			case f.Stream != id:
			case f.Type == h2relay.FrameData:
				if len(f.Payload) > 0 {
					sizes = append(sizes, len(f.Payload))
					if len(sizes) == 1 && seen != nil {
						seen <- struct{}{}
					}
					credit := binary.BigEndian.AppendUint32(nil, uint32(len(f.Payload)))
					if _, err := c.Write(h2relay.AppendFrame(nil, h2relay.FrameWindowUpdate, 0, 0, credit)); err != nil {
						t.Fatal(err)
					}
				}
				if f.Flags&h2relay.FlagEndStream != 0 {
					return sizes
				}
			case f.Type == h2relay.FrameHeaders && f.Flags&h2relay.FlagEndStream != 0:
				return sizes
			}
		}
	}
}
