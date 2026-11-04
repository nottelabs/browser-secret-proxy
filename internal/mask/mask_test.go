package mask

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	card     = "4111111111111111"
	cardSIn  = "4242424242424242"
	token    = "sk_live_a&b<c>\"d"
	tokenSIn = "tok_standin_value"
)

func testMasker(t *testing.T) *Masker {
	t.Helper()
	m := New([]Pair{{Real: card, StandIn: cardSIn}, {Real: token, StandIn: tokenSIn}, {Real: "1234", StandIn: "9999"}})
	if m == nil {
		t.Fatal("nil masker")
	}
	return m
}

func TestForms(t *testing.T) {
	m := testMasker(t)
	cases := map[string]string{
		"card " + card + "!":                       "card " + cardSIn + "!",
		"4111 1111 1111 1111":                      "4242 4242 4242 4242",
		"4111-1111-1111-1111":                      "4242-4242-4242-4242",
		"q=4111+1111+1111+1111":                    "q=4242+4242+4242+4242",
		"/p/4111%201111%201111%201111":             "/p/4242%204242%204242%204242",
		`{"t":"sk_live_a&b<c>\"d"}`:                `{"t":"tok_standin_value"}`,
		`{"t":"sk_live_a\u0026b\u003cc\u003e\"d"}`: `{"t":"tok_standin_value"}`,
		"t=sk_live_a%26b%3Cc%3E%22d":               "t=tok_standin_value",
		"<b>sk_live_a&amp;b&lt;c&gt;&#34;d</b>":    "<b>tok_standin_value</b>",
		"&#52;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;":                 "&#52;&#50;&#52;&#50;&#52;&#50;&#52;&#50;&#52;&#50;&#52;&#50;&#52;&#50;&#52;&#50;",
		"&#x34;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;&#x31;": "&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;&#x34;&#x32;",
		"pin 1234 stays":       "pin 1234 stays", // shorter than MinLength
		"last four 1111 stays": "last four 1111 stays",
		"no secret":            "no secret",
	}
	for in, want := range cases {
		if got := m.String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
	if m.SameLength() {
		t.Error("the token's stand-in has another length")
	}
	if !New([]Pair{{Real: card, StandIn: cardSIn}}).SameLength() {
		t.Error("a format-preserving card stand-in keeps every length")
	}
	if New([]Pair{{Real: "short", StandIn: "x"}}) != nil {
		t.Error("a masker with only short values should be nil")
	}
}

func TestAmexGrouping(t *testing.T) {
	m := New([]Pair{{Real: "378282246310005", StandIn: "371449635398431"}})
	if got := m.String("3782 822463 10005"); got != "3714 496353 98431" {
		t.Fatalf("got %q", got)
	}
}

func TestNonDigitStandInReplacesGroupedCard(t *testing.T) {
	m := New([]Pair{{Real: card, StandIn: "tok_card"}})
	if got := m.String("4111 1111 1111 1111"); got != "tok_card" {
		t.Fatalf("got %q", got)
	}
}

func TestLongestFormWins(t *testing.T) {
	m := New([]Pair{{Real: "abcdefgh", StandIn: "SHORT___"}, {Real: "abcdefghij", StandIn: "LONG______"}})
	if got := m.String("abcdefghij abcdefgh"); got != "LONG______ SHORT___" {
		t.Fatalf("got %q", got)
	}
}

// Whatever the write boundaries, a stream is masked exactly as a whole
// buffer is, and what is held back stays below the longest form.
func TestWriterSplitsAnywhere(t *testing.T) {
	m := testMasker(t)
	text := "a " + card + " b 4111 1111 1111 1111 c " + `"sk_live_a\u0026b\u003cc\u003e\"d"` + " d sk_live_a&b<c>\"d" + card
	want := m.String(text)
	for split := 0; split <= len(text); split++ {
		for split2 := split; split2 <= len(text); split2 += 7 {
			var out bytes.Buffer
			w := m.NewWriter(&out)
			for _, part := range []string{text[:split], text[split:split2], text[split2:]} {
				if _, err := w.Write([]byte(part)); err != nil {
					t.Fatal(err)
				}
				if w.Pending() >= m.MaxLength() {
					t.Fatalf("held back %d bytes, longest form %d", w.Pending(), m.MaxLength())
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if out.String() != want {
				t.Fatalf("split at %d and %d: got %q, want %q", split, split2, out.String(), want)
			}
		}
	}
	// Byte by byte.
	var out bytes.Buffer
	w := m.NewWriter(&out)
	for i := 0; i < len(text); i++ {
		_, _ = w.Write([]byte{text[i]})
	}
	_ = w.Close()
	if out.String() != want {
		t.Fatalf("byte by byte: got %q", out.String())
	}
}

// Text that cannot begin a real value is passed on at once, so a stream of
// events is not delayed.
func TestWriterHoldsBackOnlyPossibleBeginnings(t *testing.T) {
	m := testMasker(t)
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write([]byte("data: {\"x\":1}\n\n"))
	if out.String() != "data: {\"x\":1}\n\n" || w.Pending() != 0 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
	_, _ = w.Write([]byte("id 41111"))
	if out.String() != "data: {\"x\":1}\n\nid " || w.Pending() != 5 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
	_, _ = w.Write([]byte("2"))
	if w.Pending() != 0 || !strings.HasSuffix(out.String(), "id 411112") {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
}

func TestParseEncoding(t *testing.T) {
	cases := map[string]struct {
		want Encoding
		ok   bool
	}{
		"": {"", true}, "identity": {"", true}, "GZIP": {"gzip", true}, "x-gzip": {"gzip", true},
		"deflate": {"deflate", true}, "br": {"br", true}, " zstd ": {"zstd", true},
		"compress": {"", false}, "gzip, br": {"", false}, "dcb": {"", false},
	}
	for in, c := range cases {
		got, err := ParseEncoding([]string{in})
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParseEncoding(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseEncoding([]string{"gzip", "br"}); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("two headers: %v", err)
	}
}

func encode(t *testing.T, e Encoding, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	switch e {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "deflate":
		w = zlib.NewWriter(&b)
	case "raw-deflate":
		w, _ = flate.NewWriter(&b, flate.DefaultCompression)
	case "br":
		w = brotli.NewWriter(&b)
	case "zstd":
		w, _ = zstd.NewWriter(&b)
	default:
		t.Fatalf("encoding %q", e)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecoder(t *testing.T) {
	data := bytes.Repeat([]byte("hello "+card+" "), 1000)
	for _, e := range []Encoding{"gzip", "deflate", "raw-deflate", "br", "zstd"} {
		t.Run(string(e), func(t *testing.T) {
			name := e
			if e == "raw-deflate" {
				name = "deflate"
			}
			r, err := Decoder(name, bytes.NewReader(encode(t, e, data)), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("decoded %d bytes, %v", len(got), err)
			}
			r, _ = Decoder(name, bytes.NewReader(encode(t, e, data)), int64(len(data)-1))
			if _, err := io.ReadAll(r); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("over the limit: %v", err)
			}
		})
	}
}
