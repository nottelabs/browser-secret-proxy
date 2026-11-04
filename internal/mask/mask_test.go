package mask

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"slices"
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
		if got := m.String(Text, in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
	if m.SameLength(Text) {
		t.Error("the token's stand-in has another length")
	}
	if !New([]Pair{{Real: card, StandIn: cardSIn}}).SameLength(Text) {
		t.Error("a format-preserving card stand-in keeps every length")
	}
	if New([]Pair{{Real: "short", StandIn: "x"}}) != nil {
		t.Error("a masker with only short values should be nil")
	}
}

func TestAmexGrouping(t *testing.T) {
	m := New([]Pair{{Real: "378282246310005", StandIn: "371449635398431"}})
	if got := m.String(Text, "3782 822463 10005"); got != "3714 496353 98431" {
		t.Fatalf("got %q", got)
	}
}

func TestNonDigitStandInReplacesGroupedCard(t *testing.T) {
	m := New([]Pair{{Real: card, StandIn: "tok_card"}})
	if got := m.String(Text, "4111 1111 1111 1111"); got != "tok_card" {
		t.Fatalf("got %q", got)
	}
}

func TestLongestFormWins(t *testing.T) {
	m := New([]Pair{{Real: "abcdefgh", StandIn: "SHORT___"}, {Real: "abcdefghij", StandIn: "LONG______"}})
	if got := m.String(Text, "abcdefghij abcdefgh"); got != "LONG______ SHORT___" {
		t.Fatalf("got %q", got)
	}
}

// Whatever the write boundaries, a stream is masked exactly as a whole
// buffer is, and what is held back stays below the longest form, with
// either window.
func TestWriterSplitsAnywhere(t *testing.T) {
	for _, window := range []Window{Fixed, Minimal} {
		t.Run(window.String(), func(t *testing.T) { testWriterSplitsAnywhere(t, testMasker(t).WithWindow(window)) })
	}
}

func testWriterSplitsAnywhere(t *testing.T, m *Masker) {
	text := "a " + card + " b 4111 1111 1111 1111 c " + `"sk_live_a\u0026b\u003cc\u003e\"d"` + " d sk_live_a&b<c>\"d" + card
	want := m.String(Text, text)
	for split := 0; split <= len(text); split++ {
		for split2 := split; split2 <= len(text); split2 += 7 {
			var out bytes.Buffer
			w := m.NewWriter(&out, Text)
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
	w := m.NewWriter(&out, Text)
	for i := 0; i < len(text); i++ {
		_, _ = w.Write([]byte{text[i]})
	}
	_ = w.Close()
	if out.String() != want {
		t.Fatalf("byte by byte: got %q", out.String())
	}
}

// A Writer holds back the same number of bytes whatever they are, so text
// that cannot begin a real value waits as long as text that could.
func TestWriterHoldsBackAFixedWindow(t *testing.T) {
	m := testMasker(t)
	window := m.MaxLength() - 1
	var out bytes.Buffer
	w := m.NewWriter(&out, Text)
	_, _ = w.Write([]byte("data: {\"x\":1}\n\n"))
	if out.Len() != 0 || w.Pending() != 15 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
	text := strings.Repeat("event ", 100)
	for _, part := range []string{text, "id 41111", "2"} {
		before := out.Len()
		_, _ = w.Write([]byte(part))
		if w.Pending() != window {
			t.Fatalf("after %q: held %d, want %d", part, w.Pending(), window)
		}
		if before > 0 && out.Len()-before != len(part) {
			t.Fatalf("after %q: passed on %d bytes, want %d", part, out.Len()-before, len(part))
		}
	}
	_ = w.Close()
	if want := "data: {\"x\":1}\n\n" + text + "id 411112"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

// The Minimal window holds back only bytes that could begin a real value,
// as the masker did before the fixed window: text that cannot is passed on
// at once, so a stream of events is not delayed.
func TestMinimalWindowHoldsBackOnlyPossibleBeginnings(t *testing.T) {
	m := testMasker(t).WithWindow(Minimal)
	var out bytes.Buffer
	w := m.NewWriter(&out, Text)
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
	// A value split across writes is still masked.
	out.Reset()
	for _, part := range []string{"card 4111", " 1111 11", "11 1111!"} {
		_, _ = w.Write([]byte(part))
	}
	if out.String() != "card 4242 4242 4242 4242!" || w.Pending() != 0 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
	_, _ = w.Write([]byte("t=sk_live_a&b<c"))
	if out.String() != "card 4242 4242 4242 4242!t=" || w.Pending() != 13 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
	_, _ = w.Write([]byte(">\"d."))
	if out.String() != "card 4242 4242 4242 4242!t="+tokenSIn+"." || w.Pending() != 0 {
		t.Fatalf("passed on %q, held %d", out.String(), w.Pending())
	}
}

// What the Minimal window passes on depends on whether the end of the text
// could begin a real value: the oracle the Fixed window closes (critic-1)
// is open with it, which is why it is not the default.
func TestMinimalWindowRevealsPrefixes(t *testing.T) {
	m := testMasker(t).WithWindow(Minimal)
	written := func(parts ...string) sizes {
		var s sizes
		w := m.NewWriter(&s, Text)
		for _, p := range parts {
			_, _ = w.Write([]byte(p))
		}
		_ = w.Close()
		return s
	}
	hit, other := written("results for 41111", " end"), written("results for ~~~~~", " end")
	if slices.Equal(hit, other) {
		t.Fatalf("pieces %v for both", hit)
	}
}

func TestWindowText(t *testing.T) {
	for _, window := range []Window{Fixed, Minimal} {
		text, err := window.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got Window
		if err := got.UnmarshalText(text); err != nil || got != window {
			t.Fatalf("%q: got %v, %v", text, got, err)
		}
	}
	if Window(0) != Fixed {
		t.Fatal("the zero Window is not Fixed")
	}
	for _, bad := range []string{"", "Fixed", "min", "none"} {
		w := Minimal
		if err := w.UnmarshalText([]byte(bad)); err == nil || w != Minimal {
			t.Fatalf("%q: got %v, %v", bad, w, err)
		}
	}
}

// sizes records the size of each Write.
type sizes []int

func (s *sizes) Write(p []byte) (int, error) {
	*s = append(*s, len(p))
	return len(p), nil
}

// The size of each piece a Writer passes on does not depend on whether the
// text it holds back begins a real value: a client that has a destination
// reflect its guesses cannot tell from the framing how much of a value a
// guess matched (critic-1).
func TestWriterOutputDoesNotRevealPrefixes(t *testing.T) {
	m := testMasker(t)
	written := func(parts ...string) sizes {
		var s sizes
		w := m.NewWriter(&s, Text)
		for _, p := range parts {
			_, _ = w.Write([]byte(p))
		}
		_ = w.Close()
		return s
	}
	for _, short := range []bool{true, false} {
		pad := strings.Repeat(".", 300)
		if short {
			pad = "results for "
		}
		for _, list := range m.byFirst {
			for _, f := range list {
				for n := 1; n < len(f.from); n++ {
					guess := string(f.from[:n])
					miss := strings.Repeat("~", n)
					hit, other := written(pad+guess, " end"), written(pad+miss, " end")
					if !slices.Equal(hit, other) {
						t.Fatalf("pad %d, %q: pieces %v, %v for a text of the same length", len(pad), guess, hit, other)
					}
				}
			}
		}
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

func encode(t testing.TB, e Encoding, data []byte) []byte {
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

// A stand-in that needs escaping is escaped for the context the value is
// found in, so the response keeps its meaning: JSON stays valid, a URL keeps
// its parameters, HTML its attributes.
func TestReplacementsAreEscapedForTheirContext(t *testing.T) {
	m := New([]Pair{{Real: "abcdefgh", StandIn: `q"x&y=1 <z>`}})
	cases := []struct {
		c        Context
		in, want string
	}{
		{JSON, `{"token":"abcdefgh"}`, `{"token":"q\"x&y=1 <z>"}`},
		{URL, `/done?t=abcdefgh&n=1`, `/done?t=q%22x%26y%3D1+%3Cz%3E&n=1`},
		{HTML, `<input value="abcdefgh">`, `<input value="q&#34;x&amp;y=1 &lt;z&gt;">`},
		{Text, `token abcdefgh`, `token q"x&y=1 <z>`},
	}
	for _, c := range cases {
		if got := m.String(c.c, c.in); got != c.want {
			t.Errorf("context %d: %q, want %q", c.c, got, c.want)
		}
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(m.String(JSON, `{"token":"abcdefgh"}`)), &decoded); err != nil || decoded["token"] != `q"x&y=1 <z>` {
		t.Fatalf("masked JSON: %v %q", err, decoded)
	}
	// A form that is unambiguous keeps its own encoding in every context.
	m = New([]Pair{{Real: "a&bcdefgh", StandIn: "q&x"}})
	if got := m.String(Text, "t=a%26bcdefgh"); got != "t=q%26x" {
		t.Fatalf("got %q", got)
	}
}

func TestContextOf(t *testing.T) {
	for ct, want := range map[string]Context{
		"application/json; charset=utf-8": JSON, "application/problem+json": JSON, "text/javascript": JSON,
		"application/x-www-form-urlencoded": URL, "text/html; charset=utf-8": HTML, "application/xml": HTML,
		"image/svg+xml": HTML, "text/plain": Text, "": Text,
	} {
		if got := ContextOf(ct); got != want {
			t.Errorf("ContextOf(%q) = %d, want %d", ct, got, want)
		}
	}
	if HeaderContext("Location") != URL || HeaderContext("Set-Cookie") != URL || HeaderContext("X-Token") != Text {
		t.Error("header contexts")
	}
}
