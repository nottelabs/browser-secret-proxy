package scope

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzUnescape checks the decoders stand-in detection runs over text: each
// agrees with net/url or encoding/json where those accept the text, and
// the lenient fallback decodes only valid %XX sequences.
func FuzzUnescape(f *testing.F) {
	for _, s := range []string{"4242+4242", "4242%204242", "100% off %41", "%zz%4", "%%41", `tok_a`, `😀 \ud83d`, `\q \"x\"`, "a%e9b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := url.QueryUnescape(s); err == nil && queryUnescape(s) != d {
			t.Fatalf("queryUnescape(%q) = %q, net/url %q", s, queryUnescape(s), d)
		}
		if d, err := url.PathUnescape(s); err == nil {
			if got := pathUnescape(s); got != d {
				t.Fatalf("pathUnescape(%q) = %q, net/url %q", s, got, d)
			}
			if got := lenientUnescape(s); got != d {
				t.Fatalf("lenientUnescape(%q) = %q, net/url %q", s, got, d)
			}
		}
		got := lenientUnescape(s)
		if !strings.Contains(s, "%") && got != s {
			t.Fatalf("lenientUnescape(%q) = %q without a %%", s, got)
		}
		if len(got) > len(s) || (len(s)-len(got))%2 != 0 {
			t.Fatalf("lenientUnescape(%q) = %q", s, got)
		}
		// Each %XX it decoded leaves the rest as it was.
		var want strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				want.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
				i += 2
				continue
			}
			want.WriteByte(s[i])
		}
		if got != want.String() {
			t.Fatalf("lenientUnescape(%q) = %q, want %q", s, got, want.String())
		}

		if !utf8.ValidString(s) {
			return
		}
		var std string
		if err := json.Unmarshal([]byte(`"`+s+`"`), &std); err == nil {
			if got := jsonUnescape(s); got != std {
				t.Fatalf("jsonUnescape(%q) = %q, encoding/json %q", s, got, std)
			}
		}
	})
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}
