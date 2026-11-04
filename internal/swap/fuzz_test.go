package swap

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzDecodeJSONString checks decodeJSONString against encoding/json: what
// it decodes, encoding/json decodes the same way, and valid content without
// \u escapes, which it never refuses, it decodes.
func FuzzDecodeJSONString(f *testing.F) {
	for _, s := range []string{`tok_a`, `a&b`, `q\"x\\y\/z\b\f\n\r\t`, `😀`, `\ud83d`, `é é`, `bad\`, "x\\n\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if unescapedQuote(s) {
			return // not the content of one string: a quote ends it
		}
		got, ok := decodeJSONString(s)
		var std string
		stdErr := json.Unmarshal([]byte(`"`+s+`"`), &std)
		if ok {
			if stdErr != nil {
				t.Fatalf("decoded %q, which encoding/json refuses: %v", s, stdErr)
			}
			if got != std {
				t.Fatalf("%q decodes to %q, encoding/json gives %q", s, got, std)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("%q decodes to invalid UTF-8 %q", s, got)
			}
			return
		}
		if stdErr == nil && strings.Contains(s, `\`) && !strings.Contains(s, `\u`) && utf8.ValidString(s) {
			t.Fatalf("refused %q, which encoding/json decodes to %q", s, std)
		}
	})
}

// FuzzJSONEscape checks writeJSONEscaped and jsonEscape: the output is a
// valid JSON string that decodes to the input (invalid UTF-8 bytes each
// becoming U+FFFD), decodeJSONString reads it back, and for valid UTF-8 it
// is what encoding/json writes.
func FuzzJSONEscape(f *testing.F) {
	for _, s := range []string{"plain", `q"x\y`, "\n\r\t\b\f\x00\x1f\x7f", "é \U0001F600", "  ", "a&b<c>", "bad\xffbyte\xc3", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		w := &limitedBuilder{limit: 8*len(s) + 8}
		if err := writeJSONEscaped(w, s); err != nil {
			t.Fatalf("escape %q: %v", s, err)
		}
		escaped := w.b.String()
		var want strings.Builder
		for i := 0; i < len(s); {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				want.WriteRune(utf8.RuneError)
			} else {
				want.WriteString(s[i : i+size])
			}
			i += size
		}
		var std string
		if err := json.Unmarshal([]byte(`"`+escaped+`"`), &std); err != nil || std != want.String() {
			t.Fatalf("%q escapes to %q, which encoding/json decodes to %q (%v)", s, escaped, std, err)
		}
		if decoded, ok := decodeJSONString(escaped); ok != strings.Contains(escaped, `\`) || ok && decoded != want.String() {
			t.Fatalf("%q escapes to %q, read back as %q, %v", s, escaped, decoded, ok)
		} else if !ok && escaped != want.String() {
			t.Fatalf("%q escapes to %q without an escape", s, escaped)
		}
		if utf8.ValidString(s) {
			if std := jsonEscape(s); escaped != std {
				t.Fatalf("%q escapes to %q, encoding/json writes %q", s, escaped, std)
			}
		}
	})
}

// FuzzMatches checks Matches against the Swapper it describes: the
// stand-ins it returns for a part are exactly those whose real values a
// Swapper over all of them puts into that part. Each real value is a marker
// that no escaping changes.
func FuzzMatches(f *testing.F) {
	f.Add(uint8(Literal), "Bearer tok_a and tok_ab", "tok_a", "tok_ab", "")
	f.Add(uint8(Query), "k=tok%20a&j=tok+a&p=a%2Bb", "tok a", "a+b", "x")
	f.Add(uint8(JSON), `{"t":"tok_a","n":4242,"q":"a\"b","e":"😀"}`, "tok_a", "4242", `a"b`)
	f.Add(uint8(JSON), `["unterminated \"tok_a`, "tok_a", `"tok_a`, "a")
	f.Fuzz(func(t *testing.T, place uint8, text, a, b, c string) {
		const prefix, suffix = "Zq7V", "Vq7Z"
		p := Part{Place: Place(place % 3), Text: text}
		values := map[string]string{}
		var standIns []string
		for i, k := range []string{a, b, c} {
			if k == "" || values[k] != "" || strings.Contains(k, prefix) {
				continue
			}
			values[k] = prefix + string(rune('a'+i)) + suffix
			standIns = append(standIns, k)
		}
		// A marker the text already holds, in any form, cannot be told from
		// a replacement.
		if len(standIns) == 0 || strings.Contains(looseUnescape(text), prefix) || strings.Contains(looseUnescape(text), suffix) {
			return
		}
		s, err := New(values)
		if err != nil {
			t.Fatal(err)
		}
		var out string
		limit := 16*len(text) + 64
		switch p.Place {
		case Query:
			out, _, err = replace(s.query, text, limit)
		case JSON:
			out, _, err = s.jsonText(text, limit)
		default:
			out, _, err = replace(s.literal, text, limit)
		}
		if err != nil {
			t.Fatalf("swap: %v", err)
		}
		var swapped []string
		for _, k := range standIns {
			if strings.Contains(out, values[k]) {
				swapped = append(swapped, k)
			}
		}
		sort.Strings(swapped)
		if got := Matches(p, standIns); !slices.Equal(got, swapped) {
			t.Fatalf("Matches(%+v, %q) = %q, but the Swapper replaces %q: %q", p, standIns, got, swapped, out)
		}
	})
}

// unescapedQuote reports whether s holds a quote that no backslash escapes.
func unescapedQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return true
		}
	}
	return false
}

// looseUnescape undoes every backslash escape it recognizes, wherever it
// is, so a test can tell whether text could decode to some string.
func looseUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+5 < len(s) && s[i+1] == 'u' {
			if r, ok := hex4(s, i+2); ok {
				b.WriteRune(r)
				i += 5
				continue
			}
		}
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
