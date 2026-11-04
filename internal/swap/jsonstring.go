package swap

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeJSONString decodes the content of one JSON string literal (the text
// between its quotes) when it holds escapes, so a stand-in written with
// escapes ("tok\u005fa", or Go's "a\u0026b" for "a&b") is found like any
// other. It reports false when there is no escape, or when the content is
// not strictly valid (a bad escape, a lone surrogate, a raw control
// character, invalid UTF-8): such a string is then matched as written.
func decodeJSONString(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return "", false
			}
			switch s[i+1] {
			case '"', '\\', '/':
				b.WriteByte(s[i+1])
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := hex4(s, i+2)
				if !ok {
					return "", false
				}
				i += 6
				if utf16.IsSurrogate(r) {
					// Only a high surrogate followed by an escaped low one is a rune.
					if r >= 0xdc00 || i+1 >= len(s) || s[i] != '\\' || s[i+1] != 'u' {
						return "", false
					}
					low, ok := hex4(s, i+2)
					if !ok {
						return "", false
					}
					if r = utf16.DecodeRune(r, low); r == utf8.RuneError {
						return "", false
					}
					i += 6
				}
				b.WriteRune(r)
				continue
			default:
				return "", false
			}
			i += 2
		case c < 0x20:
			return "", false // control characters must be escaped in JSON
		case c < utf8.RuneSelf:
			b.WriteByte(c)
			i++
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				return "", false
			}
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	return b.String(), true
}

// hex4 reads the four hex digits of a \u escape at s[i:].
func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[i:i+4], 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// writeJSONEscaped writes s as JSON string content, escaped as
// encoding/json does with HTML escaping off, through w so the output limit
// applies as it grows. Invalid UTF-8 becomes U+FFFD.
func writeJSONEscaped(w *limitedBuilder, s string) error {
	const hex = "0123456789abcdef"
	start := 0
	flush := func(end int) error {
		if start < end {
			_, err := w.WriteString(s[start:end])
			return err
		}
		return nil
	}
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' && c < utf8.RuneSelf {
			i++
			continue
		}
		var esc string
		size := 1
		switch {
		case c == '"':
			esc = `\"`
		case c == '\\':
			esc = `\\`
		case c == '\n':
			esc = `\n`
		case c == '\r':
			esc = `\r`
		case c == '\t':
			esc = `\t`
		case c == '\b':
			esc = `\b`
		case c == '\f':
			esc = `\f`
		case c < 0x20:
			esc = `\u00` + string(hex[c>>4]) + string(hex[c&0xf])
		default:
			var r rune
			r, size = utf8.DecodeRuneInString(s[i:])
			switch {
			case r == utf8.RuneError && size == 1:
				esc = `\ufffd`
			case r == '\u2028':
				esc = `\u2028`
			case r == '\u2029':
				esc = `\u2029`
			default:
				i += size
				continue
			}
		}
		if err := flush(i); err != nil {
			return err
		}
		if _, err := w.WriteString(esc); err != nil {
			return err
		}
		i += size
		start = i
	}
	return flush(len(s))
}
