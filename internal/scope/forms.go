package scope

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// withDecoded returns texts followed by their query-unescaped,
// path-unescaped and JSON-unescaped copies, when those differ, so a stand-in
// pattern also finds stand-ins in the escaped forms a swap replaces ("4242
// 4242" written "4242+4242" or "4242%204242").
func withDecoded(texts []string) []string {
	out := append([]string(nil), texts...)
	for _, t := range texts {
		for _, decoded := range []string{queryUnescape(t), pathUnescape(t), jsonUnescape(t)} {
			if decoded != t {
				out = append(out, decoded)
			}
		}
	}
	return out
}

func queryUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return lenientUnescape(strings.ReplaceAll(s, "+", " "))
}

func pathUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return lenientUnescape(s)
}

// lenientUnescape decodes valid %XX sequences and keeps the others, so one
// stray "%" does not hide the rest of the text.
func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// jsonUnescape decodes the escapes of JSON strings (\" \\ \/ \b \f \n \r \t
// \uXXXX) wherever they appear, keeping invalid ones as they are.
func jsonUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case '"', '\\', '/':
			b.WriteByte(c)
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'u':
			if i+6 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
					r := rune(v)
					// A surrogate pair is one character.
					if r >= 0xd800 && r < 0xdc00 && i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
						if low, err := strconv.ParseUint(s[i+8:i+12], 16, 16); err == nil && low >= 0xdc00 && low < 0xe000 {
							r = (r-0xd800)<<10 + (rune(low) - 0xdc00) + 0x10000
							i += 6
						}
					}
					if !utf8.ValidRune(r) {
						r = utf8.RuneError
					}
					b.WriteRune(r)
					i += 5
					continue
				}
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// used returns the candidates a swap of texts would replace, in the order a
// swap.Swapper applies them: at each position the longest stand-in wins, in
// any of its forms (swap.Forms), and replaced text is not searched again. A
// candidate found only inside a longer one is not used, so its value is
// neither looked up nor checked.
func used(candidates, texts []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	keys := append([]string(nil), candidates...)
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	type form struct {
		text string
		key  int
	}
	var byFirst [256][]form // in priority order
	for k, key := range keys {
		for _, f := range swap.Forms(key) {
			if f != "" {
				byFirst[f[0]] = append(byFirst[f[0]], form{f, k})
			}
		}
	}
	hit := make([]bool, len(keys))
	for _, t := range texts {
		for i := 0; i < len(t); {
			advanced := false
			for _, f := range byFirst[t[i]] {
				if strings.HasPrefix(t[i:], f.text) {
					hit[f.key] = true
					i += len(f.text)
					advanced = true
					break
				}
			}
			if !advanced {
				i++
			}
		}
	}
	var out []string
	for k, key := range keys {
		if hit[k] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}
