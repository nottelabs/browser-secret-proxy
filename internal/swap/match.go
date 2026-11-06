package swap

import (
	"net/url"
	"sort"
	"strings"
)

// Place is where text sits in a request, which decides the forms in which a
// Swapper replaces a stand-in there.
type Place int

// Places.
const (
	// Literal is a header value or a body other than a form or JSON: the
	// stand-in as is.
	Literal Place = iota
	// Query is a query string or a form body: the stand-in as is, query- or
	// path-escaped.
	Query
	// JSON is a JSON body: as is outside strings; inside them as is,
	// JSON-escaped, or written with any JSON escapes (\u0026 for &, say).
	JSON
)

// Part is one piece of a request's swappable text, and where it sits.
type Part struct {
	Place Place
	Text  string
}

// BodyPlace is the place of a request body with this Content-Type, as Body
// swaps it.
func BodyPlace(contentType string) Place {
	switch bodyKind(contentType) {
	case formBody:
		return Query
	case jsonBody:
		return JSON
	}
	return Literal
}

// Matches returns, sorted, the stand-ins among standIns that a Swapper over
// all of them would replace in part: the same forms for the same place, the
// longer stand-in first at each position, only where it stands as a whole
// token (see TokenByte), and replaced text not searched again. A stand-in
// found only inside a longer one, only inside a longer token, or only in a
// form its place does not replace, is not returned.
func Matches(part Part, standIns []string) []string {
	if len(standIns) == 0 || part.Text == "" {
		return nil
	}
	keys := append([]string(nil), standIns...)
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	hit := make([]bool, len(keys))
	literal := newMatcher(keys, false, literalForms)
	switch part.Place {
	case Query:
		newMatcher(keys, true, queryForms).scan(part.Text, hit)
	case JSON:
		inString := newMatcher(keys, false, jsonForms)
		// The same segmentation as jsonText.
		text, in, start := part.Text, false, 0
		for i := 0; i < len(text); i++ {
			switch {
			case in && text[i] == '\\':
				i++
			case text[i] == '"':
				if in {
					scanJSONString(inString, literal, text[start:i], hit)
				} else {
					literal.scan(text[start:i], hit)
				}
				start, in = i+1, !in
			}
		}
		if start < len(text) {
			if in {
				scanJSONString(inString, literal, text[start:], hit)
			} else {
				literal.scan(text[start:], hit)
			}
		}
	default:
		literal.scan(part.Text, hit)
	}
	var out []string
	for i, k := range keys {
		if hit[i] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// scanJSONString finds stand-ins in the content of one JSON string the way
// the Swapper replaces them there: in the decoded text when the string holds
// escapes, else as written, raw or JSON-escaped.
func scanJSONString(inString, literal *matcher, segment string, hit []bool) {
	if decoded, ok := decodeJSONString(segment); ok {
		literal.scan(decoded, hit)
		return
	}
	inString.scan(segment, hit)
}

// The forms a stand-in is replaced in, by place: as is in raw text; as is,
// query- or path-escaped in a query string or form body; as is or
// JSON-escaped in a JSON string that holds no escape.
func literalForms(k string) []string { return []string{k} }
func queryForms(k string) []string   { return distinct(k, url.QueryEscape(k), url.PathEscape(k)) }
func jsonForms(k string) []string    { return distinct(k, jsonEscape(k)) }

func distinct(forms ...string) []string {
	var out []string
	for _, f := range forms {
		dup := false
		for _, o := range out {
			dup = dup || o == f
		}
		if !dup {
			out = append(out, f)
		}
	}
	return out
}

// TokenByte reports whether c can be part of a token: a letter, a digit, "_"
// or "-". A stand-in that begins or ends with one is replaced only where the
// byte next to it in the text is not one, so "919" is swapped in "cvc=919"
// but not in "amount=19190". Stand-in prefixes end their match at the first
// byte that is not one.
func TokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

type matchForm struct {
	text string
	key  int
	// Whether the stand-in begins and ends with a token byte, so the byte
	// before and after the match must not be one.
	tokenStart, tokenEnd bool
}

// matcher finds forms in the order strings.Replacer applies them: at each
// position, the first form in argument order (keys longest first, then each
// key's forms in order) that stands as a whole token there wins. Text a
// match replaces is not searched again.
type matcher struct {
	byFirst [256][]matchForm
	// query judges the bytes around a match as a query string decodes them:
	// "%20919" holds "919" after a space.
	query bool
}

func newMatcher(keys []string, query bool, forms func(string) []string) *matcher {
	m := &matcher{query: query}
	for k, key := range keys {
		if key == "" {
			continue
		}
		// Escaping never changes a token byte, so the stand-in's own edges
		// tell whether every form's edges need a boundary.
		start, end := TokenByte(key[0]), TokenByte(key[len(key)-1])
		for _, f := range forms(key) {
			if f != "" {
				m.byFirst[f[0]] = append(m.byFirst[f[0]], matchForm{f, k, start, end})
			}
		}
	}
	return m
}

// at returns the form that matches text at i, or nil.
func (m *matcher) at(text string, i int) *matchForm {
	forms := m.byFirst[text[i]]
	for j := range forms {
		f := &forms[j]
		if !strings.HasPrefix(text[i:], f.text) {
			continue
		}
		if f.tokenStart && i > 0 && TokenByte(m.before(text, i)) {
			continue
		}
		if end := i + len(f.text); f.tokenEnd && end < len(text) && TokenByte(m.after(text, end)) {
			continue
		}
		return f
	}
	return nil
}

// before is the byte before text[i], decoded when the matcher reads a query
// string and it ends a %XX escape.
func (m *matcher) before(text string, i int) byte {
	if m.query && i >= 3 && text[i-3] == '%' {
		if c, ok := unhex2(text[i-2], text[i-1]); ok {
			return c
		}
	}
	return text[i-1]
}

// after is the byte at text[i], decoded when the matcher reads a query
// string and it begins a %XX escape.
func (m *matcher) after(text string, i int) byte {
	if m.query && text[i] == '%' && i+2 < len(text) {
		if c, ok := unhex2(text[i+1], text[i+2]); ok {
			return c
		}
	}
	return text[i]
}

func unhex2(a, b byte) (byte, bool) {
	x, ok1 := unhex(a)
	y, ok2 := unhex(b)
	return x<<4 | y, ok1 && ok2
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (m *matcher) scan(text string, hit []bool) {
	for i := 0; i < len(text); {
		if f := m.at(text, i); f != nil {
			hit[f.key] = true
			i += len(f.text)
		} else {
			i++
		}
	}
}

// replacer replaces the forms a matcher finds with their key's replacement.
type replacer struct {
	m    *matcher
	repl []string // by key
	// unsafe marks, by key, real values that must not go into a header.
	unsafe []bool
}

// write writes text to w with every match replaced, and reports whether one
// of the replaced keys is unsafe.
func (r *replacer) write(w *limitedBuilder, text string) (unsafe bool, err error) {
	last := 0
	for i := 0; i < len(text); {
		f := r.m.at(text, i)
		if f == nil {
			i++
			continue
		}
		if _, err := w.WriteString(text[last:i]); err != nil {
			return false, err
		}
		if _, err := w.WriteString(r.repl[f.key]); err != nil {
			return false, err
		}
		unsafe = unsafe || r.unsafe[f.key]
		i += len(f.text)
		last = i
	}
	_, err = w.WriteString(text[last:])
	return unsafe, err
}
