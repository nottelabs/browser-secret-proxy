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
// longer stand-in first at each position, and replaced text not searched
// again. A stand-in found only inside a longer one, or only in a form its
// place does not replace, is not returned.
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
	literal := newMatcher(keys, func(k string) []string { return []string{k} })
	switch part.Place {
	case Query:
		newMatcher(keys, func(k string) []string { return distinct(k, url.QueryEscape(k), url.PathEscape(k)) }).scan(part.Text, hit)
	case JSON:
		inString := newMatcher(keys, func(k string) []string { return distinct(k, jsonEscape(k)) })
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

type matchForm struct {
	text string
	key  int
}

// matcher finds forms in the order strings.Replacer applies them: at each
// position, the first form in argument order (keys longest first, then each
// key's forms in order) wins.
type matcher struct{ byFirst [256][]matchForm }

func newMatcher(keys []string, forms func(string) []string) *matcher {
	m := &matcher{}
	for k, key := range keys {
		for _, f := range forms(key) {
			if f != "" {
				m.byFirst[f[0]] = append(m.byFirst[f[0]], matchForm{f, k})
			}
		}
	}
	return m
}

func (m *matcher) scan(text string, hit []bool) {
	for i := 0; i < len(text); {
		advanced := false
		for _, f := range m.byFirst[text[i]] {
			if strings.HasPrefix(text[i:], f.text) {
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
