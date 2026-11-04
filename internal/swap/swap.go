// Package swap replaces stand-in values with real ones.
//
// Each place a stand-in can appear gets the real value in the form that
// place needs: query strings and form bodies get it query-escaped, JSON
// strings get it JSON-escaped, header values and other bodies get it as is
// (a header refuses values with line breaks). Every swap has an output
// limit, checked while writing, so a short stand-in repeated many times
// cannot expand past it.
package swap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

var (
	// ErrTooLarge is a swap whose output would pass its limit.
	ErrTooLarge = errors.New("swapped content is larger than the limit")
	// ErrUnsafeHeader is a header swap that would put a line break or NUL
	// into a header value, which would split or corrupt the header.
	ErrUnsafeHeader = errors.New("a real value with a line break or NUL cannot go into a header")
)

// Swapper replaces every stand-in with its real value.
type Swapper struct {
	literal    *strings.Replacer // raw text: header values and bodies other than forms and JSON
	query      *strings.Replacer // query strings and form bodies, real values query-escaped
	jsonString *strings.Replacer // inside JSON strings, real values JSON-escaped
	keys       []string
}

// Load reads a JSON object mapping each stand-in to its real value.
func Load(path string) (*Swapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("%s: want a JSON object of stand-in to real value: %w", path, err)
	}
	return New(values)
}

// New builds a Swapper. Longer stand-ins win when one contains another.
func New(values map[string]string) (*Swapper, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("no stand-in values")
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		if k == "" {
			return nil, fmt.Errorf("empty stand-in")
		}
		keys = append(keys, k)
	}
	// strings.Replacer tries patterns in argument order at each position.
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	var literal, query, jsonString []string
	for _, k := range keys {
		literal = append(literal, k, values[k])
		// In a query string or form body the real value must arrive as one
		// query value ("a&b+c" becomes "a%26b%2Bc"), whichever form the
		// stand-in took there.
		query = appendForms(query, values[k], url.QueryEscape, k, url.QueryEscape(k), url.PathEscape(k))
		// In a JSON string it must decode to itself ("a\"b" for a"b).
		jsonString = appendForms(jsonString, values[k], jsonEscape, k, jsonEscape(k))
	}
	return &Swapper{
		literal:    strings.NewReplacer(literal...),
		query:      strings.NewReplacer(query...),
		jsonString: strings.NewReplacer(jsonString...),
		keys:       keys,
	}, nil
}

// appendForms adds a replacement of each distinct form of a stand-in by
// escape(real).
func appendForms(pairs []string, real string, escape func(string) string, forms ...string) []string {
	replacement := escape(real)
	seen := map[string]bool{}
	for _, form := range forms {
		if !seen[form] {
			seen[form] = true
			pairs = append(pairs, form, replacement)
		}
	}
	return pairs
}

// jsonEscape returns s as JSON string content, without the quotes.
func jsonEscape(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}

// Count is the number of stand-ins configured.
func (s *Swapper) Count() int { return len(s.keys) }

// limitedBuilder collects output and refuses to grow past its limit.
type limitedBuilder struct {
	b     strings.Builder
	limit int
}

func (w *limitedBuilder) WriteString(p string) (int, error) {
	if w.b.Len()+len(p) > w.limit {
		return 0, ErrTooLarge
	}
	return w.b.WriteString(p)
}

func (w *limitedBuilder) Write(p []byte) (int, error) { return w.WriteString(string(p)) }

func replace(r *strings.Replacer, in string, limit int) (string, bool, error) {
	w := &limitedBuilder{limit: limit}
	if _, err := r.WriteString(w, in); err != nil {
		return "", false, err
	}
	out := w.b.String()
	return out, out != in, nil
}

// Header swaps stand-ins in a header value, inserting real values as is.
// The result is at most limit bytes.
func (s *Swapper) Header(value string, limit int) (string, bool, error) {
	out, changed, err := replace(s.literal, value, limit)
	if err != nil || !changed {
		return value, false, err
	}
	if strings.ContainsAny(out, "\r\n\x00") && !strings.ContainsAny(value, "\r\n\x00") {
		return value, false, ErrUnsafeHeader
	}
	return out, true, nil
}

// Target swaps stand-ins in the query string of a request target
// ("/path?query" or an absolute URL), leaving the path untouched. Real
// values are query-escaped. The result is at most limit bytes.
func (s *Swapper) Target(target string, limit int) (string, bool, error) {
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return target, false, nil
	}
	query := target[i+1:]
	fragment := ""
	if j := strings.IndexByte(query, '#'); j >= 0 {
		query, fragment = query[:j], query[j:]
	}
	out, changed, err := replace(s.query, query, limit-(i+1)-len(fragment))
	if err != nil || !changed {
		return target, false, err
	}
	return target[:i+1] + out + fragment, true, nil
}

// Body swaps stand-ins in a request body in the form its content type
// needs: query-escaped in form bodies, JSON-escaped inside JSON strings, as
// is elsewhere. The result is at most limit bytes.
func (s *Swapper) Body(contentType string, in []byte, limit int) ([]byte, bool, error) {
	text := string(in)
	var out string
	var changed bool
	var err error
	switch bodyKind(contentType) {
	case formBody:
		out, changed, err = replace(s.query, text, limit)
	case jsonBody:
		out, changed, err = s.jsonText(text, limit)
	default:
		out, changed, err = replace(s.literal, text, limit)
	}
	if err != nil || !changed {
		return in, false, err
	}
	return []byte(out), true, nil
}

type kind int

const (
	rawBody kind = iota
	formBody
	jsonBody
)

func bodyKind(contentType string) kind {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return formBody
	case mediaType == "application/json", mediaType == "text/json", mediaType == "application/x-ndjson",
		strings.HasSuffix(mediaType, "+json"):
		return jsonBody
	}
	return rawBody
}

// jsonText swaps stand-ins in JSON text: inside string literals with
// JSON-escaped real values, outside them (a number, say) as is. Malformed
// JSON is handled the same way, as far as its quotes go.
func (s *Swapper) jsonText(in string, limit int) (string, bool, error) {
	w := &limitedBuilder{limit: limit}
	write := func(r *strings.Replacer, segment string) error {
		_, err := r.WriteString(w, segment)
		return err
	}
	inString := false
	start := 0
	for i := 0; i < len(in); i++ {
		switch {
		case inString && in[i] == '\\':
			i++ // the escaped character cannot end the string
		case in[i] == '"':
			r := s.literal
			if inString {
				r = s.jsonString
			}
			if err := write(r, in[start:i]); err != nil {
				return "", false, err
			}
			if _, err := w.WriteString(`"`); err != nil {
				return "", false, err
			}
			start = i + 1
			inString = !inString
		}
	}
	if start < len(in) {
		r := s.literal
		if inString {
			r = s.jsonString
		}
		if err := write(r, in[start:]); err != nil {
			return "", false, err
		}
	}
	out := w.b.String()
	return out, out != in, nil
}
