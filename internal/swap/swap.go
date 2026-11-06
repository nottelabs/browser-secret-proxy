// Package swap replaces stand-in values with real ones.
//
// Each place a stand-in can appear gets the real value in the form that
// place needs: query strings and form bodies get it query-escaped, JSON
// strings get it JSON-escaped, header values and other bodies get it as is
// (a header refuses values with line breaks). A stand-in is replaced only
// where it stands as a whole token: when it begins or ends with a letter, a
// digit, "_" or "-", the byte next to it must not be one (TokenByte), so a
// short stand-in such as a CVC does not replace digits of a longer number.
// Every swap has an output
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
	"slices"
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
	literal    *replacer // raw text: header values and bodies other than forms and JSON
	query      *replacer // query strings and form bodies, real values query-escaped
	jsonString *replacer // inside JSON strings, real values JSON-escaped
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
	// The matcher tries forms in key order at each position.
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	n := len(keys)
	literal, query, jsonString := make([]string, n), make([]string, n), make([]string, n)
	unsafe := make([]bool, n)
	for i, k := range keys {
		literal[i] = values[k]
		unsafe[i] = strings.ContainsAny(values[k], headerBreaks)
		// In a query string or form body the real value must arrive as one
		// query value ("a&b+c" becomes "a%26b%2Bc"), whichever form the
		// stand-in took there.
		query[i] = url.QueryEscape(values[k])
		// In a JSON string it must decode to itself ("a\"b" for a"b).
		jsonString[i] = jsonEscape(values[k])
	}
	return &Swapper{
		literal:    &replacer{m: newMatcher(keys, false, literalForms), repl: literal, unsafe: unsafe},
		query:      &replacer{m: newMatcher(keys, true, queryForms), repl: query, unsafe: unsafe},
		jsonString: &replacer{m: newMatcher(keys, false, jsonForms), repl: jsonString, unsafe: unsafe},
		keys:       keys,
	}, nil
}

// Forms returns the distinct forms in which a Swapper recognizes a
// stand-in: as is, query-escaped, path-escaped and JSON-escaped. A request
// carries the stand-in when it contains any of them.
func Forms(standIn string) []string {
	forms := []string{standIn}
	for _, f := range []string{url.QueryEscape(standIn), url.PathEscape(standIn), jsonEscape(standIn)} {
		if !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	return forms
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

func replace(r *replacer, in string, limit int) (string, bool, error) {
	out, _, changed, err := replaceUnsafe(r, in, limit)
	return out, changed, err
}

// replaceUnsafe is replace that also reports whether a replaced stand-in's
// real value must not go into a header.
func replaceUnsafe(r *replacer, in string, limit int) (string, bool, bool, error) {
	w := &limitedBuilder{limit: limit}
	unsafe, err := r.write(w, in)
	if err != nil {
		return "", false, false, err
	}
	out := w.b.String()
	return out, unsafe, out != in, nil
}

// headerBreaks are the bytes a real value must not hold to go into a header.
const headerBreaks = "\r\n\x00"

// Header swaps stand-ins in a header value, inserting real values as is.
// The result is at most limit bytes. A swap that would insert a real value
// holding a line break or NUL is refused, whatever the value already holds.
func (s *Swapper) Header(value string, limit int) (string, bool, error) {
	out, unsafe, changed, err := replaceUnsafe(s.literal, value, limit)
	if err != nil || !changed {
		return value, false, err
	}
	if unsafe {
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
	write := func(inString bool, segment string) error {
		if inString {
			return s.writeJSONString(w, segment)
		}
		_, err := s.literal.write(w, segment)
		return err
	}
	inString := false
	start := 0
	for i := 0; i < len(in); i++ {
		switch {
		case inString && in[i] == '\\':
			i++ // the escaped character cannot end the string
		case in[i] == '"':
			if err := write(inString, in[start:i]); err != nil {
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
		if err := write(inString, in[start:]); err != nil {
			return "", false, err
		}
	}
	out := w.b.String()
	return out, out != in, nil
}

// writeJSONString swaps stand-ins in the content of one JSON string. A
// string with escapes is decoded first, so an escaped stand-in is found
// too; if a stand-in was replaced, the whole string is written again with
// standard escaping, which decodes to the same text with the real value.
// Otherwise the string is copied as it was.
func (s *Swapper) writeJSONString(w *limitedBuilder, segment string) error {
	decoded, ok := decodeJSONString(segment)
	if !ok {
		_, err := s.jsonString.write(w, segment)
		return err
	}
	// The escaped output is never shorter than the decoded text, so the
	// room left bounds the replacement too.
	replaced := &limitedBuilder{limit: w.limit - w.b.Len()}
	if _, err := s.literal.write(replaced, decoded); err != nil {
		return err
	}
	if replaced.b.String() == decoded {
		_, err := w.WriteString(segment)
		return err
	}
	return writeJSONEscaped(w, replaced.b.String())
}
