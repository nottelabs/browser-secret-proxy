// Package mask replaces real values with their stand-ins in responses, so a
// destination that echoes a real value back does not reveal it to the
// client.
//
// Each real value is recognized in the forms a response is likely to carry
// it in: as is, JSON-escaped (with and without HTML escaping), query- and
// path-escaped, HTML-escaped, as decimal or hexadecimal character
// references, and, for card numbers, grouped by spaces or dashes. Each form
// is replaced by the same form of the stand-in, so the response stays valid
// JSON, URL or HTML. Where several forms are the same text (a value with no
// character to escape), the replacement is escaped for the Context it is
// found in, as the request side escapes real values: a stand-in with a quote
// goes into a JSON body JSON-escaped, into a Location header query-escaped.
//
// A Writer masks a stream with a bounded window. By default the window is
// Fixed: it always holds back the last bytes it was given, as many as the
// longest form minus one, whether or not they could begin a real value.
// When it passes text on, and how much, then depends only on how much was
// written and on whole forms replaced, never on how much of a real value the
// end of the text matched. A Minimal window holds back only bytes that could
// begin a real value, so streams keep flowing, but gives up that guarantee.
package mask

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"sort"
	"strings"
)

// MinLength is the shortest real value that is masked. Shorter values (a
// CVC, a PIN) would match unrelated text too often: replacing every "123"
// in a page would corrupt it.
const MinLength = 8

// Pair is a real value and the stand-in that replaces it.
type Pair struct {
	Real, StandIn string
}

// Context is where masked text sits, which decides how a replacement that
// could be any of several forms is escaped.
type Context int

// Contexts.
const (
	Text Context = iota // plain bodies, header values, trailers: as is
	JSON                // JSON and JavaScript: JSON-escaped
	URL                 // URLs, form bodies and cookies: query-escaped
	HTML                // HTML and XML: HTML-escaped
	numContexts
)

// encoding indexes, in the order forms tries them.
const (
	encIdentity = iota
	encJSON
	encJSONHTML
	encQuery
	encPath
	encHTML
	encDecimal
	encHex
	encHexUpper
	numEncodings
)

// preferred is the encoding each context uses for an ambiguous form.
var preferred = [numContexts]int{Text: encIdentity, JSON: encJSON, URL: encQuery, HTML: encHTML}

var encodings = [numEncodings]func(string) string{
	encIdentity: func(s string) string { return s },
	encJSON:     func(s string) string { return jsonEscape(s, false) },
	encJSONHTML: func(s string) string { return jsonEscape(s, true) },
	encQuery:    url.QueryEscape,
	encPath:     url.PathEscape,
	encHTML:     html.EscapeString,
	encDecimal:  func(s string) string { return references(s, "&#%d;") },
	encHex:      func(s string) string { return references(s, "&#x%x;") },
	encHexUpper: func(s string) string { return references(s, "&#X%X;") },
}

// ContextOf is the context of a body with this Content-Type.
func ContextOf(contentType string) Context {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case mediaType == "application/json", mediaType == "text/json", mediaType == "application/x-ndjson",
		strings.HasSuffix(mediaType, "+json"), strings.HasSuffix(mediaType, "javascript"), strings.HasSuffix(mediaType, "ecmascript"):
		return JSON
	case mediaType == "application/x-www-form-urlencoded":
		return URL
	case mediaType == "text/html", mediaType == "application/xhtml+xml", mediaType == "text/xml",
		mediaType == "application/xml", strings.HasSuffix(mediaType, "+xml"):
		return HTML
	}
	return Text
}

// HeaderContext is the context of a header's value: URLs and cookies are
// query-escaped, so a stand-in cannot add a parameter or attribute.
func HeaderContext(name string) Context {
	switch strings.ToLower(name) {
	case "location", "content-location", "link", "refresh", "set-cookie":
		return URL
	}
	return Text
}

// Window is what a Writer holds back at the end of the text written so far.
// The zero Window is Fixed.
type Window int

// Windows.
const (
	// Fixed holds back the last MaxLength-1 bytes, whatever they are. A
	// stream runs that many bytes behind until it ends.
	Fixed Window = iota
	// Minimal holds back only bytes that could begin a form, so a stream
	// keeps flowing. A client that has a destination reflect its guesses
	// can then tell, from the size or timing of what it gets, how much of
	// a real value each guess matched.
	Minimal
)

var windowNames = [...]string{Fixed: "fixed", Minimal: "minimal"}

func (w Window) String() string {
	if w < 0 || int(w) >= len(windowNames) {
		return fmt.Sprintf("Window(%d)", int(w))
	}
	return windowNames[w]
}

// MarshalText returns the name of w: fixed or minimal.
func (w Window) MarshalText() ([]byte, error) {
	if w < 0 || int(w) >= len(windowNames) {
		return nil, fmt.Errorf("unknown window %d", int(w))
	}
	return []byte(windowNames[w]), nil
}

// UnmarshalText sets w from its name: fixed or minimal.
func (w *Window) UnmarshalText(text []byte) error {
	for i, name := range windowNames {
		if string(text) == name {
			*w = Window(i)
			return nil
		}
	}
	return errors.New("want fixed or minimal")
}

// form is one way a real value can appear, and what replaces it in each
// context.
type form struct {
	from []byte
	to   [numContexts][]byte
}

// Masker replaces real values with stand-ins. A nil Masker masks nothing.
type Masker struct {
	byFirst    [256][]form // by first byte, longest first
	maxLen     int
	sameLength [numContexts]bool
	forms      int
	window     Window
}

// New builds a Masker for pairs. Values shorter than MinLength are skipped.
// It returns nil when nothing is left to mask.
func New(pairs []Pair) *Masker {
	sorted := append([]Pair(nil), pairs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Real != sorted[j].Real {
			return sorted[i].Real < sorted[j].Real
		}
		return sorted[i].StandIn < sorted[j].StandIn
	})
	m := &Masker{sameLength: [numContexts]bool{true, true, true, true}}
	seen := map[string]bool{}
	for _, p := range sorted {
		if len(p.Real) < MinLength || p.Real == p.StandIn {
			continue
		}
		for _, f := range forms(p.Real, p.StandIn) {
			if seen[string(f.from)] || f.unchanged() {
				continue
			}
			seen[string(f.from)] = true
			m.byFirst[f.from[0]] = append(m.byFirst[f.from[0]], f)
			m.maxLen = max(m.maxLen, len(f.from))
			for c := range f.to {
				m.sameLength[c] = m.sameLength[c] && len(f.from) == len(f.to[c])
			}
			m.forms++
		}
	}
	if m.forms == 0 {
		return nil
	}
	for i := range m.byFirst {
		list := m.byFirst[i]
		sort.SliceStable(list, func(a, b int) bool { return len(list[a].from) > len(list[b].from) })
	}
	return m
}

func (f form) unchanged() bool {
	for _, to := range f.to {
		if !bytes.Equal(f.from, to) {
			return false
		}
	}
	return true
}

// SameLength reports whether masking in context c never changes the length
// of the text: every form of every real value has a stand-in of the same
// length. Masked content can then keep its Content-Length.
func (m *Masker) SameLength(c Context) bool { return m == nil || m.sameLength[c] }

// WithWindow sets the window of m's Writers, and returns m. Set it before m
// is shared.
func (m *Masker) WithWindow(w Window) *Masker {
	if m != nil {
		m.window = w
	}
	return m
}

// MaxLength is the length of the longest form. A Writer holds back one byte
// less.
func (m *Masker) MaxLength() int {
	if m == nil {
		return 0
	}
	return m.maxLen
}

// String masks s, which sits in context c.
func (m *Masker) String(c Context, s string) string {
	if m == nil {
		return s
	}
	out, _ := m.scan(nil, []byte(s), c, len(s), true)
	return string(out)
}

// scan appends the masked form of buf to out, for the forms that begin
// before end, and returns where it stopped: end, or past it when a form that
// begins before end runs over it. A form is only matched whole. Unless
// final, scan also stops at the first position where a form might begin but
// buf ends first: those bytes need more input to decide. With a Fixed
// window, buf holds a form's length past end, so that never happens.
func (m *Masker) scan(out, buf []byte, c Context, end int, final bool) ([]byte, int) {
	i, last := 0, 0
	for i < end {
		matched := false
		for _, f := range m.byFirst[buf[i]] {
			if len(buf)-i >= len(f.from) {
				if bytes.Equal(buf[i:i+len(f.from)], f.from) {
					out = append(out, buf[last:i]...)
					out = append(out, f.to[c]...)
					i += len(f.from)
					last = i
					matched = true
					break
				}
			} else if !final && bytes.HasPrefix(f.from, buf[i:]) {
				// A longer form may still match; it wins over shorter ones.
				return append(out, buf[last:i]...), i
			}
		}
		if !matched {
			i++
		}
	}
	return append(out, buf[last:i]...), i
}

// Writer masks a stream written to it and passes the result on to w.
type Writer struct {
	m       *Masker
	c       Context
	w       io.Writer
	pending []byte // held back, at most MaxLength-1
}

// NewWriter returns a Writer to w, for text in context c. w may keep the
// slices it is given. Close flushes what it holds back.
func (m *Masker) NewWriter(w io.Writer, c Context) *Writer {
	return &Writer{m: m, c: c, w: w}
}

// Write masks p. With a Fixed window, the last MaxLength-1 bytes written are
// held back until the next Write or Close, whatever they are: holding back
// only bytes that could begin a real value, as a Minimal window does, lets a
// client that reflects its guesses learn, from the size or the delay of what
// it gets, how much of a value each guess matched. A form that ends in the
// held bytes but begins before them is replaced at once.
func (w *Writer) Write(p []byte) (int, error) {
	if w.m == nil {
		return w.w.Write(p)
	}
	buf := p
	if len(w.pending) > 0 {
		buf = append(w.pending, p...)
	}
	end := len(buf)
	if w.m.window != Minimal { // anything else holds back the Fixed window
		end -= w.m.maxLen - 1
	}
	if end <= 0 {
		w.pending = append([]byte(nil), buf...)
		return len(p), nil
	}
	out, done := w.m.scan(nil, buf, w.c, end, false)
	w.pending = append([]byte(nil), buf[done:]...)
	if len(out) > 0 {
		if _, err := w.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Pending is the number of bytes held back.
func (w *Writer) Pending() int { return len(w.pending) }

// Close writes what is held back, masked. It does not close w.
func (w *Writer) Close() error {
	if w.m == nil || len(w.pending) == 0 {
		return nil
	}
	out, _ := w.m.scan(nil, w.pending, w.c, len(w.pending), true)
	w.pending = nil
	_, err := w.w.Write(out)
	return err
}

// forms lists the forms of real, each with the same form of standIn.
func forms(real, standIn string) []form {
	type variant struct{ from, to string }
	variants := []variant{{real, standIn}}
	for _, g := range cardGroupings(real) {
		for _, sep := range []string{" ", "-"} {
			to := standIn
			if digitsOnly(standIn) && len(standIn) == len(real) {
				to = group(standIn, g, sep)
			}
			variants = append(variants, variant{group(real, g, sep), to})
		}
	}
	var out []form
	for _, v := range variants {
		// The encodings that write this variant as each distinct text, in
		// order: a text several encodings share is ambiguous, and takes the
		// replacement of its context's encoding when that is one of them.
		var texts []string
		byText := map[string][]int{}
		for e, encode := range encodings {
			from := encode(v.from)
			if from == "" {
				continue
			}
			if _, ok := byText[from]; !ok {
				texts = append(texts, from)
			}
			byText[from] = append(byText[from], e)
		}
		for _, from := range texts {
			encs := byText[from]
			f := form{from: []byte(from)}
			for c := range f.to {
				e := encs[0]
				for _, candidate := range encs {
					if candidate == preferred[c] {
						e = candidate
					}
				}
				f.to[c] = []byte(encodings[e](v.to))
			}
			out = append(out, f)
		}
	}
	return out
}

func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cardGroupings returns the common ways a card number of this length is
// printed in groups: fours (the last group shorter), and 4-6-5 or 4-6-4 for
// 15 and 14 digits.
func cardGroupings(s string) [][]int {
	n := len(s)
	if !digitsOnly(s) || n < 13 || n > 19 {
		return nil
	}
	var fours []int
	for left := n; left > 0; left -= 4 {
		fours = append(fours, min(4, left))
	}
	out := [][]int{fours}
	switch n {
	case 15:
		out = append(out, []int{4, 6, 5})
	case 14:
		out = append(out, []int{4, 6, 4})
	}
	return out
}

func group(s string, sizes []int, sep string) string {
	parts := make([]string, 0, len(sizes))
	for _, size := range sizes {
		parts = append(parts, s[:size])
		s = s[size:]
	}
	return strings.Join(parts, sep)
}

// references writes each character of s as a numeric character reference.
func references(s, format string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, format, r)
	}
	return b.String()
}

// jsonEscape returns s as JSON string content, without the quotes.
func jsonEscape(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}
