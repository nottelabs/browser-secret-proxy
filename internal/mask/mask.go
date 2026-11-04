// Package mask replaces real values with their stand-ins in responses, so a
// destination that echoes a real value back does not reveal it to the
// client.
//
// Each real value is recognized in the forms a response is likely to carry
// it in: as is, JSON-escaped (with and without HTML escaping), query- and
// path-escaped, HTML-escaped, as decimal or hexadecimal character
// references, and, for card numbers, grouped by spaces or dashes. Each form
// is replaced by the same form of the stand-in, so the response stays valid
// JSON, URL or HTML.
//
// A Writer masks a stream with a bounded window: it holds back at most the
// length of the longest form minus one byte, and only while those bytes
// could still begin a real value.
package mask

import (
	"bytes"
	"encoding/json"
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

// form is one way a real value can appear, and what replaces it.
type form struct {
	from, to []byte
}

// Masker replaces real values with stand-ins. A nil Masker masks nothing.
type Masker struct {
	byFirst    [256][]form // by first byte, longest first
	maxLen     int
	sameLength bool
	forms      int
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
	m := &Masker{sameLength: true}
	seen := map[string]bool{}
	for _, p := range sorted {
		if len(p.Real) < MinLength || p.Real == p.StandIn {
			continue
		}
		for _, f := range forms(p.Real, p.StandIn) {
			if seen[string(f.from)] || bytes.Equal(f.from, f.to) {
				continue
			}
			seen[string(f.from)] = true
			m.byFirst[f.from[0]] = append(m.byFirst[f.from[0]], f)
			m.maxLen = max(m.maxLen, len(f.from))
			m.sameLength = m.sameLength && len(f.from) == len(f.to)
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

// SameLength reports whether masking never changes the length of the text:
// every form of every real value has a stand-in of the same length. Masked
// content can then keep its Content-Length.
func (m *Masker) SameLength() bool { return m == nil || m.sameLength }

// MaxLength is the length of the longest form, which bounds what a Writer
// holds back.
func (m *Masker) MaxLength() int {
	if m == nil {
		return 0
	}
	return m.maxLen
}

// String masks s.
func (m *Masker) String(s string) string {
	if m == nil {
		return s
	}
	out, _ := m.scan(nil, []byte(s), true)
	return string(out)
}

// Bytes masks b. The result may share no memory with b.
func (m *Masker) Bytes(b []byte) []byte {
	if m == nil {
		return b
	}
	out, _ := m.scan(nil, b, true)
	return out
}

// scan appends the masked form of buf to out. Unless final, it stops at the
// first position where a form might begin but buf ends first, and returns
// that position: those bytes need more input to decide.
func (m *Masker) scan(out, buf []byte, final bool) ([]byte, int) {
	i, last := 0, 0
	for i < len(buf) {
		candidates := m.byFirst[buf[i]]
		if len(candidates) == 0 {
			i++
			continue
		}
		matched, hold := false, false
		for _, f := range candidates {
			if len(buf)-i >= len(f.from) {
				if bytes.Equal(buf[i:i+len(f.from)], f.from) {
					out = append(out, buf[last:i]...)
					out = append(out, f.to...)
					i += len(f.from)
					last = i
					matched = true
					break
				}
			} else if !final && bytes.HasPrefix(f.from, buf[i:]) {
				// A longer form may still match; it wins over shorter ones.
				hold = true
				break
			}
		}
		if hold {
			break
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
	w       io.Writer
	pending []byte // bytes that may begin a real value, at most MaxLength-1
}

// NewWriter returns a Writer to w, which may keep the slices it is given.
// Close flushes what it holds back.
func (m *Masker) NewWriter(w io.Writer) *Writer {
	return &Writer{m: m, w: w}
}

// Write masks p. Bytes that could begin a real value are held back until the
// next Write or Close decides them.
func (w *Writer) Write(p []byte) (int, error) {
	if w.m == nil {
		return w.w.Write(p)
	}
	buf := p
	if len(w.pending) > 0 {
		buf = append(w.pending, p...)
	}
	out, done := w.m.scan(nil, buf, false)
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
	out, _ := w.m.scan(nil, w.pending, true)
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
	encodings := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return jsonEscape(s, false) },
		func(s string) string { return jsonEscape(s, true) },
		url.QueryEscape,
		url.PathEscape,
		html.EscapeString,
		func(s string) string { return references(s, "&#%d;") },
		func(s string) string { return references(s, "&#x%x;") },
		func(s string) string { return references(s, "&#X%X;") },
	}
	var out []form
	for _, v := range variants {
		for _, encode := range encodings {
			from := encode(v.from)
			if from != "" {
				out = append(out, form{from: []byte(from), to: []byte(encode(v.to))})
			}
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
