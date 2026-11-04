package resolve

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// Patterns describe stand-ins by their shape, for resolvers that do not know
// them in advance (http) or as well as their known ones. Every match is
// looked up, and a match the resolver does not answer for stops the request,
// so a pattern must match stand-ins only.
type Patterns struct {
	// Regexps are regular expressions (RE2 syntax); each match is a
	// stand-in.
	Regexps []string
	// Prefixes are literal prefixes such as "tok_". A stand-in is the prefix
	// followed by at least one of A-Z, a-z, 0-9, "_" and "-", up to the
	// first other character, and not preceded by one of them.
	Prefixes []string
	// Luhn drops card-like matches (12 to 19 digits, optionally grouped by
	// spaces or dashes) whose check digit is wrong, so arbitrary digit runs
	// are not taken for card stand-ins.
	Luhn bool
}

// Empty reports whether no pattern is set.
func (p Patterns) Empty() bool { return len(p.Regexps) == 0 && len(p.Prefixes) == 0 }

// Detector finds the stand-ins in request text: the resolver's known
// stand-ins, in every form a swap recognizes (raw, query-escaped,
// path-escaped, JSON-escaped), plus matches of the configured patterns.
type Detector struct {
	known    KnownStandIns
	regexps  []*regexp.Regexp
	prefixes []string
	luhn     bool
}

// NewDetector builds a Detector for a resolver. It returns an error when the
// detector could never find anything: the resolver knows no stand-ins in
// advance and no pattern is set.
func NewDetector(r Resolver, p Patterns) (*Detector, error) {
	d := &Detector{luhn: p.Luhn}
	if known, ok := r.(KnownStandIns); ok {
		d.known = known
	}
	for _, expr := range p.Regexps {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("stand-in pattern %q: %w", expr, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("stand-in pattern %q matches the empty string", expr)
		}
		d.regexps = append(d.regexps, re)
	}
	for _, prefix := range p.Prefixes {
		if prefix == "" {
			return nil, fmt.Errorf("empty stand-in prefix")
		}
		d.prefixes = append(d.prefixes, prefix)
	}
	if d.known == nil && p.Empty() {
		return nil, fmt.Errorf("this resolver does not know its stand-ins in advance: set a stand-in pattern or prefix")
	}
	return d, nil
}

// Find returns the distinct stand-ins in texts, in canonical (unescaped)
// form, sorted. It returns nil when there are none.
func (d *Detector) Find(p Principal, texts ...string) []string {
	found := map[string]bool{}
	if d.known != nil {
		for _, standIn := range d.known.StandIns(p) {
			if standIn != "" && containsAny(texts, swap.Forms(standIn)) {
				found[standIn] = true
			}
		}
	}
	for _, text := range texts {
		for _, re := range d.regexps {
			for _, m := range re.FindAllString(text, -1) {
				if m != "" && (!d.luhn || !cardLike(m) || luhnValid(m)) {
					found[m] = true
				}
			}
		}
		for _, prefix := range d.prefixes {
			findPrefixed(text, prefix, found)
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func containsAny(texts, forms []string) bool {
	for _, text := range texts {
		for _, form := range forms {
			if strings.Contains(text, form) {
				return true
			}
		}
	}
	return false
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// findPrefixed adds every prefix-led token of text to found.
func findPrefixed(text, prefix string, found map[string]bool) {
	for i := 0; i < len(text); {
		j := strings.Index(text[i:], prefix)
		if j < 0 {
			return
		}
		start := i + j
		end := start + len(prefix)
		for end < len(text) && tokenByte(text[end]) {
			end++
		}
		if end > start+len(prefix) && (start == 0 || !tokenByte(text[start-1])) {
			found[text[start:end]] = true
		}
		i = start + 1
	}
}

// cardLike reports whether s is 12 to 19 digits, optionally grouped by
// spaces or dashes.
func cardLike(s string) bool {
	digits := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == ' ' || c == '-':
		default:
			return false
		}
	}
	return digits >= 12 && digits <= 19
}

// luhnValid checks the Luhn check digit of the digits in s.
func luhnValid(s string) bool {
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		n := int(c - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}
