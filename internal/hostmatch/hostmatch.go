// Package hostmatch decides which hosts the proxy decrypts.
package hostmatch

import (
	"fmt"
	"net"
	"strings"
)

// List is a host allowlist. An entry is an exact host name, or "*." followed
// by a domain, which matches every name below that domain (any depth) but not
// the domain itself.
type List struct {
	exact    map[string]bool
	suffixes []string // ".example.com"
}

// New validates the entries and builds a List.
func New(entries []string) (*List, error) {
	l := &List{exact: map[string]bool{}}
	for _, raw := range entries {
		entry := canonical(raw)
		if entry == "" {
			continue
		}
		wildcard := strings.HasPrefix(entry, "*.")
		name := strings.TrimPrefix(entry, "*.")
		if err := validate(name); err != nil {
			return nil, fmt.Errorf("host %q: %w", raw, err)
		}
		if wildcard {
			l.suffixes = append(l.suffixes, "."+name)
		} else {
			l.exact[name] = true
		}
	}
	if len(l.exact) == 0 && len(l.suffixes) == 0 {
		return nil, fmt.Errorf("the host allowlist is empty")
	}
	return l, nil
}

func validate(name string) error {
	switch {
	case name == "" || name == "*":
		return fmt.Errorf("a bare wildcard is not allowed")
	case strings.ContainsAny(name, "*"):
		return fmt.Errorf("only a leading \"*.\" wildcard is allowed")
	case strings.ContainsAny(name, "/:?#@ "):
		return fmt.Errorf("give a host name only, without scheme, port or path")
	case strings.HasPrefix(name, ".") || strings.Contains(name, ".."):
		return fmt.Errorf("empty label")
	}
	return nil
}

// Match reports whether host (with or without a port) is on the list.
func (l *List) Match(host string) bool {
	if l == nil {
		return false
	}
	name := canonical(stripPort(host))
	if name == "" {
		return false
	}
	if l.exact[name] {
		return true
	}
	for _, suffix := range l.suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func canonical(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}
