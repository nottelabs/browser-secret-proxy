// Package hostmatch decides which hosts the proxy decrypts.
package hostmatch

import (
	"fmt"
	"net"
	"strings"
	"unicode"
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

// Match reports whether host (with or without a port) is on the list. An
// authority that is not a plain host and port (see SameHost) is not.
func (l *List) Match(host string) bool {
	if l == nil {
		return false
	}
	name := hostOf(host)
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

// SameHost reports whether a and b (each with or without a port) name the
// same host: ports are ignored, case and a trailing dot too. An empty name
// matches nothing, and so does an authority that is not a plain host and
// port: one with userinfo, a path, query or fragment, whitespace, or a port
// that is empty or not a number.
func SameHost(a, b string) bool {
	x, y := hostOf(a), hostOf(b)
	return x != "" && x == y
}

func canonical(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// hostOf returns the canonical host of an authority: a name or an IPv4
// address, or an IPv6 address in brackets, each with or without ":" and a
// port, or a bare IPv6 address (as net.SplitHostPort returns it). It returns
// "" for anything else: "allowed.test:443@evil.test", for one, names
// evil.test under RFC 3986, so it must not count as allowed.test.
func hostOf(authority string) string {
	if strings.ContainsAny(authority, "@/?#") || strings.ContainsFunc(authority, unicode.IsSpace) {
		return ""
	}
	host, port, hasPort := authority, "", false
	switch {
	case strings.HasPrefix(authority, "["):
		inner, rest, ok := strings.Cut(authority[1:], "]")
		if !ok || !strings.Contains(inner, ":") || net.ParseIP(inner) == nil {
			return ""
		}
		host = inner
		if rest != "" {
			if port, hasPort = strings.CutPrefix(rest, ":"); !hasPort {
				return ""
			}
		}
	case strings.Count(authority, ":") == 1:
		host, port, hasPort = strings.Cut(authority, ":")
	case strings.Contains(authority, ":"):
		if net.ParseIP(authority) == nil {
			return ""
		}
	}
	if hasPort && (port == "" || strings.Trim(port, "0123456789") != "") {
		return ""
	}
	return canonical(host)
}
