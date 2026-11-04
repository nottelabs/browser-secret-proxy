package hostmatch

import (
	"net"
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// FuzzHostOf checks the authority parser that every host decision rests
// on. A host it returns is canonical and is the host net/url and
// net.SplitHostPort find in the same authority, and the allowlist matches
// an authority only through that host.
func FuzzHostOf(f *testing.F) {
	for _, s := range []string{
		"api.example.com", "API.Example.COM.:443", "[::1]:8443", "::1", "10.0.0.1:80", "a.pay.example",
		"allowed.test:443@evil.test", "evil.test#@allowed.test", "allowed.test:", "allowed.test:44x", "[::1", "[allowed.test]:1",
		"allowed.test\t", "allowed.test..", "%61llowed.test",
	} {
		f.Add(s)
	}
	list, err := New([]string{"api.example.com", "*.pay.example", "allowed.test"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, authority string) {
		host := hostOf(authority)
		if list.Match(authority) {
			if host == "" || !list.Match(host) {
				t.Fatalf("Match(%q) through host %q", authority, host)
			}
		}
		if SameHost(authority, authority) != (host != "") {
			t.Fatalf("SameHost(%q, itself) with host %q", authority, host)
		}
		if host == "" {
			return
		}
		if strings.ContainsAny(host, "@/?#") || strings.ContainsFunc(host, unicode.IsSpace) || host != strings.ToLower(host) {
			t.Fatalf("hostOf(%q) = %q, not canonical", authority, host)
		}
		// A bare IPv6 address has no port, and net/url and SplitHostPort
		// would cut it at its last colon.
		if strings.Count(authority, ":") > 1 && !strings.HasPrefix(authority, "[") {
			if net.ParseIP(host) == nil {
				t.Fatalf("hostOf(%q) = %q, not an IPv6 address", authority, host)
			}
			return
		}
		// net/url and SplitHostPort accept a port that is not a number.
		if i := strings.LastIndexByte(authority, ':'); i > strings.LastIndexByte(authority, ']') {
			if port := authority[i+1:]; port == "" || strings.Trim(port, "0123456789") != "" {
				t.Fatalf("hostOf(%q) = %q, with port %q", authority, host, port)
			}
		}
		if u, err := url.Parse("https://" + authority); err == nil && !strings.Contains(authority, "%") {
			if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				t.Fatalf("hostOf(%q) = %q, but net/url finds more than an authority: %#v", authority, host, u)
			}
			if got := canonical(u.Hostname()); got != host {
				t.Fatalf("hostOf(%q) = %q, net/url finds %q", authority, host, got)
			}
		}
		if h, _, err := net.SplitHostPort(authority); err == nil && canonical(h) != host {
			t.Fatalf("hostOf(%q) = %q, net.SplitHostPort finds %q", authority, host, h)
		}
	})
}

// FuzzNew builds allowlists from arbitrary entries: an exact entry matches
// its own name, with or without a port, and nothing else it accepts
// matches a name that no entry covers.
func FuzzNew(f *testing.F) {
	f.Add("api.example.com,*.pay.example", "x.pay.example:443")
	f.Add(" Upper.Example.ORG. ", "upper.example.org")
	f.Add("*.a.b", "a.b")
	f.Add("a\tb", "a\tb")
	f.Fuzz(func(t *testing.T, entries, host string) {
		raw := strings.Split(entries, ",")
		list, err := New(raw)
		if err != nil {
			return
		}
		for _, e := range raw {
			name := canonical(e)
			// An entry in brackets, with whitespace other than spaces, or
			// with two trailing dots is accepted but matches nothing.
			if name == "" || strings.HasPrefix(name, "*.") || strings.HasPrefix(name, "[") || strings.HasSuffix(name, ".") || strings.ContainsFunc(name, unicode.IsSpace) {
				continue
			}
			if !list.Match(name) || !list.Match(name+":443") || !list.Match(asciiUpper(name)+".") {
				t.Fatalf("list %q does not match its entry %q", raw, name)
			}
		}
		if !list.Match(host) {
			return
		}
		h := hostOf(host)
		for _, e := range raw {
			name := canonical(e)
			if suffix, ok := strings.CutPrefix(name, "*"); ok && strings.HasSuffix(h, suffix) || h == name {
				return
			}
		}
		t.Fatalf("list %q matches %q (host %q), which no entry covers", raw, host, h)
	})
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
