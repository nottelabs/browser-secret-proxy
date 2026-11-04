package hostmatch

import "testing"

func TestMatch(t *testing.T) {
	list, err := New([]string{"api.example.com", "*.pay.example", " Upper.Example.ORG. "})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"api.example.com":        true,
		"API.EXAMPLE.COM":        true,
		"api.example.com:443":    true,
		"api.example.com.":       true,
		"www.example.com":        false,
		"example.com":            false,
		"evil-api.example.com":   false,
		"api.example.com.evil":   false,
		"checkout.pay.example":   true,
		"a.b.pay.example:8443":   true,
		"pay.example":            false,
		"notpay.example":         false,
		"upper.example.org":      true,
		"":                       false,
		"[::1]:443":              false,
		"x.pay.example.attacker": false,
		"api.example.com:443@x":  false,
		"x@api.example.com":      false,
	}
	for host, want := range cases {
		if got := list.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestNewRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{"*", "*.", "a.*.example.com", "*example.com", "https://example.com", "example.com:443", "example.com/path", ".example.com", "a..b"} {
		if _, err := New([]string{entry}); err == nil {
			t.Errorf("New(%q) succeeded, want an error", entry)
		}
	}
	if _, err := New([]string{" ", ""}); err == nil {
		t.Error("an empty allowlist was accepted")
	}
}

func TestNilListMatchesNothing(t *testing.T) {
	var list *List
	if list.Match("example.com") {
		t.Error("nil list matched")
	}
}

// SameHost ignores ports, case and a trailing dot, and refuses any authority
// that is not a plain host and port: its host could be another one than the
// text before the port ("allowed.test:443@evil.test" names evil.test).
func TestSameHost(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"allowed.test", "allowed.test", true},
		{"allowed.test:443", "allowed.test", true},
		{"ALLOWED.Test.:8443", "allowed.test", true},
		{"[::1]:443", "::1", true},
		{"[::1]", "::1", true},
		{"127.0.0.1:443", "127.0.0.1", true},
		{"evil.test", "allowed.test", false},
		{"", "", false},
		{":443", "", false},
		{"allowed.test:443@evil.test", "allowed.test", false},
		{"allowed.test:443@evil.test", "evil.test", false},
		{"user@allowed.test", "allowed.test", false},
		{"allowed.test/", "allowed.test", false},
		{"allowed.test?x", "allowed.test", false},
		{"allowed.test#x", "allowed.test", false},
		{"allowed.test :443", "allowed.test", false},
		{" allowed.test", "allowed.test", false},
		{"allowed.test\t", "allowed.test", false},
		{"allowed.test:", "allowed.test", false},
		{"allowed.test:https", "allowed.test", false},
		{"allowed.test:443:443", "allowed.test", false},
		{"[allowed.test]:443", "allowed.test", false},
		{"[::1]x", "::1", false},
		{"[::1", "::1", false},
	}
	for _, c := range cases {
		if got := SameHost(c.a, c.b); got != c.want {
			t.Errorf("SameHost(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestHost(t *testing.T) {
	cases := map[string]string{
		"api.example.com":               "api.example.com",
		"API.Example.COM.:443":          "api.example.com",
		"api.example.com.":              "api.example.com",
		"10.0.0.1:8443":                 "10.0.0.1",
		"[2001:DB8::1]:443":             "2001:db8::1",
		"::1":                           "::1",
		"":                              "",
		"api.example.com:":              "",
		"api.example.com:443@evil.test": "",
		"api.example.com/x":             "",
		"api .example.com":              "",
	}
	for authority, want := range cases {
		if got := Host(authority); got != want {
			t.Errorf("Host(%q) = %q, want %q", authority, got, want)
		}
	}
}
