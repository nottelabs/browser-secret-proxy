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
