package resolve

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type unknownResolver struct{}

func (unknownResolver) Resolve(context.Context, Request) (Result, error) { return Result{}, nil }

func TestDetectorFindsKnownStandInsInEveryForm(t *testing.T) {
	f, err := NewStatic(map[string]string{"tok a&b": "real1", `q"x`: "real2", "unused": "real3"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDetector(f, Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"/?t=tok+a%26b":                {"tok a&b"},
		"/p/tok%20a&b":                 {"tok a&b"},
		`{"k":"q\"x"}`:                 {`q"x`},
		"raw tok a&b and q\"x":         {`q"x`, "tok a&b"},
		"nothing here":                 nil,
		"almost tok a and q":           nil,
		"Authorization: Bearer unused": {"unused"},
	}
	for text, want := range cases {
		if got := d.Find(Principal{}, text); !reflect.DeepEqual(got, want) {
			t.Errorf("Find(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestDetectorSearchesEveryText(t *testing.T) {
	f, _ := NewStatic(map[string]string{"s1": "r1", "s2": "r2"})
	d, _ := NewDetector(f, Patterns{})
	got := d.Find(Principal{}, "/?a=s2", "header s1", "")
	if want := []string{"s1", "s2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDetectorPatterns(t *testing.T) {
	d, err := NewDetector(unknownResolver{}, Patterns{
		Regexps:  []string{`\b4[0-9]{15}\b`, `ssn_[0-9]{3}`},
		Prefixes: []string{"tok_"},
		Luhn:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"card=4242424242424242&x=1":   {"4242424242424242"},
		"card=4242424242424241":       nil, // fails the check digit
		"id=ssn_123":                  {"ssn_123"},
		"Bearer tok_abc-12_Z.":        {"tok_abc-12_Z"},
		"xtok_abc":                    nil, // not at a token boundary
		"tok_":                        nil, // nothing after the prefix
		`{"a":"tok_1","b":"tok_22"}`:  {"tok_1", "tok_22"},
		"tok_tok_1":                   {"tok_tok_1"},
		"two tok_x tok_x":             {"tok_x"},
		"4242424242424242 tok_q ok_r": {"4242424242424242", "tok_q"},
	}
	for text, want := range cases {
		if got := d.Find(Principal{}, text); !reflect.DeepEqual(got, want) {
			t.Errorf("Find(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestLuhnOnlyFiltersCardLikeMatches(t *testing.T) {
	d, err := NewDetector(unknownResolver{}, Patterns{Regexps: []string{`card_[0-9]+`, `[0-9]{4}( [0-9]{4}){3}`}, Luhn: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Find(Principal{}, "card_4242424242424241"); !reflect.DeepEqual(got, []string{"card_4242424242424241"}) {
		t.Errorf("a match with letters is not card-like and is kept: %q", got)
	}
	if got := d.Find(Principal{}, "4242 4242 4242 4242"); !reflect.DeepEqual(got, []string{"4242 4242 4242 4242"}) {
		t.Errorf("a grouped valid card was dropped: %q", got)
	}
	if got := d.Find(Principal{}, "4242 4242 4242 4241"); got != nil {
		t.Errorf("a grouped invalid card was kept: %q", got)
	}
}

func TestLuhn(t *testing.T) {
	for s, want := range map[string]bool{
		"4242424242424242": true, "4000056655665556": true, "5555555555554444": true,
		"378282246310005": true, "4242424242424241": false, "1234567890123": false,
	} {
		if got := luhnValid(s); got != want {
			t.Errorf("luhnValid(%s) = %v", s, got)
		}
	}
}

func TestDetectorNeedsSomethingToFind(t *testing.T) {
	if _, err := NewDetector(unknownResolver{}, Patterns{}); err == nil {
		t.Fatal("a resolver without known stand-ins and no pattern was accepted")
	}
	if _, err := NewDetector(unknownResolver{}, Patterns{Regexps: []string{"a*"}}); err == nil {
		t.Fatal("a pattern matching the empty string was accepted")
	}
	if _, err := NewDetector(unknownResolver{}, Patterns{Regexps: []string{"("}}); err == nil {
		t.Fatal("an invalid pattern was accepted")
	}
	if _, err := NewDetector(unknownResolver{}, Patterns{Prefixes: []string{""}}); err == nil {
		t.Fatal("an empty prefix was accepted")
	}
}

func TestSecretsAreNotFormatted(t *testing.T) {
	p := Principal{ID: "user", Password: "hunter2"}
	v := Value{Real: "real-secret"}
	for _, s := range []string{fmt.Sprint(p), fmt.Sprintf("%v %+v %#v", p, p, p), fmt.Sprint(v), fmt.Sprintf("%v %+v %#v", v, v, v)} {
		if strings.Contains(s, "hunter2") || strings.Contains(s, "real-secret") {
			t.Errorf("formatted output leaks a secret: %s", s)
		}
	}
}

// A run of repeated prefixes is scanned once, not once per occurrence.
func TestPrefixScanIsLinear(t *testing.T) {
	d, err := NewDetector(unknownResolver{}, Patterns{Prefixes: []string{"tok_"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{strings.Repeat("tok_", 1<<18), "x" + strings.Repeat("tok_", 1<<18)} {
		start := time.Now()
		d.Find(Principal{}, text)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("1 MiB of repeated prefixes took %v", elapsed)
		}
	}
	if got := d.Find(Principal{}, "tok_a,tok_b tok_tok_c"); !reflect.DeepEqual(got, []string{"tok_a", "tok_b", "tok_tok_c"}) {
		t.Fatalf("got %q", got)
	}
}

func BenchmarkFindRepeatedPrefixes(b *testing.B) {
	d, _ := NewDetector(unknownResolver{}, Patterns{Prefixes: []string{"tok_"}})
	text := strings.Repeat("tok_", 1<<16)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		d.Find(Principal{}, text)
	}
}
