package swap

import (
	"strings"
	"testing"
)

// Matches returns exactly the stand-ins a Swapper replaces, in every place,
// whatever their overlaps and escaped forms.
func TestMatchesIsWhatTheSwapperReplaces(t *testing.T) {
	keys := []string{"tok_a", "tok_ab", "tok_abc", "tok_a b", "b c", `q"x`, "tok_b"}
	values := map[string]string{}
	for _, k := range keys {
		values[k] = "<" + strings.ReplaceAll(strings.ReplaceAll(k, " ", "_"), `"`, "Q") + ">"
	}
	sw, err := New(values)
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{
		"tok_abc", "tok_ab tok_a", "x=b+c", "p/b%20c", "tok_abtok_b", "tok_a", "tok_a%20b", "tok_a+b", "tok_a b",
		`{"k":"b c"}`, `{"k":"q\"x"}`, `q"x`, `{"k":"tok_a b", "n": tok_a}`, "nothing", "tok_atok_ab",
	}
	for _, place := range []Place{Literal, Query, JSON} {
		for _, text := range texts {
			var swapped string
			switch place {
			case Literal:
				swapped, _, _ = sw.Header(text, 1<<20)
			case Query:
				out, _, _ := sw.Body("application/x-www-form-urlencoded", []byte(text), 1<<20)
				swapped = string(out)
			case JSON:
				out, _, _ := sw.Body("application/json", []byte(text), 1<<20)
				swapped = string(out)
			}
			var want []string
			for _, k := range keys {
				v := values[k]
				if strings.Contains(swapped, v) || strings.Contains(swapped, jsonEscape(v)) ||
					strings.Contains(swapped, strings.ReplaceAll(strings.ReplaceAll(v, "<", "%3C"), ">", "%3E")) {
					want = append(want, k)
				}
			}
			got := Matches(Part{Place: place, Text: text}, keys)
			if strings.Join(got, "|") != strings.Join(sortedCopy(want), "|") {
				t.Errorf("place %d, %q: matches %q, the swap replaced %q (%q)", place, text, got, want, swapped)
			}
		}
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
