package swap

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeJSONString(t *testing.T) {
	cases := map[string]string{
		`tok\u005fa`:                      "tok_a",
		`a\u0026b \u003c\u003e`:           "a&b <>",
		`\u0041\u0062C`:                   "AbC",
		`q\"x\\y\/z\b\f\n\r\t`:            "q\"x\\y/z\b\f\n\r\t",
		`\ud83d\ude00 \u00e9 ` + "\u00e9": "\U0001F600 \u00e9 \u00e9",
		// Refused (""), so matched as written:
		`\U00410`:        "", // \U is not an escape
		`\u00`:           "", // short
		`\ud83d`:         "", // lone high surrogate
		`\ude00`:         "", // lone low surrogate
		`\ud83d\u0041`:   "", // high surrogate without a low one
		"tab\there\\n":   "", // raw control character
		"bad\xffutf8\\n": "", // invalid UTF-8
		`trailing\`:      "", // escape cut off
		`\u+041`:         "", // not hex
	}
	for in, want := range cases {
		got, ok := decodeJSONString(in)
		if want == "" {
			if ok {
				t.Errorf("decode(%q) = %q, want a refusal", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("decode(%q) = %q, %v; want %q", in, got, ok, want)
		}
		var std string // encoding/json agrees
		if err := json.Unmarshal([]byte(`"`+in+`"`), &std); err != nil || std != want {
			t.Errorf("encoding/json decodes %q to %q (%v)", in, std, err)
		}
	}
	if _, ok := decodeJSONString("no escapes"); ok {
		t.Error("a string without escapes was decoded: it is matched as written")
	}
}

func TestWriteJSONEscapedMatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{"plain", `q"x\y`, "\n\r\t\b\f\x00\x1f", "\u00e9 \U0001F600", "\u2028\u2029", "a&b<c>", "bad\xffbyte", ""} {
		w := &limitedBuilder{limit: 1 << 20}
		if err := writeJSONEscaped(w, s); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		want := strings.TrimSuffix(buf.String(), "\n")
		if got := `"` + w.b.String() + `"`; got != want {
			t.Errorf("escape(%q) = %s, encoding/json gives %s", s, got, want)
		}
	}
}

func TestJSONBodyFindsEscapedStandIns(t *testing.T) {
	s, err := New(map[string]string{"tok_a": "real_a", "a&b_token": "real<&>", "4242424242424242": "4111111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	// What Go's json.Marshal sends by default: & < > escaped.
	goEncoded, _ := json.Marshal(map[string]string{"t": "a&b_token", "note": "<keep>"})
	if !strings.Contains(string(goEncoded), `a\u0026b_token`) {
		t.Fatalf("json.Marshal no longer escapes &: %s", goEncoded)
	}
	cases := map[string]string{
		`{"t":"tok\u005fa"}`:                `{"t":"real_a"}`,
		`{"t":"\u0074\u006F\u006b\u005fa"}`: `{"t":"real_a"}`,
		`{"c":"\u0034242424242424242"}`:     `{"c":"4111111111111111"}`,
		string(goEncoded):                   `{"note":"\u003ckeep\u003e","t":"real<&>"}`,
		// A string with a stand-in is written again in standard form; the
		// others are copied as they were.
		`{"t":"x\u00e9 tok_a\/y","u":"\u00e9"}`: `{"t":"x` + "\u00e9" + ` real_a/y","u":"\u00e9"}`,
		// Not strictly valid: matched as written, as before.
		`{"t":"tok_a\ud83d"}`:  `{"t":"real_a\ud83d"}`,
		`{"t":"tok\u005fa\x"}`: `{"t":"tok\u005fa\x"}`,
		`{"t":"plain tok_a"}`:  `{"t":"plain real_a"}`,
	}
	for in, want := range cases {
		out, _, err := s.Body("application/json", []byte(in), 1<<20)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(out) != want {
			t.Errorf("Body(%s)\n got %s\nwant %s", in, out, want)
		}
	}
	out, _, _ := s.Body("application/json", goEncoded, 1<<20)
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil || got["t"] != "real<&>" || got["note"] != "<keep>" {
		t.Fatalf("decoded %v (%v)", got, err)
	}
}

func TestEscapedJSONSwapIsLimited(t *testing.T) {
	s, _ := New(map[string]string{"t1": strings.Repeat("R", 100)})
	in := `{"a":"` + strings.Repeat(`t\u0031`, 50) + `"}`
	if _, _, err := s.Body("application/json", []byte(in), 1000); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Control characters escape to six bytes each: the limit holds on the
	// escaped output, not only on the decoded text.
	s, _ = New(map[string]string{"t1": strings.Repeat("\x01", 100)})
	if _, _, err := s.Body("application/json", []byte(`{"a":"t\u0031"}`), 300); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge for the escaped output", err)
	}
	if out, _, err := s.Body("application/json", []byte(`{"a":"t\u0031"}`), 1000); err != nil || !strings.Contains(string(out), `\u0001`) {
		t.Fatalf("within the limit: %s, %v", out, err)
	}
}

// Matches reports what the swapper replaces in escaped JSON strings, so the
// proxy looks those stand-ins up.
func TestMatchesSeesEscapedStandIns(t *testing.T) {
	keys := []string{"a&b", "tok_a", "tok_ab"}
	s, _ := New(map[string]string{"a&b": "R", "tok_a": "R", "tok_ab": "R"})
	for in, want := range map[string]string{
		`{"x":"tok\u005fa"}`:   "tok_a",
		`{"x":"tok\u005fab"}`:  "tok_ab", // the longer stand-in wins
		`{"x":"a\u0026b"}`:     "a&b",
		`{"x":"a&b"}`:          "a&b",
		`{"x":"tok_a\ud83d"}`:  "tok_a", // matched as written
		`{"x":"tok\u005fa\x"}`: "",      // not replaced, so not looked up
		`{"x":"none\u0026"}`:   "",
		`{"x":1}`:              "",
	} {
		if got := strings.Join(Matches(Part{Place: JSON, Text: in}, keys), ","); got != want {
			t.Errorf("Matches(%s) = %q, want %q", in, got, want)
		}
		_, changed, _ := s.Body("application/json", []byte(in), 1<<20)
		if changed != (want != "") {
			t.Errorf("Body(%s) changed=%v, Matches says %q", in, changed, want)
		}
	}
}
