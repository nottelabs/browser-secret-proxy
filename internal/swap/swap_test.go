package swap

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const noLimit = 1 << 30

func newSwapper(t *testing.T) *Swapper {
	t.Helper()
	s, err := New(map[string]string{
		"4242424242424242": "4111111111111111",
		"tok_standin":      "sk_real_value_longer",
		"tok_standin_v2":   "sk_second",
		"name with space":  "Real Name&Co",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHeader(t *testing.T) {
	s := newSwapper(t)
	cases := map[string]string{
		"Bearer tok_standin":                    "Bearer sk_real_value_longer",
		"tok_standin_v2":                        "sk_second", // the longer stand-in wins
		"4242424242424242 and 4242424242424242": "4111111111111111 and 4111111111111111",
		"nothing here":                          "nothing here",
		"name%20with%20space":                   "name%20with%20space", // raw text is not decoded
	}
	for in, want := range cases {
		got, changed, err := s.Header(in, noLimit)
		if err != nil || got != want || changed != (in != want) {
			t.Errorf("Header(%q) = %q, %v, %v; want %q", in, got, changed, err, want)
		}
	}
}

// A real value with a line break or NUL is refused in a header, where it
// would split the header (or the HTTP/1.1 request) in two.
func TestHeaderRefusesLineBreaks(t *testing.T) {
	for _, real := range []string{"a\r\nX-Injected: 1", "a\nb", "a\rb", "a\x00b"} {
		s, err := New(map[string]string{"tok_standin": real})
		if err != nil {
			t.Fatal(err)
		}
		// A line break, bare CR or NUL the client put in the header itself
		// does not let the real value through.
		for _, header := range []string{"Bearer tok_standin", "tok_standin\x00", "\rtok_standin", "a\nb tok_standin"} {
			if got, _, err := s.Header(header, noLimit); !errors.Is(err, ErrUnsafeHeader) {
				t.Errorf("real value %q in %q: Header = %q, %v; want ErrUnsafeHeader", real, header, got, err)
			}
		}
		// The same value is fine in a JSON body, escaped.
		body, _, err := s.Body("application/json", []byte(`{"k":"tok_standin"}`), noLimit)
		var decoded map[string]string
		if err != nil || json.Unmarshal(body, &decoded) != nil || decoded["k"] != real {
			t.Errorf("real value %q: JSON body %q, %v", real, body, err)
		}
	}
}

// Only the real values a header swap inserts are checked: a header that
// holds a stand-in with a safe value is swapped whatever else the client put
// in it, and a stand-in with an unsafe value is refused only where it is
// the one matched, not where a longer stand-in containing it wins.
func TestHeaderChecksInsertedValues(t *testing.T) {
	s, err := New(map[string]string{
		"tok_pem":      "-----BEGIN KEY-----\nAAAA\n-----END KEY-----",
		"tok_pem_safe": "sk_safe",
		"tok_plain":    "sk_plain",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"tok_plain\x00":     "sk_plain\x00",
		"tok_pem_safe":      "sk_safe",
		"tok_pem_safe\r":    "sk_safe\r",
		"x tok_plain y":     "x sk_plain y",
		"no stand-in\x00":   "no stand-in\x00",
		"tok_pe tok_plain":  "tok_pe sk_plain",
		"tok_pem_safetok_p": "sk_safetok_p",
	}
	for in, want := range cases {
		got, _, err := s.Header(in, noLimit)
		if err != nil || got != want {
			t.Errorf("Header(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"tok_pem", "tok_plain tok_pem", "tok_pem_safe tok_pem\x00"} {
		if _, _, err := s.Header(in, noLimit); !errors.Is(err, ErrUnsafeHeader) {
			t.Errorf("Header(%q): %v; want ErrUnsafeHeader", in, err)
		}
	}
}

func TestRawBodyInsertsRealValuesAsIs(t *testing.T) {
	s := newSwapper(t)
	cases := map[string]string{
		"card=4242424242424242":      "card=4111111111111111",
		"holder: name with space":    "holder: Real Name&Co",
		"name+with+space":            "name+with+space", // only form bodies are decoded
		"no stand-in":                "no stand-in",
		"<x>tok_standin</x>":         "<x>sk_real_value_longer</x>",
		"--b\r\n\r\ntok_standin\r\n": "--b\r\n\r\nsk_real_value_longer\r\n",
	}
	for in, want := range cases {
		got, changed, err := s.Body("text/plain", []byte(in), noLimit)
		if err != nil || string(got) != want || changed != (in != want) {
			t.Errorf("Body(%q) = %q, %v, %v; want %q", in, got, changed, err, want)
		}
	}
}

func TestFormQueryEscapesRealValues(t *testing.T) {
	s := newSwapper(t)
	cases := map[string]string{
		"holder=name+with+space&cvc=123": "holder=Real+Name%26Co&cvc=123",
		"holder=name%20with%20space":     "holder=Real+Name%26Co",
		"holder=name with space":         "holder=Real+Name%26Co",
		"card=4242424242424242":          "card=4111111111111111",
	}
	for in, want := range cases {
		got, changed, err := s.Body("application/x-www-form-urlencoded", []byte(in), noLimit)
		if err != nil || string(got) != want || changed != (in != want) {
			t.Errorf("form body %q = %q, %v, %v; want %q", in, got, changed, err, want)
		}
	}
}

// A real value with query metacharacters arrives as one intact value.
func TestQueryValuesSurviveMetacharacters(t *testing.T) {
	s, err := New(map[string]string{"tok_standin": "a&b+c d=e%"})
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := s.Target("/x?key=tok_standin&other=1", noLimit)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query(); got.Get("key") != "a&b+c d=e%" || got.Get("other") != "1" || len(got) != 2 {
		t.Fatalf("Target gave %q, parsed %v", target, got)
	}
	form, _, err := s.Body("application/x-www-form-urlencoded; charset=UTF-8", []byte("key=tok_standin&other=1"), noLimit)
	values, perr := url.ParseQuery(string(form))
	if err != nil || perr != nil || values.Get("key") != "a&b+c d=e%" || len(values) != 2 {
		t.Fatalf("form body %q parsed %v, %v %v", form, values, err, perr)
	}
}

// Inside JSON strings real values are JSON-escaped, so the body stays valid
// and decodes to exactly the real values, whatever characters they hold.
func TestJSONStringsGetEscapedValues(t *testing.T) {
	reals := map[string]string{
		"tok_quote":     `a"b`,
		"tok_backslash": `c\d\"`,
		"tok_newline":   "e\nf\r\tg",
		"tok_unicode":   "ü😀 <&>",
		"tok_control":   "\x01\x1f",
	}
	s, err := New(reals)
	if err != nil {
		t.Fatal(err)
	}
	type document struct {
		Password string            `json:"password"`
		List     []string          `json:"list"`
		Nested   map[string]string `json:"nested"`
	}
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8", "application/vnd.api+json", "text/json"} {
		for standIn, real := range reals {
			in := `{"password":"` + standIn + `","list":["x-` + standIn + `-y"],"nested":{"k":"` + standIn + `"}}`
			out, changed, err := s.Body(contentType, []byte(in), noLimit)
			if err != nil || !changed {
				t.Fatalf("%s %q: %v, changed %v", contentType, standIn, err, changed)
			}
			var decoded document
			if err := json.Unmarshal(out, &decoded); err != nil {
				t.Fatalf("%s: swapping %q gave invalid JSON %q: %v", contentType, real, out, err)
			}
			want := document{Password: real, List: []string{"x-" + real + "-y"}, Nested: map[string]string{"k": real}}
			if !reflect.DeepEqual(decoded, want) {
				t.Fatalf("%s: decoded %+v, want %+v", contentType, decoded, want)
			}
		}
	}
	// Escapes already in the body are left alone, and a stand-in outside a
	// string (a number, say) is replaced as is.
	cards, err := New(map[string]string{"4242424242424242": "4111111111111111", "tok": `q"t`})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := cards.Body("application/json", []byte(`{"n":4242424242424242,"s":"a\"tok\\","t":"tok"}`), noLimit)
	if err != nil || string(out) != `{"n":4111111111111111,"s":"a\"q\"t\\","t":"q\"t"}` {
		t.Fatalf("JSON body %q, %v", out, err)
	}
}

func TestTargetSwapsOnlyTheQuery(t *testing.T) {
	s := newSwapper(t)
	cases := map[string]string{
		"/v1/tok_standin?key=tok_standin&x=1":    "/v1/tok_standin?key=sk_real_value_longer&x=1",
		"/pay?card=4242424242424242#tok_standin": "/pay?card=4111111111111111#tok_standin",
		"/no-query/4242424242424242":             "/no-query/4242424242424242",
		"https://h/p?n=name+with+space":          "https://h/p?n=Real+Name%26Co",
		"/p?n=name%20with%20space":               "/p?n=Real+Name%26Co",
	}
	for in, want := range cases {
		got, changed, err := s.Target(in, noLimit)
		if err != nil || got != want || changed != (in != want) {
			t.Errorf("Target(%q) = %q, %v, %v; want %q", in, got, changed, err, want)
		}
	}
}

// A short stand-in repeated many times cannot expand past the limit, on any
// path, and the limit is checked while writing, not after.
func TestSwapsStopAtTheLimit(t *testing.T) {
	s, err := New(map[string]string{"t1": strings.Repeat("R", 1000)})
	if err != nil {
		t.Fatal(err)
	}
	repeated := strings.Repeat("t1", 500) // 1000 bytes in, 500,000 out
	if _, _, err := s.Header(repeated, 10000); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Header: %v", err)
	}
	if _, _, err := s.Target("/x?q="+repeated, 10000); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Target: %v", err)
	}
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "application/json"} {
		body := []byte(repeated)
		if contentType == "application/json" {
			body = []byte(`{"k":"` + repeated + `"}`)
		}
		if _, _, err := s.Body(contentType, body, 10000); !errors.Is(err, ErrTooLarge) {
			t.Errorf("Body(%s): %v", contentType, err)
		}
	}
	// At the limit exactly is fine.
	out, _, err := s.Body("text/plain", []byte("t1t1"), 2000)
	if err != nil || len(out) != 2000 {
		t.Fatalf("Body at the limit: %d bytes, %v", len(out), err)
	}
	if _, _, err := s.Body("text/plain", []byte("t1t1"), 1999); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Body one byte over the limit: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"standin":"real"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(good)
	if err != nil || s.Count() != 1 {
		t.Fatalf("Load = %v, %v", s, err)
	}
	for name, content := range map[string]string{"empty.json": `{}`, "list.json": `["a"]`, "blank.json": `{"":"x"}`} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s) succeeded, want an error", name)
		}
	}
}
