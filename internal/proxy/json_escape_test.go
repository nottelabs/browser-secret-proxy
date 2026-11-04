package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// A JSON body whose strings escape the stand-in's characters (Go's
// json.Marshal sends & as \u0026; any client may escape letters as \u0061)
// still gets the real value, decoded the same by the destination.
func TestEscapedJSONStandInsAreSwappedEndToEnd(t *testing.T) {
	goEncoded, err := json.Marshal(map[string]string{"t": "a&b_token", "note": "<kept>"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(goEncoded), `a\u0026b_token`) {
		t.Fatalf("json.Marshal no longer escapes &: %s", goEncoded)
	}
	bodies := map[string]string{
		"json.Marshal":    string(goEncoded),
		"escaped letters": `{"t":"\u0074ok\u005fa","card":"\u0034242424242424242"}`,
		"surrogate pair":  `{"t":"tok_a \ud83d\ude00"}`,
	}
	want := map[string]map[string]string{
		"json.Marshal":    {"t": "real<&>", "note": "<kept>"},
		"escaped letters": {"t": "real_a", "card": "4111111111111111"},
		"surrogate pair":  {"t": "real_a \U0001F600"},
	}
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
				r, err := resolve.NewStatic(map[string]string{"a&b_token": "real<&>", "tok_a": "real_a", "4242424242424242": "4111111111111111"})
				if err != nil {
					t.Fatal(err)
				}
				setResolver(t, c, r, resolve.Patterns{})
			})
			client := proxiedClient(t, p, "", "", proto)
			for name, body := range bodies {
				expectStatus(t, name, post(t, client, body), http.StatusOK)
			}
			for _, line := range strings.Split(got.all(), "\n") {
				body := strings.TrimPrefix(line, "/post ")
				var received map[string]string
				if err := json.Unmarshal([]byte(body), &received); err != nil {
					t.Fatalf("the destination got invalid JSON %q: %v", body, err)
				}
				matched := false
				for name, w := range want {
					if len(w) == len(received) && w["t"] == received["t"] {
						matched = true
						for k, v := range w {
							if received[k] != v {
								t.Errorf("%s: %s = %q, want %q", name, k, received[k], v)
							}
						}
					}
				}
				if !matched {
					t.Errorf("the destination got %q, which is no expected body", body)
				}
				for _, standIn := range []string{"a&b_token", "tok_a", "4242424242424242"} {
					if strings.Contains(body, standIn) || strings.Contains(strings.ReplaceAll(body, `\u0026`, "&"), standIn) {
						t.Errorf("the stand-in %s reached the destination: %s", standIn, body)
					}
				}
			}
			if n := strings.Count(got.all(), "/post"); n != len(bodies) {
				t.Errorf("the destination got %d requests, want %d", n, len(bodies))
			}
		})
	}
}
