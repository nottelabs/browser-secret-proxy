package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerAnswersTheResolverAPI(t *testing.T) {
	var values map[string]value
	if err := json.Unmarshal([]byte(`{"tok_a": "real_a", "tok_b": {"real": "real_b", "hosts": ["api.test"]}, "tok_d": {"real": "real_d", "hosts": []}}`), &values); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"stand_ins": ["tok_a", "tok_b", "tok_c", "tok_d"], "host": "api.test", "principal_id": "u"}`))
	handler(values).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var answer struct {
		Values map[string]struct {
			Real  *string  `json:"real"`
			Hosts []string `json:"hosts"`
		} `json:"values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	a, b := answer.Values["tok_a"], answer.Values["tok_b"]
	if a.Real == nil || *a.Real != "real_a" || len(a.Hosts) != 0 || b.Real == nil || *b.Real != "real_b" || len(b.Hosts) != 1 {
		t.Fatalf("answer %s", rec.Body.String())
	}
	// An empty host list is passed on as one (the proxy then refuses the
	// value), not dropped, which would let it go to any host in -hosts.
	if d := answer.Values["tok_d"]; a.Hosts != nil || d.Hosts == nil || len(d.Hosts) != 0 {
		t.Fatalf("answer %s", rec.Body.String())
	}
	if _, ok := answer.Values["tok_c"]; ok {
		t.Fatal("an unknown stand-in was answered")
	}

	rec = httptest.NewRecorder()
	handler(values).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`nope`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed request: status %d", rec.Code)
	}

	if err := json.Unmarshal([]byte(`{"tok_a": {"hosts": ["api.test"]}}`), &values); err == nil {
		t.Fatal("an entry without real loaded")
	}
}

// The values file is read as written: encoding/json alone would take
// "HOSTS" for "hosts" and let the last of two members win, so an entry could
// go to other hosts than the file seems to say.
func TestLoadValuesIsStrict(t *testing.T) {
	values, err := loadValues([]byte(`{"tok_a": "real_a", "TOK_A": {"real": "real_b", "hosts": ["api.test"], "note": {"a": 1, "A": 2}}}`))
	if err != nil || values["tok_a"].Real != "real_a" || values["TOK_A"].Real != "real_b" || len(values["TOK_A"].Hosts) != 1 {
		t.Fatalf("values %v, err %v", values, err)
	}
	for name, file := range map[string]string{
		"hosts in another case": `{"tok_a": {"real": "real_a", "hosts": ["api.test"], "HOSTS": ["other.test"]}}`,
		"hosts twice":           `{"tok_a": {"real": "real_a", "hosts": ["api.test"], "hosts": ["other.test"]}}`,
		"real in another case":  `{"tok_a": {"REAL": "real_a"}}`,
		"a stand-in twice":      `{"tok_a": "real_a", "tok_a": "real_b"}`,
		"not an object":         `["tok_a"]`,
	} {
		if _, err := loadValues([]byte(file)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A request is read as the proxy writes it: one that spells a member in
// another case or names it twice is refused.
func TestHandlerRefusesAmbiguousRequests(t *testing.T) {
	values := map[string]value{"tok_a": {Real: "real_a"}}
	for name, body := range map[string]string{
		"host in another case": `{"stand_ins": ["tok_a"], "host": "api.test", "HOST": "other.test", "principal_id": "u"}`,
		"host twice":           `{"stand_ins": ["tok_a"], "host": "api.test", "host": "other.test", "principal_id": "u"}`,
		"principal twice":      `{"stand_ins": ["tok_a"], "host": "api.test", "principal_id": "u", "principal_id": "v"}`,
	} {
		rec := httptest.NewRecorder()
		handler(values).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, rec.Code)
		}
	}
}
