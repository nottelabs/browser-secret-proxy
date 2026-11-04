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
	if err := json.Unmarshal([]byte(`{"tok_a": "real_a", "tok_b": {"real": "real_b", "hosts": ["api.test"]}}`), &values); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"stand_ins": ["tok_a", "tok_b", "tok_c"], "host": "api.test", "principal_id": "u"}`))
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
