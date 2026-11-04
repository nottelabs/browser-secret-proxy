package resolve

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileResolvesWhatItHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swaps.json")
	writeFile(t, path, `{"tok_a": "real_a", "tok_b": "real_b"}`)
	f, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.StandIns(Principal{}); !reflect.DeepEqual(got, []string{"tok_a", "tok_b"}) {
		t.Fatalf("StandIns = %q", got)
	}
	res, err := f.Resolve(context.Background(), Request{StandIns: []string{"tok_a", "tok_missing"}, Host: "api.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Values) != 1 || res.Values["tok_a"].Real != "real_a" || len(res.Values["tok_a"].Hosts) != 0 || !res.Values["tok_a"].ExpiresAt.IsZero() {
		t.Fatalf("Resolve answered %d values, want only tok_a", len(res.Values))
	}
}

func TestFileErrorsDoNotQuoteTheFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"invalid": `{"tok_a": "real-secret-value"`,
		"array":   `["real-secret-value"]`,
		"empty":   `{}`,
		"blank":   `{"": "real-secret-value"}`,
		"number":  `{"tok_a": 42}`,
	} {
		path := filepath.Join(dir, name+".json")
		writeFile(t, path, content)
		_, err := LoadFile(path)
		if err == nil {
			t.Errorf("%s: loaded", name)
			continue
		}
		if strings.Contains(err.Error(), "real-secret-value") {
			t.Errorf("%s: the error quotes a real value: %v", name, err)
		}
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file loaded")
	}
}
