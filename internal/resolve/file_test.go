package resolve

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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

func realOf(t *testing.T, f *File, standIn string) string {
	t.Helper()
	res, err := f.Resolve(context.Background(), Request{StandIns: []string{standIn}})
	if err != nil {
		t.Fatal(err)
	}
	return res.Values[standIn].Real
}

func TestReloadReplacesTheMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swaps.json")
	writeFile(t, path, `{"tok_a": "real_a"}`)
	f, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := f.Reload(); changed || err != nil {
		t.Fatalf("unchanged file: changed=%v err=%v", changed, err)
	}
	writeFile(t, path, `{"tok_b": "real_b"}`)
	if changed, err := f.Reload(); !changed || err != nil {
		t.Fatalf("changed file: changed=%v err=%v", changed, err)
	}
	if realOf(t, f, "tok_a") != "" || realOf(t, f, "tok_b") != "real_b" {
		t.Fatal("the new map is not in use")
	}
	if got := f.StandIns(Principal{}); !reflect.DeepEqual(got, []string{"tok_b"}) {
		t.Fatalf("StandIns = %q", got)
	}
}

func TestReloadKeepsThePreviousMapOnABadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swaps.json")
	writeFile(t, path, `{"tok_a": "real_a"}`)
	f, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"tok_a": "real-secret-value"`, `{}`} {
		writeFile(t, path, bad)
		changed, err := f.Reload()
		if changed || err == nil {
			t.Fatalf("bad file %q: changed=%v err=%v", bad, changed, err)
		}
		if strings.Contains(err.Error(), "real-secret-value") {
			t.Fatalf("the error quotes a real value: %v", err)
		}
		if realOf(t, f, "tok_a") != "real_a" {
			t.Fatal("a bad file replaced the map")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Reload(); err == nil || realOf(t, f, "tok_a") != "real_a" {
		t.Fatal("a missing file replaced the map")
	}
	writeFile(t, path, `{"tok_a": "real_a2"}`)
	if changed, err := f.Reload(); !changed || err != nil || realOf(t, f, "tok_a") != "real_a2" {
		t.Fatalf("a fixed file was not loaded: changed=%v err=%v", changed, err)
	}
}

// The Secrets Store CSI driver and Secret volumes publish a new version as a
// new directory and swap a symlink to it.
func TestReloadFollowsASymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"v1": `{"tok_a": "real_1"}`, "v2": `{"tok_a": "real_2"}`} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, name, "swaps.json"), content)
	}
	data := filepath.Join(dir, "..data")
	if err := os.Symlink("v1", data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "swaps.json")
	if err := os.Symlink(filepath.Join("..data", "swaps.json"), path); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("v2", tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, data); err != nil {
		t.Fatal(err)
	}
	if changed, err := f.Reload(); !changed || err != nil || realOf(t, f, "tok_a") != "real_2" {
		t.Fatalf("symlink swap: changed=%v err=%v", changed, err)
	}
}

func TestWatchReloadsWhileResolving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swaps.json")
	writeFile(t, path, `{"tok_a": "a_1", "tok_b": "b_1"}`)
	f, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		f.Watch(ctx, 5*time.Millisecond, log)
	}()
	defer func() { cancel(); <-watched }()

	// Readers resolve both stand-ins in one call while the file changes: the
	// two values must always come from the same version of the map.
	stop := make(chan struct{})
	readers := make(chan struct{})
	defer func() { close(stop); <-readers }()
	go func() {
		defer close(readers)
		for {
			select {
			case <-stop:
				return
			default:
			}
			res, err := f.Resolve(context.Background(), Request{StandIns: []string{"tok_a", "tok_b"}})
			if err != nil {
				t.Error(err)
				return
			}
			a, b := res.Values["tok_a"].Real, res.Values["tok_b"].Real
			if (a != "a_1" || b != "b_1") && (a != "a_2" || b != "b_2") {
				t.Errorf("one request saw %q and %q", a, b)
				return
			}
		}
	}()

	writeFile(t, path, `{"tok_a": "broken`)
	waitFor(t, func() bool { return strings.Count(logs.String(), "does not load") == 1 })
	time.Sleep(50 * time.Millisecond) // several more ticks on the same broken content
	if n := strings.Count(logs.String(), "does not load"); n != 1 {
		t.Fatalf("a broken file was logged %d times, want once", n)
	}
	writeFile(t, path, `{"tok_a": "a_2", "tok_b": "b_2"}`)
	waitFor(t, func() bool { return realOf(t, f, "tok_b") == "b_2" })
	waitFor(t, func() bool { return strings.Contains(logs.String(), "reloaded the swaps file") })
	for _, leaked := range []string{"a_1", "b_2", "broken"} {
		if strings.Contains(logs.String(), leaked) {
			t.Fatalf("the log shows file content: %s", logs.String())
		}
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
