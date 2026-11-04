package panics

import (
	"errors"
	"strings"
	"testing"
)

const secret = "sk_live_real_secret_value"

func panicking() { panic(errors.New(secret)) }

func outOfRange(i int) int { return []int{1}[i] }

func recovered(t *testing.T, f func()) *Error {
	t.Helper()
	var got *Error
	func() {
		defer Recover(func(p *Error) { got = p })
		f()
	}()
	if got == nil {
		t.Fatal("no panic was recovered")
	}
	return got
}

// A recovered panic keeps its type and where it happened, not its value.
func TestRecoverKeepsTypeAndSiteOnly(t *testing.T) {
	p := recovered(t, panicking)
	if p.Type != "*errors.errorString" {
		t.Fatalf("type %q", p.Type)
	}
	if !strings.HasPrefix(p.Site, "github.com/nottelabs/browser-secret-proxy/internal/panics.panicking (panics_test.go:") {
		t.Fatalf("site %q does not start at the panicking function", p.Site)
	}
	for _, s := range []string{p.Type, p.Site, p.Error()} {
		if strings.Contains(s, secret) {
			t.Fatalf("%q carries the panic value", s)
		}
	}
}

// A runtime error is named after the user function that caused it, not the
// runtime functions that raised it.
func TestRecoverSkipsRuntimeFrames(t *testing.T) {
	p := recovered(t, func() { outOfRange(2) })
	if p.Type != "runtime.boundsError" {
		t.Fatalf("type %q", p.Type)
	}
	if !strings.Contains(p.Site, "panics.outOfRange") || strings.Contains(p.Site, "runtime.") {
		t.Fatalf("site %q", p.Site)
	}
	if n := strings.Count(p.Site, " < ") + 1; n > maxSiteFrames {
		t.Fatalf("site names %d functions, want at most %d", n, maxSiteFrames)
	}
}

// Without a panic, Recover does nothing.
func TestRecoverWithoutAPanic(t *testing.T) {
	called := false
	func() {
		defer Recover(func(*Error) { called = true })
	}()
	if called {
		t.Fatal("handle ran without a panic")
	}
}

// panic(nil) is recovered too.
func TestRecoverNilPanic(t *testing.T) {
	if p := recovered(t, func() { panic(nil) }); p.Type != "*runtime.PanicNilError" {
		t.Fatalf("type %q", p.Type)
	}
}
