package main

import (
	"flag"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/nottelabs/browser-secret-proxy/internal/mask"
)

func TestDescribeParentLeavesCredentialsOut(t *testing.T) {
	if got := describeParent(nil); got != "none" {
		t.Fatalf("describeParent(nil) = %q", got)
	}
	u, err := url.Parse("http://minted-user-session-abc123:secret@proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	got := describeParent(u)
	if got != "http://proxy.example:8080" || strings.Contains(got, "minted") || strings.Contains(got, "secret") {
		t.Fatalf("describeParent = %q", got)
	}
}

func TestMaskStreamWindowFlag(t *testing.T) {
	parse := func(args ...string) (mask.Window, error) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		w := registerMaskStreamWindow(fs)
		err := fs.Parse(args)
		return *w, err
	}
	for args, want := range map[string]mask.Window{
		"":                            mask.Fixed,
		"-mask-stream-window=fixed":   mask.Fixed,
		"-mask-stream-window=minimal": mask.Minimal,
	} {
		got, err := parse(strings.Fields(args)...)
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v", args, got, err)
		}
	}
	// An unknown value refuses to start, and says what is accepted.
	for _, bad := range []string{"none", "Minimal", ""} {
		_, err := parse("-mask-stream-window=" + bad)
		if err == nil || !strings.Contains(err.Error(), "want fixed or minimal") {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}
