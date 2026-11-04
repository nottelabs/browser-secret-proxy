package main

import (
	"net/url"
	"strings"
	"testing"
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
