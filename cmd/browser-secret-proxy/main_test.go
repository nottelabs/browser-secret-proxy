package main

import (
	"bytes"
	"errors"
	"flag"
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

// The usage text, printed on -h, on a bad flag and when a required flag is
// missing, names the environment variables but never prints their values.
func TestUsageLeavesTheEnvironmentOut(t *testing.T) {
	t.Setenv("SECRET_PROXY_UPSTREAM", "http://minted-user:GATEWAY-SECRET@gw.example:8080")
	t.Setenv("SECRET_PROXY_USERNAME", "proxy-user-name")
	t.Setenv("SECRET_PROXY_PASSWORD", "PROXY-SECRET")
	for _, args := range [][]string{{"-h"}, {"-bogus"}, {"-upstream-proxy"}, nil} {
		fs, _ := newFlagSet("browser-secret-proxy", flag.ContinueOnError)
		var out bytes.Buffer
		fs.SetOutput(&out)
		err := fs.Parse(args)
		if args == nil {
			if err != nil {
				t.Fatal(err)
			}
			fs.Usage() // as run does when a required flag is missing
		} else if err == nil {
			t.Fatalf("%q parsed", args)
		}
		got := out.String()
		for _, secret := range []string{"minted-user", "GATEWAY-SECRET", "gw.example", "proxy-user-name", "PROXY-SECRET"} {
			if strings.Contains(got, secret) {
				t.Fatalf("%q: usage prints %q:\n%s", args, secret, got)
			}
		}
		for _, name := range []string{"SECRET_PROXY_USERNAME", "SECRET_PROXY_PASSWORD", "SECRET_PROXY_UPSTREAM", "-upstream-proxy"} {
			if !strings.Contains(got, name) {
				t.Fatalf("%q: usage does not mention %s:\n%s", args, name, got)
			}
		}
	}
}

// A parent URL that does not parse, or that parses into something other
// than a proxy address because of an unencoded character in its password,
// is refused without quoting any part of its credentials.
func TestParseParentErrorsLeaveCredentialsOut(t *testing.T) {
	for _, raw := range []string{
		"http://minted-user:pw%zzSECRET@gw.example:8080", // invalid escape
		"socks5://minted-user:pa ss SECRET@gw.example:1080",
		"http://minted-user:SECRET@gw.example:80x",
		"http://minted-user:SECRET?x@gw.example:8080",
		"http://minted-user:12/SECRET@gw.example:8080", // host minted-user:12
		"http://minted-user:12#SECRET@gw.example:8080",
		"http://minted-user:12?SECRET@gw.example:8080",
		"minted-user:SECRET@gw.example:8080", // no scheme
		"http:minted-user:SECRET@gw.example:8080",
	} {
		u, err := parseParent(raw)
		if err == nil {
			t.Fatalf("%q parsed as %s", raw, describeParent(u))
		}
		for _, part := range []string{"minted", "SECRET", "%zz", "12", "gw.example"} {
			if strings.Contains(err.Error(), part) {
				t.Fatalf("%q: error %q quotes %q", raw, err, part)
			}
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			t.Fatalf("%q: error wraps a *url.Error, which quotes the URL", raw)
		}
	}
	// Without credentials, the cause is given.
	if _, err := parseParent("http://gw.example:80x"); err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("error %v", err)
	}
	for _, raw := range []string{"http://u:p@gw.example:8080", "http://u:p%25w@gw.example:8080/", "socks5://gw.example:1080"} {
		if u, err := parseParent(raw); err != nil || u.Host != "gw.example:8080" && u.Host != "gw.example:1080" {
			t.Fatalf("%q: %v", raw, err)
		}
	}
	if u, err := parseParent(""); u != nil || err != nil {
		t.Fatalf("empty: %v, %v", u, err)
	}
}

// Resource-limit flags remain on the FlagSet used by run after integrating
// the credential-safe usage handling.
func TestConnectionLimitFlags(t *testing.T) {
	fs, opts := newFlagSet("test", flag.ContinueOnError)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if opts.idleTimeout.String() != "5m0s" || opts.headerTimeout.String() != "10s" || opts.maxConns != 1024 {
		t.Fatalf("defaults: idle %s, header %s, max %d", opts.idleTimeout, opts.headerTimeout, opts.maxConns)
	}
	if err := fs.Parse([]string{"-idle-timeout=0", "-header-timeout=2s", "-max-conns=7"}); err != nil {
		t.Fatal(err)
	}
	if opts.idleTimeout != 0 || opts.headerTimeout.String() != "2s" || opts.maxConns != 7 {
		t.Fatalf("overrides: idle %s, header %s, max %d", opts.idleTimeout, opts.headerTimeout, opts.maxConns)
	}
}
