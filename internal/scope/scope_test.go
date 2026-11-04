package scope_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func session(t *testing.T, r resolve.Resolver, p resolve.Principal) *scope.Session {
	t.Helper()
	return sessionTo(t, r, p, "api.example.com")
}

func sessionTo(t *testing.T, r resolve.Resolver, p resolve.Principal, host string) *scope.Session {
	t.Helper()
	hosts, err := hostmatch.New([]string{"api.example.com", "*.pay.example"})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := resolve.NewDetector(r, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(scope.Config{Resolver: r, Detector: detector, Hosts: hosts, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Session(p, host)
}

func one(v resolve.Value) scopetest.Resolver {
	return scopetest.Resolver{Known: []string{"tok_a"}, Fn: func(resolve.Request) (resolve.Result, error) {
		return resolve.Result{Values: map[string]resolve.Value{"tok_a": v}}, nil
	}}
}

func TestValuesAreCheckedAgainstHostAndExpiry(t *testing.T) {
	cases := []struct {
		name  string
		value resolve.Value
		host  string
		ok    bool
	}{
		{"no hosts: the proxy allowlist", resolve.Value{Real: "r"}, "api.example.com", true},
		{"no hosts: a wildcard of the allowlist", resolve.Value{Real: "r"}, "x.pay.example:443", true},
		{"no hosts: outside the allowlist", resolve.Value{Real: "r"}, "evil.example", false},
		{"own host", resolve.Value{Real: "r", Hosts: []string{"api.example.com"}}, "API.example.com.", true},
		{"own host, other destination", resolve.Value{Real: "r", Hosts: []string{"api.example.com"}}, "x.pay.example", false},
		{"own wildcard", resolve.Value{Real: "r", Hosts: []string{"*.pay.example"}}, "a.b.pay.example", true},
		{"own wildcard does not cover the domain", resolve.Value{Real: "r", Hosts: []string{"*.pay.example"}}, "pay.example", false},
		{"invalid host list", resolve.Value{Real: "r", Hosts: []string{"*"}}, "api.example.com", false},
		{"not expired", resolve.Value{Real: "r", ExpiresAt: now.Add(time.Second)}, "api.example.com", true},
		{"expired", resolve.Value{Real: "r", ExpiresAt: now.Add(-time.Second)}, "api.example.com", false},
		{"expires now", resolve.Value{Real: "r", ExpiresAt: now}, "api.example.com", false},
		{"empty real value", resolve.Value{}, "api.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sw, err := sessionTo(t, one(c.value), resolve.Principal{}, c.host).Swapper(context.Background(), lit("Bearer tok_a")...)
			if c.ok {
				if err != nil || sw == nil {
					t.Fatalf("got %v, %v; want a swapper", sw, err)
				}
				if out, _, _ := sw.Header("Bearer tok_a", 100); out != "Bearer r" {
					t.Fatalf("swapped %q", out)
				}
				return
			}
			if !errors.Is(err, scope.ErrRefused) || sw != nil {
				t.Fatalf("got %v, %v; want a refusal", sw, err)
			}
		})
	}
}

func TestOneLookupPerRequestWithTheRequestsStandIns(t *testing.T) {
	var got []resolve.Request
	r := scopetest.Resolver{Known: []string{"tok_a", "tok_b", "tok_c"}, Fn: func(req resolve.Request) (resolve.Result, error) {
		got = append(got, req)
		out := resolve.Result{Values: map[string]resolve.Value{}}
		for _, s := range req.StandIns {
			out.Values[s] = resolve.Value{Real: "real_" + s}
		}
		return out, nil
	}}
	p := resolve.Principal{ID: "alice", Password: "pw"}
	sw, err := session(t, r, p).Swapper(context.Background(), lit("q=tok_b", "Bearer tok_a", `{"x":"tok_b"}`)...)
	if err != nil || sw == nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d lookups, want 1", len(got))
	}
	if strings.Join(got[0].StandIns, ",") != "tok_a,tok_b" || got[0].Host != "api.example.com" || got[0].Principal != p {
		t.Fatalf("lookup %q %q %v", got[0].StandIns, got[0].Host, got[0].Principal)
	}
	// No stand-in: no lookup, no swapper.
	sw, err = session(t, r, p).Swapper(context.Background(), lit("nothing here")...)
	if err != nil || sw != nil || len(got) != 1 {
		t.Fatalf("got %v, %v after %d lookups", sw, err, len(got))
	}
}

func TestValuesAreNotSharedBetweenPrincipals(t *testing.T) {
	r := scopetest.PerPrincipal(map[string]map[string]resolve.Value{
		"alice": {"tok_a": {Real: "alice_real"}},
		"bob":   {"tok_b": {Real: "bob_real"}},
	})
	alice := session(t, r, resolve.Principal{ID: "alice"})
	bob := session(t, r, resolve.Principal{ID: "bob"})
	if sw, err := alice.Swapper(context.Background(), lit("tok_a")...); err != nil || sw == nil {
		t.Fatalf("alice's own stand-in: %v", err)
	}
	// Alice resolved tok_a just before; nothing of it reaches Bob.
	if _, err := bob.Swapper(context.Background(), lit("tok_a")...); !errors.Is(err, scope.ErrRefused) {
		t.Fatalf("bob used alice's stand-in: %v", err)
	}
	if _, err := bob.Swapper(context.Background(), lit("tok_a tok_b")...); !errors.Is(err, scope.ErrRefused) {
		t.Fatalf("a request mixing bob's and alice's stand-ins was allowed: %v", err)
	}
}

// A resolver error may quote a real value: neither the client nor the log
// sees its text, only its category.
func TestResolverErrorsAreNotPassedOn(t *testing.T) {
	r := scopetest.Resolver{Known: []string{"tok_a"}, Fn: func(resolve.Request) (resolve.Result, error) {
		return resolve.Result{}, errors.New("upstream said: real value 4111111111111111 is locked")
	}}
	var logs bytes.Buffer
	hosts, _ := hostmatch.New([]string{"api.example.com"})
	detector, _ := resolve.NewDetector(r, resolve.Patterns{})
	s, err := scope.New(scope.Config{Resolver: r, Detector: detector, Hosts: hosts, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Session(resolve.Principal{}, "api.example.com").Swapper(context.Background(), lit("tok_a")...)
	if !errors.Is(err, scope.ErrRefused) || strings.Contains(err.Error(), "4111") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(logs.String(), "4111") || !strings.Contains(logs.String(), "error=error") {
		t.Fatalf("log: %s", logs.String())
	}
}

func TestResolveIsBoundedByTheTimeout(t *testing.T) {
	r := scopetest.Resolver{Known: []string{"tok_a"}}
	hosts, _ := hostmatch.New([]string{"api.example.com"})
	detector, _ := resolve.NewDetector(r, resolve.Patterns{})
	blocking := blockingResolver{r}
	s, err := scope.New(scope.Config{Resolver: blocking, Detector: detector, Hosts: hosts, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := s.Session(resolve.Principal{}, "api.example.com").Swapper(context.Background(), lit("tok_a")...); !errors.Is(err, scope.ErrRefused) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the timeout was not applied")
	}
}

type blockingResolver struct{ scopetest.Resolver }

func (blockingResolver) Resolve(ctx context.Context, _ resolve.Request) (resolve.Result, error) {
	<-ctx.Done()
	return resolve.Result{}, ctx.Err()
}

// lit is texts as header values.
func lit(texts ...string) []swap.Part {
	parts := make([]swap.Part, len(texts))
	for i, t := range texts {
		parts[i] = swap.Part{Place: swap.Literal, Text: t}
	}
	return parts
}
