package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// scopedSetup runs one echo destination for each of allowedHost and
// otherHost, both allowlisted, and a proxy with resolver.
type scopedSetup struct {
	p        *testProxy
	received map[string]*echoed // by destination host
}

func startScopedSetup(t *testing.T, proto string, resolver resolve.Resolver, patterns resolve.Patterns, mutate func(*Config)) *scopedSetup {
	t.Helper()
	s := &scopedSetup{received: map[string]*echoed{allowedHost: {}, otherHost: {}}}
	dialer := mapDialer{}
	allowed := startDestination(t, allowedHost, []string{proto}, echoDestination(s.received[allowedHost]))
	other := startDestination(t, otherHost, []string{proto}, echoDestination(s.received[otherHost]))
	dialer[allowedHost+":443"] = allowed.addr
	dialer[otherHost+":443"] = other.addr
	// Both destinations' CAs are trusted for the proxy's outgoing TLS.
	pool := allowed.ca.Clone()
	pool.AddCert(other.caCert)
	s.p = startProxy(t, dialer, pool, func(c *Config) {
		hosts, err := hostmatch.New([]string{allowedHost, otherHost})
		if err != nil {
			t.Fatal(err)
		}
		d, err := resolve.NewDetector(resolver, patterns)
		if err != nil {
			t.Fatal(err)
		}
		c.Hosts, c.Resolver, c.Detector = hosts, resolver, d
		if mutate != nil {
			mutate(c)
		}
	})
	return s
}

// clientTo is an HTTP client whose every connection is a CONNECT to
// connectHost, whatever host its requests name.
func clientTo(t *testing.T, p *testProxy, proto, connectHost string) *http.Client {
	t.Helper()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:alice-pw"))
		conn, resp := connect(t, p.addr, connectHost+":443", authorization)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, errors.New("CONNECT refused: " + resp.Status)
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: connectHost, RootCAs: p.ca, NextProtos: []string{proto}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	transport := &http.Transport{DialTLSContext: dial, ForceAttemptHTTP2: proto == "h2", DisableKeepAlives: proto != "h2"}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

// do sends one request and returns its status.
func do(t *testing.T, c *http.Client, method, url, body string) int {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func protos(t *testing.T, f func(t *testing.T, proto string)) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) { f(t, proto) })
	}
}

// A request goes where its CONNECT went, whatever its Host or :authority
// says: claiming an allowlisted host a value is scoped to, on a connection
// to another one, is refused, and nothing reaches either destination.
func TestValuesFollowTheConnectHostNotTheAuthority(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		r := scopetest.PerPrincipal(map[string]map[string]resolve.Value{
			"alice": {"tok_pay": {Real: "real_pay_value", Hosts: []string{allowedHost}}},
		})
		s := startScopedSetup(t, proto, accounts{Resolver: r, passwords: map[string]string{"alice": "alice-pw"}}, resolve.Patterns{}, nil)
		// The value's own host: swapped.
		if got := do(t, clientTo(t, s.p, proto, allowedHost), http.MethodGet, "https://"+allowedHost+"/?c=tok_pay", ""); got != http.StatusOK {
			t.Fatalf("on its own host: %d", got)
		}
		// A connection to otherHost claiming allowedHost.
		lying := clientTo(t, s.p, proto, otherHost)
		if got := do(t, lying, http.MethodGet, "https://"+allowedHost+"/?c=tok_pay", ""); got != http.StatusBadGateway {
			t.Fatalf("claimed authority: %d, want 502", got)
		}
		// Any request naming another host than its CONNECT is refused, even
		// one without a stand-in.
		if got := do(t, clientTo(t, s.p, proto, otherHost), http.MethodGet, "https://"+allowedHost+"/plain", ""); got != http.StatusBadGateway {
			t.Fatalf("claimed authority without a stand-in: %d, want 502", got)
		}
		if got := do(t, clientTo(t, s.p, proto, otherHost), http.MethodPost, "https://"+allowedHost+"/post", "c=tok_pay"); got != http.StatusBadGateway {
			t.Fatalf("claimed authority with a body: %d, want 502", got)
		}
		// Naming otherHost honestly: the value may not go there.
		if got := do(t, clientTo(t, s.p, proto, otherHost), http.MethodGet, "https://"+otherHost+"/?c=tok_pay", ""); got != http.StatusBadGateway {
			t.Fatalf("other host: %d, want 502", got)
		}
		if got := s.received[otherHost].all(); got != "" {
			t.Fatalf("other host received %q", got)
		}
		if got := s.received[allowedHost].all(); got != "/?c=real_pay_value " {
			t.Fatalf("allowed host received %q", got)
		}
	})
}

// A resolver error is never logged as is: it may quote a real value.
func TestResolverErrorTextIsNotLogged(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		r := scopetest.Resolver{Known: []string{"tok_a"}, Fn: func(resolve.Request) (resolve.Result, error) {
			return resolve.Result{}, errors.New("upstream rejected real value 4111111111111111")
		}}
		s := startScopedSetup(t, proto, r, resolve.Patterns{}, nil)
		if got := do(t, clientTo(t, s.p, proto, allowedHost), http.MethodGet, "https://"+allowedHost+"/?c=tok_a", ""); got != http.StatusBadGateway {
			t.Fatalf("got %d, want 502", got)
		}
		if logs := s.p.logs.String(); strings.Contains(logs, "4111111111111111") || !strings.Contains(logs, "resolver failed") {
			t.Fatalf("logs:\n%s", logs)
		}
	})
}

// expiringResolver is a Snapshotter whose principal's credential expires
// when expired is set: from then on every request is refused, with or
// without a stand-in.
type expiringResolver struct {
	mu      sync.Mutex
	expired bool
}

type staticSnapshot map[string]string

func (s staticSnapshot) StandIns(resolve.Principal) []string {
	var out []string
	for k := range s {
		out = append(out, k)
	}
	return out
}

func (s staticSnapshot) Resolve(_ context.Context, req resolve.Request) (resolve.Result, error) {
	out := resolve.Result{Values: map[string]resolve.Value{}}
	for _, k := range req.StandIns {
		if v, ok := s[k]; ok {
			out.Values[k] = resolve.Value{Real: v}
		}
	}
	return out, nil
}

func (e *expiringResolver) Snapshot(resolve.Principal) (resolve.Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.expired {
		return nil, fmt.Errorf("%w: the token expired (real 4111111111111111)", resolve.ErrUnauthenticated)
	}
	return staticSnapshot{"tok_a": "real_a_value"}, nil
}

// Without a snapshot the expiring resolver knows nothing, as an expired
// credential would: detection must not fall back to it.
func (e *expiringResolver) StandIns(resolve.Principal) []string { return nil }
func (e *expiringResolver) Resolve(context.Context, resolve.Request) (resolve.Result, error) {
	return resolve.Result{}, nil
}

func TestExpiredCredentialRefusesEveryRequest(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		r := &expiringResolver{}
		s := startScopedSetup(t, proto, r, resolve.Patterns{Prefixes: []string{"tok_"}}, nil)
		c := clientTo(t, s.p, proto, allowedHost)
		if got := do(t, c, http.MethodGet, "https://"+allowedHost+"/?c=tok_a", ""); got != http.StatusOK {
			t.Fatalf("before expiry: %d", got)
		}
		r.mu.Lock()
		r.expired = true
		r.mu.Unlock()
		for _, url := range []string{"https://" + allowedHost + "/?c=tok_a", "https://" + allowedHost + "/plain"} {
			if got := do(t, c, http.MethodGet, url, ""); got != http.StatusBadGateway {
				t.Fatalf("after expiry, %s: %d, want 502", url, got)
			}
		}
		if got := s.received[allowedHost].all(); got != "/?c=real_a_value " {
			t.Fatalf("destination received %q", got)
		}
		if strings.Contains(s.p.logs.String(), "4111111111111111") {
			t.Fatal("the snapshot error text was logged")
		}
	})
}

// versioned is a Snapshotter whose live answers move on between calls (as a
// file reloaded mid-request would), while each snapshot stays one version.
type versioned struct {
	mu      sync.Mutex
	version int
}

func (v *versioned) next() staticSnapshot {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.version++
	if v.version%2 == 1 {
		return staticSnapshot{"tok_a": "old_a_value"}
	}
	return staticSnapshot{"tok_a": "new_a_value", "tok_b": "new_b_value"}
}

func (v *versioned) Snapshot(resolve.Principal) (resolve.Snapshot, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return staticSnapshot{"tok_a": "new_a_value", "tok_b": "new_b_value"}, nil
}

func (v *versioned) StandIns(p resolve.Principal) []string { return v.next().StandIns(p) }
func (v *versioned) Resolve(ctx context.Context, req resolve.Request) (resolve.Result, error) {
	return v.next().Resolve(ctx, req)
}

// Detection and resolution read the same snapshot: a request is swapped
// with one version of the values, never a mix.
func TestOneSnapshotPerRequest(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		s := startScopedSetup(t, proto, &versioned{}, resolve.Patterns{}, nil)
		if got := do(t, clientTo(t, s.p, proto, allowedHost), http.MethodGet, "https://"+allowedHost+"/?a=tok_a&b=tok_b", ""); got != http.StatusOK {
			t.Fatalf("got %d", got)
		}
		if got := s.received[allowedHost].all(); got != "/?a=new_a_value&b=new_b_value " {
			t.Fatalf("destination received %q", got)
		}
	})
}

// Stand-ins found by a pattern are found in the escaped forms the swap
// replaces: a space-grouped card written with "+" in a query, "%20" in a
// path-escaped value, or inside a JSON string.
func TestPatternStandInsAreFoundInEscapedForms(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		r := scopetest.Resolver{Fn: func(req resolve.Request) (resolve.Result, error) {
			out := resolve.Result{Values: map[string]resolve.Value{}}
			for _, s := range req.StandIns {
				if s == "4242 4242 4242 4242" {
					out.Values[s] = resolve.Value{Real: "4111 1111 1111 1111"}
				}
			}
			return out, nil
		}}
		s := startScopedSetup(t, proto, r, resolve.Patterns{Regexps: []string{`[0-9]{4}( [0-9]{4}){3}`}, Luhn: true}, nil)
		c := clientTo(t, s.p, proto, allowedHost)
		for _, url := range []string{
			"https://" + allowedHost + "/?q=4242+4242+4242+4242",
			"https://" + allowedHost + "/?p=4242%204242%204242%204242",
		} {
			if got := do(t, c, http.MethodGet, url, ""); got != http.StatusOK {
				t.Fatalf("%s: %d", url, got)
			}
		}
		if got := do(t, c, http.MethodPost, "https://"+allowedHost+"/form", "card=4242+4242+4242+4242"); got != http.StatusOK {
			t.Fatalf("form: %d", got)
		}
		got := s.received[allowedHost].all()
		for _, want := range []string{"/?q=4111+1111+1111+1111 ", "/?p=4111+1111+1111+1111 ", "/form card=4111+1111+1111+1111"} {
			if !strings.Contains(got, want) {
				t.Fatalf("destination did not receive %q; got:\n%s", want, got)
			}
		}
		if strings.Contains(got, "4242") {
			t.Fatalf("a stand-in reached the destination:\n%s", got)
		}
	})
}

// The configured lookup timeout reaches the resolver, above the default too.
func TestResolveTimeoutIsConfigurable(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		var left time.Duration
		var mu sync.Mutex
		r := scopetest.Resolver{Known: []string{"tok_a"}, Fn: nil}
		resolver := deadlineResolver{Resolver: r, seen: func(d time.Duration) { mu.Lock(); left = d; mu.Unlock() }}
		s := startScopedSetup(t, proto, resolver, resolve.Patterns{}, func(c *Config) { c.ResolveTimeout = 30 * time.Second })
		if got := do(t, clientTo(t, s.p, proto, allowedHost), http.MethodGet, "https://"+allowedHost+"/?c=tok_a", ""); got != http.StatusOK {
			t.Fatalf("got %d", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if left < 20*time.Second || left > 30*time.Second {
			t.Fatalf("the resolver had %v, want about 30 s", left)
		}
	})
}

type deadlineResolver struct {
	scopetest.Resolver
	seen func(time.Duration)
}

func (d deadlineResolver) Resolve(ctx context.Context, _ resolve.Request) (resolve.Result, error) {
	deadline, _ := ctx.Deadline()
	d.seen(time.Until(deadline))
	return resolve.Result{Values: map[string]resolve.Value{"tok_a": {Real: "real_a_value"}}}, nil
}

// Only the stand-ins the swap replaces are checked: a shorter one inside a
// longer one (tok_a in tok_ab) does not count, even when its own value is
// expired, while on its own it still fails closed.
func TestOverlappingStandInsCheckOnlyWhatIsSwapped(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		var asked [][]string
		var mu sync.Mutex
		r := scopetest.Resolver{Known: []string{"tok_a", "tok_ab"}, Fn: func(req resolve.Request) (resolve.Result, error) {
			mu.Lock()
			asked = append(asked, req.StandIns)
			mu.Unlock()
			return resolve.Result{Values: map[string]resolve.Value{
				"tok_a":  {Real: "real_a_value", ExpiresAt: time.Now().Add(-time.Minute)},
				"tok_ab": {Real: "real_ab_value"},
			}}, nil
		}}
		s := startScopedSetup(t, proto, r, resolve.Patterns{}, nil)
		c := clientTo(t, s.p, proto, allowedHost)
		if got := do(t, c, http.MethodGet, "https://"+allowedHost+"/?c=tok_ab", ""); got != http.StatusOK {
			t.Fatalf("longer stand-in: %d", got)
		}
		if got := do(t, c, http.MethodGet, "https://"+allowedHost+"/?c=tok_a", ""); got != http.StatusBadGateway {
			t.Fatalf("expired shorter stand-in on its own: %d, want 502", got)
		}
		if got := s.received[allowedHost].all(); got != "/?c=real_ab_value " {
			t.Fatalf("destination received %q", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(asked) == 0 || strings.Join(asked[0], ",") != "tok_ab" {
			t.Fatalf("first lookup asked for %q, want only tok_ab", asked)
		}
	})
}
