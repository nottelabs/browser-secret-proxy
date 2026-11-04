package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// accounts is an Authenticator over fixed username and password pairs, each
// username its own principal, resolving from its own values.
type accounts struct {
	scopetest.Resolver
	passwords map[string]string
}

func (a accounts) Authenticate(username, password string) (resolve.Principal, error) {
	if want, ok := a.passwords[username]; !ok || want != password {
		return resolve.Principal{}, resolve.ErrUnauthenticated
	}
	return resolve.Principal{ID: username, Password: password}, nil
}

// scopedAccounts: alice owns tok_alice (any allowlisted host), tok_elsewhere
// (only pay.example) and tok_expired; bob owns tok_bob.
func scopedAccounts() accounts {
	return accounts{
		Resolver: scopetest.PerPrincipal(map[string]map[string]resolve.Value{
			"alice": {
				"tok_alice":     {Real: "real_alice"},
				"tok_elsewhere": {Real: "real_elsewhere", Hosts: []string{"pay.example"}},
				"tok_expired":   {Real: "real_expired", ExpiresAt: time.Now().Add(-time.Second)},
			},
			"bob": {"tok_bob": {Real: "real_bob"}},
		}),
		passwords: map[string]string{"alice": "alice-pw", "bob": "bob-pw"}, // pragma: allowlist secret
	}
}

// echoed is what the destination received: each request's target and body.
type echoed struct {
	mu       sync.Mutex
	requests []string
}

func (e *echoed) all() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.requests, "\n")
}

// echoDestination records each request and answers 200 "ok".
func echoDestination(e *echoed) func(*tls.Conn) {
	return serveWith(e, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
}

// serveWith serves handler on a destination connection, over HTTP/2 or
// HTTP/1.1, whichever was negotiated, with net/http's own server, recording
// each request it receives.
func serveWith(e *echoed, handler http.Handler) func(*tls.Conn) {
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.requests = append(e.requests, r.URL.RequestURI()+" "+string(body))
		e.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler.ServeHTTP(w, r)
	})
	return func(c *tls.Conn) {
		ln := &oneConnListener{conn: c, done: make(chan struct{})}
		server := &http.Server{Handler: recording, ReadHeaderTimeout: 10 * time.Second, ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				ln.close()
			}
		}}
		_ = server.Serve(ln)
	}
}

// oneConnListener hands out one connection, then blocks until it closes.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) close()         { l.once.Do(func() { close(l.done) }) }
func (l *oneConnListener) Close() error   { l.close(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// proxiedClient is an HTTP client whose connections go through the proxy
// with the given credentials, speaking proto ("h2" or "http/1.1").
func proxiedClient(t *testing.T, p *testProxy, username, password, proto string) *http.Client {
	t.Helper()
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		conn, resp := connect(t, p.addr, addr, authorization)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, &net.OpError{Op: "proxy", Err: io.ErrUnexpectedEOF}
		}
		host, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: p.ca, NextProtos: []string{proto}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
	transport := &http.Transport{DialTLSContext: dial, ForceAttemptHTTP2: proto == "h2"}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

// Each principal swaps its own values only, on the hosts they allow and
// before they expire; every other request is answered 502 and never reaches
// the destination. The same holds over HTTP/1.1 and HTTP/2.
func TestValuesAreScopedToPrincipalHostAndTime(t *testing.T) {
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
				r := scopedAccounts()
				d, err := resolve.NewDetector(r, resolve.Patterns{})
				if err != nil {
					t.Fatal(err)
				}
				c.Resolver, c.Detector = r, d
			})
			alice := proxiedClient(t, p, "alice", "alice-pw", proto)
			bob := proxiedClient(t, p, "bob", "bob-pw", proto)
			cases := []struct {
				name   string
				client *http.Client
				query  string
				status int
			}{
				{"own value", alice, "tok_alice", http.StatusOK},
				{"another principal's value", bob, "tok_alice", http.StatusBadGateway},
				{"own value, other host", alice, "tok_elsewhere", http.StatusBadGateway},
				{"expired value", alice, "tok_expired", http.StatusBadGateway},
				{"own value, other principal", bob, "tok_bob", http.StatusOK},
			}
			for _, c := range cases {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					url := "https://" + allowedHost + "/?" + c.name[:3] + "=" + c.query
					var body io.Reader
					if method == http.MethodPost {
						url = "https://" + allowedHost + "/post"
						body = strings.NewReader("card=" + c.query)
					}
					req, err := http.NewRequest(method, url, body)
					if err != nil {
						t.Fatal(err)
					}
					if body != nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
					resp, err := c.client.Do(req)
					if err != nil {
						t.Fatalf("%s %s: %v", c.name, method, err)
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if wantMajor := map[string]int{"h2": 2, "http/1.1": 1}[proto]; resp.ProtoMajor != wantMajor {
						t.Fatalf("%s %s: answered over HTTP/%d", c.name, method, resp.ProtoMajor)
					}
					if resp.StatusCode != c.status {
						t.Errorf("%s %s: %s, want %d", c.name, method, resp.Status, c.status)
					}
				}
			}
			seen := got.all()
			for _, want := range []string{"/?own=real_alice ", "/post card=real_alice", "/?own=real_bob ", "/post card=real_bob"} {
				if !strings.Contains(seen, want) {
					t.Errorf("destination did not receive %q; got:\n%s", want, seen)
				}
			}
			for _, never := range []string{"tok_alice", "tok_elsewhere", "real_elsewhere", "tok_expired", "real_expired", "/?ano"} {
				if strings.Contains(seen, never) {
					t.Errorf("destination received %q; got:\n%s", never, seen)
				}
			}
			if n := strings.Count(seen, "\n") + 1; n != 4 {
				t.Errorf("destination received %d requests, want 4:\n%s", n, seen)
			}
		})
	}
}

// With a resolve.Authenticator the resolver decides who may connect.
func TestAuthenticatorChecksEveryConnect(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		r := scopedAccounts()
		d, err := resolve.NewDetector(r, resolve.Patterns{})
		if err != nil {
			t.Fatal(err)
		}
		c.Resolver, c.Detector = r, d
		c.Username, c.Password = "ignored", "ignored" // pragma: allowlist secret
	})
	basic := func(credentials string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	for authorization, want := range map[string]int{
		"":                       http.StatusProxyAuthRequired,
		basic("ignored:ignored"): http.StatusProxyAuthRequired,
		basic("alice:bob-pw"):    http.StatusProxyAuthRequired,
		basic("alice:alice-pw"):  http.StatusOK,
		basic("bob:bob-pw"):      http.StatusOK,
	} {
		_, resp := connect(t, p.addr, otherHost+":443", authorization)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("authorization %q: %s, want %d", authorization, resp.Status, want)
		}
	}
}
