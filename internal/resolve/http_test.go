package resolve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testPKI is a client CA with one client certificate, written as PEM files.
type testPKI struct {
	clientCAs         *x509.CertPool
	certFile, keyFile string
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newClientPKI(t *testing.T, dir, name string) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + " CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	p := testPKI{clientCAs: x509.NewCertPool(), certFile: filepath.Join(dir, name+".pem"), keyFile: filepath.Join(dir, name+".key")}
	p.clientCAs.AddCert(ca)
	writePEM(t, p.certFile, "CERTIFICATE", der)
	writePEM(t, p.keyFile, "PRIVATE KEY", keyDER)
	return p
}

type detokenizer struct {
	t      *testing.T
	server *httptest.Server
	caFile string
	pki    testPKI
	calls  atomic.Int32

	mu       sync.Mutex
	requests []detokenizeRequest
	bodies   []string
	answer   func(req detokenizeRequest, w http.ResponseWriter)
}

// startDetokenizer runs a service that requires a client certificate from
// pki's CA.
func startDetokenizer(t *testing.T, answer func(req detokenizeRequest, w http.ResponseWriter)) *detokenizer {
	t.Helper()
	dir := t.TempDir()
	d := &detokenizer{t: t, pki: newClientPKI(t, dir, "proxy"), answer: answer}
	d.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req detokenizeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		d.requests = append(d.requests, req)
		d.bodies = append(d.bodies, string(body))
		answer := d.answer
		d.mu.Unlock()
		answer(req, w)
	}))
	d.server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: d.pki.clientCAs, MinVersion: tls.VersionTLS12}
	d.server.StartTLS()
	t.Cleanup(d.server.Close)
	d.caFile = filepath.Join(dir, "server-ca.pem")
	writePEM(t, d.caFile, "CERTIFICATE", d.server.Certificate().Raw)
	return d
}

func (d *detokenizer) config() HTTPConfig {
	return HTTPConfig{URL: d.server.URL + "/detokenize", ClientCert: d.pki.certFile, ClientKey: d.pki.keyFile, CA: d.caFile}
}

func (d *detokenizer) lastRequest() detokenizeRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.requests) == 0 {
		d.t.Fatal("no request reached the service")
	}
	return d.requests[len(d.requests)-1]
}

// answerFrom answers every known stand-in with values[s] and leaves the rest out.
func answerFrom(values map[string]map[string]any) func(detokenizeRequest, http.ResponseWriter) {
	return func(req detokenizeRequest, w http.ResponseWriter) {
		out := map[string]any{}
		for _, s := range req.StandIns {
			if v, ok := values[s]; ok {
				out[s] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"values": out})
	}
}

func newTestHTTP(t *testing.T, cfg HTTPConfig) *HTTP {
	t.Helper()
	h, err := NewHTTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHTTPResolvesInOneBatch(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	d := startDetokenizer(t, answerFrom(map[string]map[string]any{
		"tok_a": {"real": "real_a", "hosts": []string{"api.test"}, "expires_at": expires},
		"tok_b": {"real": "real_b"},
	}))
	h := newTestHTTP(t, d.config())
	res, err := h.Resolve(context.Background(), Request{
		StandIns: []string{"tok_a", "tok_b", "tok_unknown"}, Host: "api.test:443",
		Principal: Principal{ID: "user-1", Password: "proxy-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.calls.Load() != 1 {
		t.Fatalf("%d calls, want one batch", d.calls.Load())
	}
	got := d.lastRequest()
	if strings.Join(got.StandIns, ",") != "tok_a,tok_b,tok_unknown" || got.Host != "api.test" || got.PrincipalID != "user-1" {
		t.Fatalf("the service got %+v", got)
	}
	a := res.Values["tok_a"]
	if a.Real != "real_a" || len(a.Hosts) != 1 || a.Hosts[0] != "api.test" || !a.ExpiresAt.Equal(expires) {
		t.Fatalf("tok_a = %+v %v %v", a.Hosts, a.ExpiresAt, a.Real == "real_a")
	}
	if res.Values["tok_b"].Real != "real_b" {
		t.Fatal("tok_b not resolved")
	}
	if _, ok := res.Values["tok_unknown"]; ok {
		t.Fatal("a stand-in the service left out was resolved")
	}
}

func TestHTTPNeverSendsTheProxyPassword(t *testing.T) {
	d := startDetokenizer(t, answerFrom(nil))
	h := newTestHTTP(t, d.config())
	if _, err := h.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Host: "api.test", Principal: Principal{ID: "u", Password: "proxy-password"}}); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.bodies) != 1 || strings.Contains(d.bodies[0], "proxy-password") {
		t.Fatalf("the proxy password reached the service: %q", d.bodies)
	}
}

func TestHTTPCache(t *testing.T) {
	now := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&now)
	advance := func(d time.Duration) { n := clock.Load().Add(d); clock.Store(&n) }
	d := startDetokenizer(t, answerFrom(map[string]map[string]any{
		"tok_short": {"real": "r1", "expires_at": now.Add(10 * time.Second)},
		"tok_long":  {"real": "r2"},
		"tok_past":  {"real": "r3", "expires_at": now.Add(-time.Second)},
	}))
	cfg := d.config()
	cfg.CacheTTL = time.Minute
	cfg.now = func() time.Time { return *clock.Load() }
	h := newTestHTTP(t, cfg)
	resolve := func(principal string, standIns ...string) Result {
		t.Helper()
		res, err := h.Resolve(context.Background(), Request{StandIns: standIns, Host: "api.test", Principal: Principal{ID: principal}})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	resolve("u1", "tok_short", "tok_long", "tok_past", "tok_unknown")
	if d.calls.Load() != 1 {
		t.Fatal("first lookup did not call the service")
	}
	resolve("u1", "tok_short", "tok_long")
	if d.calls.Load() != 1 {
		t.Fatal("cached values were looked up again")
	}
	resolve("u1", "tok_past")
	if d.calls.Load() != 2 || strings.Join(d.lastRequest().StandIns, ",") != "tok_past" {
		t.Fatal("an expired value was cached")
	}
	resolve("u1", "tok_unknown")
	if d.calls.Load() != 3 {
		t.Fatal("an unresolved stand-in was cached")
	}
	resolve("u2", "tok_long")
	if d.calls.Load() != 4 {
		t.Fatal("another principal got the first principal's cached value")
	}

	advance(11 * time.Second) // past tok_short's expires_at, within the TTL
	resolve("u1", "tok_short", "tok_long")
	if got := strings.Join(d.lastRequest().StandIns, ","); d.calls.Load() != 5 || got != "tok_short" {
		t.Fatalf("after expires_at: calls=%d last=%q, want only tok_short looked up", d.calls.Load(), got)
	}
	advance(time.Minute) // past the TTL
	resolve("u1", "tok_long")
	if d.calls.Load() != 6 {
		t.Fatal("the cache TTL was not honored")
	}
}

func TestHTTPCacheIsBounded(t *testing.T) {
	d := startDetokenizer(t, func(req detokenizeRequest, w http.ResponseWriter) {
		out := map[string]any{}
		for _, s := range req.StandIns {
			out[s] = map[string]any{"real": "r"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"values": out})
	})
	cfg := d.config()
	cfg.CacheSize = 3
	h := newTestHTTP(t, cfg)
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		if _, err := h.Resolve(context.Background(), Request{StandIns: []string{s}}); err != nil {
			t.Fatal(err)
		}
	}
	h.mu.Lock()
	n := len(h.cache)
	h.mu.Unlock()
	if n > 3 {
		t.Fatalf("%d cached values, limit 3", n)
	}
}

func TestHTTPCacheCanBeDisabled(t *testing.T) {
	d := startDetokenizer(t, answerFrom(map[string]map[string]any{"tok_a": {"real": "r"}}))
	cfg := d.config()
	cfg.CacheTTL = -1
	h := newTestHTTP(t, cfg)
	for range 2 {
		if _, err := h.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}}); err != nil {
			t.Fatal(err)
		}
	}
	if d.calls.Load() != 2 {
		t.Fatalf("%d calls with the cache off, want 2", d.calls.Load())
	}
}

func TestHTTPFailures(t *testing.T) {
	cases := map[string]func(detokenizeRequest, http.ResponseWriter){
		"5xx": func(_ detokenizeRequest, w http.ResponseWriter) {
			http.Error(w, "real-secret-value leaked in an error page", http.StatusInternalServerError)
		},
		"4xx": func(_ detokenizeRequest, w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) },
		"not json": func(_ detokenizeRequest, w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"values": {"tok_a": "real-secret-value"`))
		},
		"wrong shape": func(_ detokenizeRequest, w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"values": {"tok_a": "real-secret-value"}}`))
		},
		"redirect": func(_ detokenizeRequest, w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.test/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
		"too large": func(_ detokenizeRequest, w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"values": {"tok_a": {"real": "` + strings.Repeat("x", maxResponse) + `"}}}`))
		},
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			d := startDetokenizer(t, answer)
			h := newTestHTTP(t, d.config())
			res, err := h.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Host: "api.test"})
			if err == nil {
				t.Fatal("no error")
			}
			if len(res.Values) != 0 {
				t.Fatal("a failed call resolved values")
			}
			if strings.Contains(err.Error(), "real-secret-value") {
				t.Fatalf("the error quotes the answer: %v", err)
			}
		})
	}
}

func TestHTTPNullRealIsUnresolved(t *testing.T) {
	d := startDetokenizer(t, func(_ detokenizeRequest, w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"values": {"tok_a": {"hosts": ["api.test"]}, "tok_b": {"real": ""}}}`))
	})
	h := newTestHTTP(t, d.config())
	res, err := h.Resolve(context.Background(), Request{StandIns: []string{"tok_a", "tok_b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Values["tok_a"]; ok {
		t.Fatal("a value without real was resolved")
	}
	if v, ok := res.Values["tok_b"]; !ok || v.Real != "" {
		t.Fatal("an empty real value is a value")
	}
}

func TestHTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	d := startDetokenizer(t, func(_ detokenizeRequest, w http.ResponseWriter) {
		<-release
		_, _ = w.Write([]byte(`{"values": {"tok_a": {"real": "r"}}}`))
	})
	defer close(release)
	cfg := d.config()
	cfg.Timeout = 100 * time.Millisecond
	h := newTestHTTP(t, cfg)
	start := time.Now()
	_, err := h.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}})
	if err == nil {
		t.Fatal("a stalled service resolved")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the call took %v, timeout 100ms", elapsed)
	}
}

func TestHTTPHonorsTheCallerContext(t *testing.T) {
	release := make(chan struct{})
	d := startDetokenizer(t, func(_ detokenizeRequest, w http.ResponseWriter) { <-release })
	defer close(release)
	h := newTestHTTP(t, d.config())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Resolve(ctx, Request{StandIns: []string{"tok_a"}}); err == nil {
		t.Fatal("a canceled lookup resolved")
	}
}

func TestHTTPBatchLimit(t *testing.T) {
	d := startDetokenizer(t, answerFrom(nil))
	cfg := d.config()
	cfg.MaxBatch = 2
	h := newTestHTTP(t, cfg)
	if _, err := h.Resolve(context.Background(), Request{StandIns: []string{"a", "b", "c"}}); err == nil {
		t.Fatal("a batch over the limit was sent")
	}
	if d.calls.Load() != 0 {
		t.Fatal("the service was called")
	}
}

func TestHTTPRequiresMutualTLS(t *testing.T) {
	d := startDetokenizer(t, answerFrom(map[string]map[string]any{"tok_a": {"real": "r"}}))
	base := d.config()

	for name, mutate := range map[string]func(*HTTPConfig){
		"plain http":     func(c *HTTPConfig) { c.URL = strings.Replace(c.URL, "https://", "http://", 1) },
		"no client cert": func(c *HTTPConfig) { c.ClientCert, c.ClientKey = "", "" },
		"no client key":  func(c *HTTPConfig) { c.ClientKey = "" },
		"credentials":    func(c *HTTPConfig) { c.URL = strings.Replace(c.URL, "https://", "https://user:pw@", 1) },
		"bad CA":         func(c *HTTPConfig) { c.CA = c.ClientKey },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := NewHTTP(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A certificate from a CA the service does not trust is refused.
	other := newClientPKI(t, t.TempDir(), "stranger")
	cfg := base
	cfg.ClientCert, cfg.ClientKey = other.certFile, other.keyFile
	if _, err := newTestHTTP(t, cfg).Resolve(context.Background(), Request{StandIns: []string{"tok_a"}}); err == nil {
		t.Fatal("a client certificate from another CA was accepted")
	}
	// The service's certificate must verify against the CA given.
	cfg = base
	cfg.CA = ""
	if _, err := newTestHTTP(t, cfg).Resolve(context.Background(), Request{StandIns: []string{"tok_a"}}); err == nil {
		t.Fatal("the service's certificate was not verified")
	}
	if d.calls.Load() != 0 {
		t.Fatal("a request without mutual TLS reached the service")
	}
}
