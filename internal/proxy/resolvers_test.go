package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// End-to-end tests of each resolver mode through the proxy, over HTTP/2 and
// HTTP/1.1: what the destination receives, and that a request whose values
// cannot all be resolved is answered 502 and never reaches it.

var protocols = []string{"h2", "http/1.1"}

// get sends GET https://allowedHost/?q=<query> and returns the status.
func get(t *testing.T, client *http.Client, query string) int {
	t.Helper()
	resp, err := client.Get("https://" + allowedHost + "/?q=" + query)
	if err != nil {
		t.Fatalf("GET ?q=%s: %v", query, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// post sends a JSON body and returns the status.
func post(t *testing.T, client *http.Client, body string) int {
	t.Helper()
	resp, err := client.Post("https://"+allowedHost+"/post", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", body, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func expectStatus(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: status %d, want %d", what, got, want)
	}
}

func setResolver(t *testing.T, c *Config, r resolve.Resolver, p resolve.Patterns) {
	t.Helper()
	d, err := resolve.NewDetector(r, p)
	if err != nil {
		t.Fatal(err)
	}
	c.Resolver, c.Detector = r, d
}

func TestFileResolverEndToEnd(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "swaps.json")
			write := func(content string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(`{"tok_a": "real_1"}`)
			file, err := resolve.LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) { setResolver(t, c, file, resolve.Patterns{}) })
			client := proxiedClient(t, p, "", "", proto)

			expectStatus(t, "first value", get(t, client, "tok_a"), http.StatusOK)
			write(`{"tok_a": "real_2", "tok_b": "real_b"}`)
			if changed, err := file.Reload(); !changed || err != nil {
				t.Fatalf("reload: changed=%v err=%v", changed, err)
			}
			expectStatus(t, "reloaded value", get(t, client, "tok_a"), http.StatusOK)
			expectStatus(t, "new stand-in", post(t, client, `{"card":"tok_b"}`), http.StatusOK)
			write(`{"tok_a": "broken`)
			if _, err := file.Reload(); err == nil {
				t.Fatal("a broken file reloaded")
			}
			expectStatus(t, "after a broken file", get(t, client, "tok_a"), http.StatusOK)

			want := "/?q=real_1 \n/?q=real_2 \n/post {\"card\":\"real_b\"}\n/?q=real_2 "
			if seen := got.all(); seen != want {
				t.Errorf("destination received:\n%s\nwant:\n%s", seen, want)
			}
		})
	}
}

// detokenizeService is a detokenize service over mutual TLS for the http
// resolver, with the files the resolver needs.
type detokenizeService struct {
	url, caFile, certFile, keyFile string

	mu         sync.Mutex
	principals []string
	calls      int
}

func (s *detokenizeService) seen() (principals []string, calls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.principals...), s.calls
}

func startDetokenizeService(t *testing.T, answer func(standIn string) (any, int)) *detokenizeService {
	t.Helper()
	dir := t.TempDir()
	writePEMFile := func(name, kind string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "proxy"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	clientKeyDER, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)

	s := &detokenizeService{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			StandIns    []string `json:"stand_ins"`
			PrincipalID string   `json:"principal_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.principals = append(s.principals, req.PrincipalID)
		s.calls++
		s.mu.Unlock()
		values := map[string]any{}
		for _, standIn := range req.StandIns {
			v, status := answer(standIn)
			if status != http.StatusOK {
				http.Error(w, "unavailable", status)
				return
			}
			if v != nil {
				values[standIn] = v
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"values": values})
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	s.url = server.URL + "/detokenize"
	s.caFile = writePEMFile("service-ca.pem", "CERTIFICATE", server.Certificate().Raw)
	s.certFile = writePEMFile("client.pem", "CERTIFICATE", clientDER)
	s.keyFile = writePEMFile("client.key", "PRIVATE KEY", clientKeyDER)
	return s
}

func TestHTTPResolverEndToEnd(t *testing.T) {
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			service := startDetokenizeService(t, func(standIn string) (any, int) {
				switch standIn {
				case "tok_known", "tok_second":
					return map[string]any{"real": "real_" + strings.TrimPrefix(standIn, "tok_")}, http.StatusOK
				case "tok_elsewhere":
					return map[string]any{"real": "real_elsewhere", "hosts": []string{"pay.example"}}, http.StatusOK
				case "tok_expired":
					return map[string]any{"real": "real_expired", "expires_at": time.Now().Add(-time.Minute)}, http.StatusOK
				case "tok_broken":
					return nil, http.StatusInternalServerError
				}
				return nil, http.StatusOK // unknown: left out of the answer
			})
			resolver, err := resolve.NewHTTP(resolve.HTTPConfig{URL: service.url, ClientCert: service.certFile, ClientKey: service.keyFile, CA: service.caFile, Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
				setResolver(t, c, resolver, resolve.Patterns{Prefixes: []string{"tok_"}})
				c.Username, c.Password = "proxy-user", "proxy-password" // pragma: allowlist secret
			})
			client := proxiedClient(t, p, "proxy-user", "proxy-password", proto)

			expectStatus(t, "known", get(t, client, "tok_known"), http.StatusOK)
			expectStatus(t, "known again (cached)", get(t, client, "tok_known"), http.StatusOK)
			expectStatus(t, "batched body", post(t, client, `{"a":"tok_known","b":"tok_second"}`), http.StatusOK)
			expectStatus(t, "plain request, no lookup", get(t, client, "nothing"), http.StatusOK)
			for _, refused := range []string{"tok_unknown", "tok_elsewhere", "tok_expired", "tok_broken"} {
				expectStatus(t, refused, get(t, client, refused), http.StatusBadGateway)
				expectStatus(t, refused+" in a body", post(t, client, `{"a":"tok_second","b":"`+refused+`"}`), http.StatusBadGateway)
			}

			want := "/?q=real_known \n/?q=real_known \n/post {\"a\":\"real_known\",\"b\":\"real_second\"}\n/?q=nothing "
			if seen := got.all(); seen != want {
				t.Errorf("destination received:\n%s\nwant:\n%s", seen, want)
			}
			principals, calls := service.seen()
			for _, id := range principals {
				if id != "proxy-user" {
					t.Fatalf("the service was asked for principal %q", id)
				}
			}
			// Calls: tok_known, then tok_second (tok_known cached), then for
			// the refused ones: tok_unknown twice and tok_expired twice
			// (neither is cached), tok_broken twice (errors are not cached),
			// tok_elsewhere once (a valid value, cached even though this host
			// may not have it).
			if calls != 9 {
				t.Errorf("%d calls to the service, want 9", calls)
			}
		})
	}
}

func TestHTTPResolverUnreachableFailsClosed(t *testing.T) {
	service := startDetokenizeService(t, func(string) (any, int) { return nil, http.StatusOK })
	resolver, err := resolve.NewHTTP(resolve.HTTPConfig{URL: "https://127.0.0.1:1/detokenize", ClientCert: service.certFile, ClientKey: service.keyFile, CA: service.caFile, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	got := &echoed{}
	dest := startDestination(t, allowedHost, []string{"h2"}, echoDestination(got))
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		setResolver(t, c, resolver, resolve.Patterns{Prefixes: []string{"tok_"}})
	})
	expectStatus(t, "service down", get(t, proxiedClient(t, p, "", "", "h2"), "tok_known"), http.StatusBadGateway)
	if seen := got.all(); seen != "" {
		t.Fatalf("destination received %q", seen)
	}
}

// sealedAudience is the proxy identity of the sealed end-to-end tests.
const sealedAudience = "proxy-e2e"

// sealedFixture is a sealed resolver whose tokens are encrypted to key and
// signed by any of issuers.
type sealedFixture struct {
	t        *testing.T
	key      *ecdsa.PrivateKey
	issuers  []ed25519.PrivateKey
	resolver *resolve.Sealed
}

func newSealedFixture(t *testing.T, issuers int) *sealedFixture {
	t.Helper()
	f := &sealedFixture{t: t}
	f.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var public []crypto.PublicKey
	for range issuers {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.issuers = append(f.issuers, priv)
		public = append(public, pub)
	}
	var err error
	f.resolver, err = resolve.NewSealed(resolve.SealedConfig{Keys: []crypto.PrivateKey{f.key}, IssuerKeys: public, Audience: sealedAudience})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// seal signs p with issuer and encrypts it to proxyKey, for this proxy's
// audience unless p names one.
func (f *sealedFixture) seal(proxyKey *ecdsa.PublicKey, issuer crypto.Signer, p resolve.SealedPayload) string {
	f.t.Helper()
	if p.Aud == nil {
		p.Aud = jwt.Audience{sealedAudience}
	}
	token, err := resolve.Seal(proxyKey, issuer, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func TestSealedResolverEndToEnd(t *testing.T) {
	f := newSealedFixture(t, 2) // two issuer keys: a rotation in progress
	resolver := f.resolver
	seal := func(p resolve.SealedPayload) string { return f.seal(&f.key.PublicKey, f.issuers[0], p) }
	hour := time.Now().Add(time.Hour).Unix()
	token := seal(resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a", "4242424242424242": "4111111111111111"}, Exp: hour, Sub: "session-1"})
	rotated := f.seal(&f.key.PublicKey, f.issuers[1], resolve.SealedPayload{Values: map[string]string{"tok_b": "real_b"}, Exp: hour})
	elsewhere := seal(resolve.SealedPayload{Values: map[string]string{"tok_a": "real_elsewhere"}, Hosts: []string{"pay.example"}, Exp: hour})
	expired := seal(resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a"}, Exp: time.Now().Add(-time.Second).Unix()})
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreign := f.seal(&otherKey.PublicKey, f.issuers[0], resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a"}, Exp: hour})
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	wrongIssuer := f.seal(&f.key.PublicKey, stranger, resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a"}, Exp: hour})
	wrongAudience := seal(resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a"}, Aud: jwt.Audience{"proxy-other"}, Exp: hour})
	legacy := legacyToken(t, &f.key.PublicKey, `{"values":{"tok_a":"real_a"},"aud":"proxy-e2e","exp":9999999999}`)

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
				setResolver(t, c, resolver, resolve.Patterns{})
			})

			client := proxiedClient(t, p, "any", token, proto)
			expectStatus(t, "token value", get(t, client, "tok_a"), http.StatusOK)
			expectStatus(t, "token card", post(t, client, `{"card":"4242424242424242"}`), http.StatusOK)
			expectStatus(t, "plain request", get(t, client, "tok_other"), http.StatusOK) // not in the token: not a stand-in
			expectStatus(t, "token for another host", get(t, proxiedClient(t, p, "any", elsewhere, proto), "tok_a"), http.StatusBadGateway)
			expectStatus(t, "token from the new issuer key", get(t, proxiedClient(t, p, "any", rotated, proto), "tok_b"), http.StatusOK)

			want := "/?q=real_a \n/post {\"card\":\"4111111111111111\"}\n/?q=tok_other \n/?q=real_b "
			if seen := got.all(); seen != want {
				t.Errorf("destination received:\n%s\nwant:\n%s", seen, want)
			}
		})
	}

	// Bad tokens never get a tunnel.
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": dest.addr}, dest.ca, func(c *Config) { setResolver(t, c, resolver, resolve.Patterns{}) })
	tampered := []byte(token)
	tampered[len(tampered)-5] ^= 1
	for name, password := range map[string]string{
		"expired": expired, "foreign key": foreign, "tampered": string(tampered), "plain": "change-me",
		"wrong issuer": wrongIssuer, "wrong audience": wrongAudience, "legacy encrypt-only": legacy,
	} {
		authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("any:"+password))
		_, resp := connect(t, p.addr, otherHost+":443", authorization)
		_ = resp.Body.Close()
		expectStatus(t, name, resp.StatusCode, http.StatusProxyAuthRequired)
	}
	_, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	expectStatus(t, "no credentials", resp.StatusCode, http.StatusProxyAuthRequired)
	if strings.Contains(p.logs.String(), "real_a") || strings.Contains(p.logs.String(), token[:40]) {
		t.Fatal("the proxy log shows a real value or a token")
	}
}

// A connection whose sealed token expires while it is open gets 502 for
// every later request, stand-in or not, and nothing more reaches the
// destination.
func TestSealedTokenExpiringMidConnectionFailsClosed(t *testing.T) {
	f := newSealedFixture(t, 1)
	resolver := f.resolver
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			t.Parallel()
			exp := time.Now().Add(2 * time.Second).Truncate(time.Second).Add(time.Second)
			token, err := resolve.Seal(&f.key.PublicKey, f.issuers[0], resolve.SealedPayload{Values: map[string]string{"tok_a": "real_a"}, Aud: jwt.Audience{sealedAudience}, Exp: exp.Unix()})
			if err != nil {
				t.Fatal(err)
			}
			got := &echoed{}
			dest := startDestination(t, allowedHost, []string{proto}, echoDestination(got))
			p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) { setResolver(t, c, resolver, resolve.Patterns{}) })
			client := proxiedClient(t, p, "any", token, proto)
			expectStatus(t, "before exp", get(t, client, "tok_a"), http.StatusOK)
			time.Sleep(time.Until(exp) + 100*time.Millisecond)
			// No stand-in at all: the token's stand-ins can no longer be found,
			// so nothing is sent.
			expectStatus(t, "plain request after exp", get(t, client, "nothing"), http.StatusBadGateway)
			if proto == "h2" { // HTTP/1.1 closes the connection after a 502
				expectStatus(t, "stand-in after exp", get(t, client, "tok_a"), http.StatusBadGateway)
			}
			if seen := got.all(); seen != "/?q=real_a " {
				t.Errorf("destination received:\n%s", seen)
			}
		})
	}
}

// legacyToken is the encrypt-only format sealed tokens had before they were
// signed: claims encrypted to key, no JWS and no cty.
func legacyToken(t *testing.T, key *ecdsa.PublicKey, claims string) string {
	t.Helper()
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte(claims))
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
