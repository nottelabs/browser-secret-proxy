package resolve

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testIssuer signs the tokens of these tests, for the proxy testAudience.
var testIssuer = func() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}()

const testAudience = "proxy-test"

// testSealed is a Sealed resolver for key that trusts testIssuer, closed
// when the test ends so its expiry sweep stops.
func testSealed(t *testing.T, key *ecdsa.PrivateKey) (*Sealed, error) {
	s, err := NewSealed(SealedConfig{Keys: []crypto.PrivateKey{key}, IssuerKeys: []crypto.PublicKey{testIssuer.Public()}, Audience: testAudience})
	if err == nil {
		t.Cleanup(s.Close)
	}
	return s, err
}

func seal(t *testing.T, key *ecdsa.PrivateKey, p SealedPayload) string {
	t.Helper()
	token, err := Seal(&key.PublicKey, testIssuer, p)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func payload(exp time.Time) SealedPayload {
	return SealedPayload{
		Values: map[string]string{"tok_a": "real-secret-a", "4242424242424242": "real-secret-card"},
		Hosts:  []string{"api.test"},
		Aud:    jwt.Audience{testAudience},
		Exp:    exp.Unix(),
		Sub:    "session-1",
	}
}

func TestSealedAuthenticatesAndResolves(t *testing.T) {
	key := ecKey(t)
	s, err := testSealed(t, key)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	token := seal(t, key, payload(exp))

	p, err := s.Authenticate("anyone", token)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "session-1" || p.Password != token {
		t.Fatalf("principal %q", p.ID)
	}
	if got := s.StandIns(p); !reflect.DeepEqual(got, []string{"4242424242424242", "tok_a"}) {
		t.Fatalf("StandIns = %q", got)
	}
	res, err := s.Resolve(context.Background(), Request{StandIns: []string{"tok_a", "tok_other"}, Host: "api.test", Principal: p})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := res.Values["tok_a"]
	if !ok || v.Real != "real-secret-a" || !reflect.DeepEqual(v.Hosts, []string{"api.test"}) || !v.ExpiresAt.Equal(exp) {
		t.Fatalf("tok_a resolved to hosts %q, expiry %v", v.Hosts, v.ExpiresAt)
	}
	if _, ok := res.Values["tok_other"]; ok {
		t.Fatal("a stand-in outside the token was resolved")
	}

	d, err := NewDetector(s, Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Find(p, "card=4242424242424242&t=tok_a"); !reflect.DeepEqual(got, []string{"4242424242424242", "tok_a"}) {
		t.Fatalf("the detector found %q in the token's keys", got)
	}
	if got := d.Find(Principal{ID: "x", Password: "not a token"}, "tok_a"); got != nil {
		t.Fatalf("an invalid token's principal found %q", got)
	}
}

func TestSealedPrincipalFallsBackToTheUsername(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	p := payload(time.Now().Add(time.Hour))
	p.Sub = ""
	principal, err := s.Authenticate("proxy-user", seal(t, key, p))
	if err != nil || principal.ID != "proxy-user" {
		t.Fatalf("principal %q, %v", principal.ID, err)
	}
	// The username only names the principal: the token alone identifies it.
	if !principal.SecretOnly {
		t.Fatal("a sealed principal is not identified by its token alone")
	}
}

// One token is one credential: the same token spelled any other way that
// base64url decoding would still take (CR or LF inside a segment, non-zero
// unused bits, padding, extra segments) is refused, so it can become neither
// another principal nor another cache entry.
func TestSealedAcceptsOnlyTheCanonicalForm(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	token := seal(t, key, payload(time.Now().Add(time.Hour)))
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] == "" {
		t.Fatalf("%d segments, encrypted key %q: want ECDH-ES+A256KW to give five, with a wrapped key", len(parts), parts[1])
	}
	respell := func(part int, f func(string) string) string {
		p := append([]string(nil), parts...)
		p[part] = f(p[part])
		return strings.Join(p, ".")
	}
	insert := func(at int, s string) func(string) string {
		return func(segment string) string { return segment[:at] + s + segment[at:] }
	}
	// The 16-byte tag is 22 characters, the last of which has 2 unused bits.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	unusedBit := func(segment string) string {
		last := strings.IndexByte(alphabet, segment[len(segment)-1])
		return segment[:len(segment)-1] + string(alphabet[last|1])
	}
	if unusedBit(parts[4]) == parts[4] {
		t.Fatal("the tag already has an unused bit set")
	}
	variants := map[string]string{
		"LF in the ciphertext": respell(3, insert(10, "\n")),
		"CRLF in the header":   respell(0, insert(5, "\r\n")),
		"LFs in the tag":       respell(4, insert(1, "\n\n\n")),
		"unused bit in tag":    respell(4, unusedBit),
		"padded tag":           respell(4, func(segment string) string { return segment + "==" }),
		"trailing LF":          token + "\n",
		"sixth segment":        token + ".",
		"four segments":        strings.Join(parts[:4], "."),
	}
	for name, variant := range variants {
		if _, err := s.Authenticate("u", variant); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
	if _, err := s.Authenticate("u", token); err != nil {
		t.Fatalf("the canonical token was refused: %v", err)
	}
	s.mu.Lock()
	cached := len(s.cache)
	s.mu.Unlock()
	if cached != 1 {
		t.Fatalf("%d cached tokens, want the canonical one only", cached)
	}
}

func TestSealedRefusesBadTokens(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	good := seal(t, key, payload(time.Now().Add(time.Hour)))

	tamper := func(token string, part int) string {
		parts := strings.Split(token, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[part])
		if err != nil || len(raw) == 0 {
			t.Fatalf("part %d: %v", part, err)
		}
		raw[len(raw)/2] ^= 1
		parts[part] = base64.RawURLEncoding.EncodeToString(raw)
		return strings.Join(parts, ".")
	}
	noExp := payload(time.Now().Add(time.Hour))
	noExp.Exp = 0
	noValues := payload(time.Now().Add(time.Hour))
	noValues.Values = nil
	emptyStandIn := payload(time.Now().Add(time.Hour))
	emptyStandIn.Values = map[string]string{"": "real-secret-a"}

	direct, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: &key.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	directObj, _ := direct.Encrypt([]byte(`{"values":{"tok_a":"real-secret-a"},"exp":9999999999}`))
	directToken, _ := directObj.CompactSerialize()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	oaep, _ := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &rsaKey.PublicKey}, nil)
	oaepObj, _ := oaep.Encrypt([]byte(`{"values":{"tok_a":"real-secret-a"},"exp":9999999999}`))
	oaepToken, _ := oaepObj.CompactSerialize()

	cases := map[string]string{
		"expired":             seal(t, key, payload(time.Now().Add(-time.Second))),
		"wrong key":           seal(t, ecKey(t), payload(time.Now().Add(time.Hour))),
		"tampered ciphertext": tamper(good, 3),
		"tampered tag":        tamper(good, 4),
		"tampered header":     tamper(good, 0),
		"tampered key":        tamper(good, 1),
		"no exp":              seal(t, key, noExp),
		"no values":           seal(t, key, noValues),
		"empty stand-in":      seal(t, key, emptyStandIn),
		"other key algorithm": directToken,
		"rsa":                 oaepToken,
		"plain password":      "change-me",
		"empty":               "",
		"oversized":           strings.Repeat("a", maxSealedToken+1),
	}
	for name, token := range cases {
		_, err := s.Authenticate("u", token)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
			continue
		}
		if strings.Contains(err.Error(), "real-secret") || (len(token) > 20 && strings.Contains(err.Error(), token[:20])) {
			t.Errorf("%s: the error quotes the token: %v", name, err)
		}
		if _, err := s.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Principal: Principal{Password: token}}); err == nil {
			t.Errorf("%s: resolved", name)
		}
	}
}

func TestSealedTokenExpiresAfterConnect(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	now := time.Now()
	s.now = func() time.Time { return now }
	token := seal(t, key, payload(now.Add(time.Minute)))
	p, err := s.Authenticate("u", token)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // a long-lived connection outlives its token
	if _, err := s.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Principal: p}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an expired cached token resolved: %v", err)
	}
	if got := s.StandIns(p); got != nil {
		t.Fatalf("an expired token still lists %q", got)
	}
}

func TestLoadSealedKeys(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := ecKey(t), ecKey(t)
	sec1, _ := x509.MarshalECPrivateKey(k1)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k2)
	both := filepath.Join(dir, "keys.pem")
	writeFile(t, both, string(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}}))+
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))+
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})))

	issuerDER, _ := x509.MarshalPKIXPublicKey(testIssuer.Public())
	issuerFile := filepath.Join(dir, "issuer.pem")
	writePEM(t, issuerFile, "PUBLIC KEY", issuerDER)
	s, err := LoadSealed(both, []string{issuerFile}, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range []*ecdsa.PrivateKey{k1, k2} {
		if _, err := s.Authenticate("u", seal(t, key, payload(time.Now().Add(time.Hour)))); err != nil {
			t.Errorf("key %d (rotation): %v", i, err)
		}
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaFile := filepath.Join(dir, "rsa.pem")
	writePEM(t, rsaFile, "PRIVATE KEY", rsaDER)
	if _, err := LoadSealed(rsaFile, []string{issuerFile}, testAudience); err == nil {
		t.Error("an RSA key was accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	writeFile(t, empty, "no pem here")
	if _, err := LoadSealed(empty, []string{issuerFile}, testAudience); err == nil {
		t.Error("a file without a key was accepted")
	}
	if _, err := LoadSealed(filepath.Join(dir, "missing.pem"), []string{issuerFile}, testAudience); err == nil {
		t.Error("a missing file was accepted")
	}
	for name, issuers := range map[string][]string{"no issuer file": nil, "issuer file without a key": {empty}, "issuer file is a private key": {both}, "missing issuer file": {filepath.Join(dir, "nope.pem")}} {
		if _, err := LoadSealed(both, issuers, testAudience); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadSealed(both, []string{issuerFile}, ""); err == nil {
		t.Error("an empty audience was accepted")
	}
}

func TestSealRefusesTokensTheProxyWouldRefuse(t *testing.T) {
	key := ecKey(t)
	p := payload(time.Now().Add(time.Hour))
	p.Values = map[string]string{"tok_a": strings.Repeat("x", maxSealedToken)}
	if _, err := Seal(&key.PublicKey, testIssuer, p); err == nil {
		t.Fatal("an oversized token was sealed")
	}
	p.Values = map[string]string{"tok_a": strings.Repeat("x", maxSealedToken/2)}
	token, err := Seal(&key.PublicKey, testIssuer, p)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testSealed(t, key)
	if _, err := s.Authenticate("u", token); err != nil {
		t.Fatalf("a token Seal accepted was refused: %v", err)
	}
	// An empty host list would be left out of the claims, and the values
	// could then go to any host in -hosts.
	p.Hosts = []string{}
	if _, err := Seal(&key.PublicKey, testIssuer, p); err == nil {
		t.Fatal("a token with an empty host list was sealed")
	}
}

// sealClaims signs claims exactly as given, then seals them to key.
func sealClaims(t *testing.T, key *ecdsa.PrivateKey, claims string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: testIssuer}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte(claims))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return encryptAsJWT(t, key, []byte(jws), true)
}

// The claims are read as the issuer wrote them. encoding/json alone would
// take a member in any case and let the last of two win, so "HOSTS": []
// or a second "exp" after the ones the issuer checked would lift the host
// restriction or extend the token: such claims are refused. Members the
// proxy does not use are still allowed.
func TestSealedClaimsAreDecodedStrictly(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	exp := time.Now().Add(time.Hour).Unix()
	later := exp + 10*365*24*3600
	claims := func(values, extra string) string {
		return fmt.Sprintf(`{"values":%s,"hosts":["api.test"],"aud":%q,"exp":%d%s}`, values, testAudience, exp, extra)
	}
	const values = `{"tok_a":"real-secret-a"}`
	for name, c := range map[string]string{
		"as signed":         claims(values, ""),
		"unknown members":   claims(values, `,"jti":"j1","iss":"issuer","nested":{"a":1,"A":2}`),
		"stand-ins by case": claims(`{"tok_a":"real-secret-a","TOK_A":"real-secret-b"}`, ""),
	} {
		p, err := s.Authenticate("u", sealClaims(t, key, c))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		res, err := s.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Principal: p})
		if v := res.Values["tok_a"]; err != nil || v.Real != "real-secret-a" || strings.Join(v.Hosts, ",") != "api.test" || !v.ExpiresAt.Equal(time.Unix(exp, 0)) {
			t.Errorf("%s: resolved %v, hosts %q, expiry %v, err %v", name, v.Real == "real-secret-a", v.Hosts, v.ExpiresAt, err)
		}
	}
	for name, c := range map[string]string{
		"hosts in upper case":    claims(values, `,"HOSTS":[]`),
		"hosts with a long s":    claims(values, `,"hoſts":[]`),
		"hosts twice":            claims(values, `,"hosts":[]`),
		"exp in upper case":      claims(values, fmt.Sprintf(`,"EXP":%d`, later)),
		"exp twice":              claims(values, fmt.Sprintf(`,"exp":%d`, later)),
		"aud in another case":    claims(values, `,"Aud":"proxy-other"`),
		"values in another case": claims(values, `,"Values":{"tok_b":"real-secret-b"}`),
		"a stand-in twice":       claims(`{"tok_a":"real-secret-a","tok_a":"real-secret-b"}`, ""),
		"a nested member twice":  claims(values, `,"extra":{"a":1,"a":2}`),
	} {
		_, err := s.Authenticate("u", sealClaims(t, key, c))
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
			continue
		}
		if strings.Contains(err.Error(), "real-secret") || strings.Contains(err.Error(), "tok_") {
			t.Errorf("%s: the error quotes the claims: %v", name, err)
		}
	}
}

// An empty host list in a token is not the same as none: the values may go
// nowhere (the scope refuses them), not wherever -hosts allows.
func TestSealedKeepsAnEmptyHostList(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	exp := time.Now().Add(time.Hour).Unix()
	for hosts, want := range map[string][]string{`,"hosts":[]`: {}, `,"hosts":null`: nil, ``: nil} {
		token := sealClaims(t, key, fmt.Sprintf(`{"values":{"tok_a":"real-secret-a"},"aud":%q,"exp":%d%s}`, testAudience, exp, hosts))
		p, err := s.Authenticate("u", token)
		if err != nil {
			t.Fatalf("%q: %v", hosts, err)
		}
		res, err := s.Resolve(context.Background(), Request{StandIns: []string{"tok_a"}, Principal: p})
		if got := res.Values["tok_a"].Hosts; err != nil || (got == nil) != (want == nil) || len(got) != 0 {
			t.Errorf("%q: hosts %#v, err %v", hosts, got, err)
		}
	}
}

func TestSealedCacheIsBoundedByExpiryTTLAndSize(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	now := time.Now()
	s.now = func() time.Time { return now }
	cached := func() int {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.cache)
	}

	// Dropped at exp: an expired token leaves nothing in memory.
	short := seal(t, key, payload(now.Add(time.Minute)))
	if _, err := s.Authenticate("u", short); err != nil || cached() != 1 {
		t.Fatalf("not cached: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Authenticate("u", short); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an expired token was accepted: %v", err)
	}
	if cached() != 0 {
		t.Fatal("an expired token's values stayed in memory")
	}

	// Kept at most sealedCacheTTL, even when exp is later.
	long := seal(t, key, payload(now.Add(24*time.Hour)))
	if _, err := s.Authenticate("u", long); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, e := range s.cache {
		if e.until.After(now.Add(sealedCacheTTL)) {
			t.Errorf("cached until %v, more than %v from now", e.until.Sub(now), sealedCacheTTL)
		}
	}
	s.mu.Unlock()
	now = now.Add(sealedCacheTTL + time.Second)
	other := seal(t, key, payload(now.Add(time.Hour)))
	if _, err := s.Authenticate("u", other); err != nil {
		t.Fatal(err)
	}
	if cached() != 1 {
		t.Fatalf("%d cached tokens, want only the new one after the TTL", cached())
	}
	if _, err := s.Authenticate("u", long); err != nil {
		t.Fatalf("a token past the cache TTL but before exp was refused: %v", err)
	}

	// Capped in size.
	for range maxSealedCache + 20 {
		if _, err := s.Authenticate("u", seal(t, key, payload(now.Add(time.Hour)))); err != nil {
			t.Fatal(err)
		}
	}
	if n := cached(); n > maxSealedCache {
		t.Fatalf("%d cached tokens, limit %d", n, maxSealedCache)
	}
}

// Decrypted tokens leave memory at their time even when no request comes:
// a sweep drops them, and leaves the ones whose time has not come.
func TestSealedCacheIsSweptWhileIdle(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	defer s.Close()
	s.sweepEvery = 10 * time.Millisecond
	short := payload(time.Now().Add(time.Hour))
	long := payload(time.Now().Add(2 * time.Hour))
	// The proxy's clock reads 100ms before the short token's exp, so its time
	// comes without waiting an hour.
	offset := time.Until(time.Unix(short.Exp, 0)) - 100*time.Millisecond
	s.now = func() time.Time { return time.Now().Add(offset) }
	for _, p := range []SealedPayload{short, long} {
		if _, err := s.Authenticate("u", seal(t, key, p)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		var kept []time.Time
		for _, e := range s.cache {
			kept = append(kept, e.expires)
		}
		s.mu.Unlock()
		if len(kept) == 1 && kept[0].Equal(time.Unix(long.Exp, 0)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("with no request, %d tokens still cached past the short token's exp (want only the long one)", len(kept))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Close stops the sweep and drops every decrypted token; tokens still open
// afterwards, without being kept.
func TestSealedCloseStopsTheSweep(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	token := seal(t, key, payload(time.Now().Add(time.Hour)))
	if _, err := s.Authenticate("u", token); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(s.cache) != 0 || !s.next.IsZero() {
		t.Fatal("Close kept tokens or the sweep")
	}
	if _, err := s.Authenticate("u", token); err != nil {
		t.Fatalf("a token was refused after Close: %v", err)
	}
	if len(s.cache) != 0 || !s.next.IsZero() {
		t.Fatal("a closed resolver cached a token or armed its sweep")
	}
}

func TestSealedViewFailsClosedOnExpiry(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	now := time.Now()
	s.now = func() time.Time { return now }
	p, err := s.Authenticate("u", seal(t, key, payload(now.Add(time.Minute))))
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.view(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.StandIns(p); !reflect.DeepEqual(got, []string{"4242424242424242", "tok_a"}) {
		t.Fatalf("StandIns = %q", got)
	}
	res, err := v.Resolve(context.Background(), Request{StandIns: v.StandIns(p)})
	if err != nil || len(res.Values) != 2 {
		t.Fatalf("the view resolved %d values: %v", len(res.Values), err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.view(p); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an expired token gave a view: %v", err)
	}
}

// Both resolvers that change over time give the proxy one snapshot per request.
var (
	_ Snapshotter = (*Sealed)(nil)
	_ Snapshotter = (*File)(nil)
)

func TestSealedSnapshotIsTheView(t *testing.T) {
	key := ecKey(t)
	s, _ := testSealed(t, key)
	now := time.Now()
	s.now = func() time.Time { return now }
	p, err := s.Authenticate("u", seal(t, key, payload(now.Add(time.Minute))))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(p)
	if err != nil || len(snap.StandIns(p)) != 2 {
		t.Fatalf("snapshot: %v", err)
	}
	now = now.Add(2 * time.Minute)
	snap, err = s.Snapshot(p)
	if !errors.Is(err, ErrUnauthenticated) || snap != nil {
		t.Fatalf("an expired token gave snapshot %v, err %v", snap, err)
	}
}

// encryptAsJWT encrypts inner to key as the outer JWE of a sealed token
// (cty JWT), whatever inner is.
func encryptAsJWT(t *testing.T, key *ecdsa.PrivateKey, inner []byte, cty bool) string {
	t.Helper()
	opts := &jose.EncrypterOptions{}
	if cty {
		opts = opts.WithContentType("JWT")
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: &key.PublicKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt(inner)
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// signJWS signs p with issuer as a compact JWS.
func signJWS(t *testing.T, alg jose.SignatureAlgorithm, issuer any, p SealedPayload) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: issuer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(p)
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return jws
}

func TestSealedRequiresASignatureAndTheAudience(t *testing.T) {
	key := ecKey(t)
	s, err := testSealed(t, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	hour := now.Add(time.Hour)
	claims, _ := json.Marshal(payload(hour))
	_, otherIssuer, _ := ed25519.GenerateKey(rand.Reader)

	jws := signJWS(t, jose.EdDSA, testIssuer, payload(hour))
	parts := strings.Split(jws, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	tamperedSignature := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	otherPayload := payload(hour)
	otherPayload.Values = map[string]string{"tok_a": "real-secret-swapped"}
	otherClaims, _ := json.Marshal(otherPayload)
	swappedClaims := parts[0] + "." + base64.RawURLEncoding.EncodeToString(otherClaims) + "." + parts[2]

	with := func(change func(*SealedPayload)) string {
		p := payload(hour)
		change(&p)
		return seal(t, key, p)
	}
	refused := map[string]string{
		"legacy encrypt-only":       encryptAsJWT(t, key, claims, false),
		"unsigned JWE with cty JWT": encryptAsJWT(t, key, claims, true),
		"signed, no cty":            encryptAsJWT(t, key, []byte(jws), false),
		"wrong issuer key":          encryptAsJWT(t, key, []byte(signJWS(t, jose.EdDSA, otherIssuer, payload(hour))), true),
		"tampered signature":        encryptAsJWT(t, key, []byte(tamperedSignature), true),
		"claims swapped":            encryptAsJWT(t, key, []byte(swappedClaims), true),
		"wrong aud":                 with(func(p *SealedPayload) { p.Aud = jwt.Audience{"proxy-other"} }),
		"no aud":                    with(func(p *SealedPayload) { p.Aud = nil }),
		"expired":                   with(func(p *SealedPayload) { p.Exp = now.Add(-time.Second).Unix() }),
		"nbf in the future":         with(func(p *SealedPayload) { p.Nbf = now.Add(5 * time.Minute).Unix() }),
		"iat in the future":         with(func(p *SealedPayload) { p.Iat = now.Add(5 * time.Minute).Unix() }),
	}
	for name, token := range refused {
		if _, err := s.Authenticate("u", token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		} else if strings.Contains(err.Error(), "real-secret") {
			t.Errorf("%s: the error quotes the token: %v", name, err)
		}
	}

	accepted := map[string]string{
		"aud list with this proxy": with(func(p *SealedPayload) { p.Aud = jwt.Audience{"proxy-other", testAudience} }),
		"nbf within the skew":      with(func(p *SealedPayload) { p.Nbf = now.Add(sealedClockSkew / 2).Unix() }),
		"iat now":                  with(func(p *SealedPayload) { p.Iat = now.Unix() }),
		"nbf and iat in the past":  with(func(p *SealedPayload) { p.Nbf, p.Iat = now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix() }),
	}
	for name, token := range accepted {
		if _, err := s.Authenticate("u", token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Old and new issuer keys work side by side during a rotation, EdDSA and
// ES256 alike; a key that is not configured does not.
func TestSealedIssuerKeyRotation(t *testing.T) {
	key := ecKey(t)
	_, oldIssuer, _ := ed25519.GenerateKey(rand.Reader)
	newIssuer := ecKey(t) // P-256: ES256
	_, retired, _ := ed25519.GenerateKey(rand.Reader)
	s, err := NewSealed(SealedConfig{
		Keys:       []crypto.PrivateKey{key},
		IssuerKeys: []crypto.PublicKey{oldIssuer.Public(), &newIssuer.PublicKey},
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	for name, issuer := range map[string]crypto.Signer{"old EdDSA key": oldIssuer, "new ES256 key": newIssuer} {
		token, err := Seal(&key.PublicKey, issuer, payload(time.Now().Add(time.Hour)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Authenticate("u", token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	token, _ := Seal(&key.PublicKey, retired, payload(time.Now().Add(time.Hour)))
	if _, err := s.Authenticate("u", token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a retired issuer key was accepted: %v", err)
	}
}

func TestSealedConfigIsChecked(t *testing.T) {
	key := ecKey(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, cfg := range map[string]SealedConfig{
		"no key":       {IssuerKeys: []crypto.PublicKey{testIssuer.Public()}, Audience: testAudience},
		"no issuer":    {Keys: []crypto.PrivateKey{key}, Audience: testAudience},
		"no audience":  {Keys: []crypto.PrivateKey{key}, IssuerKeys: []crypto.PublicKey{testIssuer.Public()}},
		"RSA issuer":   {Keys: []crypto.PrivateKey{key}, IssuerKeys: []crypto.PublicKey{&rsaKey.PublicKey}, Audience: testAudience},
		"P-384 issuer": {Keys: []crypto.PrivateKey{key}, IssuerKeys: []crypto.PublicKey{&p384.PublicKey}, Audience: testAudience},
	} {
		if _, err := NewSealed(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Seal(&key.PublicKey, rsaKey, payload(time.Now().Add(time.Hour))); err == nil {
		t.Error("Seal signed with an RSA key")
	}
}
