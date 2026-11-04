package resolve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func seal(t *testing.T, key *ecdsa.PrivateKey, p SealedPayload) string {
	t.Helper()
	token, err := Seal(&key.PublicKey, p)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func payload(exp time.Time) SealedPayload {
	return SealedPayload{
		Values: map[string]string{"tok_a": "real-secret-a", "4242424242424242": "real-secret-card"},
		Hosts:  []string{"api.test"},
		Exp:    exp.Unix(),
		Sub:    "session-1",
	}
}

func TestSealedAuthenticatesAndResolves(t *testing.T) {
	key := ecKey(t)
	s, err := NewSealed(key)
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
	s, _ := NewSealed(key)
	p := payload(time.Now().Add(time.Hour))
	p.Sub = ""
	principal, err := s.Authenticate("proxy-user", seal(t, key, p))
	if err != nil || principal.ID != "proxy-user" {
		t.Fatalf("principal %q, %v", principal.ID, err)
	}
}

func TestSealedRefusesBadTokens(t *testing.T) {
	key := ecKey(t)
	s, _ := NewSealed(key)
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
	s, _ := NewSealed(key)
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

	s, err := LoadSealed(both)
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
	if _, err := LoadSealed(rsaFile); err == nil {
		t.Error("an RSA key was accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	writeFile(t, empty, "no pem here")
	if _, err := LoadSealed(empty); err == nil {
		t.Error("a file without a key was accepted")
	}
	if _, err := LoadSealed(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestSealRefusesTokensTheProxyWouldRefuse(t *testing.T) {
	key := ecKey(t)
	p := payload(time.Now().Add(time.Hour))
	p.Values = map[string]string{"tok_a": strings.Repeat("x", maxSealedToken)}
	if _, err := Seal(&key.PublicKey, p); err == nil {
		t.Fatal("an oversized token was sealed")
	}
	p.Values = map[string]string{"tok_a": strings.Repeat("x", maxSealedToken/2)}
	token, err := Seal(&key.PublicKey, p)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewSealed(key)
	if _, err := s.Authenticate("u", token); err != nil {
		t.Fatalf("a token Seal accepted was refused: %v", err)
	}
}

func TestSealedCacheIsBoundedByExpiryTTLAndSize(t *testing.T) {
	key := ecKey(t)
	s, _ := NewSealed(key)
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

func TestSealedViewFailsClosedOnExpiry(t *testing.T) {
	key := ecKey(t)
	s, _ := NewSealed(key)
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
