package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

func TestSealedTokenOpensInTheProxy(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := filepath.Join(dir, "public.pem")
	payload := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte(`{"values": {"tok_a": "real_a"}, "hosts": ["api.test"], "sub": "s1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	issuerDER, _ := x509.MarshalPKCS8PrivateKey(issuerPriv)
	issuer := filepath.Join(dir, "issuer.key")
	if err := os.WriteFile(issuer, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := run([]string{"-public-key", pub, "-issuer-key", issuer, "-audience", "proxy-1", "-ttl", "10m", payload}, &out); err != nil {
		t.Fatal(err)
	}
	proxy := func(audience string) *resolve.Sealed {
		t.Helper()
		s, err := resolve.NewSealed(resolve.SealedConfig{Keys: []crypto.PrivateKey{key}, IssuerKeys: []crypto.PublicKey{issuerPub}, Audience: audience})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	if _, err := proxy("proxy-2").Authenticate("u", strings.TrimSpace(out.String())); err == nil {
		t.Fatal("a token for proxy-1 opened on proxy-2")
	}
	sealed := proxy("proxy-1")
	p, err := sealed.Authenticate("u", strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "s1" || strings.Join(sealed.StandIns(p), ",") != "tok_a" {
		t.Fatalf("principal %q, stand-ins %q", p.ID, sealed.StandIns(p))
	}

	if err := os.WriteFile(payload, []byte(`{"values": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-public-key", pub, "-issuer-key", issuer, "-audience", "proxy-1", payload}, &out); err == nil {
		t.Fatal("a payload without values was sealed")
	}
	if err := run([]string{payload}, &out); err == nil {
		t.Fatal("ran without a public key")
	}
	for name, c := range map[string]struct{ payload, ttl string }{
		"empty stand-in": {`{"values": {"": "real_a"}}`, "10m"},
		"negative ttl":   {`{"values": {"tok_a": "real_a"}}`, "-1m"},
		"past exp":       {`{"values": {"tok_a": "real_a"}, "exp": 1}`, "10m"},
		"unknown field":  {`{"values": {"tok_a": "real_a"}, "host": ["api.test"]}`, "10m"},
	} {
		if err := os.WriteFile(payload, []byte(c.payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"-public-key", pub, "-issuer-key", issuer, "-audience", "proxy-1", "-ttl", c.ttl, payload}, &out); err == nil {
			t.Errorf("%s: sealed a token the proxy would refuse", name)
		}
	}
	if err := run([]string{"-public-key", pub, "-audience", "proxy-1", payload}, &out); err == nil {
		t.Fatal("ran without an issuer key")
	}
	if err := run([]string{"-public-key", pub, "-issuer-key", pub, "-audience", "proxy-1", payload}, &out); err == nil {
		t.Fatal("a public key was accepted as the issuer key")
	}
}
