package main

import (
	"crypto/ecdsa"
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
	var out strings.Builder
	if err := run([]string{"-public-key", pub, "-ttl", "10m", payload}, &out); err != nil {
		t.Fatal(err)
	}
	sealed, err := resolve.NewSealed(key)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := run([]string{"-public-key", pub, payload}, &out); err == nil {
		t.Fatal("a payload without values was sealed")
	}
	if err := run([]string{payload}, &out); err == nil {
		t.Fatal("ran without a public key")
	}
}
