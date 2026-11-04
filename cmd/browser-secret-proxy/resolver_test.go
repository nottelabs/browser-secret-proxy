package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

func parseResolverFlags(t *testing.T, args ...string) *resolverFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := registerResolverFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// keyPair writes a self-signed certificate and its EC key.
func keyPair(t *testing.T) (certFile, keyFile string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile = writeTemp(t, "cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyFile = writeTemp(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certFile, keyFile, key
}

func TestSwapsAloneSelectsTheFileMode(t *testing.T) {
	swaps := writeTemp(t, "swaps.json", []byte(`{"tok_a": "real_a"}`))
	for _, args := range [][]string{{"-swaps", swaps}, {"-resolver", "file", "-swaps", swaps, "-swaps-reload", "0"}} {
		setup, err := parseResolverFlags(t, args...).build("", quiet)
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if _, ok := setup.resolver.(*resolve.File); !ok || setup.mode != "file" {
			t.Fatalf("%q: mode %s", args, setup.mode)
		}
		if (setup.watch != nil) != (len(args) == 2) {
			t.Fatalf("%q: watch set %v", args, setup.watch != nil)
		}
		if got := setup.detector.Find(resolve.Principal{}, "x=tok_a"); len(got) != 1 {
			t.Fatalf("%q: the file's stand-ins are not detected", args)
		}
	}
}

func TestEachModeBuilds(t *testing.T) {
	cert, key, ecKey := keyPair(t)
	der, _ := x509.MarshalECPrivateKey(ecKey)
	sealedKey := writeTemp(t, "sealed.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	setup, err := parseResolverFlags(t, "-resolver", "http", "-resolver-url", "https://detokenize.test/v1", "-resolver-cert", cert,
		"-resolver-key", key, "-resolver-ca", cert, "-standin-prefixes", "tok_, card_", "-standin-pattern", `\b4[0-9]{15}\b`, "-standin-luhn").build("user", quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := setup.resolver.(*resolve.HTTP); !ok {
		t.Fatal("not an http resolver")
	}
	if setup.timeout != 2*time.Second {
		t.Fatalf("the proxy's lookup deadline is %v, want -resolver-timeout's default 2s", setup.timeout)
	}
	long, err := parseResolverFlags(t, "-resolver", "http", "-resolver-url", "https://detokenize.test/v1", "-resolver-cert", cert,
		"-resolver-key", key, "-resolver-timeout", "30s", "-standin-prefixes", "tok_").build("user", quiet)
	if err != nil || long.timeout != 30*time.Second {
		t.Fatalf("-resolver-timeout 30s gave the proxy a %v deadline (%v)", long.timeout, err)
	}
	if got := setup.detector.Find(resolve.Principal{}, "tok_1 card_2 4242424242424242 4242424242424241"); strings.Join(got, ",") != "4242424242424242,card_2,tok_1" {
		t.Fatalf("detected %q", got)
	}

	setup, err = parseResolverFlags(t, "-resolver", "sealed", "-sealed-key", sealedKey).build("", quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := setup.resolver.(resolve.Authenticator); !ok {
		t.Fatal("the sealed resolver does not authenticate")
	}
}

func TestResolverFlagErrors(t *testing.T) {
	swaps := writeTemp(t, "swaps.json", []byte(`{"tok_a": "real_a"}`))
	cert, key, _ := keyPair(t)
	cases := []struct {
		name, username string
		args           []string
		want           string
	}{
		{"nothing", "", nil, "needs -swaps"},
		{"unknown mode", "", []string{"-resolver", "vault"}, "want file, http or sealed"},
		{"swaps with http", "", []string{"-resolver", "http", "-swaps", swaps}, "-swaps cannot be used with -resolver http"},
		{"http flag with file", "", []string{"-swaps", swaps, "-resolver-url", "https://x.test"}, "-resolver-url cannot be used with -resolver file"},
		{"sealed key with http", "", []string{"-resolver", "http", "-sealed-key", "k"}, "-sealed-key cannot be used"},
		{"http without mTLS", "", []string{"-resolver", "http", "-resolver-url", "https://x.test", "-standin-prefixes", "tok_"}, "client certificate"},
		{"http without patterns", "u", []string{"-resolver", "http", "-resolver-url", "https://x.test", "-resolver-cert", cert, "-resolver-key", key}, "set a stand-in pattern"},
		{"sealed without key", "", []string{"-resolver", "sealed"}, "needs -sealed-key"},
		{"sealed with fixed credentials", "proxy-user", []string{"-resolver", "sealed", "-sealed-key", key}, "not used with -resolver sealed"},
		{"bad pattern", "", []string{"-swaps", swaps, "-standin-pattern", "("}, "stand-in pattern"},
	}
	for _, c := range cases {
		_, err := parseResolverFlags(t, c.args...).build(c.username, quiet)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}
