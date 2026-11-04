package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testCA returns, in PEM, a throwaway self-signed certificate for key,
// valid until notAfter, with basicConstraints CA set to isCA.
func testCA(t *testing.T, key crypto.Signer, notAfter time.Time, isCA bool) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// authority returns an Authority over a fresh CA valid for 30 days.
func authority(t *testing.T) *Authority {
	t.Helper()
	key := ecKey(t)
	a, err := New(testCA(t, key, time.Now().Add(30*24*time.Hour), true), pkcs8(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLeafCertificate(t *testing.T) {
	a := authority(t)
	now := time.Now().Truncate(time.Second)
	a.now = func() time.Time { return now }
	cert, err := a.Certificate("API.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf.Subject.CommonName != "api.example.com" || !slices.Equal(leaf.DNSNames, []string{"api.example.com"}) || len(leaf.IPAddresses) != 0 {
		t.Errorf("CN %q, DNS names %q, IPs %v", leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses)
	}
	if !leaf.NotBefore.Equal(now.Add(-time.Hour)) || !leaf.NotAfter.Equal(now.Add(leafLifetime)) {
		t.Errorf("valid from %v to %v, issued at %v", leaf.NotBefore, leaf.NotAfter, now)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Errorf("IsCA %v, basic constraints %v", leaf.IsCA, leaf.BasicConstraintsValid)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("key usage %v, extended %v", leaf.KeyUsage, leaf.ExtKeyUsage)
	}
	if leaf.SerialNumber.Sign() <= 0 {
		t.Errorf("serial %v", leaf.SerialNumber)
	}
	// The chain is the leaf then the CA, and verifies for the host only.
	if len(cert.Certificate) != 2 || !slices.Equal(cert.Certificate[1], a.CA().Raw) {
		t.Fatalf("chain of %d certificates", len(cert.Certificate))
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.CA())
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		t.Errorf("leaf does not verify: %v", err)
	}
	if err := leaf.VerifyHostname("api.example.com"); err != nil {
		t.Error(err)
	}
	if err := leaf.VerifyHostname("www.example.com"); err == nil {
		t.Error("leaf verifies for another host")
	}
	if !cert.PrivateKey.(*ecdsa.PrivateKey).PublicKey.Equal(leaf.PublicKey) {
		t.Error("private key does not match the leaf")
	}
}

func TestLeafForIPAddress(t *testing.T) {
	a := authority(t)
	for host, want := range map[string]net.IP{"127.0.0.1": net.ParseIP("127.0.0.1"), "::1": net.ParseIP("::1"), "2001:DB8::1": net.ParseIP("2001:db8::1")} {
		cert, err := a.Certificate(host)
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.Leaf.DNSNames) != 0 || len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(want) {
			t.Errorf("%s: DNS names %q, IPs %v", host, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		if err := cert.Leaf.VerifyHostname(want.String()); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}

// The validity ends with the CA's when the CA expires first.
func TestLeafValidityIsClampedToTheCA(t *testing.T) {
	key := ecKey(t)
	caEnd := time.Now().Add(3 * 24 * time.Hour).Truncate(time.Second)
	a, err := New(testCA(t, key, caEnd, true), pkcs8(t, key))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Leaf.NotAfter.Equal(caEnd) {
		t.Fatalf("leaf ends %v, CA %v", cert.Leaf.NotAfter, caEnd)
	}
}

// One certificate per canonical host name, until shortly before it expires.
func TestLeafCacheAndRenewal(t *testing.T) {
	a := authority(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	first, err := a.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.example.com", "API.EXAMPLE.COM", "api.example.com."} {
		if c, err := a.Certificate(host); err != nil || c != first {
			t.Errorf("%q: a new certificate (%v)", host, err)
		}
	}
	other, err := a.Certificate("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if other == first || other.Leaf.DNSNames[0] != "www.example.com" {
		t.Error("another host shares the certificate")
	}

	now = first.Leaf.NotAfter.Add(-renewBefore - time.Minute)
	if c, _ := a.Certificate("api.example.com"); c != first {
		t.Error("renewed more than an hour before expiry")
	}
	now = first.Leaf.NotAfter.Add(-renewBefore + time.Minute)
	renewed, err := a.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first || renewed.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 || !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Errorf("not renewed within the last hour: serial %v, ends %v", renewed.Leaf.SerialNumber, renewed.Leaf.NotAfter)
	}
	if c, _ := a.Certificate("api.example.com"); c != renewed {
		t.Error("the renewed certificate is not cached")
	}
}

func TestCertificateRefusesAnEmptyHost(t *testing.T) {
	a := authority(t)
	for _, host := range []string{"", "."} {
		if _, err := a.Certificate(host); err == nil {
			t.Errorf("issued a certificate for %q", host)
		}
	}
}

// The CA key may be PKCS#8 (any of the three key types), PKCS#1 or SEC1,
// after other PEM blocks such as the EC PARAMETERS openssl writes first.
func TestNewKeyFormats(t *testing.T) {
	ec := ecKey(t)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}})
	cases := []struct {
		name   string
		key    crypto.Signer
		keyPEM []byte
	}{
		{"PKCS#8 EC", ec, pkcs8(t, ec)},
		{"SEC1 EC after EC PARAMETERS", ec, append(params, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})...)},
		{"PKCS#8 RSA", rsaKey, pkcs8(t, rsaKey)},
		{"PKCS#1 RSA", rsaKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
		{"PKCS#8 Ed25519", edKey, pkcs8(t, edKey)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caPEM := testCA(t, c.key, time.Now().Add(24*time.Hour), true)
			a, err := New(caPEM, c.keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := a.Certificate("api.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.Leaf.CheckSignatureFrom(a.CA()); err != nil {
				t.Fatalf("leaf not signed by the CA: %v", err)
			}
		})
	}
}

func TestNewRefuses(t *testing.T) {
	key := ecKey(t)
	caPEM := testCA(t, key, time.Now().Add(24*time.Hour), true)
	keyPEM := pkcs8(t, key)
	cases := []struct {
		name          string
		cert, key     []byte
		wantErrSubstr string
	}{
		{"no PEM", []byte("not PEM"), keyPEM, "no PEM CERTIFICATE block"},
		{"a key as the certificate", keyPEM, keyPEM, "no PEM CERTIFICATE block"},
		{"a broken certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), keyPEM, "CA certificate"},
		{"a certificate that is not a CA", testCA(t, key, time.Now().Add(24*time.Hour), false), keyPEM, "basicConstraints CA is not set"},
		{"no key", caPEM, []byte("not PEM"), "no PEM private key block"},
		{"only other PEM blocks", caPEM, caPEM, "no PEM private key block"},
		{"a broken key", caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "CA key"},
		{"another key", caPEM, pkcs8(t, ecKey(t)), "does not match the CA certificate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.cert, c.key)
			if err == nil || !strings.Contains(err.Error(), c.wantErrSubstr) {
				t.Fatalf("error %v, want one with %q", err, c.wantErrSubstr)
			}
		})
	}
}

func TestLoadFiles(t *testing.T) {
	key := ecKey(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, testCA(t, key, time.Now().Add(24*time.Hour), true), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pkcs8(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if a.CA().Subject.CommonName != "test CA" {
		t.Errorf("CA %q", a.CA().Subject.CommonName)
	}
	missing := filepath.Join(dir, "missing.pem")
	if _, err := LoadFiles(missing, keyPath); !os.IsNotExist(err) {
		t.Errorf("missing certificate: %v", err)
	}
	if _, err := LoadFiles(certPath, missing); !os.IsNotExist(err) {
		t.Errorf("missing key: %v", err)
	}
}
