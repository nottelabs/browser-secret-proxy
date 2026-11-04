package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// keyPair is a certificate and its key, parsed and as PEM.
type keyPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// newCA creates a throwaway P-256 CA valid for one day.
func newCA(name string) (*keyPair, error) {
	tmpl, err := template(name)
	if err != nil {
		return nil, err
	}
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return create(tmpl, nil)
}

// issue creates a leaf certificate signed by ca.
func (ca *keyPair) issue(name string, ips []net.IP, usage x509.ExtKeyUsage) (*keyPair, error) {
	tmpl, err := template(name)
	if err != nil {
		return nil, err
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	tmpl.IPAddresses = ips
	return create(tmpl, ca)
}

func template(name string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}, nil
}

// create signs tmpl with parent, or self-signs it when parent is nil.
func create(tmpl *x509.Certificate, parent *keyPair) (*keyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &keyPair{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	}, nil
}

// write saves the pair as certPath and keyPath. The proxy image runs as
// UID 65532, so both must be readable by others; they are throwaway and
// their directory is private to this user.
func (kp *keyPair) write(certPath, keyPath string) error {
	if err := writeReadable(certPath, kp.certPEM); err != nil {
		return err
	}
	return writeReadable(keyPath, kp.keyPEM)
}

func writeReadable(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// The container user is not this user: see write.
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // throwaway test file, in a private directory
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
