// Package certs loads the CA and issues leaf certificates for intercepted
// hosts.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	leafLifetime = 7 * 24 * time.Hour
	renewBefore  = time.Hour
)

// Authority signs leaf certificates with a CA certificate and key.
type Authority struct {
	ca      *x509.Certificate
	caDER   []byte
	caKey   crypto.Signer
	leafKey *ecdsa.PrivateKey
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadFiles reads a PEM CA certificate and its PEM private key.
func LoadFiles(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return New(certPEM, keyPEM)
}

// New builds an Authority from a PEM CA certificate and PEM private key.
func New(certPEM, keyPEM []byte) (*Authority, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate: no PEM CERTIFICATE block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("CA certificate: basicConstraints CA is not set")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	if !publicKeysEqual(key.Public(), ca.PublicKey) {
		return nil, errors.New("CA key does not match the CA certificate")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{ca: ca, caDER: block.Bytes, caKey: key, leafKey: leafKey, now: time.Now, cache: map[string]*tls.Certificate{}}, nil
}

func parseKey(keyPEM []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, keyPEM = pem.Decode(keyPEM)
		if block == nil {
			return nil, errors.New("no PEM private key block")
		}
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key type")
		}
		return signer, nil
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// Certificate returns a leaf certificate for host, issued on first use and
// renewed shortly before it expires.
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("no host name to issue a certificate for")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cert, ok := a.cache[host]; ok && a.now().Add(renewBefore).Before(cert.Leaf.NotAfter) {
		return cert, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := a.now()
	notAfter := now.Add(leafLifetime)
	if notAfter.After(a.ca.NotAfter) {
		notAfter = a.ca.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca, &a.leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("issue certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.caDER}, PrivateKey: a.leafKey, Leaf: leaf}
	a.cache[host] = cert
	return cert, nil
}

// CA returns the CA certificate.
func (a *Authority) CA() *x509.Certificate { return a.ca }
