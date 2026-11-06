// Package certs loads the CA and issues leaf certificates for intercepted
// hosts.
package certs

import (
	"context"
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
	"log/slog"
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

	// ExpiryWarning is how long before the CA expires WatchExpiry starts
	// warning: from then on leaf certificates are cut short to end with it.
	ExpiryWarning = leafLifetime
	// expiryCheckEvery is the longest WatchExpiry waits between two checks,
	// so a CA in its warning window or expired is logged once a day.
	expiryCheckEvery = 24 * time.Hour
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

// New builds an Authority from a PEM CA certificate and PEM private key. It
// refuses a CA that is not valid now: expired, or not valid yet. Every leaf
// it signed would be refused by clients, so every intercepted connection
// would fail.
func New(certPEM, keyPEM []byte) (*Authority, error) {
	return newAt(certPEM, keyPEM, time.Now())
}

func newAt(certPEM, keyPEM []byte, now time.Time) (*Authority, error) {
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
	if now.After(ca.NotAfter) {
		return nil, fmt.Errorf("CA certificate expired at %s: create a new CA (see Rotate the CA in docs/deployment.md)", ca.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(ca.NotBefore) {
		return nil, fmt.Errorf("CA certificate is not valid before %s: check the clock of this host or the CA's validity", ca.NotBefore.UTC().Format(time.RFC3339))
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

// WatchExpiry logs when the CA is close to its expiry, as soon as it is
// called and then until ctx ends: a warning once a day from ExpiryWarning
// before the CA expires, and an error once a day after it has expired. It
// checks again when the CA enters the warning window and when it expires,
// so neither is logged late.
func (a *Authority) WatchExpiry(ctx context.Context, logger *slog.Logger) {
	for {
		now := a.now()
		a.logExpiry(logger, now)
		timer := time.NewTimer(a.nextExpiryCheck(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// logExpiry logs the CA's expiry when it is ExpiryWarning away or less, or
// past.
func (a *Authority) logExpiry(logger *slog.Logger, now time.Time) {
	notAfter := a.ca.NotAfter.UTC().Format(time.RFC3339)
	switch remaining := a.ca.NotAfter.Sub(now); {
	case now.After(a.ca.NotAfter):
		logger.Error("the CA certificate has expired: clients refuse every intercepted connection until the proxy restarts with a new CA", "not_after", notAfter)
	case remaining <= ExpiryWarning:
		logger.Warn("the CA certificate expires soon: rotate it before then", "not_after", notAfter, "expires_in", remaining.Round(time.Minute).String())
	}
}

// nextExpiryCheck is how long after now WatchExpiry checks again: a day,
// or less when the CA enters its warning window or expires before that.
func (a *Authority) nextExpiryCheck(now time.Time) time.Duration {
	next := expiryCheckEvery
	for _, at := range []time.Time{a.ca.NotAfter.Add(-ExpiryWarning), a.ca.NotAfter.Add(time.Second)} {
		if d := at.Sub(now); d > 0 && d < next {
			next = d
		}
	}
	return max(next, time.Second)
}
