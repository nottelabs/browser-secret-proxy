// Command seal creates a sealed proxy credential for browser-secret-proxy's
// sealed resolver: a nested JWT that is signed with the issuer's private key
// (EdDSA for Ed25519, ES256 for P-256), then encrypted (ECDH-ES+A256KW,
// A256GCM, cty JWT) to the proxy's public key. Use it as the proxy password.
//
//	seal -public-key proxy-public.pem -issuer-key issuer.key -audience proxy-eu-1 -ttl 1h payload.json
//
// The payload file holds the values, and optionally the hosts and a subject:
//
//	{"values": {"tok_standin_123": "<real API token>"}, "hosts": ["api.example.com"], "sub": "session-42"}
//
// aud is set to -audience, iat to now, and exp to now plus -ttl unless the
// file has one. The token holds real values: treat it like them.
package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "seal:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("seal", flag.ContinueOnError)
	publicKey := flags.String("public-key", "", "PEM public key of the proxy (required)")
	issuerKey := flags.String("issuer-key", "", "PEM private key of the issuer, Ed25519 or P-256 (required)")
	audience := flags.String("audience", "", "the proxy's -sealed-audience (required)")
	ttl := flags.Duration("ttl", time.Hour, "lifetime of the token, when the payload has no exp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *publicKey == "" || *issuerKey == "" || *audience == "" || flags.NArg() != 1 {
		return errors.New("usage: seal -public-key proxy-public.pem -issuer-key issuer.key -audience proxy-id [-ttl 1h] payload.json")
	}
	keyPEM, err := os.ReadFile(*publicKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("%s: want a PEM PUBLIC KEY", *publicKey)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("%s: %w", *publicKey, err)
	}
	signer, err := loadSigner(*issuerKey)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return err
	}
	var payload resolve.SealedPayload
	// A misspelled field would be dropped silently: "host" for "hosts" would
	// seal values with no host restriction of their own.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("%s: want {\"values\": {...}, \"hosts\": [...], \"sub\": \"...\"}", flags.Arg(0))
	}
	if len(payload.Values) == 0 {
		return fmt.Errorf("%s: no values", flags.Arg(0))
	}
	for standIn := range payload.Values {
		if standIn == "" {
			return fmt.Errorf("%s: an empty stand-in", flags.Arg(0))
		}
	}
	now := time.Now()
	if payload.Exp == 0 {
		payload.Exp = now.Add(*ttl).Unix()
	}
	// The proxy refuses such tokens; say so now rather than at first use.
	if !now.Before(time.Unix(payload.Exp, 0)) {
		return errors.New("the token would already be expired: give a positive -ttl or a future exp")
	}
	payload.Aud = jwt.Audience{*audience}
	payload.Iat = now.Unix()
	token, err := resolve.Seal(key, signer, payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token)
	return err
}

// loadSigner reads the issuer's PKCS #8 private key (openssl genpkey).
func loadSigner(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: want a PEM PRIVATE KEY (PKCS #8)", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", path)
	}
	return signer, nil
}
