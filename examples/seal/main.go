// Command seal creates a sealed proxy credential for browser-secret-proxy's
// sealed resolver: a compact JWE (ECDH-ES+A256KW, A256GCM) encrypted to the
// proxy's public key. Use it as the proxy password.
//
//	seal -public-key proxy-public.pem -ttl 1h payload.json
//
// The payload file holds the values, and optionally the hosts and a subject:
//
//	{"values": {"tok_standin_123": "<real API token>"}, "hosts": ["api.example.com"], "sub": "session-42"}
//
// exp is set to now plus -ttl unless the file has one. The token holds real
// values: treat it like them.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

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
	ttl := flags.Duration("ttl", time.Hour, "lifetime of the token, when the payload has no exp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *publicKey == "" || flags.NArg() != 1 {
		return errors.New("usage: seal -public-key proxy-public.pem [-ttl 1h] payload.json")
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
	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return err
	}
	var payload resolve.SealedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("%s: want {\"values\": {...}, \"hosts\": [...], \"sub\": \"...\"}", flags.Arg(0))
	}
	if len(payload.Values) == 0 {
		return fmt.Errorf("%s: no values", flags.Arg(0))
	}
	if payload.Exp == 0 {
		payload.Exp = time.Now().Add(*ttl).Unix()
	}
	token, err := resolve.Seal(key, payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token)
	return err
}
