// Command totp-resolver is a detokenize service for browser-secret-proxy's
// http resolver that answers with time-based one-time passwords (TOTP,
// RFC 6238). It holds the TOTP seeds; the proxy, the browser and the agent
// only ever see a stand-in, and the proxy receives the current code, never
// the seed.
//
// It accepts only clients with a certificate from -client-ca (mutual TLS),
// as the proxy's -resolver-cert expects, and optionally only a certificate
// whose subject common name or DNS name is -client-name.
//
// The seeds file maps each stand-in to a seed and where its codes may go:
//
//	{
//	  "totp_acme_admin": {
//	    "secret": "JBSWY3DPEHPK3PXP",
//	    "hosts": ["login.acme.example"],
//	    "principals": ["proxy-user"]
//	  }
//	}
//
// The fields of an entry:
//
//   - secret: the base32 seed, as shown under the QR code when 2FA is set
//     up (spaces and lower case are accepted, padding is optional).
//   - hosts: required. The hosts the codes may be sent to, in the proxy's
//     -hosts syntax. A request for another host gets no code, and the
//     answer carries the list so the proxy checks it too.
//   - principals: optional. The proxy usernames (principal_id) that may
//     receive codes. Empty means any.
//   - digits (6 to 8, default 6), period (seconds, default 30) and
//     algorithm (SHA1, SHA256 or SHA512, default SHA1): only when the site
//     uses other parameters than the defaults.
//
// Each code is answered with expires_at set to the end of its time step, so
// the proxy never caches it past that step and refuses it once the step is
// over.
//
// Codes and seeds are never logged. Keep the seeds file readable by this
// service only (chmod 600): whoever reads it can generate every code.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 defines HMAC-SHA1 TOTP; most sites use it.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// seed is one TOTP generator and where its codes may go.
type seed struct {
	key        []byte
	digits     int
	period     int64
	newHash    func() hash.Hash
	hosts      []string
	principals map[string]bool
}

type seedEntry struct {
	Secret     string   `json:"secret"`
	Hosts      []string `json:"hosts"`
	Principals []string `json:"principals"`
	Digits     int      `json:"digits"`
	Period     int64    `json:"period"`
	Algorithm  string   `json:"algorithm"`
}

// loadSeeds parses the seeds file. Errors name the stand-in, never the
// seed.
func loadSeeds(data []byte) (map[string]*seed, error) {
	var entries map[string]seedEntry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, errors.New("want a JSON object of stand-in to {secret, hosts, principals, digits, period, algorithm}")
	}
	if len(entries) == 0 {
		return nil, errors.New("no stand-ins")
	}
	seeds := make(map[string]*seed, len(entries))
	for standIn, e := range entries {
		if standIn == "" {
			return nil, errors.New("an empty stand-in")
		}
		s, err := newSeed(e)
		if err != nil {
			return nil, fmt.Errorf("stand-in %q: %w", standIn, err)
		}
		seeds[standIn] = s
	}
	return seeds, nil
}

func newSeed(e seedEntry) (*seed, error) {
	secret := strings.ToUpper(strings.Join(strings.Fields(e.Secret), ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	if err != nil || len(key) == 0 {
		return nil, errors.New("secret is not a base32 seed")
	}
	if len(e.Hosts) == 0 {
		return nil, errors.New("hosts is required: the hosts its codes may be sent to")
	}
	for _, h := range e.Hosts {
		if strings.TrimPrefix(h, "*.") == "" || strings.ContainsAny(h, "/:?#@ ") {
			return nil, fmt.Errorf("host %q: give a host name or *.domain", h)
		}
	}
	s := &seed{key: key, digits: e.Digits, period: e.Period, hosts: e.Hosts, principals: map[string]bool{}}
	if s.digits == 0 {
		s.digits = 6
	}
	if s.digits < 6 || s.digits > 8 {
		return nil, errors.New("digits must be 6, 7 or 8")
	}
	if s.period == 0 {
		s.period = 30
	}
	if s.period < 1 {
		return nil, errors.New("period must be a positive number of seconds")
	}
	switch strings.ToUpper(e.Algorithm) {
	case "", "SHA1":
		s.newHash = sha1.New
	case "SHA256":
		s.newHash = sha256.New
	case "SHA512":
		s.newHash = sha512.New
	default:
		return nil, errors.New("algorithm must be SHA1, SHA256 or SHA512")
	}
	for _, p := range e.Principals {
		s.principals[p] = true
	}
	return s, nil
}

// code returns the TOTP code at t (RFC 6238 section 4, with the dynamic
// truncation of RFC 4226 section 5.3) and the end of its time step.
func (s *seed) code(t time.Time) (string, time.Time) {
	step := t.Unix() / s.period
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step)) //nolint:gosec // Unix time after 1970 is positive.
	mac := hmac.New(s.newHash, s.key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range s.digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", s.digits, binaryCode%modulus), time.Unix((step+1)*s.period, 0).UTC()
}

// allows reports whether a code may go to host for principal.
func (s *seed) allows(host, principal string) bool {
	if len(s.principals) > 0 && !s.principals[principal] {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range s.hosts {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

type detokenizeRequest struct {
	StandIns    []string `json:"stand_ins"`
	Host        string   `json:"host"`
	PrincipalID string   `json:"principal_id"`
}

type answer struct {
	Real      string    `json:"real"`
	Hosts     []string  `json:"hosts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handler answers the proxy's detokenize calls with the current code of
// each stand-in it may release. now is the clock (time.Now outside tests).
func handler(seeds map[string]*seed, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/detokenize", func(w http.ResponseWriter, r *http.Request) {
		var req detokenizeRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "want {stand_ins, host, principal_id}", http.StatusBadRequest)
			return
		}
		t := now()
		values := map[string]answer{}
		for _, standIn := range req.StandIns {
			s, ok := seeds[standIn]
			// Leaving a stand-in out makes the proxy refuse the request.
			if !ok || !s.allows(req.Host, req.PrincipalID) {
				continue
			}
			code, end := s.code(t)
			values[standIn] = answer{Real: code, Hosts: s.hosts, ExpiresAt: end}
		}
		// Counts only: never the codes.
		log.Printf("principal %q, host %q: %d of %d stand-ins answered", req.PrincipalID, req.Host, len(values), len(req.StandIns))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"values": values})
	})
	return mux
}

// requireName returns a VerifyConnection check that the client
// certificate names name, as its subject common name or a DNS name.
func requireName(name string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no client certificate")
		}
		leaf := cs.PeerCertificates[0]
		if leaf.Subject.CommonName == name {
			return nil
		}
		for _, dns := range leaf.DNSNames {
			if dns == name {
				return nil
			}
		}
		return errors.New("the client certificate does not name the expected client")
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "address to listen on")
	cert := flag.String("cert", "", "PEM server certificate (required)")
	key := flag.String("key", "", "PEM server key (required)")
	clientCA := flag.String("client-ca", "", "PEM CA that issues the proxy's client certificate (required)")
	clientName := flag.String("client-name", "", "accept only a client certificate with this common name or DNS name")
	seedsFile := flag.String("seeds", "", "JSON file of stand-in to TOTP seed (required)")
	flag.Parse()
	if *cert == "" || *key == "" || *clientCA == "" || *seedsFile == "" {
		flag.Usage()
		os.Exit(2)
	}

	info, err := os.Stat(*seedsFile)
	if err != nil {
		log.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: %s is readable by other users (mode %v): chmod 600 it", *seedsFile, info.Mode().Perm())
	}
	data, err := os.ReadFile(*seedsFile)
	if err != nil {
		log.Fatal(err)
	}
	seeds, err := loadSeeds(data)
	if err != nil {
		log.Fatalf("%s: %v", *seedsFile, err)
	}
	caPEM, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		log.Fatalf("%s: no PEM certificate", *clientCA)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
	}
	if *clientName != "" {
		tlsConfig.VerifyConnection = requireName(*clientName)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler(seeds, time.Now),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("listening on %s with %d stand-ins", ln.Addr(), len(seeds))
	log.Fatal(server.ServeTLS(ln, *cert, *key))
}
