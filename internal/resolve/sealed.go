package resolve

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The only algorithms a sealed token may use: the outer JWE, and the JWS it
// carries.
var (
	sealedKeyAlgorithms       = []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}
	sealedEncryption          = []jose.ContentEncryption{jose.A256GCM}
	sealedSignatureAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256}
)

// sealedClockSkew is how far the issuer's clock may be ahead of the proxy's
// for nbf and iat. exp gets no leeway.
const sealedClockSkew = 30 * time.Second

// maxSealedToken caps a token before it is parsed.
const maxSealedToken = 32 << 10

// SealedPayload is what a sealed token carries: the claims the issuer
// signs.
type SealedPayload struct {
	// Values maps each stand-in to its real value.
	Values map[string]string `json:"values"`
	// Hosts the values may be sent to; empty means the proxy's -hosts.
	Hosts []string `json:"hosts,omitempty"`
	// Aud names the proxies the token is for; it must contain the proxy's
	// configured audience. Required.
	Aud jwt.Audience `json:"aud"`
	// Exp is the expiry, in Unix seconds. Required.
	Exp int64 `json:"exp"`
	// Nbf and Iat, in Unix seconds, are optional: a token is refused before
	// nbf, or when iat is in the future, beyond sealedClockSkew.
	Nbf int64 `json:"nbf,omitempty"`
	Iat int64 `json:"iat,omitempty"`
	// Sub names the principal (logged and passed as its ID).
	Sub string `json:"sub,omitempty"`
}

// Sealed resolves stand-ins from the proxy credential itself. The Basic
// password is a nested JWT (RFC 7519 section 5.2): the issuer signs a
// SealedPayload as a JWS (EdDSA or ES256), then encrypts that JWS as a
// compact JWE (ECDH-ES+A256KW, A256GCM, cty "JWT") to the proxy's key.
// Opening it at CONNECT both admits the client and yields the values, with
// no lookup service and no external storage. The encryption keeps the values
// from anyone but the proxy; the signature proves a configured issuer made
// the token; the audience keeps a token for one proxy from working on
// another. A token that fails any of these, or has expired, is refused with
// 407.
//
// Decrypted tokens, real values included, are kept in memory so a request
// does not pay an ECDH per lookup: at most maxSealedCache of them, each
// until the earlier of its exp and sealedCacheTTL after it was decrypted.
type Sealed struct {
	keys       []crypto.PrivateKey // decrypt tokens
	issuerKeys []crypto.PublicKey  // verify their signature
	audience   string
	now        func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]*sealedEntry // decrypted tokens, by hash
}

type sealedEntry struct {
	payload  *SealedPayload
	standIns []string
	expires  time.Time // the token's exp
	until    time.Time // when the cache drops it: the earlier of exp and sealedCacheTTL
}

const (
	// maxSealedCache bounds the decrypted tokens kept in memory.
	maxSealedCache = 256
	// sealedCacheTTL bounds how long a decrypted token stays in memory; it is
	// decrypted again after that.
	sealedCacheTTL = 5 * time.Minute
)

// SealedConfig configures a Sealed resolver.
type SealedConfig struct {
	// Keys decrypt tokens: EC private keys (P-256, P-384 or P-521). A token
	// encrypted to any of them is accepted, so keys can be rotated.
	Keys []crypto.PrivateKey
	// IssuerKeys verify the token's signature: Ed25519 (EdDSA) or P-256
	// (ES256) public keys. A token signed by any of them is accepted, so
	// issuer keys can be rotated.
	IssuerKeys []crypto.PublicKey
	// Audience is this proxy's identity: a token's aud must contain it.
	Audience string
}

// LoadSealed reads the proxy's private keys (keyFile: one or more EC keys,
// PKCS #8 or SEC 1) and the issuers' public keys (each file: one or more
// PKIX PUBLIC KEY blocks).
func LoadSealed(keyFile string, issuerKeyFiles []string, audience string) (*Sealed, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	var keys []crypto.PrivateKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		key, err := parseECKey(block)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyFile, err)
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no EC private key", keyFile)
	}
	var issuerKeys []crypto.PublicKey
	for _, file := range issuerKeyFiles {
		found, err := loadIssuerKeys(file)
		if err != nil {
			return nil, err
		}
		issuerKeys = append(issuerKeys, found...)
	}
	return NewSealed(SealedConfig{Keys: keys, IssuerKeys: issuerKeys, Audience: audience})
}

func loadIssuerKeys(file string) ([]crypto.PublicKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var keys []crypto.PublicKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%s: unexpected PEM block %q, want PUBLIC KEY", file, block.Type)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no PUBLIC KEY", file)
	}
	return keys, nil
}

func parseECKey(block *pem.Block) (crypto.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("the sealed mode needs an EC key (ECDH-ES)")
		}
		return ec, nil
	case "EC PARAMETERS":
		return nil, nil // written by openssl ecparam -genkey; not a key
	}
	return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
}

// signingAlgorithm is the JWS algorithm a sealed token uses with key, which
// is an issuer's private or public key.
func signingAlgorithm(key any) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		return jose.EdDSA, nil
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			return jose.ES256, nil
		}
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return jose.ES256, nil
		}
	}
	return "", errors.New("an issuer key must be Ed25519 (EdDSA) or P-256 (ES256)")
}

// NewSealed builds a Sealed resolver.
func NewSealed(cfg SealedConfig) (*Sealed, error) {
	if len(cfg.Keys) == 0 {
		return nil, errors.New("no private key to decrypt sealed tokens")
	}
	if len(cfg.IssuerKeys) == 0 {
		return nil, errors.New("no issuer key to verify sealed tokens")
	}
	for _, key := range cfg.IssuerKeys {
		if _, err := signingAlgorithm(key); err != nil {
			return nil, err
		}
	}
	if cfg.Audience == "" {
		return nil, errors.New("no audience: a sealed token's aud must name this proxy")
	}
	return &Sealed{
		keys: cfg.Keys, issuerKeys: cfg.IssuerKeys, audience: cfg.Audience,
		now: time.Now, cache: map[[sha256.Size]byte]*sealedEntry{},
	}, nil
}

// Authenticate decrypts the token in password. The principal's ID is the
// token's sub, or the username when sub is empty.
func (s *Sealed) Authenticate(username, password string) (Principal, error) {
	e, err := s.open(password)
	if err != nil {
		return Principal{}, err
	}
	id := e.payload.Sub
	if id == "" {
		id = username
	}
	return Principal{ID: id, Password: password}, nil
}

// StandIns returns the stand-ins of the principal's token, nil when the
// token is no longer valid. Callers that must tell those apart use view.
func (s *Sealed) StandIns(p Principal) []string {
	v, err := s.view(p)
	if err != nil {
		return nil
	}
	return v.StandIns(p)
}

// Resolve answers from the principal's token. Each value expires with the
// token and may go to the token's hosts only.
func (s *Sealed) Resolve(ctx context.Context, req Request) (Result, error) {
	v, err := s.view(req.Principal)
	if err != nil {
		return Result{}, err
	}
	return v.Resolve(ctx, req)
}

// sealedView is one opened token: its stand-ins and its values, read
// together. A request is detected and resolved from the same view, so a
// token that expires in between cannot leave its stand-ins undetected.
type sealedView struct{ entry *sealedEntry }

// StandIns returns the token's stand-ins. The view belongs to one
// principal, so the argument is not needed.
func (v *sealedView) StandIns(Principal) []string { return v.entry.standIns }

// Resolve answers the requested stand-ins the token holds.
func (v *sealedView) Resolve(_ context.Context, req Request) (Result, error) {
	payload := v.entry.payload
	out := Result{Values: make(map[string]Value, len(req.StandIns))}
	for _, standIn := range req.StandIns {
		if real, ok := payload.Values[standIn]; ok {
			out.Values[standIn] = Value{Real: real, Hosts: payload.Hosts, ExpiresAt: v.entry.expires}
		}
	}
	return out, nil
}

// view opens the principal's token once. The error wraps ErrUnauthenticated
// when the token is no longer valid (expired, or never was): the request
// must then be refused, even when it holds no stand-in, since its stand-ins
// can no longer be found.
func (s *Sealed) view(p Principal) (*sealedView, error) {
	e, err := s.open(p.Password)
	if err != nil {
		return nil, err
	}
	return &sealedView{entry: e}, nil
}

// open decrypts and checks a token, from memory when it was decrypted
// recently. Errors wrap ErrUnauthenticated and never quote the token.
func (s *Sealed) open(token string) (*sealedEntry, error) {
	now := s.now()
	if token == "" || len(token) > maxSealedToken {
		return nil, fmt.Errorf("%w: not a sealed token", ErrUnauthenticated)
	}
	sum := sha256.Sum256([]byte(token))
	s.mu.Lock()
	e, ok := s.cache[sum]
	if ok && !now.Before(e.until) {
		delete(s.cache, sum)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		var err error
		if e, err = s.decrypt(token, now); err != nil {
			return nil, err
		}
		e.until = e.expires
		if limit := now.Add(sealedCacheTTL); limit.Before(e.until) {
			e.until = limit
		}
	}
	if !now.Before(e.expires) {
		return nil, fmt.Errorf("%w: the sealed token expired", ErrUnauthenticated)
	}
	if !ok {
		s.store(sum, e, now)
	}
	return e, nil
}

// store caches a decrypted token, first dropping every entry past its time,
// then arbitrary ones while the cache is full.
func (s *Sealed) store(sum [sha256.Size]byte, e *sealedEntry, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, old := range s.cache {
		if !now.Before(old.until) {
			delete(s.cache, k)
		}
	}
	for k := range s.cache {
		if len(s.cache) < maxSealedCache {
			break
		}
		delete(s.cache, k)
	}
	s.cache[sum] = e
}

// decrypt opens a token: decrypts it, verifies its signature, then checks
// its claims at now.
func (s *Sealed) decrypt(token string, now time.Time) (*sealedEntry, error) {
	// go-jose's jwt package refuses asymmetric key encryption for JWTs, so
	// the nesting (RFC 7519 section 5.2) is done with its JWE and JWS
	// primitives: decrypt, require cty JWT, then verify the JWS inside.
	encrypted, err := jose.ParseEncryptedCompact(token, sealedKeyAlgorithms, sealedEncryption)
	if err != nil {
		return nil, fmt.Errorf("%w: not a sealed token (a compact JWE with ECDH-ES+A256KW and A256GCM)", ErrUnauthenticated)
	}
	if cty, _ := encrypted.Header.ExtraHeaders[jose.HeaderContentType].(string); !strings.EqualFold(cty, "JWT") {
		return nil, fmt.Errorf("%w: the sealed token is not a nested JWT (cty JWT): it must be signed, then encrypted", ErrUnauthenticated)
	}
	var inner []byte
	for _, key := range s.keys {
		if inner, err = encrypted.Decrypt(key); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the sealed token does not decrypt with the proxy's key", ErrUnauthenticated)
	}
	signed, err := jose.ParseSignedCompact(string(inner), sealedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: the sealed token does not hold a JWS signed with EdDSA or ES256", ErrUnauthenticated)
	}
	var claims []byte
	for _, key := range s.issuerKeys {
		if claims, err = signed.Verify(key); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the sealed token is not signed by a configured issuer key", ErrUnauthenticated)
	}
	var payload SealedPayload
	if err := json.Unmarshal(claims, &payload); err != nil {
		return nil, fmt.Errorf("%w: the sealed token's claims are not the expected JSON", ErrUnauthenticated)
	}
	switch {
	case payload.Exp <= 0:
		return nil, fmt.Errorf("%w: the sealed token has no exp", ErrUnauthenticated)
	case len(payload.Aud) == 0:
		return nil, fmt.Errorf("%w: the sealed token has no aud", ErrUnauthenticated)
	case !payload.Aud.Contains(s.audience):
		return nil, fmt.Errorf("%w: the sealed token is for another audience", ErrUnauthenticated)
	case payload.Nbf > 0 && now.Add(sealedClockSkew).Before(time.Unix(payload.Nbf, 0)):
		return nil, fmt.Errorf("%w: the sealed token is not valid yet (nbf)", ErrUnauthenticated)
	case payload.Iat > 0 && now.Add(sealedClockSkew).Before(time.Unix(payload.Iat, 0)):
		return nil, fmt.Errorf("%w: the sealed token was issued in the future (iat)", ErrUnauthenticated)
	case len(payload.Values) == 0:
		return nil, fmt.Errorf("%w: the sealed token holds no values", ErrUnauthenticated)
	}
	e := &sealedEntry{payload: &payload, expires: time.Unix(payload.Exp, 0)}
	for standIn := range payload.Values {
		if standIn == "" {
			return nil, fmt.Errorf("%w: the sealed token has an empty stand-in", ErrUnauthenticated)
		}
		e.standIns = append(e.standIns, standIn)
	}
	sort.Strings(e.standIns)
	return e, nil
}

// Seal makes a sealed token: it signs payload with the issuer's private key
// (Ed25519 for EdDSA, or P-256 for ES256), then encrypts the signed JWT to
// the proxy's public key. It refuses a token longer than the proxy accepts.
func Seal(proxyKey crypto.PublicKey, issuerKey crypto.Signer, payload SealedPayload) (string, error) {
	alg, err := signingAlgorithm(issuerKey)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: issuerKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}
	jws, err := signed.CompactSerialize()
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: proxyKey},
		(&jose.EncrypterOptions{}).WithContentType("JWT"))
	if err != nil {
		return "", err
	}
	encrypted, err := encrypter.Encrypt([]byte(jws))
	if err != nil {
		return "", err
	}
	token, err := encrypted.CompactSerialize()
	if err != nil {
		return "", err
	}
	if len(token) > maxSealedToken {
		return "", fmt.Errorf("the sealed token is %d bytes, more than the %d the proxy accepts: seal fewer or shorter values", len(token), maxSealedToken)
	}
	return token, nil
}

// Snapshot opens the principal's token once, so a request is detected and
// resolved from the same token. Once the token has expired it fails with
// ErrUnauthenticated, and the request is refused.
func (s *Sealed) Snapshot(p Principal) (Snapshot, error) {
	v, err := s.view(p)
	if err != nil {
		return nil, err
	}
	return v, nil
}
