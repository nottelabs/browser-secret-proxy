package resolve

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The only algorithms a sealed token may use.
var (
	sealedKeyAlgorithms = []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}
	sealedEncryption    = []jose.ContentEncryption{jose.A256GCM}
)

// maxSealedToken caps a token before it is parsed.
const maxSealedToken = 32 << 10

// SealedPayload is what a sealed token carries.
type SealedPayload struct {
	// Values maps each stand-in to its real value.
	Values map[string]string `json:"values"`
	// Hosts the values may be sent to; empty means the proxy's -hosts.
	Hosts []string `json:"hosts,omitempty"`
	// Exp is the expiry, in Unix seconds. Required.
	Exp int64 `json:"exp"`
	// Sub names the principal (logged and passed as its ID).
	Sub string `json:"sub,omitempty"`
}

// Sealed resolves stand-ins from the proxy credential itself: the Basic
// password is a compact JWE (ECDH-ES+A256KW, A256GCM) encrypted to the
// proxy's key, whose payload is a SealedPayload. Decrypting it at CONNECT
// both authenticates the client and yields the values, with no lookup
// service and nothing stored. An expired, tampered or foreign token is
// refused with 407.
type Sealed struct {
	keys []crypto.PrivateKey
	now  func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]*sealedEntry // decrypted tokens, by hash
}

type sealedEntry struct {
	payload  *SealedPayload
	standIns []string
	expires  time.Time
}

// maxSealedCache bounds the decrypted tokens kept in memory.
const maxSealedCache = 1024

// LoadSealed reads the proxy's private key: a PEM file with one or more EC
// keys (P-256, P-384 or P-521; PKCS #8 or SEC 1). With several, a token
// encrypted to any of them is accepted, so keys can be rotated.
func LoadSealed(keyFile string) (*Sealed, error) {
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
	return NewSealed(keys...)
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

// NewSealed builds a Sealed resolver from private keys.
func NewSealed(keys ...crypto.PrivateKey) (*Sealed, error) {
	if len(keys) == 0 {
		return nil, errors.New("no private key")
	}
	return &Sealed{keys: keys, now: time.Now, cache: map[[sha256.Size]byte]*sealedEntry{}}, nil
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

// StandIns returns the stand-ins of the principal's token.
func (s *Sealed) StandIns(p Principal) []string {
	e, err := s.open(p.Password)
	if err != nil {
		return nil
	}
	return e.standIns
}

// Resolve answers from the principal's token. Each value expires with the
// token and may go to the token's hosts only.
func (s *Sealed) Resolve(_ context.Context, req Request) (Result, error) {
	e, err := s.open(req.Principal.Password)
	if err != nil {
		return Result{}, err
	}
	out := Result{Values: make(map[string]Value, len(req.StandIns))}
	for _, standIn := range req.StandIns {
		if real, ok := e.payload.Values[standIn]; ok {
			out.Values[standIn] = Value{Real: real, Hosts: e.payload.Hosts, ExpiresAt: e.expires}
		}
	}
	return out, nil
}

// open decrypts and checks a token, from memory when it was seen before.
// Errors wrap ErrUnauthenticated and never quote the token.
func (s *Sealed) open(token string) (*sealedEntry, error) {
	now := s.now()
	if token == "" || len(token) > maxSealedToken {
		return nil, fmt.Errorf("%w: not a sealed token", ErrUnauthenticated)
	}
	sum := sha256.Sum256([]byte(token))
	s.mu.Lock()
	e, ok := s.cache[sum]
	s.mu.Unlock()
	if !ok {
		var err error
		if e, err = s.decrypt(token); err != nil {
			return nil, err
		}
	}
	if !now.Before(e.expires) {
		return nil, fmt.Errorf("%w: the sealed token expired", ErrUnauthenticated)
	}
	if !ok {
		s.mu.Lock()
		if len(s.cache) >= maxSealedCache {
			for k, old := range s.cache {
				if !now.Before(old.expires) || len(s.cache) >= maxSealedCache {
					delete(s.cache, k)
				}
			}
		}
		s.cache[sum] = e
		s.mu.Unlock()
	}
	return e, nil
}

func (s *Sealed) decrypt(token string) (*sealedEntry, error) {
	obj, err := jose.ParseEncryptedCompact(token, sealedKeyAlgorithms, sealedEncryption)
	if err != nil {
		return nil, fmt.Errorf("%w: not a sealed token (compact JWE, ECDH-ES+A256KW, A256GCM)", ErrUnauthenticated)
	}
	var plaintext []byte
	for _, key := range s.keys {
		if plaintext, err = obj.Decrypt(key); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the sealed token does not decrypt with the proxy's key", ErrUnauthenticated)
	}
	var payload SealedPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("%w: the sealed token's payload is not the expected JSON", ErrUnauthenticated)
	}
	if payload.Exp <= 0 {
		return nil, fmt.Errorf("%w: the sealed token has no exp", ErrUnauthenticated)
	}
	if len(payload.Values) == 0 {
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

// Seal encrypts a payload to a proxy's public key, as the proxy expects. It
// refuses a token longer than the proxy accepts.
func Seal(key crypto.PublicKey, payload SealedPayload) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: key}, nil)
	if err != nil {
		return "", err
	}
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		return "", err
	}
	if len(token) > maxSealedToken {
		return "", fmt.Errorf("the sealed token is %d bytes, more than the %d the proxy accepts: seal fewer or shorter values", len(token), maxSealedToken)
	}
	return token, nil
}
