package resolve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// HTTPConfig configures an HTTP resolver.
type HTTPConfig struct {
	// URL of the detokenize endpoint. It must be https://.
	URL string
	// ClientCert and ClientKey are the PEM files of the client certificate
	// the proxy presents. Both are required: the endpoint must authenticate
	// the proxy.
	ClientCert, ClientKey string
	// CA is a PEM bundle that verifies the endpoint's certificate. Empty
	// uses the system roots.
	CA string
	// Timeout bounds one call, connection included (default 2 s).
	Timeout time.Duration
	// CacheTTL is the longest a value is kept in memory (default 60 s).
	// A value's own expires_at shortens it. Negative disables the cache.
	CacheTTL time.Duration
	// CacheSize caps the cached values (default 10000).
	CacheSize int
	// MaxBatch caps the stand-ins one request may look up (default 256). A
	// request with more is refused rather than sent.
	MaxBatch int

	// rootCAs and now are set by tests.
	rootCAs *x509.CertPool
	now     func() time.Time
}

// HTTP resolves stand-ins by calling a detokenize service over mutual TLS:
//
//	POST <URL>
//	{"stand_ins": ["tok_1", ...], "host": "api.example.com", "principal_id": "proxy-user"}
//
//	200 OK
//	{"values": {"tok_1": {"real": "...", "hosts": ["api.example.com"], "expires_at": "2026-01-02T15:04:05Z"}}}
//
// One call covers every stand-in of a request that is not cached. Any other
// status, a malformed answer or a timeout is an error, and a stand-in left
// out of values is unresolved: either way the request is refused. Answers
// are cached in memory per principal and stand-in.
type HTTP struct {
	cfg    HTTPConfig
	client *http.Client

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
}

type cacheKey struct{ principal, standIn string }

type cacheEntry struct {
	value Value
	until time.Time
}

// maxResponse caps the service's answer.
const maxResponse = 4 << 20

// NewHTTP checks the configuration and loads the certificates.
func NewHTTP(cfg HTTPConfig) (*HTTP, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("resolver URL: want an https:// URL")
	}
	if u.User != nil {
		return nil, errors.New("resolver URL: credentials in the URL are not supported, the proxy authenticates with its client certificate")
	}
	if cfg.ClientCert == "" || cfg.ClientKey == "" {
		return nil, errors.New("the http resolver needs a client certificate and key (mutual TLS)")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("resolver client certificate: %w", err)
	}
	roots := cfg.rootCAs
	if cfg.CA != "" {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("resolver CA: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("resolver CA %s: no PEM certificate", cfg.CA)
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 60 * time.Second
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 10000
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 256
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	transport := &http.Transport{
		Proxy:       nil, // the service is reached directly, never through HTTPS_PROXY
		DialContext: (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		},
		TLSHandshakeTimeout: cfg.Timeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	return &HTTP{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// A redirect could send the stand-ins elsewhere: answer it as an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cache: map[cacheKey]cacheEntry{},
	}, nil
}

type detokenizeRequest struct {
	StandIns    []string `json:"stand_ins"`
	Host        string   `json:"host"`
	PrincipalID string   `json:"principal_id"`
}

type detokenizeResponse struct {
	Values map[string]struct {
		Real      *string   `json:"real"`
		Hosts     []string  `json:"hosts"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"values"`
}

// Resolve answers cached stand-ins from memory and asks the service for the
// rest in one call.
func (h *HTTP) Resolve(ctx context.Context, req Request) (Result, error) {
	out := Result{Values: make(map[string]Value, len(req.StandIns))}
	if len(req.StandIns) > h.cfg.MaxBatch {
		return out, fmt.Errorf("%d stand-ins in one request, more than the resolver batch limit of %d", len(req.StandIns), h.cfg.MaxBatch)
	}
	now := h.cfg.now()
	var missing []string
	h.mu.Lock()
	for _, s := range req.StandIns {
		key := cacheKey{req.Principal.ID, s}
		if e, ok := h.cache[key]; ok {
			if now.Before(e.until) {
				out.Values[s] = e.value
				continue
			}
			delete(h.cache, key)
		}
		missing = append(missing, s)
	}
	h.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}

	answer, err := h.call(ctx, detokenizeRequest{StandIns: missing, Host: hostOnly(req.Host), PrincipalID: req.Principal.ID})
	if err != nil {
		return out, err
	}
	now = h.cfg.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range missing {
		v, ok := answer.Values[s]
		if !ok || v.Real == nil {
			continue // unresolved: the caller refuses the request
		}
		value := Value{Real: *v.Real, Hosts: v.Hosts, ExpiresAt: v.ExpiresAt}
		out.Values[s] = value
		h.store(cacheKey{req.Principal.ID, s}, value, now)
	}
	return out, nil
}

// store caches a value until the earlier of the cache TTL and its expiry.
// h.mu is held.
func (h *HTTP) store(key cacheKey, v Value, now time.Time) {
	if h.cfg.CacheTTL < 0 {
		return
	}
	until := now.Add(h.cfg.CacheTTL)
	if !v.ExpiresAt.IsZero() && v.ExpiresAt.Before(until) {
		until = v.ExpiresAt
	}
	if !now.Before(until) {
		return
	}
	if _, ok := h.cache[key]; !ok && len(h.cache) >= h.cfg.CacheSize {
		for k, e := range h.cache {
			if !now.Before(e.until) {
				delete(h.cache, k)
			}
		}
		for k := range h.cache {
			if len(h.cache) < h.cfg.CacheSize {
				break
			}
			delete(h.cache, k) // map order: an arbitrary entry
		}
	}
	h.cache[key] = cacheEntry{value: v, until: until}
}

// call makes one detokenize request. Errors name the status or the failure,
// never the answer's body, which may hold real values.
func (h *HTTP) call(ctx context.Context, body detokenizeRequest) (*detokenizeResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("resolver call failed: %w", redactURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return nil, fmt.Errorf("resolver answered %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("reading the resolver answer: %w", err)
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("the resolver answer is larger than %d bytes", maxResponse)
	}
	var answer detokenizeResponse
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, errors.New("the resolver answer is not the expected JSON")
	}
	return &answer, nil
}

// redactURLError keeps the cause of a failed call without the URL, whose
// query could carry a credential.
func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}
