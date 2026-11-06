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
	"sync"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/strictjson"
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
	// CacheTTL is the longest a value is kept in memory, per principal,
	// host and stand-in (default 60 s).
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
// The host is the CONNECT destination as the allowlist matches it: in lower
// case, without a port or a trailing dot. "hosts" restricts the value to
// those hosts; without it, or with null, the value may go to any host in
// the proxy's allowlist, and an empty list refuses the request.
//
// The answer is read strictly: one that names a member twice, at any depth,
// or spells a member above in another case is malformed. Other members are
// ignored.
//
// One call covers every stand-in of a request that is not cached. Any other
// status, a malformed answer or a timeout is an error, and a stand-in left
// out of values is unresolved: either way the request is refused. Answers
// are cached in memory per principal, host and stand-in: the service decides
// for each host, so an answer for one host is never reused for another. A
// timer sweep drops each cached value, real value included, within
// httpSweepEvery of its time, whether or not more requests come; Close
// stops it.
type HTTP struct {
	cfg    HTTPConfig
	client *http.Client

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
	// The expiry sweep: a timer armed for the earliest time an entry must
	// leave the cache, no sooner than sweepEvery after the previous sweep,
	// and stopped by Close.
	sweepEvery time.Duration
	timer      *time.Timer
	next       time.Time // when the timer fires; zero when it is not armed
	lastSweep  time.Time
	closed     bool
}

type cacheKey struct{ principal, host, standIn string }

type cacheEntry struct {
	value Value
	until time.Time
}

const (
	// maxResponse caps the service's answer.
	maxResponse = 4 << 20
	// httpSweepEvery is the shortest time between two sweeps of the cache:
	// a value leaves memory at most this long after its time.
	httpSweepEvery = 5 * time.Second
)

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
		cache:      map[cacheKey]cacheEntry{},
		sweepEvery: httpSweepEvery,
	}, nil
}

// Close stops the cache's expiry sweep and drops every cached value.
// Lookups still work afterwards, but nothing is cached.
func (h *HTTP) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.timer != nil {
		h.timer.Stop()
	}
	h.next = time.Time{}
	h.cache = map[cacheKey]cacheEntry{}
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

// detokenizeAnswer names the members of detokenizeResponse, as their json
// tags spell them, at every level.
var detokenizeAnswer = strictjson.Object{
	"values": strictjson.Map{Elem: strictjson.Object{"real": nil, "hosts": nil, "expires_at": nil}},
}

// Resolve answers cached stand-ins from memory and asks the service for the
// rest in one call.
func (h *HTTP) Resolve(ctx context.Context, req Request) (Result, error) {
	out := Result{Values: make(map[string]Value, len(req.StandIns))}
	if len(req.StandIns) > h.cfg.MaxBatch {
		return out, fmt.Errorf("%d stand-ins in one request, more than the resolver batch limit of %d", len(req.StandIns), h.cfg.MaxBatch)
	}
	// The host as the allowlist matches it, so the service decides, and the
	// cache keys, on one spelling of it.
	host := hostmatch.Host(req.Host)
	if host == "" {
		return out, errors.New("the request's host is not a plain host name or address")
	}
	now := h.cfg.now()
	var missing []string
	h.mu.Lock()
	for _, s := range req.StandIns {
		key := cacheKey{req.Principal.ID, host, s}
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

	answer, err := h.call(ctx, detokenizeRequest{StandIns: missing, Host: host, PrincipalID: req.Principal.ID})
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
		h.store(cacheKey{req.Principal.ID, host, s}, value, now)
	}
	return out, nil
}

// store caches a value until the earlier of the cache TTL and its expiry,
// and makes sure the sweep drops it then. A closed resolver caches nothing.
// h.mu is held.
func (h *HTTP) store(key cacheKey, v Value, now time.Time) {
	if h.cfg.CacheTTL < 0 || h.closed {
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
		h.pruneLocked(now)
		for k := range h.cache {
			if len(h.cache) < h.cfg.CacheSize {
				break
			}
			delete(h.cache, k) // map order: an arbitrary entry
		}
	}
	h.cache[key] = cacheEntry{value: v, until: until}
	h.armLocked(until)
}

// pruneLocked drops every entry past its time.
func (h *HTTP) pruneLocked(now time.Time) {
	for k, e := range h.cache {
		if !now.Before(e.until) {
			delete(h.cache, k)
		}
	}
}

// armLocked makes sure the sweep runs by until, or sweepEvery after the
// previous sweep if that is later.
func (h *HTTP) armLocked(until time.Time) {
	if h.closed {
		return
	}
	at := until
	if earliest := h.lastSweep.Add(h.sweepEvery); at.Before(earliest) {
		at = earliest
	}
	if !h.next.IsZero() && !at.Before(h.next) {
		return // already armed for that time or sooner
	}
	h.next = at
	d := max(at.Sub(h.cfg.now()), 0)
	if h.timer == nil {
		h.timer = time.AfterFunc(d, h.sweep)
	} else {
		h.timer.Reset(d)
	}
}

// sweep drops the entries past their time, then arms the next sweep for the
// earliest time left.
func (h *HTTP) sweep() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	now := h.cfg.now()
	h.next, h.lastSweep = time.Time{}, now
	h.pruneLocked(now)
	var earliest time.Time
	for _, e := range h.cache {
		if earliest.IsZero() || e.until.Before(earliest) {
			earliest = e.until
		}
	}
	if !earliest.IsZero() {
		h.armLocked(earliest)
	}
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
	// encoding/json alone would read "HOSTS" as hosts and keep the last of
	// two members, so the answer could carry another scope than the service
	// meant.
	if err := strictjson.Check(data, detokenizeAnswer); err != nil {
		return nil, fmt.Errorf("the resolver answer is ambiguous: %w", err)
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
