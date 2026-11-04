// Package scope decides which real values a request may carry.
//
// For each request on an allowlisted host, a Session finds the stand-ins the
// request holds, asks the resolver for their real values once, with the
// connection's principal, and builds a swap.Swapper that holds only those
// values. A value is used only when it may go to the request's host and has
// not expired; otherwise the whole request is refused, before anything is
// sent upstream. Nothing is cached here: every request is resolved again, so
// a value resolved for one principal is never used for another, and a
// resolver's own expiry and revocation apply to the next request.
//
// When masking is on, every value resolved for a principal is also kept on
// record (bounded, see Retention), and Session.Masker returns a mask.Masker
// that turns those values back into their stand-ins in responses, on every
// connection of that principal.
package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// DefaultTimeout bounds one Resolve call.
const DefaultTimeout = 10 * time.Second

// Config configures a Scope.
type Config struct {
	Resolver resolve.Resolver
	Detector *resolve.Detector
	// Hosts is the proxy's allowlist: where a value without its own hosts
	// may go.
	Hosts *hostmatch.List
	// Timeout bounds one Resolve call (default DefaultTimeout).
	Timeout time.Duration
	// Now is the clock that expiry is checked against (default time.Now).
	Now func() time.Time
	// Mask keeps resolved values on record for masking responses.
	Mask   bool
	Logger *slog.Logger
}

// Scope builds a Session for each intercepted connection.
type Scope struct {
	cfg    Config
	record *record
}

// New validates the configuration.
func New(cfg Config) (*Scope, error) {
	if cfg.Resolver == nil || cfg.Detector == nil || cfg.Hosts == nil {
		return nil, errors.New("scope: resolver, detector and hosts are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Scope{cfg: cfg, record: newRecord(cfg.Now)}, nil
}

// Session is the scope of one connection: the principal its CONNECT
// authenticated as.
func (s *Scope) Session(p resolve.Principal) *Session {
	return &Session{scope: s, principal: p}
}

// Session resolves the requests of one connection.
type Session struct {
	scope     *Scope
	principal resolve.Principal
}

// Masker returns the Masker for every value resolved for this session's
// principal, on any connection. It is nil when masking is off or nothing was
// resolved yet.
func (s *Session) Masker() *mask.Masker {
	if !s.scope.cfg.Mask {
		return nil
	}
	return s.scope.record.masker(s.principal)
}

// Masking reports whether responses are masked on this session's
// connection: Masker may return a Masker at any time.
func (s *Session) Masking() bool { return s.scope.cfg.Mask }

// Principal is the connection's principal.
func (s *Session) Principal() resolve.Principal { return s.principal }

// ErrRefused is a request whose stand-ins cannot be swapped: the resolver
// failed, did not answer for one of them, or answered with a value that may
// not go to the request's host or has expired. Such a request is not sent.
var ErrRefused = errors.New("request refused")

// RefusedError says why a request was refused. Its reason never contains a
// stand-in or a real value.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "request refused: " + e.Reason }

// Is makes errors.Is(err, ErrRefused) true.
func (e *RefusedError) Is(target error) bool { return target == ErrRefused }

func refused(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// Swapper returns a Swapper for one request to host whose swappable text is
// texts: the query part of the target, the header values that are not
// framing headers, and the body. It returns nil when the request holds no
// stand-in, and a *RefusedError when it must not be sent.
func (s *Session) Swapper(ctx context.Context, host string, texts ...string) (*swap.Swapper, error) {
	values, err := s.Values(ctx, host, texts...)
	if err != nil || values == nil {
		return nil, err
	}
	reals := make(map[string]string, len(values))
	for standIn, v := range values {
		reals[standIn] = v.Real
	}
	sw, err := swap.New(reals)
	if err != nil {
		return nil, refused("%v", err)
	}
	return sw, nil
}

// Values resolves the stand-ins texts hold and checks that each value may go
// to host now. It returns nil when there are no stand-ins.
func (s *Session) Values(ctx context.Context, host string, texts ...string) (map[string]resolve.Value, error) {
	cfg := s.scope.cfg
	standIns := cfg.Detector.Find(s.principal, texts...)
	if len(standIns) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	result, err := cfg.Resolver.Resolve(ctx, resolve.Request{StandIns: standIns, Host: host, Principal: s.principal})
	if err != nil {
		// The resolver's error may quote what it was sent; log it, never
		// return it to the client.
		cfg.Logger.Warn("resolver failed", "principal", s.principal.ID, "host", host, "stand_ins", len(standIns), "error", err)
		return nil, refused("the resolver failed")
	}
	if cfg.Mask {
		// Recorded before the checks: a value refused here is still the
		// principal's, and a destination may hold it already.
		s.scope.record.add(s.principal, result.Values)
	}
	now := cfg.Now()
	values := make(map[string]resolve.Value, len(standIns))
	for _, standIn := range standIns {
		v, ok := result.Values[standIn]
		switch {
		case !ok:
			return nil, refused("a stand-in has no value for this principal")
		case v.Real == "":
			return nil, refused("the resolver returned an empty value")
		case !v.ExpiresAt.IsZero() && !now.Before(v.ExpiresAt):
			return nil, refused("a value has expired")
		}
		allowed, err := s.allows(v, host)
		if err != nil {
			cfg.Logger.Warn("resolver returned an invalid host list", "principal", s.principal.ID, "error", err)
			return nil, refused("the resolver returned an invalid host list")
		}
		if !allowed {
			return nil, refused("a value may not be sent to this host")
		}
		values[standIn] = v
	}
	return values, nil
}

// allows reports whether v may be sent to host: one of its own hosts, or,
// when it has none, the proxy's allowlist.
func (s *Session) allows(v resolve.Value, host string) (bool, error) {
	if len(v.Hosts) == 0 {
		return s.scope.cfg.Hosts.Match(host), nil
	}
	list, err := hostmatch.New(v.Hosts)
	if err != nil {
		return false, err
	}
	return list.Match(host), nil
}
