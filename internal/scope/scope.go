// Package scope decides which real values a request may carry.
//
// A Session is the scope of one intercepted connection: the principal its
// CONNECT authenticated as and the host it CONNECTed to, which is where every
// request on it goes, whatever its Host or :authority says. A request whose
// authority names another host is refused. For each request, the Session
// finds the stand-ins it holds (also in their query-, path- and
// JSON-escaped forms), keeps the ones a swap would actually replace (a longer
// stand-in wins over one it contains), asks the resolver for their real
// values once, with the connection's principal, and builds a swap.Swapper
// that holds only those values. A value is used only when it may go to the
// CONNECT host and has not expired; otherwise the whole request is refused,
// before anything is sent upstream. A resolver that is a resolve.Snapshotter
// gives one consistent version for detection and resolution, and can refuse
// the principal outright (an expired credential). Nothing is cached here: every request is resolved again, so
// a value resolved for one principal is never used for another, and a
// resolver's own expiry and revocation apply to the next request.
package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
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
	Now    func() time.Time
	Logger *slog.Logger
}

// Scope builds a Session for each intercepted connection.
type Scope struct{ cfg Config }

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
	return &Scope{cfg: cfg}, nil
}

// Session is the scope of one connection: the principal its CONNECT
// authenticated as, and the host it CONNECTed to.
func (s *Scope) Session(p resolve.Principal, host string) *Session {
	return &Session{scope: s, principal: p, host: host}
}

// Session resolves the requests of one connection.
type Session struct {
	scope     *Scope
	principal resolve.Principal
	host      string // the CONNECT destination
}

// CheckAuthority refuses a request whose authority (Host or :authority) is
// not the host the connection was opened to: such a request would still
// reach the CONNECT host, so values scoped to the host it names must not go
// with it.
func (s *Session) CheckAuthority(authority string) error {
	if !hostmatch.SameHost(authority, s.host) {
		return refused("the request's authority is not the host the connection was opened to")
	}
	return nil
}

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

// Swapper returns a Swapper for one request whose swappable text is texts:
// the query part of the target, the header values that are not framing
// headers, and the body. It returns nil when the request holds no
// stand-in, and a *RefusedError when it must not be sent.
func (s *Session) Swapper(ctx context.Context, texts ...string) (*swap.Swapper, error) {
	values, err := s.Values(ctx, texts...)
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

// Values resolves the stand-ins a swap of texts would replace and checks
// that each value may go to the connection's host now. It returns nil when
// there are none.
func (s *Session) Values(ctx context.Context, texts ...string) (map[string]resolve.Value, error) {
	cfg := s.scope.cfg
	resolver := cfg.Resolver
	var known resolve.KnownStandIns
	if snapshotter, ok := cfg.Resolver.(resolve.Snapshotter); ok {
		snapshot, err := snapshotter.Snapshot(s.principal)
		if err != nil {
			cfg.Logger.Warn("resolver refused the principal", "principal", s.principal.ID, "host", s.host, "error", errorCategory(err))
			if errors.Is(err, resolve.ErrUnauthenticated) {
				return nil, refused("the proxy credential is no longer valid")
			}
			return nil, refused("the resolver failed")
		}
		resolver, known = snapshot, snapshot
	}
	var candidates []string
	if known != nil {
		candidates = cfg.Detector.FindIn(known, s.principal, withDecoded(texts)...)
	} else {
		candidates = cfg.Detector.Find(s.principal, withDecoded(texts)...)
	}
	standIns := used(candidates, texts)
	if len(standIns) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	result, err := resolver.Resolve(ctx, resolve.Request{StandIns: standIns, Host: s.host, Principal: s.principal})
	if err != nil {
		// The resolver's error may quote what it was sent, or a real value:
		// only its category is logged, and nothing reaches the client.
		cfg.Logger.Warn("resolver failed", "principal", s.principal.ID, "host", s.host, "stand_ins", len(standIns), "error", errorCategory(err))
		return nil, refused("the resolver failed")
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
		allowed, err := s.allows(v, s.host)
		if err != nil {
			cfg.Logger.Warn("resolver returned an invalid host list", "principal", s.principal.ID)
			return nil, refused("the resolver returned an invalid host list")
		}
		if !allowed {
			return nil, refused("a value may not be sent to this host")
		}
		values[standIn] = v
	}
	return values, nil
}

// errorCategory names the kind of a resolver error without its text.
func errorCategory(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, resolve.ErrUnauthenticated):
		return "credential refused"
	}
	return "error"
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
