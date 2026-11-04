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
// the principal outright (an expired credential). Nothing is cached here:
// every request is resolved again, so a value resolved for one principal is
// never used for another, and a value is no longer swapped once the
// resolver stops giving it. In the file and sealed modes that is the next
// request; the http resolver answers from its own cache, so a value revoked
// at the service is still swapped for up to -resolver-cache-ttl.
//
// The resolver is asked about the CONNECT host as the allowlist matches it
// (hostmatch.Host): in lower case, without a port or a trailing dot. A
// value's host list is nil for the allowlist; an empty one is invalid, and
// refuses the request like any other invalid list.
//
// When masking is on, every value resolved for a principal is also kept on
// record, until its expiry or for Retention after its last lookup,
// whichever is first, and never once the principal's credential is reported
// invalid. Session.Masker returns a mask.Masker that turns those values back
// into their stand-ins in responses, on every connection of that principal.
package scope

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	Mask bool
	// MaskWindow is what a masked stream holds back (default mask.Fixed).
	MaskWindow mask.Window
	Logger     *slog.Logger
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
	rec := newRecord(cfg.Now)
	rec.window = cfg.MaskWindow
	return &Scope{cfg: cfg, record: rec}, nil
}

// Close stops the expiry sweep of the values kept for masking and drops
// them. The Scope must not be used afterwards.
func (s *Scope) Close() { s.record.close() }

// Session is the scope of one connection: the principal its CONNECT
// authenticated as, and the host it CONNECTed to.
func (s *Scope) Session(p resolve.Principal, host string) *Session {
	return &Session{scope: s, principal: p, host: hostmatch.Host(host)}
}

// Session resolves the requests of one connection.
type Session struct {
	scope     *Scope
	principal resolve.Principal
	// The CONNECT destination, as hostmatch.Host gives it; empty, which
	// nothing matches, when it is not a plain host.
	host string
}

// CheckAuthority refuses a request whose authority is not the host the
// connection was opened to: such a request would still reach the CONNECT
// host, so values scoped to the host it names must not go with it. A request
// can name its authority in more than one place (Host and :authority, Host
// and an absolute-form target): every one must be that host, and all must
// be the same authority, as the server may route by any of them. A request
// that names none is refused too.
func (s *Session) CheckAuthority(authorities ...string) error {
	if len(authorities) == 0 {
		return refused("the request names no authority")
	}
	for _, authority := range authorities {
		if !hostmatch.SameHost(authority, s.host) {
			return refused("the request's authority is not the host the connection was opened to")
		}
		if !strings.EqualFold(authority, authorities[0]) {
			return refused("the request names more than one authority")
		}
	}
	return nil
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

// Swapper returns a Swapper for one request whose swappable text is parts:
// the query part of the target (swap.Query), the header values that are not
// framing headers (swap.Literal), and the body (swap.BodyPlace of its
// Content-Type). It returns nil when the request holds no stand-in, and a
// *RefusedError when it must not be sent.
func (s *Session) Swapper(ctx context.Context, parts ...swap.Part) (*swap.Swapper, error) {
	lookup, err := s.Prepare(parts...)
	if err != nil || lookup == nil {
		return nil, err
	}
	return lookup.Swapper(ctx)
}

// Values resolves the stand-ins a swap of parts would replace and checks
// that each value may go to the connection's host now. It returns nil when
// there are none.
func (s *Session) Values(ctx context.Context, parts ...swap.Part) (map[string]resolve.Value, error) {
	lookup, err := s.Prepare(parts...)
	if err != nil || lookup == nil {
		return nil, err
	}
	return lookup.Values(ctx)
}

// Lookup is one request's resolution, prepared but not made: the stand-ins
// a swap would replace, and the resolver (or snapshot of it) to ask.
type Lookup struct {
	session  *Session
	resolver resolve.Resolver
	standIns []string
}

// Prepare does everything before the resolver is called, all of it local:
// it takes the resolver's snapshot (refusing the request when the
// principal's credential is no longer valid) and finds the stand-ins a swap
// of parts would replace. It returns nil when there is nothing to resolve,
// so a caller can tell, without waiting on the resolver, which requests need
// a lookup.
func (s *Session) Prepare(parts ...swap.Part) (*Lookup, error) {
	cfg := s.scope.cfg
	resolver := cfg.Resolver
	var known resolve.KnownStandIns
	if snapshotter, ok := cfg.Resolver.(resolve.Snapshotter); ok {
		snapshot, err := snapshotter.Snapshot(s.principal)
		if err != nil {
			cfg.Logger.Warn("resolver refused the principal", "principal", s.principal.ID, "host", s.host, "error", errorCategory(err))
			if errors.Is(err, resolve.ErrUnauthenticated) {
				if cfg.Mask {
					s.scope.record.forget(s.principal)
				}
				return nil, refused("the proxy credential is no longer valid")
			}
			return nil, refused("the resolver failed")
		}
		resolver, known = snapshot, snapshot
	}
	texts := make([]string, len(parts))
	for i, p := range parts {
		texts[i] = p.Text
	}
	var candidates []string
	if known != nil {
		candidates = cfg.Detector.FindIn(known, s.principal, withDecoded(texts)...)
	} else {
		candidates = cfg.Detector.Find(s.principal, withDecoded(texts)...)
	}
	standIns := used(candidates, parts)
	if len(standIns) == 0 {
		return nil, nil
	}
	return &Lookup{session: s, resolver: resolver, standIns: standIns}, nil
}

// Local reports whether the lookup is answered from memory, without
// waiting (resolve.Local): a caller may then resolve it in line.
func (l *Lookup) Local() bool {
	_, ok := l.resolver.(resolve.Local)
	return ok
}

// Swapper resolves the lookup and returns a Swapper holding exactly its
// values, or a *RefusedError when the request must not be sent. It waits
// for the resolver, at most the scope's Timeout, or until ctx ends.
func (l *Lookup) Swapper(ctx context.Context) (*swap.Swapper, error) {
	values, err := l.Values(ctx)
	if err != nil {
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

// Values resolves the lookup and checks that each value may go to the
// connection's host now.
func (l *Lookup) Values(ctx context.Context) (map[string]resolve.Value, error) {
	s, standIns := l.session, l.standIns
	cfg := s.scope.cfg
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	result, err := l.resolver.Resolve(ctx, resolve.Request{StandIns: standIns, Host: s.host, Principal: s.principal})
	if err != nil {
		// The resolver's error may quote what it was sent, or a real value:
		// only its category is logged, and nothing reaches the client.
		cfg.Logger.Warn("resolver failed", "principal", s.principal.ID, "host", s.host, "stand_ins", len(standIns), "error", errorCategory(err))
		return nil, refused("the resolver failed")
	}
	// Recorded before the checks: a value refused here is still the
	// principal's, and a destination may hold it already. A lookup with
	// more values than the record keeps would leave some of them out, and
	// their echo unmasked: it is refused instead.
	if cfg.Mask && !s.scope.record.add(s.principal, result.Values) {
		cfg.Logger.Warn("refusing a request with more values than are masked", "principal", s.principal.ID, "host", s.host, "limit", MaxValuesPerPrincipal)
		return nil, refused("the request carries more than %d values, more than masking keeps per principal", MaxValuesPerPrincipal)
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
// when it has no host list (nil), the proxy's allowlist. An empty list is
// an error, as an invalid one is: it is not the same as none.
func (s *Session) allows(v resolve.Value, host string) (bool, error) {
	if v.Hosts == nil {
		return s.scope.cfg.Hosts.Match(host), nil
	}
	list, err := hostmatch.New(v.Hosts)
	if err != nil {
		return false, err
	}
	return list.Match(host), nil
}
