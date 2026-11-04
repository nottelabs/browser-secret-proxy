// Package resolve finds the stand-ins in a request and looks up their real
// values.
//
// A Resolver is the source of real values. The proxy calls it once per
// request on an allowlisted host, with every stand-in that request carries.
// Resolution fails closed: a stand-in the resolver does not answer for, or
// whose value may not go to the destination or has expired, stops the
// request before anything is sent.
//
// A Detector tells the proxy which strings are stand-ins: the ones a resolver
// knows in advance (KnownStandIns) and the ones that match configured
// patterns.
package resolve

import (
	"context"
	"errors"
	"time"
)

// Request is one request's lookup.
type Request struct {
	StandIns  []string  // stand-ins found in this request
	Host      string    // destination host
	Principal Principal // who is asking (from proxy auth)
}

// Principal is the authenticated proxy credential a request came through.
type Principal struct {
	ID       string // stable id of the authenticated proxy credential (e.g. username or token subject)
	Password string // raw credential secret, for modes that need it (never logged)
}

// String names the principal without its secret, so it can be logged.
func (p Principal) String() string { return "principal(" + p.ID + ")" }

// GoString hides the secret from %#v too.
func (p Principal) GoString() string { return p.String() }

// Value is a real value and where it may be sent.
type Value struct {
	Real      string
	Hosts     []string  // hosts this value may be sent to; empty means the proxy's configured hosts
	ExpiresAt time.Time // zero means no expiry
}

// String hides the real value, so a Value can be logged.
func (v Value) String() string { return "value(redacted)" }

// GoString hides the real value from %#v too.
func (v Value) GoString() string { return v.String() }

// Result is the answer to a Request.
type Result struct{ Values map[string]Value }

// Resolver looks up real values. Values may hold only some of the requested
// stand-ins: the caller refuses the request when one is missing.
type Resolver interface {
	Resolve(ctx context.Context, req Request) (Result, error)
}

// KnownStandIns is implemented by resolvers that know their stand-ins in
// advance: the file mode's keys, the sealed mode's token payload. A Detector
// looks for them in every request.
type KnownStandIns interface {
	StandIns(p Principal) []string
}

// Snapshot is one consistent view of a resolver for one principal: its
// known stand-ins and the values it resolves come from the same version.
type Snapshot interface {
	Resolver
	KnownStandIns
}

// Snapshotter is implemented by resolvers whose stand-ins and values change
// over time (a reloaded file) or end (an expiring credential). The proxy
// takes one Snapshot per request, so detection and resolution never mix two
// versions. An error refuses the request, whether or not it holds a
// stand-in; it wraps ErrUnauthenticated when the principal's credential is
// no longer valid.
type Snapshotter interface {
	Snapshot(p Principal) (Snapshot, error)
}

// Authenticator is implemented by resolvers whose proxy credential carries
// the values (sealed). When the configured resolver implements it, the proxy
// calls it on every CONNECT instead of comparing a fixed username and
// password, and answers 407 on an error.
type Authenticator interface {
	Authenticate(username, password string) (Principal, error)
}

// ErrUnauthenticated is a credential an Authenticator refuses.
var ErrUnauthenticated = errors.New("proxy credential refused")
