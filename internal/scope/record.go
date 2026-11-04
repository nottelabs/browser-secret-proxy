package scope

import (
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// Bounds of the record of resolved values kept for masking responses.
const (
	// Retention is how long a resolved value is still masked, and so kept in
	// memory, after it was last resolved: at most this long, and never past
	// the value's own expiry. Past it, a site echoing the value is not
	// masked; the bound keeps real values out of memory once they are no
	// longer in use.
	Retention = 15 * time.Minute
	// MaxValuesPerPrincipal bounds the values masked for one principal; the
	// least recently resolved go first, but never those of the lookup that
	// adds them. A request whose lookup alone has more is refused.
	MaxValuesPerPrincipal = 1024
	// MaxPrincipals bounds the principals with values on record; the least
	// recently active go first.
	MaxPrincipals = 4096
	// SweepEvery is the shortest time between two expiry sweeps: a value is
	// dropped from memory at most this long after it expires, even when no
	// request comes, and a sweep (a walk over every value on record) runs at
	// most this often.
	SweepEvery = 5 * time.Second
)

// record keeps, per principal, the real values resolved for it, so that
// every connection of that principal can mask them in responses.
type record struct {
	mu         sync.Mutex
	principals map[principalKey]*principalValues
	now        func() time.Time
	window     mask.Window // of every Masker built
	// The expiry sweep: a timer armed for the earliest expiry on record, no
	// sooner than sweepEvery after the previous sweep, and stopped by close.
	sweepEvery time.Duration
	timer      *time.Timer
	next       time.Time // when the timer fires; zero when it is not armed
	lastSweep  time.Time
	closed     bool
}

// principalKey identifies a principal by its ID and a hash of its secret, so
// two credentials with one ID never share values. A SecretOnly principal is
// identified by the hash alone: its ID may be the client's choice (a sealed
// token's username), and one credential must not split into several
// principals, whose values would not be masked on each other's connections
// and could push every other principal off the record.
type principalKey struct {
	id     string
	secret [sha256.Size]byte
}

func keyOf(p resolve.Principal) principalKey {
	if p.SecretOnly {
		return principalKey{secret: sha256.Sum256([]byte(p.Password))}
	}
	return principalKey{id: p.ID, secret: sha256.Sum256([]byte(p.Password))}
}

type principalValues struct {
	values map[string]entry // by real value
	masker *mask.Masker
	stale  bool // values changed since masker was built
	seen   time.Time
}

type entry struct {
	standIn string
	seen    time.Time // last resolved
	until   time.Time // masked and kept until then
}

func newRecord(now func() time.Time) *record {
	return &record{principals: map[principalKey]*principalValues{}, now: now, sweepEvery: SweepEvery}
}

// armLocked makes sure the sweep runs by until, or sweepEvery after the
// previous sweep if that is later.
func (r *record) armLocked(until time.Time) {
	if r.closed {
		return
	}
	at := until
	if earliest := r.lastSweep.Add(r.sweepEvery); at.Before(earliest) {
		at = earliest
	}
	if !r.next.IsZero() && !at.Before(r.next) {
		return // already armed for that time or sooner
	}
	r.next = at
	d := max(at.Sub(r.now()), 0)
	if r.timer == nil {
		r.timer = time.AfterFunc(d, r.sweep)
	} else {
		r.timer.Reset(d)
	}
}

// sweep drops expired values, and the maskers built from them, then arms the
// next sweep for the earliest expiry left.
func (r *record) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	now := r.now()
	r.next, r.lastSweep = time.Time{}, now
	r.pruneLocked(now)
	var earliest time.Time
	for _, pv := range r.principals {
		for _, e := range pv.values {
			if earliest.IsZero() || e.until.Before(earliest) {
				earliest = e.until
			}
		}
	}
	if !earliest.IsZero() {
		r.armLocked(earliest)
	}
}

// close stops the sweep and drops every value on record.
func (r *record) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.timer != nil {
		r.timer.Stop()
	}
	r.next = time.Time{}
	r.principals = map[principalKey]*principalValues{}
}

// add records values resolved for p, each until its expiry or Retention
// from now, whichever is first. When there are more than
// MaxValuesPerPrincipal on record, the least recently resolved go first,
// but never one of these values: when these alone are more than
// MaxValuesPerPrincipal, add records nothing and returns false.
func (r *record) add(p resolve.Principal, values map[string]resolve.Value) bool {
	now := r.now()
	kept := make(map[string]entry, len(values)) // by real value
	for standIn, v := range values {
		if len(v.Real) < mask.MinLength {
			continue
		}
		until := now.Add(Retention)
		if !v.ExpiresAt.IsZero() && v.ExpiresAt.Before(until) {
			until = v.ExpiresAt
		}
		if !now.Before(until) {
			continue // already expired: never kept
		}
		kept[v.Real] = entry{standIn: standIn, seen: now, until: until}
	}
	if len(kept) > MaxValuesPerPrincipal {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := keyOf(p)
	pv := r.principals[key]
	if pv == nil {
		r.pruneLocked(now)
		if len(r.principals) >= MaxPrincipals {
			r.evictPrincipalLocked()
		}
		pv = &principalValues{values: map[string]entry{}}
		r.principals[key] = pv
	}
	pv.seen = now
	for real, e := range kept {
		if old, ok := pv.values[real]; !ok || old.standIn != e.standIn {
			pv.stale = true
		}
		pv.values[real] = e
		r.armLocked(e.until)
	}
	pv.dropExpired(now)
	if excess := len(pv.values) - MaxValuesPerPrincipal; excess > 0 {
		// Only values of earlier lookups go, oldest first: one may carry
		// this same time, so comparing times alone could drop one of these.
		older := make([]string, 0, len(pv.values)-len(kept))
		for real := range pv.values {
			if _, ok := kept[real]; !ok {
				older = append(older, real)
			}
		}
		slices.SortFunc(older, func(a, b string) int { return pv.values[a].seen.Compare(pv.values[b].seen) })
		for _, real := range older[:excess] {
			delete(pv.values, real)
		}
		pv.stale = true
		pv.masker = nil
	}
	return true
}

// forget drops every value on record for p: its credential is no longer
// valid, so its values are no longer kept.
func (r *record) forget(p resolve.Principal) {
	r.mu.Lock()
	delete(r.principals, keyOf(p))
	r.mu.Unlock()
}

// pruneLocked drops expired values, and principals left with none.
func (r *record) pruneLocked(now time.Time) {
	for k, pv := range r.principals {
		pv.dropExpired(now)
		if len(pv.values) == 0 {
			delete(r.principals, k)
		}
	}
}

// dropExpired drops expired values, and the masker built with them, which
// would otherwise keep them in memory; the next lookup builds a new one.
func (pv *principalValues) dropExpired(now time.Time) {
	for real, e := range pv.values {
		if !now.Before(e.until) {
			delete(pv.values, real)
			pv.stale = true
			pv.masker = nil
		}
	}
}

func (r *record) evictPrincipalLocked() {
	var oldest principalKey
	var oldestSeen time.Time
	first := true
	for k, pv := range r.principals {
		if first || pv.seen.Before(oldestSeen) {
			oldest, oldestSeen, first = k, pv.seen, false
		}
	}
	delete(r.principals, oldest)
}

// masker returns the Masker for p's values, nil when there are none.
func (r *record) masker(p resolve.Principal) *mask.Masker {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	key := keyOf(p)
	pv := r.principals[key]
	if pv == nil {
		return nil
	}
	pv.dropExpired(now)
	if len(pv.values) == 0 {
		delete(r.principals, key)
		return nil
	}
	if pv.stale || pv.masker == nil {
		pairs := make([]mask.Pair, 0, len(pv.values))
		for real, e := range pv.values {
			pairs = append(pairs, mask.Pair{Real: real, StandIn: e.standIn})
		}
		pv.masker = mask.New(pairs).WithWindow(r.window)
		pv.stale = false
	}
	return pv.masker
}
