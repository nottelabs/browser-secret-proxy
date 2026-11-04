package scope

import (
	"crypto/sha256"
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
	// least recently resolved go first.
	MaxValuesPerPrincipal = 1024
	// MaxPrincipals bounds the principals with values on record; the least
	// recently active go first.
	MaxPrincipals = 4096
)

// record keeps, per principal, the real values resolved for it, so that
// every connection of that principal can mask them in responses.
type record struct {
	mu         sync.Mutex
	principals map[principalKey]*principalValues
	now        func() time.Time
}

// principalKey identifies a principal by its ID and a hash of its secret, so
// two credentials with one ID never share values.
type principalKey struct {
	id     string
	secret [sha256.Size]byte
}

func keyOf(p resolve.Principal) principalKey {
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
	return &record{principals: map[principalKey]*principalValues{}, now: now}
}

// add records values resolved for p, each until its expiry or Retention
// from now, whichever is first.
func (r *record) add(p resolve.Principal, values map[string]resolve.Value) {
	now := r.now()
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
		if old, ok := pv.values[v.Real]; !ok || old.standIn != standIn {
			pv.stale = true
		}
		pv.values[v.Real] = entry{standIn: standIn, seen: now, until: until}
	}
	pv.dropExpired(now)
	for len(pv.values) > MaxValuesPerPrincipal {
		oldest := ""
		for real, e := range pv.values {
			if oldest == "" || e.seen.Before(pv.values[oldest].seen) {
				oldest = real
			}
		}
		delete(pv.values, oldest)
		pv.stale = true
	}
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

func (pv *principalValues) dropExpired(now time.Time) {
	for real, e := range pv.values {
		if !now.Before(e.until) {
			delete(pv.values, real)
			pv.stale = true
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
		pv.masker = mask.New(pairs)
		pv.stale = false
	}
	return pv.masker
}
