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
	// Retention is how long a resolved value is still masked after it was
	// last resolved. A site may echo a value long after it was sent (an
	// order page, a receipt), including after it expired.
	Retention = 24 * time.Hour
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
	seen    time.Time
}

func newRecord(now func() time.Time) *record {
	return &record{principals: map[principalKey]*principalValues{}, now: now}
}

// add records values resolved for p.
func (r *record) add(p resolve.Principal, values map[string]resolve.Value) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	key := keyOf(p)
	pv := r.principals[key]
	if pv == nil {
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
		if old, ok := pv.values[v.Real]; !ok || old.standIn != standIn {
			pv.stale = true
		}
		pv.values[v.Real] = entry{standIn: standIn, seen: now}
	}
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
	for real, e := range pv.values {
		if now.Sub(e.seen) > Retention {
			delete(pv.values, real)
			pv.stale = true
		}
	}
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
