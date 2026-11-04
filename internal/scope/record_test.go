package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

type staticFor map[string]map[string]string // principal ID -> stand-in -> real

func (s staticFor) Resolve(_ context.Context, req resolve.Request) (resolve.Result, error) {
	out := resolve.Result{Values: map[string]resolve.Value{}}
	for _, standIn := range req.StandIns {
		if real, ok := s[req.Principal.ID][standIn]; ok {
			out.Values[standIn] = resolve.Value{Real: real}
		}
	}
	return out, nil
}

func (s staticFor) StandIns(p resolve.Principal) []string {
	var out []string
	for k := range s[p.ID] {
		out = append(out, k)
	}
	return out
}

func TestMaskersFollowPrincipals(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	r := staticFor{"alice": {"tok_alice": "alice_real_1"}, "bob": {"tok_bob": "bob_real_22"}}
	hosts, _ := hostmatch.New([]string{"api.example.com"})
	detector, err := resolve.NewDetector(r, resolve.Patterns{Prefixes: []string{"tok_"}})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := New(Config{Resolver: r, Detector: detector, Hosts: hosts, Mask: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	alice := sc.Session(resolve.Principal{ID: "alice", Password: "a"}, "api.example.com")
	aliceAgain := sc.Session(resolve.Principal{ID: "alice", Password: "a"}, "api.example.com")
	aliceOtherSecret := sc.Session(resolve.Principal{ID: "alice", Password: "other"}, "api.example.com")
	bob := sc.Session(resolve.Principal{ID: "bob"}, "other.example")
	if alice.Masker() != nil {
		t.Fatal("nothing resolved yet, nothing to mask")
	}
	if _, err := alice.Swapper(context.Background(), swap.Part{Text: "tok_alice"}); err != nil {
		t.Fatal(err)
	}
	if got := aliceAgain.Masker().String(mask.Text, "x alice_real_1"); got != "x tok_alice" {
		t.Fatalf("another connection of alice got %q", got)
	}
	if aliceOtherSecret.Masker() != nil || bob.Masker() != nil {
		t.Fatal("alice's values reached another principal")
	}
	// A value refused for its host is still on record: it is alice's.
	if _, err := bob.Swapper(context.Background(), swap.Part{Text: "tok_bob"}); err == nil {
		t.Fatal("expected a refusal")
	}
	if got := bob.Masker().String(mask.Text, "bob_real_22"); got != "tok_bob" {
		t.Fatalf("bob got %q", got)
	}
	now = now.Add(Retention + time.Second)
	if alice.Masker() != nil {
		t.Fatal("a value past its retention is still masked")
	}
	// Masking off: nothing is kept.
	off, _ := New(Config{Resolver: r, Detector: detector, Hosts: hosts})
	s := off.Session(resolve.Principal{ID: "alice"}, "api.example.com")
	_, _ = s.Swapper(context.Background(), swap.Part{Text: "tok_alice"})
	if s.Masker() != nil || s.Masking() {
		t.Fatal("masking is off")
	}
}

// A value is kept until its own expiry when that comes before Retention,
// and is forgotten with its principal's credential.
func TestRecordFollowsExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	rec := newRecord(func() time.Time { return now })
	p := resolve.Principal{ID: "p"}
	rec.add(p, map[string]resolve.Value{
		"s_soon":    {Real: "real_soon_1", ExpiresAt: now.Add(time.Minute)},
		"s_later":   {Real: "real_later_1", ExpiresAt: now.Add(time.Hour)},
		"s_none":    {Real: "real_none_1"},
		"s_expired": {Real: "real_expired_1", ExpiresAt: now.Add(-time.Second)},
	})
	if got := rec.masker(p).String(mask.Text, "real_soon_1 real_later_1 real_none_1 real_expired_1"); got != "s_soon s_later s_none real_expired_1" {
		t.Fatalf("got %q", got)
	}
	now = now.Add(time.Minute)
	if got := rec.masker(p).String(mask.Text, "real_soon_1 real_later_1"); got != "real_soon_1 s_later" {
		t.Fatalf("after its expiry: %q", got)
	}
	now = now.Add(Retention)
	if rec.masker(p) != nil {
		t.Fatal("values are kept past Retention")
	}
	if Retention > 15*time.Minute {
		t.Fatalf("Retention %v keeps real values in memory too long", Retention)
	}
	rec.add(p, map[string]resolve.Value{"s": {Real: "real_value_1"}})
	rec.forget(p)
	if rec.masker(p) != nil || len(rec.principals) != 0 {
		t.Fatal("a forgotten principal's values are still kept")
	}
}

// Principals whose values all expired are dropped when another principal is
// added, without waiting for a lookup of their own.
func TestExpiredPrincipalsAreDropped(t *testing.T) {
	now := time.Unix(1000, 0)
	rec := newRecord(func() time.Time { return now })
	rec.add(resolve.Principal{ID: "a"}, map[string]resolve.Value{"s": {Real: "real_value_a"}})
	now = now.Add(Retention)
	rec.add(resolve.Principal{ID: "b"}, map[string]resolve.Value{"s": {Real: "real_value_b"}})
	if _, ok := rec.principals[keyOf(resolve.Principal{ID: "a"})]; ok || len(rec.principals) != 1 {
		t.Fatalf("%d principals kept", len(rec.principals))
	}
}

func TestRecordIsBounded(t *testing.T) {
	now := time.Unix(0, 0)
	rec := newRecord(func() time.Time { now = now.Add(time.Millisecond); return now })
	p := resolve.Principal{ID: "p"}
	for i := 0; i < MaxValuesPerPrincipal+10; i++ {
		rec.add(p, map[string]resolve.Value{"s" + itoa(i): {Real: "real_value_" + itoa(i)}})
	}
	if n := len(rec.principals[keyOf(p)].values); n != MaxValuesPerPrincipal {
		t.Fatalf("%d values kept", n)
	}
	if rec.masker(p).String(mask.Text, "real_value_0 ") != "real_value_0 " {
		t.Fatal("the oldest value should have been dropped")
	}
	for i := 0; i < MaxPrincipals+5; i++ {
		rec.add(resolve.Principal{ID: itoa(i)}, map[string]resolve.Value{"s": {Real: "real_value"}})
	}
	if len(rec.principals) > MaxPrincipals {
		t.Fatalf("%d principals kept", len(rec.principals))
	}
}

// A lookup never evicts its own values from the record, even when every
// value on record was looked up at the same time: a response echoing any
// of them is masked. A lookup with more values than the record keeps per
// principal is refused, since its response could not be masked, and
// leaves the record as it was.
func TestALookupNeverEvictsItsOwnValues(t *testing.T) {
	values := map[string]string{}
	standIns := make([]string, MaxValuesPerPrincipal+200)
	for i := range standIns {
		standIns[i] = fmt.Sprintf("tok_%04d", i)
		values[standIns[i]] = fmt.Sprintf("real_value_%04d", i)
	}
	r, err := resolve.NewStatic(values)
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := hostmatch.New([]string{"api.example.com"})
	detector, err := resolve.NewDetector(r, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	newScope := func(masking bool) *Scope {
		sc, err := New(Config{Resolver: r, Detector: detector, Hosts: hosts, Mask: masking, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(sc.Close)
		return sc
	}
	s := newScope(true).Session(resolve.Principal{ID: "u", Password: "p"}, "api.example.com")
	send := func(standIns []string) (string, error) {
		t.Helper()
		body := strings.Join(standIns, " ")
		sw, err := s.Swapper(context.Background(), swap.Part{Place: swap.BodyPlace("text/plain"), Text: body})
		if err != nil {
			return "", err
		}
		sent, _, err := sw.Body("text/plain", []byte(body), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		return string(sent), nil
	}
	if _, err := send(standIns[:200]); err != nil {
		t.Fatal(err)
	}
	full := standIns[200:]
	sent, err := send(full)
	if err != nil {
		t.Fatal(err)
	}
	// The destination echoes the body it received.
	if echoed := s.Masker().String(mask.Text, sent); echoed != strings.Join(full, " ") {
		t.Fatalf("%d real values of the lookup reach the client", strings.Count(echoed, "real_value_"))
	}
	if _, err := send(standIns); !errors.Is(err, ErrRefused) {
		t.Fatalf("a lookup of %d values: %v, want a refusal", len(standIns), err)
	}
	if echoed := s.Masker().String(mask.Text, sent); echoed != strings.Join(full, " ") {
		t.Fatal("a refused lookup changed the record")
	}
	// Without masking there is nothing to keep, and no bound.
	if _, err := newScope(false).Session(resolve.Principal{ID: "u"}, "api.example.com").Swapper(context.Background(), swap.Part{Place: swap.Literal, Text: strings.Join(standIns, " ")}); err != nil {
		t.Fatalf("without masking: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// Expired values leave memory without another lookup: the sweep drops them,
// and the masker built with them, once traffic stops.
func TestIdleValuesExpireWithoutALookup(t *testing.T) {
	rec := newRecord(time.Now)
	rec.sweepEvery = 10 * time.Millisecond
	defer rec.close()
	soon, later := resolve.Principal{ID: "soon"}, resolve.Principal{ID: "later"}
	rec.add(soon, map[string]resolve.Value{"s": {Real: "real_soon_value", ExpiresAt: time.Now().Add(50 * time.Millisecond)}})
	rec.add(later, map[string]resolve.Value{
		"s1": {Real: "real_short_value", ExpiresAt: time.Now().Add(50 * time.Millisecond)},
		"s2": {Real: "real_long_value"},
	})
	if rec.masker(soon) == nil || rec.masker(later) == nil {
		t.Fatal("maskers should exist before expiry")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec.mu.Lock()
		_, soonKept := rec.principals[keyOf(soon)]
		pv := rec.principals[keyOf(later)]
		_, shortKept := pv.values["real_short_value"]
		maskerKept := pv.masker != nil
		rec.mu.Unlock()
		if !soonKept && !shortKept && !maskerKept {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after expiry, with no lookup: principal kept %v, value kept %v, masker kept %v", soonKept, shortKept, maskerKept)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The value that has not expired is still masked.
	if got := rec.masker(later).String(mask.Text, "real_long_value real_short_value"); got != "s2 real_short_value" {
		t.Fatalf("got %q", got)
	}
}

// close stops the sweep and drops everything.
func TestCloseStopsTheSweep(t *testing.T) {
	rec := newRecord(time.Now)
	rec.add(resolve.Principal{ID: "p"}, map[string]resolve.Value{"s": {Real: "real_value_p"}})
	rec.close()
	if len(rec.principals) != 0 || rec.masker(resolve.Principal{ID: "p"}) != nil {
		t.Fatal("close kept values")
	}
	rec.add(resolve.Principal{ID: "p"}, map[string]resolve.Value{"s": {Real: "real_value_p", ExpiresAt: time.Now().Add(time.Millisecond)}})
	if !rec.next.IsZero() {
		t.Fatal("a closed record armed its sweep")
	}
}
