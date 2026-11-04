package scope

import (
	"context"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
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
	if _, err := alice.Swapper(context.Background(), "tok_alice"); err != nil {
		t.Fatal(err)
	}
	if got := aliceAgain.Masker().String("x alice_real_1"); got != "x tok_alice" {
		t.Fatalf("another connection of alice got %q", got)
	}
	if aliceOtherSecret.Masker() != nil || bob.Masker() != nil {
		t.Fatal("alice's values reached another principal")
	}
	// A value refused for its host is still on record: it is alice's.
	if _, err := bob.Swapper(context.Background(), "tok_bob"); err == nil {
		t.Fatal("expected a refusal")
	}
	if got := bob.Masker().String("bob_real_22"); got != "tok_bob" {
		t.Fatalf("bob got %q", got)
	}
	now = now.Add(Retention + time.Second)
	if alice.Masker() != nil {
		t.Fatal("a value past its retention is still masked")
	}
	// Masking off: nothing is kept.
	off, _ := New(Config{Resolver: r, Detector: detector, Hosts: hosts})
	s := off.Session(resolve.Principal{ID: "alice"}, "api.example.com")
	_, _ = s.Swapper(context.Background(), "tok_alice")
	if s.Masker() != nil || s.Masking() {
		t.Fatal("masking is off")
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
	if rec.masker(p).String("real_value_0 ") != "real_value_0 " {
		t.Fatal("the oldest value should have been dropped")
	}
	for i := 0; i < MaxPrincipals+5; i++ {
		rec.add(resolve.Principal{ID: itoa(i)}, map[string]resolve.Value{"s": {Real: "real_value"}})
	}
	if len(rec.principals) > MaxPrincipals {
		t.Fatalf("%d principals kept", len(rec.principals))
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
