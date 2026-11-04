// Package scopetest builds scope sessions for tests.
package scopetest

import (
	"context"
	"testing"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
)

// Static returns a session, for the empty principal, over a fixed map of
// stand-in to real value that may go to any host on hosts.
func Static(t testing.TB, hosts *hostmatch.List, values map[string]string) *scope.Session {
	t.Helper()
	resolver, err := resolve.NewStatic(values)
	if err != nil {
		t.Fatal(err)
	}
	return Session(t, hosts, resolver, resolve.Principal{})
}

// Session returns a session for principal over resolver, whose stand-ins
// it must know in advance (resolve.KnownStandIns).
func Session(t testing.TB, hosts *hostmatch.List, resolver resolve.Resolver, principal resolve.Principal) *scope.Session {
	t.Helper()
	detector, err := resolve.NewDetector(resolver, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(scope.Config{Resolver: resolver, Detector: detector, Hosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	return s.Session(principal)
}

// Resolver is a resolver whose stand-ins are Known in advance and whose
// answers come from Fn.
type Resolver struct {
	Known []string
	Fn    func(resolve.Request) (resolve.Result, error)
}

// Resolve calls Fn.
func (r Resolver) Resolve(_ context.Context, req resolve.Request) (resolve.Result, error) {
	return r.Fn(req)
}

// StandIns returns Known, whoever asks.
func (r Resolver) StandIns(resolve.Principal) []string { return r.Known }

// PerPrincipal answers each principal ID from its own map of stand-in to
// value, and nothing to an unknown principal.
func PerPrincipal(values map[string]map[string]resolve.Value) Resolver {
	var known []string
	for _, m := range values {
		for standIn := range m {
			known = append(known, standIn)
		}
	}
	return Resolver{Known: known, Fn: func(req resolve.Request) (resolve.Result, error) {
		out := resolve.Result{Values: map[string]resolve.Value{}}
		for _, standIn := range req.StandIns {
			if v, ok := values[req.Principal.ID][standIn]; ok {
				out.Values[standIn] = v
			}
		}
		return out, nil
	}}
}

// Masked returns a session for principal over resolver with masking on,
// whose record already holds every value the resolver gives for known: as
// if a request had carried those stand-ins to host.
func Masked(t testing.TB, hosts *hostmatch.List, resolver resolve.Resolver, principal resolve.Principal, host string, known ...string) *scope.Session {
	t.Helper()
	detector, err := resolve.NewDetector(resolver, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := scope.New(scope.Config{Resolver: resolver, Detector: detector, Hosts: hosts, Mask: true})
	if err != nil {
		t.Fatal(err)
	}
	session := s.Session(principal)
	if len(known) > 0 {
		if _, err := session.Swapper(context.Background(), host, known...); err != nil {
			t.Fatal(err)
		}
	}
	return session
}
