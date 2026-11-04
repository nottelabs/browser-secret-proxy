package h2relay

import (
	"context"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// DefaultMaxLookups is the default bound on resolver lookups in flight on
// one connection.
const DefaultMaxLookups = 16

// Resolver lookups that can wait (the http resolver, up to its timeout) run
// off clientLoop, so a slow one holds back only its own stream. Lookups
// answered from memory (resolve.Local) are resolved in line, as before. clientLoop does the local
// part of a request's resolution itself (scope.Session.Prepare: the
// resolver's snapshot and finding the stand-ins). A request with no stand-in
// to resolve is opened upstream at once, in the order the client sent it, as
// before. A request that needs a lookup is published as a stream with no
// upstream ID yet, and a goroutine resolves it, then opens it upstream, or
// refuses it with 502. Upstream stream IDs are assigned when a stream is
// opened (openStream, under serverMu with the HEADERS write), so a stream
// opened after its lookup takes the next ID then: ordering never makes a
// stream wait for another's lookup. The upstream order of requests that
// needed a lookup follows when their lookups end, not the client's order;
// requests that needed none keep the client's order among themselves.
//
// A stream dropped while its lookup is in flight (the client's RST_STREAM,
// the server's GOAWAY, a buffer limit) cancels the lookup, and so does the
// end of the relay, which waits for every lookup goroutine.

// resolveLookup runs done with the answer to a published stream's lookup:
// in line for a lookup answered from memory (resolve.Local: the file and
// sealed modes), which keeps the client's request order and so the
// connection's fingerprint exactly as before, and otherwise on a goroutine
// of its own (lookupLocked). It returns done's error when done ran in line.
func (r *relay) resolveLookup(s *stream, lookup *scope.Lookup, done func(*swap.Swapper, error) error) error {
	if lookup.Local() {
		return done(lookup.Swapper(r.ctx))
	}
	r.mu.Lock()
	r.lookupLocked(s, lookup, done)
	r.mu.Unlock()
	return nil
}

// lookupLocked starts the lookup of a published stream on its own
// goroutine. Once it has an answer, and only if the stream is still current
// and the lookup was not canceled, done runs on that goroutine with the
// result; an error done returns is an I/O error that ends the connection.
func (r *relay) lookupLocked(s *stream, lookup *scope.Lookup, done func(*swap.Swapper, error) error) {
	if s.lookupCtx == nil {
		s.lookupCtx, s.lookupCancel = context.WithCancel(r.ctx)
	}
	ctx := s.lookupCtx
	r.lookups.Add(1)
	go func() {
		defer r.lookups.Done()
		select {
		case r.lookupSlots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		swapper, err := lookup.Swapper(ctx)
		<-r.lookupSlots
		r.mu.Lock()
		current := r.streams[s.clientID] == s && ctx.Err() == nil
		r.mu.Unlock()
		if !current {
			return // dropped, or the relay ended: nothing more to do
		}
		if err := done(swapper, err); err != nil {
			select {
			case r.asyncErrs <- err:
			default:
			}
		}
	}()
}

// refuseLookup answers a stream whose lookup refused the request with 502,
// after dropping it, unless it was dropped meanwhile.
func (r *relay) refuseLookup(s *stream, cause error) error {
	r.mu.Lock()
	current := r.streams[s.clientID] == s
	ended := s.clientEnded
	if current {
		r.dropLocked(s)
	}
	r.mu.Unlock()
	if !current {
		return nil
	}
	return r.badGateway(s.clientID, s.authority, ended, cause)
}

// openResolved opens a stream that is not buffered (no body, or an extended
// CONNECT) once its lookup answered.
func (r *relay) openResolved(s *stream, fields []hpack.HeaderField, priority *Priority, endStream bool, swapper *swap.Swapper, err error) error {
	if err != nil {
		return r.refuseLookup(s, err)
	}
	if swapper == nil {
		return r.open(s, fields, priority, endStream)
	}
	if err := r.swapFields(swapper, fields, s.authority); err != nil {
		// Nothing went upstream, so the client may retry elsewhere.
		r.opts.Logger.Error("refusing a request whose swapped headers cannot be sent", "stream", s.clientID, "error", err)
		return r.abort(s, errCodeRefusedStream)
	}
	return r.open(s, fields, priority, endStream)
}
