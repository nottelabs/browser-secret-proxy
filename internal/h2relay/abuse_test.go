package h2relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// splitBlock splits a client header block into a HEADERS frame with flags
// and CONTINUATION frames, the last one ending the block.
func splitBlock(id uint32, block []byte, flags uint8) []Frame {
	var out []Frame
	typ := FrameHeaders
	for first := true; first || len(block) > 0; first = false {
		n := min(len(block), defaultMaxFrame)
		f := Frame{Type: typ, Stream: id, Payload: block[:n]}
		if first {
			f.Flags = flags
		}
		block = block[n:]
		if len(block) == 0 {
			f.Flags |= FlagEndHeaders
		}
		out = append(out, f)
		typ = FrameContinuation
	}
	return out
}

// headerBytes counts the bytes of the header blocks the server receives
// until none came for quietFor, or the relay closed the connection.
func headerBytes(h *harness, quietFor time.Duration) <-chan int {
	done := make(chan int, 1)
	go func() {
		n := 0
		for {
			select {
			case f, ok := <-h.toServer:
				if !ok {
					done <- n
					return
				}
				if f.Type == FrameHeaders || f.Type == FrameContinuation {
					n += frameHeaderLength + len(f.Payload)
				}
			case <-time.After(quietFor):
				done <- n
				return
			}
		}
	}()
	return done
}

// A client may use no larger HPACK table than the relay told it, which is
// never above the 4096 bytes of the relay's upstream encoder. Before, the
// relay accepted a 64 KiB table from the first block, and references to one
// large entry went upstream as literals: about 40 bytes from the client
// became about 1 MiB to the destination, for every stream.
func TestClientTableLargerThanAdvertisedIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	big := hpack.HeaderField{Name: "x-a", Value: strings.Repeat("!", 64000)}
	h.clientEnc.SetMaxDynamicTableSizeLimit(65536)
	h.clientEnc.SetMaxDynamicTableSize(65536)
	counted := headerBytes(h, time.Second)
	clientBytes := 0
	frames := encodeFrames(append(splitBlock(1, h.clientBlock(request("GET", big)...), FlagEndStream), rstStream(1, errCodeCancel)))
	clientBytes += len(frames)
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	if _, err := h.client.Write(frames); err == nil {
		fields := request("GET")
		for range 15 {
			fields = append(fields, big)
		}
		for i := range 50 {
			id := uint32(3 + 2*i)
			b := encodeFrames([]Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(fields...)}, rstStream(id, errCodeCancel)})
			clientBytes += len(b)
			if _, err := h.client.Write(b); err != nil {
				break
			}
		}
	}
	serverBytes := <-counted
	if serverBytes > 2*clientBytes {
		t.Fatalf("client sent %d bytes of header blocks and resets; the server got %d bytes of header blocks", clientBytes, serverBytes)
	}
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "dynamic table size update too large") {
		t.Fatalf("relay error %v", err)
	}
}

// A server table size above 4096 reaches the client as 4096, and a client
// that fills that table sends the server about what it sent the relay: the
// relay's encoder table is as large, so it indexes the same entries.
func TestTableReferencesDoNotGrowUpstream(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(settingsFrame(Setting{ID: SettingHeaderTableSize, Value: 65536}))
	f := h.expect(h.toClient, "client", isType(FrameSettings))
	if got, err := ParseSettings(f.Payload); err != nil || len(got) != 1 || got[0] != (Setting{ID: SettingHeaderTableSize, Value: 4096}) {
		t.Fatalf("client settings %v, %v", got, err)
	}
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
	big := hpack.HeaderField{Name: "x-a", Value: strings.Repeat("!", 3900)}
	fields := request("GET")
	for range 200 {
		fields = append(fields, big)
	}
	counted := headerBytes(h, 500*time.Millisecond)
	clientBytes := 0
	for i := range 20 {
		id := uint32(1 + 2*i)
		b := encodeFrames(splitBlock(id, h.clientBlock(fields...), FlagEndStream))
		clientBytes += len(b)
		h.write(h.client, b)
	}
	if serverBytes := <-counted; serverBytes > 2*clientBytes {
		t.Fatalf("client sent %d bytes of header blocks; the server got %d", clientBytes, serverBytes)
	}
}

// When the destination lowers the table size, the relay's decoder keeps
// to the lower size from the client's ACK on. A client that acknowledges
// but keeps referring to entries past it ends the connection; its
// references are never sent upstream as literals.
func TestLoweredTableSizeAppliesOnTheClientsAck(t *testing.T) {
	h := newHarness(t, nil)
	big := hpack.HeaderField{Name: "x-a", Value: strings.Repeat("!", 3900)}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET", big)...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	h.serverSend(settingsFrame(Setting{ID: SettingHeaderTableSize, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
	fields := request("GET")
	for range 200 {
		fields = append(fields, big)
	}
	counted := headerBytes(h, 500*time.Millisecond)
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = h.client.Write(encodeFrames([]Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(fields...)}}))
	if serverBytes := <-counted; serverBytes > 1000 {
		t.Fatalf("the server got %d bytes of header blocks", serverBytes)
	}
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "decode client header block") {
		t.Fatalf("relay error %v", err)
	}
}

// A client that follows the lowered size, and later a raised one, keeps
// working.
func TestTableSizeChangesFollowTheDestination(t *testing.T) {
	h := newHarness(t, nil)
	get := func(id uint32, extra ...hpack.HeaderField) {
		h.t.Helper()
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET", extra...)...)})
		if f := h.expect(h.toServer, "server", isType(FrameHeaders)); f.Stream != id {
			t.Fatalf("request reached the server on stream %d, want %d", f.Stream, id)
		}
	}
	big := hpack.HeaderField{Name: "x-a", Value: strings.Repeat("!", 3900)}
	get(1, big)
	for i, size := range []uint32{0, 4096} {
		h.serverSend(settingsFrame(Setting{ID: SettingHeaderTableSize, Value: size}))
		h.expect(h.toClient, "client", isType(FrameSettings))
		h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
		h.clientEnc.SetMaxDynamicTableSizeLimit(size)
		h.clientEnc.SetMaxDynamicTableSize(size)
		id := uint32(3 + 4*i)
		get(id, big)
		get(id+2, big)
	}
	h.r.serverMu.Lock()
	size := h.r.enc.MaxDynamicTableSize()
	h.r.serverMu.Unlock()
	if size != 4096 {
		t.Fatalf("relay's upstream table is %d bytes, want 4096 again", size)
	}
}

// countingResolver counts the lookups that reach it and the ones canceled
// before their answer, which takes 200 ms, as an http resolver might.
type countingResolver struct{ calls, canceled atomic.Int64 }

func (c *countingResolver) StandIns(resolve.Principal) []string { return []string{"tok_a"} }

func (c *countingResolver) Resolve(ctx context.Context, _ resolve.Request) (resolve.Result, error) {
	c.calls.Add(1)
	select {
	case <-ctx.Done():
		c.canceled.Add(1)
		return resolve.Result{}, ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}
	return resolve.Result{Values: map[string]resolve.Value{"tok_a": {Real: "real_a"}}}, nil
}

// HEADERS followed at once by RST_STREAM, repeated (rapid reset,
// CVE-2023-44487). Each reset frees a stream slot and cancels the stream's
// lookup, so before, every stream reached the destination and every
// stand-in a lookup, at the client's frame rate. Past twice MaxStreams
// resets the connection now ends with ENHANCE_YOUR_CALM.
func TestRapidResetEndsTheConnection(t *testing.T) {
	c := &countingResolver{}
	h := newHarness(t, func(o *Options) {
		o.Session = scopetest.Session(t, o.Hosts, c, resolve.Principal{ID: "alice"})
	})
	limit := 2 * h.r.opts.MaxStreams
	var upstreamHeaders, goaways atomic.Int64
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for f := range h.toServer {
			if f.Type == FrameHeaders {
				upstreamHeaders.Add(1)
			}
		}
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for f := range h.toClient {
			if isGoAway(errCodeCalm)(f) {
				goaways.Add(1)
			}
		}
	}()
	plain := request("GET")
	withStandIn := request("GET")
	withStandIn[3].Value = "/?k=tok_a"
	_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
	for i := range 3000 {
		id := uint32(1 + 2*i)
		fields := plain
		if i%2 == 1 {
			fields = withStandIn
		}
		b := encodeFrames([]Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(fields...)}, rstStream(id, errCodeCancel)})
		if _, err := h.client.Write(b); err != nil {
			break
		}
	}
	if err := h.result(); !errors.Is(err, errTooManyResets) {
		t.Fatalf("relay error %v, want %v", err, errTooManyResets)
	}
	<-serverDone
	<-clientDone
	if goaways.Load() != 1 {
		t.Fatalf("client got %d GOAWAY ENHANCE_YOUR_CALM frames, want 1", goaways.Load())
	}
	if n := upstreamHeaders.Load(); n > int64(limit) {
		t.Fatalf("server got %d requests, want at most %d", n, limit)
	}
	if n := c.calls.Load(); n > int64(limit) {
		t.Fatalf("resolver got %d lookups, want at most %d", n, limit)
	}
}

// Resets are counted over 10-second periods: up to the limit in each is
// fine, and the count starts again with the next period.
func TestResetsAreCountedPerPeriod(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	h := newHarnessWith(t, func(o *Options) { o.MaxStreams = 4 }, func(r *relay) {
		r.now = func() time.Time { return time.Unix(0, now.Load()) }
	})
	id := uint32(1)
	resetOne := func() {
		h.t.Helper()
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)})
		h.expect(h.toServer, "server", isType(FrameHeaders))
		h.clientSend(rstStream(id, errCodeCancel))
		h.expect(h.toServer, "server", isType(FrameRSTStream))
		id += 2
	}
	for range 8 {
		resetOne()
	}
	now.Add(int64(resetWindow))
	for range 8 {
		resetOne()
	}
	h.quiet(h.toClient, 50*time.Millisecond, isType(FrameGoAway))
	// The ninth in one period ends the connection.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(request("GET")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	h.clientSend(rstStream(id, errCodeCancel))
	h.expect(h.toClient, "client", isGoAway(errCodeCalm))
	if err := h.result(); !errors.Is(err, errTooManyResets) {
		t.Fatalf("relay error %v, want %v", err, errTooManyResets)
	}
}

// A stream the relay drops for a client's WINDOW_UPDATE past 2^31-1, which
// also cancels its lookup, counts as a reset.
func TestWindowOverflowDropsCountAsResets(t *testing.T) {
	c := &countingResolver{}
	h := newHarness(t, func(o *Options) {
		o.MaxStreams = 4
		o.Session = scopetest.Session(t, o.Hosts, c, resolve.Principal{ID: "alice"})
	})
	withStandIn := request("GET")
	withStandIn[3].Value = "/?k=tok_a"
	for i := range 9 {
		id := uint32(1 + 2*i)
		h.clientSend(
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(withStandIn...)},
			windowUpdate(id, maxWindow), windowUpdate(id, maxWindow),
		)
		if i < 8 {
			h.expect(h.toClient, "client", isRefusal(id))
		}
	}
	h.expect(h.toClient, "client", isGoAway(errCodeCalm))
	if err := h.result(); !errors.Is(err, errTooManyResets) {
		t.Fatalf("relay error %v, want %v", err, errTooManyResets)
	}
}

// A stream the relay drops for the client's own frames cancels its lookup
// as a reset does, so it counts as one: trailers or data past the buffer
// budget, or a frame after the client ended the stream. A client that keeps
// the budget nearly full must not bypass the reset limit with uploads it
// makes the relay refuse. CONNECT is refused before a stream is opened, so
// these requests use ordinary POST uploads.
func TestRelayDropsCountAsResets(t *testing.T) {
	fill := bigHeaders(100 << 10)
	upload := request("POST")
	upload[3].Value = "/?k=tok_a"
	for name, after := range map[string]func(h *harness, id uint32) []Frame{
		"trailers": func(h *harness, id uint32) []Frame {
			trailers := []hpack.HeaderField{{Name: "x-t", Value: strings.Repeat("b", 2000)}}
			return []Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(trailers...)}}
		},
		"data": func(_ *harness, id uint32) []Frame {
			return []Frame{{Type: FrameData, Stream: id, Payload: bytes.Repeat([]byte("b"), 2000)}}
		},
		"frame after the end": func(_ *harness, id uint32) []Frame {
			return []Frame{{Type: FrameData, Flags: FlagEndStream, Stream: id}, {Type: FrameData, Stream: id}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := &countingResolver{}
			h := newHarness(t, func(o *Options) {
				o.MaxStreams = 4
				o.MaxBuffered = int(fieldsSize(fill)+fieldsSize(upload)) + 1000
				o.Session = scopetest.Session(t, o.Hosts, c, resolve.Principal{ID: "alice"})
			})
			limit := 2 * h.r.opts.MaxStreams
			h.write(h.client, encodeFrames(splitBlock(1, h.clientBlock(fill...), 0)))
			go func() {
				for range h.toServer {
				}
			}()
			goaway := make(chan struct{})
			go func() {
				for f := range h.toClient {
					if isGoAway(errCodeCalm)(f) {
						close(goaway)
						return
					}
				}
			}()
			_ = h.client.SetWriteDeadline(time.Now().Add(waitFor))
			for i := range 4 * limit {
				id := uint32(3 + 2*i)
				frames := append([]Frame{{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: id, Payload: h.clientBlock(upload...)}}, after(h, id)...)
				if _, err := h.client.Write(encodeFrames(frames)); err != nil {
					break
				}
			}
			if err := h.result(); !errors.Is(err, errTooManyResets) {
				t.Fatalf("relay error %v, want %v", err, errTooManyResets)
			}
			<-goaway
			if n := c.calls.Load(); n > int64(limit)+1 {
				t.Fatalf("resolver got %d lookups, want at most %d", n, limit+1)
			}
		})
	}
}

// bigHeaders is a POST with about size bytes of headers, sent as literals
// that are never indexed so each stream really holds its own.
func bigHeaders(size int) []hpack.HeaderField {
	fields := request("POST")
	for j := 0; size > 0; j++ {
		n := min(size, 60000)
		fields = append(fields, hpack.HeaderField{Name: fmt.Sprintf("x-%d", j), Value: strings.Repeat("a", n), Sensitive: true})
		size -= n
	}
	return fields
}

// The header lists of buffering streams count toward MaxBuffered. Before,
// 200 bodiless POSTs with about 1 MiB of headers each held about 200 MiB on
// a connection whose budget was 1 MiB, and none was refused.
func TestHeldHeaderListsShareTheBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 1 << 20 })
	fields := bigHeaders(300 << 10)
	size := fieldsSize(fields)
	fit := (1 << 20) / size
	for i := range fit + 3 {
		id := uint32(1 + 2*i)
		h.write(h.client, encodeFrames(splitBlock(id, h.clientBlock(fields...), 0)))
		if i >= fit {
			h.expect(h.toClient, "client", isRefusal(id))
		}
	}
	if streams, _, held := h.state(); int64(streams) != fit || held != fit*size {
		t.Fatalf("relay holds %d streams and %d bytes, want %d and %d", streams, held, fit, fit*size)
	}
	// Once a request went upstream, its headers no longer count.
	for i := range fit {
		h.clientSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: uint32(1 + 2*i)})
		h.expect(h.toServer, "server", isType(FrameHeaders))
	}
	h.released("sending the requests")
}

// released waits until the relay holds no request byte.
func (h *harness) released(what string) {
	h.t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		_, _, held := h.state()
		if held == 0 {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("after %s the relay holds %d bytes", what, held)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A request waiting for a slot under the server's concurrency limit holds
// its header list, so it counts toward MaxBuffered too.
func TestQueuedRequestsShareTheBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 1 << 20 })
	h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	fields := bigHeaders(300 << 10)
	fields[0].Value = "GET"
	size := fieldsSize(fields)
	fit := (1 << 20) / size
	for i := range fit + 1 {
		id := uint32(1 + 2*i)
		h.write(h.client, encodeFrames(splitBlock(id, h.clientBlock(fields...), FlagEndStream)))
	}
	h.expect(h.toClient, "client", isRefusal(uint32(1+2*fit)))
	if _, _, held := h.state(); held != fit*size {
		t.Fatalf("relay holds %d bytes, want %d", held, fit*size)
	}
	// Slots open: the queued requests go upstream and release their bytes.
	h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 100}))
	for range fit {
		h.expect(h.toServer, "server", isType(FrameHeaders))
	}
	if _, _, held := h.state(); held != 0 {
		t.Fatalf("relay still holds %d bytes", held)
	}
}

// Trailers held with a buffered body count toward MaxBuffered: trailers
// that would pass it refuse the request.
func TestHeldTrailersShareTheBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 512 << 10 })
	post := request("POST")
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(post...)})
	trailers := bigHeaders(600 << 10)[4:]
	h.write(h.client, encodeFrames(splitBlock(1, h.clientBlock(trailers...), FlagEndStream)))
	h.expect(h.toClient, "client", isRefusal(1))
	h.settle("refusing the trailers")
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
	// Trailers within the budget go upstream, and are released after.
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(post...)})
	small := []hpack.HeaderField{{Name: "x-trailer", Value: "tok_standin"}}
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: h.clientBlock(small...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	if f.Flags&FlagEndStream == 0 {
		t.Fatalf("trailers without END_STREAM")
	}
	h.released("sending the trailers")
}

// A swap grows a held header list in place, by as much as the real values
// are longer than their stand-ins: the swapped list counts toward
// MaxBuffered instead. Before, queued requests whose swapped headers were
// 100 times longer than what the client sent were still counted at the
// size it sent.
func TestSwappedHeaderListsShareTheBudget(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 100 << 10; expandingSession(t, o) })
	h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 0}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	get := request("GET", hpack.HeaderField{Name: "x-t", Value: strings.Repeat("t1", 100)})
	swapped := request("GET", hpack.HeaderField{Name: "x-t", Value: strings.Repeat(strings.Repeat("R", 200), 100)})
	size := fieldsSize(swapped)
	fit := (100 << 10) / size
	for i := range fit + 1 {
		id := uint32(1 + 2*i)
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: id, Payload: h.clientBlock(get...)})
	}
	h.expect(h.toClient, "client", isRefusal(uint32(1+2*fit)))
	if _, _, held := h.state(); held != fit*size {
		t.Fatalf("relay holds %d bytes, want the %d of %d swapped lists", held, fit*size, fit)
	}
	h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 100}))
	for range fit {
		h.expect(h.toServer, "server", isType(FrameHeaders))
	}
	h.released("sending the requests")
}

// The same for the headers and trailers of a buffered request, swapped
// with its body: a swap that passes the budget ends the request before it
// goes upstream, and nothing of it stays held. CONNECT tunnels are refused,
// so trailers on an intercepted connection are tested on ordinary uploads.
func TestSwapsPastTheBudgetEndTheRequest(t *testing.T) {
	standIns := hpack.HeaderField{Name: "x-t", Value: strings.Repeat("t1", 100)}
	t.Run("buffered", func(t *testing.T) {
		h := newHarness(t, func(o *Options) { o.MaxBuffered = 10000; expandingSession(t, o) })
		h.clientSend(
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST", standIns)...)},
			Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("body")},
		)
		h.expect(h.toClient, "client", isRefusal(1))
		h.settle("refusing the request")
		h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
	})
	t.Run("buffered trailers", func(t *testing.T) {
		h := newHarness(t, func(o *Options) { o.MaxBuffered = 10000; expandingSession(t, o) })
		h.clientSend(
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
			Frame{Type: FrameData, Stream: 1, Payload: []byte("body")},
			Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(standIns)},
		)
		h.expect(h.toClient, "client", isRefusal(1))
		h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
		h.released("refusing the request with expanded trailers")
	})
}
