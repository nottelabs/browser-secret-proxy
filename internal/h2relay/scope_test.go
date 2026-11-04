package h2relay

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// scoped gives the relay one stand-in, tok_a, whose value may go only to
// pay.test, and one, tok_old, that has expired.
func scoped(t *testing.T) func(*Options) { return scopedTo(t, scopetest.Host) }

// scopedTo is scoped on a connection opened to host.
func scopedTo(t *testing.T, host string) func(*Options) {
	return func(o *Options) {
		r := scopetest.Resolver{Known: []string{"tok_a", "tok_old"}, Fn: func(resolve.Request) (resolve.Result, error) {
			return resolve.Result{Values: map[string]resolve.Value{
				"tok_a":   {Real: "real_a", Hosts: []string{"pay.test"}},
				"tok_old": {Real: "real_old", ExpiresAt: time.Now().Add(-time.Minute)},
			}}, nil
		}}
		o.Session = scopetest.SessionTo(t, o.Hosts, r, resolve.Principal{ID: "alice"}, host)
	}
}

func isBadGateway(stream uint32) func(Frame) bool {
	return func(f Frame) bool {
		return f.Type == FrameHeaders && f.Stream == stream && f.Flags&FlagEndStream != 0 && bytes.Equal(f.Payload, badGatewayBlock)
	}
}

// Requests whose values may not go to their authority, or have expired, are
// answered 502 by the relay and never reach the server, with or without a
// body; a request in scope on the same connection goes through.
func TestOutOfScopeRequestsAreAnswered502(t *testing.T) {
	h := newHarness(t, scoped(t))
	expired := request("GET")
	expired[3].Value = "/?k=tok_old"
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(expired...)})
	h.expect(h.toClient, "client", isBadGateway(1))

	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 3, Payload: []byte("card=tok_a")},
	)
	h.expect(h.toClient, "client", isBadGateway(3))

	// A value refused in the trailers stops the whole buffered request.
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 5, Payload: h.clientBlock(request("POST")...)},
		Frame{Type: FrameData, Stream: 5, Payload: []byte("plain")},
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 5,
			Payload: h.clientBlock(hpack.HeaderField{Name: "x-token", Value: "tok_old"})},
	)
	h.expect(h.toClient, "client", isBadGateway(5))
	h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
	h.settle("refused requests")

	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 7, Payload: h.clientBlock(request("GET")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
}

// An extended CONNECT is not buffered: its refusal also tells the client to
// stop sending.
func TestRefusedStreamingRequestIsReset(t *testing.T) {
	h := newHarness(t, scoped(t))
	fields := request("CONNECT", hpack.HeaderField{Name: ":protocol", Value: "websocket"}, hpack.HeaderField{Name: "authorization", Value: "tok_old"})
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(fields...)})
	h.expect(h.toClient, "client", isBadGateway(1))
	if f := h.next(h.toClient, "client"); f.Type != FrameRSTStream || f.Stream != 1 {
		t.Fatalf("got frame type %d on stream %d, want RST_STREAM on 1", f.Type, f.Stream)
	}
	h.quiet(h.toServer, 50*time.Millisecond, isType(FrameHeaders))
}

// The value goes through on the authority it allows.
func TestInScopeValueIsSwapped(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		hosts, err := hostmatch.New([]string{"allowed.test", "pay.test"})
		if err != nil {
			t.Fatal(err)
		}
		o.Hosts = hosts
		scopedTo(t, "pay.test")(o)
	})
	fields := request("GET")
	fields[1].Value = "pay.test"
	fields[3].Value = "/?card=tok_a"
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(fields...)})
	f := h.expect(h.toServer, "server", isType(FrameHeaders))
	_, fragment, err := HeadersPayload(f.Flags, f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hpack.NewDecoder(4096, nil).DecodeFull(fragment)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range got {
		if field.Name == ":path" && field.Value != "/?card=real_a" {
			t.Fatalf(":path %q", field.Value)
		}
	}
}
