package h2relay

import (
	"bytes"
	"encoding/binary"
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

// A request refused before its body arrives, here an extended CONNECT
// refused as a tunnel, also tells the client to stop sending.
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

// A request whose fields a server could read as naming another host than
// the CONNECT one, or whose framing it could read differently from the
// relay, is malformed (RFC 9113 8.2.1, 8.3.1): it is answered 502, with or
// without a stand-in, and nothing of it reaches the server. An uppercase
// Content-Length would keep its length after a body swap.
func TestMalformedRequestHeadsAreAnswered502(t *testing.T) {
	withPath := func(path string, fields []hpack.HeaderField) []hpack.HeaderField {
		fields[3].Value = path
		return fields
	}
	cases := map[string]struct {
		fields []hpack.HeaderField
		body   string
	}{
		"host naming another host":              {fields: withPath("/?k=tok_standin", request("GET", hpack.HeaderField{Name: "host", Value: "evil.test"}))},
		"host naming another host, no stand-in": {fields: request("GET", hpack.HeaderField{Name: "host", Value: "evil.test"})},
		"host with another port":                {fields: request("GET", hpack.HeaderField{Name: "host", Value: "allowed.test:8443"})},
		"userinfo in :authority": {fields: []hpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "allowed.test:443@evil.test"},
			{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/?k=tok_standin"},
		}},
		"a second :authority": {fields: []hpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "evil.test"}, {Name: ":authority", Value: "allowed.test"},
			{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/?k=tok_standin"},
		}},
		"a second host":        {fields: request("GET", hpack.HeaderField{Name: "host", Value: "allowed.test"}, hpack.HeaderField{Name: "host", Value: "allowed.test"})},
		"uppercase field name": {fields: request("GET", hpack.HeaderField{Name: "X-Token", Value: "tok_standin"})},
		"uppercase Content-Length": {
			fields: request("POST",
				hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"},
				hpack.HeaderField{Name: "Content-Length", Value: "13"}),
			body: "k=tok_standin",
		},
		"NUL in a value":                {fields: request("GET", hpack.HeaderField{Name: "x-token", Value: "tok_standin\x00"})},
		"CR in a value":                 {fields: request("GET", hpack.HeaderField{Name: "x-token", Value: "\rtok_standin"})},
		"LF in a value, no stand-in":    {fields: request("GET", hpack.HeaderField{Name: "x-a", Value: "a\nhost: evil.test"})},
		"leading space in a value":      {fields: request("GET", hpack.HeaderField{Name: "x-token", Value: " tok_standin"})},
		"trailing tab in a value":       {fields: request("GET", hpack.HeaderField{Name: "x-token", Value: "tok_standin\t"})},
		"CRLF in a pseudo-header value": {fields: withPath("/?k=tok_standin\r\nx-a: 1", request("GET"))},
		"malformed value after an empty name": {fields: request("GET",
			hpack.HeaderField{Name: "", Value: "a\nb"},
			hpack.HeaderField{Name: "x-token", Value: "tok_standin\r\nx-a: 1"})},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			if c.body == "" {
				h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(c.fields...)})
			} else {
				h.clientSend(
					Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(c.fields...)},
					Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte(c.body)},
				)
			}
			h.expect(h.toClient, "client", isBadGateway(1))
			h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
		})
	}
}

// Every CONNECT, an extended CONNECT for a WebSocket (RFC 8441) included, is
// answered 502 before any swap and never sent: nothing in the server's 2xx
// to it shows whether a tunnel or a catch-all handler answered, and either
// would reach the client unmasked with the values swapped into the request.
// So is a :protocol on another method, which a server could still take for
// a tunnel, and a second :method, which a server could read instead of the
// one the relay saw. The relay never tells the client that the server
// supports extended CONNECT (TestServerSettingsNeverEnableExtendedConnect),
// so a browser sends none: it opens its WebSockets over HTTP/1.1.
func TestTunnelRequestsAreAnswered502(t *testing.T) {
	protocol := func(value string) hpack.HeaderField { return hpack.HeaderField{Name: ":protocol", Value: value} }
	token := hpack.HeaderField{Name: "x-token", Value: "tok_standin"}
	for name, fields := range map[string][]hpack.HeaderField{
		"plain CONNECT": {
			{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "allowed.test"}, token,
		},
		"plain CONNECT with a path":        request("CONNECT", token),
		"extended CONNECT for websocket":   request("CONNECT", protocol("websocket"), token),
		"extended CONNECT for WebSocket":   request("CONNECT", protocol("WebSocket"), token),
		"extended CONNECT for connect-udp": request("CONNECT", protocol("connect-udp"), token),
		"two :protocol fields":             request("CONNECT", protocol("websocket"), protocol("connect-ip")),
		"lower-case connect":               request("connect", protocol("websocket")),
		":protocol on a GET":               request("GET", protocol("websocket"), token),
		"a GET that names CONNECT too": append([]hpack.HeaderField{{Name: ":method", Value: "GET"}},
			request("CONNECT", protocol("websocket"), token)...),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(fields...)})
			h.expect(h.toClient, "client", isBadGateway(1))
			h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })
		})
	}
}

// Trailers with a malformed value (RFC 9113 8.2.1) stop the request: a
// buffered one is answered 502 and never reaches the server, a streamed one
// is reset on both sides. The streaming harness disables swapping explicitly:
// CONNECT tunnels are refused.
func TestMalformedTrailerValuesStopTheRequest(t *testing.T) {
	cases := map[string][]hpack.HeaderField{
		"NUL in a value": {{Name: "x-token", Value: "tok_standin\x00"}},
		"malformed value after an empty name": {
			{Name: "", Value: "a\nb"},
			{Name: "x-token", Value: "tok_standin\r\nx-a: 1"},
		},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.clientSend(
				Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)},
				Frame{Type: FrameData, Stream: 1, Payload: []byte("plain")},
				Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(bad...)},
			)
			h.expect(h.toClient, "client", isBadGateway(1))
			h.quiet(h.toServer, 50*time.Millisecond, func(f Frame) bool { return f.Type == FrameHeaders || f.Type == FrameData })

			streamed := newHarness(t, streaming)
			streamed.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 3, Payload: streamed.clientBlock(request("POST")...)})
			opened := streamed.expect(streamed.toServer, "server", isType(FrameHeaders))
			streamed.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 3, Payload: streamed.clientBlock(bad...)})
			streamed.expect(streamed.toClient, "client", func(f Frame) bool {
				return f.Type == FrameRSTStream && f.Stream == 3 && binary.BigEndian.Uint32(f.Payload) == errCodeProtocol
			})
			streamed.expect(streamed.toServer, "server", func(f Frame) bool {
				return f.Type == FrameRSTStream && f.Stream == opened.Stream
			})
			h.settle("malformed trailers")
			streamed.settle("malformed streamed trailers")
		})
	}
}

// A host that agrees with :authority is not refused.
func TestHostAgreeingWithAuthorityIsSwapped(t *testing.T) {
	h := newHarness(t, nil)
	fields := request("GET", hpack.HeaderField{Name: "host", Value: "Allowed.Test"})
	fields[3].Value = "/?k=tok_standin"
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
		if field.Name == ":path" && field.Value != "/?k=real_value" {
			t.Fatalf(":path %q", field.Value)
		}
	}
}
