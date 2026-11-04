package h2relay

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// Frame types the server may send that the relay drops (RFC 7838, RFC 8336,
// RFC 9218).
const (
	frameAltSvc uint8 = 0xa
	frameOrigin uint8 = 0xc
)

// eachMode runs test with masking off and on.
func eachMode(t *testing.T, test func(t *testing.T, mutate func(*Options))) {
	t.Helper()
	t.Run("plain", func(t *testing.T) { test(t, nil) })
	t.Run("masked", func(t *testing.T) { test(t, masking(t, false)) })
}

func ping(flags uint8, payload string) Frame {
	return Frame{Type: FramePing, Flags: flags, Payload: []byte(payload)}
}

func isPing(flags uint8, payload string) func(Frame) bool {
	return func(f Frame) bool {
		return f.Type == FramePing && f.Flags == flags && string(f.Payload) == payload
	}
}

// untilSettingsAck returns the frames the client gets up to the server's
// SETTINGS ACK, which the test sends last: the relay handled every frame the
// server sent before it.
func (h *harness) untilSettingsAck() []Frame {
	h.t.Helper()
	h.serverSend(Frame{Type: FrameSettings, Flags: FlagAck})
	var frames []Frame
	for {
		f := h.next(h.toClient, "client")
		if f.Type == FrameSettings && f.Flags&FlagAck != 0 {
			return frames
		}
		frames = append(frames, f)
	}
}

// The server's GOAWAY reaches the client with its error code but without its
// debug data, which can echo a real value (sec-masking-8).
func TestServerGoAwayDebugDataIsDropped(t *testing.T) {
	eachMode(t, func(t *testing.T, mutate func(*Options)) {
		h := newHarness(t, mutate)
		payload := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), errCodeCalm)
		h.serverSend(Frame{Type: FrameGoAway, Payload: append(payload, "bad token "+realToken...)})
		f := h.expect(h.toClient, "client", isType(FrameGoAway))
		if !bytes.Equal(f.Payload, payload) {
			t.Fatalf("client GOAWAY payload %q, want %q", f.Payload, payload)
		}
	})
}

// Extension and unknown frames from the server never reach the client: an
// ALTSVC or ORIGIN frame would tell the browser where else to go or which
// origins this connection serves, a PRIORITY_UPDATE from a server is a
// connection error for the client (RFC 9218 7.1), and their payloads are
// neither masked nor checked. One on a stream would also carry the server's
// stream ID, which can be another client stream's.
func TestServerExtensionFramesAreDropped(t *testing.T) {
	eachMode(t, func(t *testing.T, mutate func(*Options)) {
		h := newHarness(t, mutate)
		// Client stream 1 is buffering, so client stream 3 goes upstream as 1.
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST")...)})
		serverID := get(h, 3)
		if serverID != 1 {
			t.Fatalf("client stream 3 went upstream on %d, want 1", serverID)
		}
		origin := []byte("\x00\x15https://evil.test:443")
		h.serverSend(
			Frame{Type: frameAltSvc, Payload: append([]byte{0, 12}, `allowed.testh2="evil.test:443"`...)},
			Frame{Type: frameOrigin, Payload: origin},
			Frame{Type: FramePriorityUpdate, Payload: append(binary.BigEndian.AppendUint32(nil, serverID), "u=0"...)},
			Frame{Type: unknownType, Payload: []byte(realToken)},
			Frame{Type: unknownType, Stream: serverID, Payload: []byte(realToken)},
		)
		for _, f := range h.untilSettingsAck() {
			switch f.Type {
			case frameAltSvc, frameOrigin, FramePriorityUpdate, unknownType:
				t.Errorf("client got a frame of type %#x on stream %d: %q", f.Type, f.Stream, f.Payload)
			}
		}
	})
}

// The relay answers the server's PING itself; the client never sees the
// server's opaque PING data.
func TestServerPingIsAnsweredByTheRelay(t *testing.T) {
	eachMode(t, func(t *testing.T, mutate func(*Options)) {
		h := newHarness(t, mutate)
		h.serverSend(ping(0, "srvping1"))
		h.expect(h.toServer, "server", isPing(FlagAck, "srvping1"))
		for _, f := range h.untilSettingsAck() {
			if f.Type == FramePing {
				t.Errorf("client got PING %q, flags %#x", f.Payload, f.Flags)
			}
		}
	})
}

// The client's PING goes upstream and the server's ACK of it comes back. An
// ACK of a PING the client never sent is dropped, and so is an ACK from the
// client, which has no server PING to answer.
func TestClientPingIsAnsweredByTheServer(t *testing.T) {
	eachMode(t, func(t *testing.T, mutate func(*Options)) {
		h := newHarness(t, mutate)
		h.clientSend(ping(0, "cliping1"), ping(FlagAck, "unasked1"))
		h.expect(h.toServer, "server", isPing(0, "cliping1"))
		h.serverSend(ping(FlagAck, "unasked2"), ping(FlagAck, "cliping1"), ping(FlagAck, "cliping1"))
		var acks []string
		for _, f := range h.untilSettingsAck() {
			if f.Type == FramePing {
				acks = append(acks, string(f.Payload))
			}
		}
		if len(acks) != 1 || acks[0] != "cliping1" {
			t.Fatalf("client got PING ACKs %q, want just cliping1", acks)
		}
		h.quiet(h.toServer, 50*time.Millisecond, isPing(FlagAck, "unasked1"))
	})
}

// A server PING that arrives before the client's SETTINGS is answered after
// them: nothing may precede the client's connection preface.
func TestServerPingBeforeTheClientsSettings(t *testing.T) {
	h := newRawHarness(t, nil, nil)
	h.serverSend(Frame{Type: FrameSettings}, ping(0, "srvping1"))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.quiet(h.toServer, 50*time.Millisecond, isType(FramePing))
	h.clientSend(Frame{Type: FrameSettings})
	if f := h.next(h.toServer, "server"); f.Type != FrameSettings || f.Flags != 0 {
		t.Fatalf("server's first frame has type %d, flags %#x; want the client's SETTINGS", f.Type, f.Flags)
	}
	if f := h.next(h.toServer, "server"); !isPing(FlagAck, "srvping1")(f) {
		t.Fatalf("server got type %d %q, want the PING ACK", f.Type, f.Payload)
	}
}

// A PING whose payload is not 8 bytes is a connection error (RFC 9113 6.7).
func TestBadServerPingEndsTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	h.serverSend(ping(0, "short"))
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "bad PING") {
		t.Fatalf("relay error %v", err)
	}
}
