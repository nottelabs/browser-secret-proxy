package h2relay

import (
	"errors"
	"slices"
)

// Connection control frames from the server.
//
// What the server puts in a frame reaches the client only where the client
// needs it, since masking does not look at control frames: a GOAWAY loses
// its debug data (onServerGoAway), and frames of extension or unknown types
// (ALTSVC, ORIGIN, PRIORITY_UPDATE, ...) are dropped, as RFC 9113 5.5 lets
// an endpoint do. The relay answers the server's PINGs itself, and passes
// on only the server's ACKs of the client's own PINGs, so a PING's opaque
// data always comes from the client.

// maxUnackedPings bounds the client PINGs remembered until the server
// acknowledges them, and the relay's answers waiting for the client's
// SETTINGS. A browser has one PING out at a time.
const maxUnackedPings = 64

// forwardClientSettings sends a client SETTINGS frame upstream. The first
// one is the client's connection preface: the relay's answers to server
// PINGs that arrived before it follow it.
func (r *relay) forwardClientSettings(f Frame) error {
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	frames := append([]Frame{f}, r.pingAcks...)
	r.pingAcks, r.clientStarted = nil, true
	_, err := r.server.Write(encodeFrames(frames))
	return err
}

// onClientPing sends a client PING upstream and remembers its data, so the
// server's ACK of it can come back. An ACK from the client is dropped: the
// client never gets a server PING to answer.
func (r *relay) onClientPing(f Frame) error {
	if f.Flags&FlagAck != 0 {
		return nil
	}
	if len(f.Payload) == 8 {
		r.mu.Lock()
		if len(r.pings) == maxUnackedPings {
			r.pings = slices.Delete(r.pings, 0, 1)
		}
		r.pings = append(r.pings, [8]byte(f.Payload))
		r.mu.Unlock()
	}
	return r.writeServer(f)
}

// onServerPing answers a server PING, or passes on the server's ACK of a
// PING the client sent. An ACK of anything else is dropped.
func (r *relay) onServerPing(f Frame) error {
	if len(f.Payload) != 8 || f.Stream != 0 {
		return errors.New("server sent a bad PING")
	}
	if f.Flags&FlagAck == 0 {
		return r.answerPing(f.Payload)
	}
	r.mu.Lock()
	i := slices.Index(r.pings, [8]byte(f.Payload))
	if i >= 0 {
		r.pings = slices.Delete(r.pings, i, i+1)
	}
	r.mu.Unlock()
	if i < 0 {
		return nil
	}
	return r.writeClient(f)
}

// answerPing acknowledges a server PING (RFC 9113 6.7). Before the client's
// SETTINGS went upstream the answer waits for them; past maxUnackedPings
// waiting, more are not answered.
func (r *relay) answerPing(payload []byte) error {
	ack := Frame{Type: FramePing, Flags: FlagAck, Payload: payload}
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	if !r.clientStarted {
		if len(r.pingAcks) < maxUnackedPings {
			r.pingAcks = append(r.pingAcks, ack)
		}
		return nil
	}
	_, err := r.server.Write(encodeFrames([]Frame{ack}))
	return err
}
