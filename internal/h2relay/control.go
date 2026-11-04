package h2relay

import (
	"errors"
	"net"
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
// acknowledges them, and the relay's answers to server PINGs waiting to go
// upstream. A browser has one PING out at a time.
const maxUnackedPings = 64

// forwardClientSettings sends a client SETTINGS frame upstream. The first
// one is the client's connection preface: the relay's answers to server
// PINGs that arrived before it follow it.
func (r *relay) forwardClientSettings(f Frame) error {
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	r.ackMu.Lock()
	frames := append([]Frame{f}, r.pingAcks...)
	r.pingAcks = nil
	r.ackMu.Unlock()
	r.clientStarted = true
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
		r.answerPing(f.Payload)
		return nil
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

// answerPing acknowledges a server PING (RFC 9113 6.7). The answer is
// queued for ackLoop, not written here: a write to a server that stopped
// reading (an upload) can hold serverMu, and the server loop must go on
// reading the server meanwhile, or a server that stops reading until its
// response is read would never get it. Past maxUnackedPings waiting, more
// are not answered.
func (r *relay) answerPing(payload []byte) {
	r.ackMu.Lock()
	if len(r.pingAcks) < maxUnackedPings {
		r.pingAcks = append(r.pingAcks, Frame{Type: FramePing, Flags: FlagAck, Payload: payload})
	}
	r.ackMu.Unlock()
	select {
	case r.ackReady <- struct{}{}:
	default: // ackLoop is already due to run
	}
}

// ackLoop sends the relay's answers to server PINGs upstream. Before the
// client's SETTINGS went upstream they wait for them (forwardClientSettings
// sends them after).
func (r *relay) ackLoop() error {
	for {
		select {
		case <-r.ctx.Done():
			return net.ErrClosed
		case <-r.ackReady:
		}
		if err := r.writeAcks(); err != nil {
			return err
		}
	}
}

func (r *relay) writeAcks() error {
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	if !r.clientStarted {
		return nil
	}
	r.ackMu.Lock()
	acks := r.pingAcks
	r.pingAcks = nil
	r.ackMu.Unlock()
	if len(acks) == 0 {
		return nil
	}
	_, err := r.server.Write(encodeFrames(acks))
	return err
}
