package h2relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// unknownType is a frame type the relay forwards as is.
const unknownType = 0xfa

func unknownFrame(n int) Frame {
	return Frame{Type: unknownType, Payload: bytes.Repeat([]byte{1}, n)}
}

// sendRaw writes frames the relay may refuse partway, closing the
// connection: the write error is expected then.
func (h *harness) sendRaw(conn net.Conn, frames ...Frame) {
	_ = conn.SetWriteDeadline(time.Now().Add(waitFor))
	_, _ = conn.Write(encodeFrames(frames))
}

func isUnknown(n int) func(Frame) bool {
	return func(f Frame) bool { return f.Type == unknownType && len(f.Payload) == n }
}

// A client frame longer than the max frame size it was told (16,384 bytes:
// the server sent none) ends the connection with FRAME_SIZE_ERROR, and
// nothing of it reaches the server.
func TestOversizedClientFrameEndsTheConnection(t *testing.T) {
	h := newHarness(t, nil)
	h.sendRaw(h.client, unknownFrame(defaultMaxFrame+1))
	h.expect(h.toClient, "client", isGoAway(errCodeFrameSize))
	for f := range h.toServer {
		if f.Type == unknownType {
			t.Fatalf("a %d-byte frame reached the server", len(f.Payload))
		}
	}
	if err := h.result(); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("relay error %v, want %v", err, ErrFrameSize)
	}
}

// The client may send frames up to the server's max frame size as soon as it
// has the server's SETTINGS, and keeps that size after a decrease until it
// acknowledges it.
func TestClientFrameSizeFollowsTheServersSettings(t *testing.T) {
	h := newHarness(t, nil)
	const big = 100000
	h.serverSend(settingsFrame(Setting{ID: SettingMaxFrameSize, Value: 1 << 20}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(unknownFrame(big)) // before its ACK
	h.expect(h.toServer, "server", isUnknown(big))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})

	h.serverSend(settingsFrame(Setting{ID: SettingMaxFrameSize, Value: defaultMaxFrame}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(unknownFrame(big)) // the decrease is not acknowledged yet
	h.expect(h.toServer, "server", isUnknown(big))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck}, unknownFrame(defaultMaxFrame))
	h.expect(h.toServer, "server", isUnknown(defaultMaxFrame))
	h.sendRaw(h.client, unknownFrame(big))
	h.expect(h.toClient, "client", isGoAway(errCodeFrameSize))
	if err := h.result(); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("relay error %v, want %v", err, ErrFrameSize)
	}
}

// A server frame longer than the client's max frame size (16,384 bytes: the
// client sent none) ends the connection with FRAME_SIZE_ERROR, with and
// without masking.
func TestOversizedServerFrameEndsTheConnection(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "masked"}[masked], func(t *testing.T) {
			var mutate func(*Options)
			if masked {
				mutate = masking(t, true)
			}
			h := newHarness(t, mutate)
			h.sendRaw(h.server, unknownFrame(defaultMaxFrame+1))
			h.expect(h.toServer, "server", isGoAway(errCodeFrameSize))
			if err := h.result(); !errors.Is(err, ErrFrameSize) {
				t.Fatalf("relay error %v, want %v", err, ErrFrameSize)
			}
		})
	}
}

// The server's limit follows the client's SETTINGS the same way.
func TestServerFrameSizeFollowsTheClientsSettings(t *testing.T) {
	h := newHarness(t, nil)
	const big = 100000
	h.clientSend(settingsFrame(Setting{ID: SettingMaxFrameSize, Value: 1 << 20}))
	h.expect(h.toServer, "server", isType(FrameSettings))
	h.serverSend(unknownFrame(big)) // before its ACK
	h.expect(h.toClient, "client", isUnknown(big))
	h.serverSend(Frame{Type: FrameSettings, Flags: FlagAck})

	h.clientSend(settingsFrame(Setting{ID: SettingMaxFrameSize, Value: defaultMaxFrame}))
	h.expect(h.toServer, "server", isType(FrameSettings))
	h.serverSend(unknownFrame(big)) // the decrease is not acknowledged yet
	h.expect(h.toClient, "client", isUnknown(big))
	h.serverSend(Frame{Type: FrameSettings, Flags: FlagAck})
	h.sendRaw(h.server, unknownFrame(big))
	h.expect(h.toServer, "server", isGoAway(errCodeFrameSize))
	if err := h.result(); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("relay error %v, want %v", err, ErrFrameSize)
	}
}

// recordingReader serves data and records the largest buffer it was asked
// to fill.
type recordingReader struct {
	data    []byte
	largest int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	r.largest = max(r.largest, len(p))
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// A peer that declares a large frame and stalls makes the relay hold what it
// sent, not the declared length.
func TestStalledFrameHoldsOnlyWhatArrived(t *testing.T) {
	header := AppendFrame(nil, unknownType, 0, 0, nil)
	header[0], header[1], header[2] = 0xff, 0xff, 0xff // 2^24-1 bytes
	r := &recordingReader{data: append(header, make([]byte, 100)...)}
	_, err := readFrame(r, func() int { return maxFrameLength })
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if r.largest > defaultMaxFrame {
		t.Fatalf("the relay allocated %d bytes for a frame that sent 100", r.largest)
	}
}

// Frames of every size still read whole, in small pieces too; one over the
// limit is refused before its payload is read; the limit is only asked for
// frames over 16,384 bytes.
func TestReadFrameLimits(t *testing.T) {
	limit := func() int { return 1 << 20 }
	for _, n := range []int{0, 1, defaultMaxFrame, defaultMaxFrame + 1, 3*defaultMaxFrame + 7, 1 << 20} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		wire := AppendFrame(nil, FrameData, FlagEndStream, 3, payload)
		f, err := readFrame(iotest.HalfReader(bytes.NewReader(wire)), limit)
		if err != nil || f.Type != FrameData || f.Flags != FlagEndStream || f.Stream != 3 || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("%d-byte frame read as type %d, flags %d, stream %d, %d bytes, %v", n, f.Type, f.Flags, f.Stream, len(f.Payload), err)
		}
	}
	r := bytes.NewReader(AppendFrame(nil, FrameData, 0, 1, make([]byte, 1<<20+1)))
	if _, err := readFrame(r, limit); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("read error %v, want %v", err, ErrFrameSize)
	}
	if r.Len() != 1<<20+1 {
		t.Fatalf("%d payload bytes read from a refused frame", 1<<20+1-r.Len())
	}
	asked := false
	wire := AppendFrame(nil, FrameData, 0, 1, make([]byte, defaultMaxFrame))
	if _, err := readFrame(bytes.NewReader(wire), func() int { asked = true; return 0 }); err != nil || asked {
		t.Fatalf("a %d-byte frame: error %v, limit asked: %v", defaultMaxFrame, err, asked)
	}
}

// The limit is the largest value the peer may be using: any value it was
// sent and has not acknowledged yet, or the last one it acknowledged.
func TestFrameLimitFollowsAcks(t *testing.T) {
	var l frameLimit
	check := func(want int) {
		t.Helper()
		if got := l.size(); got != want {
			t.Fatalf("limit %d, want %d", got, want)
		}
	}
	setting := func(v uint32) []byte { return settingsFrame(Setting{ID: SettingMaxFrameSize, Value: v}).Payload }
	check(defaultMaxFrame)
	l.sent(setting(1 << 20))
	check(1 << 20)
	l.ack()
	check(1 << 20)
	l.sent(setting(defaultMaxFrame))
	l.sent(nil) // a SETTINGS frame without the setting
	check(1 << 20)
	l.ack()
	check(defaultMaxFrame)
	l.ack()
	check(defaultMaxFrame)
	l.ack() // an ACK of nothing
	check(defaultMaxFrame)
	l.sent(setting(1 << 30)) // invalid: the receiver refuses it, but never more than 2^24-1
	check(maxFrameLength)

	// Past maxUnackedSettings frames without an ACK, the oldest is
	// forgotten: the largest value ever sent applies from then on.
	l = frameLimit{}
	l.sent(setting(1 << 20))
	for range maxUnackedSettings {
		l.sent(setting(defaultMaxFrame))
	}
	check(1 << 20)
	l.ack()
	check(1 << 20)
}

// A PRIORITY_UPDATE for a stream with no server ID yet is kept until the
// stream goes upstream, outside the buffer budget. Its value is capped, so a
// client told a 16 MiB max frame size cannot make the relay keep 16 MiB per
// stream: a longer value ends the connection with PROTOCOL_ERROR.
func TestLongPriorityUpdateEndsTheConnection(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxBuffered = 1 << 20; o.MaxBody = 1 << 20 })
	h.serverSend(settingsFrame(Setting{ID: SettingMaxFrameSize, Value: maxFrameLength}))
	h.expect(h.toClient, "client", isType(FrameSettings))
	h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
	priorityUpdate := func(stream uint32, value []byte) Frame {
		return Frame{Type: FramePriorityUpdate, Payload: append(binary.BigEndian.AppendUint32(nil, stream), value...)}
	}
	for _, stream := range []uint32{1, 3} {
		h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: stream, Payload: h.clientBlock(request("POST")...)})
	}

	// A value at the cap is kept, and sent once the request goes upstream.
	atCap := []byte("u=3, i" + strings.Repeat(" ", maxPriorityValue-6))
	h.clientSend(priorityUpdate(1, atCap), Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("body")})
	headers := h.expect(h.toServer, "server", isType(FrameHeaders))
	f := h.expect(h.toServer, "server", isType(FramePriorityUpdate))
	if binary.BigEndian.Uint32(f.Payload) != headers.Stream || !bytes.Equal(f.Payload[4:], atCap) {
		t.Fatalf("server got PRIORITY_UPDATE for stream %d with a %d-byte value", binary.BigEndian.Uint32(f.Payload), len(f.Payload)-4)
	}

	h.sendRaw(h.client, priorityUpdate(3, make([]byte, maxFrameLength-4)))
	h.expect(h.toClient, "client", isGoAway(errCodeProtocol))
	if err := h.result(); err == nil || !strings.Contains(err.Error(), "PRIORITY_UPDATE") {
		t.Fatalf("relay error %v", err)
	}
}
