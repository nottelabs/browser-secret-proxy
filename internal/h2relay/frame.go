package h2relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
)

// Preface is the HTTP/2 client connection preface.
const Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame types (RFC 9113 section 6, RFC 9218).
const (
	FrameData           uint8 = 0x0
	FrameHeaders        uint8 = 0x1
	FramePriority       uint8 = 0x2
	FrameRSTStream      uint8 = 0x3
	FrameSettings       uint8 = 0x4
	FramePushPromise    uint8 = 0x5
	FramePing           uint8 = 0x6
	FrameGoAway         uint8 = 0x7
	FrameWindowUpdate   uint8 = 0x8
	FrameContinuation   uint8 = 0x9
	FramePriorityUpdate uint8 = 0x10
)

// Frame flags.
const (
	FlagEndStream  uint8 = 0x1
	FlagAck        uint8 = 0x1
	FlagEndHeaders uint8 = 0x4
	FlagPadded     uint8 = 0x8
	FlagPriority   uint8 = 0x20
)

// Settings identifiers.
const (
	SettingHeaderTableSize      uint16 = 0x1
	SettingMaxConcurrentStreams uint16 = 0x3
	SettingInitialWindowSize    uint16 = 0x4
	SettingMaxFrameSize         uint16 = 0x5
	// SettingEnableConnectProtocol is RFC 8441's
	// SETTINGS_ENABLE_CONNECT_PROTOCOL.
	SettingEnableConnectProtocol uint16 = 0x8
)

const (
	frameHeaderLength = 9
	maxFrameLength    = 1<<24 - 1
	defaultWindow     = 65535
	defaultMaxFrame   = 16384
)

// Frame is one HTTP/2 frame as it was on the wire.
type Frame struct {
	Type    uint8
	Flags   uint8
	Stream  uint32
	Payload []byte
}

// ErrFrameSize is a frame longer than the SETTINGS_MAX_FRAME_SIZE its sender
// was told (RFC 9113 4.2).
var ErrFrameSize = errors.New("frame is larger than the max frame size")

// ReadFrame reads one frame of any length.
func ReadFrame(r io.Reader) (Frame, error) {
	return readFrame(r, nil)
}

// readFrame reads one frame. maxSize, when not nil, is the largest payload
// the peer may send. It is called once the frame header has arrived, so it
// sees settings that changed while the read waited, and only for a frame
// over 16,384 bytes, which every peer may send. A longer frame is an
// ErrFrameSize error, and its payload is not read.
//
// The payload buffer grows as bytes arrive rather than taking the declared
// length at once: a peer that declares a large frame and stalls holds only
// about twice what it sent.
func readFrame(r io.Reader, maxSize func() int) (Frame, error) {
	var header [frameHeaderLength]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if maxSize != nil && length > defaultMaxFrame {
		if limit := maxSize(); length > limit {
			return Frame{}, fmt.Errorf("%w: %d bytes, at most %d", ErrFrameSize, length, limit)
		}
	}
	f := Frame{Type: header[3], Flags: header[4], Stream: binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff}
	payload := make([]byte, min(length, defaultMaxFrame))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	for len(payload) < length {
		n := len(payload)
		payload = slices.Grow(payload, min(n, length-n))[:n+min(n, length-n)]
		if _, err := io.ReadFull(r, payload[n:]); err != nil {
			return Frame{}, err
		}
	}
	f.Payload = payload
	return f, nil
}

// AppendFrame appends the wire form of a frame to b.
func AppendFrame(b []byte, typ, flags uint8, stream uint32, payload []byte) []byte {
	n := len(payload)
	b = append(b, byte(n>>16), byte(n>>8), byte(n), typ, flags)
	b = binary.BigEndian.AppendUint32(b, stream&0x7fffffff)
	return append(b, payload...)
}

// Setting is one SETTINGS parameter, in wire order.
type Setting struct {
	ID    uint16
	Value uint32
}

// ParseSettings returns the parameters of a SETTINGS payload in order.
func ParseSettings(payload []byte) ([]Setting, error) {
	if len(payload)%6 != 0 {
		return nil, errors.New("SETTINGS payload is not a multiple of 6 bytes")
	}
	out := make([]Setting, 0, len(payload)/6)
	for i := 0; i < len(payload); i += 6 {
		out = append(out, Setting{ID: binary.BigEndian.Uint16(payload[i:]), Value: binary.BigEndian.Uint32(payload[i+2:])})
	}
	return out, nil
}

// maxFrameSetting returns the last SETTINGS_MAX_FRAME_SIZE in a SETTINGS
// payload, kept between 16,384 and 2^24-1, or 0 when there is none. A
// malformed payload is the receiver's to refuse; only whole parameters are
// read.
func maxFrameSetting(payload []byte) int {
	v := 0
	for i := 0; i+6 <= len(payload); i += 6 {
		if binary.BigEndian.Uint16(payload[i:]) == SettingMaxFrameSize {
			v = min(max(int(binary.BigEndian.Uint32(payload[i+2:])), defaultMaxFrame), maxFrameLength)
		}
	}
	return v
}

// frameLimit is the largest frame a peer may send: the
// SETTINGS_MAX_FRAME_SIZE in the SETTINGS frames the relay forwarded to it.
// A new value applies once the peer acknowledges its frame (RFC 9113
// 6.5.3), but the peer may use it as soon as it arrives, so the limit is the
// largest value the peer may be using: the one as of its last ACK, or the
// one after any prefix of the frames it has not acknowledged yet. A frame
// that is legal for the peer is never refused.
type frameLimit struct {
	mu      sync.Mutex
	acked   int   // 0: the default
	unacked []int // one per SETTINGS frame not acknowledged yet, oldest first; 0: without the setting
	// overflow is set once unacked overflowed: from then on the largest
	// value ever sent applies.
	overflow bool
	largest  int
	limit    atomic.Int64 // 0: the default
}

// sent records a SETTINGS frame forwarded to the peer, before the peer can
// read it.
func (l *frameLimit) sent(payload []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := maxFrameSetting(payload)
	l.largest = max(l.largest, v)
	l.unacked = append(l.unacked, v)
	if len(l.unacked) > maxUnackedSettings {
		l.unacked = l.unacked[1:]
		l.overflow = true
	}
	l.update()
}

// ack records the peer's ACK of the oldest SETTINGS frame it was sent.
func (l *frameLimit) ack() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.unacked) == 0 {
		return
	}
	if v := l.unacked[0]; v != 0 {
		l.acked = v
	}
	l.unacked = l.unacked[1:]
	l.update()
}

func (l *frameLimit) update() {
	if l.overflow {
		l.limit.Store(int64(l.largest))
		return
	}
	state := l.acked
	largest := state
	for _, v := range l.unacked {
		if v != 0 {
			state = v
		}
		largest = max(largest, state)
	}
	l.limit.Store(int64(largest))
}

// size returns the limit; it is safe to call from any goroutine.
func (l *frameLimit) size() int {
	return max(int(l.limit.Load()), defaultMaxFrame)
}

// Priority is the priority block of a HEADERS or PRIORITY frame.
type Priority struct {
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

func parsePriority(b []byte) Priority {
	v := binary.BigEndian.Uint32(b)
	return Priority{Exclusive: v>>31 == 1, DependsOn: v & 0x7fffffff, Weight: b[4]}
}

func (p Priority) bytes() []byte {
	v := p.DependsOn & 0x7fffffff
	if p.Exclusive {
		v |= 1 << 31
	}
	return append(binary.BigEndian.AppendUint32(nil, v), p.Weight)
}

// HeadersPayload splits a HEADERS payload into its priority block (nil when
// absent) and header block fragment, dropping padding.
func HeadersPayload(flags uint8, payload []byte) (*Priority, []byte, error) {
	data, err := unpad(flags, payload)
	if err != nil {
		return nil, nil, err
	}
	if flags&FlagPriority == 0 {
		return nil, data, nil
	}
	if len(data) < 5 {
		return nil, nil, errors.New("HEADERS frame too short for its priority block")
	}
	p := parsePriority(data)
	return &p, data[5:], nil
}

func unpad(flags uint8, payload []byte) ([]byte, error) {
	if flags&FlagPadded == 0 {
		return payload, nil
	}
	if len(payload) < 1 || int(payload[0]) > len(payload)-1 {
		return nil, fmt.Errorf("invalid padding")
	}
	return payload[1 : len(payload)-int(payload[0])], nil
}
