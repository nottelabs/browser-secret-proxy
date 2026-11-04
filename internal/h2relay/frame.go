package h2relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var header [frameHeaderLength]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	f := Frame{Type: header[3], Flags: header[4], Stream: binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff}
	f.Payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, err
	}
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
