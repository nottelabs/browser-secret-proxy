// Package clienthello reads a TLS ClientHello from a connection, parses it and
// checks that a replayed ClientHello is an exact copy of the original.
package clienthello

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	recordTypeHandshake   = 22
	handshakeClientHello  = 1
	maxClientHelloLength  = 1 << 16
	recordHeaderLength    = 5
	handshakeHeaderLength = 4
)

// Extension types this package looks inside.
const (
	ExtServerName          uint16 = 0
	ExtSupportedGroups     uint16 = 10
	ExtSignatureAlgorithms uint16 = 13
	ExtALPN                uint16 = 16
	ExtPadding             uint16 = 21
	ExtPreSharedKey        uint16 = 41
	ExtEarlyData           uint16 = 42
	ExtSupportedVersions   uint16 = 43
	ExtKeyShare            uint16 = 51
	ExtEncryptedHello      uint16 = 0xfe0d
)

// Read reads TLS records from r until it holds one complete ClientHello
// handshake message. It returns every byte it consumed, so the caller can hand
// them to a TLS server unchanged, the first record's version, and the
// handshake message (header included).
func Read(r io.Reader) (consumed []byte, recordVersion uint16, message []byte, err error) {
	var raw, handshake bytes.Buffer
	header := make([]byte, recordHeaderLength)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return raw.Bytes(), 0, nil, fmt.Errorf("read TLS record header: %w", err)
		}
		raw.Write(header)
		if header[0] != recordTypeHandshake {
			return raw.Bytes(), 0, nil, fmt.Errorf("first TLS record has type %d, not a handshake", header[0])
		}
		if recordVersion == 0 {
			recordVersion = uint16(header[1])<<8 | uint16(header[2])
		}
		length := int(header[3])<<8 | int(header[4])
		if length == 0 || handshake.Len()+length > maxClientHelloLength {
			return raw.Bytes(), 0, nil, errors.New("ClientHello record has an invalid length")
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return raw.Bytes(), 0, nil, fmt.Errorf("read TLS record: %w", err)
		}
		raw.Write(body)
		handshake.Write(body)
		data := handshake.Bytes()
		if len(data) < handshakeHeaderLength {
			continue
		}
		if data[0] != handshakeClientHello {
			return raw.Bytes(), 0, nil, fmt.Errorf("first handshake message has type %d, not a ClientHello", data[0])
		}
		total := handshakeHeaderLength + (int(data[1])<<16 | int(data[2])<<8 | int(data[3]))
		if total > maxClientHelloLength {
			return raw.Bytes(), 0, nil, errors.New("ClientHello is too large")
		}
		if len(data) < total {
			continue
		}
		if len(data) > total {
			return raw.Bytes(), 0, nil, errors.New("ClientHello records carry trailing handshake data")
		}
		return raw.Bytes(), recordVersion, data, nil
	}
}

// Record wraps a handshake message in a single TLS record header, the form
// the uTLS fingerprinter expects. The message may be longer than one TLS
// record allows; the fingerprinter only parses it.
func Record(recordVersion uint16, message []byte) []byte {
	out := make([]byte, 0, recordHeaderLength+len(message))
	out = append(out, recordTypeHandshake, byte(recordVersion>>8), byte(recordVersion), byte(len(message)>>8), byte(len(message)))
	return append(out, message...)
}

// Extension is one ClientHello extension, in wire order.
type Extension struct {
	Type uint16
	Data []byte
}

// Hello is a parsed ClientHello handshake message.
type Hello struct {
	Length        int
	LegacyVersion uint16
	Random        []byte
	SessionID     []byte
	CipherSuites  []uint16
	Compression   []byte
	Extensions    []Extension
}

// Parse parses a ClientHello handshake message (with its 4 byte header).
func Parse(message []byte) (*Hello, error) {
	s := reader(message)
	var msgType uint8
	var length uint32
	if !s.u8(&msgType) || !s.u24(&length) || msgType != handshakeClientHello || int(length) != len(s) {
		return nil, errors.New("not a ClientHello handshake message")
	}
	h := &Hello{Length: len(message)}
	var suites, extensions reader
	if !s.u16(&h.LegacyVersion) || !s.bytes(32, &h.Random) || !s.vec8(&h.SessionID) || !s.vec16((*[]byte)(&suites)) || !s.vec8(&h.Compression) {
		return nil, errors.New("truncated ClientHello")
	}
	if len(suites)%2 != 0 {
		return nil, errors.New("odd cipher suite list")
	}
	for len(suites) > 0 {
		var v uint16
		suites.u16(&v)
		h.CipherSuites = append(h.CipherSuites, v)
	}
	if len(s) == 0 {
		return h, nil
	}
	if !s.vec16((*[]byte)(&extensions)) || len(s) != 0 {
		return nil, errors.New("malformed ClientHello extensions")
	}
	for len(extensions) > 0 {
		var e Extension
		if !extensions.u16(&e.Type) || !extensions.vec16(&e.Data) {
			return nil, errors.New("malformed ClientHello extension")
		}
		h.Extensions = append(h.Extensions, e)
	}
	return h, nil
}

// Extension returns the data of the first extension of the given type.
func (h *Hello) Extension(t uint16) ([]byte, bool) {
	for _, e := range h.Extensions {
		if e.Type == t {
			return e.Data, true
		}
	}
	return nil, false
}

// ExtensionTypes lists the extension types in wire order.
func (h *Hello) ExtensionTypes() []uint16 {
	out := make([]uint16, len(h.Extensions))
	for i, e := range h.Extensions {
		out[i] = e.Type
	}
	return out
}

// ServerName returns the SNI host name, or "" when there is none.
func (h *Hello) ServerName() string {
	data, ok := h.Extension(ExtServerName)
	if !ok {
		return ""
	}
	s := reader(data)
	var list reader
	if !s.vec16((*[]byte)(&list)) {
		return ""
	}
	for len(list) > 0 {
		var nameType uint8
		var name []byte
		if !list.u8(&nameType) || !list.vec16(&name) {
			return ""
		}
		if nameType == 0 {
			return string(name)
		}
	}
	return ""
}

// ALPN returns the offered application protocols in order.
func (h *Hello) ALPN() []string {
	data, ok := h.Extension(ExtALPN)
	if !ok {
		return nil
	}
	s := reader(data)
	var list reader
	if !s.vec16((*[]byte)(&list)) {
		return nil
	}
	var out []string
	for len(list) > 0 {
		var p []byte
		if !list.vec8(&p) {
			return nil
		}
		out = append(out, string(p))
	}
	return out
}

// SupportedGroups returns the supported_groups list in order.
func (h *Hello) SupportedGroups() []uint16 {
	data, _ := h.Extension(ExtSupportedGroups)
	s := reader(data)
	var list reader
	if !s.vec16((*[]byte)(&list)) {
		return nil
	}
	return list.u16s()
}

// KeyShare is one key_share entry.
type KeyShare struct {
	Group uint16
	Key   []byte
}

// KeyShares returns the key_share entries in order.
func (h *Hello) KeyShares() []KeyShare {
	data, _ := h.Extension(ExtKeyShare)
	s := reader(data)
	var list reader
	if !s.vec16((*[]byte)(&list)) {
		return nil
	}
	var out []KeyShare
	for len(list) > 0 {
		var ks KeyShare
		if !list.u16(&ks.Group) || !list.vec16(&ks.Key) {
			return nil
		}
		out = append(out, ks)
	}
	return out
}

// IsGREASE reports whether v is a GREASE value (RFC 8701).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// normalize maps every GREASE value to one placeholder. Browsers pick GREASE
// values at random per connection, like the client random.
func normalize(v uint16) uint16 {
	if IsGREASE(v) {
		return 0x0a0a
	}
	return v
}

// Compare checks that replay is an exact copy of original, apart from the
// values a client generates fresh on every connection: the random, the
// session ID, key share public keys, GREASE values and the random fields of a
// GREASE encrypted_client_hello extension. Lengths of those values must
// still match. A nil error means the two are the same fingerprint.
func Compare(original, replay *Hello) error {
	if original.LegacyVersion != replay.LegacyVersion {
		return fmt.Errorf("legacy version %#04x became %#04x", original.LegacyVersion, replay.LegacyVersion)
	}
	if len(original.SessionID) != len(replay.SessionID) {
		return fmt.Errorf("session ID length %d became %d", len(original.SessionID), len(replay.SessionID))
	}
	if !equalNormalized(original.CipherSuites, replay.CipherSuites) {
		return fmt.Errorf("cipher suites %v became %v", original.CipherSuites, replay.CipherSuites)
	}
	if !bytes.Equal(original.Compression, replay.Compression) {
		return fmt.Errorf("compression methods %v became %v", original.Compression, replay.Compression)
	}
	if !equalNormalized(original.ExtensionTypes(), replay.ExtensionTypes()) {
		return fmt.Errorf("extensions %v became %v", original.ExtensionTypes(), replay.ExtensionTypes())
	}
	for i, want := range original.Extensions {
		if err := compareExtension(want, replay.Extensions[i]); err != nil {
			return fmt.Errorf("extension %d (position %d): %w", want.Type, i, err)
		}
	}
	if original.Length != replay.Length {
		return fmt.Errorf("length %d became %d", original.Length, replay.Length)
	}
	return nil
}

func compareExtension(want, got Extension) error {
	switch want.Type {
	case ExtKeyShare:
		a, b := (&Hello{Extensions: []Extension{want}}).KeyShares(), (&Hello{Extensions: []Extension{got}}).KeyShares()
		if a == nil || b == nil || len(a) != len(b) {
			return errors.New("key share entries differ")
		}
		for i := range a {
			if normalize(a[i].Group) != normalize(b[i].Group) || len(a[i].Key) != len(b[i].Key) {
				return fmt.Errorf("key share %d: group %#04x (%d bytes) became %#04x (%d bytes)", i, a[i].Group, len(a[i].Key), b[i].Group, len(b[i].Key))
			}
			if IsGREASE(a[i].Group) && !bytes.Equal(a[i].Key, b[i].Key) {
				return fmt.Errorf("GREASE key share %d content differs", i)
			}
		}
		return nil
	case ExtEncryptedHello:
		return compareGREASEECH(want.Data, got.Data)
	case ExtSupportedGroups:
		return compareU16List(want.Data, got.Data, 2)
	case ExtSupportedVersions:
		return compareU16List(want.Data, got.Data, 1)
	default:
		if !bytes.Equal(want.Data, got.Data) {
			return fmt.Errorf("content differs (%x became %x)", want.Data, got.Data)
		}
		return nil
	}
}

// compareU16List compares a length-prefixed list of uint16 values, ignoring
// which GREASE value sits in a GREASE position.
func compareU16List(want, got []byte, prefix int) error {
	if len(want) != len(got) || len(want) < prefix || !bytes.Equal(want[:prefix], got[:prefix]) {
		return fmt.Errorf("content differs (%x became %x)", want, got)
	}
	a, b := reader(want[prefix:]).u16s(), reader(got[prefix:]).u16s()
	if !equalNormalized(a, b) {
		return fmt.Errorf("values %v became %v", a, b)
	}
	return nil
}

// compareGREASEECH compares the fixed fields of a GREASE ECH extension: the
// type, the HPKE cipher suite and the lengths of the encapsulated key and
// payload. The config ID, key and payload are random by design.
func compareGREASEECH(want, got []byte) error {
	type ech struct {
		kind     uint8
		kdf      uint16
		aead     uint16
		enc, pay []byte
	}
	parse := func(data []byte) (ech, bool) {
		var e ech
		var configID uint8
		s := reader(data)
		ok := s.u8(&e.kind) && s.u16(&e.kdf) && s.u16(&e.aead) && s.u8(&configID) && s.vec16(&e.enc) && s.vec16(&e.pay) && len(s) == 0
		return e, ok
	}
	a, okA := parse(want)
	b, okB := parse(got)
	if !okA || !okB {
		return errors.New("malformed encrypted_client_hello")
	}
	if a.kind != b.kind || a.kdf != b.kdf || a.aead != b.aead || len(a.enc) != len(b.enc) || len(a.pay) != len(b.pay) {
		return fmt.Errorf("encrypted_client_hello shape differs (suite %#04x/%#04x, %d/%d bytes became %#04x/%#04x, %d/%d bytes)",
			a.kdf, a.aead, len(a.enc), len(a.pay), b.kdf, b.aead, len(b.enc), len(b.pay))
	}
	return nil
}

func equalNormalized(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalize(a[i]) != normalize(b[i]) {
			return false
		}
	}
	return true
}

// reader is a minimal big-endian byte reader.
type reader []byte

func (r *reader) u8(v *uint8) bool {
	if len(*r) < 1 {
		return false
	}
	*v = (*r)[0]
	*r = (*r)[1:]
	return true
}

func (r *reader) u16(v *uint16) bool {
	if len(*r) < 2 {
		return false
	}
	*v = uint16((*r)[0])<<8 | uint16((*r)[1])
	*r = (*r)[2:]
	return true
}

func (r *reader) u24(v *uint32) bool {
	if len(*r) < 3 {
		return false
	}
	*v = uint32((*r)[0])<<16 | uint32((*r)[1])<<8 | uint32((*r)[2])
	*r = (*r)[3:]
	return true
}

func (r *reader) bytes(n int, v *[]byte) bool {
	if len(*r) < n {
		return false
	}
	*v = (*r)[:n:n]
	*r = (*r)[n:]
	return true
}

func (r *reader) vec8(v *[]byte) bool {
	var n uint8
	return r.u8(&n) && r.bytes(int(n), v)
}

func (r *reader) vec16(v *[]byte) bool {
	var n uint16
	return r.u16(&n) && r.bytes(int(n), v)
}

func (r reader) u16s() []uint16 {
	var out []uint16
	for len(r) >= 2 {
		var v uint16
		r.u16(&v)
		out = append(out, v)
	}
	return out
}
