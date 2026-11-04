package h2relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// FuzzReadFrame checks the frame reader against the wire format (RFC 9113
// 4.1): a 9-byte header, then exactly the declared payload, read the same
// way whatever the reads return and refused, unread, past the limit.
func FuzzReadFrame(f *testing.F) {
	f.Add(encodeFrames([]Frame{{Type: FrameSettings}}), uint32(0))
	f.Add(encodeFrames([]Frame{{Type: FrameHeaders, Flags: FlagEndHeaders | FlagPadded, Stream: 1, Payload: []byte{2, 0x82, 0, 0}}}), uint32(0))
	f.Add(append(AppendFrame(nil, FrameData, 0, 1, bytes.Repeat([]byte{'d'}, defaultMaxFrame+3)), 1, 2), uint32(defaultMaxFrame+1))
	f.Add([]byte{0xff, 0xff, 0xff, 0, 0, 0x80, 0, 0, 1}, uint32(1<<20))
	f.Fuzz(func(t *testing.T, b []byte, limit uint32) {
		for _, slow := range []bool{false, true} {
			var r io.Reader = bytes.NewReader(b)
			if slow {
				r = iotest.OneByteReader(r)
			}
			var maxSize func() int
			if limit != 0 {
				maxSize = func() int { return int(limit) }
			}
			fr, err := readFrame(r, maxSize)
			if len(b) < frameHeaderLength {
				if err == nil {
					t.Fatalf("read a frame from %d bytes", len(b))
				}
				continue
			}
			length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
			switch {
			case limit != 0 && length > defaultMaxFrame && length > int(limit):
				if !errors.Is(err, ErrFrameSize) {
					t.Fatalf("a %d-byte frame past the limit %d: %v", length, limit, err)
				}
			case len(b) < frameHeaderLength+length:
				if err == nil {
					t.Fatalf("read a %d-byte frame from %d bytes", length, len(b))
				}
			default:
				if err != nil {
					t.Fatalf("a complete %d-byte frame: %v", length, err)
				}
				want := Frame{Type: b[3], Flags: b[4], Stream: binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff, Payload: b[9 : 9+length]}
				if fr.Type != want.Type || fr.Flags != want.Flags || fr.Stream != want.Stream || !bytes.Equal(fr.Payload, want.Payload) {
					t.Fatalf("read %+v, want %+v", fr, want)
				}
				// Written again, it is the same frame, the reserved bit cleared.
				wire := append([]byte{}, b[:9+length]...)
				wire[5] &= 0x7f
				if got := AppendFrame(nil, fr.Type, fr.Flags, fr.Stream, fr.Payload); !bytes.Equal(got, wire) {
					t.Fatalf("AppendFrame gives %x, want %x", got, wire)
				}
			}
		}
	})
}

// FuzzFramePayloads checks the payload parsers: padding and the priority
// block of HEADERS (RFC 9113 6.2), SETTINGS parameters (6.5.1), and the
// rewrites of SETTINGS the relay applies.
func FuzzFramePayloads(f *testing.F) {
	f.Add(uint8(0), []byte{0x82, 0x87})
	f.Add(FlagPadded, []byte{2, 0x82, 0, 0})
	f.Add(FlagPadded|FlagPriority, []byte{1, 0x80, 0, 0, 3, 15, 0x82, 0})
	f.Add(FlagPriority, []byte{0, 0, 0, 3, 15})
	f.Add(FlagPadded, []byte{9})
	f.Add(uint8(0), []byte{0, 1, 0, 1, 0, 0, 0, 5, 0, 0, 0x40, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, flags uint8, b []byte) {
		data, err := unpad(flags, b)
		switch {
		case flags&FlagPadded == 0:
			if err != nil || !bytes.Equal(data, b) {
				t.Fatalf("unpadded payload changed: %x, %v", data, err)
			}
		case len(b) == 0 || int(b[0]) > len(b)-1:
			if err == nil {
				t.Fatalf("invalid padding accepted: %x", b)
			}
		default:
			if err != nil || !bytes.Equal(data, b[1:len(b)-int(b[0])]) {
				t.Fatalf("unpad(%x) = %x, %v", b, data, err)
			}
		}

		p, block, herr := HeadersPayload(flags, b)
		switch {
		case err != nil:
			if herr == nil {
				t.Fatalf("HEADERS with invalid padding accepted: %x", b)
			}
		case flags&FlagPriority == 0:
			if herr != nil || p != nil || !bytes.Equal(block, data) {
				t.Fatalf("HeadersPayload(%x) = %v, %x, %v", b, p, block, herr)
			}
		case len(data) < 5:
			if herr == nil {
				t.Fatalf("HEADERS too short for its priority accepted: %x", b)
			}
		default:
			if herr != nil || p == nil || !bytes.Equal(block, data[5:]) {
				t.Fatalf("HeadersPayload(%x) = %v, %x, %v", b, p, block, herr)
			}
			if got := p.bytes(); !bytes.Equal(got, data[:5]) {
				t.Fatalf("priority %x written again as %x", data[:5], got)
			}
			if p.Exclusive != (data[0]&0x80 != 0) || p.DependsOn != binary.BigEndian.Uint32(data)&0x7fffffff || p.Weight != data[4] {
				t.Fatalf("priority %x parsed as %+v", data[:5], *p)
			}
		}

		settings, err := ParseSettings(b)
		if (err != nil) != (len(b)%6 != 0) {
			t.Fatalf("ParseSettings(%d bytes): %v", len(b), err)
		}
		maxFrame := 0
		for i, s := range settings {
			if s.ID != binary.BigEndian.Uint16(b[6*i:]) || s.Value != binary.BigEndian.Uint32(b[6*i+2:]) {
				t.Fatalf("setting %d parsed as %+v", i, s)
			}
		}
		for i := 0; i+6 <= len(b); i += 6 {
			if binary.BigEndian.Uint16(b[i:]) == SettingMaxFrameSize {
				maxFrame = min(max(int(binary.BigEndian.Uint32(b[i+2:])), defaultMaxFrame), maxFrameLength)
			}
		}
		if got := maxFrameSetting(b); got != maxFrame {
			t.Fatalf("maxFrameSetting = %d, want %d", got, maxFrame)
		}

		// The client's copy only lowers SETTINGS_HEADER_TABLE_SIZE.
		out := clientSettings(b)
		if len(out) != len(b) {
			t.Fatalf("clientSettings changed the length: %d to %d", len(b), len(out))
		}
		for i := range b {
			if out[i] == b[i] {
				continue
			}
			start := i - i%6
			if start+6 > len(b) || binary.BigEndian.Uint16(b[start:]) != SettingHeaderTableSize ||
				binary.BigEndian.Uint32(b[start+2:]) <= decoderTableSize || binary.BigEndian.Uint32(out[start+2:]) != decoderTableSize {
				t.Fatalf("clientSettings changed byte %d of %x: %x", i, b, out)
			}
		}
	})
}

// FuzzRelay feeds arbitrary bytes from the client (after the preface) or
// from the server to a relay, with masking off and on. The other side
// behaves: the server answers every request, the client sends one. The
// relay must neither panic nor hang.
func FuzzRelay(f *testing.F) {
	request := []byte{0x82, 0x87, 0x84, 0x41, 0x0c, 'a', 'l', 'l', 'o', 'w', 'e', 'd', '.', 't', 'e', 's', 't'}
	client := encodeFrames([]Frame{
		{Type: FrameSettings, Flags: FlagAck},
		{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: request},
		{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("tok_standin")},
		{Type: FrameWindowUpdate, Stream: 1, Payload: []byte{0, 0, 1, 0}},
		{Type: FramePriority, Stream: 3, Payload: []byte{0, 0, 0, 1, 5}},
		{Type: FramePriorityUpdate, Payload: []byte{0, 0, 0, 1, 'u'}},
		{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream | FlagPadded | FlagPriority, Stream: 5, Payload: append(append([]byte{2, 0, 0, 0, 3, 7}, request...), 0, 0)},
		{Type: FrameRSTStream, Stream: 1, Payload: []byte{0, 0, 0, 8}},
		{Type: FramePing, Payload: make([]byte, 8)},
		{Type: FrameGoAway, Payload: make([]byte, 8)},
	})
	server := encodeFrames([]Frame{
		{Type: FrameSettings, Payload: []byte{0, 4, 0, 0, 0, 10, 0, 5, 0, 0, 0x40, 0}},
		{Type: FrameSettings, Flags: FlagAck},
		{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: []byte{0x88, 0x5f, 0x0a, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n'}},
		{Type: FrameData, Flags: FlagPadded, Stream: 1, Payload: []byte("\x02x sk_live_real_secret_value\x00\x00")},
		{Type: FrameData, Stream: 1, Payload: []byte("4111111111111111 sk_live_real_")},
		{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: []byte{0x40, 1, 'x', 4, 's', 'k', '_', 'l'}},
		{Type: FramePushPromise, Flags: FlagEndHeaders, Stream: 1, Payload: []byte{0, 0, 0, 2, 0x82}},
		{Type: FrameRSTStream, Stream: 1, Payload: []byte{0, 0, 0, 8}},
		{Type: FrameGoAway, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 0}},
	})
	for _, masked := range []bool{false, true} {
		f.Add(masked, false, client)
		f.Add(masked, true, server)
	}
	f.Fuzz(func(t *testing.T, masked, fromServer bool, in []byte) {
		hosts, err := hostmatch.New([]string{"allowed.test"})
		if err != nil {
			t.Fatal(err)
		}
		opts := Options{Hosts: hosts, Session: scopetest.Static(t, hosts, map[string]string{"tok_standin": "real_value"}), PrefaceTimeout: time.Second}
		if masked {
			masking(t, false)(&opts)
		}
		opts.Logger = slog.New(slog.DiscardHandler)
		clientTest, clientRelay := net.Pipe()
		serverRelay, serverTest := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- newRelay(clientRelay, serverRelay, opts).run() }()
		deadline := time.Now().Add(200 * time.Millisecond)
		_ = clientTest.SetWriteDeadline(deadline)
		_ = serverTest.SetWriteDeadline(deadline)
		if fromServer {
			go func() { _, _ = io.Copy(io.Discard, clientTest) }()
			go func() {
				preface := make([]byte, len(Preface))
				if _, err := io.ReadFull(serverTest, preface); err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, serverTest) }()
				_, _ = serverTest.Write(in)
			}()
			_, _ = clientTest.Write([]byte(Preface))
			_, _ = clientTest.Write(encodeFrames([]Frame{
				{Type: FrameSettings},
				{Type: FrameSettings, Flags: FlagAck},
				{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: request},
			}))
		} else {
			go func() { _, _ = io.Copy(io.Discard, clientTest) }()
			go func() {
				preface := make([]byte, len(Preface))
				if _, err := io.ReadFull(serverTest, preface); err != nil {
					return
				}
				_, _ = serverTest.Write(encodeFrames([]Frame{{Type: FrameSettings}}))
				for {
					fr, err := ReadFrame(serverTest)
					if err != nil {
						return
					}
					if fr.Type == FrameHeaders && fr.Stream != 0 {
						_, _ = serverTest.Write(encodeFrames([]Frame{
							{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: fr.Stream, Payload: []byte{0x88}},
							{Type: FrameData, Flags: FlagEndStream, Stream: fr.Stream, Payload: []byte("x real_value sk_live_real_secret_value y")},
						}))
					}
				}
			}()
			_, _ = clientTest.Write([]byte(Preface))
			_, _ = clientTest.Write(in)
		}
		time.Sleep(time.Millisecond)
		_ = clientTest.Close()
		_ = serverTest.Close()
		select {
		case <-done: //nolint:errcheck // any error is fine; only a hang is not
		case <-time.After(waitFor):
			t.Fatal("relay did not stop")
		}
	})
}
