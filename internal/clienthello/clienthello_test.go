package clienthello

import (
	"bytes"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// chromeHello builds a Chrome ClientHello with uTLS, without any I/O.
func chromeHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	uconn := utls.UClient(a, &utls.Config{ServerName: "example.test"}, utls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return append([]byte{}, uconn.HandshakeState.Hello.Raw...)
}

// replayHello rebuilds message the way the proxy does.
func replayHello(t *testing.T, message []byte) []byte {
	t.Helper()
	spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(Record(0x0301, message))
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	uconn := utls.UClient(a, &utls.Config{ServerName: "example.test"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return append([]byte{}, uconn.HandshakeState.Hello.Raw...)
}

func mustParse(t *testing.T, message []byte) *Hello {
	t.Helper()
	h, err := Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestReadReassemblesRecords(t *testing.T) {
	message := chromeHello(t)
	// Split the handshake message over three records, as a client may.
	var wire []byte
	for _, part := range [][]byte{message[:3], message[3:200], message[200:]} {
		wire = append(wire, 22, 3, 1, byte(len(part)>>8), byte(len(part)))
		wire = append(wire, part...)
	}
	wire = append(wire, 0xff) // the next bytes stay unread
	r := bytes.NewReader(wire)
	consumed, version, got, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) || !bytes.Equal(consumed, wire[:len(wire)-1]) || version != 0x0301 || r.Len() != 1 {
		t.Fatalf("Read reassembled %d bytes, consumed %d, version %#x, left %d", len(got), len(consumed), version, r.Len())
	}
	if _, _, _, err := Read(bytes.NewReader([]byte{23, 3, 3, 0, 1, 0})); err == nil {
		t.Fatal("a non-handshake record was accepted")
	}
}

func TestParseChromeHello(t *testing.T) {
	h := mustParse(t, chromeHello(t))
	if h.ServerName() != "example.test" {
		t.Fatalf("SNI %q", h.ServerName())
	}
	if alpn := h.ALPN(); len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("ALPN %v", alpn)
	}
	if len(h.KeyShares()) < 2 || len(h.SupportedGroups()) < 3 || len(h.SessionID) != 32 || len(h.Random) != 32 {
		t.Fatalf("unexpected hello: %d key shares, %d groups", len(h.KeyShares()), len(h.SupportedGroups()))
	}
	if _, ok := h.Extension(ExtEncryptedHello); !ok {
		t.Fatal("the Chrome hello has no GREASE encrypted_client_hello, the test no longer covers it")
	}
}

func TestReplayOfAChromeHelloMatches(t *testing.T) {
	for i := 0; i < 20; i++ {
		original := chromeHello(t)
		replay := replayHello(t, original)
		a, b := mustParse(t, original), mustParse(t, replay)
		if err := Compare(a, b); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		if bytes.Equal(a.Random, b.Random) || bytes.Equal(a.SessionID, b.SessionID) {
			t.Fatal("random or session ID was copied")
		}
	}
}

func TestCompareRejectsChanges(t *testing.T) {
	base := chromeHello(t)
	replay := replayHello(t, base)
	mutations := map[string]func(h *Hello){
		"extension order": func(h *Hello) {
			h.Extensions[1], h.Extensions[2] = h.Extensions[2], h.Extensions[1]
		},
		"dropped extension": func(h *Hello) { h.Extensions = h.Extensions[:len(h.Extensions)-1] },
		"cipher suites": func(h *Hello) {
			h.CipherSuites[1], h.CipherSuites[2] = h.CipherSuites[2], h.CipherSuites[1]
		},
		"ALPN": func(h *Hello) {
			for i, e := range h.Extensions {
				if e.Type == ExtALPN {
					h.Extensions[i].Data = []byte{0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
				}
			}
		},
		"key share group": func(h *Hello) {
			for i, e := range h.Extensions {
				if e.Type == ExtKeyShare {
					data := append([]byte{}, e.Data...)
					// The first share after the GREASE one starts at byte 7.
					data[7] ^= 0x01
					h.Extensions[i].Data = data
				}
			}
		},
		"ECH payload length": func(h *Hello) {
			for i, e := range h.Extensions {
				if e.Type == ExtEncryptedHello {
					// type(1) kdf(2) aead(2) config_id(1) enc(2+n) payload(2+m)
					d := append([]byte{}, e.Data...)
					p := 8 + (int(d[6])<<8 | int(d[7]))
					shorter := (int(d[p])<<8 | int(d[p+1])) - 16
					d[p], d[p+1] = byte(shorter>>8), byte(shorter)
					h.Extensions[i].Data = d[:p+2+shorter]
				}
			}
		},
		"legacy version": func(h *Hello) { h.LegacyVersion = 0x0301 },
	}
	for name, mutate := range mutations {
		original := mustParse(t, base)
		copied := mustParse(t, replay)
		mutate(copied)
		if err := Compare(original, copied); err == nil {
			t.Errorf("%s: Compare accepted a changed hello", name)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("%#04x is GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000, 0xfe0d} {
		if IsGREASE(v) {
			t.Errorf("%#04x is not GREASE", v)
		}
	}
}
