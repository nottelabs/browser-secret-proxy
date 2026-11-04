package clienthello

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// FuzzParse feeds Parse, the accessors and Compare arbitrary ClientHellos.
// testdata/fuzz/FuzzParse holds the hello that crashed the proxy (two
// session_ticket extensions).
func FuzzParse(f *testing.F) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloGolang} {
		a, b := net.Pipe()
		uconn := utls.UClient(a, &utls.Config{ServerName: "example.test"}, id)
		if err := uconn.BuildHandshakeState(); err != nil {
			f.Fatal(err)
		}
		f.Add(append([]byte{}, uconn.HandshakeState.Hello.Raw...))
		_ = a.Close()
		_ = b.Close()
	}
	f.Fuzz(func(t *testing.T, message []byte) {
		h, err := Parse(message)
		if err != nil {
			return
		}
		seen := map[uint16]bool{}
		for _, e := range h.Extensions {
			if seen[e.Type] {
				t.Fatalf("Parse accepted a repeated extension %d", e.Type)
			}
			seen[e.Type] = true
		}
		_ = h.ServerName()
		_ = h.ALPN()
		_ = h.SupportedGroups()
		_ = h.KeyShares()
		_ = Compare(h, h)
		if len(h.Extensions) > 0 {
			changed, err := Parse(message)
			if err != nil {
				t.Fatalf("a second Parse failed: %v", err)
			}
			changed.Extensions[0].Data = append([]byte{0}, changed.Extensions[0].Data...)
			if Compare(h, changed) == nil || Compare(changed, h) == nil {
				t.Fatal("Compare accepted a changed extension")
			}
		}
	})
}
