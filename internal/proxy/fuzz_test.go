package proxy

import (
	"net"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/nottelabs/browser-secret-proxy/internal/clienthello"
)

// FuzzRebuild runs what the proxy does with a client's ClientHello before
// the network handshake (Parse, then the uTLS Fingerprinter, ApplyPreset and
// BuildHandshakeState, then Compare), without the recover that guards it in
// replay, so a uTLS panic fails the target. testdata/fuzz/FuzzRebuild holds
// the hello that crashed the proxy (two session_ticket extensions).
func FuzzRebuild(f *testing.F) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloEdge_Auto, utls.HelloGolang} {
		a, b := net.Pipe()
		uconn := utls.UClient(a, &utls.Config{ServerName: allowedHost}, id)
		if err := uconn.BuildHandshakeState(); err != nil {
			f.Fatal(err)
		}
		f.Add(uint16(0x0301), append([]byte{}, uconn.HandshakeState.Hello.Raw...))
		_ = a.Close()
		_ = b.Close()
	}
	f.Add(uint16(0x0301), dupTicketHello(allowedHost))
	f.Fuzz(func(t *testing.T, recordVersion uint16, message []byte) {
		original, err := clienthello.Parse(message)
		if err != nil {
			return
		}
		// The CONNECT host is the SNI, so the SNI check passes.
		host := strings.TrimSuffix(original.ServerName(), ".")
		if host == "" {
			host = allowedHost
		}
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		_, _ = rebuild(a, host, recordVersion, message, original, nil)
	})
}
