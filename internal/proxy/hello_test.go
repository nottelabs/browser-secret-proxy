package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/clienthello"
	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// dupTicketHello is the ClientHello that crashed the proxy (audit finding
// sec-tls-connect-1): a minimal TLS 1.3 ClientHello for sni with two empty
// session_ticket extensions. uTLS panics on it in ApplyPreset.
func dupTicketHello(sni string) []byte {
	ext := func(typ uint16, data []byte) []byte {
		return append([]byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}, data...)
	}
	name := []byte(sni)
	sniData := append([]byte{byte((len(name) + 3) >> 8), byte(len(name) + 3), 0, byte(len(name) >> 8), byte(len(name))}, name...)
	key := make([]byte, 32)
	key[0] = 9
	var exts []byte
	exts = append(exts, ext(0, sniData)...)
	exts = append(exts, ext(10, []byte{0, 2, 0, 0x1d})...)
	exts = append(exts, ext(13, []byte{0, 2, 4, 3})...)
	exts = append(exts, ext(35, nil)...)
	exts = append(exts, ext(35, nil)...)
	exts = append(exts, ext(43, []byte{2, 3, 4})...)
	exts = append(exts, ext(51, append([]byte{0, 36, 0, 0x1d, 0, 32}, key...))...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session ID
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// A ClientHello that repeats an extension is refused with a decode_error
// alert before anything reaches the destination, and the proxy goes on
// serving other connections.
func TestRepeatedHelloExtensionIsRefused(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, nil)

	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	if _, err := conn.Write(clienthello.Record(0x0301, dupTicketHello(allowedHost))); err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(conn)
	// alert record: type 21, version, length 2, level fatal (2), decode_error (50)
	if len(reply) != 7 || reply[0] != 21 || reply[5] != 2 || reply[6] != 50 {
		t.Fatalf("expected a decode_error alert, got %x", reply)
	}
	if !strings.Contains(p.logs.String(), "repeats extension 35") {
		t.Fatalf("no log line names the repeated extension:\n%s", p.logs.String())
	}
	select {
	case <-dest.hellos:
		t.Fatal("a ClientHello reached the destination")
	case <-time.After(200 * time.Millisecond):
	}

	conn, resp = connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	getOK(t, chromeClient(t, conn, allowedHost, p.ca), allowedHost)
}

// A uTLS panic while replaying a ClientHello fails that replay with a
// ReplayError. Parse now refuses the hello that made uTLS panic, so the test
// hands it to replay directly.
func TestReplayRecoversFromUTLSPanic(t *testing.T) {
	authority, _ := testCA(t, "proxy CA")
	hosts, err := hostmatch.New([]string{allowedHost})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := resolve.NewStatic(map[string]string{"tok_standin": "sk_live_real_secret_value"})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := resolve.NewDetector(resolver, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	s, err := New(Config{Authority: authority, Hosts: hosts, Resolver: resolver, Detector: detector, Dialer: mapDialer{}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	uconn, err := s.replay(context.Background(), log, a, allowedHost, 0x0301, dupTicketHello(allowedHost), &clienthello.Hello{})
	var replayErr *ReplayError
	if uconn != nil || !errors.As(err, &replayErr) {
		t.Fatalf("got %v, %v", uconn, err)
	}
	if !strings.Contains(logs.String(), "uTLS panicked") || !strings.Contains(logs.String(), "syncSessionExts") {
		t.Fatalf("no log line for the panic:\n%s", logs.String())
	}
}

// panicDialer panics when asked for panicTarget.
type panicDialer struct{ mapDialer }

const panicTarget = "panic.test:443"

func (d panicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == panicTarget {
		panic("sk_live_real_secret_value")
	}
	return d.mapDialer.DialContext(ctx, network, addr)
}

// A panic in a connection handler closes that connection only. The log
// line does not carry the panic value, which could hold anything.
func TestHandlerPanicClosesOnlyItsConnection(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, nil, dest.ca, func(c *Config) {
		c.Dialer = panicDialer{mapDialer{allowedHost + ":443": dest.addr}}
	})

	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+panicTarget+" HTTP/1.1\r\nHost: "+panicTarget+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if reply, err := io.ReadAll(conn); err != nil || len(reply) != 0 {
		t.Fatalf("expected the connection closed, got %q, %v", reply, err)
	}

	conn2, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	getOK(t, chromeClient(t, conn2, allowedHost, p.ca), allowedHost)

	// The handler closes the connection before the panic reaches the
	// recover that logs it.
	var logs string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if logs = p.logs.String(); strings.Contains(logs, "connection handler panicked") {
			break
		}
	}
	if !strings.Contains(logs, "connection handler panicked") || !strings.Contains(logs, "panicDialer.DialContext") {
		t.Fatalf("no log line for the panic:\n%s", logs)
	}
	if strings.Contains(logs, "sk_live_real_secret_value") {
		t.Fatalf("the log carries the panic value:\n%s", logs)
	}
}
