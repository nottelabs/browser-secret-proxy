package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nottelabs/browser-secret-proxy/internal/certs"
	"github.com/nottelabs/browser-secret-proxy/internal/clienthello"
	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

const (
	allowedHost = "allowed.test"
	otherHost   = "other.test"
)

// testCA returns a new CA as an Authority and a pool that trusts it.
func testCA(t *testing.T, name string) (*certs.Authority, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := certs.New(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(authority.CA())
	return authority, pool
}

// mapDialer sends each host:port to a local address.
type mapDialer map[string]string

func (m mapDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	target, ok := m[addr]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: io.ErrUnexpectedEOF}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// destination is a TLS server that records each ClientHello it receives.
type destination struct {
	addr   string
	hellos chan []byte // raw ClientHello handshake messages
	ca     *x509.CertPool
}

func startDestination(t *testing.T, host string, nextProtos []string, handle func(*tls.Conn)) *destination {
	t.Helper()
	authority, pool := testCA(t, "destination CA")
	cert, err := authority.Certificate(host)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	d := &destination{addr: ln.Addr().String(), hellos: make(chan []byte, 16), ca: pool}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				consumed, _, message, err := clienthello.Read(conn)
				if err != nil {
					return
				}
				d.hellos <- message
				tlsConn := tls.Server(&readerConn{Conn: conn, r: io.MultiReader(bytes.NewReader(consumed), conn)}, &tls.Config{
					Certificates: []tls.Certificate{*cert},
					NextProtos:   nextProtos,
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				handle(tlsConn)
			}()
		}
	}()
	return d
}

type testProxy struct {
	addr   string
	ca     *x509.CertPool
	logs   *syncBuffer
	ln     net.Listener
	served chan error // Serve's result
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startProxy(t *testing.T, dialer mapDialer, destinationCAs *x509.CertPool, mutate func(*Config)) *testProxy {
	t.Helper()
	authority, pool := testCA(t, "proxy CA")
	hosts, err := hostmatch.New([]string{allowedHost})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := resolve.NewStatic(map[string]string{
		"4242424242424242": "4111111111111111",
		"tok_standin":      "sk_live_real_secret_value",
	})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := resolve.NewDetector(resolver, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	cfg := Config{
		Authority: authority, Hosts: hosts, Resolver: resolver, Detector: detector, Dialer: dialer, RootCAs: destinationCAs,
		HandshakeTimeout: 10 * time.Second, MaskResponses: true,
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		if t.Failed() {
			t.Logf("proxy log:\n%s", logs.String())
		}
	})
	return &testProxy{addr: ln.Addr().String(), ca: pool, logs: logs, ln: ln, served: served}
}

// connect opens a CONNECT tunnel through the proxy.
func connect(t *testing.T, proxyAddr, target, authorization string) (net.Conn, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if authorization != "" {
		request += "Proxy-Authorization: " + authorization + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK && br.Buffered() > 0 {
		t.Fatal("proxy sent bytes after its CONNECT response")
	}
	return conn, resp
}

// recordingConn records what the client writes.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// sentHello returns the ClientHello message the client wrote.
func (c *recordingConn) sentHello(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _, message, err := clienthello.Read(bytes.NewReader(c.written.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// chromeClient runs a uTLS Chrome handshake over conn.
func chromeClient(t *testing.T, conn net.Conn, serverName string, roots *x509.CertPool) *utls.UConn {
	t.Helper()
	uconn := utls.UClient(conn, &utls.Config{ServerName: serverName, RootCAs: roots}, utls.HelloChrome_Auto)
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return uconn
}

func parseHello(t *testing.T, message []byte) *clienthello.Hello {
	t.Helper()
	h, err := clienthello.Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
