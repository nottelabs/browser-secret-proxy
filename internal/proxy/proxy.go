// Package proxy is the forward proxy: it accepts CONNECT requests, tunnels
// hosts that are not on the allowlist untouched, and intercepts the rest.
//
// For an intercepted connection it reads the client's ClientHello, replays
// it to the destination with uTLS, checks that the replay is an exact copy,
// and only then completes the client's handshake with a certificate issued
// for the host, offering the application protocol the destination chose.
// Requests are then relayed with stand-ins swapped for real values, looked
// up for the principal the CONNECT authenticated as.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nottelabs/browser-secret-proxy/internal/certs"
	"github.com/nottelabs/browser-secret-proxy/internal/clienthello"
	"github.com/nottelabs/browser-secret-proxy/internal/h1relay"
	"github.com/nottelabs/browser-secret-proxy/internal/h2relay"
	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/upstream"
)

// Config configures a Server.
type Config struct {
	Authority *certs.Authority
	Hosts     *hostmatch.List
	// Resolver looks up the real value of each stand-in a request carries,
	// and Detector finds those stand-ins.
	Resolver resolve.Resolver
	Detector *resolve.Detector
	// Dialer reaches destinations, directly or through a parent proxy.
	Dialer upstream.Dialer
	// Username and Password, when Username is set, are required as
	// Proxy-Authorization Basic credentials on every CONNECT, unless the
	// Resolver is a resolve.Authenticator, which then checks every CONNECT's
	// credentials itself.
	Username, Password string
	// RootCAs verifies destination certificates; nil uses the system roots.
	RootCAs *x509.CertPool
	// MaxBody caps a buffered request body (default 32 MiB).
	MaxBody int
	// ResolveTimeout bounds one resolver lookup (default
	// scope.DefaultTimeout).
	ResolveTimeout time.Duration
	// MaskResponses replaces real values resolved for a connection's
	// principal with their stand-ins in responses on allowlisted hosts.
	MaskResponses    bool
	HandshakeTimeout time.Duration
	Logger           *slog.Logger
}

// shutdownWait bounds how long Serve waits for handlers after closing
// their connections.
const shutdownWait = 10 * time.Second

// Server is a forward proxy.
type Server struct {
	cfg   Config
	scope *scope.Scope
	wg    sync.WaitGroup

	mu      sync.Mutex
	conns   map[net.Conn]struct{} // client and destination connections in use
	closing bool
}

// New validates the configuration and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Authority == nil || cfg.Hosts == nil || cfg.Resolver == nil || cfg.Detector == nil || cfg.Dialer == nil {
		return nil, errors.New("proxy: authority, hosts, resolver, detector and dialer are required")
	}
	// Authentication is on only when Username is set, so a Password alone
	// would leave the proxy open while looking configured.
	if cfg.Password != "" && cfg.Username == "" {
		return nil, errors.New("proxy: a password without a username leaves authentication off: set both")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}
	sc, err := scope.New(scope.Config{Resolver: cfg.Resolver, Detector: cfg.Detector, Hosts: cfg.Hosts, Timeout: cfg.ResolveTimeout, Mask: cfg.MaskResponses, Logger: cfg.Logger})
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, scope: sc, conns: map[net.Conn]struct{}{}}, nil
}

// Serve accepts connections until the listener is closed, then closes every
// connection still open and waits (boundedly) for their handlers.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.shutdown()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// track registers a connection to close on shutdown. It returns false, after
// closing it, when the server is already shutting down.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) shutdown() {
	defer s.scope.Close()
	s.mu.Lock()
	s.closing = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownWait):
		s.cfg.Logger.Warn("stopped waiting for connection handlers", "after", shutdownWait)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if !s.track(conn) {
		return
	}
	defer s.untrack(conn)
	log := s.cfg.Logger.With("client", conn.RemoteAddr().String())
	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	// The request head is read before authentication, so it is capped:
	// http.ReadRequest itself has no limit.
	limited := &headLimiter{r: conn, remaining: maxRequestHead}
	br := bufio.NewReader(limited)
	req, err := http.ReadRequest(br)
	if err != nil {
		if errors.Is(err, errHeadTooLarge) {
			log.Warn("refusing a proxy request head over the limit", "limit_bytes", maxRequestHead)
			writeStatus(conn, http.StatusRequestHeaderFieldsTooLarge, "proxy request head too large\n")
			return
		}
		log.Debug("could not read a proxy request", "error", err)
		return
	}
	limited.disable() // what follows is tunneled or TLS, not a request head
	if req.Method != http.MethodConnect {
		writeStatus(conn, http.StatusMethodNotAllowed, "only CONNECT is supported\n")
		return
	}
	principal, ok := s.authenticate(req.Header.Get("Proxy-Authorization"))
	if !ok {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"secret-proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	target := req.Host
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		writeStatus(conn, http.StatusBadRequest, "CONNECT needs host:port\n")
		return
	}
	log = log.With("host", host, "port", port)

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.HandshakeTimeout)
	defer cancel()
	upConn, err := s.cfg.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Error("cannot reach the destination", "error", err)
		writeStatus(conn, http.StatusBadGateway, "cannot reach "+target+"\n")
		return
	}
	defer upConn.Close()
	if !s.track(upConn) {
		return
	}
	defer s.untrack(upConn)
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	if !s.cfg.Hosts.Match(host) {
		log.Debug("tunneling without decryption")
		_ = conn.SetDeadline(time.Time{})
		tunnel(&readerConn{Conn: conn, r: br}, upConn)
		return
	}
	s.intercept(ctx, log, conn, br, upConn, host, s.scope.Session(principal, host))
}

// authenticate checks a CONNECT's Proxy-Authorization and returns the
// principal its requests are resolved for. A resolve.Authenticator decides
// for itself; otherwise the configured username and password are required
// when set, and the principal is that username (empty when authentication
// is off).
func (s *Server) authenticate(header string) (resolve.Principal, bool) {
	username, password, hasCredentials := basicCredentials(header)
	if auth, ok := s.cfg.Resolver.(resolve.Authenticator); ok {
		if !hasCredentials {
			return resolve.Principal{}, false
		}
		principal, err := auth.Authenticate(username, password)
		if err != nil {
			s.cfg.Logger.Debug("proxy credential refused", "error", err)
			return resolve.Principal{}, false
		}
		return principal, true
	}
	if s.cfg.Username == "" {
		return resolve.Principal{}, true
	}
	if !hasCredentials {
		return resolve.Principal{}, false
	}
	got := []byte(username + ":" + password)
	want := []byte(s.cfg.Username + ":" + s.cfg.Password)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return resolve.Principal{}, false
	}
	return resolve.Principal{ID: username, Password: password}, true
}

// basicCredentials decodes a Basic Proxy-Authorization header.
func basicCredentials(header string) (username, password string, ok bool) {
	encoded, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", false
	}
	username, password, ok = strings.Cut(string(decoded), ":")
	return username, password, ok
}

// verbatimExtensions are ClientHello extensions uTLS does not model that are
// safe to copy byte for byte: they only carry data the server may act on, and
// a server reply the TLS client cannot handle fails the handshake loudly.
var verbatimExtensions = map[uint16]bool{
	// TLS Trust Anchor IDs (draft-ietf-tls-trust-anchor-ids), sent by
	// current Chrome: the list of trust anchors the client accepts.
	0xca34: true,
}

// maxRequestHead caps the CONNECT request line and headers.
const maxRequestHead = 64 << 10

var errHeadTooLarge = errors.New("proxy request head too large")

// headLimiter fails reads once more than remaining bytes were read, until it
// is disabled.
type headLimiter struct {
	r         io.Reader
	remaining int
	off       bool
}

func (l *headLimiter) Read(p []byte) (int, error) {
	if l.off {
		return l.r.Read(p)
	}
	if l.remaining <= 0 {
		return 0, errHeadTooLarge
	}
	if len(p) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= n
	return n, err
}

func (l *headLimiter) disable() { l.off = true }

// ReplayError is a ClientHello that cannot be copied exactly.
type ReplayError struct{ Reason string }

func (e *ReplayError) Error() string {
	return "cannot replay the client's ClientHello exactly: " + e.Reason
}

func (s *Server) intercept(ctx context.Context, log *slog.Logger, conn net.Conn, br *bufio.Reader, upConn net.Conn, host string, session *scope.Session) {
	consumed, recordVersion, message, err := clienthello.Read(br)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Browsers open spare connections and close some unused.
			log.Debug("client closed before sending a ClientHello")
		} else {
			log.Error("cannot read the client's ClientHello", "error", err)
		}
		return
	}
	clientConn := &readerConn{Conn: conn, r: io.MultiReader(bytes.NewReader(consumed), br)}
	original, err := clienthello.Parse(message)
	if err != nil {
		log.Error("cannot parse the client's ClientHello", "error", err)
		return
	}

	uconn, err := s.replay(ctx, upConn, host, recordVersion, message, original)
	if err != nil {
		var replayErr *ReplayError
		if errors.As(err, &replayErr) {
			log.Error("refusing connection: ClientHello cannot be replayed exactly", "reason", replayErr.Reason)
		} else {
			log.Error("upstream TLS handshake failed", "error", err)
		}
		s.failClient(clientConn, host, original, err)
		return
	}
	defer uconn.Close()
	protocol := uconn.ConnectionState().NegotiatedProtocol

	cert, err := s.cfg.Authority.Certificate(host)
	if err != nil {
		log.Error("cannot issue a certificate", "error", err)
		return
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		// A resumed session would put a pre_shared_key in the next
		// ClientHello, which cannot be replayed to the destination.
		SessionTicketsDisabled: true,
	}
	if protocol != "" {
		serverConfig.NextProtos = []string{protocol}
	}
	tlsConn := tls.Server(clientConn, serverConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if errors.Is(err, io.EOF) {
			log.Debug("client closed during the TLS handshake")
		} else {
			log.Error("client TLS handshake failed", "error", err)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = upConn.SetDeadline(time.Time{})
	log.Info("intercepting", "protocol", protocolName(protocol), "principal", session.Principal().ID)

	if protocol == "h2" {
		err = h2relay.Serve(tlsConn, uconn, h2relay.Options{Hosts: s.cfg.Hosts, Session: session, MaxBody: s.cfg.MaxBody, Logger: log})
	} else {
		err = h1relay.Serve(tlsConn, uconn, h1relay.Options{Hosts: s.cfg.Hosts, Session: session, MaxBody: s.cfg.MaxBody, Logger: log})
	}
	if err != nil {
		log.Warn("connection ended with an error", "error", err)
	}
}

// replay rebuilds the client's ClientHello with uTLS, checks the copy and
// completes the handshake with the destination.
func (s *Server) replay(ctx context.Context, upConn net.Conn, host string, recordVersion uint16, message []byte, original *clienthello.Hello) (*utls.UConn, error) {
	sni := original.ServerName()
	if sni != "" && !strings.EqualFold(strings.TrimSuffix(sni, "."), host) {
		return nil, &ReplayError{Reason: fmt.Sprintf("SNI %q does not match the CONNECT host %q", sni, host)}
	}
	if _, ok := original.Extension(clienthello.ExtPreSharedKey); ok {
		return nil, &ReplayError{Reason: "the client tried to resume a TLS session (pre_shared_key)"}
	}
	if _, ok := original.Extension(clienthello.ExtEarlyData); ok {
		return nil, &ReplayError{Reason: "the client sent early data"}
	}
	// Blunt mimicry turns an extension uTLS does not model into a verbatim
	// copy; only the codepoints in verbatimExtensions may be copied that way,
	// any other one fails the connection.
	fingerprinter := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fingerprinter.FingerprintClientHello(clienthello.Record(recordVersion, message))
	if err != nil {
		return nil, &ReplayError{Reason: err.Error()}
	}
	for _, ext := range spec.Extensions {
		if generic, ok := ext.(*utls.GenericExtension); ok && !verbatimExtensions[generic.Id] {
			return nil, &ReplayError{Reason: fmt.Sprintf("unsupported extension %d", generic.Id)}
		}
	}
	serverName := sni
	if serverName == "" {
		serverName = host
	}
	uconn := utls.UClient(upConn, &utls.Config{ServerName: serverName, RootCAs: s.cfg.RootCAs}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, &ReplayError{Reason: "uTLS rejected the ClientHello: " + err.Error()}
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, &ReplayError{Reason: "uTLS cannot build the ClientHello: " + err.Error()}
	}
	copied, err := clienthello.Parse(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		return nil, &ReplayError{Reason: "the rebuilt ClientHello does not parse: " + err.Error()}
	}
	if err := clienthello.Compare(original, copied); err != nil {
		return nil, &ReplayError{Reason: err.Error()}
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

// failClient tells the client why its connection failed: it completes the
// handshake and answers HTTP/1.1 502 when the client offered HTTP/1.1, and
// otherwise ends the handshake with a TLS alert.
func (s *Server) failClient(clientConn net.Conn, host string, original *clienthello.Hello, cause error) {
	offered := original.ALPN()
	http1 := len(offered) == 0
	for _, p := range offered {
		if p == "http/1.1" {
			http1 = true
		}
	}
	cert, err := s.cfg.Authority.Certificate(host)
	if err != nil || !http1 {
		_ = clientConn.Close()
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true}
	if len(offered) > 0 {
		config.NextProtos = []string{"http/1.1"}
	}
	tlsConn := tls.Server(clientConn, config)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	writeStatus(tlsConn, http.StatusBadGateway, "secret-proxy: "+cause.Error()+"\n")
	_ = tlsConn.Close()
}

func writeStatus(w io.Writer, code int, body string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

func protocolName(p string) string {
	if p == "" {
		return "http/1.1 (no ALPN)"
	}
	return p
}

// readerConn is a net.Conn whose reads come from r.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
