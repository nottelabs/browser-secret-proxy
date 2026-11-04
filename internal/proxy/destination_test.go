package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/upstream"
)

func TestBlockedReason(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1":              "loopback",
		"127.255.0.9":            "loopback",
		"::1":                    "loopback",
		"10.1.2.3":               "private",
		"172.16.0.1":             "private",
		"172.31.255.255":         "private",
		"192.168.1.1":            "private",
		"fc00::1":                "private",
		"fd00::1":                "private",
		"169.254.169.254":        "link-local",
		"fe80::1":                "link-local",
		"fe80::1%eth0":           "link-local",
		"0.0.0.0":                "unspecified",
		"0.1.2.3":                "unspecified",
		"::":                     "unspecified",
		"224.0.0.1":              "multicast",
		"239.1.2.3":              "multicast",
		"ff02::1":                "multicast",
		"100.64.0.1":             "shared (CGNAT)",
		"100.127.255.255":        "shared (CGNAT)",
		"::ffff:127.0.0.1":       "loopback",
		"::ffff:7f00:2":          "loopback",
		"::ffff:10.0.0.1":        "private",
		"::ffff:169.254.169.254": "link-local",
		"::ffff:100.64.0.1":      "shared (CGNAT)",
		"::127.0.0.1":            "loopback",
		"::10.0.0.1":             "private",
		"::169.254.169.254":      "link-local",
		"8.8.8.8":                "",
		"203.0.113.7":            "",
		"100.63.255.255":         "",
		"100.128.0.0":            "",
		"172.32.0.1":             "",
		"192.169.0.1":            "",
		"::ffff:8.8.8.8":         "",
		"::1.1.1.1":              "",
		"2606:4700:4700::1111":   "",
		"2001:db8::1":            "",
	} {
		if got := blockedReason(netip.MustParseAddr(addr)); got != want {
			t.Errorf("blockedReason(%s) = %q, want %q", addr, got, want)
		}
	}
}

func TestNumericHost(t *testing.T) {
	for host, want := range map[string]bool{
		"2130706433":      true,
		"127.1":           true,
		"0x7f.0.0.1":      true,
		"0x7f000001":      true,
		"0X7F000001":      true,
		"017700000001":    true,
		"10.0.0.1.":       true,
		"api.example.com": false,
		"1.example.com":   false,
		"0x7f.example":    false,
		"example.0xg":     false,
		"allowed.test":    false,
	} {
		if got := numericHost(host); got != want {
			t.Errorf("numericHost(%q) = %v", host, got)
		}
	}
}

// blockedCases are CONNECT targets the proxy refuses by default. The literal
// ones are refused before any lookup; the names resolve (with the test
// lookup) to internal addresses.
var blockedCases = []struct {
	target string
	ips    []string // the test lookup's answer for a name
}{
	{target: "127.0.0.1:443"},
	{target: "[::1]:443"},
	{target: "10.0.0.1:443"},
	{target: "192.168.1.1:22"},
	{target: "[fd12::1]:443"},
	{target: "169.254.169.254:80"},
	{target: "[fe80::1]:443"},
	{target: "0.0.0.0:443"},
	{target: "[::]:443"},
	{target: "224.0.0.1:443"},
	{target: "100.64.0.1:443"},
	{target: "[::ffff:127.0.0.1]:443"},
	{target: "[::ffff:a9fe:a9fe]:80"},
	{target: "[::127.0.0.1]:443"},
	{target: "2130706433:443"},
	{target: "127.1:443"},
	{target: "0x7f.0.0.1:443"},
	{target: "localhost:443", ips: []string{"127.0.0.1", "::1"}},
	{target: otherHost + ":443", ips: []string{"10.20.30.40"}},
	{target: allowedHost + ":443", ips: []string{"169.254.169.254"}},
	// One internal address is enough: the proxy does not pick the
	// public one, since a second lookup could answer differently.
	{target: allowedHost + ":443", ips: []string{"203.0.113.7", "127.0.0.1"}},
}

// fakeLookup answers names from a map and counts its calls.
type fakeLookup struct {
	mu      sync.Mutex
	answers map[string][]string
	calls   map[string]int
}

func (f *fakeLookup) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[host]++
	var addrs []netip.Addr
	for _, s := range f.answers[host] {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

func (f *fakeLookup) count(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

// recordingDialer records the addresses it is asked for and dials them
// through a mapDialer.
type recordingDialer struct {
	mu     sync.Mutex
	addrs  []string
	routes mapDialer
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	return d.routes.DialContext(ctx, network, addr)
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// By default, a CONNECT to a loopback, private, link-local or otherwise
// internal address is refused with 403 before anything is dialed, whether
// the host is tunneled or allowlisted, an IP literal or a name.
func TestInternalDestinationsAreRefused(t *testing.T) {
	for _, c := range blockedCases {
		t.Run(c.target, func(t *testing.T) {
			host, _, _ := net.SplitHostPort(c.target)
			lookup := &fakeLookup{answers: map[string][]string{host: c.ips}}
			dialer := &recordingDialer{}
			p := startProxy(t, nil, nil, func(cfg *Config) {
				cfg.Dialer = dialer
				cfg.AllowPrivateDestinations = false
				cfg.lookup = lookup.lookup
				cfg.Username, cfg.Password = "u", "p"
			})
			auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
			_, resp := connect(t, p.addr, c.target, auth)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("CONNECT %s answered %s", c.target, resp.Status)
			}
			if strings.Contains(string(body), host) {
				t.Fatalf("the refusal names the destination: %q", body)
			}
			if got := dialer.dialed(); len(got) != 0 {
				t.Fatalf("dialed %v", got)
			}
			wantLookups := 0 // literals and numeric hosts are refused unresolved
			if len(c.ips) > 0 {
				wantLookups = 1
			}
			if lookup.count(host) != wantLookups {
				t.Fatalf("%d lookups of %s", lookup.count(host), host)
			}
			logs := p.logs.String()
			if !strings.Contains(logs, `level=WARN msg="refusing an internal destination"`) {
				t.Fatalf("no refusal log line:\n%s", logs)
			}
			if strings.Contains(logs, "dTpw") || strings.Contains(logs, "u:p") {
				t.Fatalf("the credential reached the log:\n%s", logs)
			}
		})
	}
}

// The real dialer cannot reach a loopback service by default (the audit's
// pivot), and reaches it when private destinations are allowed.
func TestLoopbackServiceNeedsAllowPrivateDestinations(t *testing.T) {
	internal, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = internal.Close() })
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := internal.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() {
				defer c.Close()
				ping := make([]byte, len("ping\n"))
				if _, err := io.ReadFull(c, ping); err == nil {
					_, _ = io.WriteString(c, "INTERNAL-SERVICE-BANNER\n")
				}
			}()
		}
	}()
	direct, err := upstream.New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	refusing := startProxy(t, nil, nil, func(c *Config) {
		c.Dialer = direct
		c.AllowPrivateDestinations = false
	})
	_, resp := connect(t, refusing.addr, internal.Addr().String(), "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("default proxy answered %s", resp.Status)
	}
	select {
	case <-accepted:
		t.Fatal("the loopback service was reached")
	case <-time.After(100 * time.Millisecond):
	}

	allowing := startProxy(t, nil, nil, func(c *Config) {
		c.Dialer = direct
		c.AllowPrivateDestinations = true
	})
	conn, resp := connect(t, allowing.addr, internal.Addr().String(), "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy with private destinations allowed answered %s", resp.Status)
	}
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, len("INTERNAL-SERVICE-BANNER\n"))
	if _, err := io.ReadFull(conn, line); err != nil || string(line) != "INTERNAL-SERVICE-BANNER\n" {
		t.Fatalf("read %q: %v", line, err)
	}
}

// A destination name is resolved once, and the proxy dials the address it
// checked, never the name: a second, different DNS answer cannot redirect
// the connection. The destination still sees the name in SNI and Host.
func TestDestinationIsDialedAtTheCheckedAddress(t *testing.T) {
	for _, host := range []string{allowedHost, otherHost} {
		t.Run(host, func(t *testing.T) {
			dest := startDestination(t, host, []string{"http/1.1"}, respondOK)
			lookup := &fakeLookup{answers: map[string][]string{host: {"203.0.113.7"}}}
			dialer := &recordingDialer{routes: mapDialer{"203.0.113.7:443": dest.addr}}
			p := startProxy(t, nil, dest.ca, func(c *Config) {
				c.Dialer = dialer
				c.AllowPrivateDestinations = false
				c.lookup = lookup.lookup
			})
			conn, resp := connect(t, p.addr, host+":443", "")
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT answered %s", resp.Status)
			}
			roots := p.ca
			if host == otherHost {
				roots = dest.ca
			}
			tlsConn := tlsClient(t, conn, host, roots)
			getOK(t, tlsConn, host)
			if got := dialer.dialed(); len(got) != 1 || got[0] != "203.0.113.7:443" {
				t.Fatalf("dialed %v", got)
			}
			if n := lookup.count(host); n != 1 {
				t.Fatalf("%d lookups", n)
			}
		})
	}
}

// When the first checked address does not answer, the next one is dialed.
func TestDestinationAddressesAreTriedInTurn(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	lookup := &fakeLookup{answers: map[string][]string{otherHost: {"2001:db8::7", "203.0.113.8"}}}
	dialer := &recordingDialer{routes: mapDialer{"203.0.113.8:443": dest.addr}}
	p := startProxy(t, nil, dest.ca, func(c *Config) {
		c.Dialer = dialer
		c.AllowPrivateDestinations = false
		c.lookup = lookup.lookup
	})
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	getOK(t, tlsClient(t, conn, otherHost, dest.ca), otherHost)
	if got := dialer.dialed(); len(got) != 2 || got[0] != "[2001:db8::7]:443" || got[1] != "203.0.113.8:443" {
		t.Fatalf("dialed %v", got)
	}
}

// stallingDialer never answers for stall: it waits until the dial's context
// ends and records how long that took, then closes done. Other addresses go
// to next.
type stallingDialer struct {
	stall  string
	next   *recordingDialer
	done   chan struct{}
	mu     sync.Mutex
	waited time.Duration
}

func (d *stallingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != d.stall {
		return d.next.DialContext(ctx, network, addr)
	}
	_, _ = d.next.DialContext(ctx, network, addr) // records it; no route
	start := time.Now()
	<-ctx.Done()
	d.mu.Lock()
	d.waited = time.Since(start)
	d.mu.Unlock()
	close(d.done)
	return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
}

func (d *stallingDialer) stalled() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.waited
}

// When the first checked address does not answer at all, the next one is
// dialed after fallbackDelay, not after the stalled dial's share of the
// handshake timeout (15s by default), and the stalled dial is canceled once
// the next one connects.
func TestStalledDestinationAddressDoesNotHoldTheNext(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	lookup := &fakeLookup{answers: map[string][]string{otherHost: {"2001:db8::7", "203.0.113.8"}}}
	dialer := &stallingDialer{
		stall: "[2001:db8::7]:443",
		next:  &recordingDialer{routes: mapDialer{"203.0.113.8:443": dest.addr}},
		done:  make(chan struct{}),
	}
	p := startProxy(t, nil, dest.ca, func(c *Config) {
		c.Dialer = dialer
		c.AllowPrivateDestinations = false
		c.lookup = lookup.lookup
	})
	start := time.Now()
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	if took := time.Since(start); took < fallbackDelay || took > fallbackDelay+5*time.Second {
		t.Fatalf("CONNECT took %v, fallback delay %v", took, fallbackDelay)
	}
	getOK(t, tlsClient(t, conn, otherHost, dest.ca), otherHost)
	if got := dialer.next.dialed(); len(got) != 2 || got[0] != "[2001:db8::7]:443" || got[1] != "203.0.113.8:443" {
		t.Fatalf("dialed %v", got)
	}
	select {
	case <-dialer.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled dial was not canceled")
	}
	if waited := dialer.stalled(); waited < fallbackDelay || waited > fallbackDelay+5*time.Second {
		t.Fatalf("the stalled address held its dial for %v", waited)
	}
}

// closeRecorder is a connection that reports when it is closed.
type closeRecorder struct {
	net.Conn
	closed chan struct{}
}

func (c *closeRecorder) Close() error {
	close(c.closed)
	return c.Conn.Close()
}

// lateDialer answers slow after delay, whatever its context says, and
// every other address at once.
type lateDialer struct {
	slow  string
	delay time.Duration
	late  *closeRecorder
}

func (d *lateDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	if addr != d.slow {
		return client, nil
	}
	time.Sleep(d.delay)
	d.late.Conn = client
	return d.late, nil
}

// A dial that connects after another address has won is closed, not leaked.
func TestLosingDestinationDialIsClosed(t *testing.T) {
	d := &lateDialer{slow: "203.0.113.7:443", delay: 2 * fallbackDelay, late: &closeRecorder{closed: make(chan struct{})}}
	s := &Server{cfg: Config{Dialer: d}}
	addrs := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("203.0.113.8")}
	conn, err := s.dialAddrs(context.Background(), addrs, "443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn == d.late {
		t.Fatal("the slow address won")
	}
	select {
	case <-d.late.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the losing connection was not closed")
	}
}

// failingDialer fails every address with an error naming it.
type failingDialer struct{}

func (failingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("refused " + addr)}
}

// When every address fails, the error is the first address's.
func TestDestinationDialErrorIsTheFirstAddresss(t *testing.T) {
	s := &Server{cfg: Config{Dialer: failingDialer{}}}
	addrs := []netip.Addr{netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("203.0.113.8"), netip.MustParseAddr("2001:db8::8")}
	_, err := s.dialAddrs(context.Background(), addrs, "443")
	if err == nil || !strings.Contains(err.Error(), "refused [2001:db8::7]:443") {
		t.Fatalf("error %v", err)
	}
}

func TestInterleaveFamilies(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.1", "203.0.113.1"},
		{"2001:db8::1 2001:db8::2 2001:db8::3 203.0.113.1", "2001:db8::1 203.0.113.1 2001:db8::2 2001:db8::3"},
		{"203.0.113.1 203.0.113.2 2001:db8::1 2001:db8::2", "203.0.113.1 2001:db8::1 203.0.113.2 2001:db8::2"},
		{"::ffff:203.0.113.1 2001:db8::1 203.0.113.2", "::ffff:203.0.113.1 2001:db8::1 203.0.113.2"},
	} {
		var in []netip.Addr
		for _, a := range strings.Fields(c.in) {
			in = append(in, netip.MustParseAddr(a))
		}
		var got []string
		for _, a := range interleaveFamilies(in) {
			got = append(got, a.String())
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("interleaveFamilies(%s) = %s, want %s", c.in, strings.Join(got, " "), c.want)
		}
	}
}

// A name that does not resolve is answered 502, like a destination that
// cannot be reached.
func TestUnresolvableDestination(t *testing.T) {
	dialer := &recordingDialer{}
	p := startProxy(t, nil, nil, func(c *Config) {
		c.Dialer = dialer
		c.AllowPrivateDestinations = false
		c.lookup = (&fakeLookup{}).lookup
	})
	_, resp := connect(t, p.addr, "unresolvable.test:443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	if got := dialer.dialed(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
}

// Through a parent proxy, names are passed on for the parent to resolve,
// and only IP literals are checked.
func TestParentProxyResolvesNames(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	lookup := &fakeLookup{answers: map[string][]string{otherHost: {"127.0.0.1"}}}
	dialer := &recordingDialer{routes: mapDialer{otherHost + ":443": dest.addr}}
	p := startProxy(t, nil, dest.ca, func(c *Config) {
		c.Dialer = dialer
		c.AllowPrivateDestinations = false
		c.ParentProxy = true
		c.lookup = lookup.lookup
	})
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s answered %s", otherHost, resp.Status)
	}
	getOK(t, tlsClient(t, conn, otherHost, dest.ca), otherHost)
	if n := lookup.count(otherHost); n != 0 {
		t.Fatalf("the proxy looked the name up %d times", n)
	}
	for _, target := range []string{"127.0.0.1:443", "[::ffff:10.0.0.1]:443", "169.254.169.254:80", "2130706433:80"} {
		_, resp := connect(t, p.addr, target, "")
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT %s through a parent answered %s", target, resp.Status)
		}
	}
	if got := dialer.dialed(); len(got) != 1 || got[0] != otherHost+":443" {
		t.Fatalf("dialed %v", got)
	}
}

// tlsClient completes an HTTP/1.1 TLS handshake over conn.
func tlsClient(t *testing.T, conn net.Conn, host string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tlsConn
}
