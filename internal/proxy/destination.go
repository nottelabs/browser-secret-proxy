package proxy

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/panics"
)

// destinationError is a CONNECT destination the proxy refuses to dial.
type destinationError struct {
	addr   string // the address or host refused
	reason string // its kind: loopback, private, ...
}

func (e *destinationError) Error() string {
	return "destination " + e.addr + " is " + e.reason
}

// sharedAddressSpace is 100.64.0.0/10 (RFC 6598), used by carrier-grade NAT
// and by some cloud providers for internal services.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// blockedReason names the kind of internal address addr is, or returns ""
// for an address the proxy may dial. IPv4-mapped (::ffff:a.b.c.d) and
// IPv4-compatible (::a.b.c.d) addresses are judged by their IPv4 address.
func blockedReason(addr netip.Addr) string {
	addr = addr.WithZone("")
	if addr.Is6() && !addr.Is4In6() && addr != netip.IPv6Unspecified() && addr != netip.IPv6Loopback() {
		if b := addr.As16(); [12]byte(b[:12]) == [12]byte{} {
			addr = netip.AddrFrom4([4]byte(b[12:]))
		}
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified(), addr.Is4() && addr.As4()[0] == 0:
		return "unspecified"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsPrivate():
		return "private"
	case addr.IsLinkLocalUnicast():
		return "link-local"
	case addr.IsMulticast():
		return "multicast"
	case sharedAddressSpace.Contains(addr):
		return "shared (CGNAT)"
	}
	return ""
}

// numericHost reports whether host, which is not an IP address in standard
// form, ends in a number: "127.1", "2130706433" or "0x7f.0.0.1". Some
// resolvers read such a name as an IPv4 address, so the proxy cannot vet
// it by name.
func numericHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	last := host[strings.LastIndexByte(host, '.')+1:]
	if hex, ok := strings.CutPrefix(strings.ToLower(last), "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return last != "" && strings.Trim(last, "0123456789") == ""
}

// dial connects to host:port. Unless private destinations are allowed, it
// refuses an internal destination with a *destinationError: it resolves a
// name once, checks every address and dials only the addresses it checked,
// so a second DNS answer cannot send the connection elsewhere. Through a
// parent proxy, which resolves names itself, only IP literals are checked.
func (s *Server) dial(ctx context.Context, host, port string) (net.Conn, error) {
	target := net.JoinHostPort(host, port)
	if s.cfg.AllowPrivateDestinations {
		return s.cfg.Dialer.DialContext(ctx, "tcp", target)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if reason := blockedReason(addr); reason != "" {
			return nil, &destinationError{addr: host, reason: reason}
		}
		return s.cfg.Dialer.DialContext(ctx, "tcp", target)
	}
	if numericHost(host) {
		return nil, &destinationError{addr: host, reason: "numeric host"}
	}
	if s.cfg.ParentProxy {
		return s.cfg.Dialer.DialContext(ctx, "tcp", target)
	}
	lookup := s.cfg.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	// A name with any internal address is refused rather than dialed at
	// its other addresses: it points inside, by mistake or on purpose,
	// and a refusal shows it.
	for _, addr := range addrs {
		if reason := blockedReason(addr); reason != "" {
			return nil, &destinationError{addr: addr.String(), reason: reason}
		}
	}
	return s.dialAddrs(ctx, interleaveFamilies(addrs), port)
}

// fallbackDelay is how long a dial to one of a destination's addresses runs
// alone before the next address is dialed as well, as net.Dialer's
// FallbackDelay (RFC 8305 5).
const fallbackDelay = 300 * time.Millisecond

// dialResult is the outcome of dialing addrs[i] in dialAddrs.
type dialResult struct {
	i    int
	conn net.Conn
	err  error
}

// dialAddrs dials the checked addresses in order and returns the first
// connection made. The next address is dialed once the previous dials have
// failed, or have run for fallbackDelay without an answer, so an address
// that drops connection attempts delays a connection by fallbackDelay, not
// by its timeout. Dials still running when one succeeds are canceled, and
// a connection they make anyway is closed. When every dial fails, the error
// is the first address's.
func (s *Server) dialAddrs(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(addrs))
	errs := make([]error, len(addrs))
	next, running := 0, 0
	start := func() {
		i := next
		next++
		running++
		target := net.JoinHostPort(addrs[i].Unmap().String(), port)
		go func() {
			defer panics.Recover(func(p *panics.Error) {
				results <- dialResult{i: i, err: p}
			})
			conn, err := s.cfg.Dialer.DialContext(ctx, "tcp", target)
			results <- dialResult{i: i, conn: conn, err: err}
		}()
	}
	start()
	fallback := time.NewTimer(fallbackDelay)
	defer fallback.Stop()
	for running > 0 {
		select {
		case r := <-results:
			running--
			if r.err == nil {
				cancel()
				go closeDials(results, running)
				return r.conn, nil
			}
			errs[r.i] = r.err
			if next < len(addrs) && ctx.Err() == nil {
				start()
				fallback.Reset(fallbackDelay)
			}
		case <-fallback.C:
			if next < len(addrs) && ctx.Err() == nil {
				start()
				fallback.Reset(fallbackDelay)
			}
		}
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return nil, ctx.Err()
}

// closeDials waits for the n dials still running once another has won, and
// closes any connection they made.
func closeDials(results <-chan dialResult, n int) {
	for ; n > 0; n-- {
		if r := <-results; r.err == nil {
			_ = r.conn.Close()
		}
	}
}

// interleaveFamilies orders addrs so that the address families alternate,
// starting with the family of the first address and keeping the order
// within each family (RFC 8305 4): when one family does not work, the next
// dial is to the other one.
func interleaveFamilies(addrs []netip.Addr) []netip.Addr {
	var first, other []netip.Addr
	for _, addr := range addrs {
		if addr.Unmap().Is4() == addrs[0].Unmap().Is4() {
			first = append(first, addr)
		} else {
			other = append(other, addr)
		}
	}
	out := make([]netip.Addr, 0, len(addrs))
	for i := 0; i < len(first) || i < len(other); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(other) {
			out = append(out, other[i])
		}
	}
	return out
}
