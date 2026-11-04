package proxy

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
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
	var firstErr error
	for i, addr := range addrs {
		conn, err := s.dialAddr(ctx, net.JoinHostPort(addr.Unmap().String(), port), len(addrs)-i)
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}

// dialAddr dials one of a destination's addresses, giving it a share of the
// time left so that an address that does not answer leaves time for the
// remaining ones, as net.Dialer does.
func (s *Server) dialAddr(ctx context.Context, addr string, remaining int) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok && remaining > 1 {
		left := time.Until(deadline)
		share := max(left/time.Duration(remaining), min(left, 2*time.Second))
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, share)
		defer cancel()
	}
	return s.cfg.Dialer.DialContext(ctx, "tcp", addr)
}
