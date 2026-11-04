// Package upstream opens TCP connections to destinations, directly or through
// a parent proxy (http, https or socks5, with optional credentials).
package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer opens a connection to addr ("host:port").
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// New returns a direct dialer when parent is nil, else one that goes through
// the parent proxy. rootCAs (nil for the system roots) verifies an https
// parent proxy.
func New(parent *url.URL, base *net.Dialer, rootCAs *x509.CertPool) (Dialer, error) {
	if base == nil {
		base = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	}
	if parent == nil {
		return base, nil
	}
	if parent.Host == "" || parent.Port() == "" {
		// Scheme and host only: the URL carries credentials.
		return nil, fmt.Errorf("parent proxy %s://%s needs a host and a port", parent.Scheme, parent.Host)
	}
	switch parent.Scheme {
	case "http", "https":
		d := &connectDialer{base: base, proxy: parent}
		if parent.Scheme == "https" {
			d.tlsConfig = &tls.Config{ServerName: parent.Hostname(), MinVersion: tls.VersionTLS12, RootCAs: rootCAs}
		}
		return d, nil
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if parent.User != nil {
			password, _ := parent.User.Password()
			auth = &proxy.Auth{User: parent.User.Username(), Password: password}
		}
		d, err := proxy.SOCKS5("tcp", parent.Host, auth, base)
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks5 dialer does not support contexts")
		}
		return cd, nil
	default:
		return nil, fmt.Errorf("parent proxy scheme %q is not supported (use http, https or socks5)", parent.Scheme)
	}
}

// connectDialer tunnels through an HTTP(S) proxy with CONNECT.
type connectDialer struct {
	base      *net.Dialer
	proxy     *url.URL
	tlsConfig *tls.Config
}

func (d *connectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.base.DialContext(ctx, "tcp", d.proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("parent proxy %s: %w", d.proxy.Host, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, has := ctx.Deadline(); has {
		_ = conn.SetDeadline(deadline)
	}
	if d.tlsConfig != nil {
		tc := tls.Client(conn, d.tlsConfig.Clone())
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("parent proxy %s TLS: %w", d.proxy.Host, err)
		}
		conn = tc
	}
	request := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if d.proxy.User != nil {
		password, _ := d.proxy.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(d.proxy.User.Username() + ":" + password))
		request += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	if _, err := conn.Write([]byte(request + "\r\n")); err != nil {
		return nil, fmt.Errorf("parent proxy %s: %w", d.proxy.Host, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("parent proxy %s: %w", d.proxy.Host, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("parent proxy %s answered CONNECT %s with %s", d.proxy.Host, addr, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
