package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echoServer echoes one line back.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func roundTrip(t *testing.T, d Dialer, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo %q, %v", line, err)
	}
}

// httpParent is a CONNECT proxy that requires user:secret.
func httpParent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Method != http.MethodConnect || req.Header.Get("Proxy-Authorization") != want {
					_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
					return
				}
				target, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer target.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(target, br) }()
				_, _ = io.Copy(conn, target)
			}()
		}
	}()
	return ln.Addr().String()
}

// socksParent is a SOCKS5 proxy that requires user:secret (RFC 1928, 1929).
func socksParent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 512)
				// Greeting: require username/password (method 2).
				if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 5 {
					return
				}
				if _, err := io.ReadFull(conn, buf[:buf[1]]); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 2})
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				user := make([]byte, buf[1])
				_, _ = io.ReadFull(conn, user)
				_, _ = io.ReadFull(conn, buf[:1])
				pass := make([]byte, buf[0])
				_, _ = io.ReadFull(conn, pass)
				if string(user) != "user" || string(pass) != "secret" {
					_, _ = conn.Write([]byte{1, 1})
					return
				}
				_, _ = conn.Write([]byte{1, 0})
				// Request: CONNECT to a domain name or IPv4 address.
				if _, err := io.ReadFull(conn, buf[:4]); err != nil || buf[1] != 1 {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					_, _ = io.ReadFull(conn, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					_, _ = io.ReadFull(conn, buf[:1])
					name := make([]byte, buf[0])
					_, _ = io.ReadFull(conn, name)
					host = string(name)
				default:
					return
				}
				_, _ = io.ReadFull(conn, buf[:2])
				port := binary.BigEndian.Uint16(buf[:2])
				target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
				if err != nil {
					_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer target.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(target, conn) }()
				_, _ = io.Copy(conn, target)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDirect(t *testing.T) {
	d, err := New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, d, echoServer(t))
}

func TestHTTPParentWithCredentials(t *testing.T) {
	echo, parent := echoServer(t), httpParent(t)
	d, err := New(&url.URL{Scheme: "http", Host: parent, User: url.UserPassword("user", "secret")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, d, echo)

	wrong, err := New(&url.URL{Scheme: "http", Host: parent, User: url.UserPassword("user", "nope")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.DialContext(context.Background(), "tcp", echo); err == nil {
		t.Fatal("wrong credentials were accepted")
	}
}

func TestSOCKS5ParentWithCredentials(t *testing.T) {
	echo, parent := echoServer(t), socksParent(t)
	d, err := New(&url.URL{Scheme: "socks5", Host: parent, User: url.UserPassword("user", "secret")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, d, echo)
}

func TestNewRejectsBadParents(t *testing.T) {
	for _, raw := range []string{"ftp://h:1", "http://nohost", "socks4://h:1"} {
		u, _ := url.Parse(raw)
		if _, err := New(u, nil, nil); err == nil {
			t.Errorf("New(%q) succeeded", raw)
		}
	}
}

func TestParentErrorsLeaveCredentialsOut(t *testing.T) {
	u, err := url.Parse("http://minted-user:secret@nohost")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(u, nil, nil)
	if err == nil || strings.Contains(err.Error(), "minted-user") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error %v", err)
	}
}
