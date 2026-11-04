package proxy

import (
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A proxy request head that does not parse is logged, at debug level, by
// category only: the parse error quotes the offending line, which can carry
// the client's credential.
func TestUnreadableRequestHeadsLeaveCredentialsOut(t *testing.T) {
	credential := base64.StdEncoding.EncodeToString([]byte("u:supersecretpw"))
	heads := map[string]struct{ head, reason string }{
		"header without a colon": {
			"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\nProxy-Authorization Basic " + credential + "\r\n\r\n",
			"malformed request head",
		},
		"credential as the request line": {"Proxy-Authorization: Basic " + credential + "\r\n\r\n", "malformed request head"},
		"closed in the head": {
			"CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: Basic " + credential + "\r\n",
			"closed during the request head",
		},
	}
	for name, c := range heads {
		t.Run(name, func(t *testing.T) {
			head := c.head
			p := startProxy(t, nil, nil, func(c *Config) { c.Username, c.Password = "u", "supersecretpw" })
			conn, err := net.Dial("tcp", p.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(conn, head); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(head, "\r\n\r\n") {
				_, _ = io.ReadAll(conn) // the proxy logs, then closes
			} else {
				_ = conn.(*net.TCPConn).CloseWrite()
				_, _ = io.ReadAll(conn)
			}
			logs := p.logs.String()
			if !strings.Contains(logs, "could not read a proxy request") || !strings.Contains(logs, c.reason) {
				t.Fatalf("no log line:\n%s", logs)
			}
			if strings.Contains(logs, credential) || strings.Contains(logs, "supersecretpw") || strings.Contains(logs, "Proxy-Authorization") {
				t.Fatalf("the log quotes the head:\n%s", logs)
			}
		})
	}
}
