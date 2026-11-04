package h1relay

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

// scopedOptions has one stand-in, tok_a, whose value may go only to
// pay.test (also allowlisted), and one, tok_old, that has expired.
func scopedOptions(t *testing.T) Options {
	t.Helper()
	o := options(t)
	o.Session = scopetest.Session(t, o.Hosts, scopedResolver(), resolve.Principal{ID: "alice"})
	return o
}

func scopedResolver() scopetest.Resolver {
	return scopetest.Resolver{Known: []string{"tok_a", "tok_old"}, Fn: func(req resolve.Request) (resolve.Result, error) {
		return resolve.Result{Values: map[string]resolve.Value{
			"tok_a":   {Real: "real_a", Hosts: []string{"pay.test"}},
			"tok_old": {Real: "real_old", ExpiresAt: time.Now().Add(-time.Minute)},
		}}, nil
	}}
}

// A request whose value may not go to its host, or has expired, is
// answered 502 after the responses before it, and nothing of it reaches the
// server.
func TestOutOfScopeRequestsAreAnswered502(t *testing.T) {
	for name, request := range map[string]string{
		"wrong host":     "POST /pay HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 10\r\n\r\ncard=tok_a",
		"expired":        "GET /?k=tok_old HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"expired header": "GET / HTTP/1.1\r\nHost: allowed.test\r\nAuthorization: Bearer tok_old\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client, clientReader, server, serverReader, result := pipesWith(t, scopedOptions(t))
			// A request in scope first, whose response is still pending
			// when the refused one arrives behind it.
			send(t, client, "GET /first HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
			readHead(t, serverReader)
			go func() { _, _ = io.WriteString(client, request) }()
			time.Sleep(20 * time.Millisecond)
			send(t, server, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")

			br := bufio.NewReader(clientReader)
			first, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(first.Body)
			_ = first.Body.Close()
			if first.StatusCode != 200 || string(body) != "first" {
				t.Fatalf("first response %d %q", first.StatusCode, body)
			}
			refused, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(refused.Body)
			_ = refused.Body.Close()
			if refused.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "request refused") || strings.Contains(string(body), "real_") {
				t.Fatalf("refusal %d %q", refused.StatusCode, body)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("relay error %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay kept the connection open")
			}
			if b, err := serverReader.ReadByte(); err == nil {
				t.Fatalf("server received data starting with %q", b)
			}
		})
	}
}

// The same stand-in on the host its value allows is swapped.
func TestInScopeValueIsSwapped(t *testing.T) {
	o := scopedOptions(t)
	hosts, err := hostmatch.New([]string{"allowed.test", "pay.test"})
	if err != nil {
		t.Fatal(err)
	}
	o.Hosts = hosts
	o.Session = scopetest.SessionTo(t, hosts, scopedResolver(), resolve.Principal{ID: "alice"}, "pay.test")
	client, _, _, serverReader, _ := pipesWith(t, o)
	send(t, client, "GET /?card=tok_a HTTP/1.1\r\nHost: pay.test\r\n\r\n")
	if head := readHead(t, serverReader); !strings.HasPrefix(head, "GET /?card=real_a ") {
		t.Fatalf("server got %q", head)
	}
}

// A request whose Host headers or absolute-form target a server could read
// as naming another host than the CONNECT one is answered 502, with or
// without a stand-in, and nothing of it reaches the server: a server may
// use any Host header, and an absolute-form target instead of Host
// (RFC 9112 3.2.2).
func TestConflictingHostsAreAnswered502(t *testing.T) {
	for name, request := range map[string]string{
		"two Host headers":                     "GET /?k=tok_standin HTTP/1.1\r\nHost: allowed.test\r\nHost: evil.test\r\n\r\n",
		"two Host headers, the last one right": "GET /?k=tok_standin HTTP/1.1\r\nHost: evil.test\r\nHost: allowed.test\r\n\r\n",
		"two Host headers that agree":          "GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: allowed.test\r\n\r\n",
		"userinfo in Host":                     "GET /?k=tok_standin HTTP/1.1\r\nHost: allowed.test:443@evil.test\r\n\r\n",
		"absolute-form naming another host":    "GET https://evil.test/?k=tok_standin HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"absolute-form with userinfo":          "GET https://allowed.test:443@evil.test/?k=tok_standin HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"absolute-form disagreeing with Host":  "GET https://allowed.test/ HTTP/1.1\r\nHost: allowed.test:8443\r\n\r\n",
		"a target of no form":                  "GET evil.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
		"CONNECT to another host":              "CONNECT evil.test:443 HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client, clientReader, _, serverReader, result := pipesWith(t, options(t))
			go func() { _, _ = io.WriteString(client, request) }()
			refused, err := http.ReadResponse(clientReader, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(refused.Body)
			_ = refused.Body.Close()
			if refused.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "request refused") {
				t.Fatalf("refusal %d %q", refused.StatusCode, body)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("relay error %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("relay kept the connection open")
			}
			if b, err := serverReader.ReadByte(); err == nil {
				t.Fatalf("server received data starting with %q", b)
			}
		})
	}
}

// An absolute-form target that names the CONNECT host, as Host does, is
// swapped.
func TestAbsoluteFormOnTheConnectHostIsSwapped(t *testing.T) {
	client, _, _, serverReader := pipes(t)
	send(t, client, "GET https://allowed.test/?k=tok_standin HTTP/1.1\r\nHost: Allowed.Test\r\n\r\n")
	if head := readHead(t, serverReader); !strings.HasPrefix(head, "GET https://allowed.test/?k=real ") {
		t.Fatalf("server got %q", head)
	}
}
