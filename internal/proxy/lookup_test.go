package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// slowResolver answers tok_slow only once released, like an http resolver
// waiting on its service, and tok_fast at once. It is not resolve.Local.
type slowResolver struct{ release chan struct{} }

func (slowResolver) StandIns(resolve.Principal) []string { return []string{"tok_slow", "tok_fast"} }

func (s slowResolver) Resolve(ctx context.Context, req resolve.Request) (resolve.Result, error) {
	out := resolve.Result{Values: map[string]resolve.Value{}}
	for _, standIn := range req.StandIns {
		if standIn == "tok_slow" {
			select {
			case <-s.release:
			case <-ctx.Done():
				return resolve.Result{}, ctx.Err()
			}
		}
		out.Values[standIn] = resolve.Value{Real: "real_" + strings.TrimPrefix(standIn, "tok_")}
	}
	return out, nil
}

// Over HTTP/2, a request waiting on a slow lookup does not hold back the
// other requests of its connection; over HTTP/1.1, where a connection
// carries one request at a time, the other request goes on another
// connection as before. Both slow requests are swapped once released.
func TestSlowLookupHoldsBackOnlyItsRequest(t *testing.T) {
	protos(t, func(t *testing.T, proto string) {
		r := slowResolver{release: make(chan struct{})}
		received := &echoed{}
		dest := startDestination(t, allowedHost, []string{proto}, echoDestination(received))
		p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, func(c *Config) {
			d, err := resolve.NewDetector(r, resolve.Patterns{})
			if err != nil {
				t.Fatal(err)
			}
			c.Resolver, c.Detector = r, d
		})
		client := clientTo(t, p, proto, allowedHost)
		client.Transport.(*http.Transport).DisableKeepAlives = false
		slow := make(chan int, 1)
		go func() {
			resp, err := client.Get("https://" + allowedHost + "/?k=tok_slow")
			if err != nil {
				slow <- 0
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			slow <- resp.StatusCode
		}()
		time.Sleep(50 * time.Millisecond) // the slow request is waiting on its lookup
		for _, path := range []string{"/?k=tok_fast", "/plain"} {
			if got := do(t, client, http.MethodGet, "https://"+allowedHost+path, ""); got != http.StatusOK {
				t.Fatalf("%s: %d while another request waits on its lookup", path, got)
			}
		}
		select {
		case code := <-slow:
			t.Fatalf("the slow request finished (%d) before its lookup was released", code)
		default:
		}
		close(r.release)
		select {
		case code := <-slow:
			if code != http.StatusOK {
				t.Fatalf("slow request: %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the slow request did not finish")
		}
		got := received.all()
		for _, want := range []string{"/?k=real_fast ", "/plain ", "/?k=real_slow "} {
			if !strings.Contains(got, want) {
				t.Fatalf("destination did not get %q:\n%s", want, got)
			}
		}
		if proto == "h2" && strings.Index(got, "/?k=real_slow") < strings.Index(got, "/plain") {
			t.Fatalf("over HTTP/2 the slow request arrived before the others:\n%s", got)
		}
	})
}
