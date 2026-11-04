// Command e2e-notte checks browser-secret-proxy end to end with a real
// browser: a Notte session sends allowlisted hosts through the proxy image,
// made public with ngrok, and the scenarios check what the destinations
// received. Run it through scripts/e2e-notte.sh; see CONTRIBUTING.md.
//
// Two proxies run side by side, each with its own session:
//
//   - swap: the http resolver (a detokenize service in this program, over
//     mutual TLS), response masking off, the third-party echo host
//     allowlisted. Scenarios read what the host received from its echo:
//     card, password-form, totp, bearer-token, api-key-query, and
//     not-allowlisted for a host outside the allowlist.
//   - mask: the file resolver, response masking on, a capture server in this
//     program allowlisted through an ngrok HTTPS endpoint. Scenarios read
//     what arrived upstream from the capture server directly:
//     password-json and masking.
//
// Environment:
//
//	NOTTE_API_KEY    API key for the Notte environment (required)
//	NGROK_AUTHTOKEN  ngrok agent authtoken; TCP tunnels need a verified account (required)
//	NOTTE_API_URL    default https://us-staging.notte.cc
//	IMAGE            proxy image to test, default browser-secret-proxy:dev
//	NGROK            ngrok binary, default ngrok
//	SWAP_HOST        allowlisted echo host, default postman-echo.com
//	CONTROL_HOST     echo host outside the allowlist, default httpbingo.org
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type config struct {
	apiURL, apiKey  string
	image, ngrokBin string
	swapHost        string
	controlHost     string
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[e2e] "+format+"\n", args...)
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg := config{
		apiURL:      strings.TrimRight(env("NOTTE_API_URL", "https://us-staging.notte.cc"), "/"),
		apiKey:      os.Getenv("NOTTE_API_KEY"),
		image:       env("IMAGE", "browser-secret-proxy:dev"),
		ngrokBin:    env("NGROK", "ngrok"),
		swapHost:    env("SWAP_HOST", "postman-echo.com"),
		controlHost: env("CONTROL_HOST", "httpbingo.org"),
	}
	if cfg.apiKey == "" || os.Getenv("NGROK_AUTHTOKEN") == "" {
		logf("set NOTTE_API_KEY and NGROK_AUTHTOKEN")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	e := &e2e{cfg: cfg, api: &notteAPI{baseURL: cfg.apiURL, key: cfg.apiKey, client: &http.Client{}}}
	defer e.cleanup()
	results := map[string]error{}
	if err := e.setup(ctx); err != nil {
		logf("FAIL: setup: %v", err)
		for _, id := range scenarioIDs {
			results[id] = errors.New("not run: setup failed")
		}
	} else {
		results = e.runScenarios(ctx)
	}
	return summary(results)
}

// e2e is one run: its servers, proxies, tunnels and sessions.
type e2e struct {
	cfg    config
	api    *notteAPI
	work   string
	values values

	detokenizer *detokenizer
	capture     *captureServer
	captureHost string
	servers     []*http.Server

	ngrok                *ngrokAgent
	swapProxy, maskProxy *proxyRun
	swapSession          string
	maskSession          string
}

func (e *e2e) setup(ctx context.Context) error {
	var err error
	if e.work, err = os.MkdirTemp("", "bsp-e2e-"); err != nil {
		return err
	}
	if e.values, err = newValues(); err != nil {
		return err
	}
	path := func(name string) string { return filepath.Join(e.work, name) }

	// Throwaway CAs: one the proxy issues leaf certificates with, one for
	// the mutual TLS between the proxy and the detokenize service.
	proxyCA, err := newCA("browser-secret-proxy e2e CA")
	if err != nil {
		return err
	}
	if err := proxyCA.write(path("ca.pem"), path("ca.key")); err != nil {
		return err
	}
	resolverCA, err := newCA("browser-secret-proxy e2e detokenize CA")
	if err != nil {
		return err
	}
	serviceCert, err := resolverCA.issue("detokenize", []net.IP{net.IPv4(127, 0, 0, 1)}, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	clientCert, err := resolverCA.issue("browser-secret-proxy", nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	if err := writeReadable(path("resolver-ca.pem"), resolverCA.certPEM); err != nil {
		return err
	}
	if err := clientCert.write(path("proxy-client.pem"), path("proxy-client.key")); err != nil {
		return err
	}
	v := e.values
	swaps, err := json.Marshal(map[string]string{v.jsonStandIn: v.jsonReal, v.maskStandIn: v.maskReal})
	if err != nil {
		return err
	}
	if err := writeReadable(path("swaps.json"), swaps); err != nil {
		return err
	}

	// The detokenize service of the swap proxy.
	e.detokenizer = &detokenizer{
		host: e.cfg.swapHost,
		static: map[string]string{
			v.cardStandIn: v.cardReal, v.cvcStandIn: v.cvcReal,
			v.userStandIn: v.userReal, v.passStandIn: v.passReal,
			v.bearerStandIn: v.bearerReal, v.keyStandIn: v.keyReal,
		},
		totpStandIn: v.totpStandIn, totpSecret: v.totpSecret, now: time.Now,
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(resolverCA.cert)
	resolverAddr, err := e.serve(http.Handler(e.detokenizer), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serviceCert.cert.Raw}, PrivateKey: serviceCert.key}},
	})
	if err != nil {
		return err
	}
	// The destination of the mask proxy.
	e.capture = newCaptureServer("masking")
	captureAddr, err := e.serve(e.capture, nil)
	if err != nil {
		return err
	}

	e.swapProxy, err = newProxyRun("swap")
	if err != nil {
		return err
	}
	e.maskProxy, err = newProxyRun("mask")
	if err != nil {
		return err
	}
	logf("opening ngrok tunnels")
	var urls map[string]string
	e.ngrok, urls, err = startNgrok(ctx, e.cfg.ngrokBin, e.work, []ngrokTunnel{
		{"swap", "tcp", e.swapProxy.port},
		{"mask", "tcp", e.maskProxy.port},
		{"capture", "http", captureAddr.Port},
	})
	if err != nil {
		return err
	}
	if e.swapProxy.publicURL, err = tcpToHTTP(urls["swap"]); err != nil {
		return err
	}
	if e.maskProxy.publicURL, err = tcpToHTTP(urls["mask"]); err != nil {
		return err
	}
	captureURL, err := url.Parse(urls["capture"])
	if err != nil || captureURL.Scheme != "https" {
		return fmt.Errorf("unexpected ngrok HTTPS address %q", urls["capture"])
	}
	e.captureHost = captureURL.Hostname()

	ro := func(name string) string { return "/etc/bsp/" + name }
	e.swapProxy.mounts = map[string]string{}
	for _, name := range []string{"ca.pem", "ca.key", "resolver-ca.pem", "proxy-client.pem", "proxy-client.key"} {
		e.swapProxy.mounts[path(name)] = ro(name)
	}
	e.swapProxy.args = []string{
		"-ca-cert", ro("ca.pem"), "-ca-key", ro("ca.key"), "-hosts", e.cfg.swapHost,
		"-resolver", "http", "-resolver-url", fmt.Sprintf("https://%s/v1/detokenize", resolverAddr),
		"-resolver-cert", ro("proxy-client.pem"), "-resolver-key", ro("proxy-client.key"),
		"-resolver-ca", ro("resolver-ca.pem"),
		// No cache: the TOTP value must be computed for each request.
		"-resolver-cache-ttl", "0",
		"-standin-prefixes", "tok_", "-standin-pattern", `\b` + v.cardStandIn + `\b`,
		"-mask-responses=false",
	}
	e.maskProxy.mounts = map[string]string{}
	for _, name := range []string{"ca.pem", "ca.key", "swaps.json"} {
		e.maskProxy.mounts[path(name)] = ro(name)
	}
	e.maskProxy.args = []string{
		"-ca-cert", ro("ca.pem"), "-ca-key", ro("ca.key"), "-hosts", e.captureHost,
		"-swaps", ro("swaps.json"), "-mask-responses=true",
	}
	for _, p := range []*proxyRun{e.swapProxy, e.maskProxy} {
		logf("starting the %s proxy (%s)", p.role, e.cfg.image)
		// Set before docker run: a run that fails or is cancelled can still
		// have created the container, so cleanup must try to remove it.
		p.started = true
		if err := startProxy(ctx, e.cfg.image, p); err != nil {
			return err
		}
	}

	// Check each public address before starting sessions, so a tunnel
	// failure is reported as one. Locally the proxy gets a few seconds to
	// start; through the tunnel one answer is enough (any status, such as
	// the proxy's 407).
	for _, p := range []*proxyRun{e.swapProxy, e.maskProxy} {
		if _, err := waitHTTP(ctx, fmt.Sprintf("http://127.0.0.1:%d/", p.port), nil, 10*time.Second); err != nil {
			return fmt.Errorf("the %s proxy did not start: %w", p.role, err)
		}
		status, err := waitHTTP(ctx, p.publicURL+"/", nil, 0)
		if err != nil {
			return fmt.Errorf("the tunnel at %s does not reach the %s proxy: %w", p.publicURL, p.role, err)
		}
		logf("%s proxy is public at %s (HTTP %d)", p.role, p.publicURL, status)
	}
	skip := http.Header{ngrokSkipHeader: {"1"}}
	status, err := waitHTTP(ctx, "https://"+e.captureHost+"/", skip, 0)
	if err != nil {
		return fmt.Errorf("the capture server is not reachable at %s: %w", e.captureHost, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("the capture server at %s answered %d through ngrok", e.captureHost, status)
	}
	logf("capture server is public at https://%s", e.captureHost)

	// Both sessions start at once.
	pem := string(proxyCA.certPEM)
	type started struct {
		id  string
		err error
	}
	swapCh, maskCh := make(chan started, 1), make(chan started, 1)
	for _, s := range []struct {
		p     *proxyRun
		hosts []string
		ch    chan started
	}{{e.swapProxy, []string{e.cfg.swapHost}, swapCh}, {e.maskProxy, []string{e.captureHost}, maskCh}} {
		go func() {
			id, err := e.api.startSession(ctx, secretProxy{Server: s.p.publicURL, Username: s.p.username,
				Password: s.p.password, CACertificate: pem, Hosts: s.hosts})
			s.ch <- started{id, err}
		}()
	}
	logf("starting two sessions on %s", e.cfg.apiURL)
	swap, mask := <-swapCh, <-maskCh
	e.swapSession, e.maskSession = swap.id, mask.id
	if err := errors.Join(swap.err, mask.err); err != nil {
		return err
	}
	logf("sessions: swap %s, mask %s", e.swapSession, e.maskSession)
	return nil
}

// serve starts handler on a free port of 127.0.0.1, over TLS when tlsConf
// is set.
func (e *e2e) serve(handler http.Handler, tlsConf *tls.Config) (*net.TCPAddr, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := l.Addr().(*net.TCPAddr)
	if tlsConf != nil {
		l = tls.NewListener(l, tlsConf)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	e.servers = append(e.servers, srv)
	go func() { _ = srv.Serve(l) }()
	return addr, nil
}

func newProxyRun(role string) (*proxyRun, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	return &proxyRun{
		role:     role,
		name:     fmt.Sprintf("bsp-e2e-%s-%d", role, os.Getpid()),
		port:     port,
		username: "e2e-" + randomHex(12),
		password: randomHex(24),
	}, nil
}

// runScenarios runs each session's scenarios in order, the two sessions
// side by side, and returns each scenario's error (nil when it passed).
func (e *e2e) runScenarios(ctx context.Context) map[string]error {
	var mu sync.Mutex
	results := map[string]error{}
	runSession := func(name, sessionID, start string, scenarios []scenario) {
		prepErr := e.api.gotoURL(ctx, sessionID, start)
		if prepErr != nil {
			prepErr = fmt.Errorf("opening %s in the %s session: %w", start, name, prepErr)
		}
		for _, s := range scenarios {
			began := time.Now()
			err := prepErr
			if err == nil {
				err = s.run(ctx)
			}
			if err != nil {
				logf("%s: FAIL after %s: %v", s.id, time.Since(began).Round(time.Millisecond), err)
			} else {
				logf("%s: PASS in %s", s.id, time.Since(began).Round(time.Millisecond))
			}
			mu.Lock()
			results[s.id] = err
			mu.Unlock()
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() { runSession("swap", e.swapSession, "https://"+e.cfg.swapHost+"/get", e.swapScenarios()) })
	wg.Go(func() { runSession("mask", e.maskSession, "https://"+e.captureHost+"/", e.maskScenarios()) })
	wg.Wait()
	return results
}

// summary prints one line per scenario and returns the exit code.
func summary(results map[string]error) int {
	code := 0
	fmt.Println("scenario         result")
	for _, id := range scenarioIDs {
		err, ran := results[id]
		switch {
		case !ran:
			code = 1
			fmt.Printf("%-16s FAIL: no result\n", id)
		case err != nil:
			code = 1
			fmt.Printf("%-16s FAIL: %s\n", id, strings.ReplaceAll(err.Error(), "\n", "; "))
		default:
			fmt.Printf("%-16s PASS\n", id)
		}
	}
	return code
}

// cleanup stops the sessions first, so nothing uses the tunnels, then the
// tunnels, proxies and servers. Every step has a time limit.
func (e *e2e) cleanup() {
	ctx := context.Background()
	for _, id := range []string{e.swapSession, e.maskSession} {
		if id == "" {
			continue
		}
		logf("stopping session %s", id)
		if err := e.api.stopSession(ctx, id); err != nil {
			logf("stopping session %s: %v", id, err)
		}
	}
	if e.ngrok != nil {
		logf("ngrok log:\n%s", e.ngrok.stop())
	}
	for _, p := range []*proxyRun{e.swapProxy, e.maskProxy} {
		if p == nil || !p.started {
			continue
		}
		if logs := proxyLogs(p.name); logs != "" {
			logf("%s proxy log:\n%s", p.role, lastLines(logs, 40))
		}
		removeContainer(p.name)
	}
	for _, srv := range e.servers {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}
	if e.work != "" {
		_ = os.RemoveAll(e.work)
	}
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// randomHex returns 2n hex digits. crypto/rand.Read does not fail on the
// platforms this runs on.
func randomHex(n int) string {
	b, err := randomBytes(n)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
