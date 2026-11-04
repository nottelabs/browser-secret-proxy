// Command browser-secret-proxy is a forward proxy that swaps stand-in values
// for real ones on allowlisted hosts while keeping the client's TLS and HTTP/2
// fingerprints.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nottelabs/browser-secret-proxy/internal/certs"
	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/proxy"
	"github.com/nottelabs/browser-secret-proxy/internal/upstream"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "secret-proxy:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	caCert := flag.String("ca-cert", "", "PEM CA certificate used to issue leaf certificates (required)")
	caKey := flag.String("ca-key", "", "PEM private key of the CA (required)")
	hosts := flag.String("hosts", "", "comma-separated hosts to intercept: exact names or a leading \"*.\" (required)")
	resolverOpts := registerResolverFlags(flag.CommandLine)
	parent := flag.String("upstream-proxy", os.Getenv("SECRET_PROXY_UPSTREAM"), "parent proxy URL: http://, https:// or socks5://, credentials in the URL (env SECRET_PROXY_UPSTREAM)")
	maskResponses := flag.Bool("mask-responses", true, "replace real values with their stand-ins in responses from allowlisted hosts")
	maskWindow := registerMaskStreamWindow(flag.CommandLine)
	verbose := flag.Bool("v", false, "debug logging")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	resolverOpts.set = map[string]bool{}
	flag.Visit(func(f *flag.Flag) { resolverOpts.set[f.Name] = true })

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *caCert == "" || *caKey == "" || *hosts == "" {
		flag.Usage()
		return fmt.Errorf("-ca-cert, -ca-key and -hosts are required")
	}
	authority, err := certs.LoadFiles(*caCert, *caKey)
	if err != nil {
		return err
	}
	allow, err := hostmatch.New(strings.Split(*hosts, ","))
	if err != nil {
		return err
	}
	values, err := resolverOpts.build(os.Getenv("SECRET_PROXY_USERNAME"), logger)
	if err != nil {
		return err
	}
	if values.close != nil {
		defer values.close()
	}
	var parentURL *url.URL
	if *parent != "" {
		if parentURL, err = url.Parse(*parent); err != nil {
			return fmt.Errorf("upstream proxy: %w", err)
		}
	}
	dialer, err := upstream.New(parentURL, nil, nil)
	if err != nil {
		return err
	}
	server, err := proxy.New(proxy.Config{
		Authority: authority,
		Hosts:     allow,
		Resolver:  values.resolver,
		Detector:  values.detector,
		// The proxy's own deadline on a lookup follows -resolver-timeout.
		ResolveTimeout: values.timeout,
		Dialer:         dialer,
		Username:       os.Getenv("SECRET_PROXY_USERNAME"),
		Password:       os.Getenv("SECRET_PROXY_PASSWORD"),
		Logger:         logger,
		// Real values in responses are replaced by their stand-ins.
		MaskResponses:    *maskResponses,
		MaskStreamWindow: *maskWindow,
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	parentDescription := describeParent(parentURL)
	attrs := append([]any{"address", ln.Addr().String(), "hosts", *hosts}, values.logAttrs...)
	attrs = append(attrs, "upstream_proxy", parentDescription, "proxy_auth", os.Getenv("SECRET_PROXY_USERNAME") != "" || values.mode == "sealed",
		"mask_responses", *maskResponses, "mask_stream_window", maskWindow.String())
	logger.Info("listening", attrs...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if values.watch != nil {
		go values.watch(ctx)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = ln.Close()
	}()
	return server.Serve(ln)
}

// registerMaskStreamWindow registers -mask-stream-window on fs. An unknown
// value fails the parse, so the proxy does not start.
func registerMaskStreamWindow(fs *flag.FlagSet) *mask.Window {
	w := new(mask.Window)
	fs.TextVar(w, "mask-stream-window", mask.Fixed, "what masking holds back of a streamed response: fixed (a window of bytes, whatever they are) or minimal (only bytes that could begin a real value: lower latency, but an allowlisted host that reflects input can then reveal real values; see the README)")
	return w
}

// describeParent names the parent proxy for logs: scheme and host only.
// Credentials are left out entirely; a minted username can carry session
// details, so even url.Redacted, which hides only the password, is not used.
func describeParent(u *url.URL) string {
	if u == nil {
		return "none"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}
