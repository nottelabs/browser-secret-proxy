// Command browser-secret-proxy is a forward proxy that swaps stand-in values
// for real ones on allowlisted hosts while keeping the client's TLS and HTTP/2
// fingerprints.
package main

import (
	"context"
	"errors"
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
	fs, opts := newFlagSet(os.Args[0], flag.ExitOnError)
	_ = fs.Parse(os.Args[1:]) // ExitOnError: a bad flag exits here
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	opts.resolver.set = set

	if opts.showVersion {
		fmt.Println(version)
		return nil
	}

	level := slog.LevelInfo
	if opts.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if opts.caCert == "" || opts.caKey == "" || opts.hosts == "" {
		fs.Usage()
		return fmt.Errorf("-ca-cert, -ca-key and -hosts are required")
	}
	authority, err := certs.LoadFiles(opts.caCert, opts.caKey)
	if err != nil {
		return err
	}
	allow, err := hostmatch.New(strings.Split(opts.hosts, ","))
	if err != nil {
		return err
	}
	values, err := opts.resolver.build(os.Getenv("SECRET_PROXY_USERNAME"), logger)
	if err != nil {
		return err
	}
	if values.close != nil {
		defer values.close()
	}
	// The variable is read here, not as the flag's default: the usage text
	// prints defaults, and this one carries credentials.
	parent := opts.parent
	if !set["upstream-proxy"] {
		parent = os.Getenv("SECRET_PROXY_UPSTREAM")
	}
	parentURL, err := parseParent(parent)
	if err != nil {
		return err
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
		MaskResponses: opts.maskResponses,
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return err
	}
	parentDescription := describeParent(parentURL)
	attrs := append([]any{"address", ln.Addr().String(), "hosts", opts.hosts}, values.logAttrs...)
	attrs = append(attrs, "upstream_proxy", parentDescription, "proxy_auth", os.Getenv("SECRET_PROXY_USERNAME") != "" || values.mode == "sealed",
		"mask_responses", opts.maskResponses)
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

// describeParent names the parent proxy for logs: scheme and host only.
// Credentials are left out entirely; a minted username can carry session
// details, so even url.Redacted, which hides only the password, is not used.
func describeParent(u *url.URL) string {
	if u == nil {
		return "none"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// options are the command-line flags.
type options struct {
	listen, caCert, caKey, hosts, parent string
	resolver                             *resolverFlags
	maskResponses, verbose, showVersion  bool
}

// newFlagSet defines the command line. No default comes from the
// environment: the usage text prints every default, and the environment
// holds credentials.
func newFlagSet(name string, handling flag.ErrorHandling) (*flag.FlagSet, *options) {
	fs := flag.NewFlagSet(name, handling)
	o := &options{}
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address to listen on")
	fs.StringVar(&o.caCert, "ca-cert", "", "PEM CA certificate used to issue leaf certificates (required)")
	fs.StringVar(&o.caKey, "ca-key", "", "PEM private key of the CA (required)")
	fs.StringVar(&o.hosts, "hosts", "", "comma-separated hosts to intercept: exact names or a leading \"*.\" (required)")
	o.resolver = registerResolverFlags(fs)
	fs.StringVar(&o.parent, "upstream-proxy", "", "parent proxy URL: http://, https:// or socks5://, credentials in the URL (env SECRET_PROXY_UPSTREAM)")
	fs.BoolVar(&o.maskResponses, "mask-responses", true, "replace real values with their stand-ins in responses from allowlisted hosts")
	fs.BoolVar(&o.verbose, "v", false, "debug logging")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		out := fs.Output()
		_, _ = fmt.Fprintf(out, "Usage of %s:\n", fs.Name())
		fs.PrintDefaults()
		_, _ = fmt.Fprint(out, usageEnvironment)
	}
	return fs, o
}

// usageEnvironment ends the usage text. It names the variables, never their
// values.
const usageEnvironment = `
Environment:
  SECRET_PROXY_USERNAME, SECRET_PROXY_PASSWORD
    	Basic credentials every CONNECT must carry; authentication is off
    	when SECRET_PROXY_USERNAME is empty (not used with -resolver sealed)
  SECRET_PROXY_UPSTREAM
    	parent proxy URL, used when -upstream-proxy is not given
`

// parseParent parses the parent proxy URL; an empty one is no parent. Its
// errors never quote the URL, as url.Parse's do, credentials included.
func parseParent(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(raw, "@") {
			// The cause can quote part of the password: an invalid escape,
			// or a "port" that is the start of it.
			return nil, errors.New("upstream proxy: the URL does not parse; percent-encode special characters in its user and password")
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("upstream proxy: the URL does not parse: %w", err)
	}
	// A "/", "?" or "#" in an unencoded password ends the host early: the
	// rest would parse as a path, query or fragment, and the user and the
	// start of the password as the host, which logs name. A missing scheme
	// leaves the credentials opaque.
	if u.Opaque != "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("upstream proxy: want scheme://[user:password@]host:port with nothing after the port; percent-encode special characters in the user and password")
	}
	return u, nil
}
