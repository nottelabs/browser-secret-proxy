package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

// resolverFlags select and configure the source of real values.
type resolverFlags struct {
	mode string

	swaps       string
	swapsReload time.Duration

	url, cert, key, ca string
	timeout, cacheTTL  time.Duration

	sealedKey        string
	sealedIssuerKeys stringList
	sealedAudience   string

	patterns stringList
	prefixes string
	luhn     bool

	set map[string]bool // flags given on the command line
}

// stringList is a flag that may be repeated.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, " ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// modeFlags are the flags that belong to one mode only.
var modeFlags = map[string][]string{
	"file":   {"swaps", "swaps-reload"},
	"http":   {"resolver-url", "resolver-cert", "resolver-key", "resolver-ca", "resolver-timeout", "resolver-cache-ttl"},
	"sealed": {"sealed-key", "sealed-issuer-key", "sealed-audience"},
}

func registerResolverFlags(fs *flag.FlagSet) *resolverFlags {
	f := &resolverFlags{}
	fs.StringVar(&f.mode, "resolver", "", "source of real values: file, http or sealed (default file; -swaps alone selects file)")
	fs.StringVar(&f.swaps, "swaps", "", "file mode: JSON file mapping each stand-in to its real value")
	fs.DurationVar(&f.swapsReload, "swaps-reload", 2*time.Second, "file mode: how often to check the file for changes (0: never)")
	fs.StringVar(&f.url, "resolver-url", "", "http mode: https:// URL of the detokenize service")
	fs.StringVar(&f.cert, "resolver-cert", "", "http mode: PEM client certificate presented to the service")
	fs.StringVar(&f.key, "resolver-key", "", "http mode: PEM key of the client certificate")
	fs.StringVar(&f.ca, "resolver-ca", "", "http mode: PEM CA bundle that verifies the service (default: system roots)")
	fs.DurationVar(&f.timeout, "resolver-timeout", 2*time.Second, "http mode: timeout of one lookup")
	fs.DurationVar(&f.cacheTTL, "resolver-cache-ttl", time.Minute, "http mode: longest a looked-up value is kept in memory (0: no cache)")
	fs.StringVar(&f.sealedKey, "sealed-key", "", "sealed mode: PEM EC private key that sealed proxy passwords are encrypted to")
	fs.Var(&f.sealedIssuerKeys, "sealed-issuer-key", "sealed mode: PEM public key (Ed25519 or P-256) of an issuer allowed to sign tokens (repeatable)")
	fs.StringVar(&f.sealedAudience, "sealed-audience", "", "sealed mode: this proxy's identity; a token's aud must contain it")
	fs.Var(&f.patterns, "standin-pattern", "regular expression that matches stand-ins (repeatable)")
	fs.StringVar(&f.prefixes, "standin-prefixes", "", "comma-separated prefixes that start stand-ins, such as tok_")
	fs.BoolVar(&f.luhn, "standin-luhn", false, "drop card-like pattern matches whose Luhn check digit is wrong")
	return f
}

// resolverSetup is a configured resolver.
type resolverSetup struct {
	mode     string
	resolver resolve.Resolver
	detector *resolve.Detector
	// timeout bounds one lookup (0: the proxy's default).
	timeout time.Duration
	// watch, when set, runs until ctx ends (file reloads).
	watch func(ctx context.Context)
	// logAttrs describe the setup for the start log line, without secrets.
	logAttrs []any
}

func (f *resolverFlags) build(fixedUsername string, logger *slog.Logger) (*resolverSetup, error) {
	mode := f.mode
	if mode == "" {
		mode = "file"
	}
	if _, ok := modeFlags[mode]; !ok {
		return nil, fmt.Errorf("-resolver %q: want file, http or sealed", f.mode)
	}
	var wrong []string
	for other, names := range modeFlags {
		if other == mode {
			continue
		}
		for _, name := range names {
			if f.set[name] {
				wrong = append(wrong, "-"+name)
			}
		}
	}
	if len(wrong) > 0 {
		sort.Strings(wrong)
		return nil, fmt.Errorf("%s cannot be used with -resolver %s", strings.Join(wrong, ", "), mode)
	}

	setup := &resolverSetup{mode: mode, logAttrs: []any{"resolver", mode}}
	switch mode {
	case "file":
		if f.swaps == "" {
			return nil, errors.New("-resolver file needs -swaps")
		}
		file, err := resolve.LoadFile(f.swaps)
		if err != nil {
			return nil, err
		}
		setup.resolver = file
		setup.logAttrs = append(setup.logAttrs, "stand_ins", file.Count(), "reload_every", f.swapsReload.String())
		if f.swapsReload > 0 {
			interval := f.swapsReload
			setup.watch = func(ctx context.Context) { file.Watch(ctx, interval, logger) }
		}
	case "http":
		cacheTTL := f.cacheTTL
		if cacheTTL == 0 {
			cacheTTL = -1 // the flag's 0 turns the cache off
		}
		h, err := resolve.NewHTTP(resolve.HTTPConfig{
			URL: f.url, ClientCert: f.cert, ClientKey: f.key, CA: f.ca,
			Timeout: f.timeout, CacheTTL: cacheTTL,
		})
		if err != nil {
			return nil, err
		}
		setup.resolver = h
		setup.timeout = f.timeout
		setup.logAttrs = append(setup.logAttrs, "timeout", f.timeout.String(), "cache_ttl", f.cacheTTL.String())
		if fixedUsername == "" {
			logger.Warn("proxy authentication is off: every client shares one principal for the detokenize service")
		}
	case "sealed":
		if fixedUsername != "" {
			return nil, errors.New("SECRET_PROXY_USERNAME and SECRET_PROXY_PASSWORD are not used with -resolver sealed: the sealed password authenticates each client")
		}
		if f.sealedKey == "" || len(f.sealedIssuerKeys) == 0 || f.sealedAudience == "" {
			return nil, errors.New("-resolver sealed needs -sealed-key, -sealed-issuer-key and -sealed-audience")
		}
		s, err := resolve.LoadSealed(f.sealedKey, f.sealedIssuerKeys, f.sealedAudience)
		if err != nil {
			return nil, err
		}
		setup.resolver = s
		setup.logAttrs = append(setup.logAttrs, "issuer_key_files", len(f.sealedIssuerKeys), "audience", f.sealedAudience)
	}

	var prefixes []string
	for _, p := range strings.Split(f.prefixes, ",") {
		if p = strings.TrimSpace(p); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	detector, err := resolve.NewDetector(setup.resolver, resolve.Patterns{Regexps: f.patterns, Prefixes: prefixes, Luhn: f.luhn})
	if err != nil {
		return nil, err
	}
	setup.detector = detector
	setup.logAttrs = append(setup.logAttrs, "standin_patterns", len(f.patterns), "standin_prefixes", len(prefixes))
	return setup, nil
}
