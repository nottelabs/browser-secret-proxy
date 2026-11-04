# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release, planned as 0.1.0.

### Added

- Forward proxy that decrypts traffic to allowlisted hosts with a CA you
  provide and replaces stand-in values with real ones in request headers,
  query strings and bodies.
- Plain CONNECT tunnels, without decryption, for every other host.
- HTTP/2 and HTTP/1.1 relays.
- Optional Basic authentication on CONNECT
  (`SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD`).
- Parent proxy support (`-upstream-proxy`, `SECRET_PROXY_UPSTREAM`):
  `http://`, `https://` and `socks5://`.
- Static binaries for linux and darwin (amd64, arm64) and a multi-arch
  container image, with checksums, SBOMs and cosign signatures.
- `-version` prints the build's version.
- Values are scoped: each one is swapped only into requests for the hosts it
  allows and before it expires, and only for the principal (proxy
  credential) it was looked up for. Hosts are checked against the
  `CONNECT` destination, and a request naming another host is refused. A
  request that breaks a scope, or whose lookup fails, is answered `502` and
  not sent.
- Pluggable sources of real values (`-resolver file|http|sealed`):
  - `file`: the `-swaps` JSON file (`-swaps` alone still selects it),
    reloaded when it changes (`-swaps-reload`). A file that does not load
    keeps the previous values.
  - `http`: a detokenize service you run, called over mutual TLS once per
    request, with a timeout (`-resolver-timeout`) and an in-memory cache per
    principal, host and stand-in. A reference service is in
    `examples/http-resolver`.
  - `sealed`: the proxy password is a nested JWT that carries the values,
    so no lookup service or external storage is needed. It is signed by an
    issuer key the proxy trusts (`-sealed-issuer-key`, EdDSA or ES256,
    repeatable for rotation), then encrypted to the proxy's key (JWE,
    ECDH-ES+A256KW, A256GCM), and its `aud` must name the proxy
    (`-sealed-audience`), so a token cannot be forged with the proxy's
    public key or replayed on another proxy. Decrypted tokens stay in memory
    until their `exp`, at most 5 minutes. Unsigned, wrongly signed, foreign,
    wrong-audience or expired tokens get `407`, and a connection whose token
    expires gets `502`. `examples/seal` signs and seals tokens. Tokens in
    the earlier encrypt-only format, from before this release, are refused.
- Stand-in detection by pattern (`-standin-pattern`, `-standin-prefixes`),
  with an optional Luhn check for card-like stand-ins (`-standin-luhn`).
- Response masking, on by default (`-mask-responses`): real values looked up
  for a principal are replaced by their stand-ins in response headers,
  bodies and trailers on allowlisted hosts, over HTTP/1.1 and HTTP/2, in
  their common encoded forms and card number groupings. Compressed bodies
  (`gzip`, `deflate`, `br`, `zstd`) are decoded to be masked and sent
  without a content-coding; a response that cannot be masked is answered
  `502`.
- Stand-ins in JSON request bodies are found and swapped when the client
  escaped their characters (`\u0026` for `&`, as Go's `encoding/json` does,
  or any `\uXXXX` escape).
