# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release, planned as 0.1.0.

### Added

- A masked `br` response body cut off in transit fails the response, as the
  other codings do, rather than reaching the client as a shorter body that
  looks complete (brotli v1.2.7).
- Forward proxy that decrypts traffic to allowlisted hosts with a CA you
  provide and replaces stand-in values with real ones in request headers,
  query strings and bodies.
- Plain CONNECT tunnels, without decryption, for every other host.
- HTTP/1.1 requests whose body a server could frame differently, or whose
  head it could split into other lines, are answered `502` and not sent:
  `Transfer-Encoding` with `Content-Length`, a `Transfer-Encoding` other
  than a single `chunked` or on a request that is not HTTP/1.1, more than
  one `Content-Length` or one that is not a decimal number (only spaces and
  tabs may surround either value), a folded header line, a header name
  that is not a token, and a bare CR or NUL in the request line or a
  header line. A chunked trailer line like that closes
  the connection. Before, a `Content-Length` sent with `chunked` was
  forwarded next to the swapped, re-chunked body, so a server that framed
  by it could read part of the body as another request.
- HTTP/2 and HTTP/1.1 relays.
- On allowlisted hosts, a ClientHello that repeats an extension type
  (RFC 8446 forbids it) is refused with a `decode_error` alert, as is any
  ClientHello the proxy cannot parse. Before, two `session_ticket`
  extensions made uTLS panic and ended the whole process. A panic in a
  connection's handler, or in uTLS while it rebuilds a ClientHello, now
  closes only that connection; its log line names where it happened but not
  the panic value.
- Optional Basic authentication on CONNECT
  (`SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD`). The proxy refuses to
  start with a password but no username, which would leave authentication
  off.
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
- Values' scopes are checked more strictly. An empty `hosts` list from the
  `http` resolver or in a sealed token refuses the request instead of
  allowing every host in `-hosts`, and `examples/seal` refuses to seal one.
  The `http` resolver is sent, and caches by, the `CONNECT` host in lower
  case without its port or trailing dot. A sealed token whose claims repeat
  a member or spell a claim in another case (`"HOSTS"`) gets `407`. With
  masking on, a request carrying more than 1,024 values is refused instead
  of evicting some of its own values from the masking record.
- Releases are published only after fmt, vet, lint, the race tests and
  govulncheck pass on the tagged commit, in a job without write or signing
  permissions. The README verifies signatures against the exact identity of
  `release.yml` on the release's tag, not any workflow of the repository.
- Requests that name their host ambiguously are answered `502` and not sent:
  more than one `Host`, `:authority` or `host`, a `host` or absolute-form
  target that differs from the request's other authority, an authority with
  userinfo (`allowed.test:443@evil.test`) or a port that is not a number,
  and HTTP/2 header names with uppercase letters (an uppercase
  `Content-Length` was not updated when a swap changed the body's length).
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
- Response masking closes gaps where a real value reached the client: every
  `206` partial response is refused, so a client cannot rebuild a value
  from ranges masked one by one; the HTTP/1.1 reason phrase is masked; a
  real value in an HTTP/1.1 framing header (`Connection`, `Keep-Alive`,
  `Trailer`, `Upgrade`, ...), an HTTP/1.1 `101` to a request that did not
  ask to upgrade, and an HTTP/2 field name with an upper-case letter are
  refused with `502`; content in HTTP/2 DATA on a `HEAD`, `204` or `304`
  response resets the stream.
- Stand-ins in JSON request bodies are found and swapped when the client
  escaped their characters (`\u0026` for `&`, as Go's `encoding/json` does,
  or any `\uXXXX` escape).
- Over HTTP/2, a request waiting on a resolver lookup (the `http` mode) no
  longer holds back the other requests of its connection: each lookup runs
  on its own, at most 16 at a time per connection, and is canceled when its
  request is reset or refused. The `file` and `sealed` modes, which answer
  from memory, resolve in line and keep the browser's request order.
- In `sealed` mode, a token is accepted only in its canonical compact form,
  so one token cannot be presented as several passwords, and the token alone
  is the principal: the username names it in logs but no longer splits its
  values for masking. Decrypted tokens leave memory at their time even when
  no request comes.
- Logs, errors and the usage text keep credentials and real values out:
  `-h` and flag errors no longer print the `SECRET_PROXY_UPSTREAM` URL; a
  parent URL that does not parse, or has something after its port, is
  refused without quoting it; with `-v`, a `CONNECT` head that does not
  parse is logged by category, not quoted with its `Proxy-Authorization`;
  a refused `Content-Encoding` or `Transfer-Encoding` is not quoted; and the
  HTTP/2 body swap line no longer logs byte counts, which gave away the
  length of real values. `-help` lists the environment variables.
- Over HTTP/2, a frame longer than the max frame size its sender was told
  ends the connection with `FRAME_SIZE_ERROR`, and a frame's payload takes
  memory as it arrives rather than all at once. A `PRIORITY_UPDATE` value
  over 1 KiB ends the connection with `PROTOCOL_ERROR`. Before, one client
  could make the relay hold gigabytes on one connection.
- Real values with a line break or NUL are refused in every header, also
  when the client's header already holds such a byte (a NUL after a
  stand-in let a multi-line value through). Over HTTP/2, a request whose
  field values hold a NUL, CR or LF, or start or end with a space or tab
  (malformed, RFC 9113 8.2.1), is answered `502` and not sent.
