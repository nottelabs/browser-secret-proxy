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
- Fuzz targets for the HTTP/1.1 and HTTP/2 parsers and relays, JSON-string
  escaping, stand-in matching, content decoding and host matching, run by
  `make fuzz` and briefly on every pull request.
- Plain CONNECT tunnels, without decryption, for every other host.
- HTTP/1.1 header lines that the other side could read differently from
  the proxy are refused. A request with a control character other than a
  tab in a header value is answered `502` and not sent, and a chunked
  trailer line with one closes the connection before anything is sent:
  before, `Host: allowed.test\v` passed the host check as
  `allowed.test`. Only spaces and tabs are trimmed around a request header
  value. A response head with a folded line, a header name that is not a
  token (`Name : value`), a line without a colon, a bare CR or NUL in the
  status line or a header line, a `Content-Length` that is not a decimal
  number, or a `Transfer-Encoding` on a response that is not HTTP/1.1 is
  answered `502` with masking on or off, and a response trailer line like
  that cuts the response off. Before, an `HTTP/1.0` response with
  `Transfer-Encoding: chunked` was read as chunked by the proxy and to the
  close by a browser, so the proxy took part of its body for the next
  response. A response is read as
  `chunked` only when its last coding is `chunked` in ASCII.
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
- Idle and header timeouts and a connection cap. A connection with no
  traffic either way for `-idle-timeout` (default `5m`) is closed, the
  CONNECT head and each HTTP/1.1 request head must arrive within
  `-header-timeout` (default `10s`), and past `-max-conns` (default `1024`)
  connections a new one is answered `503`. An HTTP/1.1 request body takes
  memory as it arrives instead of all at once when its head declares its
  length.
- On allowlisted hosts, a ClientHello that repeats an extension type
  (RFC 8446 forbids it) is refused with a `decode_error` alert, as is any
  ClientHello the proxy cannot parse. Before, two `session_ticket`
  extensions made uTLS panic and ended the whole process. A panic in a
  connection's handler, or in uTLS while it rebuilds a ClientHello, now
  closes only that connection; its log line names where it happened but not
  the panic value.
- A panic on a goroutine doing work for one connection closes both sides
  of that connection, logged the same way, instead of ending the whole
  process. This covers the HTTP/2 relay's loops, PING and GOAWAY writers,
  lookups, response masking and protocol timers, the HTTP/1.1 relay's
  request and response sides, a tunnel's copies, and the idle timer.
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
- The `http` resolver's answer is read as the service wrote it, like sealed
  claims: an answer that names a member twice, at any depth, or spells
  `values`, `real`, `hosts` or `expires_at` in another case (`"HOSTS"`) is
  malformed, and the request is refused. `examples/seal` refuses such a
  payload file, and `examples/http-resolver` such a values file or request.
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
- Response masking holds back the same number of bytes at the end of a
  body received so far, whether or not they could begin a real value. It
  held back only possible beginnings, so a client that had a destination
  echo its guesses could rebuild a value from the size and timing of the
  HTTP/1.1 chunks or HTTP/2 DATA frames it got. A streamed body now runs
  that many bytes behind until it ends. `-mask-stream-window=minimal`
  restores the old behavior, and the oracle with it, for deployments that
  trust every allowlisted host not to reflect input.
- Responses no longer escape masking through a tunnel opened inside an
  intercepted connection: a `CONNECT` (HTTP/1.1, or HTTP/2 with or without
  `:protocol`, an extended `CONNECT` for `websocket` included) and an
  HTTP/1.1 upgrade to another protocol than `websocket` (such as `h2c`)
  are answered `502` and not sent. Before, any `2xx` to a `CONNECT`, or a
  `101` to an `h2c` upgrade, passed the rest of the connection to the
  client unmasked, with the real values swapped into the request that
  opened it. The HTTP/2 relay no longer passes on the destination's
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so browsers open WebSockets over
  HTTP/1.1, where only a `101` opens one; their frames still pass through
  unmasked.
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
- Over HTTP/2, a client's HPACK table is capped at the 4 KiB of the relay's
  own (it was 64 KiB). This cuts, but does not bound, how much more the
  destination receives than the client sent: several hundred times remain
  possible. More than 512 streams reset in 10 seconds, by the client or by
  the relay for the client's frames, end the connection with
  `ENHANCE_YOUR_CALM` (rapid reset, CVE-2023-44487), which also bounds how
  fast resets can start resolver lookups. Decoded headers and trailers of
  requests not yet sent upstream count toward the 64 MiB connection budget,
  as swapped.
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
- Over HTTP/2, a client that sends no connection preface within 10 seconds,
  or does not acknowledge a `SETTINGS` frame within 10 seconds (`GOAWAY`
  with `SETTINGS_TIMEOUT`), loses the connection, and so does a destination
  that leaves a response header block unfinished for 10 seconds. Before,
  either could hold the connection open for good.
- Over HTTP/2, malformed messages no longer get past swapping or masking: a
  request with a repeated, unknown or misplaced pseudo-header (two
  `:method` fields made a `POST` look like a `CONNECT`, whose response is
  not masked) is answered `502`; with masking on, response DATA before the
  final head resets the stream, a real value in `content-length` is refused
  with `502`, and trailers are masked with the values chosen at the head.
  Client frames of unknown types go upstream under their stream's server
  ID, or are dropped.
- Over HTTP/2, the destination's control frames no longer carry its data to
  the browser: GOAWAY debug data, which can echo a real value, is dropped;
  the proxy answers the destination's PINGs itself and passes on only ACKs
  of the browser's own PINGs; and `ALTSVC`, `ORIGIN`, `PRIORITY_UPDATE` and
  frames of unknown types from the destination are dropped instead of
  reaching the browser unmasked, some on the destination's stream IDs.
- Real values with a line break or NUL are refused in every header, also
  when the client's header already holds such a byte (a NUL after a
  stand-in let a multi-line value through). Over HTTP/2, a request whose
  field values hold a NUL, CR or LF, or start or end with a space or tab
  (malformed, RFC 9113 8.2.1), is answered `502` and not sent.

### Changed

- Behavior change: a `CONNECT` to an internal address is refused with `403`,
  for tunneled and decrypted hosts alike. Internal means loopback, private,
  link-local (`169.254.169.254` included), unspecified, multicast and
  `100.64.0.0/10`, also in IPv4-mapped or IPv4-compatible form. The proxy
  resolves a name once, refuses it when any of its addresses is internal,
  and dials the addresses it checked. Through `-upstream-proxy`, only
  IP-literal destinations are checked. `-allow-private-destinations` turns
  the check off. Tunnels without decryption are logged at info level, with
  their host, port and principal.
