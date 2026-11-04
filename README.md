# browser-secret-proxy

A forward proxy that fills in secrets on the way out. A browser, or an AI agent
driving it, only ever handles stand-in values. The proxy decrypts traffic to
the hosts you allowlist and replaces each stand-in with its real value in the
outgoing request. Every other host is tunneled untouched, without decryption.

It is the customer-run "secret proxy" for [Notte](https://notte.cc) browser
sessions: you run it on infrastructure you control and keep the real values
(card numbers, API tokens, passwords) there. Notte routes only the allowlisted
hosts of a session through it, so the real values never reach Notte, the
browser or the agent. It works with any client that supports HTTP CONNECT
proxies, Notte or not.

When it connects to an allowlisted destination, the proxy keeps the TLS and
HTTP/2 parameters the client offered, and it refuses a connection it cannot
reproduce instead of substituting its own.

## How it works

1. The client sends `CONNECT host:443`. If `host` is not on the allowlist, the
   proxy opens a plain tunnel and copies bytes both ways.
2. For an allowlisted host, the proxy opens a TLS connection to the
   destination, then completes the client's TLS handshake with a certificate
   for `host` issued on the fly by your CA. The client must trust that CA.
3. Each request is relayed (HTTP/2 or HTTP/1.1, whichever the destination
   chose). The proxy finds the stand-ins in header values, the query string
   and the request body, looks up their real values once for that request,
   and replaces them. A request whose values cannot all be used is answered
   `502` and not sent (see [Security model](#security-model)). In responses,
   real values are replaced by their stand-ins before they reach the client
   (see [Response masking](#response-masking)).

Real values are never logged. Log lines name the host and how many fields
were swapped.

## Quick start

You need Go 1.26 or later to build from source, or Docker.

### 1. Create a CA

The client must trust this CA. Keep the key private: anyone holding it can
impersonate any host to a client that trusts the certificate.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=browser-secret-proxy CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" -keyout ca.key -out ca.pem
chmod 600 ca.key
```

A short lifetime (30 days here) limits the damage if the key leaks. Rotate it
before it expires.

### 2. List the stand-ins

`swaps.json` maps each stand-in to its real value:

```json
{
  "4242424242424242": "<real card number>",
  "tok_standin_123": "<real API token>"
}
```

Pick stand-ins that cannot appear by accident in other traffic. When one
stand-in contains another, the longer one wins. This file holds your real
secrets: restrict its permissions (`chmod 600 swaps.json`) and never commit it.

### 3. Run the proxy

From source:

```sh
make build
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'api.example.com,*.payments.example' \
  -swaps swaps.json
```

With Docker (the image listens on `:8080` and runs as a non-root user):

```sh
make docker
docker run --rm -p 8080:8080 \
  -v "$PWD/ca.pem:/etc/browser-secret-proxy/ca.pem:ro" \
  -v "$PWD/ca.key:/etc/browser-secret-proxy/ca.key:ro" \
  -v "$PWD/swaps.json:/etc/browser-secret-proxy/swaps.json:ro" \
  -e SECRET_PROXY_USERNAME=proxy-user -e SECRET_PROXY_PASSWORD=change-me \
  browser-secret-proxy:dev \
  -ca-cert /etc/browser-secret-proxy/ca.pem \
  -ca-key /etc/browser-secret-proxy/ca.key \
  -swaps /etc/browser-secret-proxy/swaps.json -hosts 'api.example.com'
```

The image runs as UID 65532, so mounted files must be readable by that user.

### 4. Try it locally

Point a Chromium-based browser at the proxy, for example
`chromium --proxy-server=http://127.0.0.1:8080`, and make it trust `ca.pem`.
On Linux, add it to the NSS database:

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n browser-secret-proxy -i ca.pem
```

Or check a single request with curl:

```sh
curl --proxy http://127.0.0.1:8080 --cacert ca.pem \
  "https://api.example.com/echo?token=tok_standin_123"
```

## Configuration

| Flag or variable | Meaning |
| --- | --- |
| `-listen` | Address to listen on (default `127.0.0.1:8080`). The proxy serves plain HTTP; see [Exposing the proxy](#exposing-the-proxy). |
| `-ca-cert`, `-ca-key` | PEM CA certificate and key (PKCS #8, PKCS #1 or SEC 1). Required. |
| `-hosts` | Comma-separated hosts to decrypt: exact names, or `*.domain` for every name below `domain` (not `domain` itself). Required. |
| `-swaps` | JSON file of stand-in to real value. Required. See [Where values are replaced](#where-values-are-replaced). |
| `-upstream-proxy`, `SECRET_PROXY_UPSTREAM` | Parent proxy for all outgoing connections: `http://`, `https://` or `socks5://`, with a port and with credentials in the URL. The flag wins over the variable. |
| `SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD` | Require these Basic credentials on every CONNECT. Authentication is off when `SECRET_PROXY_USERNAME` is empty. |
| `-mask-responses` | Replace real values with their stand-ins in responses from allowlisted hosts (default `true`; `-mask-responses=false` turns it off). See [Response masking](#response-masking). |
| `-v` | Debug logging. |
| `-version` | Print the version and exit. |

The process stops on `SIGINT` or `SIGTERM`: it closes open connections, then
waits at most 10 seconds for them to finish.

### Where values are replaced

Swaps happen only when the request's authority is on the allowlist. Each real
value is inserted in the form its place needs:

- query strings and form bodies: query-escaped, whether the stand-in was raw
  or percent-encoded;
- JSON bodies (`application/json`, `text/json` and `+json` types):
  JSON-escaped inside strings;
- headers: as is. A real value containing a line break or NUL is refused in a
  header, and the request is not sent;
- other bodies: as is.

## Using it with a Notte session

Run the proxy on an address Notte can reach, with authentication on. Then add a
`secret` entry to the session's `proxies` list next to its normal exit. Hosts
in the entry go through your proxy; every other host keeps using the exit.

```json
{
  "proxies": [
    { "type": "notte", "country": "us" },
    {
      "type": "secret",
      "server": "https://browser-secret-proxy.example.com:8443",
      "username": "proxy-user",
      "password": "<the SECRET_PROXY_PASSWORD value>",
      "hosts": ["api.example.com", "*.payments.example"],
      "ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
    }
  ]
}
```

- `hosts` should match the proxy's `-hosts` list. A host in the entry but not
  in `-hosts` is tunneled without swaps.
- `ca_certificate` is the PEM of `ca.pem`, never the key. The session's
  browser trusts it. If the proxy's own `https://` endpoint uses a
  certificate from a private CA, include that CA in the bundle too.
- The agent and your scripts then use the stand-ins (`tok_standin_123`, ...)
  where the real values would go.

See the [Notte documentation](https://docs.notte.cc) for the session API.

### Egress through Notte's proxy gateway

By default the proxy connects to destinations from its own IP address, so a
destination sees a different IP for the swapped requests than for the rest of
the session. To keep one exit, set `-upstream-proxy` (or
`SECRET_PROXY_UPSTREAM`) to a Notte proxy gateway URL with credentials from
your Notte account. All outgoing connections, tunneled or decrypted, then go
through that parent. The parent sees only encrypted traffic for decrypted
hosts: the proxy opens its TLS connection to the destination through the
parent's tunnel.

Credentials in the parent URL are never logged; logs name only its scheme and
host.

## Security model

### What the proxy guarantees

- **Real values only reach allowlisted hosts.** Traffic to other hosts is
  tunneled without decryption, so no swap can happen there.
- **Each value only goes where it is allowed.** A value can carry its own
  host list (the same syntax as `-hosts`); without one, the `-hosts`
  allowlist applies. It is checked against the host of the `CONNECT`, which
  is where the request really goes, never against the request's own `Host`
  or `:authority`: a request naming another host than its `CONNECT` is
  answered `502`, with or without stand-ins.
- **Expired values are not used.** A value whose expiry has passed is not
  swapped.
- **Fail closed.** When a request carries a stand-in that the resolver does
  not answer for, whose value may not go to the request's host or has
  expired, or when the resolver fails or times out, nothing of the request
  is sent: the client gets `502` (on HTTP/1.1 the connection is then
  closed). Once a resolver reports that the principal's credential is no
  longer valid (an expired token), every request on its connections gets
  `502`, with or without stand-ins. Neither the client nor the log sees the
  real value or the resolver's error text; the log names only its kind
  (timeout, refused credential, error).
- **One version per request.** A resolver whose values change (a reloaded
  file) gives each request one version, for finding its stand-ins and for
  looking them up.
- **Stand-ins are found where they are swapped.** Patterns also search the
  query-, path- and JSON-unescaped forms of the request text, the forms a
  swap replaces. Only the stand-ins a swap would actually replace are
  looked up and checked: where one stand-in contains another, the longer
  one wins, as in the swap.
- **Values are isolated by principal.** The principal is the proxy
  credential of the `CONNECT` (`SECRET_PROXY_USERNAME` or the resolver's own
  credential check). Every request is looked up again for its connection's
  principal, and the proxy caches no value between requests, so a value
  looked up for one principal is never used for another.

### What it does not guarantee

- **Single use.** The proxy looks values up once per request and does not
  count uses. A value that must work only once has to be retired by the
  resolver that issues it.
- **Responses** are masked for known forms of the values only: see
  [what masking misses](#what-masking-misses).
- **WebSockets** and other upgraded connections get no swaps once upgraded.

## Exposing the proxy

- **Authentication.** Always set `SECRET_PROXY_USERNAME` and
  `SECRET_PROXY_PASSWORD` when the proxy is reachable from outside your host.
  Without them anyone who can reach it can use your real values on the
  allowlisted hosts.
- **Transport.** The listener speaks plain HTTP, so the `CONNECT` request and
  its `Proxy-Authorization` header travel in clear text (the traffic inside
  the tunnel stays encrypted). Put a TLS terminator in front of it (a load
  balancer, stunnel, or a reverse proxy in TCP mode) and give clients the
  `https://` address.
- **Network.** Restrict inbound access to the clients that need it.

## Response masking

A destination may echo a real value back: a card number on a confirmation
page, a token in an error message or a redirect URL. With masking on (the
default), the proxy replaces every real value it looked up for a principal
with its stand-in in responses on allowlisted hosts, before they reach the
browser, its logs and recordings. That covers all of the principal's
connections. To keep real values in memory no longer than needed, a value
is masked for 15 minutes after its last lookup, or until it expires if that
is sooner, and no longer once the principal's credential is reported
invalid (at most 1,024 values per principal).

What is masked:

- header values (`Location`, `Set-Cookie`, ...), the body and trailers, over
  HTTP/1.1 and HTTP/2;
- each value as is, JSON-escaped (with and without HTML escaping), query- and
  path-escaped, HTML-escaped, as decimal or hexadecimal character references,
  and, for 13 to 19 digit card numbers, grouped in fours (or 4-6-5 and 4-6-4)
  with spaces or dashes. Each form is replaced by the same form of the
  stand-in, so the response stays valid. Where the value has nothing to
  escape, so several forms look alike, the stand-in is escaped for where it
  lands, as the request side does: JSON-escaped in JSON and JavaScript
  bodies, query-escaped in form bodies and in `Location`, `Content-Location`,
  `Link`, `Refresh` and `Set-Cookie`, HTML-escaped in HTML and XML bodies,
  as is elsewhere;
- values split across HTTP/1.1 chunks or HTTP/2 DATA frames. The proxy holds
  back at most the length of the longest form, and only bytes that could
  begin a value, so streamed responses keep flowing.

How a masked response changes:

- `gzip`, `deflate`, `br` and `zstd` bodies are decoded, masked and sent
  without a content-coding: the `Content-Encoding` header is dropped. The
  proxy never passes a compressed body through unmasked. A decoded body is
  capped at 64 MiB; past it the response is cut off (HTTP/1.1: the
  connection closes mid-body; HTTP/2: the stream is reset), so the browser
  sees an error, never an unmasked byte.
- When a stand-in has the same length as its value (a format-preserving
  card stand-in, say) and the body is not compressed, the length and framing
  stay as they are. Otherwise `Content-Length` is dropped, and an HTTP/1.1
  body is sent chunked.
- A response ends with its own framing (the HTTP/1.1 zero chunk and
  trailers, the HTTP/2 end of stream), never earlier because the compressed
  data ended; bytes after the end of the compressed data are dropped.
- A response that cannot be masked gets a `502` from the proxy instead: an
  unknown or stacked content-coding (`compress`, `gzip, br`, or several
  `Content-Encoding` headers), a folded (obs-fold) HTTP/1.1 header line, a
  transfer-coding other than `chunked`, or a `206` partial response whose
  ranges masking would shift.
- Masking does not buffer bodies: memory is bounded per stream. Over HTTP/2
  the proxy is the flow-control endpoint for a masked stream, and keeps every
  other stream within the browser's windows. The request direction, and so
  what the destination sees, is unchanged.
- A response whose head arrives while its principal has nothing on record
  is passed through unchanged (over HTTP/2 its header blocks are re-encoded
  by the proxy).

### What masking misses

- Values the destination transforms: only the last four digits, other
  groupings or separators, lower-case percent-encoding (the proxy matches
  the upper-case form Go and browsers produce), base64, hashes, or a value
  split by markup
  (`4111<span>1111...`).
- Values shorter than 8 bytes (a CVC, a PIN): masking them would corrupt
  unrelated text.
- Values the proxy has not looked up for this principal in the last 15
  minutes, or past their expiry: a receipt shown later, or a card the
  destination already had on file before the principal sent its stand-in,
  is not masked. Values looked up for another principal
  are not masked on this one's connections.
- WebSockets and other tunnels (an HTTP/1.1 upgrade or an accepted HTTP/2
  `CONNECT`), whose frames pass through untouched, and responses on hosts
  that are not allowlisted (they are never decrypted).

Allowlist only the endpoints that need the values, and check what they
return.

## Limits and known gaps

- CONNECT only: plain `http://` proxy requests get `405`. The CONNECT request
  head is capped at 64 KiB (`431` beyond it), before authentication.
- TLS session resumption is not supported. A ClientHello that offers
  `pre_shared_key` or early data on an allowlisted host is refused, and every
  connection to an allowlisted host performs a full handshake.
- Request bodies on allowlisted hosts are buffered: 32 MiB per body and 64 MiB
  per HTTP/2 connection, with at most 256 open streams and 1 MiB per header
  block. An HTTP/2 stream over a limit is refused with `REFUSED_STREAM`, so the
  browser can retry it. HTTP/1.1 heads are capped at 1 MiB and chunked
  trailers at 16 KiB. A swap cannot grow a request past these limits: such a
  request is refused (HTTP/2) or its connection closed (HTTP/1.1) before
  anything is sent.
- `Expect: 100-continue` is answered by the proxy, which needs the whole body
  before forwarding the request.
- WebSockets (extended CONNECT over HTTP/2, HTTP/1.1 upgrades) are streamed
  without swaps once the destination accepts them.
- Text formats other than JSON and forms (XML, multipart) get real values as
  is; a value that needs escaping in such a body is not escaped.
- HTTP/2 clients must respect flow control: a client that sends past its
  window ends the connection with `FLOW_CONTROL_ERROR`.
- When the destination sends GOAWAY, requests it will not process are refused
  with `REFUSED_STREAM`.
- Server push is not supported.
- Response masking has limits of its own: see
  [What masking misses](#what-masking-misses).
- The swaps file and the CA are read once at start. Restart the proxy to
  change them.

## Verifying a release

Each release publishes binaries for linux and darwin (amd64, arm64), a
`checksums.txt` signed with [cosign](https://github.com/sigstore/cosign)
keyless signing, an SPDX SBOM per archive, and a signed multi-arch image,
`ghcr.io/nottelabs/browser-secret-proxy`.

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nottelabs/browser-secret-proxy/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt

cosign verify ghcr.io/nottelabs/browser-secret-proxy:<version> \
  --certificate-identity-regexp '^https://github.com/nottelabs/browser-secret-proxy/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). In short:

```sh
make test race lint vuln
```

The tests run local TLS destinations and check, end to end, that swaps happen
only on allowlisted hosts, that other hosts are tunneled without decryption,
and that the connection to the destination matches what the client sent.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
