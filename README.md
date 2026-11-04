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
   `502` and not sent (see [Security model](#security-model)). Responses are
   passed back unchanged.

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
| `-resolver` | Where real values come from: `file` (default), `http` or `sealed`. See [Production setup](#production-setup-where-real-values-come-from). |
| `-swaps` | `file` mode: JSON file of stand-in to real value. Given alone, it selects the `file` mode. |
| `-swaps-reload` | `file` mode: how often the file is checked for changes (default `2s`, `0` never). |
| `-resolver-url` | `http` mode: `https://` URL of your detokenize service. |
| `-resolver-cert`, `-resolver-key` | `http` mode: PEM client certificate and key the proxy presents to the service. Required. |
| `-resolver-ca` | `http` mode: PEM CA bundle that verifies the service (default: system roots). |
| `-resolver-timeout` | `http` mode: timeout of one lookup, connection included (default `2s`). |
| `-resolver-cache-ttl` | `http` mode: longest a looked-up value is kept in memory (default `1m`, `0` no cache). |
| `-sealed-key` | `sealed` mode: PEM EC private key (P-256, P-384 or P-521) that proxy passwords are sealed to. Several keys in the file are all accepted. |
| `-sealed-issuer-key` | `sealed` mode: PEM public key (Ed25519 or P-256) of an issuer allowed to sign tokens. Repeatable; required. |
| `-sealed-audience` | `sealed` mode: this proxy's identity. A token's `aud` must contain it. Required. |
| `-standin-pattern` | Regular expression (RE2) matching stand-ins. Repeatable. See [Finding stand-ins](#finding-stand-ins). |
| `-standin-prefixes` | Comma-separated prefixes that start stand-ins, such as `tok_`. |
| `-standin-luhn` | Ignore card-like pattern matches (12 to 19 digits) whose Luhn check digit is wrong. |
| `-upstream-proxy`, `SECRET_PROXY_UPSTREAM` | Parent proxy for all outgoing connections: `http://`, `https://` or `socks5://`, with a port and with credentials in the URL. The flag wins over the variable. |
| `SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD` | Require these Basic credentials on every CONNECT. Authentication is off when `SECRET_PROXY_USERNAME` is empty. Not used in `sealed` mode, where the sealed password authenticates each client. |
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
  JSON-escaped inside strings. A stand-in is found there however the client
  escaped it (`a\u0026b` for `a&b`, as Go's `encoding/json` writes it, or
  any character as `\uXXXX`); a string that held one is then written again
  with standard escaping, which decodes to the same text with the real value;
- headers: as is. A real value containing a line break or NUL is refused in a
  header, and the request is not sent;
- other bodies: as is.

## Production setup: where real values come from

The proxy finds the stand-ins in each request to an allowlisted host, looks
up their real values once for that request, and swaps them in. The source of
those values is the resolver, chosen with `-resolver`. Every mode fails
closed: when a stand-in cannot be resolved, may not go to the request's host
or has expired, the request is answered `502` and nothing of it is sent.

| Mode | Values live in | Use it when |
| --- | --- | --- |
| `file` | A JSON file on the proxy's host, reloaded when it changes. | A secret manager can write a file next to the proxy: Vault Agent templates, the Kubernetes Secrets Store CSI driver, a Kubernetes Secret volume. The simplest setup, with no extra service. |
| `http` | Your own detokenize service, asked over mutual TLS. | Values are issued per user or per session, change often, or must be checked and audited by a service you already run. |
| `sealed` | The proxy password itself: signed by your issuer, encrypted to the proxy's key. | You want no lookup service and no storage to provision: whoever starts the session seals the values it needs and hands the token over as the proxy password. |

### file

```sh
browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -swaps /vault/secrets/swaps.json
```

The file maps each stand-in to its real value, as in the
[quick start](#2-list-the-stand-ins). The proxy checks it every
`-swaps-reload` (2 seconds by default) and, when its content changed,
replaces the whole map in one step: a request uses either the old values or
the new ones, never a mix. Both rewrites in place and symlink swaps (how
Secret volumes and the CSI driver publish a new version) are picked up. If
the new content does not load (invalid JSON, an empty map), the proxy keeps
the previous map and logs the error once, without the file's content.

Point the secret manager at a tmpfs (an `emptyDir` with `medium: Memory`, or
the CSI driver's own mount) so the values never touch a disk.

### http

```sh
browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -resolver http -resolver-url https://detokenize.internal:8443/v1/detokenize \
  -resolver-cert proxy-client.pem -resolver-key proxy-client.key -resolver-ca detokenize-ca.pem \
  -standin-prefixes tok_
```

For each request that carries stand-ins not in its cache, the proxy sends one
call:

```http
POST /v1/detokenize
Content-Type: application/json

{"stand_ins": ["tok_1", "tok_2"], "host": "api.example.com", "principal_id": "proxy-user"}
```

Your service answers `200` with the values it releases:

```json
{"values": {"tok_1": {"real": "<real value>", "hosts": ["api.example.com"], "expires_at": "2026-01-02T15:04:05Z"}}}
```

- `principal_id` is the proxy username of the connection
  (`SECRET_PROXY_USERNAME`), empty when authentication is off. The proxy
  password is never sent.
- `hosts` (optional) restricts the value to those hosts, in the `-hosts`
  syntax. Without it the value may go to any host in `-hosts`.
- `expires_at` (optional) is when the value stops being used.
- Leave out any stand-in you do not release for this host or principal. The
  request is then refused, as it is for any other status, a malformed answer,
  a redirect or a timeout (`-resolver-timeout`, 2 seconds by default).
- Values are cached in memory per principal, host and stand-in until the earlier
  of `expires_at` and `-resolver-cache-ttl` (1 minute by default). Refusals
  and errors are not cached. A request with more than 256 stand-ins is
  refused without a call.
- The connection uses mutual TLS: the service should accept only the proxy's
  client certificate.

[`examples/http-resolver`](examples/http-resolver) is a small reference
service that answers from a JSON file and requires a client certificate:

```sh
go run ./examples/http-resolver -cert server.pem -key server.key \
  -client-ca proxy-client-ca.pem -values values.json
```

### sealed

Two key pairs: the proxy's (tokens are encrypted to it) and the issuer's
(tokens are signed with it). The issuer is the system that creates tokens,
next to where the real values live; only its public key goes to the proxy.

```sh
# Proxy key: the proxy keeps the private key, issuers get the public one.
openssl ecparam -name prime256v1 -genkey -noout -out sealed.key
openssl ec -in sealed.key -pubout -out sealed-public.pem
# Issuer key (Ed25519; a P-256 key with ES256 works too): the issuer keeps
# the private key, the proxy gets the public one.
openssl genpkey -algorithm ed25519 -out issuer.key
openssl pkey -in issuer.key -pubout -out issuer-public.pem
chmod 600 sealed.key issuer.key

browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -resolver sealed -sealed-key sealed.key \
  -sealed-issuer-key issuer-public.pem -sealed-audience proxy-eu-1
```

The proxy password is a nested JWT (RFC 7519, section 5.2): the issuer signs
the claims as a JWS (`EdDSA` with an Ed25519 key, or `ES256` with a P-256
key), then encrypts that JWS as a compact JWE to the proxy's public key
(`ECDH-ES+A256KW`, `A256GCM`, `cty` `JWT`). No other algorithm is accepted.
The signed claims carry the values:

```json
{"values": {"tok_standin_123": "<real API token>"}, "hosts": ["api.example.com"], "aud": "proxy-eu-1", "exp": 1767366245, "iat": 1767362645, "sub": "session-42"}
```

- `aud` is required and must contain the proxy's `-sealed-audience`.
- `exp` (Unix seconds) is required. An expired token is refused, and a
  connection that outlives its token stops swapping.
- `nbf` and `iat` (optional, Unix seconds): a token is refused before
  `nbf`, or when `iat` is in the future, beyond 30 seconds of clock skew.
- `hosts` (optional) restricts every value of the token to those hosts.
- `sub` (optional) names the principal in logs; the username is used when it
  is empty.

The proxy opens the token on every `CONNECT`: it decrypts it, verifies the
signature against the `-sealed-issuer-key` keys, then checks the claims.
That both admits the client and gives the values, with no lookup service
and no external storage. A token that does not decrypt with the proxy's
key, is not signed by a configured issuer key, was altered, is for another
audience, or has expired gets `407`. So does a token in the earlier
encrypt-only format. A connection whose token expires while it is open gets
`502` for every later request to an allowlisted host, whether or not the
request holds a stand-in.

What each layer gives:

- **Encryption** keeps the values from everyone but the proxy: the browser,
  the agent and Notte only ever hold an opaque token.
- **The signature** proves that a configured issuer made the token. The
  proxy's public key alone no longer lets anyone create tokens the proxy
  accepts, so it can be shared freely.
- **The audience** binds the token to one proxy: a token made for
  `proxy-eu-1` is refused by a proxy configured as `proxy-us-1`, even when
  both trust the same issuer and share an encryption key.

The token is still a bearer credential: whoever holds it can use its values
through the proxy until `exp`. Give tokens a short `exp`, and keep the
issuer's private key where the real values already are.

Decrypted tokens, real values included, are kept in memory so each request
does not decrypt again: at most 256 tokens, each until the earlier of its
`exp` and 5 minutes after it was decrypted. Nothing is written to disk.
The token's own stand-ins are what the proxy looks for, so no pattern is
needed.

Key rotation:

- **Issuer keys:** give `-sealed-issuer-key` once per key (or several PUBLIC
  KEY blocks in one file). Add the new key, switch the issuer to it, and
  remove the old key once its tokens have expired.
- **The proxy's key:** put the new and the old private key in the
  `-sealed-key` file, give issuers the new public key, and remove the old
  key once the tokens encrypted to it have expired.

For testing, [`examples/seal`](examples/seal) signs and seals a payload
file:

```sh
go run ./examples/seal -public-key sealed-public.pem -issuer-key issuer.key \
  -audience proxy-eu-1 -ttl 1h payload.json
```

### Finding stand-ins

The proxy must know which strings to look up:

- in `file` mode, the keys of the file;
- in `sealed` mode, the keys of the connection's token;
- in every mode, matches of `-standin-pattern` (regular expressions) and of
  `-standin-prefixes` (a prefix followed by letters, digits, `_` or `-`, not
  inside a longer word). In `http` mode you must set at least one of them.

A match the resolver does not answer for refuses the request, so patterns
must match stand-ins only. Pick stand-ins that cannot appear in other
traffic, such as a prefix of your own (`tok_`) or test card numbers. With
`-standin-luhn`, card-like matches (12 to 19 digits) must pass the Luhn
check, so arbitrary digit runs in a page are not taken for card stand-ins.

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
  principal, and what the resolvers keep in memory cannot serve another
  principal: the `http` cache is keyed by principal, host and stand-in, and
  the `sealed` cache by the token itself, which only its holder can present.
  The `file` mode has one map for every principal by design.

### What it does not guarantee

- **Single use.** The proxy looks values up once per request and does not
  count uses. A value that must work only once has to be retired by the
  resolver that issues it.
- **Responses** are not masked: see [Responses are not masked](#responses-are-not-masked).
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

## Responses are not masked

The proxy replaces values in requests only. If a destination echoes a real
value back (a card number in a confirmation page, a token in an error message
or a redirect URL), the browser, the agent and anything that records the
session will see it. Masking responses is your responsibility as the
operator: allowlist only endpoints that do not return the secrets, or review
what they return before relying on them.

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
- Responses are not masked (see above).
- The CA, the `http` mode's client certificate and the `sealed` key are
  read once at start. Restart the proxy to change them. The swaps file is
  reloaded (see [file](#file)).
- In `http` mode, a lookup holds back the other requests of the same HTTP/2
  connection until it answers or times out. Cached values need no lookup.

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
