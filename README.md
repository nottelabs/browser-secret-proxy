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

Real values are never logged, nor are their lengths. Log lines name the host
and how many fields were swapped.

## Quick start

You need Go 1.26 or later to build from source, or Docker. CI runs the
tests on the latest Go 1.26 and on the Go version the Dockerfile builds with.

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

### 2. Choose where real values come from

The proxy looks up the real value of each stand-in it finds. Where it looks
is the resolver, set with `-resolver`:

- `file` (the default): a JSON file next to the proxy. Use it for quick tests,
  or when a secret manager can write the file for you (Vault Agent
  templates, the Kubernetes Secrets Store CSI driver).
- `http`: a detokenize service you run, called over mutual TLS. Use it when
  your values already live in a vault or tokenization service with an API.
- `sealed`: the values travel in the proxy password, signed by your issuer
  and encrypted to the proxy. Use it for short-lived, per-session values
  with no lookup service and no storage.

Each mode is described in full under
[Production setup](#production-setup-where-real-values-come-from). To try
one locally:

**file.** `swaps.json` maps each stand-in to its real value:

```json
{
  "4242424242424242": "<real card number>",
  "tok_standin_123": "<real API token>"
}
```

Pick stand-ins that cannot appear by accident in other traffic. When one
stand-in contains another, the longer one wins. The proxy reloads the file
when it changes. It holds your real secrets: restrict its permissions
(`chmod 600 swaps.json`) and never commit it. Step 3 runs this mode.

**http.** [`examples/http-resolver`](examples/http-resolver) is a reference
detokenize service. Create a CA that issues its server certificate and the
proxy's client certificate (OpenSSL 3):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=detokenize CA" -keyout resolver-ca.key -out resolver-ca.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal" \
  -CA resolver-ca.pem -CAkey resolver-ca.key \
  -keyout service.key -out service.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=browser-secret-proxy" \
  -CA resolver-ca.pem -CAkey resolver-ca.key \
  -keyout proxy-client.key -out proxy-client.pem
```

Give the service its values in `values.json`, as a plain string or with the
hosts a value may go to:

```json
{
  "tok_standin_123": "<real API token>",
  "tok_card_1": {"real": "<real card number>", "hosts": ["api.payments.example"]}
}
```

```sh
go run ./examples/http-resolver -cert service.pem -key service.key \
  -client-ca resolver-ca.pem -values values.json
```

In step 3, replace `-swaps swaps.json` with:

```sh
  -resolver http -resolver-url https://localhost:8443/v1/detokenize \
  -resolver-cert proxy-client.pem -resolver-key proxy-client.key \
  -resolver-ca resolver-ca.pem -standin-prefixes tok_
```

The proxy does not know this mode's stand-ins in advance, so
`-standin-prefixes` or `-standin-pattern` tells it what to look up (see
[Finding stand-ins](#finding-stand-ins)).

**sealed.** Create the proxy's key pair and an issuer key pair with the
`openssl` commands under [sealed](#sealed). Put the values in
`payload.json`:

```json
{"values": {"tok_standin_123": "<real API token>"}, "hosts": ["api.example.com"], "sub": "session-42"}
```

Then sign and seal it into a token that expires in one hour:

```sh
go run ./examples/seal -public-key sealed-public.pem -issuer-key issuer.key \
  -audience proxy-eu-1 -ttl 1h payload.json > token.txt
```

In step 3, replace `-swaps swaps.json` with:

```sh
  -resolver sealed -sealed-key sealed.key \
  -sealed-issuer-key issuer-public.pem -sealed-audience proxy-eu-1
```

The client sends the token as its proxy password. Do not set
`SECRET_PROXY_USERNAME` or `SECRET_PROXY_PASSWORD` in this mode.

### 3. Run the proxy

These commands use the `file` mode. For `http` or `sealed`, replace
`-swaps swaps.json` with that mode's flags from step 2 (with Docker, mount
that mode's files instead of `swaps.json`, and drop the `-e` credentials in
`sealed` mode).

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

In `http` mode, `localhost` inside the container is the container itself,
so the proxy cannot reach a resolver running on your machine at
`localhost:8443`:

- Docker Desktop and OrbStack: use
  `-resolver-url https://host.docker.internal:8443/v1/detokenize`. The
  service certificate from step 2 already lists `host.docker.internal`.
- Linux: run the container with `--network host` (drop `-p 8080:8080` and
  add `-listen 127.0.0.1:8080`), so `https://localhost:8443` works as in
  step 2.

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

With proxy authentication on, add `--proxy-user proxy-user:change-me`. In
`sealed` mode, send the token as the password:
`--proxy-user "session:$(cat token.txt)"`.

An echo endpoint shows the stand-in, not the real value: response masking
(on by default) replaces the value on the way back. The proxy's log line
`swapped stand-ins` confirms the swap, and `-mask-responses=false` shows the
real value in the echo.

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
| `-upstream-proxy`, `SECRET_PROXY_UPSTREAM` | Parent proxy for all outgoing connections: `http://`, `https://` or `socks5://`, with a port and with credentials in the URL. Nothing but an optional `/` may follow the port; percent-encode special characters in the user and password. The flag wins over the variable. |
| `SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD` | Require these Basic credentials on every CONNECT. Authentication is off when `SECRET_PROXY_USERNAME` is empty; a `SECRET_PROXY_PASSWORD` without it is refused at start. Must not be set in `sealed` mode, where the sealed password authenticates each client. |
| `-mask-responses` | Replace real values with their stand-ins in responses from allowlisted hosts (default `true`; `-mask-responses=false` turns it off). See [Response masking](#response-masking). |
| `-mask-stream-window` | What masking holds back at the end of a streamed response: `fixed` (default), a window of bytes whatever they are, or `minimal`, only bytes that could begin a real value. `minimal` lowers streaming latency, but lets any allowlisted endpoint that reflects input reveal real values. Any other value is refused at start. See [Response masking](#response-masking). |
| `-v` | Debug logging. |
| `-version` | Print the version and exit. |

A mode's flags cannot be combined with another `-resolver`: the proxy then
refuses to start.

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
  header, whatever the header already holds, and the request is not sent.
  Over HTTP/2, a field value holding a NUL, CR or LF, or starting or ending
  with a space or tab, is malformed (RFC 9113 8.2.1): the request is
  answered `502`, with or without stand-ins, and a streamed request with
  such trailers is reset;
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
[quick start](#2-choose-where-real-values-come-from). The proxy checks it every
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

- `host` is the `CONNECT` host as `-hosts` matches it: in lower case,
  without the port or a trailing dot. `API.Example.COM.:443` is sent as
  `api.example.com`.
- `principal_id` is the proxy username of the connection
  (`SECRET_PROXY_USERNAME`), empty when authentication is off. The proxy
  password is never sent.
- `hosts` (optional) restricts the value to those hosts, in the `-hosts`
  syntax. Without it, or with `null`, the value may go to any host in
  `-hosts`. An empty list (`"hosts": []`) is not the same: like any invalid
  list, it refuses the request.
- `expires_at` (optional) is when the value stops being used.
- The answer is read as written. One that names a member twice, at any
  depth (a stand-in, or `hosts` within one value), or spells `values`,
  `real`, `hosts` or `expires_at` in another case (`"HOSTS"`,
  `"Expires_At"`) is malformed: a JSON parser that keeps the last
  duplicate, or ignores case, would read another scope than your service
  meant. Other members are ignored.
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
service that answers from a JSON file and requires a client certificate. It
reads the file and each request as strictly as the proxy reads its answer:

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
  Without it the values may go to any host in `-hosts`. An empty list
  refuses every request that carries one of them, and `examples/seal`
  refuses to seal one.
- `sub` (optional) names the principal in logs; the username is used when it
  is empty. Neither changes what the token gives: the principal is the token
  itself, so its values are masked on all of its connections, whatever
  username each one gives.

The proxy opens the token on every `CONNECT`: it decrypts it, verifies the
signature against the `-sealed-issuer-key` keys, then checks the claims.
That both admits the client and gives the values, with no lookup service
and no external storage. A token that does not decrypt with the proxy's
key, is not signed by a configured issuer key, was altered, is for another
audience, or has expired gets `407`. So does a token in the earlier
encrypt-only format, and a token that is not in its canonical compact form
(five segments of unpadded base64url, without line breaks or non-zero
unused bits), so a token cannot be presented as several passwords. So
does a token whose claims name a member twice, at any depth, or spell a
claim above in another case (`"HOSTS"`, `"Exp"`): a JSON parser that keeps
the last duplicate, or ignores case, would read other claims than the
issuer checked. Other members are allowed. A
connection whose token expires while it is open gets `502` for every later
request to an allowlisted host, whether or not the request holds a
stand-in.

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
`exp` and 5 minutes after it was decrypted. They leave memory within 5
seconds of that time, whether or not more requests come. Nothing is written
to disk.
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
file. It refuses a file with a member it does not know, or one the proxy
would refuse in the claims:

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
      "password": "<the SECRET_PROXY_PASSWORD value, or a sealed token>",
      "hosts": ["api.example.com", "*.payments.example"],
      "ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
    }
  ]
}
```

- `hosts` should match the proxy's `-hosts` list. A host in the entry but not
  in `-hosts` is tunneled without swaps.
- In `sealed` mode, `password` is the session's sealed token. `username` is
  then free: it names the principal in logs when the token has no `sub`, and
  changes nothing else. The token alone is the principal, for its values and
  for masking.
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

Credentials in the parent URL are never logged or printed, not even in the
usage text or when the URL does not parse; logs name only its scheme and
host.

## Security model

### What the proxy guarantees

- **Real values only reach allowlisted hosts.** Traffic to other hosts is
  tunneled without decryption, so no swap can happen there.
- **Each value only goes where it is allowed.** A value can carry its own
  host list (the same syntax as `-hosts`); without one, the `-hosts`
  allowlist applies (an empty list refuses the request). It is checked
  against the host of the `CONNECT`, which is where the request really goes,
  never against the request's own `Host`
  or `:authority`: a request naming another host than its `CONNECT` is
  answered `502`, with or without stand-ins. So is a request a server could
  read as naming another host: one with more than one `Host` (HTTP/1.1), or
  more than one `:authority` or `host` (HTTP/2); a `host` that differs from
  `:authority`, or an absolute-form target (`GET https://host/`) that
  differs from `Host`; an authority with userinfo (`user@host`), a path,
  query, fragment or whitespace, or a port that is not a number. Over
  HTTP/2, a header name with uppercase letters is refused the same way, and
  so is a pseudo-header that is repeated (two `:method` fields), unknown, or
  after a regular field.
  Over HTTP/1.1, so is a request whose body a server could frame
  differently, or whose head it could split into other lines (RFC 9112):
  `Transfer-Encoding` with `Content-Length`, a `Transfer-Encoding` other
  than a single `chunked` or on a request that is not HTTP/1.1, more than
  one `Content-Length` or one that is not a decimal number (only spaces and
  tabs may surround either value), a folded (obs-fold) header line, a
  header name that is not a token (`Name : value`), and a bare CR or NUL
  in the request line or a header line. A chunked trailer
  line like that closes the connection before anything is sent.
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
- **Responses** are masked for known forms of the values only: see
  [what masking misses](#what-masking-misses).
- **WebSockets** get no swaps and no masking once upgraded. They are the
  only tunnel the proxy opens inside an intercepted connection, and only
  over HTTP/1.1: an `Upgrade: websocket` that the destination answers with
  a `101`, which a handler that is not a WebSocket endpoint does not send.
  The handshake request is swapped like any other and the head of its
  answer is masked, but after the `101` the frames pass through untouched
  both ways. A WebSocket endpoint that echoes a value from its handshake
  (`wss://host/ws?token=...`) returns it unmasked. Over HTTP/2 the proxy
  never tells the browser that the destination supports WebSockets (it
  drops `SETTINGS_ENABLE_CONNECT_PROTOCOL` from the destination's
  settings), so the browser opens them over HTTP/1.1. Every other tunnel is
  answered `502` and not sent: a `CONNECT` inside an intercepted connection
  (HTTP/1.1, or HTTP/2 with or without `:protocol`, a WebSocket included)
  and an HTTP/1.1 upgrade to another protocol, such as `h2c`.

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
invalid (at most 1,024 values per principal, the least recently looked up
dropped first, but never those of the request that looks them up; a
request that alone carries more than 1,024 values is answered `502` and
not sent). Values are kept for at most 4,096 principals: when one more
principal looks a value up, the least recently active principal's values are
dropped, and its responses are not masked until it looks values up again.
Expired values leave memory within 5 seconds, whether or not more requests
come.

What is masked:

- header values (`Location`, `Set-Cookie`, ...), the HTTP/1.1 reason phrase
  (`statusText` in `fetch`), the body and trailers, over HTTP/1.1 and HTTP/2;
- each value as is, and in the escaped forms Go's standard encoders write:
  JSON-escaped as `encoding/json` writes it (with and without HTML escaping),
  query- and path-escaped as `net/url` writes it (`QueryEscape`,
  `PathEscape`), HTML-escaped as `html.EscapeString` writes it, as decimal
  references (`&#65;`) and as hexadecimal references in lower case (`&#x4a;`)
  or upper case (`&#X4A;`); and, for 13 to 19 digit card numbers, grouped in
  fours (or 4-6-5 and 4-6-4) with spaces or dashes. Other encoders often
  escape differently: see [What masking misses](#what-masking-misses). Each
  form is replaced by the same form of the stand-in, so the response stays
  valid. Where the value has nothing to escape, so several forms look alike,
  the stand-in is escaped for where it lands, as the request side does:
  JSON-escaped in JSON and JavaScript bodies, query-escaped in form bodies
  and in `Location`, `Content-Location`, `Link`, `Refresh` and `Set-Cookie`,
  HTML-escaped in HTML and XML bodies, as is elsewhere;
- values split across HTTP/1.1 chunks or HTTP/2 DATA frames. By default
  (`-mask-stream-window=fixed`) the proxy holds back a window of the last
  bytes of a body it has received: one byte fewer than the longest form of a
  value on record, so about six bytes per character of the longest value,
  since a character reference (`&#x73;`) takes up to six (149 bytes for a
  25-character token). See below for what this does to streams, and for
  `-mask-stream-window=minimal`.

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
  data ended. Bytes after the end of `deflate` data are dropped. Bytes
  after the end of `gzip`, `br` or `zstd` data make the decoder fail, so
  the response is cut off as when it passes the cap: the browser sees an
  error, never an unmasked byte.
- A response that cannot be masked gets a `502` from the proxy instead: an
  unknown or stacked content-coding (`compress`, `gzip, br`, or several
  `Content-Encoding` headers), a folded (obs-fold) HTTP/1.1 header line,
  transfer-codings other than a single `chunked` across every
  `Transfer-Encoding` header (any `transfer-encoding` field over HTTP/2), or
  any `206` partial response. Ranges would be masked one by one, so a client
  could ask for the pieces of a value (`bytes=0-7`, then `bytes=8-15`) and
  put it back together, even with a stand-in of the same length.
- Also refused with a `502`: a real value in a header that frames the
  HTTP/1.1 message or connection (`Content-Length`, `Transfer-Encoding`,
  `Content-Encoding`, `Connection`, `Keep-Alive`, `Trailer`, `Upgrade`), or
  in an HTTP/2 `content-length`, which are kept as they are; a real value in the HTTP/1.1 status line
  outside its reason phrase; and, over HTTP/2, a field name with an
  upper-case letter (malformed, RFC 9113 8.2.1). An HTTP/1.1 `101` to a
  request that did not ask to upgrade is refused the same way, with masking
  on or off: it would turn the rest of the connection into a raw stream,
  neither swapped nor masked.
- Over HTTP/2, DATA before the final response head (none yet, or only a
  `1xx`), and content in DATA on a response that cannot have any (to a
  `HEAD`, or a `204` or `304`), are malformed (RFC 9113 8.1): the stream is
  reset and the content is not passed on.
- A streamed body runs behind by the window, whatever the bytes are: each
  byte is passed on once a window's worth of bytes after it has arrived, or
  when the body ends. So the end of a server-sent event waits for more
  events (a short keep-alive comment passes on only as many bytes as it
  has), and an application that waits for the browser to act on an event
  before it sends more stalls. A response that ends, such as a long poll,
  is complete when it ends.
- `-mask-stream-window=minimal` holds back only bytes that could begin a
  value, at most the length of the longest form, so streams keep flowing.
  But it reopens a prefix oracle against every allowlisted endpoint that
  reflects input: a client that has the destination echo its guesses (a
  search page, an error message that quotes a parameter) can tell, from the
  size and timing of the HTTP/1.1 chunks, HTTP/2 DATA frames or TLS records
  it gets, how much of a value each guess matched, and rebuild the value
  byte by byte without ever receiving it. Use it only when you trust every
  allowlisted host not to reflect what a client sends, and streaming
  latency matters more to you than that.
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
- Escaped forms other than the ones Go's encoders write, though they decode
  to the same value. For example: `\/` for `/` (PHP's `json_encode`);
  `\u002B` for `+` and upper-case `\u003C` for `<` (.NET's
  `System.Text.Json`); `\u00e4` for `ä` (Python's `json.dumps`, which
  escapes non-ASCII by default); `&quot;` and `&#x27;` (Python's
  `html.escape`, Django, React); `&#x2B;` (.NET's
  `HtmlEncoder`); hexadecimal references that mix a lower-case `x` with
  upper-case digits (`&#x4A;`); `%20` for a space with `!*'()` left as is
  (`encodeURIComponent`); `%7E` for `~` (`URLSearchParams`); `/` left as is
  with `%20` for a space (Python's `urllib.parse.quote`).
- A value first recorded while a response is already open, such as a
  server-sent events stream or another long response: which values are
  masked, in the body and the trailers, is decided when the response head
  arrives, so a value the
  principal sends afterwards, on any connection, is masked only in later
  responses.
- Values that overlap: when the end of one real value is the start of
  another in the response (`abcdefgh12` then `gh12345678` in
  `abcdefgh12345678`), the first one found is replaced, and the rest of the
  other reaches the client.
- Values shorter than 8 bytes (a CVC, a PIN): masking them would corrupt
  unrelated text.
- Values the proxy has not looked up for this principal in the last 15
  minutes, or past their expiry: a receipt shown later, or a card the
  destination already had on file before the principal sent its stand-in,
  is not masked. Values looked up for another principal
  are not masked on this one's connections.
- WebSocket frames (after a `101` to an HTTP/1.1 upgrade), which pass
  through untouched, even a value the destination echoes from the swapped
  handshake. Other tunnels, HTTP/2 WebSockets included, are refused: see
  [what it does not guarantee](#what-it-does-not-guarantee).
- Responses on hosts that are not allowlisted (they are never decrypted).

Over HTTP/2, what the destination sends outside header blocks and DATA
reaches the browser only as numbers (settings, window sizes, error codes),
with masking on or off: the proxy drops GOAWAY debug data and frames of
extension or unknown types, and answers the destination's PINGs itself.

Allowlist only the endpoints that need the values, and check what they
return.

## Limits and known gaps

- CONNECT only: plain `http://` proxy requests get `405`. The CONNECT request
  head is capped at 64 KiB (`431` beyond it), before authentication.
- TLS session resumption is not supported. A ClientHello that offers
  `pre_shared_key` or early data on an allowlisted host is refused, and every
  connection to an allowlisted host performs a full handshake.
- On an allowlisted host, a ClientHello the proxy cannot parse is refused
  with a TLS `decode_error` alert. That includes one that repeats an
  extension type, which RFC 8446 forbids.
- Request bodies on allowlisted hosts are buffered: 32 MiB per body and 64 MiB
  per HTTP/2 connection, with at most 256 open streams and 1 MiB per header
  block. An HTTP/2 stream over a limit is refused with `REFUSED_STREAM`, so the
  browser can retry it. HTTP/1.1 heads are capped at 1 MiB and chunked
  trailers at 16 KiB. A swap cannot grow a request past these limits: such a
  request is refused (HTTP/2) or its connection closed (HTTP/1.1) before
  anything is sent.
- `Expect: 100-continue` is answered by the proxy, which needs the whole body
  before forwarding the request.
- WebSockets go over HTTP/1.1: the proxy does not pass on the destination's
  HTTP/2 support for them (`SETTINGS_ENABLE_CONNECT_PROTOCOL`), so browsers
  open them on an HTTP/1.1 connection of their own. Their frames are
  streamed without swaps or masking after the destination's `101`. Other
  tunnels inside an intercepted connection (`CONNECT` over HTTP/1.1 or
  HTTP/2, an HTTP/2 WebSocket, an upgrade to `h2c`) get `502`.
- Text formats other than JSON and forms (XML, multipart) get real values as
  is; a value that needs escaping in such a body is not escaped.
- HTTP/2 clients must respect flow control: a client that sends past its
  window ends the connection with `FLOW_CONTROL_ERROR`.
- An HTTP/2 frame longer than the `SETTINGS_MAX_FRAME_SIZE` its sender was
  told ends the connection with `FRAME_SIZE_ERROR`, from the client or the
  destination. A `PRIORITY_UPDATE` value over 1 KiB ends it with
  `PROTOCOL_ERROR`.
- When the destination sends GOAWAY, requests it will not process are refused
  with `REFUSED_STREAM`. The browser gets the GOAWAY without its debug data.
- Server push is not supported.
- HTTP/2 frames of a type the proxy does not know go to the destination on
  the stream they belong to there, or are dropped when that stream is not
  open upstream (its request still buffered, or ended). From the destination
  they are dropped, and so are `ALTSVC`, `ORIGIN` and `PRIORITY_UPDATE`
  frames: the destination cannot point the browser at other origins or
  services through the proxy's connection.
- The proxy answers the destination's HTTP/2 PINGs itself. The browser's
  PINGs go to the destination, and only its ACKs of them come back.
- Response masking has limits of its own: see
  [What masking misses](#what-masking-misses).
- The CA, the `http` mode's client certificate and the `sealed` key are
  read once at start. Restart the proxy to change them. The swaps file is
  reloaded (see [file](#file)).
- In `http` mode, a request that needs a lookup waits for it on its own:
  over HTTP/2, the other requests of the connection go on meanwhile, and a
  request that waited goes upstream when its lookup answers, so its order
  among the connection's requests can differ from the browser's. Requests
  that need no lookup keep the browser's order, and the `file` and `sealed`
  modes, which answer from memory, keep it for every request. At most 16
  lookups run at once per HTTP/2 connection; more wait for one to end. A
  request reset by the browser, or refused by the destination's `GOAWAY`,
  while its lookup runs cancels the lookup. An HTTP/1.1 connection carries
  one request at a time, so its lookup holds back only that connection.

## Verifying a release

Each release publishes binaries for linux and darwin (amd64, arm64), a
`checksums.txt` signed with [cosign](https://github.com/sigstore/cosign)
keyless signing, an SPDX SBOM per archive, and a signed multi-arch image,
`ghcr.io/nottelabs/browser-secret-proxy`.

No release is published yet; the first is planned as 0.1.0.

Only `.github/workflows/release.yml`, run for the release's tag, signs a
release. Check for that exact identity: a pattern that matches any workflow
of the repository also accepts a signature made by another workflow or on a
branch. Git tags have a leading `v` (`v0.1.0`), image tags do not (`0.1.0`).

```sh
VERSION=0.1.0
IDENTITY="https://github.com/nottelabs/browser-secret-proxy/.github/workflows/release.yml@refs/tags/v$VERSION"

cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt      # Linux
shasum -a 256 --ignore-missing -c checksums.txt  # macOS

cosign verify "ghcr.io/nottelabs/browser-secret-proxy:$VERSION" \
  --certificate-identity "$IDENTITY" \
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
