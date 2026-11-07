# Resolvers

A resolver is where the proxy gets real values. You pick one with
`-resolver`. Every mode fails closed: a stand-in the resolver does not
answer for, whose value may not go to the request's host, or whose value
has expired, refuses the whole request with `502` (see
[Fail-closed behavior](concepts.md#fail-closed-behavior)).

- [Choosing a mode](#choosing-a-mode)
- [file](#file)
- [http](#http)
- [sealed](#sealed)
- [Scoping by host](#scoping-by-host)
- [Scoping by principal](#scoping-by-principal)
- [Caching and expiry](#caching-and-expiry)

## Choosing a mode

| | `file` | `http` | `sealed` |
| --- | --- | --- | --- |
| Values live in | A JSON file next to the proxy | Your detokenize service | The proxy password (a signed, encrypted token) |
| Extra service to run | None | Yes, over mutual TLS | None (an issuer signs tokens) |
| Per-value host list | No: `-hosts` applies | Yes (`hosts`) | Per token (`hosts`) |
| Per-value expiry | No | Yes (`expires_at`) | Per token (`exp`) |
| Values computed at request time (TOTP) | No | Yes | No |
| Isolation between clients | One map for everyone | One principal per proxy credential | Each token is its own principal |
| Stand-ins found by | The file's keys | `-standin-pattern` / `-standin-prefixes` (required) | The token's keys |
| Changes take effect | On reload (`-swaps-reload`, default 2 s) | On the next lookup after the cache entry ends | With the next token |

Rules of thumb:

- **`file`** when a secret manager can write the values next to the proxy
  and every client of the proxy may use all of them: one team, one set of
  test cards or service tokens.
- **`http`** when values already live in a vault or tokenization service,
  must be released per host and audited by your own service, or must be
  computed per request, such as [TOTP codes](cookbook/totp.md).
- **`sealed`** when each browser session should carry only its own values,
  with no lookup service: the system that starts the session seals the
  values it needs into a short-lived token and passes it as the proxy
  password.

A mode's flags cannot be mixed with another mode's: the proxy refuses to
start.

## file

```sh
browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -swaps /run/secrets/swaps.json
```

The file is one JSON object of stand-in to real value. Values are plain
strings:

```json
{
  "4242424242424242": "<real card number>",
  "tok_standin_123": "<real API token>"
}
```

- Every key is a known stand-in: no pattern is needed.
- Values have no host list or expiry of their own. Each may go to every
  host in `-hosts`, so keep `-hosts` to the hosts that need these values.
- All principals share the file.
- The file is checked every `-swaps-reload` (default `2s`, `0` turns
  reloading off). A changed file replaces the whole map at once: a request
  uses the old values or the new ones, never a mix. Rewrites in place and
  symlink swaps (Kubernetes Secret volumes, the Secrets Store CSI driver)
  are both picked up.
- A new content that does not load (invalid JSON, an empty object, an
  empty key) keeps the previous map. The error is logged once, without the
  file's content.
- The file holds real values. Restrict it (`chmod 600`, readable by the
  proxy's user only), keep it on a memory-backed volume where you can, and
  never commit it.

## http

```sh
browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -resolver http -resolver-url https://detokenize.internal:8443/v1/detokenize \
  -resolver-cert proxy-client.pem -resolver-key proxy-client.key \
  -resolver-ca detokenize-ca.pem -standin-prefixes tok_
```

| Flag | Meaning |
| --- | --- |
| `-resolver-url` | `https://` URL of your service. Credentials in the URL are refused. |
| `-resolver-cert`, `-resolver-key` | Client certificate the proxy presents. Required. |
| `-resolver-ca` | CA bundle that verifies the service's certificate (default: system roots). |
| `-resolver-timeout` | Limit of one call, connection included (default `2s`). |
| `-resolver-cache-ttl` | Longest a value is cached (default `1m`, `0` turns the cache off). |

### The request

For each request that carries stand-ins not in the cache, the proxy makes
one call to `-resolver-url`:

```http
POST /v1/detokenize HTTP/1.1
Content-Type: application/json
Accept: application/json

{"stand_ins": ["tok_1", "tok_2"], "host": "api.example.com", "principal_id": "proxy-user"}
```

- `stand_ins`: the stand-ins of this request that are not cached, at most
  256. A request with more is refused without a call.
- `host`: the `CONNECT` host, without its port. This is where the values
  will go.
- `principal_id`: the proxy username of the connection, empty when proxy
  authentication is off. The proxy password is never sent.

### The answer

Answer `200` with a JSON object of the values you release:

```json
{"values": {"tok_1": {"real": "<real value>", "hosts": ["api.example.com"], "expires_at": "2026-01-02T15:04:05Z"}}}
```

- `real` (required): the real value. An entry without it is unresolved; an
  empty string refuses the request.
- `hosts` (optional): where the value may go, in the `-hosts` syntax.
  Without it, any host in `-hosts`. An invalid list refuses the request.
- `expires_at` (optional, RFC 3339): when the value stops being used.
- Leave out every stand-in you do not release for this host and
  principal. The proxy then refuses the request.

Any other status, a redirect, a body that is not this JSON, a body over
4 MiB, or no answer within `-resolver-timeout` refuses the request. The
proxy logs only the kind of failure, never the body.

### Mutual TLS

The service must authenticate the proxy by its client certificate and
accept no other client: anyone who can call it can read real values.

- Issue the proxy's client certificate from a CA used only for this
  purpose, and set your server to require and verify it (Go:
  `tls.RequireAndVerifyClientCert` with that CA in `ClientCAs`). If the CA
  issues other certificates, also check the client's name.
- The proxy uses TLS 1.2 or later, tries HTTP/2, and connects directly:
  `HTTPS_PROXY` and `-upstream-proxy` do not apply to resolver calls.
- The client certificate and key are read once at start. Restart the proxy
  to rotate them.

A CA, a service certificate and a proxy client certificate for testing
(OpenSSL 3):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=detokenize CA" -keyout resolver-ca.key -out resolver-ca.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -CA resolver-ca.pem -CAkey resolver-ca.key \
  -keyout service.key -out service.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj "/CN=browser-secret-proxy" \
  -CA resolver-ca.pem -CAkey resolver-ca.key \
  -keyout proxy-client.key -out proxy-client.pem
```

### Writing your own service

Two reference services are in this repository:

- [`examples/http-resolver`](../examples/http-resolver): answers stored
  values from a JSON file.
- [`examples/totp-resolver`](../examples/totp-resolver): computes TOTP
  codes from seeds it holds, with per-host and per-principal rules and
  `expires_at` at the end of each code's time step. See the
  [TOTP recipe](cookbook/totp.md).

A production service should:

- require mutual TLS, as above;
- decide per `host` and `principal_id`, and return `hosts` so the proxy
  checks the destination too;
- set `expires_at` on values that must not outlive a session or a time
  step;
- never log real values, and log each release (stand-in, host,
  principal) for audit;
- answer `Cache-Control: no-store`, and keep its own timeout well under
  `-resolver-timeout`;
- retire single-use values itself: the proxy does not count uses.

### Ordering and concurrency

Over HTTP/2, a request waiting for a lookup does not hold back the other
requests of its connection, so its order among them can change. At most 16
lookups run at once per HTTP/2 connection. A lookup is canceled when the
browser resets its request. An HTTP/1.1 connection carries one request at
a time.

## sealed

```sh
browser-secret-proxy -ca-cert ca.pem -ca-key ca.key -hosts api.example.com \
  -resolver sealed -sealed-key sealed.key \
  -sealed-issuer-key issuer-public.pem -sealed-audience proxy-eu-1
```

The proxy password is a nested JWT: claims signed by your issuer (`EdDSA`
with Ed25519 or `ES256` with P-256), then encrypted to the proxy's EC key
(`ECDH-ES+A256KW`, `A256GCM`). The claims carry the values:

```json
{"values": {"tok_standin_123": "<real API token>"}, "hosts": ["api.example.com"], "aud": "proxy-eu-1", "exp": 1767366245, "iat": 1767362645, "sub": "session-42"}
```

- `aud` must contain `-sealed-audience`; `exp` is required.
- `hosts` restricts every value of the token.
- The token is opened on every `CONNECT`. A token that does not decrypt,
  is not signed by a `-sealed-issuer-key`, is for another audience, has
  expired, or is not in canonical compact form gets `407`.
- A connection whose token expires while it is open gets `502` for every
  later request to an allowlisted host.
- Do not set `SECRET_PROXY_USERNAME` or `SECRET_PROXY_PASSWORD`: the token
  authenticates each client. The username is free and only names the
  principal in logs when the token has no `sub`.

[`examples/seal`](../examples/seal) signs and seals a payload for
testing. Key generation, key rotation and the full claim rules are in the
README under [sealed](../README.md#sealed).

The token is a bearer credential: whoever holds it can use its values
through the proxy until `exp`. Keep `exp` short (minutes to the length of
one session), and keep the issuer's private key where the real values
already are.

## Scoping by host

A value goes only to a host it allows, checked against the `CONNECT` host:

1. its own host list (`hosts` in an `http` answer or a sealed token), or
   `-hosts` when it has none;
2. and in any case only to hosts on `-hosts`: other hosts are never
   decrypted.

So `-hosts` is the outer limit for the whole proxy, and per-value lists
narrow it. With several values on one proxy (a card for the payment host,
a password for the login host), give each its own host list so one cannot
be sent to the other's host.

## Scoping by principal

| Mode | Principal | What it isolates |
| --- | --- | --- |
| `file` | The proxy username, or empty | Nothing: one map for every principal by design. |
| `http` | The proxy username, or empty (sent as `principal_id`) | What your service releases, and the cache. One proxy has one username, so all its clients share one principal. |
| `sealed` | The token | Each token's values, cache entry and masking record. |

Masking follows the principal too: a value is masked on every connection
of the principal it was looked up for, and on no other.

For several tenants on one deployment, use `sealed` tokens, or run one
proxy per tenant with its own credential (and, in `http` mode, check
`principal_id` in your service).

## Caching and expiry

| | Kept in memory | Until |
| --- | --- | --- |
| `file` | The whole map | The next successful reload |
| `http` | Each answered value, per principal, host and stand-in (at most 10,000) | The earlier of `expires_at` and `-resolver-cache-ttl` (default 1 minute). Refusals and errors are not cached. |
| `sealed` | Each decrypted token, values included (at most 256) | The earlier of its `exp` and 5 minutes after it was decrypted |
| Masking record (all modes, when masking is on) | Each value looked up, per principal | The earlier of its expiry and 15 minutes after its last lookup |

Cached `http` values, decrypted sealed tokens and the masking record leave
memory within 5 seconds of their time, whether or not more requests come.
Set `-resolver-cache-ttl 0` to keep no `http` values in memory between
requests at all. Nothing is written to disk.

A value past its `expires_at` is refused even if it was cached. Set
`expires_at` on values that change on a schedule (TOTP codes) or must end
with a session; set `-resolver-cache-ttl 0` when every request must reach
your service.
