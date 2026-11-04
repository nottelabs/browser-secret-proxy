# API token in a Bearer header

**Scenario `bearer-token`.** Exercised end to end by the E2E workflow
against a real Notte browser session.

A page or a script running in the browser calls an API with
`Authorization: Bearer <token>`. The browser holds a stand-in token; the
proxy puts the real one in the header on the way to the API host.

## What the site sends

```http
GET /v1/reports?month=2026-01 HTTP/1.1
Host: api.example.com
Authorization: Bearer tok_reports_ro_1
```

The same works for any header value: `X-Api-Key: tok_...`, a `Cookie`
with a session token, a custom auth header.

## Stand-in

A prefixed token that matches the shape the page expects, if it checks
one: `tok_reports_ro_1`. The prefix lets the `http` and `sealed` modes
find it with `-standin-prefixes tok_`, and keeps it from matching
anything else.

## Proxy

`swaps.json`, mode 600:

```json
{"tok_reports_ro_1": "<real API token>"}
```

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'api.example.com' \
  -swaps swaps.json
```

In headers, the real value is inserted as is, with no escaping. Only the
stand-in part of the value changes: `Bearer tok_reports_ro_1` becomes
`Bearer <real token>`.

A short-lived, per-session token is a good fit for the `sealed` mode: the
system that starts the session seals the token, scoped to the API host,
into the proxy password.

```json
{"values": {"tok_reports_ro_1": "<real API token>"}, "hosts": ["api.example.com"], "sub": "session-42"}
```

```sh
go run ./examples/seal -public-key sealed-public.pem -issuer-key issuer.key \
  -audience proxy-eu-1 -ttl 30m payload.json > token.txt
```

See [sealed](../resolvers.md#sealed) for the proxy flags and keys.

## Browser side

The page's code or your script uses the stand-in wherever it would use
the token:

```javascript
const res = await fetch("https://api.example.com/v1/reports?month=2026-01", {
  headers: { Authorization: "Bearer tok_reports_ro_1" },
});
```

A cross-origin `fetch` with an `Authorization` header triggers a CORS
preflight (`OPTIONS`), which carries no token: the API must answer it as
it would without the proxy.

## Verify

1. Against an echo endpoint on an allowlisted host with
   `-mask-responses=false`, the echoed `Authorization` header holds the
   real token.
2. On the real API, the call succeeds and the proxy logs
   `swapped stand-ins in request headers` (HTTP/2) or
   `swapped stand-ins in a request` (HTTP/1.1).
3. A `401` from the API with the proxy's log silent means the swap did
   not happen: check the host and that the header carries the stand-in
   as typed.

## Pitfalls

- **Line breaks.** A real value with a line break or NUL is refused in a
  header, so it cannot split the header or inject another. The request
  is not sent: over HTTP/2 the stream is refused (`REFUSED_STREAM`), over
  HTTP/1.1 the connection is closed. Trim tokens read from files: a
  trailing newline is a line break.
- **Tokens the page stores.** If the page saves the token it was given
  (local storage, a cookie it sets itself), it saves the stand-in, which
  is what you want. If the API hands back a new token in a response,
  that new token is real: masking does not replace values the proxy did
  not look up.
- **Signed requests.** APIs that sign each request with the token (HMAC
  signatures over the headers) compute the signature in the page with the
  stand-in, so the signature no longer matches once swapped. No swap is
  possible.
- **WebSockets.** A token sent inside an established WebSocket is not
  swapped. A token in the WebSocket's opening request (a header or the
  query string) is.
- **Headers the proxy never searches:** `Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer`,
  `Keep-Alive` and `Expect`.
