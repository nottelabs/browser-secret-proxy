# Password in a JSON login call

**Scenario `password-json`.** Exercised end to end by the E2E workflow
against a real Notte browser session.

Single-page apps do not submit forms: page JavaScript reads the fields
and sends a JSON request with `fetch` or `XMLHttpRequest`. The proxy finds
the stand-in inside the JSON string and inserts the real password
JSON-escaped.

## What the site sends

```http
POST /api/auth/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email":"ops@example.com","password":"pw_acme_ops_1"}
```

The API host is often not the page's host (`app.example.com` serves the
page, `api.example.com` receives the call).

## Stand-in

`pw_acme_ops_1`, as in the [form recipe](password-form.md). Letters,
digits and `_` need no JSON escaping, so the stand-in looks the same in
the body as in the field.

## Proxy

`swaps.json`, mode 600:

```json
{"pw_acme_ops_1": "<real password>"}
```

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'api.example.com' \
  -swaps swaps.json
```

The body is treated as JSON when its `Content-Type` is
`application/json`, `text/json`, `application/x-ndjson` or any `+json`
type. Inside JSON strings, the real password is JSON-escaped: a password
with `"` or `\` arrives as the same characters and the body stays valid
JSON. A stand-in the page escaped (`pw_acme_ops_1`) is found too.

## Browser side

The agent types into the fields as usual; the page's JavaScript builds
the request:

```python
page.goto("https://app.example.com/login")
page.fill("input[type=email]", "ops@example.com")
page.fill("input[type=password]", "pw_acme_ops_1")
page.click("button[type=submit]")
```

## Verify

1. In DevTools, check the login request's `Content-Type` and that its
   body holds the stand-in as typed.
2. Against an echo endpoint with `-mask-responses=false`, `fetch` a JSON
   body with the stand-in from page JavaScript: the echoed JSON holds the
   real password, and parses.
3. On the real site, the login succeeds and the proxy logs
   `swapped stand-ins in a request body` (HTTP/2) or
   `swapped stand-ins in a request` (HTTP/1.1).

## Pitfalls

- **JSON sent as `text/plain`.** Some apps send JSON with
  `Content-Type: text/plain` to avoid a CORS preflight. The proxy then
  inserts the real value as is, without JSON escaping: a password with
  `"` or `\` breaks the body, and the login fails. Against such a site,
  the recipe only works for passwords without `"`, `\` or control
  characters.
- **Values transformed in JavaScript.** Base64 (`btoa(password)`),
  hashing, or encryption with a public key before sending leave no
  stand-in in the request. No swap is possible.
- **The real password in the response.** Some APIs echo the request on
  validation errors. Masking replaces a password of 8 bytes or more in the
  response; shorter ones reach the page. See [masking](masking.md).
- **GraphQL and batched calls** are JSON too and are swapped the same way,
  but one request may carry stand-ins for several hosts' values: all must
  be allowed for this host, or the whole request is refused.
- **WebSocket logins.** A password sent over an established WebSocket is
  not swapped.
