# Response masking

**Scenario `masking`.** Exercised end to end by the E2E workflow against
a real Notte browser session.

Sites echo what they receive: a receipt shows the card number, an error
quotes the token, a redirect carries the API key. Without masking, that
real value would land in the page, the agent's view, screenshots and
session recordings. With masking, the proxy replaces it with its stand-in
before the response reaches the browser.

Masking is on by default. There is nothing to configure; this recipe
shows what to expect and how to check it.

## How it works

Every real value the proxy looks up for a principal is kept on record.
In responses from allowlisted hosts, on every connection of that
principal, the proxy replaces it with its stand-in:

- in header values (`Location`, `Set-Cookie`, ...), the HTTP/1.1 reason
  phrase, the body and trailers, over HTTP/1.1 and HTTP/2;
- as is, and in the escaped forms Go's encoders write: JSON, query and
  path escaping, HTML escaping, decimal and hexadecimal character
  references;
- for 13 to 19 digit card numbers, also grouped in fours (or 4-6-5 and
  4-6-4) with spaces or dashes;
- across chunk and frame boundaries, without buffering whole bodies;
- in `gzip`, `deflate`, `br` and `zstd` bodies, which are decoded and sent
  without a content-coding.

A value stays on record for 15 minutes after its last lookup, or until it
expires if that is sooner.

## Proxy

Nothing to add: leave `-mask-responses` at its default (`true`).

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'echo.example.com' \
  -swaps swaps.json
```

`swaps.json`:

```json
{"4242424242424242": "<real card number>", "tok_standin_123": "<real API token>"}
```

## Verify

Use an endpoint on an allowlisted host that echoes the request, such as a
test endpoint you run.

1. Send the stand-ins through the proxy:

   ```python
   page.goto("https://echo.example.com/get?card=4242424242424242&token=tok_standin_123")
   print(page.inner_text("body"))
   ```

   The page shows `4242424242424242` and `tok_standin_123`, and the proxy
   logs `swapped stand-ins`: the echo endpoint received the real values
   and the proxy masked them on the way back.
2. Restart the proxy with `-mask-responses=false` and load the same URL:
   the page now shows the real values. This is the only time a real value
   should reach the browser; switch masking back on.
3. Do the same on each real endpoint you allowlist (a confirmation page,
   a profile page, an error response), and look for the real value in
   every form the site might use: in full, last four digits, inside a
   URL. Whatever masking does not cover is what the browser sees.

## What a masked response looks like

- When a stand-in has the same length as its real value (a 16-digit card
  stand-in for a 16-digit card) and the body is not compressed, the
  response keeps its length and framing.
- Otherwise `Content-Length` is dropped, and an HTTP/1.1 body is sent
  chunked.
- A compressed body arrives decoded, without `Content-Encoding`.
- A response that cannot be masked is replaced by a `502` from the proxy:
  an unknown or stacked content-coding, a `206` partial response (ranges
  could rebuild a value from masked pieces), a real value in a framing
  header. The log line is `refusing a response that cannot be masked`.

## Pitfalls

- **Short values are never masked:** a CVC, a PIN, a 6-digit code.
  Masking values under 8 bytes would corrupt unrelated text.
- **Transformed values are not masked:** only the last four digits, other
  groupings, base64, hashes, a value split by markup
  (`4111<span>1111...`), lower-case percent-encoding.
- **Other encoders' escapes are not masked** even though they decode to
  the same value: `\/` (PHP), `+` (.NET), `ä` (Python),
  `&quot;` or `&#x27;` (Python, Django, React). The README's
  [What masking misses](../../README.md#what-masking-misses) has the full
  list.
- **Values the proxy did not look up** are not masked: a card the site
  already had on file, a token the API issues in a response.
- **Values first looked up while a response is open** (a server-sent
  events stream) are masked only in later responses.
- **Per principal and per process.** Values are masked on the
  connections of the principal that looked them up, through the same
  proxy process. With several replicas, see
  [Sizing](../deployment.md#sizing).
- **WebSocket frames and hosts not on `-hosts`** are never masked. Other
  tunnels inside a decrypted connection are refused with `502`, so they
  cannot carry a response past masking.
