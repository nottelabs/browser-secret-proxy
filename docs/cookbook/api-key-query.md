# API key in a query string

**Scenario `api-key-query`.** Exercised end to end by the E2E workflow
against a real Notte browser session.

Some APIs and embeds take the key in the URL: maps, analytics, search
widgets, export links. The browser loads the URL with a stand-in; the
proxy swaps the real key into the query string.

## What the site sends

```http
GET /v1/geocode?address=1+Main+St&api_key=tok_geo_1 HTTP/1.1
Host: api.example.com
```

## Stand-in

`tok_geo_1`. Letters, digits and `_` need no percent-encoding, so the
stand-in reads the same in every URL.

## Proxy

`swaps.json`, mode 600:

```json
{"tok_geo_1": "<real API key>"}
```

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'api.example.com' \
  -swaps swaps.json
```

The real key is query-escaped: a key with `&`, `=`, `+`, `/` or `%`
arrives as one parameter value, whether the page wrote the stand-in raw
or percent-encoded.

## Browser side

Load or fetch the URL as usual:

```python
page.goto("https://api.example.com/v1/geocode?address=1+Main+St&api_key=tok_geo_1")
```

## Verify

1. Against an echo endpoint on an allowlisted host with
   `-mask-responses=false`, the echoed query parameter is the real key.
2. With masking on, the echoed URL shows the stand-in again: masking
   covers the query-escaped form.
3. On the real API, the call succeeds and the proxy logs a swap for the
   API host.

## Pitfalls

- **Only the query string is swapped,** not the path. A key in a path
  segment (`/v1/tok_geo_1/geocode`) is sent as the stand-in. No setting
  changes this.
- **The real key ends up in URLs on the destination's side:** its access
  logs, its analytics, any redirect it builds from the request URL. That
  is true without the proxy too. A `Location` header that echoes the key
  is masked on its way back.
- **`Referer` and links.** The browser only knows the stand-in URL, so the
  `Referer` it sends to other hosts, and links it saves or shares, carry
  the stand-in.
- **Keys the page derives.** If the page signs the URL with the key (HMAC
  query signatures), no swap is possible: the signature is computed over
  the stand-in.
- **Short keys** below 8 bytes are not masked in responses.
