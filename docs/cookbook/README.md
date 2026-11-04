# Cookbook

Recipes for the secrets a browser automation run most often has to send.
Each one says what the site sends and where, which stand-in to use, the
exact proxy flags and values, how the browser side uses the stand-in, how
to check it works, and what can go wrong.

Each recipe is exercised end to end by the [E2E workflow](../../.github/workflows/e2e.yml)
against a real Notte browser session; the scenario ID is in parentheses.

| Recipe | Secret | Sent in | Resolver |
| --- | --- | --- | --- |
| [Card number and CVC at checkout](card.md) (`card`) | Card number, CVC | Form or JSON body to the payment host | `file` (or `http`) |
| [Password in a login form](password-form.md) (`password-form`) | Username, password | `application/x-www-form-urlencoded` body | `file` |
| [Password in a JSON login call](password-json.md) (`password-json`) | Password | JSON body from page JavaScript | `file` |
| [2FA TOTP code](totp.md) (`totp`) | Current TOTP code | Form or JSON body | `http`, with [`examples/totp-resolver`](../../examples/totp-resolver) |
| [API token in a Bearer header](bearer-token.md) (`bearer-token`) | API token | `Authorization` header | `file` (or `http`, `sealed`) |
| [API key in a query string](api-key-query.md) (`api-key-query`) | API key | `?api_key=` | `file` (or `http`, `sealed`) |
| [Response masking](masking.md) (`masking`) | Any value echoed by the site | Response headers and body | Any |

## Before you start

Every recipe assumes a running proxy with a CA, as in the README's
[quick start](../../README.md#quick-start), and a client set up as below.
Hosts in the recipes use reserved example names (`shop.example`,
`login.example.com`): replace them with the real hosts.

### Find the host and the field

Open the site in a normal browser with DevTools, do the action once by
hand with a dummy value, and find the request in the Network panel:

- its host: that is what goes in `-hosts`. Card fields often post to a
  payment provider's host, and logins to a separate identity host, not the
  page's own host;
- where the value is: the query string, a header, or the body, and the
  body's `Content-Type`;
- whether the value you typed appears as typed. If the page reformats,
  hashes or encrypts it before sending, see the pitfalls of each recipe.

### Point a client at the proxy

Any client that supports an HTTP `CONNECT` proxy and trusts your CA works.

**A Notte session.** Add a `secret` entry to the session's `proxies`
list. Hosts in the entry go through your proxy; every other host keeps
the session's normal exit.

```json
{
  "proxies": [
    { "type": "notte", "country": "us" },
    {
      "type": "secret",
      "server": "https://browser-secret-proxy.example.com:8443",
      "username": "proxy-user",
      "password": "<SECRET_PROXY_PASSWORD, or a sealed token>",
      "hosts": ["pay.psp.example"],
      "ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
    }
  ]
}
```

Keep the entry's `hosts` equal to the proxy's `-hosts`: a host in the
entry but not in `-hosts` is tunneled without swaps. See the README's
[Using it with a Notte session](../../README.md#using-it-with-a-notte-session).

**Playwright or another automation library.** Launch Chromium with the
proxy, and add `ca.pem` to the trust store the browser uses (on Linux, the
NSS database, as in the README's
[quick start](../../README.md#4-try-it-locally)):

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(proxy={
        "server": "http://127.0.0.1:8080",
        "username": "proxy-user",
        "password": "change-me",
    })
    page = browser.new_page()
    page.goto("https://shop.example/checkout")
```

**curl**, for a quick check of one request: `--proxy`, `--proxy-user` and
`--cacert ca.pem`. curl built with OpenSSL is refused by the proxy's TLS
replay check (`unsupported extension 22`); curl on macOS works. A browser
is the reliable check.

### Check a swap

With `-mask-responses=false` and an echo endpoint on an allowlisted host,
the echo shows the real value. With masking on (the default and what you
run in production), it shows the stand-in again, and the proxy log line
`swapped stand-ins ...` is what confirms the swap. Never leave masking off
outside such a check.
