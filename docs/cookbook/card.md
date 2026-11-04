# Card number and CVC at checkout

**Scenario `card`.** Exercised end to end by the E2E workflow against a
real Notte browser session.

The agent fills a checkout form with a stand-in card number and CVC. The
proxy swaps in the real card on the request to the payment host. The
browser, the agent and the automation vendor never see the real card.

## What the site sends

Usually a `POST` from the checkout page or from a payment widget embedded
in it, with the card in the body:

```http
POST /v1/payments HTTP/1.1
Host: pay.psp.example
Content-Type: application/x-www-form-urlencoded

card_number=4242424242424242&exp_month=12&exp_year=2030&cvc=919&amount=4200
```

Or the same fields in a JSON body. Find the exact host in DevTools: card
fields embedded from a payment provider post to the provider's host, not
to the shop's.

## Stand-ins

- **Card number:** a number that passes the page's checks: the right
  length, a valid Luhn digit and a brand prefix the form accepts. Payment
  providers' published test numbers work, such as `4242424242424242`.
  Using the same length as the real card keeps the request's length, and a
  masked response's framing, unchanged.
- **CVC:** the field only takes 3 or 4 digits, so the stand-in is short.
  Pick digits that appear nowhere else in requests to the payment host
  (see [pitfalls](#pitfalls)), such as `919`.
- **Formatted variants:** if the page sends the number with spaces or
  dashes (`4242 4242 4242 4242`), add that exact form as its own stand-in.
  The proxy finds a stand-in as typed, query-escaped, path-escaped and
  JSON-escaped, not regrouped.

## Proxy

`swaps.json`, mode 600:

```json
{
  "4242424242424242": "<real card number, digits only>",
  "4242 4242 4242 4242": "<real card number, grouped the same way>",
  "919": "<real CVC>"
}
```

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'pay.psp.example' \
  -swaps swaps.json
```

Allowlist only the host that receives the card. Every request to it is
searched for the stand-ins.

Expiry date and cardholder name are usually not secret; send them as is.

### With a detokenize service

To release the card per session, scope it to the payment host and expire
it, answer it from your vault through the [`http` resolver](../resolvers.md#http).
The proxy needs a pattern to find stand-ins it does not know in advance:

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'pay.psp.example' \
  -resolver http -resolver-url https://detokenize.internal:8443/v1/detokenize \
  -resolver-cert proxy-client.pem -resolver-key proxy-client.key \
  -resolver-ca resolver-ca.pem \
  -standin-pattern '\b4242424242424242\b' -standin-pattern '\b919\b'
```

Your service answers with the host list and an expiry:

```json
{"values": {
  "4242424242424242": {"real": "<real card number>", "hosts": ["pay.psp.example"], "expires_at": "2026-01-02T15:04:05Z"},
  "919": {"real": "<real CVC>", "hosts": ["pay.psp.example"], "expires_at": "2026-01-02T15:04:05Z"}
}}
```

Keep patterns exact. A broad one such as `\b\d{16}\b` would also match
order numbers and timestamps, and every match your service does not answer
for refuses the request.

## Browser side

The agent or script types the stand-ins where the real values go:

```python
page.fill("#card-number", "4242424242424242")
page.fill("#cvc", "919")
page.fill("#exp", "12/30")
page.click("button[type=submit]")
```

With an AI agent, give it the stand-ins as the card to use. They are not
secret, so they can sit in the prompt, the agent's memory and logs.

## Verify

1. Run once against an echo endpoint on an allowlisted host with
   `-mask-responses=false`: the echo shows the real number and CVC.
2. In production, look for the proxy's `swapped stand-ins` line for the
   payment host, and for the payment in your provider's dashboard.
3. Check that the confirmation page shows the stand-in, not the real
   card: that is [response masking](masking.md) at work.

## Pitfalls

- **Short stand-ins replace substrings.** The proxy replaces every
  occurrence of a stand-in in requests to the allowlisted host, as a
  substring. With CVC stand-in `919`, a field `amount=19190` in the same
  request becomes `amount=1<CVC>0`. Allowlist only the card endpoint,
  check what else it receives, and pick CVC digits that do not occur
  there.
- **The CVC is not masked in responses.** Masking skips values shorter
  than 8 bytes. A site that echoes the CVC shows the real one.
- **Client-side encryption.** Some payment widgets encrypt the card fields
  in the page and send only ciphertext. The stand-in is encrypted with
  them, so the proxy cannot see it: the provider receives an encrypted
  test card and declines it. No swap is possible; look for a provider
  option without in-page encryption, or a server-to-server API.
- **Reformatted numbers.** A page that sends `4242-4242-4242-4242` or
  strips the number to its last four digits needs that exact form as a
  stand-in, or cannot be swapped.
- **Page-side validation.** A stand-in that fails the Luhn check or the
  brand check is rejected before anything is sent.
- **3-D Secure and other step-ups** happen on the issuer's pages, often on
  other hosts. They do not need the card number again, but they may need
  a code sent to the cardholder.
- **One card for every client** in `file` mode: everyone who can use the
  proxy can use the card at the payment host. Use the `http` or `sealed`
  mode for per-session cards.
