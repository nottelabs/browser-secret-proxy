# 2FA TOTP code

**Scenario `totp`.** Exercised end to end by the E2E workflow against a
real Notte browser session.

The site asks for a 6-digit code from an authenticator app. You keep the
TOTP seed; neither the agent, the browser, the automation vendor nor the
proxy's configuration ever holds it. The agent types a stand-in, and the
proxy asks a small detokenize service for the current code at the moment
the request goes out.

```text
agent types totp_acme_ops  ->  proxy  --POST /v1/detokenize (mutual TLS)-->  totp-resolver
                                  ^                                            (holds the seed,
                                  '-------- {"real": "492039", expires_at} ----  computes RFC 6238)
                               request sent with otp=492039
```

[`examples/totp-resolver`](../../examples/totp-resolver) is that service:
Go standard library only, RFC 6238 (HMAC-SHA1, SHA-256 or SHA-512, 6 to 8
digits, any period), mutual TLS, per-host and per-principal rules, and
tests against the RFC 6238 test vectors.

## What the site sends

The code in a form or JSON body to the login or verification host:

```http
POST /2fa/verify HTTP/1.1
Host: login.example.com
Content-Type: application/x-www-form-urlencoded

otp=totp_acme_ops
```

## Stand-in

- If the code field accepts text, use a prefixed stand-in:
  `totp_acme_ops`. The proxy finds it with `-standin-prefixes totp_`.
- If the field accepts only digits, or only six characters (common, often
  with `inputmode=numeric` or `maxlength=6`), the stand-in must be six
  digits. Pick a fixed one, such as `909090`, and match exactly that with
  `-standin-pattern '\b909090\b'`. Any `909090` in another request to the
  same host is then looked up and swapped too; keep `-hosts` to the
  verification host.
- Some pages split the code into six one-digit boxes and join them in
  JavaScript before sending. Type the six digits of the stand-in, one per
  box; the request carries the joined value.

## Seeds

When you enable 2FA on the account, the site shows a QR code and a text
seed (base32, such as `JBSW Y3DP EHPK 3PXP`). Save the seed in the
service's seeds file instead of, or in addition to, an authenticator app.
The file maps each stand-in to its seed and where its codes may go:

```json
{
  "totp_acme_ops": {
    "secret": "JBSWY3DPEHPK3PXP",
    "hosts": ["login.example.com"],
    "principals": ["proxy-user"]
  }
}
```

- `secret`: the base32 seed. Spaces, lower case and missing padding are
  accepted.
- `hosts` (required): where codes may be sent, in the proxy's `-hosts`
  syntax. The service answers nothing for another host and returns the
  list so the proxy checks it too.
- `principals` (optional): proxy usernames that may get codes.
- `digits` (6 to 8, default 6), `period` (seconds, default 30),
  `algorithm` (`SHA1`, `SHA256` or `SHA512`, default `SHA1`): only if the
  site's QR code (`otpauth://totp/...?digits=8&period=60&algorithm=SHA256`)
  says so.

The seeds file is the most sensitive file in this setup: whoever reads it
can generate every future code. Keep it `chmod 600`, owned by the
service's user, on a memory-backed volume or written by your secret
manager. The service warns at start when the file is readable by others.

## Run the service

Certificates for mutual TLS, as in the README's
[http quick start](../../README.md#2-choose-where-real-values-come-from):

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
chmod 600 seeds.json
```

```sh
go run ./examples/totp-resolver \
  -listen 127.0.0.1:8443 \
  -cert service.pem -key service.key \
  -client-ca resolver-ca.pem -client-name browser-secret-proxy \
  -seeds seeds.json
```

- `-client-ca` and the TLS settings refuse any client without a
  certificate from that CA.
- `-client-name` also requires the certificate's common name or a DNS
  name to be `browser-secret-proxy`, for when the CA issues other client
  certificates.
- The service listens on `POST /v1/detokenize`. It logs the principal,
  the host and how many stand-ins it answered, never a code or a seed.

## Proxy

```sh
SECRET_PROXY_USERNAME=proxy-user SECRET_PROXY_PASSWORD=change-me \
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'login.example.com' \
  -resolver http -resolver-url https://localhost:8443/v1/detokenize \
  -resolver-cert proxy-client.pem -resolver-key proxy-client.key \
  -resolver-ca resolver-ca.pem \
  -standin-prefixes totp_
```

`principal_id` in each call is `SECRET_PROXY_USERNAME`, which the seeds
file's `principals` matches.

To use the same proxy for the account's password, combine this with the
[form recipe](password-form.md): the `http` mode looks up every stand-in,
so serve the password from the same service (or a
[`http-resolver`](../../examples/http-resolver)-style one) with a prefix
of its own (`-standin-prefixes totp_,pw_`).

## How expiry works

Each code is answered with `expires_at` at the end of its time step (the
next multiple of 30 seconds, by default). So:

- the proxy caches a code at most until its step ends, whatever
  `-resolver-cache-ttl` is;
- a request after the step ends asks the service again and gets the next
  code;
- a code is never sent after its step: the proxy refuses an expired
  value.

## Browser side

```python
page.fill("input[name=otp]", "totp_acme_ops")
page.click("button[type=submit]")
```

## Verify

1. Call the service directly with the proxy's client certificate:

   ```sh
   curl --cert proxy-client.pem --key proxy-client.key --cacert resolver-ca.pem \
     -H 'Content-Type: application/json' \
     -d '{"stand_ins": ["totp_acme_ops"], "host": "login.example.com", "principal_id": "proxy-user"}' \
     https://localhost:8443/v1/detokenize
   ```

   The answer's `real` matches the code your authenticator app shows for
   the same seed. Without `--cert`, the TLS handshake fails.
2. Against an echo endpoint on an allowlisted host with
   `-mask-responses=false`, the posted `otp` is the current code.
3. On the real site, the verification step succeeds.

## Pitfalls

- **Clock skew.** Codes depend on the service's clock. Run NTP on its
  host; sites usually accept one step before or after.
- **A code used twice.** Many sites refuse a code that was already used.
  Two logins in the same 30-second step get the same code; the second
  must wait for the next step.
- **Late in the step.** A code requested in the last second of its step
  can expire before the site checks it. Sites that accept the previous
  step tolerate this; if yours does not, retry after a failure.
- **SMS and email codes** are not TOTP: the code comes from the site, not
  from a seed. This recipe does not apply.
- **Push approvals and passkeys** do not use a typed code.
- **6-digit codes are not masked** in responses: masking skips values
  shorter than 8 bytes. A code is of little use once its step is over and
  the site accepted it. 8-digit codes are masked.
- **The stand-in in other requests.** A numeric stand-in like `909090` is
  replaced wherever it appears in requests to the allowlisted host. A
  prefixed text stand-in avoids this.
