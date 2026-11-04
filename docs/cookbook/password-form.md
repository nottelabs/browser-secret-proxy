# Password in a login form

**Scenario `password-form`.** Exercised end to end by the E2E workflow
against a real Notte browser session.

The agent signs in with a stand-in password. The browser submits a
classic HTML form, and the proxy swaps the real password into the body on
its way to the login host.

## What the site sends

A form `POST`, `application/x-www-form-urlencoded`:

```http
POST /session HTTP/1.1
Host: login.example.com
Content-Type: application/x-www-form-urlencoded

username=ops%40example.com&password=pw_acme_ops_1&remember=1
```

The form often lives on the site's main host but posts to a separate
login or identity host. Allowlist the host in the request, not the page's.

## Stand-ins

- **Password:** any text the password field accepts, unique to this
  value: `pw_acme_ops_1`. Letters, digits and `_` survive every encoding
  unchanged, so the stand-in is found whatever the page does with it.
- **Username:** often not secret. When it is (a shared service account),
  give it a stand-in too: `user_acme_ops_1`. Check the field's own rules:
  an `type=email` field rejects a stand-in that is not an email address,
  in which case use one that is, such as `user_acme_ops_1@standin.example`.

## Proxy

`swaps.json`, mode 600:

```json
{
  "pw_acme_ops_1": "<real password>",
  "user_acme_ops_1@standin.example": "<real username>"
}
```

```sh
./bin/browser-secret-proxy \
  -listen 127.0.0.1:8080 \
  -ca-cert ca.pem -ca-key ca.key \
  -hosts 'login.example.com' \
  -swaps swaps.json
```

The real password is query-escaped into the form body: a password with
`&`, `=`, `+`, `%`, spaces or quotes arrives as the same characters,
never as extra fields.

For per-session passwords from a vault, use the
[`http` resolver](../resolvers.md#http) with `-standin-prefixes pw_,user_`
and a `hosts` list of `["login.example.com"]` on each value. In `http` and
`sealed` modes the proxy finds stand-ins in the raw request text, and a
prefix match stops at the first character other than a letter, digit, `_`
or `-`. Use stand-ins made only of those characters there, such as
`user_acme_ops_1`. An email-shaped stand-in does not work in these modes:
the prefix match stops at `@`, and a form body sends `@` as `%40`, so a
`-standin-pattern` for the full address does not match it either. If the
username field only accepts an email address, keep that value in `file`
mode, which also matches the escaped forms of its keys.

## Browser side

```python
page.goto("https://www.example.com/login")
page.fill("input[name=username]", "user_acme_ops_1@standin.example")
page.fill("input[name=password]", "pw_acme_ops_1")
page.click("button[type=submit]")
```

## Verify

1. Against an echo endpoint on an allowlisted host with
   `-mask-responses=false`, the posted form shows the real password,
   special characters intact.
2. On the real site, the login succeeds and the proxy logs
   `swapped stand-ins` for the login host.
3. A failed login with the stand-in sent as is means the swap did not
   happen: check that the request's host is in `-hosts` and that the body
   carries the stand-in as typed.

## Pitfalls

- **Login on another host.** `www.example.com` serves the form,
  `login.example.com` or a hosted identity provider receives it. Only the
  receiving host needs to be on `-hosts`.
- **Multi-step logins.** Many sites ask for the username first, then show
  the password field, sometimes on another host. Each request that
  carries a stand-in must go to an allowlisted host.
- **Passwords hashed or encrypted in the page.** Some sites hash the
  password or encrypt it with a public key in JavaScript before sending.
  The request then carries no stand-in, and no swap is possible.
- **The password is sent by JavaScript as JSON**, not as a form: see the
  [JSON login recipe](password-json.md).
- **Browser password managers and autofill** may replace the typed
  stand-in. Use a fresh profile without saved passwords.
- **Bot and abuse checks** on login pages see the browser's real TLS
  fingerprint and behavior; the proxy does not change them.
