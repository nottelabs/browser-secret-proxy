# Concepts

This page explains what browser-secret-proxy does to a request, what it
refuses, and what it leaves alone. The [README](../README.md) is the
reference for every flag and limit; this page is the model behind them.

- [The problem](#the-problem)
- [Stand-ins](#stand-ins)
- [Allowlisted hosts and interception](#allowlisted-hosts-and-interception)
- [What is swapped, and where](#what-is-swapped-and-where)
- [What is not swapped](#what-is-not-swapped)
- [Fail-closed behavior](#fail-closed-behavior)
- [Principals](#principals)
- [Response masking](#response-masking)
- [Threat model](#threat-model)

## The problem

A browser automation run (an AI agent, a script, a hosted browser vendor)
often has to submit a secret: a card number at checkout, a password at
login, a 2FA code, an API token. Whoever handles the browser then handles
the secret: the page, the agent's prompt and memory, screenshots, session
recordings, logs, the vendor's infrastructure.

browser-secret-proxy moves the secret out of that path. The browser and
the agent only ever handle a stand-in. The proxy, which you run, replaces
the stand-in with the real value on the way out, in the encrypted request
to the one destination allowed to receive it.

```text
 browser / agent            browser-secret-proxy             destination
 (holds stand-ins)          (your infrastructure)            (allowlisted host)

 POST /pay  cc=4242...  ->  TLS to the destination,      ->  POST /pay  cc=4111...
                            stand-in replaced by the
                            real value from a resolver
                                     |
                                     v
                              file / http / sealed
                              (where real values live)
```

## Stand-ins

A stand-in is a placeholder string that the browser types or sends where
the real value would go. The proxy recognizes it and replaces it.

Good stand-ins:

- **Cannot appear by accident** in other traffic to the same host. The
  proxy replaces every occurrence it finds, as a plain substring, not as a
  word (see [pitfalls](cookbook/card.md#pitfalls) for what a short stand-in
  can break).
- **Pass the page's own checks.** A card field may check the Luhn digit
  and the length; a 2FA field may accept only six digits. A stand-in that
  the page rejects never reaches the proxy.
- **Are not secrets.** A stand-in can be logged, put in a prompt or
  recorded. It is only useful through your proxy, with your credentials,
  to your allowlisted hosts.

The proxy finds stand-ins in two ways:

- **Known stand-ins.** In `file` mode, the keys of the swaps file; in
  `sealed` mode, the keys of the connection's token. They are found in
  every form a swap replaces: as is, query-escaped, path-escaped and
  JSON-escaped.
- **Patterns.** `-standin-prefixes tok_` matches `tok_` followed by
  letters, digits, `_` or `-`, not inside a longer word.
  `-standin-pattern` takes any RE2 regular expression. `-standin-luhn`
  drops card-like matches (12 to 19 digits) whose check digit is wrong.
  The `http` mode needs at least one pattern, since it does not know its
  stand-ins in advance.

Every match is looked up. A match the resolver does not answer for refuses
the request (see [fail-closed behavior](#fail-closed-behavior)), so a
pattern must match stand-ins only.

Where one stand-in contains another, the longer one wins.

## Allowlisted hosts and interception

The proxy is a forward proxy that speaks HTTP `CONNECT`. For each
`CONNECT host:port`:

- **Host not on `-hosts`:** the proxy opens a plain TCP tunnel and copies
  bytes both ways. It never sees the content, and nothing is swapped.
- **Host on `-hosts`:** the proxy intercepts. It reads the client's TLS
  ClientHello, sends an exact copy to the destination, and completes the
  destination's handshake first. Then it completes the client's handshake
  with a certificate for `host`, issued on the fly by your CA and
  offering the application protocol (HTTP/2 or HTTP/1.1) the destination
  chose. Requests on that connection are relayed with stand-ins replaced.

`-hosts` entries are exact names (`api.example.com`) or `*.domain`, which
matches every name below `domain` at any depth, but not `domain` itself.

Consequences of the interception design:

- **The client must trust your CA.** A Notte session receives it as the
  `secret` proxy entry's `ca_certificate`. A local Chromium uses the
  system or NSS trust store.
- **The destination sees the client's own TLS fingerprint.** The proxy
  refuses a connection whose ClientHello it cannot reproduce exactly,
  rather than substituting its own. Current Chrome and Chromium work.
  Some TLS stacks do not: curl built with OpenSSL is refused with
  `unsupported extension 22` (curl on macOS, built with LibreSSL, works).
- **No TLS session resumption.** A ClientHello that offers
  `pre_shared_key` or early data is refused, and the proxy does not issue
  session tickets, so every intercepted connection does a full handshake.
- **The SNI must be the `CONNECT` host.** A client that asks for one host
  and names another in TLS is refused.
- **Values are bound to the `CONNECT` host,** never to the request's own
  `Host` or `:authority`. A request that names another host, or names its
  host ambiguously (two `Host` headers, `:authority` and `host` that
  differ, userinfo in the authority), is refused with `502`.

## What is swapped, and where

On an intercepted connection the proxy looks for stand-ins in three places
and inserts each real value in the form that place needs:

| Place | Real value inserted |
| --- | --- |
| Query string of the request target (`?key=...`) | Query-escaped, whether the stand-in was raw or percent-encoded. |
| `application/x-www-form-urlencoded` bodies | Query-escaped. |
| JSON bodies (`application/json`, `text/json`, `application/x-ndjson`, `+json` types) | JSON-escaped inside strings. A stand-in is found however the client escaped it. |
| Header values (`Authorization`, `Cookie`, `X-Api-Key`, ...) | As is. A value with a line break or NUL is refused. |
| Other bodies (`text/plain`, XML, multipart, ...) | As is, without escaping. |

Headers that frame the message are never searched: over HTTP/1.1 `Host`,
`Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`,
`Trailer`, `Keep-Alive` and `Expect`; over HTTP/2 the pseudo-headers (other
than the query part of `:path`), `content-length`, `te` and `trailer`.
`Content-Length` is set again from the body that is sent.

The log line `swapped stand-ins in a request` (HTTP/1.1), or `swapped
stand-ins in request headers` / `in a request body` (HTTP/2), confirms a
swap. It names the host and how many fields changed, never a value.

## What is not swapped

A stand-in in any of these places goes out unchanged. That is not a leak:
the destination receives the stand-in, not the real value, and the
request usually fails on the site's side.

- **The URL path** (`/users/tok_abc/keys`). Only the query string is
  searched.
- **Forms the proxy does not recognize.** The stand-in is found as is,
  query-escaped, path-escaped and JSON-escaped. A card number the page
  reformats (`4242 4242 4242 4242` for a stand-in `4242424242424242`),
  base64, hashes, page-side encryption or any other transformation hides
  it.
- **Hosts that are not allowlisted.** Their traffic is tunneled, never
  decrypted.
- **WebSocket frames**, once the destination accepts an HTTP/1.1
  `Upgrade: websocket` with a `101`. Other tunnels inside a decrypted
  connection (a `CONNECT`, an HTTP/2 extended `CONNECT`, an upgrade to
  another protocol) are refused with `502`.
- **Plain `http://` requests.** The proxy accepts `CONNECT` only and
  answers anything else with `405`.

Some sites encrypt or hash sensitive fields in the page before they send
them (client-side encryption of card fields, password hashing in
JavaScript). The proxy cannot swap a value it cannot see. The
[cookbook](cookbook/README.md) recipes show how to check a site's request
before you rely on it.

## Fail-closed behavior

When the proxy detects a stand-in but cannot use its value, it sends
nothing of the request:

- the resolver does not answer for the stand-in, fails, or times out;
- the value may not go to the `CONNECT` host (its own `hosts` list, or
  `-hosts` when it has none);
- the value has expired (`expires_at` in `http` mode, the token's `exp` in
  `sealed` mode);
- the resolver reports the principal's credential is no longer valid (an
  expired sealed token): then every request on its connections is refused,
  with or without stand-ins;
- the request names its host ambiguously, or another host than its
  `CONNECT`.

The client gets `502`. Over HTTP/1.1 its body gives a short reason
(`secret-proxy: request refused: a stand-in has no value for this
principal`) and the connection is then closed; over HTTP/2 the `502` has
no body and the other streams go on. The proxy log has the reason in both
cases (`refusing a request`). Neither the client nor the log sees a real value or the
resolver's error text; the log names only the error's kind (timeout,
refused credential, error).

Two refusals look different:

- A real value with a line break or NUL in a header: over HTTP/2 the
  stream is reset with `REFUSED_STREAM` (clients may retry, and get the
  same answer), over HTTP/1.1 the connection is closed without a response.
- A ClientHello the proxy cannot replay: `502` inside TLS when the client
  offered HTTP/1.1, otherwise a TLS alert.

The opposite case, a stand-in the proxy does not detect, is not refused:
see [What is not swapped](#what-is-not-swapped).

## Principals

The principal is who a request is resolved for: the proxy credential of
its `CONNECT`.

- With `SECRET_PROXY_USERNAME` and `SECRET_PROXY_PASSWORD` set, the
  principal is that username. The proxy accepts one fixed credential, so
  every client of one proxy shares one principal.
- With authentication off, the principal is empty.
- In `sealed` mode every token is its own principal: the token's `sub` (or
  the username) names it in logs, but the token alone identifies it.

The principal decides what a resolver releases (the `http` mode sends it
as `principal_id`), what is cached, and which values are masked on which
connections. A value looked up for one principal is never used or masked
for another. For per-session isolation, use the `sealed` mode, or give
each tenant its own proxy and credential.

## Response masking

A destination may echo a real value back: a card number on a
confirmation page, a token in an error or in a redirect URL. With masking
on (the default, `-mask-responses=true`), the proxy replaces every real
value it looked up for a principal with its stand-in, in responses from
allowlisted hosts, before they reach the browser, its screenshots and
recordings, and the agent.

Masking covers values of 8 bytes or more, for 15 minutes after their last
lookup (or until they expire), in their raw and common escaped forms and,
for card numbers, common groupings. It does not cover every
transformation a site can apply. The [masking recipe](cookbook/masking.md)
shows what to expect, and the README lists
[what masking misses](../README.md#what-masking-misses).

## Threat model

### What the design keeps out of the browser, the agent and the vendor

- **Real values.** They live in the resolver (a file, your detokenize
  service, or a token encrypted to the proxy) and in the proxy's memory.
  The browser, the agent and the automation vendor see only stand-ins, or
  an opaque sealed token.
- **Real values echoed by the site**, within masking's limits.
- **The decryption capability.** The CA key stays with the proxy. The
  vendor receives only the CA certificate, which lets a browser trust the
  proxy but cannot issue certificates.
- **Other traffic.** Hosts outside the allowlist are tunneled without
  decryption, so the proxy sees only their host name and port.

### What you must trust

- **The proxy host.** It holds the CA key, the proxy credentials, and real
  values in memory. Anyone with shell access to it, or the CA key, can
  read or misuse them. This is out of scope of the
  [security policy](../SECURITY.md#scope) for that reason.
- **The allowlisted destinations.** They receive real values, as they
  would without the proxy.
- **Your resolver.** It decides which values exist, for which principal,
  for which host, and for how long.

### What an attacker who controls the browser or agent can do

Assume the agent can be prompt-injected, or the vendor's browser is
compromised. Holding the stand-ins and the proxy credential, it can:

- **Use the values at their allowed hosts.** It can submit the card
  stand-in to the allowlisted payment host again, or log in again. The
  proxy does not count uses. Limit this with narrow host lists, short
  value lifetimes, and single-use values retired by your resolver.
- **Not** read the real value back through the proxy: responses are
  masked, and other hosts never get the value swapped in.
- **Not** send the real value to a host of its choice: values go only to
  their allowlisted hosts, checked against the `CONNECT` host, and
  requests that name a host ambiguously are refused.
- **Not** use the CA to impersonate other hosts: certificates are issued
  only for allowlisted hosts, and only the proxy has the CA key.

The remaining exposure is what the allowlisted site itself returns in a
form masking does not cover (see
[what masking misses](../README.md#what-masking-misses)). Allowlist only
the endpoints that need values and check what they return.
