# Security and hardening

A checklist for running browser-secret-proxy with the smallest exposure,
and a note on compliance. The guarantees and the threat model are in
[concepts.md](concepts.md#threat-model) and the README's
[Security model](../README.md#security-model). To report a vulnerability,
follow [SECURITY.md](../SECURITY.md).

- [Checklist](#checklist)
- [Allowlist as little as possible](#allowlist-as-little-as-possible)
- [Keep the CA short-lived and narrow](#keep-the-ca-short-lived-and-narrow)
- [Lock down access to the proxy](#lock-down-access-to-the-proxy)
- [Keep response masking on](#keep-response-masking-on)
- [Make values short-lived and scoped](#make-values-short-lived-and-scoped)
- [Audit logging](#audit-logging)
- [Run with no privileges](#run-with-no-privileges)
- [Control egress](#control-egress)
- [Keep it up to date](#keep-it-up-to-date)
- [Compliance note](#compliance-note)

## Checklist

- [ ] `-hosts` lists only the exact hosts that receive values. No broad
      wildcards.
- [ ] Each value carries its own host list (`http` or `sealed` mode), or
      one proxy serves one purpose (`file` mode).
- [ ] The CA lives 30 days or less, its key never leaves the proxy host,
      and its expiry is monitored.
- [ ] `SECRET_PROXY_USERNAME` and `SECRET_PROXY_PASSWORD` are set, or the
      `sealed` mode is used.
- [ ] Clients reach the proxy through a TLS terminator only; the proxy
      port is not reachable from anywhere else.
- [ ] `-mask-responses` is left on (the default).
- [ ] Values that must not outlive a session have `expires_at` or a short
      token `exp`; single-use values are retired by your resolver.
- [ ] The swaps file, CA key, resolver client key and sealed key are
      readable by the proxy's user only, on memory-backed storage where
      possible.
- [ ] The proxy runs as a non-root user with no capabilities and a
      read-only file system.
- [ ] Outbound traffic is limited to the allowlisted hosts, DNS and your
      resolver, or goes through `-upstream-proxy`.
- [ ] Your resolver logs each release, and the proxy's logs are kept.
- [ ] Releases are verified with cosign before deployment and pinned by
      digest.

## Allowlist as little as possible

Every host in `-hosts` is decrypted, and every value without its own host
list may go to any of them.

- List exact names: the payment endpoint (`pay.psp.example`), not the
  whole site (`*.shop.example`). A browser automation run loads dozens of
  hosts; only the ones that receive a value need interception.
- Use `*.domain` only when the receiving host name changes (regional or
  per-tenant API hosts), and never for a domain that serves user content.
- Give values their own host list where the resolver supports it:
  `hosts` in an [`http` answer](resolvers.md#the-answer) or a sealed
  token. A card value scoped to the payment host cannot be sent to the
  login host, even through the same proxy.
- In `file` mode values have no host list: run one proxy per purpose
  rather than one proxy with every value and every host.

Interception is also where the compatibility risk is (a ClientHello the
proxy cannot replay is refused), so a short list helps reliability too.

## Keep the CA short-lived and narrow

- Create the CA where the proxy runs; give clients `ca.pem` only.
- 30 days or less, with a [rotation plan](deployment.md#rotate-the-ca) and
  an expiry check: the proxy does not warn before the CA expires.
- Add name constraints for your allowlisted domains
  ([how](deployment.md#create-the-ca)), so a leaked key cannot vouch for
  other names in clients that enforce them.
- Use a separate CA per environment and per proxy deployment. Never reuse
  a CA that signs anything else.

## Lock down access to the proxy

- Turn on proxy authentication (or use `sealed` tokens). Without it,
  anyone who reaches the port can use your values at the allowlisted
  hosts.
- Put a [TLS terminator](deployment.md#tls-on-the-proxy-port) in front:
  the `Proxy-Authorization` header is otherwise sent in clear text.
- Restrict inbound traffic to the clients that need it (your automation
  vendor's egress addresses, a VPC peering, a NetworkPolicy).
- Generate the password (`openssl rand -hex 32`), keep it in a secret
  store, and pass it through the environment.

## Keep response masking on

Masking replaces real values that a site echoes back (a card on a
receipt, a token in an error or a redirect) before the response reaches
the browser, the agent, screenshots and recordings. It is on by default.

- Do not turn it off in production. `-mask-responses=false` is for local
  checks that a swap happened.
- Masking covers values of 8 bytes or more, in their common forms. It
  misses short values (a CVC, a PIN, a 6-digit code), transformed values
  (last four digits only, base64) and escapes other than Go's. See
  [what masking misses](../README.md#what-masking-misses).
- Check what each allowlisted endpoint returns with the
  [masking recipe](cookbook/masking.md) before you rely on it.

## Make values short-lived and scoped

The proxy does not count uses: whoever holds a stand-in and the proxy
credential can send it to its allowed hosts again until it expires. Limit
that:

- `http` mode: set `expires_at` per value (end of the session, end of a
  TOTP step), check `principal_id`, and retire single-use values in your
  service.
- `sealed` mode: give tokens an `exp` of minutes to one session, and one
  token per session.
- `file` mode: rotate the file's values on a schedule, and keep the file
  to the values the proxy's clients may all use.
- Keep `-resolver-cache-ttl` short (default 1 minute); `0` sends every
  lookup to your service.

## Audit logging

- The proxy logs each intercepted connection (host, principal), each swap
  (counts), and each refusal (reason), never a value. Keep these lines.
  See [Logs](deployment.md#logs).
- Your `http` resolver sees every lookup with its stand-ins, host and
  principal: that is the place to record who used which value where, and
  to alert on refusals or unusual hosts.
- Alert on `refusing a request` and `refusing connection: ClientHello
  cannot be replayed exactly` lines: a spike means a site changed what it
  sends, a client changed its TLS stack, or someone is probing the proxy.

## Run with no privileges

The proxy needs no privileges: it opens one listening port (above 1024 by
default) and outbound connections.

- The image runs as UID 65532 on a distroless base with no shell.
- In Docker: `--read-only --cap-drop ALL --security-opt no-new-privileges`.
- In Kubernetes: `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `seccompProfile: RuntimeDefault`, no service account token.
- With systemd: a dedicated user plus the sandboxing options in the
  [unit file](deployment.md#systemd).

Examples of each are in [deployment.md](deployment.md).

## Control egress

- Allow outbound traffic only to the allowlisted hosts, your DNS
  resolver, your detokenize service, and the hosts your clients tunnel to,
  where your network allows it.
- Or send all destination traffic through your egress proxy with
  `-upstream-proxy` (`http://`, `https://` or `socks5://`), and enforce
  the policy there. The parent only sees encrypted traffic. Calls to an
  `http` resolver are made directly, not through the parent.

## Keep it up to date

- Verify releases with cosign and the checksums
  ([how](../README.md#verifying-a-release)), and pin the image by digest.
- Only the latest release gets security fixes. Watch the repository's
  releases and `CHANGELOG.md`.

## Compliance note

The design keeps real card data, passwords and tokens out of the browser,
the agent and the browser automation vendor: they handle stand-ins, and
the real values exist only in your resolver, in the proxy's memory on your
infrastructure, and in the encrypted request to the allowlisted
destination.

browser-secret-proxy holds no certification or attestation, and this
document makes no compliance claim. Whether, and how much, a deployment
reduces your PCI DSS or other compliance scope is for you and your
assessor to decide. The proxy and its host handle real cardholder data, so
they are in scope themselves.
