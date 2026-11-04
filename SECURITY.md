# Security policy

browser-secret-proxy handles real secrets and a CA private key, so we treat
security reports as a priority.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a suspected
vulnerability. Report it privately instead:

- by email to [security@notte.cc](mailto:security@notte.cc), or
- through GitHub: **Security > Report a vulnerability** on this repository
  (private vulnerability reporting). This option is turned on when the
  repository becomes public; until then, use the email address.

Include the version or commit, your configuration (without real secrets),
steps to reproduce, and the impact you observed. Never send real secrets,
CA keys or customer data in a report.

What to expect, as in Notte's
[responsible disclosure policy](https://www.notte.cc/security):

- We acknowledge reports within 3 business days.
- We keep you informed while we investigate and fix the issue.
- With your permission, we credit you once the issue is resolved.

Please give us reasonable time to fix the issue before disclosing it
publicly, and coordinate the disclosure with us. Notte does not run a paid
bug bounty program.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No; please upgrade |
| `main` | Best effort |

Fixes ship in a new release. Until 1.0, a security fix may come with
breaking changes; the changelog says so.

## Scope

In scope:

- a real value reaching a host that is not allowlisted, or leaving the proxy
  in a form other than the request it was placed in;
- a real value, the CA key or proxy credentials appearing in logs or error
  messages;
- with response masking on (the default), a real value reaching the client
  in a response, in a form the README's
  [Response masking](README.md#response-masking) section says is masked;
- bypassing proxy authentication;
- decrypting traffic to a host that is not allowlisted;
- issuing a certificate for a host that is not allowlisted, or a certificate
  usable beyond the connection it was issued for;
- memory exhaustion or crashes from a single client within the documented
  limits;
- the release pipeline: published binaries, container images, checksums,
  signatures and SBOMs.

Out of scope:

- anything that requires the CA key, the swaps file or shell access on the
  host running the proxy;
- real values in responses that masking does not cover: with
  `-mask-responses=false`, or in the cases listed under
  [What masking misses](README.md#what-masking-misses);
- exposing the proxy without authentication or without TLS in front of it,
  against the README's guidance;
- denial of service through traffic volume, and load testing;
- vulnerabilities in Notte's hosted services: report those under the
  [responsible disclosure policy](https://www.notte.cc/security).
