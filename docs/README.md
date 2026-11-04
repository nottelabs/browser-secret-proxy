# browser-secret-proxy documentation

browser-secret-proxy is a forward proxy you run on your own
infrastructure. A browser, or an AI agent driving it, handles only
stand-in values; the proxy replaces them with real secrets in the
encrypted requests to the hosts you allowlist, and masks real values that
come back. The [README](../README.md) is the reference for every flag,
format and limit. These pages explain how to use it well.

## Start here

- [Concepts](concepts.md): stand-ins, allowlisted hosts, interception,
  what is and is not swapped, fail-closed behavior, principals, and the
  threat model.
- [Quick start](../README.md#quick-start): a CA, a swaps file and a
  running proxy in a few minutes.

## Run it

- [Deployment](deployment.md): Docker, systemd and Kubernetes, the CA and
  its rotation, credentials, TLS in front of the proxy port, logs, health
  checks and sizing.
- [Resolvers](resolvers.md): where real values come from (`file`, `http`,
  `sealed`), the detokenize service contract, mutual TLS, caching and
  expiry, scoping by host and principal.
- [Security and hardening](security.md): a checklist, and a note on
  compliance.

## Cookbook

Recipes with exact flags, values, browser-side code, checks and
pitfalls. Each is exercised end to end by the E2E workflow against a real
Notte browser session.

| Recipe | Scenario |
| --- | --- |
| [Card number and CVC at checkout](cookbook/card.md) | `card` |
| [Password in a login form](cookbook/password-form.md) | `password-form` |
| [Password in a JSON login call](cookbook/password-json.md) | `password-json` |
| [2FA TOTP code](cookbook/totp.md) | `totp` |
| [API token in a Bearer header](cookbook/bearer-token.md) | `bearer-token` |
| [API key in a query string](cookbook/api-key-query.md) | `api-key-query` |
| [Response masking](cookbook/masking.md) | `masking` |

See the [cookbook index](cookbook/README.md) for how to find the right
host and field on a site, and how to point a client at the proxy.

## Examples

- [`examples/http-resolver`](../examples/http-resolver): a reference
  detokenize service that answers from a JSON file.
- [`examples/totp-resolver`](../examples/totp-resolver): a detokenize
  service that computes TOTP codes (RFC 6238) from seeds it holds.
- [`examples/seal`](../examples/seal): signs and seals a token for the
  `sealed` mode.

## Project

- [Security policy](../SECURITY.md): how to report a vulnerability.
- [Contributing](../CONTRIBUTING.md) and [changelog](../CHANGELOG.md).
