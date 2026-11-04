# Contributing

Thanks for your interest in browser-secret-proxy. Bug reports, fixes and
focused improvements are welcome.

For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Development setup

You need:

- the latest Go 1.26 patch release. `go.mod` sets only the minimum version,
  and `make vuln` reports standard library fixes that your Go lacks;
- `make`;
- Docker, for `make docker` and `make snapshot` only.

The other tools (golangci-lint, govulncheck, GoReleaser) run through `go run`
at the versions pinned in the `Makefile`, and `make snapshot` installs the
pinned syft (for SBOMs) under `bin/tools`, so there is nothing else to
install.
To use a binary you already have, override its variable, for example
`make lint GOLANGCI_LINT=golangci-lint`.

```sh
git clone https://github.com/nottelabs/browser-secret-proxy
cd browser-secret-proxy
make build test
```

## Make targets

| Target | What it does |
| --- | --- |
| `make build` | Static binary in `bin/browser-secret-proxy` (`CGO_ENABLED=0`). |
| `make test` | `go test ./...` |
| `make race` | `go test -race ./...` (needs cgo, so a C compiler). |
| `make fuzz` | Run each fuzz target for `FUZZTIME` (default `20s`), as CI does on pull requests. |
| `make vet` | `go vet ./...` |
| `make lint` | golangci-lint with `.golangci.yml`. |
| `make vuln` | govulncheck against the Go vulnerability database. |
| `make fmt` / `make fmt-check` | Format the code / fail if it is not formatted. |
| `make check` | `fmt-check`, `vet`, `lint`, `race` and `vuln`, as CI runs them. |
| `make docker` | Build the container image `browser-secret-proxy:dev`. |
| `make cross` | Binaries for linux and darwin, amd64 and arm64, in `bin/`. |
| `make snapshot` | Local GoReleaser build of every release artifact, unsigned and unpublished, in `dist/`. |
| `make release-notes RELEASE_VERSION=X.Y.Z` | Print the `CHANGELOG.md` section a release uses as its notes. |
| `make clean` | Remove `bin/` and `dist/`. |

Run `make check` before opening a pull request.

## Tests

The tests start local TLS destinations and proxies in process; they need no
network access beyond the Go module proxy. Always run the race detector on
changes to the relays or the proxy (`make race`): most of the code is
concurrent.

The parsers of what clients and destinations send (HTTP/1.1 and HTTP/2
framing, JSON strings, escapes, host names, content-codings) have fuzz
targets next to their tests. `make fuzz` runs each briefly. To run one
longer:

```sh
go test -run='^$' -fuzz='^FuzzRelay$' -fuzztime=10m ./internal/h2relay
```

A failing input is written to the package's `testdata/fuzz`. Commit it with
the fix, so it stays a test.

A change in behavior needs a test that fails without it. Tests that compare
what the destination receives with what the client sent are the core of the
suite; extend them rather than loosening them.

`scripts/e2e-notte.sh` checks the image end to end with a real browser. It
runs the Go program in `scripts/e2e-notte`, which starts two proxies, makes
them public with [ngrok](https://ngrok.com) tunnels and starts one Notte
session for each:

- The first proxy uses the `http` resolver, served by a detokenize service in
  the program over mutual TLS, with response masking off. The session sends
  `postman-echo.com` through it and the page reads what the host echoes back.
- The second uses the `file` resolver with response masking on. The session
  sends a capture server in the program, public through an ngrok HTTPS
  endpoint, through it. The program reads what arrived upstream from the
  capture server directly, not through the browser.

| Scenario | What it checks |
| --- | --- |
| `card` | A card number and CVC in a form-urlencoded POST body |
| `password-form` | A username and password in a form-urlencoded login POST |
| `password-json` | A password in a JSON body sent by page JavaScript, with the stand-in written with `\u` escapes and a real value that needs JSON escaping |
| `totp` | A 2FA code: a stable stand-in whose real value is the RFC 6238 code the resolver computes for each request (its cache is off); the echoed code must be the code of that time step or an adjacent one |
| `bearer-token` | A token in an `Authorization: Bearer` header |
| `api-key-query` | An API key in the query string |
| `masking` | The capture server receives the real value and sends it back; the page sees the stand-in, and the proxy log shows the swap |
| `not-allowlisted` | `httpbingo.org`, outside the session's secret proxy hosts, receives the stand-ins unchanged |

`password-json` runs on the `file` resolver because stand-in patterns and
prefixes match the raw request text, so the `http` resolver would not find a
stand-in written with escapes. The program prints a PASS or FAIL line per
scenario and exits non-zero when one fails.

The E2E workflow runs it against Notte staging on pull requests from this
repository, on `main` and daily. To run it yourself you need Go, Docker with
host networking (Linux, OrbStack, or Docker Desktop with host networking
turned on), `ngrok` v3 with an authtoken (TCP tunnels need a verified ngrok
account) and a Notte API key:

```sh
make docker
NOTTE_API_KEY=... NGROK_AUTHTOKEN=... scripts/e2e-notte.sh
```

## Pull requests

- Keep each pull request to one purpose, and describe what changed and why.
- Update `README.md` when you change a flag, a limit or a documented
  behavior, and add a line to the `Unreleased` section of `CHANGELOG.md`.
- Never log, print or return a real value, the CA key or a credential, even at
  debug level. Tests use stand-ins and throwaway CAs only.
- New dependencies need a reason: the proxy handles secrets, so every module
  it imports is part of what users must trust.

## Commits

Write short, imperative commit messages (`Refuse oversized header blocks`,
not `refused oversized header blocks.`), with a body when the reason is not
obvious. Pull requests are squash-merged, so the title becomes the commit on
`main`.

## Releases

Before tagging, a maintainer moves the `Unreleased` entries of `CHANGELOG.md`
under a `## [X.Y.Z] - YYYY-MM-DD` heading (`make release-notes
RELEASE_VERSION=X.Y.Z` prints what the release will say), merges that, and
tags `vX.Y.Z` on `main`. The release workflow then builds the binaries and
container images with GoReleaser, generates SBOMs, signs the checksums and
images with cosign (keyless) and publishes the GitHub release with that
section as its notes. It fails if the section is missing.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license of this project (see
[NOTICE](NOTICE)).
