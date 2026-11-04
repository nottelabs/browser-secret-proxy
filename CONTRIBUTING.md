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

A change in behavior needs a test that fails without it. Tests that compare
what the destination receives with what the client sent are the core of the
suite; extend them rather than loosening them.

`scripts/e2e-notte.sh` checks the image end to end with a real browser: it
starts the proxy, makes it public with an [ngrok](https://ngrok.com) TCP
tunnel, starts a Notte session that sends one echo host through it, and checks
that host receives the real value while another host still gets the stand-in.
The E2E workflow runs it against Notte staging on pull requests from this
repository, on `main` and daily. To run it yourself you need Docker, `jq`,
`ngrok` v3 with an authtoken (TCP tunnels need a verified ngrok account) and a
Notte API key:

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
