# Contributing

Thanks for your interest in secret-proxy. Bug reports, fixes and focused
improvements are welcome.

For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Development setup

You need:

- the latest Go 1.26 patch release. `go.mod` sets only the minimum version,
  and `make vuln` reports standard library fixes that your Go lacks;
- `make`;
- Docker, for `make docker` and `make snapshot` only.

The other tools (golangci-lint, govulncheck, GoReleaser) run through `go run`
at the versions pinned in the `Makefile`, so there is nothing else to install.
To use a binary you already have, override its variable, for example
`make lint GOLANGCI_LINT=golangci-lint`.

```sh
git clone https://github.com/nottelabs/secret-proxy
cd secret-proxy
make build test
```

## Make targets

| Target | What it does |
| --- | --- |
| `make build` | Static binary in `bin/secret-proxy` (`CGO_ENABLED=0`). |
| `make test` | `go test ./...` |
| `make race` | `go test -race ./...` (needs cgo, so a C compiler). |
| `make vet` | `go vet ./...` |
| `make lint` | golangci-lint with `.golangci.yml`. |
| `make vuln` | govulncheck against the Go vulnerability database. |
| `make fmt` / `make fmt-check` | Format the code / fail if it is not formatted. |
| `make check` | `fmt-check`, `vet`, `lint`, `race` and `vuln`, as CI runs them. |
| `make docker` | Build the container image `secret-proxy:dev`. |
| `make cross` | Binaries for linux and darwin, amd64 and arm64, in `bin/`. |
| `make snapshot` | Local GoReleaser build of every release artifact, unsigned and unpublished, in `dist/`. |
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

Maintainers tag `vX.Y.Z` on `main`. The release workflow then builds the
binaries and container images with GoReleaser, generates SBOMs, signs the
checksums and images with cosign (keyless) and publishes the GitHub release.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license of this project (see
[NOTICE](NOTICE)).
