# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release, planned as 0.1.0.

### Added

- Forward proxy that decrypts traffic to allowlisted hosts with a CA you
  provide and replaces stand-in values with real ones in request headers,
  query strings and bodies.
- Plain CONNECT tunnels, without decryption, for every other host.
- HTTP/2 and HTTP/1.1 relays.
- Optional Basic authentication on CONNECT
  (`SECRET_PROXY_USERNAME`, `SECRET_PROXY_PASSWORD`).
- Parent proxy support (`-upstream-proxy`, `SECRET_PROXY_UPSTREAM`):
  `http://`, `https://` and `socks5://`.
- Static binaries for linux and darwin (amd64, arm64) and a multi-arch
  container image, with checksums, SBOMs and cosign signatures.
- `-version` prints the build's version.
