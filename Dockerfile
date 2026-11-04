# Container image for browser-secret-proxy, built from source.
#   docker build -t browser-secret-proxy .
#   docker run --rm -p 8080:8080 -v ... browser-secret-proxy -ca-cert ... -ca-key ... -hosts ... -swaps ...
#
# Base images are pinned by digest; Dependabot updates them.

FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/browser-secret-proxy ./cmd/secret-proxy

# Static, distroless, non-root (UID 65532). No shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/browser-secret-proxy /usr/local/bin/browser-secret-proxy
USER nonroot:nonroot
EXPOSE 8080
# A later -listen on the command line wins over this one.
ENTRYPOINT ["/usr/local/bin/browser-secret-proxy", "-listen", ":8080"]
