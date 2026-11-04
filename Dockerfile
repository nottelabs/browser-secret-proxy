# Container image for browser-secret-proxy, built from source.
#   docker build -t browser-secret-proxy .
#   docker run --rm -p 8080:8080 -v ... browser-secret-proxy -ca-cert ... -ca-key ... -hosts ... -swaps ...
#
# Base images are pinned by digest; Dependabot updates them. CI reads the Go
# version from the build stage below and runs the tests on it (ci.yml).

FROM --platform=$BUILDPLATFORM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/browser-secret-proxy ./cmd/browser-secret-proxy

# Static, distroless, non-root (UID 65532). No shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/browser-secret-proxy /usr/local/bin/browser-secret-proxy
USER nonroot:nonroot
EXPOSE 8080
# A later -listen on the command line wins over this one.
ENTRYPOINT ["/usr/local/bin/browser-secret-proxy", "-listen", ":8080"]
