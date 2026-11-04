# browser-secret-proxy build, test and release targets.
# Run `make help` for a list.

# Project name: the binary and the local image are named after it. GoReleaser
# has the same single setting, project_name in .goreleaser.yaml.
NAME    ?= browser-secret-proxy
BINARY  := $(NAME)
PKG     := ./cmd/browser-secret-proxy
BIN_DIR := bin
IMAGE   ?= $(NAME):dev

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Sets the version that `-version` prints.
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS_BUILD := -trimpath -ldflags "$(LDFLAGS)"

# Tool versions. Each tool runs through `go run`, so nothing needs installing;
# override the variable to use a local binary instead.
GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION   := v1.9.0
GORELEASER_VERSION    := v2.19.0
SYFT_VERSION          := v1.56.0
GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   ?= go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
GORELEASER    ?= go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.DEFAULT_GOAL := build
.PHONY: help build test race fuzz vet lint vuln fmt fmt-check check docker cross snapshot release-notes release-check clean

help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build a static binary in bin/
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o $(BIN_DIR)/$(BINARY) $(PKG)

test: ## Run the tests
	go test -count=1 ./...

race: ## Run the tests with the race detector
	CGO_ENABLED=1 go test -race -count=1 ./...

# How long `make fuzz` runs each fuzz target.
FUZZTIME ?= 20s

fuzz: ## Run each fuzz target for FUZZTIME (default 20s)
	@for file in $$(grep -rl --include='*_test.go' '^func Fuzz' cmd internal | sort); do \
	  dir=./$$(dirname $$file); \
	  for target in $$(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' $$file); do \
	    echo "fuzzing $$target in $$dir"; \
	    go test -run='^$$' -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) $$dir || exit 1; \
	  done; \
	done

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint with .golangci.yml
	$(GOLANGCI_LINT) run ./...

vuln: ## Check dependencies and code against the Go vulnerability database
	$(GOVULNCHECK) ./...

fmt: ## Format the code
	gofmt -s -w .

fmt-check: ## Fail if any Go file is not formatted
	@unformatted="$$(gofmt -s -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt -s needed on:"; echo "$$unformatted"; exit 1; fi

check: fmt-check vet lint race vuln ## Everything CI runs

docker: ## Build the container image ($(IMAGE))
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

cross: ## Build static binaries for linux and darwin, amd64 and arm64
	@for platform in $(PLATFORMS); do \
	  os=$${platform%/*}; arch=$${platform#*/}; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS_BUILD) \
	    -o $(BIN_DIR)/$(BINARY)-$$os-$$arch $(PKG) || exit 1; \
	done

# GoReleaser runs syft from PATH to write the SBOMs, so the snapshot installs
# the pinned version under bin/tools first.
SYFT_DIR := $(abspath $(BIN_DIR))/tools/syft-$(SYFT_VERSION)

$(SYFT_DIR)/syft:
	GOBIN=$(SYFT_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)

snapshot: $(SYFT_DIR)/syft ## Build every release artifact locally, unsigned and unpublished, in dist/
	PATH="$(SYFT_DIR):$$PATH" $(GORELEASER) release --snapshot --clean --skip=sign

release-notes: ## Print the CHANGELOG.md section of RELEASE_VERSION (for example 0.1.0)
	@./scripts/release-notes.sh "$(RELEASE_VERSION)"

release-check: ## Validate .goreleaser.yaml
	$(GORELEASER) check

clean: ## Remove build output
	rm -rf $(BIN_DIR) dist
