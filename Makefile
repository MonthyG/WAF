GO ?= ../scripts/go.sh
.PHONY: setup build test race vet ftw ftw-platform benchmark dev
setup:
	bash scripts/setup.sh
build:
	cd waf-node && $(GO) build -mod=readonly -o bin/waf-proxy ./cmd/waf-proxy
	cd waf-node && $(GO) build -mod=readonly -o bin/waf-origin ./cmd/waf-origin
	cd waf-node && $(GO) build -mod=readonly -o bin/waf-lint ./cmd/waf-lint
	cd waf-node && $(GO) build -mod=readonly -o bin/waf-agent ./cmd/waf-agent
test:
	cd waf-node && $(GO) test -mod=readonly ./... -count=1
race:
	cd waf-node && $(GO) test -mod=readonly -race ./... -count=1
vet:
	cd waf-node && $(GO) vet ./...
ftw:
	cd waf-node && $(GO) test -mod=readonly -tags ftw ./ftw -run TestCRS -count=1 -v -timeout=15m
ftw-platform:
	WAF_FTW_PLATFORM=1 $(MAKE) ftw
benchmark: build
	bash scripts/benchmark.sh
dev: build
	bash scripts/dev.sh
