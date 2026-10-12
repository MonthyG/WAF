#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
version=1.26.9
sha=42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d
if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
  echo 'Install Go 1.26.9 for your platform, then run the Makefile targets with GO=go.' >&2
  exit 1
fi
if [[ ! -x "$WAF_TOOLCHAIN_ROOT/go/bin/go" ]]; then
  mkdir -p "$WAF_TOOLCHAIN_ROOT"
  archive="$(mktemp)"
  trap 'rm -f "$archive"' EXIT
  curl --fail --silent --show-error --location "https://go.dev/dl/go${version}.linux-amd64.tar.gz" -o "$archive"
  printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -
  tar -C "$WAF_TOOLCHAIN_ROOT" -xzf "$archive"
fi
[[ "$(go version)" == "go version go${version} linux/amd64" ]] || { echo 'Unexpected toolchain version; use a separate WAF_TOOLCHAIN_ROOT.' >&2; exit 1; }
cd "$WAF_ROOT/waf-node"
go mod download
go mod verify
go build -mod=readonly -o bin/waf-proxy ./cmd/waf-proxy
go build -mod=readonly -o bin/waf-origin ./cmd/waf-origin
go build -mod=readonly -o bin/waf-lint ./cmd/waf-lint
go build -mod=readonly -o bin/waf-agent ./cmd/waf-agent
go install github.com/tsenart/vegeta/v12@v12.13.0
./bin/waf-proxy -config configs/local.json -check
