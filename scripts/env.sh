#!/usr/bin/env bash
# Source from other scripts; all generated artifacts stay in ignored paths.
WAF_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WAF_TOOLCHAIN_ROOT="${WAF_TOOLCHAIN_ROOT:-$WAF_ROOT/.local/toolchains}"
WAF_CACHE_ROOT="${WAF_CACHE_ROOT:-$WAF_ROOT/.local/cache}"
export PATH="$WAF_TOOLCHAIN_ROOT/go/bin:$PATH"
export GOPATH="$WAF_CACHE_ROOT/go"
export GOMODCACHE="$WAF_CACHE_ROOT/go-mod"
export GOCACHE="$WAF_CACHE_ROOT/go-build"
export GOBIN="$WAF_ROOT/waf-node/bin"
export GOTOOLCHAIN=local
export npm_config_cache="$WAF_CACHE_ROOT/npm"
