#!/usr/bin/env bash
# Source before installing dependencies or launching TypeScript tools.
if ! command -v node >/dev/null || [[ "$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null)" != 24 ]]; then
  echo 'WAF requires Node.js 24. Activate it with: nvm install 24 && nvm use 24' >&2
  echo 'See docs/local-development.md for installation on Ubuntu, Debian, and AlmaLinux.' >&2
  exit 1
fi
