#!/usr/bin/env bash
# Explicitly start a separate local installation; never deletes old data.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/env.sh"
source "$WAF_ROOT/scripts/lib/check-runtime.sh"
mkdir -p "$WAF_ROOT/.local"
if [[ -f "$WAF_ROOT/.local/dev.env" ]]; then
  backup="$(mktemp -d "$WAF_ROOT/.local/settings-backup.XXXXXXXX")"
  mv "$WAF_ROOT/.local/dev.env" "$backup/dev.env"
  chmod 600 "$backup/dev.env"
  echo "Previous settings preserved at $backup/dev.env (keep private)."
fi
# Do not inherit a project name sourced earlier in this terminal.
unset COMPOSE_PROJECT_NAME
bash "$WAF_ROOT/scripts/local-env.sh"
echo 'Created an empty, separate installation with a new project name and available ports.'
echo 'Old Docker containers and volumes are untouched. This does not recover old encrypted certificates.'
echo 'Next: npm run local:up'
