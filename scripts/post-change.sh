#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANGE_ID="${1:-manual-change}"

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/post-change.ps1" -ChangeId "$CHANGE_ID"
else
  echo "PowerShell is required for CAPSTONE-1 project validation." >&2
  exit 1
fi
