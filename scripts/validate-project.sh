#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/validate-project.ps1"
else
  echo "PowerShell is required for CAPSTONE-1 validation." >&2
  exit 1
fi
