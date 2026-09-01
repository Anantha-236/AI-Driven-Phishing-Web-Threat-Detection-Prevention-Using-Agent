#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REASON="${1:-manual-backup}"

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/backup.ps1" -Reason "$REASON"
else
  echo "PowerShell is required for CAPSTONE-1 backup management." >&2
  exit 1
fi
