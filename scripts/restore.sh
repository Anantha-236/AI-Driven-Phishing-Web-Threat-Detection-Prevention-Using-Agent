#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ID="${1:-}"

if [ -z "$BACKUP_ID" ]; then
  echo "Usage: $0 <backup-id> [--dry-run]" >&2
  exit 1
fi

if command -v pwsh >/dev/null 2>&1; then
  if [ "${2:-}" = "--dry-run" ]; then
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/restore.ps1" -BackupId "$BACKUP_ID" -DryRun
  else
    pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/restore.ps1" -BackupId "$BACKUP_ID"
  fi
else
  echo "PowerShell is required for CAPSTONE-1 backup management." >&2
  exit 1
fi
