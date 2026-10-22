#!/usr/bin/env bash
set -euo pipefail

# Yuzu Restore Script — restores from a backup created by yuzu-backup.sh.
# Usage: yuzu-restore.sh BACKUP_DIR [--data-dir DIR] [--config-dir DIR] [--yes] [--no-color]

BACKUP_DIR=""
DATA_DIR="/var/lib/yuzu"
CONFIG_DIR="/etc/yuzu"
AUTO_YES=false
NO_COLOR=false

usage() {
    echo "Usage: $0 BACKUP_DIR [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --data-dir DIR     Restore target for .db files and enablement-anchor (default: /var/lib/yuzu)"
    echo "  --config-dir DIR   Restore target for .cfg files (default: /etc/yuzu)"
    echo ""
    echo "NOT COVERED by this script: the PostgreSQL database (pg_restore)"
    echo "and the CA/keys directory — restore those TOGETHER per"
    echo "docs/user-manual/server-admin.md (ADR-0010 restore-pairing)"
    echo "  --yes              Skip confirmation prompt"
    echo "  --no-color         Disable colored output"
    echo "  --help             Show this help"
}

green()  { if $NO_COLOR; then echo "$1"; else echo -e "\033[32m$1\033[0m"; fi; }
red()    { if $NO_COLOR; then echo "$1"; else echo -e "\033[31m$1\033[0m"; fi; }
yellow() { if $NO_COLOR; then echo "$1"; else echo -e "\033[33m$1\033[0m"; fi; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-dir)   DATA_DIR="$2"; shift 2 ;;
        --config-dir) CONFIG_DIR="$2"; shift 2 ;;
        --yes)        AUTO_YES=true; shift ;;
        --no-color)   NO_COLOR=true; shift ;;
        --help)       usage; exit 0 ;;
        -*)           echo "Unknown option: $1"; usage; exit 1 ;;
        *)            BACKUP_DIR="$1"; shift ;;
    esac
done

if [[ -z "$BACKUP_DIR" ]]; then
    red "Error: BACKUP_DIR is required"
    usage
    exit 1
fi

if [[ ! -d "$BACKUP_DIR" ]]; then
    red "Error: Backup directory not found: $BACKUP_DIR"
    exit 1
fi

echo "=== Yuzu Restore ==="
echo "Backup:     $BACKUP_DIR"
echo "Data dir:   $DATA_DIR"
echo "Config dir: $CONFIG_DIR"
echo ""

# Validate SHA256 manifest
if [[ -f "$BACKUP_DIR/SHA256SUMS" ]]; then
    echo "--- Verifying manifest ---"
    if (cd "$BACKUP_DIR" && sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS 2>/dev/null); then
        green "Manifest verification passed"
    else
        red "ERROR: Manifest verification FAILED — backup may be corrupted"
        exit 1
    fi
else
    yellow "WARN: No SHA256SUMS manifest found — skipping verification"
fi

echo ""
yellow "WARNING: The Yuzu server should be STOPPED before restoring."
yellow "Running 'systemctl stop yuzu-server' or equivalent is recommended."
echo ""

if ! $AUTO_YES; then
    read -rp "Continue with restore? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Restore cancelled."
        exit 0
    fi
fi

FILE_COUNT=0

# Restore database files
echo ""
echo "--- Restoring database files ---"
mkdir -p "$DATA_DIR"
for db in "$BACKUP_DIR"/*.db "$BACKUP_DIR"/*.db-wal "$BACKUP_DIR"/*.db-shm; do
    [[ -f "$db" ]] || continue
    cp "$db" "$DATA_DIR/"
    FILE_COUNT=$((FILE_COUNT + 1))
    green "  $(basename "$db") -> $DATA_DIR/"
done

# Restore configuration files
echo ""
echo "--- Restoring configuration files ---"
mkdir -p "$CONFIG_DIR"
for cfg in "$BACKUP_DIR"/*.cfg "$BACKUP_DIR"/*.conf; do
    [[ -f "$cfg" ]] || continue
    cp "$cfg" "$CONFIG_DIR/"
    FILE_COUNT=$((FILE_COUNT + 1))
    green "  $(basename "$cfg") -> $CONFIG_DIR/"
done

# The enablement continuity anchor (ADR-3006) is outside the pg_dump: restore it with the data
# directory, from the same backup point as the dump.
echo ""
echo "--- Restoring the continuity anchor ---"
if [[ -f "$BACKUP_DIR/enablement-anchor" ]]; then
    mkdir -p "$DATA_DIR"
    cp "$BACKUP_DIR/enablement-anchor" "$DATA_DIR/"
    FILE_COUNT=$((FILE_COUNT + 1))
    green "  enablement-anchor -> $DATA_DIR/"
else
    yellow "  no enablement-anchor in this backup: the restored server reports enablement as unwitnessed"
fi

echo ""
echo "=== Restore Complete ==="
green "Files restored: $FILE_COUNT"
echo "Start the server with: systemctl start yuzu-server"
