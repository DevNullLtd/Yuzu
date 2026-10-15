#!/usr/bin/env bash
set -euo pipefail

# Yuzu Backup Script — backs up SQLite databases and configuration files.
# Usage: yuzu-backup.sh [--data-dir DIR] [--config-dir DIR] [--output DIR] [--no-color]

DATA_DIR="/var/lib/yuzu"
CONFIG_DIR="/etc/yuzu"
OUTPUT=""
NO_COLOR=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --data-dir DIR     Data directory (default: /var/lib/yuzu)"
    echo "  --config-dir DIR   Config directory (default: /etc/yuzu)"
    echo "  --output DIR       Output directory (default: ./yuzu-backup-TIMESTAMP)"
    echo "  --no-color         Disable colored output"
    echo "  --help             Show this help"
    echo ""
    echo "NOT COVERED by this script (back up separately — see"
    echo "docs/user-manual/server-admin.md 'PostgreSQL Substrate' and"
    echo "'Key management (secrets KEK)'):"
    echo "  * The PostgreSQL database (pg_dump --format=custom ...)"
    echo "  * The CA/keys directory (--ca-dir; default /etc/yuzu/certs) —"
    echo "    a Postgres restore is UNUSABLE without the paired keys dir"
    echo "    once envelope-encrypted secrets land (ADR-0010)"
}

green()  { if $NO_COLOR; then echo "$1"; else echo -e "\033[32m$1\033[0m"; fi; }
red()    { if $NO_COLOR; then echo "$1"; else echo -e "\033[31m$1\033[0m"; fi; }
yellow() { if $NO_COLOR; then echo "$1"; else echo -e "\033[33m$1\033[0m"; fi; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-dir)   DATA_DIR="$2"; shift 2 ;;
        --config-dir) CONFIG_DIR="$2"; shift 2 ;;
        --output)     OUTPUT="$2"; shift 2 ;;
        --no-color)   NO_COLOR=true; shift ;;
        --help)       usage; exit 0 ;;
        *)            echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="./yuzu-backup-${TIMESTAMP}"
fi

echo "=== Yuzu Backup ==="
echo "Data dir:   $DATA_DIR"
echo "Config dir: $CONFIG_DIR"
echo "Output:     $OUTPUT"
echo ""

mkdir -p "$OUTPUT"

FILE_COUNT=0
TOTAL_SIZE=0

# Flush SQLite WAL files before backup
if command -v sqlite3 &>/dev/null; then
    for db in "$DATA_DIR"/*.db; do
        [[ -f "$db" ]] || continue
        echo -n "Checkpointing $(basename "$db")... "
        if sqlite3 "$db" "PRAGMA wal_checkpoint(TRUNCATE);" &>/dev/null; then
            green "OK"
        else
            yellow "WARN (may be locked)"
        fi
    done
else
    yellow "WARN: sqlite3 not found — skipping WAL checkpoint (backup may include WAL files)"
fi

# Backup database files
echo ""
echo "--- Database files ---"
for db in "$DATA_DIR"/*.db "$DATA_DIR"/*.db-wal "$DATA_DIR"/*.db-shm; do
    [[ -f "$db" ]] || continue
    cp "$db" "$OUTPUT/"
    SIZE=$(stat -c%s "$db" 2>/dev/null || stat -f%z "$db" 2>/dev/null || echo 0)
    TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
    FILE_COUNT=$((FILE_COUNT + 1))
    green "  $(basename "$db") (${SIZE} bytes)"
done

# Backup configuration files
echo ""
echo "--- Configuration files ---"
for cfg_file in "$CONFIG_DIR"/*.cfg "$CONFIG_DIR"/*.conf; do
    [[ -f "$cfg_file" ]] || continue
    cp "$cfg_file" "$OUTPUT/"
    SIZE=$(stat -c%s "$cfg_file" 2>/dev/null || stat -f%z "$cfg_file" 2>/dev/null || echo 0)
    TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
    FILE_COUNT=$((FILE_COUNT + 1))
    green "  $(basename "$cfg_file") (${SIZE} bytes)"
done

# Also check for config files alongside the binary (Windows pattern).
# enrollment-tokens.cfg / pending-agents.cfg are HA WS-6 6.2's one-time import
# source only — a 6.2+ server never writes them (state is Postgres-
# authoritative, back it up via pg_dump) and renames them to `<name>.cfg.
# imported` once consumed. This loop still finds them on a PRE-6.2 install (or
# the renamed `.imported` copies, via the glob below) — kept deliberately, not
# stale: a backup taken before upgrading to 6.2 is exactly the file this
# importer reads.
for cfg_file in yuzu-server.cfg enrollment-tokens.cfg pending-agents.cfg                 enrollment-tokens.cfg.imported pending-agents.cfg.imported; do
    if [[ -f "$DATA_DIR/$cfg_file" ]] && [[ ! -f "$OUTPUT/$cfg_file" ]]; then
        cp "$DATA_DIR/$cfg_file" "$OUTPUT/"
        FILE_COUNT=$((FILE_COUNT + 1))
        green "  $cfg_file"
    fi
done

# Generate SHA256 manifest
echo ""
echo "--- Generating manifest ---"
(cd "$OUTPUT" && sha256sum * 2>/dev/null || shasum -a 256 * 2>/dev/null) > "$OUTPUT/SHA256SUMS"
green "  SHA256SUMS"

# Summary
echo ""
echo "=== Backup Complete ==="
green "Files:  $FILE_COUNT"
green "Size:   $((TOTAL_SIZE / 1024)) KB"
green "Output: $OUTPUT"

# Restore-pairing warning (ADR-0010 / governance Gate 6): this script covers
# SQLite + config files ONLY. A deployment on the PostgreSQL substrate also
# needs a pg_dump AND the CA/keys directory captured on the same schedule —
# a Postgres restore without the paired keys dir cannot recover any
# envelope-encrypted secret.
echo ""
echo "WARNING: NOT included in this backup:"
echo "  * PostgreSQL database (use pg_dump --format=custom; see"
echo "    docs/user-manual/server-admin.md 'Backing up PostgreSQL state')"
echo "  * CA/keys directory (--ca-dir, default /etc/yuzu/certs) — pair it"
echo "    with every database backup (ADR-0010 restore-pairing invariant)"
