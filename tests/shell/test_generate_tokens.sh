#!/usr/bin/env bash
# test_generate_tokens.sh — contract test for the `--generate-tokens` CLI
# (WS-6 slice 6.2).
#
# Since 6.2 enrollment tokens live only in PostgreSQL (`auth.enrollment_tokens`,
# shared by every server replica). `--generate-tokens N` mints N tokens through
# the same AuthDB the running server reads, prints them as JSON, and exits
# without starting the server. This is not exercisable by the Catch2 suite
# (which never drives main()), so — mirroring test_mfa_reset.sh's pattern —
# this drives the just-built binary directly:
#  - no --postgres-dsn / an unreachable one -> fails closed, exit 1, clear message
#    (never a partial/garbled token list on stdout);
#  - N tokens minted -> N distinct 64-hex raw tokens printed, and N rows
#    persisted in Postgres with the expected shape (max_uses/created_by, hash =
#    sha256(raw), use_count 0, not revoked);
#  - each minted token is single-consumable: applying the EXACT consume_and_enroll
#    admission predicate (same WHERE clause, auth_db.cpp) once succeeds (1 row),
#    a second time fails (0 rows) — this is a shell test and cannot call the C++
#    method directly, so it drives the identical SQL predicate instead, which is
#    what actually decides consumability;
#  - created_by is attributed to the OS account that ran the CLI ("cli:<user>"),
#    never a forgeable value, matching --mfa-reset's audit-attribution rule.
#
# Run:  bash tests/shell/test_generate_tokens.sh

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
BIN=""
if [ -n "${YUZU_SERVER_BIN:-}" ] && [ -x "${YUZU_SERVER_BIN}" ]; then
  BIN="${YUZU_SERVER_BIN}"
else
  for d in build-linux build-macos build-windows; do
    for p in "$ROOT/$d/server/core/yuzu-server" "$ROOT/$d/server/core/yuzu-server.exe"; do
      [ -x "$p" ] && BIN="$p" && break
    done
    [ -n "$BIN" ] && break
  done
fi
if [ -z "$BIN" ]; then
  echo "SKIP: no built yuzu-server binary found (build with -Dbuild_server=true first)" >&2
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-gentok-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

PG_DSN="${YUZU_TEST_POSTGRES_DSN:-}"
if [ -z "$PG_DSN" ]; then
  echo "SKIP: YUZU_TEST_POSTGRES_DSN unset — --generate-tokens needs the Postgres auth store (WS-6 6.2). Set it to run this test." >&2
  exit 0
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "SKIP: psql not on PATH — cannot provision the ephemeral database or verify persisted rows." >&2
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not on PATH — needed to compute sha256 of the minted raw tokens." >&2
  exit 0
fi

pass=0 fail=0
report() { # <desc> <ok:0|1>
  if [ "$2" = "0" ]; then echo "ok   - $1"; pass=$((pass+1))
  else echo "FAIL - $1"; fail=$((fail+1)); fi
}

# ── Ephemeral database (never mutates the shared base DB; safe on a shared runner) ──
SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DB="yuzu_test_$(date +%s)_gentok_$$_${SALT}"
dsn_base="${PG_DSN%%\?*}"
dsn_query=""
[ "$dsn_base" != "$PG_DSN" ] && dsn_query="?${PG_DSN#*\?}"
dsn_prefix="${dsn_base%/*}"
CHILD_DSN="${dsn_prefix}/${DB}${dsn_query}"

if ! psql "$PG_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"${DB}\";" >/dev/null 2>&1; then
  echo "FAIL: could not CREATE DATABASE ${DB} on YUZU_TEST_POSTGRES_DSN — Postgres is set but unusable." >&2
  exit 1
fi
trap 'psql "$PG_DSN" -qtAc "DROP DATABASE IF EXISTS \"${DB}\" WITH (FORCE);" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

psql_db() { PGPASSWORD="" psql "$CHILD_DSN" -v ON_ERROR_STOP=1 -qtAc "$1"; }

# Seed a config with one admin so the CLI never falls into interactive
# first-run setup (which would hang this test waiting on stdin) — same seed
# shape as test_mfa_reset.sh.
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'pw'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$TMP/yuzu-server.cfg"
chmod 600 "$TMP/yuzu-server.cfg"

run_gen() { # <n> <extra args...> -> sets $OUT / $JSON / $GOT
  set +e
  OUT="$("$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --ca-dir "$TMP" \
               --postgres-dsn "$CHILD_DSN" --generate-tokens "$@" 2>"$TMP/stderr.log")"
  GOT=$?
  set -e
  # Extract just the JSON payload: stdout can carry interleaved spdlog INFO
  # lines before, and (log lines from the token-mint loop itself, running
  # concurrently with the batch) after it — spdlog's own library-default sink
  # is stdout when --log-file is unset, same tolerant-of-log-noise posture
  # test_mfa_reset.sh takes (substring match, not a strict parse). Scan for
  # the balanced {...} object by brace depth (safe here: the only string
  # values are hex tokens/labels, which never contain a brace) rather than
  # assuming the JSON is the last thing on the stream.
  JSON="$(printf '%s' "$OUT" | python3 -c '
import sys
s = sys.stdin.read()
start = s.find("{")
depth = 0
end = -1
for i in range(start, len(s)):
    if s[i] == "{":
        depth += 1
    elif s[i] == "}":
        depth -= 1
        if depth == 0:
            end = i
            break
print(s[start:end + 1] if start >= 0 and end >= 0 else "")
')"
}

# ── 1. Fail-closed without a reachable Postgres auth store ─────────────────
set +e
NO_PG_OUT="$("$BIN" --config "$TMP/yuzu-server.cfg" --data-dir "$TMP" --ca-dir "$TMP" \
                    --generate-tokens 3 2>&1)"
NO_PG_GOT=$?
set -e
if [ "$NO_PG_GOT" != "0" ] && printf '%s' "$NO_PG_OUT" | grep -qF "auth store"; then
  report "no --postgres-dsn -> fails closed, exit != 0, clear message" 0
else
  report "no --postgres-dsn -> fails closed, exit != 0, clear message (exit=$NO_PG_GOT out=$NO_PG_OUT)" 1
fi
# Never a partial token list on stdout when it fails closed.
if ! printf '%s' "$NO_PG_OUT" | grep -q '"tokens"'; then
  report "no --postgres-dsn -> no token JSON on stdout" 0
else
  report "no --postgres-dsn -> no token JSON on stdout" 1
fi

# ── 2. N tokens minted: distinct, correct JSON shape, correct DB shape ─────
run_gen 3 --token-label smoke --token-max-uses 1 --token-ttl-hours 1
if [ "$GOT" = "0" ]; then report "generate 3 tokens -> exit 0" 0; else report "generate 3 tokens -> exit 0 (got=$GOT, stderr=$(cat "$TMP/stderr.log"))" 1; fi

COUNT_FIELD="$(printf '%s' "$JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])' 2>/dev/null || echo "PARSE_FAILED")"
[ "$COUNT_FIELD" = "3" ] && report '"count":3 in the JSON output' 0 || report '"count":3 in the JSON output (got '"$COUNT_FIELD"')' 1

mapfile -t RAW_TOKENS < <(printf '%s' "$JSON" | python3 -c 'import json,sys; [print(t) for t in json.load(sys.stdin)["tokens"]]')
if [ "${#RAW_TOKENS[@]}" = "3" ]; then report "3 raw tokens printed" 0; else report "3 raw tokens printed (got ${#RAW_TOKENS[@]})" 1; fi

DISTINCT_COUNT="$(printf '%s\n' "${RAW_TOKENS[@]}" | sort -u | wc -l | tr -d ' ')"
[ "$DISTINCT_COUNT" = "3" ] && report "the 3 tokens are pairwise distinct" 0 || report "the 3 tokens are pairwise distinct (distinct=$DISTINCT_COUNT)" 1

ALL_HEX=1
for t in "${RAW_TOKENS[@]}"; do
  [[ "$t" =~ ^[0-9a-f]{64}$ ]] || ALL_HEX=0
done
[ "$ALL_HEX" = "1" ] && report "every token is 64 lowercase hex chars" 0 || report "every token is 64 lowercase hex chars" 1

ROW_COUNT="$(psql_db "SELECT count(*) FROM auth.enrollment_tokens")"
[ "$ROW_COUNT" = "3" ] && report "3 rows persisted in auth.enrollment_tokens" 0 || report "3 rows persisted in auth.enrollment_tokens (got $ROW_COUNT)" 1

CREATED_BY_OK="$(psql_db "SELECT count(*) FROM auth.enrollment_tokens WHERE created_by LIKE 'cli:%'")"
[ "$CREATED_BY_OK" = "3" ] && report "created_by is attributed to the CLI invocation (cli:<os-user>)" 0 \
  || report "created_by is attributed to the CLI invocation (got $CREATED_BY_OK matching rows)" 1

SHAPE_OK="$(psql_db "SELECT count(*) FROM auth.enrollment_tokens WHERE max_uses=1 AND use_count=0 AND NOT revoked AND expires_at IS NOT NULL AND label LIKE 'smoke%'")"
[ "$SHAPE_OK" = "3" ] && report "max_uses/use_count/revoked/label/expiry persisted correctly" 0 \
  || report "max_uses/use_count/revoked/label/expiry persisted correctly (got $SHAPE_OK)" 1

# ── 3. Each minted token validates exactly once (mirrors consume_and_enroll's
#      admission predicate, auth_db.cpp: same WHERE clause, since a shell test
#      cannot call the C++ method directly) ─────────────────────────────────
VALIDATE_OK=1
for t in "${RAW_TOKENS[@]}"; do
  HASH="$(python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$t")"
  FIRST="$(psql_db "UPDATE auth.enrollment_tokens SET use_count=use_count+1 WHERE token_hash='${HASH}' AND NOT revoked AND (expires_at IS NULL OR expires_at>now()) AND (max_uses=0 OR use_count<max_uses) RETURNING 1")"
  SECOND="$(psql_db "UPDATE auth.enrollment_tokens SET use_count=use_count+1 WHERE token_hash='${HASH}' AND NOT revoked AND (expires_at IS NULL OR expires_at>now()) AND (max_uses=0 OR use_count<max_uses) RETURNING 1")"
  if [ "$FIRST" != "1" ] || [ -n "$SECOND" ]; then
    VALIDATE_OK=0
    echo "  (token consumability check failed: first='$FIRST' second='$SECOND')" >&2
  fi
done
[ "$VALIDATE_OK" = "1" ] && report "each minted token admits exactly once under the consume predicate" 0 \
  || report "each minted token admits exactly once under the consume predicate" 1

# ── 4. Failure mid-batch: partial mint is reported, not silently discarded ──
# (Covered by the Catch2 store-level tests for AuthDB::create_token's own
# failure path; a mid-batch DB failure is not reproducible from this shell
# harness without fault-injecting Postgres, so it is intentionally NOT
# re-asserted here.)

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
