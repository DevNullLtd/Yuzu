#!/usr/bin/env bash
# sweep-test-databases.sh — weekly janitor for leaked yuzu_test_* databases
# on the persistent self-hosted Postgres instances (#1367).
#
# The in-process sweeper (tests/unit/test_helpers.hpp, PR #2091) already
# reclaims epoch-named leaks at every server-suite start, but it only runs
# when a [pg] leg actually executes on the box, and it can never reclaim
# names whose epoch fails to parse (pre-epoch format yuzu_test_<salt>_<n>)
# or is implausible (skewed stamper clocks — #2097 CH-6). This script closes
# both gaps from .github/workflows/cache-prune.yml (Sundays 04:00 UTC):
#
#   Pass A — epoch-named databases, same rules as the in-process sweeper
#     (parse the name-embedded epoch, plausibility window 2020-09..now+24h,
#     age > --epoch-hours against the PG SERVER clock, DROP WITH (FORCE)).
#   Pass B — names pass A can never age (unparseable/implausible epoch):
#     age from a catalog fact instead — pg_stat_file() mtime of the datdir's
#     PG_VERSION (written at CREATE DATABASE, never rewritten) — with a long
#     --orphan-days threshold AND zero active backends, dropped WITHOUT
#     force so a racing connection vetoes the drop. #2091 deliberately
#     rejected zero-backends as a liveness signal for fast sweeps (a live
#     fixture is momentarily connection-free between drop and re-create);
#     at a 7-day threshold on a weekly cron it is belt-and-braces, not the
#     liveness test. Superuser-only (pg_stat_file) — gated, skips politely.
#
# Instance discovery (both modes may apply on one box; sweeps are idempotent):
#   docker — every RUNNING container matching ^yuzu-ci-postgres(-[0-9]+)?$
#     (the legacy shared container and #2114's per-agent ones). psql runs
#     inside the container as -U yuzu: POSTGRES_USER=yuzu makes yuzu the
#     bootstrap superuser; these containers have no 'postgres' role.
#   dsn — YUZU_TEST_POSTGRES_DSN set (Wee Tam machine env): probe the DSN's
#     port + the next --agents-1 ports (#2114 per-agent clusters); a dead
#     base port warns, dead higher ports are the normal pre-cutover state
#     and skip silently. Falls back to the docs/ci-architecture.md
#     conventional native cluster on 127.0.0.1:5432 when no DSN is set.
#
# Failure contract (SRE gate 6): per-instance failures never stop the loop —
# every remaining instance is still swept — but the script exits 1 at the end
# when any instance failed, a pass query errored, or a precondition was
# degraded (psql missing with a DB present), so the weekly run goes red as
# the alert channel instead of degradation hiding in an unread cron log.
# A box with genuinely nothing to sweep stays green. Usage errors exit 2.
# Never touches a database whose name doesn't both start with yuzu_test_ and
# match ^[a-z0-9_]+$ (names are spliced into DROP statements — same charset
# guard as the C++ sweeper).
#
# Accepted trade-off (governance 2026-07-13): the DSN — password included —
# is passed to psql as argv, briefly readable via /proc/*/cmdline by
# co-tenant processes. It crosses no new trust boundary on these boxes: the
# same DSN already sits in a machine-level env var readable under the shared
# runner identity (#1883 topology).
set -euo pipefail

# System32 precedes /usr/bin on the Wee Tam runners' PATH (the same fact
# that forces ci.yml's `source`-not-`bash` idiom), so bare `find`, `sort`
# and `timeout` resolve to the Windows binaries and every psql call dies
# quietly under the fail-soft contract. Prepend /usr/bin so coreutils win.
# $OSTYPE is a bash builtin — unlike uname it needs no PATH to be sane yet.
case "${OSTYPE:-}" in msys*|cygwin*) PATH="/usr/bin:$PATH" ;; esac

# No filename globbing is ever intended; keeps a hostile '*' datname (which
# the charset guards reject anyway) from expanding against the CWD.
set -f

DRY_RUN=0
AGENTS=4          # runner agents per box (CLAUDE.md standing invariant)
EPOCH_HOURS=6     # pass A staleness — keep aligned with kTestDbStaleAfterSeconds
ORPHAN_DAYS=7     # pass B staleness (catalog-fact age for unparseable names)

usage() {
  echo "usage: $0 [--dry-run] [--agents N] [--epoch-hours N] [--orphan-days N]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --agents|--epoch-hours|--orphan-days)
      [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || usage
      case "$1" in
        --agents) AGENTS="$2" ;;
        --epoch-hours) EPOCH_HOURS="$2" ;;
        --orphan-days) ORPHAN_DAYS="$2" ;;
      esac
      shift ;;
    *) usage ;;
  esac
  shift
done

export PGCONNECT_TIMEOUT=10
STALE_SECONDS=$((EPOCH_HOURS * 3600))

# ── SQL (server-side age math: "now" is the PG server clock, matching the
#    in-process sweeper — on the per-box CI topology the server clock IS the
#    stamper clock, collapsing stamper-vs-sweeper skew) ─────────────────────
# Epoch parse mirrors parse_test_db_epoch(): optional tpl_ infix, a 1..12
# digit run (13+ overflows in C++ and fails the bounded regex here), then
# '_' — with an EMPTY tail allowed, exactly like the C++ parser (its
# i == rest.size() check rejects a name with no separator at all, not one
# ending in '_'). Plausibility mirrors test_db_epoch_plausible().
EPOCH_RE='^yuzu_test_(tpl_)?[0-9]{1,12}_'
EPOCH_CAP='^yuzu_test_(?:tpl_)?([0-9]{1,12})_'
PLAUSIBLE="(regexp_match(datname, '${EPOCH_CAP}'))[1]::bigint
             BETWEEN 1600000000 AND extract(epoch FROM now())::bigint + 86400"

SQL_COUNT="SELECT count(*) FROM pg_database WHERE datname LIKE 'yuzu\_test\_%'"

SQL_PASS_A="SELECT datname FROM pg_database
 WHERE datname LIKE 'yuzu\_test\_%'
   AND datname ~ '^[a-z0-9_]+\$'
   AND datname ~ '${EPOCH_RE}'
   AND ${PLAUSIBLE}
   AND extract(epoch FROM now())::bigint
         - (regexp_match(datname, '${EPOCH_CAP}'))[1]::bigint > ${STALE_SECONDS}
 ORDER BY datname"

SQL_PASS_B="SELECT datname FROM pg_database
 WHERE datname LIKE 'yuzu\_test\_%'
   AND datname ~ '^[a-z0-9_]+\$'
   AND NOT (datname ~ '${EPOCH_RE}' AND ${PLAUSIBLE})
   AND (pg_stat_file('base/' || oid || '/PG_VERSION', true)).modification
         < now() - interval '${ORPHAN_DAYS} days'
   AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datid = pg_database.oid)
 ORDER BY datname"

# Names neither pass can ever reclaim (bad charset, or unparseable epoch
# still younger than the pass-B threshold shows up here until it ages).
SQL_UNSWEEPABLE="SELECT count(*) FROM pg_database
 WHERE datname LIKE 'yuzu\_test\_%'
   AND NOT (datname ~ '^[a-z0-9_]+\$' AND datname ~ '${EPOCH_RE}' AND ${PLAUSIBLE})"

SQL_IS_SUPER="SELECT rolsuper FROM pg_roles WHERE rolname = current_user"

# ── runners: same psql contract, two transports (invoked indirectly via
#    the $runner argument of sweep_instance/drop_listed) ────────────────────
# shellcheck disable=SC2329
run_psql_docker() { # container sql
  timeout 60 docker exec "$1" psql -X -tA -v ON_ERROR_STOP=1 -U yuzu -d postgres -c "$2"
}

PSQL=""
find_psql() {
  if command -v psql >/dev/null 2>&1; then
    PSQL="psql"
    return 0
  fi
  # Wee Tam runner services don't put the PG bin dir on PATH; take the
  # newest installed major (MSYS2 view of C:\Program Files\PostgreSQL).
  local candidate
  candidate=$(find "/c/Program Files/PostgreSQL" -maxdepth 3 -path '*/bin/psql.exe' 2>/dev/null | sort -V | tail -1 || true)
  if [[ -n "$candidate" ]]; then
    PSQL="$candidate"
    return 0
  fi
  return 1
}

# shellcheck disable=SC2329
run_psql_dsn() { # dsn sql
  timeout 60 "$PSQL" "$1" -X -tA -v ON_ERROR_STOP=1 -c "$2"
}

tcp_probe() { # host port — pure-bash, works in MSYS2 too (ensure-postgres.sh idiom)
  (exec 3<>"/dev/tcp/$1/$2") >/dev/null 2>&1
}

note_summary() { # line — job log always, step summary when under Actions
  echo "$1"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "- $1" >> "$GITHUB_STEP_SUMMARY" || true
  fi
}

# ── the sweep itself ──────────────────────────────────────────────────────
drop_listed() { # runner conn label force names... -> echoes dropped count
  local runner="$1" conn="$2" label="$3" force="$4" dropped=0 db stmt
  shift 4
  for db in "$@"; do
    # Defense in depth: re-guard in bash what SQL already filtered — these
    # names are spliced into a DROP statement.
    if [[ "$db" != yuzu_test_* || ! "$db" =~ ^[a-z0-9_]+$ ]]; then
      echo "::warning::sweep: refusing suspicious name on ${label}: ${db}" >&2
      continue
    fi
    if [[ "$force" == force ]]; then
      stmt="DROP DATABASE IF EXISTS \"${db}\" WITH (FORCE)"
    else
      stmt="DROP DATABASE IF EXISTS \"${db}\""
    fi
    if (( DRY_RUN )); then
      echo "sweep[dry-run] ${label}: would run: ${stmt}" >&2
      continue
    fi
    local err=""
    if err=$("$runner" "$conn" "$stmt" 2>&1 >/dev/null); then
      dropped=$((dropped + 1))
      echo "sweep ${label}: dropped ${db}" >&2
    else
      # Pass B lands here when a connection raced in (no FORCE): correct veto.
      echo "sweep ${label}: drop of ${db} failed — left in place (${err})" >&2
    fi
  done
  echo "$dropped"
}

sweep_instance() { # label runner conn
  local label="$1" runner="$2" conn="$3"
  local total stale orphan unsweepable is_super dropped_a=0 dropped_b=0

  total=$("$runner" "$conn" "$SQL_COUNT") || {
    echo "::warning::sweep-test-databases: ${label}: not reachable/queryable — skipped" >&2
    return 1
  }

  # A failing pass query must not masquerade as "dropped 0" (UP-15/CH-10):
  # warn per pass and mark the instance failed so the run exits red.
  local pass_failed=0
  if stale=$("$runner" "$conn" "$SQL_PASS_A"); then :; else
    echo "::warning::sweep: ${label}: pass-A (epoch) query failed — epoch-named leaks are NOT being swept" >&2
    stale="" pass_failed=1
  fi
  if [[ -n "$stale" ]]; then
    # Unquoted on purpose: datnames are single tokens by the charset guard.
    # shellcheck disable=SC2086
    dropped_a=$(drop_listed "$runner" "$conn" "$label" force $stale)
  fi

  is_super=$("$runner" "$conn" "$SQL_IS_SUPER") || is_super="f"
  if [[ "$is_super" == "t" ]]; then
    if orphan=$("$runner" "$conn" "$SQL_PASS_B"); then :; else
      echo "::warning::sweep: ${label}: pass-B (catalog-fact) query failed — orphaned names are NOT being swept" >&2
      orphan="" pass_failed=1
    fi
    if [[ -n "$orphan" ]]; then
      # shellcheck disable=SC2086
      dropped_b=$(drop_listed "$runner" "$conn" "$label" noforce $orphan)
    fi
  else
    echo "::notice::sweep: ${label}: catalog-fact pass skipped (needs superuser for pg_stat_file)" >&2
  fi

  unsweepable=$("$runner" "$conn" "$SQL_UNSWEEPABLE") || unsweepable="?"
  note_summary "sweep ${label}: saw ${total} yuzu_test_* database(s), dropped ${dropped_a} stale-by-epoch (>${EPOCH_HOURS}h), dropped ${dropped_b} orphaned (>${ORPHAN_DAYS}d + zero backends), ${unsweepable} unsweepable-by-epoch remain"
  if [[ "$unsweepable" =~ ^[0-9]+$ ]] && (( unsweepable > 50 )); then
    # Parity with the in-process sweeper's accumulation warning.
    echo "::warning::sweep: ${label}: ${unsweepable} yuzu_test_* databases have unparseable/implausible epochs — pass B reclaims them at >${ORPHAN_DAYS}d, but a skewed stamper clock is feeding new ones (see #2097)" >&2
  fi
  return "$pass_failed"
}

swept_any=0
SWEEP_RC=0   # flips to 1 on any instance/pass failure or degraded precondition

# docker mode (Big Tam / any docker-hosting Linux runner)
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  containers=$(docker ps --format '{{.Names}}' | grep -E '^yuzu-ci-postgres(-[0-9]+)?$' || true)
  for c in $containers; do
    swept_any=1
    sweep_instance "docker:${c}" run_psql_docker "$c" \
      || { echo "::warning::sweep-test-databases: docker:${c} sweep failed — continuing" >&2; SWEEP_RC=1; }
  done
fi

# dsn mode (Wee Tam machine env; per-agent ports post-#2114)
degraded=0   # a precondition warning already names the real problem — don't
             # also print the misleading generic "no instances" notice

if [[ -n "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
  if ! find_psql; then
    echo "::warning::sweep-test-databases: YUZU_TEST_POSTGRES_DSN is set but no psql found — DSN sweep skipped" >&2
    degraded=1
  else
    dsn="$YUZU_TEST_POSTGRES_DSN"
    host="127.0.0.1"   # default when the DSN names no host
    if [[ "$dsn" =~ ^(postgres(ql)?://([^/?@]*@)?([^:/?]+))(:([0-9]+))?(/[^?]*)?(\?.*)?$ ]]; then
      # URI form (port optional — defaults to 5432): rewrite port and
      # database per probed instance; probe the DSN's own host, not a
      # hardcoded loopback.
      base="${BASH_REMATCH[1]}" host="${BASH_REMATCH[4]}"
      port="${BASH_REMATCH[6]:-5432}" query="${BASH_REMATCH[8]}"
      mkconn() { echo "${base}:$1/postgres${query}"; }
    else
      # Keyword form: later keywords win in libpq conninfo strings. The
      # key matches are anchored to start-of-string/whitespace so a value
      # embedding "port="/"host=" (e.g. inside options='...') can't spoof
      # the top-level keyword.
      port=5432
      if [[ "$dsn" =~ (^|[[:space:]])port=([0-9]+) ]]; then port="${BASH_REMATCH[2]}"; fi
      if [[ "$dsn" =~ (^|[[:space:]])host=([^[:space:]]+) ]]; then host="${BASH_REMATCH[2]}"; fi
      mkconn() { echo "${dsn} port=$1 dbname=postgres"; }
    fi
    for ((n = 0; n < AGENTS; n++)); do
      p=$((port + n))
      if ! tcp_probe "$host" "$p"; then
        if (( n == 0 )); then
          echo "::warning::sweep-test-databases: DSN base port ${p} not answering — is the cluster down?" >&2
          SWEEP_RC=1   # a box WITH a DSN whose cluster is dark is degradation
        fi
        continue  # higher ports dark = normal pre-#2114-cutover state
      fi
      swept_any=1
      sweep_instance "dsn:${host}:${p}" run_psql_dsn "$(mkconn "$p")" \
        || { echo "::warning::sweep-test-databases: dsn:${host}:${p} sweep failed — continuing" >&2; SWEEP_RC=1; }
    done
  fi
elif (( ! swept_any )) && tcp_probe 127.0.0.1 5432; then
  # Conventional native cluster (ensure-postgres.sh path 4) on a box with
  # neither docker nor a machine DSN.
  if find_psql; then
    swept_any=1
    sweep_instance "native:127.0.0.1:5432" run_psql_dsn "postgresql://yuzu:yuzu@127.0.0.1:5432/postgres" \
      || { echo "::warning::sweep-test-databases: native:5432 sweep failed — continuing" >&2; SWEEP_RC=1; }
  else
    # A listener we can see but no client to sweep it with is a precondition
    # failure worth signalling, not a quiet "no instances".
    echo "::warning::sweep-test-databases: something listens on 127.0.0.1:5432 but no psql was found — native sweep skipped" >&2
    degraded=1
  fi
fi

if (( ! swept_any && ! degraded )); then
  echo "::notice::sweep-test-databases: no Postgres instances to sweep on this host"
fi
if (( degraded )); then SWEEP_RC=1; fi
# Red weekly run = the alert channel for sweep degradation (SRE gate 6);
# a box with genuinely nothing to sweep exits 0.
exit "$SWEEP_RC"
