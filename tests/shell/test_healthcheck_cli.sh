#!/usr/bin/env bash
# test_healthcheck_cli.sh -- contract test for `yuzu-server --healthcheck` (#5906), driven
# through the REAL binary. The unit suite covers the probe's rules and transport; only this
# test proves the CLI wiring in main.cpp: the probe runs right after CLI parsing, before any
# server init, so it needs no config, no database and writes nothing.
#
# No listener, no Postgres: every probe targets a random unused port and must fail fast.
#   A  --no-https: rc 1, stdout empty, stderr exactly one `healthcheck: GET http://...` line
#      ending `(trust anchor: none)`, and nothing is written. With YUZU_POSTGRES_DSN unset a
#      probe that ran AFTER server init would die on the missing DSN or write a config file.
#   B  TLS branch: the same through the TLS path; the line names https:// and default-ca.pem.
#   C  option checks: a bad --healthcheck-path value, and --healthcheck-path alone, are refused.
#   D  YUZU_HEALTHCHECK=1 in the environment never turns the server into a probe: it does
#      not satisfy --healthcheck-path's dependency on --healthcheck (a wired envname would),
#      and --version, which CLI11 handles before any environment option, still wins.
#   E  environment-only target: the probe reads the server's own listener variables.
#   F  an existing, invalid --config file is neither read nor touched, and changes nothing
#      about the diagnostic.
#
# Run:  bash tests/shell/test_healthcheck_cli.sh <BUILDDIR>
set -euo pipefail

# An explicit YUZU_SERVER_BIN wins (CI); otherwise <BUILDDIR>/server/core/yuzu-server[.exe].
BIN="${YUZU_SERVER_BIN:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  BIN=""
  if [ $# -ge 1 ] && BUILDDIR="$(cd "$1" 2>/dev/null && pwd)"; then
    for p in "$BUILDDIR/server/core/yuzu-server" "$BUILDDIR/server/core/yuzu-server.exe"; do
      [ -x "$p" ] && BIN="$p" && break
    done
  fi
fi
[ -n "$BIN" ] || { echo "no built yuzu-server found (pass <BUILDDIR> or set YUZU_SERVER_BIN)" >&2; exit 2; }

# A stray YUZU_* variable would retarget the probe. Clear them all, then keep only what is
# under test. MSYS2 must not rewrite `/livez`-style arguments into Windows paths.
for v in $(compgen -e | grep '^YUZU_' || true); do unset "$v"; done
export MSYS2_ARG_CONV_EXCL='*'
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_hccli.XXXXXX")"  # state dirs the probe must not write to
CAP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_hccap.XXXXXX")"   # captured output
trap 'rm -rf "$WORK" "$CAP"' EXIT
mkdir -p "$WORK/cfg" "$WORK/data" "$WORK/empty"
STATE=(--config "$(winpath "$WORK/cfg")/yuzu-server.cfg" --data-dir "$(winpath "$WORK/data")")

fail=0
check() { # check <description> <condition-exit-status>
  if [ "$2" -eq 0 ]; then echo "ok   - $1"; else echo "FAIL - $1" >&2; fail=1; fi
}
# run <name> <args...>: capture rc/stdout/stderr under $CAP/<name>.*
run() {
  local name="$1"; shift
  set +e
  "$BIN" "$@" >"$CAP/$name.out" 2>"$CAP/$name.err" </dev/null
  echo $? >"$CAP/$name.rc"
  set -e
}
rc() { cat "$CAP/$1.rc"; }
same_bytes() { [ "$(od -An -tx1 -v "$1")" = "$(od -An -tx1 -v "$2")" ]; }

PORT=$((20000 + $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 40000))

# A: plain probe.
run a "${STATE[@]}" --healthcheck --no-https --web-address 127.0.0.1 --web-port "$PORT"
check "A rc is 1" "$([ "$(rc a)" = 1 ]; echo $?)"
check "A stdout is empty" "$([ ! -s "$CAP/a.out" ]; echo $?)"
check "A stderr is exactly one line" "$([ "$(wc -l <"$CAP/a.err" | tr -d ' ')" = 1 ]; echo $?)"
line="$(head -n1 "$CAP/a.err")"
check "A line names the target" \
  "$(case "$line" in "healthcheck: GET http://127.0.0.1:$PORT/readyz -> "*) true;; *) false;; esac; echo $?)"
check "A line ends with the anchor note" \
  "$(case "$line" in *"(trust anchor: none)") true;; *) false;; esac; echo $?)"
check "A wrote no files" "$([ -z "$(find "$WORK" -type f)" ]; echo $?)"

# B: TLS probe against an empty CA dir (no default-ca.pem there).
run b "${STATE[@]}" --healthcheck --web-address 127.0.0.1 --https-port "$PORT" \
  --ca-dir "$(winpath "$WORK/empty")"
check "B rc is 1" "$([ "$(rc b)" = 1 ]; echo $?)"
check "B names https and the anchor file" \
  "$(grep -q 'https://' "$CAP/b.err" && grep -q 'default-ca.pem' "$CAP/b.err"; echo $?)"
check "B wrote no files" "$([ -z "$(find "$WORK" -type f)" ]; echo $?)"

# C: option validation.
run c1 --healthcheck --healthcheck-path /bogus
check "C bad path is refused and named" \
  "$([ "$(rc c1)" != 0 ] && grep -q -e '--healthcheck-path' "$CAP/c1.err"; echo $?)"
run c2 --healthcheck-path /livez
check "C --healthcheck-path alone is refused" \
  "$([ "$(rc c2)" != 0 ] && grep -Eq -e '--healthcheck-path.*--healthcheck([^-]|$)' "$CAP/c2.err"; echo $?)"

# D: the environment variable is not an option. --healthcheck-path alone (target pinned to a
# closed port so a wired envname could only probe, never reach a real server) must still be
# refused: --version alone cannot show that, CLI11 handles it before any environment option.
export YUZU_HEALTHCHECK=1
run d1 --healthcheck-path /livez --no-https --web-address 127.0.0.1 --web-port "$PORT"
run d --version
unset YUZU_HEALTHCHECK
check "D --healthcheck-path alone is still refused" \
  "$([ "$(rc d1)" != 0 ] && grep -Eq -e '--healthcheck-path.*--healthcheck([^-]|$)' "$CAP/d1.err"; echo $?)"
check "D no probe ran" "$(! grep -q 'healthcheck:' "$CAP/d1.out" "$CAP/d1.err"; echo $?)"
check "D --version still prints the version" "$([ "$(rc d)" = 0 ] && [ -s "$CAP/d.out" ]; echo $?)"
check "D --version ran no probe" "$(! grep -q 'healthcheck:' "$CAP/d.out" "$CAP/d.err"; echo $?)"

# E: the target comes from the server's own environment variables when no flag names it.
export YUZU_NO_HTTPS=1 YUZU_WEB_ADDRESS=127.0.0.1 YUZU_WEB_PORT="$PORT"
run e "${STATE[@]}" --healthcheck
unset YUZU_NO_HTTPS YUZU_WEB_ADDRESS YUZU_WEB_PORT
line="$(head -n1 "$CAP/e.err")"
check "E rc is 1" "$([ "$(rc e)" = 1 ]; echo $?)"
check "E line names the environment target" \
  "$(case "$line" in "healthcheck: GET http://127.0.0.1:$PORT/readyz -> "*) true;; *) false;; esac; echo $?)"
check "E line ends with the anchor note" \
  "$(case "$line" in *"(trust anchor: none)") true;; *) false;; esac; echo $?)"

# F: an invalid config file sits outside $WORK (which A/B check for stray writes). A probe that
# loaded it would log to stdout (Unsupported version) and, on first-run setup, rewrite it.
BADCFG="$CAP/invalid-yuzu-server.cfg"
printf '# Version: 99\n\377\376garbage\n' >"$BADCFG"
cp "$BADCFG" "$CAP/invalid-yuzu-server.orig"
run f --config "$(winpath "$BADCFG")" --data-dir "$(winpath "$WORK/data")" \
  --healthcheck --no-https --web-address 127.0.0.1 --web-port "$PORT"
check "F rc is 1" "$([ "$(rc f)" = 1 ]; echo $?)"
check "F stdout is empty" "$([ ! -s "$CAP/f.out" ]; echo $?)"
check "F diagnostic is identical to A's" "$(same_bytes "$CAP/f.err" "$CAP/a.err"; echo $?)"
check "F config file is byte-identical" "$(same_bytes "$BADCFG" "$CAP/invalid-yuzu-server.orig"; echo $?)"
check "F wrote no files" "$([ -z "$(find "$WORK" -type f)" ]; echo $?)"

exit "$fail"
