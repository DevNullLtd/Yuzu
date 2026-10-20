#!/usr/bin/env bash
# test_uat_netns.sh — scripts/uat-netns.sh argument contract, and (where the host
# allows unprivileged user namespaces) the property the wrapper exists for: two
# namespaces bind the SAME loopback port at the same time. Nothing here needs
# Docker or Postgres: every rejection below happens before the wrapper touches
# either, and the isolation check calls bwrap directly with the wrapper's flags.
#
# Run:  bash tests/shell/test_uat_netns.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
WRAP="$ROOT/scripts/uat-netns.sh"
[ -f "$WRAP" ] || { echo "missing $WRAP" >&2; exit 2; }

pass=0 fail=0
check() { if [ "$2" = 0 ]; then printf '  [pass] %s\n' "$1"; pass=$((pass + 1)); else printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); fi; }
run() { set +e; out=$(bash "$WRAP" "$@" 2>&1); rc=$?; set -e; }

echo "argument contract"
run run
check "run with no rig is a usage error" "$([ $rc != 0 ] && [[ $out == *usage* ]] && echo 0 || echo 1)"
for bad in 'A' '1a' 'a-b' 'a;drop' 'a b' 'abcdefghijklmnopqrstuvwxyz'; do
  run run "$bad" -- true
  check "rig name '$bad' rejected (it becomes a database name)" "$([ $rc != 0 ] && [[ $out == *'rig name must match'* ]] && echo 0 || echo 1)"
done
run run a true
check "missing -- separator rejected" "$([ $rc != 0 ] && [[ $out == *usage* ]] && echo 0 || echo 1)"
run run a --
check "empty command after -- rejected" "$([ $rc != 0 ] && [[ $out == *'no command'* ]] && echo 0 || echo 1)"
run bogus
check "unknown subcommand rejected" "$([ $rc != 0 ] && [[ $out == *'unknown subcommand'* ]] && echo 0 || echo 1)"
run --help
check "--help prints the header and exits 0" "$([ $rc = 0 ] && [[ $out == *'private network'* ]] && echo 0 || echo 1)"

echo "lexical wiring"
cnt() { grep -cF -- "$1" "$WRAP" || true; }
check "exactly the flags the isolation relies on" "$([ "$(cnt '--unshare-net --unshare-pid --die-with-parent')" = 1 ] && echo 0 || echo 1)"
check "private /tmp/yuzu-uat tmpfs" "$([ "$(cnt '--tmpfs /tmp/yuzu-uat')" = 1 ] && echo 0 || echo 1)"
check "postgres container publishes no port" "$(! grep -qE 'docker run.*(-p |--publish)' "$WRAP" && echo 0 || echo 1)"
check "state dir is created 0700" "$([ "$(cnt 'mkdir -p -m 700 "$STATE"')" = 1 ] && echo 0 || echo 1)"

echo "isolation (needs unprivileged user namespaces)"
if command -v bwrap >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
   && bwrap --unshare-net --unshare-pid --dev-bind / / true 2>/dev/null; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_netns.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  cat > "$tmp/bind.py" <<'PY'
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 8080)); s.listen(1)
open(sys.argv[1], "w").write("bound")
time.sleep(float(sys.argv[2]))
PY
  listeners() { { ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null; } | grep -c ':8080 ' || true; }
  before=$(listeners)
  for r in a b; do
    bwrap --dev-bind / / --proc /proc --unshare-net --unshare-pid --die-with-parent \
      python3 "$tmp/bind.py" "$tmp/$r.ok" 6 2> "$tmp/$r.err" &
  done
  for _ in $(seq 1 40); do [ -e "$tmp/a.ok" ] && [ -e "$tmp/b.ok" ] && break; sleep 0.25; done
  check "two namespaces bound 127.0.0.1:8080 at the same time" "$([ -e "$tmp/a.ok" ] && [ -e "$tmp/b.ok" ] && echo 0 || echo 1)"
  check "the host's :8080 listener count did not change" "$([ "$(listeners)" = "$before" ] && echo 0 || echo 1)"
  wait
else
  printf '  [skip] isolation case (bwrap missing or unprivileged user namespaces unavailable)\n'
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
