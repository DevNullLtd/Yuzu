#!/usr/bin/env bash
# test_gateway_peer_registration_lexical.sh -- static LEXICAL gate over server/core/src/server.cpp.
#
# The guard (GatewayPeerGuardedService) is the only registration of the gateway-upstream service
# on the production builder. The unit tests exercise the guard directly and nothing constructs
# ServerImpl, so this gate pins the registration site. Invariants, over the file with comments
# stripped and whitespace collapsed:
#
#   1. exactly ONE `RegisterService(gateway_peer_guard_.get())`;
#   2. NO `RegisterService(` whose argument names `gateway_service_` (any spelling of address-of,
#      get(), or a cast);
#   3. the complete set of registered services is exactly {&agent_service_, &mgmt_service_,
#      gateway_peer_guard_.get()}: a fourth RegisterService is a deliberate edit of this gate,
#      so a new service cannot be added to the builder without review.
#
# LEXICAL ONLY. It cannot see a registration reached through an alias, a helper or a different
# builder object, and it does not look for the generic-service registration APIs
# (`RegisterAsyncGenericService`, `experimental().RegisterCallbackGenericService`), which would
# route by method name without naming a generated service. It pins the one site that exists
# today; a change that introduces any of those needs its own review. The behavioural guarantee is
# the guard's own tests (tests/unit/server/test_gateway_peer_guard.cpp) and the descriptor sweep
# there.
#
# Portability: POSIX ERE, no bound over 255, grep rc>=2 is a loud gate error and never reads as
# "no match", perl (not sed -i) for the self-test mutations. bash 3.2 compatible.
#
# Usage: test_gateway_peer_registration_lexical.sh [--self-test-only] ; SERVER_CPP=<path> overrides.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SERVER_CPP="${SERVER_CPP:-$ROOT/server/core/src/server.cpp}"
TAG="test_gateway_peer_registration_lexical"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gwpeer_lexical.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' HUP INT TERM

# count_re TEXT REGEX : number of matches; a grep error (rc>=2) exits the gate loudly.
count_re() {
  local out rc
  out="$(grep -oE -- "$2" <<<"$1" 2>"$WORK/err")"; rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "::error::$TAG: grep regex error (rc=$rc) for pattern: $2 ($(cat "$WORK/err"))" >&2
    exit 3
  fi
  if [ -z "$out" ]; then echo 0; else printf '%s\n' "$out" | wc -l | tr -d ' '; fi
}

normalise() { sed 's,//.*$,,' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' '; }

HINT=" (this gate pins the gateway-upstream registration; if server.cpp was legitimately restructured, update tests/shell/test_gateway_peer_registration_lexical.sh)"

check() {
  local f="$1" t rc=0 n
  [ -f "$f" ] || { echo "::error::$TAG: $f not found" >&2; return 1; }
  t="$(normalise "$f")"

  n="$(count_re "$t" 'RegisterService\( ?gateway_peer_guard_\.get\(\) ?\)')"
  if [ "$n" -ne 1 ]; then
    echo "::error::$TAG: expected exactly one RegisterService(gateway_peer_guard_.get()), found $n$HINT" >&2; rc=1
  fi
  n="$(count_re "$t" 'RegisterService\([^)]*gateway_service_')"
  if [ "$n" -ne 0 ]; then
    echo "::error::$TAG: $n RegisterService call(s) name gateway_service_: the inner gateway-upstream handler must never be registered directly$HINT" >&2; rc=1
  fi
  n="$(count_re "$t" 'RegisterService\(')"
  if [ "$n" -ne 3 ]; then
    echo "::error::$TAG: expected exactly 3 RegisterService calls (agent, management, guarded gateway-upstream), found $n: a new service needs a deliberate edit of this gate$HINT" >&2; rc=1
  fi
  n="$(count_re "$t" 'RegisterService\( ?&agent_service_ ?\)')"
  [ "$n" -eq 1 ] || { echo "::error::$TAG: RegisterService(&agent_service_) not found exactly once ($n)$HINT" >&2; rc=1; }
  n="$(count_re "$t" 'RegisterService\( ?&mgmt_service_ ?\)')"
  [ "$n" -eq 1 ] || { echo "::error::$TAG: RegisterService(&mgmt_service_) not found exactly once ($n)$HINT" >&2; rc=1; }
  return $rc
}

selftest() {
  local rc=0 i=0 m
  local -a muts=(
    # the guard replaced by the inner handler
    's/RegisterService\(gateway_peer_guard_\.get\(\)\)/RegisterService(gateway_service_.get())/'
    # the inner handler registered in addition to the guard
    's/(builder\.RegisterService\(gateway_peer_guard_\.get\(\)\);)/$1 builder.RegisterService(gateway_service_.get());/'
    # the guard registration deleted
    's/builder\.RegisterService\(gateway_peer_guard_\.get\(\)\);//'
    # a fourth, unreviewed service
    's/(builder\.RegisterService\(&mgmt_service_\);)/$1 builder.RegisterService(&other_service_);/'
  )
  for m in "${muts[@]}"; do
    i=$((i + 1))
    if ! perl -0pe "$m" "$SERVER_CPP" > "$WORK/server_$i.cpp" 2>"$WORK/perl_err"; then
      echo "::error::$TAG: selftest mutation $i: perl failed: $(cat "$WORK/perl_err")" >&2; rc=1; continue
    fi
    if [ "$(cat "$SERVER_CPP")" = "$(cat "$WORK/server_$i.cpp")" ]; then
      echo "::error::$TAG: selftest mutation $i changed nothing (stale pattern): $m" >&2; rc=1; continue
    fi
    if check "$WORK/server_$i.cpp" >/dev/null 2>&1; then
      echo "::error::$TAG: selftest mutation $i was NOT detected by the gate: $m" >&2; rc=1
    else
      echo "selftest mutation $i: gate FAILED as required (RED)"
    fi
  done
  return $rc
}

if [ "${1:-}" != "--self-test-only" ]; then
  check "$SERVER_CPP" || { echo "$TAG: FAIL" >&2; exit 1; }
fi
selftest || { echo "$TAG: SELFTEST FAIL" >&2; exit 1; }
echo "$TAG: OK -- the gateway-upstream service is registered only through the guard; negative controls all RED"
