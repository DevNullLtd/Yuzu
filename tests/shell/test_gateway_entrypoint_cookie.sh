#!/usr/bin/env bash
# test_gateway_entrypoint_cookie.sh -- contract test for the gateway container
# entrypoint's distribution-cookie decision (F24). The check must refuse BEFORE the
# BEAM is exec'd (the in-VM guard runs after distribution is listening).
#
#   A  YUZU_GW_COOKIE unset                          -> exit 1, VM never started
#   B  the published default value                   -> exit 1, VM never started
#   C  an unsubstituted ${...} placeholder           -> exit 1, VM never started
#   D  unset + YUZU_GW_ALLOW_DEFAULT_COOKIE=1        -> VM started with a random 64-hex cookie
#                                                       (never the default, never logged)
#   E  a strong cookie                               -> VM started with that exact cookie
#   F  loopback advertise address                    -> epmd/dist pinned to 127.0.0.1
#   G  routable advertise address                    -> not pinned
set -u
here="$(cd "$(dirname "$0")" && pwd)"
entry="$here/../../deploy/docker/gateway-entrypoint.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gw_entry.XXXXXX")"
trap 'rm -rf "$work"' EXIT
stub="$work/yuzu_gw"
cat > "$stub" <<'STUB'
#!/bin/sh
printf 'STARTED cookie=%s epmd=%s aflags=%s\n' "${YUZU_GW_COOKIE:-}" "${ERL_EPMD_ADDRESS:-}" "${ERL_AFLAGS:-}"
STUB
chmod +x "$stub"
sed "s#/opt/yuzu_gw/bin/yuzu_gw#$stub#" "$entry" > "$work/entry.sh"
chmod +x "$work/entry.sh"

fail=0
check() { if [ "$2" = ok ]; then echo "PASS $1"; else echo "FAIL $1: $3"; fail=1; fi; }

run() { # env assignments as args
    env -i PATH="$PATH" YUZU_GW_ADVERTISE_ADDR="${ADDR:-127.0.0.1}" "$@" sh "$work/entry.sh" 2>"$work/err"
}

out="$(run)"; rc=$?
{ [ $rc -ne 0 ] && [ -z "$out" ]; } && check A ok || check A bad "rc=$rc out=$out"
out="$(run YUZU_GW_COOKIE=yuzu_gw_secret_change_me)"; rc=$?
{ [ $rc -ne 0 ] && [ -z "$out" ]; } && check B ok || check B bad "rc=$rc out=$out"
out="$(run 'YUZU_GW_COOKIE=${YUZU_GW_COOKIE:-yuzu_gw_x}')"; rc=$?
{ [ $rc -ne 0 ] && [ -z "$out" ]; } && check C ok || check C bad "rc=$rc out=$out"

out="$(run YUZU_GW_ALLOW_DEFAULT_COOKIE=1)"; rc=$?
c="$(printf '%s' "$out" | sed -n 's/^STARTED cookie=\([^ ]*\) .*/\1/p')"
if [ $rc -eq 0 ] && printf '%s' "$c" | grep -Eq '^[0-9a-f]{64}$' && ! grep -q "$c" "$work/err"; then
    check D ok; else check D bad "rc=$rc cookie=$c"; fi

strong="$(printf 'k%.0s' $(seq 40))"
out="$(run YUZU_GW_COOKIE="$strong")"; rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | grep -q "cookie=$strong " && check E ok || check E bad "rc=$rc"

out="$(run YUZU_GW_COOKIE="$strong")"
printf '%s' "$out" | grep -q "epmd=127.0.0.1" && printf '%s' "$out" | grep -q "inet_dist_use_interface" \
    && check F ok || check F bad "$out"
out="$(ADDR=10.1.2.3 run YUZU_GW_COOKIE="$strong")"
printf '%s' "$out" | grep -q "epmd= aflags=$" && check G ok || check G bad "$out"

exit $fail
