#!/usr/bin/env bash
# test_gateway_entrypoint_cookie.sh -- contract test for the gateway distribution-cookie
# policy (F24 of the 2026-11-17 security scan), run through the REAL container entrypoint
# and the REAL systemd ExecStartPre string, under every POSIX shell available (bash, dash,
# busybox sh: the runtime image is Alpine/busybox, the packaged unit uses /bin/sh).
#
# The policy must refuse BEFORE the BEAM is exec'd (the in-VM guard runs after distribution
# is listening) and the refusal must say why and how to fix it (asserted by message).
#
#   A  unset                              -> refused, "is unset, empty or the published default"
#   B  exactly the published default      -> refused, same message
#   C  a ${...} placeholder               -> refused, "outside the allowed"
#   S  short (<32)                        -> refused, "shorter than 32"
#   W  space / CRLF / backslash / `\&`    -> refused, "outside the allowed" (busybox awk drops a
#                                            backslash that mawk keeps, so replicas would
#                                            disagree; relx's replace_os_vars awk loops forever
#                                            at 100% CPU on `\&`)
#   L  leading - or +                     -> refused (would be read as a VM flag)
#   P  published literal INSIDE a longer cookie, no override -> refused, "contains the published"
#   D  unset + ALLOW=1                    -> started with a random 64-hex cookie, never logged
#   D2 exactly the default + ALLOW=1      -> same
#   R  ALLOW=1 + a real shared cookie that CONTAINS the literal -> passed through UNCHANGED (every
#                                            replica must keep the shared cookie)
#   G  ALLOW=1 + a bad-charset cookie     -> still refused
#   E  a strong cookie                    -> started with that exact cookie
#   F/H loopback / routable advertise     -> dist pinned / not pinned
#   U  the systemd ExecStartPre string    -> same verdicts
#   X  parity: the Erlang guard's floor and published literal equal the shell policy's
set -u
here="$(cd "$(dirname "$0")" && pwd)"
repo="$here/../.."
docker_dir="$repo/deploy/docker"
work="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_gw_entry.XXXXXX")"
trap 'rm -rf "$work"' EXIT

stub="$work/yuzu_gw"
cat > "$stub" <<'STUB'
#!/bin/sh
printf 'STARTED cookie=%s epmd=%s aflags=%s\n' "${YUZU_GW_COOKIE:-}" "${ERL_EPMD_ADDRESS:-}" "${ERL_AFLAGS:-}"
STUB
chmod +x "$stub"
mkdir -p "$work/opt"
sed "s#/opt/yuzu_gw/bin/yuzu_gw#$stub#" "$docker_dir/gateway-entrypoint.sh" > "$work/opt/gateway-entrypoint.sh"
[ -f "$docker_dir/gateway-cookie-policy.sh" ] && cp "$docker_dir/gateway-cookie-policy.sh" "$work/opt/"

shells=""
for s in "bash" "dash" "busybox sh"; do
    set -- $s
    command -v "$1" >/dev/null 2>&1 && shells="$shells|$s"
done
shells="${shells#|}"
echo "shells under test: $shells"

fail=0
pass() { echo "PASS $1"; }
bad()  { echo "FAIL $1: $2"; fail=1; }

# run <addr> <shell> VAR=value...   -> sets out, err, rc
run() {
    addr="$1"; sh="$2"; shift 2
    out="$(env -i PATH="$PATH" YUZU_GW_ADVERTISE_ADDR="$addr" "$@" $sh "$work/opt/gateway-entrypoint.sh" 2>"$work/err")"
    rc=$?
    err="$(cat "$work/err")"
}
refused() { # name shell expected-message-fragment VAR=...
    name="$1"; sh="$2"; msg="$3"; shift 3
    run 127.0.0.1 "$sh" "$@"
    if [ $rc -ne 0 ] && [ -z "$out" ] && printf '%s' "$err" | grep -qF -- "$msg"; then pass "$name [$sh]"
    else bad "$name [$sh]" "rc=$rc out=[$out] err=[$err] (wanted: $msg)"; fi
}
started_with() { # name shell VAR=...  ; prints cookie in $cookie
    name="$1"; sh="$2"; shift 2
    run "${ADDR:-127.0.0.1}" "$sh" "$@"
    cookie="$(printf '%s' "$out" | sed -n 's/^STARTED cookie=\([^ ]*\) epmd=.*/\1/p')"
    [ $rc -eq 0 ] && [ -n "$cookie" ]
}

strong="$(printf 'k%.0s' $(seq 40))"
default=yuzu_gw_secret_change_me
embedded="shared-${default}-0123456789abcdef"
cr="$(printf '\r')"

OLDIFS="$IFS"; IFS='|'
for sh in $shells; do
    IFS="$OLDIFS"
    refused A "$sh" "is unset, empty or the published default"
    refused B "$sh" "is unset, empty or the published default" YUZU_GW_COOKIE=$default
    refused C "$sh" "outside the allowed" 'YUZU_GW_COOKIE=${YUZU_GW_COOKIE:-yuzu_gw_x}'
    refused S "$sh" "shorter than 32" YUZU_GW_COOKIE=short
    refused W-space "$sh" "outside the allowed" "YUZU_GW_COOKIE=${strong} x"
    refused W-crlf "$sh" "outside the allowed" "YUZU_GW_COOKIE=${strong}${cr}"
    refused W-backslash "$sh" "outside the allowed" "YUZU_GW_COOKIE=${strong}\\n"
    refused W-amp "$sh" "outside the allowed" "YUZU_GW_COOKIE=${strong}\\&x"
    refused L-dash "$sh" "must not start with" "YUZU_GW_COOKIE=-${strong}"
    refused L-plus "$sh" "must not start with" "YUZU_GW_COOKIE=+${strong}"
    refused P "$sh" "contains the published default" YUZU_GW_COOKIE="$embedded"
    refused G "$sh" "outside the allowed" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 "YUZU_GW_COOKIE=${strong}\\&"

    if started_with D "$sh" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 && printf '%s' "$cookie" | grep -Eq '^[0-9a-f]{64}$' \
       && ! grep -qF "$cookie" "$work/err"; then pass "D [$sh]"; else bad "D [$sh]" "rc=$rc out=[$out]"; fi
    if started_with D2 "$sh" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 YUZU_GW_COOKIE=$default && printf '%s' "$cookie" | grep -Eq '^[0-9a-f]{64}$'; then
        pass "D2 [$sh]"; else bad "D2 [$sh]" "rc=$rc out=[$out]"; fi
    if started_with R "$sh" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 YUZU_GW_COOKIE="$embedded" && [ "$cookie" = "$embedded" ]; then
        pass "R [$sh]"; else bad "R [$sh]" "cookie=[$cookie] rc=$rc err=[$err]"; fi
    if started_with E "$sh" YUZU_GW_COOKIE="$strong" && [ "$cookie" = "$strong" ]; then pass "E [$sh]"; else bad "E [$sh]" "rc=$rc"; fi

    run 127.0.0.1 "$sh" YUZU_GW_COOKIE="$strong"
    if printf '%s' "$out" | grep -q "epmd=127.0.0.1" && printf '%s' "$out" | grep -q "inet_dist_use_interface"; then pass "F [$sh]"; else bad "F [$sh]" "$out"; fi
    run 10.1.2.3 "$sh" YUZU_GW_COOKIE="$strong"
    if printf '%s' "$out" | grep -q "epmd= aflags=\$"; then pass "H [$sh]"; else bad "H [$sh]" "$out"; fi
    IFS='|'
done
IFS="$OLDIFS"

# U: the systemd ExecStartPre line, run for real with the installed path pointed at the repo copy.
unit="$repo/deploy/systemd/yuzu-gateway.service"
pre="$(grep '^ExecStartPre=' "$unit" | grep -i 'cookie' | head -n1 | sed 's/^ExecStartPre=//')"
if [ -z "$pre" ]; then bad U "no cookie ExecStartPre in the unit"; else
    pre="$(printf '%s' "$pre" | sed "s#/opt/yuzu_gw#$work/opt#g")"
    unit_run() { out="$(env -i PATH="$PATH" "$@" /bin/sh -c "$pre" 2>&1)"; rc=$?; }
    unit_run;                                         { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "is unset, empty or the published default"; } && pass "U-unset" || bad U-unset "rc=$rc $out"
    unit_run YUZU_GW_ALLOW_DEFAULT_COOKIE=1;          [ $rc -ne 0 ] && pass "U-no-override" || bad U-no-override "the unit must not honour the override"
    unit_run YUZU_GW_COOKIE=short;                    { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "shorter than 32"; } && pass "U-short" || bad U-short "rc=$rc $out"
    unit_run "YUZU_GW_COOKIE=${strong}\\&";           { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "outside the allowed"; } && pass "U-amp" || bad U-amp "rc=$rc $out"
    unit_run YUZU_GW_COOKIE="$embedded";              [ $rc -ne 0 ] && pass "U-embedded" || bad U-embedded "rc=$rc"
    unit_run YUZU_GW_COOKIE="$strong";                [ $rc -eq 0 ] && pass "U-ok" || bad U-ok "rc=$rc $out"
fi

# X: the Erlang in-VM guard and the shell policy must agree on the floor and the literal.
erl_src="$repo/gateway/apps/yuzu_gw/src/yuzu_gw_app.erl"
erl_min="$(sed -n 's/^-define(MIN_COOKIE_LENGTH, *\([0-9]*\)).*/\1/p' "$erl_src")"
sh_min="$(sed -n 's/^YUZU_GW_COOKIE_MIN_LENGTH=\([0-9]*\).*/\1/p' "$docker_dir/gateway-cookie-policy.sh" 2>/dev/null)"
[ -n "$erl_min" ] && [ "$erl_min" = "$sh_min" ] && pass "X-floor" || bad X-floor "erlang=[$erl_min] shell=[$sh_min]"
erl_lit="$(grep -c 'yuzu_gw_secret_change_me' "$erl_src")"
sh_lit="$(sed -n 's/^YUZU_GW_COOKIE_PUBLISHED_DEFAULT=\(.*\)$/\1/p' "$docker_dir/gateway-cookie-policy.sh" 2>/dev/null)"
[ "$sh_lit" = "yuzu_gw_secret_change_me" ] && [ "$erl_lit" -ge 1 ] && pass "X-literal" || bad X-literal "shell=[$sh_lit] erl-mentions=$erl_lit"
grep -q 'yuzu_gw_secret_change_me' "$repo/gateway/config/vm.args.src" \
  && grep -v '^##' "$repo/gateway/config/vm.args.src" | grep -q yuzu_gw_secret_change_me \
  && bad X-vmargs "the published literal is back in an active vm.args.src line" || pass X-vmargs

exit $fail
