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
#   M  longer than 255 characters        -> refused, "longer than 255" (erl crashes in auth:init above that);
#                                            exactly 255 is accepted
#   P  published literal INSIDE a longer cookie, no override -> refused, "contains the published"
#   D  unset + ALLOW=1                    -> started with a random 64-hex cookie, never logged
#   D2 exactly the default + ALLOW=1      -> same
#   R  ALLOW=1 + a real shared cookie with the literal in the MIDDLE -> passed through UNCHANGED (every
#                                            replica must keep the shared cookie)
#   AP ALLOW=1 + a short cookie, or one that STARTS with the published literal -> refused (the override
#                                            only ever replaces an EMPTY or EXACTLY-default cookie)
#   G  ALLOW=1 + a bad-charset cookie     -> still refused
#   E  a strong cookie                    -> started with that exact cookie
#   F/H loopback / routable advertise     -> dist pinned / not pinned
#   B  boundaries 31/32/255/256 chars; the literal at offset 0/1/middle/end, with and without the override
#      (every refusal also asserts the cookie value is never echoed)
#   U  the systemd ExecStartPre string    -> same verdicts
#   T  tripwire: a LIVE (non-comment) copy/install of gateway-cookie-policy.sh and the unit in the Docker
#      image, .deb, .rpm and release tarball recipes
#   V  a real BEAM accepts the empty -setcookie and uses its own ~/.erlang.cookie (needs erl)
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
# A missing shell makes this a SKIP (exit 77, which meson reports as skipped): a silent
# bash-only pass would not test the busybox/dash behaviour this policy exists for.
# CI sets YUZU_REQUIRE_ALL_SHELLS=1, which turns the skip into a failure.
for want in bash dash "busybox sh"; do
    case "|$shells|" in
        *"|$want|"*) ;;
        *) if [ "${YUZU_REQUIRE_ALL_SHELLS:-}" = "1" ]; then
               echo "FAIL shells: '$want' not available"; exit 1
           fi
           echo "SKIP: '$want' not available (set YUZU_REQUIRE_ALL_SHELLS=1 to make this a failure)"; exit 77 ;;
    esac
done

fail=0
pass() { echo "PASS $1"; }
bad()  { echo "FAIL $1: $2"; fail=1; }

# run <addr> <shell> VAR=value...   -> sets out, err, rc
run() {
    addr="$1"; sh="$2"; shift 2
    out="$(env -i PATH="$PATH" YUZU_GW_ADVERTISE_ADDR="$addr" "$@" timeout 20 $sh "$work/opt/gateway-entrypoint.sh" 2>"$work/err")"
    rc=$?
    err="$(cat "$work/err")"
}
refused() { # name shell expected-message-fragment VAR=...
    name="$1"; sh="$2"; msg="$3"; shift 3
    run 127.0.0.1 "$sh" "$@"
    leak=""
    for kv in "$@"; do
        v="${kv#YUZU_GW_COOKIE=}"
        # a secret is never echoed back (values under 12 chars are skipped: "short" is a
        # substring of the message's own word "shorter")
        [ "$v" != "$kv" ] && [ "${#v}" -ge 12 ] && printf '%s' "$err$out" | grep -qF -- "$v" && leak=1
    done
    if [ $rc -ne 0 ] && [ -z "$out" ] && [ -z "$leak" ] && printf '%s' "$err" | grep -qF -- "$msg"; then pass "$name [$sh]"
    else bad "$name [$sh]" "rc=$rc leak=[$leak] out=[$out] err=[$err] (wanted: $msg)"; fi
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
    long256="$(printf 'k%.0s' $(seq 256))"; long255="$(printf 'k%.0s' $(seq 255))"
    refused M "$sh" "longer than 255" YUZU_GW_COOKIE="$long256"
    if started_with M255 "$sh" YUZU_GW_COOKIE="$long255"; then pass "M255 [$sh]"; else bad "M255 [$sh]" "rc=$rc err=[$err]"; fi
    b31="$(printf 'k%.0s' $(seq 31))"; b32="$(printf 'k%.0s' $(seq 32))"
    refused B31 "$sh" "shorter than 32" YUZU_GW_COOKIE="$b31"
    if started_with B32 "$sh" YUZU_GW_COOKIE="$b32" && [ "$cookie" = "$b32" ]; then pass "B32 [$sh]"; else bad "B32 [$sh]" "rc=$rc err=[$err]"; fi
    # the published literal at offset 0 / 1 / middle / end of an otherwise strong cookie
    pad="$(printf 'z%.0s' $(seq 20))"
    off0="${default}${pad}"; off1="x${default}${pad}"; offm="${pad}${default}${pad}"; offe="${pad}${default}"
    for lit in off0 off1 offm offe; do
        eval "lv=\$$lit"
        refused "LIT-$lit" "$sh" "contains the published default" YUZU_GW_COOKIE="$lv"
    done
    refused "LIT-off0-allow" "$sh" "contains the published default" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 YUZU_GW_COOKIE="$off0"
    for lit in off1 offm offe; do
        eval "lv=\$$lit"
        if started_with "LIT-$lit-allow" "$sh" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 YUZU_GW_COOKIE="$lv" && [ "$cookie" = "$lv" ]; then
            pass "LIT-$lit-allow [$sh]"; else bad "LIT-$lit-allow [$sh]" "cookie=[$cookie] rc=$rc"; fi
    done
    refused P "$sh" "contains the published default" YUZU_GW_COOKIE="$embedded"
    refused AP-short "$sh" "shorter than 32" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 YUZU_GW_COOKIE=short
    refused AP-prefix "$sh" "contains the published default" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 "YUZU_GW_COOKIE=${default}abcdefgh"
    refused AP-prefix-long "$sh" "contains the published default" YUZU_GW_ALLOW_DEFAULT_COOKIE=1 "YUZU_GW_COOKIE=${default}${strong}"
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

# (also: no refusal output of the ExecStartPre contains the cookie value; checked in U-leak below)
# U: the systemd ExecStartPre line, run for real with the installed path pointed at the repo copy.
unit="$repo/deploy/systemd/yuzu-gateway.service"
pre="$(grep '^ExecStartPre=' "$unit" | grep -i 'cookie' | head -n1 | sed 's/^ExecStartPre=//')"
if [ -z "$pre" ]; then bad U "no cookie ExecStartPre in the unit"; else
    pre="$(printf '%s' "$pre" | sed "s#/opt/yuzu_gw#$work/opt#g")"
    unit_run() { out="$(env -i PATH="$PATH" "$@" timeout 20 /bin/sh -c "$pre" 2>&1)"; rc=$?; }
    unit_run;                                         { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "is unset, empty or the published default"; } && pass "U-unset" || bad U-unset "rc=$rc $out"
    unit_run YUZU_GW_ALLOW_DEFAULT_COOKIE=1;          { [ $rc -eq 1 ] && printf '%s' "$out" | grep -qF "is unset, empty or the published default"; } && pass "U-no-override" || bad U-no-override "the unit must not honour the override: rc=$rc $out"
    unit_run YUZU_GW_COOKIE=short;                    { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "shorter than 32"; } && pass "U-short" || bad U-short "rc=$rc $out"
    unit_run "YUZU_GW_COOKIE=${strong}\\&";           { [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "outside the allowed"; } && pass "U-amp" || bad U-amp "rc=$rc $out"
    unit_run YUZU_GW_COOKIE="$embedded";              { [ $rc -eq 1 ] && printf '%s' "$out" | grep -qF "contains the published default"; } && pass "U-embedded" || bad U-embedded "rc=$rc $out"
    unit_run YUZU_GW_COOKIE="$(printf 'k%.0s' $(seq 256))"; { [ $rc -eq 1 ] && printf '%s' "$out" | grep -qF "longer than 255"; } && pass "U-long" || bad U-long "rc=$rc $out"
    leakv="${strong}\\&secretpart"; unit_run "YUZU_GW_COOKIE=$leakv"; { [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -qF -- "$leakv"; } && pass "U-leak" || bad U-leak "rc=$rc $out"
    unit_run YUZU_GW_COOKIE="$strong";                [ $rc -eq 0 ] && pass "U-ok" || bad U-ok "rc=$rc $out"
fi

# T: every packaging path must contain an ACTUAL copy/install/COPY of the policy file to where
# the unit reads it (a commented-out line, or a bare mention, does not count), and the tarball
# and both packages must carry the unit too.
chk() { # file extended-regex-on-a-non-comment-line description
    if grep -vE '^[[:space:]]*#' "$repo/$1" | grep -qE "$2"; then pass "T $1: $3"; else bad "T $1: $3" "no live line matching: $2"; fi
}
chk deploy/docker/Dockerfile.gateway '^[[:space:]]*COPY .*gateway-cookie-policy\.sh /opt/yuzu_gw/gateway-cookie-policy\.sh' "image COPY"
chk deploy/packaging/debian/build-gateway-deb.sh '^[[:space:]]*install .*gateway-cookie-policy\.sh.*opt/yuzu_gw/gateway-cookie-policy\.sh' "deb install"
chk deploy/packaging/debian/build-gateway-deb.sh '^[[:space:]]*cp .*yuzu-gateway\.service' "deb unit"
chk deploy/packaging/rpm/build-gateway-rpm.sh '^[[:space:]]*cp .*gateway-cookie-policy\.sh.*SOURCES' "rpm source stage"
chk deploy/packaging/rpm/build-gateway-rpm.sh '^[[:space:]]*cp .*yuzu-gateway\.service.*SOURCES' "rpm unit stage"
chk deploy/packaging/rpm/yuzu-gateway.spec '^[[:space:]]*install .*gateway-cookie-policy\.sh .*opt/yuzu_gw/gateway-cookie-policy\.sh' "rpm spec install"
chk deploy/packaging/rpm/yuzu-gateway.spec '^[[:space:]]*install .*yuzu-gateway\.service' "rpm spec unit"
chk .github/workflows/release.yml '^[[:space:]]*cp deploy/docker/gateway-cookie-policy\.sh "\$\{STAGING\}/gateway-cookie-policy\.sh"' "tarball policy"
chk .github/workflows/release.yml '^[[:space:]]*cp deploy/systemd/yuzu-gateway\.service "\$\{STAGING\}/yuzu-gateway\.service"' "tarball unit"

# V: the empty `-setcookie` that vm.args.src leaves when YUZU_GW_COOKIE is unset is accepted by
# a real BEAM, which then uses its own per-host random ~/.erlang.cookie (20 chars, created with
# an isolated HOME here). Skipped when no erl is on PATH. (The in-VM guard then refuses that
# short cookie unless the dev/CI override is set; the entrypoint-less chisel demo relies on it.)
if command -v erl >/dev/null 2>&1; then
    vhome="$work/erlhome"; mkdir -p "$vhome"
    grep -E '^-(name|setcookie)' "$repo/gateway/config/vm.args.src" | sed 's/\${YUZU_GW_COOKIE:-}//; s/@\${YUZU_GW_ADVERTISE_ADDR:-127.0.0.1}/@127.0.0.1/' > "$work/vm.args"
    vout="$(cd "$work" && env -i PATH="$PATH" HOME="$vhome" timeout 60 erl -noshell -args_file "$work/vm.args" -eval 'C=atom_to_list(erlang:get_cookie()), {ok,F}=file:read_file(filename:join(os:getenv("HOME"),".erlang.cookie")), io:format("V len=~p filematch=~p~n",[length(C), binary_to_list(F)=:=C]), halt().' 2>&1)"
    printf '%s' "$vout" | grep -q "^V len=20 filematch=true" && pass "V empty -setcookie uses ~/.erlang.cookie" || bad "V empty -setcookie" "$vout"
else
    echo "SKIP V: no erl on PATH"
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
