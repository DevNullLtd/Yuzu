# gateway-cookie-policy.sh -- the ONE shell statement of the gateway's Erlang
# distribution-cookie policy (F24 of the 2026-11-17 security scan). SOURCED by
# deploy/docker/gateway-entrypoint.sh and by the systemd unit's ExecStartPre; it
# is installed next to them as /opt/yuzu_gw/gateway-cookie-policy.sh (Dockerfile.gateway,
# the .deb and the .rpm). POSIX sh only (the runtime image is busybox).
#
# Why this exists outside the VM: yuzu_gw_app:check_distribution_cookie/0 runs in the
# application start callback, AFTER the kernel has started net_kernel, so a node with a
# known cookie is reachable for the whole boot window. This refuses first.
#
# Parity: the floor and the published literal below are the SAME values as
# ?MIN_COOKIE_LENGTH and the literal in gateway/apps/yuzu_gw/src/yuzu_gw_app.erl;
# tests/shell/test_gateway_entrypoint_cookie.sh (case X) fails if they drift.
#
# The character allow-list exists because the cookie is substituted into vm.args by
# relx's awk-based replace_os_vars: busybox awk drops a backslash that mawk keeps (two
# replicas would then disagree on the cookie), and a `\&` makes that awk loop forever at
# 100% CPU with no log. Whitespace and CR/LF would split or corrupt the vm.args line.

YUZU_GW_COOKIE_MIN_LENGTH=32
# erl crashes in auth:init on a cookie of 256 or more characters, before any guard runs.
YUZU_GW_COOKIE_MAX_LENGTH=255
YUZU_GW_COOKIE_PUBLISHED_DEFAULT=yuzu_gw_secret_change_me

# yuzu_gw_cookie_classify: reads $YUZU_GW_COOKIE, prints nothing. Returns
#   0  acceptable
#   10 unset, empty, or EXACTLY the published default (replaceable under the dev/CI override)
#   11 a character outside the allow-list
#   12 shorter than the floor (refused even under the dev/CI override)
#   13 contains the published default inside a longer value (the dev/CI override refuses it when it is a PREFIX, passes it through otherwise)
#   14 starts with - or + (the VM would read it as a flag)
#   15 longer than the ceiling (never tolerated, not even under the dev/CI override)
yuzu_gw_cookie_classify() {
    _c="${YUZU_GW_COOKIE:-}"
    [ -n "$_c" ] || return 10
    [ "$_c" != "$YUZU_GW_COOKIE_PUBLISHED_DEFAULT" ] || return 10
    case "$_c" in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+=-]*) return 11 ;;
        [-+]*) return 14 ;;
    esac
    [ "${#_c}" -le "$YUZU_GW_COOKIE_MAX_LENGTH" ] || return 15
    [ "${#_c}" -ge "$YUZU_GW_COOKIE_MIN_LENGTH" ] || return 12
    case "$_c" in
        *"$YUZU_GW_COOKIE_PUBLISHED_DEFAULT"*) return 13 ;;
    esac
    return 0
}

# yuzu_gw_cookie_message <code>: the refusal text, which names the fix. Never the value.
yuzu_gw_cookie_message() {
    case "$1" in
        10) echo "YUZU_GW_COOKIE is unset, empty or the published default value. The Erlang distribution cookie is the sole authentication for inter-node RPC. Set a strong unique value on every node, e.g. YUZU_GW_COOKIE=\$(openssl rand -hex 32)." ;;
        11) echo "YUZU_GW_COOKIE contains a character outside the allowed set [A-Za-z0-9._~+=-] (whitespace, CR/LF, backslash, & and \$ are refused: they are mangled differently by busybox and GNU awk or hang the release start script). Use e.g. 'openssl rand -hex 32'." ;;
        12) echo "YUZU_GW_COOKIE is shorter than ${YUZU_GW_COOKIE_MIN_LENGTH} characters, which is brute-forceable offline from a node that dials out. Use e.g. 'openssl rand -hex 32'." ;;
        13) echo "YUZU_GW_COOKIE contains the published default value. Generate a fresh cookie, e.g. 'openssl rand -hex 32'." ;;
        15) echo "YUZU_GW_COOKIE is longer than ${YUZU_GW_COOKIE_MAX_LENGTH} characters, which crashes the Erlang VM at boot. Use e.g. 'openssl rand -hex 32' (64 characters)." ;;
        14) echo "YUZU_GW_COOKIE must not start with - or + (the VM would read it as a flag). Use e.g. 'openssl rand -hex 32'." ;;
    esac
}

# yuzu_gw_cookie_check_strict: for the systemd unit, which has NO dev/CI override.
# Returns 0, or prints the refusal to stderr and returns non-zero.
yuzu_gw_cookie_check_strict() {
    yuzu_gw_cookie_classify
    _rc=$?
    [ "$_rc" -eq 0 ] && return 0
    printf 'yuzu-gateway: %s\n' "$(yuzu_gw_cookie_message "$_rc")" >&2
    return 1
}
