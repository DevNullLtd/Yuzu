# shellcheck shell=bash
# uat-grafana-password.sh - the Grafana admin password for the Docker UAT rigs (#4817).
#
# Sourced by scripts/docker-start-UAT.sh and scripts/win-start-UAT.sh. The UAT
# composes require YUZU_GRAFANA_ADMIN_PASSWORD (${...:?}) and Compose refuses
# every command that reads the file without it, `down` and `ps` included.
# UAT ONLY: the password is kept in plaintext in STATE_FILE and printed in the
# launchers' banners. Do not keep launcher output in shared logs or CI artifacts.
#
# Sourcing this file un-exports YUZU_GRAFANA_ADMIN_PASSWORD and
# UAT_GRAFANA_ADMIN_PASSWORD (an operator may have exported either), and none of
# these functions exports anything. They set the shell variable
# UAT_GRAFANA_ADMIN_PASSWORD, and each launcher passes it to one `docker compose`
# command at a time (YUZU_GRAFANA_ADMIN_PASSWORD="$UAT_GRAFANA_ADMIN_PASSWORD"
# docker compose ...), so the native server, gateway and agent the launchers
# start never inherit it, even when the operator exported it.
# tests/test_compose_default_credentials.py checks the launchers do exactly that.
#
#   uat_grafana_password_preflight
#       For `start`, BEFORE it stops or wipes anything: returns 1, with the
#       reason, when an exported YUZU_GRAFANA_ADMIN_PASSWORD would be refused,
#       so a typo never tears down a running stack first.
#
#   uat_grafana_password_stored STATE_FILE
#       Prints the stored password and returns 0, or returns 1 with no output
#       when there is none that can be used. Never writes, never prints an error.
#
#   uat_grafana_password_for_compose STATE_FILE
#       For `stop` and `status`: commands whose value Compose never uses
#       (`down`, `ps`). NEVER WRITES. Sets UAT_GRAFANA_ADMIN_PASSWORD to an
#       exported YUZU_GRAFANA_ADMIN_PASSWORD, else the stored value, else a
#       placeholder, and UAT_GRAFANA_ADMIN_PASSWORD_SOURCE to env, stored or
#       none. Always returns 0, so an unreadable or unwritable .uat can never
#       stop the stack from being stopped. Never use it for `up`: the
#       placeholder is public.
#
#   uat_grafana_password STATE_FILE [PREVIOUS]
#       For `start` only, before `up`. Takes, in order: an exported
#       YUZU_GRAFANA_ADMIN_PASSWORD; PREVIOUS (start_all reads the stored value
#       before it wipes .uat and passes it here, so the password survives
#       restarts); the stored value; 16 fresh random bytes as hex (openssl ->
#       python3 secrets -> od /dev/urandom; returns 1 if none works). Refuses an
#       empty value, leading or trailing whitespace, a line break and `admin` in
#       any case. Saves the result to STATE_FILE (0600 where the filesystem
#       honours it, via a new temporary file and a rename) and sets
#       UAT_GRAFANA_ADMIN_PASSWORD. Returns 1, with a message naming where the
#       value came from, on any refusal, and then leaves
#       UAT_GRAFANA_ADMIN_PASSWORD EMPTY, so even a caller that ignored the
#       failure would have `up` refused by the compose file's ${...:?}.
#
# A stored value is read whole; trailing newlines and then one trailing CR are
# dropped (a file saved by a Windows editor), and a file that is not a regular
# file, is a symlink, is empty or has a line break inside the value is not used.
# On Windows (MSYS2, or WSL on a /mnt/c checkout without the metadata mount
# option) chmod does not change the file's permissions: it is as private as the
# checkout.

export -n YUZU_GRAFANA_ADMIN_PASSWORD UAT_GRAFANA_ADMIN_PASSWORD 2>/dev/null || true

_uat_grafana_err() {
    echo "uat-grafana-password: $*" >&2
}

_uat_grafana_random() {
    local v
    v="$(openssl rand -hex 16 2>/dev/null)" || v=""
    if ! [[ "$v" =~ ^[0-9a-f]{32}$ ]]; then
        v="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null)" || v=""
    fi
    if ! [[ "$v" =~ ^[0-9a-f]{32}$ ]]; then
        v="$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')" || v=""
    fi
    [[ "$v" =~ ^[0-9a-f]{32}$ ]] || return 1
    printf '%s' "$v"
}

# _uat_grafana_problem VALUE -> prints why VALUE is refused, or nothing.
_uat_grafana_problem() {
    local value="$1" lower
    case "$value" in
        "") echo "is empty"; return ;;
        *$'\n'*|*$'\r'*) echo "contains a line break"; return ;;
        [[:space:]]*|*[[:space:]]) echo "starts or ends with whitespace"; return ;;
    esac
    lower="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    if [ "$lower" = "admin" ]; then
        echo "is 'admin' (Grafana's well-known default)"
    fi
}

uat_grafana_password_stored() {
    local state="${1:?uat_grafana_password_stored: state file path required}"
    local stored
    [ -f "$state" ] && [ ! -L "$state" ] || return 1
    stored="$(cat "$state" 2>/dev/null)" || return 1
    stored="${stored%$'\r'}"
    [ -z "$(_uat_grafana_problem "$stored")" ] || return 1
    printf '%s' "$stored"
}

uat_grafana_password_for_compose() {
    local state="${1:?uat_grafana_password_for_compose: state file path required}"
    local stored
    if [ -n "${YUZU_GRAFANA_ADMIN_PASSWORD:-}" ]; then
        UAT_GRAFANA_ADMIN_PASSWORD="$YUZU_GRAFANA_ADMIN_PASSWORD"
        UAT_GRAFANA_ADMIN_PASSWORD_SOURCE="env"
    elif stored="$(uat_grafana_password_stored "$state")"; then
        UAT_GRAFANA_ADMIN_PASSWORD="$stored"
        UAT_GRAFANA_ADMIN_PASSWORD_SOURCE="stored"
    else
        # Only satisfies Compose's ${...:?} for down/ps, which create nothing.
        UAT_GRAFANA_ADMIN_PASSWORD="unused-by-down-and-ps"
        UAT_GRAFANA_ADMIN_PASSWORD_SOURCE="none"
    fi
    return 0
}

uat_grafana_password_preflight() {
    local problem
    [ -n "${YUZU_GRAFANA_ADMIN_PASSWORD:-}" ] || return 0
    problem="$(_uat_grafana_problem "$YUZU_GRAFANA_ADMIN_PASSWORD")"
    if [ -n "$problem" ]; then
        _uat_grafana_err "refusing the exported YUZU_GRAFANA_ADMIN_PASSWORD: it $problem (nothing was stopped)"
        return 1
    fi
}

uat_grafana_password() {
    local state="${1:?uat_grafana_password: state file path required}"
    local previous="${2:-}" value="" from="" stored="" problem tmp
    UAT_GRAFANA_ADMIN_PASSWORD=""

    if [ -L "$state" ] || { [ -e "$state" ] && [ ! -f "$state" ]; }; then
        _uat_grafana_err "$state is not a regular file; delete it and run start again"
        return 1
    fi
    if [ -f "$state" ]; then
        stored="$(cat "$state" 2>/dev/null)" || stored=""
        stored="${stored%$'\r'}"
    fi

    if [ -n "${YUZU_GRAFANA_ADMIN_PASSWORD:-}" ]; then
        value="$YUZU_GRAFANA_ADMIN_PASSWORD"; from="the exported YUZU_GRAFANA_ADMIN_PASSWORD"
    elif [ -n "$previous" ]; then
        value="$previous"; from="the password saved by the previous start"
    elif [ -f "$state" ]; then
        value="$stored"; from="$state (delete it to generate a new password)"
    else
        if ! value="$(_uat_grafana_random)"; then
            _uat_grafana_err "could not generate YUZU_GRAFANA_ADMIN_PASSWORD (no openssl, python3 or /dev/urandom)"
            return 1
        fi
        from="the generator"
    fi

    problem="$(_uat_grafana_problem "$value")"
    if [ -n "$problem" ]; then
        _uat_grafana_err "refusing YUZU_GRAFANA_ADMIN_PASSWORD from $from: it $problem"
        return 1
    fi

    if [ ! -f "$state" ] || [ "$stored" != "$value" ]; then
        mkdir -p "$(dirname "$state")" || return 1
        tmp="$state.tmp.$$"
        rm -f "$tmp"
        if ! ( umask 077 && set -C && printf '%s\n' "$value" > "$tmp" ); then
            _uat_grafana_err "could not write $tmp"
            rm -f "$tmp"
            return 1
        fi
        chmod 600 "$tmp" 2>/dev/null || true
        if ! mv -f "$tmp" "$state"; then
            _uat_grafana_err "could not write $state"
            rm -f "$tmp"
            return 1
        fi
    fi

    UAT_GRAFANA_ADMIN_PASSWORD="$value"
}

# uat_grafana_password_describe STATE_FILE -> prints the Grafana login for a
# status banner. Read-only. A usable stored value is what the last `start`
# used; otherwise an exported value is shown with a caveat, or reported as one
# start would refuse; with neither the login is unknown.
uat_grafana_password_describe() {
    local state="${1:?uat_grafana_password_describe: state file path required}"
    local stored
    if stored="$(uat_grafana_password_stored "$state")"; then
        printf 'admin / %s' "$stored"
    elif [ -n "${YUZU_GRAFANA_ADMIN_PASSWORD:-}" ]; then
        if [ -n "$(_uat_grafana_problem "$YUZU_GRAFANA_ADMIN_PASSWORD")" ]; then
            printf 'unknown: no usable saved password, and the exported YUZU_GRAFANA_ADMIN_PASSWORD would be refused by start'
        else
            printf 'admin / %s (exported; not what a running Grafana was necessarily started with)' "$YUZU_GRAFANA_ADMIN_PASSWORD"
        fi
    else
        printf 'unknown: no usable %s (stack started outside this launcher or before #4817; see docs/uat-environment.md)' "$state"
    fi
}
