# shellcheck shell=bash
# uat-grafana-password.sh - the Grafana admin password for the Docker UAT rigs (#4817).
#
# Sourced by scripts/docker-start-UAT.sh and scripts/win-start-UAT.sh. The UAT
# composes require YUZU_GRAFANA_ADMIN_PASSWORD (${...:?}) and Compose refuses
# EVERY command without it, `down` and `ps` included, so each launcher function
# that runs `docker compose` calls uat_grafana_password first
# (tests/test_compose_default_credentials.py checks that).
#
#   uat_grafana_password STATE_FILE
#
# Exports YUZU_GRAFANA_ADMIN_PASSWORD, taken from, in order:
#   1. the caller's environment, when non-empty (saved to STATE_FILE);
#   2. STATE_FILE, when it exists;
#   3. 16 fresh random bytes as hex (saved to STATE_FILE).
# STATE_FILE is written 0600 via a new temporary file and a rename. A symlinked
# or non-regular STATE_FILE, an empty one, a value containing a line break and
# the value `admin` (any case) are refused, as is a failure to generate random
# bytes: the function returns 1 and exports nothing. On Windows (MSYS2) chmod
# does not change NTFS permissions; the file is as private as the checkout.

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

uat_grafana_password() {
    local state="${1:?uat_grafana_password: state file path required}"
    local value="" stored="" lower tmp

    if [ -L "$state" ]; then
        _uat_grafana_err "refusing symlinked state file $state"
        return 1
    fi
    if [ -e "$state" ] && [ ! -f "$state" ]; then
        _uat_grafana_err "refusing non-regular state file $state"
        return 1
    fi
    if [ -f "$state" ]; then
        IFS= read -r stored < "$state" || true
    fi

    if [ -n "${YUZU_GRAFANA_ADMIN_PASSWORD:-}" ]; then
        value="$YUZU_GRAFANA_ADMIN_PASSWORD"
    elif [ -f "$state" ]; then
        if [ -z "$stored" ]; then
            _uat_grafana_err "state file $state is empty; delete it to generate a new password"
            return 1
        fi
        value="$stored"
    else
        if ! value="$(_uat_grafana_random)"; then
            _uat_grafana_err "could not generate YUZU_GRAFANA_ADMIN_PASSWORD (no openssl, python3 or /dev/urandom)"
            return 1
        fi
    fi

    case "$value" in
        *$'\n'*|*$'\r'*)
            _uat_grafana_err "YUZU_GRAFANA_ADMIN_PASSWORD must not contain a line break"
            return 1 ;;
    esac
    lower="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    if [ "$lower" = "admin" ]; then
        _uat_grafana_err "YUZU_GRAFANA_ADMIN_PASSWORD must not be 'admin' (Grafana's well-known default)"
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

    export YUZU_GRAFANA_ADMIN_PASSWORD="$value"
}
