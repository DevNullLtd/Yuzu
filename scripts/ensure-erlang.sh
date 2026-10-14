#!/usr/bin/env bash
# scripts/ensure-erlang.sh
#
# Sourceable helper that puts `erl` (Erlang/OTP runtime) on PATH so the
# Yuzu gateway and meson custom_targets that invoke rebar3 can build.
#
# Usage:
#   source scripts/ensure-erlang.sh           # default: erlang_toolchain.py's floor (28.4 => 28.4 or any later 28.x)
#   source scripts/ensure-erlang.sh 28        # any 28.x
#   source scripts/ensure-erlang.sh 28.4.2    # 28.4.2 or any later 28.x (never 29)
#   command -v erl >/dev/null || { echo "Erlang/OTP missing" >&2; exit 1; }
#
# This script:
#   - Is a no-op if `erl` is already on PATH, runs, AND is the desired OTP version.
#   - Tries kerl → asdf → Homebrew (macOS only) → Windows installer (MSYS2 only).
#   - ALWAYS returns 0 — callers MUST verify with `command -v erl` afterwards.
#     (Returning non-zero from a sourced script trips parent `set -e`.)
#
# The default version tracks `.github/workflows/release.yml`'s
# `erlef/setup-beam` `otp-version`. Bump them together.
#
# Supported environments: Linux, macOS, WSL2, MSYS2 bash on Windows.
# Native cmd.exe / PowerShell are NOT supported — use MSYS2 (CLAUDE.md).

# Refuse to run as a subprocess: PATH mutations would be discarded.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    echo "ensure-erlang.sh must be sourced: source scripts/ensure-erlang.sh" >&2
    exit 1
fi

# Bash-only: BASH_SOURCE, shopt, etc. dash/zsh are unsupported.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ensure-erlang.sh requires bash (got: ${SHELL:-unknown})" >&2
    return 0 2>/dev/null || true
fi

# Default: the pinned release from scripts/erlang_toolchain.py (DEFAULT_OTP_VERSION),
# the same pin Meson resolves at configure time, so a shell and a Meson build
# can never disagree about which OTP the gateway is built with.
_yz_desired_erlang="${1:-}"
if [ -z "$_yz_desired_erlang" ]; then
    _yz_desired_erlang=$(sed -n 's/^DEFAULT_OTP_VERSION = "\([^"]*\)".*/\1/p' \
        "$(dirname "${BASH_SOURCE[0]}")/erlang_toolchain.py" 2>/dev/null | head -n1)
    _yz_desired_erlang="${YUZU_OTP_VERSION:-${_yz_desired_erlang:-28.4}}"
fi

# Reject characters that could cause grief in awk/glob/log expansion.
case "$_yz_desired_erlang" in
    *[!A-Za-z0-9._-]*)
        echo "[ensure-erlang] invalid version '$_yz_desired_erlang' — falling back to '28'" >&2
        _yz_desired_erlang=28
        ;;
esac

_yz_log() { printf '[ensure-erlang] %s\n' "$*" >&2; }

# Cache `uname -s` once so the failure path doesn't run uname after probes
# may have left PATH in an unusual state (also useful in test harnesses).
_yz_uname=$(uname -s 2>/dev/null || echo unknown)

# Liveness probe: `erl` exists AND can be invoked. Catches broken symlinks,
# missing libs, wrong-arch binaries.
_yz_have_erl() {
    command -v erl >/dev/null 2>&1 || return 1
    erl -version >/dev/null 2>&1
}

# Full OTP version ("28.4.2") of the erl now on PATH, or empty.
_yz_erl_version() {
    erl -noshell -eval 'F=filename:join([code:root_dir(),"releases",erlang:system_info(otp_release),"OTP_VERSION"]),{ok,B}=file:read_file(F),io:put_chars(B),halt().' 2>/dev/null | tr -d '[:space:]'
}

# True when $1 is the desired version or later WITHIN its major ("28.4"
# accepts 28.4, 28.4.2, 28.5.0.7; never 28.3 or 29.1) - the same rule as
# erlang_toolchain.version_matches.
_yz_version_ok() {
    [ -n "$1" ] || return 1
    [ "${1%%.*}" = "${_yz_desired_erlang%%.*}" ] || return 1
    [ "$(printf '%s\n%s\n' "$_yz_desired_erlang" "$1" | sort -V | head -n1)" = "$_yz_desired_erlang" ]
}

# A working erl of the desired version is first on PATH. Every probe below is
# gated on this, never on _yz_have_erl alone: "an erl that runs" is how a
# Homebrew OTP 29 ahead of kerl's 28.4 used to pass as success.
_yz_erl_ok() {
    _yz_have_erl || return 1
    _yz_version_ok "$(_yz_erl_version)"
}

# OTP_VERSION of an install directory without starting a VM (kerl/asdf layout:
# <dir>/releases/<major>/OTP_VERSION).
_yz_dir_otp_version() {
    for _yz_vf in "$1"/releases/*/OTP_VERSION "$1"/lib/erlang/releases/*/OTP_VERSION; do
        [ -f "$_yz_vf" ] && { tr -d '[:space:]' < "$_yz_vf"; return 0; }
    done
    return 1
}

_yz_cleanup() {
    unset _yz_desired_erlang _yz_activated _yz_kerl_match _yz_asdf_erl \
          _yz_brew_prefix _yz_win_match _yz_win_bindir _yz_root _yz_cand \
          _yz_ver _yz_prev_nullglob _yz_uname _yz_orig_path _yz_vf \
          _yz_path_ver _yz_kerl_dir _yz_kerl_best _yz_kerl_best_ver _yz_brew_f
    unset -f _yz_log _yz_have_erl _yz_erl_version _yz_version_ok _yz_erl_ok \
             _yz_dir_otp_version _yz_cleanup
}

# Snapshot PATH so the failure path can roll back any partial probe mutations
# (asdf/brew/MSYS2 each prepend before liveness-checking, and a failed kerl
# activate can leave fragments behind too).
_yz_orig_path="$PATH"

# Already on PATH, runs, AND is the desired version — silent success. A
# working erl of the wrong version is not success: report it and keep looking.
if _yz_erl_ok; then
    _yz_cleanup
    return 0
fi
if _yz_have_erl; then
    _yz_path_ver=$(_yz_erl_version)
    _yz_log "erl on PATH ($(command -v erl)) is OTP ${_yz_path_ver:-unknown}; need $_yz_desired_erlang - searching kerl/asdf/Homebrew/installers"
fi

_yz_activated=""

# 1. kerl — its installs are usable whether or not the `kerl` command itself is
#    on PATH, so `kerl list installations` is merged with a scan of kerl's own
#    install dirs. Each candidate is judged by its OTP_VERSION file, not its
#    (user-chosen) name; the highest matching release wins.
_yz_kerl_best=""
_yz_kerl_best_ver=""
for _yz_kerl_dir in \
    $(command -v kerl >/dev/null 2>&1 && kerl list installations 2>/dev/null | awk '{print $2}') \
    ${KERL_DEFAULT_INSTALL_DIR:+"$KERL_DEFAULT_INSTALL_DIR"/*} \
    ${KERL_BASE_DIR:+"$KERL_BASE_DIR"/*} \
    "$HOME"/.kerl/* "$HOME"/.kerl/installs/*; do
    [ -f "$_yz_kerl_dir/activate" ] || continue
    _yz_ver=$(_yz_dir_otp_version "$_yz_kerl_dir") || continue
    _yz_version_ok "$_yz_ver" || continue
    if [ -z "$_yz_kerl_best_ver" ] || \
       [ "$(printf '%s\n%s\n' "$_yz_kerl_best_ver" "$_yz_ver" | sort -V | tail -n1)" = "$_yz_ver" ]; then
        _yz_kerl_best="$_yz_kerl_dir"
        _yz_kerl_best_ver="$_yz_ver"
    fi
done
_yz_kerl_match="$_yz_kerl_best"
if [ -z "$_yz_activated" ]; then
    if [ -n "$_yz_kerl_match" ] && [ -f "$_yz_kerl_match/activate" ]; then
        # kerl's activate script (4.4.0) is not strict-mode safe: add_cleanup
        # references $_KERL_CLEANUP unbound on first call, which kills any
        # caller running under `set -u`; it also enables `set -o allexport`
        # and never restores it. Snapshot the caller's option state, relax
        # the strict modes for the duration of the source, then restore so
        # callers like scripts/release-preflight.sh that run under
        # `set -euo pipefail` aren't aborted mid-source. `$(set +o)` emits
        # every shell option's current state as `set -o foo` / `set +o foo`
        # lines, which eval restores verbatim — covers errexit, nounset,
        # allexport, pipefail, and anything else the caller set.
        _yz_saved_opts=$(set +o)
        set +eu
        # shellcheck disable=SC1090
        source "$_yz_kerl_match/activate" 2>/dev/null
        _yz_kerl_src_rc=$?
        eval "$_yz_saved_opts"
        unset _yz_saved_opts
        if [ "$_yz_kerl_src_rc" -eq 0 ] && _yz_erl_ok; then
            _yz_log "kerl activated: $_yz_kerl_match"
            _yz_activated="kerl"
        fi
        unset _yz_kerl_src_rc
    fi
fi

# 2. asdf — `asdf which erl` works on both classic and 0.16+ rewrites.
if [ -z "$_yz_activated" ] && command -v asdf >/dev/null 2>&1; then
    _yz_asdf_erl=$(asdf which erl 2>/dev/null || true)
    if [ -z "$_yz_asdf_erl" ]; then
        _yz_asdf_erl=$(asdf where erlang 2>/dev/null)/bin/erl
    fi
    if [ -n "$_yz_asdf_erl" ] && [ -x "$_yz_asdf_erl" ]; then
        export PATH="$(dirname "$_yz_asdf_erl"):$PATH"
        if _yz_erl_ok; then
            _yz_log "asdf erlang: $(dirname "$_yz_asdf_erl")"
            _yz_activated="asdf"
        fi
    fi
fi

# 3. macOS Homebrew (Intel `/usr/local`, Apple Silicon `/opt/homebrew` — both
#    handled by `brew --prefix erlang`).
if [ -z "$_yz_activated" ] && [ "$_yz_uname" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    # The versioned formula first (erlang@28 for a 28.x pin): plain `erlang`
    # tracks the newest OTP and is only accepted if it happens to match.
    for _yz_brew_f in "erlang@${_yz_desired_erlang%%.*}" erlang; do
        [ -z "$_yz_activated" ] || break
        _yz_brew_prefix=$(brew --prefix "$_yz_brew_f" 2>/dev/null || true)
        if [ -n "$_yz_brew_prefix" ] && [ -d "$_yz_brew_prefix/bin" ]; then
            export PATH="$_yz_brew_prefix/bin:$PATH"
            if _yz_erl_ok; then
                _yz_log "Homebrew $_yz_brew_f: $_yz_brew_prefix"
                _yz_activated="brew"
            fi
        fi
    done
fi

# 4. MSYS2 on Windows: probe standard installer paths.
#    Modern installers (≥ OTP 26) use "Erlang OTP\bin\erl.exe" with no version
#    in the directory name; older ones use "erl-<ver>\bin\erl.exe". Sort by
#    extracted version so a versioned install always wins over the unversioned
#    fallback.
if [ -z "$_yz_activated" ]; then
    case "$_yz_uname" in
        MINGW*|MSYS*|CYGWIN*)
            _yz_prev_nullglob=$(shopt -p nullglob 2>/dev/null || echo "shopt -u nullglob")
            shopt -s nullglob

            _yz_win_match=$(
                {
                    for _yz_root in "/c/Program Files" "/c/Program Files (x86)"; do
                        for _yz_cand in "$_yz_root"/erl-*/bin/erl.exe; do
                            _yz_ver=${_yz_cand#"$_yz_root"/erl-}
                            _yz_ver=${_yz_ver%%/*}
                            printf '%s\t%s\n' "$_yz_ver" "$_yz_cand"
                        done
                        _yz_cand="$_yz_root/Erlang OTP/bin/erl.exe"
                        [ -f "$_yz_cand" ] && printf '0.0.0\t%s\n' "$_yz_cand"
                    done
                } | sort -V | tail -n1 | cut -f2-
            )

            eval "$_yz_prev_nullglob"

            if [ -n "$_yz_win_match" ] && [ -f "$_yz_win_match" ]; then
                _yz_win_bindir=$(dirname "$_yz_win_match")
                export PATH="$_yz_win_bindir:$PATH"
                if _yz_erl_ok; then
                    _yz_log "Windows erlang: $_yz_win_bindir"
                    _yz_activated="msys2-windows"
                fi
            fi
            ;;
    esac
fi

if [ -z "$_yz_activated" ]; then
    # Roll back any half-applied PATH mutations from failed probes.
    PATH="$_yz_orig_path"
    _yz_log "Erlang/OTP $_yz_desired_erlang not found (kerl, asdf, Homebrew and installer paths searched)."
    _yz_log "PATH is unchanged: the gateway build will fail or use the wrong OTP until it is installed."
    _yz_log "See every install found, with its version: python3 scripts/erlang_toolchain.py find-otp"
    _yz_log "Install options:"
    _yz_log "  - kerl:    https://github.com/kerl/kerl"
    _yz_log "  - asdf:    asdf plugin add erlang && asdf install erlang $_yz_desired_erlang"
    _yz_log "  - macOS:   brew install erlang@${_yz_desired_erlang%%.*}"
    _yz_log "  - Windows: https://www.erlang.org/downloads (installs to C:\\Program Files\\Erlang OTP\\)"
fi

_yz_cleanup
return 0
