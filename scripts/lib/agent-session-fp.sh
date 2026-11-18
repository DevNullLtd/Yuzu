# shellcheck shell=bash
# agent-session-fp.sh -- resolve an agent's session id WITHOUT reading it from the agent log.
#
# The agent logs "Registered with server (session_fp=<8 hex>, ...)": the first 8 hex of the
# SHA-256 of its session id (a bearer credential, #8159 -- never log the id itself). The id is on
# the SERVER side: "[gateway] ProxyRegister succeeded: agent=<id>, session=<id>". A fingerprint
# is joined back to the id by hashing the server-side candidates. Sourced, not executed.
#
# There is no other source: a Registered line without session_fp is an error, not "unknown".
# grep -a throughout: a NUL byte in a log must not turn matches into "binary file matches".
# Logs written by a native Windows process end lines in CRLF: every parse strips CR first.

# Server-side candidates examined for a join: the agent registered recently, so only the most
# recent distinct sessions are hashed (one fork each; bounds the cost on a very large log).
_SESSION_FP_MAX_CANDIDATES=200

# _sha256_hex8 : read stdin, print the first 8 hex of its SHA-256. Fails LOUDLY (rc 127) when
# neither sha256sum nor shasum exists -- a silent empty result would make every join miss.
_sha256_hex8() {
    local out
    if command -v sha256sum >/dev/null 2>&1; then
        out=$(sha256sum)
    elif command -v shasum >/dev/null 2>&1; then
        out=$(shasum -a 256)
    else
        echo "agent-session-fp: neither sha256sum nor shasum is on PATH; cannot join session_fp" >&2
        return 127
    fi
    printf '%s' "${out%% *}" | cut -c1-8
}

# agent_session_fp AGENT_LOG_FILE : the last session_fp= on a Registered line, or empty
agent_session_fp() {
    [ -r "$1" ] || return 0
    tr -d '\r' < "$1" | grep -a "Registered with server" | grep -aoE 'session_fp=[0-9a-f]{8}' | tail -1 | cut -d= -f2 || true
}

# session_for_fp FP : read server log text on stdin; print the session id whose SHA-256 begins
# with FP (the last match among the most recent distinct candidates), or nothing. Returns
# non-zero (with a message) if no hash tool exists.
session_for_fp() {
    local fp="$1" s h found=""
    [ -n "$fp" ] || return 0
    while IFS= read -r s; do
        h=$(printf '%s' "$s" | _sha256_hex8) || return 127
        [ "$h" = "$fp" ] && found="$s"
    done < <(tr -d '\r' | grep -aoE 'ProxyRegister succeeded: agent=[^,]*, session=[^ ,)]+' \
                | sed 's/.*session=//' | awk '!seen[$0]++' | tail -n "$_SESSION_FP_MAX_CANDIDATES")
    [ -n "$found" ] && printf '%s\n' "$found"
    return 0
}

# resolve_agent_session AGENT_LOG SERVER_LOG_FILE : print the session id for one agent.
# Returns 1 with a message when the agent log has no session_fp on its Registered line (never a
# silent "unknown"); returns 2 with a message when the fingerprint matches no server-side session
# (or the server log is missing); 127 when no hash tool exists.
resolve_agent_session() {
    local fp id rc=0
    fp=$(agent_session_fp "$1")
    if [ -z "$fp" ]; then
        echo "resolve_agent_session: no session_fp on a 'Registered with server' line in $1" >&2
        return 1
    fi
    if [ ! -r "$2" ]; then
        echo "resolve_agent_session: server log $2 is not readable" >&2
        return 2
    fi
    id=$(session_for_fp "$fp" < "$2") || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    if [ -z "$id" ]; then
        echo "resolve_agent_session: no ProxyRegister session matches session_fp=$fp in $2 (only the most recent $_SESSION_FP_MAX_CANDIDATES distinct sessions are examined)" >&2
        return 2
    fi
    printf '%s\n' "$id"
}
