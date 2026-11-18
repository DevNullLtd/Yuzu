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

# _last_occurrence_distinct : stdin to stdout, each distinct line kept at its LAST position, so the
# tail that follows is the most RECENT distinct sessions (a first-occurrence filter would drop a
# session that registered early and again recently).
_last_occurrence_distinct() {
    awk '{ last[$0] = NR; line[NR] = $0 } END { for (i = 1; i <= NR; i++) if (last[line[i]] == i) print line[i] }'
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
                | sed 's/.*session=//' | _last_occurrence_distinct | tail -n "$_SESSION_FP_MAX_CANDIDATES")
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

# route_session_for_fp FP : the HA scripts' join, against the gateway route table. The CALLER
# defines psql_q (SQL -> tuples-only rows). Prints the ONE session id whose SHA-256 begins with FP;
# returns 1 with a message when FP is not 8 lowercase hex, the query fails, no row matches, or
# MORE THAN ONE row matches (a prefix collision is never resolved by picking one).
route_session_for_fp() {
    local fp="$1" rows n
    case "$fp" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
        *) echo "route_session_for_fp: '$fp' is not an 8-hex session_fp" >&2; return 1 ;;
    esac
    rows=$(psql_q "SELECT session_id FROM gateway_route_store.agent_routes WHERE encode(sha256(convert_to(session_id,'UTF8')),'hex') LIKE '$fp%' ORDER BY session_id") || {
        echo "route_session_for_fp: the route-table query failed (route table unreadable)" >&2
        return 1
    }
    rows=$(printf '%s\n' "$rows" | tr -d '\r' | grep -av '^[[:space:]]*$' || true)
    n=$(printf '%s' "$rows" | grep -ac '' || true)
    if [ "$n" -ne 1 ]; then
        echo "route_session_for_fp: session_fp=$fp matched $n route rows; exactly one is required" >&2
        return 1
    fi
    printf '%s\n' "$rows"
}
