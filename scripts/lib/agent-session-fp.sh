# agent-session-fp.sh -- resolve an agent's session id WITHOUT reading it from the agent log.
#
# The agent logs "Registered with server (session_fp=<8 hex>, ...)": the first 8 hex of the
# SHA-256 of its session id (a bearer credential, F50 -- never log the id itself). The id is on
# the SERVER side: "[gateway] ProxyRegister succeeded: agent=<id>, session=<id>". A fingerprint
# is joined back to the id by hashing each server-side candidate. Sourced, not executed.

# agent_session_fp AGENT_LOG_FILE : the last session_fp= in the agent log, or empty
agent_session_fp() {
    grep "Registered with server" "$1" 2>/dev/null | grep -oE 'session_fp=[0-9a-f]{8}' | tail -1 | cut -d= -f2
}

# session_for_fp FP : read server log text on stdin; print the session id whose SHA-256 begins
# with FP (the last match), or nothing.
session_for_fp() {
    local fp="$1" s found=""
    [ -n "$fp" ] || return 0
    while IFS= read -r s; do
        [ "$(printf '%s' "$s" | sha256sum | cut -c1-8)" = "$fp" ] && found="$s"
    done < <(grep -oE 'ProxyRegister succeeded: agent=[^,]*, session=[^ ,)]+' | sed 's/.*session=//')
    [ -n "$found" ] && printf '%s\n' "$found"
    return 0
}
