# agent-session-fp.sh -- resolve an agent's session id WITHOUT reading it from the agent log.
#
# The agent logs "Registered with server (session_fp=<8 hex>, ...)": the first 8 hex of the
# SHA-256 of its session id (a bearer credential, F50 -- never log the id itself). The id is on
# the SERVER side: "[gateway] ProxyRegister succeeded: agent=<id>, session=<id>". A fingerprint
# is joined back to the id by hashing each server-side candidate. Sourced, not executed.
#
# Older agent builds log "(session=<id>, ...)" instead: agent_session_fp prints nothing for them,  # tripwire-allow: legacy-agent
# and agent_session_id_legacy returns that id, so a mixed-version fleet still resolves.
# grep -a throughout: a NUL byte in a log must not turn matches into "binary file matches".
# Logs written by a native Windows process end lines in CRLF: every parse strips CR first.

# _sha256_hex8 : read stdin, print the first 8 hex of its SHA-256. Fails LOUDLY (rc 127) when no
# hash tool exists -- a silent empty result would make every join miss.
_sha256_hex8() {
    local out
    if command -v sha256sum >/dev/null 2>&1; then
        out=$(sha256sum)
    elif command -v shasum >/dev/null 2>&1; then
        out=$(shasum -a 256)
    elif command -v openssl >/dev/null 2>&1; then
        out=$(openssl dgst -sha256 | sed 's/^.*= *//')
    else
        echo "agent-session-fp: no sha256sum, shasum or openssl on PATH; cannot join session_fp" >&2
        return 127
    fi
    printf '%s' "${out%% *}" | cut -c1-8
}

# agent_session_fp AGENT_LOG_FILE : the last session_fp= in the agent log, or empty
agent_session_fp() {
    [ -r "$1" ] || return 0
    tr -d '\r' < "$1" | grep -a "Registered with server" | grep -aoE 'session_fp=[0-9a-f]{8}' | tail -1 | cut -d= -f2 || true
}

# agent_session_id_legacy AGENT_LOG_FILE : the id from a pre-F50 agent's "session=<id>" Registered  # tripwire-allow: legacy-agent
# line, or empty
agent_session_id_legacy() {
    [ -r "$1" ] || return 0
    # tripwire-allow: legacy-agent (a pre-F50 agent's own line, kept for a mixed-version fleet)
    tr -d '\r' < "$1" | grep -a "Registered with server" | grep -aoE 'session=[^ ,)]+' | tail -1 | cut -d= -f2 || true  # tripwire-allow: legacy-agent
}

# session_for_fp FP : read server log text on stdin; print the session id whose SHA-256 begins
# with FP (the last match), or nothing. Returns non-zero (with a message) if no hash tool exists.
session_for_fp() {
    local fp="$1" s h found=""
    [ -n "$fp" ] || return 0
    while IFS= read -r s; do
        h=$(printf '%s' "$s" | _sha256_hex8) || return 127
        [ "$h" = "$fp" ] && found="$s"
    done < <(tr -d '\r' | grep -aoE 'ProxyRegister succeeded: agent=[^,]*, session=[^ ,)]+' | sed 's/.*session=//')
    [ -n "$found" ] && printf '%s\n' "$found"
    return 0
}

# resolve_agent_session AGENT_LOG SERVER_LOG_FILE : the session id for one agent, "unknown" if not
# found. A missing or unreadable server log is "unknown", never an abort.
resolve_agent_session() {
    local fp id=""
    fp=$(agent_session_fp "$1")
    if [ -n "$fp" ] && [ -r "$2" ]; then
        id=$(session_for_fp "$fp" < "$2") || true
    fi
    [ -n "$id" ] || id=$(agent_session_id_legacy "$1")
    printf '%s\n' "${id:-unknown}"
}
