#pragma once

/**
 * session_log_fingerprint.hpp - the only form in which the server-issued session id may appear
 * in the agent log (#8159, CWE-532).
 *
 * The session id is the bearer proof of agent identity on Heartbeat and ReportInventory, and the
 * agent log tail is readable through agent_logging.get_log and stored in the response store. So
 * the id is never logged: a short, non-reversible fingerprint (first 8 hex of its SHA-256) lets
 * an operator correlate two log lines without disclosing the credential.
 */

#include "sync_canonical.hpp" // sha256_hex

#include <string>

namespace yuzu::agent {

[[nodiscard]] inline std::string session_log_fingerprint(const std::string& session_id) {
    if (session_id.empty())
        return "none";
    return sha256_hex(session_id).substr(0, 8);
}

} // namespace yuzu::agent
