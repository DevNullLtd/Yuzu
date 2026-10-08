#pragma once

/// @file gateway_peer_audit.hpp
/// The audit row the gateway-peer authorization code writes outside the denial path, built as a
/// pure function so its literals are testable (the server, which writes it, cannot be
/// constructed in a unit test).
///
///   * `server.gateway_peer_authz_disabled`: one row at boot when the operator acknowledged
///     running WITHOUT peer authorization (`--insecure-gateway-peer`), in either acknowledged
///     mode. System principal, result `success`, detail `mode=<mode label> tls=<true|false>`.
///     Same startup-posture shape as `server.viz_disabled` and `server.unsigned_packs_allowed`
///     (`target_id` names the feature).
///
/// The denial row (`session.gateway_peer_denied`) is built by the guard itself, where the
/// transport evidence is.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>

#include "audit_store.hpp"
#include "gateway_peer_resolution.hpp"

namespace yuzu::server::gateway_peer {

inline constexpr std::string_view kAuthzDisabledAuditAction = "server.gateway_peer_authz_disabled";

namespace detail {
[[nodiscard]] inline std::int64_t audit_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace detail

[[nodiscard]] inline AuditEvent make_authz_disabled_audit_event(AuthzMode mode, bool tls_enabled) {
    AuditEvent ev;
    ev.timestamp = detail::audit_now_seconds();
    ev.principal = "system";
    ev.action = std::string{kAuthzDisabledAuditAction};
    ev.target_type = "GatewayUpstream";
    ev.target_id = "peer_authorization";
    ev.detail = "mode=" + std::string{to_label(mode)} + " tls=" + (tls_enabled ? "true" : "false");
    ev.result = "success";
    return ev;
}

/// Writes `ev` through `log` when the audit store is open. When the row is NOT written (the store
/// is not open, `log` returned false, or `log` threw), a warning names the action and the cause:
/// a missing audit trail is a log line, never a silent skip. Returns whether the row was written.
/// Never throws.
[[nodiscard]] inline bool write_audit_row_or_warn(bool store_open,
                                                  const std::function<bool(const AuditEvent&)>& log,
                                                  const AuditEvent& ev) noexcept {
    const char* cause = nullptr;
    try {
        if (!store_open)
            cause = "the audit store is not open";
        else if (!log || !log(ev))
            cause = "the audit write failed";
        else
            return true;
    } catch (...) {
        cause = "the audit write failed (exception)";
    }
    try {
        spdlog::warn("gateway peer audit row '{}' was not written: {}", ev.action, cause);
    } catch (...) {
    }
    return false;
}

} // namespace yuzu::server::gateway_peer
