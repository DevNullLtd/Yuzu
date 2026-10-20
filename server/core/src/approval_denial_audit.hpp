#pragma once

/// @file approval_denial_audit.hpp
/// The audit half of "a kPrecondition denial gets an audit row plus a counter"
/// (#6062). Only a redeemer that supplies a precondition can produce a denial, and
/// today that is the MCP recall alone (`confirm_engine_rotation`), which ALSO writes its
/// own `mcp.*` audit row: an MCP denial therefore leaves two rows. `ApprovalManager` counts the denial itself and calls the observer built
/// here; this header owns what the audit row says, so server.cpp wires one line and a
/// unit test can drive the real row against a real `AuditStore`.
///
/// Action `approval.precondition_denied`, `result=denied`, `principal` = who tried to
/// redeem, `target_id` = the approval id, `detail` = origin + the precondition's own
/// message. The ticket's `definition_id` / `scope_expression` are caller-supplied text
/// and are deliberately NOT in the detail (see `ConsumePrecondition`).
///
/// Written with `AuditStore::log` on its OWN lease, never `log_in_txn` on the
/// redeemer's connection: a denial is evidence about the attempt, not part of the
/// redeemer's mutation, and it must survive the redeemer rolling back.

#include "approval_manager.hpp"
#include "audit_store.hpp"

#include <chrono>
#include <functional>
#include <string>

namespace yuzu::server {

inline constexpr const char* kApprovalPreconditionDeniedAction = "approval.precondition_denied";

/// `store` is a provider rather than a pointer so the observer survives the audit store
/// being absent at the moment of the denial (no row, no crash; the denial counter still
/// counted). A store that is present but closed is not skipped here: `AuditStore::log`
/// fails it and counts the failure.
[[nodiscard]] inline PreconditionDenialObserver
make_precondition_denial_audit_observer(std::function<AuditStore*()> store) {
    return [store = std::move(store)](const PreconditionDenial& d) {
        AuditStore* audit = store ? store() : nullptr;
        // No `is_open()` test here: AuditStore::log refuses a closed store itself AND
        // counts it in yuzu_server_audit_emit_failed_total, which a pre-check would skip.
        if (audit == nullptr)
            return;
        AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = d.consumed_by;
        ev.action = kApprovalPreconditionDeniedAction;
        ev.target_type = "approval";
        ev.target_id = d.approval_id;
        ev.detail = std::string("origin=") + to_string(d.origin) +
                    " reason=" + d.reason.substr(0, 256) + " (ticket not consumed)";
        ev.result = "denied";
        (void)audit->log(ev);
    };
}

} // namespace yuzu::server
