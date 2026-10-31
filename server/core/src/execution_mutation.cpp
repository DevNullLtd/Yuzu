#include "execution_mutation.hpp"

#include "execution_scope_rules.hpp"

#include <yuzu/log_token.hpp>

#include <exception>
#include <utility>

namespace yuzu::server {

namespace {

/// A throwing sink is a failed write, never an escape (a thrown audit would otherwise skip the
/// refusal and surface as a bare 500 after, or instead of, the decision).
bool write_audit(const ExecutionMutationAuditFn& audit, const char* action,
                 const std::string& result, const std::string& target, const std::string& detail) {
    if (!audit)
        return true; // audit-off deployment: not a persistence failure (AuditFn contract)
    try {
        return audit(action, result, target, detail);
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

std::string with_context(std::string detail, const std::string& context) {
    if (!context.empty()) {
        if (!detail.empty())
            detail += ' ';
        detail += context;
    }
    return detail;
}

} // namespace

const char* execution_mutation_audit_action(ExecutionMutation what) {
    return what == ExecutionMutation::kCancel ? "execution.cancel" : "execution.rerun";
}

bool is_valid_execution_id(const std::string& id) {
    if (id.empty() || id.size() > 128)
        return false;
    for (const unsigned char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

ExecutionMutationPorts make_tracker_mutation_ports(ExecutionTracker* tracker) {
    ExecutionMutationPorts p;
    if (!tracker)
        return p;
    p.get_execution = [tracker](const std::string& id) {
        return tracker->get_execution_checked(id);
    };
    p.get_statuses = [tracker](const std::string& id) {
        return tracker->get_agent_statuses_checked(id);
    };
    p.mark_cancelled = [tracker](const std::string& id, const std::string& user) {
        return tracker->mark_cancelled_checked(id, user);
    };
    p.create_rerun = [tracker](const std::string& id, const std::string& user, bool failed_only) {
        return tracker->create_rerun(id, user, failed_only);
    };
    return p;
}

ExecutionMutationOutcome apply_execution_mutation(const ExecutionMutationPorts& ports,
                                                  const ExecutionMutationRequest& req,
                                                  const ExecutionMutationAuditFn& audit) {
    using Status = ExecutionMutationStatus;
    ExecutionMutationOutcome out;
    const char* const action = execution_mutation_audit_action(req.what);
    const std::string& id = req.execution_id;
    const std::string safe_id = ::yuzu::log_token(id);

    // 1. No principal, no mutation. Not audited: there is nobody to attribute the row to.
    if (req.username.empty() || !ports.wired()) {
        out.status = req.username.empty() ? Status::kNoPrincipal : Status::kStoreDegraded;
        return out;
    }

    // 2. Unconditional reads (a confined caller must not be able to tell a nonexistent id from a
    //    hidden one by the number of store round trips).
    auto exec_r = ports.get_execution(id);
    if (!exec_r) {
        out.status = Status::kStoreDegraded;
        return out;
    }
    const std::optional<Execution>& exec_opt = *exec_r;

    bool admitted = false;
    if (req.scope) {
        auto statuses = ports.get_statuses(id);
        if (!statuses) {
            out.status = Status::kStoreDegraded;
            return out;
        }
        admitted = exec_opt.has_value() &&
                   admit_confined_mutation(*exec_opt, *statuses, req.scope, req.username);
        if (!admitted) {
            // One deny shape for nonexistent, zero-visible, partial and incomplete-cohort: a
            // distinct status or detail for "partial visibility" would be a hidden-cohort
            // oracle (#3789). The row says so without saying which.
            (void)write_audit(audit, action, "denied", id,
                              with_context("not found or outside caller's fleet-read scope",
                                           req.audit_context));
            out.status = Status::kNotFound;
            return out;
        }
    } else {
        // Unconfined: nothing is hidden, so an unknown id is an ordinary not-found, not a
        // confinement decision, and writes no row (same as the read twins).
        if (!exec_opt) {
            out.status = Status::kNotFound;
            return out;
        }
    }

    // 4. Evidence BEFORE the effect. Not durable -> the effect does not happen.
    std::string attempt_detail =
        req.what == ExecutionMutation::kRerun
            ? std::string("failed_only=") + (req.failed_only ? "true" : "false")
            : std::string{};
    if (!write_audit(audit, action, "attempted", id,
                     with_context(std::move(attempt_detail), req.audit_context))) {
        out.status = Status::kAuditFailed;
        return out;
    }

    // 5. The effect, then the outcome row.
    if (req.what == ExecutionMutation::kCancel) {
        using Outcome = ExecutionTracker::MarkCancelledOutcome;
        switch (ports.mark_cancelled(id, req.username)) {
        case Outcome::kFailed:
            out.audit_persisted = write_audit(audit, action, "failure", id,
                                              with_context("store write failed", req.audit_context));
            out.status = Status::kStoreFailed;
            return out;
        case Outcome::kNoOp:
            out.audit_persisted =
                write_audit(audit, action, "denied", id,
                            with_context("already finished (no state change)", req.audit_context));
            out.status = Status::kAlreadyFinished;
            return out;
        case Outcome::kCancelled:
            break;
        }
        out.audit_persisted = write_audit(audit, action, "success", id, req.audit_context);
        out.status = Status::kDone;
        return out;
    }

    auto rerun = ports.create_rerun(id, req.username, req.failed_only);
    if (!rerun) {
        // The store's text is never echoed (it can carry internals). "original execution not
        // found" can only mean the row vanished after the admission read above.
        const bool vanished = rerun.error() == "original execution not found";
        out.audit_persisted =
            write_audit(audit, action, vanished ? "denied" : "failure", id,
                        with_context(vanished ? "original execution no longer exists"
                                              : "store write failed",
                                     req.audit_context));
        out.status = vanished ? Status::kNotFound : Status::kStoreFailed;
        return out;
    }
    out.new_execution_id = *rerun;
    out.audit_persisted = write_audit(
        audit, action, "success", *rerun,
        with_context("rerun of " + safe_id + " failed_only=" + (req.failed_only ? "true" : "false"),
                     req.audit_context));
    out.status = Status::kDone;
    return out;
}

} // namespace yuzu::server
