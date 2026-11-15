#include "execution_mutation.hpp"

#include "execution_scope_rules.hpp"

#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

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
        return tracker->create_rerun_checked(id, user, failed_only);
    };
    return p;
}

ExecutionMutationOutcome apply_execution_mutation(const ExecutionMutationPorts& ports,
                                                  const ExecutionMutationRequest& req,
                                                  const ExecutionMutationAuditFn& audit,
                                                  const EventEmitHook& emit) {
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
            // ca8-2: the surfaces signal a lost row (Sec-Audit-Failed / audit_persisted:false),
            // so the result is carried on the outcome rather than dropped.
            out.audit_persisted =
                write_audit(audit, action, "denied", id,
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

    // 5. The effect, then the outcome row. A throwing effect (std::exception or not) leaves its
    //    outcome UNKNOWN (the write may or may not have landed), so it is a `failure` row and a
    //    distinct status that carries no retry hint: it is never reported as the benign
    //    "store failed, nothing changed" of kStoreFailed.
    // Built BEFORE the effect: an allocation failure here happens while nothing has changed yet,
    // and the failure row below then needs no allocation of its own.
    const std::string threw_detail = with_context("effect threw; outcome unknown", req.audit_context);
    const auto effect_threw = [&] {
        out.audit_persisted = write_audit(audit, action, "failure", id, threw_detail);
        out.status = Status::kEffectThrew;
        return out;
    };
    if (req.what == ExecutionMutation::kCancel) {
        using Outcome = ExecutionTracker::MarkCancelledOutcome;
        Outcome cancelled = Outcome::kFailed;
        // The handlers only note that the effect threw; the failure row (whose detail string
        // allocates) is built AFTER the handler, so a second throw while building it cannot
        // escape a catch block with no `failure` row written.
        bool threw = false;
        try {
            cancelled = ports.mark_cancelled(id, req.username);
        } catch (const std::exception& e) {
            spdlog::error("execution mutation: cancel effect threw for execution_id={}: {}",
                          safe_id, e.what());
            threw = true;
        } catch (...) {
            spdlog::error("execution mutation: cancel effect threw a non-standard exception for "
                          "execution_id={}",
                          safe_id);
            threw = true;
        }
        if (threw)
            return effect_threw();
        switch (cancelled) {
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
        // The legacy cancel route's event (execution_routes.cpp), after the evidence row.
        emit_event_guarded(emit, "execution.completed", nlohmann::json{{"status", "cancelled"}},
                           nlohmann::json{{"execution_id", id}});
        return out;
    }

    using RerunError = ExecutionTracker::RerunError;
    std::expected<std::string, RerunError> rerun = std::unexpected(RerunError::kWriteFailed);
    bool rerun_threw = false; // see the cancel arm: the failure row is built outside the handler
    try {
        rerun = ports.create_rerun(id, req.username, req.failed_only);
    } catch (const std::exception& e) {
        spdlog::error("execution mutation: rerun effect threw for execution_id={}: {}", safe_id,
                      e.what());
        rerun_threw = true;
    } catch (...) {
        spdlog::error("execution mutation: rerun effect threw a non-standard exception for "
                      "execution_id={}",
                      safe_id);
        rerun_threw = true;
    }
    if (rerun_threw)
        return effect_threw();
    if (!rerun) {
        // The store's text is never echoed (it can carry internals). kOriginalNotFound can only
        // mean the row vanished after the admission read above; an unreadable store is its own
        // typed outcome (fail closed: unavailable, never a not-found).
        switch (rerun.error()) {
        case RerunError::kOriginalNotFound:
            out.audit_persisted =
                write_audit(audit, action, "denied", id,
                            with_context("original execution no longer exists", req.audit_context));
            out.status = Status::kNotFound;
            return out;
        case RerunError::kStoreDegraded:
            out.audit_persisted = write_audit(
                audit, action, "failure", id,
                with_context("store unreadable; nothing was created", req.audit_context));
            out.status = Status::kStoreDegraded;
            return out;
        case RerunError::kWriteFailed:
            out.audit_persisted = write_audit(audit, action, "failure", id,
                                              with_context("store write failed", req.audit_context));
            out.status = Status::kStoreFailed;
            return out;
        }
        out.status = Status::kStoreFailed; // unreachable: closed enum
        return out;
    }
    out.new_execution_id = *rerun;
    out.audit_persisted = write_audit(
        audit, action, "success", *rerun,
        with_context("rerun of " + safe_id + " failed_only=" + (req.failed_only ? "true" : "false"),
                     req.audit_context));
    out.status = Status::kDone;
    // The legacy rerun route's event (execution_routes.cpp), after the evidence row.
    emit_event_guarded(emit, "execution.created", nlohmann::json(),
                       nlohmann::json{{"execution_id", *rerun}, {"parent_id", id}, {"trigger", "rerun"}});
    return out;
}

} // namespace yuzu::server
