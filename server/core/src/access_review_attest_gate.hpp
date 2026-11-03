#pragma once

/// @file access_review_attest_gate.hpp
///
/// The reviewer-differs-from-the-subject rule for Periodic Access Reviews (SOC 2 CC6.2, #4752),
/// shared by `POST /api/v1/access-reviews/{id}/attestations` and the MCP tool `record_attestation`
/// so the two surfaces refuse with ONE message, ONE audit row shape and ONE counter. EXTEND this
/// header, never fork a per-surface copy (a second copy is how the surfaces drift apart).
///
/// Who may not decide a grant, by the grant's `principal_type`:
///   * `user`   : the reviewer IS the subject (`session->username == principal_id`, byte-exact, the
///                same comparison `ApprovalManager::same_human_root` makes). `AccessReviewStore`
///                also refuses this inside the write (a `forbidden:` result), so the rule holds
///                even for a caller that skips this gate; `sod_from_store_error` maps that result
///                onto the same refusal.
///   * `engine` : the reviewer OWNS the engine principal (`EnginePrincipalRow::owner_username`),
///                revoked engines included. An engine id with no row is an orphan grant and is
///                admitted (there is no owner to compare against).
///   * `group`  : the reviewer is a MEMBER of the group (`group_members`, which IdP login
///                reconciliation also writes). A group with no row, or one the reviewer is not in,
///                is admitted.
///
/// THE WINDOW (stated honestly). The engine-owner and group-member rules are decided by a READ
/// here, before the store's write transaction. ADR-0012 s2(c) forbids a store method from calling
/// another store while it holds a lease, so the owning stores cannot be consulted inside the attest
/// transaction. The window therefore runs from this read to the attest COMMIT: a pool acquire of up
/// to the store's write budget plus a row-lock wait, normally milliseconds but not a bound this
/// file can promise. An ownership transfer or membership change that lands inside it is not seen,
/// and there is no re-read after the commit. Membership can be changed by the reviewer's own SSO
/// login. The user rule has no such window (it is decided in C++ from the arguments, before any
/// lease; the UPDATE predicate and the history CHECK are backstops). Revisit under #6060.
///
/// Both lookups FAIL CLOSED: a failed or unavailable read is `kUnavailable` (503 / retryable),
/// never "not a member" and never "not the owner". `get_group_members` is deliberately not used: it
/// collapses a read failure into an empty vector.
///
/// Identities: `Session::username` is the stable principal (a local name, `oidc:<iss>#<sub>`,
/// `saml:...`); a token session carries its owner's. Two identities of one human are two reviewers
/// (the accepted exception recorded in docs/enterprise-readiness-soc2-first-customer.md).
///
/// Audit shape, ONE for every outcome of the verb that reaches this gate or the store
/// (`access_review.attested` or `access_review.flagged`, by the requested decision; the REST
/// refusal of an engine session and of a non-JSON body run earlier and carry an empty
/// `target_id`): `target_type=AccessReview`, `target_id` =
/// the campaign id alone, and the grant tuple in the detail as
/// ` principal_type=<tok> principal_id=<tok> role=<tok>` after the outcome fields. Each tuple field
/// goes through `audit_token` (CWE-117), which folds a space, so a REFUSAL row (there is no history
/// row to recover the exact tuple from) can read the same for two distinct raw ids that fold to one
/// token. That collision is a DISCLOSED residual and applies to success rows too: `seq` numbers
/// decisions per grant, so the campaign id and the grant identify one history entry unless two
/// grants fold to the same text.
///
/// A refusal is written BEFORE its response body. A failed audit persist never lifts the refusal:
/// REST sets `Sec-Audit-Failed: true`, MCP puts `audit_persisted:false` in the error data. The
/// refusal's 403 deliberately names no `.permission`: the caller already holds
/// `AccessReview:Attest`, so naming it would claim a self-remediation grant that cannot help
/// (the service-scope row's clause 5).

#include "engine_principal_store.hpp"
#include "mcp_jsonrpc.hpp" // kPermissionDenied / kInternalError
#include "mcp_retry.hpp"   // kMcpStoreFaultRetryMs
#include "rbac_store.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp" // try_persist_audit / emit_behavioral_audit
#include "web_utils.hpp"  // audit_token, flatten_audit_text

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::access_review_sod {

/// Which transport is attesting. No default anywhere it is a parameter: the label feeds the
/// refusal counter, so a caller must say which surface it is.
enum class AttestSurface : unsigned char { kRest, kMcp };

enum class SodOutcome { kPass, kSelfSubject, kEngineOwner, kGroupMember, kUnavailable };

struct SodVerdict {
    SodOutcome outcome{SodOutcome::kPass};
    std::string store; ///< "engine" or "rbac" for kUnavailable, empty otherwise
};

/// Self-contained: the browser renders only `error.message`, so the instruction to find another
/// reviewer cannot live in a separate remediation field alone.
inline constexpr std::string_view kSodMessage =
    "the reviewer must differ from the subject of this grant; ask another reviewer to record this "
    "decision";
inline constexpr std::string_view kSodRemediation = "ask another reviewer to record this decision";
inline constexpr std::string_view kSodUnavailableMessage =
    "could not confirm that the reviewer differs from the subject of this grant; no decision was "
    "recorded";
inline constexpr std::string_view kSodUnavailableRemediation = "retry the request";

/// `retry_after_ms` for the check-unavailable answer, REST and MCP alike.
inline constexpr std::int64_t kSodUnavailableRetryMs = mcp::kMcpStoreFaultRetryMs;

/// How a store error string is answered, REST and MCP alike. The store marks a client or business
/// refusal with a machine-checkable prefix; anything else is a genuine read/write fault the caller
/// did not cause. ONE classifier: `access_review_error_status` (REST) and
/// `mcp_error_for_access_review_msg` (MCP) both delegate here so the two cannot disagree, and a
/// test pins every string the store returns.
enum class StoreErrorClass { kNotFound, kBadRequest, kForbidden, kTransient };

[[nodiscard]] inline StoreErrorClass classify_store_error(std::string_view err) {
    if (err.starts_with("not_found:"))
        return StoreErrorClass::kNotFound;
    if (err.starts_with("bad_request:"))
        return StoreErrorClass::kBadRequest;
    if (err.starts_with("forbidden:"))
        return StoreErrorClass::kForbidden;
    return StoreErrorClass::kTransient;
}

[[nodiscard]] inline int store_error_http_status(StoreErrorClass c) {
    switch (c) {
    case StoreErrorClass::kNotFound:
        return 404;
    case StoreErrorClass::kBadRequest:
        return 400;
    case StoreErrorClass::kForbidden:
        return 403;
    case StoreErrorClass::kTransient:
        break;
    }
    return 503;
}

[[nodiscard]] inline int store_error_jsonrpc_code(StoreErrorClass c) {
    switch (c) {
    case StoreErrorClass::kNotFound:
    case StoreErrorClass::kBadRequest:
        return mcp::kInvalidParams;
    case StoreErrorClass::kForbidden:
        return mcp::kPermissionDenied;
    case StoreErrorClass::kTransient:
        break;
    }
    return mcp::kInternalError;
}

/// What a caller is told when the store fails to record a decision for a reason that is not the
/// caller's (a lease timeout, a query error, a lost COMMIT acknowledgement). Fixed text: the raw
/// store error can carry `PQerrorMessage` output (relation, constraint and trigger names, CONTEXT
/// lines), which is logged server-side and never returned. A lost COMMIT may have committed the
/// decision, so the message tells the caller to read before retrying.
inline constexpr std::string_view kStoreFailureMessage =
    "the decision store is unavailable or the decision may not have been committed; read the "
    "campaign and compare decision_seq before retrying";
inline constexpr std::string_view kStoreFailureRemediation =
    "read the campaign and compare decision_seq before retrying";

/// `retry_after_ms` for the store-failure answer, the same constant the check-unavailable answer
/// uses.
inline constexpr std::int64_t kStoreFailureRetryMs = kSodUnavailableRetryMs;

/// Longest slice of the raw store error handed to `log_key_token`, which itself shortens to its own
/// cap (`kGuardianLogIdMaxBytes`, 256 bytes): the same number, so the line carries at most 256.
inline constexpr std::size_t kStoreFailureLogMaxBytes = ::yuzu::kGuardianLogIdMaxBytes;

/// Write the raw store error to the server log (bounded, control bytes neutralised so it cannot
/// forge a log line). The campaign id is validated before the store is reached.
inline void log_store_failure(std::string_view campaign_id, std::string_view surface,
                              std::string_view err) {
    const std::string_view head = err.substr(0, kStoreFailureLogMaxBytes);
    spdlog::warn("access review attestation store failure: surface={} campaign={} error='{}'",
                 surface, campaign_id, ::yuzu::log_key_token(head));
}

/// The failure audit row's detail: the fixed message plus the grant tuple. Never the raw error.
[[nodiscard]] inline std::string store_failure_audit_detail(const std::string& tuple_detail) {
    std::string out{kStoreFailureMessage};
    out += tuple_detail;
    return out;
}

/// The wire-neutral answer for one non-pass outcome.
struct SodRefusal {
    int http_status{0};
    int jsonrpc_code{0};
    std::string_view message;
    std::string_view remediation;
    std::optional<std::int64_t> retry_after_ms; ///< set only for kUnavailable
    std::string_view audit_result;              ///< "denied" | "failure"
    std::string_view audit_detail;              ///< fixed token; kUnavailable appends " store=..."
    std::string_view reason;                    ///< the `reason` label of the refusal counter
};

[[nodiscard]] inline SodRefusal sod_refusal_for(SodOutcome outcome) {
    switch (outcome) {
    case SodOutcome::kEngineOwner:
        return {403,      mcp::kPermissionDenied, kSodMessage,   kSodRemediation, std::nullopt,
                "denied", "sod_engine_owner",     "engine_owner"};
    case SodOutcome::kGroupMember:
        return {403,      mcp::kPermissionDenied, kSodMessage,   kSodRemediation, std::nullopt,
                "denied", "sod_group_member",     "group_member"};
    case SodOutcome::kUnavailable:
        return {503,
                mcp::kInternalError,
                kSodUnavailableMessage,
                kSodUnavailableRemediation,
                kSodUnavailableRetryMs,
                "failure",
                "sod_check_unavailable",
                "check_unavailable"};
    case SodOutcome::kSelfSubject:
    case SodOutcome::kPass: // not a refusal; never asked for one, answered as the safest refusal
        break;
    }
    return {403,      mcp::kPermissionDenied, kSodMessage,   kSodRemediation, std::nullopt,
            "denied", "sod_self_subject",     "self_subject"};
}

/// The store's in-write refusal (`forbidden:`) is the user rule, caught after the gate: map it onto
/// the same outcome so the wire answer is byte-identical. `nullopt` for any other store error.
[[nodiscard]] inline std::optional<SodOutcome> sod_from_store_error(std::string_view err) {
    if (classify_store_error(err) == StoreErrorClass::kForbidden)
        return SodOutcome::kSelfSubject;
    return std::nullopt;
}

/// Decide whether `reviewer` may record a decision on this grant. The user rule needs no store;
/// the engine and group rules read the owning store (see the window note above). A null store
/// pointer for a type that needs it is `kUnavailable`, never a pass.
[[nodiscard]] inline SodVerdict evaluate_attestation_sod(std::string_view reviewer,
                                                         std::string_view principal_type,
                                                         const std::string& principal_id,
                                                         const EnginePrincipalStore* engine_store,
                                                         const RbacStore* rbac_store) {
    if (principal_type == "user") {
        if (reviewer == principal_id)
            return {SodOutcome::kSelfSubject, {}};
        return {};
    }
    if (principal_type == "engine") {
        if (!engine_store)
            return {SodOutcome::kUnavailable, "engine"};
        const auto row = engine_store->get(principal_id);
        if (!row)
            return {SodOutcome::kUnavailable, "engine"};
        if (*row && (*row)->owner_username == reviewer)
            return {SodOutcome::kEngineOwner, {}};
        return {}; // an orphan engine id (no row) has no owner to compare against
    }
    if (principal_type == "group") {
        if (!rbac_store)
            return {SodOutcome::kUnavailable, "rbac"};
        const auto groups = rbac_store->user_rbac_group_names_checked(std::string(reviewer));
        if (!groups)
            return {SodOutcome::kUnavailable, "rbac"};
        if (std::ranges::find(*groups, principal_id) != groups->end())
            return {SodOutcome::kGroupMember, {}};
        return {};
    }
    return {}; // an unknown type is the store's not_found, not a separation-of-duties question
}

/// The audit verb for the requested decision, as the handlers always chose it.
[[nodiscard]] inline std::string attest_audit_action(std::string_view decision) {
    return decision == "flagged_revoke" ? "access_review.flagged" : "access_review.attested";
}

/// ` principal_type=<tok> principal_id=<tok> role=<tok>`: the grant tuple appended to every
/// attestation audit detail (the target id is the campaign alone). CWE-117 via `audit_token`.
[[nodiscard]] inline std::string attest_tuple_detail(std::string_view principal_type,
                                                     std::string_view principal_id,
                                                     std::string_view role_name) {
    std::string out = " principal_type=";
    out += audit_token(principal_type);
    out += " principal_id=";
    out += audit_token(principal_id);
    out += " role=";
    out += audit_token(role_name);
    return out;
}

/// `decision=<d> previous=<pending|attested|flagged_revoke|-> seq=<n> sod=pass` + the tuple. An
/// empty `previous` (not recorded) prints `-`.
[[nodiscard]] inline std::string attest_success_detail(std::string_view decision,
                                                       std::string_view previous, std::int32_t seq,
                                                       const std::string& tuple_detail) {
    std::string out = "decision=";
    out += decision;
    out += " previous=";
    out += previous.empty() ? std::string_view{"-"} : previous;
    out += " seq=";
    out += std::to_string(seq);
    out += " sod=pass";
    out += tuple_detail;
    return out;
}

/// The refusal audit detail: the fixed token (kUnavailable adds the failing store) + the tuple.
[[nodiscard]] inline std::string sod_refusal_detail(const SodVerdict& verdict,
                                                    const SodRefusal& refusal,
                                                    const std::string& tuple_detail) {
    std::string out{refusal.audit_detail};
    if (verdict.outcome == SodOutcome::kUnavailable && !verdict.store.empty()) {
        out += " store=";
        out += verdict.store;
    }
    out += tuple_detail;
    return out;
}

/// Write the refusal audit row and bump `yuzu_access_review_attestation_refused_total` for BOTH
/// surfaces. Returns the persist outcome (true also when audit is off) so the caller can surface a
/// dropped row on its own channel. The counter moves whether or not the row persisted; `metrics`
/// may be null. Written BEFORE the caller's response body.
template <class AuditFn>
[[nodiscard]] inline bool
audit_and_count_refusal(const AuditFn& audit_fn, const httplib::Request& req,
                        yuzu::MetricsRegistry* metrics, AttestSurface surface,
                        const SodVerdict& verdict, const std::string& audit_action,
                        const std::string& campaign_id, const std::string& tuple_detail) {
    const SodRefusal refusal = sod_refusal_for(verdict.outcome);
    if (metrics) {
        metrics
            ->counter("yuzu_access_review_attestation_refused_total",
                      {{"surface", surface == AttestSurface::kRest ? "rest" : "mcp"},
                       {"reason", std::string(refusal.reason)}})
            .increment();
    }
    return detail::try_persist_audit(audit_fn, req, audit_action, std::string(refusal.audit_result),
                                     "AccessReview", campaign_id,
                                     sod_refusal_detail(verdict, refusal, tuple_detail));
}

/// REST answer for a refusal: the status, an A4 body with the remediation (and `retry_after_ms`
/// for kUnavailable) and NO `.permission`, plus `Sec-Audit-Failed` when the refusal row did not
/// persist. The refusal stands either way.
inline void write_rest_refusal(httplib::Response& res, SodOutcome outcome, bool audit_persisted) {
    const SodRefusal refusal = sod_refusal_for(outcome);
    res.status = refusal.http_status;
    if (!audit_persisted && !res.has_header("Sec-Audit-Failed"))
        res.set_header("Sec-Audit-Failed", "true");
    res.set_content(detail::a4_error(res, refusal.message,
                                     detail::A4ErrorOpts{.retry_after_ms = refusal.retry_after_ms,
                                                         .remediation = refusal.remediation}),
                    "application/json");
}

} // namespace yuzu::server::access_review_sod
