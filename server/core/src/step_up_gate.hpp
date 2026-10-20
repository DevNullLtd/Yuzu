#pragma once

/// @file step_up_gate.hpp
///
/// The MFA step-up decision, split from its response rendering, plus the
/// request chokepoint that applies it to every route the policy table
/// (`step_up_policy.hpp`) classifies as kRequired.
///
///   decide_step_up()          PURE: reads the session and the MFA store, writes
///                             nothing (no response, no audit row, no metric).
///   render_step_up_refusal()  writes the refusal for one verdict onto one
///                             surface. `StepUpSurface` has NO default, so a new
///                             caller must say which wire shape it speaks.
///   apply_step_up_chokepoint() the pre-handler stage: table lookup, session
///                             resolution, decide, and on refusal the audit row,
///                             metric and rendered response. A thin caller,
///                             `run_pre_request_stage` in `step_up_wiring.hpp`,
///                             owns only the httplib Handled/Unhandled return.
///
/// `require_mfa_step_up` (`mfa_step_up.hpp`) is a thin wrapper over
/// decide + render. It differs from the pre-chokepoint gate in two ways: an engine principal is
/// denied first (`kEngineDenied`, 403), and every refusal sets `X-Correlation-Id`.
///
/// Because the chokepoint runs before the route handler, a refusal can be
/// answered ahead of the handler's own authorization and cross-site checks. The
/// audit rows it writes carry `stage=pre_authz` (last) so they can be told apart, and `cid=<id>`,
/// the same value as the response's `X-Correlation-Id`.
/// The decision is made per request and never cached across requests; the only
/// state is a one-request thread-local stash (see `detail::consume_step_up_pass`)
/// that lets the still-present in-handler `StepUpFn` skip a second store read.
///
/// Fail closed: a kRequired row with no usable auth store answers 503
/// (`kUnwired`), distinct from the 401 challenge and the 403 SAML refusal. That check precedes
/// the decision, so on an unwired store every caller class, an engine principal included, gets
/// the 503. With a wired store an engine principal is refused 403 (`kEngineDenied`, reason
/// `engine_principal_denied`) on every kRequired row before any RBAC grant is consulted and
/// without a store read.

#include "mfa_step_up.hpp"
#include "route_inventory.hpp"
#include "step_up_policy.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Which wire shape a refusal speaks. No default value on purpose.
enum class StepUpSurface : unsigned char {
    kRest,      // A4 JSON envelope, HTTP status carries the refusal; plus an HX-Trigger toast on
                // an htmx request (a dashboard control may call an /api/v1/ route)
    kDashboard, // as kRest (the surface differs only in the metric label)
    kMcp,       // JSON-RPC error body (HTTP 200); kPermissionDenied + data
};

enum class StepUpDecision : unsigned char {
    kPass,
    kChallenge,        // 401: proof stale or absent; client re-proves
    kSamlDenied,       // 403: SAML sessions cannot re-prove
    kStoreUnavailable, // 503: MFA status read failed with a store/decrypt outage
    kStatusFailed,     // 401: MFA status read failed for another reason (fail closed)
    kUnwired,          // 503: no auth store at all (fail closed)
    kUnsupportedClass, // 503: the row's class has no evaluator (fail closed)
    kEvaluationFailed, // 503: evaluating the row threw inside the chokepoint (fail closed)
    kEngineDenied,     // 403: an engine principal never satisfies a step-up-gated route
};

/// Everything render and the side-effect helper need, and nothing more.
struct StepUpVerdict {
    StepUpDecision decision{StepUpDecision::kPass};
    bool is_oidc{false};
    std::string user;       // session.username, for the audit detail
    long long age_secs{-1}; // -1: no usable proof
    int window_secs{0};

    [[nodiscard]] bool passed() const noexcept { return decision == StepUpDecision::kPass; }
};

using MfaStatusFn =
    std::function<std::expected<AuthDB::MfaStatus, AuthDBError>(const std::string& username)>;

using StepUpSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;

/// PURE decision. An engine principal (`session.is_engine()`) is refused (kEngineDenied) before
/// anything else, including the `window_secs <= 0` operator hatch and any store read. Otherwise
/// `window_secs <= 0` passes (the documented operator hatch).
[[nodiscard]] StepUpVerdict decide_step_up(const auth::Session& session,
                                           const MfaStatusFn& mfa_status, int window_secs,
                                           std::string_view mfa_enforcement);

/// Convenience over a concrete store.
[[nodiscard]] StepUpVerdict decide_step_up(const auth::Session& session, AuthDB& auth_db,
                                           int window_secs, std::string_view mfa_enforcement);

/// Writes the refusal for a non-passing verdict, and sets `X-Correlation-Id` to the same value as
/// the body's `correlation_id` (an upstream-set header is reused). `req` is read only (the
/// HX-Request header, which earns the toast on every surface but kMcp). Precondition:
/// `!verdict.passed()`.
void render_step_up_refusal(const httplib::Request& req, httplib::Response& res,
                            const StepUpVerdict& verdict, StepUpSurface surface);

/// The refusal's JSON-RPC `error` object, for an MCP caller that holds the request id and wraps
/// it itself. `render_step_up_refusal(.., kMcp)` wraps it with a null id. An empty
/// `correlation_id` mints one; the renderer passes the one it also sets as `X-Correlation-Id`.
[[nodiscard]] std::string step_up_refusal_json_rpc_error(const StepUpVerdict& verdict,
                                                         std::string_view correlation_id = {});

/// Side effects of a refusal, in the order the historical gate performed them: the
/// `mfa.step_up.required` audit row (an exception from `audit_fn` is swallowed and logged), the
/// fail-closed error log, and the store-outage counter. `detail_suffix` is appended to the audit
/// detail (the chokepoint passes ` cid=<correlation id> stage=pre_authz`; the in-handler callers
/// pass none). Precondition: `!verdict.passed()`.
void emit_step_up_refusal_effects(const httplib::Request& req, const StepUpVerdict& verdict,
                                  const StepUpAuditFn& audit_fn, const std::string& action_label,
                                  std::string_view detail_suffix, yuzu::MetricsRegistry* metrics);

/// Fail-closed 503 for an in-handler gate that finds no auth store: verdict kUnwired, audit,
/// metric and a kRest-shaped response, in one call.
void refuse_step_up_store_unwired(const httplib::Request& req, httplib::Response& res,
                                  const auth::Session& session, const StepUpAuditFn& audit_fn,
                                  const std::string& action_label, yuzu::MetricsRegistry* metrics);

/// Closed label set for the `source` dimension of `yuzu_auth_mfa_step_up_gate_total`; anything
/// outside the known auth sources maps to "other".
[[nodiscard]] std::string_view step_up_source_label(std::string_view auth_source) noexcept;

[[nodiscard]] std::string_view step_up_surface_label(StepUpSurface surface) noexcept;

/// `/api/v1/` is kRest, `/mcp/` is kMcp, everything else (dashboard fragments, `/api/settings/`)
/// is kDashboard.
[[nodiscard]] StepUpSurface step_up_surface_for_path(std::string_view path) noexcept;

/// Describes and pre-seeds `yuzu_auth_mfa_step_up_gate_total` for every closed-set label
/// combination so absence alerts stay meaningful.
void seed_step_up_gate_metrics(yuzu::MetricsRegistry& metrics);

/// Boot-time coverage sweep. Every mutating registration in `routes` that has no row in the policy
/// table, formatted `"METHOD pattern"`, in the order given. Empty means every mutating route is
/// classified and the server may serve. Pure.
[[nodiscard]] std::vector<std::string>
step_up_unclassified_registrations(const std::vector<RouteInventory::Route>& routes);

/// The same sweep over what `HttplibRouteSink` recorded for `server` (the web server the owners
/// registered on). `server_core` calls this after the last owner has registered and refuses to
/// start on a non-empty result.
[[nodiscard]] std::vector<std::string> step_up_unclassified_registrations(const void* server);

enum class StepUpChokepointResult : unsigned char {
    kNotApplicable, // no kRequired row for this request; nothing evaluated
    kPassed,        // evaluated and allowed; a pass stash is armed for this request
    kRefused,       // response written; the caller must stop
};

/// The points at which `StepUpChokepointDeps::fault_hook` is invoked.
enum class StepUpFaultPoint : unsigned char {
    kBeforeDecide,   // the session has resolved; the policy row is not yet evaluated
    kFallbackRender, // inside the exception fallback, immediately before its refusal is rendered
};

struct StepUpChokepointDeps {
    const StepUpSessionFn* resolve_session{nullptr};
    AuthDB* auth_db{nullptr};
    /// Test seam: when set it replaces `auth_db->mfa_status`, and counts as a wired store.
    const MfaStatusFn* mfa_status{nullptr};
    const StepUpAuditFn* audit_fn{nullptr};
    yuzu::MetricsRegistry* metrics{nullptr};
    int window_secs{0};
    std::string_view mfa_enforcement{"optional"};
    /// Test seam, null in production: called at each `StepUpFaultPoint` so a test can make the
    /// evaluation or the fallback's render throw. No effect when null.
    const std::function<void(StepUpFaultPoint)>* fault_hook{nullptr};
};

namespace detail {

/// Pure and testable, in the shape of `apply_engine_quota_gate`. Every allocation after the policy
/// lookup (the action label included) happens inside a try block: a throw while evaluating a gated
/// row is answered 503 (fail closed) with a best-effort audit row and metric, and its `what()` is
/// logged (sampled). Each step of that fallback is itself guarded, so no exception is expected to
/// escape. The function is deliberately NOT `noexcept`: that guarantee holds by construction, not
/// by the type, and if a later edit breaks it the caller's own handler in `server.cpp` answers
/// (413) instead of the process terminating. Keyed on `req.method` and `req.matched_route`, which
/// httplib sets to the registered pattern before the pre-request handler runs.
[[nodiscard]] StepUpChokepointResult apply_step_up_chokepoint(const httplib::Request& req,
                                                              httplib::Response& res,
                                                              const StepUpChokepointDeps& deps);

/// One request's pass stash. Written by the chokepoint on a pass, consumed by the in-handler
/// `StepUpFn`, and cleared by pre-routing (top), post-routing (end) and `consume_step_up_pass`,
/// so a value left by one request on a worker thread is not seen by the next. The request address
/// recorded here is NOT a unique key (successive requests on a worker thread can share a
/// `httplib::Request` address); what protects against a stale pass is those clears plus the
/// action-label match in `consume_step_up_pass`.
///
/// PR 2 deletes this stash, `consume_step_up_pass`, `finish_step_up_pass` and the
/// `handler_skipped` outcome together with the in-handler `StepUpFn` calls.
struct StepUpPassStash {
    const httplib::Request* req{nullptr};
    const StepUpPolicyEntry* row{nullptr};
    StepUpSurface surface{StepUpSurface::kRest};
    std::string_view source{"other"};
};
static_assert(std::is_trivially_destructible_v<StepUpPassStash>,
              "the thread_local stash must stay trivially destructible: it holds only pointers and "
              "views, and needs no destruction at thread exit");

[[nodiscard]] inline StepUpPassStash& tls_step_up_pass() {
    thread_local StepUpPassStash stash;
    return stash;
}

/// True (and the stash is cleared) iff the stash holds a pass for this request address and exactly
/// this action label (see `StepUpPassStash` for why the address alone is not enough).
[[nodiscard]] bool consume_step_up_pass(const httplib::Request& req,
                                        const std::string& action_label) noexcept;

inline void clear_step_up_pass() noexcept {
    tls_step_up_pass() = StepUpPassStash{};
}

/// Post-routing: an unconsumed stash on a 2xx response means the handler never ran its own gate
/// for a row the chokepoint passed; counted as outcome=handler_skipped (report-only). Always
/// clears the stash.
void finish_step_up_pass(const httplib::Request& req, const httplib::Response& res,
                         yuzu::MetricsRegistry* metrics) noexcept;

} // namespace detail

} // namespace yuzu::server
