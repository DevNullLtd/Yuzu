/// @file step_up_gate.cpp: see step_up_gate.hpp for the contract.

#include "step_up_gate.hpp"

#include "mcp_jsonrpc.hpp"
#include "on_behalf_guard.hpp" // onbehalf::sanitize_for_log
#include "rest_a4_envelope_http.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <string>

namespace yuzu::server {

namespace {

// The wire text of one refusal. Shared by the REST/dashboard envelope, the toast and the MCP
// error so the three can never drift apart.
struct RefusalText {
    int http_status{};
    std::string_view message;
    std::string_view remediation;
    std::string_view challenge_url; // empty: the envelope carries no challenge_url
    bool mfa_step_up_required{};
};

RefusalText refusal_text(const StepUpVerdict& v) {
    switch (v.decision) {
    case StepUpDecision::kSamlDenied:
        return {403,
                "MFA step-up is not available for SAML sessions in this release",
                "SAML sessions cannot satisfy step-up in this release (re-authenticating does not "
                "help); use an API token for this operation or ask an administrator",
                {},
                false};
    case StepUpDecision::kStoreUnavailable:
    case StepUpDecision::kUnwired:
    case StepUpDecision::kUnsupportedClass:
    case StepUpDecision::kEvaluationFailed:
        return {503,
                "authentication store is temporarily unavailable",
                "retry shortly or contact an administrator",
                {},
                true};
    case StepUpDecision::kStatusFailed:
        return {401, "MFA step-up required",
                "auth_db unavailable \xE2\x80\x94 retry shortly or contact an administrator",
                "/login/mfa/stepup", true};
    case StepUpDecision::kEngineDenied:
        // No challenge_url and no mfa_step_up_required: re-proving cannot help an engine
        // principal, and the remediation must not promise a grant that would admit it.
        return {403,
                "engine principals cannot perform this operation",
                "this route is not available to engine principals",
                {},
                false};
    case StepUpDecision::kChallenge:
    case StepUpDecision::kPass:
        break;
    }
    return {401, "MFA step-up required",
            v.is_oidc
                ? "Re-authenticate via SSO to refresh the identity provider's MFA assertion, "
                  "then retry"
                : "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry",
            v.is_oidc ? "/auth/oidc/start" : "/login/mfa/stepup", true};
}

void count_gate(yuzu::MetricsRegistry* metrics, std::string_view outcome,
                std::string_view auth_source, StepUpSurface surface) noexcept {
    if (!metrics)
        return;
    try {
        metrics
            ->counter(
                "yuzu_auth_mfa_step_up_gate_total",
                {{"outcome", std::string(outcome)},
                 {"source", std::string(auth_source == "none" ? auth_source
                                                              : step_up_source_label(auth_source))},
                 {"surface", std::string(step_up_surface_label(surface))}})
            .increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // Observability must never decide a security outcome.
    }
}

// A refusal storm (a stale-proof client retrying, a store outage, an engine-rate retry loop) must
// not become a log storm: one log line in `kStepUpLogSample` per site, the first always. The
// idiom is audit_store.cpp's `kReadDegradeLogSample`; the continuous signal is the counter
// `yuzu_auth_mfa_step_up_gate_total`, which counts every refusal.
constexpr std::uint64_t kStepUpLogSample = 100;

[[nodiscard]] bool should_log_sampled(std::atomic<std::uint64_t>& hits) noexcept {
    return hits.fetch_add(1, std::memory_order_relaxed) % kStepUpLogSample == 0;
}

// The reason a chokepoint evaluation threw, logged through the same sampling as the refusal
// logs. This is the ONLY log line for a thrown evaluation (the fallback's audit/metric effects do
// not log a second one). `what` is sanitised (control characters, length) like every other log
// line that echoes text an exception chose. Called from a catch clause, so it must not throw out
// of it: a formatter or logger failure is swallowed.
void note_chokepoint_exception(const std::string& label, const char* what) noexcept {
    try {
        static std::atomic<std::uint64_t> exception_hits{0};
        if (should_log_sampled(exception_hits))
            spdlog::error("step-up gate: evaluating {} threw ({}); failing closed (1 log per {} "
                          "exceptions; the counter records all)",
                          label, onbehalf::sanitize_for_log(what ? what : ""), kStepUpLogSample);
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

// The audit-detail suffix of a chokepoint refusal: ` cid=<id> stage=pre_authz`. The correlation id
// is minted (or reused, if an upstream gate set it) BEFORE the audit row is written, so the row,
// the `X-Correlation-Id` header and the body's `correlation_id` carry one value and an operator
// can join a refusal they were shown to its evidence row. `stage=pre_authz` stays LAST. An
// allocation failure while minting degrades to the bare stage (the refusal still renders, and
// renders its own id).
std::string pre_authz_suffix(httplib::Response& res) noexcept {
    try {
        return " cid=" + detail::ensure_correlation_id(res) + " stage=pre_authz";
    } catch (...) {
        return " stage=pre_authz";
    }
}

std::string_view outcome_for(StepUpDecision d) noexcept {
    switch (d) {
    case StepUpDecision::kPass:
        return "pass";
    case StepUpDecision::kStoreUnavailable:
    case StepUpDecision::kUnwired:
    case StepUpDecision::kUnsupportedClass:
    case StepUpDecision::kEvaluationFailed:
        return "unavailable";
    case StepUpDecision::kChallenge:
    case StepUpDecision::kSamlDenied:
    case StepUpDecision::kStatusFailed:
    case StepUpDecision::kEngineDenied:
        return "refused";
    }
    return "refused";
}

} // namespace

std::string_view step_up_source_label(std::string_view auth_source) noexcept {
    for (const std::string_view known :
         {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token"}) {
        if (auth_source == known)
            return known;
    }
    return "other";
}

std::string_view step_up_surface_label(StepUpSurface surface) noexcept {
    switch (surface) {
    case StepUpSurface::kRest:
        return "rest";
    case StepUpSurface::kDashboard:
        return "dashboard";
    case StepUpSurface::kMcp:
        return "mcp";
    }
    return "rest";
}

StepUpSurface step_up_surface_for_path(std::string_view path) noexcept {
    if (path.starts_with("/api/v1/"))
        return StepUpSurface::kRest;
    if (path.starts_with("/mcp/"))
        return StepUpSurface::kMcp;
    return StepUpSurface::kDashboard;
}

std::vector<std::string>
step_up_unclassified_registrations(const std::vector<RouteInventory::Route>& routes) {
    // The policy sweep takes views; `routes` outlives them for the duration of this call.
    std::vector<std::pair<std::string_view, std::string_view>> views;
    views.reserve(routes.size());
    for (const auto& [method, pattern] : routes)
        views.emplace_back(method, pattern);
    std::vector<std::string> out;
    for (const auto& [method, pattern] : step_up_unclassified_routes(views))
        out.push_back(std::string(method) + " " + std::string(pattern));
    return out;
}

std::vector<std::string> step_up_unclassified_registrations(const void* server) {
    return step_up_unclassified_registrations(RouteInventory::instance().routes_for(server));
}

void seed_step_up_gate_metrics(yuzu::MetricsRegistry& metrics) {
    metrics.describe("yuzu_auth_mfa_step_up_gate_total",
                     "MFA step-up chokepoint decisions by outcome, auth source and surface",
                     "counter");
    for (const std::string_view outcome : {"pass", "refused", "unavailable", "handler_skipped"}) {
        for (const std::string_view source :
             {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token", "other", "none"}) {
            for (const std::string_view surface : {"rest", "dashboard", "mcp"}) {
                metrics.counter("yuzu_auth_mfa_step_up_gate_total",
                                {{"outcome", std::string(outcome)},
                                 {"source", std::string(source)},
                                 {"surface", std::string(surface)}});
            }
        }
    }
}

StepUpVerdict decide_step_up(const auth::Session& session, const MfaStatusFn& mfa_status,
                             int window_secs, std::string_view mfa_enforcement) {
    StepUpVerdict v;
    v.user = session.username;
    v.window_secs = window_secs;

    // An engine principal (`session.is_engine()`, the canonical predicate shared with
    // `deny_engine_session` and the engine quota gate) is DENIED on every step-up-gated route,
    // whatever RBAC grants it holds: it is a non-interactive bearer with no `users` row and no
    // operator to re-prove, and these routes are operator-only. The denial is decided HERE, ahead
    // of the operator hatch below (a disabled gate must not admit an engine to a handler its
    // grant would otherwise reach) and before any store read: `mfa_status("engine:<slug>")`
    // answers InvalidUsername (the ':' is rejected before any store read), which would surface as
    // a misleading 401 "auth_db unavailable". Do NOT turn this back into a pass: an exempted
    // engine reaches the handler and is decided by its RBAC grant alone.
    if (session.is_engine()) {
        v.decision = StepUpDecision::kEngineDenied;
        return v;
    }

    // Escape hatch: the operator disabled the gate. Treated as fresh.
    if (window_secs <= 0)
        return v;

    // The other bearer-credential principals are step-up-exempt by design: issuing the token was
    // the step-up moment.
    if (session.auth_source == "api_token" || session.auth_source == "mcp_token")
        return v;

    // SAML sessions carry no local `users` row and no MFA attestation in this release. The gate
    // stays CLOSED with an honest denial rather than falling through to `mfa_status()`, which
    // would fail with a confusing "auth_db unavailable" message. Do NOT add an exemption here.
    if (session.auth_source == "saml") {
        v.decision = StepUpDecision::kSamlDenied;
        return v;
    }

    // OIDC sessions carry no local `users` row, so the enrolment lookup is skipped for them and
    // the session is gated purely on `mfa_verified_at`, which /auth/callback seeds from the IdP
    // `amr` claim. An OIDC session must NEVER take the local lookup: a local namesake account
    // could be enrolled and would then satisfy the gate for a factor the OIDC caller never
    // presented.
    const bool is_oidc = session.auth_source == "oidc";
    v.is_oidc = is_oidc;

    if (!is_oidc) {
        // (a) a store error or a user deleted mid-request fails CLOSED: an auth_db transient
        //     never lets a gated request through. A store/decrypt outage is distinguished
        //     (503, retryable) from other failures (401).
        // (b) a user who is not enrolled passes; under `mfa_enforcement != optional` such a user
        //     is made to enrol at login, so reaching here un-enrolled implies `optional`.
        auto status = mfa_status(session.username);
        if (!status) {
            v.decision = is_store_unavailable(status.error()) ? StepUpDecision::kStoreUnavailable
                                                              : StepUpDecision::kStatusFailed;
            return v;
        }
        if (!status->enrolled)
            return v;
    }

    // Proof age against the LOCAL MONOTONIC anchor derived at cache-populate from the DB clock
    // (ADR-2002 section 4): `steady_mfa_verified` is immune to local wall skew/steps, and its {}
    // sentinel means "no usable MFA proof" for BOTH an absent and a future-dated proof.
    const auto now = std::chrono::steady_clock::now();
    const bool no_proof = session.steady_mfa_verified.time_since_epoch().count() == 0;

    // An OIDC session whose IdP did not attest MFA carries no seeded proof. Whether that passes
    // depends on enforcement, symmetric with a local user: when the mode does not protect this
    // role it PASSES (gating would loop through re-SSO with the same amr-less token forever);
    // when it does protect the role the session falls through to the challenge. An OIDC session
    // that DOES carry a seeded proof always takes the freshness check regardless of mode.
    if (is_oidc && no_proof && !mfa_enforcement_protects(mfa_enforcement, session.role))
        return v;

    const auto age =
        no_proof
            ? std::chrono::seconds::max()
            : std::chrono::duration_cast<std::chrono::seconds>(now - session.steady_mfa_verified);
    // Hard 24 h ceiling on the effective window (ADR-2002 section 4 mitigation (b), parity with
    // JIT elevation's kMaxElevationWindow): a proof older than it never counts, whatever
    // `window_secs` is configured to.
    constexpr std::int64_t kMaxMfaStepUpWindowSecs = 24 * 3600;
    const auto effective_window =
        std::chrono::seconds((std::min<std::int64_t>)(window_secs, kMaxMfaStepUpWindowSecs));
    // Suspend backstop: `age` is on steady_clock, which pauses across host/VM suspend, so also
    // require the ABSOLUTE (wall) proof age not be grossly past the window, with the generous
    // auth::kWallSanitySkew slack so a merely clock-skewed replica is never affected.
    const auto wall_age = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - session.mfa_verified_at);
    const bool wall_stale = wall_age > effective_window + auth::kWallSanitySkew;
    if (!no_proof && age <= effective_window && !wall_stale)
        return v;

    v.decision = StepUpDecision::kChallenge;
    v.age_secs = no_proof ? -1 : age.count();
    return v;
}

StepUpVerdict decide_step_up(const auth::Session& session, AuthDB& auth_db, int window_secs,
                             std::string_view mfa_enforcement) {
    const MfaStatusFn lookup = [&auth_db](const std::string& username) {
        return auth_db.mfa_status(username);
    };
    return decide_step_up(session, lookup, window_secs, mfa_enforcement);
}

std::string step_up_refusal_json_rpc_error(const StepUpVerdict& verdict,
                                           std::string_view correlation_id) {
    const auto t = refusal_text(verdict);
    nlohmann::json data = {{"mfa_step_up_required", t.mfa_step_up_required},
                           {"http_status", t.http_status},
                           {"correlation_id", correlation_id.empty()
                                                  ? detail::make_correlation_id()
                                                  : std::string(correlation_id)},
                           {"remediation", t.remediation}};
    if (!t.challenge_url.empty())
        data["challenge_url"] = t.challenge_url;
    const nlohmann::json err = {
        {"code", mcp::kPermissionDenied}, {"message", t.message}, {"data", std::move(data)}};
    return err.dump();
}

void render_step_up_refusal(const httplib::Request& req, httplib::Response& res,
                            const StepUpVerdict& verdict, StepUpSurface surface) {
    const auto t = refusal_text(verdict);
    // The header and the body's `correlation_id` are the same value, on every surface, like the
    // other A4 error paths (`detail::a4_error`); a reused header (set upstream) is kept.
    const std::string cid = detail::ensure_correlation_id(res);
    if (surface == StepUpSurface::kMcp) {
        const auto err = nlohmann::json::parse(step_up_refusal_json_rpc_error(verdict, cid));
        const nlohmann::json body = {{"jsonrpc", "2.0"}, {"id", nullptr}, {"error", err}};
        res.status = 200;
        res.set_content(body.dump(), "application/json");
        return;
    }

    nlohmann::json meta = {{"api_version", "v1"}, {"mfa_step_up_required", t.mfa_step_up_required}};
    if (!t.challenge_url.empty())
        meta["challenge_url"] = t.challenge_url;
    const nlohmann::json envelope = {{"error",
                                      {{"code", t.http_status},
                                       {"message", t.message},
                                       {"correlation_id", cid},
                                       {"remediation", t.remediation}}},
                                     {"meta", std::move(meta)}};
    res.status = t.http_status;
    res.set_content(envelope.dump(), "application/json");

    // htmx swaps no 4xx/5xx body, so an htmx request would see a dead button without a toast.
    // The message is the envelope's own text, never the remediation (a sentence naming a URL or
    // an action the toast cannot link to).
    if (surface == StepUpSurface::kDashboard && !req.get_header_value("HX-Request").empty()) {
        const nlohmann::json toast = {{"showToast", {{"message", t.message}, {"level", "error"}}}};
        res.set_header("HX-Trigger", toast.dump());
    }
}

void emit_step_up_refusal_effects(const httplib::Request& req, const StepUpVerdict& verdict,
                                  const StepUpAuditFn& audit_fn, const std::string& action_label,
                                  std::string_view detail_suffix, yuzu::MetricsRegistry* metrics) {
    std::string detail_str;
    switch (verdict.decision) {
    case StepUpDecision::kSamlDenied:
        detail_str = "user=" + verdict.user + " reason=saml_session_no_mfa_this_release";
        break;
    case StepUpDecision::kStoreUnavailable:
    case StepUpDecision::kStatusFailed:
        detail_str = "user=" + verdict.user + " reason=mfa_status_unavailable (fail-closed)";
        break;
    case StepUpDecision::kUnwired:
        detail_str = "user=" + verdict.user + " reason=auth_store_unwired";
        break;
    case StepUpDecision::kUnsupportedClass:
        detail_str = "user=" + verdict.user + " reason=step_up_class_unsupported";
        break;
    case StepUpDecision::kEvaluationFailed:
        detail_str = "user=" + verdict.user + " reason=chokepoint_exception";
        break;
    case StepUpDecision::kEngineDenied:
        detail_str = "user=" + verdict.user + " reason=engine_principal_denied";
        break;
    case StepUpDecision::kChallenge:
    case StepUpDecision::kPass:
        detail_str = "user=" + verdict.user + " age_secs=" + std::to_string(verdict.age_secs) +
                     " window_secs=" + std::to_string(verdict.window_secs);
        break;
    }
    detail_str += detail_suffix;
    if (audit_fn) {
        try {
            (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint", action_label,
                           detail_str);
        } catch (const std::exception& ex) {
            spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
        } catch (...) {
            spdlog::warn("mfa_step_up: audit emission threw non-std exception");
        }
    }
    if (verdict.decision == StepUpDecision::kStoreUnavailable ||
        verdict.decision == StepUpDecision::kStatusFailed) {
        static std::atomic<std::uint64_t> status_failed_hits{0};
        if (should_log_sampled(status_failed_hits))
            spdlog::error("require_mfa_step_up: mfa_status({}) failed: failing closed "
                          "(1 log per {} refusals; the counter records all)",
                          verdict.user, kStepUpLogSample);
    }
    // kEvaluationFailed logs nothing here: `note_chokepoint_exception` already wrote the one
    // (sampled) line for the throw, with its what().
    if (verdict.decision == StepUpDecision::kStoreUnavailable && metrics) {
        // Same discipline as `count_gate`: observability never decides a security outcome, and the
        // refusal that follows must not be replaced by a metrics-registry throw.
        try {
            metrics->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
                .increment();
        } catch (...) { // NOLINT(bugprone-empty-catch)
        }
    }
}

void refuse_step_up_store_unwired(const httplib::Request& req, httplib::Response& res,
                                  const auth::Session& session, const StepUpAuditFn& audit_fn,
                                  const std::string& action_label, yuzu::MetricsRegistry* metrics) {
    StepUpVerdict v;
    v.decision = StepUpDecision::kUnwired;
    v.user = session.username;
    static std::atomic<std::uint64_t> unwired_hits{0};
    if (should_log_sampled(unwired_hits))
        spdlog::error("step-up gate: no auth store wired; failing closed ({}) (1 log per {} "
                      "refusals; the counter records all)",
                      action_label, kStepUpLogSample);
    emit_step_up_refusal_effects(req, v, audit_fn, action_label, {}, metrics);
    count_gate(metrics, outcome_for(v.decision), session.auth_source, StepUpSurface::kRest);
    render_step_up_refusal(req, res, v, StepUpSurface::kRest);
}

namespace detail {

StepUpChokepointResult apply_step_up_chokepoint(const httplib::Request& req, httplib::Response& res,
                                                const StepUpChokepointDeps& deps) {
    if (req.matched_route.empty() || !is_step_up_table_method(req.method))
        return StepUpChokepointResult::kNotApplicable;
    const StepUpPolicyEntry* row = step_up_policy_for(req.method, req.matched_route);
    if (row == nullptr)
        return StepUpChokepointResult::kNotApplicable;
    if (row->cls != StepUpClass::kRequired && row->cls != StepUpClass::kStrong)
        return StepUpChokepointResult::kNotApplicable; // kExempt / kOwnGate / kPendingRuling

    const StepUpSurface surface = step_up_surface_for_path(req.path);

    // Everything below that can allocate runs inside the try: the action label is assigned in it
    // (an allocation failure on it is answered by the same fail-closed fallback as any other
    // throw), and `user` / `source` are filled only once the session has resolved, so they stay
    // empty when resolution itself threw (the metric label then reads "other").
    std::string label;
    std::string user;
    std::string source;

    // The one fail-closed answer for an evaluation that threw, shared by both catch clauses so
    // they cannot drift. Not itself allowed to throw past its own try blocks.
    const auto fail_closed = [&]() -> StepUpChokepointResult {
        clear_step_up_pass();
        StepUpVerdict v;
        v.decision = StepUpDecision::kEvaluationFailed;
        count_gate(deps.metrics, outcome_for(v.decision), source, surface); // noexcept
        try {
            v.user = user;
            if (deps.fault_hook && *deps.fault_hook)
                (*deps.fault_hook)(StepUpFaultPoint::kFallbackRender);
            // The same renderer as every other refusal, so the dashboard toast, the
            // `mfa_step_up_required` discriminator and the MCP shape are produced for this
            // decision too. If rendering itself throws, the 503 below still stands.
            render_step_up_refusal(req, res, v, surface);
        } catch (...) { // NOLINT(bugprone-empty-catch)
            res.status = 503;
        }
        // Best-effort evidence: nothing thrown here may replace the refusal above.
        try {
            static const StepUpAuditFn kNoAudit;
            emit_step_up_refusal_effects(req, v, deps.audit_fn ? *deps.audit_fn : kNoAudit, label,
                                         pre_authz_suffix(res), deps.metrics);
        } catch (...) { // NOLINT(bugprone-empty-catch)
        }
        return StepUpChokepointResult::kRefused;
    };

    try {
        label = std::string(row->action_label);
        const auto refuse = [&](const StepUpVerdict& v, std::string_view source) {
            static const StepUpAuditFn kNoAudit;
            emit_step_up_refusal_effects(req, v, deps.audit_fn ? *deps.audit_fn : kNoAudit, label,
                                         pre_authz_suffix(res), deps.metrics);
            count_gate(deps.metrics, outcome_for(v.decision), source, surface);
            render_step_up_refusal(req, res, v, surface);
            return StepUpChokepointResult::kRefused;
        };

        std::optional<auth::Session> session;
        if (deps.resolve_session && *deps.resolve_session)
            session = (*deps.resolve_session)(req);
        if (!session) {
            // Pre-routing has normally answered an anonymous caller already; this stage does not
            // rely on that.
            res.status = 401;
            res.set_content(nlohmann::json{{"error",
                                            {{"code", 401},
                                             {"message", "unauthorized"},
                                             {"correlation_id", ensure_correlation_id(res)}}},
                                           {"meta", {{"api_version", "v1"}}}}
                                .dump(),
                            "application/json");
            count_gate(deps.metrics, "refused", "none", surface);
            return StepUpChokepointResult::kRefused;
        }

        user = session->username;
        source = std::string(step_up_source_label(session->auth_source));

        if (deps.fault_hook && *deps.fault_hook)
            (*deps.fault_hook)(StepUpFaultPoint::kBeforeDecide);

        if (row->cls == StepUpClass::kStrong) {
            StepUpVerdict v;
            v.decision = StepUpDecision::kUnsupportedClass;
            v.user = session->username;
            return refuse(v, session->auth_source);
        }

        // Load-bearing order: the unwired-store 503 answers EVERY caller class (an engine
        // principal included) BEFORE the decision below, which is what refuses an engine 403.
        if (deps.mfa_status == nullptr && deps.auth_db == nullptr) {
            StepUpVerdict v;
            v.decision = StepUpDecision::kUnwired;
            v.user = session->username;
            return refuse(v, session->auth_source);
        }

        StepUpVerdict v =
            deps.mfa_status != nullptr
                ? decide_step_up(*session, *deps.mfa_status, deps.window_secs, deps.mfa_enforcement)
                : decide_step_up(*session, *deps.auth_db, deps.window_secs, deps.mfa_enforcement);
        if (!v.passed())
            return refuse(v, session->auth_source);

        count_gate(deps.metrics, "pass", session->auth_source, surface);
        auto& stash = tls_step_up_pass();
        stash.req = &req;
        stash.row = row;
        stash.surface = surface;
        stash.source = step_up_source_label(session->auth_source);
        return StepUpChokepointResult::kPassed;
    } catch (const std::exception& e) {
        // Fail closed: a gated row never passes because evaluating it threw.
        note_chokepoint_exception(label, e.what());
        return fail_closed();
    } catch (...) {
        note_chokepoint_exception(label, "non-std exception");
        return fail_closed();
    }
}

bool consume_step_up_pass(const httplib::Request& req, const std::string& action_label) noexcept {
    auto& stash = tls_step_up_pass();
    if (stash.req != &req || stash.row == nullptr || stash.row->action_label != action_label)
        return false;
    clear_step_up_pass();
    return true;
}

void finish_step_up_pass(const httplib::Request& req, const httplib::Response& res,
                         yuzu::MetricsRegistry* metrics) noexcept {
    auto& stash = tls_step_up_pass();
    if (stash.req == &req && stash.row != nullptr && res.status >= 200 && res.status < 300)
        count_gate(metrics, "handler_skipped", stash.source, stash.surface);
    clear_step_up_pass();
}

} // namespace detail

} // namespace yuzu::server
