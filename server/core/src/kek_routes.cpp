#include "kek_routes.hpp"

#include "rest_a4_envelope.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstddef>
#include <ctime>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

using detail::error_json_a4;
using detail::make_correlation_id;

constexpr const char* kJson = "application/json";

// system_clock time_point -> ISO-8601 UTC ("YYYY-MM-DDTHH:MM:SSZ"). Mirrors
// auth_routes.cpp's iso8601_utc / guardian_ingest.cpp's ts_to_iso8601 — the
// established per-file idiom for this codebase (no shared formatter header
// exists yet). #2530 H1: formats KekOpResult::lock_holder_captured_at for
// the REST /status response.
std::string iso8601_utc(std::chrono::system_clock::time_point tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#if defined(_WIN32)
    if (gmtime_s(&tm, &t) != 0)
        return "invalid-time";
#else
    if (gmtime_r(&t, &tm) == nullptr)
        return "invalid-time";
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}
// All three operations take zero parameters; the body must be absent or
// `{}`. Cap it defensively before parsing (mirrors ca_routes.cpp's
// kMaxRevokeBody) — a multi-GB POST must not reach nlohmann::json::parse on
// this privileged endpoint.
constexpr std::size_t kMaxKekBody = 64 * 1024;

/// Validate that `req.body` is either empty or parses to `{}`. This is the
/// mass-assignment guard from ca_routes.cpp:418-428, specialised for a route
/// that accepts zero fields — so ANY key present makes the body unknown.
/// On failure, writes the A4 error response and returns false; the caller
/// must `return` immediately in that case.
bool validate_empty_body(const httplib::Request& req, httplib::Response& res) {
    if (req.body.size() > kMaxKekBody) {
        res.status = 413;
        res.set_content(error_json_a4(413, "request body too large", make_correlation_id()), kJson);
        return false;
    }
    if (req.body.empty())
        return true;
    // Hermes-style defensive parse (matches ca_routes.cpp's revoke handler):
    // allow_exceptions=false turns a parse error into a discarded value
    // (caught by !is_object below), and the try/catch guards against an
    // impl-specific throw (e.g. bad_alloc) reaching this privileged endpoint.
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body, nullptr, false);
    } catch (...) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    if (!body.is_object()) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    if (!body.empty()) {
        res.status = 400;
        res.set_content(error_json_a4(400, "unknown field in request body", make_correlation_id(),
                                      "this operation takes no parameters; send an empty body or {}"),
                        kJson);
        return false;
    }
    return true;
}

/// Short, static (never seam-supplied) tag for the audit `detail` column —
/// safe to log verbatim, unlike anything the seam might have classified as
/// Internal (rule B: a codec-internal error string must never surface here
/// either, in the audit trail or the HTTP body). Values match the #2530 B7
/// fixed metrics outcome vocabulary (`ceiling`/`query_canceled`/
/// `clock_anomaly`/...) even though this is a separate audit-detail string,
/// not the Prometheus label — same vocabulary, easier to grep across both.
const char* failure_tag(KekOpResult::Failure failure) {
    switch (failure) {
    case KekOpResult::Failure::Unavailable:
        return "failure=unavailable";
    case KekOpResult::Failure::Conflict:
        return "failure=conflict";
    case KekOpResult::Failure::Cooldown:
        return "failure=cooldown";
    case KekOpResult::Failure::VersionCeiling:
        return "failure=ceiling";
    case KekOpResult::Failure::QueryCanceled:
        return "failure=query_canceled";
    case KekOpResult::Failure::ClockAnomaly:
        return "failure=clock_anomaly";
    case KekOpResult::Failure::HalfCommitted:
        return "failure=half_committed";
    case KekOpResult::Failure::Internal:
    case KekOpResult::Failure::None:
        return "failure=internal";
    }
    return "failure=internal";
}

/// Map a `KekOpResult`'s failure to the A4 error envelope and write it to
/// `res`. Takes the whole result (not just the `Failure` enum) because
/// `Cooldown`'s retry hint (#2530 D) is now an honest value carried on the
/// result rather than a hardcoded constant. Rule A (#2395): HalfCommitted's
/// remediation is the single most important string in this module — it MUST
/// tell the operator to call `/rewrap` to resume and MUST NOT invite a
/// `/rotate` retry (which would mint a spurious extra version on top of an
/// already-half-rotated state). Rule B: Internal NEVER interpolates any
/// seam-supplied string — generic message + correlation id only.
///
/// #2530 D — VersionCeiling / QueryCanceled / ClockAnomaly deliberately carry
/// NO `retry_after_ms` (waiting alone never resolves any of the three: the
/// ceiling needs an operator config change, a canceled query may fail
/// identically forever at scale or was an admin cancel, and the clock the
/// cooldown math would use is the very thing proven untrustworthy).
void write_failure(httplib::Response& res, const KekOpResult& result) {
    switch (result.failure) {
    case KekOpResult::Failure::Unavailable:
        res.status = 503;
        res.set_content(error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                        kJson);
        return;
    case KekOpResult::Failure::Conflict:
        res.status = 409;
        // Retryable, and NOT the caller's fault — another rotation holds the
        // cluster-wide advisory lock. Carries an honest retry_after_ms so an
        // agentic caller backs off rather than guessing, matching the MCP
        // twin's Conflict branch exactly (agentic-first A5).
        res.set_content(error_json_a4(409, "another KEK operation is in progress",
                                      make_correlation_id(), /*retry_after_ms=*/5000,
                                      "another rotation or re-wrap holds the KEK operation lock; "
                                      "retry once it completes"),
                        kJson);
        return;
    case KekOpResult::Failure::Cooldown: {
        // Distinct from Conflict on purpose (Hermes pass 2, MEDIUM 2c): telling
        // an operator "another rotation holds the lock" when in fact they
        // attempted one two minutes ago is simply false, and sends them hunting
        // a concurrent operation that does not exist.
        //
        // #2530 D: the retry_after_ms is now honest, sourced from the seam's
        // durable rate-limit clock (`cooldown_retry_after_ms`) rather than a
        // hardcoded constant — waiting genuinely resolves a cooldown, so this
        // is the ONE failure where a numeric hint is truthful. Fall back to
        // the old fixed 5-minute hint only if the seam left the field unset
        // (0), so a stub/older seam still answers something sane instead of
        // an honest-looking `0`.
        const std::int64_t retry_after_ms = result.cooldown_retry_after_ms > 0
                                                 ? static_cast<std::int64_t>(
                                                       result.cooldown_retry_after_ms)
                                                 : 300000;
        res.status = 429;
        res.set_content(error_json_a4(429, "KEK rotation is in its cooldown window",
                                      make_correlation_id(), retry_after_ms,
                                      "a KEK rotation was attempted very recently; rotation "
                                      "attempts are rate-limited. If you are finishing a "
                                      "half-committed rotation, call the rewrap route instead — "
                                      "it is NOT rate-limited and is the correct way to resume"),
                        kJson);
        return;
    }
    case KekOpResult::Failure::VersionCeiling:
        res.status = 409;
        res.set_content(
            error_json_a4(409, "the live KEK version ceiling has been reached",
                          make_correlation_id(),
                          "rotation is blocked because the number of live KEK versions has "
                          "reached --kek-max-live-versions; there is no retire route (#2525), so "
                          "waiting will never clear this — an operator must explicitly raise the "
                          "ceiling, which is a deliberate, logged and audited risk acceptance"),
            kJson);
        return;
    case KekOpResult::Failure::QueryCanceled:
        res.status = 503;
        res.set_content(
            error_json_a4(503, "a KEK query was canceled or exceeded its statement timeout",
                          make_correlation_id(),
                          "this is not necessarily transient: check statement_timeout, current "
                          "database load, whether an administrator issued pg_cancel_backend, and "
                          "the size of the registered-column rewrap scan before retrying"),
            kJson);
        return;
    case KekOpResult::Failure::ClockAnomaly: {
        res.status = 503;
        // #2530 G7-B6: interpolate the observed skew MAGNITUDE into both the
        // message and the remediation — "2 seconds of NTP jitter" and "this
        // row is dated next year" are the same boolean condition but demand
        // completely different operator responses, and a forward skew is
        // NOT self-clearing the way a backward skew is (it persists until
        // real time catches up to the stored timestamp), so this is the one
        // 503 in this surface with no configuration escape at all — say so
        // plainly rather than implying a routine retry will resolve it.
        const std::string message = "the KEK rotation clock is untrustworthy: the newest "
                                    "kek_meta row is dated " +
                                    std::to_string(result.clock_skew_secs) +
                                    "s in the future relative to the database server's own clock";
        const std::string remediation =
            "this durable rotation rate limit cannot be computed safely; investigate the "
            "database server's clock (NTP sync, VM restore, failover to a host that is ahead) "
            "before retrying. A forward skew like this does NOT self-clear on its own the way a "
            "backward skew does — it persists until real time catches up to the stored "
            "timestamp, and there is no configuration flag to bypass this refusal";
        res.set_content(error_json_a4(503, message, make_correlation_id(), remediation), kJson);
        return;
    }
    case KekOpResult::Failure::HalfCommitted:
        res.status = 500;
        res.set_content(
            error_json_a4(500, "KEK rotation did not finish re-wrapping every secret",
                          make_correlation_id(),
                          "the new KEK version was registered but re-wrapping did not finish; "
                          "call POST /api/v1/secrets/kek/rewrap to resume — do NOT retry "
                          "POST /api/v1/secrets/kek/rotate, which would mint a spurious extra "
                          "version"),
            kJson);
        return;
    case KekOpResult::Failure::Internal:
    case KekOpResult::Failure::None: // unreachable on this path; treat as internal
        res.status = 500;
        res.set_content(error_json_a4(500, "internal error", make_correlation_id()), kJson);
        return;
    }
}

} // namespace

namespace detail {
std::string_view kek_route_failure_tag(KekOpResult::Failure failure) {
    return failure_tag(failure);
}
} // namespace detail

void KekRoutes::register_routes(httplib::Server& svr, PermFn perm_fn, AuditFn audit_fn, KekOps ops) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(perm_fn), std::move(audit_fn), std::move(ops));
}

void KekRoutes::register_routes(HttpRouteSink& sink, PermFn perm_fn, AuditFn audit_fn, KekOps ops) {
    spdlog::info("KEK routes: registering /api/v1/secrets/kek/*");

    // ── POST /api/v1/secrets/kek/rotate ── Security:Write. ────────────────────
    // Mints a new KEK version and re-wraps every registered secret row under
    // it. No request parameters. On a HalfCommitted failure the new version
    // is already active — the operator resumes via /rewrap, never by retrying
    // this route (see write_failure's HalfCommitted branch, #2395 rule A).
    sink.Post("/api/v1/secrets/kek/rotate",
             [perm_fn, audit_fn, ops](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Write"))
                     return;
                 if (!ops.rotate) {
                     res.status = 503;
                     res.set_content(
                         error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                         kJson);
                     return;
                 }
                 if (!validate_empty_body(req, res))
                     return;
                 const KekOpResult result = ops.rotate();
                 if (result.failure != KekOpResult::Failure::None) {
                     (void)audit_fn(req, "kek.rotate", "failure", "Secret", "kek",
                                    failure_tag(result.failure));
                     write_failure(res, result);
                     return;
                 }
                 if (!audit_fn(req, "kek.rotate", "success", "Secret", "kek",
                               "new_version=" + std::to_string(result.new_version)))
                     res.set_header("Sec-Audit-Failed", "true");
                 // Deliberately NO rows_rewrapped here: rotate_kek() discards
                 // its internal rewrap_all()'s count, so any number we printed
                 // would be a guess. `rotation_complete` is the honest signal
                 // and the one ADR-0010 §3 defines as the completion criterion.
                 // Call /rewrap if you want a real count.
                 nlohmann::json out = {{"new_version", result.new_version},
                                       {"rotation_complete", result.rotation_complete},
                                       {"meta", {{"api_version", "v1"}}}};
                 res.set_content(out.dump(), kJson);
             });

    // ── POST /api/v1/secrets/kek/rewrap ── Security:Write. ────────────────────
    // Idempotent RESUME: re-wraps every row still on a non-active version
    // under the current active version. Safe to call repeatedly (including
    // when nothing is left to do — rows_rewrapped==0 is a normal outcome, not
    // an error). No request parameters.
    sink.Post("/api/v1/secrets/kek/rewrap",
             [perm_fn, audit_fn, ops](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Write"))
                     return;
                 if (!ops.rewrap) {
                     res.status = 503;
                     res.set_content(
                         error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                         kJson);
                     return;
                 }
                 if (!validate_empty_body(req, res))
                     return;
                 const KekOpResult result = ops.rewrap();
                 if (result.failure != KekOpResult::Failure::None) {
                     (void)audit_fn(req, "kek.rewrap", "failure", "Secret", "kek",
                                    failure_tag(result.failure));
                     write_failure(res, result);
                     return;
                 }
                 if (!audit_fn(req, "kek.rewrap", "success", "Secret", "kek",
                               "rows_rewrapped=" + std::to_string(result.rows_rewrapped)))
                     res.set_header("Sec-Audit-Failed", "true");
                 nlohmann::json out = {{"rows_rewrapped", result.rows_rewrapped},
                                       {"meta", {{"api_version", "v1"}}}};
                 res.set_content(out.dump(), kJson);
             });

    // ── GET /api/v1/secrets/kek/status ── Security:Read. ──────────────────────
    // Read-only; not audited (matches the CA read routes — GET /ca/issued
    // etc. don't audit either). `oldest_in_use` is null when no secret rows
    // exist at all (nothing to rewrap, trivially "complete"). #2530 B2/C1:
    // `live_versions`/`lock_held`/`lock_holder_pid` are diagnostic snapshots
    // taken lock-free — see the KekOpResult doc comment — and this route
    // still deliberately never takes the `secrets_kek_op` lock itself; the
    // MCP `get_kek_status` twin surfaces the identical three fields (REST/MCP
    // parity, ADR-1005).
    //
    // #2530 T5: `live_versions` and `lock_held` serialise as JSON `null`
    // (never `0`/`false`) when the seam could not determine them — the key
    // is ALWAYS present, so a client can tell "unknown" (key present, value
    // null) apart from "the server predates this field" (key absent)
    // without a version check.
    sink.Get("/api/v1/secrets/kek/status",
            [perm_fn, ops](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                if (!ops.status) {
                    res.status = 503;
                    res.set_content(
                        error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                     /*retry_after_ms=*/5000,
                                     "the Postgres substrate or secrets codec is not available; "
                                     "retry once the server reports it is ready"),
                        kJson);
                    return;
                }
                const KekOpResult result = ops.status();
                if (result.failure != KekOpResult::Failure::None) {
                    write_failure(res, result);
                    return;
                }
                nlohmann::json out = {
                    {"active_version", result.active_version},
                    {"oldest_in_use", result.oldest_in_use.has_value()
                                          ? nlohmann::json(*result.oldest_in_use)
                                          : nlohmann::json(nullptr)},
                    {"rotation_complete", result.rotation_complete},
                    {"live_versions", result.live_versions.has_value()
                                           ? nlohmann::json(*result.live_versions)
                                           : nlohmann::json(nullptr)},
                    {"lock_held", result.lock_held.has_value() ? nlohmann::json(*result.lock_held)
                                                                : nlohmann::json(nullptr)},
                    {"lock_holder_pid", result.lock_holder_pid.has_value()
                                             ? nlohmann::json(*result.lock_holder_pid)
                                             : nlohmann::json(nullptr)},
                    // #2530 H1: when the lock_held/lock_holder_pid snapshot
                    // above was taken — null in lockstep with them when the
                    // holder query was undetermined. A pid without a visible
                    // capture instant lets a stale reading masquerade as
                    // current; see the runbook's termination step for why a
                    // pid must still be RE-CONFIRMED before acting on it.
                    {"lock_holder_captured_at",
                     result.lock_holder_captured_at.has_value()
                         ? nlohmann::json(iso8601_utc(*result.lock_holder_captured_at))
                         : nlohmann::json(nullptr)},
                    {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });
}

} // namespace yuzu::server
