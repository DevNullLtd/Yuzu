/// @file app_usage_routes.cpp
/// `GET /api/v1/forensics/agents/{agent_id}/app-usage` route registration
/// (Wave 7 PR7.2). See app_usage_routes.hpp for the auth/audit posture. The
/// handler chain mirrors `SleRoutes`' single-agent drill: correlation id +
/// header -> scope gate -> fail-closed behavioural audit -> 503-on-degrade
/// (never an empty 200); errors via the A4 envelope.
///
/// A4 / JSON helpers are re-implemented locally (small, self-contained)
/// rather than shared from rest_api_v1.cpp, whose helpers are
/// translation-unit-local — the same self-contained-route-file discipline
/// SleRoutes/InventoryRoutes follow.

#include "app_usage_routes.hpp"

#include "app_usage_read_model.hpp" // AppUsageModel, app_usage_json (Rule 1 shared builder)
#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::try_persist_audit / emit_behavioral_audit (#1647)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

using nlohmann::json;

/// grep-token correlation id, `req-<hex-ms>-<hex-seq>` — same shape as
/// sle_routes.cpp/rest_api_v1.cpp's make_correlation_id (echoed in
/// X-Correlation-Id + every A4 body). Process-global monotonic sequence so
/// two ids minted in the same ms differ.
std::string make_cid() {
    static std::atomic<std::uint64_t> seq{0};
    const auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), seq.fetch_add(1));
}

/// A4 error envelope. retry_after_ms is ALWAYS a key (null unless set), per
/// docs/agentic-first-principle.md §A4.
std::string a4_error(int code, std::string_view message, std::string_view cid,
                     std::optional<std::int64_t> retry_after_ms = std::nullopt,
                     std::string_view remediation = {}) {
    json err;
    err["code"] = code;
    err["message"] = std::string(message);
    err["correlation_id"] = std::string(cid);
    if (retry_after_ms)
        err["retry_after_ms"] = *retry_after_ms;
    else
        err["retry_after_ms"] = nullptr;
    if (!remediation.empty())
        err["remediation"] = std::string(remediation);
    json out;
    out["error"] = std::move(err);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

/// REST's `data` envelope wrapper — `app_usage_json()` (the Rule 1 shared
/// builder) already returns a fully-serialized JSON OBJECT string, so this
/// re-parses it rather than re-deriving the object, matching this file's own
/// local-helpers discipline (see file header) while still sharing the actual
/// field construction with the MCP twin.
std::string ok_json(const std::string& data_json) {
    json out;
    out["data"] = json::parse(data_json);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

void send_json(httplib::Response& res, int status, std::string body) {
    res.status = status;
    res.set_content(std::move(body), "application/json");
}

} // namespace

void AppUsageRoutes::register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                                     AgentUsageSnapshotFn agent_usage_snapshot_fn,
                                     AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(scoped_perm_fn), std::move(agent_usage_snapshot_fn),
                    std::move(audit_fn));
}

void AppUsageRoutes::register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                                     AgentUsageSnapshotFn agent_usage_snapshot_fn,
                                     AuditFn audit_fn) {
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    agent_usage_snapshot_fn_ = std::move(agent_usage_snapshot_fn);
    audit_fn_ = std::move(audit_fn);

    // ── GET /api/v1/forensics/agents/{agent_id}/app-usage — scoped + fail-closed audit ──
    // Per-device scope is MANDATORY — fail CLOSED if the gate is unwired
    // rather than silently widening to a global read (mirrors the SleRoutes/
    // dex per-device REST route; production always wires it from server.cpp).
    sink.Get(R"(/api/v1/forensics/agents/([^/]+)/app-usage)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = make_cid();
                 res.set_header("X-Correlation-Id", cid);
                 const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";

                 if (!scoped_perm_fn_) {
                     send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                     return;
                 }
                 if (!scoped_perm_fn_(req, res, "Forensics", "Read", agent_id))
                     return; // the gate wrote its own 401/403

                 // Audit-on-open FAIL-CLOSED for this behavioural-data read (G-2):
                 // refuse to serve the agent's app-usage rows when the evidence row
                 // is KNOWN to have failed to persist. A null audit_fn is audit-off
                 // (not a failure) -> serves, per the AuditFn contract. Set BEFORE
                 // the store read (per-open, not per-row).
                 if (!detail::emit_behavioral_audit(
                         audit_fn_, req, res, "app_usage.agent.view", "success", "Agent", agent_id,
                         "per-agent app-usage read cid=" + cid)) {
                     send_json(res, 503,
                               a4_error(503,
                                        "audit subsystem unavailable; refusing to serve per-agent "
                                        "app-usage data without durable evidence",
                                        cid, 5000, "retry the request"));
                     spdlog::warn("app_usage.agent.view audit fail-closed (503) cid={} agent_id={}",
                                  cid, agent_id);
                     return;
                 }

                 // Rows + collected_at come back together from ONE transaction
                 // (AppUsageStore::get_agent_usage_snapshot) — see
                 // app_usage_routes.hpp's file header for why a two-call split
                 // (get_agent_last_used + collected_at separately) risked pairing
                 // one snapshot's rows with another's collected_at. collected_at is
                 // sourced from the usage_state PARENT row, never rows.front().
                 // collected_at — a legitimate replace-to-empty snapshot has no row
                 // to carry it, and that empty case must still report the real
                 // collection time, not 0 (#C2). The MCP twin (mcp_server.cpp)
                 // sources it the same way, through the same store method.
                 std::optional<AppUsageSnapshot> snapshot;
                 if (agent_usage_snapshot_fn_)
                     snapshot = agent_usage_snapshot_fn_(agent_id);
                 if (!snapshot) {
                     // Store/pool/query degrade — a durable failure-audit (the
                     // SleRoutes drill pattern), then 503 (never a silent empty
                     // 200).
                     (void)detail::try_persist_audit(audit_fn_, req, "app_usage.agent.view",
                                                     "failure", "Agent", agent_id,
                                                     "app-usage store degraded; cid=" + cid);
                     send_json(res, 503,
                               a4_error(503, "app-usage store unavailable — read failed", cid, 5000,
                                        "retry the request"));
                     return;
                 }

                 AppUsageModel model;
                 model.agent_id = agent_id;
                 model.apps = std::move(snapshot->rows);
                 model.collected_at = snapshot->collected_at;
                 send_json(res, 200, ok_json(app_usage_json(model)));
             });
}

} // namespace yuzu::server
