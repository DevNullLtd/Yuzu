/// @file sle_routes.cpp
/// `/api/v1/sle/*` in-server discovery route registration (ADR-0024; the
/// discovery half kept in-server per "Placement under ADR-1005"). Two routes:
/// the raw per-agent detected-licence drill (GET) and the audited durable-erasure
/// trigger (DELETE). The posture/compliance reads and the fan-out list are the
/// SAM UCE module's, not built here. See sle_routes.hpp for the per-route auth
/// posture. The handler chain mirrors the `/api/v1/inventory/software` precedent:
/// correlation id + header → auth/scope gate → fail-closed behavioural audit →
/// 503-on-degrade (never an empty 200); errors via the A4 envelope.
///
/// A4 / JSON helpers are re-implemented locally (small, self-contained) rather
/// than shared from rest_api_v1.cpp, whose helpers are translation-unit-local —
/// the same self-contained-route-file discipline InventoryRoutes follows.

#include "sle_routes.hpp"

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
/// rest_api_v1.cpp's make_correlation_id (echoed in X-Correlation-Id + every A4
/// body). Process-global monotonic sequence so two ids minted in the same ms differ.
std::string make_cid() {
    static std::atomic<std::uint64_t> seq{0};
    const auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), seq.fetch_add(1));
}

/// A4 error envelope. retry_after_ms is ALWAYS a key (null unless set), per
/// docs/agentic-first-principle.md §A4; remediation/permission omitted when empty.
std::string a4_error(int code, std::string_view message, std::string_view cid,
                     std::optional<std::int64_t> retry_after_ms = std::nullopt,
                     std::string_view remediation = {}, std::string_view permission = {},
                     const json& details = json::object()) {
    // nlohmann::json takes std::string, not std::string_view, so materialise.
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
    if (!permission.empty())
        err["permission"] = std::string(permission);
    // Optional structured diagnosis merged under error.details (e.g. the per-store
    // decommission breakdown on a partial-erasure 500 — so the operator learns WHICH
    // store failed from the response itself, not only the audit log).
    if (!details.empty())
        err["details"] = details;
    json out;
    out["error"] = std::move(err);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

std::string ok_json(json data) {
    json out;
    out["data"] = std::move(data);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

void send_json(httplib::Response& res, int status, std::string body) {
    res.status = status;
    res.set_content(std::move(body), "application/json");
}

json agent_license_to_json(const AgentLicenseRow& r) {
    json j;
    j["product"] = r.product;
    j["vendor"] = r.vendor;
    j["version"] = r.version;
    j["license_type"] = r.license_type;
    j["state"] = r.state;
    j["expiry_at"] = r.expiry_at;
    j["channel"] = r.channel;
    j["key_hint"] = r.key_hint; // OS-provided partial only — never full key material
    j["detector"] = r.detector;
    j["confidence"] = r.confidence;
    j["exe_hints"] = r.exe_hints;
    // Personal data (ADR-0024 Decision 11): user_scope distinguishes per-user
    // detections; user_ref is the pseudonym (hash mode), raw name (collect), or
    // empty (omit) as minimised on-device. Rendering these is exactly why this
    // route is on the per-open behavioural-audit tier (G-2).
    j["user_scope"] = r.user_scope;
    j["user_ref"] = r.user_ref;
    j["collected_at"] = r.collected_at;
    j["first_seen"] = r.first_seen;
    j["last_seen"] = r.last_seen;
    return j;
}

} // namespace

void SleRoutes::register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                                AgentLicensesFn agent_licenses_fn, DecommissionFn decommission_fn,
                                AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(scoped_perm_fn), std::move(agent_licenses_fn),
                    std::move(decommission_fn), std::move(audit_fn));
}

void SleRoutes::register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                                AgentLicensesFn agent_licenses_fn, DecommissionFn decommission_fn,
                                AuditFn audit_fn) {
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    agent_licenses_fn_ = std::move(agent_licenses_fn);
    decommission_fn_ = std::move(decommission_fn);
    audit_fn_ = std::move(audit_fn);

    // ── GET /api/v1/sle/agents/{agent_id} — single-agent DRILL (scoped + fail-closed audit) ──
    // Decision 10/11: takes the WORKING ancestor-aware per-device scoped gate day one
    // (SoftwareLicensing:Read + agent scope; 403 outside scope), the device_routes
    // precedent. Renders per-agent detected licences INCLUDING user_scope/user_ref
    // (personal data), so it joins the per-open behavioural-audit tier
    // (emit_behavioral_audit, dex.device.view convention) and FAILS CLOSED (503 +
    // Sec-Audit-Failed) if the access-audit row cannot persist — the device's licence
    // PII is never served without durable evidence (SOC 2 CC7.2).
    sink.Get(R"(/api/v1/sle/agents/([^/]+))",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = make_cid();
                 res.set_header("X-Correlation-Id", cid);
                 const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";

                 // Per-device scope is MANDATORY — fail CLOSED if the gate is unwired
                 // rather than silently widening to a global read (mirrors the dex
                 // per-device REST route; production always wires it from server.cpp).
                 if (!scoped_perm_fn_) {
                     send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                     return;
                 }
                 if (!scoped_perm_fn_(req, res, "SoftwareLicensing", "Read", agent_id))
                     return; // the gate wrote its own 401/403

                 // Audit-on-open FAIL-CLOSED for this PII read (G-2): refuse to serve the
                 // agent's licence rows when the evidence row is KNOWN to have failed to
                 // persist. A null audit_fn is audit-off (not a failure) → serves, per the
                 // AuditFn contract. Set BEFORE the store read (per-open, not per-row).
                 if (!detail::emit_behavioral_audit(
                         audit_fn_, req, res, "sle.agent.view", "success", "Agent", agent_id,
                         "SLE per-agent detected-licence drill (renders user_scope/user_ref) cid=" +
                             cid)) {
                     send_json(res, 503,
                               a4_error(503,
                                        "audit subsystem unavailable; refusing to serve per-agent "
                                        "licence data without durable evidence",
                                        cid, 5000, "retry the request"));
                     spdlog::warn("sle.agent.view audit fail-closed (503) cid={} agent_id={}", cid,
                                  agent_id);
                     return;
                 }

                 std::optional<std::vector<AgentLicenseRow>> rows;
                 if (agent_licenses_fn_)
                     rows = agent_licenses_fn_(agent_id);
                 if (!rows) {
                     // Store/pool/query degrade — a durable failure-audit (the aggregate
                     // routes' pattern), then 503 (never a silent empty 200).
                     (void)detail::try_persist_audit(audit_fn_, req, "sle.agent.view", "failure",
                                                     "Agent", agent_id,
                                                     "detected-licence store degraded; cid=" + cid);
                     send_json(res, 503,
                               a4_error(503, "detected-licence store unavailable — read failed", cid,
                                        5000, "retry the request"));
                     return;
                 }

                 json licenses = json::array();
                 for (const auto& r : *rows)
                     licenses.push_back(agent_license_to_json(r));
                 json data;
                 data["agent_id"] = agent_id;
                 data["licenses"] = std::move(licenses);
                 data["count"] = static_cast<std::int64_t>(rows->size());
                 send_json(res, 200, ok_json(std::move(data)));
             });

    // ── DELETE /api/v1/sle/agents/{agent_id} — audited durable-erasure trigger (D-11) ──
    // The agent-decommission cascade's production caller: fans delete_agent across
    // every registered per-agent store, durably erasing the machine's stored rows
    // (including the Decision-11 user_ref personal data — the reason this route
    // exists). Gate: ONE SCOPED securable, `Decommission:Delete` (ADR-0024 Decision
    // 9, amended Wave 7 PR7.2) — a device-level erasure grant that authorizes for
    // the cascade's WHOLE blast radius, not the individual securables that govern
    // each store's READ. The radius is SIX stores: InventoryStore,
    // SoftwareInventoryStore, DeviceInventoryStore (all three read-gated by
    // `Inventory`), AppPerfDailyStore (read-gated by `GuaranteedState` — DEX
    // behavioural PII), SoftwareLicensingStore (read-gated by
    // `SoftwareLicensing`), and AppUsageStore (read-gated by `Forensics`,
    // Wave 7 PR7.2). Compat: the seeded
    // matrix is unchanged (Administrator + ITServiceOwner keep the ability, granted
    // via seed_defaults() with no migration); an operator-authored custom role that
    // had assembled the old per-store Delete grants is refused (403 naming
    // `Decommission:Delete`) until granted the new securable — breaking by design,
    // per PLAN-01 ruling (b): one nameable grant for what the operation destroys,
    // not a hand-maintained conjunction that silently widens with every store this
    // route touches. The old per-store Delete grants are NOT revoked and keep
    // gating their own stores' other routes. Scoped, so a group-confined holder
    // cannot erase an out-of-scope device.
    //
    // TWO durable audit events (spdlog alone is not GDPR Art.17 evidence):
    //   1. AUDIT-BEFORE-ERASE, FAIL-CLOSED (`sle.agent.decommission|attempt`): when
    //      the attempt row is KNOWN to have failed to persist, do NOT erase — an
    //      unaudited erasure destroys the very data that would evidence what was
    //      erased (503 + Sec-Audit-Failed). If the process dies mid-cascade, the
    //      attempt row still evidences who initiated it.
    //   2. OUTCOME (`sle.agent.decommission|success/partial`), set-and-proceed with
    //      the per-store breakdown.
    //
    // HONESTY (#1947): each store's delete_agent now returns committed status
    // (`[[nodiscard]] bool`, a false/rolled-back txn → `Failed`, never `Deleted`), so
    // `r.ok()` means every store's DELETE committed; a `Failed` store → 500 (the
    // cascade is idempotent; re-issue the DELETE).
    sink.Delete(
        R"(/api/v1/sle/agents/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            const auto cid = make_cid();
            res.set_header("X-Correlation-Id", cid);
            const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";
            if (!scoped_perm_fn_) {
                send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                return;
            }
            // ONE scoped gate for the cascade's whole blast radius (ADR-0024
            // Decision 9, amended Wave 7 PR7.2). Keep this in lockstep with
            // AgentDecommissionStores (the drift guard in test_agent_decommission.cpp
            // fails if a store is added without bumping kCascadeStoreCount).
            if (!scoped_perm_fn_(req, res, "Decommission", "Delete", agent_id))
                return; // the gate wrote its own 401/403
            if (!decommission_fn_) {
                send_json(res, 503, a4_error(503, "decommission cascade not configured", cid, 5000));
                return;
            }
            if (!detail::emit_behavioral_audit(
                    audit_fn_, req, res, "sle.agent.decommission", "attempt", "Agent", agent_id,
                    "durable-erasure cascade requested cid=" + cid)) {
                send_json(res, 503,
                          a4_error(503,
                                   "audit subsystem unavailable; refusing to erase without "
                                   "durable evidence",
                                   cid, 5000, "retry the request"));
                spdlog::warn("sle.agent.decommission audit fail-closed (503, no erase) cid={} "
                             "agent_id={}",
                             cid, agent_id);
                return;
            }

            const DecommissionResult r = decommission_fn_(agent_id);

            std::string breakdown;
            json stores = json::object();
            for (const auto& s : r.stores) {
                stores[s.store] = to_string(s.outcome);
                breakdown += s.store;
                breakdown += '=';
                breakdown += to_string(s.outcome);
                breakdown += ' ';
            }
            (void)detail::try_persist_audit(
                audit_fn_, req, "sle.agent.decommission", r.ok() ? "success" : "partial", "Agent",
                agent_id,
                breakdown + "deleted=" + std::to_string(r.deleted) +
                    " skipped=" + std::to_string(r.skipped) +
                    " failed=" + std::to_string(r.failed) + " cid=" + cid);

            if (!r.ok()) {
                // Echo the per-store breakdown into the 500 body so the operator can
                // see WHICH store failed (and which already erased) from the response
                // itself — not only by pulling the audit log. Idempotent re-DELETE
                // then targets the remaining failures.
                send_json(res, 500,
                          a4_error(500,
                                   "agent decommission incomplete — one or more stores failed (" +
                                       std::to_string(r.failed) +
                                       " failed); re-issue the DELETE (the cascade is idempotent)",
                                   cid, 5000, "retry the request", /*permission=*/{},
                                   json{{"stores", stores},
                                        {"deleted", static_cast<std::int64_t>(r.deleted)},
                                        {"skipped", static_cast<std::int64_t>(r.skipped)},
                                        {"failed", static_cast<std::int64_t>(r.failed)}}));
                return;
            }
            json data;
            data["agent_id"] = agent_id;
            data["decommissioned"] = true;
            data["stores"] = std::move(stores);
            data["deleted"] = static_cast<std::int64_t>(r.deleted);
            data["skipped"] = static_cast<std::int64_t>(r.skipped);
            data["failed"] = static_cast<std::int64_t>(r.failed);
            send_json(res, 200, ok_json(std::move(data)));
        });
}

} // namespace yuzu::server
