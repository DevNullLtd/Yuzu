/**
 * viz_routes.cpp -- /viz/fleet REST + fragment routes (PR 3 of 11)
 *
 * Each handler:
 *  1. Kill-switch consult -- 503 with structured envelope. Tier-before-
 *     permission ordering per docs/auth-architecture.md §3 + the MCP
 *     precedent at mcp_server.cpp:355: cheap configuration-pinned guards
 *     run BEFORE identity-bound RBAC. Audited so the kill switch leaves
 *     an evidence trail even when the caller would have failed RBAC
 *     anyway (DEP-1, gov R3 sec-M1/arch-B1).
 *  2. Store-availability consult -- 503 if the store is null (server
 *     started without the cache wired).
 *  3. Tier/RBAC check via perm_fn_ ("Response", "Read") -- 401/403 paths
 *     fall out of the perm_fn_ contract and short-circuit before any
 *     dispatch.
 *  4. Parse query params with strict numeric guards. Failures -> 400.
 *  5. Optional `?fresh=1` invalidates the cache before get(). Audited
 *     separately from the success row so the operator-driven cache flush
 *     is its own audit event.
 *  6. get(include_vuln) returns a non-null shared_ptr<TopologySnapshot>
 *     (UP-9 invariant from PR 2 hardening). Cache-hit/miss counters are
 *     observed by diffing the store's atomic counters across the call.
 *  7. machines_max gate -- M-1 cap-check DoS. Compared against the
 *     materialised count; 413 if over, with audit row. We do NOT serve
 *     a truncated snapshot -- truncation would mislead operators about
 *     which subset they're seeing.
 *  8. Serialise + ship. Per-request latency goes to the
 *     yuzu_viz_topology_request_seconds histogram.
 *
 * Fragment vs JSON routes share the same body via handle_topology(). The
 * fragment wraps the JSON in `<script type="application/json"
 * id="viz-data">` so the renderer can parse-on-swap without an extra
 * round-trip (agentic-first A1 -- dashboard parity).
 *
 * Result-string vocabulary: "success" / "denied" / "failure" matching
 * the audit_store counter buckets and sibling handlers (gov R3 C-1).
 * Older drafts of this file used "ok" / "error" / "oversize" -- those
 * buckets land in events_other_ in the Prometheus scrape, breaking
 * SOC 2 SIEM filter assumptions.
 */

#include "viz_routes.hpp"

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "http_route_sink.hpp"
#include "offline_endpoint_store.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

/// A4 JSON error envelope (`detail::a4_error`, `rest_a4_envelope_http.hpp`).
/// `code` derives from `res.status`, which every call site sets immediately
/// before calling this — kept as a thin file-local wrapper rather than
/// inlining `detail::a4_error` at all 13 call sites.
std::string error_envelope(httplib::Response& res, std::string_view message) {
    return detail::a4_error(res, message);
}

bool parse_bool_param(const httplib::Request& req, std::string_view key, bool default_value) {
    if (!req.has_param(std::string(key)))
        return default_value;
    auto v = req.get_param_value(std::string(key));
    return v == "1" || v == "true" || v == "yes" || v == "TRUE";
}

/// Replace any literal `</` in the serialised JSON with `<\/`. Required
/// when embedding into `<script type="application/json">` because the
/// HTML5 parser terminates the script element on the first `</script` it
/// sees, regardless of context. nlohmann::json does NOT escape `<` by
/// default (it's outside the JSON-mandatory escape set), so an
/// agent-controlled hostname/cmdline string containing `</script>` would
/// otherwise break out of the wrapper element. Backslash-solidus is
/// spec-valid JSON ("\/" is an alternate escape for "/"). gov R3
/// sec-M2/UP-16/CH-6 fix.
///
/// Re-running on already-escaped output (e.g., a `<\/` substring) does
/// not double-escape because `find("</")` skips past the inserted
/// backslash on each step: pos advances by 3 (the inserted len), past
/// the `<\/` triple, so a subsequent `</` scan starts from a char
/// after the previously-escaped slash.
void escape_json_for_script(std::string& s) {
    std::string::size_type pos = 0;
    while ((pos = s.find("</", pos)) != std::string::npos) {
        s.replace(pos, 2, "<\\/");
        pos += 3; // skip past the inserted backslash
    }
}

} // namespace

void VizRoutes::register_routes(httplib::Server& svr, AuthFn /*auth_fn*/, PermFn perm_fn,
                                AuditFn audit_fn, FleetTopologyStore* store,
                                yuzu::MetricsRegistry* metrics,
                                const std::atomic<bool>* kill_switch,
                                OfflineEndpointStore* offline_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, AuthFn{}, std::move(perm_fn), std::move(audit_fn), store, metrics,
                    kill_switch, offline_store);
}

void VizRoutes::register_routes(HttpRouteSink& sink, AuthFn /*auth_fn*/, PermFn perm_fn,
                                AuditFn audit_fn, FleetTopologyStore* store,
                                yuzu::MetricsRegistry* metrics,
                                const std::atomic<bool>* kill_switch,
                                OfflineEndpointStore* offline_store) {
    // auth_fn is accepted in the signature for parity with sibling
    // register_routes overloads but never invoked here -- require_permission
    // (which the perm_fn lambda wraps) calls require_auth internally, so a
    // separate auth_fn call would just duplicate work. Discarded explicitly
    // rather than stored, per gov R3 arch-S4.
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    store_ = store;
    metrics_ = metrics;
    kill_switch_ = kill_switch;
    offline_store_ = offline_store;

    sink.Get("/api/v1/viz/fleet/topology",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_topology(req, res, /*as_fragment=*/false);
             });

    sink.Get("/fragments/viz/fleet/topology",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_topology(req, res, /*as_fragment=*/true);
             });

    // Per-host drill-down. Pattern is a regex so the agent_id is captured in
    // req.matches[1]. fleet-viz-invariants.md § Route ordering: register
    // /viz/fleet BEFORE /viz/host/<id> — both are literal-prefix routes (the
    // regex parameter only matches after `/api/v1/viz/host/`), no overlap,
    // but follow the convention.
    sink.Get(R"(/api/v1/viz/host/([^/]+)/topology)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_host_topology(req, res, /*as_fragment=*/false);
             });

    sink.Get(R"(/fragments/viz/host/([^/]+)/topology)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_host_topology(req, res, /*as_fragment=*/true);
             });
}

void VizRoutes::handle_topology(const httplib::Request& req, httplib::Response& res,
                                bool as_fragment) {
    const auto t_start = std::chrono::steady_clock::now();

    // ── 1. Kill switch (DEP-1, tier-before-permission) ────────────────────
    // Cheap configuration-pinned guard runs before identity-bound RBAC so
    // disable state is observable regardless of caller identity, matching
    // the MCP precedent at mcp_server.cpp:355.
    if (kill_switch_ && kill_switch_->load(std::memory_order_acquire)) {
        res.status = 503;
        res.set_content(
            error_envelope(res, "viz endpoint disabled by operator (yuzu_viz_disabled)"),
            "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "denied", "FleetTopology", "", "kill_switch");
        return;
    }

    // ── 2. Store availability ────────────────────────────────────────────
    if (!store_) {
        res.status = 503;
        res.set_content(error_envelope(res, "fleet topology store not available"),
                        "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "failure", "FleetTopology", "", "store_null");
        return;
    }

    // ── 3. RBAC ───────────────────────────────────────────────────────────
    // perm_fn_ writes the 401/403 body and status itself; bail on false.
    if (!perm_fn_(req, res, "Response", "Read"))
        return;

    // ── 4. Parse query params ────────────────────────────────────────────
    const bool include_vuln = parse_bool_param(req, "include_vuln", false);
    const bool fresh = parse_bool_param(req, "fresh", false);

    int machines_max = kDefaultMachinesMax;
    try {
        if (req.has_param("machines_max")) {
            machines_max = std::stoi(req.get_param_value("machines_max"));
            if (machines_max <= 0 || machines_max > kMachinesMaxCeiling) {
                res.status = 400;
                res.set_content(error_envelope(res, "machines_max must be in [1, 100000]"),
                                "application/json");
                if (audit_fn_)
                    audit_fn_(req, "viz.fleet_topology", "denied", "FleetTopology", "",
                              "bad_machines_max");
                return;
            }
        }
    } catch (const std::exception&) {
        // std::stoi throws std::invalid_argument on non-numeric and
        // std::out_of_range on overflow; both land here.
        res.status = 400;
        res.set_content(error_envelope(res, "invalid machines_max"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "denied", "FleetTopology", "", "bad_machines_max");
        return;
    }

    // ── 5. Optional fresh -- emit its own audit row before the get ────────
    if (fresh) {
        store_->invalidate();
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology.invalidate", "success", "FleetTopology", "", "");
    }

    // ── 6. Fetch (cache-hit fast-path or single-flight refill) ────────────
    const auto pre_hits = store_->cache_hits();
    const auto pre_misses = store_->cache_misses();

    std::shared_ptr<const TopologySnapshot> snap;
    try {
        snap = store_->get(include_vuln);
    } catch (const std::exception& ex) {
        spdlog::error("VizRoutes: store->get threw: {}", ex.what());
        res.status = 500;
        res.set_content(error_envelope(res, "topology fetch failed"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "failure", "FleetTopology", "", "fetch_threw");
        return;
    }
    // PR 2 invariant UP-9: get() never returns null. Defensive belt anyway.
    if (!snap) {
        res.status = 500;
        res.set_content(error_envelope(res, "topology fetch returned null"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "failure", "FleetTopology", "", "snap_null");
        return;
    }

    if (metrics_) {
        if (store_->cache_hits() > pre_hits)
            metrics_->counter("yuzu_viz_cache_hit_total").increment();
        if (store_->cache_misses() > pre_misses)
            metrics_->counter("yuzu_viz_cache_miss_total").increment();
    }

    // ── 6b. Merge persisted offline endpoints (#1320 PR 3) ────────────────
    // Hosts whose fleet_snapshot aged out of the in-memory 60 s cache vanish
    // from snap->machines. The durable last-known store lets them render as
    // stale-flagged cubes instead of disappearing. merge_offline_topology
    // (fleet_topology_store.{hpp,cpp}) is the SHARED pure transform the MCP
    // get_fleet_topology tool also calls (api-twin-recipe.md Rule 1) — the
    // copy-on-write / online-set-dedup rule cannot drift between the two
    // surfaces. Null store (tests, or a legacy binary) = exactly the prior
    // behavior (no query, snap unchanged). Done BEFORE the DoS gate so the
    // machines_max cap counts the merged total.
    if (offline_store_) {
        auto persisted =
            offline_store_->query_stale_within(std::chrono::seconds(kOfflineStaleWindowSecs));
        const auto before = snap->machines.size();
        snap = merge_offline_topology(std::move(snap), persisted);
        const auto merged_count = snap->machines.size() - before;
        if (merged_count > 0 && metrics_)
            metrics_->counter("yuzu_viz_offline_hosts_total")
                .increment(static_cast<double>(merged_count));
    }

    // ── 7. machines_max DoS gate (M-1) ────────────────────────────────────
    if (static_cast<int>(snap->machines.size()) > machines_max) {
        res.status = 413;
        res.set_content(
            error_envelope(res, "fleet topology exceeds machines_max -- raise the cap or scope down"),
            "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "denied", "FleetTopology", "",
                      "oversize machines=" + std::to_string(snap->machines.size()) +
                          " cap=" + std::to_string(machines_max));
        if (metrics_)
            metrics_->counter("yuzu_viz_oversize_response_total").increment();
        return;
    }

    // ── 8. Serialise + respond ───────────────────────────────────────────
    nlohmann::json j = *snap;
    // Governance Gate 4 BLOCKING fix (#2146 Batch B3 review): dump_topology_safe()
    // (fleet_topology_types.hpp) substitutes U+FFFD instead of throwing on a
    // byte-clamped multi-byte codepoint - clamp_field() truncates by byte
    // length with no UTF-8 boundary awareness, and strict dump()'s uncaught
    // type_error.316 was a fleet-wide 500 triggerable by ordinary
    // internationalized agent data. Shared with the MCP twin so the fix
    // cannot drift between transports the way the original bug did.
    auto body = dump_topology_safe(j);

    if (as_fragment) {
        // HTMX fragment: parser-recoverable script tag carrying the JSON.
        // The id is fixed so the renderer can locate it deterministically
        // after htmx swaps the parent. Escape `</` to `<\/` in the JSON
        // body before wrapping -- nlohmann::json does NOT escape `<`, and
        // an agent-controlled hostname/cmdline containing `</script>`
        // would terminate the script element early without this fixup
        // (gov R3 sec-M2/UP-16).
        escape_json_for_script(body);
        std::string fragment;
        fragment.reserve(body.size() + 64); // gov R3 P-S2 fix
        fragment.append("<script type=\"application/json\" id=\"viz-data\">");
        fragment.append(body);
        fragment.append("</script>");
        res.set_content(std::move(fragment), "text/html; charset=utf-8");
    } else {
        res.set_content(std::move(body), "application/json");
    }

    if (audit_fn_) {
        audit_fn_(req, "viz.fleet_topology", "success", "FleetTopology", "",
                  "machines=" + std::to_string(snap->machines.size()) +
                      " include_vuln=" + (include_vuln ? "1" : "0") + (fresh ? " fresh=1" : "") +
                      (as_fragment ? " fragment=1" : ""));
    }

    if (metrics_) {
        const auto elapsed = std::chrono::steady_clock::now() - t_start;
        const double seconds = std::chrono::duration<double>(elapsed).count();
        metrics_->histogram("yuzu_viz_topology_request_seconds").observe(seconds);
    }
}

void VizRoutes::handle_host_topology(const httplib::Request& req, httplib::Response& res,
                                     bool as_fragment) {
    const auto t_start = std::chrono::steady_clock::now();
    const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";

    // Gate 8 security-guardian BLOCKING fix (#2146 Batch B3 review): this
    // path-captured agent_id (regex [^/]+, no length/charset constraint of
    // its own) flows unchecked into audit_fn_'s target_id below on every
    // branch - AuditStore's sanitizer scrubs invalid UTF-8/NUL but not other
    // C0 control bytes, so an unfloored agent_id let any Response:Read
    // holder write raw control bytes/CR-LF into the audit trail. Same floor
    // as GET /guaranteed-state/events and this file's own MCP twin,
    // get_host_topology (auth::kMaxAgentIdLength).
    if (agent_id.size() > auth::kMaxAgentIdLength) {
        res.status = 400;
        res.set_content(error_envelope(res, "agent_id is too long"), "application/json");
        return;
    }
    for (unsigned char c : agent_id) {
        if (c < 0x20) {
            res.status = 400;
            res.set_content(error_envelope(res, "agent_id contains control characters"),
                            "application/json");
            return;
        }
    }

    // ── 1. Kill switch (tier-before-permission) ──────────────────────────
    if (kill_switch_ && kill_switch_->load(std::memory_order_acquire)) {
        res.status = 503;
        res.set_content(
            error_envelope(res, "viz endpoint disabled by operator (yuzu_viz_disabled)"),
            "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.host_topology", "denied", "HostTopology", agent_id, "kill_switch");
        return;
    }

    // ── 2. Store availability ─────────────────────────────────────────────
    if (!store_) {
        res.status = 503;
        res.set_content(error_envelope(res, "fleet topology store not available"),
                        "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.host_topology", "failure", "HostTopology", agent_id, "store_null");
        return;
    }

    // ── 3. RBAC ──────────────────────────────────────────────────────────
    // perm_fn_ writes 401/403 body and status itself; bail on false.
    if (!perm_fn_(req, res, "Response", "Read"))
        return;

    // ── 4. Fetch (mirrors handle_topology: try/catch + null guard) ───────
    const auto pre_hits = store_->cache_hits();
    const auto pre_misses = store_->cache_misses();

    std::shared_ptr<const TopologySnapshot> snap;
    try {
        snap = store_->get(/*include_vuln=*/false);
    } catch (const std::exception& ex) {
        spdlog::error("VizRoutes: store->get threw (host_topology): {}", ex.what());
        res.status = 500;
        res.set_content(error_envelope(res, "topology fetch failed"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.host_topology", "failure", "HostTopology", agent_id, "fetch_threw");
        return;
    }
    // get() is documented never to return null; defensive belt anyway --
    // an unguarded deref here is a remotely reachable post-auth crash.
    if (!snap) {
        res.status = 500;
        res.set_content(error_envelope(res, "topology fetch returned null"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.host_topology", "failure", "HostTopology", agent_id, "snap_null");
        return;
    }

    if (metrics_) {
        if (store_->cache_hits() > pre_hits)
            metrics_->counter("yuzu_viz_cache_hit_total").increment();
        if (store_->cache_misses() > pre_misses)
            metrics_->counter("yuzu_viz_cache_miss_total").increment();
    }

    // ── 5. Slice the requested host out of the fleet snapshot ────────────
    for (const auto& m : snap->machines) {
        if (m.agent_id == agent_id) {
            HostTopologySnapshot wrapper{snap->generated_at, m.stale, m};
            nlohmann::json j = wrapper;
            // Governance Gate 4 BLOCKING fix (#2146 Batch B3 review): see
            // handle_topology's identical fix above.
            auto body = dump_topology_safe(j);

            if (as_fragment) {
                escape_json_for_script(body);
                std::string fragment;
                fragment.reserve(body.size() + 64);
                fragment.append("<script type=\"application/json\" id=\"viz-data\">");
                fragment.append(body);
                fragment.append("</script>");
                res.set_content(std::move(fragment), "text/html; charset=utf-8");
            } else {
                res.set_content(std::move(body), "application/json");
            }

            if (audit_fn_)
                audit_fn_(req, "viz.host_topology", "success", "HostTopology", agent_id,
                          as_fragment ? "fragment=1" : "");
            if (metrics_) {
                const auto elapsed = std::chrono::steady_clock::now() - t_start;
                metrics_->histogram("yuzu_viz_topology_request_seconds")
                    .observe(std::chrono::duration<double>(elapsed).count());
            }
            return;
        }
    }
    res.status = 404;
    res.set_content(error_envelope(res, "host not found"), "application/json");
    if (audit_fn_)
        audit_fn_(req, "viz.host_topology", "failure", "HostTopology", agent_id, "not_found");
}

} // namespace yuzu::server
