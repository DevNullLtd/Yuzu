#include "health_routes.hpp"

#include "http_route_sink.hpp"

#include "agent_registry.hpp"
#include "access_review_store.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "baseline_store.hpp"
#include "ca_store.hpp"
#include "custom_properties_store.hpp"
#include "default_certs.hpp"
#include "deployment_store.hpp"
#include "device_inventory_store.hpp"
#include "directory_sync.hpp"
#include "discovery_store.hpp"
#include "engine_principal_store.hpp"
#include "command_outbox_store.hpp" // WS-3 3.3
#include "execution_tracker.hpp"
#include "fleet_topology_store.hpp"
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "nvd_db.hpp"
#include "nvd_sync.hpp"
#include "offline_endpoint_store.hpp"
#include "offload_target_store.hpp"
#include "patch_manager.hpp"
#include "pg/pg_pool.hpp"
#include "pg_reachability_probe.hpp" // HA WS-8
#include "plugin_config_store.hpp"
#include "policy_store.hpp"
#include "process_health.hpp"
#include "product_pack_store.hpp"
#include "product_registry_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "result_set_store.hpp"
#include "runtime_config_store.hpp"
#include "schedule_engine.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"
#include "app_usage_store.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"
#include "upload_grant_store.hpp"
#include "vuln_finding_store.hpp"
#include "webhook_store.hpp"
#include "workflow_engine.hpp"

#include <yuzu/server/scim_store.hpp>
#include <yuzu/server/server.hpp>
#include <yuzu/version.hpp>

#include <nlohmann/json.hpp>

#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace yuzu::server::health {

void register_health_routes(HttpRouteSink& sink, Deps deps) {
    // See this file's header comment ("DEPS NULL-SAFETY") for why these are
    // hard registration-time requirements: an unbound closure is a wiring
    // bug caught at boot, not a runtime condition to degrade around (same
    // rationale as dashboard_api_routes.hpp's visible_agents_json_fn check).
    if (!deps.cfg)
        throw std::invalid_argument("register_health_routes: deps.cfg must be bound");
    if (!deps.metrics)
        throw std::invalid_argument("register_health_routes: deps.metrics must be bound");
    if (!deps.auth_fn)
        throw std::invalid_argument("register_health_routes: deps.auth_fn must be bound");
    if (!deps.resolve_session_fn)
        throw std::invalid_argument(
            "register_health_routes: deps.resolve_session_fn must be bound");
    if (!deps.deny_service_scoped_fn)
        throw std::invalid_argument(
            "register_health_routes: deps.deny_service_scoped_fn must be bound");

    // -- Prometheus metrics endpoint ----------------------------------------
    // Per-scrape serialization lock for the NVD failure-count delta loop
    // below (Pull model, #1909) — was `ServerImpl::nvd_metrics_scrape_mu_`,
    // a member with exactly ONE use site (this handler). Moved to a local,
    // shared_ptr-captured mutex: a local with no other ServerImpl
    // dependency, same justification as PR-5's `rs_get_owned` closure move
    // (see this file's header comment). The `ServerImpl` member declaration
    // is deleted by this extraction.
    auto scrape_mu = std::make_shared<std::mutex>();
    sink.Get("/metrics", [deps, scrape_mu](const httplib::Request&, httplib::Response& res) {
        // WS-3 3.3 (sre-F2/WS-11): refresh the command-outbox delivery-backlog
        // gauge on scrape (regardless of leadership — a stuck loop that never
        // acquires leadership shows flat event counters, so this gauge is the
        // only signal that scheduled dispatch has silently stopped). A degraded
        // read returns nullopt → leave the last value rather than publish a false 0.
        if (deps.command_outbox_store && deps.command_outbox_store->is_open()) {
            if (auto pending = deps.command_outbox_store->count_pending(); pending.has_value())
                deps.metrics->gauge("yuzu_server_command_outbox_pending")
                    .set(static_cast<double>(*pending));
        }
        // HA WS-8: Postgres reachability as THIS replica sees it (a leaf-locked
        // copy of the probe's snapshot, no I/O). Set on scrape so the value is
        // never older than the scrape itself.
        if (deps.pg_reachability_probe) {
            const auto snap = deps.pg_reachability_probe->snapshot();
            const auto now = yuzu::server::PgReachabilityProbe::now_ns();
            deps.metrics->gauge("yuzu_server_pg_reachable")
                .set(yuzu::server::pg_reachability::classify(snap, now) ==
                             yuzu::server::pg_reachability::Verdict::Ready
                         ? 1
                         : 0);
            if (snap.last_success_ns != yuzu::server::pg_reachability::kNever)
                deps.metrics->gauge("yuzu_server_pg_reachability_last_success_age_seconds")
                    .set(static_cast<double>(now - snap.last_success_ns) / 1e9);
        }
        // Refresh management group gauges before serializing
        if (deps.mgmt_group_store && deps.mgmt_group_store->is_open()) {
            deps.metrics->gauge("yuzu_server_management_groups_total")
                .set(static_cast<double>(deps.mgmt_group_store->count_groups()));
            deps.metrics->gauge("yuzu_server_group_members_total")
                .set(static_cast<double>(deps.mgmt_group_store->count_all_members()));
        }
        // Refresh NVD backfill gauges (multi-hour background job — needs to be
        // observable; governance sre BLOCKING).
        if (deps.nvd_db && deps.nvd_db->is_open()) {
            deps.metrics->gauge("yuzu_nvd_total_cves")
                .set(static_cast<double>(deps.nvd_db->total_cve_count()));
            if (deps.nvd_sync) {
                auto st = deps.nvd_sync->status();
                deps.metrics->gauge("yuzu_nvd_backfill_complete")
                    .set(st.backfill_complete ? 1 : 0);
                // Pull model (#1909): the manager holds the authoritative monotonic
                // per-reason failure counts; emit them as yuzu_nvd_sync_failures_total by
                // incrementing the exported series by the delta since the last scrape
                // (Counter has no set()). No sync-thread→metrics_ callback → no teardown race.
                // The whole loop is serialized so two CONCURRENT /metrics scrapes (an HA
                // Prometheus pair) can't both read the same value(), compute the same delta,
                // and double-increment the counter (which would then stall until the real
                // tally re-exceeds it).
                std::lock_guard<std::mutex> emit_lock{*scrape_mu};
                for (auto r : kNvdCountedReasons) {
                    const int i = nvd_reason_index(r);
                    auto& c = deps.metrics->counter("yuzu_nvd_sync_failures_total",
                                                     {{"reason", nvd_reason_label(r)}});
                    const double delta = static_cast<double>(st.failure_counts[i]) - c.value();
                    if (delta > 0)
                        c.increment(delta);
                }
            }
        }
        res.set_content(deps.metrics->serialize(), "text/plain; version=0.0.4; charset=utf-8");
    });

    // -- Health endpoint (7.2) ------------------------------------------------
    // Mounted on both /health and /api/health (issue #620). The /api alias
    // exists so monitoring integrations that prefix every REST call with
    // /api/ keep working — a side-effect of #401's move from /api/health → /health.
    auto health_handler = [deps](const httplib::Request& req, httplib::Response& res) {
        // Resolve auth FIRST so we can gate expensive work on it.
        // Governance Gate 7 round 2 (security MEDIUM): /health and
        // /api/health are rate-limit-exempt for monitoring stability;
        // the bounded but non-trivial work below (a pending-agents scan
        // and bounded execution_tracker reads — two PG pool leases,
        // ADR-0065) must only run for authenticated callers, otherwise
        // an unauth flood becomes a DoS amplification primitive. Unauth
        // callers get the cheap
        // probe response — status, uptime, agent count from in-memory
        // registry, store ok flags from is_open() (constant-time member
        // checks), and version. Authed callers additionally get
        // pending-agent count, execution stats, and process sampler.
        bool is_authenticated = static_cast<bool>(deps.resolve_session_fn(req));

        auto now = std::chrono::steady_clock::now();
        auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
                              now - deps.server_start_time)
                              .count();

        // Cheap: in-memory agent registry count.
        std::size_t online = deps.registry ? deps.registry->agent_count() : 0;

        // Store health — all checks are constant-time and perform no DB I/O.
        // Match /readyz's non-lease-consuming Postgres reachability signal:
        // valid() checks configuration and the breaker records real connect
        // failures without treating a saturated-but-healthy pool as down.
        bool pg_pool_ok =
            deps.pg_pool && deps.pg_pool->valid() && !deps.pg_pool->connect_breaker_open();
        // HA WS-8: the runtime reachability probe — mirrors /readyz's gating
        // `pg_reachable` row so the two probes agree (a leaf-locked copy, no I/O).
        bool pg_reachable_ok =
            deps.pg_reachability_probe &&
            deps.pg_reachability_probe->verdict() == yuzu::server::pg_reachability::Verdict::Ready;
        auto response_ok = deps.response_store && deps.response_store->is_open();
        auto audit_ok = deps.audit_store && deps.audit_store->is_open();
        auto instruction_ok = deps.instruction_store && deps.instruction_store->is_open();
        auto policy_ok = deps.policy_store && deps.policy_store->is_open();
        // Guardian store is load-bearing for the /api/v1/guaranteed-state/*
        // surface; prior to inclusion here /healthz reported "healthy" while
        // every Guardian endpoint returned 503. Mirrors the /readyz conjunction.
        bool guaranteed_state_ok =
            deps.guaranteed_state_store && deps.guaranteed_state_store->is_open();
        // Guardian Baselines store — load-bearing for the Baseline dashboard +
        // deploy surface; same rationale as the Guard store row above.
        bool baseline_ok = deps.baseline_store && deps.baseline_store->is_open();
        // Phase 8.3 #255 — same pattern as Guardian above. Without
        // this row /healthz would report "healthy" while every
        // /api/v1/offload-targets endpoint and every fire_event call
        // silently no-ops on a migration failure (HC-1 from Gate 6).
        bool offload_target_ok = deps.offload_target_store && deps.offload_target_store->is_open();
        // #3261 governance hardening (Gate 6 SRE) - same HC-1 gap class
        // as offload_target above; webhook_store was missing from this
        // probe even though its sibling was already covered.
        bool webhook_ok = deps.webhook_store && deps.webhook_store->is_open();
        // #1238 B-3: ca_store is load-bearing whenever default certs are active
        // (issuance / revocation / CRL). It was wired into /readyz but missing
        // here, so /healthz could report "healthy" with a dead ca_store. Mirrors
        // the /readyz conjunction; trivially true when not on default certs
        // (the operator brought their own, so ca_store isn't required).
        bool ca_ok = !deps.cfg->using_default_certs || (deps.ca_store && deps.ca_store->is_open());
        // ADR-0061: UpdateRegistry — only load-bearing when cfg_.ota_enabled
        // is true (default ON, opt-out via --no-ota). Mirrors /readyz's own
        // entry; NOT analogous to ca_ok just above (using_default_certs is
        // itself true for the ordinary out-of-box self-signed deployment,
        // not an "off by default" gate).
        bool update_registry_ok =
            !deps.cfg->ota_enabled || (deps.update_registry && deps.update_registry->is_open());
        // Born-on-Postgres stores (ADR-0012). They were wired into /readyz but
        // not here, so /healthz could report "healthy" with a degraded store —
        // the same gap the Guardian/CA rows above closed. The server fails
        // closed at boot if PG is unreachable, so on a running server these are
        // open. is_open() is latched at construction (#3061), so these rows report
        // BOOT state only; a post-boot Postgres outage shows on the pg_reachable row
        // of /readyz, not here.
        bool offline_endpoint_ok =
            deps.offline_endpoint_store && deps.offline_endpoint_store->is_open();
        bool software_inventory_ok =
            deps.software_inventory_store && deps.software_inventory_store->is_open();
        bool vuln_finding_ok = deps.vuln_finding_store && deps.vuln_finding_store->is_open();
        bool app_perf_daily_ok = deps.app_perf_daily_store && deps.app_perf_daily_store->is_open();
        bool app_perf_fleet_ok = deps.app_perf_fleet_store && deps.app_perf_fleet_store->is_open();
        bool device_inventory_ok =
            deps.device_inventory_store && deps.device_inventory_store->is_open();
        // Generic InventoryStore (ADR-0037) — was wired into /readyz but missing
        // here (governance IS2: the file's own comments document this exact
        // readyz-vs-healthz drift as a previously-shipped bug for other stores).
        bool inventory_ok = deps.inventory_store && deps.inventory_store->is_open();
        // Load-bearing for the MCP write surface + REST approvals (sre-BLOCKING-1).
        bool approval_ok = deps.approval_manager && deps.approval_manager->is_open();
        // RbacStore (authorization substrate, ADR-0041) — now born-on-PG and
        // load-bearing for every RBAC/authz check. It was in /readyz but not
        // here; a degraded rbac_store fails authz reads CLOSED (denies), so a
        // "healthy" report over a dead authz store would be misleading.
        bool rbac_ok = deps.rbac_store && deps.rbac_store->is_open();
        // #2636: ResultSetStore was wired into /readyz but missing here — same
        // readyz-vs-healthz drift class the InventoryStore row above documents.
        // Fixed alongside the ADR-0038 GuaranteedStateStore migration since both
        // land in the same PR.
        bool result_set_ok = deps.result_set_store && deps.result_set_store->is_open();
        // Management-group CONFINEMENT substrate (ADR-0042) — was wired into
        // /readyz but missing here, the same readyz-vs-healthz drift the
        // rows above document. A degraded confinement store fails RbacStore's
        // list gate closed, so surface it.
        bool mgmt_group_ok = deps.mgmt_group_store && deps.mgmt_group_store->is_open();
        // DiscoveryStore (ADR-0044) — wired into /readyz; adding here too so
        // this store never joins the readyz-vs-healthz drift class the rows
        // above were added to fix.
        bool discovery_ok = deps.discovery_store && deps.discovery_store->is_open();
        // DeploymentStore (ADR-0043, gov sre finding, hardening
        // round) — parity with every other migrated authoritative store's
        // readyz/healthz wiring; construction is already fail-closed, and
        // is_open() is latched (#3061), so this reports boot state only.
        bool deployment_ok = deps.deployment_store && deps.deployment_store->is_open();
        // QuarantineStore (ADR-0047) — wired into /readyz; adding here
        // too so this store never joins the readyz-vs-healthz drift
        // class the rows above were added to fix.
        bool quarantine_ok = deps.quarantine_store && deps.quarantine_store->is_open();
        // NotificationStore (ADR-0046) — born-on-PG (as of this migration),
        // same readyz-vs-healthz drift class the rows above document; wire
        // it into both from the start rather than shipping the gap and
        // fixing it in a later governance round (Gate 3 sre, Pattern E).
        bool notification_ok = deps.notification_store && deps.notification_store->is_open();
        // UploadGrantStore (ADR-3004, PR1.6a) — review finding (#3135):
        // constructed fail-closed at boot (server.cpp startup_failed_ flip
        // if migration/open fails) but was absent from both /healthz and
        // /readyz, the same readyz-vs-healthz drift class the rows above
        // document. Startup fail-closed limits the immediate blast radius,
        // and a store that failed to open would leave /api/v1/upload-grants*
        // 503ing while both probes reported healthy. (is_open() is latched at
        // boot, #3061 — this row reports that boot state.)
        bool upload_grant_ok = deps.upload_grant_store && deps.upload_grant_store->is_open();
        // TagStore (ADR-0050) — born-on-PG (as of this migration), wired
        // into both /readyz and /healthz from the start (the
        // readyz-vs-healthz drift class the rows above document). A
        // degraded tag store fails scope resolution and service-scoped
        // confinement CLOSED, so a "healthy" report over it would be
        // misleading.
        bool tag_ok = deps.tag_store && deps.tag_store->is_open();
        // ADR-0060: /readyz's StoreCheck vector already names this store; /healthz
        // omitted it (governance Gate 3 finding, architect + sre independently) --
        // /readyz is what actually gates traffic, so this was a monitoring-signal
        // gap, not an availability one, but the two probes should agree on which
        // stores exist.
        bool runtime_config_ok = deps.runtime_config_store && deps.runtime_config_store->is_open();
        // ADR-0062 (Wave 4 non-`*Store` migration) — same readyz-vs-healthz
        // drift class the rows above document; wired into both from the
        // start rather than shipping the gap. Construction is fail-closed and
        // is_open() is latched (#3061), so this reports boot state only.
        bool patch_manager_ok = deps.patch_manager && deps.patch_manager->is_open();
        // HA WS-1/1a: durable operator sessions. /readyz's StoreCheck vector
        // names this store; mirror it here so the two probes agree (same
        // anti-drift rule as runtime_config above) and match the documented
        // "reported at /readyz and /healthz" contract. is_session_store_ok()
        // is true on legacy config-file-only deployments (no store wired).
        bool session_store_ok = deps.auth_mgr && deps.auth_mgr->is_session_store_ok();
        // ADR-0063 (migration-programme PR 3) — same readyz-vs-healthz
        // drift class the rows above document; wired into both from the
        // start rather than shipping the gap. Construction is fail-closed and
        // is_open() is latched (#3061), so this reports boot state only.
        bool directory_sync_ok = deps.directory_sync && deps.directory_sync->is_open();
        // ADR-0064 (Wave 4 non-`*Store` migration) — same readyz-vs-healthz drift class:
        // workflow_engine was already in /readyz's StoreCheck vector (below) but absent
        // here in the SQLite era.
        bool workflow_engine_ok = deps.workflow_engine && deps.workflow_engine->is_open();
        // ADR-0065 (migration-programme PR 5, 1/3) — same readyz-vs-healthz
        // drift class the rows above document; wired into both from the
        // start rather than shipping the gap. Net-new: the SQLite era had
        // no is_open()/availability flag for this store at all.
        bool schedule_engine_ok = deps.schedule_engine && deps.schedule_engine->is_open();
        // ADR-0065 (migration-programme PR 5, 3/3) — net-new: the SQLite era
        // had no /healthz entry for this store at all (its shared
        // InstructionDbPool fed /readyz only; approval_ok above is the ONE
        // sibling that already had full probe coverage pre-migration).
        bool execution_tracker_ok = deps.execution_tracker && deps.execution_tracker->is_open();
        // WS-3 3.3 (arch-F1/sre-F1): born-on-PG command outbox on the live
        // scheduled-dispatch path — mirrors its /readyz row.
        bool command_outbox_ok = deps.command_outbox_store && deps.command_outbox_store->is_open();

        // Determine overall status
        bool all_stores_ok =
            pg_pool_ok && pg_reachable_ok && response_ok && audit_ok && instruction_ok &&
            policy_ok && guaranteed_state_ok && baseline_ok && offload_target_ok && webhook_ok &&
            ca_ok && update_registry_ok && offline_endpoint_ok && software_inventory_ok &&
            vuln_finding_ok && app_perf_daily_ok && app_perf_fleet_ok && device_inventory_ok &&
            inventory_ok && approval_ok && rbac_ok && result_set_ok && mgmt_group_ok &&
            discovery_ok && deployment_ok && quarantine_ok && notification_ok && upload_grant_ok &&
            tag_ok && runtime_config_ok && patch_manager_ok && session_store_ok &&
            directory_sync_ok && workflow_engine_ok && schedule_engine_ok && execution_tracker_ok &&
            command_outbox_ok;
        std::string status = all_stores_ok ? "healthy" : "degraded";

        nlohmann::json health = {
            {"status", status},
            {"uptime_seconds", uptime_sec},
            {"agents", {{"online", online}}}, // pending added below for authed callers
            {"stores",
             {{"pg_pool", pg_pool_ok ? "ok" : "error"},
              {"pg_reachable", pg_reachable_ok ? "ok" : "error"},
              {"responses", response_ok ? "ok" : "error"},
              {"audit", audit_ok ? "ok" : "error"},
              {"instructions", instruction_ok ? "ok" : "error"},
              {"policies", policy_ok ? "ok" : "error"},
              {"guaranteed_state", guaranteed_state_ok ? "ok" : "error"},
              {"baselines", baseline_ok ? "ok" : "error"},
              {"offload_target", offload_target_ok ? "ok" : "error"},
              {"webhook_store", webhook_ok ? "ok" : "error"},
              // Scoped-governance sre + consistency-auditor (2-way
              // convergence): approval_ok already gated all_stores_ok
              // below but had no entry here — the mirror of the
              // webhook_ok bug this same commit fixes. A degraded
              // approval_manager_ flipped top-level status to
              // "degraded" with no per-store detail to explain why.
              // /readyz already names it "approval_manager" (its own
              // StoreCheck vector); matching that name here.
              {"approval_manager", approval_ok ? "ok" : "error"},
              {"ca", ca_ok ? "ok" : "error"},
              {"update_registry", update_registry_ok ? "ok" : "error"},
              {"offline_endpoint_store", offline_endpoint_ok ? "ok" : "error"},
              {"software_inventory_store", software_inventory_ok ? "ok" : "error"},
              {"vuln_finding_store", vuln_finding_ok ? "ok" : "error"},
              {"app_perf_daily_store", app_perf_daily_ok ? "ok" : "error"},
              {"app_perf_fleet_store", app_perf_fleet_ok ? "ok" : "error"},
              {"device_inventory_store", device_inventory_ok ? "ok" : "error"},
              {"inventory_store", inventory_ok ? "ok" : "error"},
              {"rbac_store", rbac_ok ? "ok" : "error"},
              {"result_set_store", result_set_ok ? "ok" : "error"},
              {"management_group_store", mgmt_group_ok ? "ok" : "error"},
              {"discovery_store", discovery_ok ? "ok" : "error"},
              {"deployment_store", deployment_ok ? "ok" : "error"},
              {"quarantine_store", quarantine_ok ? "ok" : "error"},
              {"notification_store", notification_ok ? "ok" : "error"},
              {"upload_grant_store", upload_grant_ok ? "ok" : "error"},
              {"tag_store", tag_ok ? "ok" : "error"},
              {"runtime_config_store", runtime_config_ok ? "ok" : "error"},
              {"patch_manager", patch_manager_ok ? "ok" : "error"},
              {"session_store", session_store_ok ? "ok" : "error"},
              {"directory_sync", directory_sync_ok ? "ok" : "error"},
              {"workflow_engine", workflow_engine_ok ? "ok" : "error"},
              {"schedule_engine", schedule_engine_ok ? "ok" : "error"},
              {"execution_tracker", execution_tracker_ok ? "ok" : "error"},
              {"command_outbox_store", command_outbox_ok ? "ok" : "error"}}},
            // #401: was hardcoded "0.1.0" — now derived from the
            // meson-generated yuzu/version.hpp so the health endpoint
            // tracks the actual build instead of a stale literal.
            {"version", std::string(yuzu::kVersionString)}};

        // TLS posture — intentionally UNAUTHENTICATED: operators and
        // monitoring MUST be able to see when the install is on built-in
        // default certs. The CA fingerprint is public.
        //
        // `deps.default_cert_set` is null-guarded here — a deliberate
        // non-verbatim addition (see this file's header comment,
        // "DEPS NULL-SAFETY"): the original `default_cert_set_` was a
        // non-pointer `ServerImpl` member, never null.
        health["tls"] = {
            {"default_certs_active", deps.cfg->using_default_certs},
            {"ca_fingerprint", deps.default_cert_set ? deps.default_cert_set->ca_fingerprint_sha256
                                                      : std::string{}},
            {"ca_expires_at",
             deps.cfg->using_default_certs
                 ? static_cast<int64_t>(std::chrono::system_clock::to_time_t(
                       deps.default_cert_set ? deps.default_cert_set->ca_expires_at
                                              : std::chrono::system_clock::time_point{}))
                 : int64_t{0}}};

        // Authenticated extension — heavier work, only run when the caller
        // has a session. Adds: agents.pending (SQLite scan), executions.*
        // (two bounded execution_tracker pool leases, ADR-0065 + a
        // 1h-window loop), system.* (process_health_sampler).
        if (is_authenticated) {
            int pending_count = 0;
            // `deps.auth_mgr` null-guarded — deliberate non-verbatim
            // addition, same rationale as `default_cert_set` above
            // (`auth_mgr_` was a reference member, never null).
            if (deps.auth_mgr) {
                auto pending_agents = deps.auth_mgr->list_pending_agents();
                for (const auto& a : pending_agents) {
                    if (a.status == auth::PendingStatus::pending)
                        ++pending_count;
                }
            }
            health["agents"]["pending"] = pending_count;

            int in_flight = 0;
            int completed_last_hour = 0;
            int failed_last_hour = 0;
            if (deps.execution_tracker) {
                auto running = deps.execution_tracker->query_executions({.status = "running"});
                in_flight = static_cast<int>(running.size());
                auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
                auto hour_ago = now_epoch - 3600;
                auto recent = deps.execution_tracker->query_executions({.limit = 1000});
                for (const auto& e : recent) {
                    if (e.completed_at >= hour_ago) {
                        if (e.status == "completed")
                            ++completed_last_hour;
                        else if (e.status == "failed")
                            ++failed_last_hour;
                    }
                }
            }
            health["executions"] = {{"in_flight", in_flight},
                                    {"completed_last_hour", completed_last_hour},
                                    {"failed_last_hour", failed_last_hour}};

            // Process health (22.1) — leaks process internals so
            // intentionally authenticated-only.
            //
            // `deps.process_health_sampler` null-guarded — deliberate
            // non-verbatim addition, same rationale as `default_cert_set`/
            // `auth_mgr` above (`process_health_sampler_` was a non-pointer
            // member, never null).
            auto ph = deps.process_health_sampler ? deps.process_health_sampler->sample()
                                                   : yuzu::server::detail::ProcessHealth{};
            health["system"] = {{"cpu_percent", ph.cpu_percent},
                                {"memory_rss_bytes", static_cast<int64_t>(ph.memory_rss_bytes)},
                                {"memory_vss_bytes", static_cast<int64_t>(ph.memory_vss_bytes)},
                                {"grpc_connections", static_cast<int>(online)},
                                {"command_queue_depth", in_flight}};
        }

        res.set_content(health.dump(), "application/json");
    };
    // Both URLs MUST be served by the SAME handler instance — do not split
    // into two lambda bodies. The unauthenticated `system.*` gating above
    // is load-bearing and must run identically on both routes; forking the
    // body invites a future regression where the alias diverges in subtle
    // ways. Governance Gate 7, architect NICE-2.
    sink.Get("/health", health_handler);
    sink.Get("/api/health", health_handler);

    // -- Kubernetes probe endpoints (/livez, /readyz) -------------------------
    sink.Get("/livez", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    sink.Get("/readyz", [deps](const httplib::Request&, httplib::Response& res) {
        // NOTE (Gate 3/Gate 2 governance, #2542 PR-10): unlike every other
        // graceful-degrade Deps field in this file, a null `draining` fails
        // OPEN here (falls through to the normal store sweep, i.e. "not
        // draining") rather than closed. The one production Deps{} call site
        // always sets `.draining = &draining_`, so this is unreachable today
        // -- but if a future caller (a new wiring path, a test fixture)
        // constructs Deps without this field, /readyz would silently stop
        // reporting drain state rather than erring toward "not ready".
        if (deps.draining && deps.draining->load(std::memory_order_acquire)) {
            res.status = 503;
            res.set_content(R"({"status":"draining"})", "application/json");
            return;
        }

        // WHAT THESE ROWS MEAN (HA WS-8, #3061 — read before adding a row).
        //
        // Every `is_open()` / `is_*_ok()` row below is BOOT-STATE reporting.
        // Each Postgres store latches `open_` at the end of its constructor and
        // never clears it; construction failure is already fail-closed
        // (startup_failed_ stops the server before it serves). So on a running
        // server these rows never flip, and they do NOT detect a post-boot
        // outage. That includes the session_store and auth_db rows
        // (`AuthManager::is_session_store_ok()` / `is_auth_db_ok()` read the same
        // latched flags).
        //
        // RUNTIME reachability is the `pg_reachable` row — one dedicated-
        // connection probe for the one substrate every store shares
        // (pg_reachability_probe.hpp). Per-store runtime degradation (a revoked
        // schema grant, a dropped table) is DELIBERATELY out of scope for
        // /readyz: every replica shares the same database, so moving traffic to
        // another replica fixes nothing; it surfaces as request-path 503s plus
        // metrics instead. Recorded decision: docs/postgres-store-playbook.md.
        //
        // LEADERSHIP IS NOT READINESS (#4014 decision): a follower serves every
        // operator-synchronous path, so the LeaderElector is deliberately absent.
        struct StoreCheck {
            const char* name;
            bool ok;
        };
        const auto pg_verdict = deps.pg_reachability_probe
                                    ? deps.pg_reachability_probe->verdict()
                                    : yuzu::server::pg_reachability::Verdict::NotYetProbed;
        std::vector<StoreCheck> checks = {
            {"response_store", deps.response_store && deps.response_store->is_open()},
            {"audit_store", deps.audit_store && deps.audit_store->is_open()},
            {"instruction_store", deps.instruction_store && deps.instruction_store->is_open()},
            {"api_token_store", deps.api_token_store && deps.api_token_store->is_open()},
            {"engine_principal_store",
             deps.engine_principal_store && deps.engine_principal_store->is_open()},
            // Load-bearing for the MCP write surface + REST /api/approvals/*
            // (governance sre-BLOCKING-1). is_open() is false after a failed
            // consumed_at migration, so a broken approval schema fails readyz.
            {"approval_manager", deps.approval_manager && deps.approval_manager->is_open()},
            {"policy_store", deps.policy_store && deps.policy_store->is_open()},
            {"rbac_store", deps.rbac_store && deps.rbac_store->is_open()},
            {"tag_store", deps.tag_store && deps.tag_store->is_open()},
            {"management_group_store", deps.mgmt_group_store && deps.mgmt_group_store->is_open()},
            {"runtime_config_store",
             deps.runtime_config_store && deps.runtime_config_store->is_open()},
            {"inventory_store", deps.inventory_store && deps.inventory_store->is_open()},
            {"workflow_engine", deps.workflow_engine && deps.workflow_engine->is_open()},
            // ADR-0063 (migration-programme PR 3): DirectorySync became a
            // fail-closed Postgres store (was fail-open SQLite, never
            // checked here before) — load-bearing for /api/directory/*
            // and the access-review export's optional email enrichment.
            {"directory_sync", deps.directory_sync && deps.directory_sync->is_open()},
            {"custom_properties_store",
             deps.custom_properties_store && deps.custom_properties_store->is_open()},
            {"guaranteed_state_store",
             deps.guaranteed_state_store && deps.guaranteed_state_store->is_open()},
            {"baseline_store", deps.baseline_store && deps.baseline_store->is_open()},
            // PR 5b: AuthDB integrity-check coverage. Reports "ok" on
            // legacy config-file-only deployments (auth_db_ == nullptr
            // in AuthManager) and false only when an opted-in AuthDB
            // failed the integrity check or migration. SOC 2 evidence:
            // an operator can detect a corrupt auth.db without scraping
            // spdlog; pairs with docs/ops-runbooks/auth-db-recovery.md.
            {"auth_db", deps.auth_mgr && deps.auth_mgr->is_auth_db_ok()},
            // HA WS-1/1a (ADR-2002 §4): durable operator sessions. Reports
            // "ok" on legacy config-file-only deployments (no store wired in
            // AuthManager) and false only when a wired SessionStore failed
            // to migrate/open — a half-open store cannot mint or validate
            // durable sessions, so the node is not ready to front the LB.
            // Same is_*_ok() fail-closed shape as auth_db above.
            {"session_store", deps.auth_mgr && deps.auth_mgr->is_session_store_ok()},
            // Phase 8.3 #255 — load-bearing for /api/v1/offload-targets
            // and the AgentService fan-out path. A migration failure
            // would silently no-op all offload deliveries while the
            // probe reported "ready" (HC-1 gap from Gate 6 SRE).
            {"offload_target_store",
             deps.offload_target_store && deps.offload_target_store->is_open()},
            // #3261 governance hardening (Gate 6 SRE) - WebhookStore is
            // load-bearing for /api/webhooks and the same AgentService
            // fan-out path as offload_target_store above, but was
            // missing from this probe (its two siblings,
            // offload_target_store and notification_store below, were
            // already covered) - same HC-1 gap class.
            {"webhook_store", deps.webhook_store && deps.webhook_store->is_open()},
            // ADR-0065 (migration-programme PR 5, 3/3): ExecutionTracker
            // became a fail-closed Postgres store (was fail-open SQLite
            // sharing InstructionDbPool, now deleted — migration failure
            // set a flag, `migration_ok_`/`schema_ok()`, that nothing here
            // ever checked; only the pool's own `is_open()` gated
            // construction and fed this probe). Re-keyed from
            // `instr_db_pool_->is_open() && execution_tracker_->schema_ok()`
            // to the store's own `is_open()` — same governance UAT 2026-05-06
            // SRE-1 / gov B-1 property this row has always protected: a
            // failed migration must surface as /readyz=503, not a green
            // probe over silently-wedged executions.
            {"execution_tracker", deps.execution_tracker && deps.execution_tracker->is_open()},
            // ADR-0065 (migration-programme PR 5, 1/3): ScheduleEngine became
            // a fail-closed Postgres store (was fail-open SQLite with no
            // is_open() of its own — migration failure was log-only and no
            // caller ever checked availability). Net-new row: the SQLite era
            // had no equivalent probe at all.
            {"schedule_engine", deps.schedule_engine && deps.schedule_engine->is_open()},
            // WS-3 3.3 (gov HC-1, arch-F1/sre-F1): the born-on-PG command outbox
            // is on the live scheduled-dispatch path. Construction is already
            // fail-closed (startup_failed_) and is_open() is latched (#3061), so
            // this row reports boot state only. A post-boot PG hiccup (which would
            // stop every scheduled fire from delivering) is what the gating
            // pg_reachable row below catches — this row does not.
            {"command_outbox_store",
             deps.command_outbox_store && deps.command_outbox_store->is_open()},
            // gov R3 HC-1: FleetTopologyStore became load-bearing for
            // /api/v1/viz/fleet/topology + /fragments/viz/fleet/topology.
            // Pure in-memory store with no is_open(); pointer-not-null is
            // the right probe. Without this, a store-construction failure
            // would leave /readyz "ready" while every viz request 503s.
            {"fleet_topology_store", deps.fleet_topology_store != nullptr},
            // #1320 PR 3 (#1368 Pattern E): the Postgres substrate is
            // load-bearing — without it every Postgres-backed store is
            // dead. Cheap, NON-lease-consuming signal: valid() (conninfo
            // parsed) AND the connect breaker is closed. The breaker arms
            // on real connect failures (PG unreachable) but NOT on pool
            // saturation, so this reflects runtime reachability without the
            // false-negative a lease-consuming probe would hit under load
            // (gov UP-2 — a busy-but-healthy server must NOT be evicted
            // from the LB). Saturation is surfaced via the acquire-wait
            // histogram + pool gauges + their alert rules, not /readyz.
            {"pg_pool", deps.pg_pool != nullptr && deps.pg_pool->valid() &&
                            !deps.pg_pool->connect_breaker_open()},
            // HA WS-8 (ADR-2002 §12): THE runtime "can this replica reach the
            // `yuzu` primary?" signal — the row that makes /readyz go red when
            // core cannot reach Postgres. The pg_pool row above cannot: its
            // breaker arms only when a NEW connect fails, so with idle pooled
            // connections (or no traffic) it stays green through an outage.
            // A leaf-locked copy of the probe's snapshot (no I/O); a null probe fails closed.
            {"pg_reachable", pg_verdict == yuzu::server::pg_reachability::Verdict::Ready},
            // First migrated store (#1368). The server fails closed without
            // Postgres, so this is true whenever it serves; a false here is
            // the loud signal that the migration path is broken even though
            // the pool answered.
            {"offline_endpoint_store",
             deps.offline_endpoint_store && deps.offline_endpoint_store->is_open()},
            // ADR-0016 born-on-Pg store. Fail-closed at boot; a store that
            // failed to open would make ReportInventory silently ack with no
            // ingest — surface that boot state (gov Pattern E; latched, #3061).
            {"software_inventory_store",
             deps.software_inventory_store && deps.software_inventory_store->is_open()},
            // CAVM born-on-PG store (ADR-0012). Fail-closed at boot; a store
            // that failed to open would silently no-op the PR-4 matching
            // engine's findings persistence — surface that boot state
            // (Pattern E; latched, #3061).
            {"vuln_finding_store", deps.vuln_finding_store && deps.vuln_finding_store->is_open()},
            // Periodic Access Reviews (SOC 2 CC6.2) born-on-PG store. AUTHORITATIVE
            // per ADR-0012 §1 — the /api/v1/access-reviews campaign lifecycle
            // (open/attest/close) is dead without it. The read-only export route
            // does not depend on this store, but the campaign-based evidence surface
            // is the feature's core deliverable, so a not-open state must be visible
            // at /readyz, not just returning 503 per-request unnoticed.
            {"access_review_store",
             deps.access_review_store && deps.access_review_store->is_open()},
            {"app_perf_daily_store",
             deps.app_perf_daily_store && deps.app_perf_daily_store->is_open()},
            {"app_perf_fleet_store",
             deps.app_perf_fleet_store && deps.app_perf_fleet_store->is_open()},
            // ADR-0016 device-CI born-on-Pg store — same rationale as the
            // software_inventory_store row above (silent no-ingest ack if dead).
            {"device_inventory_store",
             deps.device_inventory_store && deps.device_inventory_store->is_open()},
            // ADR-0024 SLE born-on-Pg stores (roadmap G-10, HC-1 Pattern E). Same
            // rationale as the inventory stores: fail-closed at boot; a store that
            // failed to open would make ReportInventory silently ack the licensing
            // blob with no ingest (software_licensing_store) and the /api/v1/sle/*
            // reads degrade to 503 (both) — surface that boot state (latched, #3061).
            {"software_licensing_store",
             deps.software_licensing_store && deps.software_licensing_store->is_open()},
            // Wave 7 PR7.2 born-on-Pg store (ADR-0016 §5, gov Gate 3 sre HIGH
            // finding). Same rationale as software_licensing_store above:
            // fail-closed at boot; a store that failed to open would make
            // ReportInventory/ProxyInventory silently ack the app_usage blob
            // with no ingest and the Forensics REST/MCP reads degrade to
            // 503/kInternalError — surface that boot state (latched, #3061).
            {"app_usage_store", deps.app_usage_store && deps.app_usage_store->is_open()},
            {"product_registry_store",
             deps.product_registry_store && deps.product_registry_store->is_open()},
            // gov W7.4 R1 sre-B1: ProductPackStore became more load-bearing
            // post-#802. UP-2 from the W7.4 Gate 4 risk register: a store
            // that fails to open AND `--allow-unsigned-packs` set produces
            // a silent half-state — the audit row at startup says "unsigned
            // packs allowed" but every install returns 503 because the
            // store is dead. Without this readyz entry, an LB or operator
            // dashboard would not detect the half-state. Pairs with the
            // workflow_routes.cpp install handler's `is_open()` guard.
            {"product_pack_store", deps.product_pack_store && deps.product_pack_store->is_open()},
            // gov PR-E OBS-1: ResultSetStore became load-bearing — every
            // scoped command dispatch and the /api/scope/estimate preview
            // resolve from_result_set: aliases and owner-check membership
            // against it. A failed migration/backfill (migrated to Postgres,
            // schema `result_set_store`, ADR-0036) would silently degrade
            // every scoped dispatch to zero targets while /readyz reported
            // "ready" — this construction is already fail-closed
            // (startup_failed_) per ADR-0012 §1; the readyz entry reports boot
            // state only (is_open() is latched, #3061).
            {"result_set_store", deps.result_set_store && deps.result_set_store->is_open()},
            // Migrated Postgres store (ADR-0043, gov sre finding, hardening
            // round). Load-bearing for all 4 /api/deployment-jobs routes;
            // construction is already fail-closed (startup_failed_), but the
            // readyz entry stays for parity with every OTHER migrated
            // authoritative store on this ladder (all of which are wired in
            // here); boot state only (is_open() is latched, #3061).
            {"deployment_store", deps.deployment_store && deps.deployment_store->is_open()},
            // PKI PR2: ca_store is load-bearing only when the install is on
            // built-in default certs (PR3+ make it load-bearing for mTLS
            // issuance/revocation). When the operator brought their own certs
            // it is not on the request path, so report ok.
            {"ca_store",
             !deps.cfg->using_default_certs || (deps.ca_store && deps.ca_store->is_open())},
            {"ca_root",
             !deps.cfg->using_default_certs || (deps.ca_store && deps.ca_store->has_root())},
            // SRE Gate 6 HC-1: ScimStore is only constructed when
            // --scim-enable is set (opt-in, mirrors the ca_store pattern
            // above); a failed open/migration would otherwise silently
            // reject every /scim/v2/* request while /readyz reported
            // "ready". H3 (2026-07-08 review, defense-in-depth): also
            // requires has_token() — the primary fix is that a failed
            // set_token() at boot now sets startup_failed_ (server never
            // reaches run()'s serve loop at all), but this term keeps
            // /readyz honest on its own terms too, independent of that
            // guard.
            {"scim_store", !deps.cfg->scim_enable ||
                               (deps.scim_store && deps.scim_store->is_open() &&
                                deps.scim_store->has_token())},
            // ADR-0061: UpdateRegistry is only constructed when
            // cfg_.ota_enabled is true, which defaults ON (opt-out via
            // --no-ota) — unlike ca_store/scim_store's construction
            // (unconditional whenever pg_pool_ is up; only their /readyz
            // CHECK above is flag-gated), this store's CONSTRUCTION itself
            // has the opt-out. So the check below
            // covers the ordinary default deployment, not an opt-in
            // minority. A failed migration/open would otherwise silently
            // disable OTA (CheckForUpdate/DownloadUpdate always answering
            // "no update") while /readyz reported "ready".
            {"update_registry", !deps.cfg->ota_enabled ||
                                    (deps.update_registry && deps.update_registry->is_open())},
            // Wave 2 migrated Postgres store (ADR-0006/0009/0044, schema
            // `discovery_store`). AUTHORITATIVE per ADR-0012 §1 — the
            // operator-set `managed` flag is real state. Construction
            // fail-closed already makes a not-open state unreachable in
            // production (startup_failed_ stops the server before it
            // serves); boot state only (is_open() is latched, #3061),
            // matching result_set_store's equivalent row.
            {"discovery_store", deps.discovery_store && deps.discovery_store->is_open()},
            // Wave 2 migrated Postgres store (ADR-0006/0009/0047, schema
            // `quarantine_store`). AUTHORITATIVE per ADR-0012 §1 — an
            // active quarantine record is live security containment
            // state. Construction fail-closed already makes a not-open
            // state unreachable in production (startup_failed_ stops
            // the server before it serves); boot state only (is_open() is
            // latched, #3061), matching discovery_store's equivalent row.
            {"quarantine_store", deps.quarantine_store && deps.quarantine_store->is_open()},
            // ADR-0046 born-on-PG (as of this migration) store — same
            // rationale as the other rows above: fail-closed at boot; this
            // row reports that boot state (latched, #3061), so a failed open
            // cannot leave the notification feed dead behind a "ready"
            // /readyz (gov Pattern E).
            {"notification_store", deps.notification_store && deps.notification_store->is_open()},
            // ADR-3004 (PR1.6a) — review finding (#3135): same
            // readyz-vs-healthz drift class as the rows above.
            // Fail-closed at boot; this row reports that boot state
            // (latched, #3061).
            {"upload_grant_store",
             deps.upload_grant_store && deps.upload_grant_store->is_open()},
            // ADR-0062 (Wave 4 non-`*Store` migration) — was in neither
            // /readyz nor /healthz in the SQLite era (no caller ever
            // checked is_open() at all). Load-bearing for every
            // /api/patches/* route now that construction is fail-closed.
            {"patch_manager", deps.patch_manager && deps.patch_manager->is_open()},
            // Wave 7b PR7b.1 execution_artifacts — PluginConfigStore backs the
            // plugin kill switch; action_allowed() fails closed when the store
            // is not open, so a store that failed to open would silently deny
            // every kill-switched action. Same readyz-vs-healthz drift class
            // the rows above document; boot state only (latched, #3061).
            {"plugin_config_store", deps.plugin_config_store && deps.plugin_config_store->is_open()},
        };

        // Non-gating (governance Gate 2, 2026-08-16): ADR-0049's own construction
        // posture is deliberately NOT fatal for this one store (analytics is a
        // non-critical telemetry spool, on by default, every caller null-guards
        // it) — folding it into `checks` above would flip /readyz to 503 for the
        // WHOLE node on a transient migration hiccup here, directly contradicting
        // that posture and the comment that used to sit on this row. Reported
        // separately so on-call can still tell feature-off from feature-on-but-
        // dead without pulling a healthy node out of LB/orchestrator rotation.
        // nvd_db is the same shape: construction is fail-OPEN by design (a CVE
        // cache that fails to open leaves matching empty, never a 503), and it
        // is always constructed, so a null pointer or a not-open handle is
        // genuinely "broken", not "feature off". Without this row a dead CVE
        // cache showed only as the yuzu_nvd_* gauges going absent.
        std::vector<StoreCheck> notices = {
            {"analytics_event_store",
             !deps.cfg->analytics_enabled ||
                 (deps.analytics_store && deps.analytics_store->is_open())},
            {"nvd_db", deps.nvd_db && deps.nvd_db->is_open()},
        };

        std::string failed_list;
        for (const auto& c : checks) {
            if (!c.ok) {
                if (!failed_list.empty())
                    failed_list += ",";
                failed_list += "\"";
                failed_list += c.name;
                failed_list += "\"";
            }
        }
        std::string degraded_list;
        for (const auto& c : notices) {
            if (!c.ok) {
                if (!degraded_list.empty())
                    degraded_list += ",";
                degraded_list += "\"";
                degraded_list += c.name;
                degraded_list += "\"";
            }
        }

        if (failed_list.empty()) {
            res.set_content(degraded_list.empty()
                                ? R"({"status":"ready"})"
                                : "{\"status\":\"ready\",\"degraded\":[" + degraded_list + "]}",
                            "application/json");
        } else {
            res.status = 503;
            std::string body = "{\"status\":\"not ready\",\"failed_stores\":[" + failed_list + "]";
            // A stable reason token only (pg_reachability_rules.hpp `reason()`):
            // no host, DSN or libpq text — this endpoint is unauthenticated.
            if (pg_verdict != yuzu::server::pg_reachability::Verdict::Ready)
                body += std::string(",\"pg\":\"") +
                        yuzu::server::pg_reachability::reason(pg_verdict) + "\"";
            if (!degraded_list.empty())
                body += ",\"degraded\":[" + degraded_list + "]";
            body += "}";
            res.set_content(body, "application/json");
        }
    });

    // -- Health summary dashboard fragment (7.2) ----------------------------
    // guardian-confinement-2298 PR3 §3e: require_auth-only, no
    // per-target parameter — reports agent count, in-flight execution
    // count, and store health fleet-wide.
    sink.Get("/fragments/health/summary",
             [deps](const httplib::Request& req, httplib::Response& res) {
        if (deps.deny_service_scoped_fn(
                req, res, "health.fragment.access_denied",
                "service-scoped tokens may not read the fleet-wide health summary", "", ""))
            return;
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;

        auto now = std::chrono::steady_clock::now();
        auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
                              now - deps.server_start_time)
                              .count();

        // Store health
        bool response_ok = deps.response_store && deps.response_store->is_open();
        bool audit_ok = deps.audit_store && deps.audit_store->is_open();
        bool instruction_ok = deps.instruction_store && deps.instruction_store->is_open();
        bool policy_ok = deps.policy_store && deps.policy_store->is_open();
        bool guaranteed_state_ok =
            deps.guaranteed_state_store && deps.guaranteed_state_store->is_open();
        bool baseline_ok = deps.baseline_store && deps.baseline_store->is_open();
        // HA WS-8: the one RUNTIME signal — the store rows above are boot state.
        bool pg_reachable_ok =
            deps.pg_reachability_probe &&
            deps.pg_reachability_probe->verdict() == yuzu::server::pg_reachability::Verdict::Ready;
        bool all_ok = pg_reachable_ok && response_ok && audit_ok && instruction_ok && policy_ok &&
                      guaranteed_state_ok && baseline_ok;

        // Execution stats
        int in_flight = 0;
        if (deps.execution_tracker) {
            auto running = deps.execution_tracker->query_executions({.status = "running"});
            in_flight = static_cast<int>(running.size());
        }

        // Format uptime
        auto days = uptime_sec / 86400;
        auto hours = (uptime_sec % 86400) / 3600;
        auto mins = (uptime_sec % 3600) / 60;
        std::string uptime_str;
        if (days > 0)
            uptime_str = std::to_string(days) + "d " + std::to_string(hours) + "h";
        else if (hours > 0)
            uptime_str = std::to_string(hours) + "h " + std::to_string(mins) + "m";
        else
            uptime_str = std::to_string(mins) + "m";

        std::size_t online = deps.registry ? deps.registry->agent_count() : 0;

        // Process health for dashboard
        auto ph = deps.process_health_sampler ? deps.process_health_sampler->sample()
                                               : yuzu::server::detail::ProcessHealth{};
        auto rss_mb = ph.memory_rss_bytes / (1024 * 1024);
        char cpu_buf[16];
        std::snprintf(cpu_buf, sizeof(cpu_buf), "%.1f", ph.cpu_percent);

        // Only render the strip if there are issues
        if (all_ok && in_flight == 0) {
            // Minimal healthy summary
            std::string html =
                "<div class=\"health-strip health-ok\" "
                "style=\"display:flex;gap:1.5rem;align-items:center;"
                "padding:0.4rem 1rem;background:var(--surface-1);"
                "border-left:3px solid var(--green);border-radius:4px;"
                "font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem\">"
                "<span>Server healthy</span>"
                "<span>Uptime: " +
                uptime_str +
                "</span>"
                "<span>Agents online: " +
                std::to_string(online) +
                "</span>"
                "<span>CPU: " +
                std::string(cpu_buf) +
                "%</span>"
                "<span>Mem: " +
                std::to_string(rss_mb) +
                " MB</span>"
                "</div>";
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        // Degraded or busy — show warning strip
        std::string html =
            "<div class=\"health-strip health-warn\" "
            "style=\"display:flex;gap:1.5rem;align-items:center;"
            "padding:0.4rem 1rem;background:var(--surface-1);"
            "border-left:3px solid var(--yellow);border-radius:4px;"
            "font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem\">";

        if (!all_ok) {
            html += "<span style=\"color:var(--yellow)\">Stores degraded: ";
            if (!pg_reachable_ok)
                html += "postgres ";
            if (!response_ok)
                html += "responses ";
            if (!audit_ok)
                html += "audit ";
            if (!instruction_ok)
                html += "instructions ";
            if (!policy_ok)
                html += "policies ";
            html += "</span>";
        }

        html += "<span>Uptime: " + uptime_str + "</span>";
        html += "<span>Agents: " + std::to_string(online) + "</span>";
        html += "<span>CPU: " + std::string(cpu_buf) + "%</span>";
        html += "<span>Mem: " + std::to_string(rss_mb) + " MB</span>";
        if (in_flight > 0)
            html += "<span>In-flight: " + std::to_string(in_flight) + "</span>";

        html += "</div>";
        res.set_content(html, "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server::health
