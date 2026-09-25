/**
 * test_operator_surface_twins.cpp — PR1.5c + PR1.6c (p14): ADR-0031 operator
 * surface server wiring — MCP/REST twin parity, the ScheduleRunner
 * arming_check re-authorization seam, and the upload-session MCP exemption.
 *
 * WHAT THIS FILE BINDS. `ServerImpl::start_web_server`'s arming_check lambda
 * and the `kek_ops_.{rotate,rewrap,status}` multi-codec generalization are
 * private ServerImpl members with no live-Session-free construction path —
 * the same situation test_dispatch_chokepoint.cpp's file header documents
 * for `build_classified_command`. This file therefore binds the SAME pure
 * decision the arming_check lambda is built around
 * (`compose_arming_check` below — a byte-for-byte mirror of server.cpp's
 * lambda: classify() -> rbac_enforcement_in_effect() -> check_permission()),
 * wired into a real `ScheduleRunner` so the auto and approval-gated fire
 * paths are proven end-to-end, not just the composed function in isolation.
 * `ScheduleRunner` itself already has thorough D7 arming_check coverage in
 * `test_schedule_runner.cpp` (p4's file, not modified here) — that file
 * proves the runner correctly gates on a CANNED true/false arming_check;
 * this file proves the REAL composition (classify+rbac) server.cpp wires in
 * produces the right true/false for a real, permission-losing principal.
 *
 * The MCP/REST twin-parity and A5-contract sweeps bind the REAL served
 * tables via `mcp_server_testonly.hpp`'s accessors (kToolSecurity/
 * kToolAnnotation/kWriteTools/kTools mirrors) rather than a live McpServer —
 * hermetic, no httplib acceptor thread (#438).
 *
 * The multi-codec KEK enrolment (`kek_enrolled_codecs()`,
 * `kek_ops_.{rotate,rewrap,status}`) is NOT exercised through a live
 * `ServerImpl` here: it is a private ServerImpl member with no
 * live-Session-free construction path, same situation as the rest of this
 * file's bindings. It IS covered end-to-end against a live Postgres
 * substrate at the `pg::SecretCodec` level, one layer below ServerImpl, in
 * tests/unit/server/test_secret_codec.cpp: "SecretCodec: a second codec
 * joins a rotation without minting a second KEK" reproduces the exact
 * production sequence (mint once via codec_a->rotate_kek(), then bring
 * codec_b onto the same version via codec_b->init()+codec_b->rewrap_all()
 * — never a second rotate_kek() call) against two independent SecretCodec
 * instances sharing one `secrets.kek_meta` table, and asserts exactly one
 * new KEK version is minted, both codecs converge on it, and both rows
 * still decrypt. "SecretCodec: a not-yet-resynced codec's rows stay
 * decryptable through a sibling's mint-only rotate" (same file) covers the
 * HalfCommitted-adjacent half: a codec that has not yet caught up stays
 * independently correct, never corrupted or blocked by a sibling's rotate.
 */

#include "approval_manager.hpp"
#include "authz_model.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "command_capability.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "mcp_server_testonly.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "schedule_arming_check.hpp"
#include "schedule_engine.hpp"
#include "schedule_runner.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::mcp;

namespace {

// ── The seam under test: server.cpp's arming_check rule, SHARED ───────────
//
// This is no longer a mirror. It forwards to `schedule_arming_permitted`
// (schedule_arming_check.hpp) — the same function server.cpp's
// ScheduleRunner::Deps `.arming_check` lambda calls — so there is exactly
// one copy of the decision rule and the drift this file's previous
// hand-copied version suffered is unrepresentable.
//
// That drift was real, not hypothetical: BR-003's `system_reserved` branch
// landed in the lambda and never reached the copy here, so the
// confused-deputy fix was untested and freely revertible while this file
// stayed green. The wrapper is kept only so the existing call sites below
// read unchanged.
bool compose_arming_check(const CommandCapabilityRegistry& registry, const RbacStore* rbac,
                          const std::string& principal, const std::string& plugin,
                          const std::string& action) {
    return yuzu::server::schedule_arming_permitted(registry, rbac, principal, plugin, action);
}

} // namespace

namespace {
// RbacStore is Postgres-backed (ADR-0041) — a pre-migrated template cloned per
// test, the same recipe test_rbac_store.cpp uses. Every case below therefore
// carries the [pg] tag and SKIPs when YUZU_TEST_POSTGRES_DSN is unset.
yuzu::test::PgTestTemplate twins_rbac_tpl{"optwinsrbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("optwins rbac template: store failed to migrate");
}};
// InstructionStore is now a migrated Postgres store (ADR-0058). ADR-0065
// migration-programme PR 5 grew this same template/database (ADR-0008
// schema-per-store-on-one-connection) across all 3 commits — this key has
// exactly one caller in the whole test tree (this file), so growing its
// setup function was safe under the PgTestTemplate replay-fingerprint rule.
// Now covers all 4 stores.
yuzu::test::PgTestTemplate twins_instr_tpl{"optwinsinstr", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    InstructionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("optwins instruction template: store failed to migrate");
    ScheduleEngine engine{pool};
    if (!engine.is_open())
        throw std::runtime_error("optwins schedule engine template: store failed to migrate");
    ApprovalManager approvals{pool};
    if (!approvals.is_open())
        throw std::runtime_error("optwins approval manager template: store failed to migrate");
    ExecutionTracker tracker{pool};
    if (!tracker.is_open())
        throw std::runtime_error("optwins execution tracker template: store failed to migrate");
}};
} // namespace

#define TWINS_RBAC(store_var)                                                                      \
    YUZU_REQUIRE_PG_DB_TPL(twins_db_fx_, twins_rbac_tpl);                                          \
    yuzu::server::pg::PgPool twins_pool_fx_{{.conninfo = twins_db_fx_.dsn(), .size = 4}};          \
    REQUIRE(twins_pool_fx_.valid());                                                               \
    RbacStore store_var{twins_pool_fx_};                                                           \
    REQUIRE(store_var.is_open())

#define TWINS_INSTR(pool_var)                                                                      \
    YUZU_REQUIRE_PG_DB_TPL(twins_instr_db_fx_, twins_instr_tpl);                                   \
    yuzu::server::pg::PgPool pool_var{{.conninfo = twins_instr_db_fx_.dsn(), .size = 4}};          \
    REQUIRE(pool_var.valid())

// ═════════════════════════════════════════════════════════════════════════
// compose_arming_check — the composed decision in isolation
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("arming_check composition: unclassified plugin.action denies (ADR-0033 §2)",
          "[server][routes][mcp][pg]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    TWINS_RBAC(rbac);
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "alice", "Administrator"}).has_value());

    // "no.such.plugin"/"nope" is not in plugin_action_catalogue_a() — a
    // missing classification means the capability does not exist (ADR-0033
    // §2), never a permissive default, even for an Administrator principal.
    CHECK_FALSE(compose_arming_check(registry, &rbac, "alice", "no.such.plugin", "nope"));
}

TEST_CASE("arming_check composition: null/closed RbacStore denies fail-closed",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    CHECK_FALSE(compose_arming_check(registry, nullptr, "alice", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: a system_reserved capability is refused to every operator "
          "(BR-003 confused deputy)",
          "[server][routes][mcp][pg]") {
    // THE branch that drifted. A schedule is operator-authored but fires
    // through `command_dispatch_fn`, which dispatches as
    // `DispatchCaller{.system = true}`; the chokepoint's system_reserved
    // guard only refuses NON-system callers, so without this denial an
    // operator could schedule `tar.fleet_snapshot` — a definition that ships
    // operator-referencable — and reach the fleet under system authority.
    //
    // The registry is composed over BOTH fragments deliberately:
    // `plugin_action_catalogue_a()` declares no system_reserved row at all
    // (see its header note), so a registry built from it alone cannot
    // express this case — which is part of why the old mirror never covered
    // it. `tar.fleet_snapshot` is declared by the core fragment.
    CommandCapabilityRegistry registry{capdecls::core_dispatch_capabilities(),
                                       capdecls::plugin_action_catalogue_a()};

    TWINS_RBAC(rbac);
    rbac.set_rbac_enabled(true);
    // Administrator holds every (securable, operation) pair, so RBAC alone
    // would ADMIT — the denial has to come from the system_reserved branch,
    // not from a missing grant. That is what makes this a real test of it.
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "alice", "Administrator"}).has_value());
    CHECK_FALSE(compose_arming_check(registry, &rbac, "alice", "tar", "fleet_snapshot"));

    // Legacy-open RBAC does not rescue it either: the reserved check runs
    // BEFORE the enforcement-in-effect early-return. Reuse the SAME store,
    // toggled open — a second clone would double the fixture cost for no
    // additional coverage, and the toggle is itself the production lever.
    rbac.set_rbac_enabled(false);
    CHECK_FALSE(compose_arming_check(registry, &rbac, "alice", "tar", "fleet_snapshot"));
    rbac.set_rbac_enabled(true);

    // Sanity: a non-reserved row in the same composed registry still admits,
    // so the denial above is specific to system_reserved and not the
    // composition failing wholesale.
    CHECK(compose_arming_check(registry, &rbac, "alice", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC legacy-open (disabled) admits regardless of grant",
          "[server][routes][mcp][pg]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    TWINS_RBAC(rbac);
    // Fresh store defaults to rbac_enabled=false (legacy-open) — no
    // set_rbac_enabled(true) call here, on purpose.
    CHECK(compose_arming_check(registry, &rbac, "nobody-with-no-role", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC enabled + granted principal admits",
          "[server][routes][mcp][pg]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    TWINS_RBAC(rbac);
    rbac.set_rbac_enabled(true);
    // filesystem.exists classifies to FileRetrieval:Read (plugin_action_catalogue_a.hpp);
    // Administrator holds every (securable, operation) pair (rbac_store.cpp's
    // seed_defaults() generic grant loop).
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "alice", "Administrator"}).has_value());
    CHECK(compose_arming_check(registry, &rbac, "alice", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC enabled + ungranted principal denies",
          "[server][routes][mcp][pg]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    TWINS_RBAC(rbac);
    rbac.set_rbac_enabled(true);
    // "bob" holds no role at all -> check_permission's collect_roles_locked
    // returns empty -> false.
    CHECK_FALSE(compose_arming_check(registry, &rbac, "bob", "filesystem", "exists"));
}

// ═════════════════════════════════════════════════════════════════════════
// ScheduleRunner, wired to compose_arming_check — auto and approval paths
// ═════════════════════════════════════════════════════════════════════════

namespace {

// Minimal harness — the D7 unset/canned-arming_check ScheduleRunner
// contract itself is p4's test_schedule_runner.cpp's job; this harness
// exists only to wire compose_arming_check (a REAL registry + REAL
// RbacStore) through a real ScheduleRunner end to end.
struct Harness {
    yuzu::server::pg::PgPool& instr_pool;

    // ADR-0065 (migration-programme PR 5): all stores built on instr_pool
    // (one ephemeral Postgres database, schema-per-store) — the production
    // shape now that InstructionDbPool is deleted.
    ScheduleEngine engine{instr_pool};
    ExecutionTracker tracker{instr_pool};
    ApprovalManager approvals{instr_pool};
    InstructionStore is;

    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    // Postgres-backed (ADR-0041): the store is constructed by the TEST_CASE
    // via TWINS_RBAC (which carries the SKIP-if-no-DSN guard a struct member
    // cannot) and borrowed here for the harness's lifetime.
    RbacStore& rbac;

    std::vector<std::string> dispatched_actions;

    ScheduleRunner runner;

    explicit Harness(yuzu::server::pg::PgPool& instr_pool_ref, RbacStore& rbac_store)
        : instr_pool(instr_pool_ref), is(instr_pool), rbac(rbac_store),
          runner(ScheduleRunner::Deps{
              .schedule_engine = &engine,
              .instruction_store = &is,
              .execution_tracker = &tracker,
              .approval_manager = &approvals,
              // WS-3 3.3: scheduled fires enqueue a durable outbox occurrence
              // instead of dispatching inline (the delivery loop sends). The
              // arming gate still runs at fire time BEFORE the enqueue, so a
              // denied fire records nothing here exactly as a denied dispatch did
              // — which is what these operator-surface-twin cases assert.
              .enqueue_fn =
                  [this](const yuzu::server::OutboxEnqueueRequest& req)
                      -> yuzu::server::OutboxEnqueueOutcome {
                      dispatched_actions.push_back(req.plugin + "." + req.action);
                      return yuzu::server::OutboxEnqueueOutcome::Enqueued;
                  },
              .arming_check =
                  [this](const std::string& principal, const std::string& plugin,
                        const std::string& action) {
                      return compose_arming_check(registry, &rbac, principal, plugin, action);
                  },
          }) {
        tracker.create_tables();
        approvals.create_tables();
        rbac.set_rbac_enabled(true);

        // filesystem.exists -> FileRetrieval:Read (plugin_action_catalogue_a.hpp).
        InstructionDefinition d;
        d.id = "test.fsexists";
        d.name = "test.fsexists";
        d.version = "1.0.0";
        d.type = "question";
        d.plugin = "filesystem";
        d.action = "exists";
        d.enabled = true;
        REQUIRE(is.create_definition(d).has_value());
    }

    std::string make_due(const std::string& created_by, bool requires_approval) {
        InstructionSchedule s;
        s.name = "sched-" + created_by;
        s.definition_id = "test.fsexists";
        s.frequency_type = "interval";
        s.interval_minutes = 60;
        s.scope_expression = "";
        s.requires_approval = requires_approval;
        s.enabled = true;
        s.created_by = created_by;
        s.next_execution_at = 1; // due immediately
        auto id = engine.create_schedule(s);
        REQUIRE(id.has_value());
        return *id;
    }

    // ScheduleEngine now lives in Postgres (instr_pool) — poke it via a
    // pool lease (mirrors test_schedule_runner.cpp's identical helper,
    // which has direct access to the DSN and uses a second raw connection
    // instead; this Harness only receives the pool, not the DSN, so a
    // lease is the available seam).
    void force_due(const std::string& id) {
        auto lease = instr_pool.acquire();
        REQUIRE(lease);
        auto sql =
            "UPDATE schedule_engine.schedules SET next_execution_at = 1 WHERE id = '" + id + "'";
        yuzu::server::pg::PgResult res{PQexec(lease.get(), sql.c_str())};
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
};

} // namespace

TEST_CASE("arming_check (auto path): a schedule whose creator lost the required permission "
          "does not fire, and re-fires once permission is restored",
          "[server][routes][mcp][schedule][pg]") {
    TWINS_RBAC(rbac);
    TWINS_INSTR(instr_pool);
    Harness h{instr_pool, rbac};
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "carol", "Administrator"}).has_value());
    auto id = h.make_due("carol", /*requires_approval=*/false);

    h.runner.tick();
    REQUIRE(h.dispatched_actions.size() == 1);
    CHECK(h.dispatched_actions[0] == "filesystem.exists");

    // Permission lost: unassign the role the arming check re-verifies.
    REQUIRE(h.rbac.unassign_role("user", "carol", "Administrator").has_value());
    h.force_due(id);
    h.runner.tick();
    // No new dispatch — the occurrence is skipped (fire-and-advance), not
    // fired under stale authority.
    CHECK(h.dispatched_actions.size() == 1);

    // Restore: re-verified fresh on the NEXT occurrence too, not cached.
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "carol", "Administrator"}).has_value());
    h.force_due(id);
    h.runner.tick();
    CHECK(h.dispatched_actions.size() == 2);
}

TEST_CASE("arming_check (approval path): a schedule whose creator lost the required "
          "permission does not submit an approval ticket and does not fire",
          "[server][routes][mcp][schedule][pg]") {
    TWINS_RBAC(rbac);
    TWINS_INSTR(instr_pool);
    Harness h{instr_pool, rbac};
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "dave", "Administrator"}).has_value());
    auto id = h.make_due("dave", /*requires_approval=*/true);

    // Still armed: fires the approval-gated arm, submitting exactly one ticket.
    h.runner.tick();
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());
    h.runner.tick();
    REQUIRE(h.dispatched_actions.size() == 1);

    // Permission lost before the NEXT occurrence.
    REQUIRE(h.rbac.unassign_role("user", "dave", "Administrator").has_value());
    h.force_due(id);
    h.runner.tick();
    // The arming re-check gates IN FRONT OF fire_with_approval (schedule_runner.hpp's
    // fire() doc comment) — a denial here must mean fire_with_approval never
    // runs at all: no new ticket, no new dispatch.
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.dispatched_actions.size() == 1);
}

// ═════════════════════════════════════════════════════════════════════════
// MCP/REST twin parity — same securable, same operation, per pair
// ═════════════════════════════════════════════════════════════════════════

namespace {

struct TwinRow {
    std::string_view tool;
    std::string_view securable;
    std::string_view operation;
    bool is_read;
};

// Pinned against plugin_config_routes.hpp's / file_retrieval_routes.hpp's
// documented REST route tables — the SAME (securable, operation) each REST
// handler gates on (see those headers' file-header route tables).
constexpr TwinRow kExpectedTwins[] = {
    {"get_plugin_config", "PluginConfig", "Read", true},
    {"list_plugin_config", "PluginConfig", "Read", true},
    {"set_plugin_config", "PluginConfig", "Write", false},
    {"delete_plugin_config", "PluginConfig", "Delete", false},
    {"set_plugin_secret", "PluginSecret", "Write", false},
    {"delete_plugin_secret", "PluginSecret", "Delete", false},
    {"get_plugin_kill_switch", "PluginConfig", "Read", true},
    {"set_plugin_kill_switch", "PluginConfig", "Write", false},
    {"mint_upload_grant", "UploadGrant", "Write", false},
    {"list_upload_grants", "UploadGrant", "Read", true},
    {"revoke_upload_grant", "UploadGrant", "Delete", false},
    // #4036 (api-parity Batch A) — pinned against preflight_routes.cpp's /
    // deployment_routes.cpp's new GET /api/v1/preflight/runs / GET
    // /api/v1/deployments/preview handlers (same (securable, operation) each
    // REST twin gates on).
    {"list_preflight_runs", "Infrastructure", "Read", true},
    {"get_deployment_preview", "SoftwareDeployment", "Read", true},
    // #4030: executions/workflows/schedules read-twin programme.
    {"list_workflows", "Workflow", "Read", true},
    {"get_workflow", "Workflow", "Read", true},
    {"get_workflow_execution", "Workflow", "Read", true},
    // #2146 A2-R1 - pinned against the new GET /api/v1/executions/{id}/children
    // (rest_api_v1.cpp) and legacy GET /api/executions/{id}/children
    // (execution_routes.cpp) handlers' shared (securable, operation) gate.
    {"get_execution_children", "Execution", "Read", true},
    // #4029 (api-parity Batch A content/catalog half): instruction-definition
    // read twins, pinned against instruction_definition_model.hpp / the new
    // GET /api/v1/instructions* routes (rest_api_v1.cpp).
    {"list_definitions", "InstructionDefinition", "Read", true},
    {"get_definition", "InstructionDefinition", "Read", true},
    {"export_definition", "InstructionDefinition", "Read", true},
    // #4029: product-pack read twins, pinned against product_pack_model.hpp /
    // the new GET /api/v1/product-packs* routes.
    {"list_product_packs", "ProductPack", "Read", true},
    {"get_product_pack", "ProductPack", "Read", true},
    // #4027 — TAR process-tree/capture-sources/retention-paused read twins.
    // Same Infrastructure:Read gate as GET /fragments/tar/process-tree,
    // .../capture-sources, .../retention-paused (tar_tree_routes.cpp /
    // dashboard_routes.cpp).
    {"list_tar_process_tree_devices", "Infrastructure", "Read", true},
    {"list_tar_capture_sources_devices", "Infrastructure", "Read", true},
    {"list_tar_retention_paused", "Infrastructure", "Read", true},
    // #4031: directory-sync (AD/Entra) read twin — parity with GET
    // /api/v1/directory/users. The OIDC-config, auto-approve-rules, and
    // pending-agents read twins are REST-only per #520 (see
    // docs/mcp-server.md) and so carry no MCP tool, no row here.
    //
    // get_directory_status (the /directory/status twin) is deliberately NOT
    // listed here even though it shares Directory:Read: it takes no input
    // parameters, so its schema is the honest, bounded
    // {"type":"object","properties":{}} shape — same precedent as
    // get_guardian_schemas above, also absent from this array for the same
    // reason (the A5 sweep below asserts every LISTED tool's schema differs
    // from that literal, which is correct for this curated list but not a
    // universal rule; validate_tool_security_registration's boot-time check
    // is what proves get_directory_status's own table entries are
    // consistent, and test_mcp_server.cpp exercises its dispatch directly).
    {"list_directory_users", "Directory", "Read", true},
    // #4033 (#2146 Batch A) — pinned against
    // /fragments/create-group-form's own ManagementGroup:Write gate
    // (dashboard_routes.cpp) and its REST twin GET /api/v1/management-groups/
    // agent-count-preview (rest_api_v1.cpp).
    {"preview_management_group_agent_count", "ManagementGroup", "Write", false},
    // #4034 — compliance/policy REST v1 read twins.
    {"get_policy", "Policy", "Read", true},
    {"list_policy_fragments", "Policy", "Read", true},
    {"get_policy_agent_statuses", "Policy", "Read", true},
    // #4035 (api-parity #2146 Batch A): MCP-only gaps closing the REST-only
    // twins for /fragments/device/dex and /fragments/dex/device/app-perf —
    // see docs/api-twin-recipe.md §6/§7/§8, which directs a twin PR to extend
    // this array (not only the plugin-config/upload-grant families the
    // header comment above was originally pinned against).
    {"get_dex_device_score", "GuaranteedState", "Read", true},
    {"get_dex_device_app_perf", "GuaranteedState", "Read", true},
    // #4035: the 8 genuinely-new REST+MCP twins from the same issue.
    {"get_dex_app", "GuaranteedState", "Read", true},
    {"list_dex_apps", "GuaranteedState", "Read", true},
    {"get_dex_catalogue_group", "GuaranteedState", "Read", true},
    {"get_dex_device_history", "GuaranteedState", "Read", true},
    {"get_dex_observation", "GuaranteedState", "Read", true},
    {"get_dex_health", "GuaranteedState", "Read", true},
    {"get_dex_trends", "GuaranteedState", "Read", true},
    {"get_dex_overview", "GuaranteedState", "Read", true},
    // #4037 — Guardian read twins (api-parity #2146 Batch A). Pinned against
    // rest_api_v1.cpp's /api/v1/guaranteed-state/{status,rules,events,
    // rules/{id}/status,agents/{id}/rules} routes.
    {"get_guardian_status", "GuaranteedState", "Read", true},
    {"list_guardian_rules", "GuaranteedState", "Read", true},
    {"list_guardian_events", "GuaranteedState", "Read", true},
    {"get_guardian_rule_status", "GuaranteedState", "Read", true},
    {"get_guardian_device_guards", "GuaranteedState", "Read", true},
    // #2146 Batch B2 — result-set MCP twins, pinned against rest_api_v1.cpp's
    // 12-operation REST v1 result-set API (docs/scope-walking-design.md).
    // The three async dispatch producers + reevaluate share
    // execute_instruction's own Execution:Execute pair; the rest are owner-
    // scoped, no RBAC gate in the handler (Infrastructure:Read/Write/Delete
    // drive MCP tier classification only, matching validate_scope's own
    // precedent of a registered pair with no backing perm_fn call).
    //
    // create_result_set_from_inventory_query is DELIBERATELY NOT listed here:
    // its real RBAC gate is a genuine perm_fn(Inventory, Read) call (matching
    // the REST twin exactly — see that tool's own permission-denied test),
    // but its kToolSecurityRows/kWriteTools registration is Inventory:WRITE,
    // because the tool genuinely creates a new result set (a write) and
    // readOnlyHint/kWriteTools classification must stay truthful regardless
    // of which permission happens to gate the read half of the work. This
    // array's contract ("REST and MCP gate on the SAME securable/operation")
    // does not hold for this one tool by design, so pinning it here would
    // assert something false in one direction or fail in the other.
    {"list_result_sets", "Infrastructure", "Read", true},
    {"create_result_set", "Infrastructure", "Write", false},
    {"create_result_set_from_tar_query", "Execution", "Execute", false},
    {"create_result_set_from_instruction_result", "Execution", "Execute", false},
    {"reevaluate_result_set", "Execution", "Execute", false},
    {"get_result_set", "Infrastructure", "Read", true},
    {"get_result_set_members", "Infrastructure", "Read", true},
    {"get_result_set_lineage", "Infrastructure", "Read", true},
    {"pin_result_set", "Infrastructure", "Write", false},
    {"unpin_result_set", "Infrastructure", "Write", false},
    {"delete_result_set", "Infrastructure", "Delete", false},
    // #2146 Batch B3 (api-parity programme) — execution/fleet statistics +
    // fleet visualization read twins. Pinned against rest_api_v1.cpp's
    // GET /api/v1/execution-statistics{,/agents,/definitions} + GET
    // /api/v1/statistics, and viz_routes.cpp's GET /api/v1/viz/fleet/topology
    // + GET /api/v1/viz/host/{id}/topology — the SAME (securable, operation)
    // each REST twin gates on.
    {"get_execution_statistics", "Execution", "Read", true},
    {"get_execution_statistics_by_agent", "Execution", "Read", true},
    {"get_execution_statistics_by_definition", "Execution", "Read", true},
    {"get_fleet_statistics", "Infrastructure", "Read", true},
    {"get_fleet_topology", "Response", "Read", true},
    {"get_host_topology", "Response", "Read", true},
    // #2146 Batch B5 - offload targets, CA root-CSR export/subordinate-chain
    // import, platform license, and software deployments. Pinned against
    // offload_routes.cpp / ca_routes.cpp / rest_api_v1.cpp's own gates.
    {"list_offload_targets", "Infrastructure", "Read", true},
    {"create_offload_target", "Infrastructure", "Write", false},
    {"get_offload_target", "Infrastructure", "Read", true},
    {"delete_offload_target", "Infrastructure", "Write", false},
    {"list_offload_target_deliveries", "Infrastructure", "Read", true},
    {"export_ca_root_csr", "Security", "Read", true},
    {"import_ca_chain", "Security", "Write", false},
    {"get_platform_license", "License", "Read", true},
    {"activate_platform_license", "License", "Write", false},
    {"list_license_alerts", "License", "Read", true},
    {"list_software_deployments", "SoftwareDeployment", "Read", true},
    {"create_software_deployment", "SoftwareDeployment", "Execute", false},
    {"rollback_software_deployment", "SoftwareDeployment", "Execute", false},
    {"cancel_software_deployment", "SoftwareDeployment", "Execute", false},
    // Wave 7 PR7.2 — app-usage read surface. Pinned against
    // app_usage_routes.cpp's own gate (GET /api/v1/forensics/agents/{id}/
    // app-usage), same (securable, operation) the MCP twin enforces.
    {"get_agent_app_usage", "Forensics", "Read", true},
    // #2146 A2-R4 (review finding, PR #4656) — approval-review read twins.
    // Pinned against rest_api_v1.cpp's GET /api/v1/approvals and GET
    // /api/v1/approvals/pending/count, same Approval:Read gate the MCP
    // twins' tier_allows/perm_fn calls enforce.
    {"list_pending_approvals", "Approval", "Read", true},
    {"get_pending_approval_count", "Approval", "Read", true},
};

} // namespace

TEST_CASE("operator surface MCP twins: securable/operation parity with the REST routes",
          "[server][routes][mcp]") {
    const auto rows = tool_security_rows_for_test();
    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        const auto it = std::find_if(rows.begin(), rows.end(), [&](const ToolSecurityRow& r) {
            return r.name == expected.tool;
        });
        REQUIRE(it != rows.end());
        CHECK(it->securable == expected.securable);
        CHECK(it->operation == expected.operation);
    }
}

TEST_CASE("operator surface MCP twins: non-Read tools are in kWriteTools, Read tools are not",
          "[server][routes][mcp]") {
    const auto write_tools = write_tool_names_for_test();
    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        const bool present =
            std::find(write_tools.begin(), write_tools.end(), expected.tool) != write_tools.end();
        CHECK(present == !expected.is_read);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// A5 contract sweep (docs/agentic-first-principle.md:88)
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("operator surface MCP twins: every tool satisfies the A5 contract",
          "[server][routes][mcp]") {
    const auto served = tool_names_for_test();
    const auto annotated = tool_annotation_names_for_test();
    const auto schemas = input_schemas_for_test();

    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        // Served + classified.
        CHECK(std::find(served.begin(), served.end(), expected.tool) != served.end());
        // Annotation-map entry present (readOnlyHint/destructiveHint/idempotentHint).
        CHECK(std::find(annotated.begin(), annotated.end(), expected.tool) != annotated.end());
        // Bounded, typed input schema — no free-form object.
        const auto schema_it =
            std::find_if(schemas.begin(), schemas.end(),
                        [&](const auto& s) { return s.name == expected.tool; });
        REQUIRE(schema_it != schemas.end());
        CHECK(schema_it->schema_json.find("\"type\":\"object\"") != std::string::npos);
        CHECK(schema_it->schema_json.find("\"properties\"") != std::string::npos);
        // A bare {"type":"object","properties":{}} with no further structure
        // would be the free-form-object footgun the spec forbids for any
        // tool that DOES take an argument — the original 11 rows here all
        // do. A tool that genuinely takes ZERO arguments (#4027's three
        // list_tar_* tools, same shape as list_agents; #4037's
        // get_guardian_status/list_guardian_rules — the same "{}" shape
        // get_guardian_schemas already uses, outside this array) is not a
        // footgun; "{}" correctly documents "no arguments," it isn't a
        // lazily-typed free-form object. Exempted explicitly so the check
        // stays a real signal for every tool that DOES take arguments.
        static const std::unordered_set<std::string_view> kNoArgTools = {
            "list_tar_process_tree_devices",
            "list_tar_capture_sources_devices",
            "list_tar_retention_paused",
            "get_guardian_status",
            "list_guardian_rules",
            "get_pending_approval_count",
        };
        if (!kNoArgTools.contains(expected.tool))
            CHECK(schema_it->schema_json != R"({"type":"object","properties":{}})");
    }
}

TEST_CASE("operator surface MCP twins: no MCP tool exists for any agent-authenticated "
          "upload session endpoint",
          "[server][routes][mcp]") {
    // The exemption (spec item 3): POST /api/v1/uploads, PUT .../chunk, GET
    // .../{upload_id}, POST .../commit, DELETE .../{upload_id} authenticate
    // on a grant/session bearer credential, never an operator session, and
    // get NO MCP twin. The upload-grant tool family must be EXACTLY the
    // three operator routes — proving no 4th/5th tool for a session
    // endpoint slipped in alongside them.
    const auto served = tool_names_for_test();
    std::vector<std::string> upload_grant_tools;
    for (const auto& name : served)
        if (name.find("upload_grant") != std::string::npos)
            upload_grant_tools.push_back(name);
    std::sort(upload_grant_tools.begin(), upload_grant_tools.end());
    const std::vector<std::string> expected = {"list_upload_grants", "mint_upload_grant",
                                               "revoke_upload_grant"};
    CHECK(upload_grant_tools == expected);

    // Belt-and-braces: no served tool name references the session-only
    // vocabulary (chunk/commit/session) at all.
    for (const auto& name : served) {
        INFO("tool: " << name);
        CHECK(name.find("upload_chunk") == std::string::npos);
        CHECK(name.find("upload_session") == std::string::npos);
        CHECK(name.find("commit_upload") == std::string::npos);
        CHECK(name.find("cancel_upload") == std::string::npos);
        CHECK(name.find("open_upload") == std::string::npos);
    }
}
