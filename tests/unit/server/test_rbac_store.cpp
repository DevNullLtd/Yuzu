/**
 * test_rbac_store.cpp — Unit tests for RbacStore
 *
 * Covers: lifecycle, seed data, role CRUD, permission CRUD, principal-role
 * assignments, group membership, check_permission, deny-overrides-allow,
 * RBAC toggle, check_scoped_permission.
 *
 * No legacy-SQLite backfill test coverage: `RbacStore::migrate_from_sqlite()` itself was
 * retired (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0041 Update, 2026-09-03) -- no
 * production fleet has ever run a pre-Postgres build, so the mandatory backfill never had real
 * legacy data to protect. `server.cpp` now runs `legacy_sqlite_probe::warn_if_legacy_rows` over
 * the legacy tables (incl. `rbac_config`, the one that held the enabled flag) instead.
 */

#include "management_group_store.hpp"
#include "mcp_server_testonly.hpp" // rbac_ops/securables_for_test (#2383 mirror binding)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_generation_rules.hpp"
#include "rbac_store.hpp"

#include "test_auth_db_pg_helper.hpp" // RBAC_STORE_WITH_AUTH — the last-admin guard's auth.users JOIN
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace yuzu::server {

// #2703 Gate 7 item 3 — friend seam (rbac_store.hpp) for exercising
// user_rbac_group_names/role_effects_for directly; same shape as
// PreflightRoutesTestAccess (test_preflight_routes.cpp) /
// DashboardResultsColumnsTestAccess. See the friend declaration's comment for
// why authorize_list_read() alone can't reach role_effects_for's own sites.
struct RbacStoreTestAccess {
    RbacStore& store;
    auto user_rbac_group_names(const std::string& username) {
        return store.user_rbac_group_names(username);
    }
    auto role_effects_for(const std::string& securable_type, const std::string& operation) {
        return store.role_effects_for(securable_type, operation);
    }
};

} // namespace yuzu::server

namespace {
// Pre-migrated + seeded template (RbacStore construction runs the migration AND
// seed_defaults). Every store-behaviour case clones this instead of
// re-migrating/re-seeding per test (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rbac_tpl{"rbacstore", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        RbacStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "rbac template: store failed to migrate/seed");
                                    }};

// Seed a group row DIRECTLY (bypassing create_group's reserved-prefix guard) to
// reproduce a legacy artifact that predates the guard. `source` is written
// verbatim, so a local group literally named `entra:x` can be planted.
void seed_group_raw(PgPool& pool, const std::string& name, const std::string& description,
                    const std::string& source, const std::string& external_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
        "VALUES ($1, $2, $3, $4, 0)",
        std::vector<std::string>{name, description, source, external_id});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}
} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open RbacStore. Expands to
// statements (includes the SKIP-if-no-DSN guard), so it must lead a block. The
// db/pool must outlive `store_var`; declaring all three here keeps that order.
#define RBAC_STORE(store_var)                                                                      \
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_fx_, rbac_tpl);                                                  \
    PgPool rbac_pool_fx_{{.conninfo = rbac_db_fx_.dsn(), .size = 4}};                               \
    REQUIRE(rbac_pool_fx_.valid());                                                                 \
    RbacStore store_var{rbac_pool_fx_};                                                             \
    REQUIRE(store_var.is_open())

// Fixture for the A2 last-Administrator guard (governance BLOCKING #1,
// full-pipeline review on 765bc7ec1): `RbacStore::unassign_role`'s guard now
// JOINs `auth.users`, so these tests need BOTH schemas in the SAME
// database — unlike `RBAC_STORE` above, which uses the shared "rbacstore"
// `PgTestTemplate` name that 9+ OTHER test files also register verbatim
// (the registry's replay-verification requires every registration of one
// template name stay behaviorally identical), so extending THAT template to
// also carry `auth.users` is out of scope for this fix — it would have to
// change in lockstep across every one of those files. Instead: construct
// `RbacStore` DIRECTLY on a real `AuthDbPg` fixture's own pool (mirrors
// `server.cpp`'s own composition — ONE `pg_pool_`, both stores built from
// it, ADR-0006) rather than via the shared template. Slower than a
// template clone (a fresh RbacStore migration+seed every case, not a
// pre-migrated clone) but this fixture backs a small, dedicated set of
// cases, not the whole file.
#define RBAC_STORE_WITH_AUTH(store_var, auth_var)                                                 \
    yuzu::test::AuthDbPg auth_var;                                                                \
    RbacStore store_var{auth_var.pool()};                                                         \
    REQUIRE(store_var.is_open())

/// Seed an ACTIVE auth.users row for `username` (a genuinely authenticatable
/// account) — the shared building block for every last-admin-guard test
/// below. `role` doesn't matter to `unassign_role`'s guard (it JOINs only on
/// `is_active`), so this defaults to a plain non-admin `auth::Role::user`
/// row; RBAC administrator authority comes entirely from the
/// `principal_roles` grant, a separate table this helper does not touch.
void seed_active_user(yuzu::test::AuthDbPg& auth_db, const std::string& username) {
    REQUIRE(auth_db->upsert_user(username, "hash", "salt", auth::Role::user).has_value());
}

/// Doomgoose external review, PR #4985 (IMPORTANT #6): poll `pg_stat_activity`
/// for a backend GENUINELY blocked on a Postgres lock (row lock via `FOR
/// UPDATE`, or an advisory lock — both register `wait_event_type = 'Lock'`),
/// rather than a blind `sleep_for` + assume-timing "prove a thread has
/// started" (CLAUDE.md forbids sleep_for+assume-timing synchronization for
/// correctness — a sleep-gated interleaving proof can flake on a loaded
/// shared CI runner even though the load-bearing correctness here depends on
/// the real lock, not the sleep duration).
///
/// MUST run on its OWN ad-hoc connection, opened here from `dsn` — NEVER on
/// the lock HOLDER's own connection, even though that connection is idle and
/// available to accept a new query. Verified empirically while building this
/// fix (5+ minute live-PG debugging session, not a documentation guess):
/// `pg_stat_activity` is snapshotted ONCE per transaction (PostgreSQL's own
/// documented statistics-view behavior — "information ... is collected when
/// any such information is first requested within a transaction, and the
/// same information will be displayed throughout the transaction"). The lock
/// holder's connection (e.g. `lease_a` in every caller below) is ALWAYS
/// mid-explicit-transaction (`BEGIN` already issued) by the time this is
/// called, so probing through it would take ONE snapshot on the first poll
/// iteration and silently keep re-reading that SAME frozen, pre-block
/// snapshot for every remaining iteration — never observing the waiter no
/// matter how long or how many times it polls. This exact bug shipped in an
/// earlier draft of this fix and hung every test using it indefinitely (the
/// blocked backend was real — confirmed via `pg_backend_pid()` self-query
/// and independent `psql` inspection — `pg_stat_activity` just never
/// refreshed on the probing connection to show it). A separate, dedicated
/// connection issuing bare autocommit statements (no explicit `BEGIN`) gets
/// a fresh snapshot on every single statement, which is what makes polling
/// here actually work. `own_pid` excludes the lock HOLDER's own backend so
/// it's never mistaken for the waiter. Bounded: up to `max_attempts` x 50ms
/// (5s by default) before giving up and returning 0.
// (cpp-safety re-review, PR #4985 fix round: `PQntuples(r.get()) == 1` is a
// strict-equality match — a SECOND concurrent lock-waiter on a shared/loaded
// CI Postgres at the same moment (this box runs 4 runner agents as one OS
// identity, #1871) makes every iteration return 0 or 2+ rows and spin to the
// full timeout. Same shape as the blind-sleep code this replaced, not a new
// defect — flagged since it's the kind of shared-runner collision
// unit-test-conventions.md already tracks for fixed identifiers, and a
// row-count predicate is the same class of thing.)
int poll_for_blocked_backend_pid(const std::string& dsn, int own_pid, int max_attempts = 100) {
    pg::PgConn probe{PQconnectdb(dsn.c_str())};
    if (PQstatus(probe.get()) != CONNECTION_OK) {
        UNSCOPED_INFO("poll_for_blocked_backend_pid: probe connection failed, distinct from "
                      "'no lock wait observed within the bound'");
        return 0;
    }
    for (int i = 0; i < max_attempts; ++i) {
        pg::PgResult r = pg::exec_params(probe.get(),
                                         "SELECT pid FROM pg_stat_activity WHERE datname = "
                                         "current_database() AND wait_event_type = 'Lock' "
                                         "AND pid <> $1",
                                         std::vector<std::string>{std::to_string(own_pid)});
        if (r.ok() && PQntuples(r.get()) == 1)
            return std::atoi(PQgetvalue(r.get(), 0, 0));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}

// Joins its std::thread on scope exit, after running `before_join` (used to roll back a
// held lease so a worker blocked on that lease's row lock can finish). A failing REQUIRE
// therefore never leaves a joinable std::thread behind (std::terminate) and never waits
// out a lock_timeout. std::jthread is not available on Apple Clang's libc++, so this
// stands in for it.
class ScopedJoin {
public:
    explicit ScopedJoin(std::thread t, std::function<void()> before_join = {})
        : t_(std::move(t)), before_join_(std::move(before_join)) {}
    ScopedJoin(const ScopedJoin&) = delete;
    ScopedJoin& operator=(const ScopedJoin&) = delete;
    ~ScopedJoin() {
        if (t_.joinable()) {
            if (before_join_)
                before_join_();
            t_.join();
        }
    }
    void join() {
        if (t_.joinable())
            t_.join();
    }

private:
    std::thread t_;
    std::function<void()> before_join_;
};

TEST_CASE("RbacStore migration lands at v4 and poisons (not deletes) the backfill marker rows "
          "(#3623, governance unhappy-path fix)",
          "[rbac_store][pg][migration]") {
    // v4 does NOT delete backfill_complete/backfill_source_fingerprint -- an earlier revision
    // did, which let a pre-#3623 binary rolling back treat marker ABSENCE as "never migrated"
    // and fall through to an unconditional overwrite of the live rbac_enabled flag from a local
    // legacy rbac.db file, skipping that old binary's own fingerprint-verification safety net
    // entirely (governance unhappy-path, 2026-09-03). The fix poisons backfill_source_fingerprint
    // to the exact "sourceless" sentinel the retired code's own marker_present branch checks for,
    // so an old binary rolling back sees the marker as present and takes its existing fail-closed
    // path instead (refuses to auto-migrate when a real legacy file exists; silent no-op when it
    // doesn't) -- the same loud-outage-not-silent-corruption risk class already accepted for the
    // other 5 retired stores' DROP TABLE approach, see this migration's own comment in
    // rbac_store.cpp for the full trace.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    RbacStore store{pool};
    REQUIRE(store.is_open());

    pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult ver{PQexec(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                        "'rbac_store'")};
    REQUIRE(ver.ok());
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "4");

    // rbac_meta stays (it still holds rbac_enabled/write_generation) — the two one-time
    // backfill marker rows are PRESENT (poisoned), not gone.
    pg::PgResult rows{PQexec(conn.get(),
                             "SELECT key, value FROM rbac_store.rbac_meta WHERE key IN "
                             "('backfill_complete', 'backfill_source_fingerprint') ORDER BY key")};
    REQUIRE(rows.ok());
    REQUIRE(PQntuples(rows.get()) == 2);
    CHECK(std::string(PQgetvalue(rows.get(), 0, 0)) == "backfill_complete");
    CHECK_FALSE(std::string(PQgetvalue(rows.get(), 0, 1)).empty()); // presence-only, value unread
    CHECK(std::string(PQgetvalue(rows.get(), 1, 0)) == "backfill_source_fingerprint");
    // Must match the retired code's kSourcelessFingerprint literal EXACTLY -- this is the
    // string an old binary's marker_present branch compares against.
    CHECK(std::string(PQgetvalue(rows.get(), 1, 1)) == "sourceless");
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: open in-memory", "[rbac_store][db][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.is_open());
}

TEST_CASE("RbacStore: seed data — system roles exist", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto roles = store.list_roles();

    auto find = [&](const std::string& name) {
        return std::find_if(roles.begin(), roles.end(),
                            [&](const RbacRole& r) { return r.name == name; });
    };

    REQUIRE(find("Administrator") != roles.end());
    REQUIRE(find("Operator") != roles.end());
    REQUIRE(find("ITServiceOwner") != roles.end());
    REQUIRE(find("Viewer") != roles.end());
    CHECK(find("Administrator")->is_system);
    CHECK(find("Operator")->is_system);
    CHECK(find("ITServiceOwner")->is_system);
    CHECK(find("Viewer")->is_system);
}

TEST_CASE("RbacStore: seed data — securable types", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto types = store.list_securable_types();
    // +SoftwareLicensing (ADR-0024) +AccessReview (SOC 2 CC6.2) +EnginePrincipal
    // (#2376, cut away from Security:Read) +PluginConfig +PluginSecret
    // +UploadGrant (PR1.9a, peer finding PLAN-001) +PowerManagement (Wave 6 W1B) = 27,
    // +Workflow (#4030/#4032 — previously gated but never seeded) = 28,
    // +ProductPack (#4029 prerequisite fix — was used as an RBAC securable string by
    // the shipped /api/product-packs* routes but never seeded) = 29,
    // +TlsConfig +PluginSigning +ServerConfig +AnalyticsConfig (#4028
    // Settings read-twins) = 33,
    // +Directory +Enrollment +OidcConfig (#4031 prerequisite fix — Directory was
    // referenced by discovery_routes.cpp but never seeded; Enrollment/OidcConfig
    // are the two new #4031 route securables) = 36,
    // +Forensics (37th) +Decommission (38th, Wave 7 PR7.2) = 38.
    REQUIRE(types.size() == 38);

    auto has = [&](const std::string& t) {
        return std::find(types.begin(), types.end(), t) != types.end();
    };
    CHECK(has("Infrastructure"));
    CHECK(has("Execution"));
    CHECK(has("AuditLog"));
    CHECK(has("Response"));
    CHECK(has("ManagementGroup"));
    CHECK(has("ApiToken"));
    CHECK(has("Security"));
    CHECK(has("Policy"));
    CHECK(has("DeviceToken"));
    CHECK(has("SoftwareDeployment"));
    CHECK(has("License")); // Yuzu's OWN product licence (§22.3) — DISTINCT from SLE
    CHECK(has("FileRetrieval"));
    CHECK(has("GuaranteedState"));
    CHECK(has("Inventory"));
    CHECK(has("SoftwareLicensing")); // SLE securable (ADR-0024 Decision 9) — NOT `License`
    CHECK(has("AccessReview")); // Periodic Access Reviews (SOC 2 CC6.2), dedicated + narrow
    CHECK(has("PluginConfig")); // PR1.9a: plugin kill-switch config
    CHECK(has("PluginSecret")); // PR1.9a: plugin secret material
    CHECK(has("UploadGrant"));  // PR1.9a: upload-grant mint/revoke lifecycle
    CHECK(has("EnginePrincipal")); // Engine-principal inventory + grant-graph reads (#2376),
                                   // cut away from the over-broad Security:Read
    CHECK(has("Workflow")); // #4030/#4032: previously gated but never seeded
    CHECK(has("ProductPack")); // #4029 prerequisite fix
    CHECK(has("PowerManagement")); // Wave 6 W1B: power_health's set_power_plan
    CHECK(has("TlsConfig"));       // #4028: tls/https Settings fragments
    CHECK(has("PluginSigning"));   // #4028: plugin-signing fragment + GET /agent/plugin-policy (v2)
    CHECK(has("ServerConfig"));    // #4028: gateway/server-config/mcp/data-retention fragments
    CHECK(has("AnalyticsConfig")); // #4028: analytics fragment
    CHECK(has("Forensics")); // Wave 7 forensics class (execution_artifacts, app_usage)
    CHECK(has("Decommission")); // Wave 7 PR7.2: whole-device erasure cascade
    CHECK(has("Directory"));   // #4031 prerequisite fix — AD/Entra directory-sync
    CHECK(has("Enrollment"));  // #4031: auto-approve rules + pending-agent visibility
    CHECK(has("OidcConfig"));  // #4031: OIDC SSO config read (deliberately not "Directory")
}

TEST_CASE("RbacStore: seed data — operations", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto ops = store.list_operations();
    // Read, Write, Execute, Delete, Approve, Push (Push added for Guardian
    // distribute-rules-to-fleet operation; design v1.1 §9.2), Attest (added
    // for Periodic Access Reviews, SOC 2 CC6.2 — AccessReview:Attest sign-off),
    // Rotate (added for human API-token self-service rotation, P2 #11, SOC 2
    // CC6.3 — ApiToken:Rotate, deliberately distinct from ApiToken:Write).
    REQUIRE(ops.size() == 8);
}

// #2383 (governance C-3/UP-6): the MCP C8 boot validator carries closed-catalogue
// MIRRORS of this store's seeded `ops[]` and `types[]` (kRbacOps /
// kRbacSecurables in mcp_server.cpp). This test binds mirror to seed by NAME,
// both directions, so adding/removing an operation or securable in one place
// without the other fails here instead of drifting silently.
TEST_CASE("RbacStore: seeded catalogues match the MCP C8 validator mirrors",
          "[rbac_store][mcp][2g][pg]") {
    RBAC_STORE(store);

    auto sorted = [](std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    };
    CHECK(sorted(store.list_operations()) == sorted(yuzu::server::mcp::rbac_ops_for_test()));
    CHECK(sorted(store.list_securable_types()) ==
          sorted(yuzu::server::mcp::rbac_securables_for_test()));
}

TEST_CASE("RbacStore: seed data — Administrator has all permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Administrator");
    // 38 types * 5 CRUD ops = 190 permissions, plus a single targeted Push
    // grant on GuaranteedState (= 191), plus a single AccessReview:Attest grant
    // (Periodic Access Reviews, CC6.2, = 192), plus a single ApiToken:Rotate
    // grant (P2 #11, SOC 2 CC6.3) = 193 permissions total. Push, Attest, and
    // Rotate are deliberately NOT cross-seeded on other securables — see the
    // rationale in rbac_store.cpp seed_defaults(). (38th: Decommission, Wave 7
    // PR7.2; 37th: Forensics, Wave 7 forensics class; 36th-34th: Directory/
    // Enrollment/OidcConfig, #4031; 33rd-30th: TlsConfig/PluginSigning/
    // ServerConfig/AnalyticsConfig, #4028 Settings read-twins; 29th:
    // ProductPack, #4029 prerequisite fix; 28th: Workflow, #4030/#4032 —
    // previously gated but never seeded; 27th: PowerManagement, Wave 6
    // power_health set_power_plan; 26th-24th: UploadGrant/PluginSecret/
    // PluginConfig, PR1.9a peer finding PLAN-001; 23rd: EnginePrincipal,
    // #2376; 22nd: AccessReview, SOC 2 CC6.2; 21st: SoftwareLicensing,
    // ADR-0024.)
    CHECK(perms.size() == 193);
    for (auto& p : perms)
        CHECK(p.effect == "allow");

    // Confirm the Push grant exists exactly once, and only on GuaranteedState.
    size_t push_count = 0;
    for (const auto& p : perms) {
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
    }
    CHECK(push_count == 1);

    // Confirm the Rotate grant (P2 #11) exists exactly once, and only on
    // ApiToken — a cross-seeded Rotate on any other securable would be
    // exactly the kind of silent widening the round-3 finding was about.
    size_t rotate_count = 0;
    for (const auto& p : perms) {
        if (p.operation == "Rotate") {
            ++rotate_count;
            CHECK(p.securable_type == "ApiToken");
        }
    }
    CHECK(rotate_count == 1);
}

TEST_CASE("RbacStore: seed data — Viewer has read-only", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Viewer");
    // 24 types * Read only (everything except Infrastructure; incl. Inventory +
    // SoftwareLicensing, ADR-0024, + EnginePrincipal, #2376, + Workflow,
    // #4030/#4032, + ProductPack, #4029, + Directory, #4031 — AD/Entra
    // directory-sync PII, same precedent as UserManagement). Enrollment/
    // OidcConfig deliberately do NOT join Viewer's list — see the seeding
    // comment in rbac_store.cpp's Viewer read-loop. (Counted directly from
    // the merged Viewer grant-loop's type list, not derived from either
    // side's pre-merge arithmetic — see #4030's own merge-round precedent
    // for why that check matters here.)
    CHECK(perms.size() == 24);
    for (auto& p : perms) {
        CHECK(p.operation == "Read");
        CHECK(p.effect == "allow");
        CHECK(p.securable_type != "Infrastructure");
    }
}

// ── PR1.9a (peer finding PLAN-001): PluginConfig / PluginSecret / UploadGrant ──

namespace {

bool has_grant(const std::vector<Permission>& perms, const std::string& securable_type,
              const std::string& operation) {
    return std::find_if(perms.begin(), perms.end(), [&](const Permission& p) {
               return p.securable_type == securable_type && p.operation == operation &&
                      p.effect == "allow";
           }) != perms.end();
}

} // namespace

TEST_CASE("RbacStore: seed data — Administrator has full CRUD on the three new securables",
          "[rbac_store][plan-001][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Administrator");
    for (const std::string& securable : {"PluginConfig", "PluginSecret", "UploadGrant"}) {
        INFO("securable=" << securable);
        for (const char* op : {"Read", "Write", "Execute", "Delete", "Approve"}) {
            CHECK(has_grant(perms, securable, op));
        }
    }
}

TEST_CASE("RbacStore: seed data — PlatformEngineer has Read/Write/Delete on the three new "
          "securables",
          "[rbac_store][plan-001][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("PlatformEngineer");
    for (const std::string& securable : {"PluginConfig", "PluginSecret", "UploadGrant"}) {
        INFO("securable=" << securable);
        CHECK(has_grant(perms, securable, "Read"));
        CHECK(has_grant(perms, securable, "Write"));
        CHECK(has_grant(perms, securable, "Delete"));
    }
}

TEST_CASE("RbacStore: seed data — Operator has Read on PluginConfig and UploadGrant, "
          "nothing on PluginSecret",
          "[rbac_store][plan-001][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Operator");

    CHECK(has_grant(perms, "PluginConfig", "Read"));
    CHECK(has_grant(perms, "UploadGrant", "Read"));

    // Never PluginSecret — no grant of any operation, on any effect.
    for (const auto& p : perms) {
        CHECK(p.securable_type != "PluginSecret");
    }
    // And never Write/Delete on the two it does see.
    CHECK_FALSE(has_grant(perms, "PluginConfig", "Write"));
    CHECK_FALSE(has_grant(perms, "PluginConfig", "Delete"));
    CHECK_FALSE(has_grant(perms, "UploadGrant", "Write"));
    CHECK_FALSE(has_grant(perms, "UploadGrant", "Delete"));
}

// ── #4029: ProductPack prerequisite fix ────────────────────────────────────

TEST_CASE("RbacStore: seed data — Administrator has full CRUD on ProductPack",
          "[rbac_store][4029][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_role_permissions("Administrator");
    for (const char* op : {"Read", "Write", "Execute", "Delete", "Approve"}) {
        CHECK(has_grant(perms, "ProductPack", op));
    }
}

TEST_CASE("RbacStore: seed data — Operator/PlatformEngineer/Viewer have ProductPack:Read, "
          "never Write/Delete",
          "[rbac_store][4029][pg]") {
    RBAC_STORE(store);
    for (const char* role : {"Operator", "PlatformEngineer", "Viewer"}) {
        INFO("role=" << role);
        auto perms = store.get_role_permissions(role);
        CHECK(has_grant(perms, "ProductPack", "Read"));
        CHECK_FALSE(has_grant(perms, "ProductPack", "Write"));
        CHECK_FALSE(has_grant(perms, "ProductPack", "Delete"));
    }
}

// ── RBAC toggle ──────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: RBAC disabled by default", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.is_rbac_enabled());
}

TEST_CASE("RbacStore: enable and disable RBAC", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.set_rbac_enabled(true);
    CHECK(store.is_rbac_enabled());
    store.set_rbac_enabled(false);
    CHECK_FALSE(store.is_rbac_enabled());
}

// #1498 — the device-visibility fallback must distinguish a store that is
// loaded-and-explicitly-disabled (full-fleet fallback OK) from one that is
// missing or failed to load (fail CLOSED). The probe wired into
// ManagementGroupStore is exactly rbac_enforcement_in_effect(rbac_store_.get()),
// so this exercises the real predicate, not a stand-in lambda.
TEST_CASE("rbac_enforcement_in_effect fails closed on null / load-failed store",
          "[rbac_store][visibility][pg]") {
    SECTION("null store → enforcement in effect (fail closed)") {
        CHECK(rbac_enforcement_in_effect(nullptr));
    }

    SECTION("load-failed store (is_open()==false) → fail closed, not full-fleet") {
        // The PG analogue of the SQLite load-failed store (ADR-0041 fail-closed
        // construction test): a pool whose DSN never connects leaves the store's
        // construction lease empty, so migration never runs and is_open()==false
        // — the same state a corrupt/unreachable rbac substrate produces, and
        // indistinguishable by the enabled flag alone.
        PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                    .size = 1}};
        RbacStore broken{bad};
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_in_effect(&broken)); // must fail closed
    }

    SECTION("unreachable-substrate store (open/migration failed) → fail closed") {
        // The constructor's failure path when the substrate is unreachable — a
        // second unroutable DSN (distinct host) exercising the same fail-closed
        // is_open()==false outcome that #1717's corrupt-but-openable rbac.db
        // produced on SQLite.
        PgPool bad{{.conninfo = "host=192.0.2.1 port=5432 dbname=x user=x connect_timeout=1",
                    .size = 1}};
        RbacStore broken{bad};
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_in_effect(&broken)); // must fail closed
    }

    SECTION("loaded + explicitly disabled → full-fleet fallback permitted") {
        RBAC_STORE(store);
        REQUIRE(store.is_open());
        REQUIRE_FALSE(store.is_rbac_enabled()); // disabled by default
        CHECK_FALSE(rbac_enforcement_in_effect(&store));
    }

    SECTION("loaded + enabled → enforcement in effect (role-scoped path)") {
        RBAC_STORE(store);
        store.set_rbac_enabled(true);
        REQUIRE(store.is_rbac_enabled());
        CHECK(rbac_enforcement_in_effect(&store));
    }
}

// A3 (RBAC delivery plan, access-review export) — rbac_enforcement_label's
// three-way classification, exercising the SAME four scenarios as the
// boolean test above plus the "cached-enabled but view also stale" ordering
// asymmetry the header comment calls out explicitly. The exact-mapping
// property (`rbac_enforcement_in_effect(store) == (label != kDisabled)`) is
// asserted alongside every CHECK below, not just described.
TEST_CASE("rbac_enforcement_label maps exactly onto rbac_enforcement_in_effect, split into "
         "enabled/disabled/degraded",
         "[rbac_store][visibility][pg]") {
    SECTION("null store → degraded (fail closed)") {
        CHECK(rbac_enforcement_label(nullptr) == RbacEnforcementLabel::kDegraded);
        CHECK(to_string(rbac_enforcement_label(nullptr)) == "degraded");
        CHECK(rbac_enforcement_in_effect(nullptr) ==
             (rbac_enforcement_label(nullptr) != RbacEnforcementLabel::kDisabled));
    }

    SECTION("load-failed store (is_open()==false) → degraded (fail closed)") {
        PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                    .size = 1}};
        RbacStore broken{bad};
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_label(&broken) == RbacEnforcementLabel::kDegraded);
        CHECK(rbac_enforcement_in_effect(&broken) ==
             (rbac_enforcement_label(&broken) != RbacEnforcementLabel::kDisabled));
    }

    SECTION("loaded + explicitly disabled + fresh view → disabled") {
        RBAC_STORE(store);
        REQUIRE(store.is_open());
        REQUIRE_FALSE(store.is_rbac_enabled());
        CHECK(rbac_enforcement_label(&store) == RbacEnforcementLabel::kDisabled);
        CHECK(to_string(rbac_enforcement_label(&store)) == "disabled");
        CHECK(rbac_enforcement_in_effect(&store) ==
             (rbac_enforcement_label(&store) != RbacEnforcementLabel::kDisabled));
    }

    SECTION("loaded + enabled → enabled") {
        RBAC_STORE(store);
        store.set_rbac_enabled(true);
        REQUIRE(store.is_rbac_enabled());
        CHECK(rbac_enforcement_label(&store) == RbacEnforcementLabel::kEnabled);
        CHECK(to_string(rbac_enforcement_label(&store)) == "enabled");
        CHECK(rbac_enforcement_in_effect(&store) ==
             (rbac_enforcement_label(&store) != RbacEnforcementLabel::kDisabled));
    }
}

// The one asymmetry the header comment on rbac_enforcement_label() flags
// explicitly: a store that is cached-ENABLED but whose generation view is
// ALSO stale classifies as kEnabled, not kDegraded — is_rbac_enabled() short-
// circuits before rbac_enabled_view_degraded() is ever consulted, mirroring
// rbac_enforcement_in_effect()'s own precedence exactly. Reuses the same
// starved-replica technique as the sibling rbac_enforcement_in_effect
// staleness test (#2703) so this is the REAL degrade path, not a stand-in.
TEST_CASE("rbac_enforcement_label: cached-enabled short-circuits past a stale view — stays "
         "kEnabled, never kDegraded (documents the one deliberate asymmetry vs. a granular "
         "read)",
         "[rbac_store][visibility][pg]") {
    RBAC_STORE(replica_a);
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.is_rbac_enabled());

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    // replica_b observes the durable enable at its own construction (shares
    // the same already-migrated database as replica_a via RBAC_STORE's
    // template clone — but set_rbac_enabled(true) above ran AFTER replica_b's
    // template was cloned, so replica_b must independently observe it here).
    REQUIRE(replica_b.is_rbac_enabled());

    // Starve replica_b's pool so every subsequent refresh attempt times out,
    // then advance wall time past kRbacStaleServeBoundMs — the exact
    // technique the sibling rbac_enforcement_in_effect staleness test uses.
    auto held = pool_b.acquire();
    REQUIRE(held);
    std::this_thread::sleep_for(std::chrono::milliseconds(5200));

    // The view is now genuinely stale — proven directly, bypassing
    // is_rbac_enabled()'s own refresh attempt (Gate 8 technique, lines above)
    // — but the label still reports kEnabled: is_rbac_enabled() itself
    // re-attempts a refresh, fails (pool starved), and per its own "never
    // touch rbac_enabled_ on a read error" contract keeps serving the
    // last-known-good cached value, which was `true`.
    CHECK(replica_b.rbac_enabled_view_degraded());
    CHECK(replica_b.is_rbac_enabled());
    CHECK(rbac_enforcement_label(&replica_b) == RbacEnforcementLabel::kEnabled);
    // Gates still deny either way — the exact-mapping property holds even on
    // this asymmetric branch.
    CHECK(rbac_enforcement_in_effect(&replica_b));
}

// ── Role CRUD ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create custom role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.create_role({"SOC Analyst", "Security operations read access", false, 0});
    REQUIRE(result.has_value());

    auto role = store.get_role("SOC Analyst");
    REQUIRE(role.has_value());
    CHECK(role->name == "SOC Analyst");
    CHECK(role->description == "Security operations read access");
    CHECK_FALSE(role->is_system);
    CHECK(role->created_at > 0);
}

TEST_CASE("RbacStore: create duplicate role fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"MyRole", "", false, 0});
    auto result = store.create_role({"MyRole", "", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: create role with empty name fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.create_role({"", "desc", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: delete custom role succeeds", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Temp", "temporary", false, 0});
    auto result = store.delete_role("Temp");
    REQUIRE(result.has_value());
    CHECK_FALSE(store.get_role("Temp").has_value());
}

TEST_CASE("RbacStore: delete system role fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.delete_role("Administrator");
    CHECK_FALSE(result.has_value());
    CHECK(store.get_role("Administrator").has_value());
}

TEST_CASE("RbacStore: update role description", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"MyRole", "old desc", false, 0});
    auto result = store.update_role("MyRole", "new desc");
    REQUIRE(result.has_value());
    CHECK(store.get_role("MyRole")->description == "new desc");
}

// ── Permission CRUD ──────────────────────────────────────────────────────────

TEST_CASE("RbacStore: set and get permission", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"TestRole", "", false, 0});

    auto result = store.set_permission({"TestRole", "Execution", "Execute", "allow"});
    REQUIRE(result.has_value());

    auto perms = store.get_role_permissions("TestRole");
    REQUIRE(perms.size() == 1);
    CHECK(perms[0].securable_type == "Execution");
    CHECK(perms[0].operation == "Execute");
    CHECK(perms[0].effect == "allow");
}

// fable (Gate 4, #2703, HIGH — REVISED from an earlier deny-tombstone fix):
// remove_permission() DELETEs the role_permissions row (restoring the exact
// legacy contract — absence, not a 'deny' row) and separately records the
// revocation in revoked_seed_defaults, bookkeeping consulted ONLY by
// seed_defaults()'s grant(). An earlier fix upserted an explicit 'deny' row
// instead, on the theory the authorization OUTCOME was identical either
// way — false: check_permission()/check_scoped_permission() apply "deny
// overrides everything, across ALL of a principal's held roles", so a deny
// row from THIS role would veto an allow the SAME principal holds via a
// DIFFERENT role (see the dual-role divergence test below). The marker
// table fixes the resurrection bug without creating that authorization
// fact.
TEST_CASE("RbacStore: remove permission deletes the row and survives a reseed",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // Operator's AuditLog:Read is a real seed_defaults() default.
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    REQUIRE(store.remove_permission("Operator", "AuditLog", "Read").has_value());
    // THE FIX: the row is genuinely gone — absent, not tombstoned.
    for (const auto& p : store.get_role_permissions("Operator"))
        CHECK_FALSE((p.securable_type == "AuditLog" && p.operation == "Read"));
    CHECK_FALSE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    // THE REGRESSION THIS CLOSES: a second construction against the SAME
    // pool runs the REAL seed_defaults() (unconditional on every boot,
    // ON CONFLICT DO NOTHING) — its grant() now consults
    // revoked_seed_defaults and skips re-inserting the revoked row.
    RbacStore reopened{rbac_pool_fx_};
    CHECK_FALSE(reopened.check_role_has_permission("Operator", "AuditLog", "Read"));
}

// chaos-injector (Gate 5, #2703, HIGH — CHAOS-1, verified against live PG):
// grant()'s `INSERT ... SELECT ... WHERE NOT EXISTS (marker) ... ON CONFLICT
// DO NOTHING` takes its READ COMMITTED snapshot once, at statement start. If
// that snapshot is taken BEFORE a concurrent revoke's marker-insert commits,
// but grant() then blocks on the ON CONFLICT arbiter waiting for that same
// revoke's uncommitted DELETE, Postgres — once the revoke commits — only
// re-checks the CONFLICT TARGET (now gone), never re-evaluates the WHERE NOT
// EXISTS subquery. So grant()'s already-computed INSERT lands anyway: the
// marker AND the resurrected row both end up present, permanently (nothing
// ever re-syncs role_permissions against revoked_seed_defaults). Fixed by a
// pg_advisory_xact_lock, acquired in its OWN statement strictly before the
// check-and-mutate statement, in every writer (grant(), remove_permission(),
// the backfill's F1 block) — see kRevokeCoordLockSql in rbac_store.cpp.
TEST_CASE("RbacStore: seed_defaults()'s grant() cannot resurrect a permission mid-revoke "
          "(CHAOS-1)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));

    // Connection A: open a revoke transaction (lock + marker insert + DELETE)
    // and hold it UNCOMMITTED — simulating remove_permission()'s in-flight
    // write racing a concurrent seed_defaults() boot on another connection.
    auto lease_a = rbac_pool_fx_.acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pg_advisory_xact_lock(2037545589, "
                            "hashtext('rbac_store:revoke_coordination'))",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "INSERT INTO rbac_store.revoked_seed_defaults (role_name, "
                            "securable_type, operation) VALUES ('Operator','AuditLog','Read') "
                            "ON CONFLICT DO NOTHING",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "DELETE FROM rbac_store.role_permissions WHERE role_name='Operator' "
                            "AND securable_type='AuditLog' AND operation='Read'",
                            std::vector<std::string>{})
                .ok());

    // Connection B, on a separate thread: a SECOND RbacStore construction
    // against the SAME pool — a genuine replica boot, exercising the REAL
    // (production) seed_defaults()/grant() code, not a hand-copy of its SQL.
    // Its grant() call for Operator/AuditLog/Read must BLOCK on connection
    // A's held lock, and once unblocked, must see the marker and insert
    // NOTHING. No REQUIRE/CHECK runs on this background thread — a Catch2
    // assertion macro throwing off the main thread has no handler and calls
    // std::terminate() immediately; the outcome is captured in a plain
    // atomic and asserted on the main thread after join() instead.
    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_open{false};
    std::thread grant_thread([&] {
        b_started = true;
        RbacStore reopened{rbac_pool_fx_};
        b_open = reopened.is_open();
        b_done = true;
    });
    // cpp-safety (Gate 8, #2703, BLOCKING): join-on-unwind guard. A REQUIRE
    // between thread construction and the explicit .join() below throws on
    // failure, and a joinable std::thread destroyed mid-unwind calls
    // std::terminate() (test_approval_manager.cpp:888-954 hit this same
    // hazard class). Detaching instead of joining would NOT be safe here
    // (unlike that file's case): this lambda captures rbac_pool_fx_/
    // b_started/b_done/b_open BY REFERENCE — stack locals of this
    // TEST_CASE — so a detached thread outliving them would be a
    // use-after-free, not a fix. The background thread's only blocking
    // wait is the advisory lock, server-side bounded by the pool's
    // lock_timeout, so join() here cannot hang indefinitely.
    struct ThreadJoiner {
        std::thread& t;
        ~ThreadJoiner() {
            if (t.joinable())
                t.join();
        }
    } joiner{grant_thread};

    // Give the grant thread time to start and genuinely block on connection
    // A's held lock — poll pg_stat_activity for a real Lock wait rather than
    // trust a fixed sleep duration to prove it (Doomgoose external review,
    // PR #4985 IMPORTANT #6). MUST use a separate probe connection, never
    // lease_a itself — see poll_for_blocked_backend_pid's own doc comment.
    REQUIRE(poll_for_blocked_backend_pid(rbac_db_fx_.dsn(), lease_a_pid) != 0);
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    const bool commit_ok =
        pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok();
    lease_a.reset();
    grant_thread.join();
    CHECK(commit_ok);
    CHECK(b_done.load());
    CHECK(b_open.load());

    // THE FIX: the permission must stay revoked.
    CHECK_FALSE(store.check_role_has_permission("Operator", "AuditLog", "Read"));
}

// fable (Gate 4, #2703, HIGH): a principal holding BOTH a role whose default
// was revoked AND a different role that independently grants the same
// (securable_type, operation) must still be granted — matching legacy,
// where the revoked role's row was simply absent and never vetoed the other
// role's independent allow. This is the scenario the deny-tombstone fix
// silently broke (verified empirically before the marker-table fix landed:
// the same setup denied dualuser under the tombstone).
TEST_CASE("RbacStore: revoking one role's default does not veto a different role's "
          "independent grant (dual-role)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // PlatformEngineer and Operator both seed AuditLog:Read by default.
    REQUIRE(store.check_role_has_permission("PlatformEngineer", "AuditLog", "Read"));
    REQUIRE(store.check_role_has_permission("Operator", "AuditLog", "Read"));
    store.assign_role({"user", "dualuser", "PlatformEngineer"});
    store.assign_role({"user", "dualuser", "Operator"});
    REQUIRE(store.check_permission("dualuser", "AuditLog", "Read"));

    REQUIRE(store.remove_permission("PlatformEngineer", "AuditLog", "Read").has_value());
    CHECK_FALSE(store.check_role_has_permission("PlatformEngineer", "AuditLog", "Read"));
    // Operator's independent grant is untouched...
    CHECK(store.check_role_has_permission("Operator", "AuditLog", "Read"));
    // ...and dualuser, holding both roles, is STILL granted — Operator's
    // allow controls, matching legacy (an absent row from PlatformEngineer
    // is neutral, not a veto).
    CHECK(store.check_permission("dualuser", "AuditLog", "Read"));
}

// quality-engineer (#2703): remove_permission() still validates all three
// columns (role_permissions AND revoked_seed_defaults both REFERENCE the
// same catalogue tables) — an unrecognized triple must fail, not silently
// "succeed".
TEST_CASE("RbacStore: remove permission on an unrecognized triple fails", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.remove_permission("NoSuchRole", "Tag", "Read").has_value());

    store.create_role({"TestRole", "", false, 0});
    CHECK_FALSE(store.remove_permission("TestRole", "NoSuchType", "Read").has_value());
    CHECK_FALSE(store.remove_permission("TestRole", "Tag", "NoSuchOp").has_value());
}

TEST_CASE("RbacStore: deleting role cascades permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Cascade", "", false, 0});
    store.set_permission({"Cascade", "Tag", "Read", "allow"});
    store.delete_role("Cascade");

    auto perms = store.get_role_permissions("Cascade");
    CHECK(perms.empty());
}

// ── Principal-role assignments ───────────────────────────────────────────────

TEST_CASE("RbacStore: assign and list principal roles", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Administrator"});
    store.assign_role({"user", "alice", "Viewer"});

    auto roles = store.get_principal_roles("user", "alice");
    REQUIRE(roles.size() == 2);
}

TEST_CASE("RbacStore: duplicate assignment is idempotent", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "bob", "Viewer"});
    store.assign_role({"user", "bob", "Viewer"});

    auto roles = store.get_principal_roles("user", "bob");
    CHECK(roles.size() == 1);
}

TEST_CASE("RbacStore: unassign role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "carol", "Operator"});
    store.unassign_role("user", "carol", "Operator");

    auto roles = store.get_principal_roles("user", "carol");
    CHECK(roles.empty());
}

// ── A2 last-Administrator guard (delivery plan §2) ──────────────────────────

TEST_CASE("RbacStore: unassign_role refuses to remove the fleet's last remaining "
          "Administrator grant",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "onlyadmin");
    REQUIRE(store.assign_role({"user", "onlyadmin", "Administrator"}).has_value());

    auto result = store.unassign_role("user", "onlyadmin", "Administrator");
    REQUIRE_FALSE(result.has_value());
    CHECK(is_rbac_last_admin_refusal(result.error()));

    // The DELETE rolled back — the grant is still there.
    auto roles = store.get_principal_roles("user", "onlyadmin");
    REQUIRE(roles.size() == 1);
    CHECK(roles[0].role_name == "Administrator");
}

TEST_CASE("RbacStore: unassign_role removes an Administrator grant when another "
          "Administrator remains",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "admin1");
    seed_active_user(auth_db, "admin2");
    REQUIRE(store.assign_role({"user", "admin1", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "admin2", "Administrator"}).has_value());

    auto result = store.unassign_role("user", "admin1", "Administrator");
    REQUIRE(result.has_value());
    CHECK(*result); // a row was actually removed
    CHECK(store.get_principal_roles("user", "admin1").empty());
    CHECK(store.get_principal_roles("user", "admin2").size() == 1);
}

// ── Governance BLOCKING #1 (full-pipeline review on 765bc7ec1) — C1: the
// guard counts AUTHENTICATABLE administrators, not bare grant rows. Three
// sub-cases, each proving the "other" Administrator row does NOT save the
// real admin's removal from refusal, because nobody can actually log in as
// it. `remove_user()` is a SOFT delete in this codebase (auth_db.cpp:
// `UPDATE auth.users SET is_active = FALSE ...` — there is no hard-delete
// path anywhere), so (b) deactivated and (c) deleted are the SAME code path
// here; both are kept as distinct cases anyway (matching the finding's own
// three named sub-cases) to document that equivalence explicitly rather
// than assuming a reader already knows it. ────────────────────────────────

TEST_CASE("RbacStore C1(a): last-admin guard refuses when the only 'other' "
          "Administrator row names a NONEXISTENT username (pre-provisioned, "
          "never logged in)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "realadmin");
    REQUIRE(store.assign_role({"user", "realadmin", "Administrator"}).has_value());
    // "ghostadmin" has NO auth.users row at all — A2 explicitly permits
    // pre-provisioning a grant ahead of an account existing.
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());

    auto result = store.unassign_role("user", "realadmin", "Administrator");
    REQUIRE_FALSE(result.has_value());
    CHECK(is_rbac_last_admin_refusal(result.error()));
    CHECK(store.get_principal_roles("user", "realadmin").size() == 1);

    // Negative control: documents the PRE-FIX behavior this test would have
    // observed — a bare grant-row count (ignoring auth.users entirely) sees
    // TWO rows ("realadmin", "ghostadmin") and would have allowed the
    // delete, reaching zero AUTHENTICATABLE administrators. Reproduced here
    // directly against the raw table, independent of unassign_role, so this
    // assertion can never silently start exercising the real (fixed) code
    // path instead of the historical defect shape.
    {
        auto lease = auth_db.pool().acquire();
        REQUIRE(lease);
        auto bare_count = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM rbac_store.principal_roles WHERE role_name = "
            "'Administrator' AND principal_type = 'user'",
            std::vector<std::string>{});
        REQUIRE(bare_count.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(bare_count.get(), 0, 0)) == "2"); // would have allowed it
    }
}

TEST_CASE("RbacStore C1(b): last-admin guard refuses when the only 'other' "
          "Administrator row names a DEACTIVATED account",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "realadmin");
    seed_active_user(auth_db, "deactivatedadmin");
    REQUIRE(store.assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "deactivatedadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("deactivatedadmin").has_value());

    auto result = store.unassign_role("user", "realadmin", "Administrator");
    REQUIRE_FALSE(result.has_value());
    CHECK(is_rbac_last_admin_refusal(result.error()));
    CHECK(store.get_principal_roles("user", "realadmin").size() == 1);
}

TEST_CASE("RbacStore C1(c): last-admin guard refuses when the only 'other' "
          "Administrator row names a DELETED account (this codebase's "
          "remove_user() is a soft-delete — is_active=FALSE, no hard-delete "
          "path exists — so this is mechanically the SAME guard as C1(b), "
          "kept distinct to document that equivalence explicitly)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "realadmin");
    seed_active_user(auth_db, "deletedadmin");
    REQUIRE(store.assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "deletedadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("deletedadmin").has_value());

    auto result = store.unassign_role("user", "realadmin", "Administrator");
    REQUIRE_FALSE(result.has_value());
    CHECK(is_rbac_last_admin_refusal(result.error()));
    CHECK(store.get_principal_roles("user", "realadmin").size() == 1);
}

// Doomgoose external review, PR #4985 (IMPORTANT #1): the guard's post-delete
// refusal previously fired on ANY post-delete zero count, not only when the
// delete ITSELF removed one of the rows the earlier `SELECT ... FOR UPDATE OF
// pr` lock query actually counted. A ghost/deactivated Administrator row is
// never among those counted rows (it fails the `auth.users`/`is_active` JOIN)
// -- so if it is the ONLY Administrator grant left, the active-admin count is
// ALREADY zero before the call, and removing that ghost row cannot be what
// drives the count from >0 to 0. Two sub-cases (never-existed vs.
// deactivated), matching the C1(a)/(b) shape above.
TEST_CASE("RbacStore: unassign_role SUCCEEDS removing a ghost Administrator "
          "grant (no auth.users row at all) that is the ONLY Administrator "
          "row left, instead of spuriously refusing",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    // "ghostadmin" has NO auth.users row — A2 explicitly permits
    // pre-provisioning — and is the ONLY Administrator grant on this store,
    // so the counted active-admin total is ALREADY zero before this call.
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());

    auto result = store.unassign_role("user", "ghostadmin", "Administrator");
    REQUIRE(result.has_value());
    CHECK(*result); // a row was actually removed
    CHECK(store.get_principal_roles("user", "ghostadmin").empty());
}

TEST_CASE("RbacStore: unassign_role SUCCEEDS removing a DEACTIVATED "
          "Administrator grant that is the ONLY Administrator row left, "
          "instead of spuriously refusing",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "deactivatedonly");
    REQUIRE(store.assign_role({"user", "deactivatedonly", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("deactivatedonly").has_value());

    auto result = store.unassign_role("user", "deactivatedonly", "Administrator");
    REQUIRE(result.has_value());
    CHECK(*result); // a row was actually removed
    CHECK(store.get_principal_roles("user", "deactivatedonly").empty());
}

// Doomgoose external review, PR #4985 (IMPORTANT finding #1, TOCTOU): the
// `locked_admin_principal_ids` snapshot above is taken BEFORE the DELETE, and
// the candidate `auth.users` rows are deliberately left unlocked by this guard
// (see the Concurrency note in rbac_admin_authority_owner.cpp) — so a
// principal that is a ghost/deactivated Administrator grant at lock time (and
// therefore excluded from the locked/counted set) can be reactivated by a
// FULLY INDEPENDENT, concurrent transaction (`AuthDB::reactivate_user`) in the
// gap between the lock query and the DELETE. If that reactivated principal is
// the fleet's ONLY real Administrator, the guard must still refuse — this
// reproduces exactly that interleaving and confirms the fix (the fresh
// post-DELETE `auth.users.is_active` re-check) catches it.
//
// Deterministic interleaving: production's own `FOR UPDATE OF pr` lock query
// does NOT lock ghostadmin's row (it's inactive at lock time, so it fails the
// JOIN's `is_active` filter and is never in that query's result set) — so,
// unlike the CHAOS-1/race tests above, there is no natural production lock to
// hang the background thread on here. This test manufactures its own
// synchronization point instead: connection A takes a direct `FOR UPDATE` on
// ghostadmin's own `principal_roles` row (not a production statement, purely
// a test-only control point) BEFORE the background thread starts, which
// blocks that thread's own `DELETE` (targeting the identical row) until
// connection A releases it — giving a guaranteed window in which to commit
// the reactivation from a third, fully independent connection before letting
// the background thread's DELETE (and this fix's fresh re-check) proceed.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard REFUSES when "
          "the ONLY Administrator grant is reactivated by an independent "
          "transaction between the lock query and the DELETE (TOCTOU close, "
          "PR #4985 finding #1)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "ghostadmin");
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());
    // Deactivate — ghostadmin is now the fleet's ONLY Administrator grant, and
    // it is NOT counted (mirrors the "ghost/deactivated" scenario the earlier
    // succeeds-test above covers), so `unassign_role`'s lock query will find
    // zero locked/counted rows.
    REQUIRE(auth_db->remove_user("ghostadmin").has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    // Test-only lock (NOT a production statement — see the header comment
    // above): locks the exact row the background thread's DELETE will target,
    // so that DELETE blocks here regardless of the production lock query's
    // own (empty, since ghostadmin is inactive) result set.
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT principal_id FROM rbac_store.principal_roles WHERE "
                            "principal_type = 'user' AND principal_id = 'ghostadmin' AND "
                            "role_name = 'Administrator' FOR UPDATE",
                            std::vector<std::string>{})
                .ok());

    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::string b_error;
    ScopedJoin unassign_thread{std::thread([&] {
        b_started = true;
        auto res = store.unassign_role("user", "ghostadmin", "Administrator");
        b_ok = res.has_value();
        if (!res)
            b_error = res.error();
        b_done = true;
    }), [&] { lease_a.reset(); }};

    // Prove a real blocked-then-unblocked interleaving (Doomgoose external
    // review, PR #4985 IMPORTANT #6) — separate probe connection, never
    // lease_a itself. See poll_for_blocked_backend_pid's own doc comment.
    REQUIRE(poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid) != 0);
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    // Reactivate ghostadmin from a FULLY INDEPENDENT connection/transaction
    // (AuthDB::reactivate_user acquires its own pool lease and commits
    // immediately) WHILE the background thread's unassign is still blocked
    // between its lock query and its DELETE — the exact race window finding
    // #1 identified.
    REQUIRE(auth_db->reactivate_user("ghostadmin").has_value());

    // Release connection A's hold so the background DELETE can proceed.
    REQUIRE(pg::exec_params(lease_a.get(), "ROLLBACK", std::vector<std::string>{}).ok());

    unassign_thread.join();
    CHECK(b_done.load());
    // Must now be refused: ghostadmin is (as of the reactivation, already
    // committed) the fleet's ONLY real Administrator, and this delete would
    // leave zero.
    CHECK_FALSE(b_ok.load());
    CHECK(is_rbac_last_admin_refusal(b_error));

    // Refused ⇒ rolled back ⇒ the grant survives, and the account is (per the
    // reactivation) active — the fleet still has exactly one real admin.
    CHECK(store.get_principal_roles("user", "ghostadmin").size() == 1);
}

// Doomgoose external review, PR #4985 round 3 (TOCTOU residual window): the test
// above commits the reactivation BEFORE the post-DELETE recheck runs, so it also
// passes against a plain (unlocked) recheck. This one holds the reactivation IN
// FLIGHT across the recheck: connection A updates ghostadmin's own `auth.users`
// row and leaves it uncommitted, so the recheck (`SELECT ... FOR UPDATE`) must
// WAIT on that row lock and then re-read the COMMITTED reactivation. A plain
// SELECT would not wait, would read the still-inactive committed row, and the
// unassign would commit; the poll REQUIRE below is what fails in that case.
//
// The unassign's lock query reads `auth.users` through a JOIN without locking it
// (`FOR UPDATE OF pr`), so it is not blocked by connection A's row lock; nor is
// the DELETE, which targets the `principal_roles` row. The only statement that
// can wait on A is the recheck.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard WAITS for a "
          "reactivation still in flight across the post-DELETE recheck and then "
          "REFUSES (FOR UPDATE; PR #4985 round 3)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "ghostadmin");
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("ghostadmin").has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    // The in-flight reactivation: same effect as AuthDB::reactivate_user's UPDATE,
    // issued on this lease so the test controls exactly when it commits.
    REQUIRE(pg::exec_params(lease_a.get(),
                            "UPDATE auth.users SET is_active = TRUE WHERE username = 'ghostadmin'",
                            std::vector<std::string>{})
                .ok());

    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::string b_error;
    // If a REQUIRE below throws while the worker is blocked, ScopedJoin rolls back
    // lease_a before joining, which releases the row lock the worker waits on, so the
    // failure surfaces immediately instead of after the pool's lock_timeout.
    ScopedJoin unassign_thread{std::thread([&] {
        auto res = store.unassign_role("user", "ghostadmin", "Administrator");
        b_ok = res.has_value();
        if (!res)
            b_error = res.error();
        b_done = true;
    }), [&] { lease_a.reset(); }};

    // The unassign has passed its lock query (ghostadmin's COMMITTED row is still
    // inactive, so it is not counted) and its DELETE, and is now blocked in the
    // recheck on connection A's row lock. Separate probe connection, never lease_a.
    // The location is inferred by elimination: no other statement in the
    // unassign can wait on that one row lock.
    REQUIRE(poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid) != 0);
    CHECK_FALSE(b_done.load());

    REQUIRE(pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok());

    unassign_thread.join();
    CHECK(b_done.load());
    // The recheck re-read the committed reactivation: ghostadmin is now the fleet's
    // only real Administrator and this delete would leave zero.
    CHECK_FALSE(b_ok.load());
    CHECK(is_rbac_last_admin_refusal(b_error));
    // Refused => rolled back => the grant survives.
    CHECK(store.get_principal_roles("user", "ghostadmin").size() == 1);
    // Not asserted here: the two cases the guard does NOT close (an auth.users row
    // created concurrently for a pre-provisioned grant, and deactivation of a
    // surviving Administrator, #4966). Pinning a known hole would have to be
    // inverted when #4966 lands.
}

// Complement of the test above: the in-flight reactivation ROLLS BACK, so the
// recheck re-reads the unchanged inactive row and the removal must go through.
// Guards against over-refusal after the wait.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard WAITS for an "
          "in-flight reactivation that rolls back and then SUCCEEDS "
          "(FOR UPDATE; PR #4985 round 3)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "ghostadmin");
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("ghostadmin").has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "UPDATE auth.users SET is_active = TRUE WHERE username = 'ghostadmin'",
                            std::vector<std::string>{})
                .ok());

    std::atomic<bool> b_done{false};
    std::atomic<bool> b_removed{false};
    std::atomic<bool> b_ok{false};
    ScopedJoin unassign_thread{std::thread([&] {
        auto res = store.unassign_role("user", "ghostadmin", "Administrator");
        b_ok = res.has_value();
        if (res)
            b_removed = *res;
        b_done = true;
    }), [&] { lease_a.reset(); }};

    REQUIRE(poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid) != 0);
    CHECK_FALSE(b_done.load());

    REQUIRE(pg::exec_params(lease_a.get(), "ROLLBACK", std::vector<std::string>{}).ok());

    unassign_thread.join();
    CHECK(b_done.load());
    CHECK(b_ok.load());
    CHECK(b_removed.load());
    CHECK(store.get_principal_roles("user", "ghostadmin").empty());
}

// The reactivation COMMITS during the wait, but another active Administrator
// remains, so the recount is non-zero and the removal must still go through.
// Guards against an implementation that refuses outright whenever the recheck sees
// a reactivation (over-refusal, the safe direction, which no other test catches).
TEST_CASE("RbacStore: unassign_role's guard WAITS for an in-flight reactivation "
          "that commits and then SUCCEEDS when another Administrator remains "
          "(FOR UPDATE; PR #4985 round 3)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "ghostadmin");
    seed_active_user(auth_db, "realadmin");
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "realadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("ghostadmin").has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "UPDATE auth.users SET is_active = TRUE WHERE username = 'ghostadmin'",
                            std::vector<std::string>{})
                .ok());

    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::atomic<bool> b_removed{false};
    ScopedJoin unassign_thread{std::thread([&] {
        auto res = store.unassign_role("user", "ghostadmin", "Administrator");
        b_ok = res.has_value();
        if (res)
            b_removed = *res;
        b_done = true;
    }), [&] { lease_a.reset(); }};

    REQUIRE(poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid) != 0);
    CHECK_FALSE(b_done.load());

    REQUIRE(pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok());

    unassign_thread.join();
    CHECK(b_done.load());
    CHECK(b_ok.load());
    CHECK(b_removed.load());
    CHECK(store.get_principal_roles("user", "ghostadmin").empty());
    CHECK(store.get_principal_roles("user", "realadmin").size() == 1);
}

// The lock-wait bound: when the reactivation stays in flight longer than the
// pool's lock_timeout, the recheck errors, the transaction rolls back (the DELETE
// is undone), and the failure is NOT a last-Administrator refusal (callers map it
// to 503 / an MCP internal error with a retry hint, never to the 409 refusal).
// A second store on a pool with a 300 ms lock_timeout keeps the test fast; the
// call is synchronous (the statement times out on its own), so no thread is needed.
TEST_CASE("RbacStore: unassign_role's recheck lock wait times out as a store "
          "fault and rolls the DELETE back (FOR UPDATE; PR #4985 round 3)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "ghostadmin");
    REQUIRE(store.assign_role({"user", "ghostadmin", "Administrator"}).has_value());
    REQUIRE(auth_db->remove_user("ghostadmin").has_value());

    PgPool short_pool{{.conninfo = auth_db.dsn(), .size = 2, .lock_timeout_ms = 300}};
    REQUIRE(short_pool.valid());
    RbacStore short_store{short_pool};
    REQUIRE(short_store.is_open());
    {
        // Fail fast if `-c lock_timeout` did not reach the session (a DSN carrying
        // `options`, or PGOPTIONS set): the synchronous call below would otherwise
        // wait on a lock held by this same thread.
        auto probe = short_pool.acquire();
        REQUIRE(probe);
        pg::PgResult lt = pg::exec_params(probe.get(), "SELECT current_setting('lock_timeout')",
                                          std::vector<std::string>{});
        REQUIRE(lt.status() == PGRES_TUPLES_OK);
        REQUIRE(std::string(PQgetvalue(lt.get(), 0, 0)) == "300ms");
    }

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    REQUIRE(pg::exec_params(lease_a.get(),
                            "UPDATE auth.users SET is_active = TRUE WHERE username = 'ghostadmin'",
                            std::vector<std::string>{})
                .ok());

    auto res = short_store.unassign_role("user", "ghostadmin", "Administrator");
    REQUIRE_FALSE(res.has_value());
    CHECK_FALSE(is_rbac_last_admin_refusal(res.error()));
    // Pin the cause: Postgres reports "canceling statement due to lock timeout".
    CHECK(res.error().find("lock timeout") != std::string::npos);

    REQUIRE(pg::exec_params(lease_a.get(), "ROLLBACK", std::vector<std::string>{}).ok());
    // The timed-out transaction rolled back: the grant is still there.
    CHECK(store.get_principal_roles("user", "ghostadmin").size() == 1);
}

// MINOR (Doomgoose external review, PR #4985): the idempotent no-op shape a
// regression here would actually spuriously refuse — unassigning
// "Administrator" from a principal who never held it at all, on a store with
// ZERO real (counted) admins. `removed` must be false and the call must
// still succeed; a regression that fires the recount/refuse logic
// unconditionally (ignoring `removed`) would wrongly reject this.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard is a true "
          "no-op (not a refusal) for a principal who never held the role, "
          "on a store with zero real administrators",
          "[rbac_store][pg]") {
    // RBAC_STORE_WITH_AUTH, not plain RBAC_STORE: role_name=="Administrator"
    // always runs the guard's `JOIN auth.users`, which needs the `auth`
    // schema present in this database — the shared "rbacstore" PgTestTemplate
    // RBAC_STORE clones does NOT carry it (see RBAC_STORE_WITH_AUTH's own doc
    // comment above).
    RBAC_STORE_WITH_AUTH(store, auth_db);
    REQUIRE(store.get_role_members("Administrator").empty());

    auto result = store.unassign_role("user", "neverhadit", "Administrator");
    REQUIRE(result.has_value());
    CHECK_FALSE(*result); // no row was removed — genuine no-op
}

TEST_CASE("RbacStore: unassign_role's last-Administrator guard is scoped to the "
          "Administrator role only — a Viewer/Operator unassign on a ZERO-admin "
          "store still succeeds (fresh-install bootstrap shape, A2)",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    // Fresh RBAC_STORE holds ZERO Administrator principal_roles rows — this is
    // the real fresh-install shape (A2 is the bootstrap step). Assigning and
    // then removing a non-Administrator role must be a pure, unconditional
    // DELETE, exactly as it was before this guard existed — matching every
    // existing production caller (both engine-only) of unassign_role.
    REQUIRE(store.get_role_members("Administrator").empty());
    REQUIRE(store.assign_role({"user", "vera", "Viewer"}).has_value());

    auto result = store.unassign_role("user", "vera", "Viewer");
    REQUIRE(result.has_value());
    CHECK(store.get_principal_roles("user", "vera").empty());
}

TEST_CASE("RbacStore: unassign_role's last-Administrator guard IGNORES a group-held "
          "Administrator grant — it never counts as a surviving administrator "
          "(adversarial-review PR1/A2 finding: the guard must match "
          "is_rbac_administrator's gate, which never resolves group membership)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "soleadmin");
    // A group-held Administrator row (however it got there today — no
    // production caller writes one — the guard is a property of
    // unassign_role, shared by any future caller) must NOT be treated as a
    // surviving administrator: rbac_admin_predicate.hpp's
    // is_rbac_administrator gate can never authenticate as one (principal_
    // type="user" only), so a group row "surviving" would be a false sense
    // of safety — the fleet would have zero GATE-PASSING administrators.
    REQUIRE(store.assign_role({"group", "admins-group", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "soleadmin", "Administrator"}).has_value());

    // Removing the ONLY user Administrator must be refused even though a
    // group row is still present — the guard counts principal_type='user'
    // ONLY now, ignoring the group row entirely.
    auto result = store.unassign_role("user", "soleadmin", "Administrator");
    REQUIRE_FALSE(result.has_value());
    CHECK(is_rbac_last_admin_refusal(result.error()));
    CHECK(store.get_principal_roles("user", "soleadmin").size() == 1);

    // The group row is untouched by this refusal (unassign_role never
    // touched it — different principal_type).
    CHECK(store.get_principal_roles("group", "admins-group").size() == 1);
}

// Adversarial-review PR1/A2 finding #2's own regression test: seed a group
// Administrator row PLUS two real user Administrators, then drive two
// CONCURRENT REAL RbacStore::unassign_role calls (std::thread, not
// hand-copied SQL on a puppeteered connection — unlike the deterministic
// race test below, this one only needs to prove the invariant holds under
// genuine concurrency, not exercise one specific interleaving) each
// removing one of the two user rows. Exactly one must succeed and one must
// be refused — the group row must never be counted as a reason both can
// succeed.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard under real "
          "concurrency still refuses to remove the last USER administrator "
          "even with a group-held Administrator row present",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "concadmin1");
    seed_active_user(auth_db, "concadmin2");
    REQUIRE(store.assign_role({"group", "admins-group", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "concadmin1", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "concadmin2", "Administrator"}).has_value());

    std::atomic<bool> ok1{false}, ok2{false};
    std::atomic<bool> done1{false}, done2{false};
    // ScopedJoin (above) joins on scope exit, so a live std::thread is never left
    // joinable when a REQUIRE throws (std::terminate); std::jthread would do the same
    // but is not available on Apple Clang's libc++.
    ScopedJoin t1{std::thread([&] {
        ok1 = store.unassign_role("user", "concadmin1", "Administrator").has_value();
        done1 = true;
    })};
    ScopedJoin t2{std::thread([&] {
        ok2 = store.unassign_role("user", "concadmin2", "Administrator").has_value();
        done2 = true;
    })};
    t1.join();
    t2.join();
    CHECK(done1.load());
    CHECK(done2.load());

    // Exactly one succeeded, one was refused — never both (which would mean
    // the group row was silently counted as a survivor) and never neither.
    CHECK(ok1.load() != ok2.load());

    // Exactly one real user Administrator remains — never zero.
    const std::size_t user_admins_left = store.get_principal_roles("user", "concadmin1").size() +
                                         store.get_principal_roles("user", "concadmin2").size();
    CHECK(user_admins_left == 1);
    // The group row is unaffected either way.
    CHECK(store.get_principal_roles("group", "admins-group").size() == 1);
}

// chaos-injector-style: two concurrent unassigns racing to remove the last two
// Administrator grants must NOT both succeed (which would leave zero admins).
// Deterministic interleaving via a manually-held FOR UPDATE lock on connection
// A (mirrors the CHAOS-1 test above) rather than a hope-for-the-best race:
// connection A holds the SAME row lock unassign_role's own transaction takes,
// blocking a background thread's REAL store.unassign_role call; A then
// performs the exact DELETE unassign_role would (removing admin1, leaving
// admin2) and commits, unblocking the background thread's transaction, which
// must then observe exactly ONE remaining Administrator row (admin2's) before
// ITS OWN delete and refuse to remove it.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard serializes two "
          "concurrent unassigns of the last two Administrator grants — exactly "
          "one succeeds, never zero remain",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "raceadmin1");
    seed_active_user(auth_db, "raceadmin2");
    REQUIRE(store.assign_role({"user", "raceadmin1", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "raceadmin2", "Administrator"}).has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    // Mirrors the production lock statement exactly (rbac_admin_authority_owner.cpp) —
    // governance BLOCKING #1 re-verification: the JOIN must not weaken this
    // deterministic interleaving proof.
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pr.principal_id FROM rbac_store.principal_roles pr "
                            "JOIN auth.users u ON u.username = pr.principal_id "
                            "WHERE pr.role_name = 'Administrator' AND pr.principal_type = "
                            "'user' AND u.is_active "
                            "FOR UPDATE OF pr",
                            std::vector<std::string>{})
                .ok());

    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::string b_error;
    // ScopedJoin (above) joins on scope exit, so a REQUIRE failure anywhere below
    // (before the explicit .join() call further down) can never leave this thread
    // live-and-unguarded (governance NICE finding); it also rolls back lease_a first.
    // Runtime bound, stated explicitly (governance SHOULD #11 / NICE):
    // `unassign_thread` blocks on connection A's row lock for at most
    // PgPool's default `lock_timeout_ms` (10000ms, pg_pool.hpp:94), never
    // indefinitely, so this test's worst case is bounded even if connection
    // A's own COMMIT below never ran (e.g. a REQUIRE above it failed).
    ScopedJoin unassign_thread{std::thread([&] {
        b_started = true;
        auto res = store.unassign_role("user", "raceadmin2", "Administrator");
        b_ok = res.has_value();
        if (!res)
            b_error = res.error();
        b_done = true;
    }), [&] { lease_a.reset(); }};

    // Prove a real blocked-then-unblocked interleaving, not a lucky race:
    // poll pg_stat_activity for the background thread's own backend
    // registering a genuine Lock wait (Doomgoose external review, PR #4985
    // IMPORTANT #6). MUST use a separate probe connection, never lease_a
    // itself — see poll_for_blocked_backend_pid's own doc comment.
    REQUIRE(poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid) != 0);
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    // Connection A now performs the delete + count check unassign_role's own
    // transaction would for raceadmin1, and commits — mirroring the real
    // production statements exactly.
    REQUIRE(pg::exec_params(lease_a.get(),
                            "DELETE FROM rbac_store.principal_roles WHERE principal_type = "
                            "'user' AND principal_id = 'raceadmin1' AND role_name = "
                            "'Administrator'",
                            std::vector<std::string>{})
                .ok());
    REQUIRE(pg::exec_params(lease_a.get(), "COMMIT", std::vector<std::string>{}).ok());
    lease_a.reset();

    unassign_thread.join();
    CHECK(b_done.load());
    // The background thread's own FOR UPDATE only sees raceadmin2's row by the
    // time it unblocks (raceadmin1's is already gone) — removing it would
    // leave zero, so it must be refused.
    CHECK_FALSE(b_ok.load());
    CHECK(is_rbac_last_admin_refusal(b_error));

    // Exactly one Administrator remains — never zero.
    CHECK(store.get_principal_roles("user", "raceadmin1").empty());
    CHECK(store.get_principal_roles("user", "raceadmin2").size() == 1);
}

// C2 (governance BLOCKING #1's required regression test, full-pipeline
// review on 765bc7ec1): a connection lost MID-TRANSACTION, while blocked on
// the guard's own `FOR UPDATE OF pr` lock, must roll back cleanly — no
// partial delete, no generation bump — and must not wedge the pool.
// Precedent for the pg_terminate_backend idiom: test_pg_pool.cpp's "PgPool
// discards a connection lost mid-use", test_api_token_store.cpp,
// test_kek_op_lock_holder.cpp. Reuses the deterministic-race scaffold above
// (connection A holds the lock; the background thread blocks on it) but
// instead of A committing cleanly, A TERMINATES the blocked backend instead.
TEST_CASE("RbacStore: unassign_role's last-Administrator guard rolls back "
          "cleanly and never bumps the generation when its connection is "
          "lost mid-transaction (governance BLOCKING #1 C2)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    seed_active_user(auth_db, "killadmin1");
    seed_active_user(auth_db, "killadmin2");
    REQUIRE(store.assign_role({"user", "killadmin1", "Administrator"}).has_value());
    REQUIRE(store.assign_role({"user", "killadmin2", "Administrator"}).has_value());

    auto lease_a = auth_db.pool().acquire();
    REQUIRE(lease_a);
    const int lease_a_pid = PQbackendPID(lease_a.get());
    REQUIRE(lease_a_pid > 0);
    REQUIRE(pg::exec_params(lease_a.get(), "BEGIN", std::vector<std::string>{}).ok());
    // Mirrors the production lock statement exactly (rbac_admin_authority_owner.cpp) — locks
    // BOTH candidate rows, so the background unassign below has no
    // unlocked row left to race past.
    REQUIRE(pg::exec_params(lease_a.get(),
                            "SELECT pr.principal_id FROM rbac_store.principal_roles pr "
                            "JOIN auth.users u ON u.username = pr.principal_id "
                            "WHERE pr.role_name = 'Administrator' AND pr.principal_type = "
                            "'user' AND u.is_active "
                            "FOR UPDATE OF pr",
                            std::vector<std::string>{})
                .ok());

    // Durable write_generation baseline, read before the background call
    // ever starts.
    pg::PgResult gen_before_res{
        PQexec(lease_a.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key = "
                              "'write_generation'")};
    REQUIRE(gen_before_res.ok());
    REQUIRE(PQntuples(gen_before_res.get()) == 1);
    const std::string gen_before = PQgetvalue(gen_before_res.get(), 0, 0);

    std::atomic<bool> b_started{false};
    std::atomic<bool> b_done{false};
    std::atomic<bool> b_ok{false};
    std::string b_error;
    ScopedJoin unassign_thread{std::thread([&] {
        b_started = true;
        auto res = store.unassign_role("user", "killadmin2", "Administrator");
        b_ok = res.has_value();
        if (!res)
            b_error = res.error();
        b_done = true;
    }), [&] { lease_a.reset(); }};

    // Find the background thread's own backend, blocked on connection A's
    // lock — never assume which pool slot it landed on. Poll pg_stat_activity
    // for a genuine Lock wait rather than trust a fixed sleep duration
    // (Doomgoose external review, PR #4985 IMPORTANT #6). MUST use a separate
    // probe connection, never lease_a itself — see
    // poll_for_blocked_backend_pid's own doc comment.
    const int blocked_pid = poll_for_blocked_backend_pid(auth_db.dsn(), lease_a_pid);
    REQUIRE(blocked_pid > 0);
    CHECK(b_started.load());
    CHECK_FALSE(b_done.load());

    // Sever it — the F1 ledger's "connection loss mid-txn" error path,
    // fired while the transaction is genuinely mid-flight (blocked on the
    // row lock), not merely idle.
    pg::PgResult kill{pg::exec_params(lease_a.get(),
                                      "SELECT pg_terminate_backend($1)",
                                      std::vector<std::string>{std::to_string(blocked_pid)})};
    REQUIRE(kill.ok());

    // Release connection A's lock so the (now-dying) background transaction
    // isn't also waiting on anything else; its own connection loss is what
    // ends it, not this rollback.
    REQUIRE(pg::exec_params(lease_a.get(), "ROLLBACK", std::vector<std::string>{}).ok());

    unassign_thread.join();
    CHECK(b_done.load());
    // The killed transaction must report failure — never a false success on
    // a connection that died before COMMIT.
    CHECK_FALSE(b_ok.load());
    CHECK_FALSE(b_error.empty());

    // No partial delete: both grants survive, untouched by the aborted txn.
    CHECK(store.get_principal_roles("user", "killadmin1").size() == 1);
    CHECK(store.get_principal_roles("user", "killadmin2").size() == 1);

    // The generation counter must NOT have bumped — a killed transaction
    // rolls back in Postgres itself (no COMMIT ever reached), so
    // bump_generation_in_txn's own write is discarded along with everything
    // else in that transaction.
    pg::PgResult gen_after_res{
        PQexec(lease_a.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key = "
                              "'write_generation'")};
    REQUIRE(gen_after_res.ok());
    REQUIRE(PQntuples(gen_after_res.get()) == 1);
    CHECK(std::string(PQgetvalue(gen_after_res.get(), 0, 0)) == gen_before);

    // Pool recovery: the dead connection must have been discarded (never
    // recycled into the idle pool — PgPool::release's health check), and a
    // fresh call through the SAME store must still work normally.
    lease_a.reset();
    REQUIRE(store.assign_role({"user", "postkill-canary", "Viewer"}).has_value());
    CHECK(store.get_principal_roles("user", "postkill-canary").size() == 1);
}

TEST_CASE("RbacStore: get role members", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "bob", "Operator"});

    auto members = store.get_role_members("Operator");
    REQUIRE(members.size() == 2);
}

TEST_CASE("RbacStore: deleting role cascades assignments", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"Temp", "", false, 0});
    store.assign_role({"user", "alice", "Temp"});
    store.delete_role("Temp");

    auto roles = store.get_principal_roles("user", "alice");
    CHECK(roles.empty());
}

// ── check_permission ─────────────────────────────────────────────────────────

TEST_CASE("RbacStore: check_permission with direct role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Administrator"});

    CHECK(store.check_permission("alice", "Infrastructure", "Write"));
    CHECK(store.check_permission("alice", "Execution", "Execute"));
    CHECK(store.check_permission("alice", "AuditLog", "Read"));
}

TEST_CASE("RbacStore: check_permission denied when no role", "[rbac_store][pg]") {
    RBAC_STORE(store);
    CHECK_FALSE(store.check_permission("nobody", "Execution", "Execute"));
}

TEST_CASE("RbacStore: Viewer cannot write", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "bob", "Viewer"});

    CHECK(store.check_permission("bob", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("bob", "Execution", "Execute"));
    CHECK_FALSE(store.check_permission("bob", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("bob", "Infrastructure", "Read"));
}

TEST_CASE("RbacStore: check_permission via group membership", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"soc-team", "Security Operations", "local", "", 0});
    store.add_group_member("soc-team", "carol");
    store.assign_role({"group", "soc-team", "Operator"});

    CHECK(store.check_permission("carol", "Execution", "Execute"));
    CHECK(store.check_permission("carol", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("carol", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: deny overrides allow", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"NoPatch", "No patching allowed", false, 0});
    store.set_permission({"NoPatch", "Execution", "Execute", "deny"});

    // alice has Operator (allow Execute) AND NoPatch (deny Execute)
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "alice", "NoPatch"});

    CHECK_FALSE(store.check_permission("alice", "Execution", "Execute"));
    // But read still works
    CHECK(store.check_permission("alice", "Execution", "Read"));
}

TEST_CASE("RbacStore: multiple roles combine permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_role({"AuditReader", "Read audit logs", false, 0});
    store.set_permission({"AuditReader", "AuditLog", "Read", "allow"});

    store.assign_role({"user", "dave", "Viewer"});
    store.assign_role({"user", "dave", "AuditReader"});

    // Viewer gives Read on most types; AuditReader adds AuditLog Read
    CHECK(store.check_permission("dave", "AuditLog", "Read"));
    CHECK(store.check_permission("dave", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("dave", "Execution", "Execute"));
}

// ── Effective permissions ────────────────────────────────────────────────────

TEST_CASE("RbacStore: get_effective_permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.assign_role({"user", "alice", "Viewer"});

    auto perms = store.get_effective_permissions("alice");
    CHECK_FALSE(perms.empty());
    for (auto& p : perms)
        CHECK(p.effect == "allow");
}

TEST_CASE("RbacStore: effective permissions empty for unassigned user", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto perms = store.get_effective_permissions("nobody");
    CHECK(perms.empty());
}

// ── Group CRUD ───────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create and list groups", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"dev-team", "Development", "local", "", 0});
    store.create_group({"ops-team", "Operations", "local", "", 0});

    auto groups = store.list_groups();
    REQUIRE(groups.size() == 2);
}

TEST_CASE("RbacStore: group membership", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"team", "Test team", "local", "", 0});
    store.add_group_member("team", "alice");
    store.add_group_member("team", "bob");

    auto members = store.get_group_members("team");
    REQUIRE(members.size() == 2);

    store.remove_group_member("team", "bob");
    members = store.get_group_members("team");
    CHECK(members.size() == 1);
    CHECK(members[0] == "alice");
}

TEST_CASE("RbacStore: deleting group cascades members", "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"temp", "", "local", "", 0});
    store.add_group_member("temp", "alice");
    store.delete_group("temp");

    auto members = store.get_group_members("temp");
    CHECK(members.empty());
}

// ── find_local_groups_with_prefix (T8 namespace-collision preflight) ───────

TEST_CASE("RbacStore: find_local_groups_with_prefix matches local-source groups by prefix",
          "[rbac_store][pg]") {
    // create_group() rejects a new local group named inside the reserved
    // 'engine:' prefix, so a colliding row can only exist as one that predates
    // that guard — seed it directly (bypassing the app layer), the same way a
    // real pre-upgrade deployment's data would appear.
    RBAC_STORE(store);
    seed_group_raw(rbac_pool_fx_, "engine:foo", "", "local", "");
    seed_group_raw(rbac_pool_fx_, "engine:bar", "", "local", "");
    seed_group_raw(rbac_pool_fx_, "other", "", "local", "");
    // An IdP-sourced group asserting the same prefixed name is disambiguated
    // by principal_type at the resolution site, not this scan (§3.3) — must
    // not appear in the result.
    REQUIRE(store.create_group({"engine:idp-sourced", "IdP group", "entra", "ext-1", 0})
               .has_value());

    auto result = store.find_local_groups_with_prefix("engine:");
    REQUIRE(result.has_value());
    CHECK(result->size() == 2);
}

TEST_CASE("RbacStore: find_local_groups_with_prefix returns empty engaged optional "
          "when nothing matches",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    store.create_group({"other", "", "local", "", 0});

    auto result = store.find_local_groups_with_prefix("engine:");
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("RbacStore: find_local_groups_with_prefix returns nullopt (not an engaged "
          "empty optional) on a closed/load-failed store",
          "[rbac_store][visibility][pg]") {
    // Mirrors the load-failed construction used by the
    // rbac_enforcement_in_effect fail-closed tests above: an unroutable DSN
    // leaves the store unopened. The bug this guards (Blocker 2 / PR #2202
    // review): the T8 preflight in server.cpp treats nullopt as "scan failed,
    // fail closed" and an engaged empty vector as "scan completed, nothing
    // colliding" — an unopened store must return the former, not silently
    // report a clean scan.
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
                .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());

    auto result = broken.find_local_groups_with_prefix("engine:");
    CHECK_FALSE(result.has_value());
}

// ── IdP membership reconciliation (#1832) ───────────────────────────────────

TEST_CASE("RbacStore: namespaced_group_name", "[rbac_store][pg]") {
    CHECK(namespaced_group_name("entra", "abc-123") == "entra:abc-123");
    CHECK(namespaced_group_name("saml", "g1") == "saml:g1");
    // 'local' is NOT namespaced.
    CHECK(namespaced_group_name("local", "raw-name") == "raw-name");
}

TEST_CASE("RbacStore: reconcile_idp_memberships namespacing prevents confused deputy",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    // A LOCAL group named "admins" already carries a role.
    store.create_group({"admins", "Local admins", "local", "", 0});
    REQUIRE(store.assign_role({"group", "admins", "Operator"}).has_value());

    // The IdP asserts a group with the SAME raw id "admins" for carol.
    auto reconciled = store.reconcile_idp_memberships("carol", "entra", {{"admins", "Admins"}});
    REQUIRE(reconciled.has_value());

    // carol must NOT inherit the local group's role via the same-named IdP
    // group — she landed in "entra:admins", a distinct row with no role
    // assignment of its own yet.
    CHECK_FALSE(store.check_permission("carol", "Execution", "Execute"));

    // The local group's membership is never touched by reconcile.
    auto local_members = store.get_group_members("admins");
    CHECK(local_members.empty());

    // Assigning the role to the NAMESPACED group (the correct, explicit
    // grant an operator would make) is what it takes for carol to get it —
    // proving namespacing, not raw-name collision, decides the outcome.
    REQUIRE(store.assign_role({"group", "entra:admins", "Operator"}).has_value());
    CHECK(store.check_permission("carol", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships add/remove diff", "[rbac_store][pg]") {
    RBAC_STORE(store);

    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}, {"B", "B"}})
                .has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"dave"});

    // A separately-added LOCAL membership must survive every reconcile.
    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "dave");

    // Re-login only asserts A now — B must be dropped.
    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}}).has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B").empty());
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"dave"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships empty asserted removes only that source",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());
    REQUIRE(store.reconcile_idp_memberships("erin", "saml", {{"S1", "S1"}}).has_value());
    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");

    // Next SSO login asserts NO groups at all — full deprovisioning.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    CHECK(store.get_group_members("entra:A").empty());
    // Untouched: a different source, and a local group.
    CHECK(store.get_group_members("saml:S1") == std::vector<std::string>{"erin"});
    CHECK(store.get_group_members("local-crew") == std::vector<std::string>{"erin"});
}

// qa-S1: the row-presence assertions above prove the DELETE didn't touch the
// local group's *membership table row*, but the invariant that actually
// matters is the permission it grants. Attach a role to the LOCAL group and
// prove check_permission is bit-for-bit unchanged before and after an
// empty-asserted (full-deprovisioning) reconcile — this is what would catch
// a future regression that widens the stale-membership DELETE's scoping
// (e.g. a refactor that drops the `group_name IN (SELECT name FROM groups
// WHERE source = ?)` clause) even if row-presence checks were accidentally
// preserved.
TEST_CASE("RbacStore: empty-asserted reconcile cannot strip a local role grant",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");
    REQUIRE(store.assign_role({"group", "local-crew", "Operator"}).has_value());

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());

    // Baseline: erin holds Operator permissions via the local group.
    REQUIRE(store.check_permission("erin", "Execution", "Execute"));
    REQUIRE(store.check_permission("erin", "Tag", "Write"));
    REQUIRE_FALSE(store.check_permission("erin", "Infrastructure", "Write"));

    // Full deprovisioning of the 'entra' source — asserts NO groups at all.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    // The local role grant must be bit-for-bit unchanged.
    CHECK(store.check_permission("erin", "Execution", "Execute"));
    CHECK(store.check_permission("erin", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("erin", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships enforces the group-count cap", "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin + 1);
    for (size_t i = 0; i <= RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank", "entra", asserted);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == "group_count_exceeded");

    // No mutation on rejection.
    CHECK(store.list_groups().empty());
    CHECK(store.get_group_members("entra:g0").empty());
}

// qa-S3: exactly the cap boundary succeeds — only `> kMaxIdpGroupsPerLogin`
// is rejected, not `==`.
TEST_CASE("RbacStore: reconcile_idp_memberships accepts exactly the group-count cap",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin);
    for (size_t i = 0; i < RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank2", "entra", asserted);
    REQUIRE(result.has_value());
    CHECK(result->added == RbacStore::kMaxIdpGroupsPerLogin);
    CHECK(store.get_group_members("entra:g0") == std::vector<std::string>{"frank2"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships is idempotent", "[rbac_store][pg]") {
    RBAC_STORE(store);

    std::vector<std::pair<std::string, std::string>> asserted = {{"A", "A"}, {"B", "B"}};
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());

    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"gina"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"gina"});
    CHECK(store.list_groups().size() == 2);
}

// comp-S2/cons-S3: the {added, removed} counts a caller uses to decide
// whether to write a provisioning audit row.
TEST_CASE("RbacStore: reconcile_idp_memberships reports added/removed counts",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto first = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(first.has_value());
    CHECK(first->added == 2);
    CHECK(first->removed == 0);

    // No-op re-login: same asserted set, nothing added or removed.
    auto noop = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(noop.has_value());
    CHECK(noop->added == 0);
    CHECK(noop->removed == 0);

    // Drop B, add C: one added, one removed.
    auto diff = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"C", "C"}});
    REQUIRE(diff.has_value());
    CHECK(diff->added == 1);
    CHECK(diff->removed == 1);
}

// UP-6: reconcile_idp_memberships must never accept "local" (or an empty
// string) as `source` — the stale-membership DELETE it runs is scoped to
// `groups.source = ?` and is only safe for an IdP source. A miswired call
// with "local" would mass-delete local group memberships fleet-wide.
TEST_CASE("RbacStore: reconcile_idp_memberships rejects source=='local'", "[rbac_store][pg]") {
    RBAC_STORE(store);

    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "ivan");
    REQUIRE(store.assign_role({"group", "crew", "Operator"}).has_value());

    auto result = store.reconcile_idp_memberships("ivan", "local", {{"crew", "crew"}});
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(result.error().empty());

    // No mutation: the local membership and its role grant survive.
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"ivan"});
    CHECK(store.check_permission("ivan", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships rejects an empty source", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result = store.reconcile_idp_memberships("ivan", "", {{"g", "g"}});
    REQUIRE_FALSE(result.has_value());
}

// F3 (Hermes pass-2 HIGH H2): reject any `source` outside the recognized IdP
// allowlist, not just "local"/empty. Without this, a caller passing
// source="engine" (or any other unrecognized string) could mint
// `engine:`-prefixed "IdP" groups via this path — it never checks
// has_reserved_idp_prefix or the create_group collision scan, since it's a
// raw upsert into `groups`, not a call through create_group.
TEST_CASE("RbacStore: reconcile_idp_memberships rejects an unrecognized source (e.g. 'engine')",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto result =
        store.reconcile_idp_memberships("ivan", "engine", {{"vuln", "engine:vuln"}});
    REQUIRE_FALSE(result.has_value());
    // No mutation on rejection — the rejected 'source' never gets a chance to
    // mint any group row (reserved 'engine:' namespace or otherwise).
    CHECK(store.list_groups().empty());

    // Also reject an arbitrary unrecognized string, not just the specific
    // "engine" probe above.
    auto result2 = store.reconcile_idp_memberships("ivan", "totally-made-up", {{"g", "g"}});
    REQUIRE_FALSE(result2.has_value());
}

// sec-L1: a group row that pre-exists with a DIFFERENT source than this
// reconcile call (e.g. a local group literally named `entra:x`, created
// before the create_group reserved-prefix guard existed, or by direct DB
// manipulation) must never be joined — that would leak whatever roles are
// granted to the pre-existing group to the IdP-authenticated user.
TEST_CASE("RbacStore: reconcile_idp_memberships does not join a pre-existing "
         "differently-sourced group",
         "[rbac_store][pg]") {
    // The `create_group` reserved-prefix guard means a source='local' create
    // named "entra:x" can no longer be made through the public API — which
    // is exactly the point of this scenario: a row like this can only exist
    // as a LEGACY artifact from before the guard shipped (or direct DB
    // manipulation). Seed it by bypassing the app layer, the same way a real
    // pre-upgrade deployment's data would.
    RBAC_STORE(store);
    seed_group_raw(rbac_pool_fx_, "entra:x", "Local admins", "local", "");

    REQUIRE(store.assign_role({"group", "entra:x", "Administrator"}).has_value());

    auto reconciled = store.reconcile_idp_memberships("judy", "entra", {{"x", "x"}});
    REQUIRE(reconciled.has_value());
    CHECK(reconciled->added == 0); // the join was skipped, not counted as added

    // judy must NOT be a member of the pre-existing local group, and must
    // NOT inherit its Administrator role.
    CHECK(store.get_group_members("entra:x").empty());
    CHECK_FALSE(store.check_permission("judy", "Infrastructure", "Write"));
}

// UP-9: an asserted entry with a blank/whitespace-only external_id must be
// skipped, never turned into a garbage `entra:` / `entra:   ` group.
TEST_CASE("RbacStore: reconcile_idp_memberships skips blank external_id", "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto reconciled =
        store.reconcile_idp_memberships("karen", "entra", {{"", "Empty"}, {"   ", "Blank"},
                                                            {"real-id", "Real"}});
    REQUIRE(reconciled.has_value());
    CHECK(reconciled->added == 1);

    CHECK(store.get_group_members("entra:real-id") == std::vector<std::string>{"karen"});
    CHECK(store.get_group_members("entra:").empty());
    // No group was created for the blank/whitespace entries.
    auto groups = store.list_groups();
    CHECK(groups.size() == 1);
    CHECK(groups[0].name == "entra:real-id");
}

TEST_CASE("RbacStore: create_group rejects a local group with a reserved IdP prefix",
         "[rbac_store][pg]") {
    RBAC_STORE(store);

    auto local_collision = store.create_group({"entra:x", "", "local", "", 0});
    REQUIRE_FALSE(local_collision.has_value());

    // Every reserved prefix is covered.
    CHECK_FALSE(store.create_group({"saml:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"ad:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"local:x", "", "local", "", 0}).has_value());

    // An IdP-sourced create of the SAME name is exempt from the guard.
    auto idp_create = store.create_group({"entra:x", "", "entra", "x", 0});
    CHECK(idp_create.has_value());

    // A local group whose name merely CONTAINS (not starts with) a reserved
    // token is fine — only the leading `prefix:` is reserved.
    CHECK(store.create_group({"my-entra:team", "", "local", "", 0}).has_value());
}

// ── ITServiceOwner role ──────────────────────────────────────────────────────

TEST_CASE("RbacStore: ITServiceOwner role seeded with correct permissions", "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto role = store.get_role("ITServiceOwner");
    REQUIRE(role.has_value());
    CHECK(role->is_system);
    CHECK(role->description.find("IT Service") != std::string::npos);

    auto perms = store.get_role_permissions("ITServiceOwner");
    // 18 types * 5 CRUD ops = 90 permissions, plus the targeted Push grant on
    // GuaranteedState (= 91), plus a single Workflow:Read grant (#4030/#4032,
    // NOT via the CRUD loop — the issue's prerequisite scopes this fix to
    // granting Read only) = 92, plus the targeted Decommission:Delete grant
    // (Wave 7 PR7.2 — the promoted erasure securable; ITSO could decommission
    // under the old SoftwareLicensing∧Inventory∧GuaranteedState:Delete
    // conjunction and still can) = 93 permissions total. Push, the Workflow
    // grant, and the Decommission grant are deliberately NOT cross-seeded on
    // other securables — see the rationale in
    // rbac_store.cpp seed_defaults(). (18th type: SoftwareLicensing, ADR-0024 —
    // ITServiceOwner full CRUD per the D-9 matrix.)
    CHECK(perms.size() == 93);
    size_t push_count = 0;
    size_t decommission_count = 0;
    for (auto& p : perms) {
        CHECK(p.effect == "allow");
        // Should not include UserManagement, Security, ApiToken
        CHECK(p.securable_type != "UserManagement");
        CHECK(p.securable_type != "Security");
        CHECK(p.securable_type != "ApiToken");
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
        if (p.securable_type == "Decommission") {
            ++decommission_count;
            CHECK(p.operation == "Delete");
        }
    }
    CHECK(push_count == 1);
    CHECK(decommission_count == 1);
}

// Adversarial-review finding (PR7.2a round 1, Blocker/Should-fix): an operator
// who had revoked one of the OLD three conjunct grants (SoftwareLicensing,
// Inventory, or GuaranteedState Delete) specifically to strip ITServiceOwner's
// decommission ability must not silently regain it the moment the Decommission
// securable is seeded — seed_defaults() now carries a prior revocation of any
// of the three old grants forward onto Decommission:Delete before granting it.
TEST_CASE("RbacStore: a decommission-ability revocation via an old conjunct grant "
          "is preserved across the Decommission securable migration",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    // Simulate the pre-migration operator action: revoke ONE of the three old
    // conjunct grants specifically to strip decommission ability. This is the
    // exact real-world action the finding describes.
    auto removed = store.remove_permission("ITServiceOwner", "SoftwareLicensing", "Delete");
    REQUIRE(removed.has_value());
    REQUIRE_FALSE(store.check_role_has_permission("ITServiceOwner", "SoftwareLicensing", "Delete"));
    // The old conjunct grant's sibling ability was never seeded on Decommission
    // by remove_permission() itself — only seed_defaults() carries it forward.
    REQUIRE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    // A genuine replica boot: a second RbacStore construction against the SAME
    // pool re-runs the REAL (production) seed_defaults()/grant() code path,
    // not a hand-copy of its SQL.
    RbacStore reopened{rbac_pool_fx_};
    REQUIRE(reopened.is_open());

    CHECK_FALSE(reopened.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
    // The other two old conjunct grants (never revoked) should be untouched.
    CHECK(reopened.check_role_has_permission("ITServiceOwner", "Inventory", "Delete"));
    CHECK(reopened.check_role_has_permission("ITServiceOwner", "GuaranteedState", "Delete"));
}

// Governance round 5 (Blocker 1): the carry-forward marker+DELETE pair above
// must fire ONCE, at the moment the marker is first created — not on every
// boot. Prior code re-ran the unconditional DELETE on every seed_defaults()
// call gated only on "does the marker exist" (which is permanent), so an
// operator's later EXPLICIT re-grant of Decommission:Delete via
// set_permission() (which never touches revoked_seed_defaults) was silently
// wiped out again on the very next restart. Sequence under test: revoke an
// old conjunct grant -> first reopen carries the marker forward and deletes
// the seeded Decommission:Delete row (matches the existing preservation test
// above) -> operator explicitly RE-GRANTS Decommission:Delete -> second
// reopen must NOT delete it again.
TEST_CASE("RbacStore: an operator's explicit re-grant of Decommission:Delete survives "
          "a later seed_defaults() reboot",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    // Pre-migration operator action: revoke one of the three old conjunct
    // grants specifically to strip decommission ability.
    auto removed = store.remove_permission("ITServiceOwner", "SoftwareLicensing", "Delete");
    REQUIRE(removed.has_value());

    // First reboot: the real seed_defaults() carries the revocation forward
    // onto Decommission:Delete and deletes the row (the marker is created
    // here for the first time).
    {
        RbacStore first_reopen{rbac_pool_fx_};
        REQUIRE(first_reopen.is_open());
        REQUIRE_FALSE(
            first_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

        // Operator explicitly re-grants Decommission:Delete via the RBAC
        // editor's own path — set_permission() writes role_permissions
        // directly and never touches revoked_seed_defaults.
        auto regranted =
            first_reopen.set_permission({"ITServiceOwner", "Decommission", "Delete", "allow"});
        REQUIRE(regranted.has_value());
        REQUIRE(
            first_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
    }

    // Second reboot: the marker from the first reopen is still present, but
    // the carry-forward DELETE must not fire again — the re-grant must
    // survive.
    RbacStore second_reopen{rbac_pool_fx_};
    REQUIRE(second_reopen.is_open());
    CHECK(second_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
}

// Adversarial review Wave 7 PR7.2b fix round 1: the marker INSERT and
// permission DELETE used to be two SEPARATE autocommit statements. A fault
// isolated to the DELETE (marker already committed) durably recorded
// "migration complete" while the revocation it was supposed to carry
// forward silently never happened -- and because the marker now existed,
// grant()'s own WHERE NOT EXISTS guard meant NO LATER boot ever retried it
// either, so the operator's revoked-SoftwareLicensing intent was permanently
// never carried onto Decommission:Delete. Force the DELETE to fail via a
// trigger, confirm the grant survives that boot (the failed attempt must not
// half-apply), remove the trigger, and confirm the NEXT boot actually
// retries and completes the carry-forward -- proving the marker was NOT
// left behind by the failed attempt (the old bug's exact mechanism).
TEST_CASE("RbacStore: a fault during the Decommission carry-forward DELETE does not durably "
          "record the marker -- the migration retries and completes on a later boot",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    auto removed = store.remove_permission("ITServiceOwner", "SoftwareLicensing", "Delete");
    REQUIRE(removed.has_value());

    // Force the carry-forward DELETE to fail with a genuine SQL execution
    // error (never merely a zero-row match) -- a BEFORE DELETE trigger that
    // raises only for the exact row this migration targets. Scoped to this
    // test's own cloned database, so it can't leak into any other test.
    {
        pg::PgConn conn{PQconnectdb(rbac_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult fn_res{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION rbac_store.f_decommission_delete_fail() "
            "RETURNS trigger AS $$ BEGIN IF OLD.role_name = 'ITServiceOwner' AND "
            "OLD.securable_type = 'Decommission' AND OLD.operation = 'Delete' THEN "
            "RAISE EXCEPTION 'test-induced carry-forward DELETE failure'; END IF; "
            "RETURN OLD; END; $$ LANGUAGE plpgsql;")};
        REQUIRE(fn_res.ok());
        pg::PgResult trig_res{PQexec(
            conn.get(),
            "CREATE TRIGGER t_decommission_delete_fail BEFORE DELETE ON "
            "rbac_store.role_permissions FOR EACH ROW EXECUTE FUNCTION "
            "rbac_store.f_decommission_delete_fail();")};
        REQUIRE(trig_res.ok());
    }

    // First reopen: the carry-forward attempt's DELETE is blocked. The whole
    // transaction (including the marker INSERT staged in the SAME
    // transaction) must roll back -- the grant must survive this boot
    // UNCHANGED, and no marker may be left behind.
    {
        RbacStore first_reopen{rbac_pool_fx_};
        REQUIRE(first_reopen.is_open());
        CHECK(first_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
    }

    // Remove the trigger, then reopen again: if the marker was (incorrectly)
    // left behind by the failed attempt, this boot's probe would see it
    // present and skip the migration forever, permanently failing to honor
    // the operator's revocation. It must instead see the marker still
    // ABSENT, retry, and this time succeed.
    {
        pg::PgConn conn{PQconnectdb(rbac_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult drop_res{
            PQexec(conn.get(), "DROP TRIGGER t_decommission_delete_fail ON "
                               "rbac_store.role_permissions;")};
        REQUIRE(drop_res.ok());
    }
    RbacStore second_reopen{rbac_pool_fx_};
    REQUIRE(second_reopen.is_open());
    CHECK_FALSE(
        second_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
}

TEST_CASE("RbacStore: a fault at COMMIT itself (not an earlier statement) must not let the "
          "trailing grant() silently re-instate a grant the migration was deferring",
          "[rbac_store][pg]") {
    // Governance Gate 3 cpp-safety finding: `if (decommission_migrated) txn.commit();`
    // discarded commit()'s own bool. Every statement BEFORE commit can succeed
    // (probe/insert/delete all report success) and the migration can still
    // fail to durably persist if COMMIT itself is rejected -- a DEFERRABLE
    // constraint check is the real-Postgres mechanism for exactly this: it
    // passes at each statement's own execution time and is only evaluated at
    // COMMIT, unlike the DELETE-fault test above (which fails at the DELETE
    // statement itself, and can't isolate this specific bug -- see below).
    //
    // Discriminator design note: the DELETE-fault test above starts from a
    // role_permissions row that already exists (the store's own initial
    // seed), so a rolled-back DELETE simply leaves it in place either way --
    // grant()'s own `WHERE NOT EXISTS(marker) ... ON CONFLICT DO NOTHING` is
    // idempotent against an already-present row, so calling grant() when the
    // bug is present (spuriously) and NOT calling it (correctly, under the
    // fix) converge to the identical observable row state; that test does
    // NOT discriminate this bug (confirmed empirically: it still passes with
    // the fix reverted). This test instead starts with the row ABSENT and no
    // marker, and forces the COMMIT-time fault via a trigger on the MARKER
    // insert (revoked_seed_defaults) rather than the row DELETE, so the
    // fault fires regardless of whether a role_permissions row exists to
    // delete. Under the bug, the trailing grant() sees no marker (rolled
    // back) and creates a NEW row where none existed -- silently overriding
    // the operator's carried-forward revocation; under the fix, grant() is
    // correctly skipped and the row stays absent.
    RBAC_STORE(store);
    REQUIRE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    // Strip the grant via direct SQL, NOT remove_permission() -- the latter
    // would write its own revoked_seed_defaults marker for (ITServiceOwner,
    // Decommission, Delete), which would make the migration's own probe see
    // "already migrated" and skip the insert+DELETE branch entirely, never
    // reaching the COMMIT this test exists to fault.
    {
        pg::PgConn conn{PQconnectdb(rbac_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult del_res{PQexec(
            conn.get(), "DELETE FROM rbac_store.role_permissions WHERE role_name = "
                       "'ITServiceOwner' AND securable_type = 'Decommission' AND "
                       "operation = 'Delete';")};
        REQUIRE(del_res.ok());
    }
    REQUIRE_FALSE(store.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));

    auto removed = store.remove_permission("ITServiceOwner", "SoftwareLicensing", "Delete");
    REQUIRE(removed.has_value());

    {
        pg::PgConn conn{PQconnectdb(rbac_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult fn_res{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION rbac_store.f_decommission_commit_fail() "
            "RETURNS trigger AS $$ BEGIN RAISE EXCEPTION "
            "'test-induced carry-forward COMMIT failure'; END; $$ LANGUAGE plpgsql;")};
        REQUIRE(fn_res.ok());
        // CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED: the row-level
        // check runs, but the exception it raises is only evaluated when the
        // transaction issues COMMIT -- not at the INSERT statement itself.
        // Attached to the MARKER insert (fires unconditionally whenever the
        // migration's WHERE EXISTS(old conjunct revocation) is true), not
        // the role_permissions DELETE -- the role has no such row to delete
        // in this test's setup.
        pg::PgResult trig_res{PQexec(
            conn.get(),
            "CREATE CONSTRAINT TRIGGER t_decommission_commit_fail AFTER INSERT ON "
            "rbac_store.revoked_seed_defaults DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
            "WHEN (NEW.role_name = 'ITServiceOwner' AND NEW.securable_type = 'Decommission' "
            "AND NEW.operation = 'Delete') EXECUTE FUNCTION "
            "rbac_store.f_decommission_commit_fail();")};
        REQUIRE(trig_res.ok());
    }

    // The migration's own probe/marker-INSERT/DELETE all report success
    // locally (the exception only fires at COMMIT) -- the store must still
    // come up, and the grant must stay absent: the operator's carried-
    // forward revocation is still pending, not silently overridden by a
    // trailing grant() call that should have been deferred.
    {
        RbacStore first_reopen{rbac_pool_fx_};
        REQUIRE(first_reopen.is_open());
        CHECK_FALSE(
            first_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
    }

    // No marker was durably recorded (the whole transaction, including the
    // marker INSERT, rolled back with the failed COMMIT) -- the migration
    // must retry and complete once the fault is cleared.
    {
        pg::PgConn conn{PQconnectdb(rbac_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult drop_res{
            PQexec(conn.get(), "DROP TRIGGER t_decommission_commit_fail ON "
                               "rbac_store.revoked_seed_defaults;")};
        REQUIRE(drop_res.ok());
    }
    RbacStore second_reopen{rbac_pool_fx_};
    REQUIRE(second_reopen.is_open());
    CHECK_FALSE(
        second_reopen.check_role_has_permission("ITServiceOwner", "Decommission", "Delete"));
}

// ── check_scoped_permission ──────────────────────────────────────────────────

namespace {
// The ManagementGroupStore is now a Postgres store (ADR-0042); the scoped-
// permission tests below wire the SQLite RbacStore to a PG-backed mgmt store.
// Pre-migrated template cloned per test (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate scoped_mgmt_tpl{"rbacscopedmgmt", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbacscopedmgmt template: mgmt store failed to migrate");
}};
} // namespace

TEST_CASE("RbacStore: check_scoped_permission global allow bypasses scoping", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    rbac.assign_role({"user", "admin_user", "Administrator"});
    CHECK(rbac.check_scoped_permission("admin_user", "Tag", "Write", "agent-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission group-scoped allow", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // Create a management group and add agent to it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    // Assign ITServiceOwner to alice on this group
    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // alice has NO global role, but should have scoped access
    CHECK(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-crm-1", &mgmt));
    CHECK(rbac.check_scoped_permission("alice", "Execution", "Execute", "agent-crm-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission denied without scope", "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // alice has ITServiceOwner on CRM group, but agent-other is not in it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // agent-other is NOT in the CRM group
    CHECK_FALSE(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-other", &mgmt));
}

// fable (Gate 4, #2703, HIGH): the scoped/confinement path has the SAME
// dual-role hazard as the global one above — role_effects_for() maps a
// role's effect for (type,op) into resolve_perm_groups()'s deny_groups,
// which check_scoped_permission()/authorize_list_read() then treat as a
// hard veto (and expand_visible_set() subtracts whole agent subtrees for).
// A revoked-default role must stay NEUTRAL in that resolution — never a
// deny_group — so a principal's independent grant via a DIFFERENT role
// scoped to the SAME management group still controls.
TEST_CASE("RbacStore: revoking one role's default does not create a scoped deny_group "
          "vetoing a different role's independent grant",
          "[rbac_store][pg]") {
    RBAC_STORE(rbac);
    YUZU_REQUIRE_PG_DB_TPL(db, scoped_mgmt_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ManagementGroupStore mgmt{pool};

    // Both ITServiceOwner and Operator seed Tag:Write by default.
    REQUIRE(rbac.check_role_has_permission("ITServiceOwner", "Tag", "Write"));
    REQUIRE(rbac.check_role_has_permission("Operator", "Tag", "Write"));
    REQUIRE(rbac.remove_permission("ITServiceOwner", "Tag", "Write").has_value());
    CHECK_FALSE(rbac.check_role_has_permission("ITServiceOwner", "Tag", "Write"));

    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    // alice holds BOTH roles scoped to the SAME group: ITServiceOwner
    // (revoked default) and Operator (independent, unrevoked grant).
    GroupRoleAssignment a_ito;
    a_ito.group_id = *group_id;
    a_ito.principal_type = "user";
    a_ito.principal_id = "alice";
    a_ito.role_name = "ITServiceOwner";
    mgmt.assign_role(a_ito);
    GroupRoleAssignment a_op;
    a_op.group_id = *group_id;
    a_op.principal_type = "user";
    a_op.principal_id = "alice";
    a_op.role_name = "Operator";
    mgmt.assign_role(a_op);

    // If the revoked role's absence were (wrongly) treated as a deny_group,
    // this would come back false. It must not — the revoked role is
    // neutral, exactly as if alice never held it for this (type,op).
    CHECK(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-crm-1", &mgmt));
}

// The load-bearing ADR-0041 invariant (Gate 3 QE BLOCKING): every authz read
// on a degraded/unopened store must DENY, never fail open. This is the whole
// reason the migration preserves deny-on-error on the bool paths.
TEST_CASE("RbacStore: every authz read fails closed (DENY) on a broken store",
          "[rbac_store][pg]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 dbname=x user=x connect_timeout=1", .size = 1}};
    RbacStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    CHECK_FALSE(broken.check_permission("alice", "Execution", "Execute"));
    CHECK_FALSE(broken.check_scoped_permission("alice", "Execution", "Execute", "agent-1", nullptr));
    CHECK_FALSE(broken.holds_permission_via_any_group("alice", "Execution", "Execute", nullptr));
    CHECK_FALSE(broken.check_role_has_permission("Administrator", "Execution", "Execute"));
    // Tri-state read degrades distinguishably (unexpected), never an engaged allow.
    CHECK_FALSE(broken.get_principal_roles_checked("user", "alice").has_value());
    // The list-read chokepoint denies-all on a degraded store (never AdmitAll).
    CHECK(broken.authorize_list_read("alice", "Agent", "Read", nullptr).decision ==
          ListReadDecision::DenyAll);
}

// The generation-token cache must not serve a stale ALLOW after a revoke on the
// same instance (Gate 3 QE BLOCKING): a mutation bumps the durable generation
// in-txn and clears the local cache, so the next check re-reads and denies.
TEST_CASE("RbacStore: a revoke invalidates a cached allow (generation token)",
          "[rbac_store][pg]") {
    RBAC_STORE_WITH_AUTH(store, auth_db);
    // A second Administrator holder so the revoke below doesn't trip the A2
    // last-Administrator guard — this test is about cache invalidation, not
    // that guard, which has its own dedicated test cases. Both need a real
    // auth.users row now that the guard JOINs on it.
    seed_active_user(auth_db, "otheradmin");
    seed_active_user(auth_db, "cacheuser");
    store.assign_role({"user", "otheradmin", "Administrator"});
    store.assign_role({"user", "cacheuser", "Administrator"}); // Administrator = allow-all
    // Warm perm_cache_ with an ALLOW verdict.
    CHECK(store.check_permission("cacheuser", "Execution", "Execute"));
    // Revoke — bumps write_generation in the same txn + clears the local cache.
    REQUIRE(store.unassign_role("user", "cacheuser", "Administrator").has_value());
    // The previously-cached allow must NOT be served; the check re-reads → DENY.
    CHECK_FALSE(store.check_permission("cacheuser", "Execution", "Execute"));
}

// adversarial-review round (PR #2703): both external reviewers (Kimi, Codex)
// independently found that maybe_refresh_generation()'s "never touch
// rbac_enabled_ on a read error" contract only reasons about the true->false
// fail-open direction -- a replica that has never itself observed a remote
// enable stays cached false (enforcement NOT in effect, i.e. AdmitAll)
// indefinitely through an outage, even after the durable flag has genuinely
// flipped true elsewhere. Reproduces the real production code path: replica
// A durably enables RBAC (bumping write_generation); replica B (a SEPARATE
// store+pool against the SAME database) never observes that write because
// its own size-1 pool is starved for its next refresh attempt, which
// genuinely times out and lands in the !durable_gen branch.
TEST_CASE("RbacStore: rbac_enforcement_in_effect fails closed when a generation refresh fails "
          "PAST the bounded stale-serve window, while another replica has durably enabled "
          "RBAC (adversarial-review round, #2703; bounded stale-serve, #2703 Gate 7)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    REQUIRE_FALSE(replica_a.is_rbac_enabled()); // fresh install default

    // "Replica B": a separate store + size-1 pool against the SAME database,
    // so it can be starved independently of replica_a's own pool.
    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    REQUIRE_FALSE(replica_b.is_rbac_enabled());
    // Baseline this test's failure branch must diverge from: genuinely
    // fresh + disabled correctly reports enforcement NOT in effect.
    REQUIRE_FALSE(rbac_enforcement_in_effect(&replica_b));

    // Replica A durably enables RBAC -- bumps write_generation in the same
    // txn (ADR-0041 contract).
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.is_rbac_enabled());

    // Clear replica_b's refresh gate so its next read genuinely attempts a
    // durable re-read rather than serving its just-constructed cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Starve replica_b's own pool for the rest of the test: every subsequent
    // maybe_refresh_generation() call on replica_b cannot acquire a
    // connection and must time out. That acquire now uses the short
    // kAuthzAcquireTimeout (250ms, #2703 Gate 7 merge-slice item 1 commit A —
    // bounds how long a saturated pool can pin an HTTP worker on the authz
    // hot path), not the wider kReadTimeout, so a failed attempt's OWN
    // blocking time is no longer large enough to reliably carry the clock
    // across kRbacStaleServeBoundMs (5000ms) the way it could when the acquire
    // itself took ~2s. This test now advances wall time with explicit sleeps
    // instead of relying on that blocking duration.
    auto held = pool_b.acquire();
    REQUIRE(held);

    // Bounded stale-serve (#2703 Gate 7, operator-adjudicated): this FIRST
    // failed refresh attempt lands at roughly construction + 1.1s (the sleep
    // above) + <=0.25s (this call's own blocking kAuthzAcquireTimeout) — well
    // inside kRbacStaleServeBoundMs (5000ms) of replica_b's last confirmed-
    // good refresh (its own construction). This is the whole point of the
    // tolerance: a short blip must NOT immediately widen a genuinely-
    // disabled fleet to enforce. is_open() stays true throughout (no
    // store-level degrade), only the generation view is briefly unconfirmed.
    CHECK_FALSE(rbac_enforcement_in_effect(&replica_b));

    // Push past the bound with an explicit sleep — comfortably clears both
    // the 1s stampede gate (so the next call genuinely attempts a fresh
    // refresh rather than serving the gated fast path) and, combined with
    // the ~1.1-1.35s already elapsed, pushes total elapsed time since
    // construction past kRbacStaleServeBoundMs (5000ms) with margin.
    std::this_thread::sleep_for(std::chrono::milliseconds(4200));

    // Pre-fix (adversarial-review round): is_rbac_enabled() correctly stayed
    // false (the existing contract), but rbac_enforcement_in_effect() ALSO
    // returned false, wrongly admitting the full fleet. Post-fix, and now
    // past the stale-serve bound: enforcement is in effect because the view
    // is genuinely degraded, not merely aging within tolerance.
    CHECK(rbac_enforcement_in_effect(&replica_b));

    // A3 (governance round 3, SHOULD-4): the NEW three-way label must land
    // on kDegraded here, never kDisabled — this is the cached-DISABLED,
    // genuinely-stale branch (the pool is STILL starved, `held` never
    // released), as opposed to the sibling cached-ENABLED-stale test above
    // that documents the short-circuit asymmetry. rbac_enforcement_label()
    // mirrors rbac_enforcement_in_effect()'s own branch order exactly, so
    // this is the same degrade this test already proved, split three ways.
    CHECK(rbac_enforcement_label(&replica_b) == RbacEnforcementLabel::kDegraded);
}

// G11-CPPEXPERT-B2 (#2703 Gate 8, fixed): the sibling test above proves
// rbac_enforcement_in_effect() fails closed once SOME refresh attempt
// actually completes and finds itself past the bound. This test proves the
// narrower, previously-open gap: elapsed time alone must degrade the view
// even when NO refresh attempt is ever made at all -- e.g. every caller in
// the window took the gated fast-return path, or is itself still blocked
// inside a stuck query (PG-side lock contention, #3016, can block a single
// query for the whole ~10s lock_timeout). Pre-fix, rbac_enabled_view_degraded()
// was `!generation_valid_` only, which nothing in this scenario ever flips --
// generation_valid_ stays true, untouched, indefinitely. No pool starving
// here deliberately: the point is that this must degrade with ZERO refresh
// attempts, successful or failed, so the test makes none.
TEST_CASE("RbacStore: rbac_enabled_view_degraded fails closed on elapsed time alone, "
          "with no refresh attempt ever completing (#2703 Gate 8, G11-CPPEXPERT-B2)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    REQUIRE_FALSE(replica_a.is_rbac_enabled()); // fresh install default

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 4}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());

    // Fresh construction is a genuine completed refresh (the header's own
    // "construction counts as one" contract) -- not degraded yet.
    REQUIRE_FALSE(replica_b.rbac_enabled_view_degraded());

    // Advance wall time past kRbacStaleServeBoundMs (5000ms) WITHOUT calling
    // is_rbac_enabled()/check_permission()/anything that reaches
    // maybe_refresh_generation() -- replica_b's pool is left healthy and
    // untouched throughout, so if the old `!generation_valid_`-only check
    // were still in place, nothing in this test would ever flip it.
    std::this_thread::sleep_for(std::chrono::milliseconds(5200));

    // Called directly (bypassing maybe_refresh_generation() entirely, unlike
    // is_rbac_enabled()/rbac_enforcement_in_effect() which always trigger a
    // fresh attempt first): elapsed time alone must now report degraded,
    // even though generation_valid_ was never touched by a completed refresh
    // attempt of any kind.
    CHECK(replica_b.rbac_enabled_view_degraded());

    // rbac_enforcement_in_effect() itself is NOT re-checked here for
    // degraded=true: replica_b's pool is deliberately left healthy (no lock
    // held, no starving), so is_rbac_enabled()'s own maybe_refresh_generation()
    // call succeeds instantly and self-heals the view before
    // rbac_enabled_view_degraded() would even be consulted -- correct
    // behavior once nothing is actually blocking a fresh read, not a gap.
    // The genuinely-stuck-query scenario this fix targets (a real held
    // PG-side row lock, #3016) needs a second connection actively holding
    // that lock to reproduce end-to-end; the direct check above is the
    // precise unit-level proof that this fix's own code path is reachable
    // and correct independent of that heavier live-lock harness.
    CHECK_FALSE(rbac_enforcement_in_effect(&replica_b));
}

// #2703 Gate 7 (operator-adjudicated bounded stale-serve): a refresh failure
// that lands INSIDE the tolerance window must not clear a warm perm_cache_ --
// that's the entire point of tolerating it (avoid a fleet-wide cache-miss
// storm on a short blip). Verified via a genuinely warm cache (a real granted
// permission, actually served from cache), not just the generation flag.
TEST_CASE("RbacStore: a warm permission cache survives a generation-refresh "
          "failure inside the stale-serve bound (#2703 Gate 7)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.assign_role({"user", "bob", "Administrator"}).has_value());

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());

    // Clear the refresh gate, let replica_b observe the durable enable +
    // grant, and genuinely populate perm_cache_ with an ALLOW.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    REQUIRE(replica_b.check_permission("bob", "Infrastructure", "Read"));

    // Starve the pool and force one failed refresh attempt inside the bound.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    auto held = pool_b.acquire();
    REQUIRE(held);

    // Still inside kRbacStaleServeBoundMs of the successful refresh above --
    // the cached ALLOW must still be served, not silently dropped to a
    // DB-round-trip (which would itself fail while the pool is starved).
    CHECK(replica_b.check_permission("bob", "Infrastructure", "Read"));
}

// cpp-safety (#2703 Gate 8, second re-review): the sibling test above proves
// the within-bound side of check_permission()'s own trust decision (the
// exact site that read generation_valid_ directly pre-fix, see 67df7e49d).
// This proves the past-the-bound side end to end. Caveat, stated honestly:
// starving the pool here means maybe_refresh_generation()'s OWN pre-existing
// flip-on-detect path (unconditionally called at the top of
// check_permission(), unrelated to this fix) also fires and flips
// generation_valid_ false BEFORE check_permission()'s own trust check ever
// runs -- so this does not, by itself, isolate the NEW check_permission()-
// level substitution from the pre-existing mechanism the way the
// rbac_enabled_view_degraded() test isolates its own fix (that one calls the
// accessor directly, bypassing maybe_refresh_generation() entirely; nothing
// analogous exists for check_permission(), which always refreshes first).
// What this DOES prove: check_permission() correctly denies rather than
// serving a stale cached ALLOW once past the bound, end to end -- real
// regression coverage for a previously-untested boundary, even though the
// genuinely-stuck-refresh scenario this fix specifically targets stays
// covered only by the deferred live-lock harness, #3031.
TEST_CASE("RbacStore: a warm permission cache is NOT served once the "
          "generation refresh has genuinely failed PAST the stale-serve "
          "bound (#2703 Gate 8, check_permission cache-trust fix)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.assign_role({"user", "bob", "Administrator"}).has_value());

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());

    // Clear the refresh gate, let replica_b observe the durable enable +
    // grant, and genuinely populate perm_cache_ with an ALLOW.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    REQUIRE(replica_b.check_permission("bob", "Infrastructure", "Read"));

    // Starve the pool, then push wall time past kRbacStaleServeBoundMs
    // (5000ms) with an explicit sleep before the next call. Unlike the
    // sibling rbac_enforcement_in_effect fail-closed test above (whose
    // 4200ms works because its baseline is CONSTRUCTION, never updated since
    // every refresh attempt after it fails), this test's baseline is the
    // SUCCESSFUL warming call just above -- last_successful_refresh_ms_ was
    // genuinely updated to ~now there, so the sleep alone must exceed the
    // 5000ms bound, not merely combine with an earlier one to reach it.
    auto held = pool_b.acquire();
    REQUIRE(held);
    std::this_thread::sleep_for(std::chrono::milliseconds(5200));

    // Past the bound, with the pool starved: the previously-cached ALLOW
    // must NOT be served. check_permission()'s own internal
    // maybe_refresh_generation() call fails (pool starved), the fallback
    // pool acquire inside check_permission() itself also fails (same starved
    // pool) -- both directions fail closed, landing on DENY.
    CHECK_FALSE(replica_b.check_permission("bob", "Infrastructure", "Read"));
}

// #2703 Gate 7 merge-slice item 1 commit B (operator-adjudicated: trip fast,
// 2 consecutive failures), extended in commit C with the
// yuzu_server_rbac_breaker_open gauge as PRIMARY evidence — a wall-clock
// assertion alone is exactly the flake class "Green on BigColin != CI" warns
// about (a descheduled thread on a contended CI runner can blow a timing
// budget on otherwise-correct code); the gauge transition is asserted
// directly and does not depend on scheduling. The elapsed-time check is kept
// as SECONDARY evidence only. A cache MISS on every call (a unique operation
// string each time) forces every call through the real pool-fallback path
// so neither measurement is confounded by stale-serve.
TEST_CASE("RbacStore: fail-fast breaker denies without a pool touch once "
          "consecutive failures reach the trip threshold, then half-opens "
          "on the next probe (#2703 Gate 7 item 1 commits B+C)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.assign_role({"user", "bob", "Administrator"}).has_value());

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics); // wired AFTER construction — construction's
                                     // own read (if any) cannot touch the gauge

    // Clear the refresh gate opened at construction so the first starved
    // call below genuinely attempts a fresh refresh rather than serving the
    // gated fast path.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    auto held = pool_b.acquire();
    REQUIRE(held);

    // First call: maybe_refresh_generation's own attempt fails (streak 0->1,
    // still under the threshold of 2 — no gauge transition yet) -> falls
    // through to a genuine cache MISS ("probe1" was never checked) ->
    // check_permission's OWN pool-fallback attempt ALSO fails (streak 1->2,
    // NOW at the threshold — this IS a closed->open transition, so the gauge
    // goes to 1 within this same call). Denies fail-closed either way.
    CHECK_FALSE(replica_b.check_permission("bob", "Infrastructure", "probe1"));
    CHECK(metrics.gauge("yuzu_server_rbac_breaker_open").value() == 1.0);

    // Second call, immediately after (well inside kRbacGenerationRefreshMs
    // of both the refresh gate AND the breaker's cooldown): maybe_refresh_
    // generation is gated (no pool touch, no breaker interaction) and
    // check_permission's own breaker_admit() now sees streak >= threshold
    // AND the cooldown ungated-since check fails too -> denies WITHOUT any
    // pool touch, and breaker_note_result is never called (no transition,
    // gauge stays 1). Wall-clock is secondary evidence: no acquire attempt
    // means this completes in low single-digit ms, versus the >=250ms
    // (kAuthzAcquireTimeout) a real attempt would cost.
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_FALSE(replica_b.check_permission("bob", "Infrastructure", "probe2"));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(metrics.gauge("yuzu_server_rbac_breaker_open").value() == 1.0);
    CHECK(elapsed < std::chrono::milliseconds(150));

    // Clear both the refresh gate and the breaker cooldown, then release
    // the starved connection so the next attempt (the half-open probe) can
    // genuinely succeed and reset the streak to 0 — an open->closed
    // transition, so the gauge goes back to 0.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    held.reset();
    CHECK(replica_b.check_permission("bob", "Infrastructure", "Read"));
    CHECK(metrics.gauge("yuzu_server_rbac_breaker_open").value() == 0.0);

    // The latency histogram (commit C) observes on every check_permission
    // exit regardless of outcome — three calls above (probe1, probe2, Read),
    // all counted whether denied or successful.
    CHECK(metrics.serialize().find("yuzu_server_rbac_authz_check_seconds_count 3") !=
          std::string::npos);
}

// #2703 Gate 7 item 3 (BLOCKING, consistency-auditor Gate 4 + compliance-officer
// Gate 6): user_rbac_group_names and role_effects_for share check_permission's
// 3 degrade exits (breaker-denied, pool-acquire-timeout, query-error) but,
// before this fix, never called note_read_degrade() on any of them — a
// degrade on the ADR-0017 admit-then-filter chokepoint (authorize_list_read,
// which both feed) was invisible to yuzu_server_rbac_read_degrade_total and
// the YuzuRbacReadDegraded alert. Reproduces the pool-acquire-timeout path
// (first two calls, one per sibling) and the breaker-denied fast path (calls
// 3 and 4, once the first two have tripped the breaker) ON EACH sibling's OWN
// code site — quality-engineer (Gate 8) found an earlier version of this
// test exercised user_rbac_group_names' breaker-denied branch but not
// role_effects_for's own (structurally identical, but a distinct site);
// call 4 closes that. Query-error is intentionally NOT covered here (a
// pre-existing, file-wide gap — check_permission's own query-error path has
// never had a counter-asserting test either); asserts the counter directly,
// not merely that the calls return an error.
TEST_CASE("RbacStore: user_rbac_group_names and role_effects_for record "
          "read-degrade on pool-acquire-timeout and breaker-denied "
          "(#2703 Gate 7 item 3)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    (void)replica_a;

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    RbacStoreTestAccess acc{replica_b};
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics); // wired AFTER construction, same as the
                                     // breaker test — construction's own read
                                     // (if any) must not touch the counter.

    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // clear the refresh gate

    auto held = pool_b.acquire();
    REQUIRE(held);

    // Call 1 (user_rbac_group_names): breaker still closed (streak 0) ->
    // genuine pool-acquire attempt -> times out -> streak 0->1, denying,
    // reason=pool_acquire_timeout.
    auto r1 = acc.user_rbac_group_names("bob");
    REQUIRE_FALSE(r1.has_value());
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "pool_acquire_timeout"}})
              .value() == 1.0);

    // Call 2 (role_effects_for): breaker still closed (streak 1 < threshold
    // 2) -> genuine pool-acquire attempt -> times out -> streak 1->2, a
    // closed->open transition, reason=pool_acquire_timeout again.
    auto r2 = acc.role_effects_for("Infrastructure", "Read");
    REQUIRE_FALSE(r2.has_value());
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "pool_acquire_timeout"}})
              .value() == 2.0);
    CHECK(metrics.gauge("yuzu_server_rbac_breaker_open").value() == 1.0);

    // Call 3 (user_rbac_group_names again): breaker now OPEN and within its
    // cooldown -> denies WITHOUT a pool touch, via each sibling's own
    // breaker-denied branch (the other half of this fix — that branch was
    // ALSO silent pre-fix). Reason is still pool_acquire_timeout (breaker-
    // denied is recorded under the same label as check_permission's own
    // breaker-denied branch, not a distinct reason — see the HELP text).
    auto r3 = acc.user_rbac_group_names("bob");
    REQUIRE_FALSE(r3.has_value());
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "pool_acquire_timeout"}})
              .value() == 3.0);

    // Call 4 (role_effects_for, breaker-denied): quality-engineer (Gate 8) —
    // call 3 above only exercised user_rbac_group_names' OWN breaker-denied
    // branch; role_effects_for's own breaker-denied early return
    // (structurally identical, but a distinct code site) was never directly
    // hit. Still within the cooldown from call 2/3, so this denies WITHOUT a
    // pool touch too.
    auto r4 = acc.role_effects_for("Infrastructure", "Read");
    REQUIRE_FALSE(r4.has_value());
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "pool_acquire_timeout"}})
              .value() == 4.0);
}

// #2703 Gate 7 item Commit C (quality-engineer + consistency-auditor, Gate 3:
// zero test coverage for the generation_refresh_failed /
// generation_refresh_failed_within_bound reason split — the exact
// false-green-shaped gap this session already hit once with the sibling-
// method omission above). Asserts the COUNTER + its reason label directly,
// not just the behavioural side effect (a warm/dropped cache) the two
// existing generation tests already cover.
TEST_CASE("RbacStore: generation-refresh-failed degrade records the correct "
          "reason label inside vs. past the bounded stale-serve window "
          "(#2703 Gate 7 item Commit C)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    replica_a.set_rbac_enabled(true);
    REQUIRE(replica_a.assign_role({"user", "bob", "Administrator"}).has_value());

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics);

    // Genuinely populate replica_b's cache with a confirmed-good refresh.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    REQUIRE(replica_b.check_permission("bob", "Infrastructure", "Read"));
    // check_permission's own success path never fires a degrade — sanity
    // check that this test starts from a clean counter before starving.
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed_within_bound"}})
              .value() == 0.0);
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed"}})
              .value() == 0.0);

    // Starve the pool and force one failed refresh attempt INSIDE the bound.
    // check_permission() is the trigger (maybe_refresh_generation() is
    // private) — same technique as the pre-existing generation tests above.
    // The cache stays warm through this call (within-bound keeps
    // perm_cache_), so it's served from cache and never reaches
    // check_permission's OWN pool-fallback branch — only
    // maybe_refresh_generation()'s degrade fires.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    auto held = pool_b.acquire();
    REQUIRE(held);
    CHECK(replica_b.check_permission("bob", "Infrastructure", "Read")); // served from cache
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed_within_bound"}})
              .value() == 1.0);
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed"}})
              .value() == 0.0); // the denying reason must NOT fire while still tolerated

    // Push past the bound with an explicit sleep (mirrors the existing
    // rbac_enforcement_in_effect fail-closed test's technique). This second
    // failed refresh drops the cache, so THIS call also falls through to
    // check_permission's own (still-starved) pool-fallback branch — that
    // fires its own pool_acquire_timeout degrade too, a different reason
    // label from the two asserted below, so it doesn't affect them.
    std::this_thread::sleep_for(std::chrono::milliseconds(4200));
    CHECK_FALSE(replica_b.check_permission("bob", "Infrastructure", "Read"));
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed"}})
              .value() == 1.0); // now denying — the cache was actually dropped
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "generation_refresh_failed_within_bound"}})
              .value() == 1.0); // unchanged — that call's reason was the other one
}

// quality-engineer (#2703): the F3 staleness predicate, pinned with synthetic
// timestamps — no DB, no real clock. rbac_generation_rules.hpp.
TEST_CASE("rbac_generation::is_stale_beyond_bound", "[rbac_store]") {
    using yuzu::server::rbac_generation::is_stale_beyond_bound;

    // Fresh: last success just now, bound not yet reached.
    CHECK_FALSE(is_stale_beyond_bound(/*now_ms=*/1000, /*last_successful_refresh_ms=*/1000,
                                       /*bound_ms=*/1000));
    CHECK_FALSE(is_stale_beyond_bound(1500, 1000, 1000));
    // Exactly at the bound counts as stale (>=, not >).
    CHECK(is_stale_beyond_bound(2000, 1000, 1000));
    // Past the bound.
    CHECK(is_stale_beyond_bound(5000, 1000, 1000));
    // A refresh that has never succeeded (last_successful_refresh_ms_ still at
    // its zero-init) is stale from the first ms once the bound has elapsed.
    CHECK(is_stale_beyond_bound(1000, 0, 1000));
    CHECK_FALSE(is_stale_beyond_bound(999, 0, 1000));
}

// Doomgoose external review, PR #4985 IMPORTANT finding #3 — direct coverage
// of the ALLOWLIST classifier itself, no DB (a pure std::string_view
// function). From the A2 route this classifier serves, the 400 branch is
// actually UNREACHABLE today: `principal_type` is hardcoded `"user"` and
// `principal_id` has already passed `is_valid_username` (which rejects `:`,
// so none of `validate_assignment`'s engine-namespace messages can ever
// reach it either) — the 3 regression tests added alongside this fix (REST/
// MCP store-fault-maps-to-503, REST get_role()-integrity-fault-maps-to-503)
// therefore only exercise the 503/default side of the classifier through
// the route. This test exercises the ALLOWLIST side directly, so a future
// edit to `validate_assignment`'s wording that silently drifts from this
// classifier's own strings is caught here rather than nowhere.
TEST_CASE("rbac_assign_error_is_client_fault classifies the known "
          "client-validation shapes true and everything else (including "
          "store faults) false",
          "[rbac_store]") {
    using yuzu::server::rbac_assign_error_is_client_fault;

    // The 5 known validate_assignment/F1 client-validation shapes.
    CHECK(rbac_assign_error_is_client_fault(
        "principal_id in the reserved 'engine:' namespace may only be assigned under "
        "principal_type=\"engine\""));
    CHECK(rbac_assign_error_is_client_fault("unrecognized principal_type 'bogus'"));
    CHECK(rbac_assign_error_is_client_fault(
        "engine principal_id must be in the reserved 'engine:<slug>' namespace with a "
        "non-empty slug"));
    CHECK(rbac_assign_error_is_client_fault(
        "engine principals cannot be granted the admin/full-access role 'Administrator' — no "
        "admin, ever (design §4.2)"));
    CHECK(rbac_assign_error_is_client_fault(
        "engine principals cannot be granted a built-in system role 'Administrator' — no "
        "built-in role, ever (design §4.2)"));

    // Store/query faults — must default to false (503), never the allowlist.
    CHECK_FALSE(rbac_assign_error_is_client_fault("database not open"));
    CHECK_FALSE(rbac_assign_error_is_client_fault("assign_role failed"));
    CHECK_FALSE(rbac_assign_error_is_client_fault(
        "ERROR:  relation \"rbac_store.principal_roles\" does not exist"));
    CHECK_FALSE(rbac_assign_error_is_client_fault(""));
}

// fjarvis F2 (#2703, HIGH), schema-level layer: `rbac_meta.value` for
// key='rbac_enabled' is now constrained to exactly "true"/"false" (migration
// v2). A write attempting anything else — a hand-edit, a future bug writing
// a different boolean convention — must be rejected outright at write time,
// not land silently and wait to be discovered on the next boot/refresh.
TEST_CASE("RbacStore: rbac_meta rejects a non-canonical rbac_enabled value at write time",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    auto lease = rbac_pool_fx_.acquire();
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(), "UPDATE rbac_store.rbac_meta SET value = 'TRUE' WHERE key = 'rbac_enabled'",
        std::vector<std::string>{});
    CHECK(r.status() == PGRES_FATAL_ERROR);
    // 23514 = check_violation (SQLSTATE) — confirms it's the new constraint
    // firing, not some unrelated failure.
    const char* sqlstate = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    REQUIRE(sqlstate != nullptr);
    CHECK(std::string(sqlstate) == "23514");
}

// fjarvis F2 (#2703, HIGH), application-level layer (defense in depth): even
// with the schema-level guard bypassed — as an older un-migrated deployment
// would be, or a maintenance script run with elevated privilege — a
// non-canonical value already sitting in the row must not silently coerce to
// "false" (RBAC-off) on the next boot. `load_enabled_flag()` must refuse.
TEST_CASE("RbacStore: refuses to start on a non-canonical rbac_enabled value already in the row",
          "[rbac_store][pg]") {
    RBAC_STORE(store);
    {
        auto lease = rbac_pool_fx_.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "ALTER TABLE rbac_store.rbac_meta DROP CONSTRAINT "
                                "rbac_meta_enabled_canonical",
                                std::vector<std::string>{})
                    .ok());
        REQUIRE(pg::exec_params(lease.get(),
                                "UPDATE rbac_store.rbac_meta SET value = 'TRUE' WHERE key = "
                                "'rbac_enabled'",
                                std::vector<std::string>{})
                    .ok());
    }
    // A fresh construction against the SAME (now-corrupted) database must
    // refuse to open, not silently boot RBAC-off. seed_defaults()'s
    // rbac_enabled INSERT is ON CONFLICT DO NOTHING, so it does not clobber
    // the hand-set value before load_enabled_flag() reads it.
    RbacStore reopened{rbac_pool_fx_};
    CHECK_FALSE(reopened.is_open());
}

// fjarvis (PR #2703 re-review, MEDIUM, residual in the F2 fix) — a DIFFERENT
// moment than the two tests above: not initial boot (load_enabled_flag()),
// but a later REFRESH (maybe_refresh_generation()) that finds
// write_generation readable but rbac_enabled's row entirely ABSENT (as
// opposed to present-but-non-canonical, already counted). Pre-fix this had
// no counter, no log, AND kept advancing last_successful_refresh_ms_ as if
// the round had fully succeeded -- the generation view reported itself
// "fresh" indefinitely even though rbac_enabled specifically was never
// re-confirmed. The dangerous direction: a replica cached at
// rbac_enabled_=false would keep rbac_enforcement_in_effect() returning
// false (legacy-open) forever instead of degrading after
// kRbacStaleServeBoundMs.
TEST_CASE("RbacStore: a refresh finding rbac_enabled's row absent (write_generation still "
          "readable) degrades the view past the bound instead of reporting fresh forever "
          "(fjarvis re-review, MEDIUM)",
          "[rbac_store][pg]") {
    RBAC_STORE(replica_a);
    REQUIRE_FALSE(replica_a.is_rbac_enabled()); // fresh install default

    PgPool pool_b{{.conninfo = rbac_db_fx_.dsn(), .size = 4}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics);

    // Delete rbac_enabled's row directly -- write_generation stays readable,
    // isolating exactly the asymmetry this fix closes (not a general
    // refresh failure, which the existing !durable_gen path already
    // handles correctly).
    {
        auto lease = pool_b.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "DELETE FROM rbac_store.rbac_meta WHERE key = 'rbac_enabled'",
                                std::vector<std::string>{})
                    .ok());
    }

    // Clear the 1s stampede gate so the next check genuinely attempts a
    // refresh rather than serving the gated fast path, then trigger one.
    // Construction already counted as a genuine completed refresh, so
    // replica_b is not degraded yet at this point.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    REQUIRE_FALSE(replica_b.rbac_enabled_view_degraded());
    (void)replica_b.is_rbac_enabled(); // triggers maybe_refresh_generation()

    // THE FIX: the absent row is now counted (pre-fix: silently uncounted).
    CHECK(metrics.counter("yuzu_server_rbac_read_degrade_total",
                          {{"reason", "rbac_enabled_non_canonical"}})
              .value() == 1.0);

    // Push wall time past kRbacStaleServeBoundMs (5000ms) from that SAME
    // refresh attempt, with the row still absent throughout -- no
    // subsequent round can ever confirm rbac_enabled either. Each call
    // below re-triggers maybe_refresh_generation() (past its own 1s gate),
    // finding the same absent row every time.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    (void)replica_b.is_rbac_enabled();
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    (void)replica_b.is_rbac_enabled();
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    (void)replica_b.is_rbac_enabled();
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // THE FIX: the view is now degraded -- pre-fix, last_successful_refresh_ms_
    // kept advancing on every one of the calls above despite rbac_enabled
    // never being confirmed, so this would have stayed false forever.
    CHECK(replica_b.rbac_enabled_view_degraded());
    CHECK(rbac_enforcement_in_effect(&replica_b));
}
