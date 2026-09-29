// PreflightRunStore tests (#governance Gate-7 quality-B1): the OWNER-SCOPE
// security boundary (list/get/delete), the create→persist→complete→prune
// lifecycle + FK cascade, and the complete_run no-op contract. Born-on-Postgres
// store, schema `preflight_run_store`. PG-gated: skips when YUZU_TEST_POSTGRES_DSN
// is unset, fails when it is set but broken.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "preflight_eval.hpp"
#include "preflight_run_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>

using yuzu::server::PreflightRunDeviceRow;
using yuzu::server::PreflightRunRow;
using yuzu::server::PreflightRunStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::preflight::PreflightTarget;
namespace preflight = yuzu::server::preflight;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp). The
// migration-failure test stays on plain YUZU_REQUIRE_PG_DB — it pre-seeds a
// conflicting schema and needs the store's schema to NOT exist yet.
yuzu::test::PgTestTemplate preflight_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, const std::string& owner, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = owner;
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000;
    r.status = "running";
    return r;
}

PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

} // namespace

TEST_CASE("PreflightRunStore owner-scope boundary", "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_run(make_run("rA", "alice", t), {tgt("a1"), tgt("a2")}));
    REQUIRE(store.create_run(make_run("rB", "bob", t), {tgt("b1")}));

    SECTION("list_runs is owner-scoped; admin sees all") {
        auto alice = store.list_runs("alice", /*is_admin=*/false, 50);
        REQUIRE(alice.size() == 1);
        CHECK(alice[0].run_id == "rA");
        auto bob = store.list_runs("bob", false, 50);
        REQUIRE(bob.size() == 1);
        CHECK(bob[0].run_id == "rB");
        auto admin = store.list_runs("anyone", /*is_admin=*/true, 50);
        CHECK(admin.size() >= 2); // sees both
    }

    SECTION("get_run owner-scope = no existence oracle") {
        CHECK(store.get_run("rA", "alice").has_value());     // owner sees it
        CHECK_FALSE(store.get_run("rA", "bob").has_value()); // not-yours → nullopt (== not-found)
        CHECK_FALSE(store.get_run("nope", "alice").has_value());
        CHECK(store.get_run("rA").has_value()); // unscoped (internal) still works
    }

    SECTION("delete_run is owner-scoped at the seam; cascades run_device") {
        // Wrong owner: no-op, row + its devices survive.
        CHECK_FALSE(store.delete_run("rA", "bob"));
        CHECK(store.get_run("rA").has_value());
        CHECK(store.get_targets("rA").size() == 2);
        // Correct owner: deletes, run_device cascades.
        CHECK(store.delete_run("rA", "alice"));
        CHECK_FALSE(store.get_run("rA").has_value());
        CHECK(store.get_devices("rA").empty()); // FK ON DELETE CASCADE
        CHECK(store.get_targets("rA").empty());
    }
}

TEST_CASE("PreflightRunStore lifecycle: create→persist→complete→prune", "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_run(make_run("rL", "carol", t), {tgt("c1"), tgt("c2")}));

    SECTION("seeded targets read back; grid persists; complete is gated + no-op-safe") {
        // Seeded run_device rows are 'inc' with no checks yet.
        auto seeded = store.get_devices("rL");
        REQUIRE(seeded.size() == 2);
        CHECK(seeded[0].bucket == "inc");

        // persist a computed grid + summary in one txn.
        std::vector<PreflightRunDeviceRow> grid = {
            {"c1", "host-c1", "windows", "go", R"([{"key":"disk","v":0,"val":"x"}])", t},
            {"c2", "host-c2", "windows", "nogo", R"([{"key":"disk","v":1,"val":"y"}])", t},
        };
        REQUIRE(store.persist_grid("rL", grid, 2, 1, 0, 1, 0));
        auto after = store.get_devices("rL");
        REQUIRE(after.size() == 2);
        // verify the computed bucket round-tripped
        bool saw_go = false, saw_nogo = false;
        for (const auto& d : after) {
            saw_go |= (d.bucket == "go");
            saw_nogo |= (d.bucket == "nogo");
        }
        CHECK(saw_go);
        CHECK(saw_nogo);
        auto row = store.get_run("rL");
        REQUIRE(row);
        CHECK(row->go == 1);
        CHECK(row->nogo == 1);

        // complete_run: real transition true; repeat / unknown = false (no-op contract).
        CHECK(store.complete_run("rL", t));
        CHECK_FALSE(store.complete_run("rL", t));     // already complete
        CHECK_FALSE(store.complete_run("ghost", t));  // unknown run
        auto done = store.get_run("rL");
        REQUIRE(done);
        CHECK(done->status == "complete");
    }

    SECTION("prune removes old runs + cascades (clock-guarded, bootstrap-declines once)") {
        const auto old_t = t - 100000; // 100s ago (t == now_ms())
        REQUIRE(store.create_run(make_run("rOld", "carol", old_t), {tgt("o1")}));
        // WS-10: run_retention_prune reads Postgres now() itself and takes the
        // retention WINDOW, not a cutoff. 75s sits between rOld (100s) and the
        // recent runs (~now). The clock guard's part-6 Decline means the FIRST
        // pass on a store that has data but no persisted anchor DECLINES (records
        // the anchor + settled marker, deletes nothing); the next pass proceeds.
        CHECK(store.run_retention_prune(75000) == 0); // bootstrap decline
        int n = store.run_retention_prune(75000);
        CHECK(n >= 1);
        CHECK_FALSE(store.get_run("rOld").has_value());
        CHECK(store.get_devices("rOld").empty()); // cascaded
        CHECK(store.get_run("rL").has_value());    // newer run survives
    }
}

// Shared persist+complete helper (used by BOTH the runner tick and the live result
// route): persists the grid, completes only when settled or past-deadline, and —
// via persist_grid's status guard — leaves a COMPLETE run's grid immutable so a
// stale route-persist can't overwrite it (#governance architect/consistency).
TEST_CASE("persist_and_maybe_complete: completes only when settled; complete grid is immutable",
          "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    REQUIRE(store.is_open());
    const auto t = now_ms();

    auto mk_grid = [](preflight::Bucket b) {
        std::vector<preflight::PreflightDeviceResult> g;
        preflight::PreflightDeviceResult dr;
        dr.agent_id = "a1";
        dr.hostname = "host-a1";
        dr.os = "windows";
        dr.bucket = b;
        g.push_back(std::move(dr));
        return g;
    };

    SECTION("any_pending → persists grid but does NOT complete") {
        REQUIRE(store.create_run(make_run("pmc1", "alice", t), {tgt("a1")}));
        auto g = mk_grid(preflight::Bucket::kIncomplete);
        CHECK_FALSE(preflight::persist_and_maybe_complete(store, "pmc1", g, t,
                                                          /*past_deadline=*/false,
                                                          /*any_pending=*/true));
        auto row = store.get_run("pmc1");
        REQUIRE(row);
        CHECK(row->status == "running");
        CHECK(row->incomplete == 1);
    }
    SECTION("settled → completes; then a stale persist on the complete run is a no-op") {
        REQUIRE(store.create_run(make_run("pmc2", "alice", t), {tgt("a1")}));
        auto g = mk_grid(preflight::Bucket::kWarnOnly);
        CHECK(preflight::persist_and_maybe_complete(store, "pmc2", g, t, false, /*any_pending=*/false));
        auto row = store.get_run("pmc2");
        REQUIRE(row);
        CHECK(row->status == "complete");
        CHECK(row->warn == 1);
        // Immutability: a slower route-persist landing after completion must NOT
        // overwrite the final grid (persist_grid is status='running'-guarded).
        auto stale = mk_grid(preflight::Bucket::kFailed);
        CHECK_FALSE(preflight::persist_and_maybe_complete(store, "pmc2", stale, t, false, false));
        auto after = store.get_run("pmc2");
        REQUIRE(after);
        CHECK(after->warn == 1); // unchanged
        CHECK(after->nogo == 0); // NOT overwritten by the stale kFailed grid
        // The run_device grid itself must be immutable too — that's what the deploy
        // cohort reads (get_devices → bucket), not the summary counters (#gov Gate-8).
        auto devs = store.get_devices("pmc2");
        REQUIRE(devs.size() == 1);
        CHECK(devs[0].bucket == "warn"); // NOT "nogo" from the rolled-back stale persist
    }
    SECTION("past_deadline completes even with a pending device") {
        REQUIRE(store.create_run(make_run("pmc3", "alice", t), {tgt("a1")}));
        auto g = mk_grid(preflight::Bucket::kIncomplete);
        CHECK(preflight::persist_and_maybe_complete(store, "pmc3", g, t, /*past_deadline=*/true,
                                                    /*any_pending=*/true));
        CHECK(store.get_run("pmc3")->status == "complete");
    }
}

// #1720 review (ADR-0012 §1): construction must be fail-CLOSED — a reachable
// database whose schema can't migrate leaves the store !is_open(), which
// server.cpp wires to startup_failed_ (refuse to start, not serve-degraded).
// Force the failure by pre-seeding the store's schema with a conflicting table
// and no schema_meta row: the migration runner's drift guard refuses.
TEST_CASE("PreflightRunStore reports !is_open on a migration failure", "[pg][preflight][store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA preflight_run_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE preflight_run_store.runs (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    PreflightRunStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ (fail-closed)
}
