// VulnFindingStore tests (PR 2): the born-on-Postgres CAVM findings + per-agent
// coverage store. Covers the fail-closed ctor, the reconcile sequence
// (upsert-always / authoritative-gated sweep+dispose+coverage), the monotonic
// run_ts / step-back safety, the three-way coverage read, the authoritative
// fleet summary, nullable cvss/fixed_in round-trip, the per-agent advisory-lock
// serialization, whole-batch rollback on a bad row, CHECK enforcement, and the
// SoftwareInventoryStore::list_agent_ids keyset pager. Schema `vuln_finding_store`.
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails if set-but-broken.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"
#include "vuln_finding_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::AgentCoverageCounts;
using yuzu::server::AgentReconcile;
using yuzu::server::CoverageRead;
using yuzu::server::FindingKey;
using yuzu::server::FindingQuery;
using yuzu::server::FindingUpsert;
using yuzu::server::SoftwareEntry;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::VulnFindingStore;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): shared key
// with test_vuln_finding_store_adversarial.cpp (identical setup — first build
// wins). The two migration-idempotency tests stay on plain YUZU_REQUIRE_PG_DB —
// they assert the fresh-database migrate-then-re-open transition itself.
yuzu::test::PgTestTemplate vuln_tpl{"vuln", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore swinv{pool};
    if (!swinv.is_open())
        throw std::runtime_error("vuln template: SoftwareInventoryStore failed to migrate");
    VulnFindingStore vuln{pool};
    if (!vuln.is_open())
        throw std::runtime_error("vuln template: VulnFindingStore failed to migrate");
}};

FindingUpsert mk_finding(const std::string& cve, const std::string& pkg,
                         const std::string& sev = "high", const std::string& status = "potential") {
    FindingUpsert f;
    f.cve_id = cve;
    f.package_name = pkg;
    f.status = status;
    f.package_version = "1.2.3";
    f.ecosystem = "deb";
    f.severity = sev;
    f.cvss = 7.5;
    f.fixed_in = std::string{"1.2.4"};
    f.confidence = "high";
    f.feed_synced_at_ms = 1000;
    return f;
}

AgentReconcile mk_reconcile(const std::string& agent, std::vector<FindingUpsert> findings,
                            bool authoritative, AgentCoverageCounts cov = {}) {
    AgentReconcile r;
    r.agent_id = agent;
    r.findings = std::move(findings);
    r.coverage = cov;
    r.authoritative = authoritative;
    return r;
}

// Fetch a single finding's resolved_at + last_seen via include_resolved, or nullopt if absent.
std::optional<yuzu::server::FindingRow> find_row(VulnFindingStore& s, const std::string& agent,
                                                 const std::string& cve, const std::string& pkg) {
    FindingQuery q;
    q.include_resolved = true;
    for (auto& row : s.query_findings(agent, q))
        if (row.cve_id == cve && row.package_name == pkg)
            return row;
    return std::nullopt;
}

} // namespace

// (1) Fail-closed ctor: a broken pool → !is_open(); a good pool → is_open();
// a second construction over live tables (idempotent migration) → is_open().
TEST_CASE("VulnFindingStore ctor fail-closed + idempotent migration", "[pg][vuln][store]") {
    SECTION("broken pool → !is_open") {
        // Malformed conninfo → pool invalid → acquire() empty → ctor cannot migrate.
        PgPool bad{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
        REQUIRE_FALSE(bad.valid());
        VulnFindingStore store{bad};
        CHECK_FALSE(store.is_open());
    }
    SECTION("good pool → is_open; re-construct is idempotent") {
        // YUZU_REQUIRE_PG_MIGRATION_DB is NOT this TEST_CASE's first
        // statement (unlike every other of the 44 migration-skip sites) —
        // safe ONLY because this is Catch2's LAST SECTION in this
        // TEST_CASE with nothing shared following it: each SECTION gets
        // its own full re-invocation of the TEST_CASE body, so a Windows
        // SKIP here unwinds only THIS invocation (this section never runs
        // on Windows) and never touches the sibling "broken pool" SECTION
        // above, which runs to completion in its own separate invocation
        // either way. If a third SECTION or trailing shared code is ever
        // added to this TEST_CASE, move this macro to guard only itself —
        // do not assume this placement generalizes.
        YUZU_REQUIRE_PG_MIGRATION_DB(db);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        VulnFindingStore s1{pool};
        REQUIRE(s1.is_open());
        VulnFindingStore s2{pool}; // migration already applied → clean re-open
        CHECK(s2.is_open());
    }
}

// (2) insert → re-observe: last_seen_ms bumps, first_seen_ms preserved, still open.
TEST_CASE("VulnFindingStore re-observe bumps last_seen, preserves first_seen", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "openssl")}, true)));
    auto r1 = find_row(store, "a1", "CVE-1", "openssl");
    REQUIRE(r1);
    CHECK_FALSE(r1->resolved_at_ms.has_value());
    const auto first = r1->first_seen_ms;
    const auto last1 = r1->last_seen_ms;

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "openssl")}, true)));
    auto r2 = find_row(store, "a1", "CVE-1", "openssl");
    REQUIRE(r2);
    CHECK(r2->first_seen_ms == first);   // insert-only
    CHECK(r2->last_seen_ms > last1);     // bumped by the monotonic run_ts
    CHECK_FALSE(r2->resolved_at_ms.has_value());
}

// (3) disappear → authoritative sweep resolves; open query excludes it.
TEST_CASE("VulnFindingStore authoritative sweep resolves disappeared findings", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "openssl"), mk_finding("CVE-2", "curl")}, true)));
    // Second authoritative pass observes only CVE-1 → CVE-2 disappeared → swept.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "openssl")}, true)));

    auto open = store.query_findings("a1"); // open-only
    REQUIRE(open.size() == 1);
    CHECK(open[0].cve_id == "CVE-1");

    auto gone = find_row(store, "a1", "CVE-2", "curl");
    REQUIRE(gone);
    CHECK(gone->resolved_at_ms.has_value()); // resolved at the sweep run_ts
}

// (4) authoritative=false → NO resolve AND NO coverage clobber (the B1 guard).
TEST_CASE("VulnFindingStore non-authoritative preserves findings and coverage", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 100;
    cov.potential = 5;
    std::vector<FindingUpsert> five = {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2"),
                                       mk_finding("CVE-3", "p3"), mk_finding("CVE-4", "p4"),
                                       mk_finding("CVE-5", "p5")};
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", five, /*authoritative=*/true, cov)));
    CHECK(store.query_findings("a1").size() == 5);

    // A suspect/partial pass with EMPTY findings must NOT resolve anything and must
    // NOT clobber coverage to zero.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, /*authoritative=*/false)));

    CHECK(store.query_findings("a1").size() == 5); // nothing swept
    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 100); // unchanged
    CHECK(cr.row.potential == 5);
}

// (5) re-observe clears resolved_at_ms.
TEST_CASE("VulnFindingStore re-observe clears resolved_at", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, true))); // sweep resolves CVE-1
    auto resolved = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(resolved);
    REQUIRE(resolved->resolved_at_ms.has_value());

    // It reappears → upsert clears resolved_at.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
    auto reopened = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(reopened);
    CHECK_FALSE(reopened->resolved_at_ms.has_value());
    CHECK(store.query_findings("a1").size() == 1); // open again
}

// (6) status upgrade in place (potential → vulnerable): one row, first_seen kept.
TEST_CASE("VulnFindingStore status upgrade in place", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1", "high", "potential")}, true)));
    auto before = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(before);
    const auto first = before->first_seen_ms;

    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1", "high", "vulnerable")}, true)));
    auto rows = store.query_findings("a1");
    REQUIRE(rows.size() == 1); // no duplicate PK row
    CHECK(rows[0].status == "vulnerable");
    CHECK(rows[0].first_seen_ms == first); // preserved
}

// (7) disposed_clean DELETE ≠ resolve; authoritative=false skips the delete.
TEST_CASE("VulnFindingStore disposed_clean deletes (authoritative only)", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));

    // authoritative=false with the tuple in disposed_clean → NOT deleted.
    {
        AgentReconcile r = mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, /*authoritative=*/false);
        r.disposed_clean = {FindingKey{"CVE-1", "p1"}};
        REQUIRE(store.reconcile_agent(r));
        CHECK(find_row(store, "a1", "CVE-1", "p1").has_value()); // still present
    }
    // authoritative=true with disposed_clean → the tuple is DELETED (not resolved).
    {
        AgentReconcile r = mk_reconcile("a1", {}, /*authoritative=*/true);
        r.disposed_clean = {FindingKey{"CVE-1", "p1"}};
        REQUIRE(store.reconcile_agent(r));
        CHECK_FALSE(find_row(store, "a1", "CVE-1", "p1").has_value()); // gone entirely
    }
}

// (8) coverage counts + all na_* reason counters round-trip.
TEST_CASE("VulnFindingStore coverage counters round-trip", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.feed_synced_at_ms = 424242;
    cov.total_packages = 200;
    cov.potential = 7;
    cov.vulnerable = 3;
    cov.assessed_clean = 150;
    cov.not_assessed = 40;
    cov.na_no_identity = 11;
    cov.na_no_version = 12;
    cov.na_absent = 13;
    cov.na_os_native = 14;
    cov.na_low_confidence = 15;
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, true, cov)));

    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.feed_synced_at_ms == 424242);
    CHECK(cr.row.total_packages == 200);
    CHECK(cr.row.potential == 7);
    CHECK(cr.row.vulnerable == 3);
    CHECK(cr.row.assessed_clean == 150);
    CHECK(cr.row.not_assessed == 40);
    CHECK(cr.row.na_no_identity == 11);
    CHECK(cr.row.na_no_version == 12);
    CHECK(cr.row.na_absent == 13);
    CHECK(cr.row.na_os_native == 14);
    CHECK(cr.row.na_low_confidence == 15);
    CHECK(cr.row.last_run_at_ms > 0); // derived run_ts persisted
}

// (9) fleet_summary aggregates across agents and EXCLUDES resolved rows.
TEST_CASE("VulnFindingStore fleet_summary aggregates, excludes resolved", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cA;
    cA.total_packages = 100;
    cA.potential = 2;
    cA.vulnerable = 1;
    AgentCoverageCounts cB;
    cB.total_packages = 50;
    cB.potential = 1;
    cB.vulnerable = 0;
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1", "critical"), mk_finding("CVE-2", "p2", "high")}, true, cA)));
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a2", {mk_finding("CVE-3", "p3", "high")}, true, cB)));
    // Resolve CVE-2 on a1 (disappears) so it must NOT count in open_findings.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1", "critical")}, true, cA)));

    auto sum = store.fleet_summary();
    REQUIRE(sum.has_value());
    CHECK(sum->agent_count == 2);
    CHECK(sum->total_packages == 150);
    CHECK(sum->potential_packages == 3);
    CHECK(sum->vulnerable_packages == 1);
    CHECK(sum->open_findings == 2);  // CVE-1 (a1) + CVE-3 (a2); CVE-2 resolved, excluded
    CHECK(sum->critical_open == 1);  // CVE-1
    CHECK(sum->high_open == 1);      // CVE-3
}

// (10) cvss/fixed_in NULL round-trip (nullopt, not 0.0/"").
TEST_CASE("VulnFindingStore cvss/fixed_in NULL round-trip", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    FindingUpsert f = mk_finding("CVE-1", "p1");
    f.cvss = std::nullopt;
    f.fixed_in = std::nullopt;
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));

    auto row = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(row);
    CHECK_FALSE(row->cvss.has_value());     // SQL NULL, not 0.0
    CHECK_FALSE(row->fixed_in.has_value()); // SQL NULL, not ""

    // And a set value round-trips too.
    FindingUpsert g = mk_finding("CVE-2", "p2");
    g.cvss = 9.8;
    g.fixed_in = std::string{"2.0.0"};
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1"), g}, true)));
    auto row2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(row2);
    REQUIRE(row2->cvss.has_value());
    CHECK(row2->cvss.value() == 9.8);
    REQUIRE(row2->fixed_in.has_value());
    CHECK(row2->fixed_in.value() == "2.0.0");
}

// (11) get_agent_coverage tri-state: Ok / NotFound / Degraded.
TEST_CASE("VulnFindingStore get_agent_coverage tri-state", "[pg][vuln][store]") {
    SECTION("Ok vs NotFound") {
        YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        VulnFindingStore store{pool};
        REQUIRE(store.is_open());
        AgentCoverageCounts cov;
        cov.total_packages = 10;
        REQUIRE(store.reconcile_agent(mk_reconcile("known", {}, true, cov)));

        CHECK(store.get_agent_coverage("known").status == CoverageRead::Status::Ok);
        CHECK(store.get_agent_coverage("never-seen").status == CoverageRead::Status::NotFound);
    }
    SECTION("Degraded on a closed store") {
        PgPool bad{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
        REQUIRE_FALSE(bad.valid());
        VulnFindingStore store{bad};
        REQUIRE_FALSE(store.is_open());
        CHECK(store.get_agent_coverage("x").status == CoverageRead::Status::Degraded);
    }
}

// (12) concurrency: two overlapping same-agent reconciles serialize via the
// advisory lock — no phantom resolve of a freshly-observed row.
TEST_CASE("VulnFindingStore concurrent same-agent reconciles serialize", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Both threads authoritatively re-observe the SAME finding. With the advisory
    // lock + monotonic run_ts, neither pass sweeps the other's just-observed row.
    std::atomic<int> ok{0};
    auto body = [&] {
        for (int i = 0; i < 10; ++i)
            if (store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "openssl")}, true)))
                ok.fetch_add(1, std::memory_order_relaxed);
    };
    std::thread t1(body), t2(body);
    t1.join();
    t2.join();
    CHECK(ok.load() == 20); // no deadlock, every pass committed

    // CVE-1 was observed by every pass → it must still be OPEN (never phantom-resolved).
    auto open = store.query_findings("a1");
    REQUIRE(open.size() == 1);
    CHECK(open[0].cve_id == "CVE-1");
    CHECK_FALSE(open[0].resolved_at_ms.has_value());
}

// (13) partial mid-loop failure → whole-batch rollback (zero findings persisted).
TEST_CASE("VulnFindingStore bad row rolls the whole batch back", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // A valid finding followed by one with an out-of-vocab status (CHECK violation).
    FindingUpsert bad = mk_finding("CVE-2", "p2");
    bad.status = "bogus"; // not in ('potential','vulnerable') → CHECK fails
    CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1"), bad}, true)));

    // The whole txn rolled back: even the valid CVE-1 is absent.
    FindingQuery q;
    q.include_resolved = true;
    CHECK(store.query_findings("a1", q).empty());
}

// (14) migration idempotency (construct twice on the same DB).
TEST_CASE("VulnFindingStore migration is idempotent", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore a{pool};
    REQUIRE(a.is_open());
    VulnFindingStore b{pool};
    REQUIRE(b.is_open());
    // Both usable against the same schema.
    CHECK(b.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
}

// (15) CHECK enforcement vs severity normalization: bad status/confidence roll
// back; a bad severity is NORMALIZED to 'unknown' (not rejected).
TEST_CASE("VulnFindingStore CHECK enforcement vs severity normalization", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    SECTION("bad status → rollback") {
        FindingUpsert f = mk_finding("CVE-1", "p1");
        f.status = "weird";
        CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        CHECK(store.query_findings("a1").empty());
    }
    SECTION("bad confidence → rollback") {
        FindingUpsert f = mk_finding("CVE-1", "p1");
        f.confidence = "medium"; // vocab is only high|low
        CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        CHECK(store.query_findings("a1").empty());
    }
    SECTION("bad severity is normalized to 'unknown', not rejected") {
        FindingUpsert f = mk_finding("CVE-1", "p1", "SUPER_BAD");
        CHECK(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-1", "p1");
        REQUIRE(row);
        CHECK(row->severity == "unknown");
    }
}

// (16) ms-collision / step-back: a future stored last_run_at_ms still yields a
// strictly greater run_ts, so the sweep fires — no missed resolve (S4).
TEST_CASE("VulnFindingStore monotonic run_ts survives a clock step-back", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed a finding + coverage row.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));

    // Force the stored last_run_at_ms 10 minutes into the FUTURE (simulate a pass
    // that ran while the clock was skewed ahead).
    const std::int64_t future = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count() +
                                600000;
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        yuzu::server::pg::PgResult upd = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE vuln_finding_store.agent_coverage SET last_run_at_ms = $2::bigint "
            "WHERE agent_id = $1",
            std::vector<std::string>{"a1", std::to_string(future)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Reconcile at real-now with EMPTY findings. run_ts = max(now, future+1) = future+1,
    // strictly greater than CVE-1's last_seen_ms → the sweep still resolves it.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, true)));
    CHECK(store.query_findings("a1").empty()); // CVE-1 swept, none open
    auto resolved = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(resolved);
    REQUIRE(resolved->resolved_at_ms.has_value());
    CHECK(resolved->resolved_at_ms.value() > future); // resolved at the monotonic run_ts
}

// (17) SoftwareInventoryStore::list_agent_ids keyset paging returns all, no dupes.
TEST_CASE("SoftwareInventoryStore list_agent_ids keyset pages the fleet", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // Seed 25 agents each with one installed_software row (creates inventory_state).
    const int kAgents = 25;
    for (int i = 0; i < kAgents; ++i) {
        char id[16];
        std::snprintf(id, sizeof(id), "agent-%02d", i);
        std::vector<SoftwareEntry> rows(1);
        rows[0].name = "pkg";
        rows[0].version = "1.0";
        REQUIRE(store.apply_installed_software(id, "", std::move(rows), 0) ==
                yuzu::server::InventoryIngestOutcome::kStored);
    }

    // Page through in windows of 10 with keyset (after_id = last of the prior page).
    std::vector<std::string> all;
    std::string after;
    for (;;) {
        auto page = store.list_agent_ids("installed_software", after, 10);
        if (page.empty())
            break;
        for (const auto& a : page)
            all.push_back(a);
        after = page.back();
        if (static_cast<int>(page.size()) < 10)
            break; // short page → done
    }
    CHECK(static_cast<int>(all.size()) == kAgents);
    // Ascending + unique (no dupes across page boundaries).
    for (std::size_t i = 1; i < all.size(); ++i)
        CHECK(all[i - 1] < all[i]);
}

// (19) FIX 2: a non-finite cvss (NaN / +Inf) persists as SQL NULL, NOT a batch
// abort. std::to_string(NaN) would emit "nan" → PG 22P02 → the whole reconcile
// rolls back every pass; the finite-guard binds NULL instead (cvss is optional).
TEST_CASE("VulnFindingStore non-finite cvss persists as NULL, not a batch abort", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    SECTION("NaN cvss → NULL, sibling finite value survives") {
        FindingUpsert nan_f = mk_finding("CVE-NAN", "p1");
        nan_f.cvss = std::numeric_limits<double>::quiet_NaN();
        FindingUpsert good = mk_finding("CVE-OK", "p2");
        good.cvss = 6.4;
        // The whole batch must COMMIT (no 22P02 abort) with the NaN row's cvss NULL.
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {nan_f, good}, true)));
        auto rn = find_row(store, "a1", "CVE-NAN", "p1");
        REQUIRE(rn);
        CHECK_FALSE(rn->cvss.has_value()); // NaN → SQL NULL
        auto rg = find_row(store, "a1", "CVE-OK", "p2");
        REQUIRE(rg);
        REQUIRE(rg->cvss.has_value());
        CHECK(rg->cvss.value() == 6.4);
    }
    SECTION("+Inf cvss → NULL") {
        FindingUpsert inf_f = mk_finding("CVE-INF", "p3");
        inf_f.cvss = std::numeric_limits<double>::infinity();
        REQUIRE(store.reconcile_agent(mk_reconcile("a2", {inf_f}, true)));
        auto ri = find_row(store, "a2", "CVE-INF", "p3");
        REQUIRE(ri);
        CHECK_FALSE(ri->cvss.has_value());
    }
}

// (20) FIX 6: a mixed-case severity/status filter matches the canonically-stored
// (normalized) value — "HIGH" must return the 'high' rows, not empty.
TEST_CASE("VulnFindingStore query filter normalizes severity/status case", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1",
        {mk_finding("CVE-1", "p1", "high", "vulnerable"), mk_finding("CVE-2", "p2", "critical", "potential")},
        true)));

    SECTION("mixed-case severity 'HIGH' matches the stored 'high' row") {
        FindingQuery q;
        q.severity = std::string{"HIGH"};
        auto rows = store.query_findings("a1", q);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].cve_id == "CVE-1");
        CHECK(rows[0].severity == "high");
    }
    SECTION("padded + mixed-case severity ' Critical ' matches 'critical'") {
        FindingQuery q;
        q.severity = std::string{" Critical "};
        auto rows = store.query_findings("a1", q);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].cve_id == "CVE-2");
    }
    SECTION("mixed-case status 'Vulnerable' matches the stored 'vulnerable' row") {
        FindingQuery q;
        q.status = std::string{"Vulnerable"};
        auto rows = store.query_findings("a1", q);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].cve_id == "CVE-1");
    }
}

// (18) delete_agent removes both tables.
TEST_CASE("VulnFindingStore delete_agent clears findings and coverage", "[pg][vuln][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 42;
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true, cov)));
    REQUIRE(store.query_findings("a1").size() == 1);
    REQUIRE(store.get_agent_coverage("a1").status == CoverageRead::Status::Ok);

    store.delete_agent("a1");

    CHECK(store.query_findings("a1").empty());
    CHECK(store.get_agent_coverage("a1").status == CoverageRead::Status::NotFound);
}
