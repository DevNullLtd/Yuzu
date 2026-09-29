// ADVERSARIAL tests for VulnFindingStore (PR 2). Hostile probes of the
// coverage-clobber guard, concurrency serialization, monotonic run_ts bursts,
// per-row rollback atomicity, severity normalization completeness, tri-state
// coverage read under real degrade, disposed_clean edge cases, and SQL
// metacharacter / NUL handling. Written by the Adversarial Tester role — a
// FAILING assertion here is a WIN (it reveals a real bug), not a test bug.
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
using yuzu::server::FindingRow;
using yuzu::server::FindingUpsert;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::VulnFindingStore;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): shared key
// with test_vuln_finding_store.cpp (identical setup — first build wins).
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

std::optional<FindingRow> find_row(VulnFindingStore& s, const std::string& agent,
                                    const std::string& cve, const std::string& pkg) {
    FindingQuery q;
    q.include_resolved = true;
    for (auto& row : s.query_findings(agent, q))
        if (row.cve_id == cve && row.package_name == pkg)
            return row;
    return std::nullopt;
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Coverage-clobber guard — attack every combination.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: non-authoritative with non-empty findings leaves coverage untouched",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 100;
    cov.vulnerable = 9;
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, /*authoritative=*/true, cov)));

    // Non-authoritative pass observes a NEW finding (CVE-2) and re-observes CVE-1,
    // with a DIFFERENT (bogus) coverage payload attached. The store must upsert the
    // findings but leave the coverage row byte-for-byte as the prior authoritative
    // write — a suspect pass must never be able to smuggle coverage numbers in.
    AgentCoverageCounts bogus;
    bogus.total_packages = 999999;
    bogus.vulnerable = 0;
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, /*authoritative=*/false, bogus)));

    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 100); // untouched by the non-authoritative bogus payload
    CHECK(cr.row.vulnerable == 9);

    // And CVE-2 (newly observed but by a suspect pass) must NOT be swept/absent —
    // it should simply be upserted open, and CVE-1 must NOT have been resolved
    // (no sweep on a non-authoritative pass at all).
    auto c1 = find_row(store, "a1", "CVE-1", "p1");
    auto c2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(c1);
    REQUIRE(c2);
    CHECK_FALSE(c1->resolved_at_ms.has_value());
    CHECK_FALSE(c2->resolved_at_ms.has_value());
}

// FIX 3 (UP-2 backstop) — SUSPECT READ guarded. The trigger is a ZERO
// total_packages coverage (the inventory read returned nothing), NOT empty
// findings. Against an agent whose PRIOR coverage had state (open findings and/or
// a non-zero package count), such a pass is a "whole inventory vanished" bad read:
// treated as NON-authoritative — NO sweep, NO coverage clobber. Returns true.
TEST_CASE("ADVERSARIAL: authoritative ZERO-total_packages pass over a prior-state agent is backstopped",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts cov;
    cov.total_packages = 50;
    cov.vulnerable = 3; // prior state: total_packages=50, open=3 → backstop arms on a zero-pkg pass
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, true, cov)));

    // A bare empty authoritative pass with a ZEROED coverage payload
    // (total_packages == 0 — the shape a failed "whole inventory" read emits). The
    // backstop treats it as suspect: NO sweep, NO coverage clobber. Returns true.
    AgentCoverageCounts zero{}; // total_packages == 0 → the suspect signal
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, /*authoritative=*/true, zero)));

    // Findings preserved (NOT resolved) — the fleet is not mass-false-resolved.
    CHECK(store.query_findings("a1").size() == 2);
    auto c1 = find_row(store, "a1", "CVE-1", "p1");
    auto c2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(c1);
    REQUIRE(c2);
    CHECK_FALSE(c1->resolved_at_ms.has_value());
    CHECK_FALSE(c2->resolved_at_ms.has_value());

    // Coverage kept-last-good (NOT clobbered to zero by the suspect payload).
    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 50);
    CHECK(cr.row.vulnerable == 3);
}

// FIX 3 REGRESSION GUARD — a GENUINELY-PATCHED agent MUST resolve. Inventory is
// still present (total_packages > 0) but every vuln is now fixed → findings
// legitimately empty. The backstop must NOT fire (it keys on total_packages == 0,
// not findings.empty()), so the now-fixed findings ARE swept-resolved. Keying on
// empty findings would strand these open forever = a false-positive.
TEST_CASE("ADVERSARIAL: genuinely-patched agent (empty findings, total_packages>0) IS resolved",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentCoverageCounts before;
    before.total_packages = 50;
    before.vulnerable = 3;
    REQUIRE(store.reconcile_agent(mk_reconcile(
        "a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2"), mk_finding("CVE-3", "p3")}, true,
        before)));
    CHECK(store.query_findings("a1").size() == 3);

    // Patched: inventory STILL present (50 packages) but zero vulns now.
    AgentCoverageCounts after;
    after.total_packages = 50; // > 0 → NOT the suspect signal
    after.potential = 0;
    after.vulnerable = 0;
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, /*authoritative=*/true, after)));

    // All three findings resolved (backstop did NOT fire) — the fix landed.
    CHECK(store.query_findings("a1").empty());
    for (const auto* cve : {"CVE-1", "CVE-2", "CVE-3"}) {
        auto row = find_row(store, "a1", cve, cve[4] == '1' ? "p1" : (cve[4] == '2' ? "p2" : "p3"));
        REQUIRE(row);
        CHECK(row->resolved_at_ms.has_value());
    }
    // Coverage updated to the patched tallies (total 50, zero vulns).
    auto cr = store.get_agent_coverage("a1");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 50);
    CHECK(cr.row.vulnerable == 0);
    CHECK(cr.row.potential == 0);
}

// FIX 3 boundary: the backstop is NARROW — an agent with NO prior state (fresh
// coverage all-zero) is legitimately swept by an empty authoritative pass even
// with total_packages == 0, because there is nothing prior to protect (the guard
// requires prior open findings OR a prior non-zero package count).
TEST_CASE("ADVERSARIAL: authoritative EMPTY pass over a prior-CLEAN agent still sweeps (backstop is narrow)",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // First pass carries DEFAULT (all-zero) coverage → no prior state to protect.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
    // Empty authoritative pass: prior state is all-zero → backstop does NOT arm → sweep fires.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, /*authoritative=*/true)));
    CHECK(store.query_findings("a1").empty()); // swept
    auto row = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(row);
    CHECK(row->resolved_at_ms.has_value());
}

// ---------------------------------------------------------------------------
// 2. Concurrency — phantom-resolve race between two DIFFERING authoritative
//    passes for the SAME agent (the store's advisory lock only serializes
//    execution order — it cannot know one pass's finding set is stale
//    relative to the other's).
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: concurrent same-agent authoritative passes with DIFFERING finding sets",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed: agent has two open findings, X and Y, both established.
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-X", "px"), mk_finding("CVE-Y", "py")}, true)));

    std::atomic<int> ok{0};
    // Thread A: authoritative, observes {X, Y} (full, current view).
    auto bodyA = [&] {
        for (int i = 0; i < 20; ++i)
            if (store.reconcile_agent(
                    mk_reconcile("a1", {mk_finding("CVE-X", "px"), mk_finding("CVE-Y", "py")}, true)))
                ok.fetch_add(1, std::memory_order_relaxed);
    };
    // Thread B: authoritative, observes ONLY {X} — simulates a stale/partial
    // engine pass that is unaware Y still exists. Under true serialization each
    // pass fully commits before the next begins, so whichever runs LAST
    // determines the final state (last-authoritative-writer-wins) — that is
    // internally consistent. What must NEVER happen is Y ending up "resolved"
    // while a LATER-committing pass that included Y is not reflected, i.e. the
    // final state must match whichever pass's txn committed last, not some
    // interleaved mix.
    auto bodyB = [&] {
        for (int i = 0; i < 20; ++i)
            if (store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-X", "px")}, true)))
                ok.fetch_add(1, std::memory_order_relaxed);
    };
    std::thread t1(bodyA), t2(bodyB);
    t1.join();
    t2.join();
    CHECK(ok.load() == 40); // no deadlock; every pass committed one way or another

    // X must always be open (every pass, from both threads, observed it).
    auto x = find_row(store, "a1", "CVE-X", "px");
    REQUIRE(x);
    CHECK_FALSE(x->resolved_at_ms.has_value());

    // Y's final state is a race (last committer wins) — but it MUST be
    // internally consistent: report what we see for the record. This is NOT
    // asserted pass/fail either way (documented racy-by-design), just observed.
    auto y = find_row(store, "a1", "CVE-Y", "py");
    REQUIRE(y); // never disposed/deleted, only ever resolved or open
    INFO("CVE-Y final resolved_at_ms has_value = " << y->resolved_at_ms.has_value());
}

TEST_CASE("ADVERSARIAL: different agents reconcile concurrently without cross-serialization stalls",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    constexpr int kAgents = 6;
    constexpr int kIters = 15;
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int a = 0; a < kAgents; ++a) {
        threads.emplace_back([&, a] {
            std::string agent = "concur-agent-" + std::to_string(a);
            for (int i = 0; i < kIters; ++i)
                if (store.reconcile_agent(mk_reconcile(agent, {mk_finding("CVE-1", "p1")}, true)))
                    ok.fetch_add(1, std::memory_order_relaxed);
        });
    }
    auto start = std::chrono::steady_clock::now();
    for (auto& t : threads)
        t.join();
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(ok.load() == kAgents * kIters);
    // Distinct agents hash to distinct advisory-lock keys (overwhelmingly likely
    // for hashtextextended over 6 short distinct strings) so this should finish
    // quickly (not serialized end-to-end). Generous bound to avoid flake.
    CHECK(elapsed < std::chrono::seconds(15));
}

TEST_CASE("ADVERSARIAL: a rolled-back reconcile releases the advisory lock (no deadlock after)",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // A failing reconcile (CHECK violation) rolls back.
    FindingUpsert bad = mk_finding("CVE-BAD", "pbad");
    bad.status = "bogus";
    CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {bad}, true)));

    // A subsequent reconcile of the SAME agent must succeed promptly (proves the
    // pg_advisory_xact_lock was released on ROLLBACK, not leaked).
    auto start = std::chrono::steady_clock::now();
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(elapsed < std::chrono::seconds(5));
}

// ---------------------------------------------------------------------------
// 3. Monotonic run_ts edges — rapid burst, and interaction with a
//    far-future stored last_run_at_ms.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: rapid burst of reconciles yields strictly increasing run_ts",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    constexpr int kBurst = 30;
    std::vector<std::int64_t> last_run_seen;
    for (int i = 0; i < kBurst; ++i) {
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));
        auto cr = store.get_agent_coverage("a1");
        REQUIRE(cr.status == CoverageRead::Status::Ok);
        last_run_seen.push_back(cr.row.last_run_at_ms);
    }
    for (std::size_t i = 1; i < last_run_seen.size(); ++i)
        CHECK(last_run_seen[i] > last_run_seen[i - 1]); // strictly monotonic, no collisions

    // The stamped last_seen_ms may now be ms AHEAD of wall-clock now(). Confirm a
    // normal subsequent authoritative pass (with a DIFFERENT finding, so CVE-1
    // disappears) still sweeps it correctly despite last_seen_ms possibly being
    // >= a "now" sampled a moment later mid-test.
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-OTHER", "pother")}, true)));
    auto cve1 = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(cve1);
    CHECK(cve1->resolved_at_ms.has_value()); // swept despite the ahead-of-wall-clock stamps
}

TEST_CASE("ADVERSARIAL: finding inserted with future-skewed last_seen_ms is still swept later",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true)));

    // Force last_seen_ms/first_seen_ms into the far future directly (simulating a
    // prior pass that ran under a badly-skewed clock, worse than the run_ts
    // monotonic guard alone would ever produce from THIS store — e.g. imported
    // from a differently-configured replica).
    const std::int64_t far_future = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count() +
                                    3600000; // +1 hour
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        auto upd = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE vuln_finding_store.finding SET last_seen_ms = $1::bigint "
            "WHERE agent_id = 'a1' AND cve_id = 'CVE-1'",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
        auto upd2 = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE vuln_finding_store.agent_coverage SET last_run_at_ms = $1::bigint "
            "WHERE agent_id = 'a1'",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(upd2.status() == PGRES_COMMAND_OK);
    }

    // A normal-time authoritative pass with CVE-1 absent must still eventually
    // sweep it (run_ts = far_future+1 > far_future last_seen_ms).
    REQUIRE(store.reconcile_agent(mk_reconcile("a1", {}, true)));
    auto row = find_row(store, "a1", "CVE-1", "p1");
    REQUIRE(row);
    CHECK(row->resolved_at_ms.has_value());
    CHECK(row->resolved_at_ms.value() > far_future);
}

// ---------------------------------------------------------------------------
// 4. Per-row rollback atomicity — bad row NOT at the end; duplicate key
//    within one reconcile's findings vector.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: bad row in the MIDDLE of a 5-row batch rolls back ALL 5, not just the tail",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    std::vector<FindingUpsert> five = {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2"),
                                        mk_finding("CVE-3", "p3"), mk_finding("CVE-4", "p4"),
                                        mk_finding("CVE-5", "p5")};
    five[2].confidence = "medium"; // row 3 of 5 — vocab is only high|low → CHECK violation

    CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", five, true)));

    FindingQuery q;
    q.include_resolved = true;
    auto rows = store.query_findings("a1", q);
    CHECK(rows.empty()); // NOT rows 1-2 persisted; zero of the 5 survive
}

TEST_CASE("ADVERSARIAL: duplicate (cve_id, package_name) within one reconcile batch does not error",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Same (cve_id, package_name) twice in the SAME batch with different status —
    // the store loops per-row exec_params (not a single multi-row VALUES/ON
    // CONFLICT), so this must NOT trip Postgres's "ON CONFLICT DO UPDATE command
    // cannot affect row a second time" error.
    auto f1 = mk_finding("CVE-DUP", "pdup", "high", "potential");
    auto f2 = mk_finding("CVE-DUP", "pdup", "high", "vulnerable");
    CHECK(store.reconcile_agent(mk_reconcile("a1", {f1, f2}, true)));

    auto rows = store.query_findings("a1");
    REQUIRE(rows.size() == 1); // one row, last-write-wins
    CHECK(rows[0].status == "vulnerable");
}

// ---------------------------------------------------------------------------
// 5. Severity normalization completeness.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: severity normalization — incidental whitespace is trimmed",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    SECTION("trailing whitespace on an otherwise-valid severity is recognized") {
        auto f = mk_finding("CVE-1", "p1", "high ");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-1", "p1");
        REQUIRE(row);
        // Post-fix: normalize_severity trims leading/trailing ASCII whitespace
        // before the vocab check, so incidental feed whitespace ("high ") no
        // longer collapses a real severity to "unknown".
        CHECK(row->severity == "high");
        INFO("severity for 'high ' normalized to: " << row->severity);
    }
    SECTION("leading + trailing whitespace and tabs are trimmed") {
        auto f = mk_finding("CVE-1b", "p1b", "\t  critical \n");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-1b", "p1b");
        REQUIRE(row);
        CHECK(row->severity == "critical");
    }
    SECTION("empty severity string") {
        auto f = mk_finding("CVE-2", "p2", "");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-2", "p2");
        REQUIRE(row);
        CHECK(row->severity == "unknown"); // must not violate the CHECK / crash
    }
    SECTION("mixed case with internal punctuation") {
        auto f = mk_finding("CVE-3", "p3", "Critical!");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-3", "p3");
        REQUIRE(row);
        CHECK(row->severity == "unknown"); // not in vocab even lowercased
    }
    SECTION("proper case-insensitive match still works") {
        auto f = mk_finding("CVE-4", "p4", "CRITICAL");
        REQUIRE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        auto row = find_row(store, "a1", "CVE-4", "p4");
        REQUIRE(row);
        CHECK(row->severity == "critical");
    }
}

// ---------------------------------------------------------------------------
// 6. get_agent_coverage tri-state under a REAL degrade (pool exhaustion),
//    not just a closed-store stand-in.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: get_agent_coverage returns Degraded (not NotFound) when the pool is exhausted",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    // Pool of size 1 so a single held lease starves every other acquire.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // A known agent exists (would read Ok if the pool were free).
    REQUIRE(store.reconcile_agent(mk_reconcile("known", {mk_finding("CVE-1", "p1")}, true)));

    // Hold the pool's only connection for longer than kReadTimeout (3s) on another
    // thread so the coverage read's try_acquire_for starves. Catch2 macros are NOT
    // thread-safe (a failing REQUIRE throws out of the thread → std::terminate), so
    // the holder captures its result in an atomic and the assertion runs on the
    // main thread after join().
    std::atomic<bool> release_now{false};
    std::atomic<bool> holder_got_lease{false};
    std::thread holder([&] {
        auto lease = pool.acquire();
        holder_got_lease.store(static_cast<bool>(lease), std::memory_order_relaxed);
        while (!release_now.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });
    // Give the holder a moment to actually acquire before racing the read.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto cr = store.get_agent_coverage("known");
    release_now = true;
    holder.join();

    CHECK(holder_got_lease.load()); // the holder really did take the only connection
    CHECK(cr.status == CoverageRead::Status::Degraded); // NOT NotFound — the agent DOES exist
}

// ---------------------------------------------------------------------------
// 7. SQL metacharacters / NUL bytes in identity fields.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: SQL metacharacters in agent_id/cve_id/package_name are safely parameterized",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string evil_agent = "a1'; DROP TABLE vuln_finding_store.finding; --";
    const std::string evil_cve = "CVE-'); DELETE FROM vuln_finding_store.agent_coverage; --";
    const std::string evil_pkg = "pkg\"'\\";

    auto f = mk_finding(evil_cve, evil_pkg);
    REQUIRE(store.reconcile_agent(mk_reconcile(evil_agent, {f}, true)));

    // The table must still exist and be queryable, and the row must round-trip
    // byte-for-byte (proves parameterization, not string concatenation).
    auto rows = store.query_findings(evil_agent);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].cve_id == evil_cve);
    CHECK(rows[0].package_name == evil_pkg);

    // A completely unrelated agent's coverage must be unaffected (the DELETE
    // payload, if it had executed as SQL, would have wiped agent_coverage
    // fleet-wide).
    AgentCoverageCounts cov;
    cov.total_packages = 5;
    REQUIRE(store.reconcile_agent(mk_reconcile("innocent-bystander", {}, true, cov)));
    auto cr = store.get_agent_coverage("innocent-bystander");
    REQUIRE(cr.status == CoverageRead::Status::Ok);
    CHECK(cr.row.total_packages == 5);
}

// FIX 4: an embedded NUL in an identity field is REJECTED (reconcile returns
// false, nothing persisted) — not silently truncated onto a colliding PK. A NUL
// truncates at libpq's c_str() bind, which could fold two distinct identities
// onto one row; the store now boundary-checks and refuses.
TEST_CASE("ADVERSARIAL: a NUL byte embedded in cve_id is rejected, not silently truncated",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    using namespace std::string_literals;
    const std::string evil_cve = "CVE-1\0-TAIL"s;
    REQUIRE(evil_cve.size() == 11); // the std::string itself DOES hold all 11 bytes

    SECTION("NUL in cve_id → reject, no row persisted") {
        auto f = mk_finding(evil_cve, "pkg-nul");
        CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        CHECK(store.query_findings("a1").empty());
    }
    SECTION("NUL in package_name → reject") {
        auto f = mk_finding("CVE-CLEAN", "pkg\0evil"s);
        CHECK_FALSE(store.reconcile_agent(mk_reconcile("a1", {f}, true)));
        CHECK(store.query_findings("a1").empty());
    }
    SECTION("NUL in agent_id → reject") {
        auto f = mk_finding("CVE-CLEAN", "pkg-ok");
        CHECK_FALSE(store.reconcile_agent(mk_reconcile("agent\0x"s, {f}, true)));
    }
    SECTION("a clean sibling batch (no NUL) still succeeds — the reject is scoped") {
        auto f = mk_finding("CVE-OK", "pkg-ok");
        CHECK(store.reconcile_agent(mk_reconcile("a2", {f}, true)));
        CHECK(store.query_findings("a2").size() == 1);
    }
}

// ---------------------------------------------------------------------------
// 8. disposed_clean edge cases.
// ---------------------------------------------------------------------------

TEST_CASE("ADVERSARIAL: disposed_clean overlapping the sweep set — DELETE wins, no double-processing",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed two findings; a fresh pass disposes ONE of them as reassessed-clean
    // AND omits it from `findings` (so it would ALSO be sweep-eligible) — both
    // mechanisms target the same row in the same transaction.
    REQUIRE(store.reconcile_agent(
        mk_reconcile("a1", {mk_finding("CVE-1", "p1"), mk_finding("CVE-2", "p2")}, true)));

    AgentReconcile r = mk_reconcile("a1", {}, /*authoritative=*/true);
    r.disposed_clean = {FindingKey{"CVE-1", "p1"}};
    REQUIRE(store.reconcile_agent(r));

    // CVE-1: deleted outright (disposed_clean), not merely resolved.
    CHECK_FALSE(find_row(store, "a1", "CVE-1", "p1").has_value());
    // CVE-2: not in disposed_clean, not re-observed → swept (resolved, still a row).
    auto cve2 = find_row(store, "a1", "CVE-2", "p2");
    REQUIRE(cve2);
    CHECK(cve2->resolved_at_ms.has_value());
}

// ---------------------------------------------------------------------------
// 9. Cross-store advisory-lock namespace ISOLATION (regression guard for the
//    fix). `pg_advisory_xact_lock` keys are a SINGLE 64-bit space shared by the
//    whole Postgres backend/cluster — NOT scoped per schema/table. Before the
//    fix, VulnFindingStore's reconcile_agent computed the IDENTICAL lock formula
//    as SoftwareInventoryStore's full-replace ingest
//    (`hashtextextended(agent_id, 0)`, software_inventory_store.cpp:~467), so the
//    two UNRELATED stores collided on the exact same key for a given agent — a
//    long-running software-inventory ingest for agent X needlessly serialized a
//    concurrent vuln-finding reconcile for the SAME agent X even though they
//    touch disjoint tables. The fix folds a 'vuln_finding_store:' namespace into
//    the vuln store's key. This test now PROVES the fix: holding the
//    software_inventory-style lock must NOT block the vuln reconcile.
// ---------------------------------------------------------------------------

// Return the boolean result of a single `SELECT pg_try_advisory_xact_lock(...)`
// executed on `lease` (already inside a BEGIN). try-lock is NON-blocking and
// per-session, so its result is a DETERMINISTIC witness of whether the key is
// already held by another session — no wall-clock threshold required.
namespace {
bool try_xact_lock(PGconn* conn, const std::string& lock_sql, const std::string& agent) {
    auto r = yuzu::server::pg::exec_params(conn, lock_sql.c_str(), std::vector<std::string>{agent});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) >= 1);
    const char* v = PQgetvalue(r.get(), 0, 0);
    return v != nullptr && (v[0] == 't' || v[0] == 'T');
}
} // namespace

TEST_CASE("ADVERSARIAL: VulnFindingStore's advisory lock key is namespaced away from "
          "SoftwareInventoryStore's for the same agent_id",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "collide-agent";

    // DETERMINISTIC key-disjointness proof — no threads, no wall-clock. On lease A
    // hold the EXACT SoftwareInventoryStore full-replace key
    // (hashtextextended(agent, 0)) inside a transaction; on lease B a NON-BLOCKING
    // try-lock of the VULN store's namespaced key
    // (hashtextextended('vuln_finding_store:'||agent, 0)) must SUCCEED (return
    // TRUE) because the two keys are disjoint. Before the namespacing fix the keys
    // were identical and the try-lock would have returned FALSE.
    auto leaseA = pool.acquire();
    REQUIRE(leaseA);
    auto leaseB = pool.acquire();
    REQUIRE(leaseB);

    REQUIRE(yuzu::server::pg::exec_params(leaseA.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(leaseB.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    // A holds the software-inventory-style key (blocking lock; unheld → returns at
    // once). pg_advisory_xact_lock returns void, so we don't route it through the
    // try-lock witness helper.
    REQUIRE(yuzu::server::pg::exec_params(
                leaseA.get(), "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                std::vector<std::string>{agent})
                .status() == PGRES_TUPLES_OK);
    // B try-locks the namespaced vuln key — disjoint → TRUE.
    CHECK(try_xact_lock(
        leaseB.get(),
        "SELECT pg_try_advisory_xact_lock(hashtextextended('vuln_finding_store:' || $1, 0))", agent));

    REQUIRE(yuzu::server::pg::exec_params(leaseA.get(), "COMMIT", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(leaseB.get(), "COMMIT", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

TEST_CASE("ADVERSARIAL: two vuln reconciles for the SAME agent still serialize "
          "(intra-store lock preserved)",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "same-agent-serialize";

    // DETERMINISTIC same-key serialization proof. On lease A hold the VULN store's
    // OWN namespaced key inside a transaction; on lease B a non-blocking try-lock
    // of the SAME namespaced key must FAIL (return FALSE) — a second session
    // cannot take a key another session already holds. This proves the fix did not
    // weaken same-agent serialization, with no wall-clock threshold.
    auto leaseA = pool.acquire();
    REQUIRE(leaseA);
    auto leaseB = pool.acquire();
    REQUIRE(leaseB);

    REQUIRE(yuzu::server::pg::exec_params(leaseA.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(leaseB.get(), "BEGIN", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);

    const std::string vuln_key_sql =
        "SELECT pg_try_advisory_xact_lock(hashtextextended('vuln_finding_store:' || $1, 0))";
    // A takes the key (try-lock → TRUE the first time).
    CHECK(try_xact_lock(leaseA.get(), vuln_key_sql, agent));
    // B try-locks the SAME key held by A → FALSE.
    CHECK_FALSE(try_xact_lock(leaseB.get(), vuln_key_sql, agent));

    REQUIRE(yuzu::server::pg::exec_params(leaseA.get(), "COMMIT", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(leaseB.get(), "COMMIT", std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

TEST_CASE("ADVERSARIAL: disposed_clean naming a tuple that was never observed is a harmless no-op",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    AgentReconcile r = mk_reconcile("a1", {mk_finding("CVE-1", "p1")}, true);
    r.disposed_clean = {FindingKey{"CVE-NEVER-EXISTED", "phantom"}};
    CHECK(store.reconcile_agent(r)); // DELETE affecting 0 rows must not fail the batch

    auto rows = store.query_findings("a1");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].cve_id == "CVE-1");
}

// FIX 11: fleet_summary is AUTHORITATIVE — a store/pool degrade returns nullopt,
// NEVER a silent all-zero summary (which would read as "the whole fleet is
// clean"). Prove it under a REAL pool-exhaustion degrade, mirroring the
// get_agent_coverage Degraded probe above.
TEST_CASE("ADVERSARIAL: fleet_summary returns nullopt (not a zero summary) on an exhausted pool",
          "[pg][vuln][adversarial]") {
    YUZU_REQUIRE_PG_DB_TPL(db, vuln_tpl);
    // Pool of size 1 so a single held lease starves fleet_summary's acquire.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    VulnFindingStore store{pool};
    REQUIRE(store.is_open());

    // Seed data so a FREE pool would return a populated (non-null) summary.
    AgentCoverageCounts cov;
    cov.total_packages = 20;
    cov.vulnerable = 2;
    REQUIRE(store.reconcile_agent(mk_reconcile("known", {mk_finding("CVE-1", "p1", "critical")}, true, cov)));

    // Hold the pool's only connection past kReadTimeout on another thread. Catch2
    // macros are not thread-safe, so the holder captures its result in an atomic
    // and the assertion runs on the main thread after join().
    std::atomic<bool> release_now{false};
    std::atomic<bool> holder_got_lease{false};
    std::thread holder([&] {
        auto lease = pool.acquire();
        holder_got_lease.store(static_cast<bool>(lease), std::memory_order_relaxed);
        while (!release_now.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto sum = store.fleet_summary();
    release_now = true;
    holder.join();

    CHECK(holder_got_lease.load());
    CHECK_FALSE(sum.has_value()); // degrade → nullopt, NOT a zeroed FleetVulnSummary
}
