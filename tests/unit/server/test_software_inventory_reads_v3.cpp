// SoftwareInventoryStore SAM-33 reads: query_hosts, query_changes, facet_health,
// software_summary. Each is an AUTHORITATIVE read (nullopt on a degrade, never a silent empty)
// with the caller's `agent_ids` scope pushed into SQL. Seeds the three tables the reads touch
// with direct SQL, so no blob or ingest path is involved.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using yuzu::server::SoftwareChangeRow;
using yuzu::server::SoftwareChangesQuery;
using yuzu::server::SoftwareHostQuery;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

using Scope = std::optional<std::vector<std::string>>;

// Same setup as test_software_inventory_store.cpp: the shared "swinv" key is verified by replay.
yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         SoftwareInventoryStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "swinv template: store failed to migrate");
                                     }};

// One migrated clone + one persistent pool for the file, TRUNCATE-reset between cases.
struct ReadsShared {
    yuzu::test::PostgresTestDb db{swinv_tpl};
    std::optional<PgPool> pool;
    ReadsShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
ReadsShared& reads_shared() {
    static ReadsShared s;
    return s;
}

bool run_sql(PgPool& pool, const std::string& sql, const std::vector<std::string>& params = {}) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
}

void reads_reset() {
    auto& pool = *reads_shared().pool;
    REQUIRE(run_sql(pool, "TRUNCATE software_inventory_store.inventory_state, "
                          "software_inventory_store.software_facet_state, "
                          "software_inventory_store.software_changes RESTART IDENTITY"));
}

#define READS_SHARED(store, pool)                                                                  \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    reads_reset();                                                                                 \
    PgPool& pool = *reads_shared().pool;                                                           \
    SoftwareInventoryStore store{pool};                                                            \
    REQUIRE(store.is_open())

void add_state(PgPool& pool, const std::string& agent, std::int64_t last_seen,
               const std::string& source = "installed_software") {
    REQUIRE(run_sql(pool,
                    "INSERT INTO software_inventory_store.inventory_state "
                    "(agent_id, source, content_hash, first_seen, last_seen) "
                    "VALUES ($1, $2, 'h', $3::bigint, $3::bigint)",
                    {agent, source, std::to_string(last_seen)}));
}

void add_facet(PgPool& pool, const std::string& agent, const std::string& facet,
               const std::string& status, std::int64_t duration_ms = 0, std::int64_t bytes = 0,
               bool enabled = true) {
    REQUIRE(run_sql(pool,
                    "INSERT INTO software_inventory_store.software_facet_state "
                    "(agent_id, facet, status, token, section_hash, enabled, last_confirmed_at, "
                    " duration_ms, bytes_read, updated_at) "
                    "VALUES ($1, $2, $3, 'tok', 'sh', $4::boolean, 7, $5::bigint, $6::bigint, 9)",
                    {agent, facet, status, enabled ? "true" : "false", std::to_string(duration_ms),
                     std::to_string(bytes)}));
}

void add_change(PgPool& pool, std::int64_t change_id, const std::string& agent,
                std::int64_t observed_at, const std::string& kind = "install") {
    REQUIRE(run_sql(pool,
                    "INSERT INTO software_inventory_store.software_changes "
                    "(change_id, agent_id, facet, kind, name, observed_at) "
                    "VALUES ($1::bigint, $2, 'installed_apps.list_inventory', $3, 'app', $4::bigint)",
                    {std::to_string(change_id), agent, kind, std::to_string(observed_at)}));
}

std::vector<std::int64_t> ids_of(const std::vector<SoftwareChangeRow>& rows) {
    std::vector<std::int64_t> out;
    for (const auto& r : rows)
        out.push_back(r.change_id);
    return out;
}

using Ids = std::vector<std::int64_t>;

// A held transaction that is rolled back unless committed, so a failed REQUIRE never leaves a
// shared-pool connection mid-transaction.
struct HeldTxn {
    PgPool::Lease lease;
    bool open{false};
    explicit HeldTxn(PgPool& pool) : lease(pool.try_acquire_for(std::chrono::seconds{5})) {
        REQUIRE(lease);
        open = pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
               PGRES_COMMAND_OK;
        REQUIRE(open);
    }
    bool exec(const std::string& sql, const std::vector<std::string>& params = {}) {
        return pg::exec_params(lease.get(), sql.c_str(), params).status() == PGRES_COMMAND_OK;
    }
    bool commit() {
        open = false;
        return exec("COMMIT");
    }
    ~HeldTxn() {
        if (open)
            (void)exec("ROLLBACK");
    }
};

} // namespace

TEST_CASE("SAM-33 reads: nullopt on a closed store, and an empty value (not nullopt) on no rows",
          "[pg][software_inventory][reads_v3]") {
    SECTION("store not open -> nullopt for all four reads") {
        YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        REQUIRE(pool.valid());
        REQUIRE(run_sql(pool, "DELETE FROM public.schema_meta WHERE store = "
                              "'software_inventory_store'"));
        SoftwareInventoryStore store{pool}; // the v1 re-run over live tables fails the open
        REQUIRE_FALSE(store.is_open());
        SoftwareChangesQuery cq;
        cq.stable_before = 100;
        CHECK_FALSE(store.query_hosts({}).has_value());
        CHECK_FALSE(store.query_changes(cq).has_value());
        CHECK_FALSE(store.facet_health(std::nullopt).has_value());
        CHECK_FALSE(store.software_summary(1000, std::nullopt).has_value());
    }
    SECTION("no rows -> empty values") {
        READS_SHARED(store, pool);
        const auto hosts = store.query_hosts({});
        REQUIRE(hosts.has_value());
        CHECK(hosts->empty());
        SoftwareChangesQuery cq;
        cq.stable_before = 100;
        const auto changes = store.query_changes(cq);
        REQUIRE(changes.has_value());
        CHECK(changes->empty());
        const auto health = store.facet_health(std::nullopt);
        REQUIRE(health.has_value());
        CHECK(health->empty());
        const auto sum = store.software_summary(1'000'000, std::nullopt);
        REQUIRE(sum.has_value());
        CHECK(sum->devices_reporting == 0);
        CHECK(sum->devices_stale == 0);
        CHECK(sum->changes_7d.install + sum->changes_7d.remove + sum->changes_7d.upgrade == 0);
    }
}

TEST_CASE("SAM-33 reads: a present-empty agent_ids runs no SQL",
          "[pg][software_inventory][reads_v3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool one{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(one.valid());
    SoftwareInventoryStore store{one};
    REQUIRE(store.is_open());
    auto held = one.acquire(); // the only connection: any SQL would find no lease
    REQUIRE(held);

    // Control: a real read cannot get a connection and degrades (nullopt).
    CHECK_FALSE(store.query_hosts({}).has_value());

    // The same reads with a deny-all scope never reach the pool: an empty VALUE.
    SoftwareHostQuery hq;
    hq.agent_ids = std::vector<std::string>{};
    const auto hosts = store.query_hosts(hq);
    REQUIRE(hosts.has_value());
    CHECK(hosts->empty());

    SoftwareChangesQuery cq;
    cq.stable_before = 100;
    cq.agent_ids = std::vector<std::string>{};
    const auto changes = store.query_changes(cq);
    REQUIRE(changes.has_value());
    CHECK(changes->empty());

    const auto health = store.facet_health(Scope{std::vector<std::string>{}});
    REQUIRE(health.has_value());
    CHECK(health->empty());

    const auto sum = store.software_summary(1'000'000, Scope{std::vector<std::string>{}});
    REQUIRE(sum.has_value());
    CHECK(sum->devices_reporting == 0);

    // A missing settle horizon is a precondition miss: empty value, no SQL.
    SoftwareChangesQuery no_horizon;
    const auto none = store.query_changes(no_horizon);
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("query_hosts: keyset pages are stable and complete; filters and scope apply",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    // Five installed_software devices; a-04 also reported another source (must not appear twice
    // or leak in as its own host).
    add_state(pool, "a-01", 1000);
    add_state(pool, "a-02", 2000);
    add_state(pool, "a-03", 3000);
    add_state(pool, "a-04", 4000);
    add_state(pool, "a-05", 5000);
    add_state(pool, "a-04", 9999, "hardware");
    add_state(pool, "z-other", 100, "hardware");
    add_facet(pool, "a-02", "runtimes.python", "delta", 40, 400);
    add_facet(pool, "a-02", "installed_apps.list_inventory", "full", 30, 300);
    add_facet(pool, "a-04", "installed_apps.list_inventory", "full", 10, 100, /*enabled=*/false);

    SECTION("keyset walk visits every device once, in agent_id order") {
        std::vector<std::string> seen;
        SoftwareHostQuery q;
        q.limit = 2;
        for (int guard = 0; guard < 10; ++guard) {
            const auto page = store.query_hosts(q);
            REQUIRE(page.has_value());
            if (page->empty())
                break;
            CHECK(page->size() <= 2);
            for (const auto& h : *page)
                seen.push_back(h.agent_id);
            q.after_agent_id = page->back().agent_id;
        }
        CHECK(seen == std::vector<std::string>{"a-01", "a-02", "a-03", "a-04", "a-05"});
    }
    SECTION("rows carry last_seen and the device's facet rows, facet-sorted") {
        SoftwareHostQuery q;
        q.after_agent_id = "a-01";
        q.limit = 3;
        const auto page = store.query_hosts(q);
        REQUIRE(page.has_value());
        REQUIRE(page->size() == 3);
        const auto& a2 = (*page)[0];
        CHECK(a2.agent_id == "a-02");
        CHECK(a2.last_seen == 2000);
        REQUIRE(a2.facets.size() == 2);
        CHECK(a2.facets[0].facet == "installed_apps.list_inventory");
        CHECK(a2.facets[1].facet == "runtimes.python");
        CHECK(a2.facets[1].status == "delta");
        CHECK(a2.facets[1].token == "tok");
        CHECK(a2.facets[1].enabled);
        CHECK(a2.facets[1].last_confirmed_at == 7);
        CHECK(a2.facets[1].duration_ms == 40);
        CHECK(a2.facets[1].bytes_read == 400);
        CHECK((*page)[1].facets.empty()); // a-03 has no state row
        REQUIRE((*page)[2].facets.size() == 1);
        CHECK_FALSE((*page)[2].facets[0].enabled);
    }
    SECTION("last_synced_before filters on inventory_state.last_seen (strictly less)") {
        SoftwareHostQuery q;
        q.last_synced_before = 3000;
        const auto page = store.query_hosts(q);
        REQUIRE(page.has_value());
        REQUIRE(page->size() == 2);
        CHECK((*page)[0].agent_id == "a-01");
        CHECK((*page)[1].agent_id == "a-02");
    }
    SECTION("skip passes over rows after the anchor") {
        SoftwareHostQuery q;
        q.skip = 3;
        const auto page = store.query_hosts(q);
        REQUIRE(page.has_value());
        REQUIRE(page->size() == 2);
        CHECK((*page)[0].agent_id == "a-04");
    }
    SECTION("a scoped call returns only in-scope agents and still pages by keyset") {
        SoftwareHostQuery q;
        q.agent_ids = std::vector<std::string>{"a-05", "a-02", "z-other", "not-there"};
        q.limit = 1;
        const auto first = store.query_hosts(q);
        REQUIRE(first.has_value());
        REQUIRE(first->size() == 1);
        CHECK((*first)[0].agent_id == "a-02");
        q.after_agent_id = "a-02";
        const auto second = store.query_hosts(q);
        REQUIRE(second.has_value());
        REQUIRE(second->size() == 1); // z-other never reported installed_software
        CHECK((*second)[0].agent_id == "a-05");
        q.after_agent_id = "a-05";
        const auto done = store.query_hosts(q);
        REQUIRE(done.has_value());
        CHECK(done->empty());
    }
}

TEST_CASE("query_changes: strictly ascending (observed_at, change_id), never at or past stable_before",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    add_change(pool, 1, "a-01", 100);
    add_change(pool, 2, "a-01", 200, "upgrade");
    add_change(pool, 3, "a-02", 200, "remove");
    add_change(pool, 4, "a-02", 300);
    add_change(pool, 5, "a-03", 400);

    SECTION("stable_before is an exclusive upper bound on observed_at") {
        SoftwareChangesQuery q;
        q.stable_before = 300;
        const auto page = store.query_changes(q);
        REQUIRE(page.has_value());
        CHECK(ids_of(*page) == Ids{1, 2, 3});
        for (const auto& r : *page)
            CHECK(r.observed_at < 300);
        q.stable_before = 301;
        CHECK(ids_of(*store.query_changes(q)) == Ids{1, 2, 3, 4});
    }
    SECTION("rows carry every column") {
        SoftwareChangesQuery q;
        q.stable_before = 150;
        const auto page = store.query_changes(q);
        REQUIRE(page.has_value());
        REQUIRE(page->size() == 1);
        CHECK((*page)[0].change_id == 1);
        CHECK((*page)[0].agent_id == "a-01");
        CHECK((*page)[0].facet == "installed_apps.list_inventory");
        CHECK((*page)[0].kind == "install");
        CHECK((*page)[0].name == "app");
        CHECK((*page)[0].observed_at == 100);

        // add_change leaves publisher, instance_key and the versions empty, so a slipped column
        // index after the identity_key drop would pass unseen: seed one row with all four distinct.
        REQUIRE(run_sql(pool,
                        "INSERT INTO software_inventory_store.software_changes "
                        "(change_id, agent_id, facet, kind, name, publisher, instance_key, "
                        " from_version, to_version, observed_at) "
                        "VALUES (6, 'a-09', 'installed_apps.list_inventory', 'upgrade', 'tool', "
                        "'acme', 'ik-1', '1.0', '2.0', 120)"));
        q.agent_id = "a-09";
        const auto full = store.query_changes(q);
        REQUIRE(full.has_value());
        REQUIRE(full->size() == 1);
        CHECK((*full)[0].change_id == 6);
        CHECK((*full)[0].kind == "upgrade");
        CHECK((*full)[0].name == "tool");
        CHECK((*full)[0].publisher == "acme");
        CHECK((*full)[0].instance_key == "ik-1");
        CHECK((*full)[0].from_version == "1.0");
        CHECK((*full)[0].to_version == "2.0");
        CHECK((*full)[0].observed_at == 120);
    }
    SECTION("rows sharing one second page in change_id order; a cursor inside the group resumes "
            "at the next change_id") {
        SoftwareChangesQuery q;
        q.stable_before = 1000;
        q.limit = 2;
        const auto p1 = store.query_changes(q);
        REQUIRE(p1.has_value());
        CHECK(ids_of(*p1) == Ids{1, 2}); // cursor now sits inside the observed_at = 200 group
        q.after_observed_at = (*p1)[1].observed_at;
        q.after_change_id = (*p1)[1].change_id;
        const auto p2 = store.query_changes(q);
        REQUIRE(p2.has_value());
        CHECK(ids_of(*p2) == Ids{3, 4});
        q.after_observed_at = (*p2)[1].observed_at;
        q.after_change_id = (*p2)[1].change_id;
        CHECK(ids_of(*store.query_changes(q)) == Ids{5});
        q.after_observed_at = 400;
        q.after_change_id = 5;
        CHECK(store.query_changes(q)->empty());
    }
    SECTION("filters: agent, kind, since, scope") {
        SoftwareChangesQuery q;
        q.stable_before = 1000;
        q.agent_id = "a-02";
        CHECK(ids_of(*store.query_changes(q)) == Ids{3, 4});
        q.agent_id.clear();
        q.kind = "upgrade";
        CHECK(ids_of(*store.query_changes(q)) == Ids{2});
        q.kind.clear();
        q.since = 200;
        CHECK(ids_of(*store.query_changes(q)) == Ids{2, 3, 4, 5}); // observed_at >= since
        q.since = 0;
        q.agent_ids = std::vector<std::string>{"a-03", "a-01", "not-there"};
        CHECK(ids_of(*store.query_changes(q)) == Ids{1, 2, 5});
        q.agent_id = "a-02"; // the exact filter and the scope AND together
        CHECK(store.query_changes(q)->empty());
    }
    SECTION("skip passes over rows after the anchor") {
        SoftwareChangesQuery q;
        q.stable_before = 1000;
        q.skip = 3;
        CHECK(ids_of(*store.query_changes(q)) == Ids{4, 5});
    }
}

TEST_CASE("query_changes: reversed stamps page in observed_at order and skip nothing",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    // change_id order and observed_at order disagree: 100 was stamped later than 101.
    add_change(pool, 100, "a-01", 1000);
    add_change(pool, 101, "a-02", 999);

    SoftwareChangesQuery q;
    q.stable_before = 1000;
    const auto p1 = store.query_changes(q);
    REQUIRE(p1.has_value());
    CHECK(ids_of(*p1) == Ids{101}); // 100 (observed_at 1000) is not yet eligible
    q.after_observed_at = (*p1)[0].observed_at;
    q.after_change_id = (*p1)[0].change_id;

    q.stable_before = 1001; // 100 becomes eligible: the cursor (999, 101) has not stepped over it
    const auto p2 = store.query_changes(q);
    REQUIRE(p2.has_value());
    CHECK(ids_of(*p2) == Ids{100});
}

TEST_CASE("query_changes: a row committed after the cursor passed is the documented lateness "
          "contract, recovered by a re-read with `since`",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    // Connection A takes change 200 (observed_at 500) but has not committed yet.
    HeldTxn late(pool);
    REQUIRE(late.exec("INSERT INTO software_inventory_store.software_changes "
                      "(change_id, agent_id, facet, kind, name, observed_at) "
                      "VALUES (200, 'a-late', 'installed_apps.list_inventory', 'install', 'app', 500)"));
    // Connection B commits change 201 (observed_at 600) and the cursor moves past 500.
    add_change(pool, 201, "a-01", 600);

    SoftwareChangesQuery q;
    q.stable_before = 1000;
    const auto p1 = store.query_changes(q);
    REQUIRE(p1.has_value());
    CHECK(ids_of(*p1) == Ids{201});
    q.after_observed_at = (*p1)[0].observed_at;
    q.after_change_id = (*p1)[0].change_id;

    REQUIRE(late.commit()); // lands behind the cursor that already passed its position

    // Lateness contract: the cursor does NOT return it...
    const auto behind = store.query_changes(q);
    REQUIRE(behind.has_value());
    CHECK(behind->empty());

    // ...a re-read with `since` at or before its observed_at DOES, with its change_id, which is
    // the unique, stable de-duplication key against rows the earlier pages already served.
    SoftwareChangesQuery reread;
    reread.stable_before = 1000;
    reread.since = 500;
    const auto again = store.query_changes(reread);
    REQUIRE(again.has_value());
    CHECK(ids_of(*again) == Ids{200, 201});
    std::set<std::int64_t> served{201};
    Ids fresh;
    for (const auto& r : *again) {
        if (served.insert(r.change_id).second)
            fresh.push_back(r.change_id);
    }
    CHECK(fresh == Ids{200});
}

TEST_CASE("facet_health: status counts incl. enabled=false as disabled, percentiles, top-10 slowest",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    const std::string apps = "installed_apps.list_inventory";
    // Measured rows: durations 100, 200, 300, 400, 5000 and the two zeros below (p50 = 200,
    // p95 = max = 5000).
    add_facet(pool, "d-1", apps, "full", 100, 10);
    add_facet(pool, "d-2", apps, "full", 200, 20);
    add_facet(pool, "d-3", apps, "full", 300, 30);
    add_facet(pool, "d-4", apps, "delta", 400, 40);
    add_facet(pool, "d-5", apps, "timeout", 5000, 50);
    add_facet(pool, "d-6", apps, "constrained", 0, 0, true); // measured: 0, 0 joins the sample
    add_facet(pool, "d-7", apps, "oversize", 0, 0);
    add_facet(pool, "d-8", apps, "not_collected");
    add_facet(pool, "d-9", apps, "disabled");
    add_facet(pool, "d-10", apps, "full", 999999, 999999, /*enabled=*/false); // disabled, unmeasured
    // A second facet with 21 measured rows exercises the top-10 cut and gives p50, p95 and max
    // three different values for both columns (durations i * 10, bytes i): of 21 sorted rows
    // percentile_disc picks the 11th for 0.5 and the 20th for 0.95, the 21st is the max.
    for (int i = 1; i <= 21; ++i)
        add_facet(pool, "r-" + std::to_string(i), "runtimes.python", "full", i * 10, i);

    const auto health = store.facet_health(std::nullopt);
    REQUIRE(health.has_value());
    REQUIRE(health->size() == 2);
    const auto& a = (*health)[0];
    CHECK(a.facet == apps);
    CHECK(a.devices_by_status.size() == 7); // all seven v3 statuses, zeros included
    CHECK(a.devices_by_status.at("full") == 3);
    CHECK(a.devices_by_status.at("delta") == 1);
    CHECK(a.devices_by_status.at("constrained") == 1);
    CHECK(a.devices_by_status.at("timeout") == 1);
    CHECK(a.devices_by_status.at("oversize") == 1);
    CHECK(a.devices_by_status.at("not_collected") == 1);
    CHECK(a.devices_by_status.at("disabled") == 2); // d-9 and the enabled=false d-10
    // Sorted measured durations: 0, 0, 100, 200, 300, 400, 5000 -> p50 = 4th = 200.
    CHECK(a.duration_ms_p50 == 200);
    CHECK(a.duration_ms_p95 == 5000);
    CHECK(a.duration_ms_max == 5000);
    // Sorted measured bytes: 0, 0, 10, 20, 30, 40, 50 -> p50 = 4th = 20, p95 = 7th = 50.
    CHECK(a.bytes_read_p50 == 20);
    CHECK(a.bytes_read_p95 == 50);
    CHECK(a.bytes_read_max == 50);
    REQUIRE(a.slowest.size() == 7);
    CHECK(a.slowest[0].agent_id == "d-5");
    CHECK(a.slowest[0].duration_ms == 5000);
    CHECK(a.slowest[1].agent_id == "d-4");
    for (const auto& s : a.slowest)
        CHECK(s.agent_id != "d-10");

    const auto& b = (*health)[1];
    CHECK(b.facet == "runtimes.python");
    CHECK(b.devices_by_status.at("full") == 21);
    CHECK(b.devices_by_status.at("timeout") == 0);
    CHECK(b.duration_ms_p50 == 110);
    CHECK(b.duration_ms_p95 == 200);
    CHECK(b.duration_ms_max == 210);
    CHECK(b.bytes_read_p50 == 11);
    CHECK(b.bytes_read_p95 == 20);
    CHECK(b.bytes_read_max == 21);
    REQUIRE(b.slowest.size() == 10);
    CHECK(b.slowest.front().agent_id == "r-21");
    CHECK(b.slowest.back().agent_id == "r-12");
    CHECK(std::is_sorted(b.slowest.begin(), b.slowest.end(), [](const auto& x, const auto& y) {
        return x.duration_ms > y.duration_ms;
    }));

    SECTION("a scoped call counts only in-scope agents") {
        const auto scoped = store.facet_health(Scope{std::vector<std::string>{"d-1", "d-9", "r-1"}});
        REQUIRE(scoped.has_value());
        REQUIRE(scoped->size() == 2);
        CHECK((*scoped)[0].devices_by_status.at("full") == 1);
        CHECK((*scoped)[0].devices_by_status.at("disabled") == 1);
        CHECK((*scoped)[0].devices_by_status.at("delta") == 0);
        REQUIRE((*scoped)[0].slowest.size() == 1);
        CHECK((*scoped)[0].slowest[0].agent_id == "d-1");
        CHECK((*scoped)[1].devices_by_status.at("full") == 1);
        const auto none = store.facet_health(Scope{std::vector<std::string>{"nobody"}});
        REQUIRE(none.has_value());
        CHECK(none->empty());
    }
}

TEST_CASE("software_summary: device counts, stale cut, 24 h counts are a subset of 7 d counts",
          "[pg][software_inventory][reads_v3]") {
    READS_SHARED(store, pool);
    constexpr std::int64_t now = 2'000'000;
    add_state(pool, "s-fresh", now - 100);
    add_state(pool, "s-edge", now - 172800);      // exactly 48 h: not stale (last_seen < cut)
    add_state(pool, "s-stale", now - 172801);
    add_state(pool, "s-old", now - 900000);
    add_state(pool, "s-hw", now - 900000, "hardware"); // another source: not a reporting device

    add_change(pool, 1, "s-fresh", now - 10, "install");
    add_change(pool, 2, "s-fresh", now - 86400, "remove");   // on the 24 h edge: included
    add_change(pool, 3, "s-edge", now - 86401, "upgrade");   // 7 d only
    add_change(pool, 4, "s-old", now - 604800, "install");   // on the 7 d edge: included
    add_change(pool, 5, "s-old", now - 604801, "install");   // outside both
    add_change(pool, 6, "s-stale", now - 20, "install");

    const auto s = store.software_summary(now, std::nullopt);
    REQUIRE(s.has_value());
    CHECK(s->devices_reporting == 4);
    CHECK(s->devices_stale == 2);
    CHECK(s->changes_24h.install == 2);
    CHECK(s->changes_24h.remove == 1);
    CHECK(s->changes_24h.upgrade == 0);
    CHECK(s->changes_7d.install == 3);
    CHECK(s->changes_7d.remove == 1);
    CHECK(s->changes_7d.upgrade == 1);
    CHECK(s->changes_24h.install <= s->changes_7d.install);
    CHECK(s->changes_24h.remove <= s->changes_7d.remove);
    CHECK(s->changes_24h.upgrade <= s->changes_7d.upgrade);

    SECTION("a scoped call counts only in-scope agents") {
        const auto sc = store.software_summary(now, Scope{std::vector<std::string>{"s-fresh", "s-old"}});
        REQUIRE(sc.has_value());
        CHECK(sc->devices_reporting == 2);
        CHECK(sc->devices_stale == 1);
        CHECK(sc->changes_24h.install == 1);
        CHECK(sc->changes_24h.remove == 1);
        CHECK(sc->changes_7d.install == 2);
        CHECK(sc->changes_7d.upgrade == 0); // s-edge's upgrade is out of scope
        const auto none = store.software_summary(now, Scope{std::vector<std::string>{"nobody"}});
        REQUIRE(none.has_value());
        CHECK(none->devices_reporting == 0);
        CHECK(none->changes_7d.install == 0);
    }
}
