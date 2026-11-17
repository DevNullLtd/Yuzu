/**
 * test_dex_app_usage_owner.cpp -- DexAppUsageOwner (dex_app_usage_owner.cpp), the
 * ADR-0012 section-3 query owner behind the fleet application usage read model.
 * One statement reads app_usage_store.agent_last_used, app_usage_store.usage_state
 * and guaranteed_state_store.guardian_observations, so the usage totals, the
 * exposed events and the reporting count are one population. The owner returns
 * aggregates per (application, cell) and never an agent id.
 *
 * Window used throughout: since = now - 7 days (inclusive), until = now
 * (exclusive); freshness = the last 48 hours of the DATABASE clock against the server
 * receipt time (usage_state.last_seen), aged by a direct UPDATE, never by sleeping.
 */

#include "dex_app_usage_owner.hpp"

#include "app_usage_store.hpp"
#include "dex_window.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <libpq-fe.h>
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

using yuzu::server::AgentLastUsedRow;
using yuzu::server::AppUsageStore;
using yuzu::server::DexAppUsageOwner;
using yuzu::server::DexReadFault;
using yuzu::server::DexUsageCellRow;
using yuzu::server::DexUsageQuery;
using yuzu::server::DexUsageRead;
using yuzu::server::GuaranteedStateEventRow;
using yuzu::server::GuaranteedStateStore;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate dex_usage_tpl{"dexusage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AppUsageStore usage{pool};
    GuaranteedStateStore gss{pool};
    if (!usage.is_open() || !gss.is_open())
        throw std::runtime_error("dexusage template: store failed to migrate");
}};

// The aggregate types hold counts only; a string member (an agent id) would make them
// non-trivially-copyable.
static_assert(std::is_trivially_copyable_v<DexUsageCellRow>);
static_assert(std::is_trivially_copyable_v<yuzu::server::DexUsageEventRow>);

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct Use {
    std::string exe;
    std::int64_t launches;
    std::int64_t seconds;
};

void seed_usage(AppUsageStore& store, const std::string& agent, const std::vector<Use>& uses) {
    std::vector<AgentLastUsedRow> rows;
    for (const auto& u : uses)
        rows.push_back({.exe_key = u.exe, .run_count_30d = u.launches, .total_seconds_30d = u.seconds});
    REQUIRE(store.replace_agent_last_used(agent, rows, "hash-" + agent, 1));
}

void seed_obs(GuaranteedStateStore& gss, const std::string& id, const std::string& agent,
              const std::string& subject, const char* type, std::int64_t at_epoch) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = nlohmann::json{{"subject", subject}, {"version", "1.0"}, {"platform", "windows"}}.dump();
    e.timestamp = yuzu::server::dex_iso_at(at_epoch);
    REQUIRE(gss.insert_event(e));
}

// Age one device's usage_state.last_seen (the server receipt time) by raw SQL.
void age_state(const std::string& dsn, const std::string& agent, const char* interval) {
    yuzu::server::pg::PgConn c{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
    const std::string sql =
        std::string("UPDATE app_usage_store.usage_state SET last_seen = now() - interval '") + interval +
        "' WHERE agent_id = $1";
    REQUIRE(yuzu::server::pg::exec_params(c.get(), sql.c_str(), std::vector<std::string>{agent})
                .status() == PGRES_COMMAND_OK);
}

// One query over `agents` (each in cell 0 unless `cells` says otherwise) for `subjects`, with
// the real match plan. `linux_agents` get the is_linux flag.
DexUsageQuery make_query(std::int64_t now, const std::vector<std::string>& agents,
                         const std::vector<std::string>& subjects,
                         const std::vector<std::string>& linux_agents = {},
                         const std::vector<int>& cells = {}, int cell_count = 1) {
    DexUsageQuery q;
    for (std::size_t i = 0; i < agents.size(); ++i) {
        yuzu::server::DexUsageDevice d;
        d.agent_id = agents[i];
        d.cell = i < cells.size() ? cells[i] : 0;
        d.is_linux = std::find(linux_agents.begin(), linux_agents.end(), agents[i]) != linux_agents.end();
        q.devices.push_back(d);
    }
    q.cell_count = cell_count;
    q.subjects = subjects;
    q.keys = yuzu::server::dex_usage_match_plan(subjects);
    q.since_iso = yuzu::server::dex_iso_at(now - 7 * 86400);
    q.until_iso = yuzu::server::dex_iso_at(now);
    q.fresh_secs = yuzu::server::kDexUsageFreshSecs;
    return q;
}

const DexUsageCellRow* find_cell(const DexUsageRead& r, int subject, int cell) {
    for (const auto& c : r.cells)
        if (c.subject == subject && c.cell == cell)
            return &c;
    return nullptr;
}

// {reason, source=dex_usage} on yuzu_server_guardian_read_degrade_total.
double degraded(yuzu::MetricsRegistry& m, const char* reason) {
    return m.counter("yuzu_server_guardian_read_degrade_total", {{"reason", reason}, {"source", "dex_usage"}})
        .value();
}

const yuzu::server::DexUsageEventRow* find_event(const DexUsageRead& r, int subject) {
    for (const auto& e : r.events)
        if (e.subject == subject)
            return &e;
    return nullptr;
}

} // namespace

TEST_CASE("DexAppUsageOwner fleet figure equals the per-device sum and carries no agent id",
          "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "d2", {{"alpha.exe", 7, 7200}});
    seed_usage(usage, "d3", {{"alpha.exe", 1, 60}, {"beta.exe", 2, 600}});

    const std::int64_t now = now_epoch();
    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now, {"d1", "d2", "d3"}, {"alpha.exe", "beta.exe"}));
    REQUIRE(r.has_value());
    const auto* alpha = find_cell(*r, 0, 0);
    REQUIRE(alpha != nullptr);
    CHECK(alpha->devices == 3);
    CHECK(alpha->exact_devices == 3);
    CHECK(alpha->trunc_devices == 0);
    CHECK(alpha->launches == 5 + 7 + 1);
    CHECK(alpha->run_seconds == 3600 + 7200 + 60);
    const auto* beta = find_cell(*r, 1, 0);
    REQUIRE(beta != nullptr);
    CHECK(beta->devices == 1);
    CHECK(beta->run_seconds == 600);
    CHECK(r->cells.size() == 2);
    CHECK(r->reporting_devices == 3);
    CHECK(r->stale_devices == 0);
}

TEST_CASE("DexAppUsageOwner splits devices over cells and sums back to the fleet",
          "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "d2", {{"alpha.exe", 7, 7200}});
    seed_usage(usage, "d3", {{"alpha.exe", 1, 60}});
    seed_usage(usage, "d4", {{"alpha.exe", 2, 20}});

    const std::int64_t now = now_epoch();
    DexAppUsageOwner owner{pool};
    const auto fleet = owner.read(make_query(now, {"d1", "d2", "d3", "d4"}, {"alpha.exe"}));
    const auto split = owner.read(make_query(now, {"d1", "d2", "d3", "d4"}, {"alpha.exe"}, {},
                                             {0, 1, 2, 2}, 3));
    REQUIRE(fleet.has_value());
    REQUIRE(split.has_value());
    REQUIRE(split->cells.size() == 3);
    std::int64_t devices = 0, launches = 0, seconds = 0;
    for (const auto& c : split->cells) {
        devices += c.devices;
        launches += c.launches;
        seconds += c.run_seconds;
    }
    REQUIRE(fleet->cells.size() == 1);
    CHECK(devices == fleet->cells[0].devices);
    CHECK(launches == fleet->cells[0].launches);
    CHECK(seconds == fleet->cells[0].run_seconds);
    // Each cell holds its own devices, not just a share of the sum: a swap would show here.
    REQUIRE(find_cell(*split, 0, 0) != nullptr);
    REQUIRE(find_cell(*split, 0, 1) != nullptr);
    CHECK(find_cell(*split, 0, 0)->devices == 1);
    CHECK(find_cell(*split, 0, 0)->run_seconds == 3600);
    CHECK(find_cell(*split, 0, 1)->devices == 1);
    CHECK(find_cell(*split, 0, 1)->run_seconds == 7200);
    CHECK(find_cell(*split, 0, 2)->devices == 2);
    CHECK(find_cell(*split, 0, 2)->run_seconds == 80);
}

TEST_CASE("DexAppUsageOwner counts only the asked-about devices", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "outsider", {{"alpha.exe", 9, 9000}});

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now_epoch(), {"d1"}, {"alpha.exe"}));
    REQUIRE(r.has_value());
    REQUIRE(r->cells.size() == 1);
    CHECK(r->cells[0].devices == 1);
    CHECK(r->cells[0].run_seconds == 3600);
    CHECK(r->reporting_devices == 1);
}

TEST_CASE("DexAppUsageOwner exposes only events on devices that report usage for the application",
          "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(usage.is_open());
    REQUIRE(gss.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "d2", {{"alpha.exe", 7, 7200}});
    seed_usage(usage, "d4", {{"beta.exe", 1, 10}}); // reports usage, but for another application
    seed_usage(usage, "d5", {{"alpha.exe", 1, 60}});
    age_state(db.dsn(), "d5", "3 days"); // stale

    const std::int64_t now = now_epoch();
    const std::int64_t in = now - 86400;
    int n = 0;
    const auto ev = [&](const char* agent, const char* subject, const char* type, std::int64_t at) {
        seed_obs(gss, "e" + std::to_string(++n), agent, subject, type, at);
    };
    ev("d1", "Alpha.exe", "process.crashed", in); // counted: the case of the subject is the raw one
    ev("d1", "Alpha.exe", "process.hung", in);    // counted
    ev("d2", "Alpha.exe", "process.crashed", in); // counted
    ev("d3", "Alpha.exe", "process.crashed", in); // d3 never reported usage
    ev("d4", "Alpha.exe", "process.crashed", in); // d4 reports usage, but for beta.exe: not for Alpha.exe
    ev("d5", "Alpha.exe", "process.crashed", in); // d5 is stale
    ev("d4", "beta.exe", "process.hung", in);     // counted on subject 1: d4 reports beta.exe usage
    ev("d1", "gamma.exe", "process.crashed", in); // a subject that was not asked about
    ev("d1", "Alpha.exe", "process.started", in); // another observation type
    ev("d2", "Alpha.exe", "process.crashed", now - 8 * 86400); // before the window

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(
        make_query(now, {"d1", "d2", "d3", "d4", "d5"}, {"Alpha.exe", "beta.exe"}));
    REQUIRE(r.has_value());
    const auto* e = find_event(*r, 0);
    REQUIRE(e != nullptr);
    CHECK(e->crashes == 2); // d4's Alpha.exe crash is left out by the subject match
    CHECK(e->hangs == 1);
    const auto* e1 = find_event(*r, 1);
    REQUIRE(e1 != nullptr);
    CHECK(e1->crashes == 0);
    CHECK(e1->hangs == 1);
    CHECK(r->events.size() == 2);
}

TEST_CASE("DexAppUsageOwner never counts an event at or after the window end", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    GuaranteedStateStore gss{pool};
    REQUIRE(usage.is_open());
    REQUIRE(gss.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    const std::int64_t now = now_epoch();
    seed_obs(gss, "past", "d1", "alpha.exe", "process.crashed", now - 1); // one second before: counts
    seed_obs(gss, "edge", "d1", "alpha.exe", "process.crashed", now);     // the exclusive end: not
    seed_obs(gss, "future", "d1", "alpha.exe", "process.hung", now + 3600);
    seed_obs(gss, "since", "d1", "alpha.exe", "process.hung", now - 7 * 86400); // inclusive start
    seed_obs(gss, "old", "d1", "alpha.exe", "process.crashed", now - 30 * 86400); // before the window

    DexAppUsageOwner owner{pool};
    auto q = make_query(now, {"d1"}, {"alpha.exe"});
    const auto r = owner.read(q);
    REQUIRE(r.has_value());
    const auto* e = find_event(*r, 0);
    REQUIRE(e != nullptr);
    CHECK(e->crashes == 1);
    CHECK(e->hangs == 1);

    // Window `all`: no lower bound, so the 30-day-old crash counts. The event at the exclusive
    // end and the future one stay out, and the usage figure is the same.
    q.since_iso.clear();
    const auto all = owner.read(q);
    REQUIRE(all.has_value());
    const auto* ea = find_event(*all, 0);
    REQUIRE(ea != nullptr);
    CHECK(ea->crashes == 2);
    CHECK(ea->hangs == 1);
    REQUIRE(r->cells.size() == 1);
    REQUIRE(all->cells.size() == 1);
    CHECK(all->cells[0].devices == r->cells[0].devices);
    CHECK(all->cells[0].run_seconds == 3600);
}

TEST_CASE("DexAppUsageOwner leaves a stale device out of every figure", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "fresh", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "old", {{"alpha.exe", 7, 7200}});
    age_state(db.dsn(), "old", "3 days");

    const std::int64_t now = now_epoch();
    DexAppUsageOwner owner{pool};
    const auto stale = owner.read(make_query(now, {"fresh", "old"}, {"alpha.exe"}));
    REQUIRE(stale.has_value());
    REQUIRE(stale->cells.size() == 1);
    CHECK(stale->cells[0].devices == 1);
    CHECK(stale->cells[0].launches == 5);
    CHECK(stale->cells[0].run_seconds == 3600);
    CHECK(stale->reporting_devices == 1);
    CHECK(stale->stale_devices == 1);

    // With the freshness width widened past the aged row's age the same device counts again.
    auto q = make_query(now, {"fresh", "old"}, {"alpha.exe"});
    q.fresh_secs = 10 * 86400;
    const auto back = owner.read(q);
    REQUIRE(back.has_value());
    REQUIRE(back->cells.size() == 1);
    CHECK(back->cells[0].devices == 2);
    CHECK(back->reporting_devices == 2);
    CHECK(back->stale_devices == 0);
}

// Freshness is cut against the database clock (last_seen is authored by it), never the caller's
// instant: the window instants below are skewed by a day and a half either way and by two days, and
// the fresh/stale split must not move.
TEST_CASE("DexAppUsageOwner cuts freshness on the database clock, whatever instant the caller holds",
          "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "fresh", {{"alpha.exe", 1, 100}});
    seed_usage(usage, "edge", {{"alpha.exe", 2, 200}});
    seed_usage(usage, "old", {{"alpha.exe", 4, 400}});
    age_state(db.dsn(), "edge", "47 hours"); // inside the 48 h width
    age_state(db.dsn(), "old", "50 hours");  // outside it
    // "never" has no usage_state row at all: it is in neither count.

    DexAppUsageOwner owner{pool};
    const std::int64_t wall = now_epoch();
    for (const std::int64_t skew : {std::int64_t{0}, std::int64_t{36 * 3600}, std::int64_t{-36 * 3600},
                                    std::int64_t{49 * 3600}, std::int64_t{-49 * 3600}}) {
        CAPTURE(skew);
        const auto r = owner.read(make_query(wall + skew, {"fresh", "edge", "old", "never"}, {"alpha.exe"}));
        REQUIRE(r.has_value());
        CHECK(r->reporting_devices == 2); // fresh and edge
        CHECK(r->stale_devices == 1);     // old
        REQUIRE(r->cells.size() == 1);
        CHECK(r->cells[0].devices == 2);
        CHECK(r->cells[0].launches == 3); // fresh + edge; old is stale, never has no usage
        CHECK(r->cells[0].run_seconds == 300);
    }

    // The width is the only freshness input: narrowing it to 46 hours makes the 47 h device stale.
    auto q = make_query(wall, {"fresh", "edge", "old", "never"}, {"alpha.exe"});
    q.fresh_secs = 46 * 3600;
    const auto narrow = owner.read(q);
    REQUIRE(narrow.has_value());
    CHECK(narrow->reporting_devices == 1);
    CHECK(narrow->stale_devices == 2);
}

TEST_CASE("DexAppUsageOwner matches a 15-byte prefix on Linux devices only", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    // The kernel cut the long image's name at 15 bytes.
    seed_usage(usage, "lin", {{"sharedprefix123", 3, 300}});
    seed_usage(usage, "win", {{"sharedprefix123", 4, 400}});

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(
        make_query(now_epoch(), {"lin", "win"}, {"sharedprefix123-a.exe"}, {"lin"}));
    REQUIRE(r.has_value());
    REQUIRE(r->cells.size() == 1);
    CHECK(r->cells[0].devices == 1); // the Linux device only
    CHECK(r->cells[0].exact_devices == 0);
    CHECK(r->cells[0].trunc_devices == 1);
    CHECK(r->cells[0].run_seconds == 300);
}

TEST_CASE("DexAppUsageOwner counts a device matching through both keys once", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "lin", {{"sharedprefix123-a.exe", 2, 200}, {"sharedprefix123", 3, 300}});

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now_epoch(), {"lin"}, {"sharedprefix123-a.exe"}, {"lin"}));
    REQUIRE(r.has_value());
    REQUIRE(r->cells.size() == 1);
    CHECK(r->cells[0].devices == 1);
    CHECK(r->cells[0].exact_devices == 1);
    CHECK(r->cells[0].trunc_devices == 1);
    CHECK(r->cells[0].launches == 5); // both rows summed
    CHECK(r->cells[0].run_seconds == 500);
}

TEST_CASE("DexAppUsageOwner clamps agent-reported values per row", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "huge", {{"alpha.exe", yuzu::server::kDexUsageRowLaunchesCap * 1000,
                                yuzu::server::kDexUsageRowSecondsCap * 1000}});
    seed_usage(usage, "negative", {{"beta.exe", -5, -60}});

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now_epoch(), {"huge", "negative"}, {"alpha.exe", "beta.exe"}));
    REQUIRE(r.has_value());
    CHECK(find_cell(*r, 0, 0)->launches == yuzu::server::kDexUsageRowLaunchesCap);
    CHECK(find_cell(*r, 0, 0)->run_seconds == yuzu::server::kDexUsageRowSecondsCap);
    CHECK(find_cell(*r, 1, 0)->launches == 0);
    CHECK(find_cell(*r, 1, 0)->run_seconds == 0);
}

TEST_CASE("DexAppUsageOwner coverage counts need no keys", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());

    seed_usage(usage, "d1", {{"alpha.exe", 5, 3600}});
    seed_usage(usage, "empty", {}); // a state row with no usage rows still reports
    seed_usage(usage, "old", {{"alpha.exe", 1, 10}});
    age_state(db.dsn(), "old", "3 days");
    // "never" has no usage_state at all: in neither count.

    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now_epoch(), {"d1", "empty", "old", "never"}, {}));
    REQUIRE(r.has_value());
    CHECK(r->cells.empty());
    CHECK(r->events.empty());
    CHECK(r->reporting_devices == 2);
    CHECK(r->stale_devices == 1);

    // An application with no rows returns no cell row for it.
    const auto none = owner.read(make_query(now_epoch(), {"d1"}, {"nothing.exe"}));
    REQUIRE(none.has_value());
    CHECK(none->cells.empty());
    CHECK(none->reporting_devices == 1);
}

TEST_CASE("DexAppUsageOwner returns an engaged empty result for no devices", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    DexAppUsageOwner owner{pool};
    {
        // No query runs, so a held lease does not matter.
        auto held = pool.try_acquire_for(std::chrono::seconds(5));
        REQUIRE(held);
        const auto r = owner.read(make_query(now_epoch(), {}, {"alpha.exe"}));
        REQUIRE(r.has_value());
        CHECK(r->cells.empty());
        CHECK(r->events.empty());
        CHECK(r->reporting_devices == 0);
        CHECK(r->stale_devices == 0);
    }
}

TEST_CASE("DexAppUsageOwner refuses an out-of-range index on a healthy pool", "[pg][dex_usage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics};
    const std::int64_t now = now_epoch();

    for (const int subject : {-1, 1}) { // below zero, and at subjects.size()
        auto q = make_query(now, {"d1"}, {"alpha.exe"});
        q.keys[0].subject = subject;
        const auto r = owner.read(q);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == DexReadFault::kQueryError);
    }
    for (const int cell : {-1, 2}) { // below zero, and at cell_count
        auto q = make_query(now, {"d1"}, {"alpha.exe"}, {}, {cell}, 2);
        const auto r = owner.read(q);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == DexReadFault::kQueryError);
    }
    CHECK(degraded(metrics, "query_error") == 4.0); // each refusal is counted
    CHECK(owner.read(make_query(now, {"d1"}, {"alpha.exe"})).has_value()); // the same pool reads fine
}

TEST_CASE("DexAppUsageOwner degrades to a pool timeout on an unreachable pool", "[dex_usage]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    REQUIRE_FALSE(pool.valid());
    DexAppUsageOwner owner{pool};
    const auto r = owner.read(make_query(now_epoch(), {"d1"}, {"alpha.exe"}));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == DexReadFault::kPoolTimeout);
}

TEST_CASE("DexAppUsageOwner refuses over its in-flight budget before touching the pool",
          "[dex_usage]") {
    // Budget 0 admits nothing, and the pool is unreachable: a refusal that reached the pool
    // would be a pool timeout instead.
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics, /*concurrent_reads=*/0};
    const auto r = owner.read(make_query(now_epoch(), {"d1"}, {"alpha.exe"}));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == DexReadFault::kConcurrencyBudget);
    CHECK(degraded(metrics, "concurrency_budget") == 1.0);
    CHECK(degraded(metrics, "pool_acquire_timeout") == 0.0);
    CHECK(owner.consecutive_timeouts() == 0);
    // The slot is released on every exit: a second refusal is the same refusal, not a leak.
    CHECK(owner.read(make_query(now_epoch(), {"d1"}, {"alpha.exe"})).error() == DexReadFault::kConcurrencyBudget);
    CHECK(degraded(metrics, "concurrency_budget") == 2.0);
}

TEST_CASE("DexAppUsageOwner releases its slot on every admitted exit", "[dex_usage]") {
    // A budget of one and an unreachable pool: each read is admitted, reaches the pool and
    // times out. A slot that leaked would turn the second read into a budget refusal.
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics, /*concurrent_reads=*/1};
    for (int i = 0; i < 3; ++i) {
        const auto r = owner.read(make_query(now_epoch(), {"d1"}, {"alpha.exe"}));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == DexReadFault::kPoolTimeout);
    }
    CHECK(degraded(metrics, "concurrency_budget") == 0.0);
    CHECK(degraded(metrics, "pool_acquire_timeout") == 3.0);
}

TEST_CASE("DexAppUsageOwner treats no devices as an engaged empty result even with no budget",
          "[dex_usage]") {
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics, /*concurrent_reads=*/0};
    const auto r = owner.read(make_query(now_epoch(), {}, {"alpha.exe"}));
    REQUIRE(r.has_value());
    CHECK(r->cells.empty());
    CHECK(degraded(metrics, "concurrency_budget") == 0.0);
    CHECK(degraded(metrics, "pool_acquire_timeout") == 0.0);
}

TEST_CASE("dex_usage_fault_from_sqlstate maps a statement timeout and nothing else to it", "[dex_usage]") {
    using yuzu::server::dex_usage_fault_from_sqlstate;
    CHECK(dex_usage_fault_from_sqlstate("57014") == DexReadFault::kStatementTimeout);
    CHECK(dex_usage_fault_from_sqlstate("55P03") == DexReadFault::kQueryError);
    CHECK(dex_usage_fault_from_sqlstate("") == DexReadFault::kQueryError);
    CHECK(dex_usage_fault_from_sqlstate(nullptr) == DexReadFault::kQueryError);
}

TEST_CASE("dex_usage_unavailable_detail needs three timeouts AND a two-minute unbroken run",
          "[dex_usage]") {
    using namespace std::chrono_literals;
    using yuzu::server::dex_usage_unavailable_detail;
    const auto st = DexReadFault::kStatementTimeout;
    // A concurrent burst in one stall: enough timeouts, but the run is young.
    CHECK(std::string(dex_usage_unavailable_detail(st, 3, 0s)) == "statement_timeout");
    CHECK(std::string(dex_usage_unavailable_detail(st, 4, 119s)) == "statement_timeout");
    // Sustained: three in a row over two minutes.
    CHECK(std::string(dex_usage_unavailable_detail(st, 3, 120s)) == "fleet_too_large");
    CHECK(std::string(dex_usage_unavailable_detail(st, 9, 600s)) == "fleet_too_large");
    // Old but few.
    CHECK(std::string(dex_usage_unavailable_detail(st, 2, 600s)) == "statement_timeout");
    // Only a statement timeout is ever too large.
    for (const auto f : {DexReadFault::kQueryError, DexReadFault::kPoolTimeout,
                         DexReadFault::kConcurrencyBudget, DexReadFault::kStoreNotOpen})
        CHECK(std::string(dex_usage_unavailable_detail(f, 99, 1h)) == yuzu::server::dex_read_fault_token(f));
}

TEST_CASE("DexAppUsageOwner degrades when no connection can be had", "[pg][dex_usage]") {
    // A saturated pool clamps the owner's bounded acquire to the pool's fast-fail while the
    // test holds the only lease: no sleep, no elapsed-time assertion.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics};
    const std::int64_t now = now_epoch();
    {
        auto held = pool.try_acquire_for(std::chrono::seconds(5));
        REQUIRE(held);
        const auto r = owner.read(make_query(now, {"d1"}, {"alpha.exe"}));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == DexReadFault::kPoolTimeout);
        CHECK(degraded(metrics, "pool_acquire_timeout") == 1.0);
    }
    const auto after = owner.read(make_query(now, {"d1"}, {"alpha.exe"}));
    REQUIRE(after.has_value()); // lease returned: engaged again (nothing seeded)
    CHECK(after->cells.empty());
}

TEST_CASE("DexAppUsageOwner degrades when the statement is blocked", "[pg][dex_usage]") {
    // A second connection holds an ACCESS EXCLUSIVE lock on the usage table and the pool's
    // lock_timeout is short, so the SELECT fails with a real SQLSTATE 55P03 (no sleep, no
    // retry loop). The owner's own 10 s statement_timeout is deliberately not exercised: it
    // would cost 10 s of wall clock per run.
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    DexAppUsageOwner owner{pool};
    const std::int64_t now = now_epoch();

    yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE app_usage_store.agent_last_used IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // A lock timeout (55P03) is a query error, not a statement timeout: it never starts the
    // sustained-timeout run.
    const auto blocked = owner.read(make_query(now, {"d1"}, {"alpha.exe"}));
    REQUIRE_FALSE(blocked.has_value());
    CHECK(blocked.error() == DexReadFault::kQueryError);
    CHECK(owner.consecutive_timeouts() == 0);

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    locker.reset();
    CHECK(owner.read(make_query(now, {"d1"}, {"alpha.exe"})).has_value());
    CHECK(owner.consecutive_timeouts() == 0);
}

TEST_CASE("DexAppUsageOwner reports a real statement timeout, a sustained run and a success that clears it",
          "[pg][dex_usage]") {
    // A lock held on a second connection and a pool whose lock timeout (10 s) is far longer than
    // the owner's 500 ms statement bound: the statement is cancelled with a real SQLSTATE 57014,
    // no sleep. The bound is well above a few milliseconds because the success read runs on this
    // same owner (the run clears per owner) and must not time out on a loaded lane.
    using namespace std::chrono_literals;
    using yuzu::server::kDexUsageTimeoutRunBeforeTooLarge;
    YUZU_REQUIRE_PG_DB_TPL(db, dex_usage_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    yuzu::MetricsRegistry metrics;
    DexAppUsageOwner owner{pool, &metrics, yuzu::server::kDexUsageConcurrentReads, 500ms};
    const std::int64_t now = now_epoch();
    const auto detail = [&](std::chrono::steady_clock::time_point at) {
        return std::string(owner.unavailable_detail(DexReadFault::kStatementTimeout, at));
    };
    // The instant right after a run's FIRST timeout (QE-2: the run start is stamped there only).
    std::chrono::steady_clock::time_point after_first_timeout;
    // Three statement timeouts in a row, under a lock that is released on return.
    const auto timeout_run = [&] {
        yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    locker.get(), "LOCK TABLE app_usage_store.agent_last_used IN ACCESS EXCLUSIVE MODE",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        for (int i = 0; i < 3; ++i) {
            const auto timed_out = owner.read(make_query(now, {"d1"}, {"alpha.exe"}));
            REQUIRE_FALSE(timed_out.has_value());
            CHECK(timed_out.error() == DexReadFault::kStatementTimeout);
            if (i == 0)
                after_first_timeout = std::chrono::steady_clock::now();
        }
        REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    };

    timeout_run();
    CHECK(owner.consecutive_timeouts() == 3);
    CHECK(degraded(metrics, "statement_timeout") == 3.0);
    // Three in a row, but the run is young: still retryable. Two minutes on, the run (stamped by
    // its first timeout) is sustained. Only a statement timeout is ever too large.
    const auto at = std::chrono::steady_clock::now();
    const auto later = at + kDexUsageTimeoutRunBeforeTooLarge + 1s;
    CHECK(detail(at) == "statement_timeout");
    CHECK(detail(later) == "fleet_too_large");
    // The run's start is the FIRST timeout's, not the last: two more real timeouts (500 ms each)
    // ran after `after_first_timeout`, so a start that moved to the last one would be younger than
    // two minutes at that instant plus two minutes.
    CHECK(detail(after_first_timeout + kDexUsageTimeoutRunBeforeTooLarge) == "fleet_too_large");
    CHECK(std::string(owner.unavailable_detail(DexReadFault::kQueryError, later)) == "query_error");

    // A success ends the run: the same far instant is retryable again.
    CHECK(owner.read(make_query(now, {"d1"}, {"alpha.exe"})).has_value());
    CHECK(owner.consecutive_timeouts() == 0);
    CHECK(detail(later) == "statement_timeout");

    // The next run starts its own clock. The first run began at least a second before `before`
    // (two more timeouts of 500 ms each) and this one begins at least 500 ms after it, so at
    // before + 119.5 s a stale start reads as sustained and a fresh one is under two minutes old.
    const auto before = std::chrono::steady_clock::now();
    timeout_run();
    CHECK(detail(before + kDexUsageTimeoutRunBeforeTooLarge - 500ms) == "statement_timeout");
}
