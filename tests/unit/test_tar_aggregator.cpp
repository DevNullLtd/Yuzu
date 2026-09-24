/**
 * test_tar_aggregator.cpp -- Unit tests for the TAR rollup + retention engine
 *
 * Anchors the contract documented in `tar_plugin.cpp` `configure` and
 * `docs/user-manual/tar.md`: disabling a source via `<source>_enabled=false`
 * leaves existing rows queryable. Without the per-source guard in
 * `run_retention()`, time-based retention drains the hourly tier within 24h,
 * the daily tier within 31d, and the monthly tier within ~365d after disable
 * — see issue #539 and the chaos-injector CHAOS-2 reproduction.
 */

#include "tar_aggregator.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "tar_status_format.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <format>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace yuzu::tar;

namespace {

// Issue #539 anchor: 24h cutoff for the hourly tier in the schema registry.
// If the registry's `process_hourly` retention_default ever changes, the
// helpers below have to follow.
constexpr int64_t kHourlyCutoffSec = 24 * 3600;

int64_t row_count(TarDatabase& db, const std::string& table) {
    auto res = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    return std::stoll(res->rows[0][0]);
}

// Seed 48 hourly rows centered on t_now so half (h=0..23) fall inside the
// 24h retention window and half (h=24..47) fall outside it. With the source
// enabled, retention at t_now deletes the outside half only; with the source
// disabled, retention preserves all 48.
void seed_process_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO process_hourly "
                                           "(hour_ts,name,user,start_count,stop_count) "
                                           "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
                                           t_now - h * 3600)));
    }
}

void seed_tcp_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO tcp_hourly "
                                           "(hour_ts,remote_addr,remote_port,proto,process_name,"
                                           "connect_count,disconnect_count) "
                                           "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                                           t_now - h * 3600)));
    }
}

} // namespace

// ── #539 anchor: retention pauses while a source is disabled ────────────────

TEST_CASE("TAR retention: disabled source preserves hourly rows past cutoff",
          "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
    // Reproduction of /governance chaos-injector CHAOS-2. Without the
    // per-source guard, two retention passes (t0+1h and t0+25h) drain
    // process_hourly entirely after the operator disables process_enabled
    // — even though the configure docstring promises queryability.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC
    seed_process_hourly(db, t0);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "false");

    run_retention(db, t0 + 3600, guard);
    run_retention(db, t0 + kHourlyCutoffSec + 3600, guard);

    CHECK(row_count(db, "process_hourly") == 48);
}

TEST_CASE("TAR retention: enabled sources still age out past cutoff",
          "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
    // Counter-test: an enabled source must continue to age out, otherwise
    // the #539 fix would silently disable retention everywhere. With the
    // 48-row centered seed, exactly the rows with hour_ts < (t_now -
    // retention_default) are deleted.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-enabled-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    // Anchor present: this test is about the source-enabled gate, not about the
    // first-pass bootstrap decline (a pass with no stored reading declines once,
    // because the elapsed-time check cannot run without one).
    REQUIRE(db.set_config("retention_guard_last_pass", std::to_string(t_now)));

    REQUIRE(db.get_config("process_enabled", "true") == "true");

    run_retention(db, t_now, guard);

    auto remaining = row_count(db, "process_hourly");
    CHECK(remaining > 0);
    CHECK(remaining < 48);
}

TEST_CASE("TAR retention: re-enabling a source resumes retention", "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
    // Operator journey: freeze for analysis, take an export, re-enable to
    // resume normal aging. The guard is purely config-driven, so flipping
    // <source>_enabled back to "true" must immediately re-arm time-based
    // retention on the next rollup tick.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-resume-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);

    db.set_config("process_enabled", "false");
    run_retention(db, t_now, guard);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "true");
    run_retention(db, t_now, guard);

    auto after_resume = row_count(db, "process_hourly");
    CHECK(after_resume > 0);
    CHECK(after_resume < 48);
}

// ── Wave 7 PR7.2b: usage_daily_user's independent retention target ─────────

TEST_CASE("TAR retention: usage_daily_user prunes independently of usage_daily's own state",
          "[tar][retention][usage]") {
    // Round 2 finding #4 (PR #4177): usage_daily_user used to run only INSIDE
    // usage_daily's own per-pass iteration, sharing that parent's guard
    // verdict — so a tick where usage_daily's own guard declines-to-delete
    // (nothing of ITS OWN past cutoff) meant usage_daily_user's genuinely
    // expired rows were never even considered. This pins the fix: usage_daily
    // has nothing to do this pass, usage_daily_user still prunes its own
    // expired row on its own facts.
    yuzu::tar::RetentionGuardState guard;
    yuzu::test::TempDbFile tmp{std::string_view{"tar-usage-retention-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    constexpr int64_t kUsageDailyWindow = 2678400; // 31 days -- matches the registry
    const int64_t t_now = 1'735'689'600 + kUsageDailyWindow;
    REQUIRE(db.set_config("retention_guard_last_pass", std::to_string(t_now))); // skip bootstrap decline

    // usage_daily itself: ONE recent row, well inside the window -- nothing
    // for ITS OWN guard to do.
    REQUIRE(db.execute_sql(std::format(
        "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
        "last_seen, distinct_users, superseded_runs, expired_runs) VALUES ({}, 'a.exe', 1, 10, "
        "{}, {}, 1, 0, 0)",
        t_now, t_now, t_now)));

    // usage_daily_user: an OLD row past the SAME 31-day window, plus a recent
    // survivor -- proves this table reaches its OWN independent verdict.
    REQUIRE(db.execute_sql(std::format(
        "INSERT INTO usage_daily_user (day_ts, exe_key, user) VALUES ({}, 'old.exe', 'alice')",
        t_now - kUsageDailyWindow - 86400)));
    REQUIRE(db.execute_sql(std::format(
        "INSERT INTO usage_daily_user (day_ts, exe_key, user) VALUES ({}, 'a.exe', 'bob')",
        t_now)));

    run_retention(db, t_now, guard);

    auto count = [&](const std::string& table) {
        auto r = db.execute_query("SELECT COUNT(*) FROM " + table);
        REQUIRE(r.has_value());
        return std::stoi(r->rows[0][0]);
    };
    CHECK(count("usage_daily") == 1);      // usage_daily's own row: nothing expired, untouched
    CHECK(count("usage_daily_user") == 1); // the OLD row pruned; the recent survivor remains
}

// ── PR-A (#547): apply_source_enabled_transition + paused_at semantics ─────

TEST_CASE("TAR paused_at: enabled→disabled writes the timestamp", "[tar][paused_at][pr-a]") {
    // Operator transitions process_enabled from default ("true") to "false"
    // — paused_at must record the wall-clock now passed to the helper.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-disable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.get_config("process_enabled", "true") == "true");
    REQUIRE(db.get_config("process_paused_at", "0") == "0");

    const int64_t t_now = 1'735'689'600;
    REQUIRE(apply_source_enabled_transition(db, "process", "false", t_now));

    CHECK(db.get_config("process_enabled", "true") == "false");
    CHECK(db.get_config("process_paused_at", "0") == std::to_string(t_now));
}

TEST_CASE("TAR paused_at: disabled→enabled clears the timestamp to \"0\"",
          "[tar][paused_at][pr-a]") {
    // After re-enable, paused_at must read "0" (not absent — operators
    // distinguish "never paused" from "no key present"). The reverse
    // transition is the operator-journey close-out: freeze → export →
    // re-enable; the row drops out of the dashboard's retention-paused list.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "tcp", "false", 1'735'689'600));
    REQUIRE(db.get_config("tcp_paused_at", "0") == "1735689600");

    REQUIRE(apply_source_enabled_transition(db, "tcp", "true", 1'735'700'000));

    CHECK(db.get_config("tcp_enabled", "true") == "true");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
}

TEST_CASE("TAR paused_at: recovering an errored source via =true clears the timestamp (#560)",
          "[tar][paused_at][source-lifecycle]") {
    // Regression for the fjarvis-review asymmetry: the disable leg fires on any
    // non-"false" prev ("errored" included), but the re-enable leg used to reset
    // paused_at ONLY on prev == "false". So recovering a corrupt/tampered source
    // — `configure <src>_enabled=true` from an "errored" value — resumed
    // collection yet left a stale non-zero paused_at, and `status` then reported
    // enabled=true alongside a paused timestamp (dashboard renders a collecting
    // source as paused). Both legs now gate on the canonical tri-state, so the
    // recovery clears paused_at. Pre-fix this CHECK held the stale 1735689600.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-560-errored-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // 1) Pause the source for real → paused_at records the wall-clock now.
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    REQUIRE(db.get_config("process_paused_at", "0") == "1735689600");

    // 2) The on-disk _enabled value is then clobbered to a value the plugin
    //    never writes (corruption / tampering) → canonicalises to "errored".
    db.set_config("process_enabled", "maybe");
    REQUIRE(canonical_source_enabled(db.get_config("process_enabled", "true")) == "errored");

    // 3) Operator recovers the source: configure process_enabled=true.
    REQUIRE(apply_source_enabled_transition(db, "process", "true", 1'735'700'000));

    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
}

TEST_CASE("TAR source_enabled: the destructive-purge paused-guard predicate (15.A)",
          "[tar][source-enabled][purge]") {
    // source_enabled is the authoritative guard for tar.purge_source: the action
    // refuses unless this returns false (source is paused). Pin the exact predicate
    // the plugin branches on so a regression that mis-reads the enabled-state — and
    // would let a purge hit an actively-collecting source, or wrongly refuse a
    // paused one — is caught here even though do_purge_source itself lives in the
    // (test-unlinked) plugin TU. Governance B1.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-15a-guard-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // Never configured: a purge-whitelisted source defaults ENABLED → guard refuses
    // (you cannot purge a source you never deliberately paused).
    REQUIRE(source_default_enabled("process"));
    CHECK(source_enabled(db, "process")); // → tar.purge_source REFUSES

    // Paused: enabled=false → guard allows the purge.
    db.set_config("process_enabled", "false");
    CHECK_FALSE(source_enabled(db, "process")); // → tar.purge_source ALLOWED

    // Re-enabled between scan and purge (the TOCTOU the guard closes): true → refuse.
    db.set_config("process_enabled", "true");
    CHECK(source_enabled(db, "process")); // → tar.purge_source REFUSES

    // #560 fail-closed: a tampered/corrupt flag canonicalises to "errored", which
    // is NOT "true", so the source reads disabled — a purge is allowed (operator-
    // targeted, and the flag is already invalid), never wrongly treated as enabled.
    db.set_config("process_enabled", "maybe");
    CHECK_FALSE(source_enabled(db, "process")); // → tar.purge_source ALLOWED (fail-closed)
}

TEST_CASE("TAR paused_at: idempotent re-set leaves the timestamp untouched",
          "[tar][paused_at][pr-a]") {
    // If the operator submits configure with the same value the source
    // already holds, paused_at must NOT advance — otherwise repeated
    // configure round-trips would pretend the pause is fresher than it is,
    // misleading the retention-paused list's "paused since" column.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-idem-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "service", "false", 1'735'689'600));
    REQUIRE(db.get_config("service_paused_at", "0") == "1735689600");

    REQUIRE(apply_source_enabled_transition(db, "service", "false", 1'735'700'000));

    CHECK(db.get_config("service_paused_at", "0") == "1735689600");
}

TEST_CASE("TAR paused_at: per-source isolation", "[tar][paused_at][pr-a]") {
    // Disabling process must not touch tcp / service / user paused_at — the
    // PR-A retention-paused list relies on per-source rows being independent.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-iso-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
    CHECK(db.get_config("service_paused_at", "0") == "0");
    CHECK(db.get_config("user_paused_at", "0") == "0");
}

// ── #538: enabled→disabled clears the snapshot-diff baseline ──────────────
// The lock that serialises this against the collectors lives in the plugin
// (collect_mu_, do_configure) and is not unit-testable here; what IS
// deterministically verifiable — and what fails on pre-fix code — is that the
// transition wipes the diff baseline (so a later re-enable starts clean instead
// of emitting ghost "stopped" events) AND that it wipes the CORRECT key
// (tcp→"network", the easy-to-get-wrong mapping).

TEST_CASE("TAR #538: enabled→disabled clears the diff baseline state",
          "[tar][paused_at][issue538]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-clear-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // Seed a non-empty process baseline (as a live collect cycle would).
    REQUIRE(db.set_state("process", R"([{"pid":1,"name":"init"}])"));
    REQUIRE_FALSE(db.get_state("process").empty());

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_config("process_enabled", "true") == "false");
    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
    // The baseline is gone — re-enable will rebuild from a clean snapshot.
    CHECK(db.get_state("process").empty());
}

TEST_CASE("TAR #538: disabling tcp clears the 'network' baseline key, not 'tcp'",
          "[tar][paused_at][issue538]") {
    // tcp's snapshot-diff baseline lives under "network" (diff_state_key). A
    // clear that targeted the literal source name "tcp" would be a silent no-op
    // and the ghost-death bug would survive — pin the mapping here.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-tcpmap-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("network", R"([{"laddr":"0.0.0.0:22"}])"));
    REQUIRE_FALSE(db.get_state("network").empty());

    REQUIRE(apply_source_enabled_transition(db, "tcp", "false", 1'735'689'600));

    CHECK(db.get_state("network").empty());
}

TEST_CASE("TAR #538: every snapshot-diff source clears its mapped baseline",
          "[tar][paused_at][issue538]") {
    struct Case {
        const char* source;
        const char* state_key;
    };
    const Case cases[] = {{"process", "process"}, {"tcp", "network"},
                          {"service", "service"}, {"user", "user"},
                          {"software", "software"},
                          {"arp", "arp"},         {"dns", "dns"}}; // ADR-0015 snapshot-diff sources

    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-parity-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    for (const auto& c : cases) {
        // Distinct {source,state_key} per row and a fresh source each iteration,
        // so a single shared db is safe (no _enabled carry-over between rows).
        // Seed enabled first: the opt-in sources (arp/dns, default_enabled=false)
        // would otherwise see their first `=false` as a no-op (already off), so
        // the disable leg never fires and the baseline is never cleared. Setting
        // `<source>_enabled=true` makes the subsequent disable a real transition
        // for every source uniformly.
        db.set_config(std::format("{}_enabled", c.source), "true");
        REQUIRE(db.set_state(c.state_key, R"([{"x":1}])"));
        REQUIRE_FALSE(db.get_state(c.state_key).empty());

        REQUIRE(apply_source_enabled_transition(db, c.source, "false", 1'735'689'600));

        CHECK(db.get_state(c.state_key).empty());
    }
}

TEST_CASE("TAR #538: disabling one source does not clear another's baseline",
          "[tar][paused_at][issue538]") {
    // Cross-source isolation: a regression that cleared ALL keys instead of the
    // targeted one would still pass the per-source parity test above. Seed all
    // four side-by-side, disable one, assert only its key is wiped.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-xsrc-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(db.set_state("network", R"([{"laddr":"0.0.0.0:22"}])"));
    REQUIRE(db.set_state("service", R"([{"name":"sshd"}])"));
    REQUIRE(db.set_state("user", R"([{"name":"root"}])"));

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_state("process").empty());       // targeted source cleared
    CHECK_FALSE(db.get_state("network").empty()); // others untouched
    CHECK_FALSE(db.get_state("service").empty());
    CHECK_FALSE(db.get_state("user").empty());
}

TEST_CASE("TAR #538: a failed baseline clear leaves the source ENABLED (UP-1)",
          "[tar][paused_at][issue538]") {
    // Fail-safe ordering: if the baseline clear cannot persist, the disable must
    // NOT take effect — otherwise we'd have a disabled source with a stale
    // baseline, which reintroduces ghost "stopped" events on re-enable while the
    // operator saw success. Inject a clear failure by dropping tar_state so the
    // set_state INSERT prepare fails.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-clearfail-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    db.execute_sql("DROP TABLE tar_state");

    // The disable must report failure and leave the flag enabled.
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    CHECK(db.get_config("process_enabled", "true") == "true"); // still enabled
    CHECK(db.get_config("process_paused_at", "0") == "0");     // never paused
}

TEST_CASE("TAR #538: only the enable→disable TRANSITION clears (idempotent)",
          "[tar][paused_at][issue538]") {
    // The clear must fire on the transition, not on every false-write — a
    // repeated `configure ..._enabled=false` after a re-seed must NOT wipe a
    // freshly-rebuilt baseline (that would re-introduce the race by another door).
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-idem-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600)); // clears
    REQUIRE(db.get_state("process").empty());

    // Something re-seeds the baseline; a second false-write is NOT a transition.
    REQUIRE(db.set_state("process", R"([{"pid":2}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'700'000));

    CHECK_FALSE(db.get_state("process").empty());                   // untouched
    CHECK(db.get_config("process_paused_at", "0") == "1735689600"); // not advanced
}

TEST_CASE("TAR #538: re-enable neither clears nor resurrects the baseline",
          "[tar][paused_at][issue538]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600)); // clears
    REQUIRE(db.get_state("process").empty());

    REQUIRE(apply_source_enabled_transition(db, "process", "true", 1'735'700'000));

    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
    CHECK(db.get_state("process").empty()); // clean baseline preserved
}

TEST_CASE("TAR #538: diff_state_key mapping is the single source of truth", "[tar][issue538]") {
    CHECK(diff_state_key("process") == "process");
    CHECK(diff_state_key("tcp") == "network"); // NOT "tcp"
    CHECK(diff_state_key("service") == "service");
    CHECK(diff_state_key("user") == "user");
    CHECK(diff_state_key("software") == "software");
    CHECK(diff_state_key("arp") == "arp"); // ADR-0015
    CHECK(diff_state_key("dns") == "dns"); // ADR-0015
    CHECK(diff_state_key("mapdrive") == "mapdrive"); // §3.8
    // No snapshot-diff baseline: disabling these is a state no-op.
    CHECK(diff_state_key("perf").empty());
    CHECK(diff_state_key("procperf").empty());
    CHECK(diff_state_key("netqual").empty());
    CHECK(diff_state_key("nonsense").empty());
}

TEST_CASE("TAR #538: every registered capture source is classified by diff_state_key",
          "[tar][issue538]") {
    // Drift guard: diff_state_key and capture_sources() are independent lists.
    // If someone adds a 5th snapshot-diff source to the registry but forgets to
    // map it here, diff_state_key would return empty → the disable-clear becomes
    // a silent no-op and #538 silently regresses for the new source. Pin every
    // registered source to an explicit classification so a new one fails loudly.
    const std::set<std::string_view> diff_sources = {"process", "tcp",  "service",  "user",
                                                      "software", "arp", "dns", "mapdrive"};
    // module is a stream-drained source (EventRing, like the process ETW/ES
    // stream) with no snapshot-diff baseline, so diff_state_key("module") is
    // empty and disabling it is a state no-op — non-diff, same as perf/netqual.
    // netconn (ADR-0020) is high-water-mark based: its only state is the
    // netconn_backfill_hwm config key, and keeping it across a disable is the
    // FEATURE (the OS event log retains the paused window, so a re-enable
    // recovers it losslessly — no ghost events possible, nothing to clear).
    // power/removable (Wave 6) are CURSOR sources: their only durable state is
    // the tar_cursor row, not a snapshot-diff baseline, so diff_state_key is
    // empty for both and apply_source_enabled_transition has nothing to clear.
    // Unlike netconn, they do NOT recover the paused window on re-enable --
    // CursorSource::on_enabled_changed(true) re-baselines forward and emits a
    // capture_gap (tar_cursor.hpp's disable/re-enable contract), so the
    // re-baseline is the source's own responsibility rather than a state clear
    // performed out here.
    const std::set<std::string_view> non_diff_sources = {"perf",     "procperf", "netqual",
                                                          "module",   "netconn",  "power",
                                                          "removable", "usage"};

    for (const auto& src : capture_sources()) {
        const bool is_diff = diff_sources.contains(src.name);
        const bool is_non_diff = non_diff_sources.contains(src.name);
        INFO("source: " << src.name);
        // Every registered source must be explicitly classified as one or the
        // other — a brand-new source matches neither set and fails here.
        CHECK(is_diff != is_non_diff);
        // …and diff_state_key must agree with that classification.
        CHECK(diff_state_key(src.name).empty() == is_non_diff);
    }
}

TEST_CASE("TAR #538: disabling perf/procperf does not touch any baseline state",
          "[tar][paused_at][issue538]") {
    // perf/procperf keep an in-memory previous reading (out of scope for #538);
    // the transition must not error and must leave the state store untouched.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-perf-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])")); // unrelated baseline must survive
    REQUIRE(apply_source_enabled_transition(db, "perf", "false", 1'735'689'600));
    REQUIRE(apply_source_enabled_transition(db, "procperf", "false", 1'735'689'600));

    CHECK(db.get_config("perf_enabled", "true") == "false");
    CHECK_FALSE(db.get_state("process").empty());
}

TEST_CASE("TAR retention: disabling one source does not pause others",
          "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
    // Independence invariant: the guard is per-source. Disabling
    // process_enabled must not freeze tcp / service / user retention —
    // otherwise a future refactor could turn the per-source guard into a
    // global switch without deleting a named test.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-isolation-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    seed_tcp_hourly(db, t_now);
    // Anchor present: this test is about the disabled-source gate, not the
    // first-pass bootstrap decline.
    REQUIRE(db.set_config("retention_guard_last_pass", std::to_string(t_now)));

    db.set_config("process_enabled", "false");
    // tcp_enabled left at default => "true"
    run_retention(db, t_now, guard);

    CHECK(row_count(db, "process_hourly") == 48); // disabled, preserved
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0); // enabled, partially aged
    CHECK(tcp_remaining < 48);
}

// ── #541: configure-time pattern validation ────────────────────────────────

TEST_CASE("TAR validate_config_pattern enforces the length cap", "[tar][configure][issue541]") {
    const std::string ok(yuzu::tar::kMaxPatternLength, 'a');
    const std::string too_long(yuzu::tar::kMaxPatternLength + 1, 'a');
    CHECK_FALSE(yuzu::tar::validate_config_pattern(ok, /*require_min_core_len=*/false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, true).has_value());
}

TEST_CASE("TAR validate_config_pattern enforces the min core length on the STRIPPED core",
          "[tar][configure][issue541]") {
    // require_min_core_len=true (process_stabilization_exclusions): the floor is
    // measured on the EFFECTIVE substring after stripping leading/trailing '*'.
    CHECK(yuzu::tar::validate_config_pattern("a", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("ab", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("abc", true).has_value());
    // `*` does NOT bypass the floor — "*a*" strips to core "a" and would still
    // match almost every process (gov UP-2 / security MEDIUM-1).
    CHECK(yuzu::tar::validate_config_pattern("*a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("*", true).has_value());  // core empty
    CHECK(yuzu::tar::validate_config_pattern("**", true).has_value()); // core empty
    // A long-enough core with wildcards is fine.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*abc*", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("chrome-helper", true).has_value());

    // require_min_core_len=false (redaction_patterns): short patterns allowed —
    // a short redaction substring over-redacts, it does not silently drop events.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("a", false).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*a*", false).has_value());
}

TEST_CASE("TAR parse_pattern_config clamps + sanitises at load (#541 UP-1)",
          "[tar][configure][issue541]") {
    using yuzu::tar::parse_pattern_config;

    // A non-array stored value → nullopt (caller falls back to its default).
    CHECK_FALSE(parse_pattern_config("not json").has_value());
    CHECK_FALSE(parse_pattern_config("\"a string\"").has_value());
    CHECK_FALSE(parse_pattern_config("{\"k\":1}").has_value());

    // Valid empty array → empty vector (explicit "no patterns", not the default).
    auto empty = parse_pattern_config("[]");
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    // Non-string / empty / over-long elements are dropped; valid ones kept.
    std::string over_long(yuzu::tar::kMaxPatternLength + 1, 'x');
    auto mixed = parse_pattern_config(
        std::format("[123, \"keep1\", \"\", \"{}\", true, \"keep2\"]", over_long));
    REQUIRE(mixed.has_value());
    REQUIRE(mixed->size() == 2);
    CHECK((*mixed)[0] == "keep1");
    CHECK((*mixed)[1] == "keep2");

    // Element-count cap: an array of 300 valid strings truncates to the cap.
    std::string big = "[";
    for (int i = 0; i < 300; ++i)
        big += (i ? ",\"pat" : "\"pat") + std::to_string(i) + "\"";
    big += "]";
    auto clamped = parse_pattern_config(big);
    REQUIRE(clamped.has_value());
    CHECK(clamped->size() == yuzu::tar::kMaxPatternArrayElements);

    // Pre-parse byte cap (gov MEDIUM): a blob larger than kMaxPatternConfigBytes is
    // rejected as unparseable (nullopt) BEFORE json::parse, so a multi-MB tampered/
    // legacy value can't be fully parsed + copied every fast cycle. A maximal valid
    // array (just under the cap) still parses.
    std::string oversized = "[\"" + std::string(yuzu::tar::kMaxPatternConfigBytes, 'x') + "\"]";
    CHECK_FALSE(parse_pattern_config(oversized).has_value());
}

TEST_CASE("TAR parse_pattern_config enforces the min-core floor on the LOAD path (#541)",
          "[tar][configure][issue541]") {
    // The REQUIRED gap: load_stabilization_exclusions re-parses the stored value
    // every fast cycle, so the ≥3-char effective-core floor must be enforced HERE
    // (require_min_core_len=true), not only at configure. Otherwise a sub-floor
    // value persisted before the floor existed (a no-tamper upgrade) or written
    // out of band reaches should_redact and silently drops most process events.
    using yuzu::tar::parse_pattern_config;

    // Exclusions loader (floor ON): "a" and "*a*" (core "a") drop, "abc" kept.
    auto excl = parse_pattern_config(R"(["a","*a*","abc"])", /*require_min_core_len=*/true);
    REQUIRE(excl.has_value());
    REQUIRE(excl->size() == 1);
    CHECK((*excl)[0] == "abc");

    // Mixed: only cores ≥3 chars survive; '*' does not buy a pass.
    auto mixed = parse_pattern_config(R"(["ab","*x*","chrome-helper","*abc*"])", true);
    REQUIRE(mixed.has_value());
    REQUIRE(mixed->size() == 2);
    CHECK((*mixed)[0] == "chrome-helper");
    CHECK((*mixed)[1] == "*abc*");

    // Redaction loader (floor OFF, the default): short cores are KEPT — a short
    // redaction substring over-redacts a command line, it never drops an event.
    auto redact = parse_pattern_config(R"(["a","*a*","abc"])");
    REQUIRE(redact.has_value());
    CHECK(redact->size() == 3);
}

// ── $Module rollup wiring (M1 hardening — governance UP-1 / architect BLOCKING) ─

TEST_CASE("TAR rollup: $Module hourly aggregation fires and counts loads only",
          "[tar][module][rollup]") {
    // run_aggregation is now data-driven over capture_sources(); this proves the
    // $Module hourly rollup actually executes (the old hand-maintained steps[]
    // array omitted it, so the registered rollup SQL was dead code) AND that
    // load_count counts only the 'loaded' action — a 'blocked' BYOVD load stays
    // full-fidelity in module_live but is excluded from the aggregate count.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-module-rollup-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC (an hour boundary)
    auto insert_module = [&](std::string_view action) {
        REQUIRE(db.execute_sql(
            std::format("INSERT INTO module_live "
                        "(ts,snapshot_id,action,pid,process_name,module_name,module_dir,"
                        "signed_state,signer,is_kernel) "
                        "VALUES ({}, 1, '{}', 100, 'app.exe', 'evil.dll', 'appdir', "
                        "'unsigned', '', 0)",
                        t0, action)));
    };
    insert_module("loaded");
    insert_module("loaded");
    insert_module("loaded");
    // Every non-'loaded' action must be EXCLUDED from load_count while staying
    // full-fidelity in module_live: a 'blocked' BYOVD load, a boot-gap 'seed',
    // and an 'unloaded' event. They share evil.dll's GROUP-BY tuple (module_name,
    // signer, signed_state, is_kernel), so they fold into the same hourly row —
    // proving the rollup's `action='loaded'` predicate, not just row identity,
    // is what filters them.
    insert_module("blocked");
    insert_module("seed");
    insert_module("unloaded");

    REQUIRE(row_count(db, "module_live") == 6);
    REQUIRE(row_count(db, "module_hourly") == 0);

    run_aggregation(db, t0 + 7200); // boundary two hours on → window covers t0

    REQUIRE(row_count(db, "module_hourly") == 1);
    auto res = db.execute_query("SELECT load_count FROM module_hourly");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    CHECK(std::stoll(res->rows[0][0]) == 3); // only the 3 'loaded'; blocked/seed/unloaded excluded
}

TEST_CASE("TAR rollup: procperf hourly aggregation keeps a kernel-thread and "
          "same-name userspace row SEPARATE (execution-level, not just SQL-string match)",
          "[tar][procperf][rollup]") {
    // The schema test ("hourly rollup SQL exists and groups...") only string-
    // matches that `is_kthread` appears in the GROUP BY; this proves it
    // actually PARTITIONS the aggregation — a kernel thread and a userspace
    // process sharing one `name` (the PF_KTHREAD-flag/comm-collision case,
    // UP-7) must fold into TWO hourly rows, not one mislabelled row that
    // silently mixes kernel-scheduling noise into a real app's numbers.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-procperf-rollup-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC (an hour boundary)
    ProcPerfRow kthread;
    kthread.ts = t0;
    kthread.snapshot_id = 1;
    kthread.name = "collide";
    kthread.instances = 1;
    kthread.cpu_pct = 5.0;
    kthread.ws_bytes = 0;
    kthread.is_kthread = true;

    ProcPerfRow user_proc = kthread;
    user_proc.snapshot_id = 2;
    user_proc.cpu_pct = 40.0;
    user_proc.ws_bytes = 100'000'000;
    user_proc.is_kthread = false;

    REQUIRE(db.insert_proc_perf_samples({kthread, user_proc}));
    REQUIRE(row_count(db, "procperf_live") == 2);
    REQUIRE(row_count(db, "procperf_hourly") == 0);

    run_aggregation(db, t0 + 7200); // boundary two hours on → window covers t0

    // Two rows, not one collapsed row — is_kthread genuinely partitions the
    // GROUP BY rather than merely appearing in its column list.
    REQUIRE(row_count(db, "procperf_hourly") == 2);
    auto res = db.execute_query(
        "SELECT is_kthread, cpu_avg FROM procperf_hourly WHERE name = 'collide' "
        "ORDER BY is_kthread");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 2);
    CHECK(res->rows[0][0] == "0"); // userspace row
    CHECK(std::stod(res->rows[0][1]) == Catch::Approx(40.0));
    CHECK(res->rows[1][0] == "1"); // kernel-thread row
    CHECK(std::stod(res->rows[1][1]) == Catch::Approx(5.0));
}

TEST_CASE("TAR rollup: $Software live→daily→monthly counts by action",
          "[tar][software][rollup]") {
    // The software source has no hourly tier (live → daily → monthly), proving
    // the data-driven aggregator handles a non-uniform granularity set: daily
    // rolls from live and monthly rolls from daily in one pass. Each action gets
    // its own count column.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-software-rollup-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC (day + month boundary)
    auto insert_sw = [&](std::string_view action, std::string_view version,
                         std::string_view prev_version) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO software_live "
            "(ts,snapshot_id,action,name,version,prev_version,publisher,install_date) "
            "VALUES ({}, 1, '{}', '7-Zip', '{}', '{}', 'Acme', '20250101')",
            t0, action, version, prev_version)));
    };
    insert_sw("installed", "23.01", "");
    insert_sw("installed", "23.01", "");
    insert_sw("removed", "23.01", "");
    insert_sw("upgraded", "24.00", "23.01");

    REQUIRE(row_count(db, "software_live") == 4);
    REQUIRE(row_count(db, "software_daily") == 0);
    REQUIRE(row_count(db, "software_monthly") == 0);

    // Aggregate from a point in the FOLLOWING month so both the daily window
    // (covers t0's day) and the monthly window (covers t0's whole month) include
    // the seeded events in a single pass.
    run_aggregation(db, t0 + 45 * 86400); // ~2025-02-15

    REQUIRE(row_count(db, "software_daily") == 1);
    auto daily = db.execute_query(
        "SELECT install_count, remove_count, upgrade_count FROM software_daily");
    REQUIRE(daily.has_value());
    REQUIRE(daily->rows.size() == 1);
    CHECK(std::stoll(daily->rows[0][0]) == 2); // installed
    CHECK(std::stoll(daily->rows[0][1]) == 1); // removed
    CHECK(std::stoll(daily->rows[0][2]) == 1); // upgraded

    REQUIRE(row_count(db, "software_monthly") == 1);
    auto monthly = db.execute_query(
        "SELECT install_count, remove_count, upgrade_count FROM software_monthly");
    REQUIRE(monthly.has_value());
    REQUIRE(monthly->rows.size() == 1);
    CHECK(std::stoll(monthly->rows[0][0]) == 2);
    CHECK(std::stoll(monthly->rows[0][1]) == 1);
    CHECK(std::stoll(monthly->rows[0][2]) == 1);
}

// ── Default-off opt-in sources (review R1 — module/procperf/netqual) ─────────

TEST_CASE("TAR default-off: opt-in source's first disable is a no-op transition",
          "[tar][module][paused_at][default-off]") {
    // The required M1 fix: `module` (and procperf/netqual) default DISABLED on a
    // fresh DB. apply_source_enabled_transition routes the `prev` default through
    // CaptureSourceDef::default_enabled, so the first-ever `module_enabled=false`
    // is NOT an enabled→disabled transition and must write NO paused_at — whereas
    // the same call for the always-on `process` IS a real transition. This is the
    // testable proxy for "tar.status reports module disabled while default-on
    // sources stay enabled" (do_status itself reads the same default_enabled
    // field but is not compiled into the unit-test exe).
    yuzu::test::TempDbFile tmp{std::string_view{"tar-default-off-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600;

    // Opt-in sources default false → first disable is idempotent, no paused_at.
    for (const auto* src : {"module", "procperf", "netqual"}) {
        INFO("opt-in source=" << src);
        CHECK_FALSE(source_default_enabled(src));
        apply_source_enabled_transition(db, src, "false", t_now);
        CHECK(db.get_config(std::format("{}_paused_at", src), "0") == "0");
    }

    // An always-on source defaults true → first disable is a real transition.
    CHECK(source_default_enabled("process"));
    apply_source_enabled_transition(db, "process", "false", t_now);
    CHECK(db.get_config("process_paused_at", "0") == std::to_string(t_now));

    // And enabling an opt-in source IS a transition from its default-off state:
    // it clears paused_at to "0" (present, not absent).
    apply_source_enabled_transition(db, "module", "true", t_now + 100);
    CHECK(db.get_config("module_enabled", "false") == "true");
    CHECK(db.get_config("module_paused_at", "0") == "0");
}

TEST_CASE("TAR retention: a corrupt/errored _enabled value preserves rows, never prunes (#560)",
          "[tar][retention][source-lifecycle]") {
    yuzu::tar::RetentionGuardState guard;
    // The collect-time gate (source_enabled) fails closed on a non-canonical
    // _enabled value, mapping it to "errored". Retention MUST agree and preserve
    // that source's rows — otherwise a tampered or bit-flipped value would stop
    // collection (per the gate) yet still let run_retention prune the forensic
    // window the operator believes is paused, the exact breach #560/#559 guard.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-560-retention-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    seed_tcp_hourly(db, t_now);
    // Anchor present: this test is about the errored-source gate, not the
    // first-pass bootstrap decline.
    REQUIRE(db.set_config("retention_guard_last_pass", std::to_string(t_now)));

    // A value the plugin never writes — canonical_source_enabled => "errored".
    db.set_config("process_enabled", "maybe");
    REQUIRE(canonical_source_enabled(db.get_config("process_enabled", "true")) == "errored");
    // tcp_enabled left at default => "true" (actively, validly enabled).
    run_retention(db, t_now, guard);

    CHECK(row_count(db, "process_hourly") == 48); // errored => preserved, not pruned
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0); // enabled => aged normally
    CHECK(tcp_remaining < 48);
}

TEST_CASE("TAR canonical_source_enabled is a strict tri-state (#560)", "[tar][source-lifecycle]") {
    CHECK(canonical_source_enabled("true") == "true");
    CHECK(canonical_source_enabled("false") == "false");
    // Anything the plugin never writes is flagged, never coerced/guessed.
    CHECK(canonical_source_enabled("FALSE") == "errored");
    CHECK(canonical_source_enabled("0") == "errored");
    CHECK(canonical_source_enabled(" false ") == "errored");
    CHECK(canonical_source_enabled("yes") == "errored");
    CHECK(canonical_source_enabled("") == "errored");
}

// ── #2361: the retention clock guard ───────────────────────────────────────
//
// Time-based retention deletes rows older than `now - retention_default`, with
// `now` read from the endpoint's own clock - the clock in the fleet most likely
// to be wrong (dead CMOS battery, long suspend, cloned VM, boot before NTP
// converges). The delete used to be unbounded, so one bad reading took the
// whole forensic window with it. These tests drive `run_retention` at explicit
// timestamps, so nothing here depends on the real clock.

namespace {

// Insert `count` process_hourly rows all stamped at exactly `ts`.
void seed_process_hourly_at(TarDatabase& db, int64_t ts, int count) {
    REQUIRE(db.execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < count; ++i) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO process_hourly "
                                           "(hour_ts,name,user,start_count,stop_count) "
                                           "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
                                           ts)));
    }
    REQUIRE(db.execute_sql("COMMIT"));
}

// Insert `count` process_monthly rows all stamped at exactly `ts`. The monthly
// tier is the one whose retention window (~365d) exceeds kTarMinBigStepSec, so
// it is the only tier that can tell an ABSOLUTE step threshold apart from the
// max(window, constant) shape an earlier round used.
void seed_process_monthly_at(TarDatabase& db, int64_t ts, int count) {
    REQUIRE(db.execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < count; ++i) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO process_monthly "
                                           "(month_ts,name,user,start_count,stop_count) "
                                           "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
                                           ts)));
    }
    REQUIRE(db.execute_sql("COMMIT"));
}

struct TarGuardFixture {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-2361-"}};
    std::optional<TarDatabase> db;
    yuzu::tar::RetentionGuardState guard;

    // `prime_anchor` seeds the persisted clock reading, so the fixture models a
    // store that HAS run before -- which is every pass but one in the life of a
    // database, and the state nearly every test below is about.
    //
    // It matters because "no stored reading" is itself a decline trigger: the
    // elapsed-time detector cannot run without an anchor, and an endpoint whose
    // FIRST guarded pass happens under an already-wrong clock would otherwise
    // delete with no decline and then persist the bad clock (Sol adversarial
    // review). Tests about that bootstrap path pass false and assert the decline.
    explicit TarGuardFixture(bool prime_anchor = true) {
        auto opened = TarDatabase::open(tmp.path);
        REQUIRE(opened.has_value());
        db.emplace(std::move(*opened));
        REQUIRE(db->create_warehouse_tables());
        if (prime_anchor)
            REQUIRE(db->set_config("retention_guard_last_pass", std::to_string(1'735'689'600)));
    }
};

// The guard's maps are mutex-protected, so read them through the public
// snapshot rather than touching the members directly.
int64_t declines_of(const yuzu::tar::RetentionGuardState& g, const std::string& table) {
    const auto c = yuzu::tar::retention_guard_counters(g);
    auto it = c.declines.find(table);
    return it == c.declines.end() ? 0 : it->second;
}
int64_t failures_of(const yuzu::tar::RetentionGuardState& g, const std::string& table) {
    const auto c = yuzu::tar::retention_guard_counters(g);
    auto it = c.failures.find(table);
    return it == c.failures.end() ? 0 : it->second;
}
bool reported_of(const yuzu::tar::RetentionGuardState& g, const std::string& table) {
    std::lock_guard lock(g.mu);
    return g.last_reported.contains(table);
}

// A fixed "now" far from both the epoch and the real clock.
constexpr int64_t kT0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC

} // namespace

TEST_CASE("TAR #2361: a pass that would delete every datable row declines once",
          "[tar][retention][clock-guard]") {
    TarGuardFixture f;
    // Every row well past the 24h hourly cutoff: a forward clock jump looks
    // exactly like this.
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 20); // nothing deleted
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: an identical repeat is suppressed, so a genuine backlog still drains",
          "[tar][retention][clock-guard]") {
    // Declining every pass would turn the guard into a permanent retention leak
    // on any endpoint whose warehouse is legitimately all-expired.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);
    REQUIRE(row_count(*f.db, "process_hourly") == 20);

    run_retention(*f.db, kT0 + 1, f.guard); // suppressed repeat: accepted this time
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK(declines_of(f.guard, "process_hourly") == 1); // not counted twice
}

TEST_CASE("TAR #2361: the recorded fact set clears once the backlog drains, re-arming the guard",
          "[tar][retention][clock-guard]") {
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);     // decline #1
    run_retention(*f.db, kT0 + 1, f.guard); // drain
    run_retention(*f.db, kT0 + 2, f.guard); // nothing expired -> entry clears
    REQUIRE(row_count(*f.db, "process_hourly") == 0);

    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // fresh anomaly
    run_retention(*f.db, kT0 + 3, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 5);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
}

TEST_CASE("TAR #2361: one future-dated row cannot disarm the guard",
          "[tar][retention][clock-guard]") {
    // A row stamped implausibly far ahead - written while the clock was skewed
    // forward, or carried in by a VM clone - can never itself be too old. If it
    // counted as an ordinary survivor it would answer "no, this pass would not
    // delete everything" for the life of the endpoint, disarming the guard
    // exactly when it is needed.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 + yuzu::tar::kTarRetentionFutureSlackSec + 3600, 1);

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 21); // still declines
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: an in-window survivor means no wipe, so the pass deletes immediately",
          "[tar][retention][clock-guard]") {
    // The healthy steady state. The guard must be invisible here.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // inside the 24h window

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(declines_of(f.guard, "process_hourly") == 0);
}

TEST_CASE("TAR #2361: a sub-window forward jump is caught by the step check",
          "[tar][retention][clock-guard]") {
    // The outcome test alone only fires when a jump exceeds a table's WHOLE
    // retention window. A jump of just over one window expires a large slice
    // while leaving survivors, which the cap bounds but nothing would report.
    TarGuardFixture f;
    // Past the FLOOR (kTarMinBigStepSec), not merely past the 24h window: on an
    // endpoint, a day of downtime is routine and must not report as a clock jump.
    const int64_t later = kT0 + yuzu::tar::kTarMinBigStepSec + 1;

    // Each reading needs its OWN survivor inside its datable horizon: a row
    // beyond `now + slack` is treated as forward-skewed and excluded, so reusing
    // one row would make the first pass decline for the wrong reason.
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // expired at both readings
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);                  // survivor for pass 1
    run_retention(*f.db, kT0, f.guard);
    REQUIRE(row_count(*f.db, "process_hourly") == 1);
    REQUIRE(declines_of(f.guard, "process_hourly") == 0);

    seed_process_hourly_at(*f.db, kT0 - 9 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, later - 3600, 1); // survivor for pass 2
    run_retention(*f.db, later, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 7); // nothing deleted
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: a month-long jump fires on the MONTHLY tier",
          "[tar][retention][clock-guard]") {
    // The mutation-pinning sibling of the audit store's DEFAULT-retention test.
    //
    // The threshold used to be max(tier window, kTarMinBigStepSec). On the monthly
    // tier that window is ~365 days, which put the threshold a YEAR out, so the
    // step check could never fire there -- and the outcome test is separately
    // defeated by any row written after the jump, which do_rollup reliably
    // produces. Both detectors were inert on the tier holding the LONGEST
    // forensic history, which is the one an investigator reaches for.
    //
    // Every other step test in this file uses process_hourly (window 86400s),
    // where the 30-day constant dominated under BOTH shapes -- which is exactly
    // why none of them caught it, and why this one must use the monthly tier.
    constexpr int64_t kMonthlyWindow = 31536000; // process/monthly, tar_schema_registry.cpp
    static_assert(kMonthlyWindow > yuzu::tar::kTarMinBigStepSec,
                  "the monthly window must exceed the constant, or this test cannot tell an "
                  "absolute threshold apart from max(window, constant) and stops pinning it");
    TarGuardFixture f;

    // Pass 1: an expired backlog plus an in-window survivor, so would_wipe is
    // false and the pass deletes normally, anchoring the stored clock reading.
    seed_process_monthly_at(*f.db, kT0 - kMonthlyWindow - 100, 5);
    seed_process_monthly_at(*f.db, kT0 - 3600, 1); // survivor for pass 1
    run_retention(*f.db, kT0, f.guard);
    REQUIRE(row_count(*f.db, "process_monthly") == 1);
    REQUIRE(declines_of(f.guard, "process_monthly") == 0);

    // 45 days on: comfortably past the 30-day constant, nowhere near the 365-day
    // window. Under max(window, constant) this jump is invisible on this tier.
    const int64_t jumped = kT0 + 45 * 86400;
    seed_process_monthly_at(*f.db, kT0 - kMonthlyWindow - 50, 5);
    seed_process_monthly_at(*f.db, jumped - 3600, 1); // survivor, so only the STEP can fire
    run_retention(*f.db, jumped, f.guard);

    CHECK(row_count(*f.db, "process_monthly") == 7); // nothing deleted
    CHECK(declines_of(f.guard, "process_monthly") == 1);
}

TEST_CASE("TAR #2361: an ordinary over-cap backlog records no fact set",
          "[tar][retention][clock-guard]") {
    // The recorded entry tracks the WIPE condition, not the backlog. Recording
    // one on any capped pass would leave a busy endpoint permanently reported,
    // and a real clock anomaly arriving next would then delete with no decline
    // and no counter. kSurplus is deliberately independent of the cap.
    constexpr int64_t kSurplus = 7;
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec,
                           static_cast<int>(yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus));
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: a backlog, not an anomaly

    run_retention(*f.db, kT0, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == kSurplus + 1); // one cap's worth deleted
    CHECK(declines_of(f.guard, "process_hourly") == 0);

    run_retention(*f.db, kT0 + 1, f.guard); // finish the backlog
    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(declines_of(f.guard, "process_hourly") == 0);

    // Now a real anomaly. A recorded entry would let this delete silently.
    REQUIRE(f.db->execute_sql("DELETE FROM process_hourly"));
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 3);
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 3);
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: a disabled source with all-expired rows neither declines nor deletes",
          "[tar][retention][clock-guard][issue539]") {
    // The #539/#560 source gate stays strictly ahead of any guard bookkeeping. A
    // paused or errored source is not a candidate for deletion, so it must not
    // burn a decline counter (or an operator-facing warn) either - that would
    // report a clock anomaly on an endpoint whose clock is fine.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    SECTION("paused") { f.db->set_config("process_enabled", "false"); }
    SECTION("errored") { f.db->set_config("process_enabled", "maybe"); }

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 20);
    CHECK(declines_of(f.guard, "process_hourly") == 0);
}

TEST_CASE("TAR #2361: row-count retention still trims, unguarded, under a bad clock",
          "[tar][retention][clock-guard]") {
    // Row-count retention trims only the excess over a fixed ceiling and is
    // computed with no clock at all, so no clock reading can make it delete more
    // than it always would. It is therefore deliberately NOT clock-guarded and
    // NOT declined. It IS capped -- not for the clock, but because the whole
    // batch runs under one held database mutex (see the dedicated cap test). `netqual_boot` has a 400-row ceiling, small enough to
    // exercise the trim directly: seeding 410 ancient rows must still leave
    // exactly 400 and must not touch the decline counters.
    constexpr int kBootCeiling = 400;
    constexpr int kOver = 10;
    TarGuardFixture f;
    f.db->set_config("netqual_enabled", "true"); // opt-in source
    REQUIRE(f.db->execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < kBootCeiling + kOver; ++i) {
        REQUIRE(f.db->execute_sql(std::format("INSERT INTO netqual_boot (ts,boot_ts,window_s) "
                                              "VALUES ({}, {}, 60)",
                                              kT0 - 10 * kHourlyCutoffSec,
                                              kT0 - 10 * kHourlyCutoffSec - 60)));
    }
    REQUIRE(f.db->execute_sql("COMMIT"));

    // Every row is "ancient" by the clock the pass is handed.
    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "netqual_boot") == kBootCeiling);
    CHECK(declines_of(f.guard, "netqual_boot") == 0);
    CHECK(reported_of(f.guard, "netqual_boot") == false);
}

TEST_CASE("TAR #2361: a table whose count cannot be read is skipped, not declined",
          "[tar][retention][clock-guard]") {
    // Fail closed on an unreadable count: a count we could not read is not
    // evidence that deleting is safe. The table is skipped for the pass, its
    // entry is CLEARED (re-armed, so a failed pass cannot spend the guard), no
    // decline is recorded against it, and the rest of the sweep still runs.
    //
    // Dropping the table is the cheap way to force the count to error. Note this
    // covers the skip, the no-spurious-decline, and the keep-going properties;
    // the "delete anyway" variant is not separable here, because every cheap way
    // to break the count also breaks the delete that would follow it.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    for (int h = 0; h < 20; ++h) {
        REQUIRE(f.db->execute_sql(
            std::format("INSERT INTO tcp_hourly (hour_ts,remote_addr,remote_port,proto,"
                        "process_name,connect_count,disconnect_count) "
                        "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                        kT0 - 10 * kHourlyCutoffSec)));
    }
    REQUIRE(f.db->execute_sql("DROP TABLE process_hourly"));

    run_retention(*f.db, kT0, f.guard);

    CHECK(declines_of(f.guard, "process_hourly") == 0); // unreadable, not "anomalous"
    CHECK(reported_of(f.guard, "process_hourly") == false);
    // The sweep kept going: tcp_hourly is all-expired, so it declines normally.
    CHECK(declines_of(f.guard, "tcp_hourly") == 1);
    CHECK(row_count(*f.db, "tcp_hourly") == 20);
}

TEST_CASE("TAR #2361: concurrent rollup passes are race-free when the caller serialises",
          "[tar][retention][clock-guard]") {
    // do_rollup is reachable from two places at once: the 900s `tar.rollup`
    // trigger and an operator-issued manual `tar rollup`.
    //
    // BE PRECISE ABOUT WHAT THIS PROVES. RetentionGuardState now carries its own
    // mutex, so the raw data race on the maps is gone: removing the lock_guard
    // below does NOT make TSan report (verified, not assumed). What the caller's
    // lock still buys is PASS-level atomicity -- each table's probe / decide /
    // update-entry sequence spans several statements, so two interleaved passes
    // could both see an unreported table and both decline it, or both queue a
    // delete for it. TSan cannot see that; it is a logical race, not a data race.
    //
    // So this case is a coherence check under real concurrency, NOT a proof of
    // the plugin's locking. TarPlugin is translation-unit-local and unreachable
    // from a test, so `rollup_mu_` itself has no direct coverage. The audit
    // store's sibling test IS a genuine TSan target, because its dedup state is
    // guarded only by the store mutex (verified: removing it reports).
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 200);

    std::mutex rollup_mu;
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 5; ++i) {
                std::lock_guard lock(rollup_mu);
                run_retention(*f.db, kT0 + t * 10 + i, f.guard);
            }
        });
    }
    for (auto& th : threads)
        th.join();

    // First pass declines, the rest drain it. The exact interleaving is not
    // pinned -- what is pinned is that the state stays coherent: the table ends
    // empty and exactly one decline was recorded.
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: a status reader racing a rollup is safe (guard.mu has teeth)",
          "[tar][retention][clock-guard]") {
    // Governance Gate 3 found the test above has NO teeth on `guard.mu`: every
    // run_retention call there is wrapped in the test's own `rollup_mu`, so the
    // calls never overlap and nothing ever races the guard's maps. Removing the
    // internal `lock_guard(guard.mu)` would not redden it.
    //
    // The production race it should model is real: `tar status` calls
    // format_retention_guard_lines -> retention_guard_counters (taking guard.mu)
    // on the command-dispatch thread, while do_rollup -> run_retention writes
    // guard.declines / guard.failures / guard.last_reported on the rollup thread.
    // do_status deliberately does NOT take rollup_mu_, precisely so a diagnostic
    // cannot block behind a rollup -- so guard.mu is the ONLY thing making that
    // std::map access safe.
    //
    // This reproduces it: a reader outside any external lock, concurrent with
    // writers. Under TSan, removing the lock_guard in retention_guard_counters
    // (or the ones around the map writes in run_retention) reports a race here.
    // The writers must touch the SAME maps the reader copies. An earlier version
    // of this test seeded a healthy table, which only ever wrote `guard.latched`
    // -- while the reader copies `declines`/`failures`/`delete_failures`. Two
    // threads hammering disjoint state is not a race, and TSan correctly said
    // nothing even with every guard.mu removed. Dropping a table makes its probe
    // fail, so EVERY pass writes `guard.failures[...]`, which the reader reads.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    REQUIRE(f.db->execute_sql("DROP TABLE process_hourly"));

    std::atomic<bool> stop{false};
    std::atomic<int> reads{0};
    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            // Both public readers of the guard state, on the exact path
            // `tar status` uses.
            const auto counters = yuzu::tar::retention_guard_counters(f.guard);
            const auto lines = yuzu::tar::format_retention_guard_lines(f.guard);
            (void)counters.declines.size();
            (void)lines.size();
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });
    struct Joiner {
        std::atomic<bool>& stop;
        std::thread& t;
        ~Joiner() {
            stop.store(true, std::memory_order_relaxed);
            if (t.joinable())
                t.join();
        }
    } joiner{stop, reader};

    // Writers serialise among THEMSELVES, exactly as rollup_mu_ does in
    // production -- but that lock does not exclude the reader above, and that
    // asymmetry is the whole point. guard.mu is the only thing between them.
    std::mutex rollup_mu;
    std::vector<std::thread> writers;
    for (int t = 0; t < 3; ++t)
        writers.emplace_back([&, t] {
            for (int i = 0; i < 10; ++i) {
                std::lock_guard lock(rollup_mu);
                run_retention(*f.db, kT0 + t * 10 + i, f.guard);
            }
        });
    for (auto& th : writers)
        th.join();

    stop.store(true, std::memory_order_relaxed);
    if (reader.joinable())
        reader.join();

    // The assertion is mostly that we got here without TSan reporting; still,
    // pin that the reader actually ran and the state stayed coherent.
    CHECK(reads.load() > 0);
    // Every pass failed to probe the dropped table, so the map the reader was
    // copying was genuinely being written throughout.
    CHECK(failures_of(f.guard, "process_hourly") > 0);
}

TEST_CASE("TAR #2361: retention_sql's SQL text is unchanged (the guard reroutes at the caller)",
          "[tar][retention][clock-guard]") {
    // test_tar_warehouse.cpp and test_tar_perf.cpp pin retention_sql's exact
    // output. The guard therefore lives in run_retention, NOT in retention_sql -
    // this restates that contract locally so a future refactor that "tidies" the
    // guard into retention_sql fails here rather than in an unrelated file.
    const auto time_based = retention_sql("process_hourly", kT0);
    CHECK(time_based == std::format("DELETE FROM process_hourly WHERE hour_ts < {}",
                                    kT0 - kHourlyCutoffSec));
    CHECK(time_based.find("LIMIT") == std::string::npos);
}

TEST_CASE("TAR #2361: the clock-step check survives an agent restart",
          "[tar][retention][clock-guard]") {
    // The governance finding this pins. The outcome test is defeated by any row
    // written after the jump -- and `do_rollup` reliably produces one, since
    // `run_aggregation` runs FIRST and mints rows into the very tables retention
    // then reads. That leaves the elapsed-time check as the only detector, and
    // held in memory it compares against zero on the first pass of a process, so
    // an agent that BOOTS with a wrong RTC would never see a step at all.
    //
    // Persisting the reading in tar_config closes it: a fresh guard state (the
    // agent restarting) still knows when the last pass ran.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // expired
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);                  // survivor
    run_retention(*f.db, kT0, f.guard);
    REQUIRE(declines_of(f.guard, "process_hourly") == 0);

    // Agent restarts: brand-new in-memory guard state, same database.
    yuzu::tar::RetentionGuardState fresh;
    const int64_t jumped = kT0 + yuzu::tar::kTarMinBigStepSec + 1;
    seed_process_hourly_at(*f.db, kT0 - 9 * kHourlyCutoffSec, 5); // expired at the new reading
    seed_process_hourly_at(*f.db, jumped - 60, 1);                // survivor at the new reading

    run_retention(*f.db, jumped, fresh);

    CHECK(declines_of(fresh, "process_hourly") == 1);
    CHECK(row_count(*f.db, "process_hourly") == 7); // nothing deleted on the declining pass
}

TEST_CASE("TAR #2361: an unreadable table re-arms the guard and is counted separately",
          "[tar][retention][clock-guard]") {
    // Two contracts in one. (1) A failed probe must RE-ARM the guard -- clear
    // any recorded fact set, not carry it: the audit store learned this and the
    // TAR sibling originally did not, so a table that declined, then failed to
    // read for a while, would delete the next real anomaly silently. (2) A read
    // failure is NOT a clock anomaly, so it gets its own counter -- otherwise
    // `retention_guard_declines_total|0` reports "this endpoint's clock is
    // fine" about a table whose retention has actually stopped.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard); // decline #1, fact set recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    // Probes fail for exactly one pass.
    REQUIRE(f.db->execute_sql("ALTER TABLE process_hourly RENAME TO process_hourly_hidden"));
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(failures_of(f.guard, "process_hourly") == 1);
    CHECK(declines_of(f.guard, "process_hourly") == 1); // NOT counted as a clock anomaly
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // re-armed
    REQUIRE(f.db->execute_sql("ALTER TABLE process_hourly_hidden RENAME TO process_hourly"));

    // The same wipe condition, still unresolved: must decline again rather than
    // delete on an entry the failure had erased.
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 20);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
}

TEST_CASE("TAR #2361: the status lines always carry both totals",
          "[tar][retention][clock-guard]") {
    // `do_status` lives on a translation-unit-local class and cannot be reached
    // from a test, so the operator-facing FORMAT is pinned here instead. A zero
    // declines total is only meaningful alongside a zero failures total: without
    // the second line, a table whose probes fail every pass reports as a healthy
    // clock.
    yuzu::tar::RetentionGuardState g;
    auto lines = yuzu::tar::format_retention_guard_lines(g);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "retention_guard_declines_total|0");
    CHECK(lines[1] == "retention_guard_failures_total|0");

    {
        std::lock_guard lock(g.mu);
        g.declines["process_hourly"] = 3;
        g.declines["tcp_hourly"] = 0; // zero entries are not emitted
        g.failures["module_hourly"] = 2;
    }
    lines = yuzu::tar::format_retention_guard_lines(g);
    REQUIRE(lines.size() == 4);
    CHECK(lines[0] == "retention_guard|process_hourly|3");
    CHECK(lines[1] == "retention_guard_failed|module_hourly|2");
    CHECK(lines[2] == "retention_guard_declines_total|3");
    CHECK(lines[3] == "retention_guard_failures_total|2");
}

TEST_CASE("TAR #2361: every registered granularity declares the ts column its suffix maps to",
          "[tar][retention][clock-guard][registry]") {
    // `ts_column_for_suffix` is public API with three consumers now (the DDL's
    // index, retention_sql's time branch, and this guard) and it falls back to
    // "ts" for an unknown suffix. A future granularity with a suffix it does not
    // know -- `weekly`/`week_ts` -- would silently get an index on a column that
    // does not exist, aborting the warehouse DDL, and a guard that counts a
    // different column from the one the delete acts on.
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            const auto ts_col = ts_column_for_suffix(g.suffix);
            const bool declared =
                std::any_of(g.columns.begin(), g.columns.end(),
                            [&](const auto& c) { return c.name == ts_col; });
            INFO("source=" << src.name << " granularity=" << g.suffix << " ts_col=" << ts_col);
            CHECK(declared);
        }
    }
}

TEST_CASE("TAR #2361: an endpoint that was simply switched off is not a clock anomaly",
          "[tar][retention][clock-guard]") {
    // Governance UP-2, and the one that mattered most on the agent side: the
    // shortest time-based window here is 24h, so without a floor every laptop off
    // over a weekend, every suspended VM and every upgrade window longer than a
    // day would report "this endpoint's clock moved" and make the fleet-wide
    // decline counter meaningless.
    TarGuardFixture f;
    const int64_t later = kT0 + 3 * 86400; // a long weekend, far past the 24h window

    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);
    run_retention(*f.db, kT0, f.guard);
    REQUIRE(declines_of(f.guard, "process_hourly") == 0);

    seed_process_hourly_at(*f.db, kT0 - 9 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, later - 3600, 1);
    run_retention(*f.db, later, f.guard);

    CHECK(declines_of(f.guard, "process_hourly") == 0); // silent, as it must be
}

TEST_CASE("TAR #2361: a poisoned last-pass reading declines once and re-anchors",
          "[tar][retention][clock-guard]") {
    // Governance UP-1. `tar_config` sits on a device the user may control, so a
    // far-future value is both a tampering vector and an ordinary consequence of
    // a pass that ran under a forward-skewed clock. Either way it must not be
    // trusted into arithmetic.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: only the reading is wrong
    f.db->set_config("retention_guard_last_pass", "9223372036854775807");

    run_retention(*f.db, kT0, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 1);
    CHECK(row_count(*f.db, "process_hourly") == 6); // nothing deleted

    run_retention(*f.db, kT0 + 1, f.guard); // re-anchored, proceeds normally
    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: pausing a source clears its recorded fact sets so the guard is not spent",
          "[tar][retention][clock-guard][issue539]") {
    // Governance UP-9. The #539 gate skips a paused source before any guard
    // bookkeeping, so an entry recorded by a live anomaly used to survive the
    // pause untouched -- and the first pass after the operator re-enabled the
    // source would delete capped, with no decline, no counter and no warn,
    // even though the anomaly was still live.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard); // decline #1, fact set recorded
    REQUIRE(reported_of(f.guard, "process_hourly"));

    f.db->set_config("process_enabled", "false");
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // cleared while paused
    CHECK(row_count(*f.db, "process_hourly") == 20);

    f.db->set_config("process_enabled", "true");
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 20); // declines again, not deletes
    CHECK(declines_of(f.guard, "process_hourly") == 2);
}

TEST_CASE("TAR #2361: a failed delete is counted, so the totals stay honest",
          "[tar][retention][clock-guard]") {
    // Governance UP-3 / consistency B2: the third call site the first hardening
    // round did not sweep. The docs promise that a zero declines total only means
    // the clock is fine IF the failures total is also zero -- which was false
    // while a DELETE could fail every pass and increment nothing.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: the pass is accepted
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 6);     // nothing removed
    CHECK(failures_of(f.guard, "process_hourly") == 1); // exactly once, not double-counted
    CHECK(declines_of(f.guard, "process_hourly") == 0); // not misreported as a clock anomaly
}

TEST_CASE("TAR #2361: a clean drain clears the recorded fact set in the SAME pass",
          "[tar][retention][clock-guard]") {
    // Sol / Gate 8, the agent twin. Keying purely on the pre-delete
    // `would_wipe` left an entry recorded after a pass that drained the whole
    // backlog, so an anomaly arriving before the next 900s tick deleted with no
    // decline and no counter.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20); // under the cap

    run_retention(*f.db, kT0, f.guard); // decline, fact set recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    run_retention(*f.db, kT0 + 1, f.guard); // drains it entirely
    REQUIRE(row_count(*f.db, "process_hourly") == 0);
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // cleared by the drain itself

    // A fresh anomaly with no intervening empty pass must still decline.
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 4);
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 4);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
}

TEST_CASE("TAR #2361: an implausible stored reading is an anomaly, not a quiet reset",
          "[tar][retention][clock-guard]") {
    // On an endpoint the operator may control this row outright. Quietly
    // accepting a value that no pass could have written is precisely how an
    // adversary disables the step check while `tar status` reports healthy.
    auto declines_after = [](const char* stored) {
        TarGuardFixture f;
        seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
        seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: only the state is wrong
        f.db->set_config("retention_guard_last_pass", stored);
        run_retention(*f.db, kT0, f.guard);
        return declines_of(f.guard, "process_hourly");
    };
    CHECK(declines_after("-1") == 1);              // negative
    CHECK(declines_after("not-a-number") == 1);    // unparseable
    CHECK(declines_after("99999999999999") == 1);  // far ahead of now
}

TEST_CASE("TAR #2361: a failed persist of the clock reading is reported",
          "[tar][retention][clock-guard]") {
    // `set_config` used to return void, so a write that never landed left the
    // guard with no comparison point on every future pass, permanently, with
    // nothing to report -- and on an endpoint an adversary can arrange that.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_cfg BEFORE UPDATE ON tar_config "
                              "WHEN NEW.key = 'retention_guard_last_pass' "
                              "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
    // Seed the key so the write is an UPDATE the trigger can block.
    run_retention(*f.db, kT0, f.guard);
    const auto first = failures_of(f.guard, "__clock_state__");
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(failures_of(f.guard, "__clock_state__") > first);
}

TEST_CASE("TAR #2361: a delete failure stops the pass instead of leaking autocommits",
          "[tar][retention][clock-guard]") {
    // Some SQLite errors abort the transaction automatically. Continuing the loop
    // would then run the remaining deletes as AUTOCOMMITS that the guard's
    // ROLLBACK cannot undo -- deletions escaping the transaction meant to contain
    // them. The pass now stops at the first failure and reports every queued
    // table, because the transaction is going to be rolled back anyway.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);
    // tcp_hourly must be ACCEPTED (a survivor, so it is not declined) or it never
    // reaches the plan list and the leak this test hunts for cannot occur.
    auto seed_tcp = [&](int64_t ts, int n) {
        for (int h = 0; h < n; ++h) {
            REQUIRE(f.db->execute_sql(
                std::format("INSERT INTO tcp_hourly (hour_ts,remote_addr,remote_port,proto,"
                            "process_name,connect_count,disconnect_count) "
                            "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                            ts)));
        }
    };
    seed_tcp(kT0 - 10 * kHourlyCutoffSec, 5); // expired
    seed_tcp(kT0 - 3600, 1);                  // survivor -> accepted, queued
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ROLLBACK, 'aborted'); END;"));

    run_retention(*f.db, kT0, f.guard);

    // Nothing was removed anywhere: the aborting statement stopped the pass and
    // the rest never ran as autocommits.
    CHECK(row_count(*f.db, "process_hourly") == 6);
    CHECK(row_count(*f.db, "tcp_hourly") == 6); // its 5 expired rows survive too
    CHECK(failures_of(f.guard, "process_hourly") >= 1);
}

TEST_CASE("TAR #2361: a NON-aborting statement error fails one table, not the whole pass",
          "[tar][retention][clock-guard]") {
    // The other side of the test above, and the one that was missing.
    //
    // RAISE(ABORT) backs out the current STATEMENT and leaves the transaction
    // intact; RAISE(ROLLBACK) kills the transaction. The batch used to `break`
    // on both, so a single permanently-broken table -- a missing column after a
    // partial DDL, one corrupt index -- rolled back every pass forever and
    // tar.db grew without bound on the endpoint behind one warn line. Before the
    // batch existed each statement ran independently and the COMMIT kept the
    // successes, so that was a silent regression (governance Gate 3, cpp-expert).
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor -> accepted, queued
    auto seed_tcp = [&](int64_t ts, int n) {
        for (int h = 0; h < n; ++h) {
            REQUIRE(f.db->execute_sql(
                std::format("INSERT INTO tcp_hourly (hour_ts,remote_addr,remote_port,proto,"
                            "process_name,connect_count,disconnect_count) "
                            "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                            ts)));
        }
    };
    seed_tcp(kT0 - 10 * kHourlyCutoffSec, 5); // expired -> must still be deleted
    seed_tcp(kT0 - 3600, 1);                  // survivor -> accepted, queued
    // ABORT, deliberately, NOT ROLLBACK: the transaction survives this one.
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ABORT, 'one bad table'); END;"));

    run_retention(*f.db, kT0, f.guard);

    // The broken table keeps everything and is counted...
    CHECK(row_count(*f.db, "process_hourly") == 6);
    CHECK(failures_of(f.guard, "process_hourly") >= 1);
    // ...while the healthy table's expired rows are still collected. Under the
    // unconditional break this was 6, i.e. retention had stopped fleet-wide on
    // this endpoint because of one table.
    CHECK(row_count(*f.db, "tcp_hourly") == 1);
    CHECK(failures_of(f.guard, "tcp_hourly") == 0);
}

TEST_CASE("TAR #2361: a rolled-back retention pass does not discard another writer's work",
          "[tar][retention][clock-guard]") {
    // Kimi / Gate 8, and the defect that survived four rounds: driving
    // BEGIN/COMMIT through execute_sql releases the database mutex between
    // statements, so a concurrent collector INSERT or set_config joined
    // retention's transaction -- and once retention rolled back on failure, that
    // rollback discarded the other writer's work after its caller had been told
    // it succeeded.
    //
    // HOW MUCH THIS TEST IS WORTH (measured, Sol round-5 review). Against a
    // deliberately reverted implementation this catches the defect roughly 1 run
    // in 5. Two attempts to improve that made it WORSE, not better: widening the
    // window to a 5,000-row delete dropped detection to 0 in 6, and asserting the
    // stronger property directly ("no writer completes while the batch is open")
    // also passed 6 of 6 against the broken shape. The interleaving simply is not
    // reliably reachable from outside the store.
    //
    // So this is an opportunistic guard, NOT a regression barrier, and it is
    // labelled as one rather than left to look like proof. The deterministic
    // assurance for this fix is the sibling test below (a batch rolls back as a
    // unit and does not reach outside itself) plus the lock structure itself:
    // execute_atomic_batch holds mu_ across the whole transaction, which is
    // verifiable by reading it and is what two reviewers checked. The assertion
    // here is at least sound -- a DISTINCT key per write, and every acknowledged
    // key must survive, so a discarded write cannot be masked by a later one.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor -> accepted, queued
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ROLLBACK, 'aborted'); END;"));

    std::atomic<bool> stop{false};
    std::mutex ack_mu;
    std::condition_variable ack_cv;
    std::vector<int> acknowledged;
    std::thread writer([&] {
        int n = 0;
        while (!stop.load(std::memory_order_relaxed)) {
            const int mine = ++n;
            if (f.db->set_config(std::format("collector_probe_{}", mine), std::to_string(mine))) {
                std::lock_guard lk(ack_mu);
                acknowledged.push_back(mine);
                ack_cv.notify_one();
            }
        }
    });
    // Join on EVERY path: run_retention is not noexcept, and destroying a
    // joinable thread calls std::terminate while it still holds a db reference.
    struct Joiner {
        std::atomic<bool>& stop;
        std::thread& t;
        ~Joiner() {
            stop.store(true, std::memory_order_relaxed);
            if (t.joinable())
                t.join();
        }
    } joiner{stop, writer};

    // Wait for the writer to land at least one COMMITTED write BEFORE racing it.
    // The contract under test is "no acknowledged write is discarded", which needs
    // an acknowledged write to exist; without this the test relied on the writer
    // thread being scheduled during run_retention, which on a loaded box it often
    // is not (measured: 5/10 failures under CPU contention, 0/40 idle). Both CI
    // pools run four runner agents on ONE box, so contention is the normal
    // condition there, not the exceptional one. The writer keeps running through
    // run_retention below, so the race this test exists for is unchanged -- only
    // the precondition is now waited for instead of assumed.
    //
    // Declared after `joiner` so a timeout here still stops and joins the writer
    // rather than terminating on a joinable thread.
    {
        std::unique_lock lk(ack_mu);
        REQUIRE(ack_cv.wait_for(lk, std::chrono::seconds(30),
                                [&] { return !acknowledged.empty(); }));
    }

    run_retention(*f.db, kT0, f.guard);
    stop.store(true, std::memory_order_relaxed);
    if (writer.joinable())
        writer.join();

    std::vector<int> acked;
    {
        std::lock_guard lk(ack_mu);
        acked = acknowledged;
    }
    REQUIRE(acked.size() > 0); // the racing writer really did commit something
    for (int n : acked) {
        INFO("acknowledged write " << n << " of " << acked.size());
        CHECK(f.db->get_config(std::format("collector_probe_{}", n), "") == std::to_string(n));
    }
    CHECK(row_count(*f.db, "process_hourly") == 6); // retention still failed closed
    CHECK(failures_of(f.guard, "process_hourly") >= 1);
}

TEST_CASE("TAR #2361: a batch rolls back as a unit, and does not reach outside itself",
          "[tar][retention][clock-guard]") {
    // The deterministic half of the isolation contract, testing
    // execute_atomic_batch directly rather than racing it. A write made BEFORE
    // the batch must survive its rollback, and a successful statement INSIDE the
    // batch must not survive a later failing one.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 4);
    for (int h = 0; h < 4; ++h) {
        REQUIRE(f.db->execute_sql(
            std::format("INSERT INTO tcp_hourly (hour_ts,remote_addr,remote_port,proto,"
                        "process_name,connect_count,disconnect_count) "
                        "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                        kT0 - 10 * kHourlyCutoffSec)));
    }
    REQUIRE(f.db->set_config("pre_batch_write", "kept"));
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ROLLBACK, 'aborted'); END;"));

    // First statement succeeds, second aborts the transaction.
    const auto r = f.db->execute_atomic_batch(
        {"DELETE FROM tcp_hourly", "DELETE FROM process_hourly", "DELETE FROM tcp_hourly"});

    CHECK_FALSE(r.committed);
    REQUIRE(r.failed.size() == 3);
    for (char c : r.failed)
        CHECK(c == 1); // rolled back as a unit, so every statement is reported failed
    CHECK(row_count(*f.db, "tcp_hourly") == 4);     // the successful delete was undone
    CHECK(row_count(*f.db, "process_hourly") == 4);
    CHECK(f.db->get_config("pre_batch_write", "") == "kept"); // rollback stayed inside the batch
}

TEST_CASE("TAR #2361: the recorded fact set is HELD through a capped drain, then released",
          "[tar][retention][clock-guard]") {
    // Gate 8 coverage gap: every prior over-cap test used a survivor, so
    // `would_wipe` was false and no entry was recorded. This is the transition
    // the fact-set entry lifecycle actually governs -- an all-expired backlog
    // larger than one pass can delete.
    constexpr int64_t kSurplus = 3;
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec,
                           static_cast<int>(yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus));

    run_retention(*f.db, kT0, f.guard); // decline #1
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    // Accepted, capped: a backlog remains, so the entry must STAY recorded or
    // the next pass would decline a second time for the same anomaly.
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == kSurplus);
    CHECK(reported_of(f.guard, "process_hourly"));
    CHECK(declines_of(f.guard, "process_hourly") == 1);

    // Final pass clears the backlog, so the entry releases in that same pass.
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK_FALSE(reported_of(f.guard, "process_hourly"));
    CHECK(declines_of(f.guard, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: the recorded fact set does NOT survive an agent restart",
          "[tar][retention][clock-guard]") {
    // Gate 8 coverage gap. The clock reading is persisted; the recorded entry
    // deliberately is not, so a reboot re-declines. Nothing pinned that, so
    // persisting the entry by mistake would have left the whole suite green.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 10);

    run_retention(*f.db, kT0, f.guard);
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    yuzu::tar::RetentionGuardState fresh; // agent restarts
    run_retention(*f.db, kT0 + 1, fresh);
    CHECK(row_count(*f.db, "process_hourly") == 10); // declines again, does not delete
    CHECK(declines_of(fresh, "process_hourly") == 1);
}

TEST_CASE("TAR #2361: a failed delete re-arms the guard, matching the audit sibling",
          "[tar][retention][clock-guard]") {
    // Kimi / Gate 8 found the two stores had diverged here: audit re-arms on a
    // delete failure, TAR left the entry at its read-phase value. A failed pass
    // learned nothing about the clock, so carrying a recorded entry forward lets
    // the NEXT pass accept a still-live anomaly with no decline and no counter.
    // The backlog must EXCEED the per-pass cap. Below it, the entry-lifecycle
    // rule itself (`would_wipe && cap_will_bind`) already erases the entry on
    // the accepting pass, so the re-arm would be redundant and the test would
    // pass without it.
    constexpr int64_t kSurplus = 3;
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec,
                           static_cast<int>(yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus));

    run_retention(*f.db, kT0, f.guard); // decline #1, fact set recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    // Recorded, so this pass ACCEPTS -- and the delete fails.
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_del BEFORE DELETE ON process_hourly "
                              "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(row_count(*f.db, "process_hourly") ==
          yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus);
    CHECK(failures_of(f.guard, "process_hourly") >= 1);
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // re-armed

    // Same wipe condition, still unresolved: it must decline again rather than
    // delete on an entry the failure had erased.
    REQUIRE(f.db->execute_sql("DROP TRIGGER block_del"));
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") ==
          yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
}

TEST_CASE("TAR #2361: row-count retention is capped too, so the batch lock stays bounded",
          "[tar][retention][clock-guard]") {
    // Sol / round-5 review. Row-count retention needs no CLOCK guard, but it does
    // need the same per-pass bound: the whole batch now runs under one held
    // database mutex, so an uncapped `DELETE ... OFFSET ceiling` over a large
    // excess would stall every collector, `tar status` and config write on this
    // connection for as long as the delete takes. netqual_boot's ceiling is 400.
    constexpr int kCeiling = 400;
    const int64_t kCap = yuzu::tar::kMaxTarDeletesPerTablePerPass;
    TarGuardFixture f;
    f.db->set_config("netqual_enabled", "true"); // opt-in source

    // Ceiling + cap + 200: one pass can only remove `cap`, leaving 200 excess.
    const int total = static_cast<int>(kCeiling + kCap + 200);
    REQUIRE(f.db->execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < total; ++i) {
        REQUIRE(f.db->execute_sql(std::format("INSERT INTO netqual_boot (ts,boot_ts,window_s) "
                                              "VALUES ({}, {}, 60)",
                                              kT0 - 10 * kHourlyCutoffSec,
                                              kT0 - 10 * kHourlyCutoffSec - 60)));
    }
    REQUIRE(f.db->execute_sql("COMMIT"));

    run_retention(*f.db, kT0, f.guard);
    // Bounded: exactly one cap's worth removed, not the whole excess.
    CHECK(row_count(*f.db, "netqual_boot") == total - kCap);
    CHECK(declines_of(f.guard, "netqual_boot") == 0); // still no clock guard on it

    // And it converges: the next pass takes the remainder down to the ceiling.
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(row_count(*f.db, "netqual_boot") == kCeiling);
}

TEST_CASE("TAR #2361: a closed store skips the pass instead of reporting clock trouble",
          "[tar][retention][clock-guard]") {
    // Gate 8 (Kimi). With the store closed every read returns its DEFAULT, so an
    // unguarded pass walks the whole registry, queues plans against a null
    // connection, fails all of them, and warns that a restart will cost the clock
    // comparison point -- when a restart is exactly what recovers a closed store.
    // The pass must say the true thing once and stop.
    //
    // A moved-from TarDatabase has `db_ == nullptr`, which is the same state the
    // wedge path produces via sqlite3_close_v2. The close itself needs a rollback
    // that fails with the transaction still open -- a disk-level fault, not
    // inducible here -- so this covers the downstream behaviour, not the close.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 10);

    yuzu::tar::RetentionGuardState armed;
    run_retention(*f.db, kT0, armed);
    REQUIRE(declines_of(armed, "process_hourly") == 1); // normal behaviour first
    REQUIRE(row_count(*f.db, "process_hourly") == 10);

    TarDatabase live = std::move(*f.db); // *f.db is now the closed store
    REQUIRE_FALSE(f.db->is_open());
    REQUIRE(live.is_open());

    yuzu::tar::RetentionGuardState fresh;
    run_retention(*f.db, kT0 + 1, fresh);

    // No clock findings accrued against a store that could not be read at all,
    // and no per-table failure rows for plans that were never attempted.
    CHECK(retention_guard_counters(fresh).declines.empty());
    CHECK(retention_guard_counters(fresh).failures.empty());
    // The data is untouched (it lives on the moved-to connection).
    CHECK(row_count(live, "process_hourly") == 10);
}

TEST_CASE("TAR #2361: the offline status reply leads with error|, not storage_state",
          "[tar][retention][clock-guard]") {
    // Governance Gate 3 (quality-engineer) BLOCKING: this ordering is the fix
    // for the blank-capture-sources incident and NOTHING pinned it, because
    // TarPlugin is TU-local. The lines are now built by a free function so this
    // can assert the contract directly.
    //
    // The server gates failure on `output.starts_with("error|")`
    // (tar_tree_routes.cpp, device_routes.cpp, dex_routes.cpp,
    // result_set_matcher.cpp -- it is a repo-wide convention). Leading with
    // `storage_state|` makes that gate miss, and the frame falls through to a
    // renderer that parses only `config|` lines: a dead endpoint draws
    // identically to a healthy one.
    const auto lines = yuzu::tar::format_storage_offline_lines(/*query_engine_available=*/true);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0].starts_with("error|"));
    CHECK(lines[1] == "storage_state|offline");
    CHECK(lines[0].find("tar sql") != std::string::npos);

    // And when the read-only connection is gone too, the line must NOT promise
    // a read path that is not there.
    const auto dark = yuzu::tar::format_storage_offline_lines(/*query_engine_available=*/false);
    REQUIRE(dark.size() == 2);
    CHECK(dark[0].starts_with("error|"));
    CHECK(dark[1] == "storage_state|offline");
    CHECK(dark[0].find("cannot read") != std::string::npos);
}

TEST_CASE("TAR #2361: a row INSIDE the future-slack band still counts as a survivor",
          "[tar][retention][clock-guard]") {
    // The TAR half of the audit store's slack-boundary case. Every existing
    // slack test here places its poison row far OUTSIDE `now + slack`, so
    // deleting the `+ kTarRetentionFutureSlackSec` term left the suite green --
    // the row was excluded either way. The term only earns its keep at the
    // boundary.
    //
    // A row half a slack-width ahead is a legitimate survivor. Excluding it
    // would remove the one row keeping `would_wipe` false, so the table would
    // decline and then, on the pass after, delete -- the guard mis-firing in
    // the direction that costs forensic history.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // expired
    seed_process_hourly_at(*f.db, kT0 + yuzu::tar::kTarRetentionFutureSlackSec / 2, 1);

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 1); // survivor recognised -> deleted normally
    CHECK(declines_of(f.guard, "process_hourly") == 0);
}

TEST_CASE("TAR #2361: the FIRST pass with no stored anchor declines instead of deleting",
          "[tar][retention][clock-guard]") {
    // Sol adversarial review, BLOCKING. The bootstrap hole the persisted-reading
    // fix did not cover.
    //
    // On the first guarded pass against an existing database -- an agent upgrade,
    // a restored snapshot -- there is no stored reading, so `big_step` is false
    // BY CONSTRUCTION. And `do_rollup` runs `run_aggregation` FIRST, minting
    // fresh rows into these very tables, so a survivor exists and `would_wipe` is
    // false too. Every trigger false meant the pass deleted up to the cap on
    // every table with no decline, no counter and no log line -- and then
    // persisted the wrong clock as the anchor, so no LATER pass could see the
    // step either. A dead-CMOS endpoint is exactly the case the guard is for.
    TarGuardFixture f{/*prime_anchor=*/false};
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // expired
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);                  // survivor -> not a wipe

    run_retention(*f.db, kT0, f.guard);

    // Declined once, nothing deleted.
    CHECK(row_count(*f.db, "process_hourly") == 6);
    CHECK(declines_of(f.guard, "process_hourly") == 1);

    // And it is a ONE-pass cost: the anchor is now stored, so the next pass
    // proceeds normally.
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(declines_of(f.guard, "process_hourly") == 1); // not counted twice
}

TEST_CASE("TAR #2573: a DIFFERENT anomaly while a decline is still latched deletes instead of "
          "declining",
          "[tar][retention][clock-guard]") {
    // MEASURED (#2573): the bool latch cannot carry anomaly IDENTITY. Pass 1
    // declines on a corrupt stored reading (BadState) and latches. The reading
    // self-heals (the anchor is re-persisted every pass, before the decide
    // step), but the SURVIVOR is then deleted out from under the table by
    // something else entirely -- here, directly via SQL, standing in for
    // whatever emptied it -- so pass 2 presents a DISTINCT anomaly (Wipe) while
    // the latch from pass 1 is still set. The latch has no way to tell "still
    // the same problem" from "a new one arrived"; it deletes with the declines
    // counter stuck at 1. A fact-set guard must decline again, because the fact
    // set changed.
    TarGuardFixture f;
    f.db->set_config("retention_guard_last_pass", "not-a-number"); // BadState
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor

    run_retention(*f.db, kT0, f.guard); // decline #1 (BadState), nothing deleted
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(row_count(*f.db, "process_hourly") == 21);

    REQUIRE(f.db->execute_sql(
        std::format("DELETE FROM process_hourly WHERE hour_ts = {}", kT0 - 3600)));

    run_retention(*f.db, kT0 + 1, f.guard); // now Wipe: a DIFFERENT fact set

    CHECK(declines_of(f.guard, "process_hourly") == 2); // must decline again
    CHECK(row_count(*f.db, "process_hourly") == 20);     // and must NOT delete
}

TEST_CASE("TAR #2573: an implausible caller clock declines the whole pass and does not poison "
          "the anchor",
          "[tar][retention][clock-guard]") {
    // `run_retention`'s `now_epoch` parameter feeds `horizon = now_epoch +
    // kTarRetentionFutureSlackSec` (one addition from signed overflow) AND the
    // durable anchor write, which is unconditional and runs before any
    // per-table decision -- so an implausible `now` would otherwise poison the
    // comparison point for every future pass, not just this one. Same role as
    // the audit sibling's kMaxPlausibleNow clamp; see kTarMaxPlausibleNow.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1);

    constexpr int64_t kImplausibleNow = std::numeric_limits<int64_t>::max() / 2;
    run_retention(*f.db, kImplausibleNow, f.guard);

    // The pass must decline outright and leave the anchor exactly as primed.
    CHECK(f.db->get_config("retention_guard_last_pass", "") == std::to_string(kT0));
    CHECK(row_count(*f.db, "process_hourly") == 6); // nothing deleted
    CHECK(declines_of(f.guard, "process_hourly") == 0); // not a per-table decline
    CHECK(failures_of(f.guard, "__implausible_now__") == 1);

    // And it costs exactly one pass: a plausible `now` right after proceeds
    // normally, using the still-good anchor.
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 1);
}

TEST_CASE("TAR #2573: a cap-paced wipe drains with exactly ONE decline, then re-arms for a "
          "fresh anomaly",
          "[tar][retention][clock-guard]") {
    // Pins the property the retired `latched = would_wipe && cap_will_bind`
    // write existed to provide (#2361 Gate 8 / Sol): a legitimately all-expired
    // table larger than one pass's cap must decline ONCE, then drain silently
    // across as many capped passes as it takes. NOTE (Gate 3 / quality-
    // engineer): this scenario's Facts never CHANGE while the backlog is
    // being worked off, so it holds equally under the old bool latch and the
    // new fact-set equality -- it does NOT by itself discriminate the two.
    // The measured #2573 defect (a DISTINCT anomaly deleting silently under a
    // still-set latch) is pinned by the adjacent test above, which DOES
    // change the fact set mid-sequence and fails under the old latch. This
    // test's own job is the re-arm proof: once the entry releases, a FRESH
    // wipe on the same table must decline again, proving release is real
    // re-arming and not just a stuck bit.
    constexpr int64_t kSurplus = 3;
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec,
                           static_cast<int>(yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus));

    run_retention(*f.db, kT0, f.guard); // decline #1
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    run_retention(*f.db, kT0 + 1, f.guard); // suppressed repeat: drains, capped
    CHECK(row_count(*f.db, "process_hourly") == kSurplus);
    CHECK(reported_of(f.guard, "process_hourly"));
    CHECK(declines_of(f.guard, "process_hourly") == 1); // still ONE

    run_retention(*f.db, kT0 + 2, f.guard); // backlog clears in this pass
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK_FALSE(reported_of(f.guard, "process_hourly"));
    CHECK(declines_of(f.guard, "process_hourly") == 1); // still ONE

    // Proof the entry actually released: a fresh anomaly declines again.
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 4);
    run_retention(*f.db, kT0 + 3, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 4); // declined, not deleted
}

TEST_CASE("TAR #2573: a missing anchor that cannot be persisted declines every pass and never "
          "drains",
          "[tar][retention][clock-guard]") {
    // The one case a naive audit-pure port (record every fact set, including
    // NoAnchor) gets wrong. The audit store's bootstrap-settled marker is
    // written in the SAME transaction as the verdict, so a persist failure
    // there rolls back the whole pass, including the decline record. TAR's
    // anchor write is a plain `set_config` that runs independently of the
    // guard's in-memory bookkeeping -- so if it keeps failing, `no_anchor`
    // stays true forever, and RECORDING that fact set would make every
    // subsequent identical pass a suppressed repeat that drains. That would
    // silently defeat the exact fail-safe #2361 added the no-anchor trigger
    // for. NoAnchor is therefore never recorded, and the pass must decline
    // every single time this condition holds.
    TarGuardFixture f{/*prime_anchor=*/false};
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor -> would_wipe stays false

    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_cfg_ins BEFORE INSERT ON tar_config "
                              "WHEN NEW.key = 'retention_guard_last_pass' "
                              "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
    REQUIRE(f.db->execute_sql("CREATE TRIGGER block_cfg_upd BEFORE UPDATE ON tar_config "
                              "WHEN NEW.key = 'retention_guard_last_pass' "
                              "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

    run_retention(*f.db, kT0, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 1);
    CHECK(row_count(*f.db, "process_hourly") == 21);

    run_retention(*f.db, kT0 + 1, f.guard); // anchor still unwritable: NOT a suppressed repeat
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 21); // never deletes

    CHECK(failures_of(f.guard, "__clock_state__") >= 2);
}

TEST_CASE("TAR #2573: a wipe first seen without an anchor re-reports once the anchor lands",
          "[tar][retention][clock-guard]") {
    // A deliberate delta from the old latch's behaviour, and audit-parity: the
    // dedup key is the WHOLE fact set, so a Wipe recorded with no_anchor=true
    // and the identical Wipe with no_anchor=false (the very next pass, once
    // the anchor self-heals) are two DIFFERENT fact sets and each reports on
    // its own merits (`audit_retention_rules.hpp`). The old latch declined once
    // then silently drained on pass 2; this costs one extra 900s-tick delay on
    // the upgrade/restore bootstrap path in exchange for never conflating two
    // distinct anomalies.
    TarGuardFixture f{/*prime_anchor=*/false};
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // well under the cap

    run_retention(*f.db, kT0, f.guard); // Wipe, no_anchor=true
    CHECK(declines_of(f.guard, "process_hourly") == 1);
    CHECK(row_count(*f.db, "process_hourly") == 5);

    run_retention(*f.db, kT0 + 1, f.guard); // Wipe, no_anchor=false: a DIFFERENT fact set
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 5);

    run_retention(*f.db, kT0 + 2, f.guard); // identical to pass 2: suppressed, drains
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 0);
}

TEST_CASE("TAR #2573: an implausible-now bail clears every table's recorded fact set",
          "[tar][retention][clock-guard]") {
    // Governance Gate 4 (UP-1). The two whole-pass early returns -- this one
    // and the closed-store twin below -- sit BEFORE the per-table loop that
    // otherwise clears a stale entry on disable / empty / probe failure /
    // delete failure. Left unclosed, a recorded fact set could survive the
    // bail and later coincide with a genuinely NEW anomaly's fact set on a
    // later pass -- reporting nothing when something changed, the exact class
    // of bug #2573 exists to close. Both bails now clear the whole map.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard); // decline #1, fact set recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    run_retention(*f.db, std::numeric_limits<int64_t>::max() / 2, f.guard); // bails
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // cleared by the bail

    // The same still-live anomaly must decline again, not silently drain --
    // proving the clear is real, not just an unobserved no-op.
    run_retention(*f.db, kT0 + 1, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 20);
}

TEST_CASE("TAR #2573: a closed-store bail clears every table's recorded fact set",
          "[tar][retention][clock-guard]") {
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard); // decline #1, fact set recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    TarDatabase live = std::move(*f.db); // *f.db is now the closed store
    REQUIRE_FALSE(f.db->is_open());

    run_retention(*f.db, kT0 + 1, f.guard); // bails on the closed store
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // cleared by the bail

    // Reopen (the restart the warning names) and confirm the same still-live
    // anomaly declines again rather than draining silently.
    f.db.emplace(std::move(live));
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 2);
    CHECK(row_count(*f.db, "process_hourly") == 20);
}

TEST_CASE("TAR #2573: a stale Wipe entry is erased, not left dangling, when NoAnchor "
          "overtakes it",
          "[tar][retention][clock-guard]") {
    // Governance Gate 3 (quality-engineer). Pins the erase arm in the decide
    // block reached when classify() returns NoAnchor while a DIFFERENT
    // (non-NoAnchor) entry is already recorded for the table --
    // `tar_aggregator.hpp`'s doc comment calls this out explicitly, but no
    // existing test reached it: every prior no-anchor test starts from an
    // EMPTY map. Reaching it needs `no_anchor=true` and `would_wipe=false` to
    // hold SIMULTANEOUSLY (else Wipe outranks NoAnchor in classify's
    // precedence) with a prior Wipe entry still on record.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // all-expired: Wipe

    run_retention(*f.db, kT0, f.guard); // Wipe, recorded
    REQUIRE(declines_of(f.guard, "process_hourly") == 1);
    REQUIRE(reported_of(f.guard, "process_hourly"));

    // Force no_anchor=true (drop the stored reading) AND would_wipe=false (add
    // a survivor) in one shot, ahead of the next pass.
    REQUIRE(f.db->execute_sql(
        "DELETE FROM tar_config WHERE key = 'retention_guard_last_pass'"));
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: defeats would_wipe

    run_retention(*f.db, kT0 + 1, f.guard); // NoAnchor overtakes the stale Wipe entry
    CHECK(declines_of(f.guard, "process_hourly") == 2); // reports on its own merits
    CHECK_FALSE(reported_of(f.guard, "process_hourly")); // erased, not leaked

    // A fresh, independent Wipe must still decline -- proving the erase was
    // real and nothing suppressed it by residue.
    REQUIRE(f.db->execute_sql(std::format("DELETE FROM process_hourly WHERE hour_ts = {}",
                                          kT0 - 3600)));
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(declines_of(f.guard, "process_hourly") == 3);
    CHECK(row_count(*f.db, "process_hourly") == 5);
}

// ── #1654: the enable/disable transition is all-or-nothing ─────────────────────
//
// Failures are injected with RAISE(ABORT) triggers (deterministic, in-process),
// both the INSERT and UPDATE forms so the test does not depend on which UPSERT
// branch SQLite takes; they hit the same rollback path a real SQLITE_BUSY would.

namespace {
void install_fault(TarDatabase& db, const char* table, const char* col, const char* val) {
    REQUIRE(db.execute_sql(std::format("CREATE TRIGGER yuzu_test_fail_i BEFORE INSERT ON {0} "
                                       "WHEN NEW.{1}='{2}' BEGIN SELECT RAISE(ABORT,'injected'); END",
                                       table, col, val)));
    REQUIRE(db.execute_sql(std::format("CREATE TRIGGER yuzu_test_fail_u BEFORE UPDATE ON {0} "
                                       "WHEN NEW.{1}='{2}' BEGIN SELECT RAISE(ABORT,'injected'); END",
                                       table, col, val)));
}
} // namespace

TEST_CASE("TAR #1654: a failed enabled-flag write rolls back the baseline clear",
          "[tar][paused_at][issue1654]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-1654-flagfail-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());
    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(db.set_config("process_enabled", "true"));

    install_fault(db, "tar_config", "key", "process_enabled");
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    // Never "baseline cleared + still enabled": the clear rolled back with it.
    CHECK_FALSE(db.get_state("process").empty());
    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
}

TEST_CASE("TAR #1654: a failed baseline clear leaves the flag untouched (transactional)",
          "[tar][paused_at][issue1654]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-1654-clearfail-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());
    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(db.set_config("process_enabled", "true"));

    install_fault(db, "tar_state", "collector", "process");
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
}

TEST_CASE("TAR #1654: a failed paused_at write leaves an enable transition unapplied",
          "[tar][paused_at][issue1654]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-1654-pausefail-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());
    REQUIRE(db.set_config("process_enabled", "false"));
    REQUIRE(db.set_config("process_paused_at", "1735689600"));

    install_fault(db, "tar_config", "key", "process_paused_at");
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "true", 1'735'700'000));
    CHECK(db.get_config("process_enabled", "true") == "false"); // flag did not move
    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
}

TEST_CASE("TAR #1654: in-function guard rejects unvalidated values and unknown sources",
          "[tar][paused_at][issue1654]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-1654-guard-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    CHECK_FALSE(apply_source_enabled_transition(db, "process", "maybe", 1'735'689'600));
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "true'; DROP TABLE tar_config;--",
                                                1'735'689'600));
    CHECK_FALSE(apply_source_enabled_transition(db, "not_a_source", "true", 1'735'689'600));
    CHECK(db.get_config("process_enabled", "unset") == "unset");
    CHECK(db.get_config("not_a_source_enabled", "unset") == "unset");
}

TEST_CASE("TAR #1567: db_health line format", "[tar][status][issue1567]") {
    CHECK(format_db_health_line(true, 1700000000) == "db_health|quarantined|1700000000");
    CHECK(format_db_health_line(false, 0) == "db_health|ok|0");
    CHECK(format_db_health_line(false, 1700000000) == "db_health|ok|1700000000");
}
