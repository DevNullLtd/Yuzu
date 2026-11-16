/**
 * test_software_sync_runner.cpp — the shared run sequence behind POST /api/v1/hardware/sync and the
 * MCP tool sync_hardware_software: one run key, join, cooldown, pacing ledger and live-send bound
 * for both callers, audit before the send. Faked seams only; no process, thread, sleep or real
 * clock. Overlapping runs are driven by re-entering Runner::run from inside a fake audit or
 * dispatch callback (the Runner holds no lock across either), never by threads.
 */

#include "software_sync_runner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace ss = yuzu::server::software_sync;

namespace {

struct Rig {
    std::int64_t wall = 1'700'000'000;
    std::vector<std::string> resolved_ids{"d0", "d1", "d2"};
    std::unordered_set<std::string> offline;
    /// Does the caller (by username) hold an unfiltered Execution:Execute?
    std::function<bool(const std::string&)> unfiltered_of = [](const std::string&) { return true; };
    /// What the resolver reports for `caller_unfiltered`; unset follows `unfiltered_of`.
    std::optional<bool> resolve_unfiltered;
    bool admin = true;
    bool persist_ok = true;
    bool dispatch_throws = false;
    bool throws_non_std = false; // with dispatch_throws: throw something that is not a std::exception
    std::optional<std::size_t> accept; // frames the registry accepts; unset = all
    bool last_seen_ok = true;
    std::unordered_map<std::string, std::int64_t> seen;
    bool track_enabled = true;
    int resolve_calls = 0, version_lookups = 0, last_seen_calls = 0, executions = 0, live_refusals = 0;

    struct Dispatch {
        std::vector<std::string> ids;
        std::int64_t delay{0};
        std::string execution_id;
    };
    std::vector<Dispatch> dispatches;
    std::vector<std::string> events;
    std::vector<std::string> cancelled;
    std::vector<std::size_t> targeted;
    std::function<void()> on_persist, on_dispatch;
    bool bind_fleet_audit = false;
    std::int64_t cooldown_s = ss::kDefaultCooldownSecs;

    void live(std::size_t n) {
        resolved_ids.clear();
        for (std::size_t i = 0; i < n; ++i)
            resolved_ids.push_back("d" + std::to_string(i));
    }

    ss::Env env() {
        ss::Env e;
        e.resolve = [this](const auth::Session& s, const ss::Selector&) {
            ++resolve_calls;
            ss::Resolved r;
            r.status = ss::Resolved::Status::Ok;
            r.caller_unfiltered = resolve_unfiltered.value_or(unfiltered_of(s.username));
            r.ids = resolved_ids;
            return r;
        };
        e.dispatch = [this](const auth::Session&, const std::vector<std::string>& ids, std::int64_t delay,
                            const std::string& execution_id) {
            events.push_back("dispatch");
            dispatches.push_back({ids, delay, execution_id});
            if (on_dispatch)
                on_dispatch();
            if (dispatch_throws) {
                if (throws_non_std)
                    throw 42;
                throw std::runtime_error("boom");
            }
            return ss::DispatchResult{accept.value_or(ids.size()), "__sync__-test"};
        };
        e.caller_unfiltered = [this](const auth::Session& s) { return unfiltered_of(s.username); };
        e.fleet_admin = [this](const auth::Session&) { return admin; };
        e.agent_version = [this](const std::string& id) -> std::optional<std::string> {
            ++version_lookups;
            if (offline.contains(id))
                return std::nullopt;
            return std::string("0.13.1");
        };
        e.last_seen = [this](const std::vector<std::string>& ids)
            -> std::optional<std::unordered_map<std::string, std::int64_t>> {
            ++last_seen_calls;
            if (!last_seen_ok)
                return std::nullopt;
            std::unordered_map<std::string, std::int64_t> out;
            for (const auto& id : ids)
                if (const auto it = seen.find(id); it != seen.end())
                    out[id] = it->second;
            return out;
        };
        if (track_enabled) {
            e.track.create = [this](const auth::Session&, const ss::Selector&, std::int64_t) {
                events.push_back("track.create");
                return "exec-" + std::to_string(++executions);
            };
            e.track.set_targeted = [this](const std::string&, std::size_t n) {
                events.push_back("track.targeted");
                targeted.push_back(n);
                return true;
            };
            e.track.cancel = [this](const std::string& id, const auth::Session&) { cancelled.push_back(id); };
        }
        e.now = [this] { return wall; };
        e.cooldown_s = cooldown_s;
        e.on_live_bound_refused = [this] { ++live_refusals; };
        return e;
    }

    ss::Audit audit() {
        ss::Audit a;
        a.note = [this](std::string_view r, std::string_view, const std::string&, const std::string&) {
            events.push_back("note:" + std::string(r));
        };
        a.persist = [this](std::string_view r, std::string_view, const std::string&, const std::string&) {
            events.push_back("persist:" + std::string(r));
            if (on_persist)
                on_persist();
            return persist_ok;
        };
        if (bind_fleet_audit)
            a.persist_fleet_wide = [this](std::string_view r, std::string_view, const std::string&,
                                          const std::string&) {
                events.push_back("persist_fleet:" + std::string(r));
                return persist_ok;
            };
        return a;
    }
};

auth::Session session_of(std::string name) {
    auth::Session s;
    s.username = std::move(name);
    return s;
}

ss::Selector fleet(bool confirm = true) { return {DispatchArm::Broadcast, "__all__", confirm}; }
ss::Selector group(const std::string& name, bool confirm = true) {
    return {DispatchArm::Group, "group:" + name, confirm};
}
ss::Selector device(const std::string& id) { return {DispatchArm::Ids, id}; }
ss::Selector filtered(const std::string& name, std::int64_t before) {
    ss::Selector s = group(name);
    s.last_synced_before = before;
    return s;
}

bool saw(const Rig& rig, const std::string& event) {
    return std::find(rig.events.begin(), rig.events.end(), event) != rig.events.end();
}

} // namespace

// ── sequence ──────────────────────────────────────────────────────────────────────

TEST_CASE("sync runner: audit is stored before the execution record and the send; the run is accepted",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    CHECK(out.status == ss::Status::Accepted);
    CHECK(out.http == 202);
    CHECK(rig.events ==
          std::vector<std::string>{"persist:requested", "track.create", "dispatch", "track.targeted"});
    CHECK(out.summary["execution_id"] == "exec-1");
    CHECK(out.summary["command_id"] == "__sync__-test");
    CHECK(out.summary["agents_reached"] == 3);
    CHECK(out.summary["joined"] == false);
    CHECK(rig.targeted == std::vector<std::size_t>{3});
}

TEST_CASE("sync runner: a failed audit write sends nothing and gives the reservation back",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.live(1000);
    rig.persist_ok = false;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g0"), rig.audit());
    CHECK(out.status == ss::Status::AuditUnavailable);
    CHECK(out.http == 503);
    CHECK(rig.dispatches.empty());
    CHECK(rig.executions == 0); // the record is created after the audit row, never before
    // The Pending reservation and its key were erased: the next admission sees the FULL budget,
    // and the same key is neither in flight nor cooling down.
    rig.persist_ok = true;
    const auto next = runner.run(session_of("alice"), group("g0"), rig.audit());
    REQUIRE(next.status == ss::Status::Accepted);
    REQUIRE(rig.dispatches.size() == 1);
    CHECK(rig.dispatches[0].delay == 40); // 1000 at 25 per second, the whole half-budget
}

TEST_CASE("sync runner: an exception out of the audit write gives the reservation back too",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.live(1000);
    ss::Runner runner(rig.env());
    auto audit = rig.audit();
    bool armed = true;
    audit.persist = [&](std::string_view, std::string_view, const std::string&, const std::string&) -> bool {
        if (armed)
            throw std::runtime_error("db gone");
        return true;
    };
    CHECK_THROWS(runner.run(session_of("alice"), group("g0"), audit));
    armed = false;
    const auto next = runner.run(session_of("alice"), group("g0"), audit);
    REQUIRE(next.status == ss::Status::Accepted);
    CHECK(rig.dispatches.at(0).delay == 40); // nothing leaked: full budget, key free, live count back
}

TEST_CASE("sync runner: dispatch receives the admitted spread and the execution id",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(out.status == ss::Status::Accepted);
    REQUIRE(rig.dispatches.size() == 1);
    CHECK(rig.dispatches[0].ids.size() == 100);
    CHECK(rig.dispatches[0].delay == 4); // 100 devices at 25 per second
    CHECK(rig.dispatches[0].execution_id == "exec-1");
    CHECK(out.summary["delay_max_s"] == 4);
    CHECK(out.summary["requested_at"] == rig.wall);
    CHECK(out.summary["estimated_completion_at"] == rig.wall + 4);
    // A small run is immediate and carries no spread.
    Rig small;
    ss::Runner small_runner(small.env());
    REQUIRE(small_runner.run(session_of("alice"), group("g"), small.audit()).status == ss::Status::Accepted);
    CHECK(small.dispatches.at(0).delay == 0);
}

TEST_CASE("sync runner: an untracked run still runs; its execution_id is null",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.track_enabled = false;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(out.status == ss::Status::Accepted);
    CHECK(out.summary["execution_id"].is_null());
    CHECK(rig.dispatches.at(0).execution_id.empty());
}

// ── who may ask, and what must be confirmed ────────────────────────────────────────

TEST_CASE("sync runner: the fleet needs a fleet administrator and confirm; the refusal order is 403 then 400",
          "[server][software_sync][runner][security]") {
    {
        // Not an administrator: 403 before confirm is even looked at, nothing read.
        Rig rig;
        rig.admin = false;
        ss::Runner runner(rig.env());
        const auto out = runner.run(session_of("alice"), fleet(/*confirm=*/false), rig.audit());
        CHECK(out.status == ss::Status::FleetWideRequired);
        CHECK(out.http == 403);
        CHECK(out.message.find("ManagementGroup:Write") != std::string::npos);
        CHECK(rig.resolve_calls == 0);
        CHECK(rig.dispatches.empty());
    }
    {
        // A confined caller, even one with the administrator grant, is refused as well.
        Rig rig;
        rig.unfiltered_of = [](const std::string&) { return false; };
        ss::Runner runner(rig.env());
        CHECK(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::FleetWideRequired);
        CHECK(rig.resolve_calls == 0);
    }
    {
        // An unwired administrator seam denies.
        Rig rig;
        auto env = rig.env();
        env.fleet_admin = nullptr;
        ss::Runner runner(std::move(env));
        CHECK(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::FleetWideRequired);
    }
    {
        // An administrator who did not confirm: 400, the invalid-parameters class, nothing read.
        Rig rig;
        ss::Runner runner(rig.env());
        const auto out = runner.run(session_of("alice"), fleet(/*confirm=*/false), rig.audit());
        CHECK(out.status == ss::Status::BadScope);
        CHECK(out.http == 400);
        CHECK(out.message.find("confirm") != std::string::npos);
        CHECK(rig.resolve_calls == 0);
        CHECK(saw(rig, "note:denied"));
        CHECK(rig.dispatches.empty());
        // ...and the refusal took no key: confirming now runs.
        CHECK(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::Accepted);
    }
}

TEST_CASE("sync runner: a whole group needs confirm; a device and an expression never do",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    const auto bad = runner.run(session_of("alice"), group("g", /*confirm=*/false), rig.audit());
    CHECK(bad.status == ss::Status::BadScope);
    CHECK(bad.http == 400);
    CHECK(rig.resolve_calls == 0);
    CHECK(runner.run(session_of("alice"), device("host-01"), rig.audit()).status == ss::Status::Accepted);
    const ss::Selector expr{DispatchArm::Scope, R"(ostype == "linux")"};
    CHECK(runner.run(session_of("alice"), expr, rig.audit()).status == ss::Status::Accepted);
    // A confined caller may sync a group within their own set.
    rig.unfiltered_of = [](const std::string&) { return false; };
    CHECK(runner.run(session_of("bob"), group("g"), rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: a resolve whose caller class differs from the run key's is 503 and sends nothing",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.resolve_unfiltered = false; // the key was built for an unfiltered caller
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    CHECK(out.status == ss::Status::ScopeUnresolved);
    CHECK(out.http == 503);
    CHECK(rig.dispatches.empty());
    CHECK(rig.executions == 0);
    // Nothing was reserved or stamped.
    rig.resolve_unfiltered = std::nullopt;
    CHECK(runner.run(session_of("alice"), group("g"), rig.audit()).status == ss::Status::Accepted);
}

// ── join ──────────────────────────────────────────────────────────────────────────

TEST_CASE("sync runner: a repeat request for a running key joins it and sends nothing",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100); // a 4 s spread: the run is still running one second later
    ss::Runner runner(rig.env());
    const auto first = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(first.status == ss::Status::Accepted);
    rig.wall += 1;
    const auto again = runner.run(session_of("bob"), group("g"), rig.audit());
    REQUIRE(again.status == ss::Status::Accepted);
    CHECK(again.http == 202);
    CHECK(again.summary["joined"] == true);
    CHECK(again.summary["execution_id"] == first.summary["execution_id"]);
    CHECK(again.summary["command_id"] == first.summary["command_id"]);
    CHECK(again.summary["requested_at"] == first.summary["requested_at"]);
    CHECK(again.summary["agents_reached"] == 100);
    CHECK(rig.dispatches.size() == 1);   // nothing sent for the joiner
    CHECK(rig.executions == 1);          // and no second record
    CHECK(rig.resolve_calls == 1);       // and the fleet was not read again
    CHECK(saw(rig, "note:joined"));
    // Once the spread has ended the key is only cooling down.
    rig.wall += 10;
    const auto late = runner.run(session_of("alice"), group("g"), rig.audit());
    CHECK(late.status == ss::Status::Cooldown);
    CHECK(late.http == 429);
}

TEST_CASE("sync runner: callers share a run only when they see the same devices",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    // Two unfiltered callers share the group's run.
    const auto a = runner.run(session_of("alice"), group("g"), rig.audit());
    const auto b = runner.run(session_of("bob"), group("g"), rig.audit());
    REQUIRE(a.status == ss::Status::Accepted);
    CHECK(b.summary["joined"] == true);
    CHECK(rig.dispatches.size() == 1);

    // A confined caller naming the same group is never joined to it and never receives its counts:
    // their own key, their own resolve (here only the part of the group they may see), their own run.
    rig.unfiltered_of = [](const std::string& u) { return u != "carol"; };
    rig.live(60); // the part of the group carol may see
    const auto c = runner.run(session_of("carol"), group("g"), rig.audit());
    REQUIRE(c.status == ss::Status::Accepted);
    CHECK(c.summary["joined"] == false);
    CHECK(c.summary["agents_reached"] == 60);
    CHECK(c.summary["execution_id"] != a.summary["execution_id"]);
    CHECK(rig.dispatches.size() == 2);
    // A different confined caller has a key of their own as well.
    rig.unfiltered_of = [](const std::string& u) { return u != "carol" && u != "dave"; };
    const auto d = runner.run(session_of("dave"), group("g"), rig.audit());
    CHECK(d.summary["joined"] == false);
    CHECK(rig.dispatches.size() == 3);
    // A confined caller's repeat joins their own run, with their own counts.
    rig.wall += 1;
    const auto c2 = runner.run(session_of("carol"), group("g"), rig.audit());
    REQUIRE(c2.status == ss::Status::Accepted);
    CHECK(c2.summary["joined"] == true);
    CHECK(c2.summary["execution_id"] == c.summary["execution_id"]);
    CHECK(c2.summary["agents_reached"] == 60);
    CHECK(rig.dispatches.size() == 3);
}

TEST_CASE("sync runner: a scope expression is keyed by requester and the exact text",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    const ss::Selector linux_hosts{DispatchArm::Scope, R"(ostype == "linux")"};
    const ss::Selector win_hosts{DispatchArm::Scope, R"(ostype == "windows")"};
    REQUIRE(runner.run(session_of("alice"), linux_hosts, rig.audit()).status == ss::Status::Accepted);
    rig.wall += 1;
    CHECK(runner.run(session_of("alice"), linux_hosts, rig.audit()).summary["joined"] == true);
    // Another requester with the same text, and the same requester with other text, are new runs.
    CHECK(runner.run(session_of("bob"), linux_hosts, rig.audit()).summary["joined"] == false);
    CHECK(runner.run(session_of("alice"), win_hosts, rig.audit()).summary["joined"] == false);
    CHECK(rig.dispatches.size() == 3);
}

TEST_CASE("sync runner: a request the running run covers joins; a wider one is 409 with the time left",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    REQUIRE(runner.run(session_of("alice"), filtered("g", 1000), rig.audit()).status == ss::Status::Accepted);
    rig.wall += 1;
    // Narrower or equal: covered.
    CHECK(runner.run(session_of("alice"), filtered("g", 1000), rig.audit()).summary["joined"] == true);
    CHECK(runner.run(session_of("alice"), filtered("g", 900), rig.audit()).summary["joined"] == true);
    // Wider (a later bound, or none): not covered, and nothing is sent for it.
    for (const auto& wide : {filtered("g", 1100), group("g")}) {
        const auto out = runner.run(session_of("alice"), wide, rig.audit());
        CHECK(out.status == ss::Status::InFlight);
        CHECK(out.http == 409);
        CHECK(out.retry_after_ms == 3000); // 4 s spread, 1 s gone
    }
    CHECK(rig.dispatches.size() == 1);
    // A run that had NO filter covers every request, filtered or not.
    Rig other;
    other.live(100);
    ss::Runner runner2(other.env());
    REQUIRE(runner2.run(session_of("alice"), group("g"), other.audit()).status == ss::Status::Accepted);
    other.wall += 1;
    CHECK(runner2.run(session_of("alice"), filtered("g", 5), other.audit()).summary["joined"] == true);
}

// ── concurrent keys and the pacing ledger ──────────────────────────────────────────

TEST_CASE("sync runner: overlapping admissions across keys never share the same free budget",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.live(1000);
    ss::Runner runner(rig.env());
    // Each group is started from inside the previous one's audit write, so all three are admitted
    // and Pending against an empty ledger before any of them sends.
    int depth = 0;
    std::vector<ss::Outcome> inner(2);
    rig.on_persist = [&] {
        if (depth >= 2)
            return;
        ++depth;
        inner[static_cast<std::size_t>(depth - 1)] =
            runner.run(session_of("alice"), group("g" + std::to_string(depth)), rig.audit());
    };
    const auto outer = runner.run(session_of("alice"), group("g0"), rig.audit());
    REQUIRE(outer.status == ss::Status::Accepted);
    REQUIRE(inner[0].status == ss::Status::Accepted);
    REQUIRE(inner[1].status == ss::Status::Accepted);
    // The innermost sends first. 1000 devices at 25, 12.5 and 6.25 per second.
    REQUIRE(rig.dispatches.size() == 3);
    CHECK(rig.dispatches[0].delay == 160);
    CHECK(rig.dispatches[1].delay == 80);
    CHECK(rig.dispatches[2].delay == 40);
    double asked = 0;
    for (const auto& d : rig.dispatches)
        asked += 1000.0 / static_cast<double>(d.delay);
    CHECK(asked <= ss::kFleetPacingBudgetPerSec);
}

TEST_CASE("sync runner: a same-key request while the first is still being started is 409 with a 1 s hint",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    ss::Outcome inner;
    int dispatches_seen_by_inner = -1;
    bool fired = false;
    rig.on_persist = [&] {
        if (fired)
            return;
        fired = true;
        inner = runner.run(session_of("bob"), group("g"), rig.audit());
        dispatches_seen_by_inner = static_cast<int>(rig.dispatches.size());
    };
    REQUIRE(runner.run(session_of("alice"), group("g"), rig.audit()).status == ss::Status::Accepted);
    CHECK(inner.status == ss::Status::InFlight);
    CHECK(inner.http == 409);
    CHECK(inner.retry_after_ms == 1000);
    CHECK(dispatches_seen_by_inner == 0); // the inner request sent nothing
    CHECK(rig.dispatches.size() == 1);
}

TEST_CASE("sync runner: different groups run at once; the same group inside its cooldown is 429",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    REQUIRE(runner.run(session_of("alice"), group("g1"), rig.audit()).status == ss::Status::Accepted);
    REQUIRE(runner.run(session_of("alice"), group("g2"), rig.audit()).status == ss::Status::Accepted);
    CHECK(rig.dispatches.size() == 2);

    rig.wall += 10; // both spreads (4 s and 8 s) are over; the cooldown is not
    const auto held = runner.run(session_of("alice"), group("g1"), rig.audit());
    CHECK(held.status == ss::Status::Cooldown);
    CHECK(held.http == 429);
    CHECK(held.retry_after_ms == (ss::kDefaultCooldownSecs - 10) * 1000);
    CHECK(rig.dispatches.size() == 2);
    CHECK(rig.resolve_calls == 2); // and the repeat was refused before it read the fleet
    // At exactly the end of the window it runs again.
    rig.wall += ss::kDefaultCooldownSecs - 10;
    CHECK(runner.run(session_of("alice"), group("g1"), rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: the cooldown is keyed by group, not by operator", "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    ss::Runner runner(rig.env());
    REQUIRE(runner.run(session_of("alice"), group("g1"), rig.audit()).status == ss::Status::Accepted);
    rig.wall += 20; // the run is over
    // Another operator on the same group is held; the same operator on another group is not.
    CHECK(runner.run(session_of("bob"), group("g1"), rig.audit()).status == ss::Status::Cooldown);
    CHECK(runner.run(session_of("alice"), group("g2"), rig.audit()).status == ss::Status::Accepted);
    // A configured gap is honoured, and 0 turns it off.
    Rig quick;
    quick.live(100);
    quick.cooldown_s = 30;
    ss::Runner quick_runner(quick.env());
    REQUIRE(quick_runner.run(session_of("alice"), group("g"), quick.audit()).status == ss::Status::Accepted);
    quick.wall += 29;
    CHECK(quick_runner.run(session_of("alice"), group("g"), quick.audit()).status == ss::Status::Cooldown);
    quick.wall += 1;
    CHECK(quick_runner.run(session_of("alice"), group("g"), quick.audit()).status == ss::Status::Accepted);
    Rig none;
    none.live(100);
    none.cooldown_s = 0;
    ss::Runner none_runner(none.env());
    REQUIRE(none_runner.run(session_of("alice"), group("g"), none.audit()).status == ss::Status::Accepted);
    none.wall += 5; // past the 4 s spread
    CHECK(none_runner.run(session_of("alice"), group("g"), none.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: a single named device is never paced, keyed or counted",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(1);
    ss::Runner runner(rig.env());
    for (int i = 0; i < 6; ++i)
        CHECK(runner.run(session_of("alice"), device("host-01"), rig.audit()).status == ss::Status::Accepted);
    CHECK(rig.dispatches.size() == 6);
    for (const auto& d : rig.dispatches)
        CHECK(d.delay == 0);
    // And it is not held by the live-send bound: dispatch from inside three nested group runs.
    Rig busy;
    int depth = 0;
    ss::Runner busy_runner(busy.env());
    ss::Outcome single;
    busy.on_dispatch = [&] {
        if (depth < 3) {
            ++depth;
            if (depth == 3)
                single = busy_runner.run(session_of("zed"), device("host-01"), busy.audit());
            else
                (void)busy_runner.run(session_of("alice"), group("n" + std::to_string(depth)), busy.audit());
        }
    };
    CHECK(busy_runner.run(session_of("alice"), group("n0"), busy.audit()).status == ss::Status::Accepted);
    CHECK(single.status == ss::Status::Accepted);
}

TEST_CASE("sync runner: no free budget is 429 with a retry and leaves nothing behind; too large is 413",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(1000);
    ss::Runner runner(rig.env());
    // Five runs leave 1.5625 per second free: a share of 0.78, below the minimum run rate.
    for (int i = 0; i < 5; ++i)
        REQUIRE(runner.run(session_of("alice"), group("g" + std::to_string(i)), rig.audit()).status ==
                ss::Status::Accepted);
    const std::size_t dispatches = rig.dispatches.size();
    const auto busy = runner.run(session_of("alice"), group("g5"), rig.audit());
    CHECK(busy.status == ss::Status::BudgetBusy);
    CHECK(busy.http == 429);
    CHECK(busy.retry_after_ms == 40'000); // the first run's 40 s spread is the earliest end
    CHECK(rig.dispatches.size() == dispatches);
    // Nothing was left for g5: asking again is the same budget refusal, not a cooldown or a 409.
    CHECK(runner.run(session_of("alice"), group("g5"), rig.audit()).status == ss::Status::BudgetBusy);
    // When the earliest run ends its rate comes back.
    rig.wall += 40;
    const auto freed = runner.run(session_of("alice"), group("g5"), rig.audit());
    CHECK(freed.status == ss::Status::Accepted);

    // Too large: four runs (25 + 12.5 + 6.25 + 3.125) leave 3.125 free, a share of 1.5625 per
    // second, so more than 135,000 devices cannot be spread inside 86,400 s.
    Rig big;
    big.live(1000);
    ss::Runner big_runner(big.env());
    for (int i = 0; i < 4; ++i)
        REQUIRE(big_runner.run(session_of("alice"), group("h" + std::to_string(i)), big.audit()).status ==
                ss::Status::Accepted);
    big.live(135'001);
    const auto too_big = big_runner.run(session_of("alice"), group("huge"), big.audit());
    CHECK(too_big.status == ss::Status::TooMany);
    CHECK(too_big.http == 413);
    CHECK(too_big.message.find("86400") != std::string::npos);
    const std::size_t sent_before = big.dispatches.size();
    big.live(135'000); // exactly 86,400 s fits, and the refused attempt left no key behind
    const auto fits = big_runner.run(session_of("alice"), group("huge"), big.audit());
    REQUIRE(fits.status == ss::Status::Accepted);
    CHECK(big.dispatches.size() == sent_before + 1);
    CHECK(big.dispatches.back().delay == ss::kMaxSpreadSecs);
}

TEST_CASE("sync runner: a fourth concurrent send is 409 and a finished one frees its place",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    int depth = 0;
    std::vector<ss::Outcome> nested;
    rig.on_dispatch = [&] {
        if (depth >= ss::kMaxLiveRuns)
            return;
        ++depth;
        nested.push_back(runner.run(session_of("alice"), group("n" + std::to_string(depth)), rig.audit()));
    };
    REQUIRE(runner.run(session_of("alice"), group("n0"), rig.audit()).status == ss::Status::Accepted);
    // n0 holds one place, n1 and n2 take the others, n3 is refused. Completion order is innermost
    // first: n3, then n2, then n1.
    REQUIRE(nested.size() == 3);
    CHECK(nested[0].status == ss::Status::InFlight);
    CHECK(nested[0].http == 409);
    CHECK(nested[0].retry_after_ms.value_or(0) > 0);
    CHECK(nested[1].status == ss::Status::Accepted);
    CHECK(nested[2].status == ss::Status::Accepted);
    CHECK(rig.live_refusals == 1);
    CHECK(rig.dispatches.size() == 3);
    // Everything unwound: the live count is back to zero.
    rig.on_dispatch = nullptr;
    rig.wall += 20;
    CHECK(runner.run(session_of("alice"), group("fresh"), rig.audit()).status == ss::Status::Accepted);
}

// ── last_synced_before ────────────────────────────────────────────────────────────

TEST_CASE("sync runner: last_synced_before drops recently synced devices into skipped_fresh",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(5);
    rig.seen = {{"d0", 2000}, {"d1", 999}, {"d2", 1000}, {"d4", 5000}}; // d3 never reported
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), filtered("g", 1000), rig.audit());
    REQUIRE(out.status == ss::Status::Accepted);
    CHECK(out.summary["requested"] == 5);
    CHECK(out.summary["skipped_fresh"] == 3);
    CHECK(out.summary["agents_reached"] == 2);
    REQUIRE(rig.dispatches.size() == 1);
    CHECK(rig.dispatches[0].ids == std::vector<std::string>{"d1", "d3"});
    CHECK(rig.last_seen_calls == 1);
    // No filter: the store is not read at all.
    Rig plain;
    plain.live(5);
    ss::Runner plain_runner(plain.env());
    REQUIRE(plain_runner.run(session_of("alice"), group("g"), plain.audit()).status == ss::Status::Accepted);
    CHECK(plain.last_seen_calls == 0);
}

TEST_CASE("sync runner: a degraded last_seen read is 503 and sends nothing; it leaves no key behind",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.live(5);
    rig.last_seen_ok = false;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), filtered("g", 1000), rig.audit());
    CHECK(out.status == ss::Status::ScopeUnresolved);
    CHECK(out.http == 503);
    CHECK(out.retry_after_ms.value_or(0) > 0);
    CHECK(rig.dispatches.empty());
    CHECK(rig.executions == 0);
    rig.last_seen_ok = true;
    CHECK(runner.run(session_of("alice"), filtered("g", 1000), rig.audit()).status == ss::Status::Accepted);
    // An unwired last_seen seam is refused the same way, never read as "everything is stale".
    Rig unwired;
    unwired.live(2);
    auto env = unwired.env();
    env.last_seen = nullptr;
    ss::Runner unwired_runner(std::move(env));
    CHECK(unwired_runner.run(session_of("alice"), filtered("g", 1000), unwired.audit()).status ==
          ss::Status::ScopeUnresolved);
}

// ── settling ──────────────────────────────────────────────────────────────────────

TEST_CASE("sync runner: nothing live to ask is 202 with reached 0, audited no_agents, and spends the cooldown",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(3);
    rig.offline = {"d0", "d1", "d2"};
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(out.status == ss::Status::Accepted);
    CHECK(out.summary["agents_reached"] == 0);
    CHECK(out.summary["skipped_offline"] == 3);
    CHECK(out.summary["execution_id"].is_null());
    CHECK(rig.dispatches.empty());
    CHECK(rig.events == std::vector<std::string>{"persist:no_agents"}); // no execution record either
    CHECK(runner.run(session_of("alice"), group("g"), rig.audit()).status == ss::Status::Cooldown);
    // The audit row is still fail closed.
    Rig failing;
    failing.offline = {"d0", "d1", "d2"};
    failing.persist_ok = false;
    ss::Runner failing_runner(failing.env());
    CHECK(failing_runner.run(session_of("alice"), group("g"), failing.audit()).status ==
          ss::Status::AuditUnavailable);
}

TEST_CASE("sync runner: a no-target request finishing beside a running request of its key leaves that run alone",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(100);
    rig.offline.clear();
    for (const auto& id : rig.resolved_ids)
        rig.offline.insert(id); // A sees nobody live...
    ss::Runner runner(rig.env());
    ss::Outcome b;
    bool fired = false;
    rig.on_persist = [&] {
        if (fired)
            return;
        fired = true;
        rig.offline.clear(); // ...but by the time its audit row is written, B finds everybody
        b = runner.run(session_of("bob"), group("g"), rig.audit());
    };
    const auto a = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(a.status == ss::Status::Accepted);
    REQUIRE(b.status == ss::Status::Accepted);
    CHECK(a.summary["agents_reached"] == 0);
    CHECK(b.summary["agents_reached"] == 100);
    // B's run is still joinable: A's stamp did not turn it into a finished, cooling-down key.
    rig.wall += 1;
    const auto c = runner.run(session_of("carol"), group("g"), rig.audit());
    REQUIRE(c.status == ss::Status::Accepted);
    CHECK(c.summary["joined"] == true);
    CHECK(c.summary["execution_id"] == b.summary["execution_id"]);
}

TEST_CASE("sync runner: every frame refused releases the reservation and the key; the cooldown is unspent",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(1000);
    rig.accept = 0;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
    CHECK(out.status == ss::Status::NoneReachable);
    CHECK(out.http == 503);
    CHECK(out.retry_after_ms.value_or(0) > 0);
    CHECK(rig.cancelled == std::vector<std::string>{"exec-1"}); // the record is closed, not left running
    CHECK(rig.targeted.empty());
    // The whole reservation went back (the retry gets the full half-budget) and the key is free.
    rig.accept = std::nullopt;
    const auto again = runner.run(session_of("alice"), group("g"), rig.audit());
    REQUIRE(again.status == ss::Status::Accepted);
    CHECK(rig.dispatches.back().delay == 40);
}

TEST_CASE("sync runner: a partly accepted send reports the frames accepted and keeps the whole reservation",
          "[server][software_sync][runner]") {
    Rig rig;
    rig.live(1000);
    rig.accept = 600;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), group("g1"), rig.audit());
    REQUIRE(out.status == ss::Status::Accepted);
    CHECK(out.summary["requested"] == 1000);
    CHECK(out.summary["agents_reached"] == 600);
    CHECK(out.summary["skipped_offline"] == 400);
    CHECK(rig.targeted == std::vector<std::size_t>{600});
    // The frames that were not accepted keep their share until the spread ends: a second group
    // gets half of what is left, not half of the whole budget.
    rig.accept = std::nullopt;
    const auto second = runner.run(session_of("alice"), group("g2"), rig.audit());
    REQUIRE(second.status == ss::Status::Accepted);
    CHECK(rig.dispatches.back().delay == 80); // 12.5 per second
}

TEST_CASE("sync runner: a dispatch that throws keeps its budget, is neither joinable nor cooling, and is 503",
          "[server][software_sync][runner]") {
    // Any throw type behaves alike: a std::exception and one that is not (an unlisted type must not
    // slip past the handler and release the budget with no audit row and an open record).
    for (const bool non_std : {false, true}) {
        CAPTURE(non_std);
        Rig rig;
        rig.live(1000);
        rig.dispatch_throws = true;
        rig.throws_non_std = non_std;
        ss::Runner runner(rig.env());
        const auto out = runner.run(session_of("alice"), group("g"), rig.audit());
        CHECK(out.status == ss::Status::NoneReachable);
        CHECK(out.http == 503);
        CHECK(out.retry_after_ms.value_or(0) > 0);
        CHECK(saw(rig, "note:failure")); // dispatch_threw is on the record
        CHECK(rig.cancelled == std::vector<std::string>{"exec-1"});
        // The key's run state is gone: a retry is a new run, not a join and not a 429...
        rig.dispatch_throws = false;
        const auto again = runner.run(session_of("alice"), group("g"), rig.audit());
        REQUIRE(again.status == ss::Status::Accepted);
        CHECK(again.summary["joined"] == false);
        // ...but the runner could not prove nothing was sent, so the first attempt's reservation stands
        // until its spread ends: the retry got half of the remaining half.
        CHECK(rig.dispatches.back().delay == 80);
    }
}

TEST_CASE("sync runner: the whole-fleet row goes through persist_fleet_wide when it is bound",
          "[server][software_sync][runner]") {
    {
        Rig rig;
        rig.bind_fleet_audit = true;
        ss::Runner runner(rig.env());
        REQUIRE(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::Accepted);
        CHECK(rig.events.front() == "persist_fleet:requested");
        // Only the fleet: a group still writes the ordinary row.
        REQUIRE(runner.run(session_of("alice"), group("g"), rig.audit()).status == ss::Status::Accepted);
        CHECK(saw(rig, "persist:requested"));
    }
    {
        Rig rig; // not bound: the one writer takes it
        ss::Runner runner(rig.env());
        REQUIRE(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::Accepted);
        CHECK(rig.events.front() == "persist:requested");
    }
    {
        // A failing fleet-wide writer fails the run closed.
        Rig rig;
        rig.bind_fleet_audit = true;
        rig.persist_ok = false;
        ss::Runner runner(rig.env());
        CHECK(runner.run(session_of("alice"), fleet(), rig.audit()).status == ss::Status::AuditUnavailable);
        CHECK(rig.dispatches.empty());
    }
}

// ── bounded state ─────────────────────────────────────────────────────────────────

TEST_CASE("sync runner: the run-state map stays bounded; expired entries are evicted first",
          "[server][software_sync][runner]") {
    {
        // Nothing expires (a very long gap): the oldest stamps go once the map is full.
        Rig rig;
        rig.cooldown_s = ss::kMaxCooldownSecs;
        ss::Runner runner(rig.env());
        const std::size_t runs = ss::kCooldownStateCap + 10;
        for (std::size_t i = 0; i < runs; ++i) {
            REQUIRE(runner.run(session_of("alice"), group("g" + std::to_string(i)), rig.audit()).status ==
                    ss::Status::Accepted);
            rig.wall += 2; // each run is over before the next starts
        }
        CHECK(runner.tracked_keys() == ss::kCooldownStateCap);
        // The ten oldest were dropped, so they run again inside their gap; the newest still waits.
        CHECK(runner.run(session_of("alice"), group("g0"), rig.audit()).status == ss::Status::Accepted);
        CHECK(runner.run(session_of("alice"), group("g" + std::to_string(runs - 1)), rig.audit()).status ==
              ss::Status::Cooldown);
    }
    {
        // A short gap: by the time the map is full nearly every entry has expired, and those are
        // what leave. The keys still cooling down stay.
        Rig rig;
        rig.cooldown_s = 100;
        ss::Runner runner(rig.env());
        const std::size_t runs = ss::kCooldownStateCap + 76;
        for (std::size_t i = 0; i < runs; ++i) {
            REQUIRE(runner.run(session_of("alice"), group("e" + std::to_string(i)), rig.audit()).status ==
                    ss::Status::Accepted);
            rig.wall += 30;
        }
        CHECK(runner.tracked_keys() < ss::kCooldownStateCap);
        CHECK(runner.run(session_of("alice"), group("e" + std::to_string(runs - 1)), rig.audit()).status ==
              ss::Status::Cooldown);
    }
}

// ── metric label ──────────────────────────────────────────────────────────────────

TEST_CASE("sync runner: every outcome is counted once, under a closed label",
          "[server][software_sync][runner]") {
    // The mapping covers every status and only produces members of the pre-seeded set.
    const auto label = [](ss::Status st, bool joined = false) {
        ss::Outcome o;
        o.status = st;
        o.summary = nlohmann::json{{"joined", joined}};
        return std::string(ss::result_label(o));
    };
    CHECK(label(ss::Status::Accepted) == "accepted");
    CHECK(label(ss::Status::Accepted, true) == "joined");
    CHECK(label(ss::Status::BadScope) == "bad_request");
    CHECK(label(ss::Status::FleetWideRequired) == "fleet_denied");
    CHECK(label(ss::Status::Cooldown) == "cooldown");
    CHECK(label(ss::Status::InFlight) == "in_flight");
    CHECK(label(ss::Status::ScopeUnresolved) == "unresolved");
    CHECK(label(ss::Status::TooMany) == "too_large");
    CHECK(label(ss::Status::AuditUnavailable) == "audit_failed");
    CHECK(label(ss::Status::NoneReachable) == "none_reachable");
    CHECK(label(ss::Status::BudgetBusy) == "budget_busy");
    for (const auto st : {ss::Status::Accepted, ss::Status::BadScope, ss::Status::FleetWideRequired,
                          ss::Status::Cooldown, ss::Status::InFlight, ss::Status::ScopeUnresolved,
                          ss::Status::TooMany, ss::Status::AuditUnavailable, ss::Status::NoneReachable,
                          ss::Status::BudgetBusy})
        CHECK(std::find(ss::kRunResults.begin(), ss::kRunResults.end(), label(st)) != ss::kRunResults.end());

    // And `run` reports exactly one label per call, refusals included.
    Rig rig;
    rig.live(100);
    std::vector<std::string> seen_labels;
    auto env = rig.env();
    env.on_result = [&](std::string_view r) { seen_labels.emplace_back(r); };
    ss::Runner runner(std::move(env));
    (void)runner.run(session_of("alice"), group("g"), rig.audit());
    rig.wall += 1;
    (void)runner.run(session_of("bob"), group("g"), rig.audit());
    (void)runner.run(session_of("bob"), group("h", /*confirm=*/false), rig.audit());
    rig.admin = false;
    (void)runner.run(session_of("bob"), fleet(), rig.audit());
    rig.wall += 20;
    (void)runner.run(session_of("bob"), group("g"), rig.audit());
    CHECK(seen_labels == std::vector<std::string>{"accepted", "joined", "bad_request", "fleet_denied", "cooldown"});
}
