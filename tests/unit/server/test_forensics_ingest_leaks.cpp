// #4990 wave A: the paths that carry Forensics-tier plugin output OUTSIDE the stored-response
// read seam. Each case drives the real ingest (AgentServiceImpl::process_gateway_response) or the
// real consumer and asserts the exact observable output, with an ordinary-plugin control so a
// filter that silenced everything would fail too.
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <stdexcept>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "analytics_event_store.hpp"
#include "execution_tracker.hpp"
#include "forensics_error_detail.hpp"
#include "notification_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "preflight_parse.hpp"
#include "response_store.hpp"
#include "result_set_members.hpp"
#include "test_analytics_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_principal_lock_gate.hpp" // SqlFault
#include "test_offload_target_store_pg_helper.hpp"
#include "test_tracker_scope.hpp"
#include "test_webhook_store_pg_helper.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::SseEvent;
namespace apb = ::yuzu::agent::v1;

namespace {

constexpr const char* kMarker = "marker-4990-live-row";

/// The ONE row a Forensics-tier plugin's output produces on the live "output" bus: a fixed
/// constant that replaces the Console's "Waiting for results..." placeholder. It carries no plugin
/// data and nothing the agent supplied. Pinned verbatim: the documentation quotes this text.
constexpr std::string_view kForensicsLiveNotice =
    "<tr id=\"empty-row\" hx-swap-oob=\"outerHTML\"><td colspan=\"99\" class=\"empty-state\">"
    "Forensics output is not shown live. Open the execution results.</td></tr>";

apb::CommandResponse running_frame(const std::string& command_id, const std::string& output) {
    apb::CommandResponse r;
    r.set_command_id(command_id);
    r.set_status(apb::CommandResponse::RUNNING);
    r.set_output(output);
    return r;
}

/// A service with a subscriber on the shared event bus (the bus the legacy `/events` stream and
/// every dashboard session read). No stores: the live-row publish is unconditional.
struct LiveBusHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::vector<SseEvent> seen;
    std::size_t sub{};

    LiveBusHarness() {
        sub = bus.subscribe([this](const SseEvent& e) { seen.push_back(e); });
    }
    ~LiveBusHarness() { bus.unsubscribe(sub); }

    std::vector<SseEvent> output_events() const {
        std::vector<SseEvent> out;
        std::ranges::copy_if(seen, std::back_inserter(out),
                             [](const SseEvent& e) { return e.event_type == "output"; });
        return out;
    }
    std::size_t notice_count() const {
        return static_cast<std::size_t>(std::ranges::count_if(seen, [](const SseEvent& e) {
            return e.event_type == "output" && e.data == kForensicsLiveNotice;
        }));
    }
    std::size_t marker_count() const {
        std::size_t n = 0;
        for (const auto& e : seen)
            if (e.data.find(kMarker) != std::string::npos)
                ++n;
        return n;
    }
};

} // namespace

TEST_CASE("live output bus: a Forensics-tier plugin's rows are never published, one fixed notice is",
          "[server][forensics_tier][security]") {
    LiveBusHarness h;
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());

    SECTION("ordinary plugin control: the row reaches the bus") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0001", kMarker));
        const auto out = h.output_events();
        REQUIRE(out.size() == 1);
        CHECK(out[0].data.find(kMarker) != std::string::npos);
    }
    SECTION("every Forensics plugin, in any ASCII case, publishes only the fixed notice") {
        for (const auto& plugin : test::forensics_plugin_set().names()) {
            h.svc.process_gateway_response("agent-1", running_frame(plugin + "-0001", kMarker));
            std::string upper = plugin;
            for (auto& c : upper)
                if (c >= 'a' && c <= 'z')
                    c = static_cast<char>(c - 'a' + 'A');
            h.svc.process_gateway_response("agent-1", running_frame(upper + "-0002", kMarker));
        }
        // Two frames per plugin (lower and upper case): each produced exactly the notice, and
        // no output event of any other shape.
        const auto frames = test::forensics_plugin_set().names().size() * 2;
        CHECK(h.output_events().size() == frames);
        CHECK(h.notice_count() == frames);
        CHECK(h.marker_count() == 0);
    }
    SECTION("a mixed batch: the ordinary plugin's row publishes beside the notice") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0001", kMarker));
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0002", kMarker));
        CHECK(h.output_events().size() == 2);
        CHECK(h.notice_count() == 1);
        CHECK(h.marker_count() == 1);
    }
    SECTION("a Forensics frame with no output publishes nothing, notice included") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0003", ""));
        CHECK(h.output_events().empty());
    }
}

TEST_CASE("live output bus: an unwired plugin set publishes no output row at all",
          "[server][forensics_tier][security]") {
    LiveBusHarness h; // set_forensics_plugin_set deliberately not called
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0001", kMarker));
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0002", kMarker));
    CHECK(h.output_events().empty());
    CHECK(h.marker_count() == 0);

    // Wiring the set turns the control back on: the silence above was the unwired state, not a
    // harness that never publishes.
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());
    h.svc.process_gateway_response(
        "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0003", kMarker));
    CHECK(h.output_events().size() == 1);
}

// -- A2: the tracker's per-agent error_detail ----------------------------------------------------

namespace {

yuzu::test::PgTestTemplate forensics_leaks_tpl{
    "forensicsleaks", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ExecutionTracker tracker{pool};
        if (!tracker.is_open())
            throw std::runtime_error("forensicsleaks template: tracker failed to migrate");
    }};

constexpr const char* kFreeText = "marker-4990-error: could not open C:\\Users\\bob\\secret.txt";
constexpr const char* kToken = "windows:amcache:hive_locked";

apb::CommandResponse failure_frame(const std::string& command_id, const std::string& message) {
    apb::CommandResponse r;
    r.set_command_id(command_id);
    r.set_status(apb::CommandResponse::FAILURE);
    r.set_exit_code(3);
    r.mutable_error()->set_message(message);
    return r;
}

std::string outbox_data(yuzu::server::pg::PgPool& pool, const std::string& execution_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT string_agg(data, E'\\n') FROM execution_tracker.event_outbox WHERE execution_id = $1",
        std::vector<std::string>{execution_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    return PQgetisnull(res.get(), 0, 0) ? std::string{} : std::string{PQgetvalue(res.get(), 0, 0)};
}

/// The outbox payloads appended AFTER `after_event_id` for one execution, and the high-water mark
/// to pass next time. Separates what a step wrote from the rows that were already there.
std::string outbox_data_after(yuzu::server::pg::PgPool& pool, const std::string& execution_id,
                              long long after_event_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT string_agg(data, E'\\n') FROM execution_tracker.event_outbox "
        "WHERE execution_id = $1 AND event_id > $2::bigint",
        std::vector<std::string>{execution_id, std::to_string(after_event_id)});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    return PQgetisnull(res.get(), 0, 0) ? std::string{} : std::string{PQgetvalue(res.get(), 0, 0)};
}

std::string stored_error_detail(yuzu::server::pg::PgPool& pool, const std::string& execution_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT error_detail FROM execution_tracker.agent_exec_status WHERE execution_id = $1",
        std::vector<std::string>{execution_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    return PQgetvalue(res.get(), 0, 0);
}

long long outbox_high_water(yuzu::server::pg::PgPool& pool, const std::string& execution_id) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT COALESCE(max(event_id), 0) FROM execution_tracker.event_outbox WHERE execution_id = $1",
        std::vector<std::string>{execution_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    return std::stoll(PQgetvalue(res.get(), 0, 0));
}

} // namespace

TEST_CASE("forensics_error_detail: the bounded token shape", "[server][forensics_tier]") {
    CHECK(is_bounded_error_token("windows:amcache:hive_locked"));
    CHECK(is_bounded_error_token("a:b"));
    CHECK(is_bounded_error_token("a:b:c:d"));
    CHECK_FALSE(is_bounded_error_token("a:b:c:d:e"));      // four detail segments is the cap
    CHECK_FALSE(is_bounded_error_token("nocolon"));
    CHECK_FALSE(is_bounded_error_token(""));
    CHECK_FALSE(is_bounded_error_token("Upper:case"));
    CHECK_FALSE(is_bounded_error_token("a:b c"));           // a space is free text
    CHECK_FALSE(is_bounded_error_token("a:"));
    CHECK_FALSE(is_bounded_error_token(":a"));
    CHECK_FALSE(is_bounded_error_token(std::string(33, 'a') + ":b"));
    CHECK_FALSE(is_bounded_error_token("a:" + std::string(49, 'b')));
    CHECK(is_bounded_error_token("a:" + std::string(48, 'b')));
    CHECK(sanitize_forensics_error_detail("") == "");
    CHECK(sanitize_forensics_error_detail(kToken) == kToken);
    CHECK(sanitize_forensics_error_detail(kFreeText) == "forensics_error");
    CHECK(sanitize_forensics_error_detail("forensics_error") == "forensics_error"); // idempotent
}

TEST_CASE("tracker error_detail: a Forensics plugin's free-text failure is stored as a bounded value",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, forensics_leaks_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LiveBusHarness h;
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());
    ExecutionEventBus exec_bus;
    yuzu::test::TrackerScope ts{h.svc, pool, &exec_bus};

    const auto run = [&](const std::string& command_id, const std::string& message,
                         std::vector<std::string>* bus_frames = nullptr) {
        const auto exec_id = ts.make_exec();
        h.svc.record_execution_id(command_id, exec_id);
        std::size_t sub = 0;
        if (bus_frames)
            sub = exec_bus.subscribe(exec_id, [bus_frames](const ExecutionEvent& e) {
                bus_frames->push_back(e.data);
            });
        h.svc.process_gateway_response("agent-1", failure_frame(command_id, message));
        if (bus_frames)
            exec_bus.unsubscribe(exec_id, sub);
        return exec_id;
    };

    SECTION("free text from a Forensics plugin: column, outbox and bus are clean; status kept") {
        std::vector<std::string> frames;
        const auto exec_id = run(std::string{test::kForensicsPlugin} + "-0001", kFreeText, &frames);
        const auto statuses = ts.tracker->get_agent_statuses(exec_id);
        REQUIRE(statuses.size() == 1);
        CHECK(statuses[0].error_detail == "forensics_error");
        CHECK(statuses[0].status == "failure");
        CHECK(statuses[0].exit_code == 3);
        CHECK(outbox_data(pool, exec_id).find("marker-4990") == std::string::npos);
        CHECK(outbox_data(pool, exec_id).find("forensics_error") != std::string::npos);
        REQUIRE_FALSE(frames.empty());
        for (const auto& f : frames)
            CHECK(f.find("marker-4990") == std::string::npos);
    }
    SECTION("a token-shaped message from a Forensics plugin is preserved") {
        const auto exec_id = run(std::string{test::kForensicsPlugin} + "-0002", kToken);
        const auto statuses = ts.tracker->get_agent_statuses(exec_id);
        REQUIRE(statuses.size() == 1);
        CHECK(statuses[0].error_detail == kToken);
    }
    SECTION("an ordinary plugin's message is unchanged (control)") {
        const auto exec_id = run(std::string{test::kOrdinaryPlugin} + "-0003", kFreeText);
        const auto statuses = ts.tracker->get_agent_statuses(exec_id);
        REQUIRE(statuses.size() == 1);
        CHECK(statuses[0].error_detail == kFreeText);
        CHECK(outbox_data(pool, exec_id).find("marker-4990") != std::string::npos);
    }
}

TEST_CASE("tracker error_detail: an unwired plugin set sanitises every plugin's message",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, forensics_leaks_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LiveBusHarness h; // plugin set deliberately not wired
    yuzu::test::TrackerScope ts{h.svc, pool};
    const auto exec_id = ts.make_exec();
    h.svc.record_execution_id("shellexec-0001", exec_id);
    h.svc.process_gateway_response("agent-1", failure_frame("shellexec-0001", kFreeText));
    const auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].error_detail == "forensics_error");
}

TEST_CASE("tracker error_detail: a later RUNNING frame never republishes a stored free-text value",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, forensics_leaks_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LiveBusHarness h;
    h.svc.set_forensics_plugin_set(&test::forensics_plugin_set());
    ExecutionEventBus exec_bus;
    yuzu::test::TrackerScope ts{h.svc, pool, &exec_bus};
    ts.tracker->set_forensics_plugin_set(&test::forensics_plugin_set());

    // A terminal row holding RAW text, written straight to the tracker the way a row from before
    // the write-side sanitiser exists (an older binary or replica). A later RUNNING frame for the
    // same (execution, agent) leaves that terminal row as it is, and the transition event built
    // from the persisted row is published on the bus and appended to the durable outbox.
    const auto seed_raw_terminal = [&](const std::string& command_id) {
        const auto exec_id = ts.make_exec();
        h.svc.record_execution_id(command_id, exec_id);
        AgentExecStatus s;
        s.agent_id = "agent-1";
        s.status = "failure";
        s.completed_at = 100;
        s.exit_code = 3;
        s.error_detail = kFreeText;
        ts.tracker->update_agent_status(exec_id, s);
        return exec_id;
    };
    const auto any_frame_has = [](const std::vector<std::string>& frames, std::string_view needle) {
        return std::ranges::any_of(frames, [&](const std::string& f) {
            return f.find(needle) != std::string::npos;
        });
    };
    const auto replay = [&](const std::string& command_id, const std::string& exec_id,
                            std::vector<std::string>& frames) {
        const auto sub = exec_bus.subscribe(exec_id, [&frames](const ExecutionEvent& e) {
            frames.push_back(e.data);
        });
        h.svc.process_gateway_response("agent-1", running_frame(command_id, ""));
        exec_bus.unsubscribe(exec_id, sub);
    };

    SECTION("a Forensics plugin: neither the bus frame nor the outbox row carries the stored text") {
        const std::string cmd = std::string{test::kForensicsPlugin} + "-0r1";
        const auto exec_id = seed_raw_terminal(cmd);
        const auto seeded = outbox_high_water(pool, exec_id);
        // Precondition: the stored column really is raw (the reads scrub, so look at the SQL).
        REQUIRE(stored_error_detail(pool, exec_id).find("marker-4990") != std::string::npos);
        std::vector<std::string> frames;
        replay(cmd, exec_id, frames);
        REQUIRE_FALSE(frames.empty());
        for (const auto& f : frames)
            CHECK(f.find("marker-4990") == std::string::npos);
        const auto added = outbox_data_after(pool, exec_id, seeded);
        REQUIRE_FALSE(added.empty());
        CHECK(added.find("marker-4990") == std::string::npos);
        // The published value is the bounded placeholder, and the row itself is untouched.
        CHECK(any_frame_has(frames, "forensics_error"));
        const auto statuses = ts.tracker->get_agent_statuses(exec_id);
        REQUIRE(statuses.size() == 1);
        CHECK(statuses[0].status == "failure");
        CHECK(statuses[0].exit_code == 3);
    }
    SECTION("a token-shaped stored value is published as stored") {
        const auto exec_id = ts.make_exec();
        const std::string cmd = std::string{test::kForensicsPlugin} + "-0r2";
        h.svc.record_execution_id(cmd, exec_id);
        AgentExecStatus s;
        s.agent_id = "agent-1";
        s.status = "failure";
        s.completed_at = 100;
        s.error_detail = kToken;
        ts.tracker->update_agent_status(exec_id, s);
        std::vector<std::string> frames;
        replay(cmd, exec_id, frames);
        REQUIRE_FALSE(frames.empty());
        CHECK(any_frame_has(frames, kToken));
    }
    SECTION("healing control: a duplicate terminal frame replaces the stored text, then stays clean") {
        const std::string cmd = std::string{test::kForensicsPlugin} + "-0r3";
        const auto exec_id = seed_raw_terminal(cmd);
        h.svc.process_gateway_response("agent-1", failure_frame(cmd, kFreeText));
        const auto seeded = outbox_high_water(pool, exec_id);
        std::vector<std::string> frames;
        replay(cmd, exec_id, frames);
        const auto statuses = ts.tracker->get_agent_statuses(exec_id);
        REQUIRE(statuses.size() == 1);
        CHECK(statuses[0].error_detail == "forensics_error");
        REQUIRE_FALSE(frames.empty());
        for (const auto& f : frames)
            CHECK(f.find("marker-4990") == std::string::npos);
        CHECK(outbox_data_after(pool, exec_id, seeded).find("marker-4990") == std::string::npos);
    }
    SECTION("ordinary plugin control: the stored text is published unchanged") {
        const std::string cmd = std::string{test::kOrdinaryPlugin} + "-0r4";
        const auto exec_id = seed_raw_terminal(cmd);
        const auto seeded = outbox_high_water(pool, exec_id);
        std::vector<std::string> frames;
        replay(cmd, exec_id, frames);
        REQUIRE_FALSE(frames.empty());
        CHECK(any_frame_has(frames, "marker-4990"));
        CHECK(outbox_data_after(pool, exec_id, seeded).find("marker-4990") != std::string::npos);
    }
}

TEST_CASE("tracker error_detail: rows written before the sanitiser are reduced on every read",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, forensics_leaks_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecutionTracker tracker{pool};
    REQUIRE(tracker.is_open());

    const auto make_failed = [&](const std::string& command_id, bool map_command,
                                 const std::string& text) {
        Execution e;
        e.definition_id = "def-legacy";
        e.dispatched_by = "tester";
        e.status = "running";
        e.agents_targeted = 1;
        auto id = tracker.create_execution(e);
        REQUIRE(id.has_value());
        if (map_command)
            REQUIRE(tracker.record_command_execution(command_id, *id));
        AgentExecStatus s; // the pre-upgrade write: raw text, straight to the tracker
        s.agent_id = "agent-1";
        s.status = "failure";
        s.completed_at = 100;
        s.error_detail = text;
        tracker.update_agent_status(*id, s);
        tracker.refresh_counts(*id);
        return *id;
    };
    const auto forensic = make_failed(std::string{test::kForensicsPlugin} + "-0a", true, kFreeText);
    const auto upper = make_failed("BROWSER_INVENTORY-0b", true, kFreeText);
    const auto token = make_failed(std::string{test::kForensicsPlugin} + "-0c", true, kToken);
    const auto ordinary = make_failed(std::string{test::kOrdinaryPlugin} + "-0d", true, kFreeText);
    // No command_execution mapping at all: what a row older than the 24 h mapping window looks like.
    const auto unmapped = make_failed(std::string{test::kForensicsPlugin} + "-0e", false, kFreeText);

    SECTION("an UNWIRED tracker's read scrub fails OPEN: it returns the stored text") {
        // Characterised, not endorsed: the READ side is open when no plugin set is wired, while the
        // WRITE side (notify_exec_tracker, see the unwired test above) sanitises every plugin.
        // Production cannot reach the open state: boot refuses an empty set and the wiring is
        // pinned lexically (tests/test_forensics_tier_wiring_lexical.py, row `tracker-set`).
        CHECK(tracker.get_agent_statuses(forensic)[0].error_detail == kFreeText);
        CHECK(tracker.get_agent_statuses_for_executions({forensic}).at(forensic)[0].error_detail ==
              kFreeText);
        const auto got = tracker.get_execution(forensic);
        REQUIRE(got.has_value());
        CHECK(got->last_error_detail == kFreeText);
    }

    tracker.set_forensics_plugin_set(&test::forensics_plugin_set());
    SECTION("per-agent statuses, single and batched") {
        CHECK(tracker.get_agent_statuses(forensic)[0].error_detail == "forensics_error");
        CHECK(tracker.get_agent_statuses(upper)[0].error_detail == "forensics_error");
        CHECK(tracker.get_agent_statuses(token)[0].error_detail == kToken);
        CHECK(tracker.get_agent_statuses(ordinary)[0].error_detail == kFreeText);
        const auto batch =
            tracker.get_agent_statuses_for_executions({forensic, upper, token, ordinary});
        CHECK(batch.at(forensic)[0].error_detail == "forensics_error");
        CHECK(batch.at(upper)[0].error_detail == "forensics_error");
        CHECK(batch.at(token)[0].error_detail == kToken);
        CHECK(batch.at(ordinary)[0].error_detail == kFreeText);
    }
    SECTION("a row whose command mapping is gone keeps its stored text (the disclosed 24 h residual)") {
        // The scrub is keyed on the command_execution mapping, which is reaped after 24 h; older
        // rows are outside it. The write-time sanitiser covers every row written since the fix, so
        // this only concerns pre-upgrade rows. Pinned so the residual stays a decision.
        CHECK(tracker.get_agent_statuses(unmapped)[0].error_detail == kFreeText);
        CHECK(tracker.get_agent_statuses_for_executions({unmapped}).at(unmapped)[0].error_detail ==
              kFreeText);
        const auto got = tracker.get_execution(unmapped);
        REQUIRE(got.has_value());
        CHECK(got->last_error_detail == kFreeText);
        // The mapped Forensics row beside it is still reduced.
        CHECK(tracker.get_agent_statuses(forensic)[0].error_detail == "forensics_error");
    }
    SECTION("get_execution (the unchecked accessor) reduces the execution-level text too") {
        const auto f = tracker.get_execution(forensic);
        REQUIRE(f.has_value());
        CHECK(f->last_error_detail == "forensics_error");
        const auto u = tracker.get_execution(upper);
        REQUIRE(u.has_value());
        CHECK(u->last_error_detail == "forensics_error");
        const auto t = tracker.get_execution(token);
        REQUIRE(t.has_value());
        CHECK(t->last_error_detail == kToken);
        const auto o = tracker.get_execution(ordinary);
        REQUIRE(o.has_value());
        CHECK(o->last_error_detail == kFreeText);
        CHECK_FALSE(tracker.get_execution("exec-does-not-exist").has_value());
    }
    SECTION("the execution-level last_error_detail on list and get") {
        std::map<std::string, std::string> by_id;
        ExecutionQuery q;
        q.include_error_detail = true; // the list/status surfaces opt in to the preview
        for (const auto& e : tracker.query_executions(q))
            by_id[e.id] = e.last_error_detail;
        CHECK(by_id.at(forensic) == "forensics_error");
        CHECK(by_id.at(upper) == "forensics_error");
        CHECK(by_id.at(token) == kToken);
        CHECK(by_id.at(ordinary) == kFreeText);
        auto got = tracker.get_execution_checked(forensic);
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->last_error_detail == "forensics_error");
    }
}

TEST_CASE("tracker error_detail: a failed Forensics execution lookup withholds the text and logs at "
          "most once",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, forensics_leaks_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecutionTracker tracker{pool};
    REQUIRE(tracker.is_open());
    tracker.set_forensics_plugin_set(&test::forensics_plugin_set());

    Execution e;
    e.definition_id = "def-lookup-fault";
    e.dispatched_by = "tester";
    e.status = "running";
    e.agents_targeted = 1;
    const auto id = tracker.create_execution(e);
    REQUIRE(id.has_value());
    REQUIRE(tracker.record_command_execution(std::string{test::kOrdinaryPlugin} + "-0g", *id));
    AgentExecStatus s;
    s.agent_id = "agent-1";
    s.status = "failure";
    s.completed_at = 100;
    s.error_detail = kFreeText;
    tracker.update_agent_status(*id, s);
    tracker.refresh_counts(*id);
    REQUIRE(tracker.get_agent_statuses(*id)[0].error_detail == kFreeText); // control: healthy lookup

    // The plugin lookup (command_execution) fails while the main read succeeds: an unknown
    // execution is treated as Forensics-tier, so the text is withheld on EVERY read ...
    yuzu::test::SqlFault fault(
        pool, "ALTER TABLE execution_tracker.command_execution RENAME TO command_execution_gone",
        "ALTER TABLE execution_tracker.command_execution_gone RENAME TO command_execution");
    fault.arm();
    yuzu::test::LogCapture logs{spdlog::level::warn};
    for (int i = 0; i < 6; ++i)
        CHECK(tracker.get_agent_statuses(*id)[0].error_detail == "forensics_error");
    logs.stop();
    fault.repair();
    // ... and the warning (drawer polls repeat this read every few seconds) is throttled to one
    // per minute, however many reads failed. At most, not exactly: the throttle is process-wide.
    const auto text = logs.text();
    std::size_t lines = 0;
    for (std::size_t pos = text.find("Forensics execution lookup failed"); pos != std::string::npos;
         pos = text.find("Forensics execution lookup failed", pos + 1))
        ++lines;
    CHECK(lines <= 1);
}

// -- A3: the failure text in the server's other derived sinks -------------------------------------
//
// The tracker is one reader of a terminal frame's failure text. The notification store (read at
// Infrastructure:Read), the analytics event and the webhook / offload payload are the others; each
// is observed here on BOTH ingest paths (the gateway-proxied one and the direct Subscribe stream),
// with an ordinary plugin as the control so a sanitiser that blanked everything would fail too.

namespace {

yuzu::test::PgTestTemplate leaks_notif_tpl{"notifstore", [](const std::string& dsn) {
                                               yuzu::server::pg::PgPool pool{
                                                   {.conninfo = dsn, .size = 1}};
                                               NotificationStore store{pool};
                                               if (!store.is_open())
                                                   throw std::runtime_error(
                                                       "notification template: store failed to "
                                                       "migrate");
                                           }};

constexpr const char* kDirectAgent = "agent-direct";
constexpr const char* kGatewayAgent = "agent-gateway";

/// What each sink holds after one failed command.
struct SinkView {
    std::vector<std::string> notifications;    ///< messages of the "Execution Failed" rows
    std::vector<std::string> analytics_errors; ///< `error_message` of command.completed events
    std::vector<std::string> webhook_payloads;
    std::vector<std::string> offload_payloads;
};

/// A real AgentServiceImpl behind a loopback gRPC server with all four derived sinks wired to real
/// stores. MEMBER ORDER IS LOAD-BEARING: the stores are declared first so they outlive the service,
/// and the destructor body detaches them before anything is destroyed.
struct SinkHarness {
    yuzu::test::WebhookStorePg webhooks;
    yuzu::test::OffloadTargetStorePg offloads;
    yuzu::test::AuthDbPgShared auth_db;
    yuzu::server::pg::PgPool notif_pool;
    yuzu::server::pg::PgPool analytics_pool;
    NotificationStore notifications;
    std::shared_ptr<AnalyticsEventStore> analytics;
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<apb::AgentService::Stub> stub;
    int port = 0;
    int64_t wh_id = 0;
    int64_t off_id = 0;

    SinkHarness(const std::string& notif_dsn, const std::string& analytics_dsn, bool wire_set)
        : notif_pool({.conninfo = notif_dsn, .size = 4}),
          analytics_pool({.conninfo = analytics_dsn, .size = 4}), notifications(notif_pool),
          analytics(std::make_shared<AnalyticsEventStore>(analytics_pool)) {
        REQUIRE(notifications.is_open());
        REQUIRE(analytics->is_open());
        auth_mgr.set_auth_db(auth_db.get());
        if (wire_set)
            svc.set_forensics_plugin_set(&test::forensics_plugin_set());
        svc.set_notification_store(&notifications);
        svc.set_analytics_store(analytics);
        svc.set_webhook_store(webhooks.get());
        svc.set_offload_target_store(offloads.get());
        const auto wh =
            webhooks->create_webhook("http://127.0.0.1:1/hook", "execution.completed", "");
        REQUIRE(wh.has_value());
        wh_id = *wh;
        // batch_size 2 so the single event buffers deterministically until flush_all().
        const auto off = offloads->create_target("t1", "http://127.0.0.1:1/off",
                                                 OffloadAuthType::None, "", "execution.completed",
                                                 /*batch_size=*/2);
        REQUIRE(off.has_value());
        off_id = *off;

        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        stub = apb::AgentService::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                                              grpc::InsecureChannelCredentials()));
    }
    ~SinkHarness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        svc.set_notification_store(nullptr);
        svc.set_analytics_store({});
        svc.set_webhook_store(nullptr);
        svc.set_offload_target_store(nullptr);
        webhooks->quiesce(std::chrono::seconds(5));
        offloads->quiesce(std::chrono::seconds(5));
    }
    SinkHarness(const SinkHarness&) = delete;
    SinkHarness& operator=(const SinkHarness&) = delete;

    /// The gateway-proxied ingest path.
    void ingest_gateway(const apb::CommandResponse& frame) {
        svc.process_gateway_response(kGatewayAgent, frame);
    }

    /// The direct ingest path: a real Register + Subscribe stream carrying `frame`.
    void ingest_direct(const apb::CommandResponse& frame) {
        ingest_direct_frames({frame});
    }

    /// Same, for several frames on ONE stream (the agent registers once).
    void ingest_direct_frames(const std::vector<apb::CommandResponse>& frames) {
        const auto deadline = [] {
            return std::chrono::system_clock::now() + std::chrono::seconds(20);
        };
        auto token = auth_mgr.create_enrollment_token("forensics-sinks", 0, std::chrono::hours(1),
                                                      "test-admin");
        REQUIRE(token.has_value());
        apb::RegisterRequest reg;
        reg.mutable_info()->set_agent_id(kDirectAgent);
        reg.mutable_info()->set_hostname("host");
        reg.mutable_info()->mutable_platform()->set_os("windows");
        reg.mutable_info()->mutable_platform()->set_arch("x86_64");
        reg.set_enrollment_token(token->raw_token);
        apb::RegisterResponse reg_resp;
        grpc::ClientContext reg_ctx;
        reg_ctx.set_deadline(deadline());
        REQUIRE(stub->Register(&reg_ctx, reg, &reg_resp).ok());
        REQUIRE(reg_resp.accepted());

        grpc::ClientContext ctx;
        ctx.set_deadline(deadline());
        ctx.AddMetadata(std::string{AgentServiceImpl::kSessionMetadataKey}, reg_resp.session_id());
        auto stream = stub->Subscribe(&ctx);
        REQUIRE(stream != nullptr);
        for (const auto& frame : frames)
            REQUIRE(stream->Write(frame));
        REQUIRE(stream->WritesDone());
        apb::CommandRequest unused;
        while (stream->Read(&unused)) {}
        CHECK(stream->Finish().ok()); // the handler read every frame before it returned
    }

    /// Settles the delivery pools and reads every sink. Call once: it closes both pools.
    SinkView observe() {
        offloads->flush_all();
        REQUIRE(offloads->quiesce(std::chrono::seconds(5)));
        REQUIRE(webhooks->quiesce(std::chrono::seconds(5)));
        SinkView v;
        for (const auto& n : notifications.list_all())
            if (n.title == "Execution Failed")
                v.notifications.push_back(n.message);
        const auto events = analytics->query_recent(50);
        REQUIRE(events.has_value());
        for (const auto& e : *events)
            if (e.event_type == "command.completed" && e.payload.contains("error_message"))
                v.analytics_errors.push_back(e.payload["error_message"].get<std::string>());
        for (const auto& d : webhooks->get_deliveries(wh_id))
            v.webhook_payloads.push_back(d.payload);
        for (const auto& d : offloads->get_deliveries(off_id))
            v.offload_payloads.push_back(d.payload);
        return v;
    }
};

/// What every sink must hold after the failure of `command_id` on `agent`.
void check_sinks(const SinkView& v, const std::string& command_id, const std::string& agent,
                 const std::string& expected) {
    REQUIRE(v.notifications.size() == 1);
    CHECK(v.notifications[0] ==
          "Command " + command_id + " on agent " + agent + " failed: " + expected);
    REQUIRE(v.analytics_errors.size() == 1);
    CHECK(v.analytics_errors[0] == expected);
    REQUIRE(v.webhook_payloads.size() == 1);
    const auto wh = nlohmann::json::parse(v.webhook_payloads[0]);
    CHECK(wh.at("error").get<std::string>() == expected);
    CHECK(wh.at("status") == "error");
    CHECK(wh.at("exit_code") == 3); // the status and exit code are untouched
    REQUIRE(v.offload_payloads.size() == 1);
    // The offload batch is {"events": [<the same event payloads>]}.
    const auto off = nlohmann::json::parse(v.offload_payloads[0]);
    REQUIRE(off.at("events").is_array());
    REQUIRE(off.at("events").size() == 1);
    CHECK(off.at("events")[0].at("error").get<std::string>() == expected);
}

} // namespace

TEST_CASE("terminal failure text: every derived sink carries only a bounded token for a "
          "Forensics-tier plugin",
          "[pg][server][forensics_tier][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(ndb, leaks_notif_tpl);
    YUZU_REQUIRE_PG_DB_TPL(adb, yuzu::test::analytics_pg_template);
    SinkHarness h(ndb.dsn(), adb.dsn(), /*wire_set=*/true);
    const std::string agent = direct ? kDirectAgent : kGatewayAgent;
    const auto ingest = [&](const apb::CommandResponse& f) {
        if (direct)
            h.ingest_direct(f);
        else
            h.ingest_gateway(f);
    };

    SECTION("free text from a Forensics plugin, in any ASCII case, is reduced in all four sinks") {
        const std::string id = "BROWSER_INVENTORY-0e1";
        ingest(failure_frame(id, kFreeText));
        const auto v = h.observe();
        check_sinks(v, id, agent, "forensics_error");
        for (const auto& s : v.notifications)
            CHECK(s.find("marker-4990") == std::string::npos);
        for (const auto& s : v.offload_payloads)
            CHECK(s.find("marker-4990") == std::string::npos);
        for (const auto& s : v.webhook_payloads)
            CHECK(s.find("marker-4990") == std::string::npos);
    }
    SECTION("a token-shaped failure from a Forensics plugin is preserved in all four sinks") {
        const std::string id = std::string{test::kForensicsPlugin} + "-0e2";
        ingest(failure_frame(id, kToken));
        check_sinks(h.observe(), id, agent, kToken);
    }
    SECTION("an ordinary plugin keeps its full failure text in all four sinks (control)") {
        const std::string id = std::string{test::kOrdinaryPlugin} + "-0e3";
        ingest(failure_frame(id, kFreeText));
        check_sinks(h.observe(), id, agent, kFreeText);
    }
}

TEST_CASE("terminal failure text: an unwired plugin set sanitises every plugin in every sink",
          "[pg][server][forensics_tier][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(ndb, leaks_notif_tpl);
    YUZU_REQUIRE_PG_DB_TPL(adb, yuzu::test::analytics_pg_template);
    SinkHarness h(ndb.dsn(), adb.dsn(), /*wire_set=*/false);
    const std::string id = std::string{test::kOrdinaryPlugin} + "-0e4";
    if (direct)
        h.ingest_direct(failure_frame(id, kFreeText));
    else
        h.ingest_gateway(failure_frame(id, kFreeText));
    check_sinks(h.observe(), id, direct ? kDirectAgent : kGatewayAgent, "forensics_error");
}

// The live output bus through the DIRECT Subscribe stream: the same helper the gateway path uses
// (publish_output_rows), reached from the other ingest branch.
TEST_CASE("live output bus: the direct Subscribe path publishes the fixed notice, never a Forensics row",
          "[pg][server][forensics_tier][security]") {
    const bool wired = GENERATE(true, false);
    INFO((wired ? "plugin set wired" : "plugin set unwired"));
    YUZU_REQUIRE_PG_DB_TPL(ndb, leaks_notif_tpl);
    YUZU_REQUIRE_PG_DB_TPL(adb, yuzu::test::analytics_pg_template);
    SinkHarness h(ndb.dsn(), adb.dsn(), wired);
    std::mutex mu;
    std::vector<SseEvent> seen;
    const auto sub = h.bus.subscribe([&](const SseEvent& e) {
        std::lock_guard lock(mu);
        seen.push_back(e);
    });
    constexpr const char* kForensicRow = "marker-4990-forensics-row";
    h.ingest_direct_frames({running_frame(std::string{test::kOrdinaryPlugin} + "-0f1", kMarker),
                            running_frame(std::string{test::kForensicsPlugin} + "-0f2", kForensicRow),
                            running_frame("BROWSER_INVENTORY-0f3", kForensicRow)});
    h.bus.unsubscribe(sub);
    std::size_t ordinary = 0, forensic = 0, output_events = 0, notices = 0;
    {
        std::lock_guard lock(mu);
        for (const auto& e : seen) {
            if (e.event_type == "output")
                ++output_events;
            if (e.event_type == "output" && e.data == kForensicsLiveNotice)
                ++notices;
            if (e.data.find(kMarker) != std::string::npos)
                ++ordinary;
            if (e.data.find(kForensicRow) != std::string::npos)
                ++forensic;
        }
    }
    CHECK(forensic == 0); // never published, in either case, wired or not
    if (wired) {
        CHECK(ordinary == 1); // control: the ordinary plugin's row reaches the bus
        // The ordinary row plus one fixed notice for each of the two Forensics frames.
        CHECK(output_events == 3);
        CHECK(notices == 2);
    } else {
        CHECK(ordinary == 0); // an unwired set publishes no output row at all
        CHECK(output_events == 0);
        CHECK(notices == 0);
    }
}

// -- A5: the result-set materialiser's content-membership read ------------------------------------

namespace {

yuzu::test::PgTestTemplate leaks_responsestore_tpl{
    "responsestore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("responsestore template: store failed to migrate");
    }};

void put_source_row(ResponseStore& store, const std::string& execution_id,
                    const std::string& agent_id, const std::string& plugin,
                    const std::string& output) {
    StoredResponse r;
    r.instruction_id = plugin + "-1";
    r.execution_id = execution_id;
    r.agent_id = agent_id;
    r.plugin = plugin;
    r.status = 1;
    r.output = output;
    r.timestamp = 100;
    store.store(r);
}

constexpr const char* kHit =
    R"({"columns":[{"name":"hostname","type":"string"}],"rows":[{"hostname":"marker-4990-member"}]})";
constexpr const char* kContentMatcher =
    R"({"column":"hostname","op":"eq","value":"marker-4990-member"})";

} // namespace

TEST_CASE("result-set materialiser: membership is never derived from a Forensics plugin's rows",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leaks_responsestore_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    put_source_row(store, "exec-ordinary", "agent-1", test::kOrdinaryPlugin, kHit);
    put_source_row(store, "exec-ordinary", "agent-2", test::kOrdinaryPlugin,
                   R"({"columns":[{"name":"hostname","type":"string"}],"rows":[{"hostname":"other"}]})");
    put_source_row(store, "exec-forensic", "agent-1", test::kForensicsPlugin, kHit);
    put_source_row(store, "exec-forensic", "agent-3", test::kForensicsPlugin, kHit);

    const auto pending = [](const std::string& source, const std::string& matcher) {
        PendingSet p;
        p.id = "rs-" + source;
        p.owner_principal = "alice";
        p.source_kind = "instruction_result";
        p.source_execution_id = source;
        p.matcher = matcher;
        return p;
    };
    const auto& set = test::forensics_plugin_set();

    SECTION("control: an ordinary source matches by content (and by the default matcher)") {
        auto content = result_set_members(store, &set, pending("exec-ordinary", kContentMatcher));
        REQUIRE(content.has_value());
        CHECK(*content == std::vector<std::string>{"agent-1"});
        auto dflt = result_set_members(store, &set, pending("exec-ordinary", ""));
        REQUIRE(dflt.has_value());
        CHECK(dflt->size() == 2);
    }
    SECTION("a Forensics source yields no content-derived and no default membership") {
        auto content = result_set_members(store, &set, pending("exec-forensic", kContentMatcher));
        REQUIRE(content.has_value());
        CHECK(content->empty());
        auto dflt = result_set_members(store, &set, pending("exec-forensic", ""));
        REQUIRE(dflt.has_value());
        CHECK(dflt->empty());
    }
    SECTION("an unwired plugin set refuses every row, ordinary sources included") {
        auto content = result_set_members(store, nullptr, pending("exec-ordinary", kContentMatcher));
        REQUIRE(content.has_value());
        CHECK(content->empty());
    }
}

// -- A6: the SQL fold is ASCII-only, like the C++ one --------------------------------------------

TEST_CASE("response tier SQL folds the plugin name as ASCII, whatever the database locale",
          "[pg][server][forensics_tier][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leaks_responsestore_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    // U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE): a locale-aware lower() folds it to a plain
    // "i" under some database locales, which would turn this into the Forensics plugin's name.
    // An ASCII fold leaves it alone, so the row is NOT the Forensics plugin, exactly as in C++.
    const std::string lookalike = "BROWSER_\xC4\xB0NVENTORY";
    REQUIRE_FALSE(test::forensics_plugin_set().contains(lookalike));
    put_source_row(store, "exec-fold", "agent-1", "BROWSER_INVENTORY", "upper-ascii");
    put_source_row(store, "exec-fold", "agent-2", lookalike, "lookalike");
    put_source_row(store, "exec-fold", "agent-3", test::kOrdinaryPlugin, "ordinary");

    const auto non_holder = ResponseTierFilter::exclude(test::forensics_plugin_set(),
                                                        authz::deny_all());
    auto rows = store.query_by_execution("exec-fold", non_holder);
    REQUIRE(rows.has_value());
    std::vector<std::string> outputs;
    for (const auto& r : *rows)
        outputs.push_back(r.output);
    std::ranges::sort(outputs);
    // The ASCII-upper spelling is excluded; the lookalike is not the Forensics plugin.
    CHECK(outputs == std::vector<std::string>{"lookalike", "ordinary"});
}

// -- The frozen internal-consumer sites read back only fixed, non-Forensics plugins ---------------
//
// tests/test_response_store_read_tripwire.py freezes the four remaining
// `unrestricted_internal_consumer()` sites and justifies each as "a command the server dispatches
// itself from a fixed plugin set". This pins that set against the catalogue-derived Forensics set,
// so a Forensics plugin added to one of those fixed lists fails here, not silently in production.

TEST_CASE("the plugins behind the frozen internal-consumer reads are not Forensics-tier",
          "[server][forensics_tier][security]") {
    const auto& set = test::forensics_plugin_set();
    for (const char* plugin : {"tar", "content_dist", "quarantine"}) {
        INFO(plugin);
        CHECK_FALSE(set.contains(plugin));
    }
    for (const auto& check : yuzu::server::preflight::kPreflightChecks) {
        INFO(check.plugin);
        CHECK_FALSE(set.contains(check.plugin));
    }
}
