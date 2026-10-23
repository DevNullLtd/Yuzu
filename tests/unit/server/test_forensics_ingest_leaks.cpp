// #4990 wave A: the paths that carry Forensics-tier plugin output OUTSIDE the stored-response
// read seam. Each case drives the real ingest (AgentServiceImpl::process_gateway_response) or the
// real consumer and asserts the exact observable output, with an ordinary-plugin control so a
// filter that silenced everything would fail too.
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <map>
#include <stdexcept>
#include <memory>
#include <string>
#include <vector>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "event_bus.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "forensics_error_detail.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_tracker_scope.hpp"
#include "../test_helpers.hpp"
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
    std::size_t marker_count() const {
        std::size_t n = 0;
        for (const auto& e : seen)
            if (e.data.find(kMarker) != std::string::npos)
                ++n;
        return n;
    }
};

} // namespace

TEST_CASE("live output bus: a Forensics-tier plugin's rows are never published",
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
    SECTION("every Forensics plugin, in any ASCII case, publishes nothing") {
        for (const auto& plugin : test::forensics_plugin_set().names()) {
            h.svc.process_gateway_response("agent-1", running_frame(plugin + "-0001", kMarker));
            std::string upper = plugin;
            for (auto& c : upper)
                if (c >= 'a' && c <= 'z')
                    c = static_cast<char>(c - 'a' + 'A');
            h.svc.process_gateway_response("agent-1", running_frame(upper + "-0002", kMarker));
        }
        CHECK(h.output_events().empty());
        CHECK(h.marker_count() == 0);
    }
    SECTION("a mixed batch: only the ordinary plugin's frame publishes") {
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kForensicsPlugin} + "-0001", kMarker));
        h.svc.process_gateway_response(
            "agent-1", running_frame(std::string{test::kOrdinaryPlugin} + "-0002", kMarker));
        CHECK(h.output_events().size() == 1);
        CHECK(h.marker_count() == 1);
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

    SECTION("unwired tracker returns the stored text (harness behaviour)") {
        CHECK(tracker.get_agent_statuses(forensic)[0].error_detail == kFreeText);
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
