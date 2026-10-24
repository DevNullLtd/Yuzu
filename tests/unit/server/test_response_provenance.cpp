// #4990 (UP-7): server-authored response provenance.
//
// The plugin of a stored response decides its read tier and the treatment of every derived sink.
// It used to be parsed from the command id the AGENT echoes back; it is now the plugin the SERVER
// recorded when it dispatched the command, and a response whose command id has no record is stored
// under `kUnverifiedProvenanceLabel`, which is a member of the Forensics plugin set (so every SQL
// filter and every sink treats it as Forensics-tier with no per-consumer code).
//
// Part 1 pins the pure decision over a fake record source. Part 2 drives the real ingest on BOTH
// paths (the gateway proxy `process_gateway_response` and a direct Subscribe stream) against a real
// ResponseStore, ExecutionTracker, notification and analytics store, and reads the result back the
// way each kind of reader would. Every PG case runs the same expectations through both paths: the
// two paths share one function, and a divergence is the defect.
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "analytics_event_store.hpp"
#include "event_bus.hpp"
#include "execution_tracker.hpp"
#include "forensics_error_detail.hpp"
#include "forensics_plugin_set.hpp"
#include "notification_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "response_provenance.hpp"
#include "response_store.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_forensics_tier_fixture.hpp"
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

// -- Part 1: the pure decision ---------------------------------------------------------------------

TEST_CASE("response provenance: the decision over a record source",
          "[server][forensics_tier][provenance][security]") {
    int calls = 0;
    const auto make_lookup = [&](std::optional<CommandRecord> rec, std::string degrade = {}) {
        return CommandRecordLookupFn{
            [&calls, rec, degrade](const std::string&, std::string* d) -> std::optional<CommandRecord> {
                ++calls;
                if (!rec && !degrade.empty() && d)
                    *d = degrade;
                return rec;
            }};
    };

    SECTION("a recorded command takes the RECORDED plugin, whatever the id says") {
        const auto p = resolve_response_provenance(
            "echo-0001", make_lookup(CommandRecord{"browser_inventory", "exec-1"}));
        CHECK(p.verified());
        CHECK(p.plugin == "browser_inventory");
        CHECK(p.execution_id == "exec-1");
        CHECK(calls == 1);
    }
    SECTION("the id's own text is never consulted: a Forensics-looking id recorded as ordinary") {
        const auto p = resolve_response_provenance(
            "browser_inventory-0001", make_lookup(CommandRecord{"shellexec", ""}));
        CHECK(p.verified());
        CHECK(p.plugin == "shellexec");
        CHECK(p.execution_id.empty());
    }
    SECTION("no record: the unverified sentinel, with no retry (a genuine miss stays a miss)") {
        const auto p = resolve_response_provenance("echo-forged", make_lookup(std::nullopt));
        CHECK_FALSE(p.verified());
        CHECK(p.outcome == ProvenanceOutcome::kUnrecorded);
        CHECK(p.plugin == std::string(kUnverifiedProvenanceLabel));
        CHECK(p.execution_id.empty());
        CHECK(p.degrade_reasons.empty());
        CHECK(calls == 1);
    }
    SECTION("a degraded read is retried ONCE, then the frame is unverified, never ordinary") {
        const auto p =
            resolve_response_provenance("echo-0002", make_lookup(std::nullopt, "pool_exhausted"));
        CHECK(p.outcome == ProvenanceOutcome::kLookupDegraded);
        CHECK(p.plugin == std::string(kUnverifiedProvenanceLabel));
        CHECK(calls == 2);
        CHECK(p.degrade_reasons == std::vector<std::string>{"pool_exhausted", "pool_exhausted"});
    }
    SECTION("a degraded first read that the retry recovers is verified") {
        int n = 0;
        const CommandRecordLookupFn flaky = [&](const std::string&,
                                                std::string* d) -> std::optional<CommandRecord> {
            if (n++ == 0) {
                *d = "query_failed";
                return std::nullopt;
            }
            return CommandRecord{"tar", "exec-9"};
        };
        const auto p = resolve_response_provenance("tar-0003", flaky);
        CHECK(p.verified());
        CHECK(p.plugin == "tar");
        CHECK(p.degrade_reasons == std::vector<std::string>{"query_failed"});
    }
    SECTION("a record without a plugin is not a provenance record") {
        const auto p = resolve_response_provenance("echo-0004", make_lookup(CommandRecord{"", "e"}));
        CHECK_FALSE(p.verified());
        CHECK(p.plugin == std::string(kUnverifiedProvenanceLabel));
        CHECK(p.execution_id.empty()); // the correlation of an unusable record is not trusted either
    }
    SECTION("an empty command id is never looked up; an unwired source is unrecorded") {
        CHECK_FALSE(resolve_response_provenance("", make_lookup(CommandRecord{"tar", ""})).verified());
        CHECK(calls == 0);
        const auto p = resolve_response_provenance("tar-0005", CommandRecordLookupFn{});
        CHECK(p.outcome == ProvenanceOutcome::kUnrecorded);
        CHECK(p.plugin == std::string(kUnverifiedProvenanceLabel));
    }
}

TEST_CASE("response provenance: the sentinel is in the Forensics set and can never be a plugin name",
          "[server][forensics_tier][provenance][security]") {
    const auto& set = test::forensics_plugin_set();
    CHECK(set.contains(kUnverifiedProvenanceLabel));
    CHECK(set.contains("~UNVERIFIED")); // the fold the SQL uses
    // A real plugin name cannot contain '~', so the sentinel cannot collide with one.
    const CommandCapabilityRegistry registry{YUZU_ALL_CAPABILITY_FRAGMENTS};
    registry.for_each_row([](const CommandCapability& cap) {
        CHECK(cap.plugin.find('~') == std::string_view::npos);
    });
    // A Forensics-tier filter and a fixed-plugin poll both exclude it; a global grant admits it.
    CHECK_FALSE(ResponseTierFilter::exclude(set, authz::deny_all()).admits(kUnverifiedProvenanceLabel));
    CHECK_FALSE(ResponseTierFilter::for_fixed_plugin_poll(&set).admits(kUnverifiedProvenanceLabel));
    CHECK(ResponseTierFilter::exclude(set, authz::VisibleSet{}).admits(kUnverifiedProvenanceLabel));
    // An ordinary plugin is untouched (control).
    CHECK(ResponseTierFilter::exclude(set, authz::deny_all()).admits(test::kOrdinaryPlugin));
}

// -- Part 2: the real ingest, both paths -----------------------------------------------------------

namespace {

yuzu::test::PgTestTemplate provenance_tpl{
    "provenance", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ExecutionTracker tracker{pool};
        ResponseStore responses{pool};
        NotificationStore notifications{pool};
        AnalyticsEventStore analytics{pool};
        if (!tracker.is_open() || !responses.is_open() || !notifications.is_open() ||
            !analytics.is_open())
            throw std::runtime_error("provenance template: a store failed to migrate");
    }};

constexpr const char* kMarker = "marker-4990-provenance";
constexpr const char* kFreeText = "marker-4990-error: could not open C:\\Users\\bob\\secret.txt";
constexpr const char* kDirectAgent = "agent-direct";
constexpr const char* kGatewayAgent = "agent-gateway";

apb::CommandResponse frame(const std::string& command_id, apb::CommandResponse::Status status,
                           const std::string& output, const std::string& error = {}) {
    apb::CommandResponse r;
    r.set_command_id(command_id);
    r.set_status(status);
    r.set_output(output);
    if (!error.empty()) {
        r.set_exit_code(3);
        r.mutable_error()->set_message(error);
    }
    return r;
}

apb::CommandResponse running(const std::string& id, const std::string& output) {
    return frame(id, apb::CommandResponse::RUNNING, output);
}
apb::CommandResponse failed(const std::string& id, const std::string& error) {
    return frame(id, apb::CommandResponse::FAILURE, "", error);
}

/// A service wired like production for the response side: a tracker holding the dispatch records,
/// a response store, the catalogue-derived Forensics set, the notification and analytics sinks, and
/// both ingest entry points. NO prefix-labelling fake: the dispatch record is the only source.
struct Harness {
    yuzu::server::pg::PgPool pool;
    yuzu::test::AuthDbPgShared auth_db;
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    ResponseStore responses;
    NotificationStore notifications;
    std::shared_ptr<AnalyticsEventStore> analytics;
    std::unique_ptr<ExecutionTracker> tracker;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve,
                         metrics, /*gateway_mode=*/false};
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<apb::AgentService::Stub> stub;
    int port = 0;
    std::mutex bus_mu;
    std::vector<SseEvent> seen;
    std::size_t bus_sub = 0;
    bool direct = false;

    explicit Harness(const std::string& dsn, bool use_direct)
        : pool({.conninfo = dsn, .size = 6}), responses(pool), notifications(pool),
          analytics(std::make_shared<AnalyticsEventStore>(pool)), direct(use_direct) {
        REQUIRE(responses.is_open());
        REQUIRE(notifications.is_open());
        REQUIRE(analytics->is_open());
        tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());
        auth_mgr.set_auth_db(auth_db.get());
        svc.set_response_store(&responses);
        svc.set_forensics_plugin_set(&test::forensics_plugin_set());
        svc.set_notification_store(&notifications);
        svc.set_analytics_store(analytics);
        svc.set_execution_tracker(tracker.get());
        bus_sub = bus.subscribe([this](const SseEvent& e) {
            std::lock_guard lock(bus_mu);
            seen.push_back(e);
        });
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        stub = apb::AgentService::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port),
                                                              grpc::InsecureChannelCredentials()));
    }
    ~Harness() {
        bus.unsubscribe(bus_sub);
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
        svc.set_notification_store(nullptr);
        svc.set_analytics_store({});
        svc.set_execution_tracker(nullptr);
        tracker.reset();
    }
    Harness(const Harness&) = delete;
    Harness& operator=(const Harness&) = delete;

    [[nodiscard]] const char* agent() const { return direct ? kDirectAgent : kGatewayAgent; }

    /// The server dispatched `command_id` as `plugin` (what `build_classified_command` records).
    void dispatched(const std::string& command_id, const std::string& plugin,
                    const std::string& execution_id = {}) {
        svc.record_command_dispatch(command_id, plugin, execution_id);
    }

    /// One frame through the path under test.
    void ingest(const apb::CommandResponse& f) {
        if (!direct) {
            svc.process_gateway_response(kGatewayAgent, f);
            return;
        }
        const auto deadline = [] {
            return std::chrono::system_clock::now() + std::chrono::seconds(20);
        };
        auto token = auth_mgr.create_enrollment_token("provenance", 0, std::chrono::hours(1),
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
        REQUIRE(stream->Write(f));
        REQUIRE(stream->WritesDone());
        apb::CommandRequest unused;
        while (stream->Read(&unused)) {}
        CHECK(stream->Finish().ok());
    }

    /// The stored rows of `command_id`, read the way each kind of reader reads.
    [[nodiscard]] std::vector<StoredResponse> rows_for(const std::string& id,
                                                       const ResponseTierFilter& tier) const {
        auto r = responses.get_by_instruction(id, tier);
        REQUIRE(r.has_value());
        return *r;
    }
    [[nodiscard]] std::vector<StoredResponse> all_rows(const std::string& id) const {
        return rows_for(id, ResponseTierFilter::unrestricted_internal_consumer());
    }
    /// A reader holding Response:Read but not Forensics:Read.
    [[nodiscard]] std::vector<StoredResponse> lower_reader(const std::string& id) const {
        return rows_for(id, ResponseTierFilter::exclude(test::forensics_plugin_set(), authz::deny_all()));
    }
    /// A reader holding a global Forensics:Read.
    [[nodiscard]] std::vector<StoredResponse> forensics_reader(const std::string& id) const {
        return rows_for(id, ResponseTierFilter::exclude(test::forensics_plugin_set(), authz::VisibleSet{}));
    }
    [[nodiscard]] std::vector<StoredResponse> fixed_poll(const std::string& id) const {
        return rows_for(id, ResponseTierFilter::for_fixed_plugin_poll(&test::forensics_plugin_set()));
    }
    [[nodiscard]] std::size_t live_rows_with(std::string_view needle) {
        std::lock_guard lock(bus_mu);
        std::size_t n = 0;
        for (const auto& e : seen)
            if (e.event_type == "output" && e.data.find(needle) != std::string::npos)
                ++n;
        return n;
    }
    [[nodiscard]] std::vector<std::string> notification_messages() {
        std::vector<std::string> out;
        for (const auto& n : notifications.list_all())
            if (n.title == "Execution Failed")
                out.push_back(n.message);
        return out;
    }
    [[nodiscard]] std::vector<AnalyticsEvent> analytics_events(const std::string& event_type) const {
        const auto all = analytics->query_recent(50);
        REQUIRE(all.has_value());
        std::vector<AnalyticsEvent> out;
        for (const auto& e : *all)
            if (e.event_type == event_type)
                out.push_back(e);
        return out;
    }
};

const std::string kUnverified{kUnverifiedProvenanceLabel};

} // namespace

TEST_CASE("provenance ingest: an id the server never issued is stored and treated as Forensics-tier",
          "[pg][server][forensics_tier][provenance][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    // An ordinary-looking id for a command nobody dispatched (an agent forging a label).
    const std::string forged = std::string{test::kOrdinaryPlugin} + "-feedface";
    h.ingest(running(forged, kMarker));

    const auto stored = h.all_rows(forged);
    REQUIRE(stored.size() == 1);
    CHECK(stored[0].plugin == kUnverified);
    CHECK(stored[0].output == kMarker); // stored, not dropped: a Forensics-grant reader can see it
    CHECK(h.lower_reader(forged).empty());
    CHECK(h.fixed_poll(forged).empty());
    CHECK(h.forensics_reader(forged).size() == 1);
    CHECK(h.live_rows_with(kMarker) == 0); // the shared live stream carries nothing
    const auto events = h.analytics_events("command.response");
    REQUIRE(events.size() == 1);
    CHECK(events[0].plugin == kUnverified);
    CHECK(h.metrics.counter("yuzu_server_response_provenance_total", {{"outcome", "unrecorded"}})
              .value() == 1.0);
}

TEST_CASE("provenance ingest: a failure text for an id the server never issued is reduced in every "
          "sink",
          "[pg][server][forensics_tier][provenance][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    const std::string forged = std::string{test::kOrdinaryPlugin} + "-feedbee1";
    h.ingest(failed(forged, kFreeText));

    const auto notes = h.notification_messages();
    REQUIRE(notes.size() == 1);
    CHECK(notes[0] == "Command " + forged + " on agent " + h.agent() + " failed: forensics_error");
    const auto events = h.analytics_events("command.completed");
    REQUIRE(events.size() == 1);
    CHECK(events[0].plugin == kUnverified);
    CHECK(events[0].payload.at("error_message").get<std::string>() == "forensics_error");
    // The stored row keeps the raw message (it is read through the tier filter, which withholds it).
    const auto stored = h.all_rows(forged);
    REQUIRE(stored.size() == 1);
    CHECK(stored[0].error_detail == kFreeText);
    CHECK(h.lower_reader(forged).empty());
}

TEST_CASE("provenance ingest: the recorded plugin decides, not the id an endpoint echoes",
          "[pg][server][forensics_tier][provenance][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    SECTION("a command the server dispatched as a Forensics plugin under an ordinary-looking id") {
        const std::string id = std::string{test::kOrdinaryPlugin} + "-c0ffee01";
        h.dispatched(id, test::kForensicsPlugin);
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 1);
        CHECK(stored[0].plugin == test::kForensicsPlugin);
        CHECK(h.lower_reader(id).empty());
        CHECK(h.forensics_reader(id).size() == 1);
        CHECK(h.live_rows_with(kMarker) == 0);
        CHECK(h.metrics.counter("yuzu_server_response_provenance_total", {{"outcome", "verified"}})
                  .value() == 1.0);

        h.ingest(failed(id, kFreeText));
        const auto notes = h.notification_messages();
        REQUIRE(notes.size() == 1);
        CHECK(notes[0].find("marker-4990") == std::string::npos);
    }
    SECTION("the reverse: a Forensics-looking id recorded as an ordinary plugin is ordinary") {
        const std::string id = std::string{test::kForensicsPlugin} + "-c0ffee02";
        h.dispatched(id, test::kOrdinaryPlugin);
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 1);
        CHECK(stored[0].plugin == test::kOrdinaryPlugin);
        CHECK(h.lower_reader(id).size() == 1);
        CHECK(h.live_rows_with(kMarker) == 1);
    }
}

TEST_CASE("provenance ingest: a recorded ordinary dispatch is unchanged end to end",
          "[pg][server][forensics_tier][provenance]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    const auto exec = [&] {
        Execution e;
        e.definition_id = "def-prov";
        e.dispatched_by = "tester";
        e.status = "running";
        e.agents_targeted = 1;
        auto id = h.tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }();
    const std::string id = std::string{test::kOrdinaryPlugin} + "-0badf00d";
    h.dispatched(id, test::kOrdinaryPlugin, exec);
    h.ingest(running(id, kMarker));
    h.ingest(failed(id, kFreeText));

    const auto stored = h.all_rows(id);
    REQUIRE_FALSE(stored.empty());
    for (const auto& r : stored) {
        CHECK(r.plugin == test::kOrdinaryPlugin);
        CHECK(r.execution_id == exec);
    }
    CHECK(h.lower_reader(id).size() == stored.size());
    CHECK(h.fixed_poll(id).size() == stored.size()); // a fixed-plugin poll still finds it
    CHECK(h.live_rows_with(kMarker) == 1);
    const auto notes = h.notification_messages();
    REQUIRE(notes.size() == 1);
    CHECK(notes[0] == "Command " + id + " on agent " + h.agent() + " failed: " + kFreeText);
    const auto statuses = h.tracker->get_agent_statuses(exec);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].error_detail == kFreeText);
}

// The tracker classifies an execution by the plugin the server RECORDED for its commands, never by
// the prefix of the command id. Every other tracker case records plugin == id prefix, so a
// regression to a prefix parse (in the sink text or in the SQL read) would pass them all; these two
// give the recorded plugin and the prefix different values.
namespace {
std::string make_execution(Harness& h, const std::string& definition) {
    Execution e;
    e.definition_id = definition;
    e.dispatched_by = "tester";
    e.status = "running";
    e.agents_targeted = 2;
    auto id = h.tracker->create_execution(e);
    REQUIRE(id.has_value());
    return *id;
}

/// An agent-status row whose text is stored RAW, standing in for a row written before the text was
/// reduced at ingest. Only the read paths can reduce it, and they decide by the recorded plugin.
void store_raw_status(Harness& h, const std::string& exec, const std::string& agent) {
    AgentExecStatus raw;
    raw.agent_id = agent;
    raw.status = "failure";
    raw.dispatched_at = 1;
    raw.first_response_at = 2;
    raw.completed_at = 4102444800; // later than the ingested frame, so it is the latest error
    raw.exit_code = 3;
    raw.error_detail = kFreeText;
    h.tracker->update_agent_status(exec, raw);
}

/// The error text exactly as persisted, bypassing the tracker's read-time reduction.
std::string persisted_error_detail(Harness& h, const std::string& exec, const std::string& agent) {
    auto lease = h.pool.acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(
        lease.get(),
        "SELECT error_detail FROM execution_tracker.agent_exec_status "
        "WHERE execution_id = $1 AND agent_id = $2",
        std::vector<std::string>{exec, agent});
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

const AgentExecStatus* status_of(const std::vector<AgentExecStatus>& all, const std::string& agent) {
    for (const auto& a : all)
        if (a.agent_id == agent)
            return &a;
    return nullptr;
}
} // namespace

TEST_CASE("provenance tracker: a Forensics plugin recorded under an ordinary-looking id is a "
          "Forensics execution",
          "[pg][server][forensics_tier][provenance][tracker][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);
    h.tracker->set_forensics_plugin_set(&test::forensics_plugin_set());

    const auto exec = make_execution(h, "def-prov-recorded-forensics");
    const std::string id = std::string{test::kOrdinaryPlugin} + "-aa550001"; // prefix: ordinary
    h.dispatched(id, test::kForensicsPlugin, exec);                          // recorded: Forensics
    h.ingest(failed(id, kFreeText));

    // The sink text written by notify_exec_tracker comes from the recorded plugin.
    auto statuses = h.tracker->get_agent_statuses(exec);
    const auto* ingested = status_of(statuses, h.agent());
    REQUIRE(ingested != nullptr);
    CHECK(ingested->status == "failure");
    CHECK(ingested->error_detail == "forensics_error");
    // ...and it is the PERSISTED text (the value the outbox and the bus carry), not only the
    // reduction a read applies afterwards.
    CHECK(persisted_error_detail(h, exec, h.agent()) == "forensics_error");
    const auto notes = h.notification_messages();
    REQUIRE(notes.size() == 1);
    CHECK(notes[0] == "Command " + id + " on agent " + h.agent() + " failed: forensics_error");

    // The SQL read decides by the recorded plugin too: a raw row on the same execution is reduced
    // by every tracker read.
    store_raw_status(h, exec, "agent-raw");
    statuses = h.tracker->get_agent_statuses(exec);
    const auto* raw = status_of(statuses, "agent-raw");
    REQUIRE(raw != nullptr);
    CHECK(raw->error_detail == "forensics_error");
    const auto one = h.tracker->get_execution(exec);
    REQUIRE(one.has_value());
    CHECK(one->last_error_detail == "forensics_error");
}

TEST_CASE("provenance tracker: a Forensics-looking id recorded as an ordinary plugin is not reduced",
          "[pg][server][forensics_tier][provenance][tracker][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);
    h.tracker->set_forensics_plugin_set(&test::forensics_plugin_set());

    const auto exec = make_execution(h, "def-prov-recorded-ordinary");
    const std::string id = std::string{test::kForensicsPlugin} + "-aa550002"; // prefix: Forensics
    h.dispatched(id, test::kOrdinaryPlugin, exec);                            // recorded: ordinary
    h.ingest(failed(id, kFreeText));

    auto statuses = h.tracker->get_agent_statuses(exec);
    const auto* ingested = status_of(statuses, h.agent());
    REQUIRE(ingested != nullptr);
    CHECK(ingested->error_detail == kFreeText);
    CHECK(persisted_error_detail(h, exec, h.agent()) == kFreeText);
    const auto notes = h.notification_messages();
    REQUIRE(notes.size() == 1);
    CHECK(notes[0] == "Command " + id + " on agent " + h.agent() + " failed: " + kFreeText);

    store_raw_status(h, exec, "agent-raw");
    statuses = h.tracker->get_agent_statuses(exec);
    const auto* raw = status_of(statuses, "agent-raw");
    REQUIRE(raw != nullptr);
    CHECK(raw->error_detail == kFreeText);
    const auto one = h.tracker->get_execution(exec);
    REQUIRE(one.has_value());
    CHECK(one->last_error_detail == kFreeText);
}

TEST_CASE("provenance tracker: a dispatch record with an empty plugin is read as Forensics-tier",
          "[pg][server][forensics_tier][provenance][tracker][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), /*use_direct=*/false);
    h.tracker->set_forensics_plugin_set(&test::forensics_plugin_set());

    const auto exec = make_execution(h, "def-prov-empty-plugin");
    {
        // `record_command_dispatch` refuses an empty plugin, so the row is written the way the
        // column default would leave one.
        auto lease = h.pool.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "INSERT INTO execution_tracker.command_execution "
                                "(command_id, execution_id, created_at, plugin) "
                                "VALUES ('anonymous-00ee0001', $1, extract(epoch FROM now())::bigint, '')",
                                std::vector<std::string>{exec})
                    .status() == PGRES_COMMAND_OK);
    }
    store_raw_status(h, exec, "agent-raw");
    const auto statuses = h.tracker->get_agent_statuses(exec);
    const auto* raw = status_of(statuses, "agent-raw");
    REQUIRE(raw != nullptr);
    CHECK(raw->error_detail == "forensics_error");
    const auto one = h.tracker->get_execution(exec);
    REQUIRE(one.has_value());
    CHECK(one->last_error_detail == "forensics_error");
}

TEST_CASE("provenance ingest: the server's own correlation-id families keep their plugin and their "
          "consumers",
          "[pg][server][forensics_tier][provenance]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    SECTION("execution-id families: stamped, readable by the consumer, never a tracker row") {
        for (const std::string exec :
             {"polchk-abc123", "preflight-run1-check2", "deployment-xyz-stage", "bundle-def456"}) {
            CAPTURE(exec);
            const std::string id = "echo-" + exec;
            h.dispatched(id, "echo", exec);
            h.ingest(running(id, kMarker));
            const auto stored = h.all_rows(id);
            REQUIRE(stored.size() == 1);
            CHECK(stored[0].plugin == "echo");
            CHECK(stored[0].execution_id == exec);
            CHECK(h.fixed_poll(id).size() == 1);
            CHECK(h.tracker->get_agent_statuses(exec).empty()); // notify_exec_tracker still skips
        }
    }
    SECTION("system-reserved ids are recorded under their real plugin, not the id's prefix") {
        struct Family {
            std::string id;
            std::string plugin;
        };
        const std::vector<Family> families = {
            {"__sync__-now-1700000000-aabbccdd", "__sync__"},
            {"asset-tag-sync-1700000000123", "asset_tags"}, // prefix `asset` is not the plugin
            {"tar-0123456789abcdef", "tar"},
        };
        for (const auto& f : families) {
            CAPTURE(f.id);
            h.dispatched(f.id, f.plugin);
            h.ingest(running(f.id, kMarker));
            const auto stored = h.all_rows(f.id);
            REQUIRE(stored.size() == 1);
            CHECK(stored[0].plugin == f.plugin);
            CHECK(stored[0].plugin != kUnverified);
            CHECK(h.fixed_poll(f.id).size() == 1); // the hardware / TAR polls read exactly this
        }
    }
    SECTION("a reserved-looking id the server never issued is unverified like any other") {
        const std::string id = "__sync__-now-1700000000-deadbeef";
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 1);
        CHECK(stored[0].plugin == kUnverified);
        CHECK(h.fixed_poll(id).empty());
    }
}

TEST_CASE("provenance ingest: a gateway-forwarded solicited __guard__ reply keeps its recorded plugin",
          "[pg][server][forensics_tier][provenance]") {
    // The direct Subscribe path drops solicited __guard__ replies before any store work; the
    // gateway path stores them. The recorded plugin is what labels the stored row.
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), /*use_direct=*/false);
    const std::string id = "__guard__-push-1700000000-aabbccdd";
    h.dispatched(id, "__guard__");
    h.ingest(running(id, kMarker));
    const auto stored = h.all_rows(id);
    REQUIRE(stored.size() == 1);
    CHECK(stored[0].plugin == "__guard__");
}

TEST_CASE("provenance ingest: a keepalive heartbeat renews its claim but labels nothing",
          "[pg][server][forensics_tier][provenance]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    // A heartbeat for a recorded command and one for a command the server never issued: neither
    // is a response row, so neither moves the per-response outcome counter nor stores anything.
    const std::string known = std::string{test::kOrdinaryPlugin} + "-1ee70001";
    h.dispatched(known, test::kOrdinaryPlugin);
    h.ingest(running(known, "__keepalive__"));
    h.ingest(running(std::string{test::kOrdinaryPlugin} + "-1ee70002", "__keepalive__"));

    for (const char* outcome : {"verified", "unrecorded", "lookup_degraded"})
        CHECK(h.metrics.counter("yuzu_server_response_provenance_total", {{"outcome", outcome}})
                  .value() == 0.0);
    CHECK(h.all_rows(known).empty());

    // A real response still counts, so the zero above is not a dead counter.
    h.ingest(running(known, kMarker));
    CHECK(h.metrics.counter("yuzu_server_response_provenance_total", {{"outcome", "verified"}})
              .value() == 1.0);
}

TEST_CASE("provenance record: a failing record store is counted for every dispatch but logs once",
          "[pg][server][forensics_tier][provenance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), /*use_direct=*/false);
    {
        auto lease = h.pool.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "DROP TABLE execution_tracker.command_execution",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    std::string logs;
    {
        yuzu::test::LogCapture capture;
        for (int i = 0; i < 5; ++i)
            h.dispatched(std::string{test::kOrdinaryPlugin} + "-0ee0000" + std::to_string(i),
                         test::kOrdinaryPlugin);
        capture.stop();
        logs = capture.text();
    }
    // Every failure is counted; the line is throttled (at most one per 60 s per cause, and an
    // earlier case in this process may already have spent this cause's slot).
    CHECK(h.metrics.counter("yuzu_exec_correlation_write_degrade_total").value() == 5.0);
    std::size_t lines = 0;
    for (std::size_t at = logs.find("record_command_dispatch: write failed"); at != std::string::npos;
         at = logs.find("record_command_dispatch: write failed", at + 1))
        ++lines;
    CHECK(lines <= 1);
}

TEST_CASE("provenance ingest: failure to record fails safe, and a reaped record is unverified",
          "[pg][server][forensics_tier][provenance][security]") {
    const bool direct = GENERATE(false, true);
    INFO((direct ? "direct Subscribe path" : "gateway path"));
    YUZU_REQUIRE_PG_DB_TPL(db, provenance_tpl);
    Harness h(db.dsn(), direct);

    SECTION("no tracker wired: the record cannot be written and the response is unverified") {
        h.svc.set_execution_tracker(nullptr);
        const std::string id = std::string{test::kOrdinaryPlugin} + "-0000aa01";
        h.dispatched(id, test::kOrdinaryPlugin);
        CHECK(h.metrics.counter("yuzu_exec_correlation_write_degrade_total").value() == 1.0);
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 1);
        CHECK(stored[0].plugin == kUnverified);
        CHECK(h.lower_reader(id).empty());
        h.svc.set_execution_tracker(h.tracker.get()); // restored for the destructor's contract
    }
    SECTION("the record table is unreadable: the frame is lookup_degraded and unverified") {
        const std::string id = std::string{test::kOrdinaryPlugin} + "-0000aa02";
        h.dispatched(id, test::kOrdinaryPlugin);
        {
            auto lease = h.pool.acquire();
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(), "DROP TABLE execution_tracker.command_execution",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 1);
        CHECK(stored[0].plugin == kUnverified);
        CHECK(h.lower_reader(id).empty());
        CHECK(h.live_rows_with(kMarker) == 0);
        CHECK(h.metrics
                  .counter("yuzu_server_response_provenance_total", {{"outcome", "lookup_degraded"}})
                  .value() == 1.0);
        CHECK(h.metrics
                  .counter("yuzu_exec_correlation_read_degrade_total", {{"reason", "query_failed"}})
                  .value() == 2.0); // the attempt and its one retry
    }
    SECTION("a record reaped after its window: a late response is unverified") {
        const std::string id = std::string{test::kOrdinaryPlugin} + "-0000aa03";
        h.dispatched(id, test::kOrdinaryPlugin);
        h.ingest(running(id, "before-reap"));
        {
            auto lease = h.pool.acquire();
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(),
                                    "UPDATE execution_tracker.command_execution "
                                    "SET created_at = created_at - 90000",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        const auto reaped = h.tracker->reap_command_execution_mappings();
        REQUIRE(reaped.has_value());
        REQUIRE(reaped->deleted == 1);
        h.ingest(running(id, kMarker));
        const auto stored = h.all_rows(id);
        REQUIRE(stored.size() == 2);
        std::size_t unverified = 0, ordinary = 0;
        for (const auto& r : stored)
            (r.plugin == kUnverified ? unverified : ordinary) += 1;
        CHECK(ordinary == 1);   // the frame before the reap
        CHECK(unverified == 1); // the frame after it
    }
}
