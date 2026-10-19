/**
 * test_plugin_result_audit.cpp -- `registry.write` audit rows from the registry plugin's
 * mutating-action output frames (server/core/src/plugin_result_audit.hpp): the pure extractor, event
 * shape and BINDING, then the live RUNNING-frame ingest on both ingress paths (Postgres-backed, skipped
 * without YUZU_TEST_POSTGRES_DSN like every store test).
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "audit_store.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "command_capability.hpp"
#include "event_bus.hpp"
#include "grpc_audit_signal.hpp"
#include "pg/pg_pool.hpp"
#include "plugin_result_audit.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "test_principal_lock_gate.hpp"
#include "web_utils.hpp"
#include "../test_helpers.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
namespace apb = ::yuzu::agent::v1;

namespace {

constexpr std::string_view kOkLine =
    "audit|op=set_value|hive=HKLM|key=SOFTWARE\\Acme|name=Ver|type=REG_DWORD|len=4|result=ok|reason=-|"
    "verify=ok|dry_run=-|counted_keys=-|counted_values=-|capped=-|sid=-|old_state=present|"
    "old_type=REG_DWORD|old=01000000|new=02000000";

std::string line_with_result(std::string_view result, std::string_view dry_run = "-") {
    return "audit|op=delete_key|hive=HKLM|key=K|name=-|type=-|len=-|result=" + std::string{result} +
           "|reason=-|verify=-|dry_run=" + std::string{dry_run} +
           "|counted_keys=1|counted_values=0|capped=0|sid=-|old_state=-|old_type=-|old=-|new=-";
}

} // namespace

// ── extraction ───────────────────────────────────────────────────────────

TEST_CASE("registry audit: only audit| lines are extracted, byte-exact", "[server][registry_audit]") {
    const std::string output = "status|ok\n" + std::string{kOkLine} + "\nwarning|something\nnot-audit|x\n audit|leading space\n";
    const auto lines = extract_registry_audit_lines(output);
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == kOkLine);
}

TEST_CASE("registry audit: per-frame bounds and neutralisation", "[server][registry_audit]") {
    SECTION("301 lines give 300") {
        std::string output;
        for (int i = 0; i < 301; ++i) output += "audit|op=x" + std::to_string(i) + "\n";
        const auto lines = extract_registry_audit_lines(output);
        CHECK(lines.size() == kMaxRegistryAuditLinesPerFrame);
        CHECK(lines.back() == "audit|op=x299");
    }
    SECTION("a 5 KiB line is cut to 4096 bytes") {
        const std::string big = "audit|" + std::string(5000, 'k');
        const auto lines = extract_registry_audit_lines(big);
        REQUIRE(lines.size() == 1);
        CHECK(lines[0].size() == kMaxRegistryAuditLineBytes);
    }
    SECTION("the cut never lands inside a multi-byte character") {
        // 4091 ASCII bytes after "audit|" puts the next 2-byte character straddling byte 4096.
        std::string s = "audit|" + std::string(kMaxRegistryAuditLineBytes - 6 - 1, 'k');
        s += "\xC3\xA9tail";
        const auto lines = extract_registry_audit_lines(s);
        REQUIRE(lines.size() == 1);
        CHECK(lines[0].size() == kMaxRegistryAuditLineBytes - 1);
    }
    SECTION("every ASCII control byte becomes '_' (CR, NUL, ESC, BEL, DEL ...); LF is the line separator") {
        const std::string out = std::string{"audit|a\rb"} + '\0' + "c\x1b" + "d\a" + "e\x7f" + "f\naudit|g\n";
        const auto lines = extract_registry_audit_lines(out);
        REQUIRE(lines.size() == 2);
        CHECK(lines[0] == "audit|a_b_c_d_e_f");
        CHECK(lines[1] == "audit|g");
    }
}

TEST_CASE("registry audit: result comes from result=, never from dry_run=", "[server][registry_audit]") {
    const auto ev = [](const std::string& l) { return make_registry_audit_event("agent-1", "registry-77", l, 1000); };
    CHECK(ev(std::string{kOkLine}).result == "success");
    CHECK(ev(line_with_result("ok", "1")).result == "success");       // a dry run that was fine
    CHECK(ev(line_with_result("refused", "1")).result == "failure");  // a refused dry run is a failure
    CHECK(ev(line_with_result("refused", "0")).result == "failure");
    CHECK(ev(line_with_result("failed", "0")).result == "failure");
    CHECK(ev("audit|op=x").result == "failure");                       // no result= field: not a success
}

TEST_CASE("registry audit: the AuditEvent shape", "[server][registry_audit]") {
    const auto ev = make_registry_audit_event("agent-1", "registry-77", kOkLine, 1234567890);
    CHECK(ev.timestamp == 1234567890);
    CHECK(ev.principal == "agent:agent-1");
    CHECK(ev.principal_role == "agent");
    CHECK(ev.action == "registry.write");
    CHECK(ev.target_type == "Command");
    CHECK(ev.target_id == "registry-77");
    CHECK(ev.detail == std::string{kOkLine} + " agent=agent-1");
    CHECK(ev.result == "success");
    SECTION("an agent id with spaces or '=' cannot forge a detail token") {
        const auto e2 = make_registry_audit_event("a b=c", "registry-1", kOkLine, 1);
        CHECK(e2.detail.ends_with(" agent=a_b_c"));
    }
}

// ── the binding ──────────────────────────────────────────────────────────

TEST_CASE("registry audit: only the three mutating actions of the registry plugin mint rows",
          "[server][registry_audit]") {
    const std::string output = "status|ok\n" + std::string{kOkLine} + "\n";
    const auto events = [&](std::string_view plugin, std::string_view action) {
        return registry_audit_events_for_frame("agent-1", "registry-9", plugin, action, output, 5);
    };
    for (const char* a : {"set_value", "delete_value", "delete_key"}) {
        INFO(a);
        CHECK(events("registry", a).size() == 1);
        CHECK(is_registry_mutating_action(a));
    }
    SECTION("read actions, an empty action (an old agent) and unknown actions mint nothing") {
        for (const char* a : {"get_value", "key_exists", "enumerate_keys", "enumerate_values",
                              "get_user_value", "list_profiles", "", "Set_Value", "set_value ", "bogus"}) {
            INFO("[" << a << "]");
            CHECK(events("registry", a).empty());
            CHECK_FALSE(is_registry_mutating_action(a));
        }
    }
    SECTION("another plugin with a mutating-looking action mints nothing") {
        CHECK(events("filesystem", "set_value").empty());
        CHECK(events("", "set_value").empty());
        CHECK(events("registry2", "set_value").empty());
    }
    SECTION("each extracted line becomes its own row") {
        const std::string two = std::string{kOkLine} + "\n" + line_with_result("refused") + "\n";
        CHECK(registry_audit_events_for_frame("agent-1", "registry-9", "registry", "delete_key", two, 5).size() == 2);
    }
    SECTION("the plugin compares ASCII-case-insensitively: a RAW `Registry` request still runs the write") {
        // command_routes.cpp mints the id from the spelling the operator typed; the agent runs the catalogue's.
        for (const char* id : {"Registry-9", "REGISTRY-9", "rEgIsTrY-9"}) {
            INFO(id);
            CHECK(registry_audit_events_for_frame("agent-1", id, extract_plugin(id), "set_value", output, 5).size() == 1);
        }
        CHECK(events("registr", "set_value").empty());
        CHECK(events("registry ", "set_value").empty());
    }
}

TEST_CASE("registry audit: an agent-supplied command_id the server could not have minted mints no rows",
          "[server][registry_audit]") {
    // The id becomes every row's target_id and a frame is built whole before its first INSERT: a 3 MiB id times
    // 300 lines was ~943 MB resident, and a target_id past ~2.7 KB is rejected by idx_audit_target_ts.
    const std::string output = std::string{kOkLine} + "\n";
    const auto rows = [&](const std::string& id) {
        return registry_audit_events_for_frame("agent-1", id, "registry", "set_value", output, 5);
    };
    CHECK(rows("registry-9").size() == 1);
    CHECK(rows("0123456789abcdef0123456789abcdef").size() == 1);
    const std::string at_bound(kMaxServerCommandIdBytes, 'a');
    REQUIRE(rows(at_bound).size() == 1);
    CHECK(rows(at_bound)[0].target_id.size() == kMaxServerCommandIdBytes);
    CHECK(rows(at_bound + "a").empty());
    CHECK(rows(std::string(3U << 20, 'k')).empty());
    CHECK(rows("").empty());
    for (const char* bad : {"registry 9", "registry=9", "registry|9", "registry\n9", "registry-\x1b[2J", "registry-\xC3\xA9"}) {
        INFO(bad);
        CHECK(rows(bad).empty());
    }
}

TEST_CASE("registry audit: the mutating-action list matches the capability catalogue's non-ReadOnly registry rows",
          "[server][registry_audit]") {
    // A mutating registry action added to the catalogue but not to kRegistryMutatingActions would run
    // unaudited; this ties the two lists together.
    std::size_t registry_rows = 0, mutating_rows = 0;
    for (const auto& r : capdecls::plugin_action_catalogue_a()) {
        if (r.plugin != "registry") continue;
        ++registry_rows;
        const bool mutating = r.dispatch_class != DispatchClass::ReadOnly;
        if (mutating) ++mutating_rows;
        INFO("registry." << r.action);
        CHECK(is_registry_mutating_action(r.action) == mutating);
    }
    CHECK(registry_rows == 9);
    CHECK(mutating_rows == kRegistryMutatingActions.size());
}

// ── the live ingest (gateway ingress) ────────────────────────────────────

namespace {

yuzu::test::PgTestTemplate registry_audit_tpl{"agentaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open()) throw std::runtime_error("agentaudit template: store failed to migrate");
}};

/// MEMBER ORDER LOAD-BEARING (see GatewayResponseHarness in test_agent_service_impl.cpp): `svc`
/// borrows `audit` as a raw pointer, so `audit` and its pool are declared BEFORE it and outlive it.
struct IngestHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    yuzu::server::pg::PgPool pool;
    std::unique_ptr<AuditStore> audit;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve, metrics,
                         /*gateway_mode=*/false};

    explicit IngestHarness(const std::string& dsn) : pool({.conninfo = dsn, .size = 4}) {
        audit = std::make_unique<AuditStore>(pool);
        REQUIRE(audit->is_open());
        svc.set_audit_store(audit.get());
    }
    static apb::CommandResponse frame(const std::string& command_id, apb::CommandResponse::Status status,
                                      const std::string& action, const std::string& output) {
        apb::CommandResponse r;
        r.set_command_id(command_id);
        r.set_status(status);
        r.set_action(action);
        r.set_output(output);
        return r;
    }
    std::vector<AuditEvent> rows() {
        AuditQuery q;
        q.action = "registry.write";
        q.limit = 1000;
        auto r = audit->query(q);
        REQUIRE(r.has_value());
        return *r;
    }
};

} // namespace

TEST_CASE("registry audit live ingest: a RUNNING frame with output, then the empty terminal, gives ONE row",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());

    const std::string output = "audit|op=set_value|hive=HKLM|key=K|name=V|type=REG_DWORD|len=4|result=ok|reason=-|"
                               "verify=ok|dry_run=-|counted_keys=-|counted_values=-|capped=-|sid=-|old_state=absent|"
                               "old_type=-|old=-|new=01000000\nstatus|ok";
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-1700000000", apb::CommandResponse::RUNNING,
                                                                   "set_value", output));
    // The agent's terminal frame carries NO output.
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-1700000000", apb::CommandResponse::SUCCESS,
                                                                   "set_value", ""));
    const auto rows = h.rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].action == "registry.write");
    CHECK(rows[0].principal == "agent:agent-1");
    CHECK(rows[0].principal_role == "agent");
    CHECK(rows[0].target_type == "Command");
    CHECK(rows[0].target_id == "registry-1700000000");
    CHECK(rows[0].result == "success");
    CHECK(rows[0].detail.starts_with("audit|op=set_value|hive=HKLM|key=K|name=V|"));
    CHECK(rows[0].detail.ends_with(" agent=agent-1"));
    CHECK(rows[0].detail.find("status|ok") == std::string::npos); // only the audit line, not the output
}

TEST_CASE("registry audit live ingest: a refused write is a failure row; read actions and old agents write none",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    const std::string refused = line_with_result("refused", "1") + "\nerror|key_has_subkeys";

    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-5", apb::CommandResponse::RUNNING,
                                                                   "delete_key", refused));
    CHECK(h.rows().size() == 1);
    CHECK(h.rows()[0].result == "failure");

    // The same bytes under a READ action, an empty action (an agent that stamps none) and another plugin.
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-6", apb::CommandResponse::RUNNING,
                                                                   "get_value", refused));
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-7", apb::CommandResponse::RUNNING, "", refused));
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("filesystem-8", apb::CommandResponse::RUNNING,
                                                                   "delete_key", refused));
    CHECK(h.rows().size() == 1);
}

TEST_CASE("registry audit live ingest: a terminal frame that does carry output still owes its rows",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    h.svc.process_gateway_response("agent-2", IngestHarness::frame("registry-9", apb::CommandResponse::FAILURE,
                                                                   "delete_key", line_with_result("failed") + "\nerror|partial_failure"));
    const auto rows = h.rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].principal == "agent:agent-2");
    CHECK(rows[0].result == "failure");
}

TEST_CASE("registry audit live ingest: fan-out agents each get their own row for one command_id",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    for (const char* agent : {"agent-a", "agent-b", "agent-c"})
        h.svc.process_gateway_response(agent, IngestHarness::frame("registry-fan", apb::CommandResponse::RUNNING,
                                                                   "delete_value", std::string{kOkLine}));
    const auto rows = h.rows();
    CHECK(rows.size() == 3);
    std::vector<std::string> who;
    for (const auto& r : rows) who.push_back(r.principal);
    std::sort(who.begin(), who.end());
    CHECK(who == std::vector<std::string>{"agent:agent-a", "agent:agent-b", "agent:agent-c"});
}

TEST_CASE("registry audit live ingest: a store that fails ends the frame at the first row",
          "[pg][server][registry_audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    IngestHarness h(db.dsn());
    yuzu::test::SqlFault fault(h.pool, "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    const auto before = h.audit->emit_failed_count();
    const std::string one{kOkLine};
    const std::string three = one + "\n" + one + "\n" + one;
    h.svc.process_gateway_response("agent-1", IngestHarness::frame("registry-f1", apb::CommandResponse::RUNNING,
                                                                   "set_value", three));
    CHECK(h.audit->emit_failed_count() - before == 1); // the other two rows were not attempted
    fault.repair();
    CHECK(h.rows().empty());
}

// ── the direct Subscribe ingress (a live gRPC session) ───────────────────

namespace {

/// A live AgentServiceImpl over loopback with an AuthDB-backed enrolment, so an agent can Register
/// and Subscribe for real. `server` stops before `svc` is destroyed.
struct LiveHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::test::AuthDbPgShared auth_db;
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    yuzu::server::pg::PgPool pool;
    std::unique_ptr<AuditStore> audit;
    AgentServiceImpl svc{registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve, metrics,
                         /*gateway_mode=*/false};
    std::unique_ptr<grpc::Server> server;
    int port = 0;
    std::unique_ptr<apb::AgentService::Stub> stub;

    explicit LiveHarness(const std::string& dsn) : pool({.conninfo = dsn, .size = 4}) {
        auth_mgr.set_auth_db(auth_db.get());
        audit = std::make_unique<AuditStore>(pool);
        REQUIRE(audit->is_open());
        svc.set_audit_store(audit.get());
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&svc);
        server = builder.BuildAndStart();
        REQUIRE(server != nullptr);
        stub = apb::AgentService::NewStub(
            grpc::CreateChannel("127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials()));
    }
    ~LiveHarness() {
        if (server) server->Shutdown();
    }
};

} // namespace

namespace {

/// Registers `agent_id` on `h`, streams `frames` over a real Subscribe, drains it and returns whether the call
/// ended with the audit-failed trailer (a dropped row).
bool subscribe_with(LiveHarness& h, const std::string& agent_id, const std::vector<apb::CommandResponse>& frames) {
    const auto deadline = [] { return std::chrono::system_clock::now() + std::chrono::seconds(20); };
    auto token = h.auth_mgr.create_enrollment_token("registry-audit", 0, std::chrono::hours(1), "test-admin");
    REQUIRE(token.has_value());
    apb::RegisterRequest reg;
    reg.mutable_info()->set_agent_id(agent_id);
    reg.mutable_info()->set_hostname("host");
    reg.mutable_info()->mutable_platform()->set_os("windows");
    reg.mutable_info()->mutable_platform()->set_arch("x86_64");
    reg.set_enrollment_token(token->raw_token);
    apb::RegisterResponse reg_resp;
    grpc::ClientContext reg_ctx;
    reg_ctx.set_deadline(deadline());
    REQUIRE(h.stub->Register(&reg_ctx, reg, &reg_resp).ok());
    REQUIRE(reg_resp.accepted());

    grpc::ClientContext ctx;
    ctx.set_deadline(deadline());
    ctx.AddMetadata(std::string{AgentServiceImpl::kSessionMetadataKey}, reg_resp.session_id());
    auto stream = h.stub->Subscribe(&ctx);
    REQUIRE(stream != nullptr);
    for (const auto& f : frames) REQUIRE(stream->Write(f));
    REQUIRE(stream->WritesDone());
    apb::CommandRequest unused;
    while (stream->Read(&unused)) {
    }
    CHECK(stream->Finish().ok()); // the handler read every frame before it returned
    return ctx.GetServerTrailingMetadata().count(std::string{yuzu::server::kGrpcAuditFailedKey}) > 0;
}

} // namespace

TEST_CASE("registry audit live ingest: a real Subscribe session audits RUNNING output, not the empty "
          "terminal, and only for mutating actions",
          "[pg][server][registry_audit][subscribe]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    LiveHarness h(db.dsn());
    const std::string refused = line_with_result("refused", "0");
    CHECK_FALSE(subscribe_with(
        h, "agent-live",
        {IngestHarness::frame("registry-s1", apb::CommandResponse::RUNNING, "set_value", std::string{kOkLine} + "\nstatus|ok"),
         IngestHarness::frame("registry-s1", apb::CommandResponse::SUCCESS, "set_value", ""),
         IngestHarness::frame("registry-s2", apb::CommandResponse::RUNNING, "get_value", refused),
         IngestHarness::frame("registry-s3", apb::CommandResponse::RUNNING, "", refused),
         IngestHarness::frame("registry-s4", apb::CommandResponse::FAILURE, "delete_key", line_with_result("failed"))}));

    AuditQuery q;
    q.action = "registry.write";
    auto rows = h.audit->query(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    std::sort(rows->begin(), rows->end(), [](const auto& a, const auto& b) { return a.target_id < b.target_id; });
    CHECK((*rows)[0].target_id == "registry-s1");
    CHECK((*rows)[0].principal == "agent:agent-live");
    CHECK((*rows)[0].result == "success");
    CHECK((*rows)[1].target_id == "registry-s4");
    CHECK((*rows)[1].result == "failure");
}

TEST_CASE("registry audit live ingest: a dropped row sets the audit-failed trailer on the Subscribe call, and "
          "only a frame that owed a row does",
          "[pg][server][registry_audit][subscribe]") {
    YUZU_REQUIRE_PG_DB_TPL(db, registry_audit_tpl);
    LiveHarness h(db.dsn());
    yuzu::test::SqlFault fault(h.pool, "ALTER TABLE audit_store.audit_events RENAME TO audit_events_gone",
                               "ALTER TABLE audit_store.audit_events_gone RENAME TO audit_events");
    fault.arm();
    // A READ action's output owes no row, so a store that is down is not touched and the trailer stays absent ...
    CHECK_FALSE(subscribe_with(h, "agent-r", {IngestHarness::frame("registry-t1", apb::CommandResponse::RUNNING,
                                                                  "get_value", std::string{kOkLine})}));
    // ... a mutating action's row cannot be written: the trailer tells the operator the evidence chain has a gap.
    CHECK(subscribe_with(h, "agent-w", {IngestHarness::frame("registry-t2", apb::CommandResponse::RUNNING,
                                                            "set_value", std::string{kOkLine})}));
    // ... and the same holds for a TERMINAL frame.
    CHECK(subscribe_with(h, "agent-t", {IngestHarness::frame("registry-t3", apb::CommandResponse::FAILURE,
                                                            "delete_key", std::string{kOkLine})}));
    fault.repair();
}
