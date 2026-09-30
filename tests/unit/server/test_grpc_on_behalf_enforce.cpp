// End-to-end coverage for the gRPC on-behalf-of guard (ADR-1005 Interim
// rules, execution-plan PR 1.1) — closes the gap flagged in the adversarial
// review of PR #1972 (HIGH ①): a real grpc::Server, with the real
// OnBehalfRejectInterceptor wired exactly as server.cpp wires it, receiving
// a real Register call carrying a reserved metadata key.
//
// test_on_behalf_guard.cpp already pins the reserved-key parsing/matching
// logic in isolation. This file is the missing end-to-end half: it proves
// the interceptor's TryCancel() and the handler-side
// grpc_on_behalf_enforce.hpp check actually pair up over the wire to (a)
// return CANCELLED to the client and (b) leave NO side effect committed —
// the exact property TryCancel() alone cannot guarantee (see
// grpc_on_behalf_interceptor.hpp's doc comment).

#include "agent_service_impl.hpp"
#include "grpc_on_behalf_interceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "on_behalf_guard.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::OnBehalfRejectInterceptorFactory;

namespace {

namespace apb = ::yuzu::agent::v1;

// Real grpc::Server, wired identically to server.cpp's agent listener: one
// interceptor on the one ServerBuilder, insecure creds + an ephemeral
// loopback port (test-only — production always uses mTLS/TLS creds).
// MEMBER ORDER LOAD-BEARING (mirrors GatewayResponseHarness in
// test_agent_service_impl.cpp): `svc` borrows references into `registry`/
// `bus`/`auth_mgr`/`auto_approve`, all declared earlier so they outlive it;
// `server_` (built from `svc`) must stop before `svc` destructs, done
// explicitly in the destructor rather than relying on member order alone,
// since grpc::Server's own dtor does not know about `svc`'s lifetime.
struct LiveInterceptorHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    std::unique_ptr<grpc::Server> server_;
    int port_ = 0;
    std::unique_ptr<apb::AgentService::Stub> stub_;

    LiveInterceptorHarness() {
        grpc::ServerBuilder builder;
        {
            std::vector<std::unique_ptr<grpc::experimental::ServerInterceptorFactoryInterface>>
                interceptor_factories;
            interceptor_factories.push_back(
                std::make_unique<OnBehalfRejectInterceptorFactory>(&metrics));
            builder.experimental().SetInterceptorCreators(std::move(interceptor_factories));
        }
        // Port 0 -> OS assigns an ephemeral free port, captured via the
        // out-parameter — avoids fixed-port flakiness under parallel tests.
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
        builder.RegisterService(&svc);
        server_ = builder.BuildAndStart();
        REQUIRE(server_ != nullptr);
        REQUIRE(port_ != 0);

        auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port_),
                                           grpc::InsecureChannelCredentials());
        stub_ = apb::AgentService::NewStub(channel);
    }

    ~LiveInterceptorHarness() {
        if (server_) server_->Shutdown();
    }
};

}  // namespace

TEST_CASE("Register carrying a reserved on-behalf-of key is CANCELLED and commits no side effect",
          "[grpc][onbehalf][adr1005]") {
    LiveInterceptorHarness h;
    REQUIRE(h.registry.agent_count() == 0);

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("test-agent-onbehalf-reject");
    req.mutable_info()->set_hostname("test-host");

    grpc::ClientContext ctx;
    // A regression in the guard would hang this call rather than fail it
    // fast (see cpp-safety/unhappy-path Gate 4) — bound it so CI reports an
    // attributable failure, not a whole-suite timeout.
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    ctx.AddMetadata("x-yuzu-on-behalf-of", "alice");
    apb::RegisterResponse resp;

    auto status = h.stub_->Register(&ctx, req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::CANCELLED);

    // The property TryCancel() alone cannot guarantee: no side effect
    // committed. If the handler had run to completion (the pre-fix bug),
    // registry_.register_agent() would have fired despite the client
    // observing CANCELLED.
    CHECK(h.registry.agent_count() == 0);
}

TEST_CASE("every reserved on-behalf-of key is rejected over the real wire, not just one",
          "[grpc][onbehalf][adr1005]") {
    // Unhappy-path Gate 4 (UP-4): the interceptor and onbehalf::enforce() are
    // coupled only by both calling the same find_reserved_key() — sound
    // today, but nothing stops a future edit from forking one path. This is
    // the strongest coupling proof available: since grpc::ServerContext's
    // client_metadata() can't be constructed outside a live call,
    // demonstrating agreement means exercising the REAL wire path (both the
    // interceptor's TryCancel and the handler's enforce()) for every key in
    // kReservedKeys, not just the one key the tests above happen to use —
    // test_on_behalf_guard.cpp already pins the parsing half in isolation.
    for (auto key : yuzu::server::onbehalf::kReservedKeys) {
        LiveInterceptorHarness h;

        apb::RegisterRequest req;
        req.mutable_info()->set_agent_id("test-agent-onbehalf-" + std::string(key));
        req.mutable_info()->set_hostname("test-host");

        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        ctx.AddMetadata(std::string(key), "alice");
        apb::RegisterResponse resp;

        auto status = h.stub_->Register(&ctx, req, &resp);

        INFO("reserved key under test: " << key);
        CHECK(status.error_code() == grpc::StatusCode::CANCELLED);
        CHECK(h.registry.agent_count() == 0);
    }
}

TEST_CASE("Register with no reserved key proceeds normally through the same interceptor",
          "[grpc][onbehalf][adr1005]") {
    LiveInterceptorHarness h;

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("test-agent-onbehalf-clean");
    req.mutable_info()->set_hostname("test-host");

    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    ctx.AddMetadata("authorization", "Bearer irrelevant-here");
    apb::RegisterResponse resp;

    auto status = h.stub_->Register(&ctx, req, &resp);

    // A clean call is unaffected by the interceptor — proves the guard is
    // discriminating (reserved keys only), not blocking everything. This
    // harness wires NO AuthDB, so since WS-6 6.2 (enrollment state is
    // AuthDB-only and fails CLOSED) the handler that the interceptor let through
    // answers UNAVAILABLE at the enrollment-status read — proof the handler RAN
    // (a blocked call would be CANCELLED), and that a missing store never reads
    // as "accepted=false".
    CHECK(status.error_code() == grpc::StatusCode::UNAVAILABLE);
    CHECK(status.error_code() != grpc::StatusCode::CANCELLED);
}

TEST_CASE("Subscribe (bidi stream) carrying a reserved on-behalf-of key is rejected at stream-open",
          "[grpc][onbehalf][adr1005]") {
    // cpp-safety Gate 3 finding: Register's unary coverage doesn't prove the
    // guard works identically for a streaming RPC — Subscribe is the
    // "command-result handler" the execution plan's PR 1.1 rationale singles
    // out by name, and its guard placement (right after the null-context
    // check, before any session/registry work) differs structurally from the
    // unary handlers'.
    LiveInterceptorHarness h;

    grpc::ClientContext ctx;
    // Unhappy-path Gate 4: a regression here would hang Read()/Finish()
    // rather than fail fast — this is the streaming case where that risk is
    // highest (an unbounded blocking read on an open stream).
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    ctx.AddMetadata("x-yuzu-on-behalf-of", "alice");

    auto stream = h.stub_->Subscribe(&ctx);
    REQUIRE(stream != nullptr);

    // The rejection happens at stream-open (interceptor's
    // POST_RECV_INITIAL_METADATA hook, before any message exchange), so the
    // very first Read() must observe the stream already closed.
    apb::CommandRequest ignored;
    CHECK_FALSE(stream->Read(&ignored));

    auto status = stream->Finish();
    CHECK(status.error_code() == grpc::StatusCode::CANCELLED);
}
