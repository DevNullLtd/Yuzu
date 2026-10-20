/**
 * Pins what Agent::run() does with Config::enrollment_token_file around Register:
 * an accepted registration removes the file, a hard-rejected one leaves it alone.
 *
 * main() is never linked into a test target, so this is the only test that reaches
 * the removal in agent.cpp. Deleting or moving that block would otherwise keep every
 * other test green, and the token file would outlive the registration it was for.
 *
 * Same shape as test_agent_ota_disabled_lifecycle.cpp: a real Agent::run() against a
 * test-local gRPC service on an ephemeral loopback port, destroyed with the test.
 * POSIX only, as that test is. Each case runs the agent's own cloud-identity probe
 * (bounded at 2 s per provider), exactly as the OTA lifecycle test does; there is no
 * switch to skip it. No sleeps: the accepted case waits on the stub's condition
 * variable for the agent's first Subscribe, which Agent::run() opens strictly after
 * the removal block, so observing the Subscribe is observing the post-removal state.
 * The pending-then-accepted path needs the agent's backoff timer and is not covered.
 */

#ifndef _WIN32

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/subprocess_runner.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "test_helpers.hpp"

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace fs = std::filesystem;
namespace apb = yuzu::agent::v1;

namespace {

class RegisterStub final : public apb::AgentService::Service {
public:
    explicit RegisterStub(bool accept) : accept_(accept) {}

    grpc::Status Register(grpc::ServerContext*, const apb::RegisterRequest*,
                          apb::RegisterResponse* response) override {
        {
            std::lock_guard lock(mu);
            ++registrations;
        }
        if (accept_) {
            response->set_accepted(true);
            response->set_session_id("enrollment-token-file-session");
        } else {
            response->set_accepted(false);
            response->set_reject_reason("test: registration rejected");
        }
        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext*,
        grpc::ServerReaderWriter<apb::CommandRequest, apb::CommandResponse>* stream) override {
        {
            std::lock_guard lock(mu);
            ++subscriptions;
        }
        cv.notify_all();
        // Read() returns false once the agent's stop() cancels the stream.
        apb::CommandResponse ignored;
        while (stream->Read(&ignored)) {}
        return grpc::Status::OK;
    }

    grpc::Status Heartbeat(grpc::ServerContext*, const apb::HeartbeatRequest*,
                           apb::HeartbeatResponse* response) override {
        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

    bool wait_for_subscribe() {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, std::chrono::seconds(30), [this] { return subscriptions >= 1; });
    }

    int registration_count() const {
        std::lock_guard lock(mu);
        return registrations;
    }

private:
    const bool accept_;
    mutable std::mutex mu;
    std::condition_variable cv;
    int registrations{0};
    int subscriptions{0};
};

struct LoopbackHarness {
    RegisterStub service;
    std::unique_ptr<grpc::Server> server;
    int port{0};

    explicit LoopbackHarness(bool accept) : service(accept) {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&service);
        server = builder.BuildAndStart();
    }

    ~LoopbackHarness() {
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
            server->Wait();
        }
    }
};

// Runs Agent::run() on a thread; `finished` becomes ready when run() returns.
struct AgentThread {
    yuzu::agent::Agent& agent;
    const bool previous_subprocess_cancel{yuzu::agent::subprocess_cancel_requested()};
    std::promise<void> returned;
    std::future<void> finished{returned.get_future()};
    std::thread thread;

    explicit AgentThread(yuzu::agent::Agent& running_agent)
        : agent{running_agent}, thread{[this] {
              agent.run();
              returned.set_value();
          }} {}

    AgentThread(const AgentThread&) = delete;
    AgentThread& operator=(const AgentThread&) = delete;

    ~AgentThread() {
        agent.stop();
        thread.join();
        // Agent::stop requests process-wide cancellation; restore it only after
        // every agent worker has joined so later Catch2 cases stay isolated.
        yuzu::agent::request_subprocess_cancel(previous_subprocess_cancel);
    }
};

struct TokenFileFixture {
    yuzu::test::TempDir temp{"yuzu_test_enroll_token_lifecycle_"};
    fs::path token_file;
    std::string token{std::string(64, 'a')};

    TokenFileFixture() {
        fs::create_directories(temp.path / "plugins");
        fs::create_directories(temp.path / "data");
        token_file = temp.path / "enrollment-token";
        std::ofstream(token_file, std::ios::binary) << token << '\n';
    }

    yuzu::agent::Config config(int port) const {
        yuzu::agent::Config c;
        c.server_address = "127.0.0.1:" + std::to_string(port);
        c.agent_id = "enrollment-token-file-lifecycle-agent";
        c.plugin_dir = temp.path / "plugins";
        c.data_dir = temp.path / "data";
        c.tls_enabled = false;
        c.auto_provision_cert = false;
        c.auto_update = false;
        c.heartbeat_interval = std::chrono::seconds(1);
        c.inventory_disable = true;
        c.dex_disable = true;
        c.spark_disable = true;
        // What main() leaves behind after it read a token from the file.
        c.enrollment_token = token;
        c.enrollment_token_file = token_file;
        return c;
    }
};

} // namespace

TEST_CASE("an accepted registration removes the enrollment token file",
          "[agent][enrollment][enrollment_token_file][grpc]") {
    LoopbackHarness harness{true};
    REQUIRE(harness.server);
    REQUIRE(harness.port != 0);
    TokenFileFixture fixture;
    REQUIRE(fs::exists(fixture.token_file));

    auto agent = yuzu::agent::Agent::create(fixture.config(harness.port));
    REQUIRE(agent);
    {
        const AgentThread runner{*agent};
        // Subscribe is opened after the removal, so once the stub has seen it the
        // file's fate is decided -- no sleep, no polling of the filesystem.
        REQUIRE(harness.service.wait_for_subscribe());
        CHECK(harness.service.registration_count() == 1);
        CHECK_FALSE(fs::exists(fixture.token_file));
    }
}

TEST_CASE("a hard-rejected registration leaves the enrollment token file in place",
          "[agent][enrollment][enrollment_token_file][grpc]") {
    LoopbackHarness harness{false};
    REQUIRE(harness.server);
    REQUIRE(harness.port != 0);
    TokenFileFixture fixture;

    auto agent = yuzu::agent::Agent::create(fixture.config(harness.port));
    REQUIRE(agent);
    {
        AgentThread runner{*agent};
        // A permanent rejection makes run() return on its own.
        REQUIRE(runner.finished.wait_for(std::chrono::seconds(30)) ==
                std::future_status::ready);
        CHECK(harness.service.registration_count() == 1);
        CHECK(fs::exists(fixture.token_file));
    }
    CHECK(fs::exists(fixture.token_file));
}

#endif
