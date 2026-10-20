/**
 * Pins what Agent::run() does with Config::enrollment_token_file around Register:
 * an accepted registration removes the file, a hard-rejected one leaves it alone, a
 * pending one keeps it until a later accepted registration, and a removal that fails
 * is retried after the next accepted registration rather than given up on.
 *
 * main() is never linked into a test target, so this is the only test that reaches
 * the removal in agent.cpp. Deleting or moving that block would otherwise keep every
 * other test green, and the token file would outlive the registration it was for.
 *
 * Same shape as test_agent_ota_disabled_lifecycle.cpp: a real Agent::run() against a
 * test-local gRPC service on an ephemeral loopback port, destroyed with the test.
 * POSIX only, as that test is. Each case runs the agent's own cloud-identity probe
 * (bounded at 2 s per provider), exactly as the OTA lifecycle test does; there is no
 * switch to skip it. No sleeps and no filesystem polling: the cases wait on the
 * stub's condition variable for the agent's Subscribe, which Agent::run() opens
 * strictly after the removal block, so observing a Subscribe is observing the
 * post-removal state. The retry case does wait out the agent's own reconnect backoff
 * (2 s per retry, counted by the agent, not by the test).
 */

#ifndef _WIN32

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/subprocess_runner.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "test_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace apb = yuzu::agent::v1;

namespace {

// One scripted answer to a Register call.
struct Answer {
    bool accepted{true};
    std::string reject_reason;

    static Answer accept() { return {true, {}}; }
    static Answer reject(std::string reason) { return {false, std::move(reason)}; }
};

class RegisterStub final : public apb::AgentService::Service {
public:
    // `script[i]` answers Register call i+1; calls past the end repeat the last
    // answer. `on_register(call)` runs inside that call, before the answer goes out:
    // the agent is blocked on this very reply, so anything the hook changes on disk
    // is settled before the agent reacts to the answer. With `first_subscribe_ends`
    // the first Subscribe returns at once, which the agent treats as a lost
    // connection: it backs off and registers again.
    explicit RegisterStub(std::vector<Answer> script, std::function<void(int)> on_register = {},
                          bool first_subscribe_ends = false)
        : script_(std::move(script)), on_register_(std::move(on_register)),
          first_subscribe_ends_(first_subscribe_ends) {}

    grpc::Status Register(grpc::ServerContext*, const apb::RegisterRequest*,
                          apb::RegisterResponse* response) override {
        int call = 0;
        {
            std::lock_guard lock(mu);
            call = ++registrations;
        }
        if (on_register_)
            on_register_(call);
        const auto& answer = script_[std::min<std::size_t>(call, script_.size()) - 1];
        response->set_accepted(answer.accepted);
        if (answer.accepted)
            response->set_session_id("enrollment-token-file-session");
        else
            response->set_reject_reason(answer.reject_reason);
        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext*,
        grpc::ServerReaderWriter<apb::CommandRequest, apb::CommandResponse>* stream) override {
        int subscription = 0;
        {
            std::lock_guard lock(mu);
            subscription = ++subscriptions;
        }
        cv.notify_all();
        if (subscription == 1 && first_subscribe_ends_)
            return grpc::Status::OK;
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

    bool wait_for_subscribe(int count = 1) {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, std::chrono::seconds(30),
                           [this, count] { return subscriptions >= count; });
    }

    int registration_count() const {
        std::lock_guard lock(mu);
        return registrations;
    }

private:
    const std::vector<Answer> script_;
    const std::function<void(int)> on_register_;
    const bool first_subscribe_ends_;
    mutable std::mutex mu;
    std::condition_variable cv;
    int registrations{0};
    int subscriptions{0};
};

struct LoopbackHarness {
    RegisterStub service;
    std::unique_ptr<grpc::Server> server;
    int port{0};

    explicit LoopbackHarness(std::vector<Answer> script, std::function<void(int)> on_register = {},
                             bool first_subscribe_ends = false)
        : service(std::move(script), std::move(on_register), first_subscribe_ends) {
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
    LoopbackHarness harness{{Answer::accept()}};
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
    LoopbackHarness harness{{Answer::reject("test: registration rejected")}};
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

// A pending answer keeps the file, and a removal that fails is retried after the next
// accepted registration. One scripted run covers both, so the agent's reconnect
// backoff is paid once rather than per case:
//   Register 1  rejected as pending approval -> the agent backs off and registers again
//   Register 2  the file must still be there; the stub then swaps it for a NON-EMPTY
//               directory, which remove() refuses on every platform and for every user
//               (no permission setup, so it behaves the same as root in CI), and accepts
//   Subscribe 1 returns at once -> the agent treats it as a lost connection, backs off
//   Register 3  the stub swaps the directory back for a regular token file and accepts
//   Subscribe 2 is opened after the removal block, so the file's fate is decided
// What each assertion catches:
//   exists at Register 2    a pending answer that falls through into the removal
//   Register 2 never comes  a pending `continue` turned into a `return` (the 30 s wait fails)
//   directory at Register 3 a removal that deletes more than the one file it was given
//   file gone at the end    the path cleared after a FAILED removal (no second attempt)
TEST_CASE("a pending registration keeps the enrollment token file and a failed removal is retried",
          "[agent][enrollment][enrollment_token_file][grpc]") {
    TokenFileFixture fixture;
    std::atomic<bool> existed_at_second_register{false};
    std::atomic<bool> directory_at_third_register{false};

    const auto on_register = [&](int call) {
        // Error-code overloads only: an exception must not escape a gRPC handler.
        std::error_code ec;
        if (call == 2) {
            existed_at_second_register = fs::is_regular_file(fixture.token_file, ec);
            fs::remove(fixture.token_file, ec);
            fs::create_directories(fixture.token_file, ec);
            std::ofstream(fixture.token_file / "keep", std::ios::binary) << "keep";
        } else if (call == 3) {
            directory_at_third_register = fs::is_directory(fixture.token_file, ec);
            fs::remove_all(fixture.token_file, ec);
            std::ofstream(fixture.token_file, std::ios::binary) << fixture.token << '\n';
        }
    };
    LoopbackHarness harness{{Answer::reject("test: pending approval"), Answer::accept()},
                            on_register, /*first_subscribe_ends=*/true};
    REQUIRE(harness.server);
    REQUIRE(harness.port != 0);

    auto agent = yuzu::agent::Agent::create(fixture.config(harness.port));
    REQUIRE(agent);
    {
        const AgentThread runner{*agent};
        REQUIRE(harness.service.wait_for_subscribe(2));
        CHECK(harness.service.registration_count() == 3);
        CHECK(existed_at_second_register.load());
        CHECK(directory_at_third_register.load());
        CHECK_FALSE(fs::exists(fixture.token_file));
    }
}

#endif
