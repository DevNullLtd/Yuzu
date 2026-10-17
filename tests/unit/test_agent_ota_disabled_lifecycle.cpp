/**
 * Drives Agent::run() through its real registration and Subscribe reconnect
 * loop.  The test-local gRPC service is deliberately not an installed service:
 * it binds an ephemeral loopback port and is destroyed with this test.
 */

#ifndef _WIN32

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/agent/updater.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "test_helpers.hpp"

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace apb = yuzu::agent::v1;

namespace {

class OtaDisabledLifecycleService final : public apb::AgentService::Service {
public:
    grpc::Status Register(grpc::ServerContext*, const apb::RegisterRequest*,
                          apb::RegisterResponse* response) override {
        int registration = 0;
        {
            std::lock_guard lock(mu);
            registration = ++registrations;
        }
        response->set_accepted(true);
        response->set_session_id("ota-disabled-session-" + std::to_string(registration));
        cv.notify_all();
        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<apb::CommandRequest, apb::CommandResponse>* stream) override {
        int subscription = 0;
        {
            std::lock_guard lock(mu);
            subscription = ++subscriptions;
        }
        cv.notify_all();
        if (subscription == 1) {
            apb::CommandRequest command;
            command.set_command_id("ota-disabled-first-command");
            command.set_plugin("missing_test_plugin");
            command.set_action("first-command");
            if (!stream->Write(command))
                return grpc::Status::CANCELLED;
            apb::CommandResponse response;
            if (!stream->Read(&response))
                return grpc::Status::CANCELLED;
            if (response.command_id() != command.command_id() ||
                response.status() != apb::CommandResponse::REJECTED)
                return grpc::Status{grpc::StatusCode::FAILED_PRECONDITION,
                                    "unexpected first-command response"};
            {
                std::lock_guard lock(mu);
                first_command_rejected = true;
            }
            cv.notify_all();
            // A server-streaming handler stays alive until the agent's
            // session-loss path cancels its client context below.
            while (!context->IsCancelled())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return grpc::Status::CANCELLED;
        }

        apb::CommandResponse ignored;
        while (!context->IsCancelled() && stream->Read(&ignored)) {}
        return grpc::Status::OK;
    }

    grpc::Status CheckForUpdate(grpc::ServerContext*, const apb::CheckForUpdateRequest*,
                                apb::CheckForUpdateResponse*) override {
        {
            std::lock_guard lock(mu);
            ++update_checks;
        }
        cv.notify_all();
        return grpc::Status::OK;
    }

    grpc::Status Heartbeat(grpc::ServerContext*, const apb::HeartbeatRequest*,
                           apb::HeartbeatResponse* response) override {
        // The agent turns NOT_FOUND into a Subscribe cancellation and a fresh
        // Register. Only emit it after the first command was delivered.
        std::lock_guard lock(mu);
        if (first_command_rejected)
            return grpc::Status{grpc::StatusCode::NOT_FOUND, "test session expired"};
        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

    bool wait_for_second_registration() {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, std::chrono::seconds(15), [this] {
            return registrations >= 2 && subscriptions >= 2 && first_command_rejected;
        });
    }

    int registration_count() const {
        std::lock_guard lock(mu);
        return registrations;
    }

    int subscription_count() const {
        std::lock_guard lock(mu);
        return subscriptions;
    }

    int update_check_count() const {
        std::lock_guard lock(mu);
        return update_checks;
    }

    bool first_command_was_rejected() const {
        std::lock_guard lock(mu);
        return first_command_rejected;
    }

private:
    mutable std::mutex mu;
    std::condition_variable cv;
    int registrations{0};
    int subscriptions{0};
    int update_checks{0};
    bool first_command_rejected{false};
};

struct LoopbackHarness {
    OtaDisabledLifecycleService service;
    std::unique_ptr<grpc::Server> server;
    int port{0};

    LoopbackHarness() {
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

struct AgentRunner {
    yuzu::agent::Agent& agent;
    const bool previous_subprocess_cancel{yuzu::agent::subprocess_cancel_requested()};
    std::thread thread;

    explicit AgentRunner(yuzu::agent::Agent& running_agent)
        : agent{running_agent}, thread{[agent_ptr = &running_agent] { agent_ptr->run(); }} {}

    AgentRunner(const AgentRunner&) = delete;
    AgentRunner& operator=(const AgentRunner&) = delete;

    ~AgentRunner() {
        agent.stop();
        thread.join();
        // Agent::stop requests process-wide cancellation. Restore only after
        // every agent worker has joined so later Catch2 cases remain isolated.
        yuzu::agent::request_subprocess_cancel(previous_subprocess_cancel);
    }
};

std::vector<char> read_bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error{"could not open test sidecar for reading: " + path.string()};
    std::vector<char> contents{std::istreambuf_iterator<char>{input},
                               std::istreambuf_iterator<char>{}};
    if (input.bad())
        throw std::runtime_error{"could not read test sidecar completely: " + path.string()};
    return contents;
}

void write_bytes(const fs::path& path, const std::vector<char>& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
        throw std::runtime_error{"could not open test sidecar for writing: " + path.string()};
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close(); // Detect buffered flush/close failures before claiming restoration.
    if (!output)
        throw std::runtime_error{"could not write test sidecar completely: " + path.string()};
}

struct FileBackup {
    fs::path path;
    bool existed{false};
    fs::path backup_directory;
    fs::path backup;
    bool restored{false};

    explicit FileBackup(fs::path input)
        : path(std::move(input)), existed(fs::exists(fs::symlink_status(path))) {
        if (!existed)
            return;
        if (!fs::is_regular_file(fs::symlink_status(path)))
            throw std::runtime_error{"refusing non-regular test sidecar: " + path.string()};
        backup_directory = path.parent_path() /
                           yuzu::test::unique_temp_path("yuzu_test_sidecar_backup_").filename();
        if (!fs::create_directory(backup_directory))
            throw std::runtime_error{"test sidecar backup directory already exists"};
        try {
            fs::permissions(backup_directory, fs::perms::owner_all);
            backup = backup_directory / "original";
            fs::copy_file(path, backup); // Preserve originals on disk before any truncating write.
        } catch (...) {
            std::error_code ignored;
            fs::remove_all(backup_directory, ignored);
            throw;
        }
    }

    FileBackup(const FileBackup&) = delete;
    FileBackup& operator=(const FileBackup&) = delete;

    void restore() {
        if (restored)
            return;
        if (existed) {
            fs::rename(backup,
                       path); // Same-filesystem atomic replacement, no rewrite/flush window.
            restored = true;
            fs::remove(backup_directory);
            return;
        }
        std::error_code error;
        fs::remove(path, error);
        if (error)
            throw std::runtime_error{"could not remove test sidecar: " + path.string()};
        restored = true;
    }

    ~FileBackup() {
        try {
            restore();
        } catch (...) {
            std::terminate();
        }
    }
};

struct ExecutableSidecarLock {
    int fd{-1};

    explicit ExecutableSidecarLock(const fs::path& executable) {
        const auto path = executable.parent_path() / ".yuzu_agent_ota_sidecar_test.lock";
        fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd >= 0 && ::flock(fd, LOCK_EX) != 0) {
            (void)::close(fd);
            fd = -1;
        }
    }

    ExecutableSidecarLock(const ExecutableSidecarLock&) = delete;
    ExecutableSidecarLock& operator=(const ExecutableSidecarLock&) = delete;

    ~ExecutableSidecarLock() {
        if (fd >= 0) {
            (void)::flock(fd, LOCK_UN);
            (void)::close(fd);
        }
    }

    [[nodiscard]] bool locked() const noexcept { return fd >= 0; }
};

static_assert(!std::is_copy_constructible_v<FileBackup>);
static_assert(!std::is_copy_constructible_v<ExecutableSidecarLock>);

} // namespace

TEST_CASE("OTA sidecar backup retains originals when restoration fails",
          "[agent][updater][no-auto-update]") {
    yuzu::test::TempDir temp{"yuzu_test_sidecar_restore_"};
    fs::create_directories(temp.path);
    const auto path = temp.path / "sidecar";
    const std::vector<char> original{'o', 'l', 'd'};
    write_bytes(path, original);
    FileBackup backup{path};
    write_bytes(path, {'n', 'e', 'w'});
    fs::remove(path);
    fs::create_directory(path); // Force rename failure without changing process-wide limits.
    CHECK_THROWS(backup.restore());
    CHECK(read_bytes(backup.backup) == original);
    fs::remove(path);
    backup.restore();
    CHECK(read_bytes(path) == original);
    CHECK_FALSE(fs::exists(backup.backup_directory));
    backup.restore(); // Explicit restoration and destructor are idempotent.
}

TEST_CASE("disabled OTA survives registration, first command, and reconnect without update RPC",
          "[agent][updater][no-auto-update][grpc]") {
    LoopbackHarness harness;
    REQUIRE(harness.server);
    REQUIRE(harness.port != 0);

    yuzu::test::TempDir temp{"yuzu_test_ota_disabled_lifecycle-"};
    const auto plugin_dir = temp.path / "plugins";
    const auto data_dir = temp.path / "data";
    REQUIRE(fs::create_directories(plugin_dir));
    REQUIRE(fs::create_directories(data_dir));

    yuzu::agent::Config config;
    config.server_address = "127.0.0.1:" + std::to_string(harness.port);
    config.agent_id = "ota-disabled-lifecycle-agent";
    config.plugin_dir = plugin_dir;
    config.data_dir = data_dir;
    config.tls_enabled = false;
    config.auto_provision_cert = false;
    config.auto_update = false;
    config.heartbeat_interval = std::chrono::seconds(1);
    config.inventory_disable = true;
    config.dex_disable = true;
    config.spark_disable = true;

    // Agent::run() calls current_executable_path(), so seed sidecars beside the
    // actual test executable, not a synthetic updater path. A flock serializes
    // this exceptional fixed-path probe across shared-identity test processes.
    // FileBackup restores any pre-existing build artifact on assertion exit.
    const auto executable = yuzu::agent::current_executable_path();
    const ExecutableSidecarLock sidecar_lock{executable};
    REQUIRE(sidecar_lock.locked());
    const auto old_binary = fs::path{executable.string() + ".old"};
    const auto verified_marker = executable.parent_path() / ".yuzu-update-verified";
    FileBackup old_backup{old_binary};
    FileBackup marker_backup{verified_marker};
    const std::vector<char> old_sentinel{'o', 'l', 'd', '-', 's', 'e',
                                         'n', 't', 'i', 'n', 'e', 'l'};
    const std::vector<char> marker_sentinel{'m', 'a', 'r', 'k', 'e', 'r', '-', 's',
                                            'e', 'n', 't', 'i', 'n', 'e', 'l'};
    write_bytes(old_binary, old_sentinel);
    write_bytes(verified_marker, marker_sentinel);

    auto agent = yuzu::agent::Agent::create(std::move(config));
    REQUIRE(agent);
    const bool previous_cancel = yuzu::agent::subprocess_cancel_requested();
    {
        const AgentRunner runner{*agent};

        const bool completed = harness.service.wait_for_second_registration();

        REQUIRE(completed);
        CHECK(harness.service.registration_count() >= 2);
        CHECK(harness.service.subscription_count() >= 2);
        CHECK(harness.service.first_command_was_rejected());
        CHECK(harness.service.update_check_count() == 0);
        CHECK(read_bytes(old_binary) == old_sentinel);
        CHECK(read_bytes(verified_marker) == marker_sentinel);
    }
    CHECK(yuzu::agent::subprocess_cancel_requested() == previous_cancel);
    old_backup.restore();
    marker_backup.restore();
}

#endif
