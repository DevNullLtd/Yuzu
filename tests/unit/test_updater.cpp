/**
 * test_updater.cpp — Unit tests for the agent-side OTA updater utilities
 *
 * Covers: current_executable_path(), cleanup_old_binary(),
 *         rollback_if_needed(), Updater construction.
 */

#include <yuzu/agent/updater.hpp>

#include "ota_update_thread.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <future>
#include <memory>
#include <string>
#include <thread>

using namespace yuzu::agent;
namespace fs = std::filesystem;

namespace {

/// RAII per-test scratch dir, process-salted via yuzu::test::TempDir. The
/// previous fixed `yuzu_test_updater_<suffix>` dirs were cross-JOB shared
/// resources on the shared-identity CI pools: one job's cleanup remove_all
/// deleted another's just-written fixtures, and a leftover marker file could
/// flip rollback_if_needed()'s result (#1883). RAII also removes the dir when
/// a REQUIRE fails (the old trailing cleanup_dir call was skipped). The
/// suffix keeps the yuzu_test_updater_* naming inside the Defender exclusion
/// wildcard.
struct TempUpdaterDir {
    yuzu::test::TempDir guard;
    explicit TempUpdaterDir(const std::string& suffix)
        : guard("yuzu_test_updater_" + suffix + "-") {
        std::error_code ec;
        fs::create_directories(guard.path, ec);
        // A silently-failed creation (full temp volume, ACL) would hollow out
        // the negative-assertion rollback tests into no-op passes (gov safe-2).
        REQUIRE(fs::exists(guard.path));
    }
};

/// Helper: write a small file to simulate a binary.
void write_fake_binary(const fs::path& path) {
    {
        std::ofstream out(path, std::ios::binary);
        out << "fake-binary-content";
    }
    // As the updater writes binaries: owner-only, whatever the test's umask.
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace, ec);
}

} // anonymous namespace

// ── current_executable_path ─────────────────────────────────────────────────

TEST_CASE("current_executable_path returns non-empty path", "[updater][exe_path]") {
    auto path = current_executable_path();
    REQUIRE_FALSE(path.empty());
}

TEST_CASE("current_executable_path points to existing file", "[updater][exe_path]") {
    auto path = current_executable_path();
    REQUIRE(fs::exists(path));
}

// ── cleanup_old_binary ──────────────────────────────────────────────────────

TEST_CASE("cleanup_old_binary deletes .old file if present", "[updater][cleanup]") {
    TempUpdaterDir tmp("cleanup_present");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    write_fake_binary(exe_path);
    write_fake_binary(old_path);

    REQUIRE(fs::exists(old_path));

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);
    updater.cleanup_old_binary();

    REQUIRE_FALSE(fs::exists(old_path));
    REQUIRE(fs::exists(exe_path)); // Current exe must still exist
}

TEST_CASE("cleanup_old_binary does nothing if no .old exists", "[updater][cleanup]") {
    TempUpdaterDir tmp("cleanup_absent");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
#else
    auto exe_path = dir / "yuzu-agent";
#endif

    write_fake_binary(exe_path);

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    // Should not throw or crash
    updater.cleanup_old_binary();

    REQUIRE(fs::exists(exe_path));
}

// ── rollback_if_needed ──────────────────────────────────────────────────────

TEST_CASE("rollback_if_needed returns false when no .old exists", "[updater][rollback]") {
    TempUpdaterDir tmp("rollback_no_old");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
#else
    auto exe_path = dir / "yuzu-agent";
#endif

    write_fake_binary(exe_path);

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    REQUIRE_FALSE(updater.rollback_if_needed());
}

TEST_CASE("rollback_if_needed returns false when .old exists AND verified marker exists",
          "[updater][rollback]") {
    TempUpdaterDir tmp("rollback_verified");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    auto marker_path = dir / ".yuzu-update-verified";

    write_fake_binary(exe_path);
    write_fake_binary(old_path);
    write_fake_binary(marker_path); // Verification marker exists

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    // Should return false (no rollback needed) and clean up old + marker
    REQUIRE_FALSE(updater.rollback_if_needed());
    REQUIRE_FALSE(fs::exists(old_path));
    REQUIRE_FALSE(fs::exists(marker_path));
}

TEST_CASE("rollback_if_needed returns true when .old exists but NO verified marker",
          "[updater][rollback]") {
    TempUpdaterDir tmp("rollback_needed");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    write_fake_binary(exe_path);
    write_fake_binary(old_path);

    // No .yuzu-update-verified marker — should trigger rollback

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    REQUIRE(updater.rollback_if_needed());

    // After rollback, the old binary should have been moved back to exe_path
    REQUIRE(fs::exists(exe_path));
    REQUIRE_FALSE(fs::exists(old_path));
}

#ifndef _WIN32
// PR #4482 governance ch-4: a .old another account could have written is never
// promoted to the executable, whether group/world-writable or a symlink.
TEST_CASE("rollback_if_needed refuses a writable or symlinked .old",
          "[updater][rollback]") {
    TempUpdaterDir tmp("rollback_untrusted");
    const auto& dir = tmp.guard.path;
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
    write_fake_binary(exe_path);

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "darwin", "arm64", exe_path);

    SECTION("group- or world-writable") {
        write_fake_binary(old_path);
        fs::permissions(old_path, fs::perms::group_write | fs::perms::others_write,
                        fs::perm_options::add);
        REQUIRE_FALSE(updater.rollback_if_needed());
    }
    SECTION("a symlink") {
        auto target = dir / "planted";
        write_fake_binary(target);
        fs::create_symlink(target, old_path);
        REQUIRE_FALSE(updater.rollback_if_needed());
    }
    SECTION("a hard link to another file") {
        auto target = dir / "planted";
        write_fake_binary(target);
        fs::create_hard_link(target, old_path);
        REQUIRE_FALSE(updater.rollback_if_needed());
    }
    // The executable was not replaced.
    REQUIRE_FALSE(fs::is_symlink(exe_path));
    std::ifstream in(exe_path, std::ios::binary);
    REQUIRE(std::string(std::istreambuf_iterator<char>(in), {}) == "fake-binary-content");
}

// Governance g8q-2: startup maintenance removes a refused .old (cleanup runs after
// the refusal), keeps the executable, and never deletes through a symlink.
TEST_CASE("startup maintenance removes a refused .old and keeps the executable",
          "[updater][rollback][maintenance]") {
    TempUpdaterDir tmp("rollback_refused_cleanup");
    const auto& dir = tmp.guard.path;
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
    auto target = dir / "planted";
    write_fake_binary(exe_path);

    UpdateConfig config;
    config.enabled = true;
    Updater updater(config, "test-agent", "0.1.0", "darwin", "arm64", exe_path);

    SECTION("group- or world-writable") {
        write_fake_binary(old_path);
        fs::permissions(old_path, fs::perms::group_write | fs::perms::others_write,
                        fs::perm_options::add);
        REQUIRE_FALSE(updater.perform_startup_maintenance());
    }
    SECTION("a symlink") {
        write_fake_binary(target);
        fs::create_symlink(target, old_path);
        REQUIRE_FALSE(updater.perform_startup_maintenance());
        REQUIRE(fs::exists(target));
    }
    REQUIRE_FALSE(fs::exists(fs::symlink_status(old_path)));
    REQUIRE_FALSE(fs::is_symlink(exe_path));
    std::ifstream in(exe_path, std::ios::binary);
    REQUIRE(std::string(std::istreambuf_iterator<char>(in), {}) == "fake-binary-content");
}
#endif

TEST_CASE("disabled startup maintenance leaves executable-adjacent rollback files untouched",
          "[updater][maintenance][no-auto-update]") {
    TempUpdaterDir tmp("disabled_maintenance");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    const auto exe_path = dir / "yuzu-agent.exe";
    const auto old_path = dir / "yuzu-agent.old.exe";
#else
    const auto exe_path = dir / "yuzu-agent";
    const auto old_path = dir / "yuzu-agent.old";
#endif
    const auto marker_path = dir / ".yuzu-update-verified";
    write_fake_binary(exe_path);
    write_fake_binary(old_path);
    write_fake_binary(marker_path);

    UpdateConfig config;
    config.enabled = false;
    Updater updater(config, "test-agent", "0.1.0", "macos", "arm64", exe_path);

    REQUIRE_FALSE(updater.perform_startup_maintenance());
    REQUIRE(fs::exists(exe_path));
    REQUIRE(fs::exists(old_path));
    REQUIRE(fs::exists(marker_path));
}

TEST_CASE("a disabled updater's rollback and cleanup primitives are self-guarded",
          "[updater][maintenance]") {
    // PR #4482 review: the disabled no-write mode must not depend on every caller
    // going through perform_startup_maintenance().
    TempUpdaterDir tmp("disabled_primitives");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    const auto exe_path = dir / "yuzu-agent.exe";
    const auto old_path = dir / "yuzu-agent.old.exe";
#else
    const auto exe_path = dir / "yuzu-agent";
    const auto old_path = dir / "yuzu-agent.old";
#endif
    write_fake_binary(exe_path);
    { std::ofstream{old_path, std::ios::binary} << "previous-binary"; }
    // No verification marker, so an ENABLED updater would roll back here.

    UpdateConfig config;
    config.enabled = false;
    Updater updater(config, "test-agent", "0.1.0", "macos", "arm64", exe_path);

    REQUIRE_FALSE(updater.rollback_if_needed());
    updater.cleanup_old_binary();
    REQUIRE(fs::exists(old_path));
    std::ifstream current{exe_path, std::ios::binary};
    const std::string content{std::istreambuf_iterator<char>{current}, {}};
    REQUIRE(content == "fake-binary-content");
}

TEST_CASE("enabled startup maintenance retains rollback and cleanup semantics",
          "[updater][maintenance]") {
    TempUpdaterDir tmp("enabled_maintenance");
    const auto& dir = tmp.guard.path;

#ifdef _WIN32
    const auto exe_path = dir / "yuzu-agent.exe";
    const auto old_path = dir / "yuzu-agent.old.exe";
#else
    const auto exe_path = dir / "yuzu-agent";
    const auto old_path = dir / "yuzu-agent.old";
#endif
    const auto marker_path = dir / ".yuzu-update-verified";
    write_fake_binary(exe_path);
    write_fake_binary(old_path);
    write_fake_binary(marker_path);

    UpdateConfig config;
    config.enabled = true;
    Updater updater(config, "test-agent", "0.1.0", "macos", "arm64", exe_path);

    REQUIRE_FALSE(updater.perform_startup_maintenance());
    REQUIRE(fs::exists(exe_path));
    REQUIRE_FALSE(fs::exists(old_path));
    REQUIRE_FALSE(fs::exists(marker_path));
}

// ── Construction ────────────────────────────────────────────────────────────

TEST_CASE("Updater constructs without error", "[updater][construct]") {
    UpdateConfig config;
    config.enabled = true;
    config.check_interval = std::chrono::seconds{3600};

    auto exe = current_executable_path();

    // Should not throw
    Updater updater(config, "agent-123", "0.1.0", "windows", "x86_64", exe);

    // Verify stop works without prior start
    updater.stop();
}

// ── Stop unblocks the update loop (#2182) ───────────────────────────────────

TEST_CASE("Updater::stop ends run_check_loop mid-interval", "[updater][stop][2182]") {
    UpdateConfig config;
    auto updater = std::make_shared<Updater>(config, "agent-2182", "0.1.0", "linux", "x86_64",
                                             current_executable_path());

    // A null stub makes check_and_apply fail fast ("null gRPC stub"), so the loop
    // goes straight to its inter-check wait, here an hour long. The thread is
    // detached and owns the Updater so a regression fails the bound below instead
    // of hanging the suite at a std::thread destructor.
    auto done = std::make_shared<std::promise<bool>>();
    auto fut = done->get_future();
    std::thread([updater, done] {
        done->set_value(updater->run_check_loop(nullptr, std::chrono::hours{1}));
    }).detach();

    // Let the loop reach its wait, then stop as run()'s reconnect teardown does.
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    updater->stop();

    REQUIRE(fut.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    CHECK_FALSE(fut.get()); // stopped, no update applied
}

TEST_CASE("Updater::run_check_loop returns at once when already stopped",
          "[updater][stop][2182]") {
    UpdateConfig config;
    auto updater = std::make_shared<Updater>(config, "agent-2182", "0.1.0", "linux", "x86_64",
                                             current_executable_path());
    updater->stop();

    auto done = std::make_shared<std::promise<bool>>();
    auto fut = done->get_future();
    std::thread([updater, done] {
        done->set_value(updater->run_check_loop(nullptr, std::chrono::hours{1}));
    }).detach();

    REQUIRE(fut.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    CHECK_FALSE(fut.get());
}

TEST_CASE("Updater::stop ends run_check_loop for extreme intervals",
          "[updater][stop][2182]") {
    // Checks only that stop() ends the loop within the bound for seconds::max(), 0 and
    // negative intervals; it cannot observe a spin, so it does not prove the clamp itself.
    for (auto interval : {std::chrono::seconds::max(), std::chrono::seconds{0},
                          std::chrono::seconds{-5}}) {
        UpdateConfig config;
        auto updater = std::make_shared<Updater>(config, "agent-2182", "0.1.0", "linux",
                                                 "x86_64", current_executable_path());
        auto done = std::make_shared<std::promise<bool>>();
        auto fut = done->get_future();
        std::thread([updater, done, interval] {
            done->set_value(updater->run_check_loop(nullptr, interval));
        }).detach();

        std::this_thread::sleep_for(std::chrono::milliseconds{200});
        updater->stop();

        REQUIRE(fut.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
        CHECK_FALSE(fut.get());
    }
}

// ── OTA update thread lifecycle (#2182) ─────────────────────────────────────
// OtaUpdateThread is what agent.cpp's spawn, reconnect teardown and quiesce all go through, so
// this exercises the real stop-THEN-join ordering rather than a copy of it.

TEST_CASE("OtaUpdateThread::stop_and_join ends a thread parked in the check interval",
          "[updater][stop][2182]") {
    UpdateConfig config;
    auto updater = std::make_shared<Updater>(config, "agent-2182", "0.1.0", "linux", "x86_64",
                                             current_executable_path());
    struct State {
        OtaUpdateThread thread;
        std::atomic<bool> started{false};
        std::atomic<bool> applied{false};
        std::promise<void> joined;
    };
    // Owned by the detached driver so a regression (join without stop) fails the bound below
    // instead of hanging the suite or terminating in ~thread.
    auto st = std::make_shared<State>();
    auto fut = st->joined.get_future();
    // Null stub: check_and_apply fails fast, the loop parks in an hour-long wait.
    st->thread.start(updater, nullptr, std::chrono::hours{1}, [st] { st->started = true; },
                     [st] { st->applied = true; });
    REQUIRE(st->thread.joinable());

    std::thread([st, updater] {
        std::this_thread::sleep_for(std::chrono::milliseconds{200});
        st->thread.stop_and_join(updater);
        st->joined.set_value();
    }).detach();

    REQUIRE(fut.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    CHECK(st->started.load());
    CHECK_FALSE(st->applied.load()); // stopped, not applied
    CHECK_FALSE(st->thread.joinable());
}

TEST_CASE("OtaUpdateThread::join and stop tolerate an unstarted thread and a null updater",
          "[updater][stop][2182]") {
    OtaUpdateThread thread;
    CHECK_FALSE(thread.joinable());
    thread.stop_and_join(nullptr); // reconnect teardown with auto_update off / no updater
    thread.join();
}

TEST_CASE("Updater::effective_check_interval clamps to [1s, 8760h]", "[updater][2182]") {
    using std::chrono::hours;
    using std::chrono::seconds;
    static_assert(noexcept(Updater::effective_check_interval(seconds{})));

    const seconds max_interval{hours{8760}};
    CHECK(Updater::effective_check_interval(seconds{0}) == seconds{1});
    CHECK(Updater::effective_check_interval(seconds{-5}) == seconds{1});
    CHECK(Updater::effective_check_interval(seconds{1}) == seconds{1});
    CHECK(Updater::effective_check_interval(max_interval) == max_interval);
    CHECK(Updater::effective_check_interval(seconds::max()) == max_interval);
    CHECK(Updater::effective_check_interval(seconds{hours{9000}}) == max_interval);
}
