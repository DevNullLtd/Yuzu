/**
 * test_updater.cpp — Unit tests for the agent-side OTA updater utilities
 *
 * Covers: current_executable_path(), cleanup_old_binary(),
 *         rollback_if_needed(), Updater construction.
 */

#include <yuzu/agent/updater.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

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
    std::ofstream out(path, std::ios::binary);
    out << "fake-binary-content";
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
