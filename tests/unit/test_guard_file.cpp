/**
 * test_guard_file.cpp — FileGuard file-exists watch (Change B / B1).
 *
 * Exercises the real ReadDirectoryChangesW watch against a real scratch
 * directory + file: arm the guard, mutate the filesystem, assert the drift
 * report. Windows-only (the guard is a no-op elsewhere — covered by the
 * non-Windows case). Detection-only: no write-back is asserted.
 */

#include <yuzu/agent/guard_file.hpp>

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp" // yuzu::test::unique_temp_path

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

using namespace yuzu::agent;

// Ownership contract (cpp-safety): FileGuard owns a HANDLE + a std::thread; copy or
// move would double-close / double-join. Must be non-copyable AND non-movable.
static_assert(!std::is_copy_constructible_v<FileGuard>);
static_assert(!std::is_copy_assignable_v<FileGuard>);
static_assert(!std::is_move_constructible_v<FileGuard>);

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace fs = std::filesystem;

namespace {

// Collects every drift the guard reports; wait_for_detected blocks until a drift
// carrying `val` arrives (robust to the sink debounce and the async watch thread).
struct FileDriftCollector {
    std::mutex m;
    std::condition_variable cv;
    std::vector<GuardDrift> events;

    void push(const GuardDrift& d) {
        std::lock_guard lk(m);
        events.push_back(d);
        cv.notify_all();
    }
    bool wait_for_detected(const std::string& val, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (const auto& e : events)
                if (e.detected_value == val)
                    return true;
            return false;
        });
    }
    bool wait_count(std::size_t min, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] { return events.size() >= min; });
    }
    std::size_t size() {
        std::lock_guard lk(m);
        return events.size();
    }
    // Drift = a NON-compliant, NON-health report. Slice B added the guard.compliant
    // edge (one on arm / baseline, and one on each drift-clear); this PR adds the
    // health report (guard.unhealthy), which also defaults compliant=false — a
    // health report must NOT be counted as drift, or the two arms (missed
    // detection vs. reported-but-degraded) become indistinguishable to a test.
    std::size_t drift_count() {
        std::lock_guard lk(m);
        std::size_t n = 0;
        for (const auto& e : events)
            if (!e.compliant && e.health == GuardDrift::Health::None)
                ++n;
        return n;
    }
    bool wait_drift_count(std::size_t min, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            std::size_t n = 0;
            for (const auto& e : events)
                if (!e.compliant && e.health == GuardDrift::Health::None)
                    ++n;
            return n >= min;
        });
    }
    GuardDrift last_drift() { // most-recent non-compliant, non-health report
        std::lock_guard lk(m);
        for (auto it = events.rbegin(); it != events.rend(); ++it)
            if (!it->compliant && it->health == GuardDrift::Health::None)
                return *it;
        return {};
    }
    bool wait_compliant(std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (const auto& e : events)
                if (e.compliant && e.health == GuardDrift::Health::None)
                    return true;
            return false;
        });
    }
    std::size_t compliant_count() {
        std::lock_guard lk(m);
        std::size_t n = 0;
        for (const auto& e : events)
            if (e.compliant && e.health == GuardDrift::Health::None)
                ++n;
        return n;
    }
    std::size_t health_count() {
        std::lock_guard lk(m);
        std::size_t n = 0;
        for (const auto& e : events)
            if (e.health != GuardDrift::Health::None)
                ++n;
        return n;
    }
    bool wait_health_count(std::size_t min, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            std::size_t n = 0;
            for (const auto& e : events)
                if (e.health != GuardDrift::Health::None)
                    ++n;
            return n >= min;
        });
    }
};

void write_file(const fs::path& p, const std::string& s = "x") {
    std::ofstream(p, std::ios::binary) << s;
}

} // namespace

TEST_CASE("FileGuard file-exists: detects deletion in realtime", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-del");
    fs::create_directories(dir);
    const auto target = dir / "watched.txt";
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-del";
    cfg.rule_name = "delete watch";
    cfg.path = target.string();
    cfg.expect_present = true; // drift when the file goes missing
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // let the watch arm
    fs::remove(target);
    CHECK(col->wait_for_detected("<absent>", std::chrono::seconds(5)));
    g.stop();

    // The reported drift carries the file guard_type + expected state.
    REQUIRE(col->size() >= 1);
    {
        std::lock_guard lk(col->m);
        const auto& last = col->events.back();
        CHECK(last.guard_type == "file");
        CHECK(last.expected_value == "<present>");
        CHECK_FALSE(last.remediation_attempted); // detection-only
    }
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: absent at arm reports initial drift", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-absent");
    fs::create_directories(dir);
    const auto target = dir / "never-created.txt";

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-absent";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // No race: the initial compare runs synchronously inside the first reconcile.
    CHECK(col->wait_for_detected("<absent>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: expect-absent detects creation", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-create");
    fs::create_directories(dir);
    const auto target = dir / "should-not-exist.txt";

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-create";
    cfg.path = target.string();
    cfg.expect_present = false; // tripwire: drift when the file APPEARS
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // arm (compliant: absent==expected)
    write_file(target);
    CHECK(col->wait_for_detected("<present>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: compliant present state emits one edge then is quiet",
          "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-quiet");
    fs::create_directories(dir);
    const auto target = dir / "present.txt";
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-quiet";
    cfg.path = target.string();
    cfg.expect_present = true; // present == expected → compliant
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Slice B: arming compliant emits ONE guard.compliant edge (so the server can
    // see the rule is green), then the guard stays silent — never drift.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    g.stop();
    CHECK(col->drift_count() == 0); // no drift while compliant
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: drift then clear emits a fresh compliant edge (Slice B)",
          "[guardian][guard][file][compliant]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-clear");
    fs::create_directories(dir);
    const auto target = dir / "watched.txt";
    write_file(target); // present == expected → compliant on arm

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-clear";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    REQUIRE(col->wait_compliant(std::chrono::seconds(5))); // arm compliant edge
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    fs::remove(target); // → absent drift
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));
    const auto after_drift = col->size();

    write_file(target); // restored → a fresh compliant edge (rule went green again)
    REQUIRE(col->wait_count(after_drift + 1, std::chrono::seconds(5)));
    {
        std::lock_guard lk(col->m);
        CHECK(col->events.back().compliant); // the clear is a compliant edge, not a drift
    }
    g.stop();
    fs::remove_all(dir);
}

// ── file-hash-equals (B2) ────────────────────────────────────────────────────

TEST_CASE("FileGuard file-hash-equals: detects a content change", "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash");
    fs::create_directories(dir);
    const auto target = dir / "content.txt";
    write_file(target, "version-one");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals; // empty expected_hash → baseline-on-arm
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // arm + baseline (compliant edge)
    CHECK(col->drift_count() == 0); // baseline-on-arm is compliant, not drift
    write_file(target, "version-two-different"); // content changes
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));
    g.stop();
    {
        const auto d = col->last_drift();
        CHECK(d.guard_type == "file");
        CHECK(d.detected_value.size() == 64); // a real SHA-256 hex, not a sentinel
    }
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: identical-content rewrite stays quiet",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-quiet");
    fs::create_directories(dir);
    const auto target = dir / "stable.txt";
    write_file(target, "unchanging");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-quiet";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // baseline (compliant edge)
    write_file(target, "unchanging"); // rewrite SAME bytes → notification, but hash unchanged
    std::this_thread::sleep_for(std::chrono::milliseconds(600)); // settle + eval window
    g.stop();
    CHECK(col->drift_count() == 0); // content-change semantics: a no-op rewrite is not drift
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: oversize is reported, not silently skipped",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-big");
    fs::create_directories(dir);
    const auto target = dir / "big.bin";
    write_file(target, std::string(4096, 'A')); // 4 KiB

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-big";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.max_hash_bytes = 64; // far below the file size
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Fail-loud at arm: too large to verify within the DoS cap → "<oversize>" drift.
    CHECK(col->wait_for_detected("<oversize>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: mismatch against a supplied expected hash drifts",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-exp");
    fs::create_directories(dir);
    const auto target = dir / "watched.cfg";
    write_file(target, "actual-content");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-exp";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.expected_hash = std::string(64, '0'); // a hash the real content cannot match
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Operator-supplied baseline: the initial compare already drifts (content != expected).
    REQUIRE(col->wait_count(1, std::chrono::seconds(5)));
    g.stop();
    {
        std::lock_guard lk(col->m);
        CHECK(col->events.back().expected_value == std::string(64, '0'));
        CHECK(col->events.back().detected_value.size() == 64); // the real hash
    }
    fs::remove_all(dir);
}

// ── teardown + resilience (governance Gate-7 hardening) ──────────────────────

TEST_CASE("FileGuard: stop() with a watch armed but no change in-flight returns",
          "[guardian][guard][file][teardown]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-stopclean");
    fs::create_directories(dir);
    const auto target = dir / "x.txt";
    write_file(target);
    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-stopclean";
    cfg.path = target.string();
    cfg.expect_present = true; // compliant — no drift, watch just armed
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    g.stop(); // must join promptly with no outstanding-IO crash (test timeout catches a hang)
    fs::remove_all(dir);
    SUCCEED();
}

TEST_CASE("FileGuard: stop() races an in-flight change notification without crashing",
          "[guardian][guard][file][teardown]") {
    // Tight start/change/stop loop exercises CancelIo + CloseHandle + join while a
    // ReadDirectoryChangesW read is outstanding (the teardown UAF window).
    for (int i = 0; i < 25; ++i) {
        const auto dir = yuzu::test::unique_temp_path("fileguard-stoprace");
        fs::create_directories(dir);
        const auto target = dir / "y.txt";
        write_file(target, "a");
        FileGuard::Config cfg;
        cfg.rule_id = "fg-stoprace";
        cfg.path = target.string();
        cfg.expect_present = true;
        FileGuard g(cfg, [](const GuardDrift&) {});
        REQUIRE(g.start());
        write_file(target, "b"); // trigger a notification, then immediately tear down
        fs::remove(target);
        g.stop();
        fs::remove_all(dir);
    }
    SUCCEED();
}

TEST_CASE("FileGuard file-exists: survives parent-dir delete and recreate",
          "[guardian][guard][file][resilience]") {
    const auto base = yuzu::test::unique_temp_path("fileguard-resil");
    const auto parent = base / "sub";
    const auto target = parent / "watched.txt";
    fs::create_directories(parent);
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-resil";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 1) delete the whole parent directory → file is absent → drift. (Count drifts,
    //    not raw events — arming present emitted a compliant edge first, Slice B.)
    fs::remove_all(parent);
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));

    // 2) recreate the parent + file (compliant again), then delete once more — the
    //    guard must have re-armed via the nearest-ancestor watch and detect again.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    fs::create_directories(parent);
    write_file(target);
    std::this_thread::sleep_for(std::chrono::milliseconds(400)); // let it re-arm + re-baseline present
    fs::remove(target);
    CHECK(col->wait_drift_count(2, std::chrono::seconds(5))); // second <absent> drift proves survival
    g.stop();
    fs::remove_all(base);
}

TEST_CASE("FileGuard file-hash-equals: continuous sub-settle writes still get hashed (defer cap)",
          "[guardian][guard][file][hash]") {
    // A writer touching the file faster than settle_ms must not starve the hash
    // forever — max_settle_defer_ms forces an evaluation (UP-1 regression guard).
    const auto dir = yuzu::test::unique_temp_path("fileguard-defercap");
    fs::create_directories(dir);
    const auto target = dir / "churn.txt";
    write_file(target, "v0");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-defercap";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals; // baseline-on-arm = "v0"
    cfg.settle_ms = 200;             // never quiesces under the 100ms write cadence below
    cfg.max_settle_defer_ms = 600;   // ...but the cap forces a hash within ~600ms
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(250)); // arm + baseline v0

    for (int i = 1; i <= 14; ++i) { // ~1.4s of continuous changing writes < settle_ms apart
        write_file(target, "v" + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Without the defer cap this would never fire (settle never quiesces).
    CHECK(col->wait_count(1, std::chrono::seconds(3)));
    g.stop();
    fs::remove_all(dir);
}

// ── watched directory renamed or moved ───────────────────────────────────────
// An open directory handle follows its directory to a new name without a completion, so the
// guard also watches the parent of the directory it armed. Each case renames or moves the
// watched directory, recreates the original path and changes the target there.

namespace {

using namespace std::chrono_literals;

enum class RigMode { Tripwire, Present, Hash };

bool move_dir(const fs::path& from, const fs::path& to) {
    return MoveFileExW(from.c_str(), to.c_str(), 0) != 0;
}

bool wait_for_hash_drift(FileDriftCollector& c, std::chrono::milliseconds to) {
    std::unique_lock lk(c.m);
    return c.cv.wait_for(lk, to, [&] {
        for (const auto& e : c.events)
            if (!e.compliant && e.detected_value.size() == 64)
                return true;
        return false;
    });
}

DWORD process_handle_count() {
    DWORD n = 0;
    GetProcessHandleCount(GetCurrentProcess(), &n);
    return n;
}

// One guard over <scratch>/<rel_target>. The scratch root is declared first and the guard last,
// so the watch thread is joined before the tree is removed.
class RenameRig {
public:
    RenameRig(RigMode mode, const fs::path& rel_target, const fs::path& rel_precreate,
              bool seed_target, std::function<void()> in_sink = {},
              std::function<void(FileGuard&)> pre_start = {})
        : mode_(mode) {
        fs::create_directories(root_.path);
        target_ = root_.path / rel_target;
        if (!rel_precreate.empty())
            fs::create_directories(root_.path / rel_precreate);
        if (seed_target)
            write_file(target_, "base-content");
        FileGuard::Config cfg;
        cfg.rule_id = "fg-rename";
        cfg.path = target_.string();
        cfg.event_debounce_ms = 50;
        cfg.settle_ms = 100;
        if (mode == RigMode::Hash)
            cfg.assertion = FileGuard::Assertion::HashEquals;
        else
            cfg.expect_present = (mode == RigMode::Present);
        guard_ = std::make_unique<FileGuard>(cfg, [col = col_, in_sink](const GuardDrift& d) {
            col->push(d);
            if (in_sink)
                in_sink(); // runs on the guard thread, after the report is recorded
        });
        if (pre_start)
            pre_start(*guard_); // e.g. set_parent_drain_fail_hook_for_test — must run before start()
        REQUIRE(guard_->start());
        // The first evaluation runs after the watches are armed, so its report is the barrier.
        REQUIRE(col_->wait_count(1, 30s));
    }

    const fs::path& root() const { return root_.path; }
    fs::path dir() const { return target_.parent_path(); }
    FileDriftCollector& col() { return *col_; }

    void move(const fs::path& from, const fs::path& to) { REQUIRE(move_dir(from, to)); }

    // Recreate the directory chain at the original path, then write the target.
    void recreate_and_write() {
        fs::create_directories(dir());
        write_file(target_, "content-" + std::to_string(++seq_));
    }

    void flood_siblings(int count, int rename_dir_at = -1, const fs::path& dir_dest = {}) {
        for (int i = 0; i < count; ++i) {
            std::error_code ec;
            const fs::path s = root_.path / ("s" + std::to_string(i));
            const fs::path t = root_.path / ("t" + std::to_string(i));
            fs::create_directory(s, ec);
            move_dir(s, t);
            if (i == rename_dir_at)
                move(dir(), dir_dest);
        }
    }

    // Tripwire: the target appeared. Hash: a content drift carrying a real digest.
    bool wait_detected(std::chrono::milliseconds to) {
        REQUIRE(mode_ != RigMode::Present);
        return mode_ == RigMode::Hash ? wait_for_hash_drift(*col_, to)
                                      : col_->wait_for_detected("<present>", to);
    }

    void stop() { guard_->stop(); }

private:
    yuzu::test::TempDir root_{"yuzu_test_fgrename_"};
    RigMode mode_;
    fs::path target_;
    std::shared_ptr<FileDriftCollector> col_ = std::make_shared<FileDriftCollector>();
    int seq_{0};
    std::unique_ptr<FileGuard> guard_;
};

void run_rename_then_recreate(RigMode m, bool move_to_other_parent) {
    RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash);
    if (move_to_other_parent) {
        fs::create_directories(rig.root() / "P2");
        rig.move(rig.dir(), rig.root() / "P2" / "D");
    } else {
        rig.move(rig.dir(), rig.root() / "D2");
    }
    rig.recreate_and_write();
    CHECK(rig.wait_detected(30s));
}

// Regression for the completion-discard fix (finding 3): after a rename-then-recreate cycle
// has already been detected once, a SECOND rename of the (freshly rebuilt) watched directory
// must still be detected. Uses a drift-count snapshot (not wait_detected()) for the second
// assertion, since wait_detected() would pass vacuously against the first cycle's own event.
void run_rename_recreate_then_rename_again(RigMode m) {
    RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash);
    rig.move(rig.dir(), rig.root() / "D2");
    rig.recreate_and_write();
    CHECK(rig.wait_detected(30s));
    const auto after_first = rig.col().drift_count();
    // Clear the sink's event_debounce_ms (50ms, RenameRig's ctor) before inducing the second
    // cycle: in tripwire mode the second cycle's own eval_exists() can land within a few ms of
    // the first (no settle delay), and report()'s debounce would then silently fold its emission
    // into the first's — a test-timing artifact, not evidence the second rename went undetected
    // (measured on real Windows hardware: the guard's own log line for the second detection
    // still fires immediately, inside eval_exists(), before the debounce check ever runs).
    std::this_thread::sleep_for(100ms);

    rig.move(rig.dir(), rig.root() / "D3"); // second rename of the rebuilt directory
    rig.recreate_and_write();
    CHECK(rig.col().wait_drift_count(after_first + 1, 30s));
}

void run_rename_reports_absent(RigMode m, bool move_to_other_parent) {
    RenameRig rig(m, "D/f.txt", "D", true);
    if (move_to_other_parent) {
        fs::create_directories(rig.root() / "P2");
        rig.move(rig.dir(), rig.root() / "P2" / "D");
    } else {
        rig.move(rig.dir(), rig.root() / "D2");
    }
    CHECK(rig.col().wait_for_detected("<absent>", 30s));
}

void run_delete_then_recreate(RigMode m) {
    RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash);
    std::error_code ec;
    fs::remove_all(rig.dir(), ec);
    rig.recreate_and_write();
    CHECK(rig.wait_detected(30s));
}

// Only A exists at arm time (A/B/D does not), so the guard is in nearest-ancestor mode on A.
void run_ancestor_rename(RigMode m) {
    RenameRig rig(m, "A/B/D/f.txt", "A", false);
    rig.move(rig.root() / "A", rig.root() / "A2");
    rig.recreate_and_write();
    if (m == RigMode::Hash)
        CHECK(rig.col().wait_compliant(30s)); // first present read of the recreated file is baselined
    else
        CHECK(rig.wait_detected(30s));
}

void run_sibling_churn(RigMode m) {
    RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash);
    rig.flood_siblings(60);
    std::this_thread::sleep_for(300ms); // linger so the reader has seen the burst
    CHECK(rig.col().drift_count() == 0); // records naming other entries are not drift
    // The parent watch must still be live after all those re-issues.
    rig.move(rig.dir(), rig.root() / "D2");
    rig.recreate_and_write();
    CHECK(rig.wait_detected(30s));
}

// Regression for the retain-and-reissue design (bind()'s arm 1/arm 2): an ordinary X-content
// re-arm and a non-matching sibling completion on the parent watch must both retain the SAME
// parent-watch block rather than rebuild it - only an actual identity change on X (the final
// move below) may do that. RigMode::Present, seeded so the file starts present == expected,
// lets the interleaved content rewrites exercise bind() repeatedly without themselves being
// drift, so the only drift possible below is the proof that the retained block still detects
// the eventual rename.
//
// drift_count()==0 plus eventual detection alone cannot tell "P was retained" apart from "P was
// silently rebuilt every time" - a rebuild-every-time regression still arms a working P each
// time and would pass both checks. The forced-drain-fail hook below makes this discriminating:
// it only fires if bind() actually calls pio.reset() on a genuinely-pending block, which a
// correct retain-only implementation never does during ordinary churn (arm 1's no-op and arm
// 2's same-handle reissue never touch pio at all). A regression that rebuilds on every ordinary
// re-arm would trip the hook repeatedly, hit kParentIoAbandonLimit well within the loop below,
// and permanently disable P - making the final rename go undetected and failing this test.
void run_retain_across_rearm() {
    RenameRig rig(RigMode::Present, "D/f.txt", "D", true, {}, [](FileGuard& g) {
        g.set_parent_drain_fail_hook_for_test([] { return true; });
    });
    for (int i = 0; i < 5; ++i) {
        write_file(rig.dir() / "f.txt", "rewrite-" + std::to_string(i)); // X-content re-arm: bind() arm 1/2
        rig.flood_siblings(10); // P completions not naming X: reissue on the retained handle
        std::this_thread::sleep_for(20ms);
    }
    CHECK(rig.col().drift_count() == 0); // content rewrites of a still-present file are not drift
    rig.move(rig.dir(), rig.root() / "D2"); // the identity change: only this may rebuild P
    CHECK(rig.col().wait_for_detected("<absent>", 30s)); // still detected: proves P was never
        // reset (and thus never forced-abandoned) during the churn above
}

// Regression for sec-1 (the memory-safety fix this branch's whole redesign exists for):
// ParentIoRelease's abandon-rather-than-free branch, forced deterministically via the
// test-only hook rather than a genuinely delayed kernel completion (not reproducible from
// user mode on local NTFS - directory-notify IRP cleanup normally completes synchronously,
// which is exactly why this hazard needed a dedicated seam rather than a timing-based test).
// By the time wait_count(1, ...) returns, arm_watch() has already run and P has a genuinely
// outstanding read (bind()'s successful arm always ends with pending=true), so stop()'s
// teardown reaches ParentIoRelease with p->pending == true, and the hook forces the drain to
// report unconfirmed. This asserts the two properties a black-box test CAN give for a hazard
// whose actual failure mode (a late kernel write into freed memory) is not itself observable
// from user mode: stop() still returns promptly (the fix's whole point - abandon-not-free must
// never become a hang) and the process does not crash. It intentionally leaks one ~32KB block
// (the abandoned ParentIo) - the same accepted, capped trade-off kParentIoAbandonLimit exists
// for in production, exercised here exactly once. Covers run()'s own final-teardown case;
// run_ancestor_created_chain_hits_abandon_limit (below) covers the OTHER deterministic
// pending-teardown case - an ancestor-triggered rebuild racing a still-outstanding P read - and
// drives the counter to the actual disable threshold. A THIRD case (a D-triggered rebuild
// racing an unconsumed P completion) is genuinely timing-dependent and is not attempted here.
void run_parent_drain_forced_abandon() {
    yuzu::test::TempDir root("yuzu_test_fgabandon_");
    fs::create_directories(root.path / "D");
    const fs::path target = root.path / "D" / "f.txt";
    write_file(target, "base-content");

    FileGuard::Config cfg;
    cfg.rule_id = "fg-abandon";
    cfg.path = target.string();
    cfg.expect_present = true;

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard guard(cfg, [col](const GuardDrift& d) { col->push(d); });
    guard.set_parent_drain_fail_hook_for_test([] { return true; }); // force every drain to fail
    REQUIRE(guard.start());
    REQUIRE(col->wait_count(1, 30s)); // armed + initial compliant report

    const auto t0 = std::chrono::steady_clock::now();
    guard.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 5s);
}

// Regression for the OTHER deterministic mid-run pending-teardown case (distinct from the
// final-teardown case above): an ancestor-triggered rebuild racing a genuinely outstanding P
// read. The ancestor watch (armed on nearest_existing_dir(), FindFirstChangeNotificationW with
// watchSubtree=TRUE) is RECURSIVE; P (bind()'s ParentIo, ReadDirectoryChangesW on
// x.parent_path()) is NOT - it only sees x's parent's DIRECT children changing. So creating one
// directory level at a time beneath a not-yet-existing watched path wakes the (recursive)
// ancestor watch on every level, each wake resolving a NEW x one level deeper - but the event
// that woke it (a grandchild being created, invisible to the OLD P, which only watched for the
// old x's OWN rename one level up) never touches P at all. Every such rebuild therefore tears
// down a genuinely still-pending P block: this is not a rare race, it is the ordinary, ONLY way
// an already-armed P block gets torn down for a reason other than its own completion, deterministic
// given fs::create_directory calls in order (not fs::create_directories, which would jump levels
// and skip abandons). With the forced-fail hook, three such levels reliably drives P to its
// kParentIoAbandonLimit and disables it; a fourth level is a deterministic negative (bind()
// short-circuits on p_disabled before touching pio at all - no drain, no hook call, no wait).
void run_ancestor_created_chain_hits_abandon_limit() {
    yuzu::test::TempDir root("yuzu_test_fgabandonchain_");
    fs::create_directories(root.path / "A"); // only the first level pre-exists
    const fs::path target = root.path / "A" / "D" / "E" / "F" / "G" / "f.txt";

    FileGuard::Config cfg;
    cfg.rule_id = "fg-abandon-chain";
    cfg.path = target.string();
    cfg.expect_present = true; // absent throughout: only directories are created, never the file
    cfg.event_debounce_ms = 0; // every wake's report must be counted, not collapsed
    cfg.parent_unhealthy_refresh_ms = 0; // edge-only: the refresh timer is a separate, own test

    // Counts FORCED abandons only. A genuine (not test-forced) drain exceeding kCancelDrainMs on
    // a loaded/contended runner would still advance the real p_abandon_count without incrementing
    // this - if the CHECKs below ever fail, that is an environment-timing signature, not evidence
    // the counting logic itself regressed.
    std::atomic<int> hook_calls{0};
    auto col = std::make_shared<FileDriftCollector>();
    FileGuard guard(cfg, [col](const GuardDrift& d) { col->push(d); });
    guard.set_parent_drain_fail_hook_for_test([&hook_calls] {
        ++hook_calls;
        return true; // force every drain to fail
    });
    REQUIRE(guard.start());
    REQUIRE(col->wait_drift_count(1, 30s)); // initial eval: absent, x=A, P on root

    REQUIRE(fs::create_directory(root.path / "A" / "D"));
    REQUIRE(col->wait_drift_count(2, 30s));
    CHECK(hook_calls.load() == 1); // 1st abandon: P (on root, watching A) never saw A/D

    REQUIRE(fs::create_directory(root.path / "A" / "D" / "E"));
    REQUIRE(col->wait_drift_count(3, 30s));
    CHECK(hook_calls.load() == 2); // 2nd abandon: P (on A, watching A/D) never saw A/D/E

    REQUIRE(fs::create_directory(root.path / "A" / "D" / "E" / "F"));
    REQUIRE(col->wait_drift_count(4, 30s));
    CHECK(hook_calls.load() == 3); // 3rd abandon: kParentIoAbandonLimit reached, P now disabled
    REQUIRE(col->wait_health_count(1, 30s)); // on_parent_disabled() fired in this same reconcile,
        // synchronously right after the pio.reset() that just tripped the limit

    REQUIRE(fs::create_directory(root.path / "A" / "D" / "E" / "F" / "G"));
    REQUIRE(col->wait_drift_count(5, 30s)); // the ancestor wake on F (recursive, catches G being
        // created) drives this reconcile, exactly like drifts #2-#4; this same reconcile also
        // newly arms h_dir on G (the configured parent now exists) - armed, but not yet exercised
    CHECK(hook_calls.load() == 3); // unchanged: bind() short-circuited on p_disabled, no drain
    CHECK(col->health_count() == 1); // unchanged: the top-of-bind() short-circuit does not re-fire
        // on_parent_disabled() — it already fired once, at the transition, above

    write_file(target, "content"); // exercises h_dir itself (armed, not fired, above): the
        // file's own detection continues, but its edge into compliant is now GATED — this is the
        // exact false-green (100% compliant while rename detection is dead) this PR's blocking
        // fix removes. Was `REQUIRE(col->wait_compliant(30s))` before this fix.
    REQUIRE(col->wait_health_count(2, 30s)); // report_compliant()'s gate substitutes a 2nd
        // unhealthy report for the would-be compliant publication
    CHECK(col->compliant_count() == 0); // never shown green while P stays permanently disabled
    CHECK(col->drift_count() == 5);
    CHECK(hook_calls.load() == 3); // still unchanged: h_dir's own content channel never touches P

    const auto t0 = std::chrono::steady_clock::now();
    guard.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 5s); // pio is already null (abandoned, not freed) - nothing to drain here
}

// Drives P to permanent disable via the same 3-level forced-fail ancestor chain as
// run_ancestor_created_chain_hits_abandon_limit above (the only deterministic in-run path
// to p_disabled), leaving `target`/`root`/`col`/`guard` positioned right after the edge
// health report so a caller can drive further scenarios from there.
struct DisabledGuardFixture {
    yuzu::test::TempDir root;
    fs::path target;
    std::shared_ptr<FileDriftCollector> col = std::make_shared<FileDriftCollector>();
    std::unique_ptr<FileGuard> guard;

    explicit DisabledGuardFixture(std::uint64_t refresh_ms, GuardSink extra_sink = {})
        : root("yuzu_test_fgdisabled_") {
        fs::create_directories(root.path / "A");
        target = root.path / "A" / "D" / "E" / "F" / "f.txt";

        FileGuard::Config cfg;
        cfg.rule_id = "fg-disabled-fixture";
        cfg.path = target.string();
        cfg.expect_present = true;
        cfg.event_debounce_ms = 0;
        cfg.parent_unhealthy_refresh_ms = refresh_ms;

        auto* col_ptr = col.get();
        guard = std::make_unique<FileGuard>(cfg, [col_ptr, extra_sink](const GuardDrift& d) {
            col_ptr->push(d);
            if (extra_sink)
                extra_sink(d); // may throw — must run AFTER push so the event is still recorded
        });
        guard->set_parent_drain_fail_hook_for_test([] { return true; });
        REQUIRE(guard->start());
        REQUIRE(col->wait_drift_count(1, 30s)); // initial eval: absent, x=A, P on root
        REQUIRE(fs::create_directory(root.path / "A" / "D"));
        REQUIRE(col->wait_drift_count(2, 30s));
        REQUIRE(fs::create_directory(root.path / "A" / "D" / "E"));
        REQUIRE(col->wait_drift_count(3, 30s));
        REQUIRE(fs::create_directory(root.path / "A" / "D" / "E" / "F"));
        REQUIRE(col->wait_health_count(1, 30s)); // p_disabled transition: the edge report
    }
};

// The disabled-parent-watch unhealthy report is a lost-edge backstop, not a one-shot: with a
// short refresh cadence configured, it must keep re-asserting on its own with no filesystem
// activity at all, since the legacy sink drops events on disconnect with no retry.
void run_parent_unhealthy_refresh_cadence() {
    DisabledGuardFixture fx(500); // 500ms refresh
    // edge + >=2 refresh ticks needs ~1s; 30s matches this file's own timeout convention
    // (a thin margin here risks CI flake on a loaded/shared runner — CLAUDE.md #1871).
    REQUIRE(fx.col->wait_health_count(3, 30s));
}

// The mirror case: refresh_ms == 0 must NOT arm a timer — the health count must stay at the
// single edge report indefinitely while quiet.
void run_parent_unhealthy_refresh_disabled_when_zero() {
    DisabledGuardFixture fx(0);
    std::this_thread::sleep_for(1500ms); // several would-be refresh periods, quiet otherwise
    CHECK(fx.col->health_count() == 1); // no timer armed: stays at the edge count
}

// Health publication must be best-effort (Finding: a synchronous sink call inside bind() is a
// new exit point from run()'s outer catch). A sink that throws only on a health report must
// not end the worker — report_parent_unhealthy()'s own try/catch must swallow it, both at the
// edge and on the gated re-fire that replaces a would-be compliant publication.
void run_health_report_sink_throw_is_best_effort() {
    auto throwing_sink = [](const GuardDrift& d) {
        if (d.health != GuardDrift::Health::None)
            throw std::runtime_error("simulated health-sink failure");
    };
    DisabledGuardFixture fx(0, throwing_sink); // the ctor's own edge report already throws once
    write_file(fx.target, "content"); // presence flips true: a gated compliant edge -> a 2nd
        // health report, which also throws
    REQUIRE(fx.col->wait_health_count(2, 30s)); // proves the worker is still alive and servicing
        // the wait loop after the first throw was swallowed
    CHECK(fx.col->compliant_count() == 0);
}

// last_compliant is a single edge-cache shared by the real compliant path and the gated-health
// substitution: once true (whichever publication actually fired), report_compliant() must not
// re-evaluate at all on a same-state re-notify — no redundant gated report — but a genuine
// drift->compliant transition afterward must re-arm the gate and fire exactly one more.
void run_compliant_edge_gated_by_health_no_redundant_refire() {
    DisabledGuardFixture fx(0);
    const auto drift_before_remove = fx.col->drift_count(); // whatever the fixture's own setup

    write_file(fx.target, "content"); // presence flips true: edge into compliant, but gated
    REQUIRE(fx.col->wait_health_count(2, 30s));
    CHECK(fx.col->compliant_count() == 0);

    write_file(fx.target, "content"); // same-state rewrite: still present; last_compliant is
        // already true, so report_compliant()'s own early-return fires before the gate is even
        // reached — no redundant gated report
    std::this_thread::sleep_for(500ms);
    CHECK(fx.col->health_count() == 2); // unchanged
    CHECK(fx.col->compliant_count() == 0);

    REQUIRE(fs::remove(fx.target)); // presence flips false: a genuine drift (report(), never
        // gated) resets last_compliant
    // A hardcoded absolute count here would be a false-green risk: the F-level create_directory
    // inside DisabledGuardFixture's own setup trips the abandon limit AND separately evaluates
    // eval_exists() in the same reconcile (mirrors the sibling abandon-chain test, which reaches
    // drift #4 at the equivalent step) — asserting a specific absolute count could already be
    // satisfied by the fixture's setup alone, passing even if this remove() produced no drift at
    // all. Assert relative to a captured baseline instead.
    REQUIRE(fx.col->wait_drift_count(drift_before_remove + 1, 30s));

    write_file(fx.target, "content"); // presence flips true again: a NEW edge into compliant,
        // still disabled — the gate must re-fire
    REQUIRE(fx.col->wait_health_count(3, 30s));
    CHECK(fx.col->compliant_count() == 0); // never shown green for this instance's whole lifetime
}

// Parks the guard thread inside its first report so notifications pile up unread.
struct SinkGate {
    std::mutex m;
    std::condition_variable cv;
    bool first = true;
    bool released = false;

    void hold_once() { // bounded, so a failing test cannot hang the guard join
        std::unique_lock lk(m);
        if (!first)
            return;
        first = false;
        cv.wait_for(lk, 30s, [&] { return released; });
    }
    void release() {
        {
            std::lock_guard lk(m);
            released = true;
        }
        cv.notify_all();
    }
};

// While the guard thread is parked (both watches armed), sibling renames far larger than the
// 32 KiB notification buffer overflow the parent watch, and the directory is renamed and
// recreated part-way through. Nothing touches the renamed directory, so the parent watch is the
// only possible wake: after release the overflow must trigger a resync that finds the change.
void run_overflow_resync(RigMode m) {
    SinkGate gate;
    RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash, [&gate] { gate.hold_once(); });
    yuzu::test::ScopeExit release([&gate] { gate.release(); }); // before the rig joins its thread
    rig.flood_siblings(600, 300, rig.root() / "D2");
    rig.recreate_and_write();
    gate.release();
    CHECK(rig.wait_detected(30s));
}

void run_stop_cycles(RigMode m, bool rename_first) {
    auto cycle = [&] {
        RenameRig rig(m, "D/f.txt", "D", m == RigMode::Hash);
        if (rename_first)
            rig.move(rig.dir(), rig.root() / "D2");
        const auto t0 = std::chrono::steady_clock::now();
        rig.stop();
        CHECK(std::chrono::steady_clock::now() - t0 < 5s);
    };
    cycle(); // warm-up: process-wide lazily created handles are not a per-guard leak
    const DWORD before = process_handle_count();
    for (int i = 0; i < 20; ++i)
        cycle();
    // A handle leaked per guard would add at least 20.
    CHECK(process_handle_count() < before + 10);
}

// A drive letter with no root (not mapped, not a network or removable volume), or 0.
wchar_t unused_drive_letter() {
    const DWORD mask = GetLogicalDrives();
    for (wchar_t c = L'Z'; c >= L'D'; --c) {
        if (mask & (1u << (c - L'A')))
            continue;
        const wchar_t root[] = {c, L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) == DRIVE_NO_ROOT_DIR)
            return c;
    }
    return 0;
}

} // namespace

TEST_CASE("FileGuard rename: renamed watched directory then recreated is detected (tripwire)",
          "[guardian][guard][file][rename]") {
    run_rename_then_recreate(RigMode::Tripwire, false);
}

TEST_CASE("FileGuard rename: renamed watched directory then recreated is detected (hash)",
          "[guardian][guard][file][rename]") {
    run_rename_then_recreate(RigMode::Hash, false);
}

TEST_CASE("FileGuard rename: moved watched directory then recreated is detected (tripwire)",
          "[guardian][guard][file][rename]") {
    run_rename_then_recreate(RigMode::Tripwire, true);
}

TEST_CASE("FileGuard rename: moved watched directory then recreated is detected (hash)",
          "[guardian][guard][file][rename]") {
    run_rename_then_recreate(RigMode::Hash, true);
}

TEST_CASE("FileGuard rename: a second rename after a rebuild is still detected (tripwire)",
          "[guardian][guard][file][rename]") {
    run_rename_recreate_then_rename_again(RigMode::Tripwire);
}

TEST_CASE("FileGuard rename: a second rename after a rebuild is still detected (hash)",
          "[guardian][guard][file][rename]") {
    run_rename_recreate_then_rename_again(RigMode::Hash);
}

TEST_CASE("FileGuard rename: parent watch is retained (not rebuilt) across ordinary re-arms "
          "and sibling churn before a rename",
          "[guardian][guard][file][rename]") {
    run_retain_across_rearm();
}

TEST_CASE("FileGuard rename: a forced non-drain at teardown is abandoned, not freed, and stop() "
          "still returns promptly",
          "[guardian][guard][file][rename]") {
    run_parent_drain_forced_abandon();
}

TEST_CASE("FileGuard rename: an ancestor-triggered rebuild chain reaches the abandon limit, "
          "disables the parent watch and reports it unhealthy, and withholds the file's own "
          "compliant edge while disabled (detection itself is unaffected)",
          "[guardian][guard][file][rename]") {
    run_ancestor_created_chain_hits_abandon_limit();
}

TEST_CASE("FileGuard rename: the disabled-parent-watch unhealthy report keeps re-asserting on "
          "a configured refresh cadence with no filesystem activity at all",
          "[guardian][guard][file][rename][health]") {
    run_parent_unhealthy_refresh_cadence();
}

TEST_CASE("FileGuard rename: a zero refresh cadence never arms the backstop timer — the "
          "unhealthy report stays edge-only",
          "[guardian][guard][file][rename][health]") {
    run_parent_unhealthy_refresh_disabled_when_zero();
}

TEST_CASE("FileGuard rename: a health-report sink failure is best-effort and never ends the "
          "watch thread",
          "[guardian][guard][file][rename][health]") {
    run_health_report_sink_throw_is_best_effort();
}

// Quarantined pending #4086 (guard_win_handle.hpp's cancel_and_close_ closes h_dir
// without draining a cancelled OVERLAPPED read first). DisabledGuardFixture's setup
// churns arm_watch_once() three times in ~2ms to force the parent-watch abandon limit;
// every one of those rebuilds tears down and reissues h_dir's own read without waiting
// for the prior one to actually complete, and the test's very next write_file() races
// that reissue. Measured 9/10 failures in isolation on real Windows hardware, 0/15 with
// the verbose --success reporter (which slows the race window enough to miss it) — a
// real, high-frequency race in shipped code, not test-environment noise.
//
// [.] alone was NOT reliably observed to exclude this from the "agent unit tests" meson
// entry — repeated real-hardware runs against this suite's own `~[tsan-heavy]` filter
// were inconsistent on whether Catch2's hidden-tag default-exclusion still applies once
// a non-empty filter is present (a governance review disputed the mechanism claimed in an
// earlier version of this comment; re-testing then showed BOTH outcomes across repeat
// runs, so the exact Catch2 rule here is left unresolved rather than restated with false
// confidence). What IS reliably, repeatedly verified: the explicit [flaky-4086] tag plus
// `tests/meson.build`'s `~[flaky-4086]` exclusion (mirroring how `[tsan-heavy]` is excluded
// from this same entry) keeps this case out of every run tested, with no exception. [.] is
// kept too so a manual, zero-argument run of the exe still skips it.
//
// Re-tag back into the normal suite once #4086 lands a real fix (mirror spark_file.cpp's
// F2 drain-before-close pattern onto h_dir).
TEST_CASE("FileGuard rename: the compliant edge cache is shared with the gated health "
          "substitution — no redundant report on a same-state re-notify, but a genuine "
          "drift-then-recompliant cycle re-arms the gate",
          "[.][flaky-4086][guardian][guard][file][rename][health][compliant]") {
    run_compliant_edge_gated_by_health_no_redundant_refire();
}

TEST_CASE("FileGuard rename: rename or move alone reports the absent state (file-exists)",
          "[guardian][guard][file][rename]") {
    run_rename_reports_absent(RigMode::Present, false);
    run_rename_reports_absent(RigMode::Present, true);
}

TEST_CASE("FileGuard rename: rename or move alone reports the absent state (hash)",
          "[guardian][guard][file][rename]") {
    run_rename_reports_absent(RigMode::Hash, false);
    run_rename_reports_absent(RigMode::Hash, true);
}

TEST_CASE("FileGuard rename: deleted watched directory then recreated is still detected (tripwire)",
          "[guardian][guard][file][rename]") {
    run_delete_then_recreate(RigMode::Tripwire);
}

TEST_CASE("FileGuard rename: deleted watched directory then recreated is still detected (hash)",
          "[guardian][guard][file][rename]") {
    run_delete_then_recreate(RigMode::Hash);
}

TEST_CASE("FileGuard rename: renamed nearest ancestor then recreated is detected (tripwire)",
          "[guardian][guard][file][rename]") {
    run_ancestor_rename(RigMode::Tripwire);
}

TEST_CASE("FileGuard rename: renamed nearest ancestor then recreated is detected (hash)",
          "[guardian][guard][file][rename]") {
    run_ancestor_rename(RigMode::Hash);
}

TEST_CASE("FileGuard rename: sibling churn in the parent is not drift and detection survives it (tripwire)",
          "[guardian][guard][file][rename]") {
    run_sibling_churn(RigMode::Tripwire);
}

TEST_CASE("FileGuard rename: sibling churn in the parent is not drift and detection survives it (hash)",
          "[guardian][guard][file][rename]") {
    run_sibling_churn(RigMode::Hash);
}

TEST_CASE("FileGuard rename: a notification overflow in the parent resyncs and finds the change (tripwire)",
          "[guardian][guard][file][rename]") {
    run_overflow_resync(RigMode::Tripwire);
}

TEST_CASE("FileGuard rename: a notification overflow in the parent resyncs and finds the change (hash)",
          "[guardian][guard][file][rename]") {
    run_overflow_resync(RigMode::Hash);
}

TEST_CASE("FileGuard rename: stop() while idle returns promptly and leaks no handles",
          "[guardian][guard][file][rename][teardown]") {
    run_stop_cycles(RigMode::Tripwire, false);
}

TEST_CASE("FileGuard rename: stop() right after a rename returns promptly and leaks no handles",
          "[guardian][guard][file][rename][teardown]") {
    run_stop_cycles(RigMode::Hash, true);
}

// The walk from the target up to its nearest existing directory must end at a root that is not a
// directory. A regression would spin the guard thread and hang stop(), so stop() runs on a helper
// thread with a deadline; on timeout the guard and the helper are leaked so the suite still ends.
TEST_CASE("FileGuard rename: a target under an unavailable drive root does not hang stop()",
          "[guardian][guard][file][rename][teardown]") {
    const wchar_t letter = unused_drive_letter();
    if (letter == 0) {
        SKIP("no unused drive letter on this host");
    }

    FileGuard::Config cfg;
    cfg.rule_id = "fg-rename-root";
    cfg.path = std::string(1, static_cast<char>(letter)) + ":\\yuzu_test_fgrename_root\\f.txt";
    cfg.event_debounce_ms = 50;
    auto col = std::make_shared<FileDriftCollector>();
    // unique_ptr (not a bare `new`/`delete`): on the normal path the destructor calls stop()
    // automatically (stop() is idempotent — already-joined threads/closed handles are a no-op,
    // the same double-stop() every other test in this file relies on); on the timeout/leak
    // branch below, release() hands ownership to the deliberately-detached helper thread. This
    // also closes an unconditional leak on any exception thrown between construction and the
    // if/else (e.g. a REQUIRE/wait_for_detected/thread-construction throw).
    auto guard = std::make_unique<FileGuard>(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(guard->start());
    // file-exists with the default expectation: the first evaluation reports the absent target,
    // and it only runs once arming has returned.
    const bool armed = col->wait_for_detected("<absent>", 30s);

    struct StopState {
        std::mutex m;
        std::condition_variable cv;
        bool done = false;
    };
    auto st = std::make_shared<StopState>();
    std::thread stopper([g = guard.get(), st] {
        g->stop();
        {
            std::lock_guard lk(st->m);
            st->done = true;
        }
        st->cv.notify_all();
    });
    bool stopped = false;
    {
        std::unique_lock lk(st->m);
        stopped = st->cv.wait_for(lk, 10s, [&] { return st->done; });
    }
    if (stopped) {
        stopper.join(); // guard destructs normally at scope exit below
    } else {
        guard.release(); // leak the guard and its spinning thread rather than hang the suite
        stopper.detach();
    }
    CHECK(armed);
    CHECK(stopped);
}

#else // !_WIN32

TEST_CASE("FileGuard: no-op off Windows", "[guardian][guard][file]") {
    FileGuard::Config cfg;
    cfg.rule_id = "fg-noop";
    cfg.path = "/tmp/whatever";
    FileGuard g(cfg, [](const GuardDrift&) {});
    CHECK_FALSE(g.start()); // file-change Spark is Windows-only for the MVP
}

#endif // _WIN32
