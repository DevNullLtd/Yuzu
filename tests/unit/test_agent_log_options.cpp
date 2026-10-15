// test_agent_log_options.cpp -- unit coverage for make_log_handoff_options (#4666
// PR-2, agents/core/src/agent_log_options.hpp), the pure translator from main.cpp's
// already-parsed CLI flags to LogHandoff::Options.
//
// Pure-function tests for (a)-(d): no I/O, no LogHandoff constructed. (e)/(e2) exercise
// the pinned negative-conversion behaviour, the second one feeding the translated
// Options into the real LogHandoff::create() to prove the translation actually
// triggers create()'s documented console-fallback path.

#include "agent_log_options.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <limits>

using namespace std::chrono_literals;
using yuzu::agent::AgentLogCli;
using yuzu::agent::LogHandoff;
using yuzu::agent::make_log_handoff_options;

TEST_CASE("make_log_handoff_options: no file, console mode -> nullopt, defaults pass "
          "through",
          "[agent][log-options]") {
    // main.cpp's own --log-max-size/--log-max-files CLI defaults (50 MB / 5 files,
    // main.cpp:323-324), fed through unmodified -- and cross-checked below against
    // LogHandoff::Options's OWN defaults, which its doc comment says match these on
    // purpose (log_handoff.hpp:464-468).
    AgentLogCli cli{
        .log_file = "",
        .log_max_size = 50 * 1024 * 1024,
        .log_max_files = 5,
        .service_mode = false,
        .data_dir = "/var/lib/yuzu-agent",
    };
    const auto opts = make_log_handoff_options(cli);

    CHECK_FALSE(opts.log_file.has_value());
    CHECK(opts.log_max_size == LogHandoff::Options{}.log_max_size);
    CHECK(opts.log_max_files == LogHandoff::Options{}.log_max_files);
    CHECK_FALSE(opts.service_mode);
}

TEST_CASE("make_log_handoff_options: explicit --log-file, console mode -> that path, "
          "service_mode false",
          "[agent][log-options]") {
    AgentLogCli cli{
        .log_file = "/tmp/explicit-agent.log",
        .log_max_size = 10 * 1024 * 1024,
        .log_max_files = 3,
        .service_mode = false,
        .data_dir = "/var/lib/yuzu-agent",
    };
    const auto opts = make_log_handoff_options(cli);

    REQUIRE(opts.log_file.has_value());
    CHECK(*opts.log_file == std::filesystem::path{"/tmp/explicit-agent.log"});
    CHECK_FALSE(opts.service_mode);
    CHECK(opts.log_max_size == 10 * 1024 * 1024u);
    CHECK(opts.log_max_files == 3u);
}

TEST_CASE("make_log_handoff_options: service_mode with empty --log-file defaults under "
          "data_dir",
          "[agent][log-options]") {
    AgentLogCli cli{
        .log_file = "",
        .log_max_size = 50 * 1024 * 1024,
        .log_max_files = 5,
        .service_mode = true,
        .data_dir = "/var/lib/yuzu-agent",
    };
    const auto opts = make_log_handoff_options(cli);

    REQUIRE(opts.log_file.has_value());
    CHECK(*opts.log_file == std::filesystem::path{"/var/lib/yuzu-agent"} / "yuzu-agent.log");
    CHECK(opts.service_mode);
}

TEST_CASE("make_log_handoff_options: service_mode with explicit --log-file wins over "
          "the default",
          "[agent][log-options]") {
    AgentLogCli cli{
        .log_file = "/custom/path/agent.log",
        .log_max_size = 50 * 1024 * 1024,
        .log_max_files = 5,
        .service_mode = true,
        .data_dir = "/var/lib/yuzu-agent",
    };
    const auto opts = make_log_handoff_options(cli);

    REQUIRE(opts.log_file.has_value());
    CHECK(*opts.log_file == std::filesystem::path{"/custom/path/agent.log"});
    CHECK(opts.service_mode);
}

TEST_CASE("make_log_handoff_options: a negative --log-max-files pins today's "
          "int->std::size_t conversion (SIZE_MAX, not 32-bit wraparound)",
          "[agent][log-options]") {
    AgentLogCli cli{
        .log_file = "/tmp/agent.log",
        .log_max_size = 50 * 1024 * 1024,
        .log_max_files = -1,
        .service_mode = false,
        .data_dir = "/var/lib/yuzu-agent",
    };
    const auto opts = make_log_handoff_options(cli);

    // Per [conv.integral], converting -1 to std::size_t is value-mod-2^64, i.e.
    // SIZE_MAX -- not the 0xFFFFFFFF a reader might expect from "int to unsigned"
    // folklore. This is the exact value main.cpp's --log-max-files forwards to
    // rotating_file_sink_mt's ctor today; pinned here, not "fixed", per the header's
    // own doc comment.
    CHECK(opts.log_max_files == std::numeric_limits<std::size_t>::max());
}

TEST_CASE("make_log_handoff_options: the pinned SIZE_MAX conversion actually triggers "
          "LogHandoff::create()'s documented console-fallback path",
          "[agent][log-options]") {
    yuzu::test::TempDir dir{"yuzu_test_agent_log_options_"};
    std::filesystem::create_directories(dir.path);

    AgentLogCli cli{
        .log_file = (dir.path / "agent.log").string(),
        .log_max_size = 50 * 1024 * 1024,
        .log_max_files = -1,
        .service_mode = false,
        .data_dir = dir.path,
    };
    const auto opts = make_log_handoff_options(cli);
    REQUIRE(opts.log_max_files == std::numeric_limits<std::size_t>::max());

    auto result = LogHandoff::create(opts);
    REQUIRE(result.has_value()); // construction still succeeds -- console fallback,
                                  // not a hard failure (same 1.7 carve-out as U7b)
    auto handoff = std::move(*result);
    CHECK(handoff->used_log_file_fallback());
    CHECK_FALSE(handoff->log_file_fallback_reason().empty());
    // Nothing was ever written under dir.path -- rotating_file_sink_mt's ctor throws
    // its MaxFiles check before file_helper_.open() runs.
    CHECK_FALSE(std::filesystem::exists(dir.path / "agent.log"));

    handoff->teardown_with_action_for_test(2s, [] {});
}
