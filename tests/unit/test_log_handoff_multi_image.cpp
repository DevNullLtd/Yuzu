// test_log_handoff_multi_image.cpp - #4666 PR-2 W3a: the macOS multi-image open
// question. log_handoff.hpp's own MULTI-IMAGE note records Linux as CONFIRMED (by
// symbol inspection) to share one spdlog registry across the exe, libyuzu_agent_core,
// and every plugin image; Windows is INFERRED to do the same from its dynamic spdlog
// linkage, not directly measured; macOS was the open question at the time this file was
// written. This file IS the fixture that closed it: it runs the identical measurement
// on every platform the suite executes on (this binary carries no platform gate, so it
// also runs on Windows CI, though its Windows output has not itself been reviewed to
// turn it into a confirmed finding the way the Linux/macOS runs were), and the macOS run
// is a genuine empirical observation (see docs/darwin-compat.md's "spdlog registry
// identity across images" row: TWO separate registries there), not an inference.
//
// MI-1: correctness of install_log_handoff_in_this_image()/
// release_log_handoff_from_this_image() across this test binary's own image, PLUS a FIRST
// measurement - does a call compiled into THIS test binary's image and a call compiled
// into libyuzu_agent_core.so's image (log_handoff_emit_probe_for_test(), log_handoff.hpp)
// both land in the same capture sink once install_log_handoff_in_this_image() has run?
// IMPORTANT: this measurement alone does NOT distinguish "one shared registry" from "two
// separate registries, each independently pointed at the same logger by
// install_log_handoff_in_this_image()'s own redundant same-image call" - see MI-1b below,
// which is the test that actually discriminates the two.
//
// MI-1b: the actual topology discriminator - isolates LogHandoff::install()/teardown()'s
// OWN, library-only effect from agent_log_wiring.hpp's exe-image half, answering the
// question this whole fixture exists for: is that exe-image half load-bearing, or a
// defensive no-op?
//
// MI-3: a REAL agent_actions plugin dispatch measures the same question from a THIRD
// image (a loaded plugin .so/.dylib/.dll) via a production code path: its real
// set_log_level action calls the raw, registry-wide spdlog::set_level() API
// (agent_actions_plugin.cpp's do_set_log_level()).
//
// Neither REQUIREs the "shared" outcome for the topology question itself - the whole
// point of this file is to OBSERVE a property it cannot know in advance for every
// platform it runs on. Only HELPER correctness (a same-image call reaching the sink,
// teardown destroying the sink, level filtering working) is REQUIRE'd; the topology
// verdict is recorded via INFO/WARN and written to a report file (see
// write_topology_report() below) so it survives the test run for later inspection.

#include "agent_log_wiring.hpp"
#include "local_dispatcher.hpp"
#include "log_handoff.hpp"

#include "log_handoff_test_sinks.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::install_log_handoff_in_this_image;
using yuzu::agent::LogHandoff;
using yuzu::agent::log_handoff_emit_probe_for_test;
using yuzu::agent::release_log_handoff_from_this_image;
using yuzu::test::GatedCaptureSink;

namespace fs = std::filesystem;

namespace {

// Writes `text` to <build-root>/log_handoff_multi_image_topology.txt so MI-1's
// measurement survives past this test run. MESON_BUILD_ROOT is a real env var meson's
// own test runner sets (not a project convention invented here) - already relied on by
// this directory's find_users_plugin()-style helpers (see test_users_posix_actions.cpp).
// Falls back to the current working directory when unset (e.g. a direct, non-`meson
// test` invocation of this binary) - verified empirically that `meson test` itself runs
// with CWD == build root, so the fallback lands in the same place MESON_BUILD_ROOT
// would point to anyway.
//
// Catch2 does not run TEST_CASEs in source-declaration order (randomized by default in
// this suite), and MI-1/MI-1b/MI-3 each contribute their own section to this one report
// file - so the FIRST call in a given process truncates (clearing stale content left by
// an earlier `meson test` run), and every call after that appends, regardless of which
// TEST_CASE happens to run first.
void write_topology_report(const std::string& text) {
    fs::path out_dir;
    if (const auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        out_dir = fs::path{build_root};
    else
        out_dir = fs::current_path();

    std::error_code ec;
    fs::create_directories(out_dir, ec); // no-op if it already exists; ignore failure -
                                          // the ofstream open below is the real check.

    static bool truncated_once = false;
    const auto mode = truncated_once ? std::ios::app : std::ios::trunc;
    truncated_once = true;

    std::ofstream out{out_dir / "log_handoff_multi_image_topology.txt", mode};
    if (out)
        out << text;
}

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#elif defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin() - same candidate-path
// fallback list, pointed at the agent_actions plugin's own build output. Empty path
// (never a hard failure) when not found, so a build without agent plugins skips MI-3
// rather than failing.
fs::path find_agent_actions_plugin() {
    const std::string lib_name = std::string{"agent_actions"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (const auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "agent_actions" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "agent_actions" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// MI-1
// ---------------------------------------------------------------------------

TEST_CASE("MI-1: install_log_handoff_in_this_image/release_log_handoff_from_this_image "
          "round-trip in this image, and the cross-image topology measurement itself",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto closed = sink->closed_flag();

    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::info, /*json_format=*/false));

    // ---- Topology measurement --------------------------------------------------
    // "from library image" executes INSIDE libyuzu_agent_core's own compiled image -
    // log_handoff_emit_probe_for_test() is defined in log_handoff.cpp (spdlog::info()
    // called from THAT translation unit). "from test image" executes inside THIS test
    // binary's own image - a plain spdlog::info() call compiled directly into this TU.
    log_handoff_emit_probe_for_test("from library image");
    spdlog::info("from test image");

    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));

    const auto snap = sink->snapshot();
    bool saw_library_line = false;
    bool saw_test_line = false;
    for (const auto& c : snap) {
        if (c.payload == "from library image")
            saw_library_line = true;
        if (c.payload == "from test image")
            saw_test_line = true;
    }

    // The test-image line MUST reach the sink: install_log_handoff_in_this_image() just
    // set THIS image's default logger to h's logger, and the spdlog::info() call above
    // ran in this same image/TU. A failure here means the HELPER is broken, not that the
    // topology answer is "separate" - fail loudly rather than fold it into the
    // observational verdict below.
    REQUIRE(saw_test_line);

    // IMPORTANT CAVEAT (found while writing this file's own report - see MI-1b below):
    // install_log_handoff_in_this_image() does not ONLY call LogHandoff::install()
    // (which runs inside libyuzu_agent_core's own image and touches only THAT image's
    // registry) - it ALSO makes its own, SEPARATE, redundant spdlog::set_default_logger(lg)
    // call, which is header-only and therefore executes physically inside THIS CALLING
    // image, touching THIS image's OWN registry if it is a different object. That second
    // call means "both lines reach the sink" is GUARANTEED by install_log_handoff_in_this_image()'s
    // own design REGARDLESS of whether there are one or two registry objects underneath -
    // it does NOT by itself discriminate the two topologies. MI-1b below is the test that
    // actually discriminates them, by calling LogHandoff::install() directly (bypassing
    // the redundant call) and by tearing down without the exe-image swap.
    std::string finding;
    if (saw_library_line && saw_test_line) {
        finding = "both the library-image probe and the test-image call reached the same "
                  "capture sink after install_log_handoff_in_this_image() ran (does NOT by "
                  "itself distinguish one shared registry from two separately-installed "
                  "ones - see MI-1b)";
    } else if (saw_test_line && !saw_library_line) {
        finding = "the test-image call reached the capture sink but the library-image "
                  "probe did not - unexpected given install_log_handoff_in_this_image()'s "
                  "own design (LogHandoff::install() itself, which runs in the library "
                  "image, already points that image's registry at the same logger); "
                  "investigate before trusting this result";
    } else {
        finding = "neither line landed as expected - see the raw capture below";
    }

    INFO("MI-1 finding: " << finding);
    WARN("MI-1 finding: " << finding);

    std::string report = "#4666 PR-2 W3a MI-1 measurement (see MI-1b for the topology verdict)\n";
    report += "saw_library_line=" + std::string(saw_library_line ? "true" : "false") + "\n";
    report += "saw_test_line=" + std::string(saw_test_line ? "true" : "false") + "\n";
    report += "finding: " + finding + "\n";
    report += "raw capture (" + std::to_string(snap.size()) + " line(s)):\n";
    for (const auto& c : snap)
        report += "  - " + c.payload + "\n";
    write_topology_report(report);

    // ---- Teardown / R-LOGGER regression tripwire --------------------------------
    sink.reset(); // drop OUR reference - the only remaining owner is h's own
                  // wrapped_sinks_, so release_log_handoff_from_this_image()'s
                  // teardown() (T3) is what actually destroys the GatedCaptureSink.
    release_log_handoff_from_this_image(*h);
    REQUIRE(closed->load(std::memory_order_acquire));
}

TEST_CASE("MI-1: install_log_handoff_in_this_image applies the level - a below-level "
          "line never reaches the sink, an at-level line does",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*h); }};

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::warn, /*json_format=*/false));

    spdlog::info("below-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));
    CHECK(sink->count() == 0);

    spdlog::warn("at-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return sink->count() == 1; }, 2s));
    const auto snap = sink->snapshot();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].payload == "at-the-installed-level");
}

// ---------------------------------------------------------------------------
// MI-1b: the actual topology discriminator.
//
// MI-1 above cannot by itself distinguish "one shared registry" from "two separate
// registries, each independently pointed at the same logger by design" -
// install_log_handoff_in_this_image() ALWAYS makes its own redundant, same-image
// spdlog::set_default_logger(lg) call IN ADDITION TO LogHandoff::install()'s own internal
// one (see agent_log_wiring.hpp's own comment on that redundancy), so "both lines reach
// the sink" is guaranteed by that design regardless of the underlying topology. These two
// cases isolate LogHandoff::install()/teardown()'s OWN, library-only effect from
// agent_log_wiring.hpp's exe-image half, to answer the actual question this fixture
// exists for: is that exe-image half load-bearing, or a defensive no-op?
// ---------------------------------------------------------------------------

TEST_CASE("MI-1b(a): does LogHandoff::install() ALONE (bypassing the exe-image redundant "
          "spdlog::set_default_logger call) make a same-image spdlog::info() reach the sink?",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*h); }};

    {
        auto lg = h->install(); // R-LOGGER: this returned reference is dropped at the end
                                 // of this scope, never held past it (agent_log_wiring.hpp's
                                 // own rule) - deliberately NOT calling
                                 // install_log_handoff_in_this_image() here, which would
                                 // additionally make its own same-image
                                 // spdlog::set_default_logger(lg) call and defeat the whole
                                 // point of this measurement.
        REQUIRE(lg != nullptr);
        lg->set_level(spdlog::level::info);
    }

    const bool same_default_ptr = (spdlog::default_logger_raw() == h->logger().get());

    spdlog::info("MI-1b(a) probe line");
    const bool reached = yuzu::test::spin_until([&] { return sink->count() >= 1; }, 2s);

    std::string verdict;
    if (same_default_ptr && reached) {
        verdict = "ONE registry (or at least this image's default-logger pointer already "
                  "aliases the library's): LogHandoff::install() ALONE, with no exe-image "
                  "redundant call, was enough for this image's own spdlog::info() to reach "
                  "the sink";
    } else {
        verdict = "TWO (or more) registries: LogHandoff::install() alone did NOT route this "
                  "image's own spdlog::info() to the sink (same_default_ptr=" +
                  std::string(same_default_ptr ? "true" : "false") +
                  ", reached=" + std::string(reached ? "true" : "false") +
                  ") - install_log_handoff_in_this_image()'s redundant exe-image "
                  "spdlog::set_default_logger() call is what makes that work in production";
    }
    WARN("MI-1b(a) verdict: " << verdict);

    std::string report = "#4666 PR-2 W3a MI-1b(a) measurement\n";
    report += "same_default_ptr=" + std::string(same_default_ptr ? "true" : "false") + "\n";
    report += "reached=" + std::string(reached ? "true" : "false") + "\n";
    report += "verdict: " + verdict + "\n";
    write_topology_report(report);
}

TEST_CASE("MI-1b(b): with the exe-image swap skipped, does a bare LogHandoff::teardown() "
          "alone already destroy the sink, or does this image's own registry keep it alive?",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto closed = sink->closed_flag();

    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::info, /*json_format=*/false));
    sink.reset(); // drop OUR reference - see MI-1's own comment on the same pattern.

    // Deliberately call LogHandoff::teardown() DIRECTLY, bypassing
    // release_log_handoff_from_this_image()'s own exe-image spdlog::set_default_logger(null
    // sink) swap. teardown() is a real, exported LogHandoff member compiled in
    // log_handoff.cpp - it can only ever touch the registry IT physically runs in (the
    // library's own, per log_handoff.hpp's own T2 comment), never this calling image's
    // separate registry entry (if one exists) that install_log_handoff_in_this_image()'s
    // earlier redundant call created.
    h->teardown();

    const bool closed_after_bare_teardown = closed->load(std::memory_order_acquire);

    std::string verdict;
    if (closed_after_bare_teardown) {
        verdict = "a bare h->teardown() (library-only, no exe-image swap) ALREADY destroyed "
                  "the sink - the exe-image logger swap in "
                  "release_log_handoff_from_this_image() looks REDUNDANT (a defensive no-op) "
                  "on this platform";
    } else {
        verdict = "a bare h->teardown() did NOT destroy the sink - this image's OWN registry "
                  "still held a live reference to the logger (and therefore its sinks) after "
                  "the library-only teardown ran; the exe-image logger swap in "
                  "release_log_handoff_from_this_image() is LOAD-BEARING on this platform, "
                  "confirmed below by observing it actually finish the job";
    }
    WARN("MI-1b(b) verdict (before exe-image swap): " << verdict);

    // Finish the real shutdown sequence the same way main.cpp's LogHandoffEpilogue does -
    // teardown() on an already-torn-down instance is documented idempotent (a no-op), so
    // this call's only NEW effect (if any) is release_log_handoff_from_this_image()'s own
    // same-image spdlog::set_default_logger(null sink) swap.
    release_log_handoff_from_this_image(*h);
    REQUIRE(closed->load(std::memory_order_acquire));

    std::string report =
        "#4666 PR-2 W3a MI-1b(b) measurement (the direct load-bearing-vs-no-op answer)\n";
    report += "closed_after_bare_teardown=" +
              std::string(closed_after_bare_teardown ? "true" : "false") + "\n";
    report += "closed_after_exe_image_swap=true (REQUIRE'd above)\n";
    report += "verdict: " + verdict + "\n";
    write_topology_report(report);
}

// ---------------------------------------------------------------------------
// MI-3
// ---------------------------------------------------------------------------
//
// do_set_log_level() (agent_actions_plugin.cpp) calls the raw, registry-wide
// spdlog::set_level() API, which (per spdlog::details::registry::set_level()) walks
// registry::loggers_ and changes every ALREADY-REGISTERED logger's level - it only has
// any effect on this test's installed LogHandoff logger if the plugin's own
// spdlog::set_level() call resolves against the SAME registry this test installed into.

TEST_CASE("MI-3: dispatching agent_actions's real set_log_level action against a loaded "
          "plugin image measures whether it reaches this image's installed LogHandoff",
          "[log_handoff][multi_image]") {
    auto plugin_path = find_agent_actions_plugin();
    if (plugin_path.empty()) {
        WARN("agent_actions plugin library not found -- skipping MI-3");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value()) {
        WARN("agent_actions plugin failed to load -- skipping MI-3");
        return;
    }
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    // Governance hardening round, plugin-developer finding: do_set_log_level() below
    // calls the RAW, REGISTRY-WIDE spdlog::set_level() -- not scoped to this test's own
    // LogHandoff instance -- so it persists past this test case's own teardown and into
    // whichever test Catch2's randomized order runs next in this same process. Snapshot
    // and restore it regardless of outcome (the plugin's call can mutate the global
    // default even on the "did NOT reach this image" branch below, if it lands on a
    // registry this image doesn't read from but a LATER test's install() still would).
    const auto original_level = spdlog::get_level();
    yuzu::test::ScopeExit restore_level_on_exit{[original_level] { spdlog::set_level(original_level); }};

    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*h); }};

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::info, /*json_format=*/false));

    // Baseline: a debug line does NOT reach the sink at the installed 'info' level.
    spdlog::debug("before-dispatch-debug-line");
    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));
    CHECK(sink->count() == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"level", "debug"}};
    auto dispatch_result = dispatcher.run(descriptor, "set_log_level", params);
    CHECK(dispatch_result.rc == 0);

    // The actual measurement: did the plugin's own spdlog::set_level(debug) call reach
    // this image's installed logger? Recorded, not asserted either way - see the file
    // banner.
    spdlog::debug("after-dispatch-debug-line");
    const bool debug_reached = yuzu::test::spin_until([&] { return sink->count() >= 1; }, 2s);

    if (debug_reached) {
        WARN("MI-3: agent_actions's set_log_level(debug) DID change this image's "
             "installed LogHandoff level -- the plugin's spdlog::set_level() call "
             "reached this image's registered logger");
    } else {
        WARN("MI-3: agent_actions's set_log_level(debug) did NOT change this image's "
             "installed LogHandoff level -- a known possible/historical outcome (#3355): "
             "the plugin image may hold its own separate registry");
    }
}
