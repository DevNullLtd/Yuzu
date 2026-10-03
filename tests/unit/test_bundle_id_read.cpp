/**
 * test_bundle_id_read.cpp -- yuzu::agent::read_bundle_ids_bounded.
 *
 * Load-bearing cases: a reader that NEVER returns still gives the caller its
 * thread back (TimedOut + partial ids), blocks further passes (Busy, asserted
 * by ordering -- the Busy call returns before the gate is released), and a
 * Rejected admission does not leave the in-flight flag set.
 *
 * The Rejected case instantiates the header-only driver in THIS image with a
 * test-owned flag: the outstanding-call ceiling is per image (see
 * keychain_read.hpp), so saturating it from here cannot reach agent-core's
 * copy used by read_bundle_ids_bounded_for_test.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/bundle_id_read.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::BundleIdPassResult;
using yuzu::agent::BundleIdPassStatus;
using yuzu::agent::read_bundle_ids_bounded_for_test;

TEST_CASE("read_bundle_ids_bounded completes with ids aligned to paths", "[bundle_id][agent]") {
    const std::vector<std::string> paths{"/a", "/b", "/c"};
    auto r = read_bundle_ids_bounded_for_test(paths, 5000ms,
                                              [](const std::string& p) { return "com.x." + p; });
    REQUIRE(r.status == BundleIdPassStatus::Completed);
    REQUIRE(r.ids.size() == 3);
    CHECK(r.ids[0] == "com.x./a");
    CHECK(r.ids[2] == "com.x./c");
    CHECK(r.read_count == 3);
}

TEST_CASE("a blocked reader times out with a partial snapshot, then Busy, then recovers",
          "[bundle_id][agent]") {
    std::promise<void> gate;
    // Opens the gate on scope exit if the test did not: a failing REQUIRE must not
    // leave a worker wedged forever (it would hold the process-wide in-flight flag
    // and turn every later test into Busy). Declared AFTER the promise it opens.
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    yuzu::test::ScopeExit opener{release};
    // The abandoned worker outlives this scope on failure: everything it touches
    // is captured BY VALUE (shared state), never by reference to the stack.
    auto gate_f = gate.get_future().share();
    auto b_entered = std::make_shared<std::promise<void>>();
    auto b_entered_f = b_entered->get_future();

    const std::vector<std::string> paths{"/a", "/b"};
    auto r = read_bundle_ids_bounded_for_test(
        paths, 500ms, [gate_f, b_entered](const std::string& p) -> std::string {
            if (p == "/b") {
                b_entered->set_value();
                gate_f.wait();
                return {};
            }
            return "com.x.a";
        });
    CHECK(r.status == BundleIdPassStatus::TimedOut);
    REQUIRE(r.ids.size() == 2);
    CHECK(r.ids[1].empty());
    // Whether the worker reached /b inside the 500ms budget depends on the
    // scheduler; assert the snapshot's content only for the progress it shows.
    // (Wait for /b so the later Busy case is deterministic either way.)
    REQUIRE(b_entered_f.wait_for(10s) == std::future_status::ready);
    CHECK(r.read_count <= 1);
    if (r.read_count == 1)
        CHECK(r.ids[0] == "com.x.a");

    // Worker still wedged: Busy, and it returns while the gate is still shut.
    auto busy = read_bundle_ids_bounded_for_test(paths, 5000ms, [](const std::string&) { return "x"; });
    CHECK(busy.status == BundleIdPassStatus::Busy);
    CHECK(busy.read_count == 0);
    CHECK(busy.ids.size() == paths.size());
    // Admission outranks a spent budget: Busy, not TimedOut.
    auto busy0 = read_bundle_ids_bounded_for_test(paths, 0ms, [](const std::string&) { return "x"; });
    CHECK(busy0.status == BundleIdPassStatus::Busy);
    CHECK(gate_f.wait_for(0ms) == std::future_status::timeout);

    release();
    BundleIdPassResult again;
    REQUIRE(yuzu::test::spin_until(
        [&] {
            again = read_bundle_ids_bounded_for_test(
                paths, 5000ms, [](const std::string& p) { return "com.y." + p; });
            return again.status != BundleIdPassStatus::Busy;
        },
        10s));
    CHECK(again.status == BundleIdPassStatus::Completed);
    CHECK(again.ids[1] == "com.y./b");

    // Free flag + spent budget: TimedOut, and the flag is not left claimed.
    auto spent = read_bundle_ids_bounded_for_test(paths, 0ms, [](const std::string&) { return "x"; });
    CHECK(spent.status == BundleIdPassStatus::TimedOut);
    auto after = read_bundle_ids_bounded_for_test(paths, 5000ms, [](const std::string&) { return "z"; });
    CHECK(after.status == BundleIdPassStatus::Completed);
}

TEST_CASE("a Rejected admission releases the in-flight flag", "[bundle_id][agent]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;

    // Starts from zero outstanding calls in this image (sibling tests' guards
    // are released on their own threads shortly after they finish).
    REQUIRE(yuzu::test::spin_until([] { return g_outstanding_bounded_calls.load() == 0; }, 10s));

    static std::atomic_flag flag; // outlives any worker
    std::promise<void> gate;
    // Opens the gate on scope exit if the test did not: a failing REQUIRE must not
    // leave a worker wedged forever (it would hold the process-wide in-flight flag
    // and turn every later test into Busy). Declared AFTER the promise it opens.
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    yuzu::test::ScopeExit opener{release};
    auto gate_f = gate.get_future().share();
    for (int i = 0; i < kMaxOutstandingBoundedCalls; ++i) {
        auto parked = yuzu::shared::bounded_call_ex(1ms, [gate_f]() -> bool {
            gate_f.wait();
            return true;
        });
        REQUIRE(parked.status == yuzu::shared::BoundedCallStatus::TimedOut);
    }

    // By-value shared state: a worker abandoned by a failing assertion must not
    // touch this stack frame.
    auto entered = std::make_shared<std::atomic<bool>>(false);
    const std::vector<std::string> paths{"/a"};
    auto reader = [entered](const std::string& p) -> std::string {
        *entered = true;
        return "com.x." + p;
    };
    auto rej = yuzu::agent::detail::bounded_bundle_id_pass(flag, paths, 1000ms, reader);
    CHECK(rej.status == BundleIdPassStatus::Rejected);
    CHECK(rej.ids.size() == paths.size()); // path-aligned, like Busy
    CHECK_FALSE(entered->load());

    release();
    REQUIRE(yuzu::test::spin_until([] { return g_outstanding_bounded_calls.load() == 0; }, 10s));

    // Flag was released on Rejected: a Busy here means the clear was lost.
    auto ok = yuzu::agent::detail::bounded_bundle_id_pass(flag, paths, 5000ms, reader);
    CHECK(ok.status == BundleIdPassStatus::Completed);
    REQUIRE(ok.ids.size() == 1);
    CHECK(ok.ids[0] == "com.x./a");
}

#if defined(__APPLE__)
// A minimal fixture bundle (Contents/Info.plist only) keeps the case independent
// of which system apps this macOS release ships.
TEST_CASE("real reader resolves a fixture bundle's identifier", "[bundle_id][agent]") {
    yuzu::test::TempDir dir("yuzu_test_bundle_");
    const auto app = dir.path / "Fixture.app";
    std::filesystem::create_directories(app / "Contents");
    std::ofstream(app / "Contents" / "Info.plist")
        << R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.yuzu.test.fixture</string>
<key>CFBundleName</key><string>Fixture</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
)";
    auto r = yuzu::agent::read_bundle_ids_bounded({app.string()}, 10000ms);
    REQUIRE(r.status == BundleIdPassStatus::Completed);
    REQUIRE(r.ids.size() == 1);
    CHECK(r.ids[0] == "com.yuzu.test.fixture");
}
#endif
