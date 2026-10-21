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
#if defined(__APPLE__)
#include <yuzu/agent/cf_bundle_id.hpp>
#include <yuzu/agent/scoped_cfref.hpp>
#endif

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <stdexcept>
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

TEST_CASE("a throwing reader records no identifier, the pass completes and the flag is released",
          "[bundle_id][agent]") {
    static std::atomic_flag flag; // static: outlives any worker, like agent-core's own
    const std::vector<std::string> paths{"/a", "/b"};
    const auto throwing = [](const std::string& p) -> std::string {
        if (p == "/b")
            throw std::runtime_error("reader failed");
        return "com.x." + p;
    };
    const auto r = yuzu::agent::detail::bounded_bundle_id_pass(flag, paths, 5000ms, throwing);
    REQUIRE(r.status == BundleIdPassStatus::Completed);
    REQUIRE(r.ids.size() == 2);
    CHECK(r.ids[0] == "com.x./a");
    CHECK(r.ids[1].empty());
    CHECK(r.read_count == 2);

    // The Releaser ran: a Busy here means the flag stayed set after the throw.
    const auto again = yuzu::agent::detail::bounded_bundle_id_pass(
        flag, paths, 5000ms, [](const std::string& p) { return "com.x." + p; });
    CHECK(again.status == BundleIdPassStatus::Completed);
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

TEST_CASE("cfstring_to_utf8 bounds a hostile identifier at 4 KiB on a UTF-8 boundary",
          "[bundle_id][agent]") {
    const auto convert = [](const std::string& utf8) {
        yuzu::agent::ScopedCFRef<CFStringRef> s(CFStringCreateWithCString(
            nullptr, utf8.c_str(), kCFStringEncodingUTF8));
        REQUIRE(s);
        return yuzu::agent::cfstring_to_utf8(s.get());
    };
    CHECK(convert(std::string(10000, 'a')).size() == yuzu::agent::kMaxCFStringBytes);

    std::string euros;
    for (int i = 0; i < 3000; ++i)
        euros += "\xE2\x82\xAC"; // U+20AC, 3 bytes: 4096 cuts mid-character
    const auto cut = convert(euros);
    CHECK(cut.size() == 4095);
    CHECK(cut == euros.substr(0, 4095));

    CHECK(convert("com.x.y") == "com.x.y");

    // Unconvertible (a lone surrogate) stays "": stopping there is not the bound.
    const UniChar lone[] = {'a', 0xD800, 'b'};
    yuzu::agent::ScopedCFRef<CFStringRef> bad(CFStringCreateWithCharacters(nullptr, lone, 3));
    REQUIRE(bad);
    CHECK(yuzu::agent::cfstring_to_utf8(bad.get()).empty());
}

// Near-cap boundary (kMaxCFStringBytes == 4096). With < 4 bytes free CF's stop is not
// attributable to a bad character, so the whole-character prefix is returned.
TEST_CASE("cfstring_to_utf8 near the 4 KiB cap", "[bundle_id][agent]") {
    const auto convert = [](const std::string& utf8) {
        yuzu::agent::ScopedCFRef<CFStringRef> s(CFStringCreateWithCString(
            nullptr, utf8.c_str(), kCFStringEncodingUTF8));
        REQUIRE(s);
        return yuzu::agent::cfstring_to_utf8(s.get());
    };
    // 'a' x n then one lone surrogate.
    const auto with_lone_surrogate = [](std::size_t n) {
        std::vector<UniChar> chars(n, 'a');
        chars.push_back(0xD800);
        yuzu::agent::ScopedCFRef<CFStringRef> s(CFStringCreateWithCharacters(
            nullptr, chars.data(), static_cast<CFIndex>(chars.size())));
        REQUIRE(s);
        return yuzu::agent::cfstring_to_utf8(s.get());
    };

    // Exact fit.
    CHECK(convert(std::string(4096, 'a')).size() == 4096);

    // A 4-byte character with 3 bytes free does not fit: the 4093-byte prefix, not "".
    const auto emoji = convert(std::string(4093, 'a') + "\xF0\x9F\x98\x80"); // U+1F600
    CHECK(emoji.size() == 4093);
    CHECK(emoji == std::string(4093, 'a'));

    // Lone surrogate with >= 4 bytes free is unconvertible, not the bound: "".
    CHECK(with_lone_surrogate(4090).empty());
    CHECK(with_lone_surrogate(4092).empty());
    // Documented residual: with < 4 bytes free it is indistinguishable from the bound,
    // so the in-bound prefix comes back (valid UTF-8, cut again by list_field/the clamp).
    CHECK(with_lone_surrogate(4093).size() == 4093);
}
#endif
