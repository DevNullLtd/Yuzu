// test_agent_log_wiring.cpp - #4666 PR-2: single-image smoke tests for
// agents/core/src/agent_log_wiring.hpp (install_log_handoff_in_this_image(),
// release_log_handoff_from_this_image(), LogHandoffEpilogue). See that file's own
// banner and log_handoff.hpp's THREAD-SAFETY CONTRACT / TEARDOWN CONTRACT for the full
// R-LOGGER contract this exercises.
//
// SCOPE: this file drives everything within THIS test binary's own spdlog registry
// image only - a separate, later task builds the multi-image fixture that proves the
// macOS exe-vs-library-registry split (log_handoff.hpp's MULTI-IMAGE note); that is not
// duplicated here.

#include "agent_log_wiring.hpp"

#include "test_helpers.hpp"

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::install_log_handoff_in_this_image;
using yuzu::agent::LogHandoff;
using yuzu::agent::LogHandoffEpilogue;
using yuzu::agent::release_log_handoff_from_this_image;

namespace {

/// A minimal spdlog sink test double: captures every payload it receives (no
/// in-band pause gate - this file's cases only need eventual delivery, not
/// controlled ordering, unlike test_log_handoff.cpp's GatedCaptureSink) and exposes a
/// closed_flag() independent of `this` so a test can observe the sink's own
/// destruction after dropping every shared_ptr<WiringCaptureSink> reference,
/// including its own (mirrors test_log_handoff.cpp's U4 pattern).
class WiringCaptureSink final : public spdlog::sinks::sink {
public:
    WiringCaptureSink() : closed_(std::make_shared<std::atomic<bool>>(false)) {}
    ~WiringCaptureSink() override { closed_->store(true, std::memory_order_release); }

    void log(const spdlog::details::log_msg& msg) override {
        std::lock_guard<std::mutex> lk(mu_);
        captured_.emplace_back(msg.payload.data(), msg.payload.size());
    }
    void flush() override {}
    void set_pattern(const std::string&) override {}
    void set_formatter(std::unique_ptr<spdlog::formatter>) override {}

    [[nodiscard]] std::size_t count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return captured_.size();
    }
    [[nodiscard]] std::vector<std::string> snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        return captured_;
    }
    [[nodiscard]] std::shared_ptr<std::atomic<bool>> closed_flag() const { return closed_; }

private:
    mutable std::mutex mu_;
    std::vector<std::string> captured_;
    std::shared_ptr<std::atomic<bool>> closed_;
};

} // namespace

TEST_CASE("install_log_handoff_in_this_image installs the logger as this image's "
          "spdlog default and applies the level to it",
          "[agent_log_wiring]") {
    auto sink = std::make_shared<WiringCaptureSink>();
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto handoff = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*handoff); }};

    REQUIRE(install_log_handoff_in_this_image(*handoff, spdlog::level::warn, /*json_format=*/false));
    CHECK(spdlog::default_logger_raw() == handoff->logger().get());

    // Below the installed level: formatted/enqueued never happens - should_log()
    // filters it on the producer side before the async pool ever sees it.
    spdlog::info("below-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return handoff->queue_depth() == 0; }, 2s));
    CHECK(sink->count() == 0);

    // At the installed level: reaches the sink.
    spdlog::warn("at-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return sink->count() == 1; }, 2s));
    const auto snap = sink->snapshot();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0] == "at-the-installed-level");
}

TEST_CASE("release_log_handoff_from_this_image swaps this image's default logger to a "
          "null sink and tears down the handoff, destroying its sink",
          "[agent_log_wiring]") {
    auto sink = std::make_shared<WiringCaptureSink>();
    auto closed_flag = sink->closed_flag();
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto handoff = std::move(*result);
    sink.reset(); // the only remaining owner is now handoff's own wrapped_sinks_, so
                  // teardown()'s T3 is what actually destroys the WiringCaptureSink.

    REQUIRE(install_log_handoff_in_this_image(*handoff, spdlog::level::info, /*json_format=*/false));
    spdlog::info("line-before-release");
    REQUIRE(yuzu::test::spin_until([&] { return handoff->queue_depth() == 0; }, 2s));

    release_log_handoff_from_this_image(*handoff);

    CHECK(closed_flag->load(std::memory_order_acquire));
    // A straggler call through the now-swapped default logger must not crash.
    CHECK_NOTHROW(spdlog::info("goes to the null sink, not a crash"));
}

TEST_CASE("LogHandoffEpilogue's destructor releases the handoff the same way "
          "release_log_handoff_from_this_image does",
          "[agent_log_wiring]") {
    auto sink = std::make_shared<WiringCaptureSink>();
    auto closed_flag = sink->closed_flag();
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto handoff = std::move(*result);
    sink.reset();

    REQUIRE(install_log_handoff_in_this_image(*handoff, spdlog::level::info, /*json_format=*/false));
    spdlog::info("line-before-epilogue");
    REQUIRE(yuzu::test::spin_until([&] { return handoff->queue_depth() == 0; }, 2s));

    {
        LogHandoffEpilogue epilogue(*handoff); // destructor fires at the closing brace
                                                // below - declared last on purpose, so
                                                // nothing else in this scope still
                                                // needs to log past that point.
    }

    CHECK(closed_flag->load(std::memory_order_acquire));
    CHECK_NOTHROW(spdlog::info("goes to the null sink, not a crash"));
}
