#pragma once

/**
 * log_handoff_test_sinks.hpp - spdlog sink test doubles shared by
 * agents/core/src/log_handoff.{hpp,cpp}'s test coverage.
 *
 * Promoted out of test_log_handoff.cpp's anonymous namespace (#4666 PR-2) so
 * the later macOS multi-image fixture (the consumer of
 * log_handoff_emit_probe_for_test(), log_handoff.hpp) can reuse these sink
 * doubles instead of re-deriving them. Header-only, matching
 * test_log_capture.hpp's own precedent for a promoted test-support type: a
 * separate header rather than folding into test_helpers.hpp, since these
 * pull in spdlog sink headers most test_helpers.hpp consumers don't need.
 *
 * Deliberately NOT promoted alongside these: the `Harness` convenience
 * bundle in test_log_handoff.cpp (it wraps a `LogHandoff` directly and stays
 * specific to that file's own cases) and anything LogHandoff-specific - this
 * header knows nothing about LogHandoff, only about spdlog::sinks::sink.
 */

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/sink.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace yuzu::test {

/// A spdlog sink test double with an in-band pause gate plus an ordered capture of
/// every message it received (payload, the RAW log_msg time/thread_id, and the text
/// rendered through whatever formatter is installed - mirroring what an operator's log
/// file would actually show).
///
/// The gate is a single "block while paused_" check evaluated at the top of every
/// log() call, not a one-shot "park on message N" - but under a single-worker async
/// pool the two are equivalent for the "park on message #0, release once" cases: the
/// worker dequeues and calls log() for message #0 as soon as it exists, blocks there
/// until release() flips paused_ false permanently, then drains the rest without
/// blocking again. The same mechanism also supports repeated toggling, which a
/// one-shot design could not (see test_log_handoff.cpp's U6).
class GatedCaptureSink final : public spdlog::sinks::sink {
public:
    struct Captured {
        std::string payload;
        std::chrono::system_clock::time_point time;
        std::size_t thread_id{};
        std::string formatted;
    };

    explicit GatedCaptureSink(bool initially_paused = true)
        : paused_(initially_paused), closed_(std::make_shared<std::atomic<bool>>(false)) {}

    ~GatedCaptureSink() override { closed_->store(true, std::memory_order_release); }

    void log(const spdlog::details::log_msg& msg) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return !paused_; });
        std::string formatted;
        if (formatter_) {
            spdlog::memory_buf_t buf;
            formatter_->format(msg, buf);
            formatted.assign(buf.data(), buf.size());
        }
        captured_.push_back(Captured{std::string(msg.payload.data(), msg.payload.size()),
                                     msg.time, msg.thread_id, std::move(formatted)});
    }

    void flush() override {}

    void set_pattern(const std::string& pattern) override {
        set_formatter(std::make_unique<spdlog::pattern_formatter>(pattern));
    }

    void set_formatter(std::unique_ptr<spdlog::formatter> f) override {
        std::lock_guard<std::mutex> lk(mu_);
        formatter_ = std::move(f);
    }

    /// Repeated or one-shot - see the class comment.
    void set_paused(bool paused) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            paused_ = paused;
        }
        if (!paused)
            cv_.notify_all();
    }
    void release() { set_paused(false); }

    [[nodiscard]] std::vector<Captured> snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        return captured_;
    }
    [[nodiscard]] std::size_t count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return captured_.size();
    }

    /// A control block independent of `this`, so a test can hold onto it AFTER
    /// dropping every shared_ptr<GatedCaptureSink> reference (including its own), to
    /// observe whether the sink object was actually destroyed (test_log_handoff.cpp's
    /// U4).
    [[nodiscard]] std::shared_ptr<std::atomic<bool>> closed_flag() const { return closed_; }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool paused_;
    std::vector<Captured> captured_;
    std::unique_ptr<spdlog::formatter> formatter_;
    std::shared_ptr<std::atomic<bool>> closed_;
};

/// Throws on its first call only; captures every call after that
/// (test_log_handoff.cpp's U8).
class ThrowOnceSink final : public spdlog::sinks::sink {
public:
    void log(const spdlog::details::log_msg& msg) override {
        std::lock_guard<std::mutex> lk(mu_);
        if (!thrown_) {
            thrown_ = true;
            throw std::runtime_error("ThrowOnceSink: injected failure");
        }
        captured_.emplace_back(msg.payload.data(), msg.payload.size());
    }
    void flush() override {}
    void set_pattern(const std::string&) override {}
    void set_formatter(std::unique_ptr<spdlog::formatter>) override {}

    [[nodiscard]] std::size_t captured_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return captured_.size();
    }

private:
    mutable std::mutex mu_;
    bool thrown_{false};
    std::vector<std::string> captured_;
};

} // namespace yuzu::test
