#pragma once

/**
 * test_log_capture.hpp — RAII spdlog default-logger capture into a string.
 *
 * Promoted from the inline block in test_licensing_sync.cpp's
 * "k_agent never appears in the blob or in captured logs" test (governance
 * CON-S4 — promote-at-second-user). The #2238 second user
 * (test_guardian_engine_spark_reconcile.cpp) was removed after a macOS CI
 * failure showed this class's swap does not reach spdlog:: calls made from
 * code compiled into a separate shared library (libyuzu_agent_core is a
 * .dylib there) — the swap happens in the TEST BINARY's image, and that
 * image apparently does not share spdlog's default-logger/registry state
 * with the library's own image on every supported toolchain. This class is
 * therefore reliable ONLY for logging done by code compiled directly into
 * the same test binary (which is exactly test_licensing_sync.cpp's case —
 * sync_source_software_licensing.cpp is, however, ALSO compiled into
 * libyuzu_agent_core, so that test's own LogCapture use likely has the SAME
 * exposure; its assertions are negative (logs.find(key) == npos), so an
 * empty/unreachable capture would pass it vacuously rather than fail loudly.
 * Not yet verified or fixed — tracked as issue #3355.
 *
 * For code compiled into a separate shared library, prefer recording the
 * observable directly as a plain object member with a `_for_test` accessor
 * at the point of emission (see GuardianEngine::last_rearm_degrade_message_for_test
 * for the pattern this class was replaced by, for that use case) — object
 * state has no cross-image hazard.
 *
 * A separate header rather than folding into test_helpers.hpp: this pulls in
 * spdlog's ostream sink, which most test_helpers.hpp consumers don't need.
 */

#include <memory>
#include <sstream>
#include <string>

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

namespace yuzu::test {

/// RAII spdlog default-logger capture into a string.
///
/// RESTORE AND QUIESCE BEFORE text(): call stop() (or let the destructor run)
/// BEFORE asserting on text(), AND stop/join every component that may still
/// log through the captured logger — text() reads the underlying stream
/// without the ostream sink's lock, so a still-running worker thread writing
/// through a pre-restore logger copy (a shared_ptr it captured before stop())
/// is a data race against the read.
struct LogCapture {
    explicit LogCapture(spdlog::level::level_enum lvl = spdlog::level::trace)
        : prev_(spdlog::default_logger()), prev_level_(spdlog::get_level()) {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger = std::make_shared<spdlog::logger>("test_log_capture", sink);
        logger->set_level(lvl);
        spdlog::set_default_logger(logger);
        spdlog::set_level(lvl);
    }

    /// Restore the previous default logger + level. Idempotent.
    void stop() {
        if (stopped_)
            return;
        spdlog::set_default_logger(prev_);
        spdlog::set_level(prev_level_);
        stopped_ = true;
    }

    /// Captured text so far. Only safe to call after stop() (see class doc).
    [[nodiscard]] std::string text() const { return oss_.str(); }

    ~LogCapture() { stop(); }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;
    LogCapture(LogCapture&&) = delete;
    LogCapture& operator=(LogCapture&&) = delete;

private:
    std::ostringstream oss_;
    std::shared_ptr<spdlog::logger> prev_;
    spdlog::level::level_enum prev_level_;
    bool stopped_{false};
};

} // namespace yuzu::test
