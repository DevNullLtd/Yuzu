#pragma once

/// @file agent_log_wiring.hpp
/// #4666 PR-2: the thin per-image install/release protocol wrapping LogHandoff
/// (log_handoff.hpp) for main.cpp's (and, later, a multi-image test fixture's) real
/// call sites. HEADER-ONLY ON PURPOSE, no matching .cpp: on a platform with more than
/// one spdlog registry per process (macOS -- see log_handoff.hpp's own MULTI-IMAGE
/// note), the code below must physically execute inside whichever image includes it,
/// so that image's OWN spdlog::set_default_logger() call lands in its OWN registry.
/// A .cpp compiled once into agent-core would only ever touch agent-core's registry --
/// #include this header directly instead, once per image that needs to install/release.
///
/// R-LOGGER (the one rule that matters most): LogHandoff::install() returns a
/// shared_ptr<spdlog::logger> that CO-OWNS the logger and its sinks alongside
/// LogHandoff's own internal logger_ member (see log_handoff.hpp's TEARDOWN CONTRACT,
/// step T3). teardown()'s T3 only resets LogHandoff's OWN reference -- it has no way to
/// reach a copy a caller is still holding. Every function below drops its
/// install()-returned reference before returning; nothing here ever hands that
/// shared_ptr back to a caller. If a future change to this file breaks that, the final
/// sink close (e.g. a rotating-file sink's fclose()) happens whenever the leaked
/// reference finally drops -- possibly long after teardown()'s own bounded watchdog has
/// already given up and moved on, defeating the entire point of bounding shutdown.
///
/// LogHandoffEpilogue's declaration-order contract: declare it IMMEDIATELY after the
/// LogHandoff it wraps is constructed, and before anything that might still be logging
/// (e.g. the Agent object) -- C++ destroys stack/member locals in the REVERSE of
/// declaration order, so this ordering is what makes the epilogue's destructor (which
/// swaps this image's default logger to a null sink and then calls LogHandoff::teardown(),
/// see log_handoff.hpp's THREAD-SAFETY CONTRACT / TEARDOWN CONTRACT) run AFTER every
/// later-declared object has already been destroyed and can no longer log.

#include <memory>
#include <string_view>

#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include "hard_exit.hpp"
#include "log_handoff.hpp"
#include <yuzu/json_log_formatter.hpp>

namespace yuzu::agent {

/// The non-JSON default pattern (matches main.cpp's pre-#4666 `spdlog::set_pattern()`
/// call so a caller switching to this wrapper sees no behaviour change).
inline constexpr std::string_view kDefaultLogPattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v";

/// Installs `h` as this image's spdlog default logger, applies `level`/format, and
/// drops its own reference to the returned shared_ptr before returning (R-LOGGER
/// above). Returns false on any failure, including an exception from spdlog itself
/// (std::bad_alloc etc.) -- never throws. NOTE this cannot promise "installs nothing"
/// on a configuration failure: h.install() itself already calls
/// spdlog::set_default_logger() internally (log_handoff.cpp) before this function gets
/// a chance to apply `level`/`json_format`, so a later throw (from set_level()/
/// set_formatter()/set_pattern()) still leaves that FIRST, unconfigured install in
/// place in this image's registry -- there is no way to undo it from here. A caller
/// that gets `false` back should treat `h` as unusable for logging in this image and
/// go straight to its own failure path (main.cpp: EXIT_FAILURE), not assume nothing
/// changed.
[[nodiscard]] inline bool install_log_handoff_in_this_image(LogHandoff& h,
                                                             spdlog::level::level_enum level,
                                                             bool json_format) noexcept {
    try {
        auto lg = h.install();
        if (!lg)
            return false;
        lg->set_level(level);
        if (json_format)
            lg->set_formatter(std::make_unique<yuzu::JsonLogFormatter>("agent"));
        else
            lg->set_pattern(std::string(kDefaultLogPattern));
        // Redundant with h.install()'s own internal spdlog::set_default_logger() call
        // above (same shared_ptr, already installed) -- kept so the LAST registry
        // write this function makes only happens once level/format configuration has
        // actually succeeded, rather than installing, then configuring in place.
        spdlog::set_default_logger(lg);
        return true;
        // `lg` goes out of scope here -- this function never lets the install()-returned
        // shared_ptr outlive the call, which is what makes it R-LOGGER-safe.
    } catch (...) {
        return false;
    }
}

/// The exe-image half of teardown: swaps THIS image's spdlog default logger to a null
/// sink (so nothing in this image can log through the about-to-be-destroyed logger
/// while teardown() runs), then calls h.teardown() regardless of whether the swap
/// succeeded (LogHandoff::teardown() is documented to run unconditionally even if
/// install() was never called on this instance).
///
/// CATASTROPHIC ON MACOS IF THE SWAP THROW IS SWALLOWED WITHOUT FAILING CLOSED
/// (adversarial-review finding, governance-hardening round): on a platform with two
/// separate spdlog registries (macOS -- see log_handoff.hpp's MULTI-IMAGE note and this
/// file's own banner), THIS swap is the ONLY thing that ever drops THIS image's
/// registry reference to the real logger -- h.teardown() below only ever reaches the
/// registry of the image IT is compiled into (the core library), never this one. If the
/// swap throws (spdlog::set_default_logger()'s registry-mutex lock/map write is not
/// noexcept; the two make_shared calls above it can throw bad_alloc) and that exception
/// is merely swallowed, this image's registry keeps a live, real reference to the
/// logger and its sinks -- surviving teardown()'s bounded watchdog entirely and only
/// getting destroyed at UNWATCHED process static teardown, which is the exact
/// unbounded-shutdown-wedge hazard this whole primitive exists to close. So: track
/// whether the swap actually succeeded, and hard_exit() if it did not, rather than
/// silently continuing into a teardown() that cannot see or fix the retained reference.
inline void release_log_handoff_from_this_image(LogHandoff& h) noexcept {
    bool swap_ok = false;
    try {
        spdlog::set_default_logger(
            std::make_shared<spdlog::logger>("", std::make_shared<spdlog::sinks::null_sink_mt>()));
        swap_ok = true;
    } catch (...) {
        // Deliberately swallowed here, not re-thrown -- this function is noexcept and
        // h.teardown() below is unconditional regardless of swap_ok, exactly as before.
        // What changed: swap_ok now records the failure so it can be acted on AFTER
        // teardown() runs, instead of being silently treated as harmless.
    }
    h.teardown(); // already noexcept -- not double-wrapped in try/catch.
    if (!swap_ok) {
        // Fail closed, matching log_handoff.cpp's own teardown-exception precedent
        // (hard_exit(kLogTeardownExitCode) there too). On Linux/Windows (single
        // registry) this is unreachable in practice: teardown()'s own T2 step already
        // dropped the one registry's reference before this check runs. On macOS this is
        // the ONLY backstop for the retained-reference hazard above.
        hard_exit(kLogTeardownExitCode);
    }
}

/// RAII wrapper: calls release_log_handoff_from_this_image(h) in its destructor. See
/// this file's own banner for the declaration-order contract. Non-copyable,
/// non-movable -- there is exactly one well-defined owner.
class LogHandoffEpilogue {
public:
    explicit LogHandoffEpilogue(LogHandoff& h) noexcept : h_(h) {}
    ~LogHandoffEpilogue() { release_log_handoff_from_this_image(h_); }

    LogHandoffEpilogue(const LogHandoffEpilogue&) = delete;
    LogHandoffEpilogue& operator=(const LogHandoffEpilogue&) = delete;
    // No move members declared either: a user-declared destructor suppresses implicit
    // move-ctor/move-assign generation (they are simply absent, not merely deleted),
    // and the deleted copy members above rule out copy-as-fallback too -- so this
    // class is already non-movable without a separate explicit declaration.

private:
    LogHandoff& h_;
};

} // namespace yuzu::agent
