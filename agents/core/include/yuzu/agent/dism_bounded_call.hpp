#pragma once

/**
 * dism_bounded_call.hpp -- process-global, bounded DISM (Deployment Image
 * Servicing and Management) API access for the windows_optional_features
 * plugin (adversarial review C1 fix, Wave 9 PR9.2).
 *
 * WHY THIS LIVES IN AGENT-CORE AND NOT IN THE PLUGIN THAT NEEDS IT
 * ---------------------------------------------------------------
 * Same reason agents/core/include/yuzu/agent/passwd_lookup.hpp does (#3406):
 * a plugin-local `bounded_call_ex(timeout, [x]{ return f(x); })` runs its
 * callable on a DETACHED thread that is ABANDONED, not cancelled, at the
 * deadline -- the thread keeps running and eventually returns (or doesn't)
 * on its own time. If that callable's code -- and its closure's type-
 * erasure thunks, which are compiled into whichever translation unit
 * CONSTRUCTS the lambda -- lives in a plugin's shared object, the agent's
 * teardown loop can `FreeLibrary`/`dlclose` that plugin while the detached
 * thread is still executing inside it. agent.cpp's Subscribe loop gates
 * that teardown on `stop_requested_` (a plain reconnect leaves `plugins_`
 * loaded, `shutdown()` never runs) -- so this fires only at genuine final
 * agent shutdown (SIGTERM, service stop, upgrade restart), not on every
 * reconnect, which narrows EXPOSURE but does not remove the hazard: a
 * service stop/restart is a routine, recurring operational event, and DISM
 * has no caller-supplied timeout of its own. sdk/include/yuzu/plugin.hpp's
 * shutdown() doc comment states
 * this exact hazard: a worker surviving the plugin's own bounded shutdown
 * quiesce "must never touch this plugin's own code or statics after that
 * point (dlclose/FreeLibrary can unmap them while it runs)."
 *
 * So the whole DISM call body -- session lifecycle, the process-global
 * single-flight slot, the bounded wait itself -- lives here, in agent-core,
 * which is never unloaded. The plugin (windows_optional_features_plugin.cpp)
 * keeps only: parameter parsing, the two try_acquire_slot()/bounded-call
 * entry-point calls below, and turning an Outcome into CommandContext
 * output -- none of which ever runs on a thread that can outlive the
 * plugin's own unload.
 *
 * `DismSlot` itself (agents/shared/windows_optional_features_parsers.hpp)
 * stays a pure, dependency-free type any TU can instantiate; the single
 * process-global INSTANCE lives in dism_bounded_call.cpp, not here and not
 * in the plugin, so both this file's bounded-call entry points (the
 * worker/dispatching-thread acquire/timeout/release calls) and the
 * plugin's shutdown()-time slot_in_flight() read observe the same slot.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "windows_optional_features_parsers.hpp" // yuzu::wof::DismSlot, FeatureState (agents/shared)

#include <chrono>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::agent::dism {

// Per-call timeout: P92-1 measured DismGetFeatures at ~4058.7ms for 137
// features on the-rig, two orders of magnitude slower than every other call
// in the session lifecycle. 4x that (~16.2s), rounded up, comfortably
// clears the 15s floor the findings recommend. Shared by the bounded-call
// entry points below and the plugin's shutdown() quiesce (2x this value).
inline constexpr std::chrono::milliseconds kTimeout{17000};

/// One completed (or failed) DISM session's outcome -- the same shape the
/// plugin's do_windows_list()/do_windows_info() used to build directly;
/// now produced here and consumed by report_dism_outcome() in the plugin.
struct Outcome {
    enum class Kind {
        Ok,
        ApiUnavailable,
        InitializeFailed,
        OpenSessionFailed,
        GetFeaturesFailed,
        GetFeatureInfoFailed,
        FeatureNotFound,
        AccessDenied,
        Exception,
    } kind = Kind::Ok;
    std::vector<std::string> rows;
    std::string reason;
};

/// bounded_call_ex()'s three-way outcome, re-exposed at this boundary so
/// the plugin never touches yuzu::shared::bounded_call_ex (or the slot)
/// directly -- see the header comment above.
enum class BoundedStatus { Completed, TimedOut, Rejected };

struct BoundedOutcome {
    BoundedStatus status = BoundedStatus::Rejected;
    Outcome outcome; ///< meaningful only when status == Completed
};

/// True once DismApi.dll and all eight required exports resolved from
/// System32 (see dism_bounded_call.cpp's api() for the resolution itself,
/// which -- like the slot -- stays agent-core-internal).
[[nodiscard]] YUZU_EXPORT bool api_available() noexcept;

/// Called by the plugin's DISPATCHING thread, BEFORE issuing any bounded
/// call -- see yuzu::wof::DismSlot::Acquire's own doc comments for the
/// three-way result. `acquired` means the caller now owns the slot and
/// MUST follow up with exactly one of run_list_bounded()/run_info_bounded()
/// below (both release it internally, on every path -- the caller never
/// calls DismSlot::release()/mark_timed_out() itself).
[[nodiscard]] YUZU_EXPORT yuzu::wof::DismSlot::Acquire try_acquire_slot() noexcept;

/// True while a DISM call is in flight (acquired, not yet released) --
/// used by the plugin's shutdown() bounded-quiesce loop. Safe to poll from
/// any thread.
[[nodiscard]] YUZU_EXPORT bool slot_in_flight() noexcept;

/// Runs the whole init->OpenSession->GetFeatures->shutdown sequence for
/// `list`, entirely inside one bounded (kTimeout) detached call, and
/// releases the slot on every path (worker-side on Completed/TimedOut,
/// caller-side internally on Rejected) -- the caller never touches the
/// slot itself. MUST be called only after try_acquire_slot() returned
/// `acquired`.
[[nodiscard]] YUZU_EXPORT BoundedOutcome
run_list_bounded(const std::optional<std::unordered_set<yuzu::wof::FeatureState>>& filter);

/// Same shape as run_list_bounded() for `info`. `name` is assumed already
/// validated (validate_feature_name) by the caller.
[[nodiscard]] YUZU_EXPORT BoundedOutcome run_info_bounded(const std::string& name);

} // namespace yuzu::agent::dism
