#pragma once

/**
 * bundle_id_read.hpp -- bounded, abandonable CFBundleIdentifier pass over a
 * list of .app paths, for the macOS `installed_apps` plugin.
 *
 * WHY THIS LIVES IN AGENT-CORE
 * ----------------------------
 * CFBundleCreate is a synchronous filesystem read with no deadline (a hung
 * network home or dead volume wedges it). Bounding it needs a detached
 * thread (`yuzu::shared::bounded_call_ex`), and a detached thread whose code
 * lives in a plugin shared object is killed by `dlclose()` of that plugin.
 * Same argument as keychain_read.hpp:7-24 / passwd_lookup.hpp:8-24: the
 * bounded body lives in agent-core, which is never unloaded.
 *
 * ONE PASS, ONE THREAD, ONE IN FLIGHT
 * -----------------------------------
 * The whole path list is read by ONE bounded call (never a thread per app).
 * A process-wide in-flight flag admits a single pass at a time: while an
 * abandoned (TimedOut) pass is still wedged in the filesystem, the next call
 * returns Busy immediately instead of stacking another stuck thread. The flag
 * is released by the worker itself when it finishes, so it can outlive the
 * TimedOut caller. A Rejected admission means the worker never ran, so the
 * caller releases the flag itself.
 *
 * The outstanding-call ceiling that produces Rejected is PER IMAGE (see
 * keychain_read.hpp), so the driver is a header-only template taking the
 * flag by reference: production binds agent-core's flag, tests bind their own
 * and saturate their own image's counter.
 *
 * Plugins call the two exported functions ONLY and never instantiate the
 * template themselves: an instantiation inside a plugin image puts the detached
 * worker's text back into a dlclose()-able object, the hazard this header removes.
 */

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)
#include <yuzu/plugin.h>    // YUZU_EXPORT

namespace yuzu::agent {

enum class BundleIdPassStatus {
    Completed, ///< every path was read (ids[i] empty = absent / no identifier)
    TimedOut,  ///< deadline hit; ids holds what was read so far, the rest empty
    Rejected,  ///< the outstanding-call ceiling refused; nothing was read (ids all empty)
    Busy,      ///< a previous (abandoned) pass is still running; nothing was read
};

struct BundleIdPassResult {
    BundleIdPassStatus status = BundleIdPassStatus::Rejected;
    /// ids[i] belongs to app_paths[i]; empty = absent or not reached.
    std::vector<std::string> ids;
    /// Number of paths actually read (reached), whether or not they had an id.
    std::size_t read_count = 0;
};

namespace detail {

/// Header-only so tests can instantiate it in their own image. `reader` is a
/// TU-local callable `std::string(const std::string&)`; `in_flight` must
/// outlive any abandoned worker (a static).
template <typename Reader>
BundleIdPassResult bounded_bundle_id_pass(std::atomic_flag& in_flight,
                                          const std::vector<std::string>& app_paths,
                                          std::chrono::milliseconds deadline, Reader reader) {
    BundleIdPassResult out;
    // Admission first: a call during an active pass is Busy even with a spent
    // budget (Busy is the more informative answer).
    if (in_flight.test_and_set(std::memory_order_acquire)) {
        out.status = BundleIdPassStatus::Busy;
        out.ids.assign(app_paths.size(), {});
        return out;
    }
    if (deadline <= std::chrono::milliseconds::zero()) {
        in_flight.clear(std::memory_order_release); // nothing handed off
        out.status = BundleIdPassStatus::TimedOut;  // budget spent -- don't start what we can't wait for
        out.ids.assign(app_paths.size(), {});
        return out;
    }

    struct State {
        std::mutex mtx;
        std::vector<std::string> ids;
        std::size_t read_count = 0;
    };
    // The caller owns the flag until the worker is handed off, so EVERY
    // allocation that can throw (state, path copy) happens inside this try.
    std::shared_ptr<State> state;
    std::vector<std::string> paths;
    try {
        state = std::make_shared<State>();
        state->ids.assign(app_paths.size(), {});
        paths = app_paths;
    } catch (...) {
        in_flight.clear(std::memory_order_release);
        out.status = BundleIdPassStatus::Rejected; // ids left empty: allocation is failing
        return out;
    }

    auto worker = [&in_flight, state, paths = std::move(paths), reader = std::move(reader)]() mutable -> bool {
        // Releaser FIRST: runs when the worker returns or throws, even long
        // after a TimedOut caller has gone.
        struct Releaser {
            std::atomic_flag& f;
            ~Releaser() { f.clear(std::memory_order_release); }
        } releaser{in_flight};
        for (std::size_t i = 0; i < paths.size(); ++i) {
            std::string id;
            try {
                id = reader(paths[i]);
            } catch (...) {
                // Deliberate deviation from passwd_lookup.hpp's "a throw is a non-arrival"
                // rule: the production reader is CF Create/Get calls (null on failure, never
                // a throw) plus one std::string build, so the only throw is bad_alloc and the
                // column is informational. Recorded as "no identifier" rather than growing the
                // status enum; a future reader that CAN throw must add a Failed status instead
                // of relying on this catch.
            }
            std::lock_guard<std::mutex> lock(state->mtx);
            state->ids[i] = std::move(id);
            state->read_count = i + 1;
        }
        return true;
    };

    auto r = yuzu::shared::bounded_call_ex(deadline, std::move(worker));
    if (r.status == yuzu::shared::BoundedCallStatus::Rejected) {
        // fn was never invoked, so no releaser exists: clear the flag here.
        in_flight.clear(std::memory_order_release);
        out.status = BundleIdPassStatus::Rejected;
        out.ids.assign(app_paths.size(), {}); // path-aligned, like Busy
        return out;
    }
    {
        std::lock_guard<std::mutex> lock(state->mtx);
        out.ids = state->ids; // copy: an abandoned worker may still write
        out.read_count = state->read_count;
    }
    out.status = r.status == yuzu::shared::BoundedCallStatus::Completed ? BundleIdPassStatus::Completed
                                                                        : BundleIdPassStatus::TimedOut;
    return out;
}

} // namespace detail

/// Read CFBundleIdentifier for each path in ONE bounded pass. Non-macOS builds
/// return Completed with all-empty ids. Out-of-line (agent-core only).
YUZU_EXPORT BundleIdPassResult read_bundle_ids_bounded(const std::vector<std::string>& app_paths,
                                                       std::chrono::milliseconds deadline);

/// Test seam: same driver and process-wide in-flight flag, injected reader.
/// No default arguments (see keychain_read.hpp).
YUZU_EXPORT BundleIdPassResult read_bundle_ids_bounded_for_test(
    const std::vector<std::string>& app_paths, std::chrono::milliseconds deadline,
    const std::function<std::string(const std::string&)>& per_path_reader);

} // namespace yuzu::agent
