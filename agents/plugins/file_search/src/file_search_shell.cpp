/**
 * file_search_shell.cpp -- the OS-neutral shell of the file_search plugin: the process-wide single-flight slot
 * and stop flag, the in-memory search state, the cursor-key holder, the worker runner and the one live slice.
 * It compiles on every OS and stands on the bindings each OS shell defines once (file_search_os.hpp), so there
 * is exactly one copy of the single-flight seam. Everything pure lives in the headers beside it.
 *
 * THREADS. Two kinds run here. The POOL thread is the one the agent called execute() on: it takes the
 * process-wide slot, reads the mount table, writes every row and every heartbeat key, and releases the slot.
 * The WORKER is a fresh thread per slice (shared::bounded_call_ex) that makes the unit's leg, reads the
 * profile roots and runs the walk. A worker touches only heap state it co-owns (its leg, its pattern, its
 * done flag) and the operating system: never the plugin context, the slot or the search state. On a timeout
 * the pool thread stops waiting and the worker runs on, abandoned, until its next syscall returns; the plugin
 * module is pinned in memory at init (file_search_plugin.cpp) so no worker can ever run unmapped code. After
 * shutdown() returns, a call still in flight when its quiesce bound passed finishes on its pool thread inside
 * the pinned module (it releases the slot, records its abandoned worker and writes its rows), and an
 * abandoned worker touches only state it owns.
 *
 * THE CURSOR KEY. 32 random bytes from the OS (os_draw_cursor_key), drawn once per process on first use and
 * held for the life of the (pinned) module: init draws it and fails if it cannot, and a re-init never draws
 * another. It is never written anywhere. A cursor is a token the agent authenticates and seals under it
 * (file_search_volumes.hpp), so a cursor is valid, and readable, only in the agent process that issued it.
 *
 * THE SLOT. One atomic flag, taken with compare_exchange by run_slice on the pool thread before it reads any
 * state and released only by that pool thread's RAII guard (file_search_driver.hpp). A second concurrent call
 * answers busy at once. A worker never touches it: it sets only its own done flag.
 */
#include "file_search_execute.hpp"

#include <bounded_wait.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <utility>

namespace yuzu::file_search {

namespace {

// ---- process-wide state: the slot, the stop flag, the in-memory search state ----

std::atomic<bool> g_slot{false};
std::atomic<bool> g_stop{false};

/// Touched only by the pool thread that holds the slot (run_slice), never by a worker.
[[nodiscard]] SearchState& search_state() {
    static SearchState state;
    return state;
}

/// The process's cursor key. Drawn once, by whichever call comes first; a failed draw is final for the
/// process, so init keeps failing rather than the plugin running with a key it cannot vouch for.
struct CursorKeyHolder {
    CursorKey key{};
    bool ok{false};
};

[[nodiscard]] const CursorKeyHolder& cursor_key_holder() {
    static const CursorKeyHolder holder = [] {
        CursorKeyHolder h;
        h.ok = os_draw_cursor_key(h.key);
        if (!h.ok)
            h.key.fill(0); // never leave a partial draw behind
        return h;
    }();
    return holder;
}

} // namespace

/// Runs `work` on a fresh worker thread for at most `timeout`. The work runs inside the OS's worker
/// environment, whose scope is the whole call of `work`; a throw before or after it is a failed result,
/// never a timeout.
RunOutcome<WorkResult> run_on_worker(std::chrono::milliseconds timeout, std::function<WorkResult()> work) {
    auto ran = yuzu::shared::bounded_call_ex(timeout, [work = std::move(work)]() -> WorkResult {
        try {
            WorkResult result;
            os_in_worker_environment([&] { result = work(); });
            return result;
        } catch (...) {
            WorkResult failed;
            failed.threw = true;
            return failed;
        }
    });
    RunOutcome<WorkResult> out;
    switch (ran.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = RunStatus::completed;
        out.value = std::move(ran.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.status = RunStatus::timed_out;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        out.status = RunStatus::rejected;
        break;
    }
    return out;
}

// ---- the slice ----

SliceResult run_live_slice(const Request& req) {
    Boundaries b{.state = search_state(), .slot = g_slot};
    b.read_mounts = &os_read_mounts;
    b.make_leg = &os_make_leg;
    b.read_user_roots = &os_user_roots; // read by the driver on the worker, never here
    b.run_bounded = &run_on_worker;
    b.now = [] { return fsr::Clock::now(); };
    b.sleep = [](std::chrono::milliseconds d) { std::this_thread::sleep_for(d); };
    b.stop_requested = [] { return g_stop.load(std::memory_order_acquire); };
    b.os = kOs;
    b.cursor_key = cursor_key_holder().key; // all zero if the draw failed: run_slice refuses it
    return run_slice(req, b);
}

bool init_cursor_key() noexcept {
    return cursor_key_holder().ok;
}

void request_stop() noexcept {
    g_stop.store(true, std::memory_order_release);
}

void clear_stop() noexcept {
    g_stop.store(false, std::memory_order_release);
}

} // namespace yuzu::file_search
