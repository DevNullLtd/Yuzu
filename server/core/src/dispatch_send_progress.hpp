#pragma once

/// @file dispatch_send_progress.hpp
/// How many agents a confined dispatch had ALREADY been sent the command when it threw.
///
/// WHY. `ConfinedDispatchOutcome::sent` only exists if the dispatch RETURNS. A dispatch that
/// throws mid fan-out (a registry or gateway fault on the Nth target) loses the count, so the
/// execution row it belongs to was left `running` with `agents_targeted` 0. Agent results then
/// recorded against it could never close it: `ExecutionTracker::refresh_counts` only promotes a
/// row to terminal when `agents_targeted > 0`, and the stuck-execution reaper deliberately
/// excludes any row that has a per-agent response. The instruction-execute core
/// (`instruction_execute.cpp`) and `POST /api/v1/commands` (`command_v1_routes.cpp`) therefore
/// open a `SendProgressScope` around the dispatch call; when it throws they record the confirmed
/// count with `set_agents_targeted` so those agents' results complete the row normally.
///
/// HOW. A thread-local slot, not a parameter: the dispatch is synchronous on the calling thread
/// (`ServerImpl::dispatch_confined` -> `wire_and_dispatch_confined` -> the arms' sink calls), and
/// widening the nine-parameter `DispatchFn` (and its fakes) for one defaulted pointer was not
/// worth the churn. `wire_and_dispatch_confined` is the ONLY consumer: it passes its sink through
/// `instrument_sink`, which is the identity when no scope is open, so every other caller (the
/// legacy routes, background engines) is untouched.
///
/// THE COUNT IS A LOWER BOUND. A send that is in flight when the throw happens is not counted
/// (it may or may not have been delivered), and `send_to_all_unfiltered` is one call that is
/// counted only when it returns. A lower bound is the safe direction: `refresh_counts` closes a
/// row when responded >= targeted, so too low closes it slightly early, whereas too high would
/// wedge it exactly as before. The residual: a throw inside the very FIRST send that did deliver
/// reads as 0, which leaves the row `running` as it was before this header existed.
///
/// Single-thread by construction: the counters are plain ints and the scope must not be moved
/// across threads.

#include "dispatch_confined_arms.hpp"

#include <functional>
#include <string>
#include <utility>

namespace yuzu::server {

struct SendProgress {
    /// Sends accepted by the send path (a `send_to` that returned true, or the count a
    /// `send_to_all_unfiltered` returned). For a gateway-routed agent that means queued for
    /// forwarding, which can still fail afterwards: a lower bound on delivery, never a receipt.
    int sent{0};
};

/// Installs `progress` as the current thread's send-progress sink for its lifetime and restores
/// the previous one on exit (nests; exception-safe).
class SendProgressScope {
public:
    explicit SendProgressScope(SendProgress& progress) noexcept : previous_(slot()) {
        slot() = &progress;
    }
    ~SendProgressScope() { slot() = previous_; }
    SendProgressScope(const SendProgressScope&) = delete;
    SendProgressScope& operator=(const SendProgressScope&) = delete;

    /// The open scope's progress, or null when none is open.
    [[nodiscard]] static SendProgress* current() noexcept { return slot(); }

private:
    [[nodiscard]] static SendProgress*& slot() noexcept {
        thread_local SendProgress* open_scope = nullptr;
        return open_scope;
    }
    SendProgress* previous_;
};

/// `sink` with its two send operations counting into the open scope. Identity when no scope is
/// open (the common case). The returned sink keeps a raw pointer to the scope's `SendProgress`:
/// it must not outlive the scope, and `wire_and_dispatch_confined` builds and uses it inside one
/// synchronous call.
[[nodiscard]] inline ConfinedDispatchSink instrument_sink(ConfinedDispatchSink sink) {
    SendProgress* progress = SendProgressScope::current();
    if (!progress)
        return sink;
    if (sink.send_to) {
        sink.send_to = [inner = std::move(sink.send_to), progress](const std::string& aid) {
            const bool delivered = inner(aid);
            if (delivered)
                ++progress->sent;
            return delivered;
        };
    }
    if (sink.send_to_all_unfiltered) {
        sink.send_to_all_unfiltered = [inner = std::move(sink.send_to_all_unfiltered), progress] {
            const int n = inner();
            progress->sent += n;
            return n;
        };
    }
    return sink;
}

} // namespace yuzu::server
