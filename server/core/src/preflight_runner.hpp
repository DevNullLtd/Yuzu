#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file preflight_runner.hpp
/// Background lifecycle driver for `/auto` pre-flight runs — the
/// re-dispatch-on-reconnect loop. Mirrors PolicyEvaluator: this owns only the
/// per-cycle `tick()`; the server owns the thread that calls it on a cadence and
/// joins it BEFORE the stores in `stop()` / `~ServerImpl`.
///
/// Per tick, for each `running` run still inside its window: re-dispatch every
/// applicable check (under the run's per-check execution_id) to the frozen
/// targets that aren't fully answered yet — `AgentRegistry::send_to` drops
/// offline agents silently, so this costs a map lookup for them and catches the
/// reconnected ones. The checks are READ-ONLY / idempotent, so re-dispatch is
/// safe (load-bearing). Then recompute the grid from query_by_execution and
/// persist it; at the deadline (or once nothing is pending) flip the run
/// complete. Old runs are pruned past the retention window.
///
/// Lease discipline (ADR-0012): list/read/persist each take + release a
/// PreflightRunStore lease; the ResponseStore read and the gRPC dispatch run
/// with NO run-store lease held.

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class PreflightRunStore;
class ResponseStore;

class PreflightRunner {
public:
    /// Same 6-param shape as the shared command_dispatch_fn (execution_id
    /// carried, so responses correlate via query_by_execution).
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// Epoch-MILLISECONDS clock (matches the store's *_ms columns). Injectable
    /// for tests; defaults to the system clock.
    using NowFn = std::function<std::int64_t()>;

    struct Deps {
        PreflightRunStore* run_store{nullptr};
        ResponseStore* response_store{nullptr};
        CommandDispatchFn dispatch_fn;
        NowFn now_ms_fn;
        int retention_days{14};
        // #3495: lets a shutdown request stop tick() from STARTING further
        // runs' dispatch once stop_requested_ flips — checked once per run,
        // before that run's per-check dispatch_fn calls begin, so an
        // already-in-flight run's dispatches still complete cleanly (this
        // only stops the NEXT run from starting). Ports the same field
        // QuarantineContainmentReconciler::Deps already carries (governance
        // Gate 5, #3425) to the sibling this issue's design round named as
        // still missing it. Unset (default) = never stop, matching every
        // existing production/test Deps that predates this field.
        std::function<bool()> should_stop;
    };

    explicit PreflightRunner(Deps deps);

    /// One scheduler cycle. Safe to call from a single background thread.
    void tick();

private:
    Deps d_;
    [[nodiscard]] std::int64_t now_ms() const;
};

} // namespace yuzu::server
