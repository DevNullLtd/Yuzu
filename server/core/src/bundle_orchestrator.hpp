#pragma once

#include "authz_model.hpp"    // #1788: VisibleSet — dispatch() confinement param
#include "bundle_service.hpp" // BundleStepSpec, DispatchedStep, BundleAggregate
#include "dispatch_caller.hpp" // PR1.9c: DispatchCaller — DispatchFn's caller param
#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome — DispatchFn's return type

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Live-query bundle — transport-agnostic orchestration (ADR-0011).
//
// One object, shared by BOTH the REST routes and the MCP tools (REST/MCP
// parity by construction — neither surface reimplements dispatch or collate;
// they are thin wrappers that bind their request context into the callbacks
// below). The orchestrator deliberately takes NO httplib / proto / session
// types so it stays unit-testable and surface-neutral.
//
// Async fan-out: `dispatch` mints one correlation id, expands the instruction
// into N ordinary plugin commands (via the injected DispatchFn — the same
// per-command dispatcher REST/MCP already use), persists the ordered
// step↔command_id map, and returns immediately. `collate` reads the responses
// back (via ResponseStore::query_by_execution on the correlation id) and groups
// them against that map. The agent is unchanged — it only sees ordinary commands.
//
// STORAGE (ADR-0011): the manifest map below is IN-MEMORY (+ TTL) for v1. This
// is a deliberate v1 simplification with a COMMITTED migration target — the
// manifest MUST move to a durable Postgres `bundles` table for high
// availability and assurance (a mid-bundle restart currently loses in-flight
// manifests). See ADR-0011 "Future — durable manifest in Postgres (committed,
// not optional)". Do not let this in-memory store calcify.

namespace yuzu {
class MetricsRegistry; // optional metrics sink (yuzu_bundle_*)
}

namespace yuzu::server {

class ResponseStore; // collate reads responses by correlation id

/// `collate()`'s error channel (#2691, Doomgoose finding #3). `kNotFoundOrDenied`
/// deliberately conflates "unknown/expired correlation id" with "known but not
/// owned by this principal" — existence must not become an enumeration oracle,
/// so both map to the same caller-facing 404. `kDegraded` is a DISTINCT signal:
/// the underlying ResponseStore read failed (store/pool/query error), which the
/// caller must map to a retryable 503/kInternalError, never the same 404 a
/// genuinely-absent bundle gets — conflating the two previously meant a poll
/// hitting a transient store blip saw a terminal "not found" (and, on REST, a
/// false "denied" audit row) instead of a signal to retry.
enum class CollateError { kNotFoundOrDenied, kDegraded };

class BundleOrchestrator {
public:
    /// Per-command dispatcher — the SAME shape REST/MCP already use:
    /// returns {command_id, agents_reached}. agents_reached == 0 means the
    /// command did not reach any agent (offline) → that step is dispatch-failed.
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope,
        const std::unordered_map<std::string, std::string>& params,
        const std::string& correlation_id,
        // #1788: kept identical to McpServer::DispatchFn (the SAME lambda feeds
        // both). The orchestrator never derives or re-decides this set itself
        // (governance UP-8) — it threads through whatever `dispatch()`'s caller
        // supplied unchanged; see that method's doc comment below.
        //
        // PR1.9c: this carries the whole CALLER, not just the visible set.
        // `build_classified_command` refuses an empty `DispatchCaller::principal`
        // as `AnonymousOperator` BEFORE the legacy-open bypass, so a
        // VisibleSet-only shape made every bundle step undeliverable on both
        // surfaces. `dispatch()` already receives `principal`, so the caller is
        // assembled there — no new data crosses this boundary.
        const yuzu::server::DispatchCaller& caller)>;

    /// Per-step audit sink, request-bound by the wrapper (so the core stays
    /// req-free). Called once per step with a transport-agnostic verb.
    using AuditSink = std::function<void(const std::string& verb, const std::string& result,
                                         const std::string& target_type,
                                         const std::string& target_id, const std::string& detail)>;

    /// Mints the random component of ids (hex). Injected for testability.
    using IdMinter = std::function<std::string()>;

    /// Monotonic-ish wall clock in ms. Injected so TTL/eviction is deterministic
    /// in tests (mirrors IdMinter); default uses system_clock.
    using ClockFn = std::function<std::int64_t()>;

    static constexpr std::int64_t kDefaultManifestTtlMs = 10 * 60 * 1000; // 10 min
    static constexpr std::size_t kDefaultMaxManifests = 4096;

    /// `metrics`/`surface` are optional: when set, the orchestrator emits
    /// yuzu_bundle_* counters/gauges labelled by `surface` ("rest"|"mcp").
    /// `clock`/`ttl_ms`/`max_manifests` are injectable for tests; defaults
    /// preserve production behaviour.
    BundleOrchestrator(DispatchFn dispatch, ResponseStore* response_store, IdMinter mint,
                       yuzu::MetricsRegistry* metrics = nullptr, std::string surface = {},
                       ClockFn clock = {}, std::int64_t ttl_ms = kDefaultManifestTtlMs,
                       std::size_t max_manifests = kDefaultMaxManifests);

    struct DispatchResult {
        std::string correlation_id;
        std::size_t expected{0};
    };

    /// Fan one instruction out into N ordinary commands on `agent_id`. Mints a
    /// `bundle-…` correlation id, dispatches each step under it, records the
    /// step↔command_id map (with per-step dispatch outcome), audits each step,
    /// and returns immediately. `principal` owns the bundle (collate checks it).
    ///
    /// `exec_visible` is the CALLER's already-derived Execution:Execute visible
    /// set (governance UP-8) — this method threads it into `DispatchFn`
    /// unchanged for every step, it never derives or narrows it itself. The
    /// wrapper (REST/MCP) has ALREADY confined `agent_id` before calling this
    /// (the per-target scope gate — `scoped_perm_fn` on REST, `in_scope` on
    /// MCP), so a defaulted `{}` (nullopt/unfiltered) preserves that model:
    /// this orchestrator is not itself the confinement chokepoint, only a
    /// faithful conduit for whichever caller-derived set the wrapper already
    /// checked `agent_id` against.
    ///
    /// #1398 (adversarial-review finding, both reviewers independently):
    /// `principal_is_admin`/`approval_provenance` are the SAME pass-through
    /// contract as `exec_visible` above, for the two `DispatchCaller` fields
    /// the dispatch chokepoint's `ExecuteGate` gate consults. Before this fix,
    /// this method reconstructed a `DispatchCaller` carrying only `principal`
    /// + `exec_visible`, so BOTH fields silently defaulted to `false`/`None`
    /// regardless of who the real caller was — an admin's (or a
    /// ticket-holding supervised MCP caller's) bundle step targeting any of
    /// the ~42 `AdminOrApproval` pairs was refused `ApprovalRequired`
    /// unconditionally, with no way to satisfy the gate via this surface at
    /// all. Both wrappers already derive the caller's real values (the SAME
    /// `derive_dispatch_caller`/`caller_fn` every other surface uses) before
    /// calling this method; they must pass them through rather than let this
    /// method drop them on the floor.
    DispatchResult dispatch(const std::string& agent_id, const std::vector<BundleStepSpec>& steps,
                            const std::string& principal, const AuditSink& audit,
                            const yuzu::server::authz::VisibleSet& exec_visible = {},
                            bool principal_is_admin = false,
                            ApprovalProvenance approval_provenance = ApprovalProvenance::None);

    /// Collate the bundle's responses. Returns `unexpected(kNotFoundOrDenied)`
    /// when the correlation id is unknown/expired OR not owned by `principal`
    /// (and not `is_admin`) — the caller maps this to a 404 so existence isn't
    /// an enumeration oracle; the real reason is audited by the wrapper.
    /// Returns `unexpected(kDegraded)` when the manifest was found and owned
    /// but the underlying ResponseStore read failed — the caller maps THIS to
    /// a retryable 503/kInternalError, distinct from the terminal 404 above.
    [[nodiscard]] std::expected<BundleAggregate, CollateError>
    collate(const std::string& correlation_id, const std::string& principal, bool is_admin);

    /// Correlation-id prefix. `notify_exec_tracker` skips ids with this prefix
    /// (mirroring the `polchk-` guard) because a bundle is NOT a tracker
    /// execution — see ADR-0011.
    static constexpr const char* kCorrelationPrefix = "bundle-";

private:
    struct Manifest {
        std::vector<DispatchedStep> steps; // ordered; command_id empty ⇒ dispatch-failed
        std::string dispatched_by;
        std::string agent_id;
        std::int64_t created_at_ms{0};
    };

    std::int64_t now_ms() const;                            // via clock_ (or system_clock)
    void maybe_sweep_locked(std::int64_t now);              // amortized TTL sweep; holds mu_
    void evict_expired_locked(std::int64_t now);            // full TTL scan; holds mu_
    void update_manifests_gauge_locked();                   // holds mu_

    DispatchFn dispatch_;
    ResponseStore* response_store_;
    IdMinter mint_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    std::string surface_;
    ClockFn clock_;
    std::int64_t ttl_ms_{kDefaultManifestTtlMs};
    std::size_t max_manifests_{kDefaultMaxManifests};

    std::mutex mu_;
    std::unordered_map<std::string, Manifest> manifests_;
    std::int64_t last_sweep_ms_{0}; // amortize the O(n) TTL scan off the poll hot path

    // The full O(n) TTL scan runs at most this often; an actively-polled bundle
    // is kept alive by collate refreshing its timestamp, so a coarse sweep is
    // safe and keeps the poll path O(1).
    static constexpr std::int64_t kSweepIntervalMs = 30 * 1000; // 30 s
};

} // namespace yuzu::server
