#include "bundle_orchestrator.hpp"

#include "response_store.hpp" // ResponseStore, ResponseQuery, StoredResponse

#include <yuzu/metrics.hpp> // MetricsRegistry (optional sink)

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <utility>

namespace yuzu::server {

BundleOrchestrator::BundleOrchestrator(DispatchFn dispatch, ResponseStore* response_store,
                                       IdMinter mint, yuzu::MetricsRegistry* metrics,
                                       std::string surface, ClockFn clock, std::int64_t ttl_ms,
                                       std::size_t max_manifests)
    : dispatch_(std::move(dispatch)), response_store_(response_store), mint_(std::move(mint)),
      metrics_(metrics), surface_(std::move(surface)), clock_(std::move(clock)),
      ttl_ms_(ttl_ms), max_manifests_(max_manifests) {}

std::int64_t BundleOrchestrator::now_ms() const {
    if (clock_)
        return clock_();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void BundleOrchestrator::update_manifests_gauge_locked() {
    if (metrics_)
        metrics_->gauge("yuzu_bundle_manifests", {{"surface", surface_}})
            .set(static_cast<double>(manifests_.size()));
}

void BundleOrchestrator::evict_expired_locked(std::int64_t now) {
    std::size_t ttl_evicted = 0;
    for (auto it = manifests_.begin(); it != manifests_.end();) {
        if (now - it->second.created_at_ms > ttl_ms_) {
            it = manifests_.erase(it);
            ++ttl_evicted;
        } else {
            ++it;
        }
    }
    if (ttl_evicted && metrics_)
        metrics_->counter("yuzu_bundle_evictions_total", {{"reason", "ttl"}})
            .increment(static_cast<double>(ttl_evicted));
}

void BundleOrchestrator::maybe_sweep_locked(std::int64_t now) {
    // Amortize the O(n) TTL scan: a polled manifest is kept alive by collate
    // refreshing its timestamp, so the global sweep need only run coarsely.
    if (now - last_sweep_ms_ < kSweepIntervalMs)
        return;
    evict_expired_locked(now);
    last_sweep_ms_ = now;
}

BundleOrchestrator::DispatchResult
BundleOrchestrator::dispatch(const std::string& agent_id, const std::vector<BundleStepSpec>& steps,
                             const std::string& principal, const AuditSink& audit,
                             const yuzu::server::authz::VisibleSet& exec_visible,
                             bool principal_is_admin,
                             yuzu::server::ApprovalProvenance approval_provenance) {
    const std::string correlation = std::string(kCorrelationPrefix) + mint_();
    // Time the synchronous fan-out so the cost of holding the HTTP worker through
    // N gRPC writes is observable BEFORE it becomes a thread-pool-starvation
    // incident (governance UP-15, mitigation C — the async-dispatch fix that
    // removes the synchronous hold is deferred to its own PR).
    const auto dispatch_start = std::chrono::steady_clock::now();

    std::vector<DispatchedStep> dispatched;
    dispatched.reserve(steps.size());
    std::size_t ok_count = 0;
    for (const auto& s : steps) {
        std::unordered_map<std::string, std::string> params;
        params.reserve(s.params.size());
        for (const auto& [k, v] : s.params)
            params[k] = v;

        // Fan out as an ORDINARY command under the shared correlation id (the
        // agent never sees a "bundle" — just a normal plugin/action). Each step
        // is isolated: a throw from dispatch_ (gRPC write failure, bad_alloc)
        // marks ONLY that step dispatch-failed and continues, so the partial
        // fan-out's already-sent commands stay collatable — the manifest is
        // ALWAYS stored below (governance UP-1: no orphaned commands).
        std::string command_id;
        bool ok = false;
        try {
            const auto outcome =
                // governance UP-8: thread the CALLER's exec_visible through
                // unchanged rather than hardcoding an unfiltered set here — the
                // wrapper (REST scoped_perm_fn / MCP in_scope) already confined
                // `agent_id` against it, so this is a defense-in-depth pass-
                // through, not a re-decision.
                //
                // PR1.9c: the same pass-through reasoning now covers the whole
                // caller. `principal` is this method's own parameter (the bundle
                // owner the wrapper authenticated), so the chokepoint sees a real
                // identity instead of the empty one that made every bundle step
                // fail `AnonymousOperator`. `principal_role` stays empty: the
                // chokepoint requires only a non-empty principal, and the
                // orchestrator has no role to report without re-deriving one.
                //
                // #1398 (adversarial-review finding): `principal_is_admin` and
                // `approval_provenance` are this method's own parameters now,
                // for the same reason `principal`/`exec_visible` are — a
                // per-step reconstruction that drops them silently defeats the
                // gate for every legitimate admin/ticket-holding caller
                // dispatching a bundle at an `AdminOrApproval`/`AlwaysApproval`
                // pair (see this method's own doc comment in
                // bundle_orchestrator.hpp).
                dispatch_(s.plugin, s.action, {agent_id}, /*scope=*/"", params, correlation,
                          yuzu::server::DispatchCaller{.principal = principal,
                                                       .exec_visible = exec_visible,
                                                       .principal_is_admin = principal_is_admin,
                                                       .approval_provenance = approval_provenance});
            command_id = outcome.command_id;
            ok = outcome.sent > 0 && !command_id.empty();
        } catch (const std::exception& e) {
            spdlog::warn("BundleOrchestrator: dispatch threw for step {}.{} ({}): {}", s.plugin,
                         s.action, correlation, e.what());
            ok = false;
            command_id.clear();
        }
        if (ok)
            ++ok_count;

        dispatched.push_back(DispatchedStep{ok ? command_id : std::string{}, s.plugin, s.action});

        // Per-step audit under its own verb (transport-agnostic; works-council
        // countability). plugin/action are validated [a-z0-9_] upstream so the
        // verb cannot be forged. target_type="Agent" so device-access audit
        // queries see bundle rows (governance compliance F1). "dispatched"
        // records access-intent, not outcome. Wrapped in try/catch so a throwing
        // audit sink can't abort the loop and orphan an already-sent command —
        // the manifest below must ALWAYS be reached (governance Gate-8 LOW).
        if (audit) {
            try {
                audit("bundle." + s.plugin + "." + s.action, ok ? "dispatched" : "no_agents",
                      "Agent", agent_id, "correlation_id=" + correlation);
            } catch (const std::exception& e) {
                spdlog::warn("BundleOrchestrator: audit sink threw for step {}.{} ({}): {}",
                             s.plugin, s.action, correlation, e.what());
            }
        }
    }

    {
        const std::int64_t now = now_ms();
        std::lock_guard lock(mu_);
        maybe_sweep_locked(now);
        // Bound the in-memory footprint: if still at the cap after expiry
        // eviction, drop the oldest manifest rather than reject a command set we
        // have already sent. NOTE: this can drop another operator's in-flight
        // bundle under sustained flood (governance UP-5) — bounded by
        // Execution:Execute + the TTL; the committed Postgres-manifest migration
        // (ADR-0011) removes the cap. Warn + meter so the loss is observable.
        if (manifests_.size() >= max_manifests_) {
            auto oldest = std::min_element(manifests_.begin(), manifests_.end(),
                                           [](const auto& a, const auto& b) {
                                               return a.second.created_at_ms < b.second.created_at_ms;
                                           });
            if (oldest != manifests_.end()) {
                spdlog::warn("BundleOrchestrator[{}]: manifest cap ({}) reached — evicting "
                             "non-expired bundle {} (owner={}) to admit {} (governance UP-5)",
                             surface_, max_manifests_, oldest->first, oldest->second.dispatched_by,
                             correlation);
                manifests_.erase(oldest);
                if (metrics_)
                    metrics_->counter("yuzu_bundle_evictions_total", {{"reason", "cap"}})
                        .increment();
            }
        }
        manifests_[correlation] = Manifest{std::move(dispatched), principal, agent_id, now};
        update_manifests_gauge_locked();
    }

    if (metrics_) {
        const char* result =
            ok_count == steps.size() ? "ok" : (ok_count == 0 ? "no_agents" : "partial");
        metrics_->counter("yuzu_bundle_dispatched_total", {{"surface", surface_}, {"result", result}})
            .increment();
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - dispatch_start).count();
        metrics_->histogram("yuzu_bundle_dispatch_duration_seconds", {{"surface", surface_}})
            .observe(secs);
    }

    return DispatchResult{correlation, steps.size()};
}

std::expected<BundleAggregate, CollateError>
BundleOrchestrator::collate(const std::string& correlation_id, const std::string& principal,
                            bool is_admin) {
    auto meter = [&](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_bundle_collated_total", {{"surface", surface_}, {"result", result}})
                .increment();
    };

    std::vector<DispatchedStep> steps;
    {
        const std::int64_t now = now_ms();
        std::lock_guard lock(mu_);
        // Find BEFORE sweeping so a single poll at the TTL boundary doesn't
        // self-evict a still-wanted bundle (governance UP-3). An active poll
        // also slides the TTL window forward, so a bundle being polled never
        // expires out from under its caller (UP-4) — only abandoned bundles do.
        auto it = manifests_.find(correlation_id);
        if (it == manifests_.end()) {
            maybe_sweep_locked(now);
            meter("not_found");
            return std::unexpected(CollateError::kNotFoundOrDenied); // unknown / already swept
        }
        // Ownership: only the dispatcher (or an admin) may collate. An empty
        // principal never owns anything (defensive — governance sec-M2/CH-7).
        // kNotFoundOrDenied is indistinguishable from not-found so existence
        // isn't an enumeration oracle (the wrapper audits the real reason).
        if (!is_admin && (principal.empty() || it->second.dispatched_by != principal)) {
            meter("denied");
            return std::unexpected(CollateError::kNotFoundOrDenied);
        }
        it->second.created_at_ms = now; // slide: an active poll keeps it alive
        steps = it->second.steps;       // copy so we release mu_ before the DB read
        maybe_sweep_locked(now);        // evict OTHERS; the target was just refreshed
    }

    if (!response_store_) {
        // The substrate itself isn't wired — this is a degrade, not a
        // genuine absence (#2691): the manifest above WAS found and owned,
        // so a caller-facing 404 here would be exactly the same false
        // "not found" Doomgoose's finding named for a store-read failure.
        meter("degraded");
        return std::unexpected(CollateError::kDegraded);
    }

    ResponseQuery rq;
    rq.limit = 1000; // bundle <= kMaxBundleSteps; well under the cap
    rq.status = -1;  // any status (step results may ride RUNNING or terminal rows)
    auto rows_opt = response_store_->query_by_execution(correlation_id, rq);
    if (!rows_opt) {
        // Degraded read (#2691, Doomgoose finding #3): distinct from
        // "not found" in the CALLER-FACING contract too, not just the
        // meter — the manifest was found and owned, so this must map to a
        // retryable 503/kInternalError, not the same terminal 404 a
        // genuinely-absent/denied bundle gets.
        meter("degraded");
        return std::unexpected(CollateError::kDegraded);
    }
    const auto& rows = *rows_opt;

    std::vector<BundleResponseRow> brows;
    brows.reserve(rows.size());
    for (const auto& r : rows)
        brows.push_back(BundleResponseRow{r.instruction_id, r.status, r.output});

    meter("found");
    return aggregate_bundle(steps, brows);
}

} // namespace yuzu::server
