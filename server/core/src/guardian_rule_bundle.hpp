#pragma once

/// @file guardian_rule_bundle.hpp
/// Per-replica memo of the Guardian rule bundle, keyed by policy generation (#5513).
///
/// WHAT IS MEMOISED. Every heartbeat reconcile push does, before its per-agent step:
/// `GuaranteedStateStore::list_rules()` (full rows with yaml_source and spec_json),
/// `deployed_member_rule_ids()`, `guardian::filter_deployed_members(...)`, and then,
/// inside the per-rule loop, a `yuzu::scope::parse` of each distinct scope_expr. All of
/// that depends only on the rule set and the deployed-baseline set, and both are
/// changed only by operations that bump the policy generation (rule create/update/delete
/// in the store, plus the explicit bumps on baseline deploy and on delete of a deployed
/// Baseline). So one `Bundle` per generation is sound, subject to the ordering and max-age rules below.
///
/// WHAT IS NOT MEMOISED, AND MUST NOT BE. Scope MEMBERSHIP of an agent. Tags, custom
/// properties, session OS and `scopable_tags` change with no generation bump, so a
/// generation-keyed membership cache would serve stale "member" / "not a member" to an
/// enforcing rule (and invert under NOT). The bundle holds the PARSED expression only;
/// the caller evaluates it per agent with `yuzu::scope::evaluate(expr, resolver)`.
///
/// SAFETY INVARIANT. A bundle is valid ONLY for the exact generation it was stamped
/// with. `GuardianRuleBundleCache::get(g, ...)` returns a bundle whose `generation == g`
/// or an error; it never returns the bundle of any other generation. The cache stamps
/// the generation itself (the loader cannot mislabel). ORDERING REQUIREMENT on callers:
/// obtain the generation `g` BEFORE calling `get`, and have the loader read the stores
/// inside `get`, not earlier.
///
/// WHY THE ORDERING IS SUFFICIENT, AND WHAT IT DOES NOT COVER. The generation bump is NOT
/// in the same transaction as the mutation: rule create/update/delete
/// (`guaranteed_state_store.cpp`) commit the row and then bump best-effort, and baseline
/// deploy/delete (`guardian_routes.cpp`) mutate the baseline store and then call
/// `bump_policy_generation()`. The invariant therefore rests on ORDER: a mutation commits
/// BEFORE its bump, so a reader that observes generation `g` and then reads the stores sees
/// rows at least as new as `g`. A bundle can be newer than its label (harmless: the pushed
/// generation is then lower than the rules, the agent reports lower than current on its
/// next heartbeat and is reconciled again) but never older. What ordering cannot cover is a
/// bump that FAILED after its mutation committed: the generation stays `g` while the rules
/// are newer, and a bundle held for `g` would be served until `max_age`. Two backstops, with
/// different reach. (1) On the replica that took a rule create/update/delete, the store's
/// post-mutation hook (`GuaranteedStateStore::set_on_rule_mutation`, to be wired in
/// `server.cpp` by the reconcile wire-up) calls `invalidate()` after the bump attempt whether
/// or not the bump succeeded, so the next reconcile reloads at once; a Baseline update, delete
/// or deployed create on that replica does the same through
/// `BaselineStore::set_on_baseline_mutation`, which fires after the commit and BEFORE the
/// caller's own bump (a separate lease) and fan-out, and so does every fanned-out push
/// (`guardian_push_fn_`). Once wired, all three reach one `ServerImpl` wrapper that drops both
/// caches.
/// (2) `max_age` bounds everything the hook cannot see: another replica's edit, or a double
/// fault. A held bundle older than it is a miss and is reloaded. NOTE what `max_age` heals and
/// what it does not: it heals the MEMO. An agent that was already reconciled from a stale
/// bundle was labelled with the current generation and stays Converged until the next bump
/// (or its own regression); the reload does not re-push to it. So on a missed bump the memo
/// recovers within `max_age`, but the already-served agents recover only at the next bump.
///
/// A reconcile that is ALREADY RUNNING when the hook invalidates is a third case. `get()` hands
/// a load that `invalidate()` detached to its own caller and to the waiters that had joined it
/// (see SHAPE), so that result can predate an edit whose bump failed while the generation label
/// the caller holds did not move. `epoch()` is the signal: `GuardianReconcileFlow` (added with
/// the reconcile wire-up) reads it before the fresh generation read and compares it just
/// before the send, and sends NOTHING when it advanced (guardian_reconcile_flow.hpp, added
/// with the reconcile wire-up). That closes the same-replica case and
/// no more: it does not see an edit that has committed but whose hook has not yet run, an
/// invalidation that lands between the comparison and the send, another replica's edit, or an
/// agent that converged before the edit.
///
/// SHAPE.
///   - ONE bundle is held (the most recently loaded). A request for a different
///     generation reloads and replaces it, including a LOWER generation (a store reset
///     is not hidden). The install is deliberately not monotonic (unlike the generation
///     cache): a slow load for an older generation can replace a newer held bundle, which
///     costs at most one extra reload; `get(g)` still returns only generation g.
///   - A failed load is never INSTALLED as the held bundle. Every waiter of that load
///     receives the error. The error carries which read degraded so the caller can take its
///     existing per-source degraded branch and audit wording. The failure IS remembered for a
///     short `negative_ttl` (default 1 s, measured from when the load FINISHED): a call for
///     the same generation inside that window returns the remembered error without running
///     the loader, so a store that is failing slowly is probed about once per window instead
///     of by every admitted push (each probe can cost seconds). One failure slot is kept (a
///     failure for another generation replaces it), a success clears it, and `invalidate()`
///     clears it. A load already in flight when `invalidate()` runs is DETACHED: its result
///     still goes to the callers that were waiting on it, but it installs neither a bundle
///     nor a remembered failure, and a `get()` made after the `invalidate()` starts its own
///     load instead of joining the old one (a rule edit committed after that load read its
///     rows must not be hidden by it).
///   - An expired bundle (older than `max_age`) is NEVER served when its reload fails: the
///     caller gets the error and aborts the reconcile. That is a deliberate trade, fail
///     closed over stale: serving rules that may be out of date by a failed bump would
///     enforce a policy the operator has since changed.
///   - SINGLE FLIGHT per generation: concurrent `get(g)` calls share one load through a
///     `std::shared_future`. Callers asking for a different generation than a running
///     load do not wait on it; they load their own. Loads are never run under the cache
///     mutex. A waiter blocks for at most `max_wait` and then receives an error (source
///     `other`, "timed out waiting for in-flight load"); the loading thread is unaffected.
///     `get()` can report how long THIS call spent blocked that way (see its `waited`
///     parameter) so the caller can keep another thread's load out of its own cost.
///   - The cache hands out `std::shared_ptr<const Bundle>`. A reload replaces the held
///     pointer but cannot invalidate a bundle an in-flight push still holds.
///   - A loader that throws is converted to a `BundleLoadError` with source `other`. The
///     in-flight entry is erased and the promise fulfilled on EVERY path out of the flight
///     owner (a scope guard, bookkeeping inside try/catch), so an allocation failure after
///     the flight was registered cannot wedge that generation with a flight nobody will
///     complete.
///   - A held bundle older than `max_age` is a miss (see the safety invariant).
///
/// CLOCK INJECTION. `ClockFn` is `std::function<std::chrono::steady_clock::time_point()>`;
/// null selects the real steady clock. It is called under the internal mutex (and, to time a
/// wait, outside it) and must be thread-safe and not call back into the cache. A bundle's age
/// is measured from when its load STARTED, the conservative end of the read's age, so a load that
/// itself takes longer than `max_age` is stale on arrival and is reloaded by the next call
/// (deliberate: its rows may be that old). Pinned by a test that advances the clock inside the loader. A clock
/// that moves backwards leaves the bundle fresh. Tests inject a manual clock and a loader
/// that blocks on an event, so nothing sleeps.
///
/// `Bundle` is move-only because `yuzu::scope::Expression` is. Build one with
/// `make_bundle`, which parses each distinct non-empty scope_expr of the ENABLED rows
/// once.
///
/// Thread-safe. A `const Bundle` is immutable and may be read from any thread.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "guardian_types.hpp"  // GuaranteedStateRuleRow
#include "scope_engine.hpp"    // yuzu::scope::Expression, parse

namespace yuzu::server::guardian {

/// A scope_expr parsed once. `expression` is empty when the text did not parse; the
/// reconcile treats that as "not a member" (arm nothing), as it did before the memo.
struct ParsedScope {
    std::optional<yuzu::scope::Expression> expression;
    std::string parse_error;  // set iff `expression` is empty
};

struct Bundle {
    /// The generation this bundle is valid for. Stamped by the cache.
    std::uint64_t generation{0};
    /// The rules exactly as the reconcile consumes them: the result of
    /// `guardian::filter_deployed_members(list_rules(), deployed_member_rule_ids())`,
    /// order preserved. Passed straight to `guardian::build_agent_push`.
    std::vector<GuaranteedStateRuleRow> rules;
    /// The deployed member rule ids the filter used (kept for diagnostics and parity).
    std::unordered_set<std::string> deployed_rule_ids;
    /// Every distinct non-empty `scope_expr` of an enabled rule in `rules`, parsed once.
    std::unordered_map<std::string, ParsedScope> scopes;

    /// The parsed expression for `scope_expr`, or nullptr when the expression is not
    /// in the bundle or did not parse. nullptr means "not a member" to the reconcile.
    /// The pointer is valid while the bundle (the shared_ptr) is alive.
    [[nodiscard]] const yuzu::scope::Expression* find_scope(const std::string& scope_expr) const {
        const auto it = scopes.find(scope_expr);
        if (it == scopes.end() || !it->second.expression)
            return nullptr;
        return &*it->second.expression;
    }
};

/// Build a bundle from rows ALREADY filtered through `filter_deployed_members`
/// (kept out of this header so it stays free of the protobuf includes that
/// guardian_push_builder.hpp carries). The generation field is left for the cache to
/// stamp.
[[nodiscard]] inline Bundle make_bundle(std::vector<GuaranteedStateRuleRow> filtered_rules,
                                        std::unordered_set<std::string> deployed_rule_ids) {
    Bundle b;
    b.rules = std::move(filtered_rules);
    b.deployed_rule_ids = std::move(deployed_rule_ids);
    for (const auto& row : b.rules) {
        if (!row.enabled || row.scope_expr.empty() || b.scopes.contains(row.scope_expr))
            continue;
        ParsedScope ps;
        if (auto parsed = yuzu::scope::parse(row.scope_expr))
            ps.expression = std::move(*parsed);
        else
            ps.parse_error = std::move(parsed.error());
        b.scopes.emplace(row.scope_expr, std::move(ps));
    }
    return b;
}

/// Why a bundle could not be loaded. `source` lets the caller reproduce the existing
/// per-source abort counter, log and audit wording.
struct BundleLoadError {
    enum class Source { rules, deployed, other };
    Source source{Source::other};
    std::string detail;
};

/// Cache tuning (namespace scope so it can be a default argument).
struct GuardianRuleBundleCacheConfig {
    /// A held bundle older than this is reloaded even if its generation still matches.
    std::chrono::milliseconds max_age{60'000};
    /// Longest a waiter blocks on another thread's in-flight load.
    std::chrono::milliseconds max_wait{5'000};
    /// How long a FAILED load for a generation is remembered (see the header). Zero
    /// disables the negative cache.
    std::chrono::milliseconds negative_ttl{1'000};
};

class GuardianRuleBundleCache {
public:
    using Result = std::expected<std::shared_ptr<const Bundle>, BundleLoadError>;
    /// Builds a bundle from the stores. Called without any cache lock held.
    using LoaderFn = std::function<std::expected<Bundle, BundleLoadError>()>;
    using Clock = std::chrono::steady_clock;
    /// Null selects `steady_clock::now`.
    using ClockFn = std::function<Clock::time_point()>;
    using Config = GuardianRuleBundleCacheConfig;

    explicit GuardianRuleBundleCache(Config cfg = {}, ClockFn clock = {})
        : cfg_(cfg), clock_(clock ? std::move(clock) : ClockFn{[] { return Clock::now(); }}) {}
    GuardianRuleBundleCache(const GuardianRuleBundleCache&) = delete;
    GuardianRuleBundleCache& operator=(const GuardianRuleBundleCache&) = delete;

    /// The bundle for exactly `generation`, loading it if the held bundle is for a
    /// different generation or is older than `max_age`. See the header for the ordering
    /// requirement on callers.
    ///
    /// `waited`, when given, is set to the time THIS call spent blocked waiting on another
    /// thread's in-flight load: zero for a cache hit, a remembered failure, and for the
    /// thread that runs the loader itself (its load time is its own cost, not a wait).
    [[nodiscard]] Result get(std::uint64_t generation, const LoaderFn& loader,
                             std::chrono::nanoseconds* waited = nullptr) {
        if (waited != nullptr)
            *waited = std::chrono::nanoseconds{0};
        std::shared_future<Result> waiting;
        std::shared_ptr<std::promise<Result>> promise;
        Clock::time_point started;
        std::uint64_t epoch = 0;
        {
            std::lock_guard lk(mu_);
            const auto now = clock_();
            if (held_ && held_->generation == generation && fresh_locked(now))
                return held_;
            if (failed_ && failed_->generation == generation && negative_fresh_locked(now))
                return std::unexpected(failed_->error);
            if (const auto it = inflight_.find(generation); it != inflight_.end()) {
                waiting = it->second;
            } else {
                promise = std::make_shared<std::promise<Result>>();
                inflight_.emplace(generation, promise->get_future().share());
                ++loads_;
                started = now;
                epoch = epoch_;
            }
        }
        if (waiting.valid()) {
            const auto t0 = clock_();
            Result r = wait_for_flight(waiting);
            if (waited != nullptr)
                *waited = std::max(std::chrono::duration_cast<std::chrono::nanoseconds>(clock_() - t0),
                                   std::chrono::nanoseconds{0});
            return r;
        }

        // The registered flight is completed (erased) unconditionally by the guard.
        FlightGuard flight{*this, generation, epoch};
        Result r = run_loader(generation, loader);
        install(r, generation, started, epoch);
        flight.fulfil(*promise, r);
        return r;
    }

    /// Drop the held bundle and any remembered failure (called when the generation was just
    /// bumped locally, after a rule edit, and by tests). A load in flight is detached: its
    /// own callers still receive its result, but it installs nothing (neither a bundle nor a
    /// remembered failure), and the next get() starts a fresh load rather than joining it.
    void invalidate() {
        // Declared BEFORE the lock so a held bundle that this call drops is destroyed after
        // mu_ is released (a Bundle destructor must not run under the cache mutex).
        std::shared_ptr<const Bundle> dropped;
        std::lock_guard lk(mu_);
        dropped = std::move(held_);
        failed_.reset();
        inflight_.clear();
        ++epoch_;
    }

    /// The invalidation epoch: advances by one on every `invalidate()`, never otherwise.
    /// A caller that must not act on a result a concurrent `invalidate()` could have made
    /// stale reads it BEFORE `get()` and compares it again after: `get()` hands a load that was
    /// detached by `invalidate()` to its own callers (and to the waiters that had joined it),
    /// so the result alone does not say whether an invalidation overtook it. Safe from any
    /// thread.
    [[nodiscard]] std::uint64_t epoch() const {
        std::lock_guard lk(mu_);
        return epoch_;
    }

    /// Number of loads started (single-flight waiters and cache hits do not count).
    [[nodiscard]] std::uint64_t loads() const {
        std::lock_guard lk(mu_);
        return loads_;
    }

    /// The generation of the held bundle, if any (diagnostics and tests).
    [[nodiscard]] std::optional<std::uint64_t> held_generation() const {
        std::lock_guard lk(mu_);
        if (!held_)
            return std::nullopt;
        return held_->generation;
    }

private:
    bool fresh_locked(Clock::time_point now) const {
        if (now <= held_at_)
            return true;  // clock did not advance (or went backwards)
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - held_at_) <
               cfg_.max_age;
    }

    bool negative_fresh_locked(Clock::time_point now) const {
        if (now <= failed_->at)
            return true;  // clock did not advance (or went backwards)
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - failed_->at) <
               cfg_.negative_ttl;
    }

    // Never throws: a failure here only means the next get() loads again.
    //
    // Unlike GuardianGenerationCache::install (MONOTONIC INSTALL), this install is DELIBERATELY
    // not monotonic: a slow load for an older generation that finishes last can replace a
    // newer held bundle. The cost is at most one extra reload, and get(g) still returns only a
    // bundle for generation g (it checks `held_->generation`), so no caller is ever handed a
    // bundle for the wrong generation.
    void install(const Result& r, std::uint64_t generation, Clock::time_point started,
                 std::uint64_t epoch) noexcept {
        // Declared BEFORE the try/lock so the replaced bundle is destroyed after mu_ is
        // released (a Bundle destructor must not run under the cache mutex).
        std::shared_ptr<const Bundle> replaced;
        try {
            std::lock_guard lk(mu_);
            if (epoch != epoch_)
                return;  // invalidate() ran during the load: its rows may predate the edit
            if (r.has_value()) {
                replaced = std::move(held_);
                held_ = *r;
                held_at_ = started;
                failed_.reset();
            } else if (cfg_.negative_ttl.count() > 0) {
                // A failed load is never the held bundle; it is remembered only so the next
                // calls in the window do not each re-run a slow, failing loader. Stamped with
                // the time the load FINISHED, otherwise a load slower than the TTL would
                // expire its own entry before it was stored.
                failed_ = Failure{generation, r.error(), clock_()};
            }
        } catch (...) {
            try {
                std::lock_guard lk(mu_);
                failed_.reset();  // do not keep an entry that may be half-assigned
            } catch (...) {
            }
        }
    }

    Result wait_for_flight(const std::shared_future<Result>& f) const noexcept {
        try {
            if (f.wait_for(cfg_.max_wait) != std::future_status::ready)
                return std::unexpected(BundleLoadError{
                    BundleLoadError::Source::other, "timed out waiting for in-flight load"});
            return f.get();
        } catch (...) {
            // Broken promise, or the copy of the result threw. A literal short enough for
            // the small-string buffer, so building it cannot allocate.
            return std::unexpected(
                BundleLoadError{BundleLoadError::Source::other, "load failed"});
        }
    }

    // Owns one registered flight; the destructor ALWAYS erases it. The erase happens at most
    // once: a second one could remove a NEWER flight for the same generation that another
    // thread registered after the first. A promise that is never fulfilled is broken by its
    // own destructor, which wakes every waiter.
    struct FlightGuard {
        GuardianRuleBundleCache& c;
        std::uint64_t generation;
        std::uint64_t epoch;  // the cache epoch at registration
        bool erased{false};

        ~FlightGuard() { clear(); }

        void clear() noexcept {
            if (erased)
                return;
            try {
                std::lock_guard lk(c.mu_);
                // invalidate() clears the whole map and bumps the epoch: after that, an
                // entry for this generation belongs to a NEWER flight and is not ours.
                if (epoch == c.epoch_)
                    c.inflight_.erase(generation);
                erased = true;
            } catch (...) {
                // mu_ could not be taken: the destructor retries once more.
            }
        }

        // Erase the flight BEFORE publishing the value so a woken waiter that calls get()
        // again does not find this flight still registered.
        void fulfil(std::promise<Result>& p, const Result& r) noexcept {
            clear();
            try {
                p.set_value(r);
            } catch (...) {
                try {
                    p.set_exception(std::current_exception());
                } catch (...) {
                }
            }
        }
    };

    // Never throws.
    static Result run_loader(std::uint64_t generation, const LoaderFn& loader) noexcept {
        try {
            if (!loader)
                return std::unexpected(
                    BundleLoadError{BundleLoadError::Source::other, "no bundle loader configured"});
            try {
                auto loaded = loader();
                if (!loaded)
                    return std::unexpected(std::move(loaded.error()));
                loaded->generation = generation;  // the cache, not the loader, stamps validity
                return std::make_shared<const Bundle>(std::move(*loaded));
            } catch (const std::exception& e) {
                return std::unexpected(BundleLoadError{
                    BundleLoadError::Source::other, std::string("bundle loader threw: ") + e.what()});
            } catch (...) {
                return std::unexpected(BundleLoadError{
                    BundleLoadError::Source::other, "bundle loader threw a non-standard exception"});
            }
        } catch (...) {
            return std::unexpected(BundleLoadError{BundleLoadError::Source::other, "load failed"});
        }
    }

    struct Failure {
        std::uint64_t generation;
        BundleLoadError error;
        Clock::time_point at;
    };

    const Config cfg_;
    const ClockFn clock_;
    mutable std::mutex mu_;
    std::optional<Failure> failed_;
    std::uint64_t epoch_{0};
    std::shared_ptr<const Bundle> held_;
    Clock::time_point held_at_{};
    std::map<std::uint64_t, std::shared_future<Result>> inflight_;
    std::uint64_t loads_{0};
};

}  // namespace yuzu::server::guardian
