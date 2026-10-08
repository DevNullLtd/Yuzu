#pragma once

/// @file guardian_rule_bundle.hpp
/// Per-replica memo of the Guardian rule bundle, keyed by policy generation (#5513,
/// Fable opinion section B last paragraph and section F).
///
/// WHAT IS MEMOISED. Every heartbeat reconcile push does, before its per-agent step:
/// `GuaranteedStateStore::list_rules()` (full rows with yaml_source and spec_json),
/// `deployed_member_rule_ids()`, `guardian::filter_deployed_members(...)`, and then,
/// inside the per-rule loop, a `yuzu::scope::parse` of each distinct scope_expr. All of
/// that depends only on the rule set and the deployed-baseline set, and both are
/// changed only by operations that bump the policy generation (Fable opinion section B:
/// store create/update/delete in-txn, plus the explicit deploy/undeploy bumps). So one
/// `Bundle` per generation is sound.
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
/// inside `get`, not earlier. The generation is bumped in the same transaction as the
/// mutation, so rows read after `g` was read are at least as new as `g`. A bundle can
/// therefore be newer than its label (harmless: the pushed generation is then lower
/// than the rules, the agent reports lower than current on its next heartbeat and is
/// reconciled again) but never older.
///
/// SHAPE.
///   - ONE bundle is held (the most recently loaded). A request for a different
///     generation reloads and replaces it, including a LOWER generation (a store reset
///     is not hidden).
///   - A failed load is NOT cached. Every waiter of that load receives the error, and
///     the next call loads again. The error carries which read degraded so the caller
///     can take its existing per-source degraded branch and audit wording.
///   - SINGLE FLIGHT per generation: concurrent `get(g)` calls share one load through a
///     `std::shared_future`. Callers asking for a different generation than a running
///     load do not wait on it; they load their own. Loads are never run under the cache
///     mutex.
///   - The cache hands out `std::shared_ptr<const Bundle>`. A reload replaces the held
///     pointer but cannot invalidate a bundle an in-flight push still holds.
///   - A loader that throws is converted to a `BundleLoadError` with source `other`; the
///     in-flight state is always cleared so waiters never hang.
///
/// CLOCK INJECTION. None: this cache has no time dependence (no TTL; validity is the
/// generation). Tests drive it with an injected loader and events only.
///
/// `Bundle` is move-only because `yuzu::scope::Expression` is. Build one with
/// `make_bundle`, which parses each distinct non-empty scope_expr of the ENABLED rows
/// once.
///
/// Thread-safe. A `const Bundle` is immutable and may be read from any thread.

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

class GuardianRuleBundleCache {
public:
    using Result = std::expected<std::shared_ptr<const Bundle>, BundleLoadError>;
    /// Builds a bundle from the stores. Called without any cache lock held.
    using LoaderFn = std::function<std::expected<Bundle, BundleLoadError>()>;

    GuardianRuleBundleCache() = default;
    GuardianRuleBundleCache(const GuardianRuleBundleCache&) = delete;
    GuardianRuleBundleCache& operator=(const GuardianRuleBundleCache&) = delete;

    /// The bundle for exactly `generation`, loading it if the held bundle is for a
    /// different generation. See the header for the ordering requirement on callers.
    [[nodiscard]] Result get(std::uint64_t generation, const LoaderFn& loader) {
        std::shared_future<Result> waiting;
        std::shared_ptr<std::promise<Result>> promise;
        {
            std::lock_guard lk(mu_);
            if (held_ && held_->generation == generation)
                return held_;
            if (const auto it = inflight_.find(generation); it != inflight_.end()) {
                waiting = it->second;
            } else {
                promise = std::make_shared<std::promise<Result>>();
                inflight_.emplace(generation, promise->get_future().share());
                ++loads_;
            }
        }
        if (waiting.valid())
            return waiting.get();

        Result r = run_loader(generation, loader);
        {
            std::lock_guard lk(mu_);
            if (r.has_value())
                held_ = *r;  // failed loads are never installed
            inflight_.erase(generation);
        }
        promise->set_value(r);
        return r;
    }

    /// Drop the held bundle (tests; a future "rules changed locally" hook). A load in
    /// flight still completes and installs, and is still stamped with its own generation.
    void invalidate() {
        std::lock_guard lk(mu_);
        held_.reset();
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
    static Result run_loader(std::uint64_t generation, const LoaderFn& loader) {
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
            return std::unexpected(BundleLoadError{BundleLoadError::Source::other,
                                                   std::string("bundle loader threw: ") + e.what()});
        } catch (...) {
            return std::unexpected(BundleLoadError{
                BundleLoadError::Source::other, "bundle loader threw a non-standard exception"});
        }
    }

    mutable std::mutex mu_;
    std::shared_ptr<const Bundle> held_;
    std::map<std::uint64_t, std::shared_future<Result>> inflight_;
    std::uint64_t loads_{0};
};

}  // namespace yuzu::server::guardian
