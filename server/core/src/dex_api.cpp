#include "dex_api_local.hpp"

#include "dex_read_builders.hpp" // the shared build_dex_*_model helpers (store-reaching)
#include "dex_read_model.hpp"    // the pure model structs
#include "dex_window.hpp"     // dex_window_to_days / dex_iso_since / dex_normalize_os_filter (PURE)
#include "guaranteed_state_store.hpp" // the builder-less signal reads
#include "refusal_log_throttle.hpp"    // bounds the policy-unavailable warning
#include "runtime_config_store.hpp"    // dex_score_policy_store_reader
#include "sha256_hex.hpp"              // the usage cache key digest

#include <yuzu/log_token.hpp> // log_key_token: neutralise and cap an exception's text

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {
/// The usage cache holds at most this many models (each is reused for `DexUsageWiring::cache_ttl`).
constexpr std::size_t kUsageCacheCap = 32;
} // namespace

/// Store-backed `DexApi` implementation — the DEX signals/experience-score
/// assembly, moved verbatim behind the seam so it is independently testable
/// (ADR-0031 WS-A4). Behaviour is preserved exactly: every builder-backed
/// method derives `since = dex_iso_since(dex_window_to_days(window))` and the
/// `DexFleet` denominator the same way the handlers this replaces did
/// (`fleet_fn_ ? fleet_fn_() : DexFleet{}`), then calls the SAME shared
/// `build_dex_*_model` helper; every builder-less method makes the SAME raw
/// store reads the handler assembled inline, returning the pure rows for the
/// handler to serialize unchanged. `store_` may be null (every builder already
/// degrades to an empty/`-1` model; the builder-less reads guard on it).
class LocalDexApi final : public DexApi {
public:
    LocalDexApi(GuaranteedStateStore* store, FleetFn fleet_fn, DexScorePolicyFn policy_fn,
                DexObserverFn observer_fn, DexUsageWiring usage)
        : store_(store),
          fleet_fn_(std::move(fleet_fn)),
          policy_fn_(std::move(policy_fn)),
          observer_fn_(std::move(observer_fn)),
          usage_(std::move(usage)) {}

    LocalDexApi(const LocalDexApi&) = delete;
    LocalDexApi& operator=(const LocalDexApi&) = delete;

    // ── Builder-backed ──

    [[nodiscard]] DexDeviceScoreModel device_score(const std::string& agent_id,
                                                   const std::string& window) const override {
        return build_dex_device_score_model(store_, agent_id, window, since_of(window));
    }

    [[nodiscard]] DexDeviceHistoryModel device_history(const std::string& agent_id,
                                                       const std::string& window) const override {
        return build_dex_device_history_model(store_, agent_id, window, since_of(window));
    }

    [[nodiscard]] std::optional<GuardianObservationRow>
    observation(const std::string& agent_id, const std::string& event_id) const override {
        return build_dex_observation_model(store_, agent_id, event_id);
    }

    [[nodiscard]] DexAppModel app(const std::string& process_name,
                                  const std::string& window) const override {
        // `DexApi::app` has no `visible` parameter (WS-A4 PR-1 — see
        // dex_api.hpp's own doc comment); the
        // builder itself keeps its own `visible` parameter for the
        // dashboard fragment rewire (PR-2) to decide the fate of, so this
        // seam always passes `nullptr`.
        return build_dex_app_model(store_, process_name, window, since_of(window), nullptr);
    }

    [[nodiscard]] DexAppsModel apps(const std::string& window,
                                    const std::string& platform_scope) const override {
        // The scope first: an unknown token fails closed, before any policy or fleet work.
        const std::string scope = dex_normalize_apps_scope(platform_scope);
        if (scope.empty()) {
            DexAppsModel m;
            m.window = window;
            m.degraded = true;
            m.degraded_reason = "invalid_scope";
            // Constant text, never the caller's token; one line per interval.
            if (refusal_warn_throttle_.should_warn("invalid_scope"))
                spdlog::warn("DexApi::apps: platform scope refused (invalid_scope)");
            return m;
        }
        // The policy next: an unavailable policy answers without a fleet snapshot, and a
        // policy read that stalls cannot leave a stale snapshot behind it.
        auto policy = policy_in_force("DexApi::apps");
        if (!policy) {
            DexAppsModel m;
            m.window = window;
            m.degraded = true;
            m.degraded_reason = "score_policy_unavailable";
            return m;
        }
        // Absent FleetFn = unknown population (nullopt), not zero.
        std::optional<DexFleet> fleet;
        if (fleet_fn_)
            fleet.emplace(fleet_fn_());
        DexAppsModel m = apps_at(window, scope, *policy, fleet, request_instant());
        // The live observer split is read only after a successful read, from the same snapshot and
        // the same ids the population was counted from, so the split and the population cannot
        // disagree. A refused or failed read never pays the pass; no observer source = unknown.
        // The split is an optional addition to a read that already succeeded, so a provider that
        // throws is contained here, once for the REST, MCP and page callers alike: the model keeps
        // every figure and `observer_state` stays unset, the same as no source wired.
        if (!m.degraded && fleet && observer_fn_) {
            const auto failed = [this](const std::string& what) {
                // One line per interval, not per request.
                if (refusal_warn_throttle_.should_warn("observer_unavailable"))
                    spdlog::warn("DexApi::apps: observer state unavailable: {}", what);
                else
                    spdlog::debug("DexApi::apps: observer state unavailable: {}", what);
            };
            try {
                m.observer_state =
                    dex_apps_observer_split(*fleet, scope, observer_fn_(dex_apps_online_ids(*fleet, scope)));
            } catch (const std::exception& e) {
                failed(::yuzu::log_key_token(e.what()));
            } catch (...) {
                failed("non-standard exception");
            }
        }
        return m;
    }

    [[nodiscard]] std::expected<DexAppsUsageModel, DexUsageRefusal>
    apps_usage(const std::string& window, const std::string& platform_scope, const DexUsageSlice& slice,
               std::int64_t floor,
               const std::optional<std::unordered_set<std::string>>& visible) const override {
        using std::unexpected;
        const std::string scope = dex_normalize_apps_scope(platform_scope);
        if (scope.empty()) {
            if (refusal_warn_throttle_.should_warn("invalid_scope"))
                spdlog::warn("DexApi::apps_usage: platform scope refused (invalid_scope)");
            return unexpected(DexUsageRefusal{"apps_degraded", "invalid_scope"});
        }
        const auto policy = policy_in_force("DexApi::apps_usage");
        if (!policy)
            return unexpected(DexUsageRefusal{"apps_degraded", "score_policy_unavailable"});
        if (!fleet_fn_)
            return unexpected(DexUsageRefusal{"no_population", ""});
        if (!usage_.read)
            return unexpected(DexUsageRefusal{"usage_unavailable", "not_wired"});

        // ONE instant and ONE fleet snapshot for the whole request: the observation window cut, the
        // Apps population and the usage population all derive from them. The usage freshness cut
        // does not: the owner measures it against the database clock that authored `last_seen`.
        const std::int64_t now = request_instant();
        const std::optional<DexFleet> snapshot{fleet_fn_()};
        DexFleet visible_fleet = *snapshot;
        std::erase_if(visible_fleet.connected_agents, [&](const auto& agent) {
            return visible && !visible->contains(agent.first);
        });

        DexUsageSlice norm = slice;
        if (norm.kind == DexUsageSliceKind::Tag && norm.key.empty())
            norm.key = kDexDefaultCohortKey;
        floor = std::max<std::int64_t>(floor, 1); // the model applies at least 1; the key says so
        const std::string key = usage_cache_key(window, scope, norm, floor, policy->revision, visible_fleet);
        if (!key.empty()) {
            if (auto hit = usage_cache_get(key))
                return std::move(*hit);
        }

        const DexAppsModel apps = apps_at(window, scope, *policy, snapshot, now);

        std::string read_fault, group_fault;
        DexUsageSources sources;
        sources.read = [&](const DexUsageQuery& q) -> std::optional<DexUsageRead> {
            auto r = usage_.read(q);
            if (!r) {
                read_fault = r.error();
                return std::nullopt;
            }
            return std::move(*r);
        };
        if (usage_.group_members) {
            sources.group_members =
                [&](const std::string& id) -> std::optional<std::vector<std::string>> {
                auto r = usage_.group_members(id);
                if (!r) {
                    group_fault = r.error();
                    return std::nullopt;
                }
                return std::move(*r);
            };
        } else {
            group_fault = "not_wired";
        }
        sources.tag_values = usage_.tag_values;

        auto model = build_dex_apps_usage_model(
            apps, visible_fleet,
            DexUsageRequest{norm, now, usage_.observation_retention_days, floor}, sources);
        if (!model) {
            const std::string& token = model.error();
            if (token == "group_unavailable" && group_fault == "unknown_group")
                return unexpected(DexUsageRefusal{"invalid_slice", "unknown_group"});
            if (token == "apps_degraded")
                return unexpected(DexUsageRefusal{token, apps.degraded_reason});
            if (token == "group_unavailable")
                return unexpected(DexUsageRefusal{token, group_fault});
            if (token == "usage_unavailable")
                return unexpected(DexUsageRefusal{token, read_fault.empty() ? "invalid_read" : read_fault});
            return unexpected(DexUsageRefusal{token, ""});
        }
        if (!key.empty())
            usage_cache_put(key, *model);
        return std::move(*model);
    }

    [[nodiscard]] DexCatalogueModel catalogue(const std::string& os_filter,
                                              const std::string& window) const override {
        return build_dex_catalogue_model(store_, fleet(), os_filter, window);
    }

    [[nodiscard]] std::optional<DexCatalogueGroupModel>
    catalogue_group(const std::string& group_name, const std::string& os_filter,
                    const std::string& window) const override {
        return build_dex_catalogue_group_model(store_, group_name, os_filter, fleet(), window,
                                               since_of(window));
    }

    [[nodiscard]] DexHealthModel health(const std::string& weighting,
                                        const std::string& window) const override {
        return build_dex_health_model(store_, fleet(), weighting, window, since_of(window));
    }

    [[nodiscard]] DexTrendsModel trends(const std::string& window) const override {
        return build_dex_trends_model(store_, fleet(), window, since_of(window));
    }

    [[nodiscard]] DexOverviewModel overview(const std::string& window) const override {
        // Same nullptr-always posture as `app` above — see its comment.
        const int window_days = dex_window_to_days(window);
        return build_dex_overview_model(store_, fleet(), window, window_days,
                                        dex_iso_since(window_days), nullptr);
    }

    // ── Builder-less (raw store reads assembled inline in the handler today) ──

    [[nodiscard]] std::vector<DexSignalCount>
    signals(const std::string& window, const std::string& os_filter) const override {
        if (!store_)
            return {};
        return store_->dex_signal_summary(since_of(window), dex_normalize_os_filter(os_filter));
    }

    [[nodiscard]] std::vector<DexOsScope> scope(const std::string& window) const override {
        if (!store_)
            return {};
        return store_->dex_os_signal_scope(since_of(window));
    }

    [[nodiscard]] DexSignalDetailModel signal_detail(const std::string& obs_type,
                                                     const std::string& window,
                                                     const std::string& os_filter,
                                                     int limit) const override {
        DexSignalDetailModel out;
        if (!store_)
            return out;
        const std::string since = since_of(window);
        const std::string os_scope = dex_normalize_os_filter(os_filter);
        out.subjects = store_->dex_signal_subjects(obs_type, since, limit, os_scope);
        out.by_os = store_->dex_signal_by_os(obs_type, since);
        // WS-A4 PR-1 Gate 7 fix round: no per-row `visible` filter here — see
        // this method's own doc comment in dex_api.hpp for why a post-limit
        // filter was removed rather than kept (it left the sibling
        // aggregates fleet-wide for every caller regardless of confinement).
        out.devices = store_->dex_signal_devices(obs_type, since, limit, os_scope);
        out.by_day = store_->dex_signal_by_day(obs_type, since, os_scope);
        return out;
    }

private:
    [[nodiscard]] static std::string since_of(const std::string& window) {
        return dex_iso_since(dex_window_to_days(window));
    }

    /// The one instant source of this API: Apps and usage reads cut their windows from it.
    [[nodiscard]] std::int64_t request_instant() const {
        if (usage_.now_epoch)
            return usage_.now_epoch();
        return static_cast<std::int64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    }

    /// The score policy in force (the shipped defaults when no provider is wired), or nullopt
    /// when it cannot be read. One warn line per interval, not per request: an unreadable store
    /// would otherwise write one warning for every read.
    [[nodiscard]] std::optional<DexPolicyInForce> policy_in_force(const char* caller) const {
        if (!policy_fn_)
            return DexPolicyInForce{}; // empty policy_fn_: the shipped defaults
        auto p = policy_fn_();
        if (p)
            return std::move(*p);
        if (refusal_warn_throttle_.should_warn("score_policy_unavailable"))
            spdlog::warn("{}: score policy unavailable: {}", caller, p.error());
        else
            spdlog::debug("{}: score policy unavailable: {}", caller, p.error());
        return std::nullopt;
    }

    /// The Apps read for `now`: the window cut and the model, nothing else. The observer split is
    /// `apps()`'s alone, so a usage read never pays for it. The population is the scope's
    /// connected agents' own ids, so the store draws the share numerators from the same set it is
    /// divided by; an absent fleet is an unknown population (nullopt), not zero.
    [[nodiscard]] DexAppsModel apps_at(const std::string& window, const std::string& scope,
                                       const DexPolicyInForce& in_force,
                                       const std::optional<DexFleet>& fleet, std::int64_t now) const {
        std::optional<std::vector<std::string>> online;
        if (fleet)
            online.emplace(dex_apps_online_ids(*fleet, scope));
        return build_dex_apps_model(store_, window, dex_iso_since_at(now, dex_window_to_days(window)), scope,
                                    online, in_force);
    }

    /// sha256 of the length-prefixed request shape and the SORTED visible population, so the
    /// visible set is in the key and a confined caller can never hit an entry built for a wider
    /// one. Empty (= bypass the cache) when the digest fails.
    [[nodiscard]] static std::string usage_cache_key(const std::string& window, const std::string& scope,
                                                     const DexUsageSlice& slice, std::int64_t floor,
                                                     const std::string& policy_revision,
                                                     const DexFleet& visible_fleet) {
        std::string material;
        const auto add = [&material](const std::string& part) {
            material += std::to_string(part.size());
            material.push_back(':');
            material += part;
        };
        add(window);
        add(scope);
        add(std::to_string(static_cast<int>(slice.kind)));
        add(slice.key);
        add(std::to_string(floor));
        add(policy_revision);
        auto agents = visible_fleet.connected_agents;
        std::sort(agents.begin(), agents.end());
        for (const auto& [id, os] : agents) {
            add(id);
            add(os);
        }
        return sha256_hex(material).value_or(std::string{});
    }

    [[nodiscard]] std::optional<DexAppsUsageModel> usage_cache_get(const std::string& key) const {
        std::lock_guard lock(usage_cache_mu_);
        const auto it = usage_cache_.find(key);
        if (it == usage_cache_.end())
            return std::nullopt;
        if (std::chrono::steady_clock::now() - it->second.at >= usage_.cache_ttl) {
            usage_cache_.erase(it);
            return std::nullopt;
        }
        return it->second.model;
    }

    /// Only a successful model is cached. When the cache is full the expired entries go first,
    /// else it is cleared: bounded memory, no eviction order to maintain.
    void usage_cache_put(const std::string& key, const DexAppsUsageModel& model) const {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(usage_cache_mu_);
        if (usage_cache_.size() >= kUsageCacheCap && !usage_cache_.contains(key)) {
            std::erase_if(usage_cache_,
                          [&](const auto& e) { return now - e.second.at >= usage_.cache_ttl; });
            if (usage_cache_.size() >= kUsageCacheCap)
                usage_cache_.clear();
        }
        usage_cache_.insert_or_assign(key, UsageCacheEntry{now, model});
    }
    [[nodiscard]] DexFleet fleet() const { return fleet_fn_ ? fleet_fn_() : DexFleet{}; }

    GuaranteedStateStore* store_; ///< nullable — builders degrade; builder-less reads guard
    FleetFn fleet_fn_;
    DexScorePolicyFn policy_fn_;
    DexObserverFn observer_fn_;
    DexUsageWiring usage_;
    struct UsageCacheEntry {
        std::chrono::steady_clock::time_point at;
        DexAppsUsageModel model;
    };
    mutable std::mutex usage_cache_mu_;
    mutable std::unordered_map<std::string, UsageCacheEntry> usage_cache_; ///< kUsageCacheCap entries at most
    mutable RefusalLogThrottle refusal_warn_throttle_; ///< bounds the repeated warnings (score_policy_unavailable, invalid_scope, observer_unavailable)
};

std::shared_ptr<DexApi> make_local_dex_api(GuaranteedStateStore* store, FleetFn fleet_fn,
                                           DexScorePolicyFn policy_fn, DexObserverFn observer_fn,
                                           DexUsageWiring usage) {
    return std::make_shared<LocalDexApi>(store, std::move(fleet_fn), std::move(policy_fn),
                                         std::move(observer_fn), std::move(usage));
}

DexScorePolicyProvider::ReadFn dex_score_policy_store_reader(RuntimeConfigStore& store) {
    return [&store]() -> std::expected<std::optional<std::string>, std::string> {
        auto r = store.get(std::string(kDexScorePolicyKey));
        if (!r)
            return std::unexpected(r.error());
        if (!*r)
            return std::nullopt;
        return (*r)->value;
    };
}

DexScorePolicyStoreFns dex_score_policy_store_writer(RuntimeConfigStore& store) {
    return {
        [&store](const std::optional<std::string>& expected, const std::string& canonical,
                 const std::string& actor) {
            return store.compare_and_set(std::string(kDexScorePolicyKey), expected, canonical,
                                         actor);
        },
        [&store](const std::string& expected) {
            return store.compare_and_remove(std::string(kDexScorePolicyKey), expected);
        }};
}

} // namespace yuzu::server
