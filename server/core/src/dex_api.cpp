#include "dex_api_local.hpp"

#include "dex_read_builders.hpp" // the shared build_dex_*_model helpers (store-reaching)
#include "dex_read_model.hpp"    // the pure model structs
#include "dex_window.hpp"     // dex_window_to_days / dex_iso_since / dex_normalize_os_filter (PURE)
#include "guaranteed_state_store.hpp" // the builder-less signal reads
#include "refusal_log_throttle.hpp"    // bounds the policy-unavailable warning
#include "runtime_config_store.hpp"    // dex_score_policy_store_reader

#include <spdlog/spdlog.h>

#include <string>
#include <vector>

namespace yuzu::server {

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
    LocalDexApi(GuaranteedStateStore* store, FleetFn fleet_fn, DexScorePolicyFn policy_fn)
        : store_(store), fleet_fn_(std::move(fleet_fn)), policy_fn_(std::move(policy_fn)) {}

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
        DexPolicyInForce in_force; // empty policy_fn_: the shipped defaults
        if (policy_fn_) {
            auto p = policy_fn_();
            if (!p) {
                // One line per interval, not per request: an unreadable store would
                // otherwise write one warning for every Apps read.
                if (refusal_warn_throttle_.should_warn("score_policy_unavailable"))
                    spdlog::warn("DexApi::apps: score policy unavailable: {}", p.error());
                else
                    spdlog::debug("DexApi::apps: score policy unavailable: {}", p.error());
                DexAppsModel m;
                m.window = window;
                m.degraded = true;
                m.degraded_reason = "score_policy_unavailable";
                return m;
            }
            in_force = std::move(*p);
        }
        // Absent FleetFn = unknown population (nullopt), not zero. The population
        // is the scope's connected agents' own ids, so the store draws the share
        // numerators from the same set it is divided by.
        std::optional<std::vector<std::string>> online;
        if (fleet_fn_)
            online.emplace(dex_apps_online_ids(fleet_fn_(), scope));
        return build_dex_apps_model(store_, window, since_of(window), scope, online, in_force);
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
    [[nodiscard]] DexFleet fleet() const { return fleet_fn_ ? fleet_fn_() : DexFleet{}; }

    GuaranteedStateStore* store_; ///< nullable — builders degrade; builder-less reads guard
    FleetFn fleet_fn_;
    DexScorePolicyFn policy_fn_;
    mutable RefusalLogThrottle refusal_warn_throttle_; ///< bounds the repeated-refusal warnings (score_policy_unavailable, invalid_scope)
};

std::shared_ptr<DexApi> make_local_dex_api(GuaranteedStateStore* store, FleetFn fleet_fn,
                                           DexScorePolicyFn policy_fn) {
    return std::make_shared<LocalDexApi>(store, std::move(fleet_fn), std::move(policy_fn));
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
