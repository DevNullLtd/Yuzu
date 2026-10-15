#pragma once

/// @file test_dex_api_double.hpp
/// FnDexApi — a test-only `DexApi` adapter backed by plain `std::function`s,
/// mirroring `FnGuardianApi`/`FnWorkflowApi`/`FnScheduleApi`/`FnVerifyApi`
/// (test_guardian_api_double.hpp et al). Lets a route/MCP test inject an
/// ARBITRARY result for any of `DexApi`'s thirteen methods without standing
/// up a real `GuaranteedStateStore` or a `FleetFn`, and (its real purpose)
/// lets a seam-bypass tripwire test wire a DISTINGUISHING double alongside a
/// real, separately-answering store at the same id/key, so a REST/MCP
/// handler silently reverted to call the raw store directly answers
/// DIFFERENTLY than one still calling the seam.
///
/// An unwired (default-constructed, empty `std::function`) field answers with
/// the SAME "unavailable"/null-store shape `LocalDexApi`'s own builders use —
/// echoing back the request-shaped fields a builder sets BEFORE its own
/// `if (!store) return m;` early return (agent_id/window/process_name/os/
/// total_types/weighting-normalisation/…), with every data field left at the
/// model struct's own default member initializer (score/health_score/-1,
/// empty vectors, `degraded=true` where the model has that field) — so a test
/// that forgets to wire a method it actually exercises gets an HONEST,
/// visibly-degraded answer (never a fabricated "healthy" one), matching what
/// a null-store production seam would already return, rather than a value a
/// human reviewer could mistake for real data. `observation`/`catalogue_group`
/// (the two `optional`-returning methods) default to `std::nullopt`, the same
/// "not found / degraded" sentinel their own doc comments already document.
///
/// NOT for production use — the production factory is `make_local_dex_api`
/// (dex_api.hpp).

#include "dex_api.hpp"
#include "dex_window.hpp" // dex_normalize_os_filter -- PURE, needed for the catalogue() default's os echo

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnDexApi final : public yuzu::server::DexApi {
public:
    using DeviceScoreFn = std::function<yuzu::server::DexDeviceScoreModel(
        const std::string& agent_id, const std::string& window)>;
    using DeviceHistoryFn = std::function<yuzu::server::DexDeviceHistoryModel(
        const std::string& agent_id, const std::string& window)>;
    using ObservationFn = std::function<std::optional<yuzu::server::GuardianObservationRow>(
        const std::string& agent_id, const std::string& event_id)>;
    using AppFn = std::function<yuzu::server::DexAppModel(const std::string& process_name,
                                                           const std::string& window)>;
    using AppsFn = std::function<yuzu::server::DexAppsModel(const std::string& window)>;
    using CatalogueFn = std::function<yuzu::server::DexCatalogueModel(
        const std::string& os_filter, const std::string& window)>;
    using CatalogueGroupFn = std::function<std::optional<yuzu::server::DexCatalogueGroupModel>(
        const std::string& group_name, const std::string& os_filter, const std::string& window)>;
    using HealthFn = std::function<yuzu::server::DexHealthModel(const std::string& weighting,
                                                                const std::string& window)>;
    using TrendsFn = std::function<yuzu::server::DexTrendsModel(const std::string& window)>;
    using OverviewFn =
        std::function<yuzu::server::DexOverviewModel(const std::string& window)>;
    using SignalsFn = std::function<std::vector<yuzu::server::DexSignalCount>(
        const std::string& window, const std::string& os_filter)>;
    using ScopeFn = std::function<std::vector<yuzu::server::DexOsScope>(const std::string& window)>;
    using SignalDetailFn = std::function<yuzu::server::DexSignalDetailModel(
        const std::string& obs_type, const std::string& window, const std::string& os_filter,
        int limit)>;

    FnDexApi(DeviceScoreFn device_score_fn = {}, DeviceHistoryFn device_history_fn = {},
             ObservationFn observation_fn = {}, AppFn app_fn = {}, AppsFn apps_fn = {},
             CatalogueFn catalogue_fn = {}, CatalogueGroupFn catalogue_group_fn = {},
             HealthFn health_fn = {}, TrendsFn trends_fn = {}, OverviewFn overview_fn = {},
             SignalsFn signals_fn = {}, ScopeFn scope_fn = {}, SignalDetailFn signal_detail_fn = {})
        : device_score_fn_(std::move(device_score_fn)),
          device_history_fn_(std::move(device_history_fn)),
          observation_fn_(std::move(observation_fn)), app_fn_(std::move(app_fn)),
          apps_fn_(std::move(apps_fn)), catalogue_fn_(std::move(catalogue_fn)),
          catalogue_group_fn_(std::move(catalogue_group_fn)), health_fn_(std::move(health_fn)),
          trends_fn_(std::move(trends_fn)), overview_fn_(std::move(overview_fn)),
          signals_fn_(std::move(signals_fn)), scope_fn_(std::move(scope_fn)),
          signal_detail_fn_(std::move(signal_detail_fn)) {}

    [[nodiscard]] yuzu::server::DexDeviceScoreModel
    device_score(const std::string& agent_id, const std::string& window) const override {
        if (!device_score_fn_) {
            yuzu::server::DexDeviceScoreModel m;
            m.agent_id = agent_id;
            m.window = window;
            m.degraded = true; // mirrors LocalDexApi's null-store shape (#4855)
            return m;
        }
        return device_score_fn_(agent_id, window);
    }

    [[nodiscard]] yuzu::server::DexDeviceHistoryModel
    device_history(const std::string& agent_id, const std::string& window) const override {
        if (!device_history_fn_) {
            yuzu::server::DexDeviceHistoryModel m;
            m.agent_id = agent_id;
            m.window = window;
            return m; // empty summary/history -- mirrors LocalDexApi's null-store shape
        }
        return device_history_fn_(agent_id, window);
    }

    [[nodiscard]] std::optional<yuzu::server::GuardianObservationRow>
    observation(const std::string& agent_id, const std::string& event_id) const override {
        if (!observation_fn_)
            return std::nullopt; // "not found / degraded" -- same as a foreign/guessed event_id
        return observation_fn_(agent_id, event_id);
    }

    [[nodiscard]] yuzu::server::DexAppModel
    app(const std::string& process_name, const std::string& window) const override {
        if (!app_fn_) {
            yuzu::server::DexAppModel m;
            m.process_name = process_name;
            m.window = window;
            return m;
        }
        return app_fn_(process_name, window);
    }

    [[nodiscard]] yuzu::server::DexAppsModel apps(const std::string& window) const override {
        if (!apps_fn_) {
            yuzu::server::DexAppsModel m;
            m.window = window;
            return m;
        }
        return apps_fn_(window);
    }

    [[nodiscard]] yuzu::server::DexCatalogueModel
    catalogue(const std::string& os_filter, const std::string& window) const override {
        if (!catalogue_fn_) {
            yuzu::server::DexCatalogueModel m;
            m.window = window;
            m.total_types = static_cast<int>(yuzu::server::dex_catalogued_type_count());
            const std::string plat = yuzu::server::dex_normalize_os_filter(os_filter);
            m.os = plat.empty() ? "all" : plat;
            return m; // no families/uncatalogued -- mirrors build_dex_catalogue_model's null-store shape
        }
        return catalogue_fn_(os_filter, window);
    }

    [[nodiscard]] std::optional<yuzu::server::DexCatalogueGroupModel>
    catalogue_group(const std::string& group_name, const std::string& os_filter,
                    const std::string& window) const override {
        if (!catalogue_group_fn_)
            return std::nullopt; // matches the interface's own "unknown family" 404 sentinel
        return catalogue_group_fn_(group_name, os_filter, window);
    }

    [[nodiscard]] yuzu::server::DexHealthModel
    health(const std::string& weighting, const std::string& window) const override {
        if (!health_fn_) {
            yuzu::server::DexHealthModel m;
            m.window = window;
            m.weighting = (weighting == "stability" || weighting == "productivity" ||
                          weighting == "security")
                             ? weighting
                             : "default"; // mirrors build_dex_health_model's pure normalisation
            return m;
        }
        return health_fn_(weighting, window);
    }

    [[nodiscard]] yuzu::server::DexTrendsModel trends(const std::string& window) const override {
        if (!trends_fn_) {
            yuzu::server::DexTrendsModel m;
            m.window = window;
            m.total_catalogued_types =
                static_cast<int64_t>(yuzu::server::dex_catalogued_type_count());
            return m;
        }
        return trends_fn_(window);
    }

    [[nodiscard]] yuzu::server::DexOverviewModel
    overview(const std::string& window) const override {
        if (!overview_fn_) {
            yuzu::server::DexOverviewModel m;
            m.window = window;
            return m;
        }
        return overview_fn_(window);
    }

    [[nodiscard]] std::vector<yuzu::server::DexSignalCount>
    signals(const std::string& window, const std::string& os_filter) const override {
        if (!signals_fn_)
            return {};
        return signals_fn_(window, os_filter);
    }

    [[nodiscard]] std::vector<yuzu::server::DexOsScope>
    scope(const std::string& window) const override {
        if (!scope_fn_)
            return {};
        return scope_fn_(window);
    }

    [[nodiscard]] yuzu::server::DexSignalDetailModel
    signal_detail(const std::string& obs_type, const std::string& window,
                 const std::string& os_filter, int limit) const override {
        if (!signal_detail_fn_)
            return {};
        return signal_detail_fn_(obs_type, window, os_filter, limit);
    }

private:
    DeviceScoreFn device_score_fn_;
    DeviceHistoryFn device_history_fn_;
    ObservationFn observation_fn_;
    AppFn app_fn_;
    AppsFn apps_fn_;
    CatalogueFn catalogue_fn_;
    CatalogueGroupFn catalogue_group_fn_;
    HealthFn health_fn_;
    TrendsFn trends_fn_;
    OverviewFn overview_fn_;
    SignalsFn signals_fn_;
    ScopeFn scope_fn_;
    SignalDetailFn signal_detail_fn_;
};

} // namespace yuzu::server::test
