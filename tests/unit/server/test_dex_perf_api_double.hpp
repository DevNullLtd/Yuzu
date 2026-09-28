#pragma once

/// @file test_dex_perf_api_double.hpp
/// FnDexPerfApi — a test-only `DexPerfApi` adapter wrapping the pre-seam
/// `DexPerfFn` (heartbeat-now) + a bundle of per-method raw-provider
/// `std::function`s (app-perf-over-time) every existing DEX-perf REST/MCP
/// test harness already builds. Performs the SAME assembly `LocalDexPerfApi`
/// does (dex_perf_api.cpp) — apply `app_perf_fleet_trend`/
/// `app_perf_group_trend` + `kDexCohortFloor`, serialize the device drill via
/// `dex_device_app_perf_json` — so a test fixture only needs to supply the
/// SAME raw-row lambdas it did before this seam existed. Mirrors `FnVerifyApi`
/// (test_verify_api_double.hpp), the established pattern for this exact
/// "wire the real seam over a function-shaped test double" problem.
///
/// `Providers` is DELIBERATELY decoupled from the (now-retired) production
/// `AppPerfProviders` aggregate — it is this test double's OWN type, defined
/// here, so `AppPerfProviders` could be deleted from production (#4626 Concern
/// C) without breaking every harness that builds one of these. It keeps the
/// SAME field names/types `AppPerfProviders` had (including `.cohort`, which
/// `DexPerfApi` itself never reads) purely so existing callers building a
/// `Providers` and separately reusing `.cohort` for VerifyApi's own test
/// wiring need NO field-level changes (the former `.tag_values` field was
/// removed with `DexRoutes::TagValuesFn`, #4857) — only the type name at the declaration site.
///
/// The individual `AppPerfXxxFn` provider typedefs (that `Providers` below is
/// built from) used to live in the production `dex_app_perf_builders.hpp`
/// alongside the (now-retired) `AppPerfProviders` bundle; they were
/// production-orphaned the moment that bundle retired (no production caller
/// ever built one directly) and are defined below instead. `.cohort`'s
/// `AppPerfCohortFn`/`CohortRead` are `FnVerifyApi`'s own types
/// (`test_verify_api_double.hpp`) — included here rather than re-defined, so
/// the two test doubles can never drift.
///
/// NOT for production use — the production factory is `make_local_dex_perf_api`
/// (dex_perf_api_local.hpp), which wires real store pointers instead.

#include "dex_app_perf_builders.hpp" // app_perf_fleet_trend/group_trend, dex_device_app_perf_json
#include "dex_perf_api.hpp"
#include "dex_perf_model.hpp" // DexPerfFn
#include "test_verify_api_double.hpp" // CohortRead, AppPerfCohortFn (Providers::cohort)

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

// Test-only provider typedefs `FnDexPerfApi::Providers` (below) is built
// from — production-orphaned since `AppPerfProviders` retired (#4626); see
// this file's own banner above. Left in `yuzu::server` (not
// `yuzu::server::test`) to match `CohortRead`/`AppPerfCohortFn`'s own
// namespace choice in `test_verify_api_double.hpp` and avoid a needless
// second namespace for one field's type.

using AppPerfFleetFn = std::function<std::optional<std::vector<AppPerfFleetRow>>(
    std::string_view app_name, std::string_view version)>;

using AppPerfAppListFn =
    std::function<std::optional<std::vector<AppPerfAppSummary>>(bool& truncated)>;

using AppPerfDeviceFn =
    std::function<std::optional<std::vector<AppPerfDailyRow>>(std::string_view agent_id)>;

using AppPerfGroupFn = std::function<std::optional<std::vector<AppPerfFleetRow>>(
    std::string_view group_id, std::string_view app_name, std::string_view version)>;

using AppPerfTagCohortFn = std::function<std::optional<std::vector<AppPerfFleetRow>>(
    std::string_view tag_key, std::string_view tag_value, std::string_view app_name,
    std::string_view version)>;

using AppPerfVersionDevicesFn = std::function<std::optional<std::vector<AppPerfVersionDeviceRow>>(
    std::string_view app_name, std::string_view version,
    const std::optional<std::vector<std::string>>& visible_agent_ids, bool& truncated)>;

} // namespace yuzu::server

namespace yuzu::server::test {

class FnDexPerfApi final : public yuzu::server::DexPerfApi {
public:
    /// Per-method raw-provider bundle — SAME shape as the retired
    /// `AppPerfProviders` (see the file banner above for why `.cohort` is
    /// kept even though `DexPerfApi` itself never reads it).
    struct Providers {
        yuzu::server::AppPerfFleetFn fleet;
        yuzu::server::AppPerfAppListFn apps;
        yuzu::server::AppPerfDeviceFn device;
        yuzu::server::AppPerfGroupFn group;
        yuzu::server::AppPerfCohortFn cohort; ///< VERIFY before/after compare; unused by DexPerfApi
        yuzu::server::AppPerfVersionDevicesFn version_devices;
        yuzu::server::AppPerfTagCohortFn tag_cohort;
    };

    FnDexPerfApi(yuzu::server::DexPerfFn dex_perf_fn, Providers providers)
        : dex_perf_fn_(std::move(dex_perf_fn)), providers_(std::move(providers)) {}

    [[nodiscard]] yuzu::server::DexPerfSnapshot
    fleet_snapshot(const std::string& cohort_key) const override {
        return dex_perf_fn_ ? dex_perf_fn_(cohort_key) : yuzu::server::DexPerfSnapshot{};
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfAppSummary>>
    apps(bool& truncated) const override {
        if (!providers_.apps)
            return std::nullopt;
        return providers_.apps(truncated);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    app_fleet_trend(const std::string& app, const std::string& version) const override {
        if (!providers_.fleet)
            return std::nullopt;
        auto rows = providers_.fleet(app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_fleet_trend(*rows);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfVersionDeviceRow>>
    app_version_devices(const std::string& app, const std::string& version,
                        const std::optional<std::vector<std::string>>& visible_agent_ids,
                        bool& truncated) const override {
        if (!providers_.version_devices)
            return std::nullopt;
        return providers_.version_devices(app, version, visible_agent_ids, truncated);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    group_trend(const std::string& group_id, const std::string& app,
               const std::string& version) const override {
        if (!providers_.group)
            return std::nullopt;
        auto rows = providers_.group(group_id, app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_group_trend(*rows, yuzu::server::kDexCohortFloor);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    tag_trend(const std::string& tag_key, const std::string& tag_value, const std::string& app,
             const std::string& version) const override {
        if (!providers_.tag_cohort)
            return std::nullopt;
        auto rows = providers_.tag_cohort(tag_key, tag_value, app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_group_trend(*rows, yuzu::server::kDexCohortFloor);
    }

    [[nodiscard]] std::optional<std::string>
    device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                         bool audit_persisted) const override {
        if (!providers_.device)
            return std::nullopt;
        auto rows = providers_.device(agent_id);
        if (!rows)
            return std::nullopt;
        return yuzu::server::dex_device_app_perf_json(agent_id, app_filter, *rows,
                                                       audit_persisted);
    }

    // GAP-2 (#4626): the summary-shaped twin of device_app_perf_json above —
    // both derive from the SAME providers_.device(agent_id) raw-row read
    // (mirrors LocalDexPerfApi's own shared-helper contract; neither is
    // derived from the other).
    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfDeviceApp>>
    device_app_summaries(const std::string& agent_id) const override {
        if (!providers_.device)
            return std::nullopt;
        auto rows = providers_.device(agent_id);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_device_summaries(*rows);
    }

private:
    yuzu::server::DexPerfFn dex_perf_fn_;
    Providers providers_;
};

} // namespace yuzu::server::test
