#include "dex_perf_api_local.hpp"

#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "app_perf_group_reader.hpp"
#include "dex_app_perf_builders.hpp" // app_perf_fleet_trend/group_trend, dex_device_app_perf_json
#include "dex_app_version_failures_owner.hpp"
#include "dex_window.hpp"
#include "management_group_store.hpp"
#include "tag_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <utility>

namespace yuzu::server {

namespace {

/// LocalDexPerfApi — the store-backed impl. NOT an enforced-pure TU (it may,
/// and does, include the B1/B2 store headers + the core-only builders).
class LocalDexPerfApi final : public DexPerfApi {
public:
    LocalDexPerfApi(DexPerfFn dex_perf_fn, AppPerfFleetStore* fleet_store,
                    AppPerfDailyStore* daily_store, AppPerfGroupReader* group_reader,
                    ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                    DexAppVersionFailuresOwner* failures_owner)
        : dex_perf_fn_(std::move(dex_perf_fn)), fleet_store_(fleet_store),
          daily_store_(daily_store), group_reader_(group_reader),
          mgmt_group_store_(mgmt_group_store), tag_store_(tag_store),
          failures_owner_(failures_owner) {}

    LocalDexPerfApi(const LocalDexPerfApi&) = delete;
    LocalDexPerfApi& operator=(const LocalDexPerfApi&) = delete;

    // ── Heartbeat-NOW ──

    DexPerfSnapshot fleet_snapshot(const std::string& cohort_key) const override {
        return dex_perf_fn_ ? dex_perf_fn_(cohort_key) : DexPerfSnapshot{};
    }

    // ── App-perf-over-time ──

    std::optional<std::vector<AppPerfAppSummary>> apps(bool& truncated) const override {
        if (!fleet_store_)
            return std::nullopt;
        return fleet_store_->list_apps(truncated);
    }

    std::optional<std::vector<AppPerfTrendPoint>>
    app_fleet_trend(const std::string& app, const std::string& version) const override {
        return fleet_points(app, version);
    }

    std::optional<AppPerfFleetReport> app_fleet_report(const std::string& app,
                                                       const std::string& version) const override {
        if (!failures_owner_)
            return std::nullopt;
        auto points = fleet_points(app, version);
        if (!points)
            return std::nullopt; // AUTHORITATIVE degrade — the B2 read failed
        // The join keeps only the newest kAppPerfVersionJoinCap versions; ask the
        // failure read for exactly those so it never counts a version that is
        // dropped from the report.
        const auto sel = app_perf_newest_versions(*points);

        // One cut for events and exposure: the UTC midnight `window` days back.
        const int window = failures_owner_->failure_window_days();
        const auto cut = dex_day_window(std::chrono::duration_cast<std::chrono::seconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count(),
                                        window);
        // A second, separate bounded read — the B2 lease is already released.
        auto failures =
            failures_owner_->read(app, sel.versions, cut.since_day, cut.end_day, cut.since_iso);
        if (!failures)
            return std::nullopt; // AUTHORITATIVE degrade — the failure read failed
        auto report = app_perf_version_failure_join(std::move(*points), *failures, window);
        if (report.stat_failures > 0)
            spdlog::warn("DexPerfApi: {} version statistic(s) returned nothing on valid input "
                         "(app report)",
                         report.stat_failures);
        return report;
    }

    std::optional<std::vector<AppPerfVersionDeviceRow>>
    app_version_devices(const std::string& app, const std::string& version,
                        const std::optional<std::vector<std::string>>& visible_agent_ids,
                        bool& truncated) const override {
        if (!daily_store_)
            return std::nullopt;
        return daily_store_->list_devices_for_version(app, version, visible_agent_ids, truncated);
    }

    std::optional<std::vector<AppPerfTrendPoint>>
    group_trend(const std::string& group_id, const std::string& app,
               const std::string& version) const override {
        if (!group_reader_ || !mgmt_group_store_)
            return std::nullopt;
        // Resolve members (one bounded read, lease released), THEN aggregate B1
        // (a second bounded read) — never a lease held across the other
        // (ADR-0012 §1), matching the pre-seam AppPerfProviders.group closure.
        // get_members_checked (not the plain get_members()) so a member-read
        // degrade fails closed to nullopt instead of rendering as an empty
        // cohort (#1762) — same contract tag_trend already has via TagStore.
        auto members = mgmt_group_store_->get_members_checked(group_id);
        if (!members)
            return std::nullopt; // AUTHORITATIVE degrade — the member read failed
        std::vector<std::string> agent_ids;
        agent_ids.reserve(members->size());
        for (const auto& m : *members)
            agent_ids.push_back(m.agent_id);
        auto rows = group_reader_->get_group_trend(agent_ids, app, version);
        if (!rows)
            return std::nullopt;
        return app_perf_group_trend(*rows, kDexCohortFloor);
    }

    std::optional<std::vector<AppPerfTrendPoint>>
    tag_trend(const std::string& tag_key, const std::string& tag_value, const std::string& app,
             const std::string& version) const override {
        if (!group_reader_ || !tag_store_)
            return std::nullopt;
        auto agents = tag_store_->agents_with_tag(tag_key, tag_value);
        if (!agents)
            return std::nullopt; // fail closed on a degraded tag read (TagStore contract)
        auto rows = group_reader_->get_group_trend(*agents, app, version);
        if (!rows)
            return std::nullopt;
        return app_perf_group_trend(*rows, kDexCohortFloor);
    }

    std::optional<std::string> device_app_perf_json(const std::string& agent_id,
                                                     const std::string& app_filter,
                                                     bool audit_persisted) const override {
        auto rows = device_rows(agent_id);
        if (!rows)
            return std::nullopt;
        return dex_device_app_perf_json(agent_id, app_filter, *rows, audit_persisted);
    }

    // Note (#4626): derives from the SAME device_rows() helper as
    // device_app_perf_json above — neither method derives from the other,
    // both read the store exactly once and reduce independently.
    std::optional<std::vector<AppPerfDeviceApp>>
    device_app_summaries(const std::string& agent_id) const override {
        auto rows = device_rows(agent_id);
        if (!rows)
            return std::nullopt;
        return app_perf_device_summaries(*rows);
    }

private:
    /// The B2 read and floor-applying transform shared by `app_fleet_trend` and
    /// `app_fleet_report`, so the two cannot disagree on the points.
    std::optional<std::vector<AppPerfTrendPoint>>
    fleet_points(const std::string& app, const std::string& version) const {
        if (!fleet_store_)
            return std::nullopt;
        auto rows = fleet_store_->get_app_fleet_perf(app, version);
        if (!rows)
            return std::nullopt;
        return app_perf_fleet_trend(*rows);
    }

    /// Shared raw-row read backing BOTH device_app_perf_json and
    /// device_app_summaries (the single daily_store_->get_agent_app_perf
    /// call each of them needs) — see this class's two callers' own doc
    /// comments for why neither derives from the other.
    std::optional<std::vector<AppPerfDailyRow>> device_rows(const std::string& agent_id) const {
        if (!daily_store_)
            return std::nullopt;
        return daily_store_->get_agent_app_perf(agent_id);
    }

    DexPerfFn dex_perf_fn_;
    AppPerfFleetStore* fleet_store_;
    AppPerfDailyStore* daily_store_;
    AppPerfGroupReader* group_reader_;
    ManagementGroupStore* mgmt_group_store_;
    TagStore* tag_store_;
    DexAppVersionFailuresOwner* failures_owner_;
};

} // namespace

std::shared_ptr<DexPerfApi>
make_local_dex_perf_api(DexPerfFn dex_perf_fn, AppPerfFleetStore* fleet_store,
                        AppPerfDailyStore* daily_store, AppPerfGroupReader* group_reader,
                        ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                        DexAppVersionFailuresOwner* failures_owner) {
    return std::make_shared<LocalDexPerfApi>(std::move(dex_perf_fn), fleet_store, daily_store,
                                             group_reader, mgmt_group_store, tag_store,
                                             failures_owner);
}

} // namespace yuzu::server
