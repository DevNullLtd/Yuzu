#pragma once

/// @file app_perf_group_reader.hpp
/// Reader for the DEX app-perf-over-time **management-group** trend (slice 2):
/// the on-the-fly aggregate of B1 (`AppPerfDailyStore`, schema
/// `app_perf_daily_store`) over a supplied set of member `agent_id`s, for one app.
///
/// ── Why a dedicated reader, not a store method ──
/// It produces a B2-SHAPED aggregate (`AppPerfFleetRow` incl. the fixed-bucket
/// histogram) but reads the B1 schema — a composition that belongs in neither
/// per-store class: it borrows the pool (never a store lease), reuses the FROZEN
/// histogram scheme (`app_perf_hist.hpp`) and the writer's bucket-predicate SQL
/// builder (`AppPerfRollup::build_hist_array_sql`) so the GROUP histogram is
/// byte-for-byte the same scheme as B2's. The member list is resolved by the
/// caller (from `ManagementGroupStore`) and passed in — so this reader touches
/// exactly ONE schema, and the two reads (members, then aggregate) are bounded
/// single-store leases composed in the provider, never one lease held across the
/// other (ADR-0012 §1).
///
/// ── Failure posture (ADR-0012 §1) ──
///   - **Reads:** AUTHORITATIVE — `std::nullopt` on a pool/query degrade (logged),
///     never a silent empty. An empty member list or empty `app_name` is a
///     precondition miss → empty value, not a degrade.
///
/// The floor (one device: an empty point is withheld) is applied by the READ
/// model (`app_perf_group_trend`), not here — this reader just produces the
/// honest aggregate + its device_count.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct AppPerfFleetRow; // app_perf_fleet_store.hpp — the shared aggregate-row shape

class AppPerfGroupReader {
public:
    /// Borrows the shared pool. No schema of its own (it reads B1's), so no
    /// migration; `is_open()` is always true once constructed.
    explicit AppPerfGroupReader(pg::PgPool& pool);

    AppPerfGroupReader(const AppPerfGroupReader&) = delete;
    AppPerfGroupReader& operator=(const AppPerfGroupReader&) = delete;

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_app_perf_group_read_degrade_total{reason}`). Set ONCE at startup.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Aggregate B1 across `agent_ids` for one app into B2-shaped rows (one per
    /// `(version, day)`), ordered `(version, day)`. `version` empty = all
    /// versions; a non-empty `version` is canonicalized to match the stored key.
    /// AUTHORITATIVE: `std::nullopt` on a pool/query degrade; empty value when
    /// `agent_ids`/`app_name` is empty or no rows match. Capped.
    [[nodiscard]] std::optional<std::vector<AppPerfFleetRow>>
    get_group_trend(const std::vector<std::string>& agent_ids, std::string_view app_name,
                    std::string_view version);

private:
    pg::PgPool& pool_;
    std::string select_prefix_; ///< SELECT … (histogram arrays baked in) FROM … built once
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
