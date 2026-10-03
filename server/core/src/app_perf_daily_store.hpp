#pragma once

/// @file app_perf_daily_store.hpp
/// Born-on-Postgres per-device daily app-performance summary — layer **B1** of
/// the DEX app-perf-over-time feature (schema `app_perf_daily_store`). One row
/// per `(agent_id, app_name, version, day)`: the daily roll-up of the agent's
/// on-device `procperf_hourly` warehouse, shipped centrally over the daily-sync
/// `app_perf` source so fleet-wide questions ("which devices ran v124, and how
/// did it perform") are answerable WITHOUT federating to every endpoint.
///
/// ── Deliberate design choices (these surprise a reader of SoftwareInventoryStore) ──
///
/// **Hash-less.** Unlike SoftwareInventoryStore, this store persists NO content
/// hash. app_perf's per-day window changes daily, so the daily-sync hash-skip is
/// moot — the agent always sends full. A hash-only `app_perf` report (only a
/// same-day re-tick / need_full retry produces one) is therefore answered with
/// `need_full` by the ingest seam, never matched here. The big consequence: the
/// byte-identical agent↔server canonicalization burden that the installed_software
/// path carries (a one-sided change → permanent always-full) does NOT apply — the
/// wire blob only needs to be PARSEABLE, not hash-reproducible.
///
/// **Top-N scope, not a census.** `procperf` records only the per-tick top-10-CPU
/// ∪ top-10-working-set apps, so this store covers a device's RESOURCE-SIGNIFICANT
/// app-versions, NOT every app that ran. "Which devices ran app X" is qualified to
/// "…among that device's top resource consumers". A complete app-presence census is
/// `installed_software` (SoftwareInventoryStore), a different store.
///
/// **Version is canonicalized at ingest** via `yuzu::util::canon_version` — the
/// SAME function the crash/stability side applies — so a future fleet view can
/// join perf (B1/B2) to stability `(app, version)`. Canonicalization can collapse
/// two raw versions onto one key, so `apply_daily` re-canons and MERGES collisions
/// (sample-weighted) before the batched upsert; otherwise the batch would hit
/// "ON CONFLICT DO UPDATE command cannot affect row a second time".
///
/// ── Substrate contract (ADR-0008/0012) ──
/// Holds a `pg::PgPool&`, migrates at construction on a pinned lease,
/// schema-qualifies every runtime statement (`app_perf_daily_store.app_perf_daily`),
/// uses `RETURNING` for mutate-and-return. Plain indexed table + DELETE prune (NOT
/// native partitioning — the non-transactional migration kind it needs isn't built).
/// `updated_at` is the SERVER receipt time, bumped on every upsert (never the agent
/// clock — #1685 lesson).
///
/// ── Failure posture (ADR-0012 §1) ──
///   - **Data:** a projection — the agent + procperf are the source of truth.
///   - **Ingest:** fail-soft — a transient PG outage returns false; the agent
///     re-sends on its 2-day window next cycle (the window self-heals the gap).
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns
///     `std::nullopt` (logged at warn), never a silent empty. `nullopt` = degraded
///     (could not read); an empty *value* = a genuine zero-row result. Callers MUST
///     surface a `nullopt` degrade, never `.value_or({})` it into a silent empty.
///
/// ── Read-surface parity carry-forward (agentic-first A1–A4) ──
/// 3a (this store) ships NO REST/MCP surface — only this C++ read, exercised by a
/// PostgresTestDb test (pipe + reservoir; nothing drinking yet). When the read
/// surface lands (slice 2 / B2) it extends the existing dex-perf family and MUST
/// ship REST + MCP **in the same PR** (never REST-first), A4-enveloped via
/// `rest_a4_envelope.hpp` (NOT legacy `error_json`; do not add to the #1470 debt),
/// A2-discoverable (openapi.json + tools/list), behind `GuaranteedState:Read` with
/// per-device audit via `rest_audit.hpp` (fail-closed 503).

#include "app_perf_types.hpp" // AppPerfVersionDeviceRow (ADR-0031 WS-A4 DexPerfApi split)

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

/// One daily per-app-version performance summary for a single device. `agent_id`
/// is implicit on the apply/read APIs (per-agent), so it is not a row field.
/// `cpu_avg`/`cpu_max` are share-of-total-machine-capacity percent (the procperf
/// denominator); `ws_*` are bytes. `version` is the canon quad ("" = unknown).
struct AppPerfDailyRow {
    std::string app_name;
    std::string version;
    std::int64_t day{0}; ///< UTC midnight epoch seconds
    std::int64_t samples{0};
    std::int64_t instances_max{0};
    double cpu_avg{0.0};
    double cpu_max{0.0};
    std::int64_t ws_avg_bytes{0};
    std::int64_t ws_max_bytes{0};
};

/// Pure: canonicalize each row's `version` (`yuzu::util::canon_version`), clamp
/// every numeric to a finite, non-negative value, and MERGE rows that collapse to
/// the same `(app_name, version, day)` key — `samples` summed, `cpu_avg`/`ws_avg`
/// re-combined sample-weighted, the `*_max`/`instances_max` taken as the max. The
/// result is key-unique (safe for a single ON CONFLICT batch). Exposed for unit
/// testing; `apply_daily` runs it server-side as the authoritative re-canon
/// (defense-in-depth — the agent canon+merges too, but the server is sole writer).
[[nodiscard]] std::vector<AppPerfDailyRow> canon_merge_daily(std::vector<AppPerfDailyRow> rows);

/// One device's MOST RECENT retained row for a specific `(app_name, version)` —
/// backs `AppPerfDailyStore::list_devices_for_version`, the DEX app-perf trend's
/// per-version "which devices" drill. Carries `agent_id` (unlike `AppPerfDailyRow`
/// above, whose per-agent APIs make it implicit) because this is inherently a
/// fan-out read across devices, not a per-agent one — same reason
/// `AppPerfCohortRow` (app_perf_compare.hpp) is a distinct shape from
/// `AppPerfDailyRow` rather than a reuse.
// AppPerfVersionDeviceRow relocated to app_perf_types.hpp (ADR-0031 WS-A4
// DexPerfApi split, PR #4582-review) — re-exported transitively via the
// #include above, so every existing caller of this header is unaffected.

class AppPerfDailyStore {
public:
    /// Borrows the shared pool and runs the `app_perf_daily_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was empty or
    /// the migration failed (the server fails closed before reaching here).
    explicit AppPerfDailyStore(pg::PgPool& pool);

    AppPerfDailyStore(const AppPerfDailyStore&) = delete;
    AppPerfDailyStore& operator=(const AppPerfDailyStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_app_perf_read_degrade_total{reason}`). Set ONCE during
    /// single-threaded startup, before the serving threads read it without
    /// synchronisation. Null (the default, e.g. unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Upsert one agent's daily rows (the 2-day window the agent sends) and prune
    /// rows older than the 31-day retention, in one bounded transaction. Re-canons
    /// + merges (`canon_merge_daily`) so the batch is key-unique and version-joinable
    /// with the stability side. `ON CONFLICT … DO UPDATE` overwrites all metric
    /// columns unconditionally (a re-sent day is equal-or-more-complete). Ingest is
    /// fail-soft: returns false (logged) on an empty lease / SQL error so a PG blip
    /// never wedges the gRPC thread — the agent re-sends next cycle. `rows` is taken
    /// BY VALUE so the merge can move it. An empty `rows` after merge is a no-op
    /// success (still prunes).
    bool apply_daily(std::string_view agent_id, std::vector<AppPerfDailyRow> rows);

    /// All retained daily rows for one agent (per-device drill), ordered
    /// `(app_name, version, day)`. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query degrade (distinct from an empty value = genuinely no rows).
    /// An empty `agent_id` is a precondition miss → empty value, not a degrade.
    /// Capped at a hard ceiling regardless of fleet growth.
    [[nodiscard]] std::optional<std::vector<AppPerfDailyRow>>
    get_agent_app_perf(std::string_view agent_id);

    /// Devices reporting `(app_name, version)` among their retained top-N daily
    /// summaries, one row per device at its MOST RECENT reporting day for that
    /// EXACT version — the version-row "which devices" drill for the DEX app-perf
    /// trend (a fan-out read, distinct from `get_agent_app_perf`'s per-agent
    /// shape). `version` is matched AS SUPPLIED — the caller canonicalizes it
    /// first (same convention as `AppPerfCohortReader::get_cohort_rows`); `""` is
    /// the valid "unknown version" bucket, NOT an "all versions" wildcard (unlike
    /// `DexPerfApi::app_fleet_trend`'s `version` convention) — this drill is
    /// always scoped to one exact version.
    ///
    /// `visible_agent_ids` mirrors the ADR-0017 admit-then-filter contract:
    /// `nullopt` = no SQL filter (every reporting device); engaged (INCLUDING
    /// empty) = restrict to exactly these agent_ids, pushed into the WHERE clause
    /// so the filter applies BEFORE the row cap below — a post-fetch filter under
    /// a capped query would silently drop in-scope rows sitting past the cap. A
    /// present-but-empty set therefore yields zero rows (deny-all), never an
    /// unfiltered read.
    ///
    /// Ordered by DESCENDING `cpu_avg` (the highest resource consumers first),
    /// tiebreak `agent_id`, capped at a hard ceiling; `truncated` (out-param) is
    /// set when the cap bit — the DROPPED rows are the LOWEST-cpu devices past the
    /// cap, so a truncated read still surfaces the highest-consuming subset, never
    /// an arbitrary one (mirrors `AppPerfCohortReader::get_cohort_rows`'s own
    /// documented cap-drops-something contract, though that cap drops
    /// alphabetically rather than by rank).
    ///
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query degrade, never a
    /// silent empty. An empty `app_name` is a precondition miss -> empty value
    /// (`version` alone may legitimately be `""`, so it is not itself a
    /// precondition-miss signal).
    [[nodiscard]] std::optional<std::vector<AppPerfVersionDeviceRow>>
    list_devices_for_version(std::string_view app_name, std::string_view version,
                             const std::optional<std::vector<std::string>>& visible_agent_ids,
                             bool& truncated);

    /// Drop one agent's daily rows (e.g. on agent removal). Returns true iff the
    /// DELETE executed (COMMAND_OK); false on a closed store, a lease timeout, or
    /// a SQL failure — so the decommission cascade records Failed, not a false
    /// "erased".
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    /// Retention horizon — rows with `day` older than this many days before the
    /// server's current UTC day are pruned on each `apply_daily`. Matches
    /// `procperf_hourly`'s 31-day on-device retention.
    static constexpr int kRetentionDays = 31;

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
