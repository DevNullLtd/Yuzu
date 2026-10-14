#pragma once

/// @file hardware_list_model.hpp
/// PURE model for the /hardware Configuration-Item (CI) list and record — search,
/// filter, sort, pagination, KPIs, and the JSON shapes shared verbatim by the HTMX
/// fragment, the REST v1 twin, and the MCP twin (the "one builder" the twin recipe
/// mandates, docs/api-twin-recipe.md §1). No gRPC, and nothing in THIS file calls
/// into httplib — every function here is a pure transform over already-fetched
/// data (roster/query in, page/JSON out). `inventory_routes.hpp` (below, for
/// `InventoryDeviceRow`) transitively pulls in `<httplib.h>` for its own route
/// types, so the symbol is reachable from this TU, but nothing declared in this
/// file needs it — this header must stay includable from a plain unit test with
/// zero network/store dependencies, and every function here is callable without
/// ever touching an httplib type.
///
/// Roster rows are `InventoryDeviceRow`s (declared in inventory_routes.hpp), built by
/// server.cpp's `build_hw_roster` (endpoint_state + device_ci join); this header only
/// orders, filters, and paginates that roster — it never fetches it.

#include "device_inventory_store.hpp"    // DeviceCiRecord, CiReadError
#include "inventory_routes.hpp"          // InventoryDeviceRow
#include "offline_endpoint_store.hpp"    // OfflineEndpoint, PresenceReadError (stdlib-only header)
#include "software_inventory_store.hpp"  // SoftwareEntry
#include "tag_store.hpp"                 // DeviceTag

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Whitelisted sort keys for the Hardware CI list. Never accept an arbitrary column
/// name from the wire — `parse_hw_sort_key` is the sole entry point and returns
/// `nullopt` for anything outside this set, which both the fragment and the REST
/// twin turn into a 400 (a crafted/stale URL is the only realistic way to hit it).
enum class HwSortKey {
    Name,
    Os,
    Status,
    LastSeen,
    Manufacturer,
    Model,
    Serial,
    Cpu,
    Ram,
    OsVersion,
    Version, // agent_version — round-3 merge; NOT DEX (see hardware_kpis' doc note)
    Ip,
};

[[nodiscard]] std::optional<HwSortKey> parse_hw_sort_key(std::string_view token);
[[nodiscard]] std::string_view hw_sort_token(HwSortKey key);

/// Raw query as read off the wire (query-string values, unvalidated). Pass through
/// `normalise_hardware_query` before using — this struct alone makes no promises.
struct HardwareListQuery {
    std::string q;
    std::string os{"all"};      // all | windows | linux | macos
    std::string status{"all"};  // all | online | offline
    std::string sort{"name"};   // one of the HwSortKey tokens
    bool desc{false};
    std::size_t offset{0};
    std::size_t limit{50};
    /// "" = no tag filter. "key" = any value; "key=value" = exact value match.
    /// The key half is validated against TagStore::validate_key by
    /// normalise_hardware_query — an invalid key is a 400, same as a bad sort token.
    std::string tag;
};

/// Validates and clamps a raw query. Returns `nullopt` when `os`/`status`/`sort` is
/// an unrecognised token (the ONLY rejection case) — `limit`/`offset` are clamped,
/// never rejected, and empty `os`/`status`/`q` normalise to "all"/"all"/"".
[[nodiscard]] std::optional<HardwareListQuery> normalise_hardware_query(HardwareListQuery raw);

/// Lowercased, whitespace-split, deduplicated-by-position search tokens, capped at 8.
[[nodiscard]] std::vector<std::string> hw_search_tokens(std::string_view q);

/// True iff `row` matches every token in `tokens` (AND, substring, case-folded), the
/// `os`/`status` facet, AND the tag facet. `os`/`status`/`tag` are assumed
/// already-normalised ("all"/a specific value, and "" or "key"/"key=value") — call
/// `normalise_hardware_query` first. Empty `tag` = no tag filter.
[[nodiscard]] bool hw_row_matches(const InventoryDeviceRow& row, const std::vector<std::string>& tokens,
                                  std::string_view os, std::string_view status, std::string_view tag);

/// Median installed memory over the rows that have a synced, positive RAM figure, in GiB.
/// nullopt when no row has one (the readout is hidden, never "0 GB"). `count` receives the
/// number of devices the median is over.
[[nodiscard]] std::optional<double> median_ram_gb(const std::vector<InventoryDeviceRow>& rows,
                                                  std::size_t* count = nullptr);

/// Device counts per manufacturer (case-folded, whitespace-trimmed), highest first; rows
/// with no synced manufacturer are not counted. At most `top_n` entries, the remainder
/// summed into a final "Other" entry. Empty when nothing has synced.
[[nodiscard]] std::vector<std::pair<std::string, std::size_t>>
count_by_manufacturer(const std::vector<InventoryDeviceRow>& rows, std::size_t top_n = 8);

struct HardwareKpis {
    std::size_t total{0};
    std::optional<double> median_ram_gb;  ///< see median_ram_gb(); nullopt = hidden
    std::size_t ram_devices{0};           ///< devices the median is over
    std::vector<std::pair<std::string, std::size_t>> by_manufacturer; ///< top 8 + Other
    std::size_t online{0};
    std::size_t offline{0}; // non-online, including stale
    std::size_t stale{0};
    std::size_t with_ci{0}; // non-blank serial or model
};

/// Computed over the SCOPED roster, BEFORE q/os/status narrowing — the KPI strip
/// always describes "your fleet", not "your current filter".
[[nodiscard]] HardwareKpis hardware_kpis(const std::vector<InventoryDeviceRow>& roster);

struct HardwareListPage {
    std::vector<InventoryDeviceRow> rows; // the page slice only
    std::size_t total_matching{0};        // after q/os/status, before paging
    HardwareKpis kpis;                    // see hardware_kpis()
    HardwareListQuery query;              // the normalised, canonical echo
};

/// Filters, sorts, and paginates `roster` per `normalised` (already validated —
/// pass the output of `normalise_hardware_query`, never a raw query). `roster` is
/// consumed by value since the sort is in-place.
[[nodiscard]] HardwareListPage build_hardware_list_page(std::vector<InventoryDeviceRow> roster,
                                                        const HardwareListQuery& normalised);

// ── Shared JSON builders — REST and MCP call exactly these; the HTML fragment
// renders the same structs directly, so all three surfaces agree by construction.

/// One CI row. String `ci_*` sentinels ("" or "unknown") normalise to JSON `null` —
/// the JSON reader has no `ci_disp()`, so "not yet synced" must be explicit.
[[nodiscard]] nlohmann::json hardware_row_json(const InventoryDeviceRow& row);

[[nodiscard]] nlohmann::json hardware_list_json(const HardwareListPage& page, bool ci_degraded,
                                                std::size_t devices_omitted, bool tags_degraded = false);

/// The full CI record composition — identity + CI blob + installed software + tags.
/// Each optional/expected member independently distinguishes "degraded" from
/// "absent" (ADR-0016 §7): a store failure must never render as "this device has no
/// software" or "this device has no CI record".
struct HardwareCiDetail {
    std::optional<InventoryDeviceRow> identity; // nullopt = not in the last-30d roster (or see identity_degraded)
    /// The offline-roster identity fallback FAILED (#5531): identity is nullopt
    /// but the device may exist.
    bool identity_degraded{false};
    std::expected<std::optional<DeviceCiRecord>, CiReadError> ci{std::unexpected(CiReadError::kDegraded)};
    std::optional<std::vector<SoftwareEntry>> software; // nullopt = store degraded/unwired
    bool software_truncated{false};                     // capped at kHwSoftwareCap
    std::optional<std::vector<DeviceTag>> tags;          // nullopt = tag store degraded/unwired
    /// The live session's self-reported agent_version; nullopt = no live session.
    std::optional<std::string> agent_version;
    /// `inventory_state.last_seen` (server receipt epoch-secs) for the
    /// installed_software source; nullopt = store degraded/unwired, 0 = never synced.
    std::optional<std::int64_t> software_last_seen;
};

inline constexpr std::size_t kHwSoftwareCap = 2000;

/// Sync-on-demand (`__sync__.now`) shipped in the 0.13.1 dev line; a release
/// 0.13.0 agent answers the command with "plugin not found". True iff the
/// `major.minor.patch` prefix of `agent_version` is >= 0.13.1 — the `+build`
/// suffix (kFullVersionString = "@PROJECT_VERSION@+@YUZU_BUILD_NUMBER@") is
/// ignored, missing components read as 0, and anything empty / non-numeric /
/// pre-release-tagged fails CLOSED (false).
inline constexpr std::array<int, 3> kSyncNowMinAgentVersion{0, 13, 1};
[[nodiscard]] bool agent_supports_sync_now(std::string_view agent_version) noexcept;

/// Hardware roster read window and stale threshold: the list and the record fallback must
/// agree, or a listed device's record reads "not found".
inline constexpr std::chrono::hours kHardwareRosterWindow{24 * 30};
inline constexpr std::int64_t kHardwareStaleAfterMs = 2LL * 24 * 60 * 60 * 1000;

// ── #5531: the store-to-bit mappings, pure so a revert is visible to a unit test ──

/// Failed read -> `roster_degraded` + `ci_degraded` + `tags_degraded` (no enrichment of an
/// unknown roster) and returns false; a healthy read touches nothing and returns true.
[[nodiscard]] bool apply_roster_read(InventoryDevicesResult& result, const OfflineRosterRead& eps);

/// `agent_id -> (key -> value)` bulk tag read (`TagStore::get_values_for_keys`).
using TagValuesRead =
    std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
                  TagReadError>;
using TagValuesReader = std::function<TagValuesRead(const std::vector<std::string>&)>;

/// Fills `result.rows[*].tags` from the bulk tag read, or sets `tags_degraded`. A failed KEY read
/// degrades without calling `read_values` (an empty key list would otherwise read back as an
/// authoritative blank); a failed VALUES read degrades; a healthy read — including an empty key
/// list or a device with no tags — leaves `tags_degraded` false.
void apply_tag_read(InventoryDevicesResult& result,
                    const std::expected<std::vector<std::string>, TagReadError>& keys,
                    const TagValuesReader& read_values);

/// One device's identity from an offline-roster read: the error is propagated (a failed read
/// is never "not in the roster"); a healthy read yields the matching row (online=false, stale
/// past 2 days) or nullopt when the agent is absent.
[[nodiscard]] std::expected<std::optional<InventoryDeviceRow>, PresenceReadError>
offline_identity_row(const OfflineRosterRead& eps, std::string_view agent_id, std::int64_t now_ms,
                     std::string (*human_age)(std::int64_t));

/// Identity read -> `identity` on success (nullopt = absent), `identity_degraded` on error.
void apply_identity_read(HardwareCiDetail& detail,
                         std::expected<std::optional<InventoryDeviceRow>, PresenceReadError> ident);

/// `ci_state` and `identity_state` in the output are each one of "found" |
/// "absent" | "degraded" — never inferred by the reader from a blank field.
[[nodiscard]] nlohmann::json hardware_ci_json(const HardwareCiDetail& detail, std::int64_t now_secs);

} // namespace yuzu::server
