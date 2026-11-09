#pragma once

/// @file software_list_model.hpp
/// The pure model behind the SAM-17 lookup reads: `GET /api/v1/inventory/software` (installs) and
/// `GET /api/v1/inventory/software/components`. It answers "how many installs, on which devices,
/// last polled when, in what status" for an application or a component in one call. No httplib,
/// no libpq: the route handlers inject the store reads, and the same functions can back an MCP
/// twin later without a second copy of any rule.
///
/// Rules this file owns (each stated once, here):
///  * VERSION RANGE: `version_min`/`version_max` are inclusive bounds under the catalogue's
///    transitive comparator (`software_catalog::catalog_version_compare`), resolved against the
///    title's fleet-wide distinct versions into an exact version SET that becomes a SQL
///    predicate. The set never appears in a response (a confined caller learns nothing beyond its
///    own rows). A title with kCatalogRowCap distinct versions cannot be resolved (refused).
///  * TOTALS (ADR-0017: a fleet rollup cannot be confined, and distinct counts are not additive):
///    a `totals` block is served ONLY when the gate admitted the caller globally
///    (ListReadDecision::AdmitAll) AND the filters are exactly `name` with match=exact, plus
///    optionally one version filter (and `kind` on components). Otherwise `totals` is null with
///    `totals_omitted` = "scope" | "filters" | "building". Null means "not shown", never zero.
///    `installs` always means INSTALL ROWS (a device with two architectures counts twice),
///    `instances` the same for components, `devices` DISTINCT devices.
///  * STATUS: one derivation (`derive_status`) pinned to the SQL's kRowStatusCaseSql.

#include "software_catalogue_model.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::server {
class DeviceApi;
}

namespace yuzu::server::software_list {

using Params = software_catalogue::Params;

// ── Constants ────────────────────────────────────────────────────────────────

/// kInstallsCsvHeader (14 columns) + the eight lookup columns.
inline constexpr std::string_view kListCsvHeader =
    "agent_id,name,version,publisher,install_date,kind,ecosystem,epoch,release,arch,"
    "signature_status,distro_id,distro_version,source,"
    "hostname,last_seen,status,last_confirmed_at,install_type,install_scope,install_location,"
    "instance_key";
inline constexpr std::size_t kListCsvColumns = 22;

inline constexpr std::string_view kComponentsCsvHeader =
    "agent_id,hostname,last_seen,kind,name,version,version_source,path,anchor_app,first_seen,"
    "status,last_confirmed_at";
inline constexpr std::size_t kComponentsCsvColumns = 12;

/// The refusal for a title whose distinct versions fill the read cap (wording-neutral: it names
/// no title and no count).
inline constexpr std::string_view kRangeNotResolvable =
    "version range not resolvable for this title; use version=";

// ── Status ───────────────────────────────────────────────────────────────────

/// "current" | "unconfirmed" | "disabled" from a facet state (`facet_status` '' = no state row).
/// The C++ twin of software_inventory_store.hpp kRowStatusCaseSql; a [pg] case pins the two.
[[nodiscard]] std::string_view derive_status(std::string_view facet_status, bool facet_enabled) noexcept;

// ── Parameters ───────────────────────────────────────────────────────────────

struct ListRequest {
    software_catalogue::DevicesRequest base; ///< query.match / query.status filled by the parser
    std::string version_min;
    std::string version_max;
    [[nodiscard]] bool has_range() const { return !version_min.empty() || !version_max.empty(); }
};

/// parse_devices_params + `match` (exact|prefix|contains), `status` (current|unconfirmed|
/// disabled), `version_min`, `version_max`. `version_min` and `version_max` REQUIRE a non-empty
/// `name` with match=exact; a bare exact `version` is a plain equality predicate and needs no name;
/// a non-exact `match` requires `name`; `version` cannot be combined with a range. The error is the
/// 400 message.
[[nodiscard]] std::expected<ListRequest, std::string> parse_list_params(const Params& p);

struct ComponentsRequest {
    SoftwareComponentQuery query;
    std::string cursor;
    std::string format; ///< "" | "json" | "csv"; non-empty = an export (the TOTAL-rows cap applies)
    std::string version_min;
    std::string version_max;
    [[nodiscard]] bool has_range() const { return !version_min.empty() || !version_max.empty(); }
    /// `version=` (exact) is kept apart so the range/exact exclusion and the fingerprint can
    /// tell it from a resolved range; the parser mirrors it into query.versions.
    std::optional<std::string> version;
};

/// Keys: kind, name, match, version, version_min, version_max, agent_id, q, status, limit, cursor,
/// format. Same hygiene, version-requires-exact-name rule, limits and export cap as the installs
/// parser. A repeated key keeps the FIRST value.
[[nodiscard]] std::expected<ComponentsRequest, std::string> parse_components_params(const Params& p);

// ── Version range ────────────────────────────────────────────────────────────

/// The members of `distinct_versions` within [min, max] (an empty bound is open) under
/// catalog_version_compare; the empty version never matches a bound. `distinct_versions` is a
/// fleet-wide read bounded at kCatalogRowCap: a read that returned that many rows may be cut, so
/// it is refused with kRangeNotResolvable rather than resolved against a partial set.
[[nodiscard]] std::expected<std::vector<std::string>, std::string>
resolve_version_range(const std::vector<std::string>& distinct_versions, std::string_view version_min,
                      std::string_view version_max);

// ── Fingerprints, audit targets, cursors ─────────────────────────────────────

/// Bound to the request's filters including the RANGE INPUTS (not the resolved set, which moves
/// with each rollup refresh). A default-filter request keeps devices_fingerprint's exact value.
[[nodiscard]] std::string list_fingerprint(const ListRequest& rq);
[[nodiscard]] std::string components_fingerprint(const ComponentsRequest& rq);

[[nodiscard]] std::string audit_target(const ListRequest& rq);
[[nodiscard]] std::string audit_target(const ComponentsRequest& rq);

/// `c2:<fp16>:<b64url(length-prefixed {name, agent_id, kind, path_hash, skip})>`. Any other
/// prefix (a `d2:` token) is malformed. Refusal order: malformed -> filter mismatch.
[[nodiscard]] std::string encode_components_cursor(const SoftwareComponentCursor& after,
                                                   std::int64_t skip, std::string_view fp);
[[nodiscard]] std::expected<std::pair<SoftwareComponentCursor, std::int64_t>,
                            software_catalogue::CursorError>
decode_components_cursor(std::string_view token, std::string_view fp);

/// `read_scoped_page`'s Ops for the components list.
struct ComponentsOps {
    using Row = SoftwareComponentRow;
    using Query = SoftwareComponentQuery;
    using Anchor = SoftwareComponentCursor;
    static std::expected<std::pair<Anchor, std::int64_t>, software_catalogue::CursorError>
    decode(std::string_view token, std::string_view fp) {
        return decode_components_cursor(token, fp);
    }
    static std::string encode(const Anchor& a, std::int64_t skip, std::string_view fp) {
        return encode_components_cursor(a, skip, fp);
    }
    static Anchor key_of(const Row& r) { return {r.name, r.agent_id, r.kind, r.path_hash}; }
    static bool is_head(const Anchor& a) {
        return a.name.empty() && a.agent_id.empty() && a.kind.empty() && a.path_hash.empty();
    }
};

using ComponentsPage = software_catalogue::ScopedPage<SoftwareComponentRow>;
using ComponentsReader = software_catalogue::ScopedReader<ComponentsOps>;

/// One installs page for the list route (read_scoped_page<DevicesOps> with list_fingerprint).
[[nodiscard]] std::expected<software_catalogue::DevicesPage, std::optional<software_catalogue::CursorError>>
read_list_page(const software_catalogue::DevicesReader& read, const ListRequest& rq,
               const authz::VisibleSet& scope);

/// One components page (read_scoped_page<ComponentsOps> with components_fingerprint).
[[nodiscard]] std::expected<ComponentsPage, std::optional<software_catalogue::CursorError>>
read_components_page(const ComponentsReader& read, const ComponentsRequest& rq,
                     const authz::VisibleSet& scope);

// ── Per-page device facts (hostname, last poll) ──────────────────────────────

struct DeviceFacts {
    std::unordered_map<std::string, std::string> hostname;
    std::unordered_map<std::string, std::int64_t> last_seen; ///< absent = never synced
};

struct FactsReads {
    /// agent_id -> server-receipt epoch of its last accepted `installed_software` report.
    std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(
        const std::vector<std::string>&)>
        last_seen;
    const DeviceApi* device_api{nullptr}; ///< null = no registry wired (hostnames stay unknown)
};

/// The distinct agent ids of a page, in first-seen order.
template <class Row>
[[nodiscard]] std::vector<std::string> page_agent_ids(const std::vector<Row>& rows) {
    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    for (const auto& r : rows)
        if (seen.insert(r.agent_id).second)
            out.push_back(r.agent_id);
    return out;
}

/// Hostnames from ONE roster read per page (list_devices_basic, the crypto precedent) and last
/// polls from one bulk store read. nullopt = the store read degraded (503, never a blank).
/// Empty `ids` -> empty facts, no read.
[[nodiscard]] std::optional<DeviceFacts> load_device_facts(const FactsReads& io,
                                                           const std::vector<std::string>& ids);

// ── Totals ───────────────────────────────────────────────────────────────────

struct TotalsDecision {
    bool serve{false};
    std::string_view omitted; ///< "scope" | "filters" when !serve
};

/// `admit_all` is the gate's decision == ListReadDecision::AdmitAll. See the file banner.
[[nodiscard]] TotalsDecision totals_decision(bool admit_all, const SoftwareFleetQuery& q);
[[nodiscard]] TotalsDecision totals_decision(bool admit_all, const SoftwareComponentQuery& q);

struct TotalsReads {
    std::function<std::optional<CatalogRollupMeta>()> catalog_meta;
    std::function<std::optional<ComponentRollupMeta>()> component_meta;
    std::function<std::optional<SoftwareTotals>(std::string_view)> title_totals;
    std::function<std::optional<SoftwareTotals>(std::string_view, const std::vector<std::string>&)>
        version_set_totals;
    std::function<std::optional<SoftwareTotals>(std::string_view, std::string_view,
                                                const std::optional<std::vector<std::string>>&)>
        component_totals;
};

enum class TotalsStatus { kServed, kBuilding, kDegraded };

struct TotalsOutcome {
    TotalsStatus status{TotalsStatus::kDegraded};
    SoftwareTotals totals;
    std::optional<std::int64_t> as_of; ///< rollup refresh epoch; nullopt = computed live
};

/// Application totals for a SERVED decision: a version filter (exact or the resolved range) is a
/// live exact aggregate over the version set; none reads the title's rollup row (kBuilding while
/// the rollup was never computed). Any failed read is kDegraded (a 503, never a zero).
[[nodiscard]] TotalsOutcome read_application_totals(const TotalsReads& io, const SoftwareFleetQuery& q);
/// Component totals for a SERVED decision: kind + no version filter reads the (kind, name)
/// rollup row; every other shape is a live aggregate.
[[nodiscard]] TotalsOutcome read_component_totals(const TotalsReads& io, const SoftwareComponentQuery& q);

// ── JSON / CSV ───────────────────────────────────────────────────────────────

/// device_row_json fields (unchanged) + hostname (null when the registry does not know the
/// device), last_seen (null when never synced), status, last_confirmed_at (null when 0),
/// install_type, install_scope, install_location, instance_key.
[[nodiscard]] nlohmann::json list_row_json(const SoftwareFleetRow& r, const DeviceFacts& facts);
[[nodiscard]] nlohmann::json component_row_json(const SoftwareComponentRow& r, const DeviceFacts& facts);

/// `{software|components: [...], count, next_cursor, devices_omitted[, result_truncated_by_cap]}`;
/// the caller adds `totals`/`totals_omitted` with set_totals / set_totals_omitted.
[[nodiscard]] nlohmann::json list_response_json(const std::vector<SoftwareFleetRow>& rows,
                                                const DeviceFacts& facts, std::string_view next_cursor,
                                                std::int64_t devices_omitted, bool truncated_by_cap);
[[nodiscard]] nlohmann::json components_response_json(const std::vector<SoftwareComponentRow>& rows,
                                                      const DeviceFacts& facts,
                                                      std::string_view next_cursor,
                                                      std::int64_t devices_omitted,
                                                      bool truncated_by_cap);
void set_totals(nlohmann::json& body, const TotalsOutcome& t, bool components);
/// `totals: null, totals_omitted: <reason>`.
void set_totals_omitted(nlohmann::json& body, std::string_view reason);

[[nodiscard]] std::string list_csv(const std::vector<SoftwareFleetRow>& rows, const DeviceFacts& facts);
[[nodiscard]] std::string components_csv(const std::vector<SoftwareComponentRow>& rows,
                                         const DeviceFacts& facts);

} // namespace yuzu::server::software_list
