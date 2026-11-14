#pragma once

/// @file software_changes_model.hpp
/// The pure model behind the SAM-33 reads `GET /api/v1/inventory/software/changes` (the change
/// feed) and `GET /api/v1/inventory/software/summary`. No httplib, no libpq, no clock: the route
/// handler injects the store reads and the current time.
///
/// Rules this file owns (each stated once, here):
///  * ORDER AND CURSOR: the feed is ordered (observed_at, change_id) and the keyset anchor is that
///    pair taken from the last row of the page. change_id is a BIGSERIAL taken at insert while
///    observed_at is the writing replica's clock, so a change_id-only cursor could step over a lower
///    id that becomes eligible later. Both anchor fields are required in a cursor and are
///    non-negative; anything else is an invalid cursor.
///  * SETTLE WINDOW: a row is published once it is older than kSettleSecs. The model only derives
///    `stable_before = now - kSettleSecs` and hands it to the query; it never filters rows. The
///    cursor is NOT bound to `stable_before` (it advances on every request), so a cursor survives
///    the next request. Lateness contract (60 s, no watermark): a row committed later than that
///    after its own observed_at lands behind any cursor that already passed it and is recovered by
///    a re-read with `since`, de-duplicated on change_id.
///  * SUMMARY: a block whose input is absent renders null with `omitted` = "scope" | "building",
///    never zeros.

#include "software_list_model.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::software_changes {

using Params = software_catalogue::Params;

inline constexpr std::int64_t kSettleSecs = 60;

inline constexpr std::string_view kOmittedScope = "scope";
inline constexpr std::string_view kOmittedBuilding = "building";

// ── Parameters ───────────────────────────────────────────────────────────────

/// The keyset position of the feed: the (observed_at, change_id) of the last row served.
struct ChangesAnchor {
    std::int64_t observed_at{0};
    std::int64_t change_id{0};
};

/// The store query plus the anchor `read_scoped_page` drives (`after`); to_store_query folds the
/// anchor into the store's two `after_*` fields.
struct ChangesQuery : SoftwareChangesQuery {
    ChangesAnchor after;
};

struct ChangesRequest {
    ChangesQuery query;
    std::string cursor;
};

/// Keys: cursor, since, agent_id, kind, limit. `since` is a non-negative epoch (empty = none);
/// `kind` is install|remove|upgrade (else 400 "invalid kind"); `agent_id` has the list parsers'
/// text hygiene; `limit` is clamped to [1, kCataloguePageMax], default kCatalogueDefaultLimit. A
/// repeated key keeps the FIRST value. `query.stable_before` = now - kSettleSecs. The error is
/// the 400 message.
[[nodiscard]] std::expected<ChangesRequest, std::string> parse_changes_params(const Params& p,
                                                                              std::int64_t now);

[[nodiscard]] inline SoftwareChangesQuery to_store_query(const ChangesQuery& q) {
    SoftwareChangesQuery out = q;
    out.after_observed_at = q.after.observed_at;
    out.after_change_id = q.after.change_id;
    return out;
}

// ── Fingerprint and cursor ───────────────────────────────────────────────────

/// Bound to since, agent_id and kind. Never to stable_before (it moves) or to the scope.
[[nodiscard]] std::string changes_fingerprint(const SoftwareChangesQuery& q);

/// `g1:<fp16>:<b64url(length-prefixed {observed_at, change_id, skip})>`.
[[nodiscard]] std::string encode_changes_cursor(const ChangesAnchor& after, std::int64_t skip,
                                                std::string_view fp);
/// Refusal order: malformed -> filter mismatch. A missing or negative anchor field is malformed.
[[nodiscard]] std::expected<std::pair<ChangesAnchor, std::int64_t>, software_catalogue::CursorError>
decode_changes_cursor(std::string_view token, std::string_view fp);

/// `read_scoped_page`'s Ops for the change feed.
struct ChangesOps {
    using Row = SoftwareChangeRow;
    using Query = ChangesQuery;
    using Anchor = ChangesAnchor;
    static std::expected<std::pair<Anchor, std::int64_t>, software_catalogue::CursorError>
    decode(std::string_view token, std::string_view fp) {
        return decode_changes_cursor(token, fp);
    }
    static std::string encode(const Anchor& a, std::int64_t skip, std::string_view fp) {
        return encode_changes_cursor(a, skip, fp);
    }
    static Anchor key_of(const Row& r) { return {r.observed_at, r.change_id}; }
    static bool is_head(const Anchor& a) { return a.observed_at == 0 && a.change_id == 0; }
};

using ChangesPage = software_catalogue::ScopedPage<SoftwareChangeRow>;
using ChangesReader = software_catalogue::ScopedReader<ChangesOps>;

/// One feed page (read_scoped_page<ChangesOps> with changes_fingerprint).
[[nodiscard]] std::expected<ChangesPage, std::optional<software_catalogue::CursorError>>
read_changes_page(const ChangesReader& read, const ChangesRequest& rq, const authz::VisibleSet& scope);

// ── JSON ─────────────────────────────────────────────────────────────────────

/// change_id, agent_id, hostname (null when the roster does not know the device), facet, kind,
/// name, publisher, from_version, to_version, instance_key, observed_at.
[[nodiscard]] nlohmann::json change_row_json(const SoftwareChangeRow& r,
                                             const software_list::DeviceFacts& facts);

/// `{changes, count, next_cursor, devices_omitted, stable_before}`.
[[nodiscard]] nlohmann::json changes_response_json(const std::vector<SoftwareChangeRow>& rows,
                                                   const software_list::DeviceFacts& facts,
                                                   std::string_view next_cursor,
                                                   std::int64_t devices_omitted,
                                                   std::int64_t stable_before);

/// `{devices{reporting,stale}, changes{last_24h{install,remove,upgrade}, last_7d{...}},
/// catalogue{titles,installs,devices}, as_of, omitted}`. A null `summary` renders `devices` and
/// `changes` null; a null `catalog` (a confined caller) or one with refreshed_at == 0 renders
/// `catalogue` null. `omitted` is null when every block is present, else "building" for a never-computed
/// rollup, else `omitted_reason`
/// ("scope" | "building"; empty = "building").
[[nodiscard]] nlohmann::json summary_json(const std::optional<SoftwareSummary>& summary,
                                          const std::optional<CatalogRollupMeta>& catalog,
                                          std::int64_t as_of, std::string_view omitted_reason);

} // namespace yuzu::server::software_changes
