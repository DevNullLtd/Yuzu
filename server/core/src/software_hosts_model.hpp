#pragma once

/// @file software_hosts_model.hpp
/// The pure model behind the SAM-33 hosts reads: `GET /api/v1/inventory/software/hosts` (one row
/// per reporting device with its facet state) and the host detail (one device plus its installs
/// page). No httplib, no libpq: the route handlers inject the store reads.
///
/// Rules this file owns (each stated once, here):
///  * SEARCH SCOPE: `q` is resolved against the device roster AFTER the roster is cut to the
///    caller's scope, so a device outside the scope takes no part in the match or in the cap. The
///    "search matches too many devices" refusal is therefore a fact about the caller's own rows.
///    The roster is the 30-day, newest-100,000 read, so `q` finds only devices it holds: a roster
///    cut at the cap is served with `roster_truncated` (a miss then proves nothing), and a device
///    quiet for over 30 days is listed with a null hostname and not matched (tracked by #7790).
///  * ROW STATUS: each facet carries the raw stored `status` and the derived `row_status`
///    (software_list::derive_status); there is no per-host rollup field.
///  * CURSOR: `h1:<fp16>:<b64url(length-prefixed {agent_id, skip})>`, bound to `q` and
///    `last_synced_before`, never to the scope.

#include "software_catalogue_model.hpp"
#include "software_list_model.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::software_hosts {

namespace swc = software_catalogue;
using Params = swc::Params;

/// The 400 message when the caller's own matches exceed swc::kScopePushdownMaxIds.
inline constexpr std::string_view kSearchTooBroad = "search matches too many devices; narrow q";

// ── Parameters ───────────────────────────────────────────────────────────────

struct HostsRequest {
    std::string q;                       ///< clamped to software_catalog::kSearchMaxBytes
    std::int64_t last_synced_before{0};  ///< epoch seconds; 0 = no filter
    std::int64_t limit{swc::kCatalogueDefaultLimit};
    std::string cursor;
};

/// Keys: q, last_synced_before, limit, cursor. A repeated key keeps the FIRST value. The error is
/// the 400 message.
[[nodiscard]] std::expected<HostsRequest, std::string> parse_hosts_params(const Params& p);

// ── Search ───────────────────────────────────────────────────────────────────

/// agent_id -> hostname (blank = unknown).
using Roster = std::unordered_map<std::string, std::string>;

/// The scope to read with. Empty `q`: `scope` unchanged. Otherwise the roster is cut to `scope`
/// (nullopt = global caller), then matched (case-insensitive LITERAL substring over hostname and
/// agent_id), then capped: the matching in-scope ids as an engaged set (empty included), or
/// kSearchTooBroad when they exceed swc::kScopePushdownMaxIds.
[[nodiscard]] std::expected<authz::VisibleSet, std::string>
resolve_host_search(std::string_view q, const Roster& roster, const authz::VisibleSet& scope);

// ── Fingerprint, audit targets, cursor ───────────────────────────────────────

[[nodiscard]] std::string hosts_fingerprint(const HostsRequest& rq);
[[nodiscard]] std::string audit_target(const HostsRequest& rq);
[[nodiscard]] std::string audit_target_host(std::string_view agent_id);

[[nodiscard]] std::string encode_hosts_cursor(const std::string& after_agent_id, std::int64_t skip,
                                              std::string_view fp);
/// Refusal order: malformed -> filter mismatch -> scan limit.
[[nodiscard]] std::expected<std::pair<std::string, std::int64_t>, swc::CursorError>
decode_hosts_cursor(std::string_view token, std::string_view fp);

/// The store query plus the members `read_scoped_page` drives (`agent_id`, `after`); store_query()
/// folds `after` into the store's `after_agent_id`.
struct HostsQuery : SoftwareHostQuery {
    std::string agent_id; ///< unused (hosts are not filtered to one device here); "" always
    std::string after;
};

[[nodiscard]] HostsQuery make_query(const HostsRequest& rq);
[[nodiscard]] SoftwareHostQuery store_query(const HostsQuery& q);

/// `read_scoped_page`'s Ops for the hosts list (key = agent_id).
struct HostsOps {
    using Row = SoftwareHostRow;
    using Query = HostsQuery;
    using Anchor = std::string;
    static std::expected<std::pair<Anchor, std::int64_t>, swc::CursorError>
    decode(std::string_view token, std::string_view fp) {
        return decode_hosts_cursor(token, fp);
    }
    static std::string encode(const Anchor& a, std::int64_t skip, std::string_view fp) {
        return encode_hosts_cursor(a, skip, fp);
    }
    static Anchor key_of(const Row& r) { return r.agent_id; }
    static bool is_head(const Anchor& a) { return a.empty(); }
};

using HostsPage = swc::ScopedPage<SoftwareHostRow>;
using HostsReader = swc::ScopedReader<HostsOps>;

/// One hosts page (read_scoped_page<HostsOps> with hosts_fingerprint). `scope` is the result of
/// resolve_host_search (or the gate's scope when q is empty).
[[nodiscard]] std::expected<HostsPage, std::optional<swc::CursorError>>
read_hosts_page(const HostsReader& read, const HostsRequest& rq, const authz::VisibleSet& scope);

// ── JSON ─────────────────────────────────────────────────────────────────────

/// `{agent_id, hostname (null when the roster does not know it), last_seen,
/// facets: [{facet, status, row_status, token, enabled, last_confirmed_at (null when 0),
/// duration_ms, bytes_read}]}`.
[[nodiscard]] nlohmann::json host_row_json(const SoftwareHostRow& r,
                                           const software_list::DeviceFacts& facts);
/// `{hosts, count, next_cursor (null when empty), devices_omitted, roster_truncated, roster_cap}`.
/// The last two are the roster read's own flag and cap (kOfflineRosterRowCap), as the hardware list.
[[nodiscard]] nlohmann::json hosts_response_json(const std::vector<SoftwareHostRow>& rows,
                                                 const software_list::DeviceFacts& facts,
                                                 std::string_view next_cursor,
                                                 std::int64_t devices_omitted,
                                                 bool roster_truncated);
/// `{host, software, count, next_cursor}` from a host_row_json and a
/// software_list::list_response_json page.
[[nodiscard]] nlohmann::json host_detail_json(const nlohmann::json& host,
                                              const nlohmann::json& installs_page);

} // namespace yuzu::server::software_hosts
