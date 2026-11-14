#include "software_changes_model.hpp"

#include "list_keyset.hpp"
#include "model_param_helpers.hpp"

#include <utility>

namespace yuzu::server::software_changes {

namespace swc = software_catalogue;

namespace {

using model_detail::first_param_or_empty;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::split;
using ::yuzu::server::keyset::b64url_decode;
using ::yuzu::server::keyset::b64url_encode;

nlohmann::json counts_json(const SoftwareChangeCounts& c) {
    return {{"install", c.install}, {"remove", c.remove}, {"upgrade", c.upgrade}};
}

} // namespace

std::expected<ChangesRequest, std::string> parse_changes_params(const Params& p, std::int64_t now) {
    ChangesRequest r;
    SoftwareChangesQuery& q = r.query;
    q.agent_id = first_param_or_empty(p, "agent_id");
    q.kind = first_param_or_empty(p, "kind");
    r.cursor = first_param_or_empty(p, "cursor");
    const std::string since = first_param_or_empty(p, "since");
    const std::string limit = first_param_or_empty(p, "limit");
    if (auto bad = swc::text_error({&q.agent_id, &q.kind, &since, &r.cursor, &limit},
                                   {&q.agent_id, &q.kind, &since, &limit}))
        return std::unexpected(*bad);
    if (r.cursor.size() > swc::kCursorMaxBytes)
        return std::unexpected("invalid cursor");
    if (!q.kind.empty() && q.kind != "install" && q.kind != "remove" && q.kind != "upgrade")
        return std::unexpected("invalid kind");
    if (!since.empty()) {
        const auto s = parse_nonneg(since);
        if (!s)
            return std::unexpected("invalid since");
        q.since = *s;
    }
    const auto lim = swc::read_limit(limit, swc::kCatalogueDefaultLimit, swc::kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    q.limit = static_cast<int>(*lim);
    q.stable_before = now - kSettleSecs;
    return r;
}

// ── Fingerprint and cursor ───────────────────────────────────────────────────

std::string changes_fingerprint(const SoftwareChangesQuery& q) {
    const std::string since = std::to_string(q.since);
    return fnv1a_hex16(length_prefixed({&since, &q.agent_id, &q.kind}));
}

std::string encode_changes_cursor(const ChangesAnchor& after, std::int64_t skip,
                                  std::string_view fp) {
    const std::string at = std::to_string(after.observed_at);
    const std::string id = std::to_string(after.change_id);
    const std::string s = std::to_string(skip);
    std::string out = "g1:";
    out += fp;
    out += ':';
    out += b64url_encode(length_prefixed({&at, &id, &s}));
    return out;
}

std::expected<std::pair<ChangesAnchor, std::int64_t>, swc::CursorError>
decode_changes_cursor(std::string_view token, std::string_view fp) {
    const auto parts = split(token, ':');
    if (parts.size() != 3 || parts[0] != "g1" || !is_lower_hex16(parts[1]))
        return std::unexpected(swc::CursorError::kMalformed);
    const auto payload = b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(swc::CursorError::kMalformed);
    const auto fields = read_length_prefixed(*payload, 3);
    if (!fields)
        return std::unexpected(swc::CursorError::kMalformed);
    // parse_nonneg refuses an empty or signed field: both anchor fields are required, >= 0.
    const auto at = parse_nonneg((*fields)[0]);
    const auto id = parse_nonneg((*fields)[1]);
    const auto skip = parse_nonneg((*fields)[2]);
    if (!at || !id || !skip)
        return std::unexpected(swc::CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(swc::CursorError::kFilterMismatch);
    return std::pair{ChangesAnchor{*at, *id}, *skip};
}

std::expected<ChangesPage, std::optional<swc::CursorError>>
read_changes_page(const ChangesReader& read, const ChangesRequest& rq, const authz::VisibleSet& scope) {
    return swc::read_scoped_page<ChangesOps>(read, rq.query, rq.cursor, changes_fingerprint(rq.query),
                                             scope);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json change_row_json(const SoftwareChangeRow& r, const software_list::DeviceFacts& facts) {
    const auto host = facts.hostname.find(r.agent_id);
    return {
        {"change_id", r.change_id},
        {"agent_id", r.agent_id},
        {"hostname", host == facts.hostname.end() ? nlohmann::json(nullptr)
                                                  : nlohmann::json(host->second)},
        {"facet", r.facet},
        {"kind", r.kind},
        {"name", r.name},
        {"publisher", r.publisher},
        {"from_version", r.from_version},
        {"to_version", r.to_version},
        {"instance_key", r.instance_key},
        {"observed_at", r.observed_at},
    };
}

nlohmann::json changes_response_json(const std::vector<SoftwareChangeRow>& rows,
                                     const software_list::DeviceFacts& facts,
                                     std::string_view next_cursor, std::int64_t devices_omitted,
                                     std::int64_t stable_before) {
    auto arr = nlohmann::json::array();
    for (const auto& r : rows)
        arr.push_back(change_row_json(r, facts));
    return {
        {"changes", std::move(arr)},
        {"count", rows.size()},
        {"next_cursor", next_cursor.empty() ? nlohmann::json(nullptr)
                                            : nlohmann::json(std::string(next_cursor))},
        {"devices_omitted", devices_omitted},
        {"stable_before", stable_before},
    };
}

nlohmann::json summary_json(const std::optional<SoftwareSummary>& summary,
                            const std::optional<CatalogRollupMeta>& catalog,
                            std::int64_t as_of, std::string_view omitted_reason) {
    nlohmann::json out;
    if (summary) {
        out["devices"] = {{"reporting", summary->devices_reporting},
                          {"stale", summary->devices_stale}};
        out["changes"] = {{"last_24h", counts_json(summary->changes_24h)},
                          {"last_7d", counts_json(summary->changes_7d)}};
    } else {
        out["devices"] = nullptr;
        out["changes"] = nullptr;
    }
    const bool catalog_ready = catalog && catalog->refreshed_at > 0;
    if (catalog_ready)
        out["catalogue"] = {{"titles", catalog->total_titles},
                            {"installs", catalog->total_installs},
                            {"devices", catalog->total_devices}};
    else
        out["catalogue"] = nullptr;
    out["as_of"] = as_of;
    if (summary && catalog_ready) {
        out["omitted"] = nullptr;
    } else {
        // A catalogue rollup that exists but was never computed is "building" whatever the caller
        // passed; otherwise the caller's reason (an absent input), defaulting to "building".
        const bool building = catalog && !catalog_ready;
        out["omitted"] = std::string(building || omitted_reason.empty() ? kOmittedBuilding
                                                                         : omitted_reason);
    }
    return out;
}

} // namespace yuzu::server::software_changes
