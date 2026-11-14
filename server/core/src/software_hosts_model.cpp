#include "software_hosts_model.hpp"

#include "list_keyset.hpp"
#include "model_param_helpers.hpp"
#include "software_catalog_rules.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <utility>

namespace yuzu::server::software_hosts {

namespace sc = software_catalog;

namespace {

using model_detail::first_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::split;
using model_detail::valid_text;
using ::yuzu::server::keyset::b64url_decode;
using ::yuzu::server::keyset::b64url_encode;

std::string get(const Params& p, const char* k) {
    const auto* v = first_param(p, k);
    return v ? *v : std::string{};
}

std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace

// ── Parameters ───────────────────────────────────────────────────────────────

std::expected<HostsRequest, std::string> parse_hosts_params(const Params& p) {
    HostsRequest r;
    std::string search = get(p, "q");
    r.cursor = get(p, "cursor");
    const std::string before = get(p, "last_synced_before");
    const std::string limit = get(p, "limit");
    if (auto bad = swc::text_error({&search, &r.cursor, &before}, {}))
        return std::unexpected(*bad);
    r.q = sc::clamp_utf8(search, sc::kSearchMaxBytes);
    if (r.cursor.size() > swc::kCursorMaxBytes)
        return std::unexpected("invalid cursor");
    if (!before.empty()) {
        const auto v = parse_nonneg(before);
        if (!v)
            return std::unexpected("invalid last_synced_before (expected a non-negative epoch)");
        r.last_synced_before = *v;
    }
    const auto lim = swc::read_limit(limit, swc::kCatalogueDefaultLimit, swc::kCataloguePageMax);
    if (!lim)
        return std::unexpected(lim.error());
    r.limit = *lim;
    return r;
}

// ── Search ───────────────────────────────────────────────────────────────────

std::expected<authz::VisibleSet, std::string>
resolve_host_search(std::string_view q, const Roster& roster, const authz::VisibleSet& scope) {
    if (q.empty())
        return scope;
    const std::string needle = lower(q);
    std::unordered_set<std::string> hits;
    for (const auto& [id, host] : roster) {
        if (!authz::in_scope(scope, id)) // cut to the caller's scope BEFORE matching or counting
            continue;
        if (lower(host).find(needle) == std::string::npos &&
            lower(id).find(needle) == std::string::npos)
            continue;
        hits.insert(id);
        if (hits.size() > swc::kScopePushdownMaxIds)
            return std::unexpected(std::string(kSearchTooBroad));
    }
    return authz::VisibleSet{std::move(hits)};
}

// ── Fingerprint, audit targets, cursor ───────────────────────────────────────

std::string hosts_fingerprint(const HostsRequest& rq) {
    const std::string before = std::to_string(rq.last_synced_before);
    return fnv1a_hex16("hosts" + length_prefixed({&rq.q, &before}));
}

std::string audit_target(const HostsRequest& rq) {
    std::string out = "hosts:fleet";
    if (!rq.q.empty())
        out += ";q=" + ::yuzu::log_token(rq.q);
    if (rq.last_synced_before > 0)
        out += ";last_synced_before=" + std::to_string(rq.last_synced_before);
    return out;
}

std::string audit_target_host(std::string_view agent_id) {
    return "host=" + ::yuzu::log_token(std::string(agent_id));
}

std::string encode_hosts_cursor(const std::string& after_agent_id, std::int64_t skip,
                                std::string_view fp) {
    const std::string s = std::to_string(skip);
    std::string out = "h1:";
    out += fp;
    out += ':';
    out += b64url_encode(length_prefixed({&after_agent_id, &s}));
    return out;
}

std::expected<std::pair<std::string, std::int64_t>, swc::CursorError>
decode_hosts_cursor(std::string_view token, std::string_view fp) {
    const auto parts = split(token, ':');
    if (parts.size() != 3 || parts[0] != "h1" || !is_lower_hex16(parts[1]))
        return std::unexpected(swc::CursorError::kMalformed);
    const auto payload = b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(swc::CursorError::kMalformed);
    const auto fields = read_length_prefixed(*payload, 2);
    if (!fields)
        return std::unexpected(swc::CursorError::kMalformed);
    const auto skip = parse_nonneg((*fields)[1]);
    if (!skip || !valid_text((*fields)[0]))
        return std::unexpected(swc::CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(swc::CursorError::kFilterMismatch);
    if (*skip > swc::kWideScopeMaxSkip)
        return std::unexpected(swc::CursorError::kScanLimit);
    return std::pair{std::string((*fields)[0]), *skip};
}

HostsQuery make_query(const HostsRequest& rq) {
    HostsQuery q;
    q.last_synced_before = rq.last_synced_before;
    q.limit = rq.limit;
    return q;
}

SoftwareHostQuery store_query(const HostsQuery& q) {
    SoftwareHostQuery s;
    s.agent_ids = q.agent_ids;
    s.last_synced_before = q.last_synced_before;
    s.after_agent_id = q.after;
    s.limit = static_cast<int>(q.limit);
    s.skip = q.skip;
    return s;
}

std::expected<HostsPage, std::optional<swc::CursorError>>
read_hosts_page(const HostsReader& read, const HostsRequest& rq, const authz::VisibleSet& scope) {
    return swc::read_scoped_page<HostsOps>(read, make_query(rq), rq.cursor, hosts_fingerprint(rq),
                                           scope);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json host_row_json(const SoftwareHostRow& r, const software_list::DeviceFacts& facts) {
    nlohmann::json facets = nlohmann::json::array();
    for (const auto& f : r.facets) {
        facets.push_back({{"facet", f.facet},
                          {"status", f.status},
                          {"row_status", software_list::derive_status(f.status, f.enabled)},
                          {"token", f.token},
                          {"enabled", f.enabled},
                          {"last_confirmed_at",
                           f.last_confirmed_at == 0 ? nlohmann::json(nullptr)
                                                    : nlohmann::json(f.last_confirmed_at)},
                          {"duration_ms", f.duration_ms},
                          {"bytes_read", f.bytes_read}});
    }
    const auto host = facts.hostname.find(r.agent_id);
    return {{"agent_id", r.agent_id},
            {"hostname", host == facts.hostname.end() || host->second.empty()
                             ? nlohmann::json(nullptr)
                             : nlohmann::json(host->second)},
            {"last_seen", r.last_seen},
            {"facets", std::move(facets)}};
}

nlohmann::json hosts_response_json(const std::vector<SoftwareHostRow>& rows,
                                   const software_list::DeviceFacts& facts,
                                   std::string_view next_cursor, std::int64_t devices_omitted) {
    nlohmann::json hosts = nlohmann::json::array();
    for (const auto& r : rows)
        hosts.push_back(host_row_json(r, facts));
    return {{"hosts", std::move(hosts)},
            {"count", rows.size()},
            {"next_cursor", next_cursor.empty() ? nlohmann::json(nullptr)
                                                : nlohmann::json(std::string(next_cursor))},
            {"devices_omitted", devices_omitted}};
}

nlohmann::json host_detail_json(const nlohmann::json& host, const nlohmann::json& installs_page) {
    return {{"host", host},
            {"software", installs_page.value("software", nlohmann::json::array())},
            {"count", installs_page.value("count", 0)},
            {"next_cursor", installs_page.contains("next_cursor") ? installs_page["next_cursor"]
                                                                  : nlohmann::json(nullptr)}};
}

} // namespace yuzu::server::software_hosts
