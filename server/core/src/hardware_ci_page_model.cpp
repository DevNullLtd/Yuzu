#include "hardware_ci_page_model.hpp"

#include "hardware_list_model.hpp"       // hardware_ci_scalars_json, id_is_audit_safe
#include "list_keyset.hpp"               // the strict base64url codec shared by every cursor
#include "model_param_helpers.hpp"       // shared param/cursor helpers (one copy across models)
#include "software_catalogue_model.hpp"  // kScopePushdownMaxIds, kWideScopeMaxReads

#include <algorithm>
#include <cstddef>
#include <format>
#include <iterator>
#include <unordered_set>
#include <utility>

namespace yuzu::server::hardware_ci_page {

namespace {

using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_i64;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

namespace sc = software_catalogue;

constexpr std::string_view kCursorPrefix = "h1";

std::vector<std::string_view> split_colon(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = s.find(':', start);
        if (pos == std::string_view::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
}

// The text checks every channel applies to the two string inputs. nullopt = acceptable.
std::optional<std::string> text_error(const std::string& agent_id, const std::string& cursor) {
    if (!valid_text(agent_id) || !valid_text(cursor))
        return "invalid parameter encoding";
    if (!agent_id.empty() && !id_is_audit_safe(agent_id))
        return "invalid agent_id";
    if (cursor.size() > kCursorMaxBytes)
        return "invalid cursor";
    return std::nullopt;
}

} // namespace

// ── Parameters ───────────────────────────────────────────────────────────────

std::expected<Request, std::string> parse_params(const Params& p) {
    const auto first = [&](const char* key) -> std::string {
        const auto it = p.lower_bound(key);
        return it != p.end() && it->first == key ? it->second : std::string{};
    };
    Request r;
    r.agent_id = first("agent_id");
    r.cursor = first("cursor");
    if (const auto bad = text_error(r.agent_id, r.cursor))
        return std::unexpected(*bad);
    if (const std::string limit = first("limit"); !limit.empty()) {
        const auto n = parse_i64(limit);
        if (!n)
            return std::unexpected("invalid limit (expected integer)");
        r.limit = static_cast<int>(std::clamp<std::int64_t>(*n, 1, kPageMax));
    }
    return r;
}

std::expected<Request, std::string> request_from_args(const nlohmann::json& args) {
    Request r;
    if (!args.is_object())
        return r;
    for (const char* key : {"agent_id", "cursor"})
        if (args.contains(key) && !args[key].is_string())
            return std::unexpected(std::string(key) + " must be a JSON string");
    if (args.contains("agent_id")) {
        r.agent_id = args["agent_id"].get<std::string>();
        if (r.agent_id.empty())
            return std::unexpected("agent_id must be a non-empty string when given");
    }
    if (args.contains("cursor"))
        r.cursor = args["cursor"].get<std::string>();
    if (const auto bad = text_error(r.agent_id, r.cursor))
        return std::unexpected(*bad);
    if (args.contains("limit")) {
        const auto& l = args["limit"];
        // nlohmann stores every non-negative integer as unsigned: refuse above INT64_MAX here
        // rather than let the get<int64_t>() below wrap.
        if (!l.is_number_integer() ||
            (l.is_number_unsigned() &&
             l.get<std::uint64_t>() > static_cast<std::uint64_t>(INT64_MAX)))
            return std::unexpected("limit must be a JSON integer");
        const auto n = l.get<std::int64_t>();
        if (n < 1 || n > kPageMax)
            return std::unexpected("limit must be between 1 and " + std::to_string(kPageMax));
        r.limit = static_cast<int>(n);
    }
    return r;
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    switch (e) {
    case CursorError::kMalformed:
        return "invalid cursor";
    case CursorError::kFilterMismatch:
        return "cursor does not match this request's agent_id filter; restart from the first page";
    }
    return "invalid cursor";
}

std::string filter_fingerprint(const Request& rq) {
    return fnv1a_hex16("agent_id=" + rq.agent_id);
}

std::string encode_cursor(const Position& at, std::string_view fp) {
    const std::string skip = std::to_string(at.skip);
    std::string out(kCursorPrefix);
    out += ':';
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&at.after, &skip}));
    return out;
}

std::expected<Position, CursorError> decode_cursor(std::string_view token, std::string_view fp) {
    const auto parts = split_colon(token);
    if (parts.size() != 3 || parts[0] != kCursorPrefix || !is_lower_hex16(parts[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto payload = keyset::b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(CursorError::kMalformed);
    const auto fields = read_length_prefixed(*payload, 2);
    if (!fields)
        return std::unexpected(CursorError::kMalformed);
    const auto skip = parse_nonneg((*fields)[1]);
    const std::string after((*fields)[0]);
    // The decoded id is bound as a SQL parameter: strict UTF-8, no NUL, and the audit-safe floor
    // every id on this surface meets.
    if (!skip || !valid_text(after) || (!after.empty() && !id_is_audit_safe(after)))
        return std::unexpected(CursorError::kMalformed);
    const Position pos{after, *skip};
    // One spelling per position: a token that does not re-encode to itself (non-canonical
    // base64url tail bits, a leading-zero length or skip) is malformed.
    if (encode_cursor(pos, parts[1]) != token)
        return std::unexpected(CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return pos;
}

// ── One page ─────────────────────────────────────────────────────────────────

std::expected<Page, std::optional<CursorError>>
read_page(const Reader& read, const Request& rq, const authz::VisibleSet& scope) {
    const std::string fp = filter_fingerprint(rq);
    Position incoming; // the head: nothing served yet
    if (!rq.cursor.empty()) {
        auto cur = decode_cursor(rq.cursor, fp);
        if (!cur)
            return std::unexpected(cur.error());
        incoming = std::move(*cur);
    }
    Page out;
    // A named device outside the scope is answered without touching the store: nothing of it is
    // read, and the page is the same empty page a scoped caller gets for a device that has no row.
    if (!rq.agent_id.empty() && !authz::in_scope(scope, rq.agent_id)) {
        out.target_denied = true;
        return out;
    }
    DeviceCiKeysetQuery q;
    q.after = incoming.after;
    q.limit = rq.limit;
    if (!rq.agent_id.empty())
        q.agent_id = rq.agent_id;
    // TOP leaves the query alone; an engaged-empty scope is agent_ids = {} (the store answers
    // empty without SQL); a bounded set is pushed into SQL; a wider one is post-filtered below.
    const bool wide = scope && scope->size() > sc::kScopePushdownMaxIds;
    if (scope && !wide)
        q.agent_ids.emplace(scope->begin(), scope->end());

    if (!wide) {
        // Every returned row is in scope. One extra row is read to know whether the page is the
        // last, so a final page carries no cursor. A skip is only ever minted by the wide path
        // below and has no meaning here.
        q.limit = rq.limit + 1;
        auto rows = read(q);
        if (!rows)
            return std::unexpected(std::nullopt);
        const auto limit = static_cast<std::size_t>(rq.limit);
        if (rows->size() > limit) {
            rows->resize(limit);
            out.next_cursor = encode_cursor({rows->back().agent_id, 0}, fp);
        }
        out.rows = std::move(*rows);
        return out;
    }

    // Wide scope: post-filter, refilling the page with at most kWideScopeMaxReads bounded reads.
    // The cursor must never carry a dropped row's key, so it is the last IN-SCOPE row served (the
    // incoming anchor if there is none) plus the number of rows scanned after it, which the next
    // request passes over in SQL. Each refill read continues after the last row SCANNED, kept
    // in-process only.
    const auto limit = static_cast<std::size_t>(rq.limit);
    q.skip = incoming.skip;
    std::int64_t since_anchor = incoming.skip;
    std::unordered_set<std::string> dropped;
    bool more = false;
    out.rows.reserve(limit);
    for (int reads = 1;; ++reads) {
        auto rows = read(q);
        if (!rows)
            return std::unexpected(std::nullopt);
        const bool full = !rows->empty() && rows->size() == limit;
        std::string last_scanned;
        if (full && reads < sc::kWideScopeMaxReads)
            last_scanned = rows->back().agent_id;
        std::size_t i = 0;
        for (; i < rows->size() && out.rows.size() < limit; ++i) {
            auto& r = (*rows)[i];
            if (authz::in_scope(scope, r.agent_id)) {
                out.rows.push_back(std::move(r));
                since_anchor = 0;
            } else {
                dropped.insert(r.agent_id); // each DISTINCT device counts once
                ++since_anchor;
            }
        }
        if (out.rows.size() >= limit) { // page filled: rows may remain here or beyond
            more = i < rows->size() || full;
            break;
        }
        if (!full) // a short read is the end of the data
            break;
        if (reads >= sc::kWideScopeMaxReads) { // bound reached: say there may be more
            more = true;
            break;
        }
        q.after = std::move(last_scanned);
        q.skip = 0;
    }
    out.devices_omitted = static_cast<std::int64_t>(dropped.size());
    if (more)
        out.next_cursor = encode_cursor(
            {out.rows.empty() ? incoming.after : out.rows.back().agent_id, since_anchor}, fp);
    return out;
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json row_json(const DeviceCiRecord& rec) {
    return nlohmann::json{
        {"agent_id", rec.agent_id},
        {"hostname", rec.hostname.empty() || rec.hostname == "unknown" ? nlohmann::json(nullptr)
                                                                        : nlohmann::json(rec.hostname)},
        {"ci", hardware_ci_scalars_json(rec)},
        {"content_hash", rec.content_hash.empty() ? nlohmann::json(nullptr)
                                                   : nlohmann::json(rec.content_hash)},
        {"blob_version", rec.blob_version},
    };
}

nlohmann::json page_json(const Page& page) {
    auto devices = nlohmann::json::array();
    for (const auto& r : page.rows)
        devices.push_back(row_json(r));
    return nlohmann::json{
        {"devices", std::move(devices)},
        {"next_cursor", page.next_cursor},
        {"devices_omitted", page.devices_omitted},
    };
}

// ── Audit text ───────────────────────────────────────────────────────────────

std::string audit_target_type(const Request& rq) {
    return rq.agent_id.empty() ? "Inventory" : "Agent";
}

std::string audit_target_id(const Request& rq) {
    return rq.agent_id.empty() ? "fleet" : rq.agent_id;
}

std::string audit_detail(const Page& page, const Request& rq, std::string_view surface,
                         bool confined, bool include_omitted) {
    std::string out = std::format("hardware CI records ({}): rows={}", surface, page.rows.size());
    if (include_omitted)
        out += " omitted=" + std::to_string(page.devices_omitted);
    if (!rq.cursor.empty())
        out += " page=continuation";
    out += confined ? " scope=confined" : " scope=fleet";
    return out;
}

} // namespace yuzu::server::hardware_ci_page
