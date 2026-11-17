#include "hardware_ci_page_model.hpp"

#include "hardware_list_model.hpp"       // hardware_ci_scalars_json, id_is_audit_safe
#include "list_keyset.hpp"               // the strict base64url codec shared by every cursor
#include "model_param_helpers.hpp"       // shared param/cursor helpers (one copy across models)

#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <format>
#include <iterator>
#include <system_error>
#include <utility>

namespace yuzu::server::hardware_ci_page {

namespace {

using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

constexpr std::string_view kCursorPrefix = "h1";
// The refusal of a present-but-empty `agent_id`, spelled once for REST and MCP.
constexpr std::string_view kEmptyAgentIdMessage = "agent_id must be a non-empty string when given";

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

// REST `limit`: an optional leading '-' and decimal digits only, nothing else. A value that is
// that shape but too large for 64 bits clamps by its sign (the documented rule for an
// out-of-range integer); anything of another shape is nullopt (a 400).
std::optional<int> parse_rest_limit(std::string_view s) {
    const bool negative = !s.empty() && s.front() == '-';
    const std::string_view digits = negative ? s.substr(1) : s;
    if (digits.empty() ||
        !std::ranges::all_of(digits, [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec == std::errc::result_out_of_range)
        return static_cast<int>(negative ? 1 : kPageMax);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    return static_cast<int>(std::clamp<std::int64_t>(v, 1, kPageMax));
}

// The text checks every channel applies to the two string inputs. nullopt = acceptable.
struct TextFault {
    std::string message;
    ArgFault fault{ArgFault::kOther};
};

// A cursor that is not valid text (NUL, bad UTF-8) or is over-long is refused with the SAME
// message and fault as every other refused cursor, so a caller and the audit trail see one cursor
// refusal whatever made the token unusable. The cursor is judged first for that reason.
std::optional<TextFault> text_error(const std::string& agent_id, const std::string& cursor) {
    if (!valid_text(cursor) || cursor.size() > kCursorMaxBytes)
        return TextFault{std::string(cursor_error_message(CursorError::kMalformed)),
                         ArgFault::kCursorRefused};
    if (!valid_text(agent_id))
        return TextFault{"invalid parameter encoding"};
    if (!agent_id.empty() && !id_is_audit_safe(agent_id))
        return TextFault{"invalid agent_id"};
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
        return std::unexpected(bad->message);
    // A present-but-empty `agent_id` is refused, not read as "every device": a client that
    // interpolates a missing id into the query would otherwise be served a page of OTHER devices'
    // records and could attach the first to the wrong one. An empty `cursor` is the first page.
    if (const auto it = p.lower_bound("agent_id"); it != p.end() && it->first == "agent_id" &&
                                                    r.agent_id.empty())
        return std::unexpected(std::string(kEmptyAgentIdMessage));
    if (const std::string limit = first("limit"); !limit.empty()) {
        const auto n = parse_rest_limit(limit);
        if (!n)
            return std::unexpected("invalid limit (expected integer)");
        r.limit = *n;
    }
    return r;
}

std::expected<Request, ArgError> request_from_args(const nlohmann::json& args) {
    Request r;
    r.limit = static_cast<int>(kMcpDefaultLimit);
    if (args.is_null())
        return r;
    // Anything but an object would otherwise read as "no arguments", a default request for the
    // whole fleet.
    if (!args.is_object())
        return std::unexpected(ArgError{"arguments must be a JSON object"});
    for (const char* key : {"agent_id", "cursor"})
        if (args.contains(key) && !args[key].is_string())
            return std::unexpected(ArgError{std::string(key) + " must be a JSON string"});
    if (args.contains("agent_id")) {
        r.agent_id = args["agent_id"].get<std::string>();
        if (r.agent_id.empty())
            return std::unexpected(ArgError{std::string(kEmptyAgentIdMessage)});
    }
    if (args.contains("cursor"))
        r.cursor = args["cursor"].get<std::string>();
    if (const auto bad = text_error(r.agent_id, r.cursor))
        return std::unexpected(ArgError{bad->message, bad->fault});
    if (args.contains("limit")) {
        const auto& l = args["limit"];
        // nlohmann stores every non-negative integer as unsigned: refuse above INT64_MAX here
        // rather than let the get<int64_t>() below wrap.
        if (!l.is_number_integer() ||
            (l.is_number_unsigned() &&
             l.get<std::uint64_t>() > static_cast<std::uint64_t>(INT64_MAX)))
            return std::unexpected(ArgError{"limit must be a JSON integer"});
        const auto n = l.get<std::int64_t>();
        if (n < 1 || n > kPageMax)
            return std::unexpected(ArgError{"limit must be between 1 and " + std::to_string(kPageMax)});
        r.limit = static_cast<int>(n);
    }
    return r;
}

// ── Cursors ──────────────────────────────────────────────────────────────────

std::string_view cursor_error_message(CursorError e) {
    switch (e) {
    case CursorError::kMalformed:
    case CursorError::kFilterMismatch:
        return "invalid cursor; restart from the first page";
    }
    return "invalid cursor; restart from the first page";
}

std::string filter_fingerprint(const Request& rq) {
    return fnv1a_hex16("agent_id=" + rq.agent_id);
}

std::string encode_cursor(const Position& at, std::string_view fp) {
    std::string out(kCursorPrefix);
    out += ':';
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&at.after}));
    return out;
}

std::expected<Position, CursorError> decode_cursor(std::string_view token, std::string_view fp) {
    // Defence in depth: it bounds the work done on hostile oversized input. For a valid token it
    // is unreachable by result, because the longest id (256 bytes) encodes to far fewer bytes.
    if (token.size() > kCursorMaxBytes)
        return std::unexpected(CursorError::kMalformed);
    const auto parts = split_colon(token);
    if (parts.size() != 3 || parts[0] != kCursorPrefix || !is_lower_hex16(parts[1]))
        return std::unexpected(CursorError::kMalformed);
    const auto payload = keyset::b64url_decode(parts[2]);
    if (!payload)
        return std::unexpected(CursorError::kMalformed);
    // Exactly one field. A second field (the retired `skip` form) is a different position kind
    // this server no longer issues, so it is refused rather than ignored.
    const auto fields = read_length_prefixed(*payload, 1);
    if (!fields)
        return std::unexpected(CursorError::kMalformed);
    const std::string after((*fields)[0]);
    // A token is only ever minted after a served row, so `after` is never empty: an empty one
    // would be a second spelling of the first page. The decoded id reaches only the bound SQL
    // parameter of the keyset query, never a log, audit or response string, so it needs only what
    // a bound text parameter needs (strict UTF-8, no NUL) and the id length bound. It is
    // deliberately NOT held to the audit-trail floor (no byte below 0x20) that the `agent_id`
    // request filter meets: `encode_cursor` mints a token from any stored id, so a stored id with
    // a control byte at a page boundary must still decode, or the walk would wedge on a 400.
    if (after.empty() || after.size() > auth::kMaxAgentIdLength || !valid_text(after))
        return std::unexpected(CursorError::kMalformed);
    const Position pos{after};
    // One spelling per position: a token that does not re-encode to itself (non-canonical
    // base64url tail bits, a leading-zero length) is malformed.
    if (encode_cursor(pos, parts[1]) != token)
        return std::unexpected(CursorError::kMalformed);
    if (parts[1] != fp)
        return std::unexpected(CursorError::kFilterMismatch);
    return pos;
}

// ── One page ─────────────────────────────────────────────────────────────────

std::string_view read_error_message(ReadError e) {
    switch (e) {
    case ReadError::kDegraded:
        return "hardware CI records unavailable";
    case ReadError::kCursorMalformed:
        return cursor_error_message(CursorError::kMalformed);
    case ReadError::kCursorFilterMismatch:
        return cursor_error_message(CursorError::kFilterMismatch);
    case ReadError::kScopeTooWide:
        return "the caller's scope covers more than 10000 devices and no agent_id was given; a "
               "credential with global read has no such limit";
    case ReadError::kCount: // a sentinel, not an error: answered like an out-of-range value
        break;
    }
    return "invalid request";
}

ReadFailure describe_read_error(ReadError e, Surface surface) {
    const std::string_view name = surface == Surface::kRest ? "REST" : "MCP";
    ReadFailure f;
    f.message = read_error_message(e);
    switch (e) {
    case ReadError::kDegraded:
        // A failed store read is never an empty page (ADR-0016 section 7).
        f.unavailable = true;
        f.retry_after_ms = 5000;
        f.domain_audit_row = true;
        f.audit_outcome = "failure";
        f.audit_detail = std::format("hardware CI records ({}) state=store unreadable", name);
        return f;
    case ReadError::kCursorMalformed:
    case ReadError::kCursorFilterMismatch:
        // The same refusal as an over-long or non-text cursor (`kCursorRefusedAuditDetail`). Only
        // MCP audits it, as its generic row; REST writes no row and sends no hint.
        f.audit_outcome = "denied";
        if (surface == Surface::kMcp) {
            f.remediation = kCursorRefusedRemediation;
            f.audit_detail = std::string(kCursorRefusedAuditDetail);
        }
        return f;
    case ReadError::kScopeTooWide:
        // TERMINAL: the caller's own scope is the cause and no store read ran. No count anywhere.
        f.remediation = kScopeTooWideRemediation;
        f.domain_audit_row = true;
        f.audit_outcome = "denied";
        f.audit_detail = audit_detail_scope_too_wide(name);
        return f;
    case ReadError::kCount: // a sentinel, not an error: answered like an out-of-range value
        break;
    }
    // Unreachable for a named enumerator (the switch above has no default, so a new one is a
    // -Wswitch warning). An out-of-range value is answered as a refusal with no domain audit row
    // and an empty audit detail; the MCP handler still writes its generic `denied` row for it.
    f.audit_outcome = "denied";
    return f;
}

std::expected<Page, ReadError>
read_page(const Reader& read, const Request& rq, const authz::VisibleSet& scope) {
    const std::string fp = filter_fingerprint(rq);
    Position incoming; // the head: nothing served yet
    if (!rq.cursor.empty()) {
        auto cur = decode_cursor(rq.cursor, fp);
        if (!cur)
            return std::unexpected(cur.error() == CursorError::kMalformed
                                       ? ReadError::kCursorMalformed
                                       : ReadError::kCursorFilterMismatch);
        incoming = std::move(*cur);
    }
    Page out;
    // A named device outside the scope is answered without touching the store: nothing of it is
    // read, and the page is the same empty page a scoped caller gets for a device that has no row.
    if (!rq.agent_id.empty() && !authz::in_scope(scope, rq.agent_id)) {
        out.target_denied = true;
        return out;
    }
    // A scope above the push-down ceiling cannot be applied in SQL, and filtering its rows after
    // the read would let a short page or a skipping cursor count the hidden ones. Without an
    // `agent_id` it is refused before any read; with one the device is read by key and the
    // `in_scope` check above is the whole filter.
    const bool wide = scope && scope->size() > kMaxPushdownScopeIds;
    if (wide && rq.agent_id.empty())
        return std::unexpected(ReadError::kScopeTooWide);

    DeviceCiKeysetQuery q;
    q.after = incoming.after;
    if (!rq.agent_id.empty())
        q.agent_id = rq.agent_id;
    // TOP leaves the query alone; an engaged-empty scope is agent_ids = {} (the store answers
    // empty without SQL); a bounded set is pushed into SQL. A wide scope with an agent_id sends
    // no id array: the one device is the whole read.
    if (scope && !wide)
        q.agent_ids.emplace(scope->begin(), scope->end());

    // Every returned row is in scope. One extra row is read to know whether the page is the last,
    // so a final page carries no cursor.
    // `rq.limit` is clamped here so that a caller that built a Request by hand (the parsers never
    // produce one outside [1, kPageMax]) cannot reach `limit + 1` overflow or a zero/negative
    // store limit, which the store reads as its whole row ceiling.
    const int want = std::clamp(rq.limit, 1, static_cast<int>(kPageMax));
    q.limit = want + 1;
    auto rows = read(q);
    if (!rows)
        return std::unexpected(ReadError::kDegraded);
    const auto limit = static_cast<std::size_t>(want);
    if (rows->size() > limit) {
        rows->resize(limit);
        out.next_cursor = encode_cursor({rows->back().agent_id}, fp);
    }
    out.rows = std::move(*rows);
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
    // Element assignment, not an initializer list: a braced list copies every element, which for a
    // 1000-row page is a deep copy of the whole array.
    nlohmann::json out = nlohmann::json::object();
    out["devices"] = std::move(devices);
    out["next_cursor"] = page.next_cursor;
    return out;
}

void apply_scope_disclosure(nlohmann::json& body, bool confined) {
    if (confined)
        body["scope_basis"] = "authority_scoped";
}

// ── Audit text ───────────────────────────────────────────────────────────────

std::string audit_target_type(const Request& rq) {
    return rq.agent_id.empty() ? "Inventory" : "Agent";
}

std::string audit_target_id(const Request& rq) {
    return rq.agent_id.empty() ? "fleet" : rq.agent_id;
}

std::string audit_detail(const Page& page, const Request& rq, std::string_view surface,
                         bool confined) {
    std::string out = std::format("hardware CI records ({}): rows={}", surface, page.rows.size());
    if (!rq.cursor.empty())
        out += " page=continuation";
    out += confined ? " scope=authority_scoped" : " scope=fleet";
    return out;
}

std::string audit_detail_scope_too_wide(std::string_view surface) {
    return std::format("hardware CI records ({}) state=scope too wide", surface);
}

std::string audit_detail_target_denied(std::string_view surface) {
    return std::format("hardware CI records ({}) state=agent_id outside the caller's scope", surface);
}

} // namespace yuzu::server::hardware_ci_page
