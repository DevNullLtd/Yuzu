#include "quarantine_reapply.hpp"

#include "cidr_match.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <exception>
#include <tuple>

namespace yuzu::server {

namespace {

constexpr std::size_t kMaxTokenLen = 45;

/// The agent's `is_safe_ip` charset (`[0-9a-fA-F.:]`, <=45 chars): the first line of defence before
/// the literal reaches the mapper's real check.
bool safe_token_charset(std::string_view tok) {
    if (tok.empty() || tok.size() > kMaxTokenLen)
        return false;
    for (char c : tok)
        if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == '.' || c == ':'))
            return false;
    return true;
}

/// The agent refuses an IPv4 octet with a leading zero (firewall_quarantine_parsers.hpp), so the
/// server must not emit one: inet_pton accepts them on some platforms.
bool ipv4_has_leading_zero_octet(std::string_view tok) {
    std::size_t start = 0;
    while (start <= tok.size()) {
        const auto dot = tok.find('.', start);
        const auto octet =
            tok.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start);
        if (octet.size() > 1 && octet.front() == '0')
            return true;
        if (dot == std::string_view::npos)
            break;
        start = dot + 1;
    }
    return false;
}

/// One token is a bare IPv4 or IPv6 literal the agent's exception grammar can express.
bool expressible_address(std::string_view tok) {
    if (!safe_token_charset(tok))
        return false;
    // The charset has no '/', so is_valid_cidr sees a bare literal (it also accepts a prefix).
    if (!detail::is_valid_cidr(tok))
        return false;
    if (tok.find(':') == std::string_view::npos)
        return !ipv4_has_leading_zero_octet(tok);
    // IPv6: an embedded dotted quad (IPv4-mapped forms) is not in the agent's grammar.
    return tok.find('.') == std::string_view::npos;
}

} // namespace

std::optional<std::string> map_whitelist_to_exceptions(std::string_view whitelist) {
    if (whitelist.size() > kQuarantineWhitelistMaxLen)
        return std::nullopt;
    std::string out;
    std::size_t addresses = 0;
    std::size_t start = 0;
    while (start <= whitelist.size()) {
        const auto comma = whitelist.find(',', start);
        auto tok = whitelist.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        const auto b = tok.find_first_not_of(' ');
        const auto e = tok.find_last_not_of(' ');
        tok = (b != std::string_view::npos) ? tok.substr(b, e - b + 1) : std::string_view{};
        if (!tok.empty()) {
            if (!expressible_address(tok) || ++addresses > kContainmentMaxAddresses)
                return std::nullopt;
            if (!out.empty())
                out += ',';
            out += tok;
            out += "/out,";
            out += tok;
            out += "/in";
        }
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

std::optional<std::unordered_map<std::string, std::string>>
build_quarantine_reapply_params(std::string_view stored_whitelist) {
    auto mapped = map_whitelist_to_exceptions(stored_whitelist);
    if (!mapped)
        return std::nullopt;
    std::unordered_map<std::string, std::string> params;
    if (!mapped->empty())
        params[std::string(kContainmentExceptionsParam)] = std::move(*mapped);
    return params;
}

ContainmentReply parse_containment_reply(std::string_view payload) {
    ContainmentReply reply;
    bool ttl_seen = false;
    std::size_t line_start = 0;
    while (line_start <= payload.size()) {
        const auto nl = payload.find('\n', line_start);
        auto line = payload.substr(
            line_start, nl == std::string_view::npos ? std::string_view::npos : nl - line_start);
        // #3425 adversarial review K3: strip a trailing CR so a CRLF-terminated line (a Windows
        // agent, or a wrapped tool's output) still matches; a bare `\n` split alone would leave a
        // token that never equals "active" and silently stall confirmation on that platform.
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (!reply.status_seen && line.starts_with("status|")) {
            reply.status_seen = true; // the FIRST status line decides; the plugin renders it first
            const auto rest = line.substr(7);
            const auto pipe = rest.find('|');
            const auto token = pipe == std::string_view::npos ? rest : rest.substr(0, pipe);
            if (token == "active")
                reply.state = QuarantineEndpointState::active;
            else if (token == "active_unproven")
                reply.state = QuarantineEndpointState::active_unproven;
            else if (token == "inactive")
                reply.state = QuarantineEndpointState::inactive;
            else if (token == "busy")
                reply.state = QuarantineEndpointState::busy;
            // any other token (refused, partial, degraded, ...) stays `unconfirmed`
        } else if (line.starts_with("note|ttl_expires=") && !ttl_seen) {
            ttl_seen = true;
            const auto digits = line.substr(17);
            std::int64_t v = 0;
            const auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), v);
            // anything but a clean, non-negative integer reads as "no limit"
            if (ec == std::errc{} && ptr == digits.data() + digits.size() && v > 0)
                reply.ttl_expires = v;
        } else if (line.starts_with("note|probe_target=")) {
            reply.probe_configured = true;
        }

        if (nl == std::string_view::npos)
            break;
        line_start = nl + 1;
    }
    return reply;
}

std::string combined_output(const std::vector<StoredResponse>& rows) {
    std::string out;
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
        if (!out.empty())
            out += '\n';
        out += it->output;
    }
    return out;
}

std::expected<ContainmentReapplyResult, ContainmentReapplyError>
redispatch_stored_containment(QuarantineStore& store, const std::string& agent_id,
                              const ReapplyDispatchFn& dispatch_fn, QuarantineRecord& out_record) {
    auto status_res = store.get_status(agent_id);
    if (!status_res)
        return std::unexpected(
            ContainmentReapplyError{ContainmentReapplyErrorKind::store_error, status_res.error()});
    if (!status_res->has_value())
        return std::unexpected(ContainmentReapplyError{
            ContainmentReapplyErrorKind::no_active_record, "quarantine record not found on retry read"});

    out_record = **status_res;

    // A release is in flight for this row: containment is not put back under it.
    if (out_record.release_requested_at != 0)
        return std::unexpected(
            ContainmentReapplyError{ContainmentReapplyErrorKind::release_pending, ""});

    auto params = build_quarantine_reapply_params(out_record.whitelist);
    if (!params)
        return std::unexpected(
            ContainmentReapplyError{ContainmentReapplyErrorKind::whitelist_invalid, ""});

    ContainmentReapplyResult result;
    try {
        std::tie(result.command_id, result.agents_reached) = dispatch_fn(*params);
    } catch (const std::exception&) {
        result.dispatch_threw = true;
    }
    return result;
}

} // namespace yuzu::server
