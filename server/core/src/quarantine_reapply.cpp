#include "quarantine_reapply.hpp"

#include "quarantine_store.hpp"

#include <cctype>

namespace yuzu::server {

namespace {

bool safe_ip_token(std::string_view tok) {
    if (tok.empty() || tok.size() > 45)
        return false;
    for (char c : tok)
        if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == '.' || c == ':'))
            return false;
    return true;
}

} // namespace

bool quarantine_whitelist_tokens_safe(std::string_view whitelist) {
    std::size_t start = 0;
    while (start <= whitelist.size()) {
        std::size_t comma = whitelist.find(',', start);
        auto tok = whitelist.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        // trim surrounding spaces
        auto b = tok.find_first_not_of(' ');
        auto e = tok.find_last_not_of(' ');
        tok = (b != std::string_view::npos) ? tok.substr(b, e - b + 1) : std::string_view{};
        if (!tok.empty() && !safe_ip_token(tok))
            return false;
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return true;
}

std::optional<std::unordered_map<std::string, std::string>>
build_quarantine_reapply_params(std::string_view stored_whitelist) {
    if (stored_whitelist.size() > kQuarantineWhitelistMaxLen ||
        !quarantine_whitelist_tokens_safe(stored_whitelist))
        return std::nullopt;
    std::unordered_map<std::string, std::string> params;
    if (!stored_whitelist.empty())
        params[std::string(kQuarantineWhitelistParam)] = std::string(stored_whitelist);
    return params;
}

QuarantineEndpointState parse_quarantine_endpoint_state(std::string_view payload) {
    std::size_t line_start = 0;
    while (line_start <= payload.size()) {
        std::size_t nl = payload.find('\n', line_start);
        auto line = payload.substr(
            line_start, nl == std::string_view::npos ? std::string_view::npos : nl - line_start);
        // #3425 adversarial review K3: strip a trailing CR so a CRLF-
        // terminated line (a Windows agent, or a wrapped tool's output)
        // still matches — a bare `\n` split alone would otherwise leave a
        // `state|active\r` token that never equals "active" and silently
        // stalls confirmation forever on that platform.
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (line.starts_with("state|")) {
            auto rest = line.substr(6);
            auto pipe = rest.find('|');
            auto token = pipe == std::string_view::npos ? rest : rest.substr(0, pipe);
            if (token == "active")
                return QuarantineEndpointState::active;
            if (token == "partial")
                return QuarantineEndpointState::partial;
            if (token == "inactive")
                return QuarantineEndpointState::inactive;
            if (token == "uncertain")
                return QuarantineEndpointState::uncertain;
            if (token == "degraded")
                return QuarantineEndpointState::degraded;
            return QuarantineEndpointState::unknown;
        }
        if (line == "status|busy")
            return QuarantineEndpointState::busy;

        if (nl == std::string_view::npos)
            break;
        line_start = nl + 1;
    }
    return QuarantineEndpointState::unknown;
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
