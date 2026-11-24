#pragma once

/// @file approval_continuation.hpp
/// One approval for a whole multi-slice read. Pure: no store, no clock, no I/O, and no plugin name
/// (a row opts in through `CommandCapability::continuation_param`, never by name).
///
/// THE PROBLEM. A ticket is spent once, per exact dispatch (`dispatch_caller.hpp`). A read that
/// returns its answer in slices, each slice a dispatch carrying the agent's resume token, would
/// need one human approval per slice.
///
/// THE RULE. A row that declares a continuation parameter (and passes `covered_param`) binds its
/// ticket to the call WITHOUT that parameter (`ticket_subject`). The first use spends the ticket as
/// for any other call. A later call that carries a token (`carries_token`), from the same principal
/// with the same arguments, rides the already-spent ticket for `kCoverSeconds`, or until the
/// approval's 7-day lifetime ends, whichever comes first (`ApprovalManager::covers_continuation`).
/// A call without a token always needs an unspent ticket.
///
/// WHAT KEEPS IT SAFE. The server never reads the token: it only sees that a non-empty one is
/// present. The AGENT is what refuses a token it did not issue for these same arguments, before any
/// work, so a made-up token reads nothing. Different arguments (another root, pattern, action,
/// target set, or one device widened to the fleet) change the subject and so match no ticket.
/// Another principal, a mutating or `AlwaysApproval` row, and a bound (four-eyes) ticket are all
/// refused. The approval primitive itself (one-time consume, its schema) is untouched.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>

#include "command_capability.hpp"

namespace yuzu::server::approval_continuation {

/// How long after its FIRST use a ticket still covers continuation calls (database time, measured
/// from `consumed_at`), or until the approval's own 7-day lifetime ends, whichever comes first (the
/// lifetime is the ticket-liveness predicate, applied by `covers_continuation`; this constant only
/// sets the window from first use). Part of the ticket subject (`ticket_subject`), so a build that
/// changes it never lets a ticket minted under another window cover anything.
inline constexpr std::int64_t kCoverSeconds = 24 * 3600;

/// The continuation parameter this row declares AND may use, else empty. Honoured only for a
/// read (`ReadOnly`/`None`) gated `None` or `AdminOrApproval`: a mutating or `AlwaysApproval` row
/// never gets a cover, whatever it declares.
[[nodiscard]] inline std::string_view covered_param(const CommandCapability& cap) noexcept {
    if (cap.dispatch_class != DispatchClass::ReadOnly || cap.mutability != Mutability::None)
        return {};
    if (cap.execute_gate != ExecuteGate::None && cap.execute_gate != ExecuteGate::AdminOrApproval)
        return {};
    return cap.continuation_param;
}

/// True only when `args.params[param]` is a string, non-empty, with every byte in 0x21..0x7E.
/// The byte rule is load-bearing: the plugin ABI hands values over as C strings
/// (`sdk/include/yuzu/plugin.hpp`), so a value that starts with NUL reads as EMPTY on the agent
/// and would start a NEW search under the cover, and a space or control byte is never part of a
/// token an agent issues.
[[nodiscard]] inline bool carries_token(const nlohmann::json& args, std::string_view param) {
    if (param.empty() || !args.is_object())
        return false;
    const auto params = args.find("params");
    if (params == args.end() || !params->is_object())
        return false;
    const auto value = params->find(std::string(param));
    if (value == params->end() || !value->is_string())
        return false;
    const std::string& token = value->get_ref<const std::string&>();
    if (token.empty())
        return false;
    for (const char c : token) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x21 || byte > 0x7E)
            return false;
    }
    return true;
}

/// The ticket's bound subject for a covered row: one marker line, a newline, then the canonical
/// JSON of `args` with `approval_id` and `params[param]` erased WHATEVER the parameter's value is
/// (a token, an empty string, a number), so every slice of one search matches one ticket and the
/// token is never part of a stored copy. `nlohmann::json` is map-backed, so keys dump sorted and a
/// caller's key order does not matter. The marker names the parameter and the window, so a ticket
/// minted for a row that does not cover (no marker line) can never match one that does.
[[nodiscard]] inline std::string ticket_subject(nlohmann::json args, std::string_view param) {
    if (args.is_object()) {
        args.erase("approval_id");
        const auto params = args.find("params");
        if (params != args.end() && params->is_object())
            params->erase(std::string(param));
    }
    return "continuation=" + std::string(param) + " window_s=" + std::to_string(kCoverSeconds) +
           "\n" + args.dump();
}

} // namespace yuzu::server::approval_continuation
