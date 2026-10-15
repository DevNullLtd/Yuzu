#pragma once

/// @file software_sync_decision.hpp
/// Pure decision core for `POST /api/v1/hardware/sync` — the Software page's "Sync now"
/// fan-out (this device / a scope expression or management group / the whole fleet).
///
/// WHY A HEADER OF ITS OWN: the route is a one-click multi-device side effect, so every
/// rule that bounds it lives here, where a fixture vector can reach it without a process,
/// a clock, a registry or a store: how a request body selects its targets, who may name
/// the whole fleet, how a resolved candidate list partitions into reachable / offline /
/// too-old, the 500-target cap, the per-operator cooldown, the audit wording and the
/// response summary. `hardware_routes.cpp` only sequences them (auth, resolve, decide,
/// audit, dispatch) and maps each verdict to a status code.
///
/// The agent ignores `stagger_seconds` for `__sync__.now`, so the server is the only thing
/// standing between one click and a thundering herd — hence the hard cap, the cooldown and
/// the single in-flight run. ponytail: hard cap; ADR-3007 wants a paced, unbounded run,
/// tracked as a follow-up rather than built here.
///
/// Nothing here authorises anything. Execution:Execute is checked by the route; targets
/// arrive already intersected with the caller's Execution:Execute visible set by
/// `Resolved` (server.cpp), and `fleet_wide_denied` only decides who may NAME the fleet.

#include "dispatch_target_shape.hpp" // DispatchArm, classify_dispatch_arm, kBroadcastScope

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server::software_sync {

/// Hard ceiling on devices reached by one request (counted AFTER the offline/version
/// partition — the cap bounds what is dispatched, not what is merely named).
inline constexpr std::size_t kMaxTargets = 500;
/// Per-operator gap between two multi-device runs.
inline constexpr std::int64_t kCooldownSecs = 60;
/// Bound on the per-operator cooldown map (oldest stamp evicted past it).
inline constexpr std::size_t kCooldownStateCap = 1024;
/// Same ceiling as `auth::kMaxAgentIdLength` (hardware_routes.cpp static_asserts the match).
inline constexpr std::size_t kMaxIdLen = 256;
/// A scope DSL expression is a few atoms; the 4 KiB body cap is the outer bound.
inline constexpr std::size_t kMaxExpressionLen = 1024;
/// The one source a fan-out may request (the per-device route accepts more; a herd of
/// `all` is not what the Software page asks for).
inline constexpr std::string_view kSource = "installed_software";
/// Audit wording for a caller-supplied expression: bounded, control bytes defanged.
inline constexpr std::size_t kAuditTokenMax = 128;

// ── request ───────────────────────────────────────────────────────────────────────

/// What the body selected. `expr` is the string the resolver acts on: `__all__`,
/// `group:<id>`, the DSL expression, or (Ids arm) the one agent id.
struct Selector {
    DispatchArm arm{DispatchArm::None};
    std::string expr;
};

struct Request {
    Selector sel;
    std::string source{kSource};
};

[[nodiscard]] inline bool token_ok(std::string_view s, std::size_t max_len) {
    if (s.empty() || s.size() > max_len)
        return false;
    for (const unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}

/// Parse a request body into a selector + source, or the caller-facing 400 message.
///
/// `scope` is `__all__`, `group:<id>` or an agent id; `scope_expression` is a scope DSL
/// expression. They are ALTERNATIVES (supplying both is refused, mirroring
/// `check_targeting_shape`: the executed set must be the requested set, never a
/// precedence outcome), and naming neither is refused rather than read as "everyone".
/// A present-but-non-string field is a 400, never a throw out of the JSON library.
[[nodiscard]] inline std::expected<Request, std::string> parse_request(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected("body must be a JSON object");

    Request out;
    if (const auto it = body.find("source"); it != body.end()) {
        if (!it->is_string())
            return std::unexpected("source must be a string");
        if (it->get_ref<const std::string&>() != kSource)
            return std::unexpected("source must be installed_software");
    }

    const auto field = [&](const char* key) -> std::expected<std::optional<std::string>, std::string> {
        const auto it = body.find(key);
        if (it == body.end())
            return std::optional<std::string>{};
        if (!it->is_string())
            return std::unexpected(std::string(key) + " must be a string");
        return std::optional<std::string>{it->get<std::string>()};
    };
    const auto scope = field("scope");
    if (!scope)
        return std::unexpected(scope.error());
    const auto expression = field("scope_expression");
    if (!expression)
        return std::unexpected(expression.error());

    if (scope->has_value() && expression->has_value())
        return std::unexpected("scope and scope_expression are alternatives; supply exactly one");
    if (!scope->has_value() && !expression->has_value())
        return std::unexpected("scope is required: __all__, group:<id>, an agent id, or a "
                               "scope_expression");

    if (expression->has_value()) {
        const std::string& e = **expression;
        if (!token_ok(e, kMaxExpressionLen))
            return std::unexpected("scope_expression must be 1-1024 characters with no control "
                                   "characters");
        // classify_dispatch_arm is the one place the arm vocabulary is decided; an
        // expression of `__all__` or `group:<id>` lands on the same arm as via `scope`.
        out.sel = {classify_dispatch_arm(false, e), e};
    } else {
        const std::string& s = **scope;
        if (!token_ok(s, kMaxIdLen))
            return std::unexpected("scope must be 1-256 characters with no control characters");
        if (s == kBroadcastScope) {
            out.sel = {DispatchArm::Broadcast, s};
        } else if (s.starts_with("group:")) {
            if (s.size() == 6)
                return std::unexpected("group scope needs an id: group:<id>");
            out.sel = {DispatchArm::Group, s};
        } else {
            out.sel = {DispatchArm::Ids, s}; // a bare agent id
        }
    }
    return out;
}

/// Short, bounded, control-free rendering of caller text for an audit row.
[[nodiscard]] inline std::string audit_token(std::string_view s, std::size_t max_len = kAuditTokenMax) {
    std::string out;
    out.reserve(std::min(s.size(), max_len));
    for (const unsigned char c : s.substr(0, max_len))
        out.push_back((c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c));
    if (s.size() > max_len)
        out += "...";
    return out;
}

/// The audit `target_id`: the agent id or group id when that is the whole selector, a
/// fixed word otherwise (an expression never becomes an identifier).
[[nodiscard]] inline std::string target_label(const Selector& sel) {
    switch (sel.arm) {
    case DispatchArm::Broadcast: return std::string(kBroadcastScope);
    case DispatchArm::Scope: return "expression";
    case DispatchArm::Group:
    case DispatchArm::Ids: return audit_token(sel.expr, kMaxIdLen);
    case DispatchArm::None: break;
    }
    return "none";
}

/// A single named device needs neither the cooldown nor the in-flight guard — there is no
/// herd. Group, scope and fleet runs take both.
[[nodiscard]] inline bool needs_run_guard(DispatchArm arm) { return arm != DispatchArm::Ids; }

// ── resolution (the shapes server.cpp's resolver and dispatcher return) ───────────

/// What the resolver reports. `ids` are ALREADY intersected with the caller's
/// Execution:Execute visible set (a hidden id is dropped, never reported).
/// `caller_unfiltered` == that visible set is unfiltered, i.e. the caller holds a
/// fleet-wide Execution:Execute (or RBAC is off). `Aborted` is a degraded store or a
/// failed scope owner check: never "no matches".
struct Resolved {
    enum class Status { Ok, InvalidScope, Aborted } status{Status::Aborted};
    std::string detail; // InvalidScope: the parse error; Aborted: the abort reason
    bool caller_unfiltered{false};
    std::vector<std::string> ids;
};

struct DispatchResult {
    std::size_t sent{0};
    std::string command_id;
};

// ── partition ─────────────────────────────────────────────────────────────────────

struct Candidate {
    std::string id;
    std::optional<std::string> version; // nullopt == no live session (offline)
};

struct Counts {
    std::size_t requested{0};
    std::size_t reached{0};
    std::size_t skipped_offline{0};
    std::size_t skipped_version{0};
};

struct Plan {
    std::vector<std::string> targets; // the live, new-enough subset, in input order
    Counts counts;
};

/// Split candidates into targets / offline / too-old. `supports(version)` is the
/// sync-now version floor (`agent_supports_sync_now`: 0.13.1+); an unparseable version
/// fails it, so it counts as too old, never as reachable.
template <class SupportsFn>
[[nodiscard]] Plan partition(const std::vector<Candidate>& candidates, SupportsFn&& supports) {
    Plan p;
    p.counts.requested = candidates.size();
    for (const auto& c : candidates) {
        if (!c.version) {
            ++p.counts.skipped_offline;
        } else if (!supports(std::string_view(*c.version))) {
            ++p.counts.skipped_version;
        } else {
            p.targets.push_back(c.id);
        }
    }
    p.counts.reached = p.targets.size();
    return p;
}

/// Counts after dispatch: `reached` is what the registry accepted; a target that was live
/// at partition time but refused the send is reported with the offline ones.
[[nodiscard]] inline Counts finalize(Counts planned, std::size_t sent) {
    if (sent > planned.reached)
        sent = planned.reached; // a dispatcher cannot have reached more than it was given
    planned.skipped_offline += planned.reached - sent;
    planned.reached = sent;
    return planned;
}

// ── verdicts ──────────────────────────────────────────────────────────────────────

enum class Verdict { Proceed, FleetWideRequired, TooMany };

/// Only a caller whose Execution:Execute is unfiltered may name the whole fleet. A
/// confined caller asking for `__all__` is refused outright rather than silently narrowed
/// to their own devices: the request they made is not the request that would run.
[[nodiscard]] inline bool fleet_wide_denied(DispatchArm arm, bool caller_unfiltered) {
    return arm == DispatchArm::Broadcast && !caller_unfiltered;
}

[[nodiscard]] inline Verdict decide(DispatchArm arm, bool caller_unfiltered, const Counts& planned) {
    if (fleet_wide_denied(arm, caller_unfiltered))
        return Verdict::FleetWideRequired;
    if (planned.reached > kMaxTargets)
        return Verdict::TooMany;
    return Verdict::Proceed;
}

// ── cooldown ──────────────────────────────────────────────────────────────────────

/// Seconds the operator still has to wait (0 = clear). A clock that stepped backwards
/// reads as a full wait, never as a negative one.
[[nodiscard]] inline std::int64_t cooldown_remaining(std::optional<std::int64_t> last_run, std::int64_t now) {
    if (!last_run)
        return 0;
    const std::int64_t elapsed = now - *last_run;
    if (elapsed < 0)
        return kCooldownSecs;
    return elapsed >= kCooldownSecs ? 0 : kCooldownSecs - elapsed;
}

[[nodiscard]] inline std::optional<std::int64_t>
last_run_of(const std::unordered_map<std::string, std::int64_t>& state, const std::string& user) {
    const auto it = state.find(user);
    return it == state.end() ? std::nullopt : std::optional<std::int64_t>(it->second);
}

/// Record a run, keeping the map bounded: past the cap the oldest stamp is dropped (an
/// operator who falls off simply regains an early run — the in-flight guard and the 500
/// cap still hold).
inline void stamp(std::unordered_map<std::string, std::int64_t>& state, const std::string& user,
                  std::int64_t now) {
    if (state.size() >= kCooldownStateCap && !state.contains(user)) {
        auto oldest = state.begin();
        for (auto it = state.begin(); it != state.end(); ++it)
            if (it->second < oldest->second)
                oldest = it;
        state.erase(oldest);
    }
    state[user] = now;
}

// ── wording ───────────────────────────────────────────────────────────────────────

/// The pre-dispatch audit `detail`: scope, arm, source and the four counts.
[[nodiscard]] inline std::string audit_detail(const Request& rq, const Counts& c) {
    return "scope=" + audit_token(rq.sel.expr) + " arm=" + std::string(dispatch_arm_label(rq.sel.arm)) +
           " source=" + rq.source + " requested=" + std::to_string(c.requested) +
           " reached=" + std::to_string(c.reached) +
           " skipped_offline=" + std::to_string(c.skipped_offline) +
           " skipped_version=" + std::to_string(c.skipped_version);
}

/// "requested" when something will be sent, "no_agents" when nothing can be (the same two
/// result words the per-device route uses).
[[nodiscard]] inline const char* audit_result(const Counts& planned) {
    return planned.reached > 0 ? "requested" : "no_agents";
}

/// The 202 `data` object. Counts only — never a per-device list — so the body cannot
/// disclose which devices were matched, skipped or hidden.
[[nodiscard]] inline nlohmann::json summary_json(const Counts& c, const std::string& command_id,
                                                 std::int64_t requested_at) {
    return {{"requested", c.requested},
            {"reached", c.reached},
            {"skipped_offline", c.skipped_offline},
            {"skipped_version", c.skipped_version},
            {"command_id", command_id},
            {"source", std::string(kSource)},
            {"requested_at", requested_at}};
}

} // namespace yuzu::server::software_sync
