#pragma once

/// @file software_sync_decision.hpp
/// Pure decision core for `POST /api/v1/hardware/sync` — the Software page's "Sync now"
/// fan-out (this device / a scope expression or management group / the whole fleet).
///
/// WHY A HEADER OF ITS OWN: the route is a one-click multi-device side effect, so every
/// rule that bounds it lives here, where a fixture vector can reach it without a process,
/// a clock, a registry or a store: how a request body selects its targets, who may name
/// the whole fleet and what a group or fleet run must confirm, how a resolved candidate list
/// partitions into reachable / offline / too-old / recently-synced, the run key that decides
/// which requests share one run, the cooldown rule, the audit wording and the response summary.
/// `Runner` sequences them (resolve, filter, partition, admit, audit, dispatch) and the surfaces
/// (`hardware_routes.cpp`, the MCP tool) map each outcome to a status or error code.
///
/// There is no ceiling on the number of devices a run may name. What bounds the herd is the
/// pacing rule (software_sync_pacing.hpp: the run asks the fleet to report inside a spread
/// window, under one per-process budget), the confirmation a whole group or the whole fleet must
/// carry, the fleet-administrator gate on the whole fleet, and one run per key at a time.
///
/// The cooldown stamps and the live runs live in `software_sync::Runner` (software_sync_runner.hpp),
/// so they are per server PROCESS, not cluster-wide: under active-active each replica paces and
/// de-duplicates on its own, and a restart forgets them (agents keep the delays they already armed).
///
/// Nothing here authorises anything. Execution:Execute is checked by the route; targets
/// arrive already intersected with the caller's Execution:Execute visible set by
/// `resolve_targets` (server.cpp only supplies the store reads it calls), and
/// `fleet_wide_denied` only decides who may NAME the fleet.

#include "authz_model.hpp"           // authz::VisibleSet, authz::filter_to_scope (std-only header)
#include "dispatch_target_shape.hpp" // DispatchArm, classify_dispatch_arm, kBroadcastScope

#include <yuzu/log_token.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server::software_sync {

/// Default gap between two runs of one run key (`--inventory-sync-cooldown`, in seconds), and the
/// largest value that flag accepts (0 turns the gap off).
inline constexpr std::int64_t kDefaultCooldownSecs = 600;
inline constexpr std::int64_t kMaxCooldownSecs = 86'400;
/// Bound on the per-key run-state map (expired entries are evicted first).
inline constexpr std::size_t kCooldownStateCap = 1024;
/// The execution definition the tracker rows of a sync run carry; the status route serves only
/// rows with this value.
inline constexpr std::string_view kSyncDefinitionId = "__sync__.now";
/// Same ceiling as `auth::kMaxAgentIdLength` (hardware_routes.cpp static_asserts the match).
inline constexpr std::size_t kMaxIdLen = 256;
/// A scope DSL expression is a few atoms; the 4 KiB body cap is the outer bound.
inline constexpr std::size_t kMaxExpressionLen = 1024;
/// The one source a fan-out may request (the per-device route accepts more; a herd of
/// `all` is not what the Software page asks for).
inline constexpr std::string_view kSource = "installed_software";
/// Audit wording for a caller-supplied expression: bounded, field delimiters defanged.
inline constexpr std::size_t kAuditTokenMax = 128;

// ── request ───────────────────────────────────────────────────────────────────────

/// What the body selected. `expr` is the string the resolver acts on: `__all__`,
/// `group:<id>`, the DSL expression, or (Ids arm) the one agent id.
struct Selector {
    DispatchArm arm{DispatchArm::None};
    std::string expr;
    /// `"confirm": true` in the body. A whole group or the whole fleet is refused without it.
    bool confirm{false};
    /// `"last_synced_before"`: epoch seconds. Only devices whose last accepted installed-software
    /// report is OLDER than this are asked (a device that never reported counts as older).
    std::optional<std::int64_t> last_synced_before{};
};

[[nodiscard]] inline bool token_ok(std::string_view s, std::size_t max_len) {
    if (s.empty() || s.size() > max_len)
        return false;
    for (const unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}

/// Parse a request body into the selector it names, or the caller-facing 400 message. `source`
/// is optional and may only be `installed_software` (anything else is refused); it selects
/// nothing, so it is checked here and not carried.
///
/// `scope` is `__all__`, `group:<id>` or an agent id; `scope_expression` is a scope DSL
/// expression. They are ALTERNATIVES (supplying both is refused, mirroring
/// `check_targeting_shape`: the executed set must be the requested set, never a
/// precedence outcome), and naming neither is refused rather than read as "everyone".
/// A present-but-non-string field is a 400, never a throw out of the JSON library.
///
/// `confirm` is a JSON boolean (anything else is a 400, never coerced: `"true"` and `1` do not
/// confirm) and `last_synced_before` a non-negative integer of epoch seconds (a float, a string,
/// a negative number or a value past int64 is a 400). Neither selects anything; whether `confirm`
/// is needed is `confirmation_required`'s rule, applied by the Runner.
[[nodiscard]] inline std::expected<Selector, std::string> parse_request(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected("body must be a JSON object");

    if (const auto it = body.find("source"); it != body.end()) {
        if (!it->is_string())
            return std::unexpected("source must be a string");
        if (it->get_ref<const std::string&>() != kSource)
            return std::unexpected("source must be installed_software");
    }

    bool confirm = false;
    if (const auto it = body.find("confirm"); it != body.end()) {
        if (!it->is_boolean())
            return std::unexpected("confirm must be a JSON boolean");
        confirm = it->get<bool>();
    }
    std::optional<std::int64_t> synced_before;
    if (const auto it = body.find("last_synced_before"); it != body.end()) {
        constexpr const char* kBadBefore =
            "last_synced_before must be a non-negative integer (epoch seconds)";
        if (!it->is_number_integer())
            return std::unexpected(kBadBefore);
        if (it->is_number_unsigned()) {
            const auto v = it->get<std::uint64_t>();
            if (v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                return std::unexpected(kBadBefore);
            synced_before = static_cast<std::int64_t>(v);
        } else {
            const auto v = it->get<std::int64_t>();
            if (v < 0)
                return std::unexpected(kBadBefore);
            synced_before = v;
        }
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

    Selector sel;
    if (expression->has_value()) {
        const std::string& e = **expression;
        if (!token_ok(e, kMaxExpressionLen))
            return std::unexpected("scope_expression must be 1-1024 bytes with no control "
                                   "characters");
        // classify_dispatch_arm is the one place the arm vocabulary is decided; an
        // expression of `__all__` or `group:<id>` lands on the same arm as via `scope`.
        sel.arm = classify_dispatch_arm(false, e);
        sel.expr = e;
    } else {
        const std::string& s = **scope;
        if (!token_ok(s, kMaxIdLen))
            return std::unexpected("scope must be 1-256 bytes with no control characters");
        const DispatchArm arm = s == kBroadcastScope               ? DispatchArm::Broadcast
                                : s.starts_with(kGroupScopePrefix) ? DispatchArm::Group
                                                                   : DispatchArm::Ids; // a bare agent id
        sel.arm = arm;
        sel.expr = s;
    }
    // Either spelling of a group must name one: `group:` alone would reach the store with an
    // empty id.
    if (sel.arm == DispatchArm::Group && sel.expr.size() == kGroupScopePrefix.size())
        return std::unexpected("group scope needs an id: group:<id>");
    sel.confirm = confirm;
    sel.last_synced_before = synced_before;
    return sel;
}

/// Bounded rendering of caller text for an audit row. `log_token` neutralises control bytes,
/// DEL, space, '=' and ',' (CWE-117), so a hostile expression cannot start a new line or forge
/// a neighbouring `key=value` field such as `reached=0` in `audit_detail`, and folds the Unicode
/// line separators and maps bytes that are not well-formed UTF-8 to '_' (log_token.hpp).
/// The cut is on a CODE POINT boundary: when `max_len` falls inside a multi-byte character the
/// whole character is dropped (the result is up to 3 bytes shorter than `max_len`), never half
/// of it kept.
[[nodiscard]] inline std::string audit_token(std::string_view s, std::size_t max_len = kAuditTokenMax) {
    std::size_t cut = std::min(s.size(), max_len);
    // s[cut] is the first byte EXCLUDED from the head. A continuation byte there means the head
    // ends mid-sequence: step back (at most 3 bytes, the longest sequence minus its lead) onto
    // the lead byte, which is then excluded too. Stray continuation bytes in garbage input just
    // stop the walk after 3 steps; log_token maps whatever invalid bytes remain to '_'.
    for (int back = 0; back < 3 && cut > 0 && cut < s.size() &&
                       (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80;
         ++back)
        --cut;
    std::string out = ::yuzu::log_token(s.substr(0, cut));
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

/// A single named device needs no run key, cooldown, pacing or live-send count — there is no
/// herd. Group, scope and fleet runs take all of them.
[[nodiscard]] inline bool needs_run_guard(DispatchArm arm) { return arm != DispatchArm::Ids; }

/// Only a fleet administrator may name the whole fleet: a caller whose Execution:Execute is
/// unfiltered AND who holds the global ManagementGroup:Write grant (the same people who may
/// change collection settings for the whole fleet). Anyone else asking for `__all__` is refused
/// outright rather than silently narrowed to their own devices: the request they made is not the
/// request that would run. `fleet_admin` is the Runner's answer for the session (an answer that
/// could not be determined is `false`).
[[nodiscard]] inline bool fleet_wide_denied(DispatchArm arm, bool caller_unfiltered, bool fleet_admin) {
    return arm == DispatchArm::Broadcast && !(caller_unfiltered && fleet_admin);
}

/// A whole group or the whole fleet is one click for a very large number of devices, so it must
/// say so: the body carries `"confirm": true`. A single device and a scope expression never need
/// it. Evaluated after `fleet_wide_denied`, so a caller who may not name the fleet at all is told
/// 403, not asked to confirm.
[[nodiscard]] inline bool confirmation_required(DispatchArm arm, bool confirm) {
    return (arm == DispatchArm::Group || arm == DispatchArm::Broadcast) && !confirm;
}

/// Which requests share one run. A request that finds a run of its key still spreading JOINS it
/// (the same answer, nothing sent), so the key must separate every pair of callers who could be
/// handed a different device set or have a different right to its counts:
///   - `fleet` — only an administrator names the fleet, and every administrator sees the same one;
///   - `group:<id>` — for a caller whose Execution:Execute is unfiltered (they all see the whole
///     group). A confined caller's resolved set is only the group's members they may see, so
///     their key adds the username (`group:<id>` + 0x1f + username): they never join another
///     caller's run and never receive its counts, only their own earlier request's;
///   - `scope:<username>` + 0x1f + the full expression — an expression resolves per caller (a
///     result-set reference is owner-scoped), so it is keyed by requester and by the exact text,
///     never hashed, so two different expressions can never share a run.
/// (Both usernames and expressions are bounded, so a key is a few KiB at most.) A single device has
/// no run; its key is only a label.
[[nodiscard]] inline std::string run_key(const Selector& sel, std::string_view username,
                                         bool caller_unfiltered) {
    constexpr char kSep = '\x1f';
    switch (sel.arm) {
    case DispatchArm::Broadcast: return "fleet";
    case DispatchArm::Group:
        return caller_unfiltered ? sel.expr : sel.expr + kSep + std::string(username);
    case DispatchArm::Scope: return "scope:" + std::string(username) + kSep + sel.expr;
    case DispatchArm::Ids: return "device:" + sel.expr;
    case DispatchArm::None: break;
    }
    return "none";
}

/// Does a run already spreading cover a new request? `running_before` is the running run's
/// `last_synced_before` and `requested_before` the new request's (nullopt = no filter, i.e. every
/// device). A run with no filter covered every device; one with a filter covered the devices
/// older than it, which includes everything a request with the same or an older filter wants.
/// A wider request (a later or no filter) over a filtered run is NOT covered.
[[nodiscard]] inline bool join_covers(std::optional<std::int64_t> running_before,
                                      std::optional<std::int64_t> requested_before) {
    if (!running_before)
        return true;
    return requested_before && *requested_before <= *running_before;
}

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

/// What a scope-expression expansion reported: exactly the outcomes the ADR-0036 ladder has.
/// `matched` is nullopt for both an invalid expression (`parse_error` set) and an abort
/// (`abort_detail` names why) - a caller must never read either as "matched nothing".
struct ScopeExpansion {
    std::optional<std::vector<std::string>> matched;
    std::optional<std::string> parse_error;
    std::string abort_detail;
};

/// The store reads `resolve_targets` needs, injected so the confinement rules around them are
/// testable with fakes. An EMPTY callable is a missing dependency and resolves to Aborted
/// (fail closed), never to an empty target list.
struct Expansion {
    std::function<std::vector<std::string>()> all_ids;
    /// nullopt == the group store is absent or degraded (distinct from a group with no members).
    std::function<std::optional<std::vector<std::string>>(const std::string& group_id)> group_members;
    std::function<ScopeExpansion(const std::string& expression)> scope_matches;
};

/// Expand a selector to the devices it names and confine them to `visible` (the caller's own
/// Execution:Execute set; nullopt == unfiltered, present-but-empty == deny-all). Only `Ok`
/// carries ids, and an `Ok` result is already confined: a device the caller cannot see is
/// dropped here and never reported. Anything the expansion could not answer (an unwired or
/// degraded store, an aborted scope, no target at all) is `Aborted`, never an empty `Ok`;
/// an invalid expression is `InvalidScope`. `caller_unfiltered` is set from `visible` on every
/// path so the route can apply the fleet-wide rule.
[[nodiscard]] inline Resolved resolve_targets(const Selector& sel, const authz::VisibleSet& visible,
                                              const Expansion& ex) {
    Resolved out; // status defaults to Aborted: each early return below refuses to guess
    out.caller_unfiltered = !visible.has_value();
    std::vector<std::string> ids;
    switch (sel.arm) {
    case DispatchArm::Ids:
        ids.push_back(sel.expr);
        break;
    case DispatchArm::Broadcast:
        if (!ex.all_ids) {
            out.detail = "unwired";
            return out;
        }
        // Only an unfiltered caller may name the fleet (the Runner has already refused every
        // non-administrator before any read), so a confined caller's answer is empty and the
        // fleet is not read at all. The administrator half is the Runner's; it is not known here.
        if (fleet_wide_denied(sel.arm, out.caller_unfiltered, /*fleet_admin=*/true)) {
            out.status = Resolved::Status::Ok;
            return out;
        }
        ids = ex.all_ids();
        break;
    case DispatchArm::Group: {
        if (!ex.group_members) {
            out.detail = "unwired";
            return out;
        }
        // parse_request guarantees both; a selector built any other way never reaches the store
        // with an empty or unprefixed id.
        if (!sel.expr.starts_with(kGroupScopePrefix) || sel.expr.size() == kGroupScopePrefix.size()) {
            out.detail = "bad_selector";
            return out;
        }
        auto members = ex.group_members(sel.expr.substr(kGroupScopePrefix.size()));
        if (!members) {
            out.detail = "db_degraded";
            return out;
        }
        ids = std::move(*members);
        break;
    }
    case DispatchArm::Scope: {
        if (!ex.scope_matches) {
            out.detail = "unwired";
            return out;
        }
        auto r = ex.scope_matches(sel.expr);
        if (r.parse_error) {
            out.status = Resolved::Status::InvalidScope;
            out.detail = std::move(*r.parse_error);
            return out;
        }
        if (!r.matched) {
            out.detail = r.abort_detail.empty() ? std::string("unknown") : std::move(r.abort_detail);
            return out;
        }
        ids = std::move(*r.matched);
        break;
    }
    case DispatchArm::None:
        out.detail = "no_target";
        return out;
    }
    out.ids = authz::filter_to_scope(ids, visible);
    out.status = Resolved::Status::Ok;
    return out;
}

// ── fan-out ───────────────────────────────────────────────────────────────────────

/// Send one prepared command to each id under ONE command id. The three steps are injected so
/// the sequencing is testable without a registry:
///   `mint_id()`          -> the command id (called once, and only when there is something to send);
///   `prepare(command_id)`-> the command, or an empty/false result when it cannot be built
///                           (an `optional` or `expected`; nothing is sent and no id is reported);
///   `send_one(id, cmd)`  -> true when the registry accepted the frame for that id.
/// `sent` counts accepted frames only; a refused send does not stop the loop. An empty id list
/// sends nothing and mints no id. The caller flushes the gateway once if `sent > 0`.
template <class MintId, class Prepare, class SendOne>
[[nodiscard]] DispatchResult fan_out(const std::vector<std::string>& ids, MintId&& mint_id,
                                     Prepare&& prepare, SendOne&& send_one) {
    DispatchResult out;
    if (ids.empty())
        return out;
    const std::string command_id = mint_id();
    auto cmd = prepare(command_id);
    if (!cmd)
        return out;
    out.command_id = command_id;
    for (const auto& id : ids)
        if (send_one(id, *cmd))
            ++out.sent;
    return out;
}

// ── partition ─────────────────────────────────────────────────────────────────────

struct Counts {
    /// Every candidate the resolver named (`requested` = reached + skipped_offline +
    /// skipped_version + skipped_fresh at the time of the plan).
    std::size_t requested{0};
    std::size_t reached{0};
    /// Candidates this server process did not reach and that are not too old: no live session
    /// here (a disconnected device, or one attached to another server) OR a send the live stream
    /// refused (`finalize` adds those, e.g. a gateway-attached agent whose gateway lacks the
    /// dispatch capability). Which devices are candidates depends on the arm: a group or a named
    /// device lists its disconnected members too, but `__all__` and a scope expression list only
    /// this server's own sessions plus the shared presence record, so a device offline everywhere
    /// is never enumerated or counted. If the presence read is degraded, an `__all__` run lists
    /// fewer devices (those attached to other servers) and a scope-expression run is refused with
    /// 503. So `requested` and `skipped_offline` describe what THIS server could reach; they are
    /// not a census of the fleet.
    std::size_t skipped_offline{0};
    std::size_t skipped_version{0};
    /// Candidates left out because their last accepted report is not older than the request's
    /// `last_synced_before`. Counted before the offline and version split, so a recently synced
    /// device that is also offline is counted here only.
    std::size_t skipped_fresh{0};
};

struct Plan {
    std::vector<std::string> targets; // the live, new-enough subset, in input order
    Counts counts;
};

/// The candidates a `last_synced_before` request still wants, and how many it dropped.
struct FreshSplit {
    std::vector<std::string> stale; // in input order
    std::size_t fresh{0};
};

/// Drop the devices whose last accepted report is NOT older than `before`. `last_seen` maps a
/// device to the server-receipt epoch seconds of its last accepted report; a device with no entry
/// has never reported and counts as older (it is asked). Pure: the store read is the Runner's.
[[nodiscard]] inline FreshSplit split_fresh(const std::vector<std::string>& ids,
                                            const std::unordered_map<std::string, std::int64_t>& last_seen,
                                            std::int64_t before) {
    FreshSplit out;
    out.stale.reserve(ids.size());
    for (const auto& id : ids) {
        const auto it = last_seen.find(id);
        if (it != last_seen.end() && it->second >= before)
            ++out.fresh;
        else
            out.stale.push_back(id);
    }
    return out;
}

/// Split ids into targets / offline / too-old. `version_of(id)` is the agent version of a
/// session on THIS process or nullopt (a device attached to another replica looks the same as a
/// disconnected one, and is counted with it - see `Counts::skipped_offline`); `supports(version)`
/// is the sync-now version floor (`agent_supports_sync_now`: 0.13.1+), and an unparseable version
/// fails it, so it counts as too old, never as reachable. There is no ceiling on the number of
/// targets: the run is paced, not refused (software_sync_pacing.hpp).
template <class VersionFn, class SupportsFn>
[[nodiscard]] Plan partition(const std::vector<std::string>& ids, VersionFn&& version_of,
                             SupportsFn&& supports) {
    Plan p;
    p.counts.requested = ids.size();
    for (const auto& id : ids) {
        const std::optional<std::string> version = version_of(id);
        if (!version)
            ++p.counts.skipped_offline;
        else if (!supports(std::string_view(*version)))
            ++p.counts.skipped_version;
        else
            p.targets.push_back(id);
    }
    p.counts.reached = p.targets.size();
    return p;
}

/// Counts after dispatch: `reached` is what the registry accepted; a target that was live
/// at partition time but whose send the live stream refused is added to `skipped_offline`.
[[nodiscard]] inline Counts finalize(Counts planned, std::size_t sent) {
    if (sent > planned.reached)
        sent = planned.reached; // a dispatcher cannot have reached more than it was given
    planned.skipped_offline += planned.reached - sent;
    planned.reached = sent;
    return planned;
}

// ── cooldown ──────────────────────────────────────────────────────────────────────

/// Seconds a run key still has to wait (0 = clear), `cooldown_secs` after its last run started
/// (0 turns the gap off). A stamp from the FUTURE (the clock stepped backwards since the run) is
/// stale, not a lock-out: it would otherwise hold the key for the size of the step plus the gap.
/// The next run replaces it.
[[nodiscard]] inline std::int64_t cooldown_remaining(std::optional<std::int64_t> last_run, std::int64_t now,
                                                     std::int64_t cooldown_secs) {
    if (!last_run || cooldown_secs <= 0)
        return 0;
    const std::int64_t elapsed = now - *last_run;
    if (elapsed < 0)
        return 0;
    return elapsed >= cooldown_secs ? 0 : cooldown_secs - elapsed;
}

// ── wording ───────────────────────────────────────────────────────────────────────

/// The pre-dispatch audit `detail`: scope, arm, the counts and the spread. `reached` here is the
/// PLAN (devices the run will send to); the 202's `agents_reached` is what was accepted.
/// `delay_max_s` is the spread window the run was admitted with (0 = immediate).
[[nodiscard]] inline std::string audit_detail(const Selector& sel, const Counts& c, std::int64_t delay_max_s) {
    return "scope=" + audit_token(sel.expr) + " arm=" + std::string(dispatch_arm_label(sel.arm)) +
           " requested=" + std::to_string(c.requested) +
           " reached=" + std::to_string(c.reached) +
           " skipped_offline=" + std::to_string(c.skipped_offline) +
           " skipped_version=" + std::to_string(c.skipped_version) +
           " skipped_fresh=" + std::to_string(c.skipped_fresh) +
           " delay_max_s=" + std::to_string(delay_max_s);
}

/// "requested" when something will be sent, "no_agents" when nothing can be (the same two
/// result words the per-device route uses).
[[nodiscard]] inline const char* audit_result(const Counts& planned) {
    return planned.reached > 0 ? "requested" : "no_agents";
}

/// The 202 `data` object. Counts only — never a per-device list — so the body cannot
/// disclose which devices were matched, skipped or hidden. `execution_id` is null when the run
/// could not be tracked. `estimated_completion_at` is `requested_at + delay_max_s`: an ESTIMATE of
/// when the last device the run asked will have fired (a device whose own scheduled sync is due
/// sooner reports sooner), not a promise that every report is stored by then. `joined` is false
/// here; the Runner sets it on the answer a joining request receives.
[[nodiscard]] inline nlohmann::json summary_json(const Counts& c, const std::string& command_id,
                                                 std::int64_t requested_at, const std::string& execution_id,
                                                 std::int64_t delay_max_s) {
    nlohmann::json out = {{"requested", c.requested},
                          {"agents_reached", c.reached}, // the name /api/command and the per-device route use
                          {"skipped_offline", c.skipped_offline},
                          {"skipped_version", c.skipped_version},
                          {"skipped_fresh", c.skipped_fresh},
                          {"command_id", command_id},
                          {"source", std::string(kSource)},
                          {"requested_at", requested_at},
                          {"delay_max_s", delay_max_s},
                          {"estimated_completion_at", requested_at + delay_max_s},
                          {"joined", false}};
    out["execution_id"] = execution_id.empty() ? nlohmann::json(nullptr) : nlohmann::json(execution_id);
    return out;
}

} // namespace yuzu::server::software_sync
