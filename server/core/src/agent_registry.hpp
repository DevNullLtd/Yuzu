#pragma once

/// @file agent_registry.hpp
/// Agent session tracking, scope evaluation, and fleet health aggregation.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include "agent.grpc.pb.h"
#include "command_capability.hpp"
#include "command_capability_parsers.hpp"
#include "dispatch_caller.hpp"
#include "event_bus.hpp"
#include "offline_endpoint_store.hpp" // HA WS-5: PresenceIdentity is a value member (presence_cache_)
#include "scope_engine.hpp"

// Forward declarations
namespace yuzu::server {
class TagStore;
class CustomPropertiesStore;
class ResultSetStore;
class DeviceTokenStore;
/// PLAN (p8/PR1.9c): forward-declared so `ClassifiedCommand` below can name
/// it as the only PRODUCTION friend able to construct one — the full
/// definition lives entirely in server.cpp (`ServerImpl` has no separate
/// header; `Server`'s factory is the only public surface).
class ServerImpl;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

/// CC-03 (`proto/yuzu/gateway/v1/gateway.proto`'s `StreamStatusNotification.
/// wire_capabilities` doc comment): the ONE literal a gateway build must
/// advertise on every CONNECTED notification before the server will route a
/// dispatch-tagged `CommandRequest` to an agent behind it — proof the
/// gateway's vendored `agent.proto` carries `CommandRequest.dispatch_tag = 9`
/// and forwards it untouched. Named here (not re-typed at each call site)
/// because `gateway_service_impl.cpp` reads it off the wire and this file's
/// own send path checks for it — a second, independently spelled copy is
/// exactly the kind of drift this file's #1788 doc comments warn about
/// elsewhere.
inline constexpr std::string_view kGatewayWireCapabilityDispatchTagV1{"command_dispatch_tag_v1"};

// ── Dispatch classification + authorization (PR1.9c) ─────────────────────────
//
// The chokepoint invariant this section exists to hold: it must be
// IMPOSSIBLE to put a `CommandRequest` on the wire without BOTH a
// classification decision (does this `plugin.action` pair exist, and what is
// it?) AND an authorization decision (may `caller` issue it?). Provenance,
// not syntax (peer finding PLAN-011): a syntactically valid `dispatch_tag` on
// a hand-built `pb::CommandRequest` proves nothing on its own, because
// `encode_dispatch_tag` is a public, pure helper — so the guarantee below is
// a TYPE invariant (`ClassifiedCommand`'s private constructor), never a
// string check alone.

/// Why `ServerImpl::build_classified_command` refused a dispatch. Every
/// value is counted separately by the caller (ADR-0033 §2: "never a
/// permissive default") — `Unclassified`/`Ambiguous` mirror
/// `ClassificationError` 1:1; `AnonymousOperator`/`Forbidden` are this
/// package's own authorization arm.
enum class DispatchDenialReason : uint8_t {
    Unclassified,      ///< No `CommandCapability` row matches `plugin.action`
                       ///< (also raised for a row whose `execute_gate` parsed
                       ///< as `ExecuteGate::Unspecified` — #1398 defense in
                       ///< depth; see `command_capability.hpp`. That should be
                       ///< IMPOSSIBLE by construction — every fragment's own
                       ///< compile-time sweep makes an omitted `.execute_gate`
                       ///< a build failure — so reaching this arm at runtime
                       ///< means that sweep itself is broken, not that this
                       ///< row is merely unclassified in the ordinary sense).
    Ambiguous,         ///< Two+ fragments independently declared the same row.
    AnonymousOperator, ///< `caller.system == false` with an empty `principal`.
    Forbidden,         ///< Classified, but `caller` may not issue it — either an
                       ///< operator lacking the resolved securable/operation, or
                       ///< ANY operator attempting a `system_reserved` row.
    ApprovalRequired,  ///< #1398: classified and RBAC-authorized, but `cap
                       ///< .execute_gate` requires proof of an approval
                       ///< decision (`DispatchCaller::approval_provenance`)
                       ///< the caller does not carry — `AdminOrApproval`
                       ///< additionally admits an effective-admin caller with
                       ///< no provenance at all; `AlwaysApproval` never does.
                       ///< Deliberately AFTER `Forbidden` in evaluation order:
                       ///< approval is never a substitute for a missing RBAC
                       ///< grant, only for the ADDITIONAL gate on top of one.
    KillSwitched,      ///< Classified and authorized, but the per-action kill
                       ///< switch is OFF for this `plugin.action` (or the config
                       ///< store is degraded, which `action_allowed` reports as
                       ///< disabled — never as enabled). Deliberately DISTINCT
                       ///< from `Forbidden`: this is an operator-thrown
                       ///< emergency stop, not an authorization verdict, and an
                       ///< incident review needs to tell the two apart.
};

/// A refused dispatch. `securable`/`operation` are populated only once
/// classification itself succeeded — `Unclassified`/`Ambiguous` carry no
/// resolved securable, there is nothing to name yet (a caller
/// logging/auditing a denial must branch on `reason` before trusting
/// `securable`). `AnonymousOperator` and `Forbidden` are raised AFTER
/// classification resolved, so both DO name the securable the caller failed
/// to satisfy — that is what makes the audit line actionable.
///
/// `securable` owns its characters rather than viewing `CommandCapability`'s
/// static storage: a denial is the exceptional path, and the consumers
/// concatenate it into operator-facing messages.
struct DispatchDenial {
    DispatchDenialReason reason;
    std::string securable;
    authz::Operation operation{authz::Operation::Read};
};

/// The ONE string form of a `DispatchDenialReason` — snake_case, matching
/// the existing `yuzu_server_dispatch_denied_total{reason=...}` metric label
/// values (unchanged by #1398; this function only deduplicates the mapping,
/// it does not relabel anything already in production dashboards/alerts).
/// Used for BOTH the metric label and the route-local audit detail
/// (`server.cpp`'s `/api/command` handler) — an incident review needs the
/// SAME string in both places to correlate a metric spike with the audit
/// rows that produced it, and a single source avoids the two silently
/// drifting apart the way a hand-duplicated switch invites. No `default:`
/// case (see `authz::to_string` in `authz_model.hpp` for the same pattern)
/// so `-Werror=switch` catches a future `DispatchDenialReason` enumerator
/// added here without a matching label.
[[nodiscard]] constexpr std::string_view to_string(DispatchDenialReason reason) {
    switch (reason) {
        case DispatchDenialReason::Unclassified: return "unclassified";
        case DispatchDenialReason::Ambiguous: return "ambiguous";
        case DispatchDenialReason::AnonymousOperator: return "anonymous_operator";
        case DispatchDenialReason::Forbidden: return "forbidden";
        case DispatchDenialReason::ApprovalRequired: return "approval_required";
        case DispatchDenialReason::KillSwitched: return "kill_switched";
    }
    return "";
}

/// The pure classify+authorize DECISION `ServerImpl::build_classified_command`
/// is built around, extracted so it is directly unit-testable without a live
/// `ServerImpl`/`RbacStore`/database — the same reasoning
/// `dispatch_confined_arms.hpp` and `dispatch_target_shape.hpp` give for their
/// own extractions: a from-scratch copy inside a test is how a shared rule
/// silently drifts from what production actually enforces.
///
/// `has_permission` is injected rather than a live `RbacStore*` so this
/// function's job stays exactly one question — "is `principal` granted
/// `operation` on `securable`, right now" — and every HTTP/session-layer
/// nuance stays OUTSIDE it, owned by whatever binds the callback. Never
/// memoize the callback's answer across calls (ADR-0012 §4) — this function
/// itself never does, and neither may a caller.
///
/// WHAT THE PRODUCTION BINDER ACTUALLY HANDLES TODAY (server.cpp): legacy-open
/// (a loaded-and-disabled RbacStore admits, as every other dispatch-adjacent
/// read here does) and a raw `RbacStore::check_permission`. It does NOT apply
/// JIT elevation: `auth::effective_role` elevates a cookie session to admin for
/// its window, and the elevation-aware surface gate (`require_permission`)
/// admits on that, but this callback receives only a principal STRING and
/// resolves that principal's BASE grants. So a JIT-elevated operator can clear
/// the surface gate and then be denied `Forbidden` here for a securable their
/// base role lacks. That is FAIL-CLOSED — it denies, never over-permits — but
/// it is a real gap in the elevated-dispatch workflow rather than a design
/// choice, and whether elevated authority SHOULD reach dispatch is a security
/// decision that needs its own review. Tracked; do not silently widen this
/// callback to close it.
///
/// System arm (PLAN item 2): `caller.system == true` is trusted BY
/// CONSTRUCTION — `DispatchCaller::system` is set explicitly only at
/// background/system call sites, never derived from external input
/// (`dispatch_caller.hpp`) — so it is routed under an explicit system
/// identity rather than a caller-attributable RBAC decision, which is
/// exactly what `system_reserved` rows are FOR
/// (`capability_decls/core_dispatch_capabilities.hpp`). What a system caller
/// is NOT excused from is classification itself: an unclassified or
/// ambiguous `plugin.action` is refused for a system caller exactly as for an
/// operator one — "route under an identity", never "skip the chokepoint".
[[nodiscard]] inline std::expected<CommandCapability, DispatchDenial>
classify_and_authorize_dispatch(
    const CommandCapabilityRegistry& registry, const DispatchCaller& caller,
    std::string_view plugin, std::string_view action,
    const std::function<bool(std::string_view principal, std::string_view securable,
                             authz::Operation operation)>& has_permission) {
    auto classified = registry.classify(plugin, action);
    if (!classified) {
        return std::unexpected(DispatchDenial{
            classified.error() == ClassificationError::Ambiguous ? DispatchDenialReason::Ambiguous
                                                                  : DispatchDenialReason::Unclassified,
            {}, authz::Operation::Read});
    }
    const CommandCapability cap = *classified;

    // #1398 defense in depth: see DispatchDenialReason::Unclassified's doc
    // comment — every fragment's compile-time sweep should make this
    // unreachable, so reaching it means that sweep is broken, not that this
    // row is ordinarily unclassified. Checked before the system-caller early
    // return: an unclassified/ambiguous plugin.action is refused for a
    // system caller exactly as for an operator one (see this function's own
    // "System arm" doc comment above), and an Unspecified gate is the same
    // shape of classification failure.
    if (cap.execute_gate == ExecuteGate::Unspecified) {
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Unclassified, {}, authz::Operation::Read});
    }

    if (caller.system)
        return cap;

    // No anonymous operator dispatch (PLAN item 2): an empty principal must
    // never reach `has_permission`, where a legacy-open store would admit it
    // by accident — `RbacStore::check_permission` has no notion of "no such
    // caller", only of "no matching role_permissions row".
    if (caller.principal.empty())
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::AnonymousOperator, std::string(cap.securable),
                           cap.operation});

    // A `system_reserved` row is dispatchable ONLY under a system caller
    // (PLAN item 2) — never caller-attributable, so an operator is refused
    // here regardless of what RBAC says about them; consulting
    // `has_permission` for a row that by definition names no legitimate
    // operator grant would be a category error, not a stricter check.
    if (cap.system_reserved)
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Forbidden, std::string(cap.securable),
                           cap.operation});

    if (!has_permission(caller.principal, cap.securable, cap.operation))
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Forbidden, std::string(cap.securable),
                           cap.operation});

    // #1398: the approval-gate dimension, checked LAST — after RBAC, never
    // instead of it. Approval proves an additional decision was made on top
    // of a grant the caller already holds; it can never substitute for a
    // missing one. `AdminOrApproval` additionally admits an effective-admin
    // caller with no approval provenance at all (mirrors the governed
    // `POST /api/instructions/:id/execute` path's own `role-gated` bypass);
    // `AlwaysApproval` admits ONLY a caller carrying real provenance,
    // effective-admin or not.
    const bool has_provenance = caller.approval_provenance != ApprovalProvenance::None;
    // Gate 3 (cpp-expert): a `switch` with no `default:`, not an if-chain —
    // matches `to_string(DispatchDenialReason)`'s own no-`default:` doctrine
    // above, so a future 5th `ExecuteGate` value is a `-Werror=switch` build
    // failure here instead of a silent "no approval required" fallthrough.
    switch (cap.execute_gate) {
        case ExecuteGate::Unspecified:
            // Unreachable in practice — the check earlier in this function
            // already denies `Unspecified` before this point is reached.
            // Enumerated explicitly (not folded into a `default:`, which
            // would defeat the switch-exhaustiveness protection above) so
            // this arm stays defense-in-depth rather than dead code that
            // silently permits if the earlier check is ever removed.
            return std::unexpected(
                DispatchDenial{DispatchDenialReason::ApprovalRequired, std::string(cap.securable),
                               cap.operation});
        case ExecuteGate::None:
            break;
        case ExecuteGate::AdminOrApproval:
            if (!has_provenance && !caller.principal_is_admin) {
                return std::unexpected(DispatchDenial{DispatchDenialReason::ApprovalRequired,
                                                       std::string(cap.securable), cap.operation});
            }
            break;
        case ExecuteGate::AlwaysApproval:
            if (!has_provenance) {
                return std::unexpected(DispatchDenial{DispatchDenialReason::ApprovalRequired,
                                                       std::string(cap.securable), cap.operation});
            }
            break;
    }

    return cap;
}

/// The frozen v1 dispatch-tag wire grammar (`command_capability_parsers.hpp`),
/// composed once so `ServerImpl::build_classified_command` and this file's own
/// tests always stamp/verify a tag the IDENTICAL way — `encode_dispatch_tag` +
/// `compute_plan_hash` are p1-owned pure helpers; this is the one place p8
/// composes them, so a test can call this directly rather than re-deriving the
/// composition from scratch.
[[nodiscard]] inline std::string
compute_dispatch_tag(const CommandCapability& cap, std::string_view plugin, std::string_view action,
                     const std::map<std::string, std::string>& parameters,
                     std::string_view target_arm, std::string_view execution_id) {
    return encode_dispatch_tag(
        cap.dispatch_class, cap.mutability,
        compute_plan_hash(plugin, action, parameters, target_arm, execution_id));
}

class ClassifiedCommand; // Forward decl — completed below; needed as an
                         // incomplete type by the declaration immediately
                         // following.

/// Forward declaration so `ClassifiedCommand` can friend it below — the
/// definition (which needs the completed class) follows the class. Default
/// arguments live here, the one declaration every caller and the friend
/// grant both see; the out-of-class definition repeats none of them (a
/// second default-argument set on the same declaration is ill-formed).
[[nodiscard]] inline std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
    const CommandCapability& cap,
    const std::function<bool(std::string_view plugin, std::string_view action)>& action_allowed,
    std::string_view raw_plugin, std::string_view raw_action, const std::string& command_id,
    const std::unordered_map<std::string, std::string>& parameters = {},
    const std::string& payload = {}, int stagger_seconds = 0, int delay_seconds = 0,
    const std::string& target_arm = {}, const std::string& execution_id = {});

/// PLAN item 3 (PLAN-011, provenance not syntax): the type-level guarantee
/// that a `pb::CommandRequest` reaching `AgentRegistry::send_to`/`send_to_all`
/// passed through `ServerImpl::build_classified_command` — a syntactically
/// valid `dispatch_tag` proves nothing on its own, since `encode_dispatch_tag`
/// is a public, pure helper any caller could stamp onto a hand-built proto.
/// The guarantee is therefore a TYPE invariant: PRIVATE constructor, no public
/// setter, no public conversion that yields a mutable `pb::CommandRequest` —
/// only `ServerImpl` (production), `finalize_classified_command` (production,
/// below), and `ClassifiedCommandTestAccess` (tests, mirroring
/// `EngineLivenessTestAccess` in `engine_principal_store.hpp`) may construct
/// one. A caller that hand-builds a protobuf cannot reach the registry at
/// all: there is no overload of `send_to`/`send_to_all` that accepts one.
class ClassifiedCommand {
public:
    /// Read-only view of the wire command. Deliberately a named accessor
    /// returning `const&`, never a conversion operator — a conversion would
    /// let a `ClassifiedCommand` silently decay to a mutable
    /// `pb::CommandRequest` at a call site that forgot which type it held.
    [[nodiscard]] const pb::CommandRequest& wire() const noexcept { return cmd_; }

private:
    friend class yuzu::server::ServerImpl;
    friend struct ClassifiedCommandTestAccess;
    friend std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
        const CommandCapability&, const std::function<bool(std::string_view, std::string_view)>&,
        std::string_view, std::string_view, const std::string&,
        const std::unordered_map<std::string, std::string>&, const std::string&, int, int,
        const std::string&, const std::string&);

    explicit ClassifiedCommand(pb::CommandRequest cmd) : cmd_(std::move(cmd)) {}

    pb::CommandRequest cmd_;
};

/// #3687 (Gate 6 governance fix): the per-action kill-switch DECISION
/// `finalize_classified_command` applies (below), extracted to its own
/// function for the IDENTICAL reason `finalize_classified_command` itself was
/// extracted from `ServerImpl::build_classified_command` — see that
/// function's own doc comment immediately below: "a from-scratch copy inside
/// a test/caller is how a shared rule silently drifts from what production
/// actually enforces". This PR's own first round reintroduced that exact
/// shape once already (the MCP pre-dispatch dry run's production wiring,
/// `server.cpp`, re-expressed this boolean inline instead of sharing code —
/// caught by governance, this extraction is the fix), which is the concrete
/// proof this class of drift is not hypothetical.
///
/// `action_allowed`'s contract is IDENTICAL to `classify_and_authorize_
/// dispatch`'s `has_permission`: injected, not looked up — the production
/// binder wraps `PluginConfigStore::action_allowed`, fail-closed by that
/// store's own contract (a closed store, a lease timeout, or a query failure
/// all report "not allowed"). An empty/unset callback means no kill-switch
/// store is wired at all (legacy-open for THIS gate ONLY, mirroring how an
/// absent `plugin_config_store_` behaves in `server.cpp`) — never call this
/// with a callback that unconditionally returns `true` "to be safe"; that
/// reintroduces exactly the ZERO-callers gap `finalize_classified_command`'s
/// own extraction (M6, wave1 remediation) closed.
///
/// Returns `std::nullopt` when the action is allowed (including when
/// `action_allowed` is unset — legacy-open); a populated `DispatchDenial`
/// (always `DispatchDenialReason::KillSwitched`) otherwise. Every caller of
/// `classify_and_authorize_dispatch` that also needs the kill-switch
/// dimension — today `finalize_classified_command` and the MCP pre-dispatch
/// dry run (server.cpp's `authorize_dispatch_fn_` production closure) — calls
/// this directly rather than re-deriving the condition.
[[nodiscard]] inline std::optional<DispatchDenial> kill_switch_denial(
    const CommandCapability& cap,
    const std::function<bool(std::string_view plugin, std::string_view action)>& action_allowed) {
    if (action_allowed && !action_allowed(cap.plugin, cap.action)) {
        return DispatchDenial{DispatchDenialReason::KillSwitched, std::string(cap.securable),
                              cap.operation};
    }
    return std::nullopt;
}

/// The composition step `ServerImpl::build_classified_command` runs AFTER
/// `classify_and_authorize_dispatch` succeeds — extracted for the identical
/// reason that function was: a from-scratch copy inside a test is how a
/// shared rule silently drifts from what production actually enforces, and
/// until this extraction NOTHING unit-tested it directly (M6, wave1
/// remediation). Two behaviours live here, both revert-survivor-sensitive:
///
/// 1. **The per-action kill switch** — delegates to `kill_switch_denial`
///    (above); see that function's own doc comment for the injection
///    contract.
/// 2. **BR-009 canonical wire names.** The wire command is built from `cap`'s
///    catalogue-resolved spelling (`cap.plugin`/`cap.action`), never the
///    caller's raw strings — `classify()` is case-insensitive but the agent
///    matches case-SENSITIVELY, so a caller passing `plugin="TAR"` would
///    otherwise be authorized here and rejected on the endpoint. `raw_plugin`/
///    `raw_action` are threaded through ONLY into the dispatch-tag hash
///    (`compute_dispatch_tag`), unchanged from what `build_classified_command`
///    always passed there — the hash and the wire fields are deliberately
///    fed different spellings and this preserves that, rather than "fixing"
///    it as part of an unrelated extraction.
[[nodiscard]] inline std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
    const CommandCapability& cap,
    const std::function<bool(std::string_view plugin, std::string_view action)>& action_allowed,
    std::string_view raw_plugin, std::string_view raw_action, const std::string& command_id,
    const std::unordered_map<std::string, std::string>& parameters,
    const std::string& payload, int stagger_seconds, int delay_seconds,
    const std::string& target_arm, const std::string& execution_id) {
    if (auto denial = kill_switch_denial(cap, action_allowed)) {
        return std::unexpected(*denial);
    }

    pb::CommandRequest cmd;
    cmd.set_command_id(command_id);
    cmd.set_plugin(std::string(cap.plugin));
    cmd.set_action(std::string(cap.action));
    for (const auto& [k, v] : parameters)
        (*cmd.mutable_parameters())[k] = v;
    if (!payload.empty())
        cmd.set_payload(payload);
    if (stagger_seconds > 0)
        cmd.set_stagger_seconds(stagger_seconds);
    if (delay_seconds > 0)
        cmd.set_delay_seconds(delay_seconds);

    const std::map<std::string, std::string> ordered_params(parameters.begin(), parameters.end());
    cmd.set_dispatch_tag(
        compute_dispatch_tag(cap, raw_plugin, raw_action, ordered_params, target_arm, execution_id));

    return ClassifiedCommand(std::move(cmd));
}

/// Test-only door to the private constructor above (#2367 pattern — mirrors
/// `EngineLivenessTestAccess`, `engine_principal_store.hpp`, identical
/// rationale). Declared here; the definition is deliberately withheld from
/// every production translation unit and lives ONLY in
/// `tests/unit/server/classified_command_test_access.cpp`, a TU that links
/// into the test binary and is never added to server_core's (or any other
/// production target's) source list. Production code MUST go through
/// `ServerImpl::build_classified_command` — if a production TU ever
/// referenced `ClassifiedCommandTestAccess::make`, it would still COMPILE
/// (the declaration is visible via this header) but FAIL TO LINK, because no
/// production link line carries the definition. That is what upgrades
/// "test-only" from a doc-comment convention to a structural,
/// compile/link-time-enforced control, exactly as #2367 did for
/// `EngineLivenessTestAccess`. This exists only so a unit test can construct
/// a `ClassifiedCommand` fixture without a live
/// `ServerImpl`/`RbacStore`/`CommandCapabilityRegistry`, and so the ONE
/// pre-existing test that threads a real `pb::CommandRequest` through
/// `wire_and_dispatch_confined` into a REAL `AgentRegistry`
/// (`test_dispatch_confined_arms.cpp`'s K-1 case) keeps compiling against
/// `send_to`'s narrowed signature.
struct ClassifiedCommandTestAccess {
    [[nodiscard]] static ClassifiedCommand make(pb::CommandRequest cmd);
};

// -- Plugin metadata ----------------------------------------------------------

struct PluginMeta {
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> actions;
};

// -- Agent session (one per connected agent) ----------------------------------
//
// IMMUTABILITY CONTRACT: the identity fields (agent_id..scopable_tags) are
// fully populated BEFORE the session is installed in the registry and are
// never mutated afterwards — re-registration REPLACES the shared_ptr, it
// does not edit in place. Lock-free readers (scope evaluation, the DEX perf
// provider) depend on this — NONE of them reads `gateway_node`,
// `gateway_wire_capabilities`, or `gateway_stream_home_id` (verified: their
// only readers are send_to/send_to_all and agent_registry.cpp's own
// gateway_stream_home_id() accessor, all under `stream_mu`), which is
// exactly why those three are NOT in this list. Post-publication writes are
// confined to stream/server_context/peer_cert_pem, gateway_node +
// gateway_wire_capabilities + gateway_stream_home_id (all under stream_mu —
// the trio published together by set_gateway_route, M1 review fix +
// #4324; an earlier revision wrote gateway_node under the registry mu_
// instead, which both raced stream_mu's readers and contradicted this
// comment) and the atomic last_activity_epoch_ms. (Governance G3
// cpp-safety — keep it true.)

struct AgentSession {
    std::string agent_id;
    std::string session_id; // Unique per connection — used to prevent stale cleanup races
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::vector<std::string> plugin_names;
    std::vector<PluginMeta> plugin_meta;
    std::unordered_map<std::string, std::string> scopable_tags;
    std::string gateway_node; // Non-empty if agent is connected via gateway
    /// HA WS-4 4.3: the gateway cluster this session's most recent CONNECTED
    /// `StreamStatusNotification` announced (`request.cluster_id()`),
    /// published by `set_gateway_route` under `stream_mu` alongside
    /// `gateway_node`/capabilities/`gateway_stream_home_id` — same lock,
    /// same call, for the same atomic-publish reason (see `gateway_node`'s
    /// sibling comments). Read by `send_to`/`send_to_all` to stamp
    /// `GatewayPendingCmd::cluster_id` so `forward_gateway_pending` dials the
    /// owning cluster instead of always the single legacy stub. Empty for a
    /// direct (non-gateway) agent, or a gateway build predating 4.3 that
    /// never sets `StreamStatusNotification.cluster_id`.
    std::string cluster_id;

    // Stream pointer -- valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    grpc::ServerContext* server_context = nullptr; // for timeout cancellation
    // PR3 H-1: the client leaf PEM presented when this Subscribe stream was
    // established, captured so a background sweep can re-evaluate revocation on
    // the long-lived stream (the establishment gate only runs once). Empty when
    // the agent presented no client cert. Guarded by stream_mu alongside stream/
    // server_context.
    std::string peer_cert_pem;
    /// PLAN item 5 (CC-03): the literal wire-capability strings this agent's
    /// gateway advertised on its most recent CONNECTED
    /// `StreamStatusNotification` — empty for a direct (non-gateway) agent
    /// and for a gateway build too old to advertise any. Guarded by
    /// `stream_mu` alongside the other post-publication, connection-lifetime
    /// fields above: a reconnect (a fresh CONNECTED) REPLACES this set, it is
    /// never merged with a prior connection's advertisement (PLAN item 5).
    std::unordered_set<std::string> gateway_wire_capabilities;
    /// HA WS-4 #4324: the opaque per-connection-instance id (minted once per
    /// gateway-side `yuzu_gw_agent` process, task 1 of #4324) this session's
    /// most recent CONNECTED `StreamStatusNotification` carried — published
    /// by `set_gateway_route` under `stream_mu` alongside `gateway_node`/
    /// `gateway_wire_capabilities`, same lock, same call, for the same
    /// atomic-publish reason (see that field's comment). Empty for a direct
    /// (non-gateway) agent, or a gateway build predating #4324. Read by
    /// `gateway_stream_home_id()` to fence a stale DISCONNECTED from a
    /// torn-down home against a NEWER re-home reusing the same `session_id`
    /// (`GatewayUpstreamServiceImpl::NotifyStreamStatus`).
    std::string gateway_stream_home_id;
    std::mutex stream_mu;

    // Last activity timestamp -- updated on Subscribe reads and Heartbeats.
    // Atomic to avoid acquiring the registry mutex on every stream Read.
    std::atomic<int64_t> last_activity_epoch_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count()};
};

// -- Agent registry -----------------------------------------------------------

class AgentRegistry {
public:
    explicit AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics);

    /// Register (or re-register) an agent. On re-registration, first revokes any device tokens
    /// bound to this agent_id (W1.5 / #823, corrected by #3401 — see `revoke_by_device`) BEFORE
    /// installing the new session, so a briefly-impersonated agent (mTLS-disabled flow, #779)
    /// cannot keep replaying a token issued to the legitimate agent. First-time registrations
    /// (no prior entry) skip the revoke, preserving the operator workflow of pre-issuing a token
    /// for an agent_id that has not registered yet.
    ///
    /// Fails closed (ADR-0012 §1): if a wired device-token store reports a genuine revoke
    /// failure, the registration is REFUSED — `unexpected(msg)` — and nothing changes (no
    /// session installed, no management-group membership, no topology invalidation). A caller
    /// MUST NOT install a session after a refusal. The revoke runs OFF the registry mutex (see
    /// the .cpp for the two-phase structure, precedent `sweep_revoked`) — only the map
    /// read/write is held under `mu_`, not the blocking Postgres round-trip.
    ///
    /// Also refused, same way, if superseded: because the revoke runs off-lock, a second
    /// `register_agent` call for the same `agent_id` can install its session while this call's
    /// revoke is still in flight. Phase 2 re-checks the map entry against the pointer this call
    /// observed in phase 1 — a mismatch means a newer registration already won, and THIS call
    /// yields rather than overwriting a live session with a stale one (its own revoke already
    /// committed, so nothing is lost by not installing). This restores the ordering the old
    /// single-locked implementation gave for free; it does not add a NEW guarantee beyond that.
    ///
    /// Follow-up (HA WS-4 4.2b, post-merge review #4344, MEDIUM finding 1): on success, returns
    /// the `shared_ptr<AgentSession>` this call just installed — pointer identity a caller can
    /// hand to `remove_agent_if_same` for an identity-guarded rollback if a LATER step in its own
    /// registration flow (e.g. `GatewayRouteStore::register_fresh`) fails after this call already
    /// installed the session. session_id is still empty at this point (mapped later by
    /// `map_session`), so identity — not session_id string equality — is the only safe key for
    /// that rollback; see `remove_agent_if_same`.
    [[nodiscard]] std::expected<std::shared_ptr<AgentSession>, std::string>
    register_agent(const pb::AgentInfo& info);

    void set_stream(const std::string& agent_id,
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
                    grpc::ServerContext* context = nullptr,
                    const std::string& peer_cert_pem = {});

    void clear_stream(const std::string& agent_id);

    /// PR3 H-1: re-evaluate revocation on every live Subscribe stream and tear
    /// down (TryCancel) any whose presented client leaf is now revoked. The
    /// establishment gate (`Subscribe`) only checks once; a long-lived stream
    /// would otherwise keep dispatching to a revoked/compromised agent until it
    /// voluntarily reconnects (which a hostile agent never does). Driven
    /// periodically from the reaper thread and callable immediately after an
    /// operator revoke (PR4) for prompt teardown. `is_revoked(peer_pem)` returns
    /// true iff that leaf is on the CRL; sessions with no presented cert are
    /// skipped. The predicate is evaluated OFF stream_mu (it reads ca_store);
    /// teardown re-acquires the lock and re-checks the cert is unchanged.
    /// Returns the `agent_id`s whose streams were cancelled (so the caller can
    /// emit a per-teardown audit row — the registry holds no AuditStore). Null
    /// predicate → no-op (empty).
    std::vector<std::string>
    sweep_revoked(const std::function<bool(const std::string& peer_cert_pem)>& is_revoked);

    /// Update last_activity timestamp for an agent (called on heartbeat + subscribe reads).
    void touch_activity(const std::string& agent_id);

    /// Cancel Subscribe streams for agents that haven't heartbeated within the timeout.
    void reap_stale_sessions(std::chrono::seconds timeout);

    void remove_agent(const std::string& agent_id);

    /// Remove an agent only if its current session_id matches (prevents stale
    /// Subscribe cleanup from clobbering a newer reconnection). Returns true
    /// iff the CURRENT session was removed, false on a session mismatch
    /// (no-op — a newer connection has already taken over).
    ///
    /// HA WS-5 governance hardening (external review finding, 2026-09-22):
    /// the return value is load-bearing for the caller's durable-presence
    /// mirror (agent_service_impl.cpp / gateway_service_impl.cpp), which
    /// must fire OfflineEndpointStore::remove_if_session ONLY when this
    /// returns true. The durable row's own session_id column is
    /// heartbeat-driven, not registration-driven (see heartbeat_ingestion.cpp)
    /// — so on an ordinary same-replica reconnect (S1 disconnects, S2
    /// registers, S2 hasn't heartbeated yet), the durable row can still read
    /// S1's session_id even though S1 is already locally superseded by S2.
    /// A caller that fires the durable delete unconditionally (using S1's
    /// own session_id, which still legitimately matches the stale row) would
    /// delete a LIVE agent's presence row — a false-negative other replicas'
    /// evaluate_scope()/all_ids() would silently inherit. Bool was `void`
    /// before this fix; every caller was already local to this repo (grep
    /// verified two call sites, both updated in the same change).
    [[nodiscard]] bool remove_agent_if_session(const std::string& agent_id,
                                               const std::string& session_id);

    /// HA WS-4 4.2b follow-up (post-merge review #4344, MEDIUM finding 1): remove an agent ONLY
    /// if the CURRENTLY installed session is the exact object `install` returned — pointer
    /// identity, not session_id (which is empty until `map_session` runs, so a string key cannot
    /// discriminate here). Ghost-session rollback: a caller whose `register_agent` succeeded but
    /// a LATER step in its own registration flow failed (e.g. gateway `register_fresh`) calls
    /// this with the shared_ptr `register_agent` returned, tearing the just-installed session
    /// back down. A concurrent `register_agent` for the same `agent_id` that has already
    /// superseded `installed` by the time this runs is left alone — this call is a no-op, exactly
    /// like `remove_agent_if_session`'s own supersede tolerance.
    void remove_agent_if_same(const std::string& agent_id,
                              const std::shared_ptr<AgentSession>& installed);

    /// Clear stream only if the session_id matches the current session.
    void clear_stream_if_session(const std::string& agent_id, const std::string& session_id);

    /// PLAN item 5 (CC-03) / M1 (review finding, post-merge round): record
    /// the gateway node AND the literal wire-capability strings it
    /// advertised for `agent_id` on a CONNECTED `StreamStatusNotification` —
    /// called by `GatewayUpstreamServiceImpl::NotifyStreamStatus`. ONE call,
    /// not two: both fields are published together under `stream_mu`, the
    /// SAME lock `send_to`/`send_to_all` read them under (agent_registry.cpp)
    /// — this used to be two setters in two different lock domains (`node`
    /// under the registry `mu_` only), which was both a C++ data race on
    /// `gateway_node` and let a reader observe `node` present with
    /// capabilities not yet replaced (a false gateway-capability denial).
    /// `capabilities` is ALWAYS a full replace, never a merge: a reconnect
    /// (fresh CONNECTED) behind an upgraded — or downgraded — gateway build
    /// must not keep stacking capabilities the new connection never
    /// advertised. No-op if `agent_id` is not currently registered.
    ///
    /// `stream_home_id` (HA WS-4 #4324) is published in the SAME call, under
    /// the SAME lock, for the SAME reason `node`/`capabilities` are — see
    /// `AgentSession::gateway_stream_home_id`'s comment. Defaults to empty so
    /// every pre-#4324 call site (tests, any caller not yet threading the
    /// wire field through) keeps compiling and behaving exactly as before.
    ///
    /// `cluster_id` (HA WS-4 4.3) is published in the SAME call, under the
    /// SAME lock, for the SAME reason — see `AgentSession::cluster_id`'s
    /// comment. Defaults to empty so every pre-4.3 call site keeps compiling
    /// and behaving exactly as before (empty means "single-cluster / legacy
    /// stub", see `forward_gateway_pending`).
    ///
    /// HA WS-4 4.4 post-build adversarial review (PR #4636 FortitudeEtc,
    /// BLOCKER 2): `session_id` is now REQUIRED and checked against the
    /// currently-installed session before anything is written — mirroring
    /// `gateway_stream_home_id`'s own guard two members below, which already
    /// had this check while this setter did not. Without it, a delayed
    /// CONNECTED for a session already superseded by a genuine newer
    /// registration (`NotifyStreamStatus`'s OWN session check only confirms
    /// `session_id` is SOME live entry for this `agent_id` in
    /// `gateway_sessions_`, not that it is the CURRENT one) could clobber the
    /// live session's `gateway_node`/capabilities/`stream_home_id` before the
    /// durable store even had a chance to reject the corresponding
    /// `announce_connected` write. Returns `false` (no-op, nothing written)
    /// when `agent_id` is unknown OR its currently-installed session's id
    /// does not equal `session_id` — the caller must treat `false` as a
    /// stale/rejected publish, not a silent success.
    [[nodiscard]] bool set_gateway_route(const std::string& agent_id, const std::string& session_id,
                                         const std::string& node,
                                         std::vector<std::string> capabilities,
                                         std::string stream_home_id = {},
                                         std::string cluster_id = {});

    /// pr-rev finding (FortitudeEtc/Codex+Kimi, BLOCKER, 2026-09-22): the
    /// #4669 affinity pre-check (`has_cluster_affinity_conflict`,
    /// `gateway_service_impl.cpp`) is READ-ONLY and fails OPEN on a degraded
    /// read, so `set_gateway_route` can publish a claimed placement BEFORE
    /// the durable `announce_connected` write gets a chance to definitively
    /// refuse it as a `cluster_affinity_violation`. Before this method, that
    /// definitive refusal only emitted a metric+audit — the ALREADY-PUBLISHED
    /// in-memory placement (the actual dispatch target `send_to`/`send_to_all`
    /// read) was never rolled back, so a rogue's cluster could persist as the
    /// live dispatch target indefinitely with no reconciliation, even though
    /// the durable store correctly refused to record it. This reverts EXACTLY
    /// what `set_gateway_route` just published for `session_id` — ALL FOUR
    /// fields it sets together (`gateway_node`/`gateway_wire_capabilities`/
    /// `gateway_stream_home_id`/`cluster_id`), back to the "no confirmed
    /// placement yet" state — session-guarded the SAME way `set_gateway_route`
    /// is, under the SAME lock, so a legitimate LATER publish for a newer
    /// session can never be the one accidentally reverted. Returns `false`
    /// (no-op) when `agent_id` is unknown or `session_id` no longer matches
    /// the currently-installed session (already superseded — nothing to
    /// revert). Call this ONLY in direct response to a definitive
    /// `cluster_affinity_violation` on the write that follows the publish
    /// this same call sequence made; it is not a general-purpose clear.
    bool unpublish_gateway_route(const std::string& agent_id, const std::string& session_id);

    /// HA WS-4 #4324: the `stream_home_id` most recently published for
    /// `agent_id` via `set_gateway_route`, IFF the presented `session_id`
    /// still matches the CURRENTLY installed session — mirrors
    /// `remove_agent_if_session`'s own session guard. Returns `nullopt` when
    /// the agent is unknown, or when its currently-installed session's id
    /// does not equal `session_id` (a genuinely different/superseded
    /// session, already correctly handled by the legacy session-id guards on
    /// `clear_stream_if_session`/`remove_agent_if_session`/
    /// `GatewayRouteStore::deregister` — this accessor has nothing additional
    /// to fence in that case). A present-but-empty result IS meaningful: it
    /// means this session matched but was never stamped with a home id
    /// (legacy/no-fence). Read under `stream_mu`, the same lock
    /// `set_gateway_route` publishes under.
    [[nodiscard]] std::optional<std::string>
    gateway_stream_home_id(const std::string& agent_id, const std::string& session_id) const;

    /// PLAN item 5: drop every advertised wire capability for `agent_id`.
    /// Called on DISCONNECTED. `clear_stream_if_session` also clears this set
    /// (a session whose stream is gone has nothing live to route through),
    /// so a caller that reaches disconnection via that path needs no
    /// separate call.
    void clear_gateway_wire_capabilities(const std::string& agent_id);

    /// PLAN item 5: true iff `agent_id` is currently registered AND its most
    /// recent gateway CONNECTED notification advertised `capability`
    /// literally. False for an unknown agent, a direct (non-gateway) agent,
    /// or a gateway build that never advertised it — every one of those is
    /// "cannot prove this gateway forwards a tagged command", the fail-closed
    /// direction `send_to`/`send_to_all`'s routed-path check depends on.
    [[nodiscard]] bool gateway_has_wire_capability(const std::string& agent_id,
                                                   std::string_view capability) const;

    /// #826: record a peer-IP (e.g. `1.2.3.4`, no port, no scheme) as a
    /// trusted gateway. Populated by `GatewayUpstreamServiceImpl` when a
    /// gateway successfully proxy-registers an agent — the gateway's own
    /// peer becomes "known good" for the TTL window.
    ///
    /// Subscribe's peer-mismatch check (`agent_service_impl.cpp`) consults
    /// this map IN ADDITION to checking that the Subscribe peer IP equals
    /// the Register peer IP. A peer that is NEITHER the original Register
    /// peer NOR a recorded trusted gateway is always rejected, even when
    /// `--gateway-mode` is on (the old code skipped the check entirely
    /// under gateway-mode — the #826 vulnerability).
    ///
    /// **W1.3 R2 / UP-2 / UP-3.** The set used to be `unordered_set` with
    /// no eviction; in a churn-heavy NAT environment the map grew
    /// unboundedly, and an attacker who briefly controlled a routable IP
    /// would keep trust for the lifetime of the process. The map now
    /// records `peer_ip → last_seen` and lookups also require the entry to
    /// be within the TTL window (default 1 h). On every insert we
    /// opportunistically sweep stale entries; if at the entry cap (1024),
    /// we evict the oldest entry first to make room for the new one. Each
    /// successful insert/refresh emits the `yuzu_trusted_gateway_peer_set_size`
    /// gauge so the operator can dashboard the set's health.
    void note_trusted_gateway_peer(std::string_view peer_ip);

    /// Returns true if `peer_ip` was previously recorded via
    /// `note_trusted_gateway_peer` AND the entry is still within the TTL
    /// window. Empty `peer_ip` always returns false — a defence-in-depth
    /// guard so a caller that fails to extract the IP cannot accidentally
    /// satisfy the trusted check.
    bool is_trusted_gateway_peer(std::string_view peer_ip) const;

    /// W1.3 R2: trusted-gateway TTL (eviction window for an entry that
    /// has not been refreshed). Hard-coded for this PR — operator-tunable
    /// flag is tracked as a follow-up.
    static constexpr auto kTrustedGatewayTtl = std::chrono::hours(1);

    /// W1.3 R2: cap on the number of trusted-gateway entries the registry
    /// will hold simultaneously. At cap, the oldest entry is evicted on
    /// insert. 1024 is comfortable headroom for any realistic deployment
    /// (load-balanced gateway clusters have O(tens) of peers); the cap
    /// exists strictly as a memory-DoS guard.
    static constexpr std::size_t kTrustedGatewayCap = 1024;

    /// Test hook: number of entries currently in the trusted-gateway map.
    /// Mirrors `yuzu_trusted_gateway_peer_set_size` for unit tests that
    /// don't want to scrape the Prometheus surface.
    std::size_t trusted_gateway_peer_count() const;

    /// Test hook: subtract `offset` from every entry's last_seen, then
    /// re-publish the gauge. Pushes entries toward (or past) the TTL
    /// boundary without sleeping. Production code MUST NOT call this —
    /// no caller in `server/core/src/**` references it.
    void expire_trusted_gateway_for_test(std::chrono::seconds offset);

    /// W1.5 / #823: install the device-token store so `register_agent`
    /// revokes any device tokens bound to a previous incarnation of the
    /// same agent_id whenever a re-registration is detected. Optional —
    /// if never called, register_agent behaves as before and stale
    /// tokens survive re-registration. Wiring lives behind a setter rather
    /// than the constructor to avoid disturbing the existing AgentRegistry
    /// construction sites, and because production `server.cpp` does not
    /// yet construct a DeviceTokenStore (the call site exists in tests
    /// today; the invariant lands now so it can't be forgotten when the
    /// production wiring catches up).
    ///
    /// Thread contract: holds the registry mutex so a concurrent
    /// `register_agent` cannot observe a partially-installed pointer.
    /// In practice the only caller is the startup wiring path, but the
    /// lock costs nothing and removes a footgun. `register_agent` itself
    /// only reads this pointer under `mu_` — the revoke call it makes
    /// through it runs OFF the lock (#3401; see the .cpp).
    void set_device_token_store(DeviceTokenStore* store);

    /// Test hook: fires once, synchronously, in the calling thread between `register_agent`'s
    /// phase 1 (revoke) and phase 2 (install) — the exact window in which a concurrent
    /// registration for the same `agent_id` can complete and install its own session. Setting
    /// this to a callback that itself calls `register_agent` again deterministically exercises
    /// the supersede-detection path without real threads or timing (mirrors the
    /// `inject_*_fault_for_test` seams in `mcp_stream.hpp`). Cleared after firing — a callback
    /// that re-arms it will recurse. Production code MUST NOT call this — no caller in
    /// `server/core/src/**` references it.
    ///
    /// Single-threaded test use only: the member this sets is read/moved/cleared inside
    /// `register_agent` with no synchronization of its own (guarded neither by `mu_` nor a
    /// dedicated lock — deliberately, since the whole point of this hook is a same-thread,
    /// synchronous interleave rather than a real race). Setting it from one thread while another
    /// thread's `register_agent` call may read or fire it is a data race; every test using this
    /// hook must do so single-threaded (set, call the one `register_agent` that fires it, done).
    void set_register_agent_interleave_hook_for_test(std::function<void()> hook);

    // PLAN item 3 (provenance not syntax): only a `ClassifiedCommand` — mintable
    // ONLY by `ServerImpl::build_classified_command` (or the test-only door) —
    // can reach either of these. A hand-built `pb::CommandRequest` has no
    // overload to bind to; this is a compile-time invariant, not a runtime
    // check (`tests/unit/server/test_dispatch_chokepoint.cpp` pins it).
    //
    // Send a command to a specific agent. Returns false if agent not found,
    // the defensive dispatch_tag check fails, the routed-path gateway-capability
    // check refuses it (PLAN item 5), or the write itself failed. For gateway
    // agents (no local stream), adds to gateway_pending and returns true.
    bool send_to(const std::string& agent_id, const ClassifiedCommand& cmd);

    // Send command to all connected agents. Returns count of agents actually
    // reached — an agent refused by the defensive tag check or the routed-path
    // gateway-capability check (PLAN item 5) is silently excluded from the count,
    // never treated as an error for the other recipients.
    int send_to_all(const ClassifiedCommand& cmd);

    // WS-4 4.2b Task C: fallback-ONLY queue for an agent this replica has NO
    // local session for at all (the precondition every caller must have
    // already established — this method does not itself check `agents_`).
    // The caller (`GatewayRouteFallback`, dispatch_route_fallback.hpp) has
    // already resolved `cluster_id` from a BATCHED GatewayRouteStore
    // directory read. Mirrors `send_to`'s existing gateway_node branch: the
    // same defensive `tag_is_valid` check, the same `gw_pending_` queue —
    // just keyed off a directory-resolved cluster rather than a live
    // session's advertised `gateway_node`. Returns false only on a
    // malformed dispatch tag (the defensive check); queuing itself cannot
    // fail. NEVER call this for an agent that DOES have a local session —
    // `send_to` is the sole path for that (this method has no capability
    // advertisement to check, because there is no session to have
    // advertised one).
    bool send_via_directory(const std::string& agent_id, const ClassifiedCommand& cmd,
                            const std::string& cluster_id);

    struct GatewayPendingCmd {
        std::string agent_id;
        // Unwrapped to the raw wire type on purpose: by the time a command is
        // queued here, `send_to`/`send_to_all` have already required a
        // `ClassifiedCommand` to reach this point — the provenance guarantee
        // has already done its job, and `forward_gateway_pending` (server.cpp)
        // only re-wraps this into a `SendCommandRequest`, never re-decides
        // classification or authorization.
        pb::CommandRequest cmd;
        /// WS-4 4.2b Task C introduced this field for the GatewayRouteStore
        /// directory FALLBACK path (`send_via_directory`) alone, "carried
        /// through for 4.3, inert until then." WS-4 4.3 makes it live and
        /// extends population to the far more common `send_to`/`send_to_all`
        /// gateway-session path too (`AgentSession::cluster_id`, stamped by
        /// `set_gateway_route`) — `nullopt` now means "no cluster identity
        /// available" (a direct agent, or a gateway build predating 4.1/4.3),
        /// not "not the fallback path." `forward_gateway_pending`
        /// (server.cpp) resolves this against the configured per-cluster
        /// stub map; `nullopt`/empty resolves to the legacy single stub.
        std::optional<std::string> cluster_id;
    };

    std::vector<GatewayPendingCmd> drain_gateway_pending();

    bool has_any() const;

    // HA WS-5 governance hardening (external review finding, 2026-09-22):
    // has_any() above is LOCAL-ONLY (!agents_.empty()) and predates presence
    // entirely — two REST dispatch entrypoints (command_routes.cpp,
    // server.cpp's forward_legacy_command) use it as a cheap pre-dispatch
    // 503-short-circuit, which on a replica holding zero local sessions but
    // a healthy presence-visible fleet (the ordinary HA topology this slice
    // exists to support) rejected every dispatch with "no agent connected"
    // BEFORE all_ids()/evaluate_scope() or any presence lookup ever ran —
    // deterministic, not a race. This is the presence-aware replacement:
    // local_any first (cheap, matches has_any()'s existing fast path when
    // true), then live_presence() (already cached, kPresenceCacheTtl) only
    // when the fleet looks empty locally.
    [[nodiscard]] bool has_any_reachable() const;

    std::string display_name(const std::string& agent_id) const;

    // Build JSON array of all agents for the web UI (structured).
    nlohmann::json to_json_obj() const;

    // Build JSON array as a serialized string.
    std::string to_json() const;

    // Per-action description map: "plugin.action" -> human-readable description.
    static const std::unordered_map<std::string, std::string>& action_descriptions();

    // Build help catalog: deduplicated plugin metadata across all agents.
    std::string help_json() const;

    // Render help table as HTML fragment (thead + tbody rows).
    std::string help_html(std::string_view filter = "") const;

    // Render autocomplete dropdown items as HTML.
    std::string autocomplete_html(std::string_view query) const;

    // Render command palette instruction results as HTML.
    std::string palette_html(std::string_view query) const;

    // Get list of all agent IDs. HA WS-5 (ADR-2002 §7a): merges in any
    // cross-replica presence row (see configure_presence below) for an id
    // this replica has no local session for — local ids always take
    // precedence, no id is ever duplicated. Unconfigured (no presence store
    // wired), this is byte-identical to the pre-WS-5 local-only behavior.
    std::vector<std::string> all_ids() const;

    // Local-only agent count, under the SAME lock all_ids() uses — never
    // includes presence. Exposed for tests/diagnostics; NOT used by
    // dispatch_confined_arms.hpp's fast-path gate (see has_remote_presence
    // below and its own doc comment for why a two-call size comparison is
    // racy and this single-call membership check replaced it, governance
    // Gate 4 unhappy-path finding, 2026-09-22).
    [[nodiscard]] std::size_t local_agent_count() const;

    // HA WS-5 governance hardening (Gate 4 unhappy-path finding, 2026-09-22):
    // returns true iff ANY of `ids` is NOT in the local live registry, under
    // ONE lock acquisition against the registry's CURRENT state — replaces
    // the two-call `known_agent_ids().size() == local_agent_count()`
    // comparison `confined_broadcast`'s fast-path gate originally used.
    // That comparison raced: `local_agent_count()` and `known_agent_ids()`
    // (→ all_ids()) are two SEPARATE lock acquisitions, so concurrent local
    // registry churn between them could make the SIZES coincidentally match
    // while the SETS differ (a local disconnect and a presence addition
    // canceling out numerically) — silently taking the fast path
    // (`send_to_all_unfiltered`, which re-walks a FRESH local snapshot and
    // has no per-id directory-fallback hook) while `ids` genuinely contained
    // a presence-only id, with no `not_sent` entry and no metric to catch
    // it. This method instead does a DIRECT membership check against `ids`
    // (already fetched by the caller) — self-correcting in the safe
    // direction: if an id in `ids` was presence-only at fetch time but has
    // since genuinely registered locally, this correctly reports "no longer
    // remote" and the fast path (which walks the CURRENT registry) reaches
    // it anyway.
    [[nodiscard]] bool has_remote_presence(const std::vector<std::string>& ids) const;

    // HA WS-5 (ADR-2002 §7a): wires the durable cross-replica presence store
    // that all_ids()/evaluate_scope() merge in for ids absent from the local
    // live registry. `ttl` bounds how stale a presence row may be and still
    // count as live — pass the same window `reap_stale_sessions` uses
    // (`cfg_.session_timeout`), so a single replica's presence-derived
    // liveness window matches its own local one. Called once during server
    // wiring; unset (default) = local-only behavior, unchanged from
    // pre-WS-5. Non-owning — the caller (ServerImpl) outlives this registry.
    void configure_presence(OfflineEndpointStore* store, std::chrono::seconds ttl);

    // Look up the agent_id that was registered for a given Subscribe call.
    std::string find_agent_by_stream(
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const;

    std::size_t agent_count() const;

    // Map a session_id to an agent_id (called when Subscribe completes handshake).
    void map_session(const std::string& session_id, const std::string& agent_id);

    // Look up agent session by session_id (for heartbeat validation).
    std::shared_ptr<AgentSession> find_by_session(std::string_view session_id) const;

    // Get a session by agent_id (for scope evaluation).
    std::shared_ptr<AgentSession> get_session(const std::string& agent_id) const;

    // #3424/#3511: ids POSITIVELY known to lack `plugin`, for
    // dispatch_confined_arms's plugin-presence filter. One locked pass over
    // every session, same shape as all_ids() above. An agent with an EMPTY
    // plugin_names (never registered with a plugin list -- a fresh
    // registration race, a degraded AgentInfo, or any future caller that
    // legitimately omits it) is never included: absence of DATA is not
    // evidence of absence of the PLUGIN, and the caller-visible effect of a
    // false positive here (a dispatch silently withheld from a real, present
    // agent) is worse than the caller-visible effect of a false negative (the
    // pre-existing #3511 behaviour: the agent finds out itself, same as
    // today). plugin_names is populated once at register_agent from the
    // agent's self-reported inventory and never refreshed until the agent's
    // next re-register -- a plugin installed since is not visible here until
    // then; documented at the call site, not re-litigated per caller.
    std::unordered_set<std::string> ids_missing_plugin(std::string_view plugin) const;

    // Evaluate a scope expression against all agents, return matching agent IDs.
    // `rs_store` resolves the `from_result_set:<id>` scope kind (capability §30)
    // to per-device membership, scoped to `principal`: a referenced set that
    // `principal` does not own resolves to an empty membership and never matches
    // (no cross-operator targeting — review finding B1). Pass the dispatching
    // operator as `principal` on every command path. Leaving `rs_store` null
    // (with `principal` empty) is safe ONLY for a scope expression that
    // contains NO from_result_set: atom — that is a CALLER OBLIGATION, not an
    // invariant this function can supply: nothing filters the atom out of a
    // parsed expression, so a no-store call site whose expression might carry
    // one (e.g. an operator-authored rule scope) must treat nullopt as
    // "unresolvable here — match nothing" (governance H1, 2026-07-29).
    // Aliases must be pre-resolved
    // to canonical ids by the caller. A genuinely offline/decommissioned
    // agent (absent from BOTH the local live registry and — HA WS-5,
    // ADR-2002 §7a — cross-replica presence, when configured via
    // configure_presence) drops silently; an agent connected to a DIFFERENT
    // replica no longer drops merely for that reason — see
    // configure_presence's doc comment.
    //
    // Returns std::nullopt (ADR-0036 + 2026-07-26 B2 fail-closed contract,
    // widened per governance H1 2026-07-29, and again per ADR-0045) in FIVE
    // cases, all load-bearing:
    //   1. The from_result_set: membership preload hits a Postgres error
    //      mid-scan — NEVER a partial/degraded membership map.
    //   2. The expression references a from_result_set: atom but `principal`
    //      is empty — e.g. a dispatch path that recovers the principal from
    //      an execution row's `dispatched_by` and that lookup missed. A real
    //      store exists but there is no owner to resolve against.
    //   3. The expression references a from_result_set: atom but `rs_store`
    //      is null — the atom cannot be resolved AT ALL at this call site.
    //      (Previously this case silently evaluated the atom false; under a
    //      NOT combinator that inverted to a fleet-wide match — for a
    //      Guardian rule arming an enforcing guard, a fleet-wide arm.)
    //   4. The expression references a props.<key> atom but `props_store`
    //      is null (ADR-0045) — same "cannot resolve at all here" shape as
    //      case 3.
    //   5. The expression references a props.<key> atom and the bulk
    //      get_values_for_keys preload hits a Postgres error (ADR-0045) —
    //      same shape as case 1, for CustomPropertiesStore instead of
    //      ResultSetStore.
    // All five are the same fail-open shape: under a NOT combinator, an atom
    // that resolves "no match" silently INVERTS to "matches every agent" — a
    // fleet-wide dispatch/arm, not a theoretical hardening gap. Every caller
    // that dispatches/enforces/targets on this result MUST treat nullopt as
    // "abort — do not proceed" (dispatch paths) or "match nothing" (push
    // paths, where arming nothing is the safe direction). NARROW: a scope
    // with NEITHER a from_result_set: NOR a props.<key> atom is completely
    // unaffected — value_or({}) is safe there.
    std::optional<std::vector<std::string>>
    evaluate_scope(const yuzu::scope::Expression& expr, const TagStore* tag_store,
                   const CustomPropertiesStore* props_store = nullptr,
                   ResultSetStore* rs_store = nullptr, std::string_view principal = {}) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    std::unordered_map<std::string, std::string> session_to_agent_;
    EventBus& bus_;
    yuzu::MetricsRegistry& metrics_;

    /// HA WS-5 (ADR-2002 §7a). Non-owning; null = presence unconfigured
    /// (local-only behavior, unchanged from pre-WS-5). Set once via
    /// configure_presence during server wiring, read (without mu_ held — a
    /// Postgres round trip must never run under the same lock
    /// register_agent/send_to/evaluate_scope contend on) by all_ids() and
    /// evaluate_scope().
    OfflineEndpointStore* presence_store_{nullptr};
    std::chrono::seconds presence_ttl_{90};

    /// HA WS-5 governance hardening (Gate 3 performance + sre, 2026-09-22):
    /// a bare `presence_store_->query_live_ids(...)` on every all_ids()/
    /// evaluate_scope() call put a synchronous Postgres round trip on paths
    /// that were previously pure in-memory on EVERY deployment — presence is
    /// wired unconditionally at boot whenever `OfflineEndpointStore`
    /// constructs, not gated behind an HA/2nd-replica signal (none exists).
    /// This collapses arbitrarily many callers within `kPresenceCacheTtl` of
    /// each other into ONE Postgres query, on the SAME read-cache mutex
    /// (deliberately separate from `mu_` — the whole point of keeping the
    /// Postgres read off `mu_` is defeated if a second lock serializes it
    /// against that one instead). A `kPresenceCacheTtl`-stale read is
    /// harmless here specifically because presence is already an
    /// eventually-consistent, over-inclusion-safe signal (bounded by
    /// `presence_ttl_`, itself ~90s) — a few extra seconds of read staleness
    /// on top of that is a negligible relative addition, never a new
    /// correctness class. `live_presence()` is the ONLY caller of
    /// `presence_store_->query_live_ids`; all_ids()/evaluate_scope() must
    /// route through it, never call query_live_ids directly.
    static constexpr std::chrono::seconds kPresenceCacheTtl{3};
    mutable std::mutex presence_cache_mu_;
    mutable std::vector<PresenceIdentity> presence_cache_;
    mutable std::chrono::steady_clock::time_point presence_cache_at_{};

    /// Returns the cached (or freshly-fetched, if stale/first-call) live
    /// presence set. Empty immediately, no lock taken, when presence is
    /// unconfigured (`presence_store_ == nullptr`) — the common single-
    /// replica case pays only the pointer check.
    std::vector<PresenceIdentity> live_presence() const;

    std::mutex gw_pending_mu_;
    std::vector<GatewayPendingCmd> gw_pending_;

    /// #826 + W1.3 R2: trusted gateway peer-IPs → last_seen timestamp
    /// (steady_clock). Lookups are read-mostly (every Subscribe consults
    /// the map, inserts happen only on ProxyRegister success). Could be a
    /// `shared_mutex`, but the map is small (capped at
    /// `kTrustedGatewayCap`) and contention is negligible — keep a plain
    /// `mutex` for simplicity.
    ///
    /// Map (not set) so insert/refresh-on-existing-key updates the
    /// last_seen timestamp in-place, and stale entries can be swept by
    /// last_seen. Eviction policy: TTL (kTrustedGatewayTtl) at lookup
    /// time; opportunistic sweep on every insert; oldest-first eviction
    /// when at cap.
    mutable std::mutex trusted_gateway_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        trusted_gateway_peer_ips_;

    /// W1.3 R2: shared eviction-and-publish helper called by
    /// `note_trusted_gateway_peer`. Sweeps any entry older than
    /// kTrustedGatewayTtl, then if the map is at kTrustedGatewayCap
    /// removes the single oldest entry. Caller MUST hold
    /// `trusted_gateway_mu_`. Republishes the Prometheus gauge after the
    /// edit lands.
    void sweep_and_publish_trusted_gateway_locked();

    /// W1.5 / #823: optional device-token store used by `register_agent`
    /// to revoke stale tokens on re-registration. Guarded by `mu_` (set
    /// via `set_device_token_store`, read inside `register_agent`).
    ///
    /// Non-owning. `AgentRegistry` never constructs, destroys, or extends the lifetime of the
    /// pointee — the owner (test-scoped `DeviceTokenStore` instances only, today; the server's
    /// long-lived one once a wiring PR lands) MUST outlive this registry, or call
    /// `set_device_token_store(nullptr)` before its own destruction. There is NO production
    /// caller of `set_device_token_store` today (`server.cpp` never invokes it; the pointer stays
    /// `nullptr` in production, matching this store's own dormancy record). Once a wiring PR adds
    /// one, it MUST be one-time startup wiring, before any `register_agent` call can race it — a
    /// re-call mid-lifetime would need the same care `set_stream`/`clear_stream` already take
    /// around a session's raw pointers.
    DeviceTokenStore* device_token_store_{nullptr};

    /// Test-only, see `set_register_agent_interleave_hook_for_test`.
    std::function<void()> register_agent_interleave_hook_for_test_;
};

// -- Scope kind discovery catalog ---------------------------------------------
//
// One row per scope-expression ATTRIBUTE kind the `evaluate_scope` resolver
// (agent_registry.cpp, the `resolver` lambda inside the `agents_` loop) knows
// how to answer. Deliberately colocated with `evaluate_scope` rather than in
// the discovery module (`discover_routes.cpp`) so a reviewer touching the
// resolver sees this list in the same diff hunk / file.
//
// Does NOT cover the two GROUND kinds (`__all__`, `group:<name>`) — those are
// short-circuited by call sites BEFORE a scope expression ever reaches
// yuzu::scope::parse/evaluate (see docs/scope-walking-design.md §"Scope kind"
// and the `scope != "__all__"` guards in server.cpp / dashboard_routes.cpp),
// so they are never seen by this resolver and are listed separately by the
// discovery route.
//
// DRIFT CONTRACT: any NEW `if (key == ...)` / `key.starts_with(...)` branch
// added to the resolver lambda MUST get a matching entry here. The
// `test_discovery_routes.cpp` CROSS-CHECK test exercises `evaluate_scope` for
// every entry below (proving the enumerator is a SUBSET of what the resolver
// honors) and confirms a made-up kind resolves to no match (proving the
// resolver doesn't silently accept everything) — but it cannot detect a
// resolver branch that was added without a matching entry here. Keep both in
// sync by inspection when editing the resolver.
struct ScopeKindInfo {
    std::string kind;        ///< e.g. "tag:<key>"
    std::string syntax;      ///< e.g. "tag:<key> <op> <value>"
    std::string example;     ///< e.g. "tag:department == \"finance\""
    std::string description;
};

/// Every scope-expression ATTRIBUTE kind (post-ground-kind) the resolver
/// answers. Built once (static local) and cached; pure after construction.
const std::vector<ScopeKindInfo>& scope_kind_catalog();

// -- AgentHealthStore ---------------------------------------------------------
// Aggregates per-agent heartbeat status_tags into fleet-wide Prometheus metrics.

struct AgentHealthSnapshot {
    std::string agent_id;
    std::unordered_map<std::string, std::string> status_tags;
    std::chrono::steady_clock::time_point last_seen;
};

class AgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const google::protobuf::Map<std::string, std::string>& tags);

    void remove(const std::string& agent_id);

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness);

    /// Per-agent snapshots carrying ONLY the yuzu.perf_* heartbeat tags
    /// (dex_perf_rules.hpp keys) + agent_id, excluding entries staler than
    /// `staleness` (the same contract recompute_metrics prunes by — pass the
    /// same value so the /dex Performance read model and the Prometheus gauges
    /// see the same population). Deliberately NOT a general-purpose accessor:
    /// the copy runs under the heartbeat-upsert mutex, so it copies the
    /// minimum (G3 performance S1). Do NOT call on a hot path.
    std::vector<AgentHealthSnapshot> perf_snapshot(std::chrono::seconds staleness) const;

    /// Like perf_snapshot, but copies the NETWORK heartbeat facts
    /// (network_perf_rules.hpp kNetTag* keys) PLUS the perf tags the
    /// co-occurrence pressure check reads — the minimum the /network read model
    /// needs. Same staleness contract as recompute_metrics (pass the same value
    /// so the dashboard and the yuzu_fleet_net_* gauges see the same population).
    std::vector<AgentHealthSnapshot> net_snapshot(std::chrono::seconds staleness) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, AgentHealthSnapshot> snapshots_;

    /// C1: per-OS twin of recompute_metrics' four yuzu_fleet_perf_* exports —
    /// yuzu_fleet_perf_os_{reporting,cpu_pct,commit_pct,disk_lat_ms}{os[,stat]},
    /// cleared then rebuilt every sweep (absent-not-zero), mirroring the
    /// existing yuzu_fleet_net_*{os} pattern. Pure export over data
    /// recompute_metrics already accumulated — no snapshots_/mu_ access, so
    /// it's static. `*_os` maps are non-const: set_stats-style helpers sort
    /// their vector in place.
    static void recompute_perf_os_gauges(
        yuzu::MetricsRegistry& metrics,
        std::unordered_map<std::string, int>& reporting_os,
        std::unordered_map<std::string, std::vector<double>>& cpu_os,
        std::unordered_map<std::string, std::vector<double>>& commit_os,
        std::unordered_map<std::string, std::vector<double>>& disk_lat_os);
};

} // namespace yuzu::server::detail
