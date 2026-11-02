#pragma once

/// @file instruction_execute.hpp
/// The ONE copy of "execute a stored instruction DEFINITION" for the v1 REST twin
/// (`POST /api/v1/instructions/{id}/execute`, instruction_execute_routes.cpp) and the MCP
/// twin (`execute_instruction_definition`, mcp_instruction_execute.cpp). Ledger row
/// `post.api-instructions-param-execute` (#2146, ADR-1005 Decision 4).
///
/// WHY A SHARED CORE. The two surfaces differ only in transport (an A4 REST envelope versus a
/// JSON-RPC result), in how they authenticate and in the audit action they write. Everything
/// that decides WHO IS REACHED, WHAT RUNS and WHETHER A HUMAN MUST FIRST APPROVE is below, once.
/// A second copy is how the identical defect survives on one surface after the other is fixed
/// (the lesson dispatch_destructive_gate.hpp records for #3685).
///
/// This does NOT replace the legacy `POST /api/instructions/{id}/execute` handler in
/// workflow_routes.cpp, which keeps its own hand-written pipeline on purpose (the five
/// zero-reach cascades are likewise left alone, see dispatch_zero_reach.hpp).
///
/// PIPELINE, in order. Every deterministic refusal happens BEFORE the one step that creates a
/// human-visible ticket, so a refused call never queues an approval, mints a tier ticket or
/// creates an execution row:
///   1. definition lookup            store fault -> StoreUnavailable, absent -> NotFound
///   2. dispatch authorization       the shared chokepoint's dry run for (def.plugin, def.action)
///                                   (classify + RBAC + approval gate + kill switch) -> DispatchDenied
///   3. body shape                   a JSON object; `check_targeting_shape` on the PARSED body
///   4. stored parameter_schema      fail CLOSED on an unpreparable schema; reject a violation
///   5. destructive targeting        `evaluate_destructive_targeting` + `confine_destructive_targets`
///   6. the definition's approval_mode (NOT the tier ladder): see below
///   7. audit `requested`, FAIL CLOSED   -> nothing is dispatched without durable evidence
///   8. execution row (with `definition_id`), then ONE confined dispatch carrying
///      `def.id`/`def.concurrency_mode` (the ADR-1007 per-device claim is taken, and released for
///      every undelivered target, inside `wire_and_dispatch_confined`)
///   9. zero-reach -> `classify_zero_reach`; success -> targeted count + counters refresh
///
/// APPROVAL COMPOSITION (owner ruling, 2026-10-30; the binding security rule). The definition's
/// own `approval_mode` is evaluated FIRST and INDEPENDENTLY of any MCP tier mechanism. An
/// operator-tier token's auto-approval and a supervised-tier ticket that C8 consumed are TIER
/// facts about the caller; neither is an input to this module, and `Request` deliberately has no
/// field through which one could arrive (`Request::expected_effect` is not one: it carries the
/// effect a ticket was bound to, never an approval). `auto` dispatches; `always` and any unknown value
/// (fail closed) need approval; `role-gated` needs approval unless the caller is an effective
/// administrator (`DispatchCaller::principal_is_admin`, JIT-elevation aware). A call that needs
/// approval is answered `PendingApproval` and dispatches NOTHING. There is no redemption path
/// for such a ticket: it is minted with `ApprovalOrigin::kInstruction`, which the MCP recall
/// refuses (`origin_redeemable_as`), and no interactive redemption exists. Such a ticket records
/// the definition, the scope expression and the resolved `target_plugin`/`target_action` ONLY: it
/// does NOT approve explicit `agent_ids` or `params`
/// (they are not stored with it), so any future redemption must bind them (a bound request,
/// `ApprovalManager::submit_bound`) before it ships. An administrator
/// still reaches `role-gated` definitions because the token or session carries the creator's
/// role: that is a ROLE fact, not a tier fact.
///
/// DispatchCaller CONSTRUCTION. This module never builds a `DispatchCaller`: the surface hands
/// one in, derived from its own session (REST: `caller_from_session`; MCP: `caller_fn`). The only
/// field it reads that carries approval authority is `principal_is_admin`, and it never writes
/// `approval_provenance`; NO adapter stamps `Ticket` for this capability, REST or MCP (sec-F1,
/// kept as a policy line: the MCP ticket binds the resolved plugin/action since L1, but the
/// pair comes from a stored definition, not from the caller's own arguments, so the ticket
/// never lifts the pair's ExecuteGate; dispatch_caller.hpp, stamping site 2 excludes this tool).
///
/// Everything impure arrives through `Ports` so the pipeline is testable without Postgres
/// (InstructionStore, ApprovalManager and ExecutionTracker are all Postgres-backed).

#include "agent_registry.hpp"            // detail::DispatchDenial
#include "command_capability.hpp"        // CommandCapability / ClassificationError
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp"    // ConfinedDispatchOutcome
#include "dispatch_zero_reach.hpp"       // ZeroReachCause
#include "event_emit_hook.hpp"           // EventEmitHook (request-free: no DIRECT <httplib.h> include)
#include "instruction_param_schema.hpp"  // instr::ParamValidatorCache
#include "instruction_store.hpp"         // InstructionDefinition

#include <yuzu/log_token.hpp> // utf8_sequence_length (definition_id_is_invalid_utf8)

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::instruction_execute {

enum class Surface : std::uint8_t { kRest, kMcp };

/// One principal's share of the global pending-approval queue (`ApprovalManager::
/// kMaxPendingApprovals`, 1000). ONE constant for every surface that creates a pending approval
/// on a principal's behalf: REST `POST /api/v1/instructions/{id}/execute`, MCP
/// `execute_instruction_definition` and the MCP C8 ticket mint. An agentic loop (or a script)
/// must not be able to fill the cap it shares with every human and every schedule.
inline constexpr int kSubmitterPendingCap = 25;

/// `reason` label of `yuzu_server_approval_submit_refused_total`, and the same token the audit
/// row and the wire `reason` carry. CLOSED set, every member pre-seeded at boot in server.cpp from
/// this array. `approval_cap_reached` is the per-principal cap above; `approval_unavailable` is
/// "no approval manager wired" (or a cap requested with its counter unwired: a server defect,
/// 503 with a null `retry_after_ms`) and also "the pending count could not be read" (a store
/// fault: 503 with `retry_after_ms` 5000);
/// `approval_queue_full` is the GLOBAL 1000-row pending queue being full (nobody can submit
/// until a human reviewer decides a pending approval or the 7-day expiry clears one: a retry
/// loop cannot help, so it carries no `retry_after_ms`); `approval_submit_failed` is any other
/// store fault refusing the row (retryable). Only refusals at the approval-submit step count: a
/// refusal earlier in `prepare` (targeting, params, gate) creates no approval and counts under
/// its own family.
inline constexpr char kApprovalRefusedMetric[] = "yuzu_server_approval_submit_refused_total";
inline constexpr char kReasonApprovalCapReached[] = "approval_cap_reached";
inline constexpr char kReasonApprovalUnavailable[] = "approval_unavailable";
inline constexpr char kReasonApprovalSubmitFailed[] = "approval_submit_failed";
inline constexpr char kReasonApprovalQueueFull[] = "approval_queue_full";
inline constexpr std::array<std::string_view, 4> kApprovalRefusedReasons{
    kReasonApprovalCapReached, kReasonApprovalUnavailable, kReasonApprovalSubmitFailed,
    kReasonApprovalQueueFull};

/// `route` label of `yuzu_server_dispatch_target_rejected_total` and
/// `yuzu_server_instruction_param_rejected_total` for a surface. Both are pre-seeded in
/// server.cpp / seed_instruction_param_rejected_metrics. REST shares the legacy route's label
/// because it is the same capability; MCP shares `execute_instruction`'s `mcp` label.
[[nodiscard]] constexpr std::string_view route_label(Surface s) noexcept {
    return s == Surface::kRest ? "instruction_execute" : "mcp";
}

/// `surface` label of `yuzu_exec_tracker_bookkeeping_failed_total` (pre-seeded: rest, mcp).
[[nodiscard]] constexpr std::string_view bookkeeping_label(Surface s) noexcept {
    return s == Surface::kRest ? "rest" : "mcp";
}

/// What the surface asks for. `body` is the request JSON: REST its parsed body, MCP its
/// `arguments` object minus control-plane keys. Keys read: `agent_ids`, `scope`, `params`.
struct Request {
    Surface surface{Surface::kRest};
    std::string definition_id;
    nlohmann::json body;
    /// The caller, fully derived by the surface. `principal` is the audit/approval identity,
    /// `exec_visible` the confinement set, `principal_is_admin` the role-gated bypass.
    DispatchCaller caller;
    /// 0 = no cap. Every production surface sets `kSubmitterPendingCap`: it bounds one principal's
    /// share of the global pending approval queue (an agentic loop or a script must not fill the
    /// cap shared with every human). Only a test leaves it 0.
    int submitter_pending_cap{0};
    /// The ONE correlation id of this call. Every audit row the core writes for the call
    /// (`denied`, `requested`, `pending`, `success`, `failure`) carries it as the trailing
    /// `correlation_id=<id>` detail token, the same spelling `POST /api/v1/commands` uses, so an
    /// orphan `requested` row can be paired with its outcome row and with the error body the
    /// caller saw. A surface passes the id it already put on its response (REST: the
    /// `X-Correlation-Id` header; MCP: the same header, shared by the pre-mint probe and the
    /// handler, so one call is one id). Empty -> the core mints one; either way the id used comes
    /// back in `Outcome::correlation_id` / `PrepareOutcome::correlation_id`.
    std::string correlation_id;
    /// MCP supervised tier only (#2146, L1). The `effect_binding()` text the C8 approval ticket
    /// was minted over; engaged only on the call that is about to spend that ticket. The core
    /// recomputes the binding from the definition it looks up (step 1) and, if it differs,
    /// refuses with `definition_changed` BEFORE the authorizer, any row or any dispatch. This
    /// closes the window between the recall's pre-consume probe and this call's own fresh
    /// lookup: the definition dispatched is the definition the human approved, or nothing runs.
    /// Unset (REST, operator tier, the probe itself) = no binding to hold the lookup to.
    std::optional<std::string> expected_effect;
};

using DefinitionLookup = std::expected<std::optional<InstructionDefinition>, std::string>;

/// What the result-set producers bind when the stored definition cannot be resolved at all
/// (empty or oversize id, absent or not-owned set, unsupported source kind, missing definition).
/// It can never equal an `effect_binding()` result, so state that later becomes resolvable is
/// refused rather than run; the producer's own handler refuses the unresolvable cases itself.
inline constexpr std::string_view kUnresolvedEffect = "effect=unresolved\n";

/// The effect-bearing part of a resolved definition, as the text a supervised-tier approval
/// ticket binds in front of the call's canonical arguments (#2146, ADR-0033 section 10: an
/// approval binds to the effect, not to a name that can be repointed). `effect=` + a compact
/// JSON array of (plugin, action, approval_mode, concurrency_mode) + one `\n`. JSON, so a
/// hostile or odd stored value cannot forge a field boundary or inject a control byte; the
/// array is FIRST in the ticket text because the approvals table clips the scope cell to 120
/// bytes and the reviewer must see what will run. Deliberately NOT a content hash and NOT
/// `version`/`updated_at`: a comment or schema edit that leaves the effect alone must not
/// invalidate an approval, and repointing the definition BACK restores it. Parameter values are
/// not part of it: `Plan::params` is the supplied params verbatim (no defaults are applied), and
/// they are already in the ticket's canonical arguments. A caller with no concurrency mode (the
/// result-set producers dispatch by pair only) passes empty strings for the last two.
[[nodiscard]] std::string effect_binding(std::string_view plugin, std::string_view action,
                                         std::string_view approval_mode,
                                         std::string_view concurrency_mode);

/// What gets persisted as the execution row; the production binding fills an `Execution`.
struct ExecutionRow {
    std::string definition_id;
    std::string scope_expression;
    std::string parameter_values; ///< REDACTED copy (sensitive_instruction_params.hpp)
    std::string dispatched_by;
};

using DispatchFn = std::function<ConfinedDispatchOutcome(
    const std::string& plugin, const std::string& action,
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const std::unordered_map<std::string, std::string>& parameters,
    const std::string& execution_id, const DispatchCaller& caller,
    const std::string& definition_id, const std::string& concurrency_mode)>;

/// Per request, bound by the surface (it owns the audit action and target).
/// `result` is one of "denied", "failure", "pending", "requested", "success". Returns whether
/// the row persisted. Never throws (the core also guards it).
using AuditHook = std::function<bool(std::string_view result, const std::string& detail)>;

/// Why an approval submit failed, as much as the surface needs to answer it truthfully: a full
/// global queue is not a store fault (only a reviewer or the expiry clears it).
struct ApprovalSubmitError {
    bool queue_full{false};
    std::string message;
};

struct Ports {
    /// Unset reads as "store unavailable".
    std::function<DefinitionLookup(const std::string&)> lookup_definition;
    /// Required (the cache is shared with the legacy route in production). NOT owned: in
    /// production the pointee is `ServerImpl::param_validator_cache_`, a member declared BEFORE
    /// `web_server_`, and `ServerImpl::stop()` halts the web server (so no handler holding these
    /// ports can still run) before any member is destroyed.
    instr::ParamValidatorCache* validators{nullptr};
    /// The destructive-targeting classifier. Unset -> `ClassifierUnavailable` (fail closed).
    std::function<std::expected<CommandCapability, ClassificationError>(std::string_view,
                                                                         std::string_view)>
        classify;
    /// The chokepoint dry run. Unset -> `Misconfigured` (fail closed, never "no gate").
    std::function<std::expected<CommandCapability, detail::DispatchDenial>(
        const DispatchCaller&, std::string_view, std::string_view)>
        authorize;
    /// `ApprovalManager::submit(def, user, scope, "", kInstruction, plugin, action)`. Unset means
    /// there is no approval manager: a non-auto definition then answers `ApprovalUnavailable`.
    std::function<std::expected<std::string, ApprovalSubmitError>(
        const std::string& definition_id, const std::string& submitted_by,
        const std::string& scope_expression, const std::string& plugin, const std::string& action)>
        submit_approval;
    /// `ApprovalManager::pending_count_for_checked`; only consulted when `submitter_pending_cap
    /// > 0`. `nullopt` = the count could not be read: the cap then REFUSES (503
    /// `approval_unavailable`, a retryable store fault), it never reads as zero and admits.
    std::function<std::optional<int>(const std::string&)> pending_count_for;
    /// `ManagementGroupStore::get_visible_agents`. nullopt = absent or degraded = FAIL CLOSED
    /// (the opposite of `authz::VisibleSet`'s nullopt, see DestructiveVisibleAgents).
    std::function<std::optional<std::vector<std::string>>(const std::string&)> visible_agents;
    /// Execution ledger. Unset `create_execution` = no tracker: dispatch runs with an empty id.
    std::function<std::optional<std::string>(const ExecutionRow&)> create_execution;
    std::function<bool(const std::string& id, const std::string& user)> mark_cancelled;
    std::function<bool(const std::string& id, int agents)> set_agents_targeted;
    std::function<void(const std::string& id)> refresh_counts;
    DispatchFn dispatch;
    /// NOT owned: null (counting off) or `ServerImpl::metrics_`, a member that outlives the web
    /// server for the same reason as `validators` above (`stop()` halts it before member
    /// destruction).
    yuzu::MetricsRegistry* metrics{nullptr};
};

enum class RefusalKind : std::uint8_t {
    kStoreUnavailable,     ///< 503: the definition store is unavailable or errored
    kNotFound,             ///< 404: no such definition
    kBadRequest,           ///< 400: body type, targeting shape, params violation, untargeted destructive
    kNoVisibleTarget,      ///< 404: a destructive pair whose named targets are all out of scope
    kDispatchDenied,       ///< the chokepoint dry run refused; see Refusal::denial
    kSchemaInvalid,        ///< 500: the stored parameter_schema cannot be prepared (fail closed)
    kApprovalUnavailable,  ///< 503: no approval manager (a server defect: NO retry hint), or the pending count
                           ///< could not be read (a store fault: retryable)
    kApprovalSubmitFailed, ///< 500: the approval store could not take the ticket (a store fault; retryable)
    kApprovalQueueFull,    ///< 503: the global pending queue is full (only a reviewer or the expiry clears it: NO retry hint)
    kApprovalCapReached,   ///< 429-class: this principal already holds the cap of pending approvals
    kClassifierUnavailable,///< 503: the destructive-targeting classifier is not wired
    kMisconfigured,        ///< 500: a required port is unwired (a server defect: NO retry hint, ever)
    kAuditUnavailable,     ///< 503 + Sec-Audit-Failed: nothing was dispatched without durable evidence
    kDispatchFailed,       ///< 500: the dispatch threw (any exception type); the execution row (if any) is left
                           ///< `running` (NOT cancelled: agents may hold the command), a `failure` audit row is
                           ///< written, and NO retry is advertised (agents may have been sent it)
};

struct Refusal {
    RefusalKind kind{RefusalKind::kBadRequest};
    /// Closed token for audit and the wire `reason` ("" when none applies).
    std::string reason;
    std::string message;
    std::string remediation;
    /// Honest retry hint in ms; nullopt = not retryable (the wire carries null).
    std::optional<int> retry_after_ms;
    /// Engaged for kDispatchDenied.
    std::optional<detail::DispatchDenial> denial;
    /// The definition's pair, set with `denial`: the denial text names it ("approval required
    /// for testplug.gated"), so the renderers must not pass empty strings.
    std::string plugin;
    std::string action;
    /// Set for kDispatchFailed only (a dispatch that THREW): the execution row the call left
    /// running ("" when no row exists) and the lower-bound count of agents the sink counted an
    /// accepted send to before the throw (0 = none known). Both surface as typed fields on the wire
    /// (REST `error.execution_id` / `error.agents_sent`, MCP `error.data` likewise), exactly as
    /// POST /api/v1/commands does, so a caller reads them without parsing the remediation prose.
    std::string execution_id;
    int agents_sent{0};
};

struct PendingApproval {
    std::string approval_id;
    std::string approval_mode;
    std::string definition_id;
};

struct Dispatched {
    std::string command_id;
    std::string execution_id;
    int agents_reached{0};
    std::string definition_id;
    std::string plugin;
    std::string action;
};

struct ZeroReach {
    ZeroReachCause cause{ZeroReachCause::Generic};
    std::string command_id;
    std::string execution_id;
    std::string message;
    std::string definition_id;
    std::string plugin;
    std::string action;
    std::size_t agents_quarantined{0};
    std::size_t agents_unknown_plugin{0};
    std::size_t agents_kill_switched_os{0};
};

struct Outcome {
    std::variant<Refusal, PendingApproval, Dispatched, ZeroReach> result;
    /// True when a row the core wrote best-effort (a denial, the pending row, the final row)
    /// did not persist. The surface reports it (REST: `Sec-Audit-Failed`; MCP:
    /// `audit_persisted:false`). The fail-closed `requested` row is a Refusal instead.
    bool audit_dropped{false};
    /// The correlation id stamped on every row this call wrote (see `Request::correlation_id`).
    /// A surface renders its error body with THIS value so the body joins the rows.
    std::string correlation_id{};
};

/// What `prepare` hands to the dispatch stage.
struct Plan {
    InstructionDefinition def;
    std::vector<std::string> agent_ids;
    std::string scope; ///< the caller's scope expression; empty when none was named
    std::unordered_map<std::string, std::string> params;
};

struct PrepareOutcome {
    std::variant<Refusal, PendingApproval, Plan> result;
    bool audit_dropped{false};
    std::string correlation_id{}; ///< see `Outcome::correlation_id`
};

/// Steps 0-6. Writes an audit row for a refusal from step 0 on (`denied`, or `failure` for an
/// unusable stored schema or an approval that could not be queued) and for a pending approval:
/// an unknown definition writes `denied reason=not_found`. It writes NO `instruction.execute`
/// row for a definition-store fault (step 1), a missing port (an unwired lookup, authorizer,
/// validator cache or classifier), or the classifier being unavailable: only `requested` (step 7)
/// is guaranteed before the effect. Every row carries `correlation_id=` (`Request::correlation_id`).
/// MCP calls this alone as its pre-mint probe, so a refused call mints no tier ticket.
///
/// `emit` (optional, bound per request by the surface) publishes the events the LEGACY
/// `POST /api/instructions/{id}/execute` publishes, so the twins match it: `approval.created`
/// when this call created the pending approval (once, at the creation, so an MCP probe that
/// answers `pending_approval` and a REST call emit exactly one each), and `instruction.executed`
/// when a dispatch reached at least one agent. Both with null attributes and payload, as the
/// legacy route does. A refusal, a zero-reach and a throwing dispatch emit nothing. Best effort,
/// after the audit row; it can never change the outcome.
[[nodiscard]] PrepareOutcome prepare(const Request& rq, const Ports& ports, const AuditHook& audit,
                                     const EventEmitHook& emit = {});

/// Steps 1-9.
[[nodiscard]] Outcome run(const Request& rq, const Ports& ports, const AuditHook& audit,
                          const EventEmitHook& emit = {});

/// Longest definition id (bytes) that is ever written to an audit row (`target_id`, `definition=`)
/// or a log line. The REST route's id is the raw `([^/]+)` path capture (kilobytes), the MCP tool
/// already refuses more than this; the definition is still LOOKED UP by the raw id.
inline constexpr std::size_t kAuditDefinitionIdMax = 128;

/// `id` bounded for audit and logs: at most `kAuditDefinitionIdMax` bytes, cut on a UTF-8 code
/// point boundary (a character that straddles the limit is dropped whole, never half kept), with
/// "..." appended when anything was cut. NOT neutralised: the `target_id` column keeps the id
/// as-is; a value embedded in a `key=value` detail line still goes through `log_token`.
[[nodiscard]] std::string bounded_definition_id(std::string_view id);

/// True when `id` holds a byte below 0x20 or equal to 0x7F (NUL included). Such an id is refused
/// (`invalid_definition_id`, 400 / -32602) before the store is read: the Postgres binding passes
/// the id as a C string, so `"foo\0xyz"` would resolve the definition `foo` while every audit row
/// and log line records a different string. Use `definition_id_is_malformed` for the full step-0
/// test; this is its control-byte half.
[[nodiscard]] constexpr bool definition_id_has_control_byte(std::string_view id) noexcept {
    for (const char ch : id) {
        const auto b = static_cast<unsigned char>(ch);
        if (b < 0x20 || b == 0x7F)
            return true;
    }
    return false;
}

/// True when `id` is not well-formed UTF-8 in the sense PostgreSQL's UTF8 encoding accepts (no
/// overlong forms, no surrogates, nothing above U+10FFFF, no truncated sequence). The route's path
/// capture is percent-decoded by httplib, so `%C0%80` or `%FF` arrive as raw bytes; handed to the
/// store they raise SQLSTATE 22021, which would read as a retryable 503 `store_unavailable` for an
/// input that can never succeed. Reuses `yuzu::utf8_sequence_length` (log_token.hpp), the documented
/// copy of the rules whose server-side original is utf8_sanitize.hpp; this adds no UTF-8 logic of
/// its own.
[[nodiscard]] inline bool definition_id_is_invalid_utf8(std::string_view id) noexcept {
    for (std::size_t i = 0; i < id.size();) {
        if (static_cast<unsigned char>(id[i]) < 0x80) {
            ++i;
            continue;
        }
        const std::size_t len = ::yuzu::utf8_sequence_length(id, i);
        if (len == 0)
            return true;
        i += len;
    }
    return false;
}

/// The step-0 predicate: the id holds a control byte OR is not well-formed UTF-8. Such an id is
/// refused (`invalid_definition_id`, 400 / -32602) before ANY store read. One predicate, used by
/// the shared core (and the REST route's audit target cleaning) only, so REST and MCP cannot
/// drift. A valid multibyte id (U+00E9, CJK, ...) is NOT malformed and goes to the lookup.
[[nodiscard]] inline bool definition_id_is_malformed(std::string_view id) noexcept {
    return definition_id_has_control_byte(id) || definition_id_is_invalid_utf8(id);
}

/// True when `id` holds a code point `yuzu::log_token` folds that is NOT refused at step 0: a C1
/// control (U+0080..U+009F, `C2 80`..`C2 9F`), U+2028 or U+2029 (`E2 80 A8` / `E2 80 A9`).
/// Meaningful for a well-formed id (a malformed one is caught by `definition_id_is_malformed`
/// first). Such an id stays VALID: it reaches the lookup (and, if absent, `not_found`) exactly as
/// today. This predicate exists ONLY so the REST route's audit `target_id` cleaning can fold it
/// the way the `definition=` detail token is already folded; it must NOT be added to step 0.
[[nodiscard]] inline bool definition_id_has_log_folded_codepoint(std::string_view id) noexcept {
    for (std::size_t i = 0; i + 1 < id.size(); ++i) {
        const auto c = static_cast<unsigned char>(id[i]);
        const auto c1 = static_cast<unsigned char>(id[i + 1]);
        if (c == 0xC2 && c1 <= 0x9F)
            return true;
        if (c == 0xE2 && c1 == 0x80 && i + 2 < id.size()) {
            const auto c2 = static_cast<unsigned char>(id[i + 2]);
            if (c2 == 0xA8 || c2 == 0xA9)
                return true;
        }
    }
    return false;
}

/// The REST route's audit `target_id` predicate: the id is malformed (step-0 refusal) OR holds a
/// code point `log_token` folds. A normal id is neither, so its `target_id` stays byte-identical
/// to the id. Used ONLY by the route's target cleaning, never by step 0.
[[nodiscard]] inline bool definition_id_needs_audit_fold(std::string_view id) noexcept {
    return definition_id_is_malformed(id) || definition_id_has_log_folded_codepoint(id);
}

/// The `denied` row for a refusal that happens BEFORE the core runs and so before it could stamp
/// one itself: today the REST route's body-too-deep and unparseable-JSON refusals (the MCP twin's
/// equivalents are its argument-bound refusals, written by the MCP adapter with the same
/// `correlation_id=` token). Detail is `reason=<reason> definition=<id> correlation_id=<id>`, each
/// value through `log_token` (CWE-117). Returns whether the row persisted (a hook that throws
/// reads as not persisted); the caller reports a lost row the way the core's own best-effort rows
/// are reported (REST `Sec-Audit-Failed`).
[[nodiscard]] bool audit_pre_core_denial(const AuditHook& audit, std::string_view correlation_id,
                                         std::string_view reason, std::string_view definition_id);

/// The approval verdict for a definition, factored so tests pin the matrix without a store.
/// `approval_mode` is the stored string; `caller_is_admin` is `principal_is_admin`.
[[nodiscard]] bool definition_needs_approval(std::string_view approval_mode,
                                             bool caller_is_admin) noexcept;

} // namespace yuzu::server::instruction_execute
