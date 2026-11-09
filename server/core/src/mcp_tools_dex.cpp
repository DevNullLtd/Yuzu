// Registry-resident DEX score policy tools (see mcp_tool_registry.hpp): the MCP twins of
// GET / PUT / DELETE /api/v1/dex/score-policy (#6087). Three tools, `get_dex_score_policy`,
// `set_dex_score_policy` and `reset_dex_score_policy`, over the one customer score policy
// document (runtime-config key kDexScorePolicyKey).
//
// ONE write path. Both writes go through `apply_dex_score_policy` (dex_score_policy_writer.hpp)
// via the single forwarding closure ToolDeps::dex_score_policy_apply_fn, the same function the
// REST PUT and DELETE call: no second validator, no second If-Match parser, no second audit-row
// shape. The pure argument / status / payload logic is dex_score_policy_mcp.hpp.
//
// Posture, which differs from REST in the places named here:
//   * get_dex_score_policy is readable at every tier (GuaranteedState:Read, a fleet-wide
//     configuration read: no per-agent data, so no domain audit row, as for REST GET).
//   * set_dex_score_policy and reset_dex_score_policy are supervised-tier only
//     (tier_allows refuses Infrastructure Write / Delete below it). The gates are the LOUD pair
//     tier_allows + ctx.perm_fn (never probe_permission): Infrastructure:Write (Delete for
//     reset) and THEN GuaranteedState:Read, because the answer carries the application names
//     the policy lists. REST PUT / DELETE gate only Infrastructure:Write.
//   * reset is registered as the DISTINCT operation Infrastructure:Delete so the generic
//     supervised "Delete needs an approval ticket" rule applies (the delete_plugin_config /
//     delete_result_set mechanism); MCP is therefore stricter than REST DELETE, which needs
//     Infrastructure:Write only. set is NOT approval-gated (Infrastructure:Write, like
//     set_runtime_config). The ticket gates this MCP tool, not the capability: the same
//     supervised token can DELETE over REST with Infrastructure:Write alone and no ticket, and
//     set stores any valid document without one (an accepted residual, ADR-1005 2026-11-09).
//     The ticket is consumed BEFORE the handler runs, so any failure after
//     that point spends it: the remediation says so and how to recover (the one exception is a
//     refusal by the handler's own perm_fn gate, whose 403 body is the gate's; the tool
//     description says that spends the ticket too).
//   * deny_mcp_token_session is deliberately absent: the REST routes admit MCP-tier tokens and
//     this twin exists to serve them.
//
// Audit. apply writes the `attempted` row itself before it touches the store and fails closed
// when that row is refused (no audit row, no mutation); stricter than REST, an UNWIRED session
// or session-bound audit writer is refused here too. apply discards the result of every later
// row, so the per-request hook below records whether any row was dropped, and the answer
// reports it as `audit_persisted:false` (success body) or through the A4 error's audit flag.
// That is the MCP equivalent of REST's Sec-Audit-Failed header.
//
// Attribution. A write resolves the caller's session ONCE (ToolDeps::session_fn) and stamps
// every DOMAIN row (dex.score_policy.*) and the stored `updated_by` from it through the
// session-bound writer (ToolDeps::audit_as_session_fn), exactly as REST PUT/DELETE bind their
// rows (audit_as, #6065 PR-Q): a credential that lapses mid-request cannot leave a row naming
// no one while the write proceeds. The generic `mcp.<tool>` row is the dispatcher's
// (mcp_server.cpp), outside this file, and is resolved per row.
//
// ONE handler per tool, never a shared one: the A5 retry-hint gate
// (scripts/ci/check-mcp-retry-hints.py) scans each tool's own handler body. Three shared
// helpers answer outside a handler, and all are non-retryable by design, each marked
// `// retry-hint-exempt:` on its a4_error line: refuse_params (a caller-input rejection),
// tier_admits (the token's tier never changes) and writer_identity (an unwired closure is a
// misconfiguration; an unresolved caller is a credential that no longer resolves, revoked or
// lapsed mid-request; neither is retryable as sent). Every retryable answer lives inside a
// handle_* body.

#include "mcp_tool_registry.hpp"

#include "dex_score_policy_mcp.hpp"  // the pure half: request, code, success payload
#include "mcp_jsonrpc.hpp"           // kInvalidParams, kInternalError, kTierDenied, success_response
#include "mcp_policy.hpp"            // tier_allows
#include "mcp_tool_deps.hpp"         // ToolDeps (provider closures)
#include "mcp_tool_helpers.hpp"      // answer, answer_unwired, dump_replace (shared by the registry files)
#include "rest_audit.hpp"            // detail::try_persist_audit (the shared audit kernel)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/server/auth.hpp> // auth::Session, effective_role, role_to_string

#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {
namespace {

// Typed output schemas, mirroring the OpenAPI DexScorePolicyData keys (rest_api_v1.cpp). The
// three tools share the in-force triple; the writes add previous_revision, dry_run and the
// audit flag.
constexpr const char* kGetOutputSchema =
    R"j({"type":"object","properties":{)j"
    R"j("document":{"type":"object","description":"The policy in force, in the stored shape: version, tiers.edges, tiers.names, weights, model (only when a parameter is in use), overrides"},)j"
    R"j("revision":{"type":"string","description":"16 lower-case hex digits, or 'default' when nothing is stored; send it as if_match on a write"},)j"
    R"j("source":{"type":"string","enum":["default","custom"],"description":"custom when a stored document is in force, default for the shipped defaults"},)j"
    R"j("fault":{"type":"string","description":"Present only when a stored document was refused and the shipped defaults are served: why"})j"
    R"j(},"required":["document","revision","source"]})j";

constexpr const char* kWriteOutputSchema =
    R"j({"type":"object","properties":{)j"
    R"j("document":{"type":"object","description":"The policy now in force (a dry run: the policy that would be), in the stored shape"},)j"
    R"j("revision":{"type":"string","description":"The revision now in force (a dry run: the revision a real set would produce)"},)j"
    R"j("source":{"type":"string","enum":["default","custom"],"description":"custom when a stored document is in force, default for the shipped defaults"},)j"
    R"j("fault":{"type":"string","description":"Present only when the shipped defaults are served because a stored document was refused"},)j"
    R"j("previous_revision":{"type":"string","description":"The revision the store held when the write was checked; 'default' when none"},)j"
    R"j("dry_run":{"type":"boolean","description":"Present and true only on a dry run: nothing was stored"},)j"
    R"j("audit_persisted":{"type":"boolean","description":"Present and false only when an audit row after the change failed to persist; the change stands"})j"
    R"j(},"required":["document","revision","source","previous_revision"]})j";

/// Carried by every reset refusal or failure the handler answers after the ticket is consumed:
/// the generic gate consumed the approval ticket before the handler ran (mcp_server.cpp), so a
/// repeat with the same approval_id is refused. The remediation of a reset error that already
/// has one gets it after a "; ".
constexpr std::string_view kResetTicketSpentNote =
    "the approval ticket this call consumed is spent: read the policy with "
    "get_dex_score_policy, compare its revision with the one named here (or with your if_match "
    "when none is named), then submit a new request without approval_id for a fresh ticket";

/// Remediation for an argument-shape refusal (get, set and reset); reset appends the
/// spent-ticket note to it.
constexpr std::string_view kBadArgsRemediation = "correct the arguments and call again";

/// A caller-input refusal judged before apply runs: the generic `mcp.<tool>|denied` row, then
/// the A4 envelope (-32602, non-retryable) with `remediation` and the row's persistence flag.
void refuse_params(const ToolCallContext& ctx, const std::string& message,
                   std::string_view remediation) {
    const bool audited = ctx.audit("denied", "invalid arguments: " + message);
    answer(ctx, ctx.a4_error(kInvalidParams, message, remediation, -1, {}, audited)); // retry-hint-exempt: caller-input rejection
}

/// The handler's own tier check (the generic C8 gate has already run; this is the defence in
/// depth every registry handler repeats). False = the answer is written.
bool tier_admits(const ToolCallContext& ctx, const char* securable, const char* operation) {
    if (tier_allows(ctx.tier, securable, operation))
        return true;
    (void)ctx.audit("denied", "tier does not allow this operation");
    answer(ctx, ctx.a4_error(kTierDenied, "MCP tier does not allow this operation",
                             kTierRemediation, -1, {}, true)); // retry-hint-exempt: the token's tier never changes
    return false;
}

/// The caller as a write binds it: the session resolved ONCE and its effective role read once
/// (a JIT elevation that lapses between two rows cannot make them disagree), the same pair
/// REST's audit_as captures.
struct WriterIdentity {
    auth::Session session;
    std::string role;
};

/// One request's domain-audit hook for apply_dex_score_policy: writes every row through the
/// session-bound writer (`who`, resolved once) and records, in `persisted`, whether ANY row of
/// this request was dropped. The returned callable borrows `ctx`, `who` and `persisted` and
/// lives for one call only. A throwing writer is caught by the shared kernel and counts as a
/// dropped row.
ToolDeps::DexScorePolicyAuditFn audit_hook(const ToolCallContext& ctx, const WriterIdentity& who,
                                           bool& persisted) {
    return [&ctx, &who, &persisted](std::string_view verb, std::string_view result,
                                    const std::string& detail_json) {
        // The kernel takes the bool(req, 5 strings) shape every route class shares; the session
        // and role are bound here, as RestApiV1's audit_as binds them. A std::function, not a
        // bare lambda: the kernel null-checks its sink (`!audit_fn`), which a capturing lambda
        // cannot answer.
        const std::function<bool(const httplib::Request&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&)>
            bound = [&](const httplib::Request& req, const std::string& action,
                        const std::string& outcome, const std::string& target_type,
                        const std::string& target_id, const std::string& detail) {
                return ctx.deps->audit_as_session_fn(req, who.session, who.role, action, outcome,
                                                     target_type, target_id, detail);
            };
        const bool ok = yuzu::server::detail::try_persist_audit(
            bound, ctx.req, std::string(verb), std::string(result), "RuntimeConfig",
            std::string(kDexScorePolicyKey), detail_json);
        if (!ok)
            persisted = false;
        return ok;
    };
}

/// The preamble the two write handlers share, run after the arguments parse and before any
/// row: the apply closure, the session resolver and the session-bound audit writer must be
/// wired (an unwired writer would be called "persisted" by the kernel, so it is refused here;
/// stricter than REST, which treats an empty sink as audit-off: "no audit row, no mutation")
/// and the caller's session must resolve with a username (it would name no one). Either
/// refusal is answered here and yields nullopt; otherwise the identity every row and the
/// stored `updated_by` are stamped from. The answer is answer_unwired's shape (the generic
/// failure row, no retry hint, no data), written here because answer_unwired carries no
/// remediation: `remediation` is empty for set, and for reset the spent-ticket recovery, since
/// its approval ticket was consumed before the handler ran and these refusals spend it too.
std::optional<WriterIdentity> writer_identity(const ToolCallContext& ctx, std::string_view tool,
                                              std::string_view remediation) {
    const auto refuse = [&](const std::string& detail, const std::string& log) {
        spdlog::error("{}", log);
        const bool audited = ctx.audit("failure", detail);
        answer(ctx, ctx.a4_error(kInternalError, "service unavailable", remediation, -1, {}, audited)); // retry-hint-exempt: an unwired closure is a misconfiguration and an unresolved caller a credential that no longer resolves; neither is retryable as sent
    };
    if (ctx.deps == nullptr || !ctx.deps->dex_score_policy_apply_fn ||
        !ctx.deps->session_fn || !ctx.deps->audit_as_session_fn) {
        refuse("dex score policy provider unwired; policy not changed",
               std::string(tool) + ": apply, session or session-bound audit closure unwired - "
                                   "misconfigured call site; failing closed, policy not changed");
        return std::nullopt;
    }
    auto session = ctx.deps->session_fn(ctx.req);
    if (!session || session->username.empty()) {
        refuse("caller identity unresolved; policy not changed",
               std::string(tool) + ": the caller's session could not be resolved - failing "
                                   "closed, policy not changed");
        return std::nullopt;
    }
    std::string role = auth::role_to_string(auth::effective_role(*session));
    return WriterIdentity{std::move(*session), std::move(role)};
}

// ── get_dex_score_policy ──────────────────────────────────────────────────────────────────
void handle_get_dex_score_policy(const ToolCallContext& ctx) {
    // ctx.args is a JSON object here (the dispatch chain's central check refuses anything else
    // first), so "takes no arguments" is an emptiness test.
    if (!ctx.args.empty()) {
        refuse_params(ctx, "get_dex_score_policy takes no arguments", kBadArgsRemediation);
        return;
    }
    if (!tier_admits(ctx, "GuaranteedState", "Read"))
        return;
    if (!ctx.perm_fn(ctx.req, ctx.res, "GuaranteedState", "Read"))
        return; // loud: the gate wrote its own 403
    if (ctx.deps == nullptr || !ctx.deps->dex_score_policy_read_fn) {
        answer_unwired(ctx, "service unavailable", "dex score policy provider unwired", {},
                       "get_dex_score_policy: dex_score_policy_read_fn unwired - misconfigured "
                       "call site; failing closed");
        return;
    }
    const auto stored = ctx.deps->dex_score_policy_read_fn();
    if (!stored) {
        const bool audited = ctx.audit("failure", "store read failed");
        answer(ctx, ctx.a4_error(kInternalError, kDexScorePolicyStoreUnavailableMessage,
                                 "retry shortly", /*retry_after_ms=*/kDexScorePolicyRetryMs, {},
                                 audited));
        return;
    }
    (void)ctx.audit("success", "");
    answer(ctx, success_response(ctx.id, ctx.tool_result(
                                             dump_replace(dex_score_policy_in_force_json(
                                                 dex_policy_in_force_from_stored(*stored))),
                                             kGetOutputSchema)));
}

// ── set_dex_score_policy ──────────────────────────────────────────────────────────────────
void handle_set_dex_score_policy(const ToolCallContext& ctx) {
    if (!tier_admits(ctx, "Infrastructure", "Write"))
        return;
    if (!ctx.perm_fn(ctx.req, ctx.res, "Infrastructure", "Write"))
        return; // loud
    if (!ctx.perm_fn(ctx.req, ctx.res, "GuaranteedState", "Read"))
        return; // loud: the answer carries application names
    auto rq = dex_score_policy_mcp_request(DexScorePolicyWriteRequest::Op::Put, ctx.args);
    if (!rq) {
        refuse_params(ctx, rq.error(), kBadArgsRemediation);
        return;
    }
    const auto who = writer_identity(ctx, "set_dex_score_policy", {});
    if (!who)
        return; // refused BEFORE any row; the answer is written
    rq->actor = who->session.username;
    bool persisted = true;
    const auto r = ctx.deps->dex_score_policy_apply_fn(*rq, audit_hook(ctx, *who, persisted));
    if (r.status == DexScorePolicyWriteStatus::Ok) {
        if (!ctx.audit("success", r.dry_run ? "dry_run" : ""))
            persisted = false;
        answer(ctx, success_response(ctx.id, ctx.tool_result(
                                                 dump_replace(dex_score_policy_mcp_success_json(
                                                     r, persisted)),
                                                 kWriteOutputSchema)));
        return;
    }
    const int code = dex_score_policy_mcp_code(r.status);
    if (!ctx.audit(code == kInvalidParams ? "denied" : "failure",
                   std::string(dex_score_policy_mcp_status_token(r.status))))
        persisted = false;
    const std::string message = dex_score_policy_mcp_message(r.message);
    const std::string remediation = dex_score_policy_mcp_remediation(r.remediation);
    if (code == kInvalidParams) {
        answer(ctx, ctx.a4_error(kInvalidParams, message, remediation, -1, {}, persisted)); // retry-hint-exempt: caller refusal (If-Match, dry_run, invalid or stale document); resending fails identically
        return;
    }
    answer(ctx, ctx.a4_error(kInternalError, message, remediation,
                             /*retry_after_ms=*/r.retry_after_ms.value_or(kDexScorePolicyRetryMs),
                             {}, persisted));
}

// ── reset_dex_score_policy ────────────────────────────────────────────────────────────────
void handle_reset_dex_score_policy(const ToolCallContext& ctx) {
    if (!tier_admits(ctx, "Infrastructure", "Delete"))
        return;
    if (!ctx.perm_fn(ctx.req, ctx.res, "Infrastructure", "Delete"))
        return; // loud
    if (!ctx.perm_fn(ctx.req, ctx.res, "GuaranteedState", "Read"))
        return; // loud: the answer carries application names
    // approval_id was consumed by the generic approval gate before this handler; the strict
    // check accepts and ignores it.
    auto rq = dex_score_policy_mcp_request(DexScorePolicyWriteRequest::Op::Reset, ctx.args);
    if (!rq) {
        // The ticket was spent before this handler ran: this refusal carries the recovery too.
        refuse_params(ctx, rq.error(),
                      std::string(kBadArgsRemediation) + "; " + std::string(kResetTicketSpentNote));
        return;
    }
    const auto who = writer_identity(ctx, "reset_dex_score_policy", kResetTicketSpentNote);
    if (!who)
        return;
    rq->actor = who->session.username;
    bool persisted = true;
    const auto r = ctx.deps->dex_score_policy_apply_fn(*rq, audit_hook(ctx, *who, persisted));
    if (r.status == DexScorePolicyWriteStatus::Ok) {
        if (!ctx.audit("success", ""))
            persisted = false;
        answer(ctx, success_response(ctx.id, ctx.tool_result(
                                                 dump_replace(dex_score_policy_mcp_success_json(
                                                     r, persisted)),
                                                 kWriteOutputSchema)));
        return;
    }
    const int code = dex_score_policy_mcp_code(r.status);
    if (!ctx.audit(code == kInvalidParams ? "denied" : "failure",
                   std::string(dex_score_policy_mcp_status_token(r.status))))
        persisted = false;
    // The approval ticket was spent before this handler ran, so every refusal or failure here
    // has burned it: say how to recover.
    const std::string message = dex_score_policy_mcp_message(r.message);
    const std::string remediation = dex_score_policy_mcp_remediation(r.remediation) + "; " +
                                    std::string(kResetTicketSpentNote);
    if (code == kInvalidParams) {
        answer(ctx, ctx.a4_error(kInvalidParams, message, remediation, -1, {}, persisted)); // retry-hint-exempt: caller refusal (If-Match, stale revision); resending fails identically
        return;
    }
    answer(ctx, ctx.a4_error(kInternalError, message, remediation,
                             /*retry_after_ms=*/r.retry_after_ms.value_or(kDexScorePolicyRetryMs),
                             {}, persisted));
}

// Positional initialisation only (no designated initialisers): the lexical CI gates
// (check-api-parity.py, check-mcp-retry-hints.py) read this slice.
constexpr ToolRecord kToolRecords[] = {
    {"get_dex_score_policy",
     "Get the customer DEX score policy in force: the document that sets the four score tier "
     "edges and names, the signal weights, the optional model parameters and the per-application "
     "overrides every DEX score is computed under. Returns document (the stored shape: version, "
     "tiers.edges, tiers.names, weights, model, overrides), revision (the 16-digit lower-case hex "
     "revision, or 'default' when nothing has been written), source (custom, or default for the "
     "shipped defaults) and, when a stored document was refused and the shipped defaults are "
     "being served, a fault reason: document is then the shipped defaults, NOT your stored "
     "policy, so do not edit it and send it to set_dex_score_policy. Pass revision back as "
     "if_match to set_dex_score_policy or reset_dex_score_policy. Read from the store, not this "
     "instance's cache, so it is the revision a write will be checked against. A fleet-wide "
     "configuration read: no per-agent data and no domain audit row (the generic "
     "mcp.get_dex_score_policy row is written). The stored text is also listed by "
     "get_runtime_config for a caller holding Infrastructure:Read. An unreadable store is a "
     "retryable error with retry_after_ms, never the defaults served as if nothing were stored. "
     "Takes no arguments. Requires GuaranteedState:Read, held outright (a management-group-scoped "
     "grant alone does not pass); readable at every MCP tier. Mirrors "
     "GET /api/v1/dex/score-policy. Read-only.",
     R"({"type":"object","properties":{},"additionalProperties":false})",
     kGetOutputSchema,
     "GuaranteedState", "Read", ServiceScopeClass::denied, ToolEffect::ReadOnly, true,
     "Get the DEX score policy", &handle_get_dex_score_policy},

    {"set_dex_score_policy",
     "Replace the customer DEX score policy with the given document, or check one without "
     "storing it (dry_run). It overwrites the stored document (destructive to that one "
     "fleet-wide document: every DEX score, tier and Apps view is computed under it, on this "
     "instance at once and on other instances typically within 5 seconds; nothing else is "
     "touched). Send document in the shape get_dex_score_policy returns, and if_match (REQUIRED: "
     "the revision get_dex_score_policy returned, or 'default' when none has been written) so the "
     "write is refused if the policy changed meanwhile. When get_dex_score_policy returns a fault "
     "its document is the shipped defaults, not your stored policy: do not edit it and send it "
     "back. Do not set during a rolling upgrade or rollback: a document carrying model is stored "
     "as version 2, which an older replica refuses and scores under the shipped defaults until "
     "the roll ends. dry_run true validates the document and the revision and answers what WOULD "
     "be in force (revision = what a real set would produce) without storing anything; it leaves "
     "one dex.score_policy.validate audit row. Idempotent: the same document with the current "
     "revision twice stores the same policy. A missing, malformed or stale if_match, an invalid "
     "document, an unknown argument or a non-boolean dry_run is a non-retryable invalid-params "
     "error naming the field (resending fails identically; read the policy again, fix the "
     "document, retry). A busy writer, an unavailable store, a write whose outcome is unknown "
     "(after a lost response, call get_dex_score_policy and compare revisions before sending "
     "again) or an audit store that refused the attempted row (the policy was NOT changed) is a "
     "retryable error with retry_after_ms. audit_persisted:false appears only when an audit row "
     "failed to persist: on a success the change stands and a row after it is missing; on an "
     "error answer the row recording that refusal was not stored. Audited as "
     "dex.score_policy.update (an attempted row first: if it cannot be written the policy is not "
     "changed) or dex.score_policy.validate, plus the generic mcp.set_dex_score_policy row. "
     "Requires a supervised-tier token with Infrastructure:Write and GuaranteedState:Read; no "
     "approval ticket. Mirrors PUT /api/v1/dex/score-policy.",
     R"j({"type":"object","properties":{)j"
     R"j("document":{"type":"object","description":"The whole policy document in the shape get_dex_score_policy returns (version, tiers.edges, tiers.names, weights, optional model, overrides); it replaces the stored one"},)j"
     R"j("if_match":{"type":"string","maxLength":64,"description":"The revision get_dex_score_policy returned: 16 lower-case hex digits, or 'default' when no policy has been written. Required; a stale value is refused"},)j"
     R"j("dry_run":{"type":"boolean","description":"true validates the document and the revision and answers what would be in force without storing it; default false"})j"
     R"j(},"required":["document","if_match"],"additionalProperties":false})j",
     kWriteOutputSchema,
     "Infrastructure", "Write", ServiceScopeClass::denied, ToolEffect::Destructive, true,
     "Replace the DEX score policy", &handle_set_dex_score_policy},

    {"reset_dex_score_policy",
     "Reset the customer DEX score policy to the shipped defaults by removing the stored "
     "document (destructive to that one fleet-wide document: every DEX score, tier and Apps view "
     "returns to the defaults, on this instance at once and on other instances typically within "
     "5 seconds). if_match is REQUIRED: the revision get_dex_score_policy returned, so the reset "
     "is refused if the policy changed meanwhile; resetting a policy that was never written "
     "records an attempted and a no_change row and answers the defaults. Idempotent: a second "
     "reset with the current revision changes nothing. Requires a supervised-tier token with "
     "Infrastructure:Delete and GuaranteedState:Read, and an approval ticket: the first call "
     "answers kApprovalRequired with an approval_id, and after a human approves it you repeat the "
     "SAME call with that approval_id. A missing, malformed or over-long if_match or an unknown "
     "argument is refused by the input schema before any ticket is created or consumed. The "
     "ticket is consumed before the handler runs, so ANY failure after approval (a busy writer, "
     "an unavailable store or audit log, a write whose outcome is unknown, a stale if_match) "
     "spends it: call get_dex_score_policy (also after a lost response), compare its revision "
     "with the one the error names (or with your if_match when none is named), then submit a NEW "
     "request without approval_id for a fresh ticket (a repeat with the spent approval_id answers "
     "'approval already used'). A refusal by the handler's own permission gate (its 403 carries "
     "no such hint) spends the ticket too. Busy, unavailable and unknown-outcome errors are "
     "retryable: retry after retry_after_ms with a NEW request (no approval_id), never the spent "
     "one; invalid-params errors name the field and are not. Under RBAC this tool needs "
     "Infrastructure:Delete, which REST DELETE does not (it needs Infrastructure:Write only). The "
     "ticket gates this MCP tool, not the capability: the same supervised token can DELETE "
     "/api/v1/dex/score-policy over REST with Infrastructure:Write alone and no ticket, and "
     "set_dex_score_policy stores any valid document without one. audit_persisted:false appears "
     "only when an audit row failed to persist: on a success the change stands and a row after it "
     "is missing; on an error answer the row recording that refusal was not stored. Audited as "
     "dex.score_policy.reset (attempted first) plus the generic mcp.reset_dex_score_policy row. "
     "Mirrors DELETE /api/v1/dex/score-policy.",
     R"j({"type":"object","properties":{)j"
     R"j("if_match":{"type":"string","maxLength":64,"pattern":"^(default|[0-9a-f]{16})$","description":"The revision get_dex_score_policy returned: 16 lower-case hex digits, or 'default' when no policy has been written, sent bare (no quotes; the reset schema refuses the quoted ETag form before any approval ticket is created). Required; a stale value is refused"},)j"
     R"j("approval_id":{"type":"string","maxLength":128,"description":"Approval ticket id from a prior kApprovalRequired response; repeat the same call with it once a human has approved"})j"
     R"j(},"required":["if_match"],"additionalProperties":false})j",
     kWriteOutputSchema,
     "Infrastructure", "Delete", ServiceScopeClass::denied, ToolEffect::Destructive, true,
     "Reset the DEX score policy to defaults", &handle_reset_dex_score_policy},
};

static_assert(records_well_formed(kToolRecords),
              "mcp_tools_dex.cpp: a record is malformed (null field or handler, bad name, "
              "effect/operation mismatch) or two records share a name; see record_defect()");

} // namespace

std::span<const ToolRecord> dex_tool_records() {
    return kToolRecords;
}

} // namespace yuzu::server::mcp
