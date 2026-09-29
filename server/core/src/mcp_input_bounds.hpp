#pragma once

#include <array>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "bundle_service.hpp"        // kMaxParamCountPerStep / kMaxParamKeyLen / kMaxParamValueLen
                                     // (also kMaxBundleSteps, which the sizing test reaches
                                     // through this header)
#include "dispatch_target_shape.hpp" // BoundViolation + check_targeting_shape: the
                                     // omitted-vs-supplied rule, shared with the REST
                                     // twins (#2500) because it was never MCP-specific
#include "mcp_jsonrpc.hpp"           // kMcpMaxRequestBodyBytes, for the sizing static_asserts below

/// @file mcp_input_bounds.hpp
/// The ONE home for MCP request-size bounds (#2437) — transport and handler.
///
/// These live in a header rather than TU-local in mcp_server.cpp for a
/// specific reason: the served `kTools[]` schema literals and these constants
/// are the SAME contract expressed twice, and a comment saying "keep them in
/// sync" is not a check. test_mcp_server.cpp reads the served schema back via
/// `input_schemas_for_test()` and asserts each literal equals its twin here,
/// so bumping one without the other fails a test instead of silently
/// reopening the gap this issue closed.
namespace yuzu::server::mcp {

// ── execute_instruction, per-field ────────────────────────────────────────
// Each has a twin in the served inputSchema; the cross-check test binds them.
inline constexpr std::size_t kExecInstrIdentMaxLen = 128;        // plugin, action, each agent_ids entry
inline constexpr std::size_t kExecInstrScopeMaxLen = 8192;       // scope expression
inline constexpr std::size_t kExecInstrParamValueMaxLen = kMaxParamValueLen; // 64 KiB
inline constexpr std::size_t kExecInstrAgentIdsMaxItems = 10000; // agent_ids length

// The closed schema subset has no `maxProperties` / `propertyNames`, so these
// two CANNOT be expressed in the served schema and have no twin to cross-check.
// Consequence: C8 cannot pre-validate them from the schema, so
// `check_exec_instruction_shape` below is run EXPLICITLY inside the C8
// block as well as in the handler. Without that a supervised call violating
// one would mint a ticket, spend a human's approval, CONSUME it, then fail —
// the ticket-burn class #2405 exists to prevent. They remain invisible in
// `tools/list`; publishing them needs the subset catalogue extended (#2444).
//
// Borrowed from bundle_service.hpp rather than invented so the two execute
// surfaces agree on what a param may be — shape AND value size. They used to
// disagree 8x on value size; that was not a decision, and the divergence was
// documented as deliberate before anyone checked why it existed.
inline constexpr std::size_t kExecInstrParamCountMax = kMaxParamCountPerStep; // 32
inline constexpr std::size_t kExecInstrParamKeyMaxLen = kMaxParamKeyLen;      // 256

/// The CLOSED `reason` label set for `yuzu_mcp_tool_args_too_large_total`.
///
/// This array is the single source: `server.cpp` pre-seeds the counter by
/// iterating it at boot, so the emitted set and the pre-seeded set cannot
/// drift apart. Before it existed the two were independent literal lists, and
/// a rule landing with an unseeded reason would still pass its own test (the
/// registry creates a series on demand) while silently breaking `absent()`
/// alerting — the dashboard reads zero while calls are being refused.
///
/// ADDING A REASON: append it here, emit it from `check_exec_instruction_shape`
/// or the handler's `too_large`, and document it in
/// `docs/user-manual/metrics.md`. The boot pre-seed follows automatically; the
/// docs copy does not, and a test asserts this array's size so the third copy
/// cannot be forgotten quietly.
inline constexpr std::array<std::string_view, 14> kExecInstrBoundReasons{
    // Length/count bounds.
    "ident_len",       "scope_len",       "param_count",     "param_key_len",
    "param_value_len", "agent_ids_count", "agent_id_len",
    // Targeting shape (#2437 split 3): a type-confused or supplied-but-empty
    // target is REJECTED, never silently dropped and never widened to
    // `__all__`. `ident_empty` subsumes the handler's old bare
    // plugin/action-required guard so that rejection is counted too.
    "agent_id_type",   "agent_ids_type",  "agent_ids_empty", "scope_type",
    "scope_empty",     "ident_empty",
    // #2500: agent_ids AND a real scope together are ambiguous - the old
    // precedence silently discarded the explicit id list in favour of the
    // broader scope. Same surface, same rule, so the same closed label.
    "target_conflict",
};

// ── #4353 follow-up: batch B2/B4 field bounds (handler-side) ──────────────
// Gate 2 finding on #4364 (governance re-run): the maxLength bounds #4353
// added to 19 of its 20 tools' served schemas were enforced ONLY on the
// approval-gated path - `mcp_server.cpp`'s sole `compiled_input_schemas()
// .at(tool_name).validate(args)` call site sits inside `requires_approval()`
// (mcp_policy.hpp), which itself returns false immediately for an EMPTY
// `mcp_tier` - and `/mcp/v1/`'s `auth_fn` (`require_auth`) admits a plain
// RBAC session or a non-MCP-tiered API token the same way any REST route
// does, so that caller class never reaches C8 at all, on ANY tool. 11 of the
// 19 are ALSO never approval-gated even at a non-empty tier; 3
// (`create_result_set_from_tar_query`, `create_result_set_from_instruction_result`,
// `reevaluate_result_set`) are approval-gated at supervised tier only, so an
// operator-tier call skipped validate() too; the remaining 5
// (`create_management_group`, `update_management_group`,
// `add_management_group_member`, `assign_management_group_role`,
// `delete_result_set`) are approval-gated whenever `mcp_tier` is non-empty,
// but the empty-tier gap above still applies to them. `unlock_account` is
// the ONE tool of #4353's 20 that needed nothing further: it already denies
// an empty `mcp_tier` outright (Gate 6 #2146 B4 fix) and its `username`
// already goes through `is_valid_username()`, whose own limit IS this
// field's 64-byte bound - not merely equal to it by coincidence. Each
// constant below mirrors its field's served schema `maxLength` exactly -
// the same "one contract in two places" discipline as kExecInstr* above,
// minus the cross-check test (these are single-tool, low-traffic surfaces;
// execute_instruction's worst-case-body static_asserts don't apply here -
// none of these tools accept unbounded-count arrays).
// `update_management_group`'s `membership_type` has no constant here for the
// same reason it has none in the schema - it is enum-constrained
// (`static`/`dynamic`), not a free-text field.
inline constexpr std::size_t kResultSetIdMaxLen = 64;             // result-set `id`
inline constexpr std::size_t kMgmtGroupIdMaxLen = 256;            // management-group `group_id` (and
                                                                   // `agent_id`/`principal_id`, same value)
inline constexpr std::size_t kMgmtGroupNameMaxLen = 256;          // management-group `name`
inline constexpr std::size_t kMgmtGroupDescriptionMaxLen = 1024;  // management-group `description`
inline constexpr std::size_t kMgmtGroupScopeExprMaxLen = 4096;    // management-group `scope_expression`
inline constexpr std::size_t kMcpCursorMaxLen = 2048;             // pagination `cursor`
inline constexpr std::size_t kResultSetNameMaxLen = 256;          // result-set `name`
inline constexpr std::size_t kResultSetParentIdMaxLen = 64;       // result-set `parent_id`
inline constexpr std::size_t kResultSetSourceKindMaxLen = 64;     // create_result_set `source_kind`
inline constexpr std::size_t kResultSetDeviceIdMaxLen = 256;      // create_result_set `device_ids[]` item
inline constexpr std::size_t kCheckPermSecurableTypeMaxLen = 128; // check_permission `securable_type`
inline constexpr std::size_t kCheckPermOperationMaxLen = 64;      // check_permission `operation`
inline constexpr std::size_t kInventoryQueryPluginMaxLen = 64;    // inventory-query `conditions[].plugin`
inline constexpr std::size_t kInventoryQueryFieldMaxLen = 128;    // inventory-query `conditions[].field`
inline constexpr std::size_t kInventoryQueryOpMaxLen = 32;        // inventory-query `conditions[].op`
inline constexpr std::size_t kInventoryQueryValueMaxLen = 512;    // inventory-query `conditions[].value`
inline constexpr std::size_t kInstructionIdMaxLen = 256;          // from-instruction-result `instruction_id`
inline constexpr std::size_t kMatcherColumnMaxLen = 128;          // from-instruction-result `matcher.column`
inline constexpr std::size_t kMatcherOpMaxLen = 32;               // from-instruction-result `matcher.op`
inline constexpr std::size_t kMatcherValueMaxLen = 512;           // from-instruction-result `matcher.value`

/// The 19 of #4353's 20 tools whose schema `maxLength` needed a handler-side
/// twin (see block above; `unlock_account` is the exception). Single source
/// for the `yuzu_mcp_tool_args_too_large_total` boot pre-seed in server.cpp -
/// same discipline as kExecInstrBoundReasons: a second literal list here is
/// how a tool ends up emitted-but-unseeded.
inline constexpr std::array<std::string_view, 19> kFieldBoundTools{
    "create_management_group",
    "update_management_group",
    "add_management_group_member",
    "get_management_group",
    "list_management_group_roles",
    "assign_management_group_role",
    "check_permission",
    "list_result_sets",
    "create_result_set",
    "create_result_set_from_inventory_query",
    "create_result_set_from_tar_query",
    "create_result_set_from_instruction_result",
    "get_result_set",
    "get_result_set_members",
    "get_result_set_lineage",
    "pin_result_set",
    "unpin_result_set",
    "reevaluate_result_set",
    "delete_result_set",
};

// ── Sizing: the per-field caps must fit under the TRANSPORT cap ───────────
// #2478 refuses a /mcp/ body over kMcpMaxRequestBodyBytes before reading it.
// The caps above are what a caller may legitimately fill, so their sum has to
// stay UNDER that cap — otherwise a maximal-but-legal execute_instruction is
// 413'd at the transport before the handler could ever accept it.
//
// These are static_asserts in the HEADER, not checks in a test, so widening a
// field bound past the transport cap fails the BUILD rather than a test run.
// Derived from the constants rather than restated, so the relation cannot
// drift away from what is enforced.
inline constexpr std::size_t kExecInstrWorstCaseBody =
    kExecInstrAgentIdsMaxItems * (kExecInstrIdentMaxLen + 3) +  // "<ident>",
    kExecInstrParamCountMax * (kExecInstrParamKeyMaxLen + kExecInstrParamValueMaxLen + 6) +
    (kExecInstrScopeMaxLen + 16) + 2 * (kExecInstrIdentMaxLen + 16) +
    2048; // jsonrpc/method/id/_meta.progressToken envelope

// A MARGIN, not merely ">". The params widening took the headroom from 62% to
// 18% and nobody recomputed it until review, so the next careless bump should
// fail to compile rather than ship a cap that refuses schema-legal calls.
//
// 10% is a FLOOR, not "what the numbers support" - an earlier version of this
// comment said the latter and was wrong. The true ceiling is 22.4% (the actual
// headroom); 25% fails, 20% would still hold. 10% is deliberately slack so a
// small legitimate change does not fail the build, which means this assert
// alone would permit drift to ~9% headroom while the docs publish 18%. Closing
// that gap is the job of the exact-figure CHECK in test_mcp_server.cpp, not of
// a tighter bound here - the assert pins the RELATION, the test pins the
// PUBLISHED NUMBER. Both are needed; neither substitutes for the other.
//
// Written as cap/11*10 rather than worst*11/10: the latter multiplies a value
// that grows with the field bounds, and on a 32-bit size_t would WRAP above
// ~390 MB and satisfy the assert spuriously - precisely the careless-bump case
// it exists to catch. cap is a fixed 4 MiB, so cap*10 cannot overflow.
static_assert(kMcpMaxRequestBodyBytes / 11 * 10 > kExecInstrWorstCaseBody,
              "a maximal execute_instruction must fit with room for JSON escaping - if this "
              "fires, raise the transport cap or lower a field bound, and update the figures "
              "in docs/mcp-server.md");
static_assert(kMcpMaxRequestBodyBytes > kExecInstrWorstCaseBody,
              "the transport cap must admit the largest execute_instruction the per-field "
              "caps permit — below that, a legitimate maximal call would 413 before the "
              "handler ever saw it");

// The cap is DELIBERATELY below what execute_bundle's own validator accepts,
// and that clamp is the part most likely to be "fixed" by someone reading only
// the assert above. One saturated bundle step is ~2 MiB, so a 2-step bundle
// validate_bundle_steps would accept is refused at the transport. A stated
// product clamp (docs/mcp-server.md), NOT a derivation error.
inline constexpr std::size_t kOneSaturatedBundleStep =
    kMaxParamCountPerStep * (kMaxParamValueLen + kMaxParamKeyLen + 6);

static_assert(kOneSaturatedBundleStep < kMcpMaxRequestBodyBytes,
              "one saturated bundle step must still fit, or execute_bundle is unusable at "
              "its own declared per-step limits over MCP");
static_assert(2 * kOneSaturatedBundleStep > kMcpMaxRequestBodyBytes,
              "the bundle clamp documented in docs/mcp-server.md — if this stops holding, "
              "the clamp changed and the docs must change with it");

/// One violated bound. Defined in `dispatch_target_shape.hpp` now that the
/// targeting rules are shared with the REST twins (#2500).
///
/// Kept as a compat shim, not because call sites need it: governance checked,
/// and every consumer in `server/` and `tests/` spells it `auto`, so nothing
/// outside these two headers names the type. An earlier version of this comment
/// claimed the alias keeps existing call sites unchanged — it does, vacuously.
using BoundViolation = yuzu::server::BoundViolation;

/// Every reason `check_targeting_shape` can emit must ALSO be a member of
/// `kExecInstrBoundReasons` above, because `server.cpp` pre-seeds the MCP
/// counter by iterating that array and `check_exec_instruction_shape`
/// delegates its targeting arm to that function. Adding a targeting reason in
/// the shared header and forgetting this one would leave the MCP series
/// emitted-but-unseeded — the exact `absent()`-alerting break the single-array
/// discipline exists to prevent, reintroduced through the seam that split the
/// arrays apart. Same both-or-neither rule as the H2/G9 enum cross-checks: a
/// build failure, not a test failure.
[[nodiscard]] constexpr bool targeting_reasons_are_bound() {
    for (const auto r : yuzu::server::kTargetingShapeReasons) {
        bool found = false;
        for (const auto e : kExecInstrBoundReasons)
            if (e == r)
                found = true;
        if (!found)
            return false;
    }
    return true;
}
static_assert(targeting_reasons_are_bound(),
              "a reason in kTargetingShapeReasons is missing from kExecInstrBoundReasons - the "
              "MCP counter's boot pre-seed would not cover it, so it would be emitted but "
              "unseeded and absent() alerting would silently break");

/// The `execute_instruction` bounds the CLOSED schema subset cannot express
/// (it has no `maxProperties` / `propertyNames`), factored out so the C8
/// approval gate can run them BEFORE a ticket is minted or consumed.
///
/// WHY PRE-MINT AND NOT HANDLER-ONLY: a rule checked only in the handler runs
/// AFTER the C8 gate has minted a ticket, waited for a human, and consumed it
/// - so a call that was always going to be refused burns an approval, and an
/// automated client re-mints on every retry and floods the approval queue.
/// That is the waste #2405 exists to prevent. Adding a rule HERE rather than
/// at a call site is what keeps both paths in agreement: mcp_server.cpp calls
/// this from the C8 block (pre-mint) and from the handler (defense in depth
/// for the ungated tiers, which never reach C8).
///
/// Pure and total: no I/O. Returns the FIRST violation in a deterministic
/// order so a denial is reproducible.
[[nodiscard]] inline std::optional<BoundViolation>
check_exec_instruction_shape(const nlohmann::json& args) {
    // ── required identifiers must be non-empty ───────────────────────────
    // The schema marks plugin/action `required`, which C8 enforces, but the
    // SERVED schema puts no floor on their length, so `""` passes every
    // published check. The handler then refuses it — AFTER the C8 gate has
    // minted a ticket, waited for a human, and consumed it. Fifth instance of
    // the burn class, on the two most obvious fields in the tool.
    // The closed subset compiler CAN express that floor since #2444 added
    // `minLength`; the served schema does not use it yet, because those
    // literals live in kTools[] in mcp_server.cpp (frozen for a parallel
    // rebase). This check is what makes the bound real in the meantime, and
    // stays afterwards as the defense in depth the ungated tiers need — they
    // never reach C8 at all.
    // Absent, non-string, or empty - all three, because this must SUBSUME the
    // handler's own `plugin.empty() || action.empty()` guard rather than sit
    // behind it. It previously sat behind: that guard returned first with a
    // bare error, so `ident_empty` never fired on the ungated tiers and the
    // rule this function exists to make tier-independent was, once again,
    // supervised-only (governance, security MEDIUM-2).
    for (const char* key : {"plugin", "action"}) {
        if (!args.contains(key) || !args[key].is_string() ||
            args[key].template get_ref<const std::string&>().empty())
            return BoundViolation{"ident_empty",
                                  std::format("{} is required and must be a non-empty string",
                                              key)};
    }

    if (args.contains("params") && args["params"].is_object()) {
        const auto& p = args["params"];
        if (p.size() > kExecInstrParamCountMax)
            return BoundViolation{"param_count",
                                  std::format("params must have at most {} keys",
                                              kExecInstrParamCountMax)};
        for (const auto& [k, v] : p.items()) {
            (void)v;
            if (k.size() > kExecInstrParamKeyMaxLen)
                return BoundViolation{"param_key_len",
                                      std::format("a params key exceeds {} bytes",
                                                  kExecInstrParamKeyMaxLen)};
        }
    }
    // ── targeting: type, and supplied-but-empty ──────────────────────────
    // Delegated to the shared `check_targeting_shape` (#2500). The rules and
    // their messages are unchanged — they moved out of this function verbatim
    // — but they were never MCP-specific: `POST /api/command` and
    // `POST /api/instructions/{id}/execute` had the identical widening under a
    // weaker gate, and a second copy over there is how the same defect would
    // survive the fix a third time. Kept LAST so the violation order this
    // function documents is unchanged.
    return yuzu::server::check_targeting_shape(args);
}

} // namespace yuzu::server::mcp
