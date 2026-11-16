#pragma once

/// @file mcp_instruction_authoring.hpp
/// The MCP twins of the legacy instruction-definition and instruction-set authoring routes
/// (#2146 batch C, ADR-1005 Decision 4): `create_definition`, `update_definition`,
/// `delete_definition`, `import_definition`, `save_definition_yaml`, `validate_definition_yaml`,
/// `list_instruction_sets`, `create_instruction_set`, `delete_instruction_set`. The v1 REST twins
/// are instruction_authoring_routes.{hpp,cpp}. Both surfaces call the same request builders in
/// instruction_definition_model.hpp (`build_definition_from_create_body`,
/// `apply_definition_update_body`, `build_instruction_set_from_body`,
/// `describe_dispatch_binding_change`, `check_dispatch_identifier`, `classify_store_error`,
/// `definition_from_yaml_fields`) and the same store methods, so the request contract, the
/// vocabulary of refusals and the audit action names cannot drift between them.
///
/// This file owns only what is MCP-specific: the store sequences over a `Ports` seam (so they run
/// without an httplib request), and the mapping of a `Result` to a JSON-RPC response. The tier,
/// approval-ticket (C8), service-scope and RBAC gates all run in mcp_server.cpp BEFORE these
/// functions (the dispatch branches pin the declared (securable, operation) pair).
///
/// AUDIT-FIRST (ADR-0033 section 9; revoke_upload_grant is the MCP precedent). Every WRITE writes
/// an `attempted` domain row BEFORE the mutation and refuses (retryable internal error, nothing
/// mutated) when that row cannot be stored, then writes one outcome row (`success`; `denied` for
/// not_found / conflict / invalid; `error` for a store fault). A lost OUTCOME row does not undo
/// the mutation: the success payload carries `audit_persisted:false` (docs/api-twin-recipe.md
/// section 4: MCP is set-and-proceed). The domain action names are the legacy ones
/// (`instruction.create` / `.update` / `.delete` / `.import`, `instruction_set.create` /
/// `.delete`); the generic `mcp.<tool>` row is written by the caller.
///
/// WHAT THESE DO NOT DO: they never call `InstructionStore::import_definition_json_trusted`
/// (import is the one signature-gated surface; the signature is verified against the
/// request-supplied `publicKey`, so it proves integrity, not authorization) and never
/// `create_set_seed` (the boot-time seed path). The legacy handlers are untouched.
///
/// Every refusal message is fixed text or the store's own controlled error text; none carries
/// `e.what()` or an echo of caller bytes beyond what the shared builders already quote.

#include "event_emit_hook.hpp" // EventEmitHook
#include "instruction_definition_model.hpp" // the shared request bounds (kMaxDefinition*)
#include "instruction_referrers.hpp" // DefinitionReferrersFn
#include "instruction_store.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::mcp::instruction_authoring {

// ── Input bounds. The shared builders (instruction_definition_model.hpp) own the numbers; these
// alias them, and each has a twin literal in the served input schema that a test binds. ─────────
inline constexpr std::size_t kIdMaxLen = kMaxDefinitionIdLen; ///< definition id, set id, instruction_set_id
inline constexpr std::size_t kNameMaxLen = kMaxDefinitionNameLen; ///< definition and set name
inline constexpr std::size_t kVersionMaxLen = kMaxDefinitionVersionLen; ///< definition version
inline constexpr std::size_t kDescriptionMaxLen = kMaxDefinitionDescriptionLen; ///< definition and set description
inline constexpr std::size_t kInstructionSetIdMaxLen = kMaxDefinitionInstructionSetIdLen;
inline constexpr std::size_t kDispatchIdentMaxLen = kMaxDefinitionDispatchIdentifierLen; ///< plugin and action
inline constexpr std::size_t kYamlSourceMaxBytes = kMaxDefinitionYamlSourceBytes; ///< == the store's own 1 MiB cap
inline constexpr int kMaxGatherTtlSeconds = kMaxDefinitionGatherTtlSeconds;
inline constexpr int kMaxResponseTtlDays = kMaxDefinitionResponseTtlDays;

/// What one operation did. `kind` selects the JSON-RPC mapping in `render`.
enum class Kind {
    kOk,
    kInvalid,          ///< the arguments are wrong (or the store refused them as invalid)
    kNotFound,         ///< no such definition / set
    kConflict,         ///< a duplicate id, or a stale `expected_updated_at` / `updated_at`
    kReferenced,       ///< a delete refused: schedules, workflows or policy fragments still use it
    kStoreUnavailable, ///< the store is unwired, closed or faulted (retryable)
    kAuditRefused,     ///< the `attempted` row could not be stored; nothing was mutated (retryable
                       ///< unless the sink is unwired: `Result::not_retryable`)
};

struct Result {
    Kind kind{Kind::kOk};
    std::string message;                ///< fixed text, or the store's controlled error text
    std::vector<std::string> errors;    ///< a YAML validation list (kInvalid only)
    nlohmann::json payload;             ///< the tool result object (kOk only)
    bool audit_persisted{true};         ///< false when an OUTCOME row was lost after the mutation
    /// kStoreUnavailable on a WRITE after its attempted row: the commit may have landed, so the
    /// caller must read before retrying (the remediation says so).
    bool outcome_unknown{false};
    /// kStoreUnavailable, or kAuditRefused for an UNSET `Ports::audit`, from a CONFIGURATION fault
    /// (a seam the deployment never wired): waiting does not fix it, so the error carries no
    /// `retry_after_ms` (REST answers the same).
    bool not_retryable{false};
};

/// What the operations need besides the arguments. Every member is a seam: a test wires fakes.
struct Ports {
    InstructionStore* store{nullptr};
    /// `session->username` (`engine:<slug>` for an engine principal): stamped as `created_by`.
    std::string created_by;
    /// The domain audit row writer: (action, result, target_type, target_id, detail) -> stored?
    /// A throwing sink is the caller's to catch (it wraps `try_persist_audit`). Unset = no row can
    /// be stored, so every write refuses (kAuditRefused): an unwired sink is never "audit off".
    std::function<bool(std::string_view action, std::string_view result,
                       std::string_view target_type, const std::string& target_id,
                       const std::string& detail)>
        audit;
    /// The legacy routes' `instruction.created` / `.updated` / `.deleted` event, request bound.
    /// Unset = no event.
    EventEmitHook emit;
    /// The approval ticket that authorised this call, set by the caller ONLY when the C8 gate
    /// consumed one for it (empty otherwise). The SUCCESS row the call writes then ends with
    /// ` approval_id=<id>`, so the change can be traced to the human approval that allowed it;
    /// the attempted row and a refusal row keep their exact detail (a SIEM rule keys on it).
    std::string approval_id;
    /// What still references a definition (instruction_referrers.hpp). `delete_definition`
    /// refuses a referenced one (kReferenced). Unset or failing = kStoreUnavailable and nothing is
    /// deleted: an unwired lookup is never "no referrers".
    DefinitionReferrersFn referrers_fn;
    /// Advisory only: the packs that contain the definition, noted as `packs=` in
    /// `delete_definition`'s success row. Unset or failing = no note; the delete is unaffected.
    DefinitionPackAdvisoryFn pack_advisory_fn;
};

/// The referrer guard of `delete_definition` (UP-6), also run by mcp_server.cpp BEFORE a ticket is
/// minted or consumed so a delete that is going to be refused burns no approval; the handler runs it
/// again (the world can change between the two). nullopt = nothing references `id` (or `id` is
/// malformed, which the caller's own id check refuses with the right text); otherwise the refusal:
/// kReferenced listing the referrers (bounded), or kStoreUnavailable when the lookup is unwired or
/// failed. Writes nothing. `existence_store` (the pre-mint caller passes it; the handler, which has
/// already read the row, does not) limits the check to a row that exists: an absent id yields
/// nullopt so the call reaches the version check and answers not_found, as REST does; an unopened
/// or unreadable store is kStoreUnavailable.
[[nodiscard]] std::optional<Result> delete_referrer_refusal(
    const std::string& id, const DefinitionReferrersFn& referrers_fn,
    const InstructionStore* existence_store = nullptr);

/// The tools whose approval ticket binds a DIGEST of their large argument, not its bytes:
/// `import_definition` (the `document`, up to 4 MiB) and `save_definition_yaml` (the
/// `yaml_source`, up to 1 MiB). Binding the bytes would store them in `approvals.scope_expression`
/// and ship them to every approvals list; the digest binds the same document at a fixed size.
[[nodiscard]] bool ticket_binds_digest(std::string_view tool) noexcept;

/// The ticket subject for a `ticket_binds_digest` tool: the arguments minus the control-plane
/// `approval_id`, with the large field replaced by `<field>_bytes` (its length) and
/// `<field>_sha256` (lowercase hex), plus the `tool` name. Every other argument (the id, the
/// version token) stays in the subject verbatim, under an `arg_` prefix if its name is one the
/// subject itself writes (the whole summary key set, reserved whether or not it is emitted for
/// this call, so an argument can never paint a false field). So the approver is not shown a bare
/// digest, the subject also carries the definition's own plain fields, each bounded
/// (`bounded_definition_id`) and folded (`log_token`), empty ones omitted: for an import the
/// document's own top-level keys (the action lowercased, as the store stores it), with plugin,
/// action and approval_mode (only those three; an id the document omits is generated by the
/// server at import and a name it omits is refused, neither is ever read from the YAML) read from
/// its `yaml_source` ONLY when the document is signed (`signature` and `publicKey` both present,
/// the store's signed branch); for an object document `approval_mode` is ALWAYS present as the
/// effective value (the document's, else the signed YAML's, else `auto`). For a YAML save, the
/// YAML's own fields; `approval_mode` is the YAML's when it states one, else `auto` for a create
/// (no or an empty `id` argument: the new definition stores `auto`) and absent for an update (it
/// keeps the stored value). `parse_error: true` when nothing readable was found (the handler
/// refuses the call later; no validation text is produced here).
/// Insertion-ordered JSON in a fixed order (tool, approval_mode, plugin, action, definition_id,
/// name, parse_error, the other arguments by key, the digest keys), the dispatch-relevant fields
/// first because the Approvals list cell shows only the START of the subject; the full subject is
/// on the request.
/// A client's key order does not matter. The mint and the recall both call this on their own
/// arguments, so the same document gives the same subject and one changed byte gives a different
/// one. Linear in the number of arguments. `nullopt` = the digest provider failed
/// (sha256_hex.hpp): the caller refuses BEFORE any ticket is minted or consumed, and must not
/// fall back to the bytes.
[[nodiscard]] std::optional<std::string> ticket_subject(std::string_view tool,
                                                        const nlohmann::json& args);

/// At the supervised tier the human approves ONE VERSION of a definition, so `update_definition`
/// and `delete_definition` without `expected_updated_at`, and `save_definition_yaml` with a
/// non-empty `id` and no `updated_at`, are refused before a ticket is minted or consumed. Returns
/// the refusal message, or nullopt when the call carries what it needs (or the tool needs
/// nothing: a create, an import). The caller applies it only to a ticketed (supervised) call.
[[nodiscard]] std::optional<std::string> missing_version_token(std::string_view tool,
                                                               const nlohmann::json& args);

/// The best-effort early version check (UP-12), run by mcp_server.cpp at the supervised tier after
/// `missing_version_token` and BEFORE a ticket is minted or consumed, for the tools that carry a
/// version token for an existing row: `update_definition` / `delete_definition`
/// (`expected_updated_at`) and `save_definition_yaml` with an `id` (`updated_at`). nullopt = the
/// token matches the stored row (or there is nothing to compare: another tool, a missing or
/// malformed id or token, which the version-token check and the handler refuse with their own
/// text; a token above INT64_MAX never gets here, the tool input-schema validation refuses it
/// first); otherwise the refusal the handler would give: kNotFound for an absent row, kConflict
/// (naming `get_definition` for the re-read) for a moved-on one, kStoreUnavailable when the store is
/// unwired or the read fails (never read as "matches"). Read-only; the handler still enforces the
/// token atomically.
[[nodiscard]] std::optional<Result> stale_version_refusal(std::string_view tool,
                                                          const nlohmann::json& args,
                                                          const InstructionStore* store);

[[nodiscard]] Result create_definition(const nlohmann::json& args, const Ports& ports);
[[nodiscard]] Result update_definition(const nlohmann::json& args, const Ports& ports);
[[nodiscard]] Result delete_definition(const nlohmann::json& args, const Ports& ports);
[[nodiscard]] Result import_definition(const nlohmann::json& args, const Ports& ports);
[[nodiscard]] Result save_definition_yaml(const nlohmann::json& args, const Ports& ports);
/// No store, no audit: pure validation (the Read gate is the caller's).
[[nodiscard]] Result validate_definition_yaml(const nlohmann::json& args);
[[nodiscard]] Result list_instruction_sets(const Ports& ports);
[[nodiscard]] Result create_instruction_set(const nlohmann::json& args, const Ports& ports);
[[nodiscard]] Result delete_instruction_set(const nlohmann::json& args, const Ports& ports);

/// One JSON-RPC response, ready for `res.set_content`: `is_error` selects `error_response` (with
/// `data_json` as `error.data`) or `success_response(tool_result(payload_json, ...))`.
struct Rendered {
    bool is_error{false};
    int code{0};
    std::string message;
    std::string data_json;    ///< error.data: correlation_id, retry_after_ms, remediation, reason[, errors]
    std::string payload_json; ///< the tool result object when !is_error
};

/// `extra_audit_dropped` is true when the caller's own generic `mcp.<tool>` row was lost; it
/// joins `result.audit_persisted` in the `audit_persisted:false` flag.
[[nodiscard]] Rendered render(const Result& result, const std::string& correlation_id,
                              bool extra_audit_dropped);

/// The generic `mcp.<tool>` audit row's result word for `kind`.
[[nodiscard]] std::string_view generic_audit_result(Kind kind) noexcept;

} // namespace yuzu::server::mcp::instruction_authoring
