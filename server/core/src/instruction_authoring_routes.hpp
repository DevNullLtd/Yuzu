#pragma once

/// @file instruction_authoring_routes.hpp
/// The versioned REST twins of the legacy instruction-definition and instruction-set authoring
/// routes (#2146 batch C, ADR-1005 Decision 4; ledger rows `post.api-instructions`,
/// `put.api-instructions-param`, `delete.api-instructions-param`, `post.api-instructions-import`,
/// `post.api-instructions-yaml`, `post.api-instructions-validate-yaml`, `get/post.api-instruction-sets`,
/// `delete.api-instruction-sets-param`). The MCP twins are `create_definition`, `update_definition`,
/// `delete_definition`, `import_definition`, `save_definition_yaml`, `validate_definition_yaml`,
/// `list_instruction_sets`, `create_instruction_set` and `delete_instruction_set`
/// (mcp_instruction_authoring.cpp). Both surfaces share the request builders in
/// instruction_definition_model.hpp; this file owns the gate, the wire envelope and the audit rows.
///
/// ROUTES (registered literal-before-id: `import`, `yaml`, `validate-yaml` never reach `{id}`):
///   POST   /api/v1/instructions                InstructionDefinition:Write   201 {id}
///   POST   /api/v1/instructions/import         InstructionDefinition:Write   201 {id}
///   POST   /api/v1/instructions/yaml           InstructionDefinition:Write   201|200 {id, created}
///   POST   /api/v1/instructions/validate-yaml  InstructionDefinition:Read    200 {valid, errors}
///   PUT    /api/v1/instructions/{id}           InstructionDefinition:Write   200 {id, updated}
///   DELETE /api/v1/instructions/{id}           InstructionDefinition:Delete  200 {id, deleted}
///   GET    /api/v1/instruction-sets            InstructionSet:Read           200 [{id,name,description,created_by,created_at}]
///   POST   /api/v1/instruction-sets            InstructionSet:Write          201 {id}
///   DELETE /api/v1/instruction-sets/{id}       InstructionSet:Delete         200 {id, deleted}
/// Success bodies are `{"data":..., "meta":{"api_version":"v1"}}`; every error is the A4 envelope.
///
/// GATE: `perm_fn` (plain, global), the legacy routes' own pairs. No service-scope allow-list entry
/// (a service-scoped token is refused by `require_permission` itself). A supervised-tier MCP token
/// is refused on the `InstructionDefinition:Write` routes by `requires_approval` (mcp_policy.hpp);
/// the C8 ticket flow exists only on `/mcp/v1/`. There is NO CSRF check here: the central
/// same-site write gate (`apply_same_site_write_gate`) covers every cookie-session write before
/// routing.
///
/// AUDIT-FIRST (ADR-0033 section 9; the `instruction_set.create` precedent in instruction_routes.cpp):
/// every WRITE route writes an `attempted` row BEFORE the mutation and refuses (503 + `Sec-Audit-Failed`,
/// nothing mutated) when that row cannot be stored, then writes one outcome row (`success`, `denied`
/// for not_found / conflict / invalid, `error` for a store fault). A failed OUTCOME row sets
/// `Sec-Audit-Failed` on a response whose mutation already happened. Actions are the legacy names:
/// `instruction.create` / `.update` / `.delete` / `.import`, `instruction_set.create` / `.delete`.
/// A refusal before the `attempted` row (gate, depth guard, JSON shape, field validation, an
/// unknown id on PUT) writes no row, as on the legacy routes. An UNWIRED `audit_fn` is a 503
/// `Sec-Audit-Failed`, never "audit off".
///
/// WHAT THE TWINS DO NOT DO: they never call `InstructionStore::import_definition_json_trusted`
/// (import is the one signature-gated surface; the signature is verified against the
/// request-supplied `publicKey`, so it proves integrity, not authorization) and never
/// `create_set_seed` (the boot-time seed path). The legacy handlers are untouched.

#include "event_emit.hpp" // EmitEventFn / bind_event_emit
#include "instruction_referrers.hpp" // DefinitionReferrersFn

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class InstructionStore;
} // namespace yuzu::server

namespace yuzu::server::instruction_authoring {

struct RouteDeps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string& securable, const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Wraps `AuthRoutes::resolve_session` (non-blocking, never writes to the response): only the
    /// username is read, to stamp `created_by`. Unset or unresolved = empty `created_by`.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;

    PermFn perm_fn;
    AuditFn audit_fn;
    ResolveSessionFn resolve_session_fn;
    /// `ServerImpl::emit_event`: publishes the legacy routes' `instruction.created` /
    /// `instruction.updated` / `instruction.deleted`. Unset = no event.
    EmitEventFn emit_event_fn;
    /// `ServerImpl::instruction_store_`. Null or not open -> 503 on every route but validate-yaml.
    InstructionStore* store{nullptr};
    /// What still references a definition (schedules, workflows, policy fragments). The DELETE
    /// refuses 409 listing them. Unset, or a lookup that fails, is a retryable 503 and nothing is
    /// deleted: "could not look" is never "no referrers" (instruction_referrers.hpp).
    DefinitionReferrersFn referrers_fn;
    /// Advisory only: the packs that contain the definition, noted as `packs=` in the DELETE's
    /// success outcome detail. Unset or failing = no note; the delete is never affected.
    DefinitionPackAdvisoryFn pack_advisory_fn;
    /// Counts an event emission that threw (`yuzu_server_event_emit_failed_total`). May be null.
    yuzu::MetricsRegistry* metrics{nullptr};
};

void register_instruction_authoring_routes(HttpRouteSink& sink, RouteDeps deps);

} // namespace yuzu::server::instruction_authoring
