#pragma once

/// @file instruction_definition_model.hpp
///
/// #4029 (api-parity Batch A, content/catalog half): the ONE shared pure
/// builder family for `InstructionDefinition` JSON, so `GET /api/instructions`
/// (legacy), `GET /api/v1/instructions*` (new), and MCP's `list_definitions` /
/// `get_definition` / `export_definition` cannot drift from each other by
/// construction (docs/api-twin-recipe.md §1 — the `discover_routes.hpp`
/// pattern). No `httplib.h`, no MCP-specific includes: every function here
/// takes only an already-fetched `InstructionDefinition` and returns a plain
/// `nlohmann::json` object — each surface serializes/wraps it however that
/// surface's envelope requires (`ok_json`/`list_json` for REST v1, `JObj::raw`/
/// `JArr::add_raw` for MCP, a bare `nlohmann::json::array().push_back(...)`
/// for the legacy route).
///
/// THREE reconciled shapes, per the issue's evidence of drift between the
/// pre-existing REST fragment and the pre-existing MCP tools:
///   - `instruction_definition_row_json`    — the LIST row. Was two different
///     shapes: the legacy REST fragment's 11 fields vs. MCP `list_definitions`'
///     narrower 8 (missing `instruction_set_id`/`created_at`/`updated_at`).
///     This is the REST fragment's superset field set — MCP `list_definitions`
///     now calls this too, closing that drift.
///   - `instruction_definition_detail_json` — the SINGLE-definition detail.
///     Was two different shapes: the legacy REST fragment's
///     `gather_ttl_seconds`/`response_ttl_days`/`created_by`/timestamps vs. MCP
///     `get_definition`'s `approval_mode`/`parameter_schema`/`result_schema`/
///     `yaml_source`. This is the RECONCILED SUPERSET of both — `GET
///     /api/v1/instructions/{id}` and MCP `get_definition` both call this now.
///   - `instruction_definition_export_json` — the full export document (every
///     field on the struct). `InstructionStore::export_definition_json` itself
///     delegates here (see instruction_store.cpp) so the store's own export
///     format, `GET /api/v1/instructions/{id}/export`, and MCP
///     `export_definition` are the same shape by construction too.

#include "instruction_store.hpp"
#include "instruction_yaml.hpp" // DefinitionFields (definition_from_yaml_fields)

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// List-row shape (11 fields) — id/name/version/type/plugin/action/
/// description/enabled/instruction_set_id/created_at/updated_at. Used by
/// `GET /api/instructions` (legacy), `GET /api/v1/instructions`, and MCP
/// `list_definitions`.
nlohmann::json instruction_definition_row_json(const InstructionDefinition& d);

/// Single-definition detail shape (18 fields) — `instruction_definition_row_json`'s
/// 11 fields plus `gather_ttl_seconds`/`response_ttl_days`/`created_by` (the
/// legacy REST fragment's extra fields) plus `approval_mode`/`parameter_schema`/
/// `result_schema`/`yaml_source` (MCP `get_definition`'s extra fields). Used by
/// `GET /api/v1/instructions/{id}` and MCP `get_definition`. NOTE: the legacy
/// (non-v1) `GET /api/instructions/{id}` route is deliberately left on its own
/// narrower 14-field shape (no `approval_mode`/`parameter_schema`/
/// `result_schema`/`yaml_source`) rather than migrated onto this superset —
/// widening an already-shipped response body is a live judgment call, not a
/// zero-risk refactor like the list row above, and is out of this issue's
/// scope.
nlohmann::json instruction_definition_detail_json(const InstructionDefinition& d);

/// Full export document (every field on `InstructionDefinition`) — the same
/// shape `InstructionStore::export_definition_json` has always produced.
/// `export_definition_json` now delegates to this pure builder (see
/// instruction_store.cpp) instead of carrying its own independent field list,
/// so the store's export format, `GET /api/v1/instructions/{id}/export`, and
/// MCP `export_definition` cannot drift from each other. Takes an
/// already-fetched struct so a caller that already holds one (MCP
/// `export_definition`, which fetches via `get_definition` to distinguish
/// 404-vs-503 itself) does not need a second store round-trip.
nlohmann::json instruction_definition_export_json(const InstructionDefinition& d);

// ---------------------------------------------------------------------------
// Request side (#2146 batch C): the authoring twins' body -> InstructionDefinition builders.
//
// ONE strict parser for `POST /api/v1/instructions`, `PUT /api/v1/instructions/{id}` and the MCP
// `create_definition` / `update_definition` tools, so the REST and MCP request contracts cannot
// drift (docs/api-twin-recipe.md section 1). Pure: no I/O, no store, no clock. The legacy
// `POST/PUT /api/instructions` handlers keep their own lenient `j.value(...)` parsing on purpose
// (their shipped behaviour is not touched), so these functions are deliberately STRICTER than
// them: a wrongly typed field, an unknown key, an out-of-vocabulary `approval_mode` or an
// out-of-bounds identifier/TTL is a refusal here, never a coercion and never a silent drop.
// Every message is fixed text (no `e.what()`, no echo of caller bytes).
// ---------------------------------------------------------------------------

/// Bounds the twins apply on top of the store's own validation. The JSON builders below, the YAML
/// authoring check (`check_yaml_field_bounds`: name, version and description) and the store's
/// operator (signature-gated) import path (name, version, instruction_set_id and description, the
/// description at the wider `kMaxDefinitionImportDescriptionLen`) apply them; the trusted boot
/// seed and the legacy dashboard create/update/validate routes do not. These are the ONE source of truth: the MCP
/// schema literals in mcp_server.cpp's kTools[] and `mcp::instruction_authoring::k*Len` mirror
/// them and a test (`[bounds]` in test_mcp_instruction_authoring.cpp) fails if any diverges.
inline constexpr std::size_t kMaxDefinitionDispatchIdentifierLen = 128; ///< plugin and action
inline constexpr std::size_t kMaxDefinitionIdLen = 128;                 ///< definition id on the YAML save
inline constexpr std::size_t kMaxDefinitionYamlSourceBytes = 1024 * 1024; ///< == the store's own cap
inline constexpr std::size_t kMaxDefinitionNameLen = 128;              ///< `name`, 1..128
inline constexpr std::size_t kMaxDefinitionVersionLen = 64;             ///< `version`, 1..64
inline constexpr std::size_t kMaxDefinitionDescriptionLen = 512;        ///< `description`, 0..512
/// `description` on the operator import and the YAML authoring check, 0..16384. Wider than the
/// JSON builders' 512 because the bundled content carries descriptions past it (91 of 296; the
/// longest is about 4.9 KB) and an export of one must stay importable.
inline constexpr std::size_t kMaxDefinitionImportDescriptionLen = 16 * 1024;
inline constexpr std::size_t kMaxDefinitionInstructionSetIdLen = 128;   ///< `instruction_set_id`, 0..128
/// The `type` values the store's create accepts (`validate_and_prepare`); `update_definition` does
/// not re-check it, so the twins' PUT does here.
[[nodiscard]] constexpr bool is_valid_definition_type(std::string_view t) noexcept {
    return t == "question" || t == "action";
}
inline constexpr int kMaxDefinitionGatherTtlSeconds = 86400;           ///< 1 day
inline constexpr int kMaxDefinitionResponseTtlDays = 3650;             ///< ~10 years

/// `plugin` / `action` shape: 1..128 of `[A-Za-z0-9_.-]`. Returns the refusal text (naming
/// `field`, which the caller supplies as a literal) or nullopt when `value` is acceptable. An
/// EMPTY value is NOT accepted here; callers that allow "unset" skip the check themselves.
[[nodiscard]] std::optional<std::string> check_dispatch_identifier(std::string_view field,
                                                                   std::string_view value);

/// Build the definition a `POST` create body describes. `body` must be a JSON object; keys:
/// `id`, `name`, `version`, `type`, `plugin`, `action` (lowercased, as the legacy route does),
/// `description`, `enabled`, `instruction_set_id` (strings/bool), `gather_ttl_seconds` (1..86400),
/// `response_ttl_days` (1..3650) and `approval_mode` (`auto` | `role-gated` | `always`).
/// Absent keys take the legacy create defaults (`version` "1.0", `enabled` true, 300 s, 90 days,
/// `approval_mode` "auto"). `parameter_schema`, `result_schema`, `yaml_source` and every other
/// column are NOT accepted (an unknown key is refused). `created_by` is stamped by the caller.
/// The store still owns the rules it already enforces (name/type/plugin required, id charset and
/// reserved namespaces).
[[nodiscard]] std::expected<InstructionDefinition, std::string>
build_definition_from_create_body(const nlohmann::json& body, std::string_view created_by);

/// What a `PUT` update body asks for beyond the field edits applied to the definition.
struct DefinitionUpdateRequest {
    /// `expected_updated_at`: the `updated_at` version token the caller read (monotonic, see
    /// `InstructionStore::update_definition`); the store applies the update only
    /// if the row still carries it (409 otherwise). Absent = the caller did not ask for a check.
    std::optional<std::int64_t> expected_updated_at;
};

/// Apply a `PUT` update body to `def` (a copy of the stored row). Same keys and bounds as the
/// create body MINUS `id`, all optional, plus `expected_updated_at` (a non-negative integer). Only
/// keys present are applied. `parameter_schema` is left as loaded: the CALLER blanks it before
/// the store write (see `InstructionStore::update_definition`).
[[nodiscard]] std::expected<DefinitionUpdateRequest, std::string>
apply_definition_update_body(const nlohmann::json& body, InstructionDefinition& def);

/// A `PUT` / `update_definition` edits COLUMNS, and a stored `yaml_source` still describing the old
/// values would let a later YAML round trip (`get_definition`, edit, `save_definition_yaml`) silently
/// revert the edit: `merge_yaml_into_stored` takes `name`, `plugin` and `action` from the YAML always
/// and `approval_mode`, `concurrency_mode`, `version`, `type` and `description` whenever it states
/// them. `enabled` is NOT in the set: the merge starts from the stored row and never writes it, so a
/// YAML round trip cannot revert an `enabled` edit and clearing the YAML for it would destroy
/// authored text for no benefit. So when `def` changes any of `name`, `description`, `version`,
/// `type`, `plugin`, `action`, `approval_mode` or `concurrency_mode` against `before` AND `before`
/// carries a non-empty `yaml_source`, this clears `def.yaml_source` (the columns become the
/// authority, which is already the state of every definition created through the JSON routes) and
/// returns true. An edit to `enabled` and the rest leaves it alone. Called by the v1 PUT,
/// the legacy `PUT /api/instructions/{id}` and the MCP `update_definition` only; a YAML save is the YAML authority and never calls it.
/// `describe_dispatch_binding_change` then ends the audit detail with `yaml_source cleared
/// yaml_source_bytes=<n> yaml_source_sha256=<hex>` (the cleared text's size and digest) and, just
/// before it, names which of `name`, `version`, `type` and `description` changed.
[[nodiscard]] bool clear_stale_yaml_source(const InstructionDefinition& before,
                                           InstructionDefinition& def);

/// The change an update makes to the five columns that decide what a definition RUNS and whether
/// a human must approve it: `plugin`, `action`, `approval_mode`, `concurrency_mode`, `enabled`
/// (instruction_execute.cpp binds the first four into the effect; `enabled` gates dispatch).
/// `type` is deliberately NOT recorded: it only labels the definition. Empty when none changed. Format: `field: old -> new` entries joined
/// by `; ` (each value through `log_token`, CWE-117). Shared by the legacy `PUT
/// /api/instructions/{id}` and dashboard YAML-save success rows and the v1/MCP twins' rows, so an
/// approval downgrade (`always` -> `auto`), a repoint or a concurrency change is visible in the
/// audit trail on every surface. (The YAML save cannot change `enabled`: it carries it forward.)
/// An update that emptied a non-empty `yaml_source` (`clear_stale_yaml_source`) first names which of
/// `name`, `version` and `type` changed (`old -> new`, as above) and that the `description` did
/// (`description: changed <old> -> <new> bytes`, sizes only), then ends the text with
/// `yaml_source cleared yaml_source_bytes=<n> yaml_source_sha256=<hex>`. Those four are recorded
/// only in that case: they do not decide what a definition runs.
[[nodiscard]] std::string describe_dispatch_binding_change(const InstructionDefinition& before,
                                                           const InstructionDefinition& after);

/// The dispatch tuple of a definition about to be deleted, for the `instruction.delete` audit
/// rows (the pre-image: once the row is gone nothing else records what it ran). Format:
/// `name=... plugin=... action=... approval_mode=... concurrency_mode=... enabled=true|false`,
/// each free-text value bounded (`bounded_definition_id`) then folded through `log_token`
/// (CWE-117). Shared by the v1 REST and MCP delete twins.
[[nodiscard]] std::string describe_deleted_definition(const InstructionDefinition& def);

/// Build the set a `POST /instruction-sets` body describes: `name` and `description` strings, no
/// other key. Length bounds are the store's (`kMaxInstructionSetNameLen` /
/// `kMaxInstructionSetDescriptionLen`), enforced by `create_set`; this only checks shape.
[[nodiscard]] std::expected<InstructionSet, std::string>
build_instruction_set_from_body(const nlohmann::json& body, std::string_view created_by);

/// The request a YAML save carries: `POST /api/v1/instructions/yaml` and MCP
/// `save_definition_yaml`. Keys: `yaml_source` (required, non-empty string), `id` (string; non-empty
/// selects an UPDATE of that definition, empty or absent a CREATE) and `updated_at` (a
/// non-negative int64, the `updated_at` version token the caller read; the store applies the update
/// only if the row still carries it). Any other key is refused. Fixed refusal text.
struct YamlSaveRequest {
    std::string yaml_source;
    std::string id;
    std::optional<std::int64_t> expected_updated_at;
};
[[nodiscard]] std::expected<YamlSaveRequest, std::string>
parse_yaml_save_body(const nlohmann::json& body);

/// The `validate-yaml` request: `yaml_source` (a string; empty is allowed and validates to the
/// store's own "missing" errors) and nothing else.
[[nodiscard]] std::expected<std::string, std::string>
parse_yaml_validate_body(const nlohmann::json& body);

/// A parsed YAML's `plugin` / `action` must meet `check_dispatch_identifier` when present. Returns
/// the refusal text or nullopt. (`validate_and_prepare` enforces only a non-empty plugin; the operator
/// import path applies `check_dispatch_identifier` itself.)
[[nodiscard]] std::optional<std::string>
check_yaml_dispatch_fields(const instruction_yaml::DefinitionFields& fields);

/// A parsed YAML's `name` and `version` meet the same bounds the JSON builders enforce (the YAML
/// cannot express `instruction_set_id`), and its `description` meets `kMaxDefinitionImportDescriptionLen`
/// (the same bound as the operator import; wider than the builders' 512 because the bundled content
/// carries descriptions past that). An absent field is not checked here
/// (required-ness is `validate_definition_yaml`'s). Returns the refusals, in field order; same
/// texts as the builders.
[[nodiscard]] std::vector<std::string>
check_yaml_field_bounds(const instruction_yaml::DefinitionFields& fields);

/// The byte-level refusal of a YAML source that must not be parsed at all: a NUL byte or more than
/// `kMaxDefinitionYamlSourceBytes`. Returns the exact text `validate_definition_yaml` reports for
/// it, or nullopt. A separate pure function so the "refuse before any parse" rule is unit-testable
/// by its verdict (`validate_yaml_for_authoring` returns on it before running the parser).
[[nodiscard]] std::optional<std::string> yaml_source_byte_refusal(const std::string& yaml_source);

/// Store error text for an audit-row detail. The one caller-controlled echo in the import path is
/// `invalid approval_mode: <value> (must be ...)`: that value is bounded and folded through
/// `log_token` (CR/LF, ESC and every other control byte, C1 controls, U+2028/U+2029 and invalid
/// UTF-8 become `_`) and the fixed text around it is kept byte for byte, so a SIEM rule keying on
/// the prefix still matches. Any other text is flattened to one line, cut to 200 bytes, and
/// folded through `log_token` only when it holds a byte that needs it. Shared by the v1 REST and
/// MCP import twins.
[[nodiscard]] std::string audit_store_error_text(const std::string& err);

/// The ONE error list the YAML authoring twins answer: `validate_yaml_source`'s errors followed by
/// the `check_yaml_dispatch_fields` refusal of the parsed document. `validate_definition_yaml`
/// never checks the plugin/action charset or length, but a save refuses them, so validate-pass must
/// imply save-pass: `POST /api/v1/instructions/validate-yaml`, MCP `validate_definition_yaml`,
/// `POST /api/v1/instructions/yaml` and MCP `save_definition_yaml` all call this and nothing else
/// for the document's own validity. Empty = the save will not fail validation (it can still
/// conflict on an id or a stale `updated_at`). A source `yaml_source_byte_refusal` refuses is never
/// parsed. The legacy validate route is deliberately NOT moved onto it.
[[nodiscard]] std::vector<std::string> validate_yaml_for_authoring(const std::string& yaml_source);

/// An UPDATE's id is authoritative: a YAML naming a DIFFERENT `metadata.id` would be stored
/// verbatim and fork the definition on a later re-import. Returns the refusal text or nullopt.
[[nodiscard]] std::optional<std::string>
check_yaml_update_id(const instruction_yaml::DefinitionFields& fields, std::string_view def_id);

/// How an `InstructionStore` mutation error string classifies. The store signals the class by
/// prefix (`kInstructionStoreDbErrorPrefix`, `not_found: `, `kConflictPrefix`); anything else is a
/// validation refusal the caller's input caused. ONE classifier for the v1 REST routes and the MCP
/// tools so the two cannot map the same store error to different outcomes.
enum class StoreFault { kDb, kNotFound, kConflict, kInvalid };

[[nodiscard]] StoreFault classify_store_error(const std::string& err);

/// The definition a YAML-save CREATE writes: the YAML's own fields plus the create defaults
/// (`version` "1.0.0", `type` "question", `concurrency_mode` "per-device", `approval_mode`
/// "auto", enabled). `def.id` is the YAML's `metadata.id` (empty = the store generates one).
/// Shared by `POST /api/v1/instructions/yaml` and the MCP `save_definition_yaml`.
[[nodiscard]] InstructionDefinition
definition_from_yaml_fields(const instruction_yaml::DefinitionFields& fields,
                            const std::string& yaml_source, std::string_view created_by);

} // namespace yuzu::server
