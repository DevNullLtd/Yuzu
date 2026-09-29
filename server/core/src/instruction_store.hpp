#pragma once

/// @file instruction_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0058, schema `instruction_store`) for the content-plane
/// catalog `docs/Instruction-Engine.md` describes: `InstructionDefinition -> InstructionSet ->
/// ProductPack`. Two tables, no FK between them (`instruction_set_id` is a soft TEXT reference;
/// `delete_set` unsets it on referencing definitions rather than relying on a cascade).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime — a
/// silent-empty definition read breaks dispatch (`execute_instruction` resolves definitions
/// here). `create_definition`/`update_definition`/`import_definition_json`/
/// `import_definition_json_trusted`/`create_set` already returned `std::expected`
/// pre-migration; `query_definitions`/`get_definition`/`list_sets`/`delete_definition`/
/// `delete_set`/`export_definition_json` are widened to `std::expected` here (ADR-0036
/// typed-read policy) so a genuine DB error is never collapsed into "no definitions" / "not
/// found" — matching `ProductPackStore::get`'s `std::expected<std::optional<T>, std::string>`
/// shape.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement. Mutate-and-return uses `RETURNING` where a caller needs to distinguish "inserted"
/// from "conflicted" — never a bare `PGRES_COMMAND_OK` on `ON CONFLICT DO NOTHING`.
///
/// **No legacy-SQLite backfill (ADR-0009's fresh-start-by-default class).** Unlike most stores
/// on the Postgres migration ladder, this store does NOT read the pre-migration
/// `instructions.db` on cutover — no production fleet has ever run a pre-Postgres build of any
/// Yuzu store, so there is no real legacy data to protect. Follows `ResponseStore`'s
/// unconditional-skip precedent: no flag, no `migrate_from_sqlite`, just a one-time boot log
/// line noting the fresh start.
///
/// **Seed-vs-live semantics (ADR-0058, the headline decision).** The boot-time reseed loop
/// (`server.cpp`'s every-boot walk of `kBundledDefinitions`/`kBundledSets`) stays
/// conflict-skip-on-id-existence, content-blind, exactly as pre-migration — an operator's edit
/// to a bundled definition is never clobbered by a later reseed. Deletion, however, is now an
/// INTENTIONAL SUPPRESSION rather than a plain DELETE: `deleted_seed_content(kind, id)` records
/// every deleted definition/set id, consulted ONLY by the seed-aware insert paths below — never
/// by any read path, any normal `create_definition`/`create_set` call, or any
/// authorization/targeting decision. This is a DELIBERATE BEHAVIOUR
/// CHANGE from the pre-migration SQLite store, which resurrected an operator-deleted bundled
/// definition on the very next boot (pinned and then inverted — see
/// `tests/unit/server/test_instruction_store.cpp` tag `[instruction_store][seed]`). See
/// `docs/adr/0058-instruction-store-postgres-migration.md` for the full reasoning, the
/// independent-model consult that informed it, and what this migration does NOT solve (an
/// untouched-but-stale bundled row never auto-refreshes to newer bundled content on a release
/// upgrade — flagged as a follow-up, not fixed here).
///
/// **Two named entry points make the seed-vs-tombstone distinction explicit at every call
/// site**, mirroring `import_definition_json`/`import_definition_json_trusted`'s existing
/// signature-trust-boundary pattern:
///   - `import_definition_json_trusted` (its own signature gate bypass is unchanged) now ALSO
///     routes through the seed-aware insert path internally — it is exclusively the boot-loop
///     caller (no REST/MCP/network surface reaches it, by design), so `!check_signature` is
///     already a sound proxy for "this is the reseed loop."
///   - `create_set_seed` is a NEW public method, the set-side seed-aware entry point (sets have
///     no signature concept at all — "seed" names the actual distinction being made, not
///     "trusted", which would misleadingly imply one). Plain `create_set` is unchanged — used by
///     the REST-facing "create a custom instruction set" route, no lock, no tombstone
///     consultation, exactly as before.
/// Callers of `create_set_seed` MUST be internal boot-time code — there is no REST/MCP/network
/// surface for this method by design, matching `import_definition_json_trusted`'s contract.
///
/// No secrets (ADR-0010 N/A): verified against `docs/Instruction-Engine.md`/
/// `docs/yaml-dsl-spec.md`, neither of which defines a secret-typed/credential-bearing YAML
/// field — the only crypto-adjacent fields are the definition's public `signature`/`publicKey`
/// pair (Ed25519), not secret material. Free-text columns are `sanitize_pg_text`'d before every
/// write (NUL-truncation hygiene over libpq's C-string text binding), applied AFTER signature
/// verification, over the pre-sanitized bytes — mirrors `product_pack_store.hpp`'s identical
/// note; `verify_signature` runs once over the exact bytes that were signed.
///
/// **No `mtx_`** (the pre-migration `shared_mutex` is dropped) — Postgres's MVCC + the pool's
/// own connection-level concurrency replace it, matching every other migrated store on the
/// ladder.

#include "store_errors.hpp"

#include <atomic>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `InstructionStore` `unexpected()` that represents a
/// genuine DB/lease failure rather than caller-input validation, a signature/policy rejection,
/// or a not-found error (mirrors `ProductPackStore::kProductPackDbErrorPrefix` — both alias
/// the single shared `kDbErrorPrefix`, `store_errors.hpp`). Callers classify: `"not_found:"`
/// prefix -> 404, this prefix -> 503, else -> 400.
inline constexpr std::string_view kInstructionStoreDbErrorPrefix = kDbErrorPrefix;

struct InstructionDefinition {
    std::string id;
    std::string name;
    std::string version;
    std::string type; // "question" or "action"
    std::string plugin;
    std::string action;
    std::string description;
    bool enabled{true};
    std::string instruction_set_id;
    int gather_ttl_seconds{300};
    int response_ttl_days{90};
    std::string created_by;
    int64_t created_at{0};
    int64_t updated_at{0};
    // Extended fields (Phase 2)
    std::string yaml_source;      // verbatim YAML (source of truth)
    std::string parameter_schema; // JSON Schema for parameters
    std::string result_schema;    // result column definitions JSON
    std::string approval_mode;    // "auto", "role-gated", "always"
    std::string concurrency_mode; // "per-device", "per-definition", etc.
    std::string platforms;        // comma-separated: "windows,linux,darwin"
    std::string min_agent_version;
    std::string required_plugins; // comma-separated
    std::string readable_payload; // e.g. "Inspect service '${serviceName}'"
    // Issue #253: spec.visualization serialized as JSON. Empty (or "{}") means
    // the definition has no visualization configured and the
    // /api/v1/executions/{id}/visualization endpoint returns 404 for it.
    std::string visualization_spec;
    // Issue #254 (8.2): spec.responseTemplates serialized as a JSON array of
    // template objects. Empty (or "[]") means no operator-defined templates;
    // the response-templates engine synthesises a __default__ from
    // result_schema / plugin columns at read time.
    std::string response_templates_spec;
};

struct InstructionQuery {
    std::string name_filter;
    std::string plugin_filter;
    std::string type_filter;
    std::string set_id_filter;
    bool enabled_only{false};
    int limit{100};
};

struct InstructionSet {
    std::string id;
    std::string name;
    std::string description;
    std::string created_by;
    int64_t created_at{0};
};

/// Store-level yaml_source gates shared by create AND update (size cap,
/// scope-walking `fromResultSet` combos, inline flow-mapping rejection).
/// Exposed so the dashboard validate-yaml/preview endpoints can run the same
/// gates ahead of Save — validate must never pass a document the store then
/// rejects (#1993 / governance UP-3). Returns the error, or nullopt when OK.
std::optional<std::string> validate_definition_scope(const std::string& yaml_source);

/// Full byte-level + store-level YAML validation, shared by `POST
/// /api/instructions/validate-yaml` (`instruction_routes.cpp`), the `POST
/// /api/instructions/yaml` save path (`instruction_routes.cpp`), and `POST
/// /fragments/instructions/yaml-preview` (`instruction_fragment_routes.cpp`,
/// #2542 PR-12) — one contract, so
/// YAML that passes validation can always be saved (#1993). Runs
/// `instruction_yaml::validate_definition_yaml` (byte-level: required
/// fields, structural shape) first, then `validate_definition_scope` above
/// (store-level: size cap, scope-walking combos) only when the byte-level
/// pass is already clean. Returns human-readable errors; empty means valid.
///
/// Promoted from `ServerImpl::validate_yaml_source` (#2542 PR-7) rather than
/// duplicated into `instruction_routes.cpp`: `POST /fragments/instructions/
/// yaml-preview` was NOT one of the 13 routes that extraction moved (it
/// stayed inline in server.cpp at PR-7 time, later extracted into its own
/// `instruction_fragment_routes.cpp`, #2542 PR-12) and shares this exact
/// function, so copying it would have created a second copy of the very
/// validate/save consistency contract this function's own doc comment
/// promises — the #2557 `json_extract.hpp` precedent for a call-site-
/// straddling helper. Unqualified call sites inside `ServerImpl`/
/// `yuzu::server::instruction_fragment` (both `yuzu::server`-nested)
/// resolve here via ordinary namespace lookup; no call site's calling
/// syntax changed when the route moved.
std::vector<std::string> validate_yaml_source(const std::string& yaml_source);

class InstructionStore {
public:
    /// Borrows the shared pool and runs the `instruction_store` schema migration on a pinned
    /// lease. `is_open()` is false if the lease was empty or the migration failed.
    explicit InstructionStore(pg::PgPool& pool);

    InstructionStore(const InstructionStore&) = delete;
    InstructionStore& operator=(const InstructionStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counters
    /// (`yuzu_server_instruction_read_degrade_total{reason}`) and their write-side counterpart,
    /// matching `ProductPackStore`/`CustomPropertiesStore`'s #1675 convention. Set ONCE during
    /// single-threaded startup. A null registry (the default, e.g. in unit tests) disables
    /// emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// When true, `import_definition_json` rejects payloads that lack a
    /// `signature` field. Payloads WITH a signature are always verified
    /// regardless of the flag — failed verification rejects unconditionally.
    /// Defaults to true since #1073 / W7.4 sibling-gap closure: unsigned
    /// instruction imports are a fleet-wide arbitrary-code-execution surface
    /// (an operator with InstructionDefinition:Write can publish a malicious
    /// definition that executes on every targeted agent). Operators with
    /// legacy unsigned import flows must explicitly opt out via the
    /// `--allow-unsigned-definitions` / `YUZU_ALLOW_UNSIGNED_DEFINITIONS`
    /// server flag, which calls `set_require_signed_definitions(false)` and
    /// emits a `server.unsigned_definitions_allowed` startup audit event —
    /// exact parity with #802 / `--allow-unsigned-packs`.
    ///
    /// Atomic for the same reason as `ProductPackStore::require_signed_packs_`: the setter is
    /// called at startup before any concurrent reader, but TSAN cannot prove that; atomic
    /// load/store with relaxed memory order silences TSAN and future-proofs against any later
    /// runtime-toggle endpoint.
    void set_require_signed_definitions(bool require) {
        require_signed_definitions_.store(require, std::memory_order_relaxed);
    }
    bool require_signed_definitions() const {
        return require_signed_definitions_.load(std::memory_order_relaxed);
    }

    // Definitions

    /// `unexpected(msg)` (prefixed `kInstructionStoreDbErrorPrefix`) is a genuine read failure —
    /// never treat it as "no definitions match."
    std::expected<std::vector<InstructionDefinition>, std::string>
    query_definitions(const InstructionQuery& q = {}) const;

    /// `nullopt` = a successful read finding none; `unexpected(msg)` (prefixed
    /// `kInstructionStoreDbErrorPrefix`) = a genuine read failure — never treat the latter as
    /// "not found." Matches `ProductPackStore::get`'s exact shape.
    std::expected<std::optional<InstructionDefinition>, std::string>
    get_definition(const std::string& id) const;

    std::expected<std::string, std::string> create_definition(const InstructionDefinition& def);
    std::expected<void, std::string> update_definition(const InstructionDefinition& def);

    /// `unexpected("not_found: ...")` when no definition with this id exists; any other
    /// `unexpected(msg)` (prefixed `kInstructionStoreDbErrorPrefix`) is a genuine failure.
    /// Stamps `deleted_seed_content` in the SAME transaction as the delete (ADR-0058
    /// seed-suppression) under `kSeedCoordLockSql`.
    std::expected<void, std::string> delete_definition(const std::string& id);

    // Import/Export

    /// `unexpected(msg)` (prefixed `kInstructionStoreDbErrorPrefix`) on a genuine read failure
    /// — never treat as "nothing to export." Returns `"{}"` only for a successful read that
    /// found nothing.
    std::expected<std::string, std::string> export_definition_json(const std::string& id) const;

    /// Parse a JSON-encoded InstructionDefinition envelope and create it.
    ///
    /// SECURITY SCOPE (#1073): this method gates the **import** surface
    /// — definitions that arrive from outside the operator's authoring
    /// session, e.g. CI-built packs, content distributed via the
    /// supply chain, manifests fetched from a registry. The signature
    /// + `require_signed_definitions_` gate authenticates the publisher,
    /// not the operator pushing the import. Failed verification rejects
    /// regardless of the flag.
    ///
    /// **NOT in scope of this method:** the authoring surfaces
    /// (`POST /api/instructions`, `POST /api/instructions/yaml`, and
    /// `PUT /api/instructions/{id}`) that go through `create_definition`
    /// /`update_definition` directly. Those surfaces trust the
    /// `InstructionDefinition:Write` RBAC permission as the author
    /// trust boundary (the operator IS the source — there is no supply
    /// chain to authenticate). See follow-up issue for the architectural
    /// question of whether the authoring surfaces should ALSO require
    /// signed envelopes (operator-decision-required, UX trade-off).
    ///
    /// Wire format for signing:
    ///   * Optional top-level `signature` field — hex-encoded Ed25519
    ///     signature over the `yaml_source` field's bytes verbatim.
    ///   * Optional top-level `publicKey` field — hex-encoded Ed25519
    ///     public key (64 hex chars / 32 bytes).
    ///   * `yaml_source` is the authoritative signed-content carrier
    ///     (mirrors ProductPack's YAML-document signing model). If the
    ///     import lacks `yaml_source` the signature can never verify.
    ///   * Both fields present + valid signature → accept.
    ///   * Both present + invalid signature → reject (tampered).
    ///   * Neither present → unsigned; gated by `require_signed_definitions_`.
    ///   * Exactly one present → reject (incomplete signing metadata).
    ///   * Field present but wrong JSON type (non-string) → reject as
    ///     `incomplete signing metadata` (distinct error message).
    ///   * Signature/publicKey wrong length → reject before allocation
    ///     (DoS amplification guard).
    std::expected<std::string, std::string> import_definition_json(const std::string& json);

    /// Trusted-content variant — bypasses the signature gate AND routes through the seed-aware
    /// insert path (ADR-0058 — see the file header's "Seed-vs-live semantics" section). ONLY
    /// for build-time-baked content (the `kBundledDefinitions` boot seed in `bundled_content.cpp`),
    /// where the authenticity of the bytes is established by the build-time linkage into the
    /// binary itself, not by a runtime signature. The operator-facing
    /// `--allow-unsigned-definitions` flag controls the public path only;
    /// it does NOT affect this trusted path. Callers MUST be internal
    /// boot-time code — there is no REST / MCP / network surface for this
    /// method by design.
    std::expected<std::string, std::string> import_definition_json_trusted(const std::string& json);

    // Instruction Sets

    /// `unexpected(msg)` (prefixed `kInstructionStoreDbErrorPrefix`) is a genuine read failure —
    /// never treat it as "no sets."
    std::expected<std::vector<InstructionSet>, std::string> list_sets() const;

    /// Operator-facing entry point — no lock, no `deleted_seed_content` consultation. Used by
    /// the REST "create a custom instruction set" route.
    std::expected<std::string, std::string> create_set(const InstructionSet& s);

    /// Boot-time seed-aware entry point (ADR-0058) — used ONLY by `server.cpp`'s
    /// `kBundledSets` reseed loop. Same id-existence conflict-skip semantics as `create_set`,
    /// PLUS: an id present in `deleted_seed_content` (an operator having deleted this bundled
    /// set via `delete_set`) is ALSO treated as a conflict-skip, so an every-boot replay can
    /// never resurrect it. Takes `kSeedCoordLockSql` as its first statement. No REST/MCP/network
    /// surface reaches this method by design, matching `import_definition_json_trusted`.
    std::expected<std::string, std::string> create_set_seed(const InstructionSet& s);

    /// `unexpected("not_found: ...")` when no set with this id exists; any other
    /// `unexpected(msg)` (prefixed `kInstructionStoreDbErrorPrefix`) is a genuine failure.
    /// Unsets `instruction_set_id` on every referencing definition and stamps
    /// `deleted_seed_content` in the SAME transaction as the delete, under `kSeedCoordLockSql`.
    std::expected<void, std::string> delete_set(const std::string& id);

private:
    pg::PgPool& pool_;
    bool open_{false};
    /// Security-by-default since #1073 (W7.4 sibling-gap closure): imports
    /// without a `signature` field are rejected by `import_definition_json`.
    /// See setter doc above for the operator opt-out flag.
    std::atomic<bool> require_signed_definitions_{true};
    yuzu::MetricsRegistry* metrics_{nullptr};

    // Shared validation (name/type/plugin required; yaml_source scope gates; explicit-id
    // charset + length + reserved-namespace checks) — pure C++/string logic, no DB access.
    // Mutates `def.id` to a generated id when the caller supplied none. Returns the (possibly
    // generated) id on success.
    std::expected<std::string, std::string> validate_and_prepare(InstructionDefinition& def) const;

    // Executes the INSERT for an already-validated definition. `is_seed=false` (every normal
    // caller: create_definition, and import_definition_json's signed path) is a plain
    // `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id`, no lock, no tombstone consultation.
    // `is_seed=true` (import_definition_json_trusted only) takes `kSeedCoordLockSql` first, then
    // checks `deleted_seed_content` before inserting — ADR-0058.
    std::expected<std::string, std::string> insert_definition_row(const InstructionDefinition& def,
                                                                   bool is_seed);

    // Executes the INSERT for an already-validated set, mirroring insert_definition_row's
    // is_seed split. Shared by create_set (is_seed=false) and create_set_seed (is_seed=true).
    std::expected<std::string, std::string> insert_set_row(const InstructionSet& s, bool is_seed);

    /// Shared implementation behind `import_definition_json` and
    /// `import_definition_json_trusted`. When `check_signature` is true,
    /// runs the #1073 Ed25519 signature gate against `signature` +
    /// `publicKey` + `yaml_source` JSON fields before parsing the
    /// definition. When false, bypasses the gate entirely AND routes the
    /// final insert through the seed-aware path (ADR-0058). Public callers
    /// must use one of the two named entry points so the trust boundary
    /// is explicit at every call site.
    std::expected<std::string, std::string> import_definition_json_impl(const std::string& json,
                                                                        bool check_signature);
};

} // namespace yuzu::server
