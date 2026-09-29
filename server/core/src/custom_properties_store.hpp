#pragma once

/// @file custom_properties_store.hpp
/// Migrated Postgres store (ADR-0006/ADR-0045, schema `custom_properties_store`).
/// Typed operator-authored metadata for devices — property VALUES the operator
/// sets per-agent (`custom_properties`) plus optional per-key TYPE/VALIDATION
/// definitions (`custom_property_schemas`) — usable in scope expressions via
/// `props.<key>` (`AgentRegistry::evaluate_scope`, `docs/asset-tagging-guide.md`).
///
/// **Posture: AUTHORITATIVE (ADR-0012 §1)** — device custom properties and
/// their schemas are irreducible operator intent (asset-tagging data feeding
/// scope/dispatch targeting), not expendable telemetry. Construction fails
/// CLOSED (ADR-0007/ADR-0012 §1: `!is_open()` → `startup_failed_`). Every
/// runtime read/write that can feed a scope/dispatch decision returns a typed
/// `std::expected`/`std::optional` distinguishing "read fine, genuinely
/// nothing here" from "DB error, could not read" (2026-07-25 program policy,
/// `docs/postgres-store-playbook.md` "Authoritative reads must be
/// type-distinguishable", ADR-0036) — a caller that collapses a DB error to
/// an empty/false result feeding `props.<key>` scope evaluation reproduces the
/// exact `NOT from_result_set:<id>` fleet-wide fail-open ADR-0036 closed,
/// just on this store's data instead. See `AgentRegistry::evaluate_scope`
/// (`agent_registry.cpp`) for how the typed channel is consumed.
///
/// **Cross-table validation stays application-layer, not a Postgres FK/CHECK**
/// (decision recorded per the kickoff doc's explicit prompt): `set_property`'s
/// `validate_against_schema` reads `custom_property_schemas` for the given key
/// and enforces type/regex before the write — same behavior as the SQLite
/// original. A real FK from `custom_properties.type` to
/// `custom_property_schemas.type` doesn't fit the data model (schemas are
/// optional per-key policy, not a fixed enum a property's `type` column must
/// reference) and a schema key can be deleted out from under existing
/// properties without orphaning them (SQLite behavior preserved: existing
/// property rows are untouched by `delete_schema`, matching how the original
/// `DELETE FROM custom_property_schemas` never touched `custom_properties`).
///
/// **Secrets: none.** Property values are free-form operator-set text (max
/// 1024 bytes, `validate_value`) with no dedicated secret column or schema
/// commitment to structured secret material — same conclusion the kickoff doc
/// asked to be stated explicitly, not silently assumed. An operator COULD
/// paste a credential-shaped string into a property value, but that is true
/// of any free-text field in the product (a tag value, a management-group
/// description) and is not treated as a `SecretCodec`-requiring column
/// anywhere else in the codebase; ADR-0010's secrets seam targets columns the
/// STORE itself commits to holding secret material, not free text an operator
/// could theoretically misuse.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`custom_properties_store.*`)
/// — pooled connections carry no per-store `search_path`. Mutate-and-return
/// uses `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b,
/// #3623): no production fleet ever ran a pre-Postgres build of this store —
/// see ADR-0045's Update. `server.cpp` now runs a detect-and-warn probe over
/// the legacy file instead.

#include <libpq-fe.h> // PGconn — private_ methods below take a live connection; see api_token_store.hpp's rationale for including directly rather than forward-declaring libpq's private `pg_conn` tag.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `CustomPropertiesStore` `unexpected()`
/// string that represents a genuine DB/lease failure rather than caller-input
/// validation or a schema-mismatch business rule (mirrors `DeploymentStore`'s
/// `kDeploymentDbErrorPrefix` idiom, `deployment_store.hpp`). Exported here —
/// not left as a private literal duplicated at the REST-route classification
/// site — so the two can never silently drift apart (same "gov F3" reasoning
/// DeploymentStore's own comment records). Applies to `set_property` and
/// `upsert_schema`'s `std::expected<void, std::string>` error channel only;
/// the typed-`CustomPropertiesReadError` reads below don't need it — they
/// already carry `kDegraded` as a distinct type, not a string to classify.
inline constexpr const char* kCustomPropertiesDbErrorPrefix = "db_error: ";

struct CustomProperty {
    std::string agent_id;
    std::string key;
    std::string value;
    std::string type; // "string", "int", "bool", "datetime"
    std::int64_t updated_at{0};
};

struct CustomPropertySchema {
    std::string key;
    std::string display_name;
    std::string type; // "string", "int", "bool", "datetime"
    std::string description;
    std::string validation_regex;
};

/// Error type for the authoritative reads. The success type is an
/// `std::optional<T>`/container: a value == found, absent/empty == the read
/// succeeded and there is genuinely nothing there. `std::unexpected(kDegraded)`
/// == store/pool/query failure — the caller MUST NOT treat this the same as
/// "not found"/"no properties" on any path that feeds a scope/dispatch
/// decision (`props.<key>` resolution). Mirrors `CiReadError`/`RegistryReadError`
/// (out-params are forbidden in new code — docs/cpp-conventions.md).
enum class CustomPropertiesReadError { kDegraded };

/// Typed custom metadata for devices, usable in scope expressions via `props.<key>`.
class CustomPropertiesStore {
public:
    /// Borrows the shared pool and runs the `custom_properties_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before reaching
    /// here, so in production the migration runs against a proven-reachable
    /// database).
    explicit CustomPropertiesStore(pg::PgPool& pool);

    CustomPropertiesStore(const CustomPropertiesStore&) = delete;
    CustomPropertiesStore& operator=(const CustomPropertiesStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_server_custom_properties_read_degrade_total{reason}`). Set ONCE
    /// during single-threaded startup, before serving begins; a null registry
    /// (the default, e.g. in unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // ── Property CRUD ────────────────────────────────────────────────────

    /// All custom properties for an agent, key-ordered. `std::unexpected` on
    /// a store/pool/query failure — see the type-distinguishable-reads note
    /// above; a caller feeding a scope/dispatch decision off this MUST treat
    /// `kDegraded` as "cannot evaluate", never as "no properties".
    [[nodiscard]] std::expected<std::vector<CustomProperty>, CustomPropertiesReadError>
    get_properties(const std::string& agent_id) const;

    /// A single property. `nullopt` == read fine, no such property.
    /// `std::unexpected` == store/pool/query failure.
    [[nodiscard]] std::expected<std::optional<CustomProperty>, CustomPropertiesReadError>
    get_property(const std::string& agent_id, const std::string& key) const;

    /// Property value as a string. `nullopt` == read fine, not found. A
    /// found property with an empty value returns an ENGAGED
    /// `optional{""}`, distinguishable from `nullopt` (unlike the prior
    /// plain-`std::string` `get_value` contract, where both cases returned
    /// the same empty string). `std::unexpected` == store/pool/query
    /// failure. NOT the accessor `AgentRegistry::evaluate_scope`'s
    /// `props.<key>` resolver uses — that's the bulk `get_values_for_keys`
    /// below, which preloads once for the whole agent loop rather than
    /// per-agent.
    [[nodiscard]] std::expected<std::optional<std::string>, CustomPropertiesReadError>
    get_value(const std::string& agent_id, const std::string& key) const;

    /// All properties for an agent as a map (bulk preload for scope
    /// evaluation — see `AgentRegistry::evaluate_scope`). `std::unexpected`
    /// on a store/pool/query failure; an empty map on success means
    /// genuinely no properties.
    [[nodiscard]] std::expected<std::unordered_map<std::string, std::string>,
                                CustomPropertiesReadError>
    get_property_map(const std::string& agent_id) const;

    /// Fleet-wide bulk preload for exactly the keys a scope expression
    /// references: `agent_id -> (key -> value)`, restricted to `keys`. ONE
    /// query for however many agents/keys match, never a per-agent
    /// round-trip in a loop — the shape `AgentRegistry::evaluate_scope`'s
    /// `props.<key>` resolution preload uses (same reasoning as the
    /// `from_result_set:` membership preload it already does: preload once
    /// before the agent loop, not a store query per agent while holding
    /// `AgentRegistry::mu_`). `std::unexpected` on a store/pool/query
    /// failure — the caller MUST treat this the same as the
    /// `from_result_set:` preload's `DbError`: abort the whole scope
    /// evaluation, never silently resolve every `props.<key>` atom to "no
    /// match" (which inverts to "matches every agent" under `NOT`). An empty
    /// `keys` returns an empty map without a query.
    [[nodiscard]] std::expected<std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
                                CustomPropertiesReadError>
    get_values_for_keys(const std::vector<std::string>& keys) const;

    /// Set a property. Validates against schema if one exists.
    std::expected<void, std::string> set_property(const std::string& agent_id,
                                                   const std::string& key,
                                                   const std::string& value,
                                                   const std::string& type = "string");

    /// Delete a property. Returns false on "not found" AND on a store/query
    /// failure alike (matches the prior SQLite contract's boolean shape —
    /// deletion is not a scope/dispatch-feeding read, so this is not widened
    /// to a typed error).
    [[nodiscard]] bool delete_property(const std::string& agent_id, const std::string& key);

    /// Delete all properties for an agent. Best-effort (logged on failure).
    void delete_all_properties(const std::string& agent_id);

    // ── Schema CRUD ──────────────────────────────────────────────────────

    /// All defined property schemas, key-ordered. Empty on either "no
    /// schemas" or a store/query failure (matches the prior SQLite contract
    /// — schema listing is an admin-surface read, not scope/dispatch-feeding).
    [[nodiscard]] std::vector<CustomPropertySchema> list_schemas() const;

    /// A single schema. `nullopt` == read fine, no such schema.
    /// `std::unexpected(kDegraded)` == store/pool/query failure — widened
    /// from a plain `std::optional` (gov Gate 8 finding, fjarvis re-review of
    /// PR #3065): unlike `list_schemas`/`delete_property`, this had no
    /// callers to justify keeping the SQLite-era not-found/degrade
    /// conflation, so there was no reason to keep it. Not currently called
    /// by any REST route (schema lookup is only exposed via `list_schemas`
    /// today) — widened ahead of a future caller inheriting the wrong shape.
    [[nodiscard]] std::expected<std::optional<CustomPropertySchema>, CustomPropertiesReadError>
    get_schema(const std::string& key) const;

    /// Create or update a property schema.
    std::expected<void, std::string> upsert_schema(const CustomPropertySchema& schema);

    /// Delete a property schema. `true` == deleted, `false` == read fine, no
    /// such schema. `std::unexpected(kDegraded)` == store/pool/query failure
    /// — widened for the same reason as `get_schema` above (gov Gate 8
    /// finding, fjarvis re-review of PR #3065).
    [[nodiscard]] std::expected<bool, CustomPropertiesReadError> delete_schema(const std::string& key);

    // ── Validation ───────────────────────────────────────────────────────

    /// Validate key: 1-64 chars, [a-zA-Z0-9_.-:]
    static bool validate_key(const std::string& key);

    /// Validate value: max 1024 bytes
    static bool validate_value(const std::string& value);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    /// Validate a value against the schema for a key (if one exists). Runs on
    /// the SAME lease as the caller's write (no separate schema-read lease —
    /// keeps `set_property` to one logical operation, ADR-0012 §2(c)), and
    /// its ONE query is also the caller's sole source for the schema's type
    /// (a second, separate "what type does this schema have" query would
    /// read a possibly-different row under READ COMMITTED if a concurrent
    /// `upsert_schema`/`delete_schema` commits between the two statements —
    /// governance Gate 4 unhappy-path, this PR). Returns the schema's type
    /// on success when a schema exists (`nullopt` when none does); a query
    /// failure is `std::unexpected` — NOT silently treated as "no schema"
    /// (that conflation was a validation-bypass gap the SQLite original's
    /// prepare-failure fallthrough carried over unnoticed).
    std::expected<std::optional<std::string>, std::string>
    validate_against_schema(PGconn* conn, const std::string& key, const std::string& value) const;
};

} // namespace yuzu::server
