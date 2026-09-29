#pragma once

/// @file tag_store.hpp
/// Migrated Postgres store (ADR-0006/ADR-0050, schema `tag_store`). Device
/// tags — free-form operator/agent/API-authored key→value labels per agent,
/// plus the four fixed structured categories (`get_tag_categories`) — usable
/// in scope expressions via `tag:<key>` (`AgentRegistry::evaluate_scope`,
/// `docs/asset-tagging-guide.md`).
///
/// **Posture: AUTHORITATIVE (ADR-0012 §1)** — tags are scope-resolution
/// input: `tag:X` in the scope DSL resolves through this store, and scope
/// decides WHICH AGENTS a command reaches. Construction fails CLOSED
/// (ADR-0007/ADR-0012 §1: `!is_open()` → `startup_failed_`). Every runtime
/// read that can feed a scope/dispatch/confinement decision returns a typed
/// `std::expected` distinguishing "read fine, genuinely nothing here" from
/// "DB error, could not read" (2026-07-25 program policy, ADR-0036,
/// `docs/postgres-store-playbook.md` "Authoritative reads must be
/// type-distinguishable") — a caller that collapses a DB error to an
/// empty/false result feeding `tag:` scope evaluation or service-scoped
/// confinement under- OR over-targets a dispatch (the #2500 targeting
/// family). This SUPERSEDES the pre-migration two-accessor split
/// (`agents_with_tag` collapsing + `agents_with_tag_checked` distinguishing,
/// B-2b): the collapse-by-default accessor is removed rather than kept —
/// the "existing callers depend on the collapsed contract" rationale its
/// comment recorded dies in this same PR's caller sweep, and the program
/// policy postdates (and mandates widening at) this store's migration.
///
/// **Secrets: none.** Tag keys are validated identifiers (`validate_key`,
/// 1–64 chars `[a-zA-Z0-9_.:-]`) and values are free-form operator/agent
/// text (max 448 bytes, `validate_value`) with no dedicated secret column
/// and no secret-valued tag convention anywhere in the tree (verified: no
/// caller writes credential material through this store — same conclusion,
/// and same free-text caveat, as `CustomPropertiesStore`'s header records
/// per ADR-0010's scope: the secrets seam targets columns the STORE commits
/// to holding secret material, not free text an operator could misuse).
///
/// **Source precedence (#1411)** is preserved across the migration: the PK
/// is (agent_id, key) with `source` outside the key; an 'agent'-sourced
/// write (self-reported `scopable_tags`, re-synced on every Register) may
/// only upsert when the existing row is itself agent-sourced or absent; any
/// non-'agent' source (operator/API/MCP) is authoritative and overwrites
/// unconditionally. Implemented as `ON CONFLICT … DO UPDATE … WHERE
/// tags.source = 'agent'` — semantics verified against live Postgres 18
/// (four cases: fresh insert, agent-over-agent, operator-unconditional,
/// agent-over-operator = 0-row clean no-op) before shipping, per the
/// playbook's "verify the exact upsert against a live Postgres instance"
/// rule.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned
/// lease, and schema-qualifies every runtime statement (`tag_store.*`) —
/// pooled connections carry no per-store `search_path`. Mutate-and-return
/// uses `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b,
/// #3623): no production fleet ever ran a pre-Postgres build of this store —
/// see ADR-0050's Update. `server.cpp` now runs a detect-and-warn probe over
/// the legacy file instead.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct DeviceTag {
    std::string agent_id;
    std::string key;
    std::string value;
    std::string source;    // "agent", "server", "api", "mcp"
    int64_t updated_at{0}; // epoch seconds
};

struct TagCategory {
    std::string_view key;
    std::string_view display_name;
    std::vector<std::string_view> allowed_values; // empty = free-form
};

// Fixed categories — the only structured tag categories that exist
inline constexpr std::string_view kCategoryKeys[] = {"role", "environment", "location", "service"};

const std::vector<TagCategory>& get_tag_categories();

/// Machine-checkable prefix on every `TagStore` `unexpected()` string that
/// represents a genuine DB/lease failure rather than caller-input validation
/// (mirrors `kCustomPropertiesDbErrorPrefix`, custom_properties_store.hpp).
/// Exported so the REST/MCP classification sites (#3097: degrade → 503,
/// caller/validation error → 400) can never silently drift from the store's
/// own error strings. Applies to the `std::expected<void, std::string>`
/// write channels only; the typed `TagReadError` reads carry `kDegraded` as
/// a distinct type, not a string to classify.
inline constexpr const char* kTagDbErrorPrefix = "db_error: ";

/// Error type for the authoritative reads. The success type is an
/// `std::optional<T>`/container: a value == found, absent/empty == the read
/// succeeded and there is genuinely nothing there. `std::unexpected(kDegraded)`
/// == store/pool/query failure — the caller MUST NOT treat this the same as
/// "not found"/"no tags" on any path that feeds a scope/dispatch/confinement
/// decision (`tag:<key>` resolution, service-scoped token confinement).
enum class TagReadError { kDegraded };

/// Device tags usable in scope expressions via `tag:<key>`.
class TagStore {
public:
    /// Borrows the shared pool and runs the `tag_store` schema migration on
    /// a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (the server fails closed before reaching here, so in
    /// production the migration runs against a proven-reachable database).
    explicit TagStore(pg::PgPool& pool);

    TagStore(const TagStore&) = delete;
    TagStore& operator=(const TagStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_server_tag_store_read_degrade_total{reason}`). Set ONCE during
    /// single-threaded startup, before serving begins; a null registry (the
    /// default, e.g. in unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // ── Writes ───────────────────────────────────────────────────────────

    /// Set a tag. Error strings prefixed `kTagDbErrorPrefix` are DB/lease
    /// failures (degrade → 503); anything else is caller-input validation
    /// (→ 400). An 'agent'-sourced write against an existing non-'agent'
    /// row is a SUCCESSFUL precedence no-op (#1411), not an error.
    [[nodiscard]] std::expected<void, std::string> set_tag(const std::string& agent_id,
                                                           const std::string& key,
                                                           const std::string& value,
                                                           const std::string& source = "server");

    /// Set tag with category validation. If key matches a category with
    /// allowed_values, value must be in the list. Delegates to set_tag()
    /// and — unlike the pre-migration contract — PROPAGATES the write
    /// result rather than swallowing it (kickoff lesson 3 / #3064: every
    /// mutator returns the error, every caller surfaces it).
    [[nodiscard]] std::expected<void, std::string>
    set_tag_checked(const std::string& agent_id, const std::string& key, const std::string& value,
                    const std::string& source = "server");

    /// Delete a tag. `true` == deleted, `false` == read fine, no such tag.
    /// `std::unexpected(kDegraded)` == store/pool/query failure — widened
    /// from the pre-migration bool (which conflated not-found with failure),
    /// same reasoning as `CustomPropertiesStore::delete_schema`.
    [[nodiscard]] std::expected<bool, TagReadError> delete_tag(const std::string& agent_id,
                                                               const std::string& key);

    /// Sync tags from agent registration (gRPC Register only — there is no
    /// heartbeat sync path, and ProxyRegister/gateway-proxied agents do not
    /// call this at all, tracked as #3372) — sets source="agent".
    /// One transaction: delete all agent-sourced tags, re-insert the
    /// reported set (operator/API rows survive per #1411; the precedence
    /// no-op on a per-row conflict is success, not failure). Malformed
    /// entries (invalid key/value) are skipped, matching the pre-migration
    /// contract. Any DB failure rolls the whole sync back — the agent keeps
    /// its prior complete tag set — and is returned (`kTagDbErrorPrefix`).
    [[nodiscard]] std::expected<void, std::string>
    sync_agent_tags(const std::string& agent_id,
                    const std::unordered_map<std::string, std::string>& tags);

    /// Delete all tags for an agent (every source). `kTagDbErrorPrefix` on
    /// a DB/lease failure.
    [[nodiscard]] std::expected<void, std::string> delete_all_tags(const std::string& agent_id);

    // ── Reads (typed; see TagReadError above) ────────────────────────────

    /// A single tag value. `nullopt` == read fine, no such tag. A present
    /// tag with an empty value returns an ENGAGED `optional{""}`,
    /// distinguishable from `nullopt` (unlike the pre-migration plain
    /// `std::string` contract, where both returned the same empty string).
    [[nodiscard]] std::expected<std::optional<std::string>, TagReadError>
    get_tag(const std::string& agent_id, const std::string& key) const;

    /// All tags for an agent, key-ordered.
    [[nodiscard]] std::expected<std::vector<DeviceTag>, TagReadError>
    get_all_tags(const std::string& agent_id) const;

    /// All tags for an agent as a key→value map.
    [[nodiscard]] std::expected<std::unordered_map<std::string, std::string>, TagReadError>
    get_tag_map(const std::string& agent_id) const;

    /// Agents carrying a tag key (optionally with a specific value).
    /// Replaces BOTH pre-migration accessors (`agents_with_tag` collapsing +
    /// `agents_with_tag_checked`, B-2b) — see the header comment for the
    /// supersession rationale. Feeds service-scoped confinement
    /// (`derive_exec_visible`) and dispatch targeting: a degraded read MUST
    /// fail the caller closed, never resolve to "no agents".
    [[nodiscard]] std::expected<std::vector<std::string>, TagReadError>
    agents_with_tag(const std::string& key, const std::string& value = {}) const;

    /// Fleet-wide bulk preload for exactly the keys a scope expression
    /// references: `agent_id -> (key -> value)`, restricted to `keys`. ONE
    /// query for however many agents/keys match — the shape
    /// `AgentRegistry::evaluate_scope`'s `tag:<key>` resolution preload
    /// uses (mirrors `CustomPropertiesStore::get_values_for_keys`, ADR-0045:
    /// preload once before the agent loop, never a per-agent store query
    /// while holding `AgentRegistry::mu_`). The caller MUST treat
    /// `kDegraded` as "abort the whole scope evaluation", never as "no
    /// match" (which inverts to "matches every agent" under `NOT`). An
    /// empty `keys` returns an empty map without a query.
    [[nodiscard]] std::expected<
        std::unordered_map<std::string, std::unordered_map<std::string, std::string>>,
        TagReadError>
    get_values_for_keys(const std::vector<std::string>& keys) const;

    /// Returns (agent_id, [missing category keys]) for agents missing any
    /// category tags. An agent is evaluated only if it has at least one tag
    /// row; a category is "missing" when no row exists OR the row's value
    /// is empty (both match the pre-migration semantics). Bulk: two queries
    /// on one lease, never the pre-migration per-agent×per-category loop
    /// (N×4 point lookups — the NFR anti-pattern — was tolerable on local
    /// SQLite, not on a network substrate).
    [[nodiscard]] std::expected<std::vector<std::pair<std::string, std::vector<std::string>>>,
                                TagReadError>
    get_compliance_gaps() const;

    /// Returns distinct values for a given tag key, sorted.
    [[nodiscard]] std::expected<std::vector<std::string>, TagReadError>
    get_distinct_values(const std::string& key) const;

    /// Returns the distinct tag keys present on any device (F2a cohort
    /// picker), sorted.
    [[nodiscard]] std::expected<std::vector<std::string>, TagReadError> get_distinct_keys() const;

    /// Bulk agent_id→value map for one key — ONE query instead of a
    /// per-agent get_tag loop (the F2a perf snapshot provider walks the
    /// whole fleet per render; N point lookups would be the NFR
    /// anti-pattern).
    [[nodiscard]] std::expected<std::unordered_map<std::string, std::string>, TagReadError>
    get_values_for_key(const std::string& key) const;

    // ── Validation ───────────────────────────────────────────────────────

    /// Validation: key max 64 chars [a-zA-Z0-9_.:-], value max 448 bytes
    static bool validate_key(const std::string& key);
    static bool validate_value(const std::string& value);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
