#pragma once

/// @file directory_sync.hpp
/// Postgres-backed directory sync store (ADR-0063, migration-programme PR 3
/// of the 7-store SQLite→Postgres ladder). Schema `directory_sync`, five
/// tables (`directory_users`, `directory_groups`, `directory_memberships`,
/// `directory_group_role_mappings`, `directory_sync_status`).
///
/// Posture (ADR-0012 §1): construction is fail-CLOSED (`is_open()` false ⇒
/// the server refuses to start, same as every other migrated store).
/// `sync_entra`/`sync_ldap` and every query method degrade to their
/// SQLite-era plain-container contract on a closed store or a failed query —
/// empty vector/map, default `SyncStatus`, `nullopt` — never a distinguished
/// degraded-vs-not-found signal. This is a deliberate, documented
/// non-upgrade: `discovery_routes.cpp` already gates every route on
/// `is_open()` before calling any query method (503 on a closed store), and
/// `access_review_model.cpp`'s `build_email_index` already treats a closed
/// store as "no enrichment" — both callers are shared with the sibling
/// `PatchManager` PR and outside this PR's blast radius, so a typed-degrade
/// read contract is structurally unavailable here, not merely declined.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of this store).
/// The legacy `directory-sync.db` is never read for data; construction logs
/// a one-time "fresh start, no legacy backfill" line, and `server.cpp` runs
/// `legacy_sqlite_probe::warn_if_legacy_rows` once at boot to warn (never
/// fail) if that file still holds real rows.
///
/// Only the ~111 SQL-touching lines of the original SQLite implementation
/// migrate — the Microsoft Graph OAuth2 token flow and the WinHTTP/httplib
/// transport are untouched, verbatim, with one exception: `fetch_paginated`
/// (below) is new client-side pagination logic, added once a security review
/// found the original single-page fetch dangerous rather than merely
/// incomplete once this port's stale-row deletion existed (see its own doc
/// comment).
///
/// Pre-existing self-deadlock fix (independent of the storage backend):
/// the SQLite-era `sync_entra` took `std::unique_lock lock(mtx_)` and, still
/// inside that scope, called `get_group_role_mappings()`, which itself took
/// `std::shared_lock lock(mtx_)` on the SAME non-recursive `std::shared_mutex`
/// — undefined behavior. `mtx_` is deleted entirely in this port: this store
/// carries no in-memory state beyond what now lives in Postgres, so the PG
/// connection pool's own concurrency model fully replaces it (per-store
/// recipe step 3) and the specific hazard class (a non-recursive lock
/// re-entered on the same thread) becomes structurally impossible, not
/// merely reordered.
///
/// The role-mapping-preservation behavior the buggy nested call was reaching
/// for is NOT resolved by a denormalized column on `directory_groups` — an
/// earlier revision of this port tried a `COALESCE` subselect inside the
/// group upsert statement (reasoning that one statement execution has no
/// read-then-write window), which adversarial review (2026-08-28)
/// empirically disproved with a two-connection libpq test: under READ
/// COMMITTED, a concurrent `configure_group_role_mapping` that commits after
/// the upsert's snapshot but before it acquires the `directory_groups` row
/// lock is invisible to the subselect even after Postgres's EvalPlanQual
/// retry (EvalPlanQual re-checks the conflicting row; it does not re-snapshot
/// unrelated tables the SET clause reads), silently clobbering the
/// concurrent write. `directory_groups` carries no `mapped_role` column at
/// all now — `get_synced_groups()` resolves it via `LEFT JOIN
/// directory_group_role_mappings` at read time, which has no window to race
/// because there is no second copy of the value to go stale.
///
/// `sync_entra`'s clear-then-repopulate cannot be one short Postgres
/// transaction end to end, because live external Microsoft Graph HTTP calls
/// happen in between fetching users, groups, and each group's membership
/// (ADR-0012 §2 forbids holding a lease across external work). Chosen shape
/// (recorded in the ADR): fetch the complete remote snapshot first
/// (`EntraSyncData`, built with no lease held), then apply it in ONE short
/// transaction (`apply_entra_sync`) — delete any `directory_users`/
/// `directory_groups` row absent from the new snapshot (Entra's own record
/// of what still exists), upsert every user/group the snapshot names, then
/// clear and repopulate `directory_memberships`. The SQLite era never
/// deleted stale users/groups either (upsert-only, verified against the base
/// commit) — this port closes that gap rather than silently carrying it
/// forward under this file's own "complete snapshot" framing (adversarial
/// review, 2026-08-28). Because deletion is now real, `sync_entra` hard-errors
/// on a malformed/missing Graph "value" array for BOTH users and groups (the
/// SQLite era silently treated a malformed groups response as "zero groups"
/// — safe there since nothing was ever deleted, but dangerous now: an empty
/// snapshot from a fetch problem would otherwise wipe every synced group).
/// Graph's `/groups/{id}/members` can return non-user directoryObjects
/// (devices, service principals, nested groups); `apply_entra_sync` filters
/// membership pairs against the fetched user-id set before the bulk
/// membership insert so a foreign-key violation from a non-user member can
/// never abort the whole sync (the SQLite era had no FK and simply never
/// surfaced those rows at read time — this reproduces the same observable
/// behavior at write time instead).

#include <nlohmann/json_fwd.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct DirectoryUser {
    std::string id;
    std::string display_name;
    std::string email;
    std::string upn; // User Principal Name
    std::vector<std::string> groups;
    bool enabled = true;
    int64_t synced_at{0};
};

struct DirectoryGroup {
    std::string id;
    std::string display_name;
    std::string description;
    std::string mapped_role; // RBAC role this group maps to
    int64_t synced_at{0};
};

enum class SyncProviderType {
    kEntraId,
    kLdap
};

struct SyncStatus {
    std::string provider;  // "entra" or "ldap"
    std::string status;    // "idle", "running", "completed", "failed"
    int64_t last_sync_at{0};
    int64_t next_sync_at{0};
    int user_count{0};
    int group_count{0};
    std::string last_error;
};

struct EntraConfig {
    std::string tenant_id;
    std::string client_id;
    std::string client_secret;
};

struct LdapConfig {
    std::string server;
    int port{389};
    std::string base_dn;
    std::string bind_dn;
    std::string bind_password;
    bool use_ssl{false};
};

// ── DirectorySync ────────────────────────────────────────────────────────────

/// The exact `sync_entra` busy-rejection string, shared with
/// `discovery_routes.cpp` so its 409-vs-500 classification is keyed off a
/// single symbol rather than two independent string literals (Gate 3
/// cpp-expert / consistency-auditor: a docs-writer wording pass on one copy
/// used to silently revert the 409 mapping back to 500 with no compiler
/// diagnostic).
inline constexpr std::string_view kEntraSyncAlreadyInProgress = "sync already in progress";

class DirectorySync {
public:
    /// Borrows the shared pool (ADR-0008 "Connection model"). Runs the
    /// `directory_sync` schema migration on a pinned lease. `is_open()` is
    /// false if the lease was empty or the migration failed — the caller
    /// (`server.cpp`) treats that as fatal at boot (ADR-0012 §1).
    explicit DirectorySync(pg::PgPool& pool);
    ~DirectorySync();

    DirectorySync(const DirectorySync&) = delete;
    DirectorySync& operator=(const DirectorySync&) = delete;

    bool is_open() const;

    // ── Sync operations ─────────────────────────────────────────────────

    /// Sync users and groups from Microsoft Entra ID (Azure AD) via Graph API.
    /// Uses OAuth2 client credentials flow to obtain an access token, then
    /// fetches /users and /groups from Microsoft Graph.
    ///
    /// ADR-1007: re-entrancy guarded — two concurrent callers racing this
    /// method previously both proceeded (the deleted `mtx_`, see the file
    /// header's self-deadlock note, never guarded the OPERATION as a whole,
    /// only individual data-structure mutations that no longer exist post-
    /// port). A busy call returns `std::unexpected("sync already in
    /// progress")` immediately rather than queuing or blocking — callers
    /// map this to HTTP 409, not 500 (see `discovery_routes.cpp`).
    std::expected<void, std::string> sync_entra(const EntraConfig& config);

    /// Fires once, synchronously, immediately after `sync_entra` wins the
    /// re-entrancy guard and before any network/store work — TEST ONLY, a
    /// deterministic way to hold a sync "in progress" while a second call is
    /// attempted concurrently. `nullptr` (default) in production: zero
    /// overhead, matches this codebase's `test_hook_*` convention
    /// (`ApiTokenStore`/`EnginePrincipalStore`).
    std::function<void()> test_hook_after_entra_guard_acquired_;

    /// Sync from on-prem AD via LDAP (stub — full LDAP requires a library not
    /// in vcpkg. Entra ID is available now; LDAP support planned).
    std::expected<void, std::string> sync_ldap(const LdapConfig& config);

    // ── Query ───────────────────────────────────────────────────────────

    /// Get all synced users, optionally filtered by group. Empty on a closed
    /// store or a degraded query — same plain-container contract as the
    /// SQLite era (see file header).
    std::vector<DirectoryUser> get_synced_users(const std::string& group_filter = {}) const;

    /// Get a single synced user by directory object ID.
    std::optional<DirectoryUser> get_user(const std::string& id) const;

    /// Get all synced groups.
    std::vector<DirectoryGroup> get_synced_groups() const;

    /// Get sync status for each configured provider.
    SyncStatus get_status() const;

    // ── Group-to-role mapping ───────────────────────────────────────────

    /// Map a directory group to an RBAC role name.
    void configure_group_role_mapping(const std::string& group_id,
                                      const std::string& role_name);

    /// Remove a group-to-role mapping.
    void remove_group_role_mapping(const std::string& group_id);

    /// Get all group-to-role mappings.
    std::map<std::string, std::string> get_group_role_mappings() const;

private:
    pg::PgPool& pool_;
    bool open_{false};

    /// ADR-1007 re-entrancy guard for `sync_entra` — see its doc comment.
    /// `compare_exchange_strong` at entry, reset via RAII on every exit path
    /// (the function has several early `return std::unexpected(...)`s).
    std::atomic<bool> entra_sync_in_progress_{false};

    /// Complete remote snapshot fetched from Microsoft Graph before any
    /// database write — see the file header's transaction-shape note.
    /// `memberships` maps group_id -> the raw member ids Graph returned
    /// (users, and possibly devices/service principals/nested groups —
    /// filtered to known users at apply time).
    struct EntraSyncData {
        std::vector<DirectoryUser> users;
        std::vector<DirectoryGroup> groups;
        std::unordered_map<std::string, std::vector<std::string>> memberships;
    };

    /// Applies a fetched `EntraSyncData` snapshot in one short transaction:
    /// deletes any user/group absent from the snapshot, upserts every
    /// user/group the snapshot names (role mapping is NOT stored here — see
    /// file header), then clears and bulk-repopulates memberships (filtered
    /// to known user ids, so a non-user Graph member can never abort the
    /// sync via a foreign-key violation). This is where the SQLite-era
    /// self-deadlock lived; it is exposed to the private
    /// `friend struct DirectorySyncTestAccess` test seam so that logic is
    /// unit-testable without a live/stubbed Graph HTTP endpoint (the client
    /// itself stays untouched — see file header).
    std::expected<void, std::string> apply_entra_sync(const EntraSyncData& data);

    // Internal: update sync status. Self-contained (acquires its own lease) —
    // called independently of apply_entra_sync at several points in
    // sync_entra (running/failed/completed), never from inside its
    // transaction.
    void update_status(const std::string& provider, const std::string& status,
                       int user_count = 0, int group_count = 0,
                       const std::string& error = {});

    // Internal: WinHTTP GET helper (Windows) / httplib GET (other platforms)
    std::expected<std::string, std::string> http_get(const std::string& url,
                                                     const std::string& bearer_token);

    /// Fetches every page of a Microsoft Graph collection response, following
    /// `@odata.nextLink` until absent, invoking `on_item` for each element of
    /// every page's `value` array. Hard-errors (aborting the whole sync,
    /// leaving the store untouched) on a malformed/missing `value` array on
    /// ANY page — a single-page tenant's `$top=999` request was previously
    /// the sync's ONLY request, so a tenant with more users/groups/members
    /// than that silently lost everything past page 1 on every sync, which
    /// `apply_entra_sync`'s stale-row deletion (see file header) then treated
    /// as "deleted in Entra" (security review, 2026-08-29). Bounded at
    /// kMaxGraphPages pages against a runaway or malicious nextLink chain.
    std::expected<void, std::string> fetch_paginated(
        const std::string& initial_url, const std::string& bearer_token,
        const std::function<void(const nlohmann::json&)>& on_item);

    // Internal: obtain OAuth2 access token via client credentials
    std::expected<std::string, std::string> acquire_token(const EntraConfig& config);

    friend struct DirectorySyncTestAccess;
};

} // namespace yuzu::server
