#pragma once

/**
 * scim_store.hpp — storage layer for SCIM v2 provisioning (slice 1),
 * born-on-Postgres (ADR-0006, schema `scim_store`).
 *
 * Maps the IdP-facing SCIM `id` / `externalId` to a Yuzu username, and holds
 * the SCIM bearer credential(s) as sha256 hashes only — mirrors
 * `ApiTokenStore`'s token-hashing pattern (server/core/src/api_token_store.cpp).
 * SCIM tokens stay verify-only hashes (no `SecretCodec` — there is no
 * plaintext to envelope-encrypt; a hash cannot be decrypted back to a raw
 * bearer value the way a `SecretCodec` blob can).
 *
 * Posture (ADR-0012 §1): FRESH START, no `migrate_from_sqlite()` — this is a
 * greenfield born-on-PG store (no prior release shipped a Postgres SCIM
 * store to backfill from); any pre-existing `auth.db`-resident SCIM mappings
 * are not carried forward. Construction is fail-CLOSED: `is_open()` is false
 * if the pool lease or schema migration fails, and server.cpp treats that as
 * a fatal startup error (same pattern as every other born-on-PG store).
 * Runtime reads/mutations degrade to the empty/false/nullopt value the
 * existing (SQLite-era) callers already treat as "operation did not
 * succeed" — `scim_routes.cpp` (a separate, un-touched slice) already
 * handles that outcome as a 5xx, so this store keeps the same signatures
 * rather than introducing a parallel `std::expected` surface here.
 *
 * Substrate contract (ADR-0008/0012): holds a `pg::PgPool&` (not a
 * `sqlite3*`), runs its migration at construction on a pinned lease,
 * schema-qualifies every runtime statement (`scim_store.scim_resources`,
 * `scim_store.scim_tokens`, `scim_store.scim_groups`,
 * `scim_store.scim_group_members`), and uses `RETURNING` for
 * mutate-and-return (never `sqlite3_changes()`/row-count polling, #1033).
 * Bounded `try_acquire_for` leases on every runtime path.
 *
 * NO per-connection `db_mtx_` anymore (the SQLite single-handle serialization
 * this store used to rely on) — a `PgPool` hands out independent connections
 * per lease, same as every other born-on-PG store. `scim_routes.cpp`'s
 * `recompute_scim_user_role` doc comment references a "LOCK ORDER ...
 * ScimStore::db_mtx_" that predates this port; that comment is stale as of
 * this port (member removed) and is out of this store's scope to fix
 * (routes layer, not touched here) — flagged for the routes owner.
 *
 * This class does NOT implement any HTTP/REST route or JSON codec — it is
 * the data + token layer only (slice 1 of 3; a sibling junior owns the JSON
 * codec, another owns the routes).
 *
 * SCIM v2 Groups (#2021, slice 2): schema version 2 adds `scim_groups` +
 * the `scim_group_members` join table, and this class exposes group CRUD +
 * membership management + the `list_group_display_names_for_user` reverse
 * lookup a later, separate task consumes to map SCIM groups to Yuzu roles.
 * Still no HTTP/REST route, JSON codec, or role-application logic here.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// A single SCIM resource mapping: the IdP-facing `id`/`externalId` bound to
/// a Yuzu username.
struct ScimResource {
    std::string scim_id;     ///< IdP-facing SCIM `id` (server-generated, opaque hex).
    std::string external_id; ///< IdP's `externalId` claim. Empty if the IdP never sent one.
    std::string username;    ///< The Yuzu username this resource maps to.
    bool active{true};
    std::string created_at; ///< ISO-8601 UTC text (`YYYY-MM-DDTHH:MM:SSZ`).
    std::string updated_at;
    int64_t etag_version{1}; ///< Bumped on every mutation; usable as a SCIM ETag.
};

/// One `(iss, sub)` OIDC identity linked to a SCIM resource (ADR-2001 §2,
/// `identity_links` table). The owning `scim_id` is the query input for
/// `links_for_scim_id` and is deliberately not repeated on this struct.
struct LinkedIdentity {
    std::string iss;
    std::string sub;
};

/// One SAML NameID identity linked to a SCIM resource (ADR-2001 PR4a,
/// `saml_identity_links` table — the SAML analogue of `LinkedIdentity`
/// above). Deliberately a SEPARATE table/struct rather than a generalized
/// `identity_links`, so this stays off the OIDC linkage surface (PR3). The
/// owning `scim_id` is the query input for `saml_links_for_scim_id` and is
/// deliberately not repeated on this struct.
struct SamlLinkedIdentity {
    std::string entity_id;
    std::string name_id;
};

/// Distinguishes a store error from a genuine no-match/ambiguous outcome for
/// `find_unique_active_by_external_id_checked` (ADR-2001 #3072, SAML D2
/// observability store layer) — the same tri-state motivation as
/// `resource_exists`/`get_by_username_checked`: a caller that needs to tell
/// "no active resource claims this externalId" apart from "the store could
/// not answer" (rather than folding both into a bare `nullopt`) uses this
/// variant instead of the plain `find_unique_active_by_external_id`.
enum class ActiveExternalIdLookupStatus { matched, no_match, ambiguous, store_error };

/// Result of `find_unique_active_by_external_id_checked`. `resource` is only
/// ever set when `status == matched`.
struct ActiveExternalIdLookupResult {
    ActiveExternalIdLookupStatus status;
    std::optional<ScimResource> resource;
};

/// The deny-at-login backstop's resolved state for one `(iss, sub)` (ADR-2001
/// §4), returned engaged (see `linked_resource_active`'s doc comment for the
/// full tri-state contract — this struct only carries what an ENGAGED result
/// means):
///  - `scim_id == nullopt, active == nullopt`: no `identity_links` row for
///    this identity — genuinely unlinked.
///  - `scim_id` set, `active == nullopt`: an orphaned link — the linked
///    `scim_resources` row was hard-DELETEd (`identity_links` is not
///    FK-cascaded); `scim_id` still names which resource used to own it.
///  - `scim_id` set, `active` set: exactly one linked row and its
///    `scim_resources.active` value.
struct LinkedResourceState {
    std::optional<std::string> scim_id;
    std::optional<bool> active;
};

/// A single SCIM Group resource (slice 2, #2021): the IdP-facing group `id`/
/// `externalId`/`displayName` — membership itself lives in the separate
/// `scim_group_members` join table, not on this struct.
struct ScimGroup {
    std::string scim_id;     ///< IdP-facing SCIM `id` (server-generated, opaque hex).
    std::string external_id; ///< IdP's `externalId` claim. Empty if the IdP never sent one.
    std::string display_name; ///< The Group's SCIM `displayName`.
    bool active{true};
    std::string created_at; ///< ISO-8601 UTC text (`YYYY-MM-DDTHH:MM:SSZ`).
    std::string updated_at;
    int64_t etag_version{1}; ///< Bumped on every mutation; usable as a SCIM ETag.
};

class ScimStore {
public:
    /// Borrows the shared pool and runs the `scim_store` schema migration on
    /// a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed — the server fails closed (startup_failed_) before
    /// reaching here in production.
    explicit ScimStore(pg::PgPool& pool);
    ~ScimStore() = default;

    ScimStore(const ScimStore&) = delete;
    ScimStore& operator=(const ScimStore&) = delete;

    bool is_open() const noexcept;

    // ── Bearer token (SCIM credential) ───────────────────────────────────

    /// Hash and store the SCIM bearer token under `label`. Any existing
    /// non-revoked token sharing the same label is revoked first (upsert by
    /// label) — used at boot from a config flag, not exposed over any route
    /// in this slice. Returns false on CSPRNG/db failure or an empty `raw`.
    bool set_token(const std::string& raw, const std::string& label);

    /// True if at least one non-revoked token row exists.
    bool has_token() const;

    /// Constant-time validate a raw Bearer token against every non-revoked
    /// token hash (via `CRYPTO_memcmp`). Empty input always rejects.
    bool validate_token(const std::string& raw) const;

    // ── SCIM resources ────────────────────────────────────────────────────

    /// Create a new resource mapping, generating a fresh `scim_id`. Returns
    /// `nullopt` if `username` already has a mapping (UNIQUE constraint) or
    /// on CSPRNG/db failure.
    std::optional<ScimResource> create_resource(const std::string& username,
                                                const std::string& external_id = {});

    std::optional<ScimResource> get_by_scim_id(const std::string& scim_id) const;

    /// Tri-state existence check: `true` = a resource with this `scim_id`
    /// exists, `false` = it definitively does not, `nullopt` = the store
    /// could not answer (closed, lease timeout, failed statement).
    ///
    /// ★ SECURITY (2026-07-25 Hermes pass, MEDIUM): `get_by_scim_id` collapses
    /// "no such resource" and "read failed" into the same `nullopt`, which is
    /// harmless for a plain lookup but NOT for group-membership resolution:
    /// `resolve_member_values` treats an unresolvable id as validate-and-skip,
    /// so on a transient blip a genuinely-provisioned member is dropped and
    /// the PUT/PATCH handler then persists the SMALLER set — a partial version
    /// of the durable membership loss the tri-state membership reads fix. Use
    /// this (not `get_by_scim_id().has_value()`) anywhere a negative answer
    /// feeds a write. Deliberately additive: `get_by_scim_id`'s many read-only
    /// call sites keep their existing contract.
    std::optional<bool> resource_exists(const std::string& scim_id) const;
    std::optional<ScimResource> get_by_username(const std::string& username) const;

    /// Tri-state variant of `get_by_username` distinguishing "the store
    /// could not answer" from "genuinely no such resource" (governance
    /// Gate 7 BLOCKING fix, UP-7): the OUTER `nullopt` means a store error
    /// (closed store, lease timeout, or a failed statement) — the caller
    /// MUST treat this as "unknown", never as "not found", exactly the
    /// `resource_exists`/`list_group_member_user_scim_ids` tri-state
    /// pattern above. The INNER `nullopt` (i.e. an engaged
    /// `std::optional<ScimResource>` holding no value) means the store
    /// answered and genuinely has no row for `username`. Use this (not
    /// `get_by_username`) anywhere a negative answer feeds a fail-
    /// open/fail-closed branch — `get_by_username`'s many plain read-only
    /// call sites keep their existing collapsed contract.
    std::optional<std::optional<ScimResource>>
    get_by_username_checked(const std::string& username) const;

    /// Empty `external_id` always returns `nullopt` (an empty externalId is
    /// not a meaningful lookup key).
    std::optional<ScimResource> find_by_external_id(const std::string& external_id) const;

    /// ADR-2001 §2 mis-link guard (codex-sol plan-review BLOCK): forms a
    /// result ONLY when exactly one ACTIVE resource matches `external_id`.
    /// Returns `nullopt` on zero matches (normal — no such resource) AND on
    /// more than one match (an externalId ambiguity — the caller MUST treat
    /// this as "no link formed" plus a loud signal, never pick one
    /// arbitrarily). Empty `external_id` always returns `nullopt`, matching
    /// `find_by_external_id`. Belt-and-braces alongside the partial-unique
    /// index on `scim_resources.external_id` (migration v3): this check is
    /// the layer that still holds even if the index is ever bypassed or
    /// absent. Does NOT change `find_by_external_id`'s existing contract —
    /// other callers keep using that one.
    ///
    /// Thin COMPATIBILITY WRAPPER over `find_unique_active_by_external_id_checked`
    /// (ADR-2001 #3072 store-layer task): returns the resource for `matched`,
    /// `nullopt` for every other status (`no_match`, `ambiguous`,
    /// `store_error`). Byte-unchanged signature/behaviour — every existing
    /// caller (OIDC link formation, OIDC + SAML orphan/reprovision checks,
    /// SAML link formation, deny-at-login) keeps collapsing store-error and
    /// no-match/ambiguous into the same `nullopt`, exactly as before this
    /// checked variant was added.
    std::optional<ScimResource> find_unique_active_by_external_id(const std::string& external_id) const;

    /// CHECKED variant of `find_unique_active_by_external_id` that
    /// distinguishes a store error from a genuine no-match/ambiguous outcome
    /// (ADR-2001 #3072). Same underlying query/logic as the wrapper above:
    /// `matched` = exactly one active row (`resource` populated);
    /// `no_match` = zero rows; `ambiguous` = more than one active row (the
    /// mis-link guard, ADR-2001 §2); `store_error` = store not open, lease
    /// timeout, or a failed statement. An empty `external_id` is `no_match`
    /// (not a store error), matching `find_unique_active_by_external_id`'s
    /// existing empty-input contract.
    ActiveExternalIdLookupResult
    find_unique_active_by_external_id_checked(const std::string& external_id) const;

    /// 1-based `start_index` per the SCIM list-response convention (RFC 7644
    /// §3.4.2 `startIndex`). `total_out` receives the total resource count
    /// (independent of the pagination window) so a caller can build
    /// `totalResults`. Stable creation-order pagination.
    std::vector<ScimResource> list(int start_index, int count, int& total_out) const;

    /// Toggle active/inactive (SCIM PATCH `active`). Bumps `etag_version` and
    /// `updated_at`. Returns false if no row matched `scim_id`.
    bool set_active(const std::string& scim_id, bool active);

    /// Update the mutable identity fields (username/external_id). Bumps
    /// `etag_version` and `updated_at`. Returns false if no row matched
    /// `scim_id`.
    bool update_resource(const std::string& scim_id, const std::string& username,
                         const std::string& external_id);

    /// Delete the resource mapping. Tri-state return so a caller can treat
    /// "the row is already gone" as idempotent success rather than a
    /// failure (UP-N4): `nullopt` on a genuine DB error (no connection,
    /// lease timeout, or a query-time error — the caller should fail
    /// closed/retry, never treat it as "already gone"); `true` if a row
    /// existed and was deleted; `false` if no row matched `scim_id` (e.g. a
    /// concurrent/duplicate DELETE already removed it).
    std::optional<bool> delete_by_scim_id(const std::string& scim_id);

    // ── SCIM groups (slice 2, #2021) ─────────────────────────────────────
    //
    // Storage + membership only — no HTTP route, no JSON codec, no role-
    // application logic. `list_group_display_names_for_user` is the reverse
    // lookup the (separate) role-application task consumes.

    /// Create a new group, generating a fresh `scim_id`. Returns `nullopt` if
    /// `display_name` is empty, on CSPRNG/db failure, or if `display_name`
    /// already has a mapping (see `get_group_by_display_name` for the
    /// idempotent-create check a caller should do first).
    std::optional<ScimGroup> create_group(const std::string& display_name,
                                          const std::string& external_id = {});

    std::optional<ScimGroup> get_group_by_id(const std::string& scim_id) const;

    /// Exact-match lookup by `displayName` — used for idempotent create /
    /// uniqueness checks by the routes layer (no DB-level UNIQUE constraint
    /// on this column; SCIM `displayName` collisions are a caller-level 409,
    /// not a storage-level rejection).
    std::optional<ScimGroup> get_group_by_display_name(const std::string& display_name) const;

    /// 1-based `start_index` per the SCIM list-response convention (RFC 7644
    /// §3.4.2 `startIndex`), mirroring `list()`. `total_out` receives the
    /// total group count.
    std::vector<ScimGroup> list_groups(int start_index, int count, int& total_out) const;

    /// Total number of groups (no pagination window).
    int count_groups() const;

    /// Update the mutable identity fields (display_name/external_id). Bumps
    /// `etag_version` and `updated_at`. Returns false if no row matched
    /// `scim_id`.
    bool update_group(const std::string& scim_id, const std::string& display_name,
                      const std::string& external_id);

    /// Delete the group (its `scim_group_members` rows are deleted alongside
    /// it, in the same transaction, so the reverse lookup never dangles).
    /// Tri-state return mirrors `delete_by_scim_id` (UP-N4): `nullopt` on a
    /// genuine DB error, `true` if a row existed and was deleted, `false` if
    /// no row matched `scim_id` (idempotent no-op).
    std::optional<bool> delete_group(const std::string& scim_id);

    /// Replace-all semantics: the group's membership becomes exactly
    /// `user_scim_ids` (existing rows deleted, then the new set inserted, in
    /// one transaction). Returns false on a db error; a group with zero
    /// members is expressed by passing an empty vector (not by omission).
    bool set_group_members(const std::string& group_scim_id,
                           const std::vector<std::string>& user_scim_ids);

    /// Atomically (single transaction) update the group's display_name/
    /// external_id AND replace its entire membership set — the durable fix
    /// for PUT/PATCH committing the rename and the membership change as
    /// separate transactions (#2127 review), which could leave a committed
    /// rename with a stale/partial membership set on a mid-write failure.
    /// Tri-state return mirrors `delete_group`: `nullopt` on a genuine DB
    /// error (rolled back — neither the rename nor the membership change
    /// persists), `false` if no row matched `scim_id` (no side effects),
    /// `true` if the group was updated.
    std::optional<bool> replace_group_and_members(
        const std::string& scim_id, const std::string& display_name,
        const std::string& external_id, const std::vector<std::string>& member_user_scim_ids);

    /// Add a single member (SCIM PATCH `add`). Idempotent: adding an
    /// already-present member returns true (no-op), not an error.
    bool add_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// Remove a single member (SCIM PATCH `remove`). Idempotent: removing an
    /// absent member returns true (no-op), not an error.
    bool remove_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// All `user_scim_id`s currently a member of `group_scim_id`.
    ///
    /// ★ SECURITY (2026-07-25 review, HIGH #3): returns `nullopt` when the
    /// store could not answer (pool-lease timeout, failed statement) —
    /// DISTINCT from an engaged-but-empty vector, which means the group
    /// genuinely has no members. These were fused into a bare empty vector,
    /// and because this read feeds a read-modify-write membership replace,
    /// a momentary blip read as "no current members" and the subsequent
    /// write then DURABLY DELETED the real membership. Callers MUST fail
    /// closed on `nullopt` and never treat it as an empty set. Existence of
    /// the group itself is still not distinguished — check `get_group_by_id`
    /// first if you need that.
    std::optional<std::vector<std::string>>
    list_group_member_user_scim_ids(const std::string& group_scim_id) const;

    /// Reverse lookup: every group `displayName` that `user_scim_id` is
    /// currently a member of (join scim_group_members -> scim_groups). This
    /// is the primary read the role-application task consumes to decide
    /// SCIM-group-to-Yuzu-role mapping.
    ///
    /// ★ SECURITY (same finding): `nullopt` on store failure. An empty vector
    /// here resolves the user to `role=user`, so a blip that read as "member
    /// of no groups" would silently demote a SCIM-provisioned admin — the
    /// authoritative-read-fails-open anti-pattern `docs/postgres-store-playbook.md`
    /// rejects, and the same argument this PR makes for MFA.
    std::optional<std::vector<std::string>>
    list_group_display_names_for_user(const std::string& user_scim_id) const;

    // ── Identity linkage (ADR-2001) ──────────────────────────────────────
    //
    // `identity_links` durably records the (iss, sub) OIDC identity that a
    // successful OIDC login resolved to a SCIM resource under a configured
    // `--oidc-scim-link-claim`. No route/orchestration logic here — that is
    // a later ADR-2001 task; this store owns the table only (INV-31-3, one
    // owning store).

    /// Idempotent upsert keyed `(iss, sub)` (the table's UNIQUE constraint —
    /// one link per OIDC identity). Re-linking the same `(iss, sub)` updates
    /// `scim_id` and bumps `linked_at` to now; calling twice with identical
    /// arguments is a no-op-equivalent (same row, refreshed timestamp).
    /// Returns false on CSPRNG/db failure or an empty `iss`/`sub`/`scim_id`.
    /// ADR-2001 §2: the write is deliberately fail-OPEN from the login
    /// path's point of view — the CALLER (a later task) must not fail a
    /// login because this returned false; the missing link is instead
    /// caught by the D2 detector (`observation_matches`).
    bool upsert_link(const std::string& iss, const std::string& sub, const std::string& scim_id);

    /// Every OIDC identity currently linked to `scim_id` — the deprovision
    /// seam's lookup direction (by `scim_id`, which the table's `(iss,sub)`
    /// key does not serve; hence the secondary index). `nullopt` when the
    /// store could not answer (mirrors `list_group_member_user_scim_ids`):
    /// a deprovision path folding this into "nothing to revoke" on a
    /// transient blip is exactly the CC6.8 gap ADR-2001 exists to close, so
    /// callers MUST fail closed on `nullopt` rather than treat it as "no
    /// linked identities". An engaged-but-empty vector means the scim_id
    /// genuinely has no linked OIDC identity yet.
    std::optional<std::vector<LinkedIdentity>>
    links_for_scim_id(const std::string& scim_id) const;

    // ── SAML identity linkage (ADR-2001 PR4a) ────────────────────────────
    //
    // `saml_identity_links` durably records the (entity_id, name_id) SAML
    // identity that a successful SAML login resolved to a SCIM resource
    // (`saml_scim_link.cpp`'s login-site orchestration). A SEPARATE table
    // from `identity_links` (OIDC) — keeps this PR off PR3's scim_store
    // schema surface. No route/orchestration logic here — this store owns
    // the table only (INV-31-3, one owning store).

    /// Idempotent upsert keyed `(entity_id, name_id)` (the table's UNIQUE
    /// constraint — one link per SAML identity). Re-linking the same
    /// `(entity_id, name_id)` updates `scim_id` and bumps `linked_at` to
    /// now. Returns false on CSPRNG/db failure or an empty
    /// `entity_id`/`name_id`/`scim_id`. Mirrors `upsert_link`'s fail-OPEN
    /// contract from the login path's point of view — the CALLER
    /// (`saml_scim_link.cpp`) must not fail a login because this returned
    /// false.
    bool upsert_saml_link(const std::string& entity_id, const std::string& name_id,
                          const std::string& scim_id);

    /// Every SAML identity currently linked to `scim_id` — the deprovision
    /// seam's lookup direction, mirroring `links_for_scim_id` exactly.
    /// `nullopt` when the store could not answer: a deprovision path
    /// folding this into "nothing to revoke" on a transient blip is exactly
    /// the CC6.8 gap ADR-2001 exists to close, so callers MUST fail closed
    /// on `nullopt` rather than treat it as "no linked identities". An
    /// engaged-but-empty vector means the scim_id genuinely has no linked
    /// SAML identity yet.
    std::optional<std::vector<SamlLinkedIdentity>>
    saml_links_for_scim_id(const std::string& scim_id) const;

    /// The deny-at-login backstop's sole store read (ADR-2001 §4): resolves
    /// `(iss, sub)` against `identity_links` FUSED with a LEFT JOIN to
    /// `scim_resources` in one query (selecting BOTH `il.scim_id` and
    /// `sr.active`), so an ORPHANED link (the `scim_resources` row was
    /// hard-DELETEd by a SCIM DELETE — `identity_links` is not
    /// FK-cascaded) is distinguishable from "no link at all", reads as
    /// deprovisioned, AND still names which resource used to own it (the
    /// CC6.8 audit trail needs a self-contained "denied because resource
    /// X was deprovisioned" row, not just "denied"). An INNER join would
    /// instead silently treat a fully-deprovisioned user's now-rowless
    /// link as "no link", letting them re-authenticate — the bypass this
    /// LEFT join exists to close (codex-caught). `iss` is carried on
    /// `identity_links` itself, so this lookup is single-issuer-safe by
    /// construction; do NOT resolve the decision via
    /// `scim_resources.external_id` instead (ADR-2001 §5's single-issuer
    /// precondition).
    ///
    /// OUTER `optional<LinkedResourceState>` carries the store-availability
    /// half of the tri-state (mirrors `get_by_username_checked`); the
    /// ENGAGED value's `scim_id`/`active` fields (see `LinkedResourceState`'s
    /// doc comment) carry the rest:
    ///  - OUTER `nullopt`: the store could not answer (closed, lease
    ///    timeout, or a failed statement) — the caller MUST fail CLOSED
    ///    (deny the login), never treat this as "no link".
    ///  - engaged, `scim_id == nullopt` (zero rows): no `identity_links`
    ///    row exists for this `(iss, sub)` at all — a genuinely unlinked
    ///    OIDC identity is not a deprovisioned SCIM user, so the caller
    ///    PROCEEDS.
    ///  - engaged, `scim_id` set, `active == nullopt`: exactly one linked
    ///    row, and the joined `scim_resources` row is gone (NULL `active`,
    ///    the orphaned-link case above) — the caller DENIES.
    ///  - engaged, `scim_id` set, `active == false`: exactly one linked
    ///    row, deactivated — the caller DENIES.
    ///  - engaged, `scim_id` set, `active == true`: exactly one linked row,
    ///    active — the caller PROCEEDS.
    std::optional<LinkedResourceState>
    linked_resource_active(const std::string& iss, const std::string& sub) const;

    /// The SAML analogue of `linked_resource_active` — the deny-at-login
    /// backstop's sole store read for a SAML `(entity_id, name_id)` identity
    /// (ADR-2001 §4/PR4b). Resolves against `saml_identity_links` FUSED with
    /// a LEFT JOIN to `scim_resources` in one query, exactly mirroring
    /// `linked_resource_active`'s LEFT-join/tri-state contract — an INNER
    /// join would instead collapse an orphaned link (the `scim_resources`
    /// row hard-DELETEd by a SCIM DELETE — `saml_identity_links` is not
    /// FK-cascaded) into "no rows", letting a fully-deprovisioned SAML
    /// identity re-authenticate. Reuses `LinkedResourceState` (see its doc
    /// comment) rather than a new struct — the tri-state shape is identical.
    ///
    /// OUTER `optional<LinkedResourceState>` carries the store-availability
    /// half of the tri-state; the ENGAGED value's `scim_id`/`active` fields
    /// carry the rest:
    ///  - OUTER `nullopt`: the store could not answer (closed, lease
    ///    timeout, or a failed statement) — the caller MUST fail CLOSED
    ///    (deny the login), never treat this as "no link".
    ///  - engaged, `scim_id == nullopt` (zero rows): no `saml_identity_links`
    ///    row exists for this `(entity_id, name_id)` at all — a genuinely
    ///    unlinked SAML identity is not a deprovisioned SCIM user, so the
    ///    caller PROCEEDS.
    ///  - engaged, `scim_id` set, `active == nullopt`: exactly one linked
    ///    row, and the joined `scim_resources` row is gone (NULL `active`,
    ///    the orphaned-link case above) — the caller DENIES.
    ///  - engaged, `scim_id` set, `active == false`: exactly one linked
    ///    row, deactivated — the caller DENIES.
    ///  - engaged, `scim_id` set, `active == true`: exactly one linked row,
    ///    active — the caller PROCEEDS.
    std::optional<LinkedResourceState>
    saml_linked_resource_active(const std::string& entity_id, const std::string& name_id) const;

    // ── OIDC login observations (ADR-2001 D2 detector) ───────────────────
    //
    // Records every OIDC login's attempted CANDIDATE claim value(s) —
    // regardless of whether any of them matched a SCIM resource — so a
    // later deprovision can surface a should-have-matched candidate under a
    // misconfigured `--oidc-scim-link-claim` (a real, actionable "your link
    // claim is wrong for this IdP" signal instead of a silent gap). Callers
    // record one row PER CANDIDATE claim (`sub` and, when present, `oid`),
    // not just the configured link claim — governance Gate 7 BLOCKING fix:
    // under the prior (iss, sub)-only key, only the configured claim's
    // value survived the upsert, so a login presenting the OTHER candidate
    // (the exact "operator configured the wrong claim" case) left nothing
    // for `observation_matches` to find.

    /// Idempotent upsert keyed `(iss, sub, claim_name)` — one observation
    /// PER CANDIDATE CLAIM per identity, refreshed on every login (a login
    /// that presents both `sub` and `oid` upserts two rows). Returns false
    /// on db failure or an empty `iss`/`sub`/`claim_name`.
    bool record_login_observation(const std::string& iss, const std::string& sub,
                                  const std::string& claim_name, const std::string& claim_value);

    /// True if any recorded login observation carries this exact
    /// `claim_value` — the D2 "did any login present a candidate that
    /// should have matched" signal. This is a best-effort detection signal,
    /// not an authorization decision (ADR-2001 D2), so a store-unusable
    /// read collapses to `false` rather than a tri-state failure — treating
    /// "cannot tell" as "no candidate seen" is the safe direction for a
    /// signal that only ever ADDS a human-facing hint, never gates access.
    bool observation_matches(const std::string& claim_value) const;

    // ── SAML login observations (ADR-2001 #3072, D2-style SAML detector) ──
    //
    // Records every SAML login's NameID observation (`saml_login_observations`
    // table, migration v5) — the SAML analogue of `record_login_observation`/
    // `observation_matches` above. Unlike the OIDC surface there is no
    // multi-candidate-claim shape to preserve: a SAML assertion carries
    // exactly one NameID, so this is keyed `(entity_id, name_id,
    // name_id_format)` rather than `(iss, sub, claim_name)`.
    // `name_id_format` is deliberately IN the uniqueness key (not folded
    // into `(entity_id, name_id)` alone): a later login presenting the same
    // NameID value under a STABLE format (`persistent`/`emailAddress`,
    // `saml::is_linkable_name_id_format`) must not silently overwrite — and
    // so erase — an earlier observation recorded under an unstable format
    // (`transient`/`unspecified`); each `(entity_id, name_id, format)`
    // triple is its own row.

    /// Idempotent upsert keyed `(entity_id, name_id, name_id_format)` — one
    /// observation per distinct NameID+format pair, refreshed (`seen_at`) on
    /// every login. Returns false on db failure or an empty
    /// `entity_id`/`name_id`. An IdP that omits the NameID Format attribute
    /// is a common, legitimate configuration — `name_id_format` MAY be
    /// empty and is recorded as `""` (the column is NOT NULL; an empty
    /// string is a valid, distinct key component), so that population is
    /// never silently dropped from the D2 detector. The caller
    /// (`link_saml_login_to_scim`) is responsible for bounding/normalizing
    /// an oversized or malformed `name_id_format` before it reaches here —
    /// this method itself does not cap it.
    bool record_saml_login_observation(const std::string& entity_id, const std::string& name_id,
                                       const std::string& name_id_format);

    /// TRI-STATE (deliberately, unlike `observation_matches`'s bool — ADR-2001
    /// #3072 design): whether any recorded SAML login observation carries
    /// this exact `name_id`, distinguishing "no login ever presented it" from
    /// "the store could not answer". A store-unusable read collapses to
    /// `nullopt`, not `false` — this is a detector feeding a caller that
    /// SKIPS on `nullopt` rather than reporting a false-positive "never
    /// seen" on a transient blip.
    ///  - `nullopt`: the store could not answer (closed, lease timeout, or a
    ///    failed statement) — the caller MUST skip (treat as "cannot tell"),
    ///    never as a negative match.
    ///  - engaged `true`: at least one observation row carries this
    ///    `name_id`.
    ///  - engaged `false`: the store answered and genuinely has no
    ///    observation for this `name_id`.
    std::optional<bool> saml_observation_matches(const std::string& name_id) const;

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
