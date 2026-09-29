#pragma once

/// @file access_review_model.hpp
/// Pure read-model for Periodic Access Reviews (SOC 2 CC6.2) — a
/// cross-principal enumeration of the DIRECT role grants currently on record
/// across all three RBAC principal types (user / group / engine). No
/// route/store-write dependency: this file only READS other stores and
/// projects the result into `AccessReviewRow`. The persistence of a review
/// CAMPAIGN (which freezes a population and records reviewer decisions) is a
/// separate concern — `access_review_store.hpp`.
///
/// UP-1 (governance hardening round, HIGH — completeness): the export's
/// SPINE is the grant table, not any roster. `build_access_review` reads
/// EVERY `(principal_type, principal_id, role_name)` row on record via
/// `RbacStore::list_all_principal_roles_checked()` — one bulk read — and
/// groups it by principal. A principal holding a live grant ALWAYS produces
/// a row, even when its `principal_id` matches nothing in the
/// users/groups/engine-principal rosters (a since-deleted user, a stale IdP-
/// provisioned row, or an OIDC/SSO principal minted outside any roster,
/// e.g. `oidc:<iss>#<sub>`) — such a row is enriched as an "orphan"
/// (`display_name = principal_id`, `source = "orphan"`,
/// `lifecycle_state = "unknown"`) rather than silently omitted. The prior
/// design walked the three ROSTERS and asked RBAC per member — a grant
/// belonging to a principal outside every roster was a silent false
/// negative in exactly the evidence CC6.2 exists to produce; walking the
/// grant table directly makes that omission structurally impossible. The
/// rosters (`AuthDB::list_users_including_inactive`, `RbacStore::list_groups_checked`,
/// `EnginePrincipalStore::list_all_checked`) are still read, but only to
/// ENRICH a grant-table row with display metadata — a principal with ZERO
/// grants produces no row (nothing to review), which is the intended scope
/// narrowing: this export answers "who currently has access", not "who
/// exists".
///
/// R1 (error propagation, codex BLOCK): a compliance export that silently
/// drops rows on a transient read failure is worse than one that fails
/// loudly — a partial grant set that reads as "the complete list" is a false
/// negative in exactly the evidence this feature exists to produce.
/// `build_access_review` therefore returns `std::unexpected` on the FIRST
/// read failure it hits (across the grant table, role-permission table,
/// users, groups, engine principals, and API tokens) and NEVER a partial
/// result. Every bulk read this function drives uses a
/// `std::expected`-returning accessor; five of those accessors
/// (`RbacStore::list_all_principal_roles_checked`,
/// `list_all_role_permissions_checked`, `get_role_permissions_checked`,
/// `list_groups_checked`, `EnginePrincipalStore::list_all_checked`) were
/// added/exist specifically because the pre-existing bare-vector form
/// swallows a query error to an indistinguishable-from-empty result — see
/// the doc comments on those methods. Roster reads (users/groups/engines)
/// are enrichment-only in the row-population sense (UP-1 above) but are
/// STILL required reads here — a dropped roster read would silently blank
/// every row's display metadata rather than fail loudly, which R1 rules
/// out just as much as a dropped grant read would.
///
/// R2 (per-principal-type permission computation, codex BLOCK, perf-
/// hardened): `RbacStore::get_effective_permissions(username)` is
/// USER-keyed — it resolves direct user grants, group-membership-derived
/// grants, AND direct engine grants via one three-way UNION
/// (`RbacStore::collect_roles_locked`). Calling it with a GROUP name would
/// silently look up `principal_type='user' AND principal_id=<group name>`
/// plus a (vacuous) group-membership check for a "user" named after the
/// group — never the group's own grants. This model therefore NEVER calls
/// `get_effective_permissions`. Instead, for ALL principal types uniformly,
/// it expands the DIRECT role names a grant-table group already produced
/// (this is also why the exported `roles` field is direct-only, not
/// group-inheritance-resolved, for a user row: mirrors the no-admin
/// auditor route's own direct-grant-only treatment of engine principals) to
/// a distinct `allow`-permission set via a `role_name -> permission set`
/// map built ONCE from `list_all_role_permissions_checked()` — not
/// re-queried per role per principal, which is the perf fix for the N×M
/// fan-out the prior per-roster-member walk incurred. For an ENGINE
/// principal this produces the SAME result `get_effective_permissions
/// (engine_id)` would (the engine UNION arm in `collect_roles_locked` only
/// ever contributes an engine principal's own direct grants — engines are
/// never group members). For a USER this is narrower than
/// `get_effective_permissions` (it excludes group-inherited roles) — a
/// user's group-derived access is still fully visible in this same export,
/// on that GROUP's own row. A follow-up could add a "resolved effective
/// access" column that flattens group inheritance onto the user row;
/// deferred here to avoid inventing a reverse group-membership bulk
/// accessor RbacStore does not currently expose.
///
/// Not part of the R1 error-propagation contract: `ApiTokenStore` (used only
/// to enrich an engine row's `last_activity_ms` via its most recent
/// non-revoked credential's `last_used_at`) and `DirectorySync` (used only to
/// best-effort enrich a user row's `owner_or_email`) are OPTIONAL enrichment
/// — a null pointer, or (for DirectorySync, whose `get_synced_users` has no
/// `std::expected` surface at all) an empty/unavailable read, degrades that
/// one field rather than failing the whole export. A genuine
/// `ApiTokenStore::list_tokens` READ FAILURE (store present, query erred)
/// DOES propagate — the pointer being present makes it part of the read set
/// this call promised to read completely.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server {

class AuthDB;
class RbacStore;
class EnginePrincipalStore;
class ApiTokenStore;
class DirectorySync;

/// One row of the cross-principal access-review export. One row per
/// principal HOLDING AT LEAST ONE GRANT (UP-1, file header) — a principal
/// with zero grants produces no row.
struct AccessReviewRow {
    std::string principal_type; ///< "user" | "group" | "engine" — as recorded on the grant row;
                                ///< see UP-1 for the unrecognised-type defensive fallback
    std::string principal_id;
    std::string display_name; ///< username / group name / engine display_name; == principal_id
                              ///< when the grant is orphaned (UP-1 — no matching roster row)
    std::string owner_or_email; ///< user: email if resolvable via DirectorySync, else ""; group: "";
                                 ///< engine: owner_username; orphan: ""
    std::vector<std::string> roles; ///< DIRECT role grants only — see file header R2 note
    int effective_permission_count{0}; ///< distinct (securable_type,operation) allow-permissions
                                        ///< the `roles` above grant, computed type-correctly
    std::int64_t last_activity_ms{0};  ///< epoch ms; 0 when unknown/not applicable
    std::string last_activity_kind;    ///< "last_login" | "last_used" | "n/a"
    std::string classification;        ///< engine: "internal"|"external"; else ""
    std::string lifecycle_state;       ///< engine: "active"|"revoked"; user: "active"|"disabled"
                                        ///< (per AuthDB::list_users_including_inactive's is_active
                                        ///< flag — a disabled user still holding a grant is matched
                                        ///< evidence, NOT an orphan); group: ""; orphan: "unknown"
    std::string source; ///< "local" | "scim" | "idp" | "engine" | "orphan" — best-effort
                        ///< normalisation of the principal's provenance ("orphan" = grant with no
                        ///< matching roster row, UP-1); see the .cpp for the exact mapping
};

/// Build the full cross-principal access-review export. `users`, `rbac`, and
/// `engines` are REQUIRED — a null pointer, or a store that reports itself
/// closed, fails the whole call with `std::unexpected` (this export cannot
/// honestly represent "some principal types unavailable" as a partial
/// result). `tokens` and `dirsync` are OPTIONAL enrichment (see file header);
/// pass `nullptr` to skip that enrichment without failing the export.
///
/// R1: returns `std::unexpected(msg)` on the FIRST read failure encountered
/// (the bulk grant-table read, the bulk role-permission read, or the
/// user/group/engine-principal/token roster reads) — never a partial
/// `vector<AccessReviewRow>`.
[[nodiscard]] std::expected<std::vector<AccessReviewRow>, std::string>
build_access_review(AuthDB* users, RbacStore* rbac, EnginePrincipalStore* engines,
                    ApiTokenStore* tokens, DirectorySync* dirsync);

/// Serialize rows to CSV (leading metadata line + header + one row per
/// principal). `roles` is semicolon-joined within a field. RFC 4180-style
/// escaping: any field containing a comma, double-quote, or newline is
/// wrapped in double quotes with interior double-quotes doubled. CWE-1236
/// (CSV/formula injection) hardening: any field whose first byte is one
/// Excel/Sheets treats as a formula trigger (`=`, `+`, `-`, `@`, tab, CR) is
/// prefixed with a literal `'` BEFORE the RFC-4180 quoting pass — several
/// fields here (principal_id/display_name/owner_or_email/role names) are
/// influenceable by an external identity provider (SCIM username, engine
/// display_name), so this is not a theoretical input. See the `.cpp`
/// `csv_field` for the exact character set.
///
/// A3 (RBAC delivery plan): the FIRST line is an unconditional metadata
/// comment, `# rbac_enforcement=<enabled|disabled|degraded>\r\n`, carrying
/// `rbac_enforcement` (caller-supplied — typically
/// `access_review_rbac_enforcement()`'s result, computed once alongside
/// the same row population; never re-derived here, so this function gains
/// no `RbacStore` dependency of its own). Present even when `rows` is
/// empty, so a zero-grant population is never ambiguous with "the stamp
/// was omitted". This line is emitted verbatim (not `csv_field`-escaped) —
/// the value is always one of the three fixed literals above, never
/// externally influenced, so RFC 4180/CWE-1236 handling does not apply to
/// it. A consumer parsing this file as strict single-header tabular data
/// skips this first line before the real header row (documented in
/// `docs/user-manual/rest-api.md`'s CSV section). This CSV is the
/// RETAINED, OFFLINE evidence artifact an auditor pulls
/// (`docs/security-reviews/access-reviews-2026-07-21.md`), so the stamp
/// must travel WITH the file, not only its JSON sibling response.
[[nodiscard]] std::string to_csv(const std::vector<AccessReviewRow>& rows,
                                 const std::string& rbac_enforcement);

/// A3 (RBAC delivery plan) — "enabled" | "disabled" | "degraded" enforcement
/// stamp for the SAME cross-principal export `build_access_review` produces.
/// Kept as a separate call rather than folded into `AccessReviewRow`/the
/// returned vector: the value is fleet-wide, not per-row, so every caller
/// stamps it ONCE alongside the row list — both for the live export (GET
/// .../export) and for the frozen campaign row `access_review_store.hpp`
/// persists at `open_campaign` time (SOC 2 CC6.2 evidence should say whether
/// the grant population it lists was actually enforced when frozen). Thin
/// wrapper over `rbac_enforcement_label()`/`to_string()` (`rbac_store.hpp`)
/// — see that pair for the exact three-way derivation and its relationship
/// to `rbac_enforcement_in_effect()`. `rbac` may be null (degrades to
/// `"degraded"`, matching `rbac_enforcement_label(nullptr)`).
[[nodiscard]] std::string access_review_rbac_enforcement(const RbacStore* rbac);

} // namespace yuzu::server
