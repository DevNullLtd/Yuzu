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
/// (`RbacStore::collect_roles`). Calling it with a GROUP name would
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
/// (engine_id)` would (the engine UNION arm in `collect_roles` only
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

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
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
    std::string last_activity_kind;    ///< "last_used" | "n/a"; only an engine principal with a
                                       ///< recorded use is "last_used"
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

/// Longest campaign id any surface accepts (the store mints 16 hex digits; this is wider).
inline constexpr std::size_t kCampaignIdMaxLen = 64;

/// The refusal text every surface (REST 400, MCP invalid-params) returns for an id that fails
/// `valid_campaign_id`, so the two transports cannot drift.
inline constexpr std::string_view kCampaignIdInvalidMessage =
    "campaign id must be 1-64 characters of A-Z, a-z, 0-9, _ or -";

/// Longest `principal_type` / `principal_id` and `role_name` an attestation names, in bytes. The
/// cap bounds what a caller can make an audit row (and a log line) carry before any existence proof,
/// and must still admit every grant the stores can freeze: an OIDC principal is
/// `oidc:<iss>#<sub>` with `iss` and `sub` each capped at 255 bytes by `oidc_provider.cpp` (about
/// 516 bytes), a SAML principal caps each component the same way, and an IdP group is stored as
/// `<source>:<external_id>` with an external id up to 512 bytes (`kMaxExternalIdLength` in
/// `rbac_store.cpp`). `RbacStore::create_role` and the engine principal id carry no length cap of
/// their own, so 1024 is a bound on what is attestable, not a proven upper bound of every store.
/// A row carries at most three such fields (`audit_token` neutralises bytes but does not shorten
/// them), so an audit row stays under about 3.3 KiB.
inline constexpr std::size_t kPrincipalIdMaxLen = 1024;
inline constexpr std::size_t kRoleNameMaxLen = 1024;

/// The refusal text REST (400) and MCP (invalid-params) return for an attestation grant field that
/// is over its cap or holds a NUL byte, so the two transports (and the store backstop, which
/// prefixes `bad_request: `) cannot drift. An EMPTY field keeps its own "required" refusal. The
/// number is spelled out in the text, so the `static_assert`s below pin it to the constants:
/// change the text and the asserts together with `kPrincipalIdMaxLen`/`kRoleNameMaxLen`.
inline constexpr std::string_view kGrantFieldInvalidMessage =
    "principal_type, principal_id and role_name must be 1-1024 bytes without NUL";
static_assert(kPrincipalIdMaxLen == 1024 && kRoleNameMaxLen == 1024,
              "kGrantFieldInvalidMessage spells out 1024: update the text with the constants");

/// Most decisions one grant keeps. `record_attestation` refuses the next one (`bad_request:` +
/// `kDecisionCapMessage`, nothing written) and `get_campaign(id, true)` returns at most this many
/// history entries per grant (the latest), so one grant cannot make a read or a response grow
/// without bound. `decision_seq` stays the total count: a consumer detects a truncated history as
/// `decision_seq > history.size()`. Same type as `decision_seq`.
inline constexpr std::int32_t kMaxDecisionsPerGrant = 100;

/// The refusal text REST (400) and MCP (invalid-params) return for a decision past the cap, so the
/// two transports (and the store, which prefixes `bad_request: `; the handlers strip that prefix
/// for this one refusal) cannot drift. It spells out 100, pinned below.
inline constexpr std::string_view kDecisionCapMessage =
    "this grant already has the maximum number of recorded decisions (100) in this campaign; no "
    "further decision can be recorded on it. Close the campaign and open a new one to review it "
    "again. If an earlier attempt may have been recorded, read the campaign first";
static_assert(kMaxDecisionsPerGrant == 100,
              "kDecisionCapMessage spells out 100: update the text with the constant");

/// The `bad_request: ` prefix the store puts on a refusal it classifies as the caller's.
inline constexpr std::string_view kBadRequestPrefix = "bad_request: ";

/// The wire text of the cap refusal: the store's `bad_request: <kDecisionCapMessage>` without the
/// classification prefix, or `nullopt` for any other store error. Exact match, so no other
/// `bad_request:` string changes behaviour.
[[nodiscard]] inline std::optional<std::string_view>
decision_cap_wire_message(std::string_view store_error) noexcept {
    if (store_error.size() == kBadRequestPrefix.size() + kDecisionCapMessage.size() &&
        store_error.starts_with(kBadRequestPrefix) &&
        store_error.substr(kBadRequestPrefix.size()) == kDecisionCapMessage)
        return kDecisionCapMessage;
    return std::nullopt;
}

/// True when `principal_type`, `principal_id` and `role_name` are each within their cap and free of
/// a NUL byte (emptiness is the caller's own check). `pg/pg_exec.hpp` binds `c_str()`, so a NUL
/// would truncate the bound value and name a different grant than the one audited.
[[nodiscard]] inline bool attest_grant_fields_within_bounds(std::string_view principal_type,
                                                            std::string_view principal_id,
                                                            std::string_view role_name) noexcept {
    const auto ok = [](std::string_view s, std::size_t cap) {
        return s.size() <= cap && s.find('\0') == std::string_view::npos;
    };
    return ok(principal_type, kPrincipalIdMaxLen) && ok(principal_id, kPrincipalIdMaxLen) &&
           ok(role_name, kRoleNameMaxLen);
}

/// The single shared campaign id validator: 1..kCampaignIdMaxLen bytes, each in `[A-Za-z0-9_-]`.
/// REST, MCP and the Access page all call this (the Settings fragment does from its own change);
/// never fork a second copy. It tests every byte of the view, so an embedded NUL is rejected:
/// `pg/pg_exec.hpp` binds `c_str()`, so a NUL (httplib decodes `%00` in a route capture to a real
/// one) would truncate the bound id and read or write a different row than the one named. The
/// accepted alphabet excludes every URL-significant byte, so an id that passes can be placed in a
/// query value or a path segment unchanged.
[[nodiscard]] inline bool valid_campaign_id(std::string_view id) noexcept {
    if (id.empty() || id.size() > kCampaignIdMaxLen)
        return false;
    for (const unsigned char c : id) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

} // namespace yuzu::server
