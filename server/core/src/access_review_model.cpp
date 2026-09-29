#include "access_review_model.hpp"

#include "api_token_store.hpp"
#include "data_export.hpp"
#include "directory_sync.hpp"
#include "engine_principal_store.hpp"
#include "rbac_store.hpp"

#include <yuzu/server/auth_db.hpp>

#include <algorithm>
#include <locale>
#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

/// Best-effort provenance normalisation shared by user/group rows. Maps the
/// store-native provenance vocabulary onto the export's small enum
/// (`"local" | "scim" | "idp" | "engine"`); anything unrecognised passes
/// through unchanged rather than being silently coerced (forward-compat with
/// a future provenance value neither of us has seen yet).
std::string normalize_source(const std::string& raw) {
    if (raw == "local")
        return "local";
    if (raw == "oidc" || raw == "saml" || raw == "ad" || raw == "entra")
        return "idp";
    if (raw == "scim")
        return "scim";
    return raw;
}

/// Best-effort user→email lookup off a synced directory roster (Entra/AD).
/// Matched on UPN == username (the common case for a synced directory whose
/// login identity mirrors the local/SSO username); no match is not an
/// error — the field is simply left empty. `dirsync` may be null.
std::unordered_map<std::string, std::string> build_email_index(DirectorySync* dirsync) {
    std::unordered_map<std::string, std::string> idx;
    if (!dirsync || !dirsync->is_open())
        return idx;
    for (const auto& du : dirsync->get_synced_users()) {
        if (!du.upn.empty() && !du.email.empty())
            idx.emplace(du.upn, du.email);
    }
    return idx;
}

/// Fill the non-`roles`/`effective_permission_count` fields of `row` for a
/// grant whose (principal_type, principal_id) matched NOTHING in any roster
/// — a since-deleted user, a stale IdP-provisioned row, an OIDC/SSO
/// principal that was never materialized into a roster, or (defensively) an
/// unrecognised `principal_type` on a live grant row. UP-1: surfaced as
/// evidence, never dropped.
void fill_orphan(AccessReviewRow& row) {
    row.display_name = row.principal_id;
    row.owner_or_email = "";
    row.last_activity_ms = 0;
    row.last_activity_kind = "n/a";
    row.classification = "";
    row.lifecycle_state = "unknown";
    row.source = "orphan";
}

} // namespace

std::expected<std::vector<AccessReviewRow>, std::string>
build_access_review(AuthDB* users, RbacStore* rbac, EnginePrincipalStore* engines,
                    ApiTokenStore* tokens, DirectorySync* dirsync) {
    if (!users)
        return std::unexpected("auth store unavailable");
    if (!rbac || !rbac->is_open())
        return std::unexpected("rbac store unavailable");
    if (!engines || !engines->is_open())
        return std::unexpected("engine principal store unavailable");

    // ── UP-1: the grant table is the spine ─────────────────────────────────
    // EVERY (principal_type, principal_id, role_name) row on record, in one
    // bulk read — not a per-roster-member fan-out. A roster walk can never
    // see a grant whose principal was deleted, or an OIDC/SSO principal
    // never materialized into a roster; this can't miss any of those,
    // because it reads the grants directly.
    auto grants_r = rbac->list_all_principal_roles_checked();
    if (!grants_r)
        return std::unexpected("failed to read grants: " + grants_r.error());

    // ── Perf fix: role → distinct allow-permission set, computed ONCE ──────
    // (not once per principal per role — the N×M fan-out the prior
    // per-roster-member walk incurred).
    auto role_perms_r = rbac->list_all_role_permissions_checked();
    if (!role_perms_r)
        return std::unexpected("failed to read role permissions: " + role_perms_r.error());
    std::unordered_map<std::string, std::unordered_set<std::string>> role_perm_memo;
    for (const auto& p : *role_perms_r) {
        if (p.effect == "allow")
            role_perm_memo[p.role_name].insert(p.securable_type + "\x1f" + p.operation);
    }

    // ── Optional enrichment reads (never fail the export) ─────────────────
    const std::unordered_map<std::string, std::string> email_by_upn = build_email_index(dirsync);

    // Engine `principal_id -> most recent last_used_at across its non-
    // revoked API-token credentials`. `tokens` itself is optional (a null
    // pointer just means no enrichment); a REAL read failure on a present
    // store DOES propagate (R1 — it is part of what this export promised to
    // read).
    std::unordered_map<std::string, std::int64_t> engine_last_used;
    if (tokens) {
        auto all_tokens = tokens->list_tokens("");
        if (!all_tokens)
            return std::unexpected("failed to read api tokens: " + all_tokens.error());
        for (const auto& t : *all_tokens) {
            if (t.principal_kind != "engine" || t.revoked)
                continue;
            auto& slot = engine_last_used[t.principal_id];
            slot = std::max(slot, t.last_used_at);
        }
    }

    // ── Roster reads — REQUIRED for enrichment ──────────────────────────────
    // Not part of the R1 "grant" read set itself, but treated as required
    // (rather than optional-degrade like `tokens`/`dirsync` above): a
    // silently-dropped roster read would silently blank every user/group/
    // engine row's display_name/owner/classification/lifecycle rather than
    // fail loudly, which is exactly the kind of quiet evidence corruption R1
    // exists to rule out.
    // list_users_including_inactive(), NOT list_users(): a disabled user
    // still holding a grant is materially different CC6.2 evidence than an
    // "orphan" grant with no matching roster row at all — see the file
    // header + AccessReviewRow::lifecycle_state doc.
    auto users_r = users->list_users_including_inactive();
    if (!users_r)
        return std::unexpected("failed to read users (code=" +
                               std::to_string(static_cast<int>(users_r.error())) + ")");
    std::unordered_map<std::string, const UserWithStatus*> user_by_name;
    user_by_name.reserve(users_r->size());
    for (const auto& u : *users_r)
        user_by_name.emplace(u.username, &u);

    auto groups_r = rbac->list_groups_checked();
    if (!groups_r)
        return std::unexpected("failed to read groups: " + groups_r.error());
    std::unordered_map<std::string, const RbacGroup*> group_by_name;
    group_by_name.reserve(groups_r->size());
    for (const auto& g : *groups_r)
        group_by_name.emplace(g.name, &g);

    auto engines_r = engines->list_all_checked(/*include_revoked=*/true);
    if (!engines_r)
        return std::unexpected("failed to read engine principals: " + engines_r.error());
    std::unordered_map<std::string, const EnginePrincipalRow*> engine_by_id;
    engine_by_id.reserve(engines_r->size());
    for (const auto& e : *engines_r)
        engine_by_id.emplace(e.principal_id, &e);

    // ── Group grants by (principal_type, principal_id) ─────────────────────
    // `std::map<pair<...>>` gives deterministic (type, id)-lexicographic
    // output order for free; `grants_r` is already `ORDER BY principal_type,
    // principal_id, role_name` but nothing here depends on that.
    std::map<std::pair<std::string, std::string>, std::vector<std::string>> grouped;
    for (const auto& g : *grants_r)
        grouped[{g.principal_type, g.principal_id}].push_back(g.role_name);

    std::vector<AccessReviewRow> out;
    out.reserve(grouped.size());
    for (auto& [key, role_names] : grouped) {
        const auto& [ptype, pid] = key;

        // Perf fix: union the per-role memoized permission sets rather than
        // re-querying `role_permissions` per role per principal.
        std::unordered_set<std::string> distinct;
        for (const auto& role_name : role_names) {
            auto it = role_perm_memo.find(role_name);
            if (it != role_perm_memo.end())
                distinct.insert(it->second.begin(), it->second.end());
        }

        AccessReviewRow row;
        row.principal_type = ptype;
        row.principal_id = pid;
        row.roles = std::move(role_names);
        row.effective_permission_count = static_cast<int>(distinct.size());

        if (ptype == "user") {
            auto it = user_by_name.find(pid);
            if (it != user_by_name.end()) {
                const UserWithStatus& u = *it->second;
                row.display_name = u.username;
                auto email_it = email_by_upn.find(u.username);
                row.owner_or_email = email_it != email_by_upn.end() ? email_it->second : "";
                // AuthDB does not currently expose a bulk (or even
                // single-user) read of `users.last_login_at` —
                // `touch_last_login` is write-only (auth_db.cpp:874's own
                // comment: "is_active and last_login_at exist in DB but not
                // in UserEntry struct"). Honest unknown, not a fabricated 0
                // that would read as "never logged in".
                row.last_activity_ms = 0;
                row.last_activity_kind = "n/a";
                row.classification = "";
                // A matched user row that is DISABLED (still holds this
                // grant, but the account itself is deactivated) is
                // "disabled", not "orphan" — the principal exists and is
                // identifiable, it just shouldn't have standing access.
                row.lifecycle_state = u.is_active ? "active" : "disabled";
                row.source = normalize_source(u.identity_source);
            } else {
                fill_orphan(row);
            }
        } else if (ptype == "group") {
            auto it = group_by_name.find(pid);
            if (it != group_by_name.end()) {
                row.display_name = pid;
                row.owner_or_email = "";
                row.last_activity_ms = 0;
                row.last_activity_kind = "n/a";
                row.classification = "";
                row.lifecycle_state = "";
                row.source = normalize_source(it->second->source);
            } else {
                fill_orphan(row);
            }
        } else if (ptype == "engine") {
            auto it = engine_by_id.find(pid);
            if (it != engine_by_id.end()) {
                const EnginePrincipalRow& e = *it->second;
                row.display_name = e.display_name;
                row.owner_or_email = e.owner_username;
                auto lu = engine_last_used.find(pid);
                if (lu != engine_last_used.end() && lu->second > 0) {
                    row.last_activity_ms = lu->second;
                    row.last_activity_kind = "last_used";
                } else {
                    row.last_activity_ms = 0;
                    row.last_activity_kind = "n/a";
                }
                row.classification = e.classification;
                row.lifecycle_state = e.lifecycle_state;
                row.source = "engine";
            } else {
                fill_orphan(row);
            }
        } else {
            // Defensive: an unrecognized principal_type on a live grant row
            // (corrupt data, or a future type this export hasn't been
            // taught about yet). Still surfaced, never dropped — UP-1.
            fill_orphan(row);
        }

        out.push_back(std::move(row));
    }

    return out;
}

namespace {

/// RFC 4180-style field escaping, including CWE-1236 formula-injection
/// neutralization (`principal_id`/`display_name`/`owner_or_email`/role names
/// are all influenceable by an external identity provider -- not a
/// theoretical input for a compliance evidence export a reviewer is expected
/// to open in a spreadsheet). Delegates to the shared `data_export::csv_escape`
/// chokepoint -- this file was the original precedent for the fix; every CSV
/// exporter routes through the same helper now, rather than each forking its
/// own copy.
std::string csv_field(const std::string& field) {
    return data_export::csv_escape(field);
}

std::string csv_join_roles(const std::vector<std::string>& roles) {
    std::string out;
    for (std::size_t i = 0; i < roles.size(); ++i) {
        if (i > 0)
            out += ";";
        out += roles[i];
    }
    return out;
}

} // namespace

std::string to_csv(const std::vector<AccessReviewRow>& rows, const std::string& rbac_enforcement) {
    std::ostringstream ss;
    // Locale-independent numeric formatting (cpp-expert NICE): under a
    // grouping locale (e.g. "de_DE"), the default-imbued stream would emit
    // thousands separators into effective_permission_count/last_activity_ms
    // — corrupting the CSV's numeric columns for any downstream parser.
    ss.imbue(std::locale::classic());
    // A3 (RBAC delivery plan): unconditional leading metadata line — present
    // even for an empty `rows` population, so "no grants" is never ambiguous
    // with "the stamp was omitted". Emitted verbatim: `rbac_enforcement` is
    // always one of the three fixed literals the caller derived via
    // `access_review_rbac_enforcement()`, never externally influenced, so
    // csv_field's RFC-4180/CWE-1236 handling does not apply here.
    ss << "# rbac_enforcement=" << rbac_enforcement << "\r\n";
    ss << "principal_type,principal_id,display_name,owner_or_email,roles,"
          "effective_permission_count,last_activity_ms,last_activity_kind,"
          "classification,lifecycle_state,source\r\n";
    for (const auto& r : rows) {
        ss << csv_field(r.principal_type) << ',' << csv_field(r.principal_id) << ','
           << csv_field(r.display_name) << ',' << csv_field(r.owner_or_email) << ','
           << csv_field(csv_join_roles(r.roles)) << ',' << r.effective_permission_count << ','
           << r.last_activity_ms << ',' << csv_field(r.last_activity_kind) << ','
           << csv_field(r.classification) << ',' << csv_field(r.lifecycle_state) << ','
           << csv_field(r.source) << "\r\n";
    }
    return ss.str();
}

std::string access_review_rbac_enforcement(const RbacStore* rbac) {
    return std::string(to_string(rbac_enforcement_label(rbac)));
}

} // namespace yuzu::server
