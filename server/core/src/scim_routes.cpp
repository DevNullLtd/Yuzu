#include "scim_routes.hpp"

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "deprovision_revoke.hpp"
#include "engine_principal_store.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/server.hpp> // Config — scim_boot_guard_ok

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── Boot guard (S-BOOTGUARD-TEST) ───────────────────────────────────────────

// M1 (2026-07-08 review): floor on the operator-supplied bearer token.
// ScimStore stores it as unsalted single-round SHA-256 (S-BEARER-HASH) —
// verify-only, but with no per-attempt slowdown, so a short/weak token is
// brute-forceable against a leaked hash far faster than a properly-sized
// credential. 24 chars is generous headroom over a 128-bit CSPRNG token
// hex-encoded (32 chars) while still accepting a hand-typed high-entropy
// passphrase.
constexpr std::size_t kMinScimTokenLength = 24;

bool scim_boot_guard_ok(const Config& cfg, std::string& err) {
    if (!cfg.scim_enable)
        return true;
    if (cfg.scim_token.empty()) {
        err = "--scim-enable requires --scim-token (or YUZU_SCIM_TOKEN) — refusing "
              "to start an unauthenticated provisioning surface.";
        return false;
    }
    if (cfg.scim_token.size() < kMinScimTokenLength) {
        err = "--scim-token must be at least " + std::to_string(kMinScimTokenLength) +
              " characters (it is stored as an unsalted SHA-256 hash and is the sole "
              "credential gating an account-provisioning surface) — refusing to start "
              "with a short/low-entropy token.";
        return false;
    }
    if (!cfg.https_enabled) {
        err = "--scim-enable requires HTTPS (the bearer token would otherwise cross "
              "the wire in plaintext) — refusing to start with --no-https set. Enable "
              "HTTPS or disable --scim-enable.";
        return false;
    }
    return true;
}

namespace {

using json = nlohmann::json;

constexpr const char* kScimJson = "application/scim+json";
// Bound POST/PUT/PATCH bodies before parsing — a real SCIM User payload
// (even with IdP-sent fields Yuzu ignores: name, emails, groups, ...) is a
// few KB; 64 KiB is generous headroom while refusing a multi-MB POST on this
// provisioning surface.
constexpr std::size_t kMaxBodyBytes = 64 * 1024;

// sre-capacity (governance hardening round): every Group mutation fans out a
// per-member `recompute_scim_user_role` call under the global AuthManager
// lock (O(N members x |sessions_|) per op, via the session-invalidation
// sweep in `AuthManager::update_role`/`remove_user`). Bound N so a single
// pathological IdP-authored Group cannot turn one PUT/PATCH/POST into an
// unbounded stall. 5000 is generous headroom over any real deployment's
// admin/role-mapping group size while still bounding the worst case.
constexpr std::size_t kMaxGroupMembers = 5000;

void send_scim_error(httplib::Response& res, int status, std::string_view detail,
                     std::string_view scim_type = "") {
    res.status = status;
    res.set_content(scim::error(status, detail, scim_type).dump(), kScimJson);
}

void send_scim_error(httplib::Response& res, const scim::ScimError& e) {
    res.status = e.status;
    res.set_content(scim::error(e).dump(), kScimJson);
}

/// S-BOUND-INTPARAM (sec MEDIUM-2): parse a SCIM list query int param
/// (`startIndex`/`count`) with a shape check on the raw string BEFORE ever
/// handing it to `std::stoi` — an empty value, non-numeric garbage, or an
/// absurdly long digit string must fail cleanly with a SCIM 400
/// `invalidValue`, never an unhandled `std::invalid_argument`/
/// `std::out_of_range` escaping to an unhandled-exception 500. `raw` is
/// rejected if empty, longer than 10 characters (a legitimate startIndex/
/// count never needs more digits than `INT_MAX`), or not all-digits with an
/// optional leading `-`. `std::stoi` is still wrapped in try/catch as
/// belt-and-suspenders. On failure, sends the 400 response and returns
/// `std::nullopt`; the caller is responsible for `record_request(...)`.
std::optional<int> parse_scim_int_param(httplib::Response& res, std::string_view raw,
                                        std::string_view param_name) {
    bool shape_ok = !raw.empty() && raw.size() <= 10;
    if (shape_ok) {
        std::size_t i = (raw.front() == '-') ? 1 : 0;
        shape_ok = i < raw.size();
        for (; shape_ok && i < raw.size(); ++i)
            shape_ok = std::isdigit(static_cast<unsigned char>(raw[i])) != 0;
    }
    if (shape_ok) {
        try {
            return std::stoi(std::string(raw));
        } catch (const std::exception&) {
            shape_ok = false;
        }
    }
    send_scim_error(res, 400, std::string(param_name) + " must be an integer", "invalidValue");
    return std::nullopt;
}

/// Fixed audit principal — there is no session/human operator on this
/// bearer-only surface (see scim_routes.hpp header doc).
constexpr const char* kScimPrincipal = "scim-service";

// ── Metrics (M-METRICS) ─────────────────────────────────────────────────────

/// Bucket an HTTP status into Prometheus's conventional 2xx/4xx/5xx label so
/// `yuzu_scim_requests_total` stays low-cardinality regardless of the exact
/// status code.
std::string_view status_bucket(int status) {
    if (status >= 200 && status < 300)
        return "2xx";
    if (status >= 400 && status < 500)
        return "4xx";
    if (status >= 500)
        return "5xx";
    return "other";
}

/// Record one `/scim/v2/Users` request outcome. `op` is one of
/// create/get/list/replace/patch/delete. No-op when no MetricsRegistry is
/// wired (AuthManager::metrics_registry() is null in test/CLI contexts).
void record_request(auth::AuthManager* auth_mgr, const char* op, int status) {
    if (!auth_mgr)
        return;
    auto* m = auth_mgr->metrics_registry();
    if (!m)
        return;
    m->counter("yuzu_scim_requests_total",
               {{"op", op}, {"status", std::string(status_bucket(status))}})
        .increment();
}

void bump_auth_failure(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_auth_failures_total").increment();
}

void bump_audit_write_failure(auth::AuthManager* auth_mgr, const std::string& action) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_audit_write_failures_total", {{"action", action}}).increment();
}

void bump_provenance_denied(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_provenance_denied_total").increment();
}

/// #2021 slice 2: bumped every time `recompute_scim_user_role` actually
/// changes a SCIM-provisioned user's role (promotion OR demotion).
void bump_role_changed(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_role_changes_total").increment();
}

/// CC6.7 evidence-gap fix (governance hardening round): bumped when
/// `recompute_scim_user_role`'s `AuthManager::update_role` call reports a
/// genuine AuthDB write failure — a durable role change that did not apply.
void bump_role_change_failure(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_role_change_failures_total").increment();
}

/// ADR-2001 D1: a deprovision `deprovision_role_ok` refused (the #2021
/// role-refusal fork) for a slug that has at least one active linked
/// federated identity (OIDC and/or SAML) — the federated credentials were
/// NOT auto-revoked and a human must terminate them manually.
void bump_deprovision_role_refused_with_link(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_deprovision_role_refused_with_active_link_total").increment();
}

/// The result of `federated_links_for_scim_id` below: whether `scim_id` has
/// at least one active linked federated identity, and how many were
/// confirmed (best-effort — see that function's doc comment on partial
/// lookup failure).
struct FederatedLinkCount {
    bool has_link = false;
    std::size_t count = 0;
};

/// ADR-2001 PR4a — D1's "does this scim_id have any active linked federated
/// identity" test, UNIONED across OIDC (`links_for_scim_id`) and SAML
/// (`saml_links_for_scim_id`) — mirrors `resolve_deprovision_principals`'s
/// union pattern (deprovision_revoke.cpp:17-33), but stays a fire/no-fire +
/// count question for D1's best-effort LOUDNESS signal rather than a
/// deprovision-gating resolve (D1 never gates access — see deactivate()'s
/// doc comment; the underlying role refusal is already fail-closed before
/// this runs).
///
/// A lookup failure on EITHER side is a store blip, not "no linked
/// identity" — but D1 is best-effort, so it must not CRASH and must not
/// SUPPRESS a signal the other side would have fired on its own: if OIDC
/// alone confirms a link, this fires on that count even when the SAML read
/// blipped, and vice versa (this is why OIDC-only behavior is unchanged
/// when SAML is the side that blips or is empty). This reports no link
/// whenever no side actually CONFIRMS one — both blipped, both confirmed-
/// empty, OR one confirmed-empty while the other blipped. That last case is
/// the residual: if the blipping side was the one genuinely holding the only
/// link, the signal is skipped — a single-store-blip degradation identical
/// in kind to the pre-existing OIDC-only path (no regression, and never a
/// false-positive fire), acceptable because D1 is a best-effort loudness
/// overlay on a refusal that has already fail-closed.
FederatedLinkCount federated_links_for_scim_id(ScimStore& scim_store, const std::string& scim_id) {
    FederatedLinkCount out;
    auto oidc_links = scim_store.links_for_scim_id(scim_id);
    if (oidc_links.has_value()) {
        out.count += oidc_links->size();
    } else {
        spdlog::warn("ScimRoutes: D1 — links_for_scim_id lookup failed for scim_id={} (store "
                    "blip); the OIDC half of the D1 signal is best-effort skipped, not treated "
                    "as \"no linked identity\"",
                    scim_id);
    }
    auto saml_links = scim_store.saml_links_for_scim_id(scim_id);
    if (saml_links.has_value()) {
        out.count += saml_links->size();
    } else {
        spdlog::warn("ScimRoutes: D1 — saml_links_for_scim_id lookup failed for scim_id={} "
                    "(store blip); the SAML half of the D1 signal is best-effort skipped, not "
                    "treated as \"no linked identity\"",
                    scim_id);
    }
    out.has_link = out.count > 0;
    return out;
}

/// ADR-2001 D1 — the LOUD *severity* channel. `AuditEvent`/`AuditStore`
/// (what every other call on this surface writes to, via `audit()` below)
/// has NO severity field — its `result` column is success/denied/failure/
/// partial, never a severity level, so a D1 audit row can only ever be as
/// loud as any other row. The one severity-carrying mechanism in this
/// codebase is `AnalyticsEvent::severity` via `AnalyticsEventStore` — the
/// SAME channel `AuthRoutes::emit_event` (auth_routes.cpp) uses to record
/// `Severity::kCritical` break-glass-login events. This mirrors that
/// function's body: no session to resolve on this bearer-only surface, so
/// `principal`/`principal_role` are stamped with the fixed SCIM service
/// principal instead of a resolved session's username/role. `analytics_
/// store` may be null (deferred-wiring precedent, see the header doc) —
/// a no-op in that case; the AuditStore row and the counter this always
/// runs alongside still fire regardless.
void emit_scim_critical_event(AnalyticsEventStore* analytics_store, const std::string& event_type,
                              const nlohmann::json& attrs) {
    if (!analytics_store)
        return;
    AnalyticsEvent ae;
    ae.event_type = event_type;
    ae.severity = Severity::kCritical;
    ae.attributes = attrs;
    ae.principal = kScimPrincipal;
    ae.principal_role = kScimPrincipal;
    analytics_store->emit(std::move(ae));
}

/// ADR-2001 D2: a deprovision resolved NO linked OIDC identity for a slug,
/// but a recorded login observation shows a claim value matching that
/// slug's externalId — the user DID authenticate via OIDC but the link
/// never formed, almost certainly a misconfigured `--oidc-scim-link-claim`.
/// The CC6.8 false-green tripwire: a deprovision that revokes nothing for a
/// federated user who exists.
void bump_deprovision_unlinked(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_deprovision_unlinked_total").increment();
}

/// ADR-2001 #3072 — the SAML analogue of `bump_deprovision_unlinked`/
/// `yuzu_scim_deprovision_unlinked_total`: a deprovision resolved NO linked
/// SAML identity for a slug, but a recorded SAML login observation shows a
/// NameID matching that slug's externalId — the user DID authenticate via
/// SAML but the identity link never formed (either a non-linkable NameID
/// Format, or a genuine store hiccup on the write side). SEPARATE counter
/// from the OIDC one — the two federation protocols are independently
/// actionable signals.
void bump_deprovision_saml_unlinked(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_deprovision_saml_unlinked_total").increment();
}

// ── Audit ────────────────────────────────────────────────────────────────

/// Emit a SCIM audit row. AuditStore::log is [[nodiscard]] bool; per the
/// evidence-integrity contract (audit_store.hpp) EVERY caller on this
/// surface — including the three termination actions (deactivated/deleted/
/// reactivated) — "set-and-proceed" rather than fail the IdP's request over
/// an audit-store hiccup: the mutation already committed, and a fail-closed
/// 500 here does not help, because the IdP's retry observes post-state
/// (e.g. the account is already inactive) and takes the non-termination
/// branch on the next request — it never re-attempts the lost audit write,
/// so failing closed only costs the caller a spurious 500 without
/// recovering the evidence row. CC6.8 evidence integrity is instead
/// enforced by an alert on `yuzu_scim_audit_write_failures_total`, which
/// every failure (including `audit_store == nullptr`, an equally real
/// evidence gap) bumps regardless of the caller's response.
bool audit(auth::AuthManager* auth_mgr, AuditStore* audit_store, const httplib::Request& req,
          const std::string& action, const std::string& result, const std::string& target_id,
          const std::string& detail = {}, const std::string& target_type = "User") {
    if (!audit_store) {
        bump_audit_write_failure(auth_mgr, action);
        return false;
    }
    AuditEvent ev;
    ev.principal = kScimPrincipal;
    ev.principal_role = kScimPrincipal; // S-PRINCIPAL-ROLE — every other machine principal sets one
    ev.action = action;
    ev.target_type = target_type; // "User" (default) or "Group" (#2021 group ops)
    ev.target_id = target_id;
    ev.detail = detail;
    ev.result = result;
    ev.source_ip = req.remote_addr;
    ev.user_agent = req.get_header_value("User-Agent");
    bool ok = audit_store->log(ev);
    if (!ok) {
        spdlog::error("ScimRoutes: audit write failed action='{}' target_id='{}' result='{}'",
                     action, target_id, result);
        bump_audit_write_failure(auth_mgr, action);
    }
    return ok;
}

// Two-mode owner-deprovision enforcement (engine principals, PR 4.3
// governance hardening; enterprise-architect ruling). The interactive
// dashboard delete (settings_routes.cpp) PREVENTS removing a user who owns
// active engine principals (409 — the admin can transfer ownership first).
// Automated SCIM deprovision is a CC6.8-mandated termination with no such
// actor: refusing would leave a terminated employee active; cascade
// auto-revoke is rejected because revoke() is terminal/irreversible. So SCIM
// deprovision is DETECTIVE — it always succeeds, but a deprovisioned owner
// (or an unverifiable count) raises a high-signal audit + metric for
// out-of-band ownership reassignment. The principal authenticates on its own
// credential and never re-derived authority from the owner.
void flag_owner_deprovisioned(EnginePrincipalStore* engine_principal_store,
                              auth::AuthManager* auth_mgr, AuditStore* audit_store,
                              const httplib::Request& req, const std::string& username) {
    if (!engine_principal_store) return;
    auto owned = engine_principal_store->count_active_owned_by(username);
    if (owned.has_value() && *owned == 0) return; // clean — common case
    std::string detail = owned.has_value()
        ? "orphaned_active_engine_principals=" + std::to_string(*owned)
        : "engine_ownership_unverifiable";
    audit(auth_mgr, audit_store, req, "engine_principal.owner_deprovisioned", "success",
         username, detail, "EnginePrincipal");
    if (auto* m = auth_mgr ? auth_mgr->metrics_registry() : nullptr)
        m->counter("yuzu_engine_principal_owner_deprovisioned_total").increment();
}

/// Build the `/scim/v2/Users` collection URL for this request so
/// `scim::user_to_json`'s `meta.location` / the `Location` header point at a
/// resolvable absolute URL. `--scim-enable` refuses to start without HTTPS
/// (see main.cpp), so "https" is the safe assumed scheme when no reverse
/// proxy sets X-Forwarded-Proto.
std::string location_base(const httplib::Request& req) {
    std::string scheme = req.get_header_value("X-Forwarded-Proto");
    if (scheme.empty())
        scheme = "https";
    std::string host = req.get_header_value("Host");
    return scheme + "://" + host + "/scim/v2/Users";
}

/// Group counterpart of `location_base` — the `/scim/v2/Groups` collection
/// URL for `meta.location`/`Location` header on the Group codec (#2021).
std::string groups_location_base(const httplib::Request& req) {
    std::string scheme = req.get_header_value("X-Forwarded-Proto");
    if (scheme.empty())
        scheme = "https";
    std::string host = req.get_header_value("Host");
    return scheme + "://" + host + "/scim/v2/Groups";
}

/// #2021: resolve raw Group `members[].value` strings against live SCIM
/// User resources. VALIDATE-AND-SKIP: an unresolvable/unknown value (never
/// provisioned, already deleted, or simply a typo/garbage from the IdP) is
/// silently dropped rather than erroring the whole request — but a phantom
/// membership pointing at nothing is NEVER persisted (`ScimStore::
/// set_group_members`/`add_group_member` only ever see values this function
/// already confirmed resolve to a real User resource). Deduplicates and
/// preserves the relative order of `values`.
///
/// ★ SECURITY (2026-07-25 Hermes pass, MEDIUM): validate-and-skip is only safe
/// against a DEFINITIVE negative. This used to call `get_by_scim_id`, whose
/// `nullopt` also means "the read failed" — so a transient store blip made a
/// real member look unresolvable, it was skipped, and the caller persisted the
/// SMALLER set. That is the same durable membership loss as the fold-onto-
/// empty-set bug, just partial instead of total. It now uses the tri-state
/// `resource_exists` and returns `nullopt` if ANY id could not be resolved, so
/// the caller refuses the whole write rather than committing a set built from
/// an unreliable read.
std::optional<std::vector<std::string>>
resolve_member_values(ScimStore* scim_store, const std::vector<std::string>& values) {
    std::vector<std::string> resolved;
    resolved.reserve(values.size());
    for (const auto& v : values) {
        auto exists = scim_store->resource_exists(v);
        if (!exists.has_value())
            return std::nullopt; // could not determine — fail closed, never skip
        if (!*exists)
            continue; // definitively unknown — validate-and-skip, as before
        if (std::find(resolved.begin(), resolved.end(), v) == resolved.end())
            resolved.push_back(v);
    }
    return resolved;
}

/// #2127 review HIGH fix: fold an ORDERED list of `ScimGroupMemberOp`s onto
/// a starting membership set, applying each op in the body's own document
/// order — never all-removes-then-all-adds (the old bucketed-apply order,
/// which made `[{add:U},{remove:U}]` and `[{remove:U},{add:U}]` produce the
/// SAME wrong result: U left a member either way, because a `remove` on a
/// not-yet-added id was an idempotent no-op and the `remove`/`add` buckets
/// were applied in a fixed order regardless of which the caller sent last).
/// Values are the RAW (unresolved) `value` strings from the request body —
/// the caller resolves the final result against live SCIM Users in one pass
/// (`resolve_member_values`), not per-op, per the reworked
/// resolve-final -> validate-final -> persist design.
std::vector<std::string> fold_group_member_ops(const std::vector<std::string>& current,
                                               const std::vector<scim::ScimGroupMemberOp>& ops) {
    std::vector<std::string> result = current;
    for (const auto& op : ops) {
        switch (op.kind) {
        case scim::ScimGroupMemberOp::Kind::Add:
            for (const auto& v : op.values) {
                if (std::find(result.begin(), result.end(), v) == result.end())
                    result.push_back(v);
            }
            break;
        case scim::ScimGroupMemberOp::Kind::Remove:
            for (const auto& v : op.values)
                result.erase(std::remove(result.begin(), result.end(), v), result.end());
            break;
        case scim::ScimGroupMemberOp::Kind::RemoveAll:
            result.clear();
            break;
        case scim::ScimGroupMemberOp::Kind::ReplaceAll:
            result = op.values;
            break;
        }
    }
    return result;
}

/// Bearer gate shared by every /scim/v2/* route. Reads ONLY the
/// `Authorization: Bearer <token>` header (no cookie/CSRF — there is no
/// session on this surface) and validates it against ScimStore's hashed
/// token(s). On failure, sends 401 + WWW-Authenticate + a SCIM error body,
/// audits `scim.auth.denied` + bumps `yuzu_scim_auth_failures_total`
/// (M-BEARER-AUDIT — a rejected bearer against a surface that can
/// provision/deprovision operator accounts is a credential-guess/replay
/// signal), and returns false so the caller can bail out of the handler.
bool require_bearer(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                    const httplib::Request& req, httplib::Response& res) {
    constexpr std::string_view kPrefix = "Bearer ";
    std::string token;
    if (auto h = req.get_header_value("Authorization");
        h.size() > kPrefix.size() && h.compare(0, kPrefix.size(), kPrefix) == 0) {
        token = h.substr(kPrefix.size());
    }
    if (!scim_store || !scim_store->is_open() || token.empty() ||
        !scim_store->validate_token(token)) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Bearer");
        res.set_content(scim::error(401, "invalid or missing bearer token").dump(), kScimJson);
        audit(auth_mgr, audit_store, req, "scim.auth.denied", "denied", "");
        bump_auth_failure(auth_mgr);
        return false;
    }
    return true;
}

/// LOAD-BEARING SECURITY INVARIANT — the provenance guard. SCIM must only
/// ever mutate accounts IT provisioned. `ScimStore::get_by_scim_id` already
/// gives defense against a locally-created admin (which has no scim_resource
/// row at all, so the caller 404s before this is even reached) — this is a
/// SECOND, independent check straight against the auth substrate: even if a
/// scim_resource row somehow existed for a non-SCIM account (e.g. a future
/// bug, or an operator hand-editing scim_resources), we refuse to touch the
/// underlying auth account unless `provisioning_source == "scim"` RIGHT NOW.
/// Returns true iff the mutation may proceed. On refusal, sends 404 (NEVER
/// 403 — a 403 would confirm to the IdP that a local account by this name
/// exists) and audits `scim.user.provenance_denied`.
bool provenance_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                   const httplib::Request& req, const std::string& username,
                   const std::string& scim_id, httplib::Response& res) {
    AuthDB* db = auth_mgr ? auth_mgr->auth_db_ptr() : nullptr;
    if (!db) {
        // No persistent AuthDB configured — SCIM cannot durably record/verify
        // provenance, so refuse rather than risk mutating an account we can't
        // prove we provisioned.
        spdlog::error("ScimRoutes: provenance check unavailable (no AuthDB) — refusing "
                     "mutation of '{}'",
                     username);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "no AuthDB configured");
        bump_provenance_denied(auth_mgr);
        return false;
    }
    auto source = db->get_provisioning_source(username);
    if (!source || *source != kProvisioningSourceScim) {
        spdlog::warn("SCIM: refusing to mutate account '{}' (scim_id={}) — "
                    "provisioning_source is not 'scim' (this account was not created by SCIM)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "provisioning_source is not 'scim' for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// H2 (2026-07-08 review, fail-open on a cold cache): read a user's role
/// AUTHORITATIVELY from `AuthDB`, never `AuthManager::get_user_role`'s
/// in-memory `users_` cache. That cache is populated lazily (login/upsert/
/// reactivate call sites) and nothing preloads it at process start, so a
/// freshly-booted server — or any process that has simply never touched
/// this username yet — reads back `nullopt` from the cache even when the
/// durable row is `admin`. The SCIM deprovision/revive guards previously
/// treated that `nullopt` as "no elevation on file, allowed", which is
/// fail-OPEN: a cold-cache process would deactivate a DB-elevated admin an
/// IdP pushes `active:false` for. Returns `nullopt` only when the role
/// genuinely cannot be determined (no `AuthDB` configured, or
/// `AuthDB::get_user` errors / finds no active row for `username`) —
/// every caller MUST treat `nullopt` as "refuse", never as "allowed"
/// (S-ROLE-FAILCLOSED).
std::optional<auth::Role> db_authoritative_role(auth::AuthManager* auth_mgr,
                                                const std::string& username) {
    AuthDB* db = auth_mgr ? auth_mgr->auth_db_ptr() : nullptr;
    if (!db)
        return std::nullopt;
    auto entry = db->get_user(username);
    if (!entry)
        return std::nullopt;
    return entry->role;
}

/// M-DEPROV-ROLE (sec MEDIUM): a demote-before-delete ORDERING GATE — refuse
/// to deprovision (deactivate/delete) an account whose CURRENT role is not
/// `user`, whether that elevation was applied by an operator (manual) or by
/// `recompute_scim_user_role` (group-derived, Model A: IdP group membership
/// is authoritative for role). Either way, the account must first be
/// demoted back to `user` — by an operator, or by the IdP removing it from
/// the admin group — before SCIM may tear it down; this is a sequencing
/// requirement, not a permanent carve-out for operator-owned accounts.
/// Checked only while the account is still ACTIVE. Role is read via
/// `db_authoritative_role` (H2) — the DB row, never the AuthManager
/// in-memory cache, which can be cold on a freshly-started process. Returns
/// true iff the deprovision may proceed; FAILS CLOSED (refuses) if the role
/// cannot be determined at all, not just when it resolves to something
/// other than `user`. On refusal sends 404 (never 403 — matches the
/// provenance guard's no-existence-oracle posture) and reuses
/// `scim.user.provenance_denied` (same "SCIM does not own this account's
/// lifecycle right now" refusal class).
bool deprovision_role_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                        const httplib::Request& req, const std::string& username,
                        const std::string& scim_id, httplib::Response& res) {
    // #2021 (Groups->role): deliberately NOT weakened for a group-elevated
    // admin. A SCIM user promoted to admin via Group membership still fails
    // this guard exactly like an operator-elevated one — the IdP must
    // remove them from the admin group FIRST (recompute_scim_user_role then
    // demotes them to 'user' on the next membership change), and only THEN
    // can SCIM deprovision (deactivate/delete) them. This ordering is the
    // point, not a gap: it stops a compromised/misconfigured IdP from
    // group-promoting an account to admin and deprovisioning it in the same
    // breath in a way that could race an operator's own admin actions on
    // that account. Do not add a bypass for the group-elevated case.
    auto role = db_authoritative_role(auth_mgr, username);
    if (!role.has_value() || *role != auth::Role::user) {
        spdlog::warn("SCIM: refusing to deprovision '{}' (scim_id={}) — role is not 'user' or "
                    "could not be authoritatively determined (an operator may have elevated "
                    "this account outside SCIM's ownership, or the DB-authoritative role read "
                    "failed closed)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "role is not 'user' (or undetermined) for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// ⚠️ SECURITY-CRITICAL (#2021 slice 2) — the SCIM-group->Yuzu-role
/// application core. Re-derives `user_scim_id`'s role from its CURRENT SCIM
/// group memberships and applies the change if it differs from the
/// authoritative DB role. Called after every mutation that could have
/// changed a user's group membership (Group POST/PUT/PATCH/DELETE, User
/// POST including the revive-on-reprovision path) — see scim_routes.hpp's
/// header doc.
///
/// Steps (in order, each a hard gate — any failure means "return, no
/// action"):
///   1. Resolve `user_scim_id` to a live SCIM User resource (`ScimStore::
///      get_by_scim_id`). If it doesn't resolve to a scim user resource
///      (e.g. a Group member value that never matched a real User, or one
///      that has since been deleted), there is nothing to recompute.
///   2. PROVENANCE GUARD (LOAD-BEARING, do not weaken): the resolved
///      username's `AuthDB::get_provisioning_source` MUST read exactly
///      `"scim"` RIGHT NOW. A Group member `value` that happens to map to a
///      local admin, a break-glass account, or any other non-SCIM-owned
///      principal must NEVER cause a role change — this is the same
///      provenance boundary `provenance_ok` enforces for every other
///      mutation on this surface, checked independently here because this
///      helper can be reached from a DIFFERENT resource's route (a Group
///      mutation) than the one whose provenance was already checked by the
///      caller's own guard.
///   3. Resolve the role via `auth::resolve_role_from_groups` over
///      `ScimStore::list_group_display_names_for_user` and
///      `scim_admin_group` (empty ⇒ always `Role::user`, never promotes).
///   4. Read the CURRENT role via `db_authoritative_role` (H2 — the DB row,
///      never the in-memory cache). `nullopt` fails closed (no change) —
///      matching every other role read on this surface.
///   5. If the resolved role differs from the current role, apply it via
///      `AuthManager::update_role` (which also invalidates the user's
///      sessions) and audit `scim.user.role_changed` (set-and-proceed, same
///      posture as every other audit on this surface — see `audit()`'s doc
///      comment). `trigger_detail` is a caller-supplied, human-readable
///      description of WHAT triggered this recompute (e.g. the triggering
///      group's displayName + op, or "user_provision" for the user
///      create/revive call site) and is folded into the audit detail as
///      `via_group="<...>"` (CC6.7 evidence: which group/op caused this role
///      change, since a user can match via multiple admin groups). Purely
///      cosmetic — never affects the resolved role logic.
///
/// CONCURRENCY (TOCTOU role drift, Hermes security gate): steps 1-5 above are
/// a non-atomic read-resolve-write. `ScimStore` is now Postgres-backed
/// (ADR-0006 migration) — it holds a `pg::PgPool&` and hands out an
/// INDEPENDENT connection per call (no single shared-connection mutex to
/// serialize on, unlike the SQLite-era `db_mtx_` this comment used to
/// reference), and `AuthManager`'s `mu_` is taken and released independently
/// per step. Two concurrent Group mutations affecting the SAME user (e.g.
/// one removing them from the admin group, another concurrently adding
/// them) can otherwise interleave so the second-committing recompute reads a
/// stale `current` role, no-ops on `resolved == current`, and leaves the
/// durable DB role contradicting the FINAL committed group membership.
/// `kRecomputeMu` serializes the entire body below so recomputes for (in
/// practice) any user are linearized process-wide — recompute is not a hot
/// path (only Group ops + user create/revive, bounded by
/// `kMaxGroupMembers`), so a single mutex is fine; per-user striping would
/// be over-engineering here. Because each Group op commits its membership
/// change to `ScimStore` BEFORE calling this function, serializing the
/// critical section guarantees the last-scheduled recompute observes the
/// final committed membership and applies the correct role — any earlier,
/// now-stale role gets corrected by whichever recompute runs last.
///
/// LOCK ORDER (do not invert): `kRecomputeMu` → `AuthManager::mu_` (taken
/// and released inside `db_authoritative_role`/`update_role`). The
/// `ScimStore` calls (`get_by_scim_id`/`list_group_display_names_for_user`)
/// no longer hold any process-wide lock across their PgPool round-trip — a
/// per-connection Postgres lease is not a mutex this function's callers can
/// invert against. `kRecomputeMu` is acquired ACROSS the `AuthManager::mu_`
/// call but is never itself acquired by any code reachable from within
/// `mu_` — this function is the only acquirer, so there is no path back
/// into `kRecomputeMu` while the inner lock is held, and thus no
/// inversion/deadlock. Do not add a second acquirer without re-checking
/// this.
void recompute_scim_user_role(ScimStore* scim_store, auth::AuthManager* auth_mgr,
                              AuditStore* audit_store, const httplib::Request& req,
                              const std::string& user_scim_id,
                              const std::string& scim_admin_group,
                              const std::string& trigger_detail) {
    if (!scim_store || !auth_mgr)
        return;

    static std::mutex kRecomputeMu;
    std::lock_guard<std::mutex> recompute_lock(kRecomputeMu);

    // Step 1: user_scim_id must resolve to a live SCIM User resource.
    auto resource = scim_store->get_by_scim_id(user_scim_id);
    if (!resource)
        return;

    AuthDB* db = auth_mgr->auth_db_ptr();
    if (!db)
        return;

    // Step 2 — PROVENANCE GUARD (LOAD-BEARING): refuse to touch anything
    // SCIM did not provision, no matter how a Group came to reference it.
    auto source = db->get_provisioning_source(resource->username);
    if (!source || *source != kProvisioningSourceScim) {
        spdlog::warn("SCIM: recompute_scim_user_role refusing to touch '{}' (scim_id={}) — "
                    "provisioning_source is not 'scim' (a Group referenced a non-SCIM account)",
                    resource->username, user_scim_id);
        // Metric-only signal (Minor #2, reviewer-adjudicated): this IS a
        // provenance-based skip, so it reuses the same counter every other
        // provenance refusal on this surface bumps. Deliberately NOT an
        // audit row here — recompute runs per-member, and a bulk Group
        // mutation with many non-SCIM members would flood the audit log;
        // the counter is the right-weight signal for a load-bearing guard
        // that still needs to be observable.
        bump_provenance_denied(auth_mgr);
        return;
    }

    // Step 3: resolve the role from CURRENT group membership.
    //
    // ★ SECURITY (2026-07-25 review, HIGH #3): an UNDETERMINED membership read
    // is not "member of no groups". Resolving nullopt as an empty set would
    // demote a SCIM-provisioned admin to `user` on a momentary store blip —
    // the same fail-open shape step 4 below already refuses for the current
    // role. Decline the recompute instead; the next Group mutation or User
    // reprovision recomputes it (Model A stays eventually-authoritative).
    auto groups = scim_store->list_group_display_names_for_user(user_scim_id);
    if (!groups.has_value()) {
        spdlog::warn("SCIM: recompute_scim_user_role — could not determine current group "
                     "membership for '{}' (scim_id={}); declining to recompute (fail-closed)",
                     resource->username, user_scim_id);
        return;
    }
    auth::Role resolved = auth::resolve_role_from_groups(*groups, scim_admin_group);

    // Step 4: fail-closed on an undetermined current role (S-ROLE-FAILCLOSED
    // posture, matching db_authoritative_role's every other caller).
    auto current = db_authoritative_role(auth_mgr, resource->username);
    if (!current.has_value()) {
        spdlog::warn("SCIM: recompute_scim_user_role — could not determine the DB-authoritative "
                    "current role for '{}' (scim_id={}); declining to recompute (fail-closed)",
                    resource->username, user_scim_id);
        return;
    }

    // Step 5: apply only on an actual change.
    if (resolved == *current)
        return;

    std::string old_role_str = auth::role_to_string(*current);
    std::string new_role_str = auth::role_to_string(resolved);
    // CC6.7: fold the caller-supplied trigger context (which group/op — or
    // user-provision — caused this recompute) into the audit detail. A user
    // can match via multiple admin groups; this records the one whose
    // mutation actually triggered THIS recompute call.
    std::string via_detail =
        trigger_detail.empty() ? "" : " via_group=\"" + trigger_detail + "\"";
    if (!auth_mgr->update_role(resource->username, resolved)) {
        spdlog::error("SCIM: recompute_scim_user_role — update_role failed for '{}' "
                     "(scim_id={}, intended {} -> {}); role change did NOT apply",
                     resource->username, user_scim_id, old_role_str, new_role_str);
        audit(auth_mgr, audit_store, req, "scim.user.role_changed", "failure", user_scim_id,
             "reason=group old_role=" + old_role_str + " intended_new_role=" + new_role_str +
                 via_detail);
        bump_role_change_failure(auth_mgr);
        return;
    }
    spdlog::info("SCIM: recompute_scim_user_role — '{}' (scim_id={}) role changed {} -> {} "
                "via group membership",
                resource->username, user_scim_id, old_role_str, new_role_str);
    // Set-and-proceed (UP-N2) — see `audit()`'s doc comment; the role change
    // above already committed.
    audit(auth_mgr, audit_store, req, "scim.user.role_changed", "success", user_scim_id,
         "reason=group old_role=" + old_role_str + " new_role=" + new_role_str + via_detail);
    bump_role_changed(auth_mgr);
}

/// ADR-2001 D2 detector: called once a deprovision has resolved its
/// principal set. When `resource`'s scim_id has NO linked OIDC identity AND
/// its externalId has a recorded login observation, a user DID authenticate
/// via OIDC but the link never formed — surface the CC6.8 false-green
/// tripwire. `scim_store`/`auth_mgr` may be null (defense in depth, matching
/// every other helper on this surface); a no-op then.
///
/// Governance fix (PR4a CHANGES_REQUESTED, C2): this used to gate on the
/// resolved principal-set SIZE (`principals.size() != 1`) as a proxy for
/// "no OIDC link exists". Once the resolver started appending SAML
/// principals into that same vector, a user with a coexisting SAML link
/// AND an unformed OIDC link — the exact D2 misconfiguration this detector
/// exists to catch — pushed `principals.size()` to 2+, so the proxy read
/// "has a link" and D2 silently never fired. Query the OIDC link count
/// SPECIFICALLY instead, independent of any SAML link on the same scim_id.
/// A store blip on the OIDC read (`nullopt`) is "cannot confirm", not "no
/// link" — D2 is best-effort and never gates access, so it must not fire a
/// false tripwire off an unanswerable read; it silently skips instead,
/// exactly as the OIDC-only code did on any other unanswerable read on this
/// surface.
void maybe_flag_d2_unlinked(ScimStore* scim_store, auth::AuthManager* auth_mgr,
                            const ScimResource& resource) {
    if (!scim_store || resource.external_id.empty())
        return;
    auto oidc_links = scim_store->links_for_scim_id(resource.scim_id);
    if (!oidc_links.has_value()) {
        spdlog::warn("ScimRoutes: D2 — links_for_scim_id lookup failed for scim_id={} (store "
                    "blip); skipping the unlinked-OIDC tripwire check rather than risk a false "
                    "positive off an unconfirmed read",
                    resource.scim_id);
        return;
    }
    if (!oidc_links->empty())
        return; // an OIDC link IS formed for this scim_id — nothing to flag
    if (!scim_store->observation_matches(resource.external_id))
        return;
    spdlog::warn("ScimRoutes: deprovision of '{}' (scim_id={}) found a login observation "
                "matching externalId '{}' but no formed identity_link — possible "
                "--oidc-scim-link-claim misconfiguration",
                resource.username, resource.scim_id, resource.external_id);
    bump_deprovision_unlinked(auth_mgr);
}

/// ADR-2001 #3072 — SAML analogue of `maybe_flag_d2_unlinked` above. Fires
/// the SAML D2 tripwire when `resource`'s scim_id has NO linked SAML
/// identity AND a recorded SAML login observation shows a NameID matching
/// its externalId. MUST query `saml_links_for_scim_id` SPECIFICALLY — never
/// `links_for_scim_id` (OIDC) or a `principals.size()` proxy — mirroring the
/// PR4a C2 lesson `maybe_flag_d2_unlinked` already learned: an OIDC link
/// coexisting on the same scim_id must never mask a missing SAML link, and
/// vice-versa. `scim_store`/`auth_mgr` may be null (defense in depth,
/// matching every other helper on this surface); a no-op then.
void maybe_flag_saml_d2_unlinked(ScimStore* scim_store, auth::AuthManager* auth_mgr,
                                 const ScimResource& resource) {
    if (!scim_store || resource.external_id.empty())
        return;
    auto saml_links = scim_store->saml_links_for_scim_id(resource.scim_id);
    // NOTE: via the deprovision route this nullopt branch is currently unreachable —
    // resolve_deprovision_principals reads saml_links_for_scim_id first and fails the
    // request closed (500) before this D2 check runs. It is retained as defense-in-depth
    // so a future reordering (or a caller that reaches D2 without that pre-read) still
    // fails safe rather than firing a false-positive off an unconfirmed read. The
    // saml_observation_matches nullopt-skip below IS route-reachable and is tested.
    if (!saml_links.has_value()) {
        spdlog::warn("ScimRoutes: SAML D2 — saml_links_for_scim_id lookup failed for "
                    "scim_id={} (store blip); skipping the unlinked-SAML tripwire check "
                    "rather than risk a false positive off an unconfirmed read",
                    resource.scim_id);
        return;
    }
    if (!saml_links->empty())
        return; // a SAML link IS formed for this scim_id — nothing to flag
    auto observed = scim_store->saml_observation_matches(resource.external_id);
    if (!observed.has_value() || !*observed)
        return; // nullopt (store blip) or a genuine no-match — skip either way
    spdlog::warn("ScimRoutes: deprovision of '{}' (scim_id={}) found a SAML login observation "
                "matching externalId '{}' but no formed saml_identity_link — the user "
                "authenticated via SAML but the identity was never linked",
                resource.username, resource.scim_id, resource.external_id);
    bump_deprovision_saml_unlinked(auth_mgr);
}

/// ADR-2001 §§1,3 — resolve the deprovision principal set for `resource` and
/// revoke credentials (tokens then sessions, per principal) across it,
/// credentials-FIRST, before the caller proceeds to mark the account
/// inactive/deleted. Shared by `deactivate()` (PATCH/PUT active:false) and
/// the DELETE handler's own active-branch inline flow (which cannot reuse
/// `deactivate()` wholesale — it persists a row DELETE, not a
/// `set_active(false)` mirror). Also runs the D2 detector once the
/// principal set is known.
///
/// Returns false (and has already sent a response + audited `audit_action`
/// as "failure"/"partial") on identity-link resolution failure, a missing/
/// closed `token_store`, or a non-persisted token revoke — the caller MUST
/// NOT proceed to `remove_user`/mark-inactive in any of those cases
/// (ADR-2001 §3 fail-closed-on-non-persist). On success, returns true and
/// writes the revoked counts into `detail_out` (folded into the caller's own
/// success audit's detail string, mirroring `/me`'s
/// `api_tokens_revoked=N`/`sessions_revoked=N` pattern).
bool revoke_linked_credentials_or_fail(ScimStore* scim_store, ApiTokenStore* token_store,
                                       auth::AuthManager* auth_mgr, AuditStore* audit_store,
                                       const httplib::Request& req, httplib::Response& res,
                                       const ScimResource& resource,
                                       const std::string& audit_action, std::string& detail_out) {
    auto principals =
        resolve_deprovision_principals(*scim_store, resource.scim_id, resource.username);
    if (!principals.has_value()) {
        // FAIL CLOSED (ADR-2001 §1): the link population is UNKNOWN, never
        // treated as "no links to revoke" — that is the exact silent-under-
        // revocation gap this ADR closes.
        spdlog::error("ScimRoutes: identity-link resolution failed for scim_id={} — refusing "
                     "to deprovision (a store blip must not read as \"no linked identities to "
                     "revoke\")",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to resolve linked identities");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             "identity_link_resolution_failed");
        return false;
    }
    maybe_flag_d2_unlinked(scim_store, auth_mgr, resource);
    maybe_flag_saml_d2_unlinked(scim_store, auth_mgr, resource);
    if (!token_store || !token_store->is_open()) {
        spdlog::error("ScimRoutes: ApiTokenStore unavailable — refusing to deprovision '{}' "
                     "(scim_id={}) without being able to revoke its credentials",
                     resource.username, resource.scim_id);
        send_scim_error(res, 503, "credential store unavailable");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             "api_token_store_unavailable");
        return false;
    }
    auto revoke_result = revoke_deprovision_credentials(*token_store, *auth_mgr, *principals);
    detail_out = "api_tokens_revoked=" + std::to_string(revoke_result.api_tokens_revoked) +
                " sessions_revoked=" + std::to_string(revoke_result.sessions_revoked) +
                " principals=" + std::to_string(principals->size()) +
                // Governance Gate 7 SHOULD fix (UP-5): enumerate the actual
                // principal strings, not just the count, so the audit row is
                // self-contained CC6.8 evidence.
                enumerate_principals_for_audit(*principals);
    if (!revoke_result.api_tokens_persisted) {
        detail_out += " api_tokens_db_error=true";
        spdlog::error("ScimRoutes: revoke_for_principal did not persist for one or more "
                     "principals linked to '{}' (scim_id={}) — refusing to report a clean "
                     "deprovision (ADR-2001 §3 fail-closed)",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to revoke API tokens for one or more linked identities");
        audit(auth_mgr, audit_store, req, audit_action, "partial", resource.scim_id, detail_out);
        return false;
    }
    return true;
}

/// Deactivate the auth account backing `resource` (provenance- and role-
/// guarded) and mark the SCIM resource inactive. Shared by PATCH
/// active=false, PUT active=false, and DELETE. Returns false (and has
/// already sent a response) on provenance/role refusal, identity-link
/// resolution failure, a non-persisted credential revoke (ADR-2001 §3), an
/// AuthManager failure, or a ScimStore mirror-write failure (M-ATOMICITY,
/// UP-5). A failed termination audit does NOT fail the call — see
/// `audit()`'s doc comment (set-and-proceed, CC6.8 enforced via the
/// failure-counter alert).
bool deactivate(ScimStore* scim_store, ApiTokenStore* token_store, auth::AuthManager* auth_mgr,
                AuditStore* audit_store, const httplib::Request& req, httplib::Response& res,
                const ScimResource& resource, const std::string& audit_action,
                EnginePrincipalStore* engine_principal_store = nullptr,
                AnalyticsEventStore* analytics_store = nullptr) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!deprovision_role_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id,
                             res)) {
        // ADR-2001 D1: deprovision_role_ok already sent 404 + audited
        // scim.user.provenance_denied — #2021's protection for a manually-
        // elevated account stands, and this deprovision is NOT auto-
        // revoking any linked federated identity. Leaving that silent would
        // hide that the termination is incomplete: make it LOUD whenever a
        // linked identity actually exists to be missed — an AuditStore row
        // (result="failure": the termination did NOT complete), the
        // role-refused-with-link counter, AND a Severity::kCritical
        // analytics event (the codebase's actual severity channel — see
        // emit_scim_critical_event's doc comment; AuditEvent itself has no
        // severity field, so "kCritical" is never a legal `result` value).
        // `links == nullopt` (the lookup itself failed) is treated as
        // "nothing to report" here — D1's signal is a best-effort ADD-ON
        // that never gates access, so a store blip skips only the extra
        // signal, not the underlying (already fail-closed) role refusal.
        if (scim_store) {
            auto links = federated_links_for_scim_id(*scim_store, resource.scim_id);
            if (links.has_link) {
                std::string detail = "role-refused deprovision has " +
                                     std::to_string(links.count) +
                                     " active linked federated identity(ies) (OIDC and/or "
                                     "SAML) that were NOT auto-revoked (ADR-2001 D1) — a "
                                     "human must terminate them manually";
                audit(auth_mgr, audit_store, req,
                     "scim.user.deprovision_role_refused_with_link", "failure", resource.scim_id,
                     detail);
                bump_deprovision_role_refused_with_link(auth_mgr);
                emit_scim_critical_event(analytics_store,
                                         "scim.user.deprovision_role_refused_with_link",
                                         {{"scim_id", resource.scim_id},
                                          {"linked_identity_count", links.count},
                                          {"detail", detail}});
            }
        }
        return false;
    }

    // ADR-2001 §§1,3 — credentials-FIRST revoke across the resolved
    // principal set (slug + every linked OIDC identity) BEFORE the account
    // is marked inactive. Reorders this function's former remove_user-first
    // sequence (safe: every op below is idempotent).
    std::string revoke_detail;
    if (!revoke_linked_credentials_or_fail(scim_store, token_store, auth_mgr, audit_store, req,
                                           res, resource, audit_action, revoke_detail))
        return false;

    if (!auth_mgr->remove_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::remove_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to deactivate the underlying account");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             revoke_detail);
        return false;
    }
    // M-ATOMICITY (UP-5): the AuthManager (AuthDB connection) write above
    // succeeded; now persist the SCIM-side mirror on ScimStore's SEPARATE
    // connection. If THIS write fails, the auth account is already
    // deactivated but the SCIM resource still reports active=true — fail
    // closed (500) so the IdP retries. The DB-level write inside
    // remove_user() is idempotent (its `UPDATE ... is_active = 0` re-applies
    // cleanly against an already-inactive row), and its bool *return value*
    // now agrees: AuthDB::remove_user's `RETURNING 1` matches on
    // `WHERE username = ?` alone, so it fires — and the return value reads
    // true — for any extant row regardless of `is_active`, i.e. idempotent-
    // true on a second call too, not "no-op success" vs. false. Retry safety
    // therefore does NOT rest on this return value distinguishing first vs.
    // repeat calls — it comes from the handler's re-fetch-and-skip at every
    // call site (`deactivate()` is only invoked when the freshly-fetched
    // `resource->active` is still true — see the PATCH/PUT/DELETE call
    // sites). The irreducible window between the two writes (a crash/kill
    // exactly between them) is a documented residual — reconciled by the
    // IdP's next full sync.
    if (!scim_store->set_active(resource.scim_id, false)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(false) failed for scim_id={} after the "
                     "underlying account was already deactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the deactivated state");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             "auth account deactivated but scim_resource mirror write failed; " + revoke_detail);
        return false;
    }
    // Set-and-proceed (UP-N2): the mutation above already committed — a lost
    // audit row does not change that, and a fail-closed 500 here cannot
    // re-land it (the IdP's retry would observe active=false and take the
    // non-termination branch, never re-attempting this audit write). CC6.8
    // evidence integrity is enforced by an alert on
    // `yuzu_scim_audit_write_failures_total` (bumped inside `audit()` on
    // every failure), not by refusing to report the 2xx that already
    // happened.
    audit(auth_mgr, audit_store, req, audit_action, "success", resource.scim_id, revoke_detail);
    // Detective control (PR 4.3, engine principals): the deprovision above
    // already committed — flag (never block) if the deprovisioned operator
    // owned active engine principals. See `flag_owner_deprovisioned`'s doc
    // comment.
    flag_owner_deprovisioned(engine_principal_store, auth_mgr, audit_store, req,
                             resource.username);
    return true;
}

/// Reactivate the auth account backing `resource` (provenance-guarded) and
/// mark the SCIM resource active again. Shared by PATCH active=true and PUT
/// active=true — the un-suspend counterpart of `deactivate`. The provenance
/// guard applies here too: reactivation is itself a mutation of the auth
/// account, so it must be refused (404) if the account isn't SCIM-owned —
/// same reasoning as deactivate/delete. Returns false (and has already sent
/// a response) on provenance refusal, an AuthManager failure, or a ScimStore
/// mirror-write failure (M-ATOMICITY). A failed termination-class audit does
/// NOT fail the call — see `audit()`'s doc comment (set-and-proceed, CC6.8
/// enforced via the failure-counter alert).
bool reactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->reactivate_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::reactivate_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to reactivate the underlying account");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id);
        return false;
    }
    if (!scim_store->set_active(resource.scim_id, true)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(true) failed for scim_id={} after the "
                     "underlying account was already reactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the reactivated state");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id,
             "auth account reactivated but scim_resource mirror write failed");
        return false;
    }
    // Set-and-proceed (UP-N2) — see the matching comment in `deactivate()`.
    audit(auth_mgr, audit_store, req, "scim.user.reactivated", "success", resource.scim_id);
    return true;
}

} // namespace

void ScimRoutes::register_routes(httplib::Server& svr, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store,
                                 std::string scim_admin_group,
                                 EnginePrincipalStore* engine_principal_store,
                                 ApiTokenStore* token_store,
                                 AnalyticsEventStore* analytics_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, scim_store, auth_mgr, audit_store, std::move(scim_admin_group),
                    engine_principal_store, token_store, analytics_store);
}

void ScimRoutes::register_routes(HttpRouteSink& sink, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store,
                                 std::string scim_admin_group,
                                 EnginePrincipalStore* engine_principal_store,
                                 ApiTokenStore* token_store,
                                 AnalyticsEventStore* analytics_store) {
    spdlog::info("SCIM routes: registering /scim/v2/* (provisioning surface)");

    // ── Discovery documents — PUBLIC-behind-the-bearer-gate (least exposure:
    // even the capability documents require the token, matching every other
    // /scim/v2/* route rather than carving out an unauthenticated exception). ──

    sink.Get("/scim/v2/ServiceProviderConfig",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::service_provider_config().dump(), kScimJson);
            });

    sink.Get("/scim/v2/ResourceTypes",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::resource_types().dump(), kScimJson);
            });

    sink.Get("/scim/v2/Schemas",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::schemas().dump(), kScimJson);
            });

    // ── POST /scim/v2/Users — provision. ──────────────────────────────────

    sink.Post("/scim/v2/Users", [scim_store, auth_mgr, audit_store, scim_admin_group,
                                 token_store](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
            record_request(auth_mgr, "create", res.status);
            return;
        }
        if (req.body.size() > kMaxBodyBytes) {
            send_scim_error(res, 413, "request body too large");
            record_request(auth_mgr, "create", 413);
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (const std::exception&) {
            send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }
        auto parsed = scim::parse_user(body);
        if (!parsed) {
            send_scim_error(res, parsed.error());
            record_request(auth_mgr, "create", parsed.error().status);
            return;
        }
        const auto& input = *parsed;
        if (!is_valid_username(input.user_name)) {
            send_scim_error(res, 400,
                           "userName is not a valid Yuzu username (1-64 chars, alnum/._-)",
                           "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }

        // Step 1 (unchanged): a LIVE scim_resource row means this identity
        // is provisioned RIGHT NOW — a re-POST for an already-provisioned
        // (active OR PATCH-deactivated-but-not-DELETEd) identity is a
        // protocol error; the IdP should PATCH/PUT instead.
        if (scim_store->get_by_username(input.user_name).has_value()) {
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists");
            record_request(auth_mgr, "create", 409);
            return;
        }

        // Step 2 (M-LIFECYCLE — revive-on-reprovision): no live scim_resource
        // row, so decide fresh-create vs. revive vs. refuse from
        // provisioning_source, read INCLUSIVE of inactive rows
        // (get_provisioning_source's contract) so a DELETE-then-re-POST
        // tombstone and a half-create orphan both read back "scim" here —
        // exactly the state a returning employee's account is in
        // (fixes UP-1/2/3's deadlock: previously DELETE removed the
        // scim_resource but ON CONFLICT DO NOTHING made re-provisioning via
        // POST permanently fail).
        // FIX-2 (Hermes LOW): auth_mgr is a raw pointer threaded through from
        // the server's wiring — every other handler on this surface derefs
        // it freely too, but provenance_ok() (below, indirectly reached from
        // PATCH/PUT/DELETE) guards it explicitly before calling
        // auth_db_ptr(). Match that posture here at this handler's first
        // direct deref, rather than trust a caller-supplied non-null.
        if (!auth_mgr) {
            spdlog::error("ScimRoutes: cannot provision '{}' — no AuthManager configured",
                         input.user_name);
            send_scim_error(res, 500, "SCIM provisioning is unavailable (no AuthManager configured)");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }
        AuthDB* db = auth_mgr->auth_db_ptr();
        if (!db) {
            spdlog::error("ScimRoutes: cannot provision '{}' — no AuthDB configured (SCIM "
                         "provisioning requires durable provenance tracking)",
                         input.user_name);
            send_scim_error(res, 500, "SCIM provisioning is unavailable (no AuthDB configured)");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }
        auto source_result = db->get_provisioning_source(input.user_name);
        if (source_result.has_value() && *source_result != kProvisioningSourceScim) {
            // A local (or otherwise-sourced) account already owns this
            // username — SCIM must never adopt it (S-UNIQUE-DBREAD: this DB
            // read also catches a SOFT-DELETED local account the in-memory
            // get_user_role cache would have missed).
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists (non-SCIM account)");
            record_request(auth_mgr, "create", 409);
            return;
        }

        // UP-N1 (FIX-1): tracks whether THIS call is the one that created the
        // auth row (the fresh-create branch below) vs. revived a pre-existing
        // one — gates the create_resource-failure rollback further down so a
        // concurrent revive's rollback can never deactivate a DIFFERENT
        // call's winning account.
        bool created_auth_row_this_call = false;

        if (source_result.has_value()) {
            // REVIVE: a tombstoned or half-created SCIM account this IdP
            // previously provisioned. Reactivate the EXISTING auth row —
            // never upsert_user again (that would UserAlreadyExists
            // pointlessly, and reactivate_user is the correct idempotent
            // primitive: it does not touch credentials/rotate the discard
            // password).
            if (!auth_mgr->reactivate_user(input.user_name)) {
                spdlog::error("ScimRoutes: reactivate_user failed reviving '{}'",
                             input.user_name);
                send_scim_error(res, 500, "failed to revive the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }

            // UP-N5 (FIX-5, defensive): reactivate_user() leaves `role`
            // untouched. If an operator elevated this account before it was
            // tombstoned, its role is still whatever they set it to —
            // SCIM's model owns only read-only 'user' accounts, so do not
            // resurrect an out-of-band-elevated account through the revive
            // path. Checked AFTER reactivate_user() (not before): the
            // tombstoned row is soft-deleted, so a plain cache read has no
            // entry for it until reactivate_user() loads it. Role is read
            // via `db_authoritative_role` (H2, consistency with
            // deprovision_role_ok) — the DB row, never the AuthManager
            // in-memory cache — and FAILS CLOSED (refuses) if the role
            // cannot be determined at all, not just when it resolves to
            // something other than 'user'. On refusal, undo the
            // reactivation (remove_user) so "refuse" actually means the
            // account stays down, not just that this response says 404.
            // Same posture as the deprovision role guard: 404 (never 403 —
            // no existence oracle), scim.user.provenance_denied.
            if (auto role = db_authoritative_role(auth_mgr, input.user_name);
                !role.has_value() || *role != auth::Role::user) {
                spdlog::warn("ScimRoutes: refusing to revive '{}' via POST — role is not "
                            "'user' (an operator elevated this account before it was "
                            "tombstoned)",
                            input.user_name);
                if (!auth_mgr->remove_user(input.user_name)) {
                    // remove_user() writes the DB first and returns false if
                    // that write failed (same contract as deactivate()'s
                    // check, above). Unchecked, a failure here would leave
                    // the account ACTIVE at its elevated role while this
                    // handler still claims 404 "resource not found" — and
                    // since 404 isn't retried by the IdP, the elevated
                    // account would stay reactivated indefinitely
                    // (privilege fail-open). Fail closed (500) instead so
                    // the IdP retries the whole POST.
                    spdlog::error("ScimRoutes: remove_user failed undoing the revive-role-"
                                 "refusal for '{}' — account remains ACTIVE at an elevated "
                                 "role",
                                 input.user_name);
                    send_scim_error(res, 500, "failed to revive the underlying account");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                         input.user_name,
                         "role-refusal undo (remove_user) failed — account left active at "
                         "an elevated role");
                    record_request(auth_mgr, "create", 500);
                    return;
                }
                send_scim_error(res, 404, "resource not found");
                audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied",
                     input.user_name, "role is not 'user' for username=" + input.user_name);
                bump_provenance_denied(auth_mgr);
                record_request(auth_mgr, "create", 404);
                return;
            }
        } else {
            // FRESH create (UP-9 duplicate-POST race handled below).
            // SCIM-provisioned accounts authenticate via the IdP/SSO only —
            // mint a long CSPRNG password and discard it immediately so
            // local password login is unusable (an unknowable password, not
            // a weak one). Always provisioned at the read-only 'user' role.
            std::vector<uint8_t> pw_bytes;
            try {
                pw_bytes = auth::AuthManager::random_bytes(32);
            } catch (const std::exception& e) {
                // S-RANDBYTES: random_bytes throws on a CSPRNG/RAND_bytes
                // failure — catch rather than let it unwind to a bare 500.
                spdlog::error(
                    "ScimRoutes: CSPRNG failure minting a discard password for '{}': {}",
                    input.user_name, e.what());
                send_scim_error(res, 503, "temporarily unable to provision (CSPRNG unavailable)");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 503);
                return;
            }
            auto discard_password = auth::AuthManager::bytes_to_hex(pw_bytes);
            if (!auth_mgr->upsert_user(input.user_name, discard_password, auth::Role::user)) {
                // UP-9: distinguish a genuine DB failure from a concurrent
                // duplicate POST that won the race between the uniqueness
                // check above and this write — re-read: if the account now
                // resolves, someone else just created it.
                if (auth_mgr->get_user_role(input.user_name).has_value()) {
                    send_scim_error(res, 409, "userName already exists", "uniqueness");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                         input.user_name, "userName already exists (concurrent create)");
                    record_request(auth_mgr, "create", 409);
                    return;
                }
                send_scim_error(res, 500, "failed to create the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
            created_auth_row_this_call = true;

            // S-IDENTITY-SRC: SCIM is its own login surface (IdP-driven SSO,
            // no usable local password) — distinct from the v6 'local'
            // default, which would render this account as local-login-
            // capable in the Settings UI. Best-effort: a failure here
            // doesn't block provisioning (the account still functions; only
            // the Settings UI badge would be wrong).
            if (auto r = db->set_identity_source(input.user_name, "scim"); !r) {
                spdlog::warn("ScimRoutes: set_identity_source failed for '{}' — the account "
                            "will still function, but the Settings UI may misrender its login "
                            "surface",
                            input.user_name);
            }

            // M-ORPHAN (UP-6/B1): set provenance BEFORE creating the
            // scim_resource row, and roll back the just-created auth account
            // if it fails — never leave an orphaned account with no SCIM
            // mapping AND no provenance marker (unmanageable by SCIM
            // forever after — a future revive attempt would read
            // provisioning_source=='local' and refuse it).
            if (auto r = db->set_provisioning_source(input.user_name,
                                                     std::string(kProvisioningSourceScim));
                !r) {
                spdlog::error("ScimRoutes: set_provisioning_source failed for '{}', rolling back",
                             input.user_name);
                auth_mgr->remove_user(input.user_name);
                send_scim_error(res, 500, "failed to record provisioning provenance");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
        }

        auto resource = scim_store->create_resource(input.user_name, input.external_id);
        if (!resource) {
            // UP-N1 (FIX-1): create_resource() returns nullopt on a
            // UNIQUE(username) conflict OR a genuine CSPRNG/db failure — the
            // two demand opposite responses, so distinguish them by
            // re-reading. If a live scim_resource mapping now exists, a
            // CONCURRENT re-POST for the same identity already won the race
            // between Step 1's uniqueness check and this write and has
            // already created/revived its own account — that is the winner;
            // touch nothing here (in particular, do NOT remove_user, which
            // would silently deactivate the winner's freshly-provisioned
            // account: 201 to them, no error, no retry, but is_active=0).
            if (scim_store->get_by_username(input.user_name).has_value()) {
                send_scim_error(res, 409, "userName already exists", "uniqueness");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                     input.user_name, "userName already exists (concurrent revive/create)");
                record_request(auth_mgr, "create", 409);
                return;
            }
            // Governance Gate 7 SHOULD fix (UP-1): a NEW userName carrying an
            // externalId already held by a DIFFERENT (typically inactive)
            // row hits `scim_resources_external_id_uniq` the same way the
            // concurrent-revive race above does, but for a distinct reason —
            // distinguish it with its own 409 rather than falling through to
            // the opaque 500 below. `find_by_external_id` is the plain
            // (not-active-filtered) lookup: an inactive row still legitimately
            // holds the externalId. Same M-ORPHAN rollback rule as the 500
            // branch just below applies here too — this IS a genuine create
            // failure, just a distinguishable one.
            if (!input.external_id.empty()) {
                if (auto colliding = scim_store->find_by_external_id(input.external_id);
                    colliding.has_value() && colliding->username != input.user_name) {
                    if (created_auth_row_this_call)
                        auth_mgr->remove_user(input.user_name);
                    send_scim_error(res, 409, "externalId already mapped to another resource",
                                    "uniqueness");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                         input.user_name,
                         "externalId already mapped to scim_id=" + colliding->scim_id);
                    record_request(auth_mgr, "create", 409);
                    return;
                }
            }
            // No mapping — a genuine create failure. Roll back to a
            // deactivated tombstone ONLY if THIS call created the auth row
            // (the fresh-create branch): the next POST for the same
            // userName retries this exact step (provisioning_source ==
            // "scim" still holds). In the REVIVE branch the account
            // pre-existed before this call — do NOT remove_user; leave the
            // just-reactivated row as-is so the IdP's retry re-enters the
            // revive branch above and adopts it (rolling it back here would
            // just re-tombstone an account the retry has to re-revive for no
            // benefit, and risks racing a DIFFERENT concurrent caller that
            // is also reviving the same identity).
            if (created_auth_row_this_call)
                auth_mgr->remove_user(input.user_name);
            send_scim_error(res, 500, "failed to create the SCIM resource mapping");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                 input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }

        // #2021 (Groups->role, trigger (d)): a fresh-create is always
        // provisioned at 'user' (see the fresh-create branch above) so this
        // is a no-op there, but the REVIVE branch can hand back an account
        // that is already referenced by an existing Group's membership (the
        // IdP re-adds a member by the scim_id it learns from THIS response,
        // and — defensively — in case any stale membership already points
        // at this identity) — recompute now so the freshly (re)provisioned
        // account's role reflects group membership immediately, not only
        // after the next Group mutation.
        recompute_scim_user_role(scim_store, auth_mgr, audit_store, req, resource->scim_id,
                                 scim_admin_group, "user_provision");

        // Honour an explicit active:false on create (some IdPs stage a user
        // deactivated) by immediately deactivating the account we just
        // made/revived.
        std::string revoke_detail;
        if (input.active.has_value() && !*input.active) {
            // ADR-2001 §§1,3 — credentials-FIRST revoke, same as every other
            // deprovision seam. `create_resource` (just above) always mints
            // a fresh CSPRNG scim_id — even on the REVIVE branch (a prior
            // DELETE hard-removes the old scim_resource row) — so
            // resolve_deprovision_principals resolves to the slug alone
            // here in practice (no identity_links row can yet reference a
            // scim_id that didn't exist until this request). Still routed
            // through the shared resolver/orchestrator rather than a bare
            // remove_user(), both for uniformity with the other three
            // deprovision seams and because SCIM-provisioned accounts are
            // SSO-only in name only — nothing stops a slug-keyed API token
            // from existing (e.g. minted directly against the username by
            // an operator), and this is the credentials-first ordering
            // that must revoke it before the account goes inactive.
            if (!revoke_linked_credentials_or_fail(scim_store, token_store, auth_mgr, audit_store,
                                                   req, res, *resource, "scim.user.provisioned",
                                                   revoke_detail)) {
                record_request(auth_mgr, "create", res.status);
                return;
            }
            if (!auth_mgr->remove_user(input.user_name)) {
                // FIX-1 (Hermes MEDIUM, fail-open): previously this branch
                // only logged and fell through to set_active(false) below,
                // so a failed deactivation still shipped a 201 with
                // active:false while the underlying auth account stayed
                // LIVE — the IdP believes the user is deactivated when it
                // is not. Fail closed (500) and stop here, mirroring
                // deactivate()'s remove_user-failure branch above.
                spdlog::error("ScimRoutes: remove_user failed honouring active:false on create "
                             "for '{}' — the account remains active",
                             input.user_name);
                send_scim_error(res, 500, "failed to deactivate the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name,
                     "active:false on create — remove_user failed, account left active");
                record_request(auth_mgr, "create", 500);
                return;
            }
            // UP-N3 (FIX-3): check the ScimStore mirror write — previously
            // unchecked, so a failure here silently shipped a 201 body
            // claiming active:true while the underlying account was already
            // deactivated. Fail closed (500); the IdP retries the whole
            // POST, which now sees the live mapping at Step 1 (409) or, if
            // the account genuinely ends up torn down first, the revive
            // path — either way the retry reconciles it.
            if (!scim_store->set_active(resource->scim_id, false)) {
                spdlog::error("ScimRoutes: ScimStore::set_active(false) failed honouring "
                             "active:false on create for scim_id={} — inconsistent state, "
                             "failing closed so the IdP retries",
                             resource->scim_id);
                send_scim_error(res, 500, "failed to persist the deactivated state");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
            // S-POST-REFETCH: re-fetch so the 201 body's ETag/meta.version/
            // lastModified reflect the bump set_active just made — PUT/PATCH
            // already re-fetch after their own mutations; mirror that here
            // so a later GET can't disagree with what this response claimed.
            if (auto refreshed = scim_store->get_by_scim_id(resource->scim_id))
                resource = refreshed;
            else
                resource->active = false; // M-OPTDEREF fallback — shouldn't happen
        }

        auto base = location_base(req);
        res.status = 201;
        res.set_header("Location", base + "/" + resource->scim_id);
        res.set_header("ETag", "W/\"" + std::to_string(resource->etag_version) + "\"");
        res.set_content(scim::user_to_json(*resource, base).dump(), kScimJson);
        // set-and-proceed (every SCIM audit call is, per `audit()`'s doc
        // comment) — the 201 above already committed regardless of whether
        // this row persists. `revoke_detail` is empty unless the
        // active:false branch above ran a credential revoke.
        audit(auth_mgr, audit_store, req, "scim.user.provisioned", "success", resource->scim_id,
             revoke_detail);
        record_request(auth_mgr, "create", 201);
    });

    // ── GET /scim/v2/Users/{id} ────────────────────────────────────────────

    sink.Get(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "get", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "get", 404);
                    return;
                }
                res.set_content(scim::user_to_json(*resource, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "get", 200);
            });

    // ── GET /scim/v2/Users — list / filter. ───────────────────────────────

    sink.Get("/scim/v2/Users",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "list", res.status);
                    return;
                }
                auto base = location_base(req);

                int start_index = 1;
                if (req.has_param("startIndex")) {
                    auto parsed =
                        parse_scim_int_param(res, req.get_param_value("startIndex"), "startIndex");
                    if (!parsed) {
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                    start_index = *parsed;
                    // SCIM startIndex is 1-based (RFC 7644 §3.4.2); clamp
                    // anything below 1 up to the first page rather than
                    // echoing a negative/zero value back in the response.
                    if (start_index < 1)
                        start_index = 1;
                }
                int count = 100;
                if (req.has_param("count")) {
                    auto parsed = parse_scim_int_param(res, req.get_param_value("count"), "count");
                    if (!parsed) {
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                    count = *parsed;
                }
                // S-CLAMP-COUNT: never serve more than the maxResults this
                // server advertises in ServiceProviderConfig, regardless of
                // what the caller asks for.
                if (count > scim::kMaxScimListResults)
                    count = scim::kMaxScimListResults;

                if (req.has_param("filter")) {
                    auto filter_username = scim::parse_username_filter(req.get_param_value("filter"));
                    if (!filter_username) {
                        send_scim_error(res, filter_username.error());
                        record_request(auth_mgr, "list", filter_username.error().status);
                        return;
                    }
                    std::vector<json> resources;
                    int total = 0;
                    if (auto resource = scim_store->get_by_username(*filter_username)) {
                        resources.push_back(scim::user_to_json(*resource, base));
                        total = 1;
                    }
                    res.set_content(
                        scim::list_response(resources, total, 1,
                                           static_cast<int>(resources.size()))
                            .dump(),
                        kScimJson);
                    record_request(auth_mgr, "list", 200);
                    return;
                }

                int total = 0;
                auto page = scim_store->list(start_index, count, total);
                std::vector<json> resources;
                resources.reserve(page.size());
                for (const auto& r : page)
                    resources.push_back(scim::user_to_json(r, base));
                res.set_content(scim::list_response(resources, total, start_index,
                                                    static_cast<int>(resources.size()))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "list", 200);
            });

    // ── PUT /scim/v2/Users/{id} — full replace (identity fields only). ────

    sink.Put(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store, engine_principal_store, token_store,
             analytics_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "replace", 404);
                    return;
                }
                if (req.body.size() > kMaxBodyBytes) {
                    send_scim_error(res, 413, "request body too large");
                    record_request(auth_mgr, "replace", 413);
                    return;
                }
                json body;
                try {
                    body = json::parse(req.body);
                } catch (const std::exception&) {
                    send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }
                auto parsed = scim::parse_user(body);
                if (!parsed) {
                    send_scim_error(res, parsed.error());
                    record_request(auth_mgr, "replace", parsed.error().status);
                    return;
                }
                const auto& input = *parsed;

                // Rename is out of scope for slice 1 (the SCIM `id`, not
                // `userName`, is the stable identifier IdPs are expected to
                // key on going forward) — refuse rather than silently
                // ignoring the IdP's intent.
                if (input.user_name != resource->username) {
                    send_scim_error(res, 400,
                                   "userName change via PUT is not supported in this slice",
                                   "mutability");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }

                bool active_transitioned = false;
                if (input.active.has_value() && !*input.active && resource->active) {
                    if (!deactivate(scim_store, token_store, auth_mgr, audit_store, req, res,
                                    *resource, "scim.user.deactivated", engine_principal_store,
                                    analytics_store)) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = false;
                    active_transitioned = true;
                } else if (input.active.has_value() && *input.active && !resource->active) {
                    if (!reactivate(scim_store, auth_mgr, audit_store, req, res, *resource)) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = true;
                    active_transitioned = true;
                } else if (input.active.has_value() && !*input.active && !resource->active) {
                    // FIX (MEDIUM-1, CC6.8 deprovision desync): the
                    // scim_resource mirror already reads inactive, but do
                    // not trust it blindly before taking the no-op
                    // short-circuit — a prior mirror-write failure (see
                    // deactivate()'s M-ATOMICITY comment) or an
                    // out-of-band reactivation could leave the underlying
                    // auth account genuinely LIVE while SCIM/the IdP
                    // believes it is already deprovisioned. Check the real
                    // auth state; only take the no-op when it is ALSO
                    // genuinely inactive.
                    if (auth_mgr->get_user_role(resource->username).has_value()) {
                        spdlog::warn(
                            "ScimRoutes: PUT active:false — scim_resource mirror for '{}' "
                            "(scim_id={}) says inactive but the auth account is still live; "
                            "re-running deactivation",
                            resource->username, resource->scim_id);
                        if (!deactivate(scim_store, token_store, auth_mgr, audit_store, req, res,
                                        *resource, "scim.user.deactivated", engine_principal_store,
                                        analytics_store)) {
                            record_request(auth_mgr, "replace", res.status);
                            return;
                        }
                        resource->active = false;
                        active_transitioned = true;
                    }
                    // else: genuinely already inactive — true no-op, no audit.
                }

                // L3 (2026-07-08 review): externalId-only mutation. The
                // active-transition branches above already re-verify both
                // guards via deactivate()/reactivate(), but a PUT that
                // leaves `active` unset/unchanged (or already reads false)
                // reaches this write with NO guard check at all — re-verify
                // provenance immediately before the mutating call so every
                // mutation on this surface, including an externalId-only
                // one, re-checks it (matches the doc's "every mutation
                // re-verifies" claim). The role check is gated on
                // `resource->active` (the CURRENT, post-transition state) —
                // same posture as the DELETE handler's already-inactive
                // branch: once the account is inactive there is nothing
                // further being torn down for the role guard to protect,
                // and `deprovision_role_ok` would otherwise fail closed on
                // every inactive-but-legitimately-SCIM-owned account (its
                // DB-authoritative read only resolves an ACTIVE row).
                if (!provenance_ok(auth_mgr, audit_store, req, resource->username,
                                   resource->scim_id, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                if (resource->active &&
                    !deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                         resource->scim_id, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                 input.external_id)) {
                    send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                auto updated = scim_store->get_by_scim_id(resource->scim_id);
                if (!updated) {
                    // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                    // resource between the mutation above and this
                    // re-fetch. The mutation already committed — 500 (not
                    // 404, which would misleadingly imply "never existed").
                    spdlog::error("ScimRoutes: PUT — resource scim_id={} vanished mid-request",
                                 resource->scim_id);
                    send_scim_error(res, 500, "resource state changed mid-request");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                if (!active_transitioned) {
                    // deactivate()/reactivate() already audited their own
                    // action (and already fail closed on their own audit
                    // failure); avoid a duplicate "updated" row for that
                    // case. "updated" itself is NOT a termination action —
                    // set-and-proceed.
                    audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                         resource->scim_id);
                }
                res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "replace", 200);
            });

    // ── PATCH /scim/v2/Users/{id} — the critical deprovision path. ────────

    sink.Patch(R"(/scim/v2/Users/([0-9a-fA-F]+))",
              [scim_store, auth_mgr, audit_store, engine_principal_store, token_store,
               analytics_store](const httplib::Request& req,
                                                  httplib::Response& res) {
                  if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                      record_request(auth_mgr, "patch", res.status);
                      return;
                  }
                  auto id = req.matches[1].str();
                  auto resource = scim_store->get_by_scim_id(id);
                  if (!resource) {
                      send_scim_error(res, 404, "resource not found");
                      record_request(auth_mgr, "patch", 404);
                      return;
                  }
                  if (req.body.size() > kMaxBodyBytes) {
                      send_scim_error(res, 413, "request body too large");
                      record_request(auth_mgr, "patch", 413);
                      return;
                  }
                  json body;
                  try {
                      body = json::parse(req.body);
                  } catch (const std::exception&) {
                      send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }
                  auto parsed = scim::parse_patch(body);
                  if (!parsed) {
                      send_scim_error(res, parsed.error());
                      record_request(auth_mgr, "patch", parsed.error().status);
                      return;
                  }
                  const auto& patch = *parsed;

                  // Validate the unsupported-mutation case BEFORE applying
                  // anything else, so a body combining an unsupported
                  // userName change with a supported active/externalId
                  // change can't leave a partial mutation committed behind
                  // a 400 response.
                  if (patch.user_name.has_value() && *patch.user_name != resource->username) {
                      send_scim_error(res, 400,
                                     "userName change via PATCH is not supported in this slice",
                                     "mutability");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }

                  bool active_transitioned = false;
                  if (patch.active.has_value()) {
                      if (!*patch.active && resource->active) {
                          if (!deactivate(scim_store, token_store, auth_mgr, audit_store, req,
                                          res, *resource, "scim.user.deactivated",
                                          engine_principal_store, analytics_store)) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = false;
                          active_transitioned = true;
                      } else if (*patch.active && !resource->active) {
                          if (!reactivate(scim_store, auth_mgr, audit_store, req, res,
                                         *resource)) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = true;
                          active_transitioned = true;
                      } else if (!*patch.active && !resource->active) {
                          // FIX (MEDIUM-1, CC6.8 deprovision desync): same
                          // reasoning as the PUT active:false no-op branch
                          // — verify the real auth state before trusting
                          // the mirror's "already inactive" and short-
                          // circuiting to a no-op.
                          if (auth_mgr->get_user_role(resource->username).has_value()) {
                              spdlog::warn(
                                  "ScimRoutes: PATCH active:false — scim_resource mirror for "
                                  "'{}' (scim_id={}) says inactive but the auth account is "
                                  "still live; re-running deactivation",
                                  resource->username, resource->scim_id);
                              if (!deactivate(scim_store, token_store, auth_mgr, audit_store, req,
                                              res, *resource, "scim.user.deactivated",
                                              engine_principal_store, analytics_store)) {
                                  record_request(auth_mgr, "patch", res.status);
                                  return;
                              }
                              resource->active = false;
                              active_transitioned = true;
                          }
                          // else: genuinely already inactive — true no-op, no audit.
                      }
                      // else: no-op (active:true already reads active — no
                      // desync risk on the reactivate path).
                  }

                  if (patch.external_id.has_value()) {
                      // L3 (2026-07-08 review): same reasoning as the PUT
                      // externalId-update path above — a PATCH carrying
                      // only `externalId` (no `active` op) reached this
                      // write with no guard check at all. Role check gated
                      // on the CURRENT `resource->active`: matches the
                      // DELETE handler's already-inactive posture (nothing
                      // further being torn down once inactive, and
                      // `deprovision_role_ok` only resolves an ACTIVE row).
                      if (!provenance_ok(auth_mgr, audit_store, req, resource->username,
                                        resource->scim_id, res)) {
                          record_request(auth_mgr, "patch", res.status);
                          return;
                      }
                      if (resource->active &&
                          !deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                              resource->scim_id, res)) {
                          record_request(auth_mgr, "patch", res.status);
                          return;
                      }
                      if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                       *patch.external_id)) {
                          send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                          record_request(auth_mgr, "patch", 500);
                          return;
                      }
                  }

                  auto updated = scim_store->get_by_scim_id(resource->scim_id);
                  if (!updated) {
                      // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                      // resource between the mutation above and this
                      // re-fetch.
                      spdlog::error("ScimRoutes: PATCH — resource scim_id={} vanished "
                                   "mid-request",
                                   resource->scim_id);
                      send_scim_error(res, 500, "resource state changed mid-request");
                      record_request(auth_mgr, "patch", 500);
                      return;
                  }
                  if (!active_transitioned) {
                      // deactivate()/reactivate() already audited their own
                      // action; avoid a duplicate "updated" row for that
                      // case.
                      audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                           resource->scim_id);
                  }
                  res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                                 kScimJson);
                  record_request(auth_mgr, "patch", 200);
              });

    // ── DELETE /scim/v2/Users/{id} ─────────────────────────────────────────

    sink.Delete(R"(/scim/v2/Users/([0-9a-fA-F]+))",
               [scim_store, auth_mgr, audit_store, engine_principal_store, token_store,
                analytics_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                       record_request(auth_mgr, "delete", res.status);
                       return;
                   }
                   auto id = req.matches[1].str();
                   auto resource = scim_store->get_by_scim_id(id);
                   if (!resource) {
                       send_scim_error(res, 404, "resource not found");
                       record_request(auth_mgr, "delete", 404);
                       return;
                   }
                   std::string revoke_detail;
                   if (resource->active) {
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                               id, res)) {
                           // ADR-2001 D1 — same loud-refusal signal as
                           // deactivate()'s doc comment: deprovision_role_ok
                           // already sent 404 + audited
                           // scim.user.provenance_denied; make it LOUD if a
                           // linked federated identity exists to be missed
                           // (AuditStore result="failure" + the counter +
                           // a Severity::kCritical analytics event — see
                           // emit_scim_critical_event's doc comment for why
                           // severity cannot live on the AuditEvent itself).
                           auto links = federated_links_for_scim_id(*scim_store, id);
                           if (links.has_link) {
                               std::string detail =
                                   "role-refused deprovision has " +
                                   std::to_string(links.count) +
                                   " active linked federated identity(ies) (OIDC and/or "
                                   "SAML) that were NOT auto-revoked (ADR-2001 D1) — a human "
                                   "must terminate them manually";
                               audit(auth_mgr, audit_store, req,
                                    "scim.user.deprovision_role_refused_with_link", "failure", id,
                                    detail);
                               bump_deprovision_role_refused_with_link(auth_mgr);
                               emit_scim_critical_event(
                                   analytics_store, "scim.user.deprovision_role_refused_with_link",
                                   {{"scim_id", id},
                                    {"linked_identity_count", links.count},
                                    {"detail", detail}});
                           }
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       // ADR-2001 §§1,3 — credentials-FIRST revoke across the
                       // resolved principal set BEFORE remove_user/delete
                       // below. Never reuse deactivate() here — this handler
                       // persists a row DELETE, not a set_active(false)
                       // mirror, so it shares the resolve+revoke helper only.
                       if (!revoke_linked_credentials_or_fail(scim_store, token_store, auth_mgr,
                                                              audit_store, req, res, *resource,
                                                              "scim.user.deleted",
                                                              revoke_detail)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!auth_mgr->remove_user(resource->username)) {
                           send_scim_error(res, 500, "failed to deactivate the underlying account");
                           audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id,
                                revoke_detail);
                           record_request(auth_mgr, "delete", 500);
                           return;
                       }
                   } else {
                       // Already deactivated — still re-verify provenance
                       // before the DELETE removes the mapping row, so a
                       // scim_resource somehow pointing at a non-SCIM
                       // account still can't be wiped out from under it. No
                       // role re-check here: the account is already
                       // inactive, so there is nothing further being torn
                       // down (see deprovision_role_ok's doc comment — the
                       // in-memory role cache has no entry to check anyway).
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                   }

                   // M-ATOMICITY (UP-5): check the ScimStore write too. On
                   // the resource->active branch above, the AuthManager
                   // write already succeeded — a failure here leaves the
                   // account deactivated but the mapping row still present.
                   // delete_by_scim_id's tri-state return distinguishes a
                   // real DB error (nullopt — fail closed below so the IdP
                   // retries) from "the mapping row is already gone" (false
                   // — a concurrent/duplicate DELETE beat us to it; UP-N4/
                   // FIX-4: that is idempotent SUCCESS, not a failure — the
                   // account is deleted either way). Retry safety for the
                   // resource->active branch above comes from the handler's
                   // own re-fetch-and-skip (a retry sees resource->active ==
                   // false and takes the already-deactivated branch instead
                   // of re-calling remove_user), not from remove_user()
                   // itself being a true no-op — see deactivate()'s
                   // M-ATOMICITY comment for why that distinction matters.
                   auto delete_result = scim_store->delete_by_scim_id(id);
                   if (!delete_result.has_value()) {
                       spdlog::error("ScimRoutes: ScimStore::delete_by_scim_id failed for "
                                    "scim_id={}",
                                    id);
                       send_scim_error(res, 500, "failed to remove the SCIM resource mapping");
                       audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id);
                       record_request(auth_mgr, "delete", 500);
                       return;
                   }
                   if (!*delete_result) {
                       spdlog::info("ScimRoutes: DELETE scim_id={} — mapping row already gone "
                                   "(concurrent/duplicate DELETE); treating as idempotent "
                                   "success",
                                   id);
                   }
                   // Set-and-proceed (UP-N2) — see the matching comment in
                   // `deactivate()`. `revoke_detail` is empty for the
                   // already-inactive branch (no fresh revoke ran there).
                   audit(auth_mgr, audit_store, req, "scim.user.deleted", "success", id,
                        revoke_detail);
                   // Detective control (PR 4.3, engine principals): flag
                   // (never block) if the deprovisioned operator owned
                   // active engine principals — see
                   // `flag_owner_deprovisioned`'s doc comment.
                   flag_owner_deprovisioned(engine_principal_store, auth_mgr, audit_store, req,
                                            resource->username);
                   res.status = 204;
                   record_request(auth_mgr, "delete", 204);
               });

    // ── SCIM v2 Groups (#2021, slice 2) ───────────────────────────────────
    //
    // Every mutation below that can change a user's group membership calls
    // `recompute_scim_user_role` for every AFFECTED member (added AND
    // removed) once its own ScimStore write has committed — see that
    // function's doc comment for the provenance guard it enforces
    // independently of this route's own checks.

    // ── POST /scim/v2/Groups — create. ────────────────────────────────────

    sink.Post("/scim/v2/Groups", [scim_store, auth_mgr, audit_store,
                                  scim_admin_group](const httplib::Request& req,
                                                    httplib::Response& res) {
        if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
            record_request(auth_mgr, "group_create", res.status);
            return;
        }
        if (req.body.size() > kMaxBodyBytes) {
            send_scim_error(res, 413, "request body too large");
            record_request(auth_mgr, "group_create", 413);
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (const std::exception&) {
            send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
            record_request(auth_mgr, "group_create", 400);
            return;
        }
        auto parsed = scim::parse_group(body);
        if (!parsed) {
            send_scim_error(res, parsed.error());
            record_request(auth_mgr, "group_create", parsed.error().status);
            return;
        }
        const auto& input = *parsed;

        // #7 (sre capacity): bound the member count before doing any further
        // work — see kMaxGroupMembers's doc comment.
        if (input.member_values.size() > kMaxGroupMembers) {
            send_scim_error(res, 400, "members exceeds the maximum group size", "invalidValue");
            audit(auth_mgr, audit_store, req, "scim.group.created", "denied", "",
                 "member count exceeds cap", "Group");
            record_request(auth_mgr, "group_create", 400);
            return;
        }

        // Idempotent-create on displayName — no DB-level UNIQUE (ScimStore's
        // doc comment on get_group_by_display_name); the routes layer owns
        // the 409.
        if (scim_store->get_group_by_display_name(input.display_name).has_value()) {
            send_scim_error(res, 409, "displayName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.group.created", "denied", "",
                 "displayName already exists: " + input.display_name, "Group");
            record_request(auth_mgr, "group_create", 409);
            return;
        }

        auto group = scim_store->create_group(input.display_name, input.external_id);
        if (!group) {
            send_scim_error(res, 500, "failed to create the SCIM group");
            audit(auth_mgr, audit_store, req, "scim.group.created", "failure", "",
                 input.display_name, "Group");
            record_request(auth_mgr, "group_create", 500);
            return;
        }

        auto members_resolved = resolve_member_values(scim_store, input.member_values);
        if (!members_resolved.has_value()) {
            // Could not resolve every member — persisting the partial set
            // would silently drop real members from a brand-new group.
            send_scim_error(res, 503, "membership unavailable");
            audit(auth_mgr, audit_store, req, "scim.group.created", "failure", group->scim_id,
                 "member resolution unavailable", "Group");
            record_request(auth_mgr, "group_create", 503);
            return;
        }
        const std::vector<std::string>& members = *members_resolved;
        if (!members.empty() && !scim_store->set_group_members(group->scim_id, members)) {
            spdlog::error("ScimRoutes: set_group_members failed for group scim_id={}",
                         group->scim_id);
            send_scim_error(res, 500, "failed to persist group membership");
            audit(auth_mgr, audit_store, req, "scim.group.created", "failure", group->scim_id, {},
                 "Group");
            record_request(auth_mgr, "group_create", 500);
            return;
        }

        // #2021 trigger (a): recompute role for every member on create.
        for (const auto& uid : members)
            recompute_scim_user_role(scim_store, auth_mgr, audit_store, req, uid,
                                     scim_admin_group,
                                     input.display_name + " op=group_create");

        auto gbase = groups_location_base(req);
        auto ubase = location_base(req);
        res.status = 201;
        res.set_header("Location", gbase + "/" + group->scim_id);
        res.set_header("ETag", "W/\"" + std::to_string(group->etag_version) + "\"");
        res.set_content(scim::group_to_json(*group, members, gbase, ubase).dump(), kScimJson);
        audit(auth_mgr, audit_store, req, "scim.group.created", "success", group->scim_id, {},
             "Group");
        record_request(auth_mgr, "group_create", 201);
    });

    // ── GET /scim/v2/Groups/{id} ───────────────────────────────────────────

    sink.Get(R"(/scim/v2/Groups/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "group_get", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto group = scim_store->get_group_by_id(id);
                if (!group) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "group_get", 404);
                    return;
                }
                // Fail closed: rendering an undetermined membership as an
                // empty `members[]` tells the IdP the group is empty, and a
                // reconciling connector may then "restore" that emptiness.
                auto members = scim_store->list_group_member_user_scim_ids(id);
                if (!members.has_value()) {
                    send_scim_error(res, 503, "membership unavailable");
                    record_request(auth_mgr, "group_get", 503);
                    return;
                }
                res.set_content(scim::group_to_json(*group, *members, groups_location_base(req),
                                                    location_base(req))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "group_get", 200);
            });

    // ── GET /scim/v2/Groups — list / filter. ──────────────────────────────

    sink.Get("/scim/v2/Groups",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "group_list", res.status);
                    return;
                }
                auto gbase = groups_location_base(req);
                auto ubase = location_base(req);

                int start_index = 1;
                if (req.has_param("startIndex")) {
                    auto parsed =
                        parse_scim_int_param(res, req.get_param_value("startIndex"), "startIndex");
                    if (!parsed) {
                        record_request(auth_mgr, "group_list", 400);
                        return;
                    }
                    start_index = *parsed;
                    if (start_index < 1)
                        start_index = 1;
                }
                int count = 100;
                if (req.has_param("count")) {
                    auto parsed = parse_scim_int_param(res, req.get_param_value("count"), "count");
                    if (!parsed) {
                        record_request(auth_mgr, "group_list", 400);
                        return;
                    }
                    count = *parsed;
                }
                if (count > scim::kMaxScimListResults)
                    count = scim::kMaxScimListResults;

                if (req.has_param("filter")) {
                    auto filter_name = scim::parse_displayname_filter(req.get_param_value("filter"));
                    if (!filter_name) {
                        send_scim_error(res, filter_name.error());
                        record_request(auth_mgr, "group_list", filter_name.error().status);
                        return;
                    }
                    std::vector<json> resources;
                    int total = 0;
                    if (auto group = scim_store->get_group_by_display_name(*filter_name)) {
                        auto members = scim_store->list_group_member_user_scim_ids(group->scim_id);
                        if (!members.has_value()) { // fail closed, never "empty group"
                            send_scim_error(res, 503, "membership unavailable");
                            record_request(auth_mgr, "group_list", 503);
                            return;
                        }
                        resources.push_back(scim::group_to_json(*group, *members, gbase, ubase));
                        total = 1;
                    }
                    res.set_content(
                        scim::list_response(resources, total, 1,
                                           static_cast<int>(resources.size()))
                            .dump(),
                        kScimJson);
                    record_request(auth_mgr, "group_list", 200);
                    return;
                }

                int total = 0;
                auto page = scim_store->list_groups(start_index, count, total);
                std::vector<json> resources;
                resources.reserve(page.size());
                for (const auto& g : page) {
                    auto members = scim_store->list_group_member_user_scim_ids(g.scim_id);
                    if (!members.has_value()) { // fail closed, never "empty group"
                        send_scim_error(res, 503, "membership unavailable");
                        record_request(auth_mgr, "group_list", 503);
                        return;
                    }
                    resources.push_back(scim::group_to_json(g, *members, gbase, ubase));
                }
                res.set_content(scim::list_response(resources, total, start_index,
                                                    static_cast<int>(resources.size()))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "group_list", 200);
            });

    // CONCURRENCY (lost-update on Group membership): PUT/PATCH/DELETE each do
    // a read-modify-write of a group's membership — read the current members,
    // fold/compute the final set, persist the WHOLE set via
    // `replace_group_and_members`/`delete_group`. That read...persist is not
    // atomic across two concurrent mutations of the SAME group: two requests
    // touching DIFFERENT members can interleave read-then-write and last-
    // writer-wins loses one (a lost REMOVAL leaves a member admin who should
    // have been demoted). `kGroupMutationMu` serializes the entire
    // read-modify-write critical section (current-members read through the
    // store persist call through the old-union-final recompute loop) across
    // all three handlers, process-wide — mirrors `recompute_scim_user_role`'s
    // `kRecomputeMu` precedent above; Group mutation is not a hot path so a
    // single mutex is fine, no per-group striping needed.
    //
    // LOCK ORDER (do not invert): `kGroupMutationMu` is the OUTER lock;
    // `recompute_scim_user_role` (called from inside each critical section)
    // takes `kRecomputeMu` internally, so the order is always
    // `kGroupMutationMu` -> `kRecomputeMu`, never the reverse.
    // `kGroupMutationMu`'s sole acquirers are the three critical sections
    // below (PUT/PATCH/DELETE) — nothing reachable while it is held (the
    // store calls, `resolve_member_values`, `fold_group_member_ops`,
    // `recompute_scim_user_role`) acquires it again, so there is no
    // self-deadlock. The User create/revive call site of
    // `recompute_scim_user_role` takes only `kRecomputeMu`, never
    // `kGroupMutationMu` — no inversion there either.
    static std::mutex kGroupMutationMu;

    // ── PUT /scim/v2/Groups/{id} — full replace. ──────────────────────────

    sink.Put(R"(/scim/v2/Groups/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store, scim_admin_group](const httplib::Request& req,
                                                                   httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "group_replace", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto group = scim_store->get_group_by_id(id);
                if (!group) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "group_replace", 404);
                    return;
                }
                if (req.body.size() > kMaxBodyBytes) {
                    send_scim_error(res, 413, "request body too large");
                    record_request(auth_mgr, "group_replace", 413);
                    return;
                }
                json body;
                try {
                    body = json::parse(req.body);
                } catch (const std::exception&) {
                    send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                    record_request(auth_mgr, "group_replace", 400);
                    return;
                }
                auto parsed = scim::parse_group(body);
                if (!parsed) {
                    send_scim_error(res, parsed.error());
                    record_request(auth_mgr, "group_replace", parsed.error().status);
                    return;
                }
                const auto& input = *parsed;

                // #7 (sre capacity): bound the member count before doing any
                // further work — see kMaxGroupMembers's doc comment.
                if (input.member_values.size() > kMaxGroupMembers) {
                    send_scim_error(res, 400, "members exceeds the maximum group size", "invalidValue");
                    audit(auth_mgr, audit_store, req, "scim.group.updated", "denied", id,
                         "member count exceeds cap", "Group");
                    record_request(auth_mgr, "group_replace", 400);
                    return;
                }

                // #4 (arch-S4/UP-2): a rename onto an existing (possibly
                // admin) group's displayName is refused — mirrors the
                // create-time 409 (S1526).
                if (input.display_name != group->display_name) {
                    if (auto existing = scim_store->get_group_by_display_name(input.display_name);
                        existing && existing->scim_id != id) {
                        send_scim_error(res, 409, "displayName already exists", "uniqueness");
                        audit(auth_mgr, audit_store, req, "scim.group.updated", "denied", id,
                             "displayName already exists", "Group");
                        record_request(auth_mgr, "group_replace", 409);
                        return;
                    }
                }

                std::vector<std::string> new_members;
                {
                    // CONCURRENCY: kGroupMutationMu's doc comment above —
                    // serializes this read-modify-write critical section
                    // (current-members read -> persist -> recompute) against
                    // concurrent PUT/PATCH/DELETE.
                    std::lock_guard<std::mutex> group_mutation_lock(kGroupMutationMu);

                    // Snapshot membership BEFORE the replace so the recompute
                    // below can cover the union of old+new (a PUT replace can
                    // both add and remove members in the same call — spec
                    // trigger (a), "for PUT also the REMOVED members").
                    //
                    // ★ Fail closed on an undetermined snapshot (2026-07-25
                    // review, HIGH #3) — BEFORE the write, not after. The
                    // replace itself uses `input.member_values`, so an empty
                    // `old_members` does not corrupt the stored set here; what
                    // it silently drops is the recompute fan-out over REMOVED
                    // members, leaving a just-demoted operator holding
                    // `role=admin` until some later mutation happens to touch
                    // them. Refusing the whole PUT is the safe outcome: the
                    // IdP retries, and no partial state is written.
                    auto old_members_read = scim_store->list_group_member_user_scim_ids(id);
                    if (!old_members_read.has_value()) {
                        spdlog::error("ScimRoutes: PUT Groups — could not snapshot current "
                                     "membership for group scim_id={}; refusing the replace "
                                     "(fail-closed, role recompute would be incomplete)",
                                     id);
                        send_scim_error(res, 503, "membership unavailable");
                        audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id,
                             "membership snapshot unavailable", "Group");
                        record_request(auth_mgr, "group_replace", 503);
                        return;
                    }
                    const std::vector<std::string>& old_members = *old_members_read;
                    auto new_members_resolved =
                        resolve_member_values(scim_store, input.member_values);
                    if (!new_members_resolved.has_value()) {
                        spdlog::error("ScimRoutes: PUT Groups — could not resolve every requested "
                                     "member for group scim_id={}; refusing the replace "
                                     "(fail-closed, would persist a partial set)",
                                     id);
                        send_scim_error(res, 503, "membership unavailable");
                        audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id,
                             "member resolution unavailable", "Group");
                        record_request(auth_mgr, "group_replace", 503);
                        return;
                    }
                    new_members = *new_members_resolved;

                    // #2127 review MEDIUM fix: persist the rename AND the
                    // membership replace atomically, in ONE transaction (was
                    // `update_group` + `set_group_members` as two separate
                    // transactions — a membership-write failure after a
                    // committed rename left partial state + stale roles).
                    auto commit_result = scim_store->replace_group_and_members(
                        id, input.display_name, input.external_id, new_members);
                    if (!commit_result.has_value()) {
                        spdlog::error("ScimRoutes: replace_group_and_members failed for group "
                                     "scim_id={}",
                                     id);
                        send_scim_error(res, 500, "failed to update the SCIM group");
                        audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id, {},
                             "Group");
                        record_request(auth_mgr, "group_replace", 500);
                        return;
                    }
                    if (!*commit_result) {
                        // The group existed at the top of this handler but is
                        // gone now — a concurrent DELETE won the race.
                        send_scim_error(res, 404, "resource not found");
                        record_request(auth_mgr, "group_replace", 404);
                        return;
                    }

                    std::vector<std::string> affected = old_members;
                    for (const auto& m : new_members)
                        if (std::find(affected.begin(), affected.end(), m) == affected.end())
                            affected.push_back(m);
                    for (const auto& uid : affected)
                        recompute_scim_user_role(scim_store, auth_mgr, audit_store, req, uid,
                                                 scim_admin_group,
                                                 input.display_name + " op=group_replace");
                }

                auto updated = scim_store->get_group_by_id(id);
                if (!updated) {
                    spdlog::error("ScimRoutes: PUT Groups — group scim_id={} vanished "
                                 "mid-request",
                                 id);
                    send_scim_error(res, 500, "resource state changed mid-request");
                    audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id, {},
                         "Group");
                    record_request(auth_mgr, "group_replace", 500);
                    return;
                }
                audit(auth_mgr, audit_store, req, "scim.group.updated", "success", id, {},
                     "Group");
                res.set_content(scim::group_to_json(*updated, new_members,
                                                    groups_location_base(req), location_base(req))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "group_replace", 200);
            });

    // ── PATCH /scim/v2/Groups/{id} — the critical role-driving path. ──────

    sink.Patch(R"(/scim/v2/Groups/([0-9a-fA-F]+))",
              [scim_store, auth_mgr, audit_store, scim_admin_group](const httplib::Request& req,
                                                                     httplib::Response& res) {
                  if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                      record_request(auth_mgr, "group_patch", res.status);
                      return;
                  }
                  auto id = req.matches[1].str();
                  auto group = scim_store->get_group_by_id(id);
                  if (!group) {
                      send_scim_error(res, 404, "resource not found");
                      record_request(auth_mgr, "group_patch", 404);
                      return;
                  }
                  if (req.body.size() > kMaxBodyBytes) {
                      send_scim_error(res, 413, "request body too large");
                      record_request(auth_mgr, "group_patch", 413);
                      return;
                  }
                  json body;
                  try {
                      body = json::parse(req.body);
                  } catch (const std::exception&) {
                      send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                      record_request(auth_mgr, "group_patch", 400);
                      return;
                  }
                  auto parsed = scim::parse_group_patch(body);
                  if (!parsed) {
                      send_scim_error(res, parsed.error());
                      record_request(auth_mgr, "group_patch", parsed.error().status);
                      return;
                  }
                  const auto& patch = *parsed;

                  // #2127 review rework: resolve-final -> validate-final ->
                  // atomic-persist -> recompute-union. Everything below reads
                  // the CURRENT state once, computes what the FINAL state
                  // would be, validates that FINAL state before touching the
                  // store at all, then persists it in one transaction — no
                  // partial-commit window between the rename and the
                  // membership change (finding #3), no early-return that
                  // skips recompute after a commit (finding #3), and no
                  // stale-arithmetic cap bypass (finding #2).

                  std::vector<std::string> final_members;
                  std::string final_display;
                  bool renamed = false;
                  {
                      // CONCURRENCY: kGroupMutationMu's doc comment above —
                      // serializes this read-modify-write critical section
                      // (current-members read -> persist -> recompute)
                      // against concurrent PUT/PATCH/DELETE.
                      std::lock_guard<std::mutex> group_mutation_lock(kGroupMutationMu);

                      // Re-read the group's CURRENT metadata under the lock —
                      // the pre-lock `group` snapshot (top of handler) can be
                      // stale by the time we get here: a concurrent PATCH/PUT
                      // may have renamed it between that read and acquiring
                      // this lock. Using the stale snapshot as the `value_or`
                      // baseline for a PATCH that omits displayName would
                      // silently revert the concurrent rename (and, since
                      // display_name drives the --scim-admin-group match,
                      // could re-promote/un-demote members). Also covers the
                      // group having been deleted entirely in that window.
                      auto current = scim_store->get_group_by_id(id);
                      if (!current) {
                          send_scim_error(res, 404, "resource not found");
                          record_request(auth_mgr, "group_patch", 404);
                          return;
                      }

                      // Step 1: fold the ORDERED member ops onto a copy of the
                      // CURRENT membership (raw ids, not yet resolved against
                      // live Users) — see fold_group_member_ops's doc comment
                      // for why order matters ([HIGH] finding #1).
                      //
                      // ★ SECURITY (2026-07-25 review, HIGH #3) — THE durable
                      // data-loss path, and the reason this read had to become
                      // a tri-state. PATCH folds its ops onto the CURRENT
                      // membership and then persists the whole folded set via
                      // `replace_group_and_members`. When the read failed open
                      // as an empty vector, a momentary pool-lease timeout made
                      // the fold start from "this group has no members", and
                      // the replace below COMMITTED that emptiness — one blip
                      // silently and permanently wiped a group's entire
                      // membership, and (via the recompute) every admin role
                      // that membership conferred. Refuse the PATCH instead:
                      // nothing is written, and the IdP's retry succeeds.
                      auto old_members_read = scim_store->list_group_member_user_scim_ids(id);
                      if (!old_members_read.has_value()) {
                          spdlog::error("ScimRoutes: PATCH Groups — could not read current "
                                       "membership for group scim_id={}; refusing the patch "
                                       "(fail-closed, folding onto an empty set would delete "
                                       "the real membership)",
                                       id);
                          send_scim_error(res, 503, "membership unavailable");
                          audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id,
                               "membership read unavailable", "Group");
                          record_request(auth_mgr, "group_patch", 503);
                          return;
                      }
                      const std::vector<std::string>& old_members = *old_members_read;
                      auto final_members_raw =
                          fold_group_member_ops(old_members, patch.member_ops);

                      // Step 2: resolve/validate-and-skip the WHOLE final set
                      // against live SCIM User resources in one pass (never
                      // per-op) — an id that DEFINITIVELY does not resolve
                      // (never provisioned, deleted, or garbage from the IdP)
                      // is silently dropped, same validate-and-skip contract
                      // as before; an id that could not be CHECKED fails the
                      // whole patch closed rather than being skipped.
                      auto final_members_resolved =
                          resolve_member_values(scim_store, final_members_raw);
                      if (!final_members_resolved.has_value()) {
                          spdlog::error("ScimRoutes: PATCH Groups — could not resolve every "
                                       "member for group scim_id={}; refusing the patch "
                                       "(fail-closed, would persist a partial set)",
                                       id);
                          send_scim_error(res, 503, "membership unavailable");
                          audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id,
                               "member resolution unavailable", "Group");
                          record_request(auth_mgr, "group_patch", 503);
                          return;
                      }
                      final_members = *final_members_resolved;

                      const std::string pre_update_display_name = current->display_name;
                      final_display = patch.display_name.value_or(current->display_name);
                      const std::string final_external =
                          patch.external_id.value_or(current->external_id);
                      renamed = (final_display != pre_update_display_name);

                      // Step 3a: member cap on the FINAL set — closes the
                      // requested-remove-arithmetic bypass ([MEDIUM] finding #2):
                      // N bogus removes no longer buy headroom for N real adds,
                      // because the cap is checked against what would ACTUALLY
                      // persist, not what the request claims to remove.
                      if (final_members.size() > kMaxGroupMembers) {
                          send_scim_error(res, 400, "members exceeds the maximum group size",
                                         "invalidValue");
                          audit(auth_mgr, audit_store, req, "scim.group.updated", "denied", id,
                               "member count exceeds cap", "Group");
                          record_request(auth_mgr, "group_patch", 400);
                          return;
                      }

                      // Step 3b: rename-uniqueness — refused BEFORE any mutation
                      // (arch-S4/UP-2), same as before.
                      if (renamed) {
                          if (auto existing = scim_store->get_group_by_display_name(final_display);
                              existing && existing->scim_id != id) {
                              send_scim_error(res, 409, "displayName already exists", "uniqueness");
                              audit(auth_mgr, audit_store, req, "scim.group.updated", "denied", id,
                                   "displayName already exists", "Group");
                              record_request(auth_mgr, "group_patch", 409);
                              return;
                          }
                      }

                      // Step 4: persist the rename AND the membership replace
                      // atomically, in ONE transaction — the durable fix for
                      // finding #3 (a mid-write failure could previously leave a
                      // committed rename with stale/partial membership).
                      auto commit_result =
                          scim_store->replace_group_and_members(id, final_display, final_external,
                                                                final_members);
                      if (!commit_result.has_value()) {
                          spdlog::error("ScimRoutes: replace_group_and_members failed for group "
                                       "scim_id={}",
                                       id);
                          send_scim_error(res, 500, "failed to update the SCIM group");
                          audit(auth_mgr, audit_store, req, "scim.group.updated", "failure", id, {},
                               "Group");
                          record_request(auth_mgr, "group_patch", 500);
                          return;
                      }
                      if (!*commit_result) {
                          // The group existed at the top of this handler but is
                          // gone now — a concurrent DELETE won the race.
                          send_scim_error(res, 404, "resource not found");
                          record_request(auth_mgr, "group_patch", 404);
                          return;
                      }

                      // Step 5: recompute is gated on the commit above actually
                      // having happened — affected = old ∪ final, unconditional,
                      // covers promotions, demotions, removed members, AND a
                      // rename that flips the --scim-admin-group match, all in
                      // one pass (no more separate display_name_changed-gated
                      // "recompute everybody current" branch — folding old ∪
                      // final already subsumes it, since a metadata-only PATCH
                      // has final == old).
                      std::vector<std::string> to_recompute = old_members;
                      for (const auto& uid : final_members)
                          if (std::find(to_recompute.begin(), to_recompute.end(), uid) ==
                              to_recompute.end())
                              to_recompute.push_back(uid);

                      std::string trigger = final_display + " op=group_patch";
                      if (renamed)
                          trigger += " renamed_from='" + pre_update_display_name + "'";
                      for (const auto& uid : to_recompute)
                          recompute_scim_user_role(scim_store, auth_mgr, audit_store, req, uid,
                                                   scim_admin_group, trigger);
                  }

                  auto updated = scim_store->get_group_by_id(id);
                  if (!updated) {
                      spdlog::error("ScimRoutes: PATCH Groups — group scim_id={} vanished "
                                   "mid-request",
                                   id);
                      send_scim_error(res, 500, "resource state changed mid-request");
                      record_request(auth_mgr, "group_patch", 500);
                      return;
                  }
                  audit(auth_mgr, audit_store, req, "scim.group.updated", "success", id, {},
                       "Group");
                  res.set_content(scim::group_to_json(*updated, final_members,
                                                      groups_location_base(req),
                                                      location_base(req))
                                      .dump(),
                                  kScimJson);
                  record_request(auth_mgr, "group_patch", 200);
              });

    // ── DELETE /scim/v2/Groups/{id} ────────────────────────────────────────

    sink.Delete(R"(/scim/v2/Groups/([0-9a-fA-F]+))",
               [scim_store, auth_mgr, audit_store, scim_admin_group](const httplib::Request& req,
                                                                      httplib::Response& res) {
                   if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                       record_request(auth_mgr, "group_delete", res.status);
                       return;
                   }
                   auto id = req.matches[1].str();
                   auto group = scim_store->get_group_by_id(id);
                   if (!group) {
                       send_scim_error(res, 404, "resource not found");
                       record_request(auth_mgr, "group_delete", 404);
                       return;
                   }
                   {
                       // CONCURRENCY: kGroupMutationMu's doc comment above —
                       // serializes this read-modify-write critical section
                       // (former-members read -> delete -> recompute) against
                       // concurrent PUT/PATCH/DELETE.
                       std::lock_guard<std::mutex> group_mutation_lock(kGroupMutationMu);

                       // #2021 trigger (c): snapshot the full membership
                       // BEFORE delete_group tears down the
                       // scim_group_members rows alongside the group
                       // (ScimStore::delete_group's doc comment) — these are
                       // the users who lose this group.
                       //
                       // ★ Fail closed BEFORE the delete (2026-07-25 review,
                       // HIGH #3). Deleting the admin group is exactly when the
                       // recompute matters most: every member must be demoted.
                       // An undetermined snapshot read as "no members" would
                       // tear the group down and demote nobody, leaving the
                       // whole former membership holding `role=admin` with no
                       // group left to justify it and no later mutation that
                       // would ever revisit them.
                       auto former_members_read =
                           scim_store->list_group_member_user_scim_ids(id);
                       if (!former_members_read.has_value()) {
                           spdlog::error("ScimRoutes: DELETE Groups — could not snapshot "
                                        "membership for group scim_id={}; refusing the delete "
                                        "(fail-closed, members would keep a role this group "
                                        "conferred)",
                                        id);
                           send_scim_error(res, 503, "membership unavailable");
                           audit(auth_mgr, audit_store, req, "scim.group.deleted", "failure", id,
                                "membership snapshot unavailable", "Group");
                           record_request(auth_mgr, "group_delete", 503);
                           return;
                       }
                       const std::vector<std::string>& former_members = *former_members_read;

                       auto delete_result = scim_store->delete_group(id);
                       if (!delete_result.has_value()) {
                           spdlog::error(
                               "ScimRoutes: ScimStore::delete_group failed for scim_id={}", id);
                           send_scim_error(res, 500, "failed to remove the SCIM group");
                           audit(auth_mgr, audit_store, req, "scim.group.deleted", "failure", id,
                                {}, "Group");
                           record_request(auth_mgr, "group_delete", 500);
                           return;
                       }
                       if (!*delete_result) {
                           spdlog::info("ScimRoutes: DELETE Groups scim_id={} — already gone "
                                       "(concurrent/duplicate DELETE); treating as idempotent "
                                       "success",
                                       id);
                       }

                       for (const auto& uid : former_members)
                           recompute_scim_user_role(scim_store, auth_mgr, audit_store, req, uid,
                                                    scim_admin_group,
                                                    group->display_name + " op=group_delete");
                   }

                   audit(auth_mgr, audit_store, req, "scim.group.deleted", "success", id, {},
                        "Group");
                   res.status = 204;
                   record_request(auth_mgr, "group_delete", 204);
               });
}

} // namespace yuzu::server
