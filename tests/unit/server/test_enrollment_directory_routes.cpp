/**
 * test_enrollment_directory_routes.cpp — HTTP-level coverage for #4031's five
 * REST v1 read twins (`EnrollmentDirectoryRoutes`):
 *   - GET /api/v1/directory/users             (Directory:Read, [pg])
 *   - GET /api/v1/directory/status             (Directory:Read, [pg])
 *   - GET /api/v1/enrollment/auto-approve-rules (Enrollment:Read)
 *   - GET /api/v1/enrollment/pending-agents     (Enrollment:Read)
 *   - GET /api/v1/settings/oidc                 (OidcConfig:Read)
 *
 * Registers EnrollmentDirectoryRoutes against an in-process TestRouteSink and
 * dispatches synthesised requests directly into the captured handlers — no
 * socket, no acceptor thread (the #438 TSan trap).
 *
 * Coverage:
 *   - perm_fn denial (403) on every route, with the exact (securable, op) it
 *     was called with
 *   - 503 when the backing dependency is null (directory_sync / auto_approve
 *     / auth_mgr / cfg)
 *   - success-path shape for auto-approve-rules / pending-agents / oidc
 *     (all in-memory, no Postgres needed)
 *   - success-path shape + audit-fail-closed 503 for directory/users and
 *     directory/status ([pg]-tagged, DirectorySyncPg helper)
 *   - the naming-trap regression: /settings/oidc gates on OidcConfig, never
 *     Directory
 */

#include "authz_gates.hpp" // authz::FleetReadGate — the pending-agents ADR-0017 fake gate
#include "enrollment_directory_model.hpp" // directory_status_json — direct builder test
#include "enrollment_directory_routes.hpp"
#include "pg/pg_exec.hpp"
#include "test_directory_sync_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct PermCall {
    std::string securable, operation;
};

/// REST harness for EnrollmentDirectoryRoutes. `auto_approve`/`auth_mgr`/`cfg`
/// are plain value members (no Postgres) so most of this file needs no [pg]
/// tag; `directory_sync` stays a raw pointer the caller wires separately
/// (nullptr by default — the null-dependency 503 path) since DirectorySync is
/// Postgres-backed. Member order: dependencies before `sink`/`routes`, so
/// they outlive the handlers that capture pointers into them (same
/// discipline as WebhookRouteHarness, test_webhook_routes.cpp).
struct EnrollmentDirectoryRouteHarness {
    auth::AutoApproveEngine auto_approve;
    auth::AuthManager auth_mgr;
    Config cfg;
    std::shared_mutex oidc_mu;
    DirectorySync* directory_sync{nullptr};

    bool perm_grant{true};
    std::vector<PermCall> perm_calls;
    std::vector<AuditRecord> audit_log;
    bool audit_persists{true};

    // #4031 hardening: pending-agents alone gates on fleet_read_fn (ADR-0017)
    // instead of perm_fn — a separate fake so denial/admit/scope are testable
    // independently of the (now-unrelated, for this one route) perm_calls
    // tracking above. `fleet_scope` default (nullopt) = unfiltered TOP,
    // matching an Administrator's real AdmitAll result; a test that wants to
    // exercise the AdmitScoped/empty-intersection path sets it explicitly.
    bool fleet_admit{true};
    authz::VisibleSet fleet_scope;
    std::vector<PermCall> fleet_read_calls;

    yuzu::server::test::TestRouteSink sink;
    EnrollmentDirectoryRoutes routes;

    explicit EnrollmentDirectoryRouteHarness() {
        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& op) -> bool {
            perm_calls.push_back({securable, op});
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return audit_persists;
        };
        auto fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string& securable,
                                    const std::string& op) -> authz::FleetReadGate {
            fleet_read_calls.push_back({securable, op});
            if (!fleet_admit) {
                res.status = 403;
                return authz::FleetReadGate{}; // admitted=false, scope=deny_all() default
            }
            return authz::FleetReadGate{true, fleet_scope};
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, directory_sync, &auto_approve,
                               &auth_mgr, &cfg, oidc_mu, fleet_read_fn);
    }
};

} // namespace

// ── perm_fn denial (403) — every route, exact securable/operation ─────────

// NOTE (Gate 4 hardening): every denial test below also asserts
// `h.audit_log.empty()` and (where the route can only ever call perm_fn
// once) `h.perm_calls.size() == 1`. Neither assertion existed originally —
// quality-engineer's Gate 3 SHOULD noted that a future edit dropping the
// early `return` after a denied `perm_fn` would fall through, write an
// audit row, and overwrite `res.status` via `set_content` (which never
// touches `status`), yet every pre-existing assertion here would still
// pass — a 403 status carrying a 200-shaped PII/config body. These two
// extra checks close that gap.

TEST_CASE("REST enrollment/directory[pg]: perm_fn denial 403s directory/users on Directory:Read",
          "[rest][enrollment_directory][pg]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.size() == 1);
    CHECK(h.perm_calls.back().securable == "Directory");
    CHECK(h.perm_calls.back().operation == "Read");
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s directory/status on Directory:Read",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.size() == 1);
    CHECK(h.perm_calls.back().securable == "Directory");
    CHECK(h.perm_calls.back().operation == "Read");
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s auto-approve-rules on Enrollment:Read",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.size() == 1);
    CHECK(h.perm_calls.back().securable == "Enrollment");
    CHECK(h.perm_calls.back().operation == "Read");
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST enrollment/directory: fleet_read_fn denial 403s pending-agents on "
          "Enrollment:Read (#4031 hardening -- migrated off perm_fn onto the ADR-0017 "
          "admit-then-filter chokepoint; NEVER stacked with perm_fn, see authz_gates.hpp's "
          "own falsifier)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.fleet_admit = false;
    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.fleet_read_calls.empty());
    CHECK(h.fleet_read_calls.size() == 1);
    CHECK(h.fleet_read_calls.back().securable == "Enrollment");
    CHECK(h.fleet_read_calls.back().operation == "Read");
    CHECK(h.audit_log.empty());
    // Never-stacked regression pin: perm_fn must not be consulted at all for
    // this route any more -- a re-added perm_fn call ahead of/behind
    // fleet_read_fn is the exact BLOCKING defect authz_gates.hpp's own doc
    // comment warns about (it makes the AdmitScoped branch permanently
    // unreachable for a management-group-scoped-only caller).
    CHECK(h.perm_calls.empty());
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s settings/oidc on OidcConfig:Read — "
          "NEVER Directory (the naming-trap regression)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    // Pins call COUNT, not just the last call's securable — catches a
    // regression that inserted an extra, earlier permission probe (e.g.
    // gating on Directory first, then OidcConfig) ahead of the real check,
    // not just a straight securable swap.
    CHECK(h.perm_calls.size() == 1);
    CHECK(h.perm_calls.back().securable == "OidcConfig");
    CHECK(h.perm_calls.back().operation == "Read");
    CHECK(h.audit_log.empty());
}

// ── 503 on a null dependency ────────────────────────────────────────────

TEST_CASE("REST enrollment/directory: directory/users 503s when directory_sync is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h; // directory_sync stays nullptr
    auto res = h.sink.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory: directory/status 503s when directory_sync is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    auto res = h.sink.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── auto-approve-rules: success shape + audit (in-memory, no PG) ──────────

TEST_CASE("REST enrollment/directory: auto-approve-rules returns the configured rule set",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auto_approve.add_rule(
        {auth::AutoApproveRuleType::hostname_glob, "*.prod.example.com", "prod hosts"});
    h.auto_approve.set_require_all(true);

    auto res = h.sink.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("data"));
    REQUIRE(j["data"]["rules"].is_array());
    REQUIRE(j["data"]["rules"].size() == 1);
    CHECK(j["data"]["rules"][0]["type"] == "hostname_glob");
    CHECK(j["data"]["rules"][0]["value"] == "*.prod.example.com");
    CHECK(j["data"]["rules"][0]["label"] == "prod hosts");
    CHECK(j["data"]["rules"][0]["enabled"] == true);
    CHECK(j["data"]["require_all"] == true);
    CHECK(j["meta"]["api_version"] == "v1");

    // Audited, non-blocking posture — a row was written even though it never
    // gates the response.
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "enrollment.auto_approve.view");
}

TEST_CASE("REST enrollment/directory: auto-approve-rules 503s when the engine is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    // Rebuild against a null auto_approve pointer to exercise the 503 arm —
    // register a second sink directly (cheaper than modifying the fixture).
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, &h.cfg,
                            h.oidc_mu);
    auto res = sink2.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory: pending-agents 503s when auth_mgr is null "
          "(Gate 4: closes a coverage gap the file header claimed was already covered)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    // Wire a permissive fleet_read_fn -- pending-agents' sole gate is now
    // this, not perm_fn (above), so leaving it unwired (default `{}`) would
    // 503 for "fleet-read authorization gate unavailable" instead of the
    // auth_mgr-null reason this test claims to exercise.
    auto fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                            const std::string&) -> authz::FleetReadGate {
        return authz::FleetReadGate{true, std::nullopt};
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, &h.cfg,
                            h.oidc_mu, fleet_read_fn);
    auto res = sink2.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory: pending-agents 503s when fleet_read_fn is unwired "
          "(#4031 hardening -- misconfiguration fails closed, mirrors the "
          "GET /api/v1/inventory/software precedent)",
          "[rest][enrollment_directory]") {
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    auth::AutoApproveEngine auto_approve;
    auth::AuthManager auth_mgr;
    Config cfg;
    std::shared_mutex oidc_mu;
    // fleet_read_fn left at its default `{}` -- deliberately unwired.
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, nullptr, &auto_approve, &auth_mgr,
                            &cfg, oidc_mu);
    auto res = sink2.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory: settings/oidc 503s when cfg is null "
          "(Gate 4: closes a coverage gap the file header claimed was already covered)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, nullptr, &h.auto_approve,
                            &h.auth_mgr, nullptr, h.oidc_mu);
    auto res = sink2.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── pending-agents: success shape + audit (in-memory, no PG) ──────────────

TEST_CASE("REST enrollment/directory: pending-agents returns pending+denied only, EXCLUDES "
          "already-approved agents (Gate 4 fix -- matches render_pending_fragment()'s "
          "identical filter; the route previously returned every agent that had ever "
          "enrolled, silently diverging from its own name/docs/API-parity ledger)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auth_mgr.add_pending_agent("agent-1", "host1.example.com", "linux", "x86_64", "1.2.3");
    h.auth_mgr.add_pending_agent("agent-2", "host2.example.com", "windows", "x86_64", "1.2.3");
    REQUIRE(h.auth_mgr.approve_pending_agent("agent-2"));

    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    // Only agent-1 (still pending) should appear -- agent-2 (approved) must
    // be excluded. Before the fix this returned BOTH (size 2), including
    // agent-2 with status:"approved" -- this assertion fails on the
    // unfiltered code, closing the false-green floor for this finding.
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"] == "agent-1");
    CHECK(j["data"][0]["hostname"] == "host1.example.com");
    CHECK(j["data"][0]["os"] == "linux");
    CHECK(j["data"][0]["arch"] == "x86_64");
    CHECK(j["data"][0]["agent_version"] == "1.2.3");
    CHECK(j["data"][0]["status"] == "pending");
    // pagination.total must reflect the FILTERED count, not the raw
    // pending_agents_ map size -- list_json computes it from the array
    // actually pushed, so this also guards against a fix that filters the
    // rows but forgets to recompute the count from the same filtered set.
    CHECK(j["pagination"]["total"] == 1);

    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "enrollment.pending_agents.view");
}

TEST_CASE("REST enrollment/directory: pending-agents includes denied agents (only "
          "'approved' is excluded, matching PendingStatus's exact 3-value enum)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auth_mgr.add_pending_agent("agent-3", "host3.example.com", "macos", "arm64", "1.2.3");
    REQUIRE(h.auth_mgr.deny_pending_agent("agent-3"));

    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"] == "agent-3");
    CHECK(j["data"][0]["status"] == "denied");
}

// ── pending-agents: ADR-0017 scope filtering (#4031 hardening) ────────────

TEST_CASE("REST enrollment/directory: pending-agents narrows to an engaged scope -- an "
          "out-of-scope pending agent is dropped, an in-scope one is kept",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auth_mgr.add_pending_agent("agent-1", "host1.example.com", "linux", "x86_64", "1.2.3");
    h.auth_mgr.add_pending_agent("agent-3", "host3.example.com", "macos", "arm64", "1.2.3");
    // Engaged (non-nullopt) scope containing only agent-1 -- simulates a
    // management-group-scoped `fleet_read_fn` admit, distinct from the
    // harness default's unfiltered TOP.
    h.fleet_scope = std::unordered_set<std::string>{"agent-1"};

    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"] == "agent-1");
    CHECK(j["pagination"]["total"] == 1);
}

TEST_CASE("REST enrollment/directory: pending-agents admitted-engaged-EMPTY scope -- 200 with "
          "an empty list, never a 403 (route half of the under-admission fix: an admitted gate "
          "result is always answered with its real intersection, even when that intersection "
          "is empty, rather than being treated as a denial)",
          "[rest][enrollment_directory]") {
    // NOTE: `h.fleet_scope` below is a hand-injected fake -- it exercises
    // only this route's own post-gate `authz::in_scope` filtering, not a
    // real RbacStore+ManagementGroupStore composition. It intentionally
    // does NOT prove that a scoped grant against real enrollment data is
    // always empty (it is not -- see the CONFINEMENT comment above the
    // pending-agents route in enrollment_directory_routes.cpp for why the
    // data model doesn't guarantee that). The real gate composition is
    // covered elsewhere, in two separate pieces -- neither of which alone
    // is the exact "require_fleet_read against a real, memberless
    // management group" case, and this test doesn't claim to be either:
    // test_authz_gates.cpp's GatesRig cases cover require_fleet_read with
    // real Postgres-backed RbacStore/ManagementGroupStore state, but every
    // GatesRig group has a real member -- its only admitted-empty case is
    // an empty *service-tag* intersection under a global grant, a
    // different axis. The AdmitScoped-on-a-memberless-group shape itself
    // (INV-2) is covered in test_list_read_confinement.cpp's "allow on an
    // empty group ⇒ AdmitScoped empty" case, but that drives
    // RbacStore::authorize_list_read directly, one layer below
    // require_fleet_read.
    EnrollmentDirectoryRouteHarness h;
    h.auth_mgr.add_pending_agent("agent-1", "host1.example.com", "linux", "x86_64", "1.2.3");
    // Engaged-empty scope (authz::deny_all() shape) -- admitted, but the
    // real visible-agent intersection is empty.
    h.fleet_scope = std::unordered_set<std::string>{};

    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 200); // admitted, not denied -- this is the whole point of the fix
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
    CHECK(j["pagination"]["total"] == 0);
}

// ── settings/oidc: success shape + secret masking (in-memory, no PG) ──────

TEST_CASE("REST enrollment/directory: settings/oidc reports configured=true and never echoes "
          "the client secret",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.cfg.oidc_issuer = "https://login.microsoftonline.com/tenant/v2.0";
    h.cfg.oidc_client_id = "client-abc";
    h.cfg.oidc_client_secret = "super-secret-value";
    h.cfg.oidc_redirect_uri = "https://yuzu.example.com/auth/callback";
    h.cfg.oidc_admin_group = "admin-group-id";
    h.cfg.oidc_skip_tls_verify = true;

    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["configured"] == true);
    CHECK(j["data"]["issuer"] == "https://login.microsoftonline.com/tenant/v2.0");
    CHECK(j["data"]["client_id"] == "client-abc");
    CHECK(j["data"]["client_secret_configured"] == true);
    CHECK(j["data"]["redirect_uri"] == "https://yuzu.example.com/auth/callback");
    CHECK(j["data"]["admin_group"] == "admin-group-id");
    CHECK(j["data"]["skip_tls_verify"] == true);

    // The raw secret must never appear anywhere in the response body.
    CHECK(res->body.find("super-secret-value") == std::string::npos);

    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "settings.oidc.view");
}

TEST_CASE("REST enrollment/directory: settings/oidc reports configured=false and "
          "client_secret_configured=false when unset",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["configured"] == false);
    CHECK(j["data"]["client_secret_configured"] == false);
}

// ── directory/users, directory/status: [pg] ────────────────────────────────

TEST_CASE("REST enrollment/directory[pg]: directory/users returns an empty list against a "
          "freshly-opened store and audits directory.users.view",
          "[rest][enrollment_directory][pg]") {
    // Deliberately does NOT call sync_entra/apply_entra_sync: sync_entra
    // makes a real outbound Graph API call (unsuitable for a unit test, and
    // the private apply_entra_sync test seam is a file-local friend struct
    // in test_directory_sync.cpp — duplicating it here would risk an ODR
    // violation across TUs). DirectorySync's own sync/row semantics are
    // covered by test_directory_sync.cpp; this file's job is only to prove
    // the ROUTE calls the store and builds a correct response + audit row,
    // which an empty-but-open store already exercises.
    yuzu::test::DirectorySyncPg ds;

    EnrollmentDirectoryRouteHarness h;
    h.directory_sync = ds.get();
    // Re-register against the now-set directory_sync (harness ctor already
    // ran with nullptr) — cheap to build a second sink here rather than
    // reorder the fixture's construction.
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    std::vector<AuditRecord> audit_log;
    auto audit_fn = [&audit_log](const httplib::Request&, const std::string& a,
                                 const std::string& r, const std::string& tt,
                                 const std::string& ti, const std::string& d) {
        audit_log.push_back({a, r, tt, ti, d});
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &h.auto_approve,
                            &h.auth_mgr, &h.cfg, h.oidc_mu);

    auto res = sink2.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
    CHECK(j["pagination"]["total"] == 0);

    REQUIRE_FALSE(audit_log.empty());
    CHECK(audit_log.back().action == "directory.users.view");
}

TEST_CASE("REST enrollment/directory[pg]: directory/users fails closed (503) when the audit "
          "row cannot persist",
          "[rest][enrollment_directory][pg]") {
    yuzu::test::DirectorySyncPg ds;

    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return false; // simulate a persist failure
    };
    auth::AutoApproveEngine auto_approve;
    auth::AuthManager auth_mgr;
    Config cfg;
    std::shared_mutex oidc_mu;
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &auto_approve,
                            &auth_mgr, &cfg, oidc_mu);

    auto res = sink2.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory[pg]: directory/status returns provider/status/counts, "
          "unaudited",
          "[rest][enrollment_directory][pg]") {
    yuzu::test::DirectorySyncPg ds;

    EnrollmentDirectoryRouteHarness h;
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    int audit_calls = 0;
    auto audit_fn = [&audit_calls](const httplib::Request&, const std::string&,
                                   const std::string&, const std::string&, const std::string&,
                                   const std::string&) {
        ++audit_calls;
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &h.auto_approve,
                            &h.auth_mgr, &h.cfg, h.oidc_mu);

    auto res = sink2.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("data"));
    CHECK(j["data"].contains("provider"));
    CHECK(j["data"].contains("status"));
    CHECK(j["data"].contains("user_count"));
    CHECK(j["data"].contains("group_count"));
    CHECK(j["data"]["groups"].is_array());
    CHECK(audit_calls == 0); // no PII — deliberately unaudited, matches the legacy route
}

// ── mapped_role redaction (colleague-review finding on #4176) ──────────────
//
// groups[].mapped_role is the AD/Entra group -> Yuzu-role authorization map —
// the same data class as the floored OidcConfig:admin_group field. Reachable
// at Viewer role / readonly MCP tier by design (list_directory_users and the
// rest of get_directory_status stay at that level), but mapped_role itself
// must be admin-only. directory_status_json's `reveal_mapped_role` parameter
// is the mechanism; this pins the builder directly (no store needed — a
// DirectoryGroup is a plain struct) plus one route-level round trip proving
// the wiring (auth_fn -> effective_role -> the builder call) actually holds.

TEST_CASE("directory_status_json: redacts mapped_role when reveal_mapped_role is false, reveals "
          "it when true",
          "[enrollment_directory][model]") {
    SyncStatus status{.provider = "entra", .status = "completed"};
    std::vector<DirectoryGroup> groups{
        {.id = "g1", .display_name = "Eng", .description = "", .mapped_role = "Administrator",
         .synced_at = 100}};

    auto redacted = directory_status_json(status, groups, /*reveal_mapped_role=*/false);
    REQUIRE(redacted["groups"].size() == 1);
    CHECK(redacted["groups"][0]["mapped_role"] == "");
    // Every other field is untouched by the redaction — only mapped_role is cut.
    CHECK(redacted["groups"][0]["id"] == "g1");
    CHECK(redacted["groups"][0]["display_name"] == "Eng");

    auto revealed = directory_status_json(status, groups, /*reveal_mapped_role=*/true);
    REQUIRE(revealed["groups"].size() == 1);
    CHECK(revealed["groups"][0]["mapped_role"] == "Administrator");
}

TEST_CASE("REST enrollment/directory[pg]: directory/status redacts mapped_role for a non-admin "
          "caller and reveals it for an admin caller",
          "[rest][enrollment_directory][pg]") {
    yuzu::test::DirectorySyncPg ds;

    // Seed one group + its role mapping. directory_groups has no public
    // writer (store_group is private, apply_entra_sync's friend-struct seam
    // is file-local to test_directory_sync.cpp — see this file's header
    // note) so the group row itself goes in via a raw statement on the
    // pool DirectorySyncPg exposes for exactly this ("asserting ... with a
    // raw statement", test_directory_sync_pg_helper.hpp); the mapping goes
    // in via the real public configure_group_role_mapping, so the LEFT JOIN
    // read path this test actually cares about is exercised for real.
    {
        auto lease = ds.pool().acquire();
        REQUIRE(lease);
        auto ins = pg::exec_params(
            lease.get(),
            "INSERT INTO directory_sync.directory_groups (id, display_name, description, "
            "synced_at) VALUES ($1, $2, $3, $4)",
            std::vector<std::string>{"g1", "Engineering", "", "100"});
        REQUIRE(ins.ok());
    }
    ds->configure_group_role_mapping("g1", "Administrator");
    REQUIRE(ds->get_synced_groups().size() == 1);
    REQUIRE(ds->get_synced_groups()[0].mapped_role == "Administrator");

    EnrollmentDirectoryRouteHarness h;
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };

    yuzu::server::test::TestRouteSink admin_sink;
    EnrollmentDirectoryRoutes admin_routes;
    auto admin_auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "admin-tester";
        s.role = auth::Role::admin;
        return s;
    };
    admin_routes.register_routes(admin_sink, admin_auth_fn, perm_fn, audit_fn, ds.get(),
                                 &h.auto_approve, &h.auth_mgr, &h.cfg, h.oidc_mu);
    auto admin_res = admin_sink.Get("/api/v1/directory/status");
    REQUIRE(admin_res);
    auto admin_json = nlohmann::json::parse(admin_res->body);
    REQUIRE(admin_json["data"]["groups"].size() == 1);
    CHECK(admin_json["data"]["groups"][0]["mapped_role"] == "Administrator");

    yuzu::server::test::TestRouteSink viewer_sink;
    EnrollmentDirectoryRoutes viewer_routes;
    auto viewer_auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "viewer-tester";
        s.role = auth::Role::user; // Viewer holds Directory:Read via RBAC, but role != admin
        return s;
    };
    viewer_routes.register_routes(viewer_sink, viewer_auth_fn, perm_fn, audit_fn, ds.get(),
                                  &h.auto_approve, &h.auth_mgr, &h.cfg, h.oidc_mu);
    auto viewer_res = viewer_sink.Get("/api/v1/directory/status");
    REQUIRE(viewer_res);
    auto viewer_json = nlohmann::json::parse(viewer_res->body);
    REQUIRE(viewer_json["data"]["groups"].size() == 1);
    CHECK(viewer_json["data"]["groups"][0]["mapped_role"] == "");
    // Everything else stays reachable — the redaction is narrow.
    CHECK(viewer_json["data"]["groups"][0]["id"] == "g1");
    CHECK(viewer_json["data"]["groups"][0]["display_name"] == "Engineering");
}
