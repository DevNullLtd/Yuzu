/**
 * test_rbac_admin_hint.cpp - `rbac_admin_hint` (rbac_admin_predicate.hpp), the advisory
 * tri-state the Users and roles page uses to decide whether to draw the Assign button and the
 * enforcement switch (#6034).
 *
 * Two layers:
 *   1. The ROUTE-LEVEL equality matrix, the empirical control that the hint equals the gate for
 *      every persona it models. The assign routes call the same two functions in the same
 *      order; the enforcement route applies the regime rule inside set_enforcement on a real
 *      transition, so its equality rests on this matrix. A change to the gate sequence of
 *      any of the three routes needs a matching row here. Per persona, the hint is computed
 *      from the same stores the routes read, then the
 *      REAL `POST /api/v1/rbac/roles/{name}/assignments` (plus `DELETE .../assignments/{id}`
 *      for two personas, and, for the personas that can reach a real transition,
 *      `PUT /api/v1/rbac/enforcement`) is called and its answer
 *      classified: 2xx / 400 / 409 = authority admitted (kMay), 403 = kMayNot, 503 = kUnconfirmed.
 *      A 403 or 503 counts only when its message is one of the gates the hint models (see
 *      `classify`), so a refusal from the wrong gate fails the persona. The hint must equal that
 *      classification, and must not have written an audit row (every route, the MCP twins
 *      included, is checked against an `AuditWatch` that is shown to see a write). A persona the
 *      hint calls kMay must also get the exact status its REST route answers (`admitted_status` at
 *      each REST call site; the MCP twins are held to the classification and the side effects,
 *      not a status): 201 for assign, 200 for unassign and for PUT enforcement, and 409 for the PUT
 *      destination-guard persona (P4: admitted by both gates, then refused by the
 *      destination guard, a deterministic refusal that is characterised, not a transition). So a
 *      400 or a 409 from a gate the hint does not model cannot pass for "authority admitted".
 *   2. The fold itself: structural denies need no store, a null or degraded store is
 *      kUnconfirmed, `RbacAdminSurface` has no default argument.
 *
 * PG-gated (RbacStore, AuthDB). Skips when YUZU_TEST_POSTGRES_DSN is unset; a skip is NOT a pass.
 */

#include "rbac_admin_predicate.hpp"

#include "audit_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_rbac_admin_surface_harness.hpp"
#include "test_rbac_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

using namespace yuzu::server;

namespace {

/// The route's A4 error message ("error"."message"), or the raw body when it is not an A4 error.
std::string error_message_of(const std::string& body) {
    const auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object() || !j.contains("error") || !j["error"].is_object())
        return body;
    return j["error"].value("message", "");
}

bool starts_with(const std::string& s, std::string_view prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

/// What a real route answer says about the caller's authority. Anything outside the three
/// shapes is not an authority answer, so the test fails loudly rather than guessing. The status
/// alone is not enough (a 403 or 503 from the WRONG place would pass for the right one), so a
/// refusal also has to carry the message of a gate the hint models: the shared predicate refusal,
/// the three structural belts that run before it (engine, MCP-tier and service-scoped sessions),
/// or the enforcement store's own authority refusal for a 403; the shared "cannot confirm"
/// message or the enforcement write failure for a 503. A message outside that closed set
/// (notably the unassign route's 403 `self_admin_unassign_blocked`, a refusal about the request
/// after the gates passed, and any other 503 from a read after the gates) returns nullopt: the
/// persona then fails its `REQUIRE(classified)` instead of reading as kMayNot or kUnconfirmed.
std::optional<RbacAdminHint> classify(int status, const std::string& body) {
    if ((status >= 200 && status < 300) || status == 400 || status == 409)
        return RbacAdminHint::kMay; // the gates passed; the refusal (if any) is about the request
    const auto message = error_message_of(body);
    if (status == 403) {
        if (message == kRbacAdminGateDeniedMessage ||
            starts_with(message, "engine principals cannot access this endpoint") ||
            starts_with(message, "MCP tokens cannot perform admin operations") ||
            starts_with(message, "service-scoped tokens cannot") ||
            starts_with(message, "refused: caller does not currently hold"))
            return RbacAdminHint::kMayNot;
        return std::nullopt;
    }
    if (status == 503) {
        if (message == kRbacAdminGateUnavailableMessage ||
            message == "RBAC store write failed; retry shortly")
            return RbacAdminHint::kUnconfirmed;
        return std::nullopt;
    }
    return std::nullopt;
}

/// The MCP twin of `classify`, over the same closed set of refusal messages. A tool answers a
/// JSON-RPC `result` when it acted (kMay) or an `error` whose message names the gate that refused.
/// The enforcement tool's destination-guard refusal ("refused: ...", the REST route's 409) is an
/// answer about the request after the authority gates passed, so it is kMay, except the regime
/// refusal ("refused: caller does not currently hold ...") which IS an authority refusal. Any other
/// error (the empty-tier guard, the tier gate, a store fault) returns nullopt.
std::optional<RbacAdminHint> classify_mcp(const nlohmann::json& body) {
    if (body.contains("error")) {
        const std::string message = body["error"].value("message", "");
        if (message == kRbacAdminGateDeniedMessage ||
            starts_with(message, "refused: caller does not currently hold"))
            return RbacAdminHint::kMayNot;
        if (message == kRbacAdminGateUnavailableMessage ||
            message == "RBAC store write failed; retry shortly")
            return RbacAdminHint::kUnconfirmed;
        if (starts_with(message, "refused: "))
            return RbacAdminHint::kMay;
        return std::nullopt;
    }
    if (body.contains("result"))
        return RbacAdminHint::kMay;
    return std::nullopt;
}

const char* name_of(RbacAdminHint h) {
    switch (h) {
    case RbacAdminHint::kMay:
        return "kMay";
    case RbacAdminHint::kMayNot:
        return "kMayNot";
    case RbacAdminHint::kUnconfirmed:
        return "kUnconfirmed";
    }
    return "?";
}

/// The refusal's message and remediation, without the per-request correlation id: a stable,
/// remediable refusal answers byte-identically in these two fields every time.
std::string refusal_text(const std::string& body) {
    const auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.contains("error"))
        return body;
    return j["error"].value("message", "") + " | " + j["error"].value("remediation", "");
}

// The two destination-guard refusals, verbatim: `message | remediation` as the route answers them
// (rbac_admin_authority_owner.cpp's `refusal_message`, rest_api_v1.cpp's PUT enforcement
// `remediation`). Pinned whole so a reworded or dropped remediation is a deliberate edit here.
constexpr const char* kEnableRefusal =
    "refused: enabling RBAC enforcement would leave the caller with no fleet-wide Administrator "
    "grant; assign yourself Administrator first | POST /api/v1/rbac/roles/Administrator/"
    "assignments {\"principal_type\":\"user\",\"principal_id\":\"<your username>\"} (or MCP "
    "assign_rbac_role), then retry";
constexpr const char* kDisableRefusal =
    "refused: disabling RBAC enforcement would leave the caller without the local admin role that "
    "is the only durable administrator authority while enforcement is off | only a local account "
    "holding the admin role can disable enforcement; sign in as one, or have one set your local "
    "role via POST /api/settings/users/{username}/role, then retry";

RbacAdminHint hint_of(RbacRoleHarness& h) {
    return rbac_admin_hint(h.rest_session(), h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest);
}

/// A REAL AuditStore on the harness's database, counted by querying its table. The harness's own
/// `audit_log` is fed only by the REST audit_fn, which the hint never receives, so it can never
/// observe a hint-path write; this is the observation that could (the same rule
/// test_access_authz.cpp's last case follows). `rbac_admin_hint` is handed no audit hook and no
/// store writes `audit_store.audit_events` on its behalf, so "the count did not move" is only
/// evidence if the watch is shown to see a write: `write_marker` is that positive control (a known
/// write through a store on the same database), and every silence check calls it.
class AuditWatch {
public:
    explicit AuditWatch(RbacRoleHarness& h)
        : pool_{{.conninfo = h.auth_db.dsn(), .size = 1}}, store_{pool_} {
        REQUIRE(store_.is_open());
    }
    std::size_t rows() {
        AuditQuery q;
        q.limit = 100000;
        auto r = store_.query(q);
        REQUIRE(r.has_value());
        return r->size();
    }
    /// Writes one row through the watched store.
    bool write_marker() {
        AuditEvent e;
        e.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
        e.principal = "audit-watch-control";
        e.action = "test.audit_watch_control";
        e.target_type = "Test";
        e.target_id = "";
        e.result = "success";
        e.detail = "positive control";
        return store_.log(e);
    }

private:
    pg::PgPool pool_;
    AuditStore store_;
};

/// The hint wrote no audit row, and the watch is shown to be able to see one.
void check_hint_silent(AuditWatch& watch, std::size_t audits_before) {
    CHECK(watch.rows() == audits_before); // the hint path is silent (#5792)
    REQUIRE(watch.write_marker());        // positive control: the same watch sees a known write
    CHECK(watch.rows() == audits_before + 1);
}

/// The break-glass rename P13 uses: the regime check's auth.users JOIN cannot run, while the
/// predicate (principal_roles) still answers.
void make_regime_store_unreadable(RbacRoleHarness& h) {
    auto lease = h.auth_db.pool().acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(lease.get(), "ALTER TABLE auth.users RENAME TO users_hint_gone",
                             std::vector<std::string>{});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

/// A persona the hint calls kMay is held to the exact status its route answers, not to "any of
/// 2xx/400/409": a 400 or 409 from a gate the hint does not model would otherwise pass for
/// "authority admitted". `admitted_status` is mandatory for a kMay persona and ignored otherwise
/// (a refusal's status is already pinned by the closed message set in `classify`). No persona
/// below legitimately varies its admitted status.
void check_admitted_status(RbacAdminHint expected, int admitted_status, int actual) {
    if (expected != RbacAdminHint::kMay)
        return;
    REQUIRE(admitted_status != 0); // a kMay call site must name the status it expects
    CHECK(actual == admitted_status);
}

/// The hint equals the real POST assign answer, and the hint wrote no audit row.
void check_assign(RbacRoleHarness& h, RbacAdminHint expected, int admitted_status = 0) {
    AuditWatch watch{h};
    const auto audits_before = watch.rows();
    const auto hint = hint_of(h);
    check_hint_silent(watch, audits_before);
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);

    const auto res = h.assign_rest("Viewer", R"({"principal_type":"user","principal_id":"hint-target"})");
    REQUIRE(res);
    INFO("assign status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status, res->body);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
    check_admitted_status(expected, admitted_status, res->status);
}

/// The hint equals the real DELETE unassign answer. The target holds the grant first, so a
/// request that clears both gates succeeds (2xx) instead of answering 404, which is not an
/// authority answer and fails the classification loudly.
void check_unassign(RbacRoleHarness& h, RbacAdminHint expected, int admitted_status = 0) {
    REQUIRE(h.rbac->assign_role({"user", "hint-target", "Viewer"}).has_value());
    AuditWatch watch{h};
    const auto audits_before = watch.rows();
    const auto hint = hint_of(h);
    check_hint_silent(watch, audits_before);
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);

    const auto res = h.unassign_rest("Viewer", "hint-target");
    REQUIRE(res);
    INFO("unassign status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status, res->body);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
    check_admitted_status(expected, admitted_status, res->status);
}

/// The hint equals the real PUT enforcement answer for a REAL transition (`target` is the
/// opposite of the current state, so the idempotent no-op path never hides the gates).
void check_enforcement(RbacRoleHarness& h, RbacAdminHint expected, bool target,
                       int admitted_status = 0) {
    AuditWatch watch{h};
    const auto audits_before = watch.rows();
    const auto hint = hint_of(h);
    check_hint_silent(watch, audits_before);
    INFO("hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);
    const auto res = h.set_enforcement_rest(target);
    REQUIRE(res);
    INFO("enforcement status=" << res->status << " body=" << res->body);
    const auto classified = classify(res->status, res->body);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
    check_admitted_status(expected, admitted_status, res->status);
}

void make_user(RbacRoleHarness& h, const std::string& name, auth::Role role) {
    REQUIRE(h.auth_db->upsert_user(name, "hash", "salt", role).has_value());
}

template <typename S>
concept HintCallableWithoutSurface =
    requires(S s) { rbac_admin_hint(s, static_cast<AuthDB*>(nullptr), static_cast<const RbacStore*>(nullptr)); };

} // namespace

// The surface parameter has NO default, exactly like the predicate it folds.
static_assert(!HintCallableWithoutSurface<const auth::Session&>,
              "rbac_admin_hint must force every caller to name its surface");

// ── Route-level equality, POST assign ───────────────────────────────────────

TEST_CASE("rbac_admin_hint == POST assign: base admin, RBAC off (P1)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    check_assign(h, RbacAdminHint::kMay, /*admitted_status=*/201);
}

TEST_CASE("rbac_admin_hint == POST assign: base admin with NO Administrator grant, RBAC on (P2)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_assign(h, RbacAdminHint::kMayNot); // the old base-role hint drew the button here
}

TEST_CASE("rbac_admin_hint == POST assign: base admin WITH the Administrator grant, RBAC on (P3)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_assign(h, RbacAdminHint::kMay, /*admitted_status=*/201);
}

TEST_CASE("rbac_admin_hint == POST assign: base user WITH the Administrator grant and an active row, RBAC on (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true); // role=user + grant + active auth.users row
    check_assign(h, RbacAdminHint::kMay,
                 /*admitted_status=*/201); // the #6034 headline: the old hint drew nothing
}

TEST_CASE("rbac_admin_hint == POST assign: Administrator grant is inert while RBAC is off (P5)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: base user holding a non-administrator role, RBAC on (P6)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Viewer"}).has_value());
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: SSO principal with the grant but NO auth.users row (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    // The predicate admits (bare principal_roles membership); the regime check needs an active
    // auth.users row, so the route refuses. A predicate-only hint would overstate here.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: SSO-labelled principal WITH a break-glass active row (P7b)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "sso-breakglass";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::user); // the documented SQL-provisioned row
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_assign(h, RbacAdminHint::kMay, /*admitted_status=*/201);
}

TEST_CASE("rbac_admin_hint == POST assign: SAML principal with the grant but NO auth.users row (P7c)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "saml:https://idp.example#alice";
    h.session_auth_source = "saml";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());

    // The SAML twin of P7: `saml:<idp>#<NameID>` can never be an auth.users name
    // (`is_valid_username` refuses ':' and '#'), so the regime check refuses and the hint is
    // kMayNot although the predicate admits. This pins the hint only: a SAML session is also
    // refused earlier by the MFA step-up chokepoint (#4935), which runs before the route
    // handler and is not part of the hint.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: durable demotion after sign-in, RBAC off (P14)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::admin);
    {
        // upsert_user refuses to demote an account (#4966); break-glass SQL stands in for the
        // demotion that landed after this session was minted.
        auto lease = h.auth_db.pool().acquire();
        REQUIRE(lease);
        auto r = pg::exec_params(lease.get(), "UPDATE auth.users SET role = 'user' WHERE username = $1",
                                 std::vector<std::string>{h.session_user});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    check_assign(h, RbacAdminHint::kMayNot); // the durable row is re-read, never the session
}

TEST_CASE("rbac_admin_hint == POST assign: a principal with no auth.users row at all, RBAC off",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    check_assign(h, RbacAdminHint::kMayNot);
}

// DELETE unassign calls the same two authority functions in the same order as POST assign
// (rest_api_v1.cpp), but through its own handler, so its sequence is pinned on its own.
TEST_CASE("rbac_admin_hint == DELETE unassign: base user WITH the Administrator grant, RBAC on (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    check_unassign(h, RbacAdminHint::kMay, /*admitted_status=*/200);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: SSO principal with the grant but NO auth.users row (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    // Past the predicate, refused by the regime check: the second gate of the DELETE handler.
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: MCP-tier token on the REST surface (P9)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.rest_session_mcp_tier = "supervised";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: service-scoped token (P10)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "payments";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: engine session (P11)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_principal_kind = "engine";
    check_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == POST assign: plain API-token session of an administrator (P12)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_auth_source = "api_token"; // no tier, unscoped: the gates never read auth_source
    check_assign(h, RbacAdminHint::kMay, /*admitted_status=*/201);
}

TEST_CASE("rbac_admin_hint == POST assign: regime store unreadable, RBAC on (P13)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    // The predicate (principal_roles) still answers kAdmin; the regime check's auth.users JOIN
    // cannot run. A hint that skipped the regime check would say kMay here, the route says 503.
    make_regime_store_unreadable(h);
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    check_assign(h, RbacAdminHint::kUnconfirmed);
}

// ── Route-level equality, PUT enforcement (real transitions only) ────────────

TEST_CASE("rbac_admin_hint == PUT enforcement: durable admin holding the grant, RBAC off -> on (P1)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/true, /*admitted_status=*/200);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base admin with NO grant, RBAC on (P2)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base admin with the grant, RBAC on -> off (P3)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/false, /*admitted_status=*/200);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base user with the grant, RBAC on -> off (P4)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    // Authority is admitted; the destination guard then answers 409 every time (the caller would
    // not remain a local admin, see the CHARACTERISATION cases), which classifies as admitted, not
    // as a refusal of authority, and is pinned as the exact status.
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/false, /*admitted_status=*/409);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: SSO principal with the grant and no row, RBAC on (P7)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.session_user = "oidc:https://idp.example#sub-1";
    h.session_auth_source = "oidc";
    h.rbac->set_rbac_enabled(true);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false); // the store's source check
}

TEST_CASE("rbac_admin_hint == PUT enforcement: engine session (P11)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.session_principal_kind = "engine";
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
}

// ── The MCP surface (kMcp): the hint equals the real assign_rbac_role answer ──────────────────
//
// The hint's `kMcp` branch has no production caller yet, so it is pinned here against the real MCP
// tool, called through the harness's ticket-then-recall dance with the harness's MCP session (its
// `session_mcp_tier`, which `is_rbac_administrator(..., kMcp)` does not consult). The tool answers
// with a result when it assigned the role (kMay), or a JSON-RPC error whose message is the shared
// gate wording (kMayNot / kUnconfirmed).

namespace {
/// Whether the target holds no grant, read through the CHECKED variant: `get_principal_roles`
/// answers an empty list on a failed read, which would let a "no grant happened" probe pass
/// vacuously. A failed read fails the test here instead.
bool target_roles_empty(RbacRoleHarness& h) {
    const auto roles = h.rbac->get_principal_roles_checked("user", "hint-target");
    INFO("get_principal_roles_checked: " << (roles ? "ok" : roles.error()));
    REQUIRE(roles.has_value());
    return roles->empty();
}

/// The kMcp hint for the harness's MCP session, the silence check around it, and the real tool's
/// classified answer (ticket-then-recall through the harness). Returns what the tool answered so
/// the caller can check the side effect that tool owns.
RbacAdminHint check_mcp_tool(RbacRoleHarness& h, RbacAdminHint expected, const char* tool,
                             const nlohmann::json& args) {
    AuditWatch watch{h};
    const auto audits_before = watch.rows();
    const auto hint = rbac_admin_hint(h.session_with_tier(h.session_mcp_tier), h.auth_db.get(),
                                      h.rbac.get(), RbacAdminSurface::kMcp);
    check_hint_silent(watch, audits_before);
    INFO(tool << " hint=" << name_of(hint) << " expected=" << name_of(expected));
    CHECK(hint == expected);

    const auto res = h.mcp_call_tool_approved(tool, args);
    REQUIRE(res);
    INFO("mcp body=" << res->body);
    const auto body = nlohmann::json::parse(res->body, nullptr, /*allow_exceptions=*/false);
    REQUIRE_FALSE(body.is_discarded());
    const auto classified = classify_mcp(body);
    REQUIRE(classified.has_value());
    CHECK(*classified == hint);
    return *classified;
}

void check_mcp_assign(RbacRoleHarness& h, RbacAdminHint expected) {
    const auto answered = check_mcp_tool(
        h, expected, "assign_rbac_role",
        {{"principal_type", "user"}, {"principal_id", "hint-target"}, {"role", "Viewer"}});
    // The side effect agrees: only an admitted caller's assignment happened.
    CHECK(target_roles_empty(h) == (answered != RbacAdminHint::kMay));
}

/// The target holds the grant first, so an admitted request removes it (a request that clears
/// both gates but names a missing grant would answer an error that is not an authority answer).
void check_mcp_unassign(RbacRoleHarness& h, RbacAdminHint expected) {
    REQUIRE(h.rbac->assign_role({"user", "hint-target", "Viewer"}).has_value());
    const auto answered = check_mcp_tool(h, expected, "unassign_rbac_role",
                                         {{"principal_id", "hint-target"}, {"role", "Viewer"}});
    CHECK(target_roles_empty(h) == (answered == RbacAdminHint::kMay));
}

/// `target` is the opposite of the current state, so the idempotent no-op never hides the gates.
/// Every persona below that expects kMay can really transition, so the state must move exactly
/// when the caller was admitted.
void check_mcp_enforcement(RbacRoleHarness& h, RbacAdminHint expected, bool target) {
    const bool before = h.rbac->is_rbac_enabled();
    REQUIRE(before != target);
    const auto answered =
        check_mcp_tool(h, expected, "set_rbac_enforcement", {{"enabled", target}});
    CHECK(h.rbac->is_rbac_enabled() == (answered == RbacAdminHint::kMay ? target : before));
}
} // namespace

TEST_CASE("rbac_admin_hint (kMcp) == MCP assign_rbac_role: base user WITH the Administrator grant, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    check_mcp_assign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint (kMcp) == MCP assign_rbac_role: base admin with NO grant, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_mcp_assign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint (kMcp) == MCP assign_rbac_role: regime store unreadable, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    check_mcp_assign(h, RbacAdminHint::kUnconfirmed);
}

// The unassign and enforcement twins are reached through the same harness path. Not modelled, on
// purpose: the empty-mcp_tier personas. Both tools deny an empty tier AFTER the authority gate
// with a message of their own (not one of the gate's), and the hint folds authority only; the
// harness's `session_mcp_tier` is "supervised" for every case here so the tier ladder is not what
// is under test. Also unmodelled: the gate being unavailable on the FIRST read (the predicate), as
// opposed to the regime read: the regime persona below covers the 503 shape, and no case here
// builds a store that fails the predicate's read while the regime read still works.

TEST_CASE("rbac_admin_hint (kMcp) == MCP unassign_rbac_role: base user WITH the Administrator "
          "grant, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    check_mcp_unassign(h, RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint (kMcp) == MCP unassign_rbac_role: base admin with NO grant, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_mcp_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint (kMcp) == MCP unassign_rbac_role: regime store unreadable, RBAC on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    check_mcp_unassign(h, RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint (kMcp) == MCP set_rbac_enforcement: durable admin holding the grant, "
          "RBAC off -> on",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_mcp_enforcement(h, RbacAdminHint::kMay, /*target=*/true);
}

TEST_CASE(
    "rbac_admin_hint (kMcp) == MCP set_rbac_enforcement: base admin with NO grant, RBAC on -> off",
    "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    check_mcp_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false);
}

// The ON -> OFF kMay twin of REST P3: a base admin WITH the grant really transitions. The REST P4
// persona (base USER with the grant) has no MCP twin on purpose: its destination guard refuses
// with a 409 for a caller who is not a local admin, so the state never moves, and
// `check_mcp_enforcement` asserts that an admitted caller's state moves to `target`.
TEST_CASE("rbac_admin_hint (kMcp) == MCP set_rbac_enforcement: base admin with the grant, RBAC on "
          "-> off",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::admin);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    check_mcp_enforcement(h, RbacAdminHint::kMay, /*target=*/false);
}

TEST_CASE(
    "rbac_admin_hint (kMcp) == MCP set_rbac_enforcement: regime store unreadable, RBAC on -> off",
    "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    check_mcp_enforcement(h, RbacAdminHint::kUnconfirmed, /*target=*/false);
}

// ── More personas on the PUT and DELETE routes (qe-2) ────────────────────────

TEST_CASE("rbac_admin_hint == PUT enforcement: regime store unreadable, RBAC on (P13)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    REQUIRE(is_rbac_administrator(h.rest_session(), h.auth_db.get(), h.rbac.get(),
                                  RbacAdminSurface::kRest) == RbacAdminGate::kAdmin);
    // The route answers 503 (set_enforcement cannot read the source regime); a hint that skipped
    // the regime check would say kMay.
    check_enforcement(h, RbacAdminHint::kUnconfirmed, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: the Administrator grant is inert while RBAC is off (P5)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: base user holding a non-administrator role, RBAC on (P6)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.rbac->set_rbac_enabled(true);
    make_user(h, h.session_user, auth::Role::user);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Viewer"}).has_value());
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/false);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: MCP-tier token on the REST surface (P9)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.rest_session_mcp_tier = "supervised";
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: service-scoped token (P10)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.session_token_scope_service = "payments";
    check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
}

TEST_CASE("rbac_admin_hint == PUT enforcement: plain API-token session of an administrator (P12)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    h.session_auth_source = "api_token";
    check_enforcement(h, RbacAdminHint::kMay, /*target=*/true, /*admitted_status=*/200);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: MCP-tier token on the REST surface (P9)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.rest_session_mcp_tier = "supervised";
    check_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: service-scoped token (P10)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_token_scope_service = "payments";
    check_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: engine session (P11)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/false);
    h.session_principal_kind = "engine";
    check_unassign(h, RbacAdminHint::kMayNot);
}

TEST_CASE("rbac_admin_hint == DELETE unassign: regime store unreadable, RBAC on (P13)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true);
    make_regime_store_unreadable(h);
    check_unassign(h, RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint == the routes: an administrator whose account was deactivated after sign-in, "
          "RBAC off",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    // The predicate and the regime check read the same `role = 'admin' AND is_active` population,
    // so a persona the predicate admits and the regime check refuses under RBAC off cannot be
    // built from stored state; this is the nearest one, and it pins that the hint re-reads the
    // live row (the session still says admin) on every route.
    for (const char* route : {"assign", "unassign", "enforcement"}) {
        INFO(route);
        RbacRoleHarness h;
        make_user(h, h.session_user, auth::Role::admin);
        {
            auto lease = h.auth_db.pool().acquire();
            REQUIRE(lease);
            auto r = pg::exec_params(lease.get(), "UPDATE auth.users SET is_active = FALSE WHERE username = $1",
                                     std::vector<std::string>{h.session_user});
            REQUIRE(r.status() == PGRES_COMMAND_OK);
        }
        if (std::string_view{route} == "assign")
            check_assign(h, RbacAdminHint::kMayNot);
        else if (std::string_view{route} == "unassign")
            check_unassign(h, RbacAdminHint::kMayNot);
        else
            check_enforcement(h, RbacAdminHint::kMayNot, /*target=*/true);
    }
}

// ── CHARACTERISATION: a live switch the destination guard always refuses (sec-3 / hp-1) ────────
//
// The hint models AUTHORITY only (the predicate, then the regime check). The enforcement route
// can still answer 409 from the DESTINATION guard (the caller would not remain an administrator
// under the new regime). Two personas draw a live switch that is refused every time. This is the
// documented decision (rbac.md "Why is a control disabled or missing?"): the hint is not changed,
// the refusal is shown with its remediation text, and nothing changes state. These tests pin the
// residual so that a later fix flips them knowingly instead of silently.

TEST_CASE("rbac_admin_hint CHARACTERISATION: RBAC off, a local administrator with NO Administrator "
          "grant is drawn the switch, and enabling is refused 409 every time",
          "[pg][rbac_admin_predicate][rbac_admin_hint][characterisation]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::admin); // RBAC off, no grant
    REQUIRE_FALSE(h.rbac->is_rbac_enabled());
    CHECK(hint_of(h) == RbacAdminHint::kMay);
    std::string first_body;
    for (int i = 0; i < 5; ++i) {
        const auto res = h.set_enforcement_rest(true);
        REQUIRE(res);
        INFO("attempt " << i << " status=" << res->status << " body=" << res->body);
        CHECK(res->status == 409);
        if (i == 0)
            first_body = refusal_text(res->body);
        CHECK(refusal_text(res->body) == first_body); // a stable, remediable refusal
        CHECK_FALSE(h.rbac->is_rbac_enabled()); // nothing changed
    }
    CHECK(first_body == kEnableRefusal); // the full message and remediation, not a fragment
}

TEST_CASE("rbac_admin_hint CHARACTERISATION: RBAC on, a base-user Administrator-grant holder is drawn "
          "the switch, and disabling is refused 409 every time",
          "[pg][rbac_admin_predicate][rbac_admin_hint][characterisation]") {
    RbacRoleHarness h;
    h.make_caller_admin(/*rbac_on=*/true); // role=user + grant + active row
    REQUIRE(h.rbac->is_rbac_enabled());
    CHECK(hint_of(h) == RbacAdminHint::kMay);
    std::string first_body;
    for (int i = 0; i < 5; ++i) {
        const auto res = h.set_enforcement_rest(false);
        REQUIRE(res);
        INFO("attempt " << i << " status=" << res->status << " body=" << res->body);
        CHECK(res->status == 409);
        if (i == 0)
            first_body = refusal_text(res->body);
        CHECK(refusal_text(res->body) == first_body);
        CHECK(h.rbac->is_rbac_enabled()); // nothing changed
    }
    CHECK(first_body == kDisableRefusal); // the full message and remediation, not a fragment
}

// ── The classifier itself ────────────────────────────────────────────────────

namespace {
std::string a4_body(int code, const std::string& message) {
    return nlohmann::json{{"error", {{"code", code}, {"message", message}}}}.dump();
}
} // namespace

TEST_CASE("rbac_admin_hint classify: a refusal counts as an authority answer only from a modelled gate",
          "[rbac_admin_predicate][rbac_admin_hint]") {
    // The shared gate refusals classify as before.
    CHECK(classify(403, a4_body(403, std::string(kRbacAdminGateDeniedMessage))) == RbacAdminHint::kMayNot);
    CHECK(classify(503, a4_body(503, std::string(kRbacAdminGateUnavailableMessage))) ==
          RbacAdminHint::kUnconfirmed);
    CHECK(classify(409, a4_body(409, "anything")) == RbacAdminHint::kMay);
    // A 403 from a gate the hint does not model is NOT kMayNot: the unassign route's post-gate
    // self-removal refusal, and a 403 from somewhere else entirely.
    CHECK_FALSE(classify(403, a4_body(403, "cannot remove your own Administrator role assignment"))
                    .has_value());
    CHECK_FALSE(classify(403, a4_body(403, "cross-site request refused")).has_value());
    CHECK_FALSE(classify(403, "not json").has_value());
    // Likewise a 503 that is not the authority gate's "cannot confirm".
    CHECK_FALSE(classify(503, a4_body(503, "RBAC store read failed")).has_value());
    CHECK_FALSE(classify(500, a4_body(500, "boom")).has_value());
}

TEST_CASE("rbac_admin_hint classify: every arm of the closed refusal set classifies, each by its "
          "production text, and a near miss does not",
          "[rbac_admin_predicate][rbac_admin_hint]") {
    // The texts below are the routes' own (rest_api_v1.cpp:317/357/7915/8261/8444, matched by
    // prefix where the route appends detail; rbac_admin_authority_owner.cpp:594/607), so a dead arm
    // in `classify` is a failure here and not a silent pass for a persona that happens to hit
    // another arm.
    const char* const kMayNotTexts[] = {
        "engine principals cannot access this endpoint",
        "MCP tokens cannot perform admin operations; use the MCP tool assign_rbac_role instead",
        "service-scoped tokens cannot manage RBAC role assignments",
        "service-scoped tokens cannot change RBAC enforcement",
        "refused: caller does not currently hold a fleet-wide Administrator grant, required to "
        "change "
        "enforcement while it is on",
        "refused: caller does not currently hold the local admin role, required to change "
        "enforcement "
        "while it is off",
    };
    for (const char* text : kMayNotTexts) {
        INFO(text);
        CHECK(classify(403, a4_body(403, text)) == RbacAdminHint::kMayNot);
        // The same text on any other status is not an authority answer of that kind.
        CHECK_FALSE(classify(500, a4_body(500, text)).has_value());
    }
    // The 503 arms: the shared "cannot confirm" and the enforcement write failure.
    CHECK(classify(503, a4_body(503, "RBAC store write failed; retry shortly")) ==
          RbacAdminHint::kUnconfirmed);
    // A 403 text is not accepted on a 503, nor the reverse.
    CHECK_FALSE(
        classify(503, a4_body(503, "engine principals cannot access this endpoint")).has_value());
    CHECK_FALSE(classify(403, a4_body(403, "RBAC store write failed; retry shortly")).has_value());
    // Near misses: a prefix that is not the closed text, and the post-gate self-removal refusal.
    CHECK_FALSE(classify(403, a4_body(403, "refused: caller is not an administrator")).has_value());
    CHECK_FALSE(classify(403, a4_body(403, "engine principals cannot")).has_value());
    CHECK_FALSE(classify(403, a4_body(403, "self_admin_unassign_blocked")).has_value());
    CHECK_FALSE(classify(403, a4_body(403, "cannot remove your own Administrator role assignment"))
                    .has_value());
}

TEST_CASE("rbac_admin_hint classify_mcp: the tool answers classify by the same closed set",
          "[rbac_admin_predicate][rbac_admin_hint]") {
    const auto err = [](const std::string& message) {
        return nlohmann::json{{"error", {{"code", 1}, {"message", message}}}};
    };
    CHECK(classify_mcp({{"result", {{"ok", true}}}}) == RbacAdminHint::kMay);
    CHECK(classify_mcp(err(std::string(kRbacAdminGateDeniedMessage))) == RbacAdminHint::kMayNot);
    CHECK(classify_mcp(
              err("refused: caller does not currently hold a fleet-wide Administrator grant")) ==
          RbacAdminHint::kMayNot);
    CHECK(classify_mcp(err(std::string(kRbacAdminGateUnavailableMessage))) ==
          RbacAdminHint::kUnconfirmed);
    CHECK(classify_mcp(err("RBAC store write failed; retry shortly")) ==
          RbacAdminHint::kUnconfirmed);
    // The destination guard's refusal is about the request, after the authority gates passed.
    CHECK(classify_mcp(err("refused: enabling RBAC enforcement would leave the caller with no "
                           "fleet-wide Administrator grant")) == RbacAdminHint::kMay);
    // Anything else, including the tool's empty-tier guard and the self-removal refusal, is not an
    // authority answer.
    CHECK_FALSE(
        classify_mcp(err("set_rbac_enforcement requires an MCP-tier bearer token")).has_value());
    CHECK_FALSE(
        classify_mcp(err("cannot remove your own Administrator role assignment")).has_value());
    CHECK_FALSE(classify_mcp(nlohmann::json::object()).has_value());
}

// ── The fold itself ──────────────────────────────────────────────────────────

TEST_CASE("rbac_admin_hint: structural denies need no store",
          "[rbac_admin_predicate][rbac_admin_hint]") {
    auth::Session engine;
    engine.username = "e";
    engine.principal_kind = "engine";
    auth::Session scoped;
    scoped.username = "s";
    scoped.token_scope_service = "payments";
    auth::Session tiered;
    tiered.username = "t";
    tiered.mcp_tier = "readonly";
    for (const auto* s : {&engine, &scoped, &tiered}) {
        INFO(s->username);
        CHECK(rbac_admin_hint(*s, nullptr, nullptr, RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);
    }
    // The MCP surface applies no tier rule: with no store it cannot decide, never kMayNot.
    CHECK(rbac_admin_hint(tiered, nullptr, nullptr, RbacAdminSurface::kMcp) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: a null RbacStore is kUnconfirmed", "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    yuzu::test::AuthDbPg auth_db;
    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, auth_db.get(), nullptr, RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: RBAC off with a null AuthDB is kUnconfirmed",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    yuzu::test::RbacStorePg rbac;
    REQUIRE_FALSE(rbac->is_rbac_enabled());
    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, nullptr, rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}

TEST_CASE("rbac_admin_hint: a session elevated to admin is still kMayNot without a durable grant (P8)",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    RbacRoleHarness h;
    make_user(h, h.session_user, auth::Role::user);
    auto s = h.rest_session();
    s.role = auth::Role::admin; // the effective role a JIT elevation produces
    s.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
    s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);

    // RBAC on: still no durable grant, still kMayNot.
    h.rbac->set_rbac_enabled(true);
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMayNot);

    // The grant, not the elevation, is what admits (P8b).
    REQUIRE(h.rbac->assign_role({"user", h.session_user, "Administrator"}).has_value());
    CHECK(rbac_admin_hint(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest) == RbacAdminHint::kMay);
}

TEST_CASE("rbac_admin_hint: the predicate's DEGRADED enforcement view folds to kUnconfirmed, not kMayNot",
          "[pg][rbac_admin_predicate][rbac_admin_hint]") {
    // Same construction as test_rbac_admin_predicate.cpp's degraded-view case: a replica whose
    // pool is starved past the stale-serve bound reads the enabled flag as degraded.
    yuzu::test::RbacStorePg rbac;
    yuzu::test::AuthDbPg auth_db;
    yuzu::server::pg::PgPool pool_b{{.conninfo = rbac.dsn(), .size = 1}};
    REQUIRE(pool_b.valid());
    RbacStore replica_b{pool_b};
    REQUIRE(replica_b.is_open());
    replica_b.age_refresh_state_for_test(std::chrono::milliseconds(1100));
    auto held = pool_b.acquire();
    REQUIRE(held);
    CHECK_FALSE(rbac_enforcement_in_effect(&replica_b));
    replica_b.age_refresh_state_for_test(std::chrono::milliseconds(4200));
    REQUIRE(rbac_enforcement_in_effect(&replica_b));
    REQUIRE(rbac_enforcement_label(&replica_b) == RbacEnforcementLabel::kDegraded);
    held.reset();

    auth::Session s;
    s.username = "whoever";
    CHECK(rbac_admin_hint(s, auth_db.get(), &replica_b, RbacAdminSurface::kRest) == RbacAdminHint::kUnconfirmed);
}
