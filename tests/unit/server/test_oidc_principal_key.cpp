/**
 * test_oidc_principal_key.cpp — Unit tests for #1837: OIDC session principal
 * keyed on stable `iss`+`sub`, not the mutable display name.
 *
 * Covers: AuthManager::create_oidc_session stable-username construction and
 * RbacStore::reconcile_idp_memberships keyed on the stable principal shape
 * (`oidc:<iss>#<sub>`). Also covers the #1837 hardening-round sanitisation of
 * IdP-supplied `display`/`email` values before they reach an audit `detail`
 * string (detail::sanitize_detail_value in auth_routes.hpp).
 *
 * (The RbacStore v2 -> v3 SQLite migration test that used to live here was
 * removed when RbacStore moved to PostgreSQL — RbacStore no longer runs
 * SQLite schema migrations; the reconcile-on-stable-key behaviour it
 * exercised is covered by the cases in this file and test_rbac_store.cpp.)
 */

#include <yuzu/server/auth.hpp>

#include "auth_routes.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server::auth;
using yuzu::server::RbacStore;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {
// Pre-migrated + seeded template (RbacStore construction runs the migration AND
// seed_defaults). Every store-behaviour case clones this instead of
// re-migrating/re-seeding per test (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rbac_tpl{"rbacstore", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        RbacStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "rbac template: store failed to migrate/seed");
                                    }};
} // namespace

// ── AuthManager::create_oidc_session — stable principal ─────────────────────

TEST_CASE("AuthManager: two OIDC logins with same display name but different "
         "sub get distinct stable usernames, and roles do not leak between them",
         "[auth][oidc][1837][pg]") {
    AuthManager mgr;
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());

    const std::string iss = "https://idp.example.com/";
    // Same display name deliberately — this is exactly the collision #1837
    // fixes: two different humans (or one IdP account renamed onto
    // another's old name) sharing a display label must never collide onto
    // one authorization principal.
    auto token_a = mgr.create_oidc_session("Alex Kim", "alex.k@corp.example", "sub-AAA", iss);
    auto token_b = mgr.create_oidc_session("Alex Kim", "alex.kim2@corp.example", "sub-BBB", iss);

    auto sess_a = mgr.validate_session(token_a);
    auto sess_b = mgr.validate_session(token_b);
    REQUIRE(sess_a.has_value());
    REQUIRE(sess_b.has_value());

    CHECK(sess_a->username == "oidc:" + iss + "#sub-AAA");
    CHECK(sess_b->username == "oidc:" + iss + "#sub-BBB");
    CHECK(sess_a->username != sess_b->username);
    // Display name is the same (as configured), but lives in a separate
    // field that is never consulted for authorization.
    CHECK(sess_a->display_name == "Alex Kim");
    CHECK(sess_b->display_name == "Alex Kim");

    // Mirror the OIDC callback's reconcile step: only subject A is asserted
    // as a member of the IdP "admins" group.
    auto reconciled = rbac.reconcile_idp_memberships(sess_a->username, "entra",
                                                     {{"admins-gid", "Admins"}});
    REQUIRE(reconciled.has_value());
    REQUIRE(rbac.assign_role({"group", "entra:admins-gid", "Administrator"}).has_value());

    // Distinct group_members rows: only A is a member.
    auto members = rbac.get_group_members("entra:admins-gid");
    REQUIRE(members.size() == 1);
    CHECK(members[0] == sess_a->username);

    // check_permission for B must NOT return A's roles — the headline
    // regression this ticket exists to close.
    CHECK(rbac.check_permission(sess_a->username, "Infrastructure", "Write"));
    CHECK_FALSE(rbac.check_permission(sess_b->username, "Infrastructure", "Write"));
}

TEST_CASE("AuthManager: OIDC rename (same sub, changed name) keeps the stable "
         "username stable and updates the minted session's display_name",
         "[auth][oidc][1837][pg]") {
    AuthManager mgr;
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());
    const std::string iss = "https://idp.example.com/";

    auto token1 = mgr.create_oidc_session("Pat Original", "pat@corp.example", "sub-PAT", iss);
    auto sess1 = mgr.validate_session(token1);
    REQUIRE(sess1.has_value());
    const std::string stable_username = sess1->username;

    // Grant via reconcile before the rename.
    auto reconciled1 =
        rbac.reconcile_idp_memberships(stable_username, "entra", {{"eng-gid", "Engineering"}});
    REQUIRE(reconciled1.has_value());
    CHECK(reconciled1->added == 1);

    // Same sub, changed display name and email (legal name change / IdP
    // profile update) — simulates a second login.
    auto token2 = mgr.create_oidc_session("Pat Renamed", "pat.renamed@corp.example", "sub-PAT", iss);
    auto sess2 = mgr.validate_session(token2);
    REQUIRE(sess2.has_value());

    // Stable username is UNCHANGED across the rename.
    CHECK(sess2->username == stable_username);
    CHECK(sess2->display_name == "Pat Renamed");
    CHECK(sess2->display_name != sess1->display_name);

    // Membership survives the rename because it was keyed on the stable id.
    auto reconciled2 =
        rbac.reconcile_idp_memberships(stable_username, "entra", {{"eng-gid", "Engineering"}});
    REQUIRE(reconciled2.has_value());
    CHECK(reconciled2->added == 0); // idempotent — no-op re-assertion
    CHECK(reconciled2->removed == 0);
    CHECK(rbac.get_group_members("entra:eng-gid") == std::vector<std::string>{stable_username});

    // The freshly-minted session's display_name reflects the LATEST login's
    // display/email (already asserted above via sess2), never the map that
    // used to exist for this purpose — there is no persistent principal→name
    // directory (see #1852); a human name for a principal with no live
    // session is recovered from that login's SSO audit row `display=`/
    // `email=` detail instead (auth_routes.cpp /auth/callback).
    CHECK(sess2->display_name == "Pat Renamed");
}

TEST_CASE("AuthManager: reconcile add/remove/deprovision fires correctly "
         "keyed on the oidc:<iss>#<sub> principal shape",
         "[auth][oidc][1837][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());
    const std::string principal = "oidc:https://idp.example.com/#sub-DEPROV";

    // Add.
    auto added = rbac.reconcile_idp_memberships(principal, "entra",
                                                {{"g1", "G1"}, {"g2", "G2"}});
    REQUIRE(added.has_value());
    CHECK(added->added == 2);
    CHECK(added->removed == 0);
    CHECK(rbac.get_group_members("entra:g1") == std::vector<std::string>{principal});
    CHECK(rbac.get_group_members("entra:g2") == std::vector<std::string>{principal});

    // Remove one (IdP-side membership shrinks).
    auto removed = rbac.reconcile_idp_memberships(principal, "entra", {{"g1", "G1"}});
    REQUIRE(removed.has_value());
    CHECK(removed->added == 0);
    CHECK(removed->removed == 1);
    CHECK(rbac.get_group_members("entra:g1") == std::vector<std::string>{principal});
    CHECK(rbac.get_group_members("entra:g2").empty());

    // Full deprovision (IdP asserts zero groups on next login).
    auto deprovisioned = rbac.reconcile_idp_memberships(principal, "entra", {});
    REQUIRE(deprovisioned.has_value());
    CHECK(deprovisioned->removed == 1);
    CHECK(rbac.get_group_members("entra:g1").empty());
}

// ── detail::sanitize_detail_value — IdP-supplied detail-field sanitisation ──
//
// #1837 hardening round: `/auth/callback` concatenates the IdP-supplied
// `display`/`email` claims (and claims.sub/claims.name for emit_event) into
// an audit `detail` string / analytics JSON attribute. A hostile or
// misconfigured IdP, or a user-set display name, is not trusted input —
// these tests assert no raw delimiter, newline, or control byte survives
// into the sanitised output.

TEST_CASE("sanitize_detail_value: strips ';' and '=' delimiters that would "
         "forge additional k=v fields in a flat audit detail string",
         "[auth][oidc][1837][sanitize]") {
    // A malicious display name attempting to inject a fake second field.
    auto out = yuzu::server::detail::sanitize_detail_value(
        "Alex Kim;role=admin=true");
    CHECK(out.find(';') == std::string::npos);
    CHECK(out.find('=') == std::string::npos);
    CHECK(out == "Alex Kim_role_admin_true");
}

TEST_CASE("sanitize_detail_value: strips embedded newlines (log-line injection)",
         "[auth][oidc][1837][sanitize]") {
    auto out = yuzu::server::detail::sanitize_detail_value(
        "evil\r\naction=auth.privilege_escalation;result=ok");
    CHECK(out.find('\r') == std::string::npos);
    CHECK(out.find('\n') == std::string::npos);
    // The embedded ';' and '=' from the forged second "action=" line are
    // also stripped, so the whole payload can't reconstitute a fake row.
    CHECK(out.find(';') == std::string::npos);
    CHECK(out.find('=') == std::string::npos);
}

TEST_CASE("sanitize_detail_value: strips other control bytes incl. DEL, "
         "leaves ordinary printable text untouched",
         "[auth][oidc][1837][sanitize]") {
    std::string in = "Alex";
    in.push_back('\t');   // control byte (0x09)
    in += "Kim";
    in.push_back('\x7F'); // DEL
    in += "!";
    auto out = yuzu::server::detail::sanitize_detail_value(in);
    CHECK(out == "Alex_Kim_!");

    // Ordinary display names / emails pass through unchanged.
    CHECK(yuzu::server::detail::sanitize_detail_value("alex.kim@corp.example") ==
         "alex.kim@corp.example");
    CHECK(yuzu::server::detail::sanitize_detail_value("Alex Kim") == "Alex Kim");
}

TEST_CASE("sanitize_detail_value: caps length at a UTF-8 code-point boundary",
         "[auth][oidc][1837][sanitize]") {
    // An over-long ASCII value is truncated to exactly the cap.
    std::string long_ascii(500, 'a');
    auto out_ascii = yuzu::server::detail::sanitize_detail_value(long_ascii);
    CHECK(out_ascii.size() == 128);

    // A value whose truncation point would otherwise land mid-UTF-8-sequence
    // is backed up to the preceding code-point boundary rather than
    // emitting a malformed trailing byte sequence.
    std::string multibyte(127, 'a');
    multibyte += "\xE2\x82\xAC"; // U+20AC EURO SIGN (3 bytes), lands at 127-129
    auto out_multibyte = yuzu::server::detail::sanitize_detail_value(multibyte);
    CHECK(out_multibyte.size() <= 128);
    // No dangling continuation byte at the very end.
    CHECK((static_cast<unsigned char>(out_multibyte.back()) & 0xC0) != 0x80);
}

TEST_CASE("sanitize_detail_value: an empty input yields an empty output",
         "[auth][oidc][1837][sanitize]") {
    CHECK(yuzu::server::detail::sanitize_detail_value("").empty());
}
