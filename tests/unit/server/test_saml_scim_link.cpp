/**
 * test_saml_scim_link.cpp — Unit tests for `link_saml_login_to_scim` and
 * `is_linkable_name_id_format` (ADR-2001 PR4a), the SAML analogue of
 * `test_oidc_scim_link.cpp` — the login-site orchestration extracted out of
 * the `/saml/acs` handler (`auth_routes.cpp`) into `saml_scim_link.{hpp,cpp}`
 * so it is directly testable against a real `ScimStore` without a live IdP.
 *
 * Covers the ADR-2001 PR4a spec's link-formation contract: exactly-one
 * active match forms the link, zero/more-than-one match forms none (with a
 * mutation-check that the strict lookup wasn't quietly widened back to
 * LIMIT 1), the NameID Format gate (architect BLOCK fix — persistent/
 * emailAddress link, transient/unspecified/missing do not, with a
 * mutation-check pinning the gate is actually load-bearing), and the whole
 * call is fail-OPEN (never throws, never propagates a store failure).
 */

#include "saml_scim_link.hpp"

#include "deprovision_deny_split.hpp"
#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <stdexcept>
#include <string>

using yuzu::MetricsRegistry;
using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::saml::is_linkable_name_id_format;
using yuzu::server::saml::link_saml_login_to_scim;
using yuzu::server::saml::saml_login_denied_deprovisioned;
using yuzu::server::saml::SamlLoginDenyDecision;
using yuzu::server::saml::SamlScimLinkOutcome;
using yuzu::server::record_deprovision_deny_split;

namespace {

constexpr const char* kPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
constexpr const char* kEmail11    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
constexpr const char* kTransient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

// Pre-migrated template (mirrors test_scim_store_pg.cpp's scim_tpl / the
// oidc_scim_link_tpl sibling in test_oidc_scim_link.cpp).
yuzu::test::PgTestTemplate saml_scim_link_tpl{"samlscimlink", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("samlscimlink template: store failed to migrate");
}};

} // namespace

// ── is_linkable_name_id_format ───────────────────────────────────────────

TEST_CASE("is_linkable_name_id_format: persistent and 1.1 emailAddress are linkable",
          "[saml][scim][2001]") {
    CHECK(is_linkable_name_id_format(kPersistent));
    CHECK(is_linkable_name_id_format(kEmail11));
}

TEST_CASE("is_linkable_name_id_format: transient, empty, and an unrecognised format are "
          "NOT linkable",
          "[saml][scim][2001]") {
    CHECK_FALSE(is_linkable_name_id_format(kTransient));
    CHECK_FALSE(is_linkable_name_id_format(""));
    CHECK_FALSE(is_linkable_name_id_format("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));
    CHECK_FALSE(is_linkable_name_id_format("not-a-format-uri-at-all"));
}

// ── link_saml_login_to_scim: link formation ───────────────────────────────

TEST_CASE("link_saml_login_to_scim: exactly-one active match with a persistent Format forms "
          "the link",
          "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("alice", "alice@example.com");
    REQUIRE(resource.has_value());

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "alice@example.com", kPersistent);
    CHECK(outcome == SamlScimLinkOutcome::linked);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
    CHECK((*links)[0].entity_id == "https://idp.example.com/saml/metadata");
    CHECK((*links)[0].name_id == "alice@example.com");
}

TEST_CASE("link_saml_login_to_scim: exactly-one active match with the SAML 1.1 emailAddress "
          "Format also forms the link",
          "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("bob", "bob@example.com");
    REQUIRE(resource.has_value());

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "bob@example.com", kEmail11);
    CHECK(outcome == SamlScimLinkOutcome::linked);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
}

TEST_CASE("link_saml_login_to_scim: a transient NameID Format forms NO link — the login "
          "site still mints a session independently (MUTATION-CHECK target, see the comment "
          "below)",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("carol", "carol@example.com");
    REQUIRE(resource.has_value());

    // externalId matches EXACTLY — only the Format is unstable. If the
    // Format gate were removed, this would form a link (mis-linking a
    // per-login-reassigned identifier into a durable row).
    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "carol@example.com", kTransient);
    CHECK(outcome == SamlScimLinkOutcome::not_linkable);

    // MUTATION-CHECK (manually verified during development): removing the
    // `if (!is_linkable_name_id_format(name_id_format)) return;` guard in
    // link_saml_login_to_scim makes this REQUIRE fail (a link forms) —
    // confirming this test actually exercises the Format gate rather than
    // passing vacuously because the externalId happened not to match.
    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // ADR-2001 #3072 — the observation is still recorded UNCONDITIONALLY,
    // before this gate, even though the format is unstable/unlinkable.
    // MUTATION-CHECK (task spec): moving the
    // `record_saml_login_observation` call to AFTER the
    // `is_linkable_name_id_format` gate makes this assertion fail (a
    // transient-format login would then record nothing) — confirming this
    // is the D2-observability half of the fix, not just the link-formation
    // guard above.
    auto observed = store.saml_observation_matches("carol@example.com");
    REQUIRE(observed.has_value());
    CHECK(*observed);

    // The login itself is independent of this call — mirrors
    // test_oidc_scim_link.cpp's fail-OPEN pattern: a session minted before
    // (as auth_routes.cpp's /saml/acs does — link, then mint) stays exactly
    // as valid whether or not a link formed.
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_saml_session("carol@example.com",
                                              "https://idp.example.com/saml/metadata");
    REQUIRE_FALSE(token.empty());
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}

TEST_CASE("link_saml_login_to_scim: a missing/empty NameID Format forms NO link, BUT the "
          "observation IS recorded (Gate 7 fix — a common, legitimate IdP config must not "
          "be dropped from the D2 detector) and does not bump the write-failure counter",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("dave", "dave@example.com");
    REQUIRE(resource.has_value());

    MetricsRegistry metrics;
    const double before = metrics.counter("yuzu_scim_saml_link_write_failures_total").value();

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "dave@example.com", /*name_id_format=*/"", &metrics);
    CHECK(outcome == SamlScimLinkOutcome::not_linkable);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // MUTATION-CHECK (task spec): restoring the
    // `name_id_format.empty()` guard in
    // `ScimStore::record_saml_login_observation` makes this assertion fail
    // — an empty-format login (a common, legitimate IdP omitting the
    // NameID Format attribute) would then record NOTHING, defeating the D2
    // detector for that population.
    auto observed = store.saml_observation_matches("dave@example.com");
    REQUIRE(observed.has_value());
    CHECK(*observed);

    // The empty-format case is an ordinary, successfully-recorded
    // observation — it must never be conflated with a genuine store
    // write failure.
    const double after = metrics.counter("yuzu_scim_saml_link_write_failures_total").value();
    CHECK(after == before);
}

TEST_CASE("link_saml_login_to_scim: an oversized/control-byte NameID Format is normalized to "
          "\"\" before it reaches the store — bounded, and the login/observation still "
          "proceed",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("heidi", "heidi@example.com");
    REQUIRE(resource.has_value());

    // Two malformed shapes: over the 255-byte cap, and control bytes.
    const std::string oversized_format(300, 'x');
    const std::string control_byte_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:\x01x";

    auto outcome1 = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                            "heidi@example.com", oversized_format);
    CHECK(outcome1 == SamlScimLinkOutcome::not_linkable);

    auto outcome2 = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                            "heidi@example.com", control_byte_format);
    CHECK(outcome2 == SamlScimLinkOutcome::not_linkable);

    // The login proceeds (no deny) regardless — mirrors every other
    // non-linkable-format case.
    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // The observation was still recorded (bounded, not dropped).
    auto observed = store.saml_observation_matches("heidi@example.com");
    REQUIRE(observed.has_value());
    CHECK(*observed);

    // Raw-SQL peek: the stored row's format is the normalized "" — bounded
    // even though two malformed formats were presented (both collapse to
    // the same normalized row under the (entity_id, name_id, name_id_format)
    // upsert key).
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res = yuzu::server::pg::exec_params(
        conn.get(),
        "SELECT name_id_format FROM scim_store.saml_login_observations WHERE name_id = $1",
        std::vector<std::string>{"heidi@example.com"});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    CHECK(std::string(PQgetvalue(res.get(), 0, 0)).empty());
}

TEST_CASE("link_saml_login_to_scim: zero matches forms no link", "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // A resource exists, but under a DIFFERENT externalId than the login
    // presents — no match.
    auto resource = store.create_resource("erin", "erin@example.com");
    REQUIRE(resource.has_value());

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "no-such-name-id@example.com", kPersistent);
    CHECK(outcome == SamlScimLinkOutcome::no_active_match);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // ADR-2001 #3072 — the observation is recorded even though no link
    // formed (the D2 signal fires regardless of match outcome, mirroring
    // the OIDC side's zero-match test).
    auto observed = store.saml_observation_matches("no-such-name-id@example.com");
    REQUIRE(observed.has_value());
    CHECK(*observed);
}

// Mutation-check (ADR-2001 PR4a spec, mirrors test_oidc_scim_link.cpp's own
// mis-link mutation-check): if `find_unique_active_by_external_id` regressed
// to `... LIMIT 1`, this test's login would silently link to WHICHEVER of
// the two duplicate rows Postgres happened to return first. Seeding the
// duplicate externalId requires dropping the partial-unique index first
// (mirrors test_scim_store_pg.cpp's own mutation-check for the store method
// this orchestration consumes).
TEST_CASE("link_saml_login_to_scim: TWO active matches forms NO link (mis-link guard, "
          "mutation-checked)",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
    REQUIRE(drop.ok());

    auto r1 = store.create_resource("dup-user-1", "dup-name-id@example.com");
    auto r2 = store.create_resource("dup-user-2", "dup-name-id@example.com");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r1->scim_id != r2->scim_id);

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "dup-name-id@example.com", kPersistent);
    CHECK(outcome == SamlScimLinkOutcome::ambiguous_match);

    auto links1 = store.saml_links_for_scim_id(r1->scim_id);
    auto links2 = store.saml_links_for_scim_id(r2->scim_id);
    REQUIRE(links1.has_value());
    REQUIRE(links2.has_value());
    CHECK(links1->empty());
    CHECK(links2->empty());
}

TEST_CASE("link_saml_login_to_scim: a null ScimStore is a safe no-op", "[saml][scim][2001]") {
    // Mirrors the "no PG configured" boot posture — must not crash.
    auto outcome = link_saml_login_to_scim(nullptr, "https://idp.example.com/saml/metadata",
                                           "x@example.com", kPersistent);
    CHECK(outcome == SamlScimLinkOutcome::not_linkable);
    SUCCEED("did not throw");
}

TEST_CASE("link_saml_login_to_scim: a closed/unusable ScimStore is fail-OPEN — call returns "
          "normally (lookup_store_error) and a SAML session minted independently stays valid",
          "[pg][saml][scim][2001][failopen]") {
    // A store whose pool cannot deliver a connection (invalid conninfo)
    // reports !is_open(), so every ScimStore accessor called through it
    // returns false/nullopt internally — exercising the exact failure path
    // link_saml_login_to_scim must swallow.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    // Must not throw despite every underlying write failing. The store is
    // non-null (unlike the null-store test above) so this reaches the
    // linkable-format branch and the lookup itself reports store_error —
    // distinguishable from a genuine no_active_match.
    auto outcome = link_saml_login_to_scim(&broken_store, "https://idp.example.com/saml/metadata",
                                           "failopen@example.com", kPersistent);
    CHECK(outcome == SamlScimLinkOutcome::lookup_store_error);
    SUCCEED("did not throw despite a closed store");

    // The login itself is independent of this call (mint-then-link at the
    // real ACS handler; here we exercise the reverse order — link-then-mint
    // — which is the actual production order, see auth_routes.cpp).
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_saml_session("failopen@example.com",
                                              "https://idp.example.com/saml/metadata");
    REQUIRE_FALSE(token.empty());
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}

// ── yuzu_scim_saml_link_write_failures_total (compliance F2) ────────────
//
// The counter must fire on a genuine WRITE failure specifically — not on a
// wholly-closed/unreachable store, which never reaches the write at all
// (find_unique_active_by_external_id's own `!open_` guard returns nullopt
// first, and link_saml_login_to_scim returns before ever calling
// upsert_saml_link — see the fail-OPEN test above, which is a DIFFERENT
// code path and does not exercise this counter). To force a write failure
// while the READ still succeeds, drop ONLY the saml_identity_links table
// (mirrors the mutation-check idiom used elsewhere in this PR) — the
// scim_resources lookup still finds the resource, then the INSERT into the
// now-missing table fails.
//
// The sibling OIDC counter (yuzu_scim_oidc_link_write_failures_total,
// server.cpp) has no equivalent unit-level assertion today — pre-existing
// gap, not expanded here (scope is the new SAML counter only).
TEST_CASE("link_saml_login_to_scim: yuzu_scim_saml_link_write_failures_total increments on a "
         "forced upsert_saml_link failure (the read still succeeds)",
         "[pg][saml][scim][2001][metrics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("frank", "frank@example.com");
    REQUIRE(resource.has_value());

    // Drop the write target. scim_resources (the read path) is untouched.
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP TABLE scim_store.saml_identity_links")};
    REQUIRE(drop.ok());

    MetricsRegistry metrics;
    // Baseline: absent-but-pre-seeded semantics are server.cpp's job (the
    // boot-time bare .counter() call) — this fresh, unregistered
    // MetricsRegistry starts every series at 0 either way, so a plain
    // pre/post comparison is sufficient here without duplicating that
    // pre-seed wiring in a unit test.
    const double before = metrics.counter("yuzu_scim_saml_link_write_failures_total").value();

    auto outcome = link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                                           "frank@example.com", kPersistent, &metrics);
    CHECK(outcome == SamlScimLinkOutcome::link_write_error);

    // The read succeeded (a real match existed) and the write failed (the
    // table is gone) — confirms this test exercises the WRITE-failure path,
    // not the store-closed path the fail-OPEN test above already covers.
    auto links = store.saml_links_for_scim_id(resource->scim_id);
    // saml_links_for_scim_id itself now queries the dropped table too, so
    // it also fails — nullopt is the expected (and consistent) outcome
    // here, not a second independent assertion of "no link formed".
    CHECK_FALSE(links.has_value());

    const double after = metrics.counter("yuzu_scim_saml_link_write_failures_total").value();
    CHECK(after == before + 1.0);
}

TEST_CASE("link_saml_login_to_scim: a null metrics pointer is a safe no-op (no crash on a "
         "forced write failure with no MetricsRegistry wired)",
         "[pg][saml][scim][2001][metrics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("grace", "grace@example.com");
    REQUIRE(resource.has_value());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP TABLE scim_store.saml_identity_links")};
    REQUIRE(drop.ok());

    // Default metrics=nullptr (test/CLI contexts, per the header doc).
    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata", "grace@example.com",
                            kPersistent);
    SUCCEED("did not throw despite a null metrics pointer and a forced write failure");
}

// ── saml_login_denied_deprovisioned (ADR-2001 §4 PR4b deny-at-login) ─────
//
// Mirrors test_oidc_scim_link.cpp's `oidc_login_denied_deprovisioned`
// section exactly, adapted for SAML's single-join-key shape: there is no
// separate `link_claim_value` parameter (see saml_scim_link.hpp's doc
// comment) — the reprovision check always resolves against `name_id`
// itself, the same value `saml_linked_resource_active` above it already
// used.

TEST_CASE("saml_login_denied_deprovisioned: a null ScimStore proceeds (SCIM not "
         "configured, not a store degrade) — PR3-blocker regression guard",
         "[saml][scim][2001][deny-at-login]") {
    // Mirrors link_saml_login_to_scim's null-safety posture: no store means
    // no link could ever have formed, so there is nothing to deny against —
    // must NOT be conflated with a present-but-unusable store (which fails
    // closed, below). A deployment that never enables SCIM must not have
    // every SAML login denied by this backstop (the exact PR3 regression
    // this test pins).
    auto decision = saml_login_denied_deprovisioned(nullptr, "https://idp.example.com/saml/metadata",
                                                     "name-x");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("saml_login_denied_deprovisioned: an unlinked SAML identity proceeds",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto decision = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                     "name-never-linked");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("saml_login_denied_deprovisioned: an active linked identity proceeds",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("active-user", "ext-active");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-active", r->scim_id));

    auto decision = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                     "ext-active");
    CHECK_FALSE(decision.denied);
    // PROCEED always carries scim_id=nullopt, even though a linked resource
    // exists — the audit detail only needs the id on a DENY.
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("saml_login_denied_deprovisioned: a deactivated linked identity is DENIED "
         "unconditionally — no reprovision check on this branch — and names the "
         "resource",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("inactive-user", "ext-inactive");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-inactive",
                                   r->scim_id));
    REQUIRE(store.set_active(r->scim_id, false));

    auto decision = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                     "ext-inactive");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value());
    CHECK(*decision.scim_id == r->scim_id); // the id the audit detail carries

    // MUTATION-CHECK (manually verified during development): flipping this
    // branch's `if (!*result->active) return {.denied = true, ...};` to
    // `.denied = false` (unconditional proceed on the inactive branch) makes
    // the `decision.denied` CHECK above fail — the exact fail-open
    // regression ADR-2001 §4 exists to prevent.
}

TEST_CASE("saml_login_denied_deprovisioned: an orphaned link with NO reprovision "
         "(genuinely deleted, no active resource for its externalId) is DENIED and "
         "still names the resource",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("deleted-user", "ext-deleted");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-deleted",
                                   r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // name_id = the deleted resource's own (now-orphaned) externalId — no
    // active resource exists for it (nothing was re-created), so this is
    // the "genuinely deleted" case.
    auto decision = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                     "ext-deleted");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value()); // saml_identity_links row still names the (now-gone) id
    CHECK(*decision.scim_id == r->scim_id);

    // MUTATION-CHECK (manually verified during development): making the
    // orphaned branch unconditional-proceed (removing the
    // find_unique_active_by_external_id reprovision check entirely) makes
    // the `decision.denied` CHECK above fail — see the paired reprovision
    // test below for the OTHER half of this mutation (a genuine
    // reprovision sibling must still proceed).
}

TEST_CASE("saml_login_denied_deprovisioned: an orphaned link WITH an active reprovision "
         "sibling at the same externalId proceeds — the identity was DELETE'd then "
         "re-CREATE'd under a new scim_id",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r1 = store.create_resource("orig-user", "ext-reprovision");
    REQUIRE(r1.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-reprovision",
                                   r1->scim_id));
    REQUIRE(store.delete_by_scim_id(r1->scim_id).value());

    // Re-provision under a NEW scim_id, same externalId.
    auto r2 = store.create_resource("new-user", "ext-reprovision");
    REQUIRE(r2.has_value());
    REQUIRE(r2->scim_id != r1->scim_id);

    auto decision = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                     "ext-reprovision");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("saml_login_denied_deprovisioned: a reactivated identity proceeds again — no "
         "latched denial, a live read every call",
         "[pg][saml][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("flapping-user", "ext-flapping");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-flapping",
                                   r->scim_id));

    CHECK_FALSE(saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                "ext-flapping")
                    .denied);

    REQUIRE(store.set_active(r->scim_id, false));
    auto mid = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                               "ext-flapping");
    CHECK(mid.denied);
    REQUIRE(mid.scim_id.has_value());
    CHECK(*mid.scim_id == r->scim_id);

    REQUIRE(store.set_active(r->scim_id, true));
    auto after = saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata",
                                                 "ext-flapping");
    CHECK_FALSE(after.denied);
    CHECK_FALSE(after.scim_id.has_value());
}

// Models the post-mint re-check race exactly like the OIDC helper's test:
// two calls to this SAME decision function separated by the mint window.
TEST_CASE("saml_login_denied_deprovisioned: models the post-mint re-check race — a "
         "concurrent deprovision between two calls flips PROCEED to DENY and names "
         "the resource",
         "[pg][saml][scim][2001][deny-at-login][race]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("race-user", "ext-race");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata", "ext-race", r->scim_id));

    // "Primary check" — proceeds.
    CHECK_FALSE(
        saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata", "ext-race")
            .denied);

    // A concurrent SCIM deactivate lands in the mint window.
    REQUIRE(store.set_active(r->scim_id, false));

    // "Post-mint re-check" — the SAME call, now denies and names the resource.
    auto recheck =
        saml_login_denied_deprovisioned(&store, "https://idp.example.com/saml/metadata", "ext-race");
    CHECK(recheck.denied);
    REQUIRE(recheck.scim_id.has_value());
    CHECK(*recheck.scim_id == r->scim_id);
}

TEST_CASE("saml_login_denied_deprovisioned: a closed/unusable ScimStore fails CLOSED, "
         "with no scim_id to name (MUTATION-CHECK target, see the comment below)",
         "[pg][saml][scim][2001][deny-at-login][failclosed]") {
    // Mirrors the existing "closed/unusable ScimStore" test above for
    // link_saml_login_to_scim: an unreachable pool reports !is_open(), so
    // saml_linked_resource_active's OUTER nullopt path is exercised.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    auto decision = saml_login_denied_deprovisioned(&broken_store,
                                                     "https://idp.example.com/saml/metadata",
                                                     "name-unreachable");
    CHECK(decision.denied);
    // The store could not be asked, so there is no resource to name — the
    // audit detail on this DENY omits scim_id gracefully (audited as
    // `reason=scim_store_unavailable`, never `linked_scim_resource_inactive`,
    // at the ACS handler call site).
    CHECK_FALSE(decision.scim_id.has_value());

    // MUTATION-CHECK (manually verified during development): flipping
    // `saml_login_denied_deprovisioned`'s `if (!result) return {.denied =
    // true, ...};` branch to `.denied = false` (i.e. treating a store that
    // could not answer as PROCEED instead of DENY) makes the
    // `decision.denied` assertion above fail — the exact fail-open
    // regression ADR-2001 §4 exists to prevent (a ScimStore outage must
    // never let a deprovisioned identity re-authenticate by luck of
    // timing).
}

// ── #3069 — deny-counter split: genuine vs store-unavailable ──
//
// Both `/saml/acs` deny sites in auth_routes.cpp (primary check + post-mint
// recheck) bump the TOTAL counter (`yuzu_auth_saml_deprovisioned_denied_total`)
// unconditionally, then call the SHARED `record_deprovision_deny_split`
// helper (deprovision_deny_split.hpp, Gate 7 quality-engineer fix — the same
// helper the OIDC side uses in test_oidc_scim_link.cpp) to split into
// `yuzu_auth_saml_deprovisioned_denied_genuine_total` (scim_id present) vs
// `yuzu_auth_saml_deprovisioned_denied_store_unavailable_total` (scim_id
// absent) — a Postgres outage must never inflate the genuine/alertable
// sub-counter. Both sites call the IDENTICAL helper, so ONE TEST_CASE
// pinning the helper directly (rather than a hand-copied mirror of the
// increment logic, which could not catch a predicate flip at a real call
// site) covers both — there is no second, site-specific behaviour left to
// pin separately.
TEST_CASE("#3069: record_deprovision_deny_split bumps genuine XOR "
          "store-unavailable, never both",
          "[pg][saml][scim][2001][deny-at-login][3069]") {
    SECTION("store-unavailable DENY (scim_id absent) -> store_unavailable_total, "
           "NOT genuine_total") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        auto decision = saml_login_denied_deprovisioned(
            &broken_store, "https://idp.example.com/saml/metadata", "name-3069-unavailable");
        REQUIRE(decision.denied);
        REQUIRE_FALSE(decision.scim_id.has_value());

        MetricsRegistry m;
        m.counter("yuzu_auth_saml_deprovisioned_denied_total").increment();
        // MUTATION-CHECK target: flipping the predicate inside
        // record_deprovision_deny_split (`scim_id_present` instead of
        // `!scim_id_present`) makes the SECTIONs below fail — verified by
        // hand during review, reverted before merge (see the junior task's
        // VERIFY report).
        record_deprovision_deny_split(
            &m, "yuzu_auth_saml_deprovisioned_denied_genuine_total",
            "yuzu_auth_saml_deprovisioned_denied_store_unavailable_total",
            decision.scim_id.has_value());

        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_store_unavailable_total").value() ==
              1.0);
        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_genuine_total").value() == 0.0);
    }

    SECTION("resolved-deprovisioned DENY (scim_id present) -> genuine_total, "
           "NOT store_unavailable_total") {
        YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        ScimStore store{pool};
        REQUIRE(store.is_open());

        auto r = store.create_resource("u3069-saml-inactive-user", "ext-3069-saml-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_saml_link("https://idp.example.com/saml/metadata",
                                       "ext-3069-saml-inactive", r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto decision = saml_login_denied_deprovisioned(
            &store, "https://idp.example.com/saml/metadata", "ext-3069-saml-inactive");
        REQUIRE(decision.denied);
        REQUIRE(decision.scim_id.has_value());

        MetricsRegistry m;
        m.counter("yuzu_auth_saml_deprovisioned_denied_total").increment();
        record_deprovision_deny_split(
            &m, "yuzu_auth_saml_deprovisioned_denied_genuine_total",
            "yuzu_auth_saml_deprovisioned_denied_store_unavailable_total",
            decision.scim_id.has_value());

        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_genuine_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_saml_deprovisioned_denied_store_unavailable_total").value() ==
              0.0);
    }
}
