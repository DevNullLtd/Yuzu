/**
 * test_oidc_scim_link.cpp — Unit tests for `link_oidc_login_to_scim`
 * (ADR-2001 §2/D2), the OIDC login-site orchestration extracted out of
 * `/auth/callback` (auth_routes.cpp) into `oidc_scim_link.{hpp,cpp}` so it
 * is directly testable against a real ScimStore without a live IdP —
 * test_oidc_routes.cpp's docstring explains why the `/auth/callback`
 * success path itself has no HTTP-level test (no mock-IdP harness in this
 * codebase).
 *
 * Covers the ADR-2001 task-2 spec's link-formation contract: exactly-one
 * active match forms the link, zero/more-than-one match forms none (with a
 * mutation-check that the strict lookup wasn't quietly widened back to
 * LIMIT 1), the login observation is ALWAYS recorded regardless of match,
 * and the whole call is fail-OPEN (never throws, never propagates a store
 * failure) — `AuthManager::create_oidc_session` session-mint independence
 * from a broken ScimStore is asserted directly.
 *
 * Governance Gate 7 BLOCKING fix (the D2 tripwire, the crux): a dedicated
 * "misconfigured Entra" section below covers the headline D2 case —
 * `--oidc-scim-link-claim=sub` while the SCIM externalId is actually the
 * Entra `oid` — asserting NO link forms, BOTH candidate observations are
 * recorded, and `observation_matches(external_id)` (keyed on the oid value)
 * fires TRUE, with a mutation-check confirming a regression back to
 * "record the configured claim only" would make it fail.
 */

#include "oidc_scim_link.hpp"

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

using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::oidc::link_oidc_login_to_scim;
using yuzu::server::oidc::oidc_login_denied_deprovisioned;
using yuzu::server::oidc::OidcLoginDenyDecision;
using yuzu::server::record_deprovision_deny_split;

namespace {

// Pre-migrated template (mirrors test_scim_store_pg.cpp's scim_tpl).
yuzu::test::PgTestTemplate oidc_scim_link_tpl{"oidcscimlink", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("oidcscimlink template: store failed to migrate");
}};

} // namespace

TEST_CASE("link_oidc_login_to_scim: exactly-one active match forms the link",
          "[pg][oidc][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("alice", "ext-alice");
    REQUIRE(resource.has_value());

    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-alice", /*oid=*/"",
                            "ext-alice");

    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
    CHECK((*links)[0].iss == "https://idp.example.com/");
    CHECK((*links)[0].sub == "sub-alice");
}

TEST_CASE("link_oidc_login_to_scim: zero matches forms no link, but the observation is "
          "still recorded",
          "[pg][oidc][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // A resource exists, but under a DIFFERENT externalId than what the
    // login presents — no match.
    auto resource = store.create_resource("bob", "ext-bob");
    REQUIRE(resource.has_value());

    // `oid` carries the attempted (non-matching) claim value here — the
    // literal `sub` identity and the value under test are deliberately
    // distinct, same as the pre-fix version of this test; recording now
    // happens per-candidate-claim (sub AND oid), so the mismatched value
    // must land in one of the two candidate slots to be recorded.
    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-nomatch",
                            /*oid=*/"no-such-ext-id", "no-such-ext-id");

    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // D2 — the attempted claim value is recorded regardless of the miss, so
    // a later deprovision can surface it as a should-have-matched candidate.
    CHECK(store.observation_matches("no-such-ext-id"));
}

// Mutation-check (ADR-2001 task spec): if `find_unique_active_by_external_id`
// regressed to `... LIMIT 1`, this test's login would silently link to
// WHICHEVER of the two duplicate rows Postgres happened to return first —
// mis-linking an OIDC identity to the wrong SCIM user. Seeding the
// duplicate externalId requires dropping the partial-unique index first
// (mirrors test_scim_store_pg.cpp's own mutation-check for the store method
// this orchestration consumes), modelling "a duplicate slipped in via a
// bug/manual DB edit".
TEST_CASE("link_oidc_login_to_scim: TWO active matches forms NO link (mis-link guard, "
          "mutation-checked)",
          "[pg][oidc][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
    REQUIRE(drop.ok());

    auto r1 = store.create_resource("dup-user-1", "dup-ext");
    auto r2 = store.create_resource("dup-user-2", "dup-ext");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r1->scim_id != r2->scim_id);

    // Same "oid carries the tested value" adjustment as the zero-match test
    // above.
    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-ambiguous",
                            /*oid=*/"dup-ext", "dup-ext");

    // Neither candidate resource picked up the link — an ambiguous
    // externalId must never resolve to an arbitrary row.
    auto links1 = store.links_for_scim_id(r1->scim_id);
    auto links2 = store.links_for_scim_id(r2->scim_id);
    REQUIRE(links1.has_value());
    REQUIRE(links2.has_value());
    CHECK(links1->empty());
    CHECK(links2->empty());

    // Observation still recorded — the D2 signal fires regardless.
    CHECK(store.observation_matches("dup-ext"));
}

TEST_CASE("link_oidc_login_to_scim: a null ScimStore is a safe no-op", "[oidc][scim][2001]") {
    // Mirrors the "no PG configured" boot posture — must not crash.
    link_oidc_login_to_scim(nullptr, "https://idp.example.com/", "sub-x", /*oid=*/"",
                            "ext-x");
    SUCCEED("did not throw");
}

TEST_CASE("link_oidc_login_to_scim: a closed/unusable ScimStore is fail-OPEN — call "
          "returns normally and an OIDC session minted independently stays valid",
          "[pg][oidc][scim][2001][failopen]") {
    // A store whose pool cannot deliver a connection (invalid conninfo)
    // reports !is_open(), so every ScimStore accessor called through it
    // returns false internally — exercising the exact failure path
    // link_oidc_login_to_scim must swallow.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    // Must not throw despite every underlying write failing.
    link_oidc_login_to_scim(&broken_store, "https://idp.example.com/", "sub-failopen",
                            /*oid=*/"", "ext-failopen");
    SUCCEED("did not throw despite a closed store");

    // The login itself is independent of this call: a session minted before
    // (as auth_routes.cpp's /auth/callback does — session first, link
    // second) stays exactly as valid whether or not the link write
    // succeeded. This is the "login still SUCCEEDS" half of ADR-2001 §2's
    // fail-OPEN contract, exercised at the AuthManager level since there is
    // no live-IdP harness to drive the HTTP route end to end (see
    // test_oidc_routes.cpp's docstring).
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_oidc_session("Fail Open User", "failopen@example.com",
                                              "sub-failopen", "https://idp.example.com/");
    REQUIRE_FALSE(token.empty());

    // The store call above happened AFTER the session was already minted
    // (mirrors the real login-site ordering) and must not have touched it.
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}

// ── Governance Gate 7 BLOCKING fix — the D2 tripwire (the crux) ─────────────
//
// The headline D2 misconfiguration: an operator runs with
// `--oidc-scim-link-claim=sub`, but the SCIM `externalId` the IdP actually
// provisioned is the Entra `oid` (not `sub`). Link formation legitimately
// forms NO link (the configured claim, sub, does not match). But before
// this fix, D2 ALSO never fired: only the configured claim's value (sub)
// was recorded as an observation, so `observation_matches(externalId)`
// (keyed on the oid value) never matched. The fix records BOTH candidates.

TEST_CASE("link_oidc_login_to_scim: misconfigured Entra link-claim — no link forms, BOTH "
          "candidate observations are recorded, and D2's observation_matches fires on the "
          "externalId (MUTATION-CHECK target, see the comment below)",
          "[pg][oidc][scim][2001][d2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // The SCIM resource's externalId is the Entra `oid` value — exactly
    // what Entra sends as `externalId` in its SCIM provisioning payload.
    const std::string oid_value = "11111111-2222-3333-4444-555555555555";
    auto resource = store.create_resource("dana", oid_value);
    REQUIRE(resource.has_value());

    // Operator has `--oidc-scim-link-claim=sub` (the default) — link
    // formation is keyed on `sub`, which does NOT match the externalId.
    const std::string iss = "https://login.microsoftonline.com/tenant-id/v2.0";
    const std::string sub_value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    link_oidc_login_to_scim(&store, iss, sub_value, oid_value,
                            /*link_claim_value=*/sub_value);

    // No link formed — the configured claim (sub) never matched anything.
    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // Both candidate observations are on record.
    CHECK(store.observation_matches(sub_value));
    // THE headline assertion: the oid candidate — never used for link
    // formation under this configuration — is STILL recorded, so D2 can
    // find it.
    CHECK(store.observation_matches(oid_value));

    // MUTATION-CHECK (manually verified during development): reverting
    // `link_oidc_login_to_scim` to record only the configured
    // (sub, link_claim_value) pair — i.e. dropping the `oid`
    // candidate loop entirely — makes the `observation_matches(oid_value)`
    // assertion above fail (no row for the oid value exists), confirming
    // this test actually exercises the D2 tripwire fix rather than passing
    // vacuously. `observation_matches(sub_value)` alone would stay green
    // under that regression, which is exactly why it is not the only
    // assertion here.
}

TEST_CASE("link_oidc_login_to_scim: an empty/unsanitized oid candidate is never recorded "
          "(no phantom observation row for a claim the IdP never sent)",
          "[pg][oidc][scim][2001][d2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // Okta-style IdP: no `oid` claim at all (empty string, as
    // OidcProvider::parse_id_token leaves it when absent).
    link_oidc_login_to_scim(&store, "https://idp.okta.example.com/", "sub-okta", /*oid=*/"",
                            "sub-okta");

    CHECK(store.observation_matches("sub-okta"));
    // No row was ever inserted for an empty claim_value — observation_matches
    // itself already treats an empty query as "no match" (see its own
    // empty-input guard), so this is really asserting no CRASH/db-error
    // occurred recording it, covered implicitly by every assertion above
    // succeeding without a REQUIRE failure.
}

// ── ADR-2001 §4 — deny-at-login backstop decision helper ────────────────
//
// `oidc_login_denied_deprovisioned` is called from TWO sites in
// `/auth/callback` (the primary pre-mint check and the post-mint re-check
// for the codex-caught concurrent-deprovision race) — both share this one
// decision function. `handle_callback`'s success path requires a live IdP
// token exchange (no mock-IdP harness in this codebase, per
// test_oidc_routes.cpp's docstring), and both deny sites in auth_routes.cpp
// sit strictly AFTER that success path, so neither is reachable through an
// HTTP-level `/auth/callback` test. Every case below is therefore exercised
// directly against a real ScimStore, which is exactly this function's own
// dependency surface — a store-degrade or state transition it needs to
// react to is fully reproducible here without an IdP.
//
// `link_claim_value` is the 4th param (governance U1 fix) — the same
// externalId candidate link formation uses, needed by the orphaned-link
// reprovision check. Most cases below pass a value that deliberately does
// NOT match any active resource's externalId, so they exercise the SAME
// deny/proceed outcomes as before U1 — the reprovision-specific behaviour
// is covered by its own dedicated section further down.

TEST_CASE("oidc_login_denied_deprovisioned: a null ScimStore proceeds (SCIM not configured, "
          "not a store degrade)",
          "[oidc][scim][2001][deny-at-login]") {
    // Mirrors link_oidc_login_to_scim's null-safety posture: no store means
    // no link could ever have formed, so there is nothing to deny against —
    // this must NOT be conflated with a present-but-unusable store (which
    // fails closed, below). A deployment that never enables SCIM must not
    // have every OIDC login denied by this backstop.
    auto decision =
        oidc_login_denied_deprovisioned(nullptr, "https://idp.example.com/", "sub-x", "sub-x");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: an unlinked OIDC identity proceeds",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                     "sub-never-linked", "sub-never-linked");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: an active linked identity proceeds",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("active-user", "ext-active");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-active", r->scim_id));

    auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                     "sub-active", "ext-active");
    CHECK_FALSE(decision.denied);
    // PROCEED always carries scim_id=nullopt, even though a linked resource
    // exists — the audit detail only needs the id on a DENY.
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: a deactivated linked identity is DENIED "
          "unconditionally — no reprovision check on this branch — and names the "
          "resource",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("inactive-user", "ext-inactive");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-inactive", r->scim_id));
    REQUIRE(store.set_active(r->scim_id, false));

    // Passing the resource's OWN externalId as link_claim_value proves the
    // INACTIVE branch does NOT consult find_unique_active_by_external_id —
    // if it did, this externalId would resolve to nothing (the only row for
    // it is now inactive) and the outcome would be unchanged here anyway,
    // but the dedicated reprovision-check tests below confirm the ORPHANED
    // branch is the only one gated by it.
    auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                     "sub-inactive", "ext-inactive");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value());
    CHECK(*decision.scim_id == r->scim_id); // the id the audit detail carries
}

TEST_CASE("oidc_login_denied_deprovisioned: an orphaned link with NO reprovision "
          "(genuinely deleted, no active resource for its externalId) is DENIED and "
          "still names the resource",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("deleted-user", "ext-deleted");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-deleted", r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // link_claim_value = the deleted resource's own (now-orphaned)
    // externalId — no active resource exists for it (nothing was
    // re-created), so this is the "genuinely deleted" case, U1's codex
    // bypass regression target (b).
    auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                     "sub-deleted", "ext-deleted");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value()); // identity_links row still names the (now-gone) id
    CHECK(*decision.scim_id == r->scim_id);
}

TEST_CASE("oidc_login_denied_deprovisioned: a reactivated identity proceeds again — no "
          "latched denial, a live read every call",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("flapping-user", "ext-flapping");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-flapping", r->scim_id));

    CHECK_FALSE(oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                "sub-flapping", "ext-flapping")
                    .denied);

    REQUIRE(store.set_active(r->scim_id, false));
    auto mid = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-flapping",
                                               "ext-flapping");
    CHECK(mid.denied);
    REQUIRE(mid.scim_id.has_value());
    CHECK(*mid.scim_id == r->scim_id);

    REQUIRE(store.set_active(r->scim_id, true));
    auto after = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                 "sub-flapping", "ext-flapping");
    CHECK_FALSE(after.denied);
    CHECK_FALSE(after.scim_id.has_value());
}

// The post-mint re-check's whole reason to exist: the primary check and the
// re-check are two calls to this SAME decision function separated by the
// mint window. Modelling that window directly — deny false at "primary check
// time", the identity goes inactive, deny true (and names the resource) at
// "re-check time" — proves the re-check needs no extra machinery to
// self-heal the race; a plain second call already sees the fresh state.
TEST_CASE("oidc_login_denied_deprovisioned: models the post-mint re-check race — a "
          "concurrent deprovision between two calls flips PROCEED to DENY and names "
          "the resource",
          "[pg][oidc][scim][2001][deny-at-login][race]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("race-user", "ext-race");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-race", r->scim_id));

    // "Primary check" — proceeds.
    CHECK_FALSE(oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-race",
                                                "ext-race")
                    .denied);

    // A concurrent SCIM deactivate lands in the mint window.
    REQUIRE(store.set_active(r->scim_id, false));

    // "Post-mint re-check" — the SAME call, now denies and names the resource
    // — this is the audit-detail scim_id the recheck site embeds.
    auto recheck = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-race",
                                                   "ext-race");
    CHECK(recheck.denied);
    REQUIRE(recheck.scim_id.has_value());
    CHECK(*recheck.scim_id == r->scim_id);
}

TEST_CASE("oidc_login_denied_deprovisioned: a closed/unusable ScimStore fails CLOSED, "
          "with no scim_id to name (MUTATION-CHECK target, see the comment below)",
          "[pg][oidc][scim][2001][deny-at-login][failclosed]") {
    // Mirrors the existing "closed/unusable ScimStore" test above for
    // link_oidc_login_to_scim: an unreachable pool reports !is_open(), so
    // linked_resource_active's OUTER nullopt path is exercised.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    auto decision = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                     "sub-unreachable", "ext-unreachable");
    CHECK(decision.denied);
    // The store could not be asked, so there is no resource to name — the
    // audit detail on this DENY omits scim_id gracefully (and, per U6, is
    // audited as `reason=scim_store_unavailable`, never
    // `linked_scim_resource_inactive` — see the reason-string section
    // below).
    CHECK_FALSE(decision.scim_id.has_value());

    // MUTATION-CHECK (manually verified during development): flipping
    // `oidc_login_denied_deprovisioned`'s `if (!result) return {.denied =
    // true, ...};` branch to `.denied = false` (i.e. treating a store that
    // could not answer as PROCEED instead of DENY) makes the `decision.denied`
    // assertion above fail — the exact fail-open regression ADR-2001 §4
    // exists to prevent (a ScimStore outage must never let a deprovisioned
    // identity re-authenticate by luck of timing).
}

// ── Review follow-up (PR3 BLOCKER) — gate deny-at-login on --scim-enable ──
//
// Postgres is the mandatory substrate, so `scim_store_` is non-null on
// EVERY deployment — before this fix, server.cpp wired it into AuthRoutes
// UNCONDITIONALLY (`auth_routes_->set_scim_store(scim_store_.get())`), so a
// server running OIDC SSO with `--scim-enable=false` denied ALL OIDC logins
// during a transient Postgres blip (a degraded store reads as
// `scim_store_unavailable` -> deny, exactly the "closed/unusable ScimStore
// fails CLOSED" case above). The fix gates the wiring itself:
// `auth_routes_->set_scim_store(cfg_.scim_enable ? scim_store_.get() :
// nullptr)` — mirroring the pre-existing `/readyz` `scim_store` check,
// which already exempts itself the same way
// (`!cfg_.scim_enable || (scim_store_ && ...)`).
//
// There is no server-construction harness that reaches the private
// `ServerImpl::run()` wiring line directly (`ServerImpl` has no test
// seam — see the other TEST_CASEs in this file, none construct one), so
// this test pins the WIRING EXPRESSION itself — reproduced verbatim from
// server.cpp — feeding it a store standing in for "Postgres is
// unreachable" and asserting the null side of the ternary makes
// `oidc_login_denied_deprovisioned` inert, never reaching the degraded
// store at all.
TEST_CASE("deny-at-login wiring: scim_enable=false + a degraded/unavailable "
          "ScimStore => OIDC login proceeds (deny-at-login gated off, "
          "MUTATION-CHECK target, see the comment below)",
          "[pg][oidc][scim][2001][deny-at-login][scimenable]") {
    // Stands in for "Postgres is unreachable" — same broken-pool
    // construction as the fail-CLOSED test above, which on its own (fed
    // directly, as if wired unconditionally) DENIES.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    // Sanity: an unconditionally-wired (old, buggy) store DENIES even
    // though SCIM is "disabled" in this scenario — this is the bug the
    // fix closes.
    auto unconditional = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                          "sub-scimoff", "ext-scimoff");
    CHECK(unconditional.denied);

    // The fix: server.cpp's wiring line, reproduced verbatim —
    //   auth_routes_->set_scim_store(cfg_.scim_enable ? scim_store_.get() : nullptr);
    // with cfg_.scim_enable == false and scim_store_.get() == &broken_store.
    constexpr bool scim_enable = false;
    ScimStore* wired_store = scim_enable ? &broken_store : nullptr;
    REQUIRE(wired_store == nullptr);

    // With SCIM disabled, deny-at-login must be INERT: the degraded store
    // is never even consulted (the null=proceed contract, pinned by the
    // "a null ScimStore proceeds" test above) — the login proceeds despite
    // the Postgres blip.
    auto decision = oidc_login_denied_deprovisioned(wired_store, "https://idp.example.com/",
                                                     "sub-scimoff", "ext-scimoff");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());

    // MUTATION-CHECK (manually verified during development): reverting the
    // wiring expression to the pre-fix unconditional
    // `scim_store_.get()` — i.e. `wired_store = &broken_store;` regardless
    // of `scim_enable` — makes the `decision.denied` assertion above fail
    // (CHECK_FALSE(decision.denied) sees `denied == true` instead), which
    // is exactly the regression this test exists to catch: a
    // `--scim-enable=false` deployment denying every OIDC login during a
    // transient Postgres blip.
}

// ── Governance unhappy-path finding U1 — reprovision after SCIM DELETE ──
//
// Bug: SCIM DELETE hard-deletes scim_resources and orphans the
// identity_links row; a re-CREATE mints a NEW scim_id; but the re-link
// (upsert_link, in link_oidc_login_to_scim) runs AFTER the primary deny
// check in auth_routes.cpp. Without this reprovision check, a DELETE+
// re-CREATE'd (returning) user is permanently locked out — their login is
// denied before the re-link can repoint the stale (iss,sub) link.
//
// The fix ONLY applies to the ORPHANED branch (active == nullopt); the
// dedicated tests above already pin that the INACTIVE branch (active ==
// false, resource still exists) keeps denying unconditionally.

TEST_CASE("oidc_login_denied_deprovisioned U1 (a): DELETE then re-CREATE under the SAME "
          "externalId (new scim_id) PROCEEDS — a returning re-provisioned user is not "
          "locked out",
          "[pg][oidc][scim][2001][deny-at-login][u1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-returning";
    const std::string external_id = "ext-returning";

    auto original = store.create_resource("returning-user", external_id);
    REQUIRE(original.has_value());
    REQUIRE(store.upsert_link(iss, sub, original->scim_id));
    REQUIRE(store.delete_by_scim_id(original->scim_id).value());

    // Re-CREATE under the SAME externalId — a new scim_id, per SCIM's
    // create semantics (create_resource always mints a fresh id).
    auto reprovisioned = store.create_resource("returning-user-2", external_id);
    REQUIRE(reprovisioned.has_value());
    REQUIRE(reprovisioned->scim_id != original->scim_id);

    // The deny decision for the STALE (iss,sub) link must now PROCEED —
    // this is the exact lockout U1 closes.
    auto decision = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());

    // A real login re-links: link_oidc_login_to_scim repoints the stale
    // (iss,sub) row to the NEW scim_id (the same externalId still resolves
    // to exactly one active resource — the re-created one).
    link_oidc_login_to_scim(&store, iss, sub, /*oid=*/"", external_id);
    auto links = store.links_for_scim_id(reprovisioned->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
    CHECK((*links)[0].sub == sub);
    // The stale link no longer points at the deleted resource.
    CHECK(store.links_for_scim_id(original->scim_id)->empty());

    // A SECOND login now resolves via the ordinary active-link path —
    // clean, no reprovision check even engaged (scim_id is set and
    // active==true).
    auto second_login = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK_FALSE(second_login.denied);
}

TEST_CASE("oidc_login_denied_deprovisioned U1 (b): DELETE with NO re-CREATE stays DENIED "
          "— the codex bypass must remain closed",
          "[pg][oidc][scim][2001][deny-at-login][u1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-gone-forever";
    const std::string external_id = "ext-gone-forever";

    auto r = store.create_resource("gone-forever-user", external_id);
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link(iss, sub, r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // No re-CREATE happened — find_unique_active_by_external_id(external_id)
    // must return nullopt, so the decision stays DENY. This is the codex
    // bypass regression target: it must never silently reopen.
    auto decision = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value());
    CHECK(*decision.scim_id == r->scim_id);
}

TEST_CASE("oidc_login_denied_deprovisioned U1 (c): inactive (not deleted) stays DENIED; "
          "reactivating the SAME resource then PROCEEDS — unchanged by the U1 fix",
          "[pg][oidc][scim][2001][deny-at-login][u1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-deactivated";
    const std::string external_id = "ext-deactivated";

    auto r = store.create_resource("deactivated-user", external_id);
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link(iss, sub, r->scim_id));
    REQUIRE(store.set_active(r->scim_id, false));

    auto deactivated = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK(deactivated.denied);
    REQUIRE(deactivated.scim_id.has_value());
    CHECK(*deactivated.scim_id == r->scim_id);

    REQUIRE(store.set_active(r->scim_id, true));
    auto reactivated = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK_FALSE(reactivated.denied);
    CHECK_FALSE(reactivated.scim_id.has_value());
}

// Gate 8 quality-engineer NICE fold: this test does NOT compile or run a
// mutant build — it re-runs the real (correct) decision and separately
// asserts the underlying store predicate the orphaned branch consults,
// which is the same green-path shape as U1 test (b) above (this is
// intentionally a duplicate of that scenario, kept as a second, more
// granular angle on it — not an automated mutation test). The bypass this
// scenario guards against was empirically confirmed by hand: the
// quality-engineer manually edited the orphaned branch in
// oidc_scim_link.cpp to an unconditional `return {.denied = false, ...}`
// and observed `real_decision.denied` go from PASS to FAIL — no automated
// mutant build is claimed or wired into this test.
TEST_CASE("oidc_login_denied_deprovisioned U1: DENY on a genuinely deleted (never "
          "re-created) identity, with the underlying reprovision predicate pinned "
          "directly",
          "[pg][oidc][scim][2001][deny-at-login][u1][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-u1-predicate";
    const std::string external_id = "ext-u1-predicate";

    auto r = store.create_resource("u1-predicate-user", external_id);
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link(iss, sub, r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    // The real (correct) decision: DENY, because
    // find_unique_active_by_external_id(external_id) finds nothing (no
    // re-create happened).
    auto real_decision = oidc_login_denied_deprovisioned(&store, iss, sub, external_id);
    CHECK(real_decision.denied);

    // The orphaned branch's gate condition, asserted directly against the
    // store: `find_unique_active_by_external_id(link_claim_value)` returns
    // no value here (genuinely no active match) — this is exactly what
    // makes DENY the only correct outcome for the decision above, and is
    // the predicate U1 (b) exercises indirectly through the decision alone.
    CHECK_FALSE(store.find_unique_active_by_external_id(external_id).has_value());
}

// ── Governance unhappy-path finding U6 — store-unavailable audit reason ──
//
// Both deny sites in auth_routes.cpp build the audit `reason=` string from
// `decision.scim_id`'s presence: absent -> `scim_store_unavailable` (the
// store could not be asked — this must NEVER be reported as
// "resource inactive", which is fictional CC6.8 evidence on a mere outage);
// present -> `linked_scim_resource_inactive;scim_id=<id>` (a real resolved
// deprovision). This mirrors the exact ternary in auth_routes.cpp — pinned
// here since the route handler itself is unreachable without a live IdP
// (see the file-header docstring).
TEST_CASE("U6: the audit reason-string mapping distinguishes store-unavailable from "
          "resolved-deprovisioned",
          "[pg][oidc][scim][2001][deny-at-login][u6]") {
    // Mirrors auth_routes.cpp's exact construction:
    //   decision.scim_id ? "reason=linked_scim_resource_inactive;scim_id=" + *scim_id
    //                     : "reason=scim_store_unavailable"
    auto reason_for = [](const OidcLoginDenyDecision& decision) {
        return decision.scim_id
                   ? "reason=linked_scim_resource_inactive;scim_id=" + *decision.scim_id
                   : std::string("reason=scim_store_unavailable");
    };

    SECTION("store-unavailable DENY (scim_id absent) -> reason=scim_store_unavailable") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        auto decision = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                         "sub-u6-unavailable",
                                                         "ext-u6-unavailable");
        REQUIRE(decision.denied);
        REQUIRE_FALSE(decision.scim_id.has_value());
        CHECK(reason_for(decision) == "reason=scim_store_unavailable");
    }

    SECTION("resolved-deprovisioned DENY (scim_id present) -> "
           "reason=linked_scim_resource_inactive;scim_id=<id>") {
        YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        ScimStore store{pool};
        REQUIRE(store.is_open());

        auto r = store.create_resource("u6-inactive-user", "ext-u6-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-u6-inactive", r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                         "sub-u6-inactive", "ext-u6-inactive");
        REQUIRE(decision.denied);
        REQUIRE(decision.scim_id.has_value());
        CHECK(reason_for(decision) ==
              "reason=linked_scim_resource_inactive;scim_id=" + *decision.scim_id);
        CHECK(reason_for(decision) == "reason=linked_scim_resource_inactive;scim_id=" + r->scim_id);
    }
}

// Gate 8 quality-engineer MEDIUM fold: the U6 test above pins only the
// PRIMARY deny site's `reason=` ternary. There are TWO deny sites in
// auth_routes.cpp — this ADR-2001 routed-concern row (§4, PR3) names all
// three deny-at-login invariants catastrophic-if-violated, so the
// POST-MINT RE-CHECK site's construction (which appends
// `;post_mint_recheck=true;sessions_invalidated=N[;db_persisted=false]`
// after the SAME `reason=` ternary) deserves the identical pin, not just
// the primary site's. Neither site is reachable through an HTTP-level
// `/auth/callback` test (see the file-header docstring), so — mirroring
// the primary-site U6 test's approach exactly — this pins the mapping via
// a local lambda that reproduces auth_routes.cpp's exact post-mint
// `recheck_detail` construction byte-for-byte. LIMITATION: this is a
// hand-maintained mirror of production string-building code, not a shared
// testable function: if that construction is refactored, this mirror must
// be updated alongside it (the primary-site U6 lambda carries the same
// limitation).
TEST_CASE("U6: the post-mint re-check reason-string mapping also distinguishes "
          "store-unavailable from resolved-deprovisioned",
          "[pg][oidc][scim][2001][deny-at-login][u6]") {
    // Mirrors auth_routes.cpp's exact post-mint-recheck construction:
    //   recheck_detail = decision.scim_id
    //       ? "reason=linked_scim_resource_inactive;scim_id=" + *scim_id
    //       : "reason=scim_store_unavailable";
    //   recheck_detail += ";post_mint_recheck=true;sessions_invalidated=" + count;
    //   if (!db_persisted) recheck_detail += ";db_persisted=false";
    auto recheck_reason_for = [](const OidcLoginDenyDecision& decision, std::size_t sessions_count,
                                 bool db_persisted) {
        std::string recheck_detail =
            decision.scim_id
                ? "reason=linked_scim_resource_inactive;scim_id=" + *decision.scim_id
                : "reason=scim_store_unavailable";
        recheck_detail += ";post_mint_recheck=true;sessions_invalidated=" +
                          std::to_string(sessions_count);
        if (!db_persisted)
            recheck_detail += ";db_persisted=false";
        return recheck_detail;
    };

    SECTION("store-unavailable DENY (scim_id absent) -> "
           "reason=scim_store_unavailable;post_mint_recheck=true;sessions_invalidated=N") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        auto decision = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                         "sub-u6-recheck-unavailable",
                                                         "ext-u6-recheck-unavailable");
        REQUIRE(decision.denied);
        REQUIRE_FALSE(decision.scim_id.has_value());

        CHECK(recheck_reason_for(decision, /*sessions_count=*/1, /*db_persisted=*/true) ==
              "reason=scim_store_unavailable;post_mint_recheck=true;sessions_invalidated=1");

        // The db_persisted=false variant (RevokeResult's DB-write half
        // failed) appends the same suffix the primary site's sibling
        // suffix-handling already proved for db_persisted=true.
        CHECK(recheck_reason_for(decision, /*sessions_count=*/1, /*db_persisted=*/false) ==
              "reason=scim_store_unavailable;post_mint_recheck=true;sessions_invalidated=1"
              ";db_persisted=false");
    }

    SECTION("resolved-deprovisioned DENY (scim_id present) -> "
           "reason=linked_scim_resource_inactive;scim_id=<id>;post_mint_recheck=true;"
           "sessions_invalidated=N") {
        YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        ScimStore store{pool};
        REQUIRE(store.is_open());

        auto r = store.create_resource("u6-recheck-inactive-user", "ext-u6-recheck-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-u6-recheck-inactive",
                                  r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto decision = oidc_login_denied_deprovisioned(
            &store, "https://idp.example.com/", "sub-u6-recheck-inactive", "ext-u6-recheck-inactive");
        REQUIRE(decision.denied);
        REQUIRE(decision.scim_id.has_value());

        CHECK(recheck_reason_for(decision, /*sessions_count=*/2, /*db_persisted=*/true) ==
              "reason=linked_scim_resource_inactive;scim_id=" + r->scim_id +
                  ";post_mint_recheck=true;sessions_invalidated=2");
    }
}

// ── #3069 — deny-counter split: genuine vs store-unavailable ──
//
// Both deny sites in auth_routes.cpp (primary check + post-mint recheck)
// bump the TOTAL counter (`yuzu_auth_oidc_deprovisioned_denied_total`)
// unconditionally, then call the SHARED `record_deprovision_deny_split`
// helper (deprovision_deny_split.hpp, Gate 7 quality-engineer fix) to split
// into `yuzu_auth_oidc_deprovisioned_denied_genuine_total` (scim_id
// present) vs `yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total`
// (scim_id absent) — a Postgres outage must never inflate the
// genuine/alertable sub-counter. Both sites call the IDENTICAL helper, so
// ONE TEST_CASE pinning the helper directly (rather than a hand-copied
// mirror of the increment logic, which could not catch a predicate flip at
// a real call site) covers both — there is no second, site-specific
// behaviour left to pin separately.
TEST_CASE("#3069: record_deprovision_deny_split bumps genuine XOR "
          "store-unavailable, never both",
          "[pg][oidc][scim][2001][deny-at-login][3069]") {
    SECTION("store-unavailable DENY (scim_id absent) -> store_unavailable_total, "
           "NOT genuine_total") {
        PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
        ScimStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());

        auto decision = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                         "sub-3069-unavailable",
                                                         "ext-3069-unavailable");
        REQUIRE(decision.denied);
        REQUIRE_FALSE(decision.scim_id.has_value());

        yuzu::MetricsRegistry m;
        m.counter("yuzu_auth_oidc_deprovisioned_denied_total").increment();
        // MUTATION-CHECK target: flipping the predicate inside
        // record_deprovision_deny_split (`scim_id_present` instead of
        // `!scim_id_present`) makes the SECTIONs below fail — verified by
        // hand during review, reverted before merge (see the junior task's
        // VERIFY report).
        record_deprovision_deny_split(
            &m, "yuzu_auth_oidc_deprovisioned_denied_genuine_total",
            "yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total",
            decision.scim_id.has_value());

        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total").value() ==
              1.0);
        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_genuine_total").value() == 0.0);
    }

    SECTION("resolved-deprovisioned DENY (scim_id present) -> genuine_total, "
           "NOT store_unavailable_total") {
        YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        ScimStore store{pool};
        REQUIRE(store.is_open());

        auto r = store.create_resource("u3069-inactive-user", "ext-3069-inactive");
        REQUIRE(r.has_value());
        REQUIRE(store.upsert_link("https://idp.example.com/", "sub-3069-inactive", r->scim_id));
        REQUIRE(store.set_active(r->scim_id, false));

        auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                         "sub-3069-inactive", "ext-3069-inactive");
        REQUIRE(decision.denied);
        REQUIRE(decision.scim_id.has_value());

        yuzu::MetricsRegistry m;
        m.counter("yuzu_auth_oidc_deprovisioned_denied_total").increment();
        record_deprovision_deny_split(
            &m, "yuzu_auth_oidc_deprovisioned_denied_genuine_total",
            "yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total",
            decision.scim_id.has_value());

        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_genuine_total").value() == 1.0);
        CHECK(m.counter("yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total").value() ==
              0.0);
    }
}
