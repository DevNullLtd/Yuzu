/**
 * test_access_review_store.cpp — `AccessReviewStore` (Periodic Access
 * Reviews, SOC 2 CC6.2 campaign persistence).
 *
 * Covers:
 *  - R3 freeze-at-open: `open_campaign` inserts every frozen grant as a
 *    `decision='pending'` row, in one call.
 *  - `record_attestation` transitions a pending row and upserts in place on
 *    a re-attest (no duplicate row).
 *  - the closed-campaign guard: a write into a closed campaign is rejected.
 *  - the `not_found: ` prefix contract on attestation/get/close.
 *  - fail-closed construction, both the migration-drift case (a live but
 *    unmigratable database) and the fresh/unreachable-pool case that needs
 *    no live database at all (mirrors `test_engine_principal_store.cpp`'s
 *    two fail-closed cases).
 *  - persistence: a campaign's evidence survives a fresh pool/store
 *    reconnect against the SAME database — this store deliberately has NO
 *    prune method (unlike the /auto pre-flight/deployment 14-day prune);
 *    closed campaigns are permanent SOC 2 evidence, so there is no expiry
 *    path to exercise, only durability.
 *  - `list_campaigns`: returns opened campaigns newest-first (governance
 *    hardening round, H-2), empty when none.
 *
 * Born-on-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated:
 * skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken
 * (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases use the
 * pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md step
 * 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no gate at all, per
 * the plain-migration-test carve-out documented on that macro.
 */

#include "access_review_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AccessReviewStore;
using yuzu::server::GrantRef;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate access_review_store_tpl{
    "accrevstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        AccessReviewStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("access_review_store template: store failed to migrate");
    }};

std::vector<GrantRef> three_grants() {
    return {
        GrantRef{"user", "alice", "Admin", R"({"display_name":"alice"})"},
        GrantRef{"group", "eng", "Reader", R"({"display_name":"eng"})"},
        GrantRef{"engine", "engine:svc", "Writer", R"({"display_name":"svc"})"},
    };
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

// ADR-0012 §1: construction is fail-CLOSED — a reachable database whose
// schema can't migrate leaves the store !is_open() (server.cpp wires this to
// startup_failed_). Force it by pre-seeding the schema with a conflicting
// table and no schema_meta row, so the migration runner's drift guard
// refuses. Mirrors test_engine_principal_store.cpp's equivalent test.
TEST_CASE("AccessReviewStore reports !is_open on a migration failure",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA access_review_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(),
                          "CREATE TABLE access_review_store.access_review_campaign (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AccessReviewStore store{pool};
    CHECK_FALSE(store.is_open());
}

// No live database needed at all — a malformed conninfo never connects
// (PgPool::valid() is false, acquire() never attempts a connection). Mirrors
// test_engine_principal_store.cpp's StoreUnreachable section. Also proves
// EVERY mutator/reader surfaces the closed store rather than silently
// no-opping or crashing.
TEST_CASE("AccessReviewStore reports !is_open on an unreachable pool, and every method fails "
          "closed",
          "[access_review][store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    AccessReviewStore store{pool};
    CHECK_FALSE(store.is_open());

    CHECK_FALSE(store.open_campaign("t", "admin", {}, "enabled").has_value());
    CHECK_FALSE(store.record_attestation("x", "user", "a", "R", "attested", "r", "").has_value());
    CHECK_FALSE(store.get_campaign("x").has_value());
    CHECK_FALSE(store.close_campaign("x", "admin").has_value());
}

// ── Migration v1->v2 (rbac_enforcement column, A3) ──────────────────────────

// UP-7 pattern (test_api_token_store.cpp's v2->v3 case, test_quarantine_store.cpp's
// own v1->v2 case): every other test in this file clones access_review_store_tpl,
// already at v2 — the real v1->v2 upgrade path (PgMigrationRunner applying v2's
// ALTER against a genuinely-populated v1 table) is otherwise untested. Hand-seeds
// v1 DDL verbatim (copied from migrations() in access_review_store.cpp, file-local
// and not exported), stamps schema_meta at v1, and inserts a pre-existing campaign
// row BEFORE handing the database to a real AccessReviewStore construction — the
// column's '' default is the honest-empty value this test proves for a row that
// genuinely predates rbac_enforcement, never re-derived or backfilled.
TEST_CASE("AccessReviewStore: a genuine v1->v2 upgrade (real ALTER against a populated "
         "table) opens cleanly and rbac_enforcement defaults to '' on the pre-existing row",
         "[access_review][store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    std::string pre_v2_id;
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA access_review_store")};
        REQUIRE(schema.ok());

        // v1 DDL, copied from migrations() in access_review_store.cpp, but
        // SCHEMA-QUALIFIED throughout (a raw PQexec on a plain connection
        // does not get the transaction-scoped search_path the real runner
        // sets — see that file's "Unqualified DDL" comment).
        PgResult v1{PQexec(
            conn.get(),
            "CREATE TABLE access_review_store.access_review_campaign ("
            "  campaign_id    TEXT PRIMARY KEY,"
            "  title          TEXT NOT NULL,"
            "  status         TEXT NOT NULL CHECK (status IN ('open','closed')),"
            "  created_by     TEXT NOT NULL,"
            "  created_at_ms  BIGINT NOT NULL,"
            "  closed_by      TEXT NOT NULL DEFAULT '',"
            "  closed_at_ms   BIGINT NOT NULL DEFAULT 0);"
            "CREATE INDEX access_review_campaign_status_idx ON "
            "access_review_store.access_review_campaign (status);"
            "CREATE TABLE access_review_store.access_review_attestation ("
            "  campaign_id     TEXT NOT NULL REFERENCES "
            "access_review_store.access_review_campaign(campaign_id) ON DELETE CASCADE,"
            "  principal_type  TEXT NOT NULL CHECK (principal_type IN ('user','group','engine')),"
            "  principal_id    TEXT NOT NULL,"
            "  role_name       TEXT NOT NULL,"
            "  decision        TEXT NOT NULL CHECK (decision IN ('pending','attested',"
            "                  'flagged_revoke')),"
            "  reviewer        TEXT NOT NULL DEFAULT '',"
            "  decided_at_ms   BIGINT NOT NULL DEFAULT 0,"
            "  justification   TEXT NOT NULL DEFAULT '',"
            "  grant_snapshot  TEXT NOT NULL DEFAULT '',"
            "  PRIMARY KEY (campaign_id, principal_type, principal_id, role_name));")};
        REQUIRE(v1.ok());
        PgResult stamp{
            PQexec(conn.get(), "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                               "VALUES ('access_review_store', 1, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());

        // A row genuinely present BEFORE the v2 ALTER runs — no
        // rbac_enforcement column exists at this point at all.
        PgResult seed{PQexec(
            conn.get(), "INSERT INTO access_review_store.access_review_campaign "
                       "(campaign_id, title, status, created_by, created_at_ms) VALUES "
                       "('pre-v2-campaign', 'Pre-A3 campaign', 'open', 'admin', 1000) "
                       "RETURNING campaign_id")};
        REQUIRE(seed.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(seed.get()) == 1);
        pre_v2_id = PQgetvalue(seed.get(), 0, 0);
    }

    // The real construction path: PgMigrationRunner::run reads version 1 from
    // schema_meta and applies v2's ALTER against the table seeded above.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto view = store.get_campaign(pre_v2_id);
    REQUIRE(view.has_value());
    CHECK(view->campaign.title == "Pre-A3 campaign");
    // The honest-empty default — NOT "degraded": the store never degraded,
    // the column simply didn't exist when this row was written.
    CHECK(view->campaign.rbac_enforcement.empty());

    // A NEW campaign opened after the upgrade gets a real value, proving the
    // ALTER's CHECK constraint (added in the same migration) doesn't reject
    // a live open_campaign() write.
    auto open_res = store.open_campaign("Post-A3 campaign", "admin", {}, "enabled");
    REQUIRE(open_res.has_value());
    auto view2 = store.get_campaign(*open_res);
    REQUIRE(view2.has_value());
    CHECK(view2->campaign.rbac_enforcement == "enabled");
}

// ── rbac_enforcement validation (A3, RBAC delivery plan) ───────────────────

// The column's own '' default exists ONLY for a pre-A3 row (schema migration
// 2) — a live open_campaign() caller must always supply one of the three
// real values, mirroring record_attestation's decision validation below.
TEST_CASE("open_campaign rejects an rbac_enforcement value outside "
         "{enabled,disabled,degraded}",
         "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    for (const std::string& bad : {std::string(""), std::string("on"), std::string("ENABLED"),
                                   std::string("unknown")}) {
        auto res = store.open_campaign("Bad enforcement", "admin", {}, bad);
        REQUIRE_FALSE(res.has_value());
        CHECK_FALSE(res.error().starts_with("not_found:"));
    }
}

// ── Freeze-at-open (R3) ──────────────────────────────────────────────────────

TEST_CASE("open_campaign freezes the full population as pending rows (R3)",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Q3 Review", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    CHECK_FALSE(open_res->empty());

    auto view_res = store.get_campaign(*open_res);
    REQUIRE(view_res.has_value());
    CHECK(view_res->campaign.campaign_id == *open_res);
    CHECK(view_res->campaign.title == "Q3 Review");
    CHECK(view_res->campaign.status == "open");
    CHECK(view_res->campaign.created_by == "admin");
    CHECK(view_res->campaign.closed_by.empty());
    CHECK(view_res->campaign.closed_at_ms == 0);
    CHECK(view_res->campaign.rbac_enforcement == "enabled"); // A3 — frozen at open
    REQUIRE(view_res->attestations.size() == 3);
    CHECK(view_res->pending_count == 3);
    for (const auto& a : view_res->attestations) {
        CHECK(a.decision == "pending");
        CHECK(a.reviewer.empty());
        CHECK(a.decided_at_ms == 0);
    }
}

TEST_CASE("open_campaign with an empty population still opens a campaign (zero pending rows)",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Empty", "admin", {}, "disabled");
    REQUIRE(open_res.has_value());
    auto view_res = store.get_campaign(*open_res);
    REQUIRE(view_res.has_value());
    CHECK(view_res->attestations.empty());
    CHECK(view_res->pending_count == 0);
    CHECK(view_res->campaign.rbac_enforcement == "disabled");
}

// governance hardening round: get_campaign's two reads (campaign row +
// attestation rows) now run under REPEATABLE READ instead of a plain
// `with_txn_for` BEGIN (READ COMMITTED); this test pins that get_campaign's
// genuine mid-read failure path — as opposed to the not_found path above —
// still surfaces as a plain error, distinguishable by NOT carrying the
// `not_found:` prefix. Forced by dropping the attestation table out from
// under an already-open store (the campaign row read succeeds first, the
// attestation-rows read then fails), mirroring the migration-fail fixture's
// raw-connection pattern at the top of this file.
TEST_CASE("get_campaign: a genuine read failure mid-enumeration is a plain error, never "
         "mistaken for not_found",
         "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Drop test", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE access_review_store.access_review_attestation")};
        REQUIRE(d.ok());
    }

    auto view_res = store.get_campaign(*open_res);
    REQUIRE_FALSE(view_res.has_value());
    CHECK_FALSE(view_res.error().starts_with("not_found:"));
    CHECK(view_res.error().find("attestation read failed") != std::string::npos);
}

// ── record_attestation: transition + upsert ─────────────────────────────────

TEST_CASE("record_attestation transitions a pending row and upserts in place on re-attest",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("R1", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    auto rec1 = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "ok");
    REQUIRE(rec1.has_value());

    auto view1 = store.get_campaign(cid);
    REQUIRE(view1.has_value());
    CHECK(view1->pending_count == 2);
    bool found_attested = false;
    for (const auto& a : view1->attestations) {
        if (a.principal_type == "user" && a.principal_id == "alice" && a.role_name == "Admin") {
            found_attested = true;
            CHECK(a.decision == "attested");
            CHECK(a.reviewer == "carol");
            CHECK(a.justification == "ok");
            CHECK(a.decided_at_ms > 0);
        }
    }
    CHECK(found_attested);

    // Re-attest the SAME grant with a different decision: overwrites in
    // place — still exactly one row for this (campaign, principal, role).
    auto rec2 =
        store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "dave", "stale");
    REQUIRE(rec2.has_value());
    auto view2 = store.get_campaign(cid);
    REQUIRE(view2.has_value());
    CHECK(view2->attestations.size() == 3); // no new row added
    int matches = 0;
    for (const auto& a : view2->attestations) {
        if (a.principal_type == "user" && a.principal_id == "alice" && a.role_name == "Admin") {
            ++matches;
            CHECK(a.decision == "flagged_revoke");
            CHECK(a.reviewer == "dave");
            CHECK(a.justification == "stale");
        }
    }
    CHECK(matches == 1);
    CHECK(view2->pending_count == 2); // unchanged — still one non-pending row
}

TEST_CASE("record_attestation rejects a decision outside {attested,flagged_revoke}",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Bad decision", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());

    auto rec = store.record_attestation(*open_res, "user", "alice", "Admin", "pending", "carol",
                                        "");
    REQUIRE_FALSE(rec.has_value());
    // Not the not_found: prefix — this is a caller-input validation failure,
    // rejected before any query runs.
    CHECK_FALSE(rec.error().starts_with("not_found:"));
}

// ── Closed-campaign guard ────────────────────────────────────────────────────

TEST_CASE("record_attestation rejects a write into a closed campaign",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Closed test", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    auto close_res = store.close_campaign(cid, "admin");
    REQUIRE(close_res.has_value());

    auto rec = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "");
    REQUIRE_FALSE(rec.has_value());
    CHECK(rec.error().starts_with("not_found:"));

    // Evidence unchanged: the campaign still shows the row as pending — a
    // rejected write must never partially land.
    auto view = store.get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
}

// ── not_found: prefix contract ──────────────────────────────────────────────

TEST_CASE("not_found: mapping on attestation/get/close for a bogus campaign_id",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto att = store.record_attestation("bogus-campaign-id", "user", "alice", "Admin", "attested",
                                        "carol", "");
    REQUIRE_FALSE(att.has_value());
    CHECK(att.error().starts_with("not_found:"));

    auto get = store.get_campaign("bogus-campaign-id");
    REQUIRE_FALSE(get.has_value());
    CHECK(get.error().starts_with("not_found:"));

    auto close = store.close_campaign("bogus-campaign-id", "admin");
    REQUIRE_FALSE(close.has_value());
    CHECK(close.error().starts_with("not_found:"));
}

TEST_CASE("record_attestation on a grant never in the frozen population is not_found",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Narrow", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());

    // A real, open campaign — but this (principal, role) tuple was never in
    // the frozen population.
    auto rec = store.record_attestation(*open_res, "user", "nobody", "NoSuchRole", "attested",
                                        "carol", "");
    REQUIRE_FALSE(rec.has_value());
    CHECK(rec.error().starts_with("not_found:"));
}

TEST_CASE("close_campaign is idempotent-rejecting: closing twice returns not_found",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Double close", "admin", {}, "enabled");
    REQUIRE(open_res.has_value());
    REQUIRE(store.close_campaign(*open_res, "admin").has_value());

    auto second = store.close_campaign(*open_res, "admin");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().starts_with("not_found:"));
}

// ── Persistence — no prune ──────────────────────────────────────────────────

TEST_CASE("campaign evidence persists across a fresh store/connection — there is no prune path "
          "to exercise, only durability",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    std::string cid;
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        AccessReviewStore store{pool};
        REQUIRE(store.is_open());
        auto open_res = store.open_campaign("Durable", "admin", three_grants(), "degraded");
        REQUIRE(open_res.has_value());
        cid = *open_res;
        REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "")
                   .has_value());
    } // pool/store fully torn down here

    // A FRESH pool + store instance against the SAME database — this is what
    // distinguishes "durable Postgres state" from "an in-process cache".
    // AccessReviewStore deliberately has no prune method (unlike the /auto
    // pre-flight/deployment runs' 14-day prune) — a closed-or-open campaign's
    // evidence is meant to persist indefinitely, so there is no expiry to
    // exercise here.
    PgPool pool2{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store2{pool2};
    REQUIRE(store2.is_open());
    auto view = store2.get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->campaign.title == "Durable");
    CHECK(view->campaign.rbac_enforcement == "degraded"); // A3 — frozen value survives too
    CHECK(view->pending_count == 2);
    bool found_attested = false;
    for (const auto& a : view->attestations)
        if (a.decision == "attested")
            found_attested = true;
    CHECK(found_attested);
}

// ── list_campaigns ───────────────────────────────────────────────────────────

TEST_CASE("list_campaigns: empty when no campaign has ever been opened",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto list_res = store.list_campaigns();
    REQUIRE(list_res.has_value()); // a genuine empty result, never unexpected
    CHECK(list_res->empty());
}

TEST_CASE("list_campaigns: returns every opened campaign's metadata, newest-first",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_a = store.open_campaign("Campaign A", "admin", {}, "enabled");
    REQUIRE(open_a.has_value());
    auto open_b = store.open_campaign("Campaign B", "admin", {}, "disabled");
    REQUIRE(open_b.has_value());
    auto open_c = store.open_campaign("Campaign C", "admin", three_grants(), "degraded");
    REQUIRE(open_c.has_value());

    auto list_res = store.list_campaigns();
    REQUIRE(list_res.has_value());
    REQUIRE(list_res->size() == 3);

    // The store orders by `created_at_ms DESC, campaign_id DESC`
    // (access_review_store.cpp) — the secondary key is a deterministic
    // tie-breaker for opens that land in the same millisecond, so the
    // returned order must be internally consistent on every run rather than
    // depending on wall-clock spacing between the three opens above.
    for (std::size_t i = 1; i < list_res->size(); ++i) {
        const auto& prev = (*list_res)[i - 1];
        const auto& cur = (*list_res)[i];
        CHECK((prev.created_at_ms > cur.created_at_ms ||
               (prev.created_at_ms == cur.created_at_ms &&
                prev.campaign_id > cur.campaign_id)));
    }

    std::set<std::string> seen_ids;
    for (const auto& c : *list_res)
        seen_ids.insert(c.campaign_id);
    CHECK(seen_ids == std::set<std::string>{*open_a, *open_b, *open_c});

    // list_campaigns is metadata-only — it does NOT return attestation rows
    // (get_campaign is the surface for those); every listed row's status
    // reflects the fresh-open state.
    for (const auto& c : *list_res) {
        CHECK(c.status == "open");
        CHECK(c.created_by == "admin");
        CHECK(c.closed_by.empty());
        CHECK(c.closed_at_ms == 0);
    }

    // Each campaign's own rbac_enforcement stamp survives the round trip
    // through list_campaigns (A3) — distinct per campaign, so this also
    // proves the column isn't shared/aliased across rows.
    auto find = [&](const std::string& id) {
        return std::find_if(list_res->begin(), list_res->end(),
                            [&](const auto& c) { return c.campaign_id == id; });
    };
    REQUIRE(find(*open_a) != list_res->end());
    CHECK(find(*open_a)->rbac_enforcement == "enabled");
    REQUIRE(find(*open_b) != list_res->end());
    CHECK(find(*open_b)->rbac_enforcement == "disabled");
    REQUIRE(find(*open_c) != list_res->end());
    CHECK(find(*open_c)->rbac_enforcement == "degraded");
}

TEST_CASE("list_campaigns: a closed campaign's metadata still appears (list is not filtered by "
          "status)",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Will be closed", "admin", {}, "enabled");
    REQUIRE(open_res.has_value());
    REQUIRE(store.close_campaign(*open_res, "admin").has_value());

    auto list_res = store.list_campaigns();
    REQUIRE(list_res.has_value());
    REQUIRE(list_res->size() == 1);
    CHECK((*list_res)[0].campaign_id == *open_res);
    CHECK((*list_res)[0].status == "closed");
    CHECK((*list_res)[0].closed_by == "admin");
    CHECK((*list_res)[0].closed_at_ms > 0);
}
