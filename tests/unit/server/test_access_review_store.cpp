/**
 * test_access_review_store.cpp — `AccessReviewStore` (Periodic Access
 * Reviews, SOC 2 CC6.2 campaign persistence).
 *
 * Covers:
 *  - R3 freeze-at-open: `open_campaign` inserts every frozen grant as a
 *    `decision='pending'` row, in one call.
 *  - `record_attestation` transitions a pending row and APPENDS on a later
 *    decision (#4752): the current row advances, every decision is kept in
 *    the history table, a reviewer cannot decide a `user` grant naming
 *    themselves, and the schema-v3 guards refuse every raw-SQL route around it.
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

#include "access_review_model.hpp"
#include "access_review_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include "test_principal_lock_gate.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <set>
#include <chrono>
#include <cstdlib>
#include <expected>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
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

TEST_CASE("open_campaign bounds the title: the cap is accepted, one byte over is a bad_request "
          "and nothing is written",
          "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    const std::string at_cap(yuzu::server::kCampaignTitleMaxLen, 'a');
    auto ok = store.open_campaign(at_cap, "admin", {}, "enabled");
    REQUIRE(ok.has_value());

    auto over = store.open_campaign(at_cap + "a", "admin", {}, "enabled");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error() ==
          "bad_request: " + std::string(yuzu::server::kCampaignTitleTooLongMessage));

    // Only the campaign at the cap exists.
    auto list = store.list_campaigns();
    REQUIRE(list.has_value());
    CHECK(list->size() == 1);
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
        // CASCADE: the history table's foreign key (schema v3) makes a plain DROP fail.
        PgResult d{
            PQexec(conn.get(), "DROP TABLE access_review_store.access_review_attestation CASCADE")};
        REQUIRE(d.ok());
    }

    auto view_res = store.get_campaign(*open_res);
    REQUIRE_FALSE(view_res.has_value());
    CHECK_FALSE(view_res.error().starts_with("not_found:"));
    CHECK(view_res.error().find("attestation read failed") != std::string::npos);
}

// ── record_attestation: transition + append ────────────────────────────────

namespace {

const yuzu::server::AccessReviewAttestationRow* find_row(const yuzu::server::CampaignView& v,
                                                         std::string_view type, std::string_view id,
                                                         std::string_view role) {
    for (const auto& a : v.attestations)
        if (a.principal_type == type && a.principal_id == id && a.role_name == role)
            return &a;
    return nullptr;
}

} // namespace

TEST_CASE("record_attestation transitions a pending row and APPENDS a later decision",
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
    CHECK(rec1->previous_decision == "pending");
    CHECK(rec1->seq == 1);

    auto view1 = store.get_campaign(cid);
    REQUIRE(view1.has_value());
    CHECK(view1->pending_count == 2);
    const auto* r1 = find_row(*view1, "user", "alice", "Admin");
    REQUIRE(r1 != nullptr);
    CHECK(r1->decision == "attested");
    CHECK(r1->reviewer == "carol");
    CHECK(r1->justification == "ok");
    CHECK(r1->decided_at_ms > 0);
    CHECK(r1->decision_seq == 1);
    CHECK(r1->history.empty()); // history is opt-in

    // A different reviewer decides the SAME grant again: the current row advances to seq 2
    // and the earlier decision stays in the history, with what it superseded.
    auto rec2 =
        store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "dave", "stale");
    REQUIRE(rec2.has_value());
    CHECK(rec2->previous_decision == "attested");
    CHECK(rec2->seq == 2);

    auto view2 = store.get_campaign(cid, /*include_history=*/true);
    REQUIRE(view2.has_value());
    CHECK(view2->attestations.size() == 3); // no new row added
    CHECK(view2->pending_count == 2);       // unchanged: still one non-pending row
    const auto* r2 = find_row(*view2, "user", "alice", "Admin");
    REQUIRE(r2 != nullptr);
    CHECK(r2->decision == "flagged_revoke");
    CHECK(r2->reviewer == "dave");
    CHECK(r2->justification == "stale");
    CHECK(r2->decision_seq == 2);
    REQUIRE(r2->history.size() == 2);
    CHECK(r2->history[0].seq == 1);
    CHECK(r2->history[0].decision == "attested");
    CHECK(r2->history[0].previous_decision == "pending");
    CHECK(r2->history[0].reviewer == "carol");
    CHECK(r2->history[0].justification == "ok");
    CHECK(r2->history[0].decided_at_ms == r1->decided_at_ms);
    CHECK(r2->history[1].seq == 2);
    CHECK(r2->history[1].decision == "flagged_revoke");
    CHECK(r2->history[1].previous_decision == "attested");
    CHECK(r2->history[1].reviewer == "dave");
    CHECK(r2->history[1].justification == "stale");
    CHECK(r2->history[1].decided_at_ms == r2->decided_at_ms);

    // The other grants are untouched and carry no history.
    for (const auto& a : view2->attestations)
        if (a.principal_id != "alice") {
            CHECK(a.decision == "pending");
            CHECK(a.decision_seq == 0);
            CHECK(a.history.empty());
        }
}

TEST_CASE("record_attestation: an identical repeat decision appends at seq+1 too",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Repeat", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    auto first = store.record_attestation(cid, "group", "eng", "Reader", "attested", "carol", "ok");
    REQUIRE(first.has_value());
    CHECK(first->seq == 1);
    auto again = store.record_attestation(cid, "group", "eng", "Reader", "attested", "carol", "ok");
    REQUIRE(again.has_value());
    CHECK(again->previous_decision == "attested"); // equal to the new decision
    CHECK(again->seq == 2);

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "group", "eng", "Reader");
    REQUIRE(row != nullptr);
    CHECK(row->decision_seq == 2);
    REQUIRE(row->history.size() == 2);
    CHECK(row->history[1].decision == "attested");
    CHECK(row->history[1].previous_decision == "attested");
}

TEST_CASE("record_attestation: a grant keeps at most kMaxDecisionsPerGrant decisions; the next is "
          "refused with bad_request and writes nothing",
          "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Cap", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    for (std::int32_t i = 1; i <= yuzu::server::kMaxDecisionsPerGrant; ++i) {
        const std::string decision = i % 2 ? "attested" : "flagged_revoke";
        auto r = store.record_attestation(cid, "group", "eng", "Reader", decision, "carol", "n");
        REQUIRE(r.has_value());
        CHECK(r->seq == i);
        CHECK(r->previous_decision ==
              (i == 1 ? "pending" : (i % 2 ? "flagged_revoke" : "attested")));
    }

    const std::string expected = "bad_request: " + std::string(yuzu::server::kDecisionCapMessage);
    for (int attempt = 0; attempt < 2; ++attempt) { // refused again, never a different answer
        auto over =
            store.record_attestation(cid, "group", "eng", "Reader", "attested", "dave", "x");
        REQUIRE_FALSE(over.has_value());
        CHECK(over.error() == expected);
    }

    auto view = store.get_campaign(cid, /*include_history=*/true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "group", "eng", "Reader");
    REQUIRE(row != nullptr);
    CHECK(row->decision_seq == 100);
    CHECK(row->decision == "flagged_revoke"); // the 100th decision, not the refused one
    CHECK(row->reviewer == "carol");
    REQUIRE(row->history.size() == 100);
    CHECK(row->history.front().seq == 1);
    CHECK(row->history.back().seq == 100);

    // A different grant of the same campaign is unaffected.
    auto other = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "ok");
    REQUIRE(other.has_value());
    CHECK(other->seq == 1);
    CHECK(other->previous_decision == "pending");
}

TEST_CASE("get_campaign(include_history) returns each grant's latest kMaxDecisionsPerGrant entries "
          "in ascending order and keeps decision_seq as the total",
          "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Bounded", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    REQUIRE(store.record_attestation(cid, "group", "eng", "Reader", "attested", "carol", "first")
                .has_value());
    REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "one")
                .has_value());
    REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "dave", "two")
                .has_value());

    {
        // The per-test clone lets the owner reach the state the write cap prevents: 105 history
        // rows for one grant. Both guard triggers are disabled here, in this database only.
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string att = "access_review_store.access_review_attestation";
        const std::string hist = "access_review_store.access_review_attestation_history";
        for (const std::string sql :
             {"ALTER TABLE " + att + " DISABLE TRIGGER access_review_attestation_guard",
              "ALTER TABLE " + hist + " DISABLE TRIGGER access_review_history_consistent",
              "INSERT INTO " + hist +
                  " (campaign_id, principal_type, principal_id, role_name, seq, decision, "
                  "previous_decision, reviewer, justification, decided_at_ms) "
                  "SELECT '" +
                  cid +
                  "','group','eng','Reader', g, 'attested', 'attested', "
                  "'carol', 'row ' || g, g FROM generate_series(2,105) g",
              "UPDATE " + att + " SET decision_seq=105 WHERE campaign_id='" + cid +
                  "' AND principal_id='eng'"}) {
            PgResult r{PQexec(conn.get(), sql.c_str())};
            INFO(sql);
            REQUIRE(r.ok());
        }
    }

    auto view = store.get_campaign(cid, /*include_history=*/true);
    REQUIRE(view.has_value());
    const auto* eng = find_row(*view, "group", "eng", "Reader");
    REQUIRE(eng != nullptr);
    CHECK(eng->decision_seq == 105); // the total, so truncation reads as decision_seq > entries
    REQUIRE(eng->history.size() == 100);
    CHECK(eng->history.front().seq == 6);
    CHECK(eng->history.back().seq == 105);
    for (std::size_t i = 0; i < eng->history.size(); ++i)
        CHECK(eng->history[i].seq == 6 + static_cast<std::int32_t>(i));
    CHECK(eng->history.front().justification == "row 6");

    // The other grants are not cut: alice keeps both entries, the pending grant has none.
    const auto* alice = find_row(*view, "user", "alice", "Admin");
    REQUIRE(alice != nullptr);
    CHECK(alice->decision_seq == 2);
    REQUIRE(alice->history.size() == 2);
    CHECK(alice->history[0].seq == 1);
    CHECK(alice->history[1].seq == 2);
    const auto* pending = find_row(*view, "engine", "engine:svc", "Writer");
    REQUIRE(pending != nullptr);
    CHECK(pending->decision_seq == 0);
    CHECK(pending->history.empty());

    // The default read is unchanged: no history, the total still reported.
    auto bare = store.get_campaign(cid);
    REQUIRE(bare.has_value());
    const auto* bare_eng = find_row(*bare, "group", "eng", "Reader");
    REQUIRE(bare_eng != nullptr);
    CHECK(bare_eng->decision_seq == 105);
    CHECK(bare_eng->history.empty());

    // Past the cap the write is refused, so the row stays at 105.
    auto over = store.record_attestation(cid, "group", "eng", "Reader", "attested", "erin", "x");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().starts_with("bad_request:"));
}

TEST_CASE("record_attestation: the reviewer must differ from the subject of a user grant",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("SoD", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    auto self = store.record_attestation(cid, "user", "alice", "Admin", "attested", "alice", "me");
    REQUIRE_FALSE(self.has_value());
    CHECK(self.error() == "forbidden: reviewer is the subject of this grant");

    // Byte-exact: a different case is a different reviewer (no case folding).
    auto cased = store.record_attestation(cid, "user", "alice", "Admin", "attested", "Alice", "");
    REQUIRE(cased.has_value());
    CHECK(cased->seq == 1);

    // Nothing was written by the refused call (the cased call above wrote seq 1 only).
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "user", "alice", "Admin");
    REQUIRE(row != nullptr);
    CHECK(row->decision_seq == 1);
    CHECK(row->history.size() == 1);
    // A flag cannot be undone by the subject either.
    auto flagged =
        store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "carol", "no");
    REQUIRE(flagged.has_value());
    auto unflag = store.record_attestation(cid, "user", "alice", "Admin", "attested", "alice", "");
    REQUIRE_FALSE(unflag.has_value());
    CHECK(unflag.error().starts_with("forbidden:"));
    auto after = store.get_campaign(cid, true);
    REQUIRE(after.has_value());
    const auto* arow = find_row(*after, "user", "alice", "Admin");
    REQUIRE(arow != nullptr);
    CHECK(arow->decision == "flagged_revoke");
    CHECK(arow->history.size() == 2);
}

TEST_CASE("record_attestation: a self-subject user decision is forbidden even in a closed or "
          "unknown campaign, and an engine or group subject is not refused by the store",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("SoD closed", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    REQUIRE(store.close_campaign(cid, "admin").has_value());

    // forbidden precedes not_found: the caller holds Attest and can read the campaign anyway.
    auto self_closed =
        store.record_attestation(cid, "user", "alice", "Admin", "attested", "alice", "");
    REQUIRE_FALSE(self_closed.has_value());
    CHECK(self_closed.error().starts_with("forbidden:"));
    auto self_unknown = store.record_attestation(std::string(64, 'a'), "user", "alice", "Admin",
                                                 "attested", "alice", "");
    REQUIRE_FALSE(self_unknown.has_value());
    CHECK(self_unknown.error().starts_with("forbidden:"));
    // A malformed campaign id is still a bad_request, ahead of the reviewer rule.
    auto bad_id =
        store.record_attestation("bad id", "user", "alice", "Admin", "attested", "alice", "");
    REQUIRE_FALSE(bad_id.has_value());
    CHECK(bad_id.error().starts_with("bad_request:"));

    // The same reviewer name on an engine or group subject is NOT refused here: those rules need
    // other stores and belong to the route layer's gate.
    auto open2 = store.open_campaign("SoD kinds", "admin", three_grants(), "enabled");
    REQUIRE(open2.has_value());
    auto grp = store.record_attestation(*open2, "group", "eng", "Reader", "attested", "eng", "");
    REQUIRE(grp.has_value());
    auto eng = store.record_attestation(*open2, "engine", "engine:svc", "Writer", "attested",
                                        "engine:svc", "");
    REQUIRE(eng.has_value());

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations) {
        CHECK(a.decision_seq == 0);
        CHECK(a.history.empty());
    }
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
    // rejected write must never partially land, history included.
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations)
        CHECK(a.history.empty());
}

TEST_CASE("record_attestation into a closed campaign after a decision leaves history unchanged",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Closed after", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "ok")
                .has_value());
    REQUIRE(store.close_campaign(cid, "admin").has_value());

    auto late =
        store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "dave", "late");
    REQUIRE_FALSE(late.has_value());
    CHECK(late.error().starts_with("not_found:"));

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "user", "alice", "Admin");
    REQUIRE(row != nullptr);
    CHECK(row->decision == "attested");
    CHECK(row->decision_seq == 1);
    CHECK(row->history.size() == 1);
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

// ── campaign id validation and input bounds (#6939) ─────────────────────────

TEST_CASE("get/record/close refuse a malformed campaign_id with bad_request, never not_found",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Bad ids", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());

    // A NUL id would truncate to "abc" at the libpq bind; 65 bytes is one over the cap; the empty
    // id used to be not_found. Every one must be refused before the pool is touched.
    const std::vector<std::string> bad_ids = {std::string("abc\0def", 7), std::string(65, 'a'),
                                              std::string(""), std::string("has space"),
                                              std::string("a.b")};
    for (const auto& bad : bad_ids) {
        INFO("id size " << bad.size());
        auto get = store.get_campaign(bad);
        REQUIRE_FALSE(get.has_value());
        CHECK(get.error().starts_with("bad_request:"));

        auto att = store.record_attestation(bad, "user", "alice", "Admin", "attested", "carol", "");
        REQUIRE_FALSE(att.has_value());
        CHECK(att.error().starts_with("bad_request:"));

        auto close = store.close_campaign(bad, "admin");
        REQUIRE_FALSE(close.has_value());
        CHECK(close.error().starts_with("bad_request:"));
    }

    // Nothing landed: the real campaign is still open with every row pending.
    auto view = store.get_campaign(*open_res);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "open");
    CHECK(view->pending_count == 3);
}

TEST_CASE("a well-formed but unknown campaign_id is still not_found (64 bytes accepted)",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    const std::string id64(64, 'a');
    auto get = store.get_campaign(id64);
    REQUIRE_FALSE(get.has_value());
    CHECK(get.error().starts_with("not_found:"));
    auto att = store.record_attestation(id64, "user", "alice", "Admin", "attested", "carol", "");
    REQUIRE_FALSE(att.has_value());
    CHECK(att.error().starts_with("not_found:"));
    auto close = store.close_campaign(id64, "admin");
    REQUIRE_FALSE(close.has_value());
    CHECK(close.error().starts_with("not_found:"));
}

TEST_CASE("record_attestation refuses an embedded NUL in any text field and writes nothing",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("NUL fields", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    const std::string nul("ab\0cd", 5);

    // principal_id "alice\0x" would truncate to the real grant "alice" and decide it.
    const std::string alice_nul("alice\0x", 7);
    auto r1 = store.record_attestation(cid, "user", alice_nul, "Admin", "attested", "carol", "");
    REQUIRE_FALSE(r1.has_value());
    CHECK(r1.error().starts_with("bad_request:"));
    auto r2 = store.record_attestation(cid, "user", "alice", std::string("Admin\0x", 7), "attested",
                                       "carol", "");
    REQUIRE_FALSE(r2.has_value());
    CHECK(r2.error().starts_with("bad_request:"));
    auto r3 = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", nul);
    REQUIRE_FALSE(r3.has_value());
    CHECK(r3.error().starts_with("bad_request:"));
    auto r4 = store.record_attestation(cid, "user", "alice", "Admin", "attested", nul, "ok");
    REQUIRE_FALSE(r4.has_value());
    CHECK(r4.error().starts_with("bad_request:"));

    auto view = store.get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations) {
        CHECK(a.decision == "pending");
        CHECK(a.reviewer.empty());
        CHECK(a.justification.empty());
    }
}

TEST_CASE("record_attestation refuses an embedded NUL in principal_type and writes nothing",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("NUL type", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    // "user\0x" would truncate to the real principal_type "user" and decide alice's row.
    auto r = store.record_attestation(cid, std::string("user\0x", 6), "alice", "Admin", "attested",
                                      "carol", "");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().starts_with("bad_request:"));
    CHECK(r.error().find("principal_type") != std::string::npos);

    auto view = store.get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations) {
        CHECK(a.decision == "pending");
        CHECK(a.reviewer.empty());
    }
}

TEST_CASE("close_campaign refuses an embedded NUL in closed_by and leaves the campaign open",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("NUL closer", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    auto close = store.close_campaign(cid, std::string("admin\0x", 7));
    REQUIRE_FALSE(close.has_value());
    CHECK(close.error().starts_with("bad_request:"));
    CHECK(close.error().find("closed_by") != std::string::npos);

    auto view = store.get_campaign(cid);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "open");
    CHECK(view->campaign.closed_by.empty());
    CHECK(view->pending_count == 3);

    // A clean close of the same campaign still works afterwards.
    REQUIRE(store.close_campaign(cid, "admin").has_value());
}

TEST_CASE("open_campaign refuses an embedded NUL in title or created_by and creates nothing",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto bad_title =
        store.open_campaign(std::string("Q3\0x", 4), "admin", three_grants(), "enabled");
    REQUIRE_FALSE(bad_title.has_value());
    CHECK(bad_title.error().starts_with("bad_request:"));
    CHECK(bad_title.error().find("title") != std::string::npos);

    auto bad_creator =
        store.open_campaign("Q3", std::string("admin\0x", 7), three_grants(), "enabled");
    REQUIRE_FALSE(bad_creator.has_value());
    CHECK(bad_creator.error().starts_with("bad_request:"));
    CHECK(bad_creator.error().find("created_by") != std::string::npos);

    auto campaigns = store.list_campaigns();
    REQUIRE(campaigns.has_value());
    CHECK(campaigns->empty());
}

TEST_CASE("record_attestation refuses an empty reviewer and an over-long grant field, and writes "
          "nothing",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Bounds", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    // An empty reviewer: bad_request (400), the same posture as close_campaign's empty closed_by.
    auto empty = store.record_attestation(cid, "user", "alice", "Admin", "attested", "", "ok");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error().starts_with("bad_request:"));
    CHECK(empty.error().find("reviewer") != std::string::npos);

    // Each grant field is capped at 1024 bytes; one more is bad_request with the shared text, and
    // exactly 1024 passes the bound (not_found: no such frozen grant).
    REQUIRE(yuzu::server::kPrincipalIdMaxLen == 1024);
    REQUIRE(yuzu::server::kRoleNameMaxLen == 1024);
    const std::string text = "bad_request: " + std::string(yuzu::server::kGrantFieldInvalidMessage);
    const std::string over(1025, 'a');
    const std::string at_cap(1024, 'a');
    auto r1 = store.record_attestation(cid, "user", over, "Admin", "attested", "carol", "");
    REQUIRE_FALSE(r1.has_value());
    CHECK(r1.error() == text);
    auto r2 = store.record_attestation(cid, "user", "alice", over, "attested", "carol", "");
    REQUIRE_FALSE(r2.has_value());
    CHECK(r2.error() == text);
    auto r3 = store.record_attestation(cid, over, "alice", "Admin", "attested", "carol", "");
    REQUIRE_FALSE(r3.has_value());
    CHECK(r3.error() == text);
    auto ok_len = store.record_attestation(cid, "user", at_cap, "Admin", "attested", "carol", "");
    REQUIRE_FALSE(ok_len.has_value());
    CHECK(ok_len.error().starts_with("not_found:"));

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations) {
        CHECK(a.decision == "pending");
        CHECK(a.history.empty());
    }
}

TEST_CASE("record_attestation: a frozen grant with the longest ids the identity stores produce "
          "can be attested, and exactly 1024 bytes is the limit",
          "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    // `oidc:<iss>#<sub>` at the 255-byte caps of oidc_provider.cpp (516 bytes), an IdP group
    // `<source>:<external_id>` with a 512-byte external id (about 530), and a role name at the
    // attestable limit.
    const std::string oidc_id = "oidc:" + std::string(255, 'i') + "#" + std::string(255, 's');
    const std::string group_id = "saml:" + std::string(525, 'g');
    const std::string max_role(yuzu::server::kRoleNameMaxLen, 'r');
    const std::string max_id(yuzu::server::kPrincipalIdMaxLen, 'p');
    REQUIRE(oidc_id.size() == 516);
    std::vector<GrantRef> grants = {
        GrantRef{"user", oidc_id, "Operator", R"({"display_name":"sso"})"},
        GrantRef{"group", group_id, max_role, R"({"display_name":"idp"})"},
        GrantRef{"engine", max_id, "Writer", R"({"display_name":"max"})"},
    };
    auto open_res = store.open_campaign("Long ids", "admin", grants, "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    for (const auto& g : grants) {
        INFO(g.principal_type);
        auto r = store.record_attestation(cid, g.principal_type, g.principal_id, g.role_name,
                                          "attested", "carol", "ok");
        REQUIRE(r.has_value());
        CHECK(r->seq == 1);
    }
    auto view = store.get_campaign(cid, /*include_history=*/true);
    REQUIRE(view.has_value());
    CHECK(view->pending_count == 0);
    const auto* row = find_row(*view, "group", group_id, max_role);
    REQUIRE(row != nullptr);
    CHECK(row->history.size() == 1);
}

TEST_CASE("record_attestation caps justification at 4096 bytes", "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Justification cap", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    REQUIRE(yuzu::server::kMaxJustificationBytes == 4096);

    auto over = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol",
                                         std::string(4097, 'j'));
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().starts_with("bad_request:"));
    auto still_pending = store.get_campaign(cid);
    REQUIRE(still_pending.has_value());
    CHECK(still_pending->pending_count == 3);

    auto at_cap = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol",
                                           std::string(4096, 'j'));
    REQUIRE(at_cap.has_value());
    auto decided = store.get_campaign(cid);
    REQUIRE(decided.has_value());
    CHECK(decided->pending_count == 2);
    for (const auto& a : decided->attestations)
        if (a.principal_id == "alice")
            CHECK(a.justification.size() == 4096);
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

// ── Schema v3 guards: every raw-SQL route around the store is refused ───────

namespace {

// SQLSTATE of a failed statement; "" when it succeeded.
std::string sqlstate_of(PGconn* conn, const std::string& sql) {
    PgResult r{PQexec(conn, sql.c_str())};
    if (r.ok())
        return "";
    const char* st = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return st != nullptr ? st : "?";
}

// First column of the first row, "" when there is none.
std::string scalar_of(PGconn* conn, const std::string& sql) {
    PgResult r{PQexec(conn, sql.c_str())};
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

bool integrity_violation(const std::string& sqlstate) {
    return sqlstate.starts_with("23");
}

} // namespace

// The "zero-row UPDATE emulation" below pins the DATABASE guard: a history row committed with no
// matching state change is refused at COMMIT by the deferred consistency trigger. It does NOT run
// record_attestation's own `PQntuples(upd) == 0` return-false branch: under the attestation row
// lock that branch is unreachable through the public API, so it is covered by review, not by this
// test (the trigger is the backstop for the case where it ever were reached).
TEST_CASE("schema v3 guards refuse every raw-SQL route around record_attestation, and the "
          "deferred trigger refuses an orphan history row at COMMIT (database guard, not the C++ "
          "return-false branch)",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());

    auto open_res = store.open_campaign("Guards", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;
    REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "ok")
                .has_value());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PGconn* c = conn.get();
    const std::string att = "access_review_store.access_review_attestation";
    const std::string hist = "access_review_store.access_review_attestation_history";
    const std::string key = "campaign_id='" + cid + "' AND principal_type='";

    // An older binary's bare UPDATE (no history row, no seq advance).
    CHECK(integrity_violation(sqlstate_of(c, "UPDATE " + att +
                                                 " SET decision='flagged_revoke', reviewer='dave', "
                                                 "decided_at_ms=1, justification='x' WHERE " +
                                                 key + "user' AND principal_id='alice'")));
    // Resetting the sequence to forge a later primary-key collision.
    CHECK(integrity_violation(sqlstate_of(c, "UPDATE " + att + " SET decision_seq=0 WHERE " + key +
                                                 "user' AND principal_id='alice'")));
    // A decided row inserted directly.
    CHECK(integrity_violation(
        sqlstate_of(c, "INSERT INTO " + att +
                           " (campaign_id, principal_type, principal_id, role_name, decision, "
                           "reviewer, decided_at_ms, justification, grant_snapshot) VALUES ('" +
                           cid + "','user','mallory','Admin','attested','carol',1,'','{}')")));
    // A justification-only edit of a pending row.
    CHECK(integrity_violation(sqlstate_of(c, "UPDATE " + att + " SET justification='x' WHERE " +
                                                 key + "group' AND principal_id='eng'")));
    // History is append-only.
    CHECK(integrity_violation(sqlstate_of(c, "UPDATE " + hist + " SET reviewer='eve'")));
    CHECK(integrity_violation(sqlstate_of(c, "DELETE FROM " + hist)));
    // Evidence rows are never deleted, so neither is a campaign that has any.
    CHECK(integrity_violation(
        sqlstate_of(c, "DELETE FROM " + att + " WHERE campaign_id='" + cid + "'")));
    CHECK(integrity_violation(sqlstate_of(
        c,
        "DELETE FROM access_review_store.access_review_campaign WHERE campaign_id='" + cid + "'")));
    // A history row naming the subject as reviewer fails the table CHECK.
    CHECK(sqlstate_of(c,
                      "INSERT INTO " + hist +
                          " (campaign_id, principal_type, principal_id, "
                          "role_name, seq, decision, previous_decision, reviewer, justification, "
                          "decided_at_ms) VALUES ('" +
                          cid + "','user','alice','Admin',2,'attested','attested','alice','',9)") ==
          "23514");

    // A history row committed with no state change is refused AT COMMIT (deferred consistency
    // guard), so it cannot poison the next decision's primary key.
    REQUIRE(sqlstate_of(c, "BEGIN").empty());
    CHECK(
        sqlstate_of(c, "INSERT INTO " + hist +
                           " (campaign_id, principal_type, principal_id, "
                           "role_name, seq, decision, previous_decision, reviewer, justification, "
                           "decided_at_ms) VALUES ('" +
                           cid + "','group','eng','Reader',1,'attested','pending','carol','',5)")
            .empty());
    CHECK(integrity_violation(sqlstate_of(c, "COMMIT")));

    // The zero-row UPDATE emulation (the shape a callback that wrongly returned true would
    // commit): history inserted, the state UPDATE matched nothing, COMMIT.
    REQUIRE(sqlstate_of(c, "BEGIN").empty());
    CHECK(
        sqlstate_of(c, "INSERT INTO " + hist +
                           " (campaign_id, principal_type, principal_id, "
                           "role_name, seq, decision, previous_decision, reviewer, justification, "
                           "decided_at_ms) VALUES ('" +
                           cid + "','group','eng','Reader',1,'attested','pending','carol','',5)")
            .empty());
    CHECK(sqlstate_of(c, "UPDATE " + att +
                             " SET decision='attested', reviewer='carol', "
                             "decided_at_ms=5, justification='', decision_seq=1 WHERE " +
                             key + "group' AND principal_id='eng' AND decision_seq=99")
              .empty());
    CHECK(integrity_violation(sqlstate_of(c, "COMMIT")));

    // Nothing from any refused statement landed.
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->attestations.size() == 3);
    CHECK(view->pending_count == 2);
    const auto* alice = find_row(*view, "user", "alice", "Admin");
    REQUIRE(alice != nullptr);
    CHECK(alice->decision == "attested");
    CHECK(alice->reviewer == "carol");
    CHECK(alice->decision_seq == 1);
    CHECK(alice->history.size() == 1);
    const auto* eng = find_row(*view, "group", "eng", "Reader");
    REQUIRE(eng != nullptr);
    CHECK(eng->decision == "pending");
    CHECK(eng->decision_seq == 0);
    CHECK(eng->history.empty());

    // The normal paths still work: a campaign still opens (the pending freeze insert passes the
    // guard), and the next decision on the grant the failed emulations touched lands at seq 1
    // with no primary-key collision.
    CHECK(store.open_campaign("After guards", "admin", three_grants(), "enabled").has_value());
    auto next = store.record_attestation(cid, "group", "eng", "Reader", "attested", "dave", "");
    REQUIRE(next.has_value());
    CHECK(next->previous_decision == "pending");
    CHECK(next->seq == 1);
    auto cl = store.close_campaign(cid, "admin");
    CHECK(cl.has_value());
}

namespace {

// "SQLSTATE|primary message" of a failed statement; "" when it succeeded.
std::string failure_of(PGconn* conn, const std::string& sql) {
    PgResult r{PQexec(conn, sql.c_str())};
    if (r.ok())
        return "";
    const char* st = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    const char* msg = PQresultErrorField(r.get(), PG_DIAG_MESSAGE_PRIMARY);
    return std::string(st != nullptr ? st : "?") + "|" + (msg != nullptr ? msg : "");
}

} // namespace

// Each probe runs in its own transaction on the group/eng grant (pending, seq 0): insert the
// history row a seq+1 advance would need (reviewer carol, justification 'j', decided_at 5,
// previous 'pending'), then UPDATE the state row to seq 1 with ONE value that does not match it.
// The control run advances with every value matching and the guard lets it through, so each refusal
// below is that single field, not the probe's own shape. The message text names the guard clause.
TEST_CASE("schema v3 guard: every field the state row must share with its history row is checked, "
          "and the key, snapshot and +1 clauses refuse",
          "[access_review][store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Guard probes", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PGconn* c = conn.get();
    const std::string att = "access_review_store.access_review_attestation";
    const std::string hist = "access_review_store.access_review_attestation_history";
    const std::string where = " WHERE campaign_id='" + cid +
                              "' AND principal_type='group' AND principal_id='eng' "
                              "AND role_name='Reader'";
    const auto insert_history = [&](int seq) {
        return "INSERT INTO " + hist +
               " (campaign_id, principal_type, principal_id, role_name, seq, decision, "
               "previous_decision, reviewer, justification, decided_at_ms) VALUES ('" +
               cid + "','group','eng','Reader'," + std::to_string(seq) +
               ",'attested','pending','carol','j',5)";
    };
    // The state UPDATE with every value matching the history row, `set` overriding one.
    const auto update_state = [&](const std::string& decision, const std::string& reviewer,
                                  const std::string& decided_at, const std::string& justification,
                                  int seq, const std::string& extra = "") {
        return "UPDATE " + att + " SET decision='" + decision + "', reviewer='" + reviewer +
               "', decided_at_ms=" + decided_at + ", justification='" + justification +
               "', decision_seq=" + std::to_string(seq) + extra + where;
    };
    const auto probe = [&](int hist_seq, const std::string& update) {
        REQUIRE(failure_of(c, "BEGIN").empty());
        REQUIRE(failure_of(c, insert_history(hist_seq)).empty());
        auto out = failure_of(c, update);
        REQUIRE(failure_of(c, "ROLLBACK").empty());
        return out;
    };

    // Control: every value matches, seq advances by one: the guard allows the UPDATE.
    CHECK(probe(1, update_state("attested", "carol", "5", "j", 1)).empty());

    // No matching history row: one probe per compared field (the NOT EXISTS clause of the guard).
    const auto expect = [&](const std::string& got, const std::string& clause) {
        INFO("got: " << got);
        CHECK(got.starts_with("23"));
        CHECK(got.find(clause) != std::string::npos);
    };
    const std::string no_history = "no matching history row at seq 1";
    // reviewer (h.reviewer = NEW.reviewer)
    expect(probe(1, update_state("attested", "dave", "5", "j", 1)), no_history);
    // justification (h.justification = NEW.justification)
    expect(probe(1, update_state("attested", "carol", "5", "other", 1)), no_history);
    // decided_at_ms (h.decided_at_ms = NEW.decided_at_ms)
    expect(probe(1, update_state("attested", "carol", "6", "j", 1)), no_history);
    // decision (h.decision = NEW.decision)
    expect(probe(1, update_state("flagged_revoke", "carol", "5", "j", 1)), no_history);
    // previous_decision (h.previous_decision = OLD.decision): the history row says the old
    // decision was 'attested' while the state row's OLD decision is 'pending'.
    {
        REQUIRE(failure_of(c, "BEGIN").empty());
        REQUIRE(failure_of(
                    c, "INSERT INTO " + hist +
                           " (campaign_id, principal_type, principal_id, role_name, seq, "
                           "decision, previous_decision, reviewer, justification, decided_at_ms) "
                           "VALUES ('" +
                           cid + "','group','eng','Reader',1,'attested','attested','carol','j',5)")
                    .empty());
        const auto got = failure_of(c, update_state("attested", "carol", "5", "j", 1));
        REQUIRE(failure_of(c, "ROLLBACK").empty());
        expect(got, no_history);
    }

    // Key and grant_snapshot are immutable even with a valid +1 advance and a matching history row
    // (the clause that runs BEFORE the seq check, so these are not the seq clause's refusals).
    expect(probe(1, update_state("attested", "carol", "5", "j", 1,
                                 ", grant_snapshot='{\"changed\":true}'")),
           "key and grant_snapshot are immutable");
    expect(probe(1, update_state("attested", "carol", "5", "j", 1, ", principal_id='eng2'")),
           "key and grant_snapshot are immutable");
    expect(probe(1, update_state("attested", "carol", "5", "j", 1, ", role_name='Other'")),
           "key and grant_snapshot are immutable");

    // A +2 jump is refused by the seq clause even with a history row at the target seq.
    expect(probe(2, update_state("attested", "carol", "5", "j", 2)),
           "decision_seq must advance by exactly one (old 0, new 2)");
    // A no-advance UPDATE (seq unchanged) is refused by the same clause.
    expect(probe(1, update_state("attested", "carol", "5", "j", 0)),
           "decision_seq must advance by exactly one (old 0, new 0)");

    // Nothing from any probe landed: the grant is still pending at seq 0 with no history.
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* eng = find_row(*view, "group", "eng", "Reader");
    REQUIRE(eng != nullptr);
    CHECK(eng->decision == "pending");
    CHECK(eng->decision_seq == 0);
    CHECK(eng->history.empty());
    // And the store still records on that grant.
    auto next = store.record_attestation(cid, "group", "eng", "Reader", "attested", "dave", "");
    REQUIRE(next.has_value());
    CHECK(next->seq == 1);
}

// ── Concurrency on the HeldLocks seam (no sleeps, no thread loops) ──────────

namespace {

// True once at least `n` backends of this database are blocked on a row lock. A row-lock queue
// shows the first waiter on `transactionid` and later ones on `tuple`.
bool wait_for_row_lock_waiters(PgPool& pool, int n) {
    const auto end = std::chrono::steady_clock::now() + yuzu::test::kLockWaitDeadline;
    while (std::chrono::steady_clock::now() < end) {
        if (auto probe = pool.try_acquire_for(std::chrono::milliseconds(100))) {
            PgResult r{PQexec(probe.get(),
                              "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                              "current_database() AND wait_event_type = 'Lock' AND wait_event IN "
                              "('transactionid', 'tuple')")};
            if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
                std::atoi(PQgetvalue(r.get(), 0, 0)) >= n)
                return true;
        }
        std::this_thread::sleep_for(yuzu::test::kLockWaitPoll);
    }
    return false;
}

std::string grant_lock_sql(const std::string& cid) {
    // The same locks the attest pre-read takes, on the alice/Admin grant.
    return "SELECT 1 FROM access_review_store.access_review_attestation a "
           "JOIN access_review_store.access_review_campaign c ON c.campaign_id = a.campaign_id "
           "WHERE a.campaign_id='" +
           cid +
           "' AND a.principal_type='user' AND "
           "a.principal_id='alice' AND a.role_name='Admin' FOR UPDATE OF a FOR SHARE OF c";
}

} // namespace

// #4752 read ceiling: the per-grant limit of 100 decisions does not bound a campaign with many
// grants, so a superseded entry returns a justification preview and only the latest is whole.
TEST_CASE(
    "get_campaign history: a superseded justification is cut to the preview length and flagged, "
    "the latest entry and short entries are whole",
    "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    constexpr auto kPreview =
        static_cast<std::size_t>(yuzu::server::kHistoryJustificationPreviewChars);
    // The boundary cases below are built from the constant; this pins that it is a real preview
    // (below the 4096 byte limit, so a long justification is cut) and not zero.
    static_assert(kPreview > 0 && kPreview < yuzu::server::kMaxJustificationBytes);
    auto open_res = store.open_campaign("Read ceiling", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    // 1: 4096 chars (cut); 2: short (whole); 3: exactly the preview length (whole, the boundary);
    // 4: one more (cut by one); 5: 4096 chars and the latest (whole).
    const std::vector<std::string> texts = {std::string(4096, 'a'), "short",
                                            std::string(kPreview, 'e'),
                                            std::string(kPreview + 1, 'f'), std::string(4096, 'g')};
    for (const auto& t : texts)
        REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", t)
                    .has_value());

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "user", "alice", "Admin");
    REQUIRE(row != nullptr);
    REQUIRE(row->decision_seq == 5);
    REQUIRE(row->history.size() == 5);
    CHECK(row->history[0].justification == std::string(kPreview, 'a'));
    CHECK(row->history[0].justification_truncated);
    CHECK(row->history[1].justification == "short");
    CHECK_FALSE(row->history[1].justification_truncated);
    CHECK(row->history[2].justification == std::string(kPreview, 'e'));
    CHECK_FALSE(row->history[2].justification_truncated);
    CHECK(row->history[3].justification == std::string(kPreview, 'f'));
    CHECK(row->history[3].justification_truncated);
    // The latest entry is whole and equals the state row's justification.
    CHECK(row->history[4].justification == std::string(4096, 'g'));
    CHECK_FALSE(row->history[4].justification_truncated);
    CHECK(row->justification == std::string(4096, 'g'));

    // The database keeps every full text: the cut is the read's, not the write's.
    {
        PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        const std::string sql =
            "SELECT length(justification) FROM "
            "access_review_store.access_review_attestation_history WHERE campaign_id='" +
            cid + "' AND principal_id='alice' ORDER BY seq";
        PgResult r{PQexec(c.get(), sql.c_str())};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 5);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "4096");
        CHECK(std::string(PQgetvalue(r.get(), 3, 0)) == std::to_string(kPreview + 1));
    }

    // A grant decided once has only its latest entry: never cut, never flagged.
    REQUIRE(store
                .record_attestation(cid, "group", "eng", "Reader", "attested", "carol",
                                    std::string(4096, 'z'))
                .has_value());
    auto again = store.get_campaign(cid, true);
    REQUIRE(again.has_value());
    const auto* once = find_row(*again, "group", "eng", "Reader");
    REQUIRE(once != nullptr);
    REQUIRE(once->history.size() == 1);
    CHECK(once->history[0].justification == std::string(4096, 'z'));
    CHECK_FALSE(once->history[0].justification_truncated);
}

TEST_CASE("get_campaign history: the cut counts characters, so a multibyte justification is never "
          "split mid-sequence",
          "[access_review][store][pg][4752]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Multibyte cut", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    const auto repeat = [](const std::string& unit, std::size_t n) {
        std::string s;
        for (std::size_t i = 0; i < n; ++i)
            s += unit;
        return s;
    };
    constexpr auto kPreview =
        static_cast<std::size_t>(yuzu::server::kHistoryJustificationPreviewChars);
    // Well over the preview length in characters, so the cut falls mid-text: two-byte and
    // three-byte characters (a byte cut at the preview length would split a sequence; the
    // character cut must not), each under the 4096 byte cap.
    constexpr std::size_t kLong = kPreview + 88;
    const std::string two = repeat("\xC3\xA9", kLong);       // U+00E9
    const std::string three = repeat("\xE2\x82\xAC", kLong); // U+20AC
    const std::string last = repeat("\xC3\xA9", kLong);
    for (const auto& t : {two, three, last})
        REQUIRE(store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", t)
                    .has_value());

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "user", "alice", "Admin");
    REQUIRE(row != nullptr);
    REQUIRE(row->history.size() == 3);
    CHECK(row->history[0].justification == repeat("\xC3\xA9", kPreview));
    CHECK(row->history[0].justification.size() == 2 * kPreview);
    CHECK(row->history[0].justification_truncated);
    CHECK(row->history[1].justification == repeat("\xE2\x82\xAC", kPreview));
    CHECK(row->history[1].justification.size() == 3 * kPreview);
    CHECK(row->history[1].justification_truncated);
    // The latest entry is whole, past the preview length.
    CHECK(row->history[2].justification == last);
    CHECK_FALSE(row->history[2].justification_truncated);

    // Valid UTF-8 on every cut entry: each lead byte is followed by its continuation bytes.
    for (std::size_t k = 0; k < 2; ++k) {
        const auto& s = row->history[k].justification;
        std::size_t chars = 0;
        for (std::size_t i = 0; i < s.size();) {
            const auto b = static_cast<unsigned char>(s[i]);
            const std::size_t len = b < 0x80 ? 1 : (b >> 5) == 0x6 ? 2 : (b >> 4) == 0xE ? 3 : 0;
            REQUIRE(len != 0);
            REQUIRE(i + len <= s.size());
            for (std::size_t j = 1; j < len; ++j)
                REQUIRE((static_cast<unsigned char>(s[i + j]) & 0xC0) == 0x80);
            i += len;
            ++chars;
        }
        CHECK(chars == kPreview);
    }
}

TEST_CASE("two attests of one grant serialise on the row lock and chain to seq 2",
          "[access_review][store][pg][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Chain", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    std::expected<yuzu::server::AttestationOutcome, std::string> r1, r2;
    yuzu::test::HeldLocks held(pool);
    held.run(grant_lock_sql(cid));
    yuzu::test::Workers workers([&] { held.rollback(); });
    workers.add([&] {
        r1 = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "a");
    });
    workers.add([&] {
        r2 = store.record_attestation(cid, "user", "alice", "Admin", "flagged_revoke", "dave", "b");
    });
    REQUIRE(wait_for_row_lock_waiters(pool, 2)); // both are parked behind the held row
    held.rollback();
    workers.join_all();

    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    // One of them was first, the other chained behind it.
    CHECK(((r1->seq == 1 && r2->seq == 2) || (r1->seq == 2 && r2->seq == 1)));
    CHECK((r1->seq == 1 ? r1->previous_decision : r2->previous_decision) == "pending");
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    const auto* row = find_row(*view, "user", "alice", "Admin");
    REQUIRE(row != nullptr);
    CHECK(row->decision_seq == 2);
    REQUIRE(row->history.size() == 2);
    CHECK(row->history[0].previous_decision == "pending");
    CHECK(row->history[1].previous_decision == row->history[0].decision);
    CHECK(row->history[1].decision == row->decision);
    CHECK(row->history[1].reviewer == row->reviewer);
}

TEST_CASE("a close issued while an attest holds its locks waits, then succeeds; an attest after "
          "the close is not_found",
          "[access_review][store][pg][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Close waits", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    std::expected<void, std::string> closed;
    yuzu::test::HeldLocks held(pool);
    held.run(grant_lock_sql(cid)); // an in-flight attest: FOR SHARE on the campaign row
    yuzu::test::Workers workers([&] { held.rollback(); });
    workers.add([&] { closed = store.close_campaign(cid, "admin"); });
    REQUIRE(yuzu::test::wait_for_lock_waiter(pool)); // the close is parked behind the attest
    held.commit();
    workers.join_all();
    REQUIRE(closed.has_value());

    auto late = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "");
    REQUIRE_FALSE(late.has_value());
    CHECK(late.error().starts_with("not_found:"));
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "closed");
    CHECK(view->pending_count == 3);
}

TEST_CASE("an attest issued while a close is in flight waits, then is not_found once the close "
          "commits",
          "[access_review][store][pg][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Attest waits", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    std::expected<yuzu::server::AttestationOutcome, std::string> attested;
    yuzu::test::HeldLocks held(pool);
    held.run("UPDATE access_review_store.access_review_campaign SET status='closed', "
             "closed_by='held', closed_at_ms=1 WHERE campaign_id='" +
             cid + "'");
    yuzu::test::Workers workers([&] { held.rollback(); });
    workers.add([&] {
        attested = store.record_attestation(cid, "user", "alice", "Admin", "attested", "carol", "");
    });
    REQUIRE(yuzu::test::wait_for_lock_waiter(pool)); // the attest is parked behind the close
    held.commit();
    workers.join_all();

    REQUIRE_FALSE(attested.has_value());
    CHECK(attested.error().starts_with("not_found:"));
    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "closed");
    CHECK(view->pending_count == 3);
    for (const auto& a : view->attestations)
        CHECK(a.history.empty());
}

// A queued close does NOT stop a NEW attest from taking its FOR SHARE on the campaign row, so
// under a continuous attest stream a close can wait for the whole lock_timeout and answer a write
// failure. Documented behaviour (access_review_store.hpp), pinned here so a change to it is seen.
// The close can only return at its lock_timeout (attest A never releases), so the ordering is
// decided by a flag attest B sets and the close reads at the moment it returns, not by how fast B
// is: the 3 s timeout leaves B room on a loaded runner, and nothing else sleeps.
TEST_CASE("a close waiting behind an attest does not block a new attest of another grant, and "
          "ends in a retryable write failure at lock_timeout, never not_found",
          "[access_review][store][pg][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, access_review_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 6, .lock_timeout_ms = 3000}};
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    auto open_res = store.open_campaign("Starvation", "admin", three_grants(), "enabled");
    REQUIRE(open_res.has_value());
    const auto cid = *open_res;

    std::expected<void, std::string> closed;
    std::atomic<bool> b_done{false};
    bool b_done_when_close_returned = false;
    yuzu::test::HeldLocks held(pool);
    held.run(grant_lock_sql(cid)); // attest A in flight: its row, and FOR SHARE on the campaign
    yuzu::test::Workers workers([&] { held.rollback(); });
    workers.add([&] {
        closed = store.close_campaign(cid, "admin");
        b_done_when_close_returned = b_done.load();
    });
    REQUIRE(yuzu::test::wait_for_lock_waiter(pool)); // the close is parked behind attest A

    // Attest B, a different grant of the same campaign, is issued AFTER the close queued.
    auto b = store.record_attestation(cid, "group", "eng", "Reader", "attested", "carol", "");
    b_done = true;
    REQUIRE(b.has_value());
    CHECK(b->seq == 1);
    CHECK(b->previous_decision == "pending");

    workers.join_all(); // attest A never releases: the close times out on its own
    // B had completed before the close gave up: it was not blocked behind the queued close.
    CHECK(b_done_when_close_returned);
    REQUIRE_FALSE(closed.has_value());
    CHECK_FALSE(closed.error().starts_with("not_found:"));
    CHECK(closed.error().starts_with("close_campaign write failed"));
    held.rollback();

    auto view = store.get_campaign(cid, true);
    REQUIRE(view.has_value());
    CHECK(view->campaign.status == "open");
    const auto* eng = find_row(*view, "group", "eng", "Reader");
    REQUIRE(eng != nullptr);
    CHECK(eng->decision == "attested");
    CHECK(eng->decision_seq == 1);
    // A close issued once nothing holds the campaign succeeds: the failure left it open.
    CHECK(store.close_campaign(cid, "admin").has_value());
}

// ── Migration v2 -> v3 (history table, guards, refusal) ─────────────────────

namespace {

// The shipped v1 + v2 shape (schema-qualified), stamped at version 2, with decided and pending
// rows. A raw PQexec does not get the runner's search_path, hence the qualification.
void seed_v2_database(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(
        conn.get(),
        "CREATE TABLE public.schema_meta (store TEXT PRIMARY KEY, version INTEGER NOT NULL, "
        "  upgraded_at BIGINT NOT NULL);"
        "CREATE SCHEMA access_review_store;"
        "CREATE TABLE access_review_store.access_review_campaign ("
        "  campaign_id    TEXT PRIMARY KEY,"
        "  title          TEXT NOT NULL,"
        "  status         TEXT NOT NULL CHECK (status IN ('open','closed')),"
        "  created_by     TEXT NOT NULL,"
        "  created_at_ms  BIGINT NOT NULL,"
        "  closed_by      TEXT NOT NULL DEFAULT '',"
        "  closed_at_ms   BIGINT NOT NULL DEFAULT 0);"
        "CREATE INDEX access_review_campaign_status_idx "
        "  ON access_review_store.access_review_campaign (status);"
        "CREATE TABLE access_review_store.access_review_attestation ("
        "  campaign_id     TEXT NOT NULL REFERENCES "
        "    access_review_store.access_review_campaign(campaign_id) ON DELETE CASCADE,"
        "  principal_type  TEXT NOT NULL CHECK (principal_type IN ('user','group','engine')),"
        "  principal_id    TEXT NOT NULL,"
        "  role_name       TEXT NOT NULL,"
        "  decision        TEXT NOT NULL CHECK (decision IN "
        "('pending','attested','flagged_revoke')),"
        "  reviewer        TEXT NOT NULL DEFAULT '',"
        "  decided_at_ms   BIGINT NOT NULL DEFAULT 0,"
        "  justification   TEXT NOT NULL DEFAULT '',"
        "  grant_snapshot  TEXT NOT NULL DEFAULT '',"
        "  PRIMARY KEY (campaign_id, principal_type, principal_id, role_name));"
        "ALTER TABLE access_review_store.access_review_campaign "
        "  ADD COLUMN rbac_enforcement TEXT NOT NULL DEFAULT '' "
        "  CHECK (rbac_enforcement IN ('', 'enabled', 'disabled', 'degraded'));"
        "INSERT INTO public.schema_meta (store, version, upgraded_at) "
        "  VALUES ('access_review_store', 2, 1);"
        "INSERT INTO access_review_store.access_review_campaign "
        "  (campaign_id, title, status, created_by, created_at_ms, rbac_enforcement) VALUES "
        "  ('c1','R1','open','admin',1000,'enabled'), ('c2','R2','open','admin',1001,'enabled');"
        "INSERT INTO access_review_store.access_review_attestation (campaign_id, principal_type, "
        "  principal_id, role_name, decision, reviewer, decided_at_ms, justification, "
        "  grant_snapshot) VALUES "
        "  ('c1','user','alice','Admin','attested','carol',1234,'ok','{}'),"
        "  ('c1','user','bob','Operator','pending','',0,'','{}'),"
        "  ('c1','group','eng','Reader','flagged_revoke','dave',1235,'stale','{}'),"
        "  ('c1','user','erin','Viewer','pending','',0,'','{}'),"
        "  ('c2','user','zed','Viewer','pending','',0,'','{}');")};
    REQUIRE(r.ok());
}

} // namespace

TEST_CASE("AccessReviewStore: a genuine v2->v3 upgrade backfills the history and keeps the "
          "decided rows",
          "[access_review][store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    seed_v2_database(db.dsn());

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AccessReviewStore store{pool};
    REQUIRE(store.is_open());
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        CHECK(scalar_of(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                    "'access_review_store'") == "3");
    }

    auto view = store.get_campaign("c1", true);
    REQUIRE(view.has_value());
    REQUIRE(view->attestations.size() == 4);
    CHECK(view->pending_count == 2);
    // A decided row: seq 1, one backfilled history row, "not recorded" as the prior decision.
    const auto* alice = find_row(*view, "user", "alice", "Admin");
    REQUIRE(alice != nullptr);
    CHECK(alice->decision == "attested");
    CHECK(alice->decision_seq == 1);
    REQUIRE(alice->history.size() == 1);
    CHECK(alice->history[0].seq == 1);
    CHECK(alice->history[0].decision == "attested");
    CHECK(alice->history[0].previous_decision.empty());
    CHECK(alice->history[0].reviewer == "carol");
    CHECK(alice->history[0].justification == "ok");
    CHECK(alice->history[0].decided_at_ms == 1234);
    const auto* eng = find_row(*view, "group", "eng", "Reader");
    REQUIRE(eng != nullptr);
    CHECK(eng->decision == "flagged_revoke");
    CHECK(eng->decision_seq == 1);
    REQUIRE(eng->history.size() == 1);
    CHECK(eng->history[0].decided_at_ms == 1235);
    // A pending row: seq 0 and no history.
    const auto* bob = find_row(*view, "user", "bob", "Operator");
    REQUIRE(bob != nullptr);
    CHECK(bob->decision == "pending");
    CHECK(bob->decision_seq == 0);
    CHECK(bob->history.empty());

    // The next decision on a migrated row chains behind the backfill.
    auto next = store.record_attestation("c1", "user", "alice", "Admin", "flagged_revoke", "dave",
                                         "revisit");
    REQUIRE(next.has_value());
    CHECK(next->previous_decision == "attested");
    CHECK(next->seq == 2);
    // And a pending one starts at 1.
    auto first = store.record_attestation("c1", "user", "bob", "Operator", "attested", "carol", "");
    REQUIRE(first.has_value());
    CHECK(first->previous_decision == "pending");
    CHECK(first->seq == 1);
}

TEST_CASE("AccessReviewStore: a v2 database holding a self-recorded decision is refused, with "
          "the version unchanged",
          "[access_review][store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    seed_v2_database(db.dsn());
    {
        // What the earlier build allowed: the subject of the grant recorded its own decision.
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{
            PQexec(conn.get(),
                   "INSERT INTO access_review_store.access_review_attestation (campaign_id, "
                   "principal_type, principal_id, role_name, decision, reviewer, decided_at_ms, "
                   "justification, grant_snapshot) VALUES "
                   "('c1','user','mallory','Admin','attested','mallory',1236,'me','{}')")};
        REQUIRE(r.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    yuzu::test::LogCapture log;
    AccessReviewStore store{pool};
    log.stop();
    CHECK_FALSE(store.is_open());
    // The runner logs the database's message; this is the named refusal, not the history CHECK's.
    CHECK(log.text().find("1 decision row(s) were recorded by the subject of the grant") !=
          std::string::npos);

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    CHECK(scalar_of(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                "'access_review_store'") == "2");
    // The whole migration rolled back: no history table was left behind.
    CHECK(scalar_of(conn.get(), "SELECT to_regclass('access_review_store."
                                "access_review_attestation_history')::text")
              .empty());
}
