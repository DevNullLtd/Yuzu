// UploadGrantStore born-on-Postgres tests (PR1.6a, CC-06 server-side fix).
// Schema `upload_grant_store`. Covers: fresh-start / migration-failure
// construction, mint + list + revoke, the atomic single-redemption
// open_session (including a genuine concurrent-open race), session
// authentication, offset CAS, commit/cancel/expire terminal transitions,
// and the "no plaintext secret ever persisted" invariant.

#include <catch2/catch_test_macros.hpp>

#include "upload_grant_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::OpenSessionOutcome;
using yuzu::server::SessionAuthOutcome;
using yuzu::server::UploadGrantMintParams;
using yuzu::server::UploadGrantStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp). The
// migration-failure / fresh-start-construction tests stay on plain
// YUZU_REQUIRE_PG_DB — they need an empty database, not an already-migrated
// one.
yuzu::test::PgTestTemplate upload_grant_tpl{"uploadgrant", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    UploadGrantStore store{pool}; // ctor runs the schema migration
    if (!store.is_open())
        throw std::runtime_error("upload_grant template: store failed to migrate");
}};

UploadGrantMintParams basic_params(const std::string& agent_id = "agent-1") {
    UploadGrantMintParams p;
    p.agent_id = agent_id;
    p.source_path = "/var/tmp/whatever.log"; // informational only — never used to derive a path
    p.declared_max_size = 1000;
    p.retention_class = "standard";
    p.minted_by = "operator-1";
    return p;
}

} // namespace

TEST_CASE("UploadGrantStore fresh-start construction succeeds on an empty database", "[pg][store][upload]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    UploadGrantStore store{pool};
    CHECK(store.is_open());
}

TEST_CASE("UploadGrantStore reports !is_open on a migration failure", "[pg][store][upload]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA upload_grant_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE upload_grant_store.grants (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    UploadGrantStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("UploadGrantStore mint validates input and rejects an unknown retention_class",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto no_agent = basic_params();
    no_agent.agent_id = "";
    CHECK_FALSE(store.mint(no_agent, 1000).has_value());

    auto bad_size = basic_params();
    bad_size.declared_max_size = 0;
    CHECK_FALSE(store.mint(bad_size, 1000).has_value());

    auto bad_class = basic_params();
    bad_class.retention_class = "../../etc";
    CHECK_FALSE(store.mint(bad_class, 1000).has_value());
}

TEST_CASE("UploadGrantStore mint returns the raw secret ONCE; only its digest is ever persisted",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), /*now=*/1000);
    REQUIRE(minted.has_value());
    CHECK_FALSE(minted->grant_id.empty());
    CHECK(minted->grant_secret.size() == 64); // 32 random bytes, hex
    CHECK(minted->expires_at == 1000 + 900);  // default <= 15 min TTL
    CHECK(minted->destination_key == "standard/" + minted->grant_id);

    // Direct-SQL assertion: the stored column is a digest, not the raw
    // secret, and it is not equal to the raw value under any encoding.
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(), "SELECT grant_secret_hash FROM upload_grant_store.grants WHERE grant_id=$1",
        std::vector<std::string>{minted->grant_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    std::string stored = PQgetvalue(res.get(), 0, 0);
    CHECK(stored != minted->grant_secret);
    CHECK(stored.size() == 64); // sha256 hex
}

TEST_CASE("UploadGrantStore list_for_agent and revoke", "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto a = store.mint(basic_params("agent-A"), 1000);
    auto b = store.mint(basic_params("agent-B"), 1000);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    auto all = store.list_for_agent();
    REQUIRE(all.has_value());
    CHECK(all->size() >= 2);

    auto only_a = store.list_for_agent("agent-A");
    REQUIRE(only_a.has_value());
    for (auto& row : *only_a)
        CHECK(row.agent_id == "agent-A");

    auto revoked = store.revoke(a->grant_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked == true);

    // Idempotent: revoking again reports false (already revoked).
    auto revoked_again = store.revoke(a->grant_id);
    REQUIRE(revoked_again.has_value());
    CHECK(*revoked_again == false);

    CHECK_FALSE(store.revoke("no-such-grant").value());
}

TEST_CASE("UploadGrantStore open_session: wrong secret and unknown grant both report GrantUnknown",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());

    auto wrong_secret = store.open_session(minted->grant_id, std::string(64, 'f'), 1001);
    CHECK(wrong_secret.outcome == OpenSessionOutcome::kGrantUnknown);

    auto unknown_grant = store.open_session(std::string(32, '0'), minted->grant_secret, 1001);
    CHECK(unknown_grant.outcome == OpenSessionOutcome::kGrantUnknown);

    // A revoked grant collapses onto the same reason.
    auto revoke_target = store.mint(basic_params(), 1000);
    REQUIRE(revoke_target.has_value());
    REQUIRE(store.revoke(revoke_target->grant_id).value());
    auto revoked_open = store.open_session(revoke_target->grant_id, revoke_target->grant_secret, 1001);
    CHECK(revoked_open.outcome == OpenSessionOutcome::kGrantUnknown);
}

TEST_CASE("UploadGrantStore open_session succeeds once and echoes chunk_max_bytes/offset 0",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());

    auto opened = store.open_session(minted->grant_id, minted->grant_secret, 1001);
    REQUIRE(opened.outcome == OpenSessionOutcome::kOpened);
    CHECK_FALSE(opened.session.upload_id.empty());
    CHECK(opened.session.session_secret.size() == 64);
    CHECK(opened.session.offset == 0);
    CHECK(opened.session.chunk_max_bytes > 0);
    CHECK(opened.session.expires_at == minted->expires_at);

    // A second open with the SAME credential is a straightforward replay —
    // grant_already_redeemed, not a fresh session.
    auto replay = store.open_session(minted->grant_id, minted->grant_secret, 1002);
    CHECK(replay.outcome == OpenSessionOutcome::kAlreadyRedeemed);

    // The session secret's digest, not the plaintext, is what's stored.
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT session_secret_hash FROM upload_grant_store.sessions WHERE upload_id=$1",
        std::vector<std::string>{opened.session.upload_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    CHECK(std::string(PQgetvalue(res.get(), 0, 0)) != opened.session.session_secret);
}

TEST_CASE("UploadGrantStore open_session reports Expired for a grant past its expiry",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto p = basic_params();
    p.requested_ttl_secs = 10;
    auto minted = store.mint(p, /*now=*/1000);
    REQUIRE(minted.has_value());
    CHECK(minted->expires_at == 1010);

    auto opened = store.open_session(minted->grant_id, minted->grant_secret, /*now=*/1011);
    CHECK(opened.outcome == OpenSessionOutcome::kExpired);

    // The exact boundary is still valid.
    auto minted2 = store.mint(basic_params(), 1000);
    REQUIRE(minted2.has_value());
    auto boundary = store.open_session(minted2->grant_id, minted2->grant_secret, minted2->expires_at);
    CHECK(boundary.outcome == OpenSessionOutcome::kOpened);
}

TEST_CASE("UploadGrantStore open_session: a grant redeems EXACTLY once under concurrent callers",
          "[pg][store][upload][concurrency]") {
    // The load-bearing acceptance test: two threads race the SAME grant
    // credential through open_session on a pool sized for real concurrency.
    // The atomic `UPDATE ... WHERE state='minted' ... RETURNING` is what
    // makes this safe — NOT a read-then-write in this store's own code.
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());

    std::atomic<bool> start{false};
    std::atomic<int> opened_count{0};
    std::atomic<int> already_redeemed_count{0};
    std::atomic<int> other_count{0};

    auto worker = [&]() {
        while (!start.load(std::memory_order_acquire)) {
            // busy-wait for the synchronized start
        }
        auto result = store.open_session(minted->grant_id, minted->grant_secret, 1001);
        switch (result.outcome) {
        case OpenSessionOutcome::kOpened:
            opened_count.fetch_add(1);
            break;
        case OpenSessionOutcome::kAlreadyRedeemed:
            already_redeemed_count.fetch_add(1);
            break;
        default:
            other_count.fetch_add(1);
            break;
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);
    start.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    CHECK(opened_count.load() == 1);
    CHECK(already_redeemed_count.load() == 1);
    CHECK(other_count.load() == 0);

    // Exactly one session row exists for this grant.
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM upload_grant_store.sessions WHERE grant_id=$1",
        std::vector<std::string>{minted->grant_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(res.get(), 0, 0)) == "1");
}

TEST_CASE("UploadGrantStore authenticate_session: wrong secret and unknown id are session_unknown",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());
    auto opened = store.open_session(minted->grant_id, minted->grant_secret, 1001);
    REQUIRE(opened.outcome == OpenSessionOutcome::kOpened);

    auto wrong = store.authenticate_session(opened.session.upload_id, std::string(64, '0'), 1002);
    CHECK(wrong.outcome == SessionAuthOutcome::kSessionUnknown);

    auto unknown = store.authenticate_session(std::string(32, '0'), opened.session.session_secret,
                                              1002);
    CHECK(unknown.outcome == SessionAuthOutcome::kSessionUnknown);

    // Presenting the GRANT credential (not a session credential) against
    // authenticate_session must also fail — the grant never authenticates a
    // chunk.
    auto grant_as_session =
        store.authenticate_session(minted->grant_id, minted->grant_secret, 1002);
    CHECK(grant_as_session.outcome == SessionAuthOutcome::kSessionUnknown);

    auto ok = store.authenticate_session(opened.session.upload_id, opened.session.session_secret,
                                         1002);
    REQUIRE(ok.outcome == SessionAuthOutcome::kOk);
    CHECK(ok.info.state == "open");
    CHECK(ok.info.recorded_offset == 0);
    CHECK(ok.info.agent_id == "agent-1");
}

TEST_CASE("UploadGrantStore advance_offset is a CAS on the previous offset", "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());
    auto opened = store.open_session(minted->grant_id, minted->grant_secret, 1001);
    REQUIRE(opened.outcome == OpenSessionOutcome::kOpened);
    const auto& upload_id = opened.session.upload_id;

    auto advanced = store.advance_offset(upload_id, 0, 100);
    REQUIRE(advanced.has_value());
    CHECK(*advanced == true);

    // Stale CAS (still claims prev=0) now misses.
    auto stale = store.advance_offset(upload_id, 0, 200);
    REQUIRE(stale.has_value());
    CHECK(*stale == false);

    auto ok = store.authenticate_session(upload_id, opened.session.session_secret, 1002);
    REQUIRE(ok.outcome == SessionAuthOutcome::kOk);
    CHECK(ok.info.recorded_offset == 100);
}

TEST_CASE("UploadGrantStore commit_session writes completed_uploads and terminates the session",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());
    auto opened = store.open_session(minted->grant_id, minted->grant_secret, 1001);
    REQUIRE(opened.outcome == OpenSessionOutcome::kOpened);
    const auto& upload_id = opened.session.upload_id;
    REQUIRE(store.advance_offset(upload_id, 0, 1000).value());

    auto committed = store.commit_session(upload_id, 1000, std::string(64, 'a'), 1003);
    REQUIRE(committed.has_value());
    CHECK(*committed == true);

    auto post = store.authenticate_session(upload_id, opened.session.session_secret, 1004);
    CHECK(post.outcome == SessionAuthOutcome::kSessionTerminal);
    CHECK(post.info.state == "committed");

    // A second commit is a CAS miss — false, not an error.
    auto second = store.commit_session(upload_id, 1000, std::string(64, 'a'), 1005);
    REQUIRE(second.has_value());
    CHECK(*second == false);

    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT actual_size, verified_hash FROM upload_grant_store.completed_uploads "
        "WHERE upload_id=$1",
        std::vector<std::string>{upload_id});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    CHECK(std::string(PQgetvalue(res.get(), 0, 0)) == "1000");
    CHECK(std::string(PQgetvalue(res.get(), 0, 1)) == std::string(64, 'a'));
}

TEST_CASE("UploadGrantStore cancel_session terminates an open session and is idempotent-false after",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto minted = store.mint(basic_params(), 1000);
    REQUIRE(minted.has_value());
    auto opened = store.open_session(minted->grant_id, minted->grant_secret, 1001);
    REQUIRE(opened.outcome == OpenSessionOutcome::kOpened);
    const auto& upload_id = opened.session.upload_id;

    auto cancelled = store.cancel_session(upload_id);
    REQUIRE(cancelled.has_value());
    CHECK(*cancelled == true);

    auto second = store.cancel_session(upload_id);
    REQUIRE(second.has_value());
    CHECK(*second == false);

    auto post = store.authenticate_session(upload_id, opened.session.session_secret, 1002);
    CHECK(post.outcome == SessionAuthOutcome::kSessionTerminal);
    CHECK(post.info.state == "cancelled");
}

TEST_CASE("UploadGrantStore expire_now and expire_stale_sessions mark a session expired",
          "[pg][store][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, upload_grant_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());

    auto p1 = basic_params();
    p1.requested_ttl_secs = 10;
    auto minted1 = store.mint(p1, 1000);
    REQUIRE(minted1.has_value());
    auto opened1 = store.open_session(minted1->grant_id, minted1->grant_secret, 1001);
    REQUIRE(opened1.outcome == OpenSessionOutcome::kOpened);

    auto expired_now = store.expire_now(opened1.session.upload_id);
    REQUIRE(expired_now.has_value());
    CHECK(*expired_now == true);
    // Idempotent: already expired, no longer 'open'.
    CHECK(store.expire_now(opened1.session.upload_id).value() == false);

    auto p2 = basic_params();
    p2.requested_ttl_secs = 10;
    auto minted2 = store.mint(p2, 1000);
    REQUIRE(minted2.has_value());
    auto opened2 = store.open_session(minted2->grant_id, minted2->grant_secret, 1001);
    REQUIRE(opened2.outcome == OpenSessionOutcome::kOpened);

    auto swept = store.expire_stale_sessions(/*now=*/opened2.session.expires_at + 1);
    CHECK(swept >= 1);

    auto post = store.authenticate_session(opened2.session.upload_id, opened2.session.session_secret,
                                           opened2.session.expires_at + 1);
    // Past expiry AND already flipped to 'expired' by the sweep -> STILL
    // kExpired, not kSessionTerminal: the frozen protocol says "any request
    // after [expiry] -> 410 expired", not just the first one. A row already
    // sitting in the 'expired' terminal state must keep reporting kExpired on
    // every subsequent request, the same as a still-'open' row whose clock
    // has simply passed its own expiry.
    CHECK(post.outcome == SessionAuthOutcome::kExpired);
    CHECK(post.info.state == "expired");
}
