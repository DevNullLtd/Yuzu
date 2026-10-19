/**
 * test_ca_store.cpp — `CaStore` (Yuzu internal CA inventory + lifecycle, ADR-0053).
 *
 * Covers:
 *  - fail-closed construction (a live but unmigratable database).
 *  - root: try_insert_root's first-boot race-safety (winner/loser semantics), set_root's
 *    unconditional-replace contract (subordinate import / test seeding), get_root's
 *    type-distinguishable read.
 *  - issued-cert record/get/list/list_issued_by_key_id, provenance columns, duplicate-serial
 *    classification (#1276), revoke (idempotent, expected<bool,...> semantics), is_revoked
 *    (fail-closed bool), list_revoked, a real-leaf revocation round-trip through pki::.
 *  - serial normalisation (pure function).
 *  - CRL numbering + record/latest roundtrip, publish_next_crl atomic allocation,
 *    record_crl_for_test's duplicate-version refusal, and the HA WS-6 6.1 cross-replica publish
 *    contract (two stores on separate pools: distinct gap-free numbers, superset-on-wait,
 *    clean lock timeout).
 *
 * No legacy-SQLite backfill test coverage: `CaStore::migrate_from_sqlite()` itself was retired
 * (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0053 Update, 2026-09-03) -- no production
 * fleet has ever run a pre-Postgres build, so the mandatory three-table fingerprinted backfill
 * never had real legacy data to protect. `server.cpp` now runs
 * `legacy_sqlite_probe::warn_if_legacy_rows` over the three legacy tables instead.
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction case uses
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test carve-out documented on that
 * macro.
 */

#include "ca_store.hpp"
#include "crypto_widget_catalogue.hpp"
#include "x509_ca.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// CaStore borrows a PgPool&; it must be non-copyable (and non-movable) so the borrow can never be
// duplicated.
static_assert(!std::is_copy_constructible_v<CaStore>);
static_assert(!std::is_copy_assignable_v<CaStore>);

namespace {

yuzu::test::PgTestTemplate ca_store_tpl{"castore", [](const std::string& dsn) {
                                            PgPool pool{{.conninfo = dsn, .size = 1}};
                                            CaStore store{pool};
                                            if (!store.is_open())
                                                throw std::runtime_error(
                                                    "ca_store template: store failed to migrate");
                                        }};

int64_t now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Deterministic stand-in for a signed CRL: DER encodes the number, validity is derived from it.
std::optional<CaStore::BuiltCrl> fake_crl(uint64_t n, const std::vector<IssuedCertRecord>&) {
    const std::string s = "CRL#" + std::to_string(n);
    return CaStore::BuiltCrl{std::vector<uint8_t>(s.begin(), s.end()),
                             1000 + static_cast<int64_t>(n), 2000 + static_cast<int64_t>(n)};
}

// Joins every thread on scope exit, so a failing REQUIRE cannot leave a joinable std::thread
// behind (std::terminate). std::jthread is not available on Apple Clang's libc++.
struct JoinAll {
    std::vector<std::thread>& threads;
    ~JoinAll() {
        for (auto& t : threads)
            if (t.joinable())
                t.join();
    }
};

// Blocks until some session in THIS database is waiting for a lock on ca_crl_versions. The
// database filter matters: template-cloned test databases share relation OIDs, and pg_locks is
// cluster-wide, so without it another CI job's waiter could satisfy the probe.
bool wait_for_crl_lock_waiter(const std::string& dsn) {
    PgConn probe{PQconnectdb(dsn.c_str())};
    if (PQstatus(probe.get()) != CONNECTION_OK)
        return false;
    // 2.5 s budget: a publisher gives up on the lock after CaStore::kCrlLockTimeout (5 s), so
    // the probe must observe it well before that.
    for (int i = 0; i < 100; ++i) {
        PgResult w{PQexec(probe.get(),
                          "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                          "WHERE c.relname = 'ca_crl_versions' AND NOT l.granted "
                          "AND l.database = (SELECT oid FROM pg_database "
                          "WHERE datname = current_database())")};
        if (w.status() != PGRES_TUPLES_OK)
            return false;
        if (std::string(PQgetvalue(w.get(), 0, 0)) != "0")
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

// A raw connection that holds the CRL table lock, standing in for another replica mid-publish.
struct CrlLockHolder {
    PgConn conn;
    explicit CrlLockHolder(const std::string& dsn) : conn{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(conn.get(), "BEGIN")}.status() == PGRES_COMMAND_OK);
        REQUIRE(PgResult{PQexec(conn.get(), "LOCK TABLE ca_store.ca_crl_versions IN SHARE ROW "
                                            "EXCLUSIVE MODE")}
                    .status() == PGRES_COMMAND_OK);
    }
    void release() { REQUIRE(PgResult{PQexec(conn.get(), "COMMIT")}.status() == PGRES_COMMAND_OK); }
};

IssuedCertRecord sample_issued(const std::string& serial, const std::string& purpose = "agent") {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "CN=agent-" + serial;
    r.san = "URI:yuzu://inst/agent/" + serial;
    r.purpose = purpose;
    r.not_after = now_s() + 86400;
    r.issued_at = now_s();
    return r;
}

CaRoot sample_root(const std::string& fingerprint = "AB:CD:EF") {
    CaRoot root;
    root.cert_pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
    root.key_ref = "/etc/yuzu/certs/ca.key";
    root.algo = "EcP384";
    root.not_before = now_s();
    root.not_after = now_s() + 10L * 31557600L;
    root.fingerprint_sha256 = fingerprint;
    root.mode = CaMode::Builtin;
    return root;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("CaStore reports !is_open on a migration failure", "[ca_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA ca_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE ca_store.ca_root (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE_FALSE(store.is_open());
}

TEST_CASE("CaStore migration lands at v5 and drops sqlite_backfill_source (#3623)",
          "[ca_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult ver{PQexec(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                    "'ca_store'")};
    REQUIRE(ver.ok());
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "5");
    PgResult trg{PQexec(conn.get(), "SELECT COUNT(*) FROM pg_trigger t JOIN pg_class c ON c.oid = "
                                    "t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                                    "WHERE n.nspname = 'ca_store' AND c.relname = 'ca_issued' "
                                    "AND t.tgname = 'ca_issued_keep_revoked'")};
    REQUIRE(trg.ok());
    CHECK(std::string(PQgetvalue(trg.get(), 0, 0)) == "1");
    // v5: the dashboard indexes, additive — the v4 trigger above is still in place.
    PgResult idx{PQexec(conn.get(),
                        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'ca_store' "
                        "AND tablename = 'ca_issued' AND indexname IN ('idx_ca_issued_dashboard', "
                        "'idx_ca_issued_active_not_after', 'idx_ca_issued_revoked_at') "
                        "ORDER BY indexname")};
    REQUIRE(idx.ok());
    REQUIRE(PQntuples(idx.get()) == 3);
    CHECK(std::string(PQgetvalue(idx.get(), 0, 0)) == "idx_ca_issued_active_not_after");
    CHECK(std::string(PQgetvalue(idx.get(), 0, 1)).find("WHERE (status = 'active'::text)") !=
          std::string::npos);
    CHECK(std::string(PQgetvalue(idx.get(), 1, 0)) == "idx_ca_issued_dashboard");
    CHECK(std::string(PQgetvalue(idx.get(), 1, 1)).find("INCLUDE (revocation_reason)") !=
          std::string::npos);
    CHECK(std::string(PQgetvalue(idx.get(), 2, 0)) == "idx_ca_issued_revoked_at");
    CHECK(std::string(PQgetvalue(idx.get(), 2, 1)).find("WHERE (revoked_at > 0)") !=
          std::string::npos);
    PgResult col{PQexec(conn.get(), "SELECT COUNT(*) FROM information_schema.columns WHERE "
                                    "table_schema = 'ca_store' AND table_name = "
                                    "'ca_crl_versions' AND column_name = 'revoked_count'")};
    REQUIRE(col.ok());
    CHECK(std::string(PQgetvalue(col.get(), 0, 0)) == "1");
    PgResult tbl{PQexec(conn.get(), "SELECT COUNT(*) FROM information_schema.tables WHERE "
                                    "table_schema = 'ca_store' AND table_name = "
                                    "'sqlite_backfill_source'")};
    REQUIRE(tbl.ok());
    CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
}

// ── Root ──────────────────────────────────────────────────────────────────

TEST_CASE("CaStore: opens with no root", "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE_FALSE(store.has_root());
    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE_FALSE(got->has_value());
}

TEST_CASE("CaStore: set_root unconditionally replaces (subordinate import / test seeding)",
          "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto root = sample_root();
    REQUIRE(store.set_root(root).has_value());
    REQUIRE(store.has_root());

    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->cert_pem == root.cert_pem);
    CHECK((*got)->key_ref == root.key_ref);
    CHECK((*got)->algo == "EcP384");
    CHECK((*got)->fingerprint_sha256 == "AB:CD:EF");
    CHECK((*got)->mode == CaMode::Builtin);
    CHECK((*got)->chain_pem.empty()); // builtin → no parent chain (PR6)

    // Replace with a subordinate-CA import: single row, latest wins, and the parent chain
    // (enterprise root above our issuing intermediate) round-trips.
    CaRoot root2 = root;
    root2.fingerprint_sha256 = "99:88:77";
    root2.mode = CaMode::Subordinate;
    root2.chain_pem = "-----BEGIN CERTIFICATE-----\nENTERPRISE-ROOT\n-----END CERTIFICATE-----\n";
    REQUIRE(store.set_root(root2).has_value());
    auto got2 = store.get_root();
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->fingerprint_sha256 == "99:88:77");
    CHECK((*got2)->mode == CaMode::Subordinate);
    CHECK((*got2)->chain_pem == root2.chain_pem);
}

TEST_CASE("CaStore: set_root rejects empty cert/key_ref", "[ca_store][pg][root][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CaRoot bad;
    bad.algo = "EcP384";
    REQUIRE_FALSE(store.set_root(bad).has_value());
    REQUIRE_FALSE(store.has_root());
}

// ADR-0053 "Root-singleton first-boot race": the one genuinely new problem a shared Postgres
// substrate introduces over per-instance SQLite.
TEST_CASE("CaStore: try_insert_root — first caller wins, echoes its own root",
          "[ca_store][pg][root]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto root = sample_root("WINNER:FP");
    auto result = store.try_insert_root(root);
    REQUIRE(result.has_value());
    CHECK(result->fingerprint_sha256 == "WINNER:FP");

    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->fingerprint_sha256 == "WINNER:FP");
}

TEST_CASE("CaStore: try_insert_root — a losing caller reads back the winner, never clobbers it",
          "[ca_store][pg][root][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    auto winner_root = sample_root("WINNER:FP");
    auto winner_result = store.try_insert_root(winner_root);
    REQUIRE(winner_result.has_value());
    CHECK(winner_result->fingerprint_sha256 == "WINNER:FP");

    // A second instance independently generated DIFFERENT root material and races the same
    // call — it must NOT win, must NOT clobber, and must read back the ALREADY-established root.
    auto loser_root = sample_root("LOSER:FP");
    loser_root.cert_pem = "-----BEGIN CERTIFICATE-----\nLOSER\n-----END CERTIFICATE-----\n";
    auto loser_result = store.try_insert_root(loser_root);
    REQUIRE(loser_result.has_value());
    CHECK(loser_result->fingerprint_sha256 == "WINNER:FP"); // NOT its own — the winner's
    CHECK(loser_result->cert_pem == winner_root.cert_pem);

    // The stored row is still exactly the winner's — never clobbered.
    auto got = store.get_root();
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->fingerprint_sha256 == "WINNER:FP");
}

TEST_CASE("CaStore: try_insert_root rejects empty cert/key_ref", "[ca_store][pg][root][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CaRoot bad;
    bad.algo = "EcP384";
    REQUIRE_FALSE(store.try_insert_root(bad).has_value());
    REQUIRE_FALSE(store.has_root());
}

TEST_CASE("CaStore: get_root() reports a genuine store failure as unexpected, while has_root() "
          "collapses the SAME failure to false (governance Gate 3 quality-engineer, 2026-08-21)",
          "[ca_store][pg][root][security]") {
    // The distinction this test pins is exactly what the a14138449 adversarial-review fix
    // depends on: server.cpp's boot-time PKI wiring block must call get_root() (typed,
    // distinguishes "genuine DB error" from "no root") rather than has_root() (collapses
    // BOTH cases to false) — a lossy has_root() at that ONE call site was the HIGH. This
    // test does not exercise server.cpp's full boot sequence (not unit-constructible, see
    // test_default_certs.cpp's existing note on that class of code) — it instead proves the
    // store-level CONTRACT the fix relies on: given the identical underlying failure, the two
    // methods must disagree in exactly this way, in isolation, cheaply, without booting a
    // real ServerImpl.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // Establish a real root first — the pre-migration bug specifically mattered when a root
    // ALREADY EXISTS and a later read of it degrades; a permanently-empty store never reaches
    // the boot-wiring block's true branch in the first place.
    auto root = sample_root("EXISTING:FP");
    REQUIRE(store.try_insert_root(root).has_value());
    REQUIRE(store.has_root());

    // Sabotage the store out from under the open CaStore instance — same technique as
    // test_deployment_store.cpp's "list_jobs/get_job report a genuine store failure as
    // unexpected" and test_api_token_store.cpp's equivalent (both cited as this codebase's
    // established pattern for this exact class of test).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE ca_store.ca_root CASCADE")};
        REQUIRE(d.status() == PGRES_COMMAND_OK);
    }

    // get_root(): typed, distinguishable — a genuine DB error, never folded into "no root".
    auto got = store.get_root();
    CHECK_FALSE(got.has_value());
    CHECK(got.error().starts_with(kCaDbErrorPrefix));

    // has_root(): the SAME underlying failure collapses to false — indistinguishable, by
    // design, from a genuinely-empty store. This is exactly why ADR-0053 restricts has_root()
    // to the two callers that are provably safe with that collapse (the CRL-freshness sweep
    // tick, /readyz) and why the boot-time PKI wiring block must NOT be a third.
    CHECK_FALSE(store.has_root());
}

// ── Issued inventory ─────────────────────────────────────────────────────

TEST_CASE("CaStore: issued record/get/list", "[ca_store][pg][issued]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    REQUIRE(store.record_issued(sample_issued("AA11")).has_value());
    REQUIRE(store.record_issued(sample_issued("BB22", "https")).has_value());

    auto got = store.get_issued("AA11");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->purpose == "agent");
    CHECK((*got)->status == CertStatus::Active);

    auto nope = store.get_issued("NOPE");
    REQUIRE(nope.has_value());
    REQUIRE_FALSE(nope->has_value());

    auto all = store.list_issued();
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);
}

// #1276 (record_issued's flake lead): a serial collision is classified distinctly, prefixed
// kCaDuplicateSerialPrefix, not the generic kCaDbErrorPrefix — a caller can retry with a fresh
// serial rather than treating it as an outage.
TEST_CASE("CaStore: record_issued classifies a duplicate serial distinctly (#1276)",
          "[ca_store][pg][issued][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    REQUIRE(store.record_issued(sample_issued("AA11")).has_value());
    auto dup = store.record_issued(sample_issued("AA11"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().starts_with(kCaDuplicateSerialPrefix));
    CHECK_FALSE(dup.error().starts_with(kCaDbErrorPrefix));
}

TEST_CASE("CaStore: record_issued rejects empty serial", "[ca_store][pg][issued][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE_FALSE(store.record_issued(sample_issued("")).has_value());
}

TEST_CASE("CaStore: issued provenance columns round-trip", "[ca_store][pg][issued]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto rec = sample_issued("CAFE");
    rec.issued_by = "operator:alice";
    rec.enrollment_request_id = "enr-123";
    rec.cert_pem = "-----BEGIN CERTIFICATE-----\nXYZ\n-----END CERTIFICATE-----\n";
    REQUIRE(store.record_issued(rec).has_value());
    auto got = store.get_issued("CAFE");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issued_by == "operator:alice");
    CHECK((*got)->enrollment_request_id == "enr-123");
    CHECK((*got)->cert_pem == rec.cert_pem);
}

// gap-matrix #10: code-signing leaf issuance (server.cpp's
// ServerImpl::issue_code_signing_leaf) records purpose="code-signing" —
// already an allowed IssuedCertRecord::purpose value (see the doc comment),
// so this needs no schema migration. Confirm it round-trips through
// get_issued/list_issued like every other purpose, and that revoke() treats
// it identically to "agent"/"https".
TEST_CASE("CaStore: purpose=\"code-signing\" round-trips through get_issued/list_issued/revoke",
          "[ca_store][pg][issued][code-signing]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    auto rec = sample_issued("C5C1FEED", "code-signing");
    rec.subject = "build-signer-01"; // CN=label — the non-agent namespace (never an agent_id).
    rec.san.clear();                 // no SAN on a code-signing leaf (never a yuzu://…/agent/… URI).
    rec.issued_by = "operator:alice";
    REQUIRE(store.record_issued(rec).has_value());

    auto got = store.get_issued("C5C1FEED");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->purpose == "code-signing");
    CHECK((*got)->subject == "build-signer-01");
    CHECK((*got)->san.empty());
    CHECK((*got)->issued_by == "operator:alice");
    CHECK((*got)->status == CertStatus::Active);

    auto all = store.list_issued();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 1);
    CHECK((*all)[0].purpose == "code-signing");

    // revoke() has no purpose-specific branch — a code-signing leaf revokes
    // exactly like every other purpose.
    auto r = store.revoke("C5C1FEED", "operator decommission");
    REQUIRE(r.has_value());
    CHECK(*r);
    REQUIRE(store.is_revoked("C5C1FEED"));
    auto revoked = store.list_revoked();
    REQUIRE(revoked.has_value());
    REQUIRE(revoked->size() == 1);
    CHECK((*revoked)[0].purpose == "code-signing");
}

TEST_CASE("CaStore: revoke is idempotent and reflected", "[ca_store][pg][revoke]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("DEAD")).has_value());

    REQUIRE_FALSE(store.is_revoked("DEAD"));

    auto r1 = store.revoke("DEAD", "key compromise");
    REQUIRE(r1.has_value());
    CHECK(*r1); // first revoke changes a row

    auto r2 = store.revoke("DEAD", "again");
    REQUIRE(r2.has_value());
    CHECK_FALSE(*r2); // idempotent: no change

    auto r3 = store.revoke("UNKNOWN", "n/a");
    REQUIRE(r3.has_value());
    CHECK_FALSE(*r3); // unknown serial: no change

    REQUIRE(store.is_revoked("DEAD"));
    auto got = store.get_issued("DEAD");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->status == CertStatus::Revoked);
    CHECK((*got)->revocation_reason == "key compromise");
    CHECK((*got)->revoked_at > 0);

    auto revoked = store.list_revoked();
    REQUIRE(revoked.has_value());
    REQUIRE(revoked->size() == 1);
    CHECK((*revoked)[0].serial_hex == "DEAD");
}

// PR3 governance regression net: exercise the EXACT chain the server's is_peer_cert_revoked()
// uses against a REAL issued leaf — issue → parse_certificate to recover the serial →
// record_issued → revoke → is_revoked(parsed serial). Also pins the serial-format round-trip
// (sign side and parse side both BN_bn2hex → identical).
TEST_CASE("CaStore: revocation round-trip against a real issued leaf",
          "[ca_store][pg][pki][security]") {
    using namespace yuzu::server::pki;

    auto ca_key = generate_private_key(KeyAlgo::EcP384);
    REQUIRE(ca_key);
    CaParams cp;
    cp.subject = {"Yuzu Test CA", "Yuzu"};
    cp.validity = validity_years_from_now(10);
    auto ca_cert = self_sign_ca(*ca_key, cp);
    REQUIRE(ca_cert);

    auto leaf_key = generate_private_key(KeyAlgo::EcP256);
    REQUIRE(leaf_key);
    CsrParams csrp;
    csrp.subject = {"agent-rt", "Yuzu"};
    auto csr = make_csr(*leaf_key, csrp);
    REQUIRE(csr);
    LeafParams lp;
    lp.subject = {"agent-rt", "Yuzu"};
    lp.validity = validity_days_from_now(365);
    lp.usage.client_auth = true;
    auto issued = sign_csr(*csr, *ca_cert, *ca_key, lp);
    REQUIRE(issued);

    auto parsed = parse_certificate(issued->cert_pem);
    REQUIRE(parsed);
    REQUIRE(parsed->serial_hex == issued->serial_hex);

    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    IssuedCertRecord rec;
    rec.serial_hex = issued->serial_hex;
    rec.subject = "agent-rt";
    rec.purpose = "agent";
    rec.not_after = now_s() + 365 * 86400;
    rec.cert_pem = issued->cert_pem;
    REQUIRE(store.record_issued(rec).has_value());

    REQUIRE_FALSE(store.is_revoked(parsed->serial_hex));
    REQUIRE(store.revoke(issued->serial_hex, "compromised").value_or(false));
    REQUIRE(store.is_revoked(parsed->serial_hex));
    CHECK_FALSE(store.revoke(issued->serial_hex, "again").value_or(true));
}

// ── Serial normalisation (pure function, unchanged by the migration) ────────

TEST_CASE("CaStore: normalize_serial_hex canonicalises + fails closed", "[ca_store][serial]") {
    REQUIRE(normalize_serial_hex("ab:cd:ef") == "ABCDEF");
    REQUIRE(normalize_serial_hex("ABCDEF") == "ABCDEF");
    REQUIRE(normalize_serial_hex(" aa bb\t") == "AABB");
    REQUIRE(normalize_serial_hex("00ab") == "AB");
    REQUIRE(normalize_serial_hex("0A") == "A");
    REQUIRE(normalize_serial_hex("0000") == "0");
    REQUIRE(normalize_serial_hex("0") == "0");
    REQUIRE_FALSE(normalize_serial_hex(""));
    REQUIRE_FALSE(normalize_serial_hex(":::"));
    REQUIRE_FALSE(normalize_serial_hex("12xy"));
    REQUIRE_FALSE(normalize_serial_hex("-1"));
    REQUIRE_FALSE(normalize_serial_hex(std::string(300, 'a')));
}

TEST_CASE("CaStore: revoke/is_revoked match across case + colon variance",
          "[ca_store][pg][serial][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("ABCD12")).has_value());
    REQUIRE(store.revoke("ab:cd:12", "operator typed colons + lowercase").value_or(false));
    REQUIRE(store.is_revoked("ABCD12"));
    REQUIRE(store.is_revoked("abcd12"));
    REQUIRE(store.is_revoked("AB:CD:12"));
    REQUIRE(store.is_revoked("00ABCD12"));
    CHECK_FALSE(store.revoke("ABCD12", "again").value_or(true));
}

TEST_CASE("CaStore: record_issued normalises + is_revoked fails closed on non-hex",
          "[ca_store][pg][serial][negative][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("aa:bb")).has_value());
    REQUIRE(store.get_issued("AABB")->has_value());
    REQUIRE(store.get_issued("aa:bb")->has_value());
    REQUIRE_FALSE(store.record_issued(sample_issued("zz-not-hex")).has_value());
    // is_revoked treats an un-normalisable serial as revoked (reject), not "clean".
    REQUIRE(store.is_revoked("not-a-serial"));
}

TEST_CASE("CaStore: issuer_fingerprint provenance round-trips (issued + CRL)",
          "[ca_store][pg][provenance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto rec = sample_issued("FACE01");
    rec.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_issued(rec).has_value());
    auto got = store.get_issued("FACE01");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issuer_fingerprint == "AA:BB:CC:DD");

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_fingerprint = "AA:BB:CC:DD";
    REQUIRE(store.record_crl_for_test(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->issuer_fingerprint == "AA:BB:CC:DD");
}

TEST_CASE("CaStore: issuer_key_id round-trips and list_issued_by_key_id filters (#1296)",
          "[ca_store][pg][provenance][pki]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    const std::string kid_a = "AA:AA:AA:AA";
    const std::string kid_b = "BB:BB:BB:BB";

    auto mk = [&](const std::string& serial, const std::string& kid) {
        auto r = sample_issued(serial);
        r.issuer_key_id = kid;
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", kid_a)).has_value());
    REQUIRE(store.record_issued(mk("A2", kid_a)).has_value());
    REQUIRE(store.record_issued(mk("B1", kid_b)).has_value());
    REQUIRE(store.record_issued(sample_issued("C1")).has_value()); // empty issuer_key_id

    auto got = store.get_issued("A1");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->issuer_key_id == kid_a);

    auto a = store.list_issued_by_key_id(kid_a);
    REQUIRE(a.has_value());
    REQUIRE(a->size() == 2);
    for (const auto& r : *a)
        CHECK(r.issuer_key_id == kid_a);
    auto b = store.list_issued_by_key_id(kid_b);
    REQUIRE(b.has_value());
    CHECK(b->size() == 1);

    // The empty key id is the unpopulated-row sentinel, NOT a CA identity.
    auto blank = store.list_issued_by_key_id("");
    REQUIRE(blank.has_value());
    CHECK(blank->empty());

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x00};
    crl.this_update = now_s();
    crl.next_update = now_s() + 86400;
    crl.issuer_key_id = kid_a;
    REQUIRE(store.record_crl_for_test(crl));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->issuer_key_id == kid_a);
}

TEST_CASE("CaStore: list_revoked surfaces a revoked agent cert by BARE agent_id (re-issue guard)",
          "[ca_store][pg][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    const std::string agent_id = "agent-7f3c";
    const std::string other_id = "agent-other";

    auto mk = [&](const std::string& serial, const std::string& subject) {
        IssuedCertRecord r;
        r.serial_hex = serial;
        r.subject = subject;
        r.purpose = "agent";
        r.not_after = now_s() + 365 * 86400;
        r.issued_at = now_s();
        return r;
    };
    REQUIRE(store.record_issued(mk("A1", agent_id)).has_value());
    REQUIRE(store.record_issued(mk("B2", other_id)).has_value());
    REQUIRE(store.revoke("A1", "compromised").value_or(false));

    auto revoked = store.list_revoked();
    REQUIRE(revoked.has_value());
    REQUIRE(revoked->size() == 1);
    CHECK(revoked->front().subject == agent_id);
    CHECK(revoked->front().not_after > now_s());
    CHECK(revoked->front().subject != other_id);
}

TEST_CASE("CaStore: list_revoked_serials matches list_revoked's serial set exactly "
          "(Gate 8 fix, 2026-08-21)",
          "[ca_store][pg][revoke][security]") {
    // Gate 8 (unhappy-path): the revocation-sweep tick now reads this cheaper,
    // serials-only variant instead of the full list_revoked() (cert_pem blobs +
    // ORDER BY) — same WHERE clause, same partial index, must return the SAME
    // set of serials or the sweep silently diverges from CRL construction.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    auto mk = [&](const std::string& serial) {
        IssuedCertRecord r;
        r.serial_hex = serial;
        r.subject = "agent-" + serial;
        r.purpose = "agent";
        r.not_after = now_s() + 365 * 86400;
        r.issued_at = now_s();
        return r;
    };
    REQUIRE(store.record_issued(mk("A1")).has_value());
    REQUIRE(store.record_issued(mk("B2")).has_value());
    REQUIRE(store.record_issued(mk("C3")).has_value());
    REQUIRE(store.revoke("A1", "compromised").value_or(false));
    REQUIRE(store.revoke("C3", "key_loss").value_or(false));

    auto serials = store.list_revoked_serials();
    REQUIRE(serials.has_value());
    std::set<std::string> got(serials->begin(), serials->end());
    CHECK(got == std::set<std::string>{"A1", "C3"});

    auto full = store.list_revoked();
    REQUIRE(full.has_value());
    std::set<std::string> from_full;
    for (const auto& rec : *full)
        from_full.insert(rec.serial_hex);
    CHECK(got == from_full);
}

TEST_CASE("CaStore: list_revoked_serials reports a genuine store failure as unexpected, "
          "never as an empty (nobody-revoked) set (Gate 8 fix, 2026-08-21)",
          "[ca_store][pg][revoke][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    IssuedCertRecord r;
    r.serial_hex = "DEAD";
    r.subject = "agent-x";
    r.purpose = "agent";
    r.not_after = now_s() + 365 * 86400;
    REQUIRE(store.record_issued(r).has_value());
    REQUIRE(store.revoke("DEAD", "compromised").value_or(false));

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE ca_store.ca_issued CASCADE")};
        REQUIRE(d.status() == PGRES_COMMAND_OK);
    }

    auto serials = store.list_revoked_serials();
    CHECK_FALSE(serials.has_value());
    CHECK(serials.error().starts_with(kCaDbErrorPrefix));
}

// ── CRL versions ─────────────────────────────────────────────────────────

TEST_CASE("CaStore: CRL numbering and roundtrip", "[ca_store][pg][crl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};

    auto n1 = store.next_crl_number();
    REQUIRE(n1.has_value());
    CHECK(*n1 == 1);
    REQUIRE_FALSE(store.latest_crl());

    CrlVersionRecord v1;
    v1.version = 1;
    v1.der = {0x30, 0x82, 0x01, 0x02};
    v1.this_update = now_s();
    v1.next_update = now_s() + 7 * 86400;
    REQUIRE(store.record_crl_for_test(v1));

    auto n2 = store.next_crl_number();
    REQUIRE(n2.has_value());
    CHECK(*n2 == 2);
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 1);
    CHECK(latest->der == v1.der);

    CrlVersionRecord v2 = v1;
    v2.version = 2;
    v2.der = {0x30, 0x82, 0x02, 0x05};
    REQUIRE(store.record_crl_for_test(v2));
    auto latest2 = store.latest_crl();
    REQUIRE(latest2);
    CHECK(latest2->version == 2);
    CHECK(latest2->der == v2.der);
}

TEST_CASE("CaStore: publish_next_crl allocates monotonic numbers atomically", "[ca_store][pg][crl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.set_root(sample_root("FP1")).has_value());
    REQUIRE(store.record_issued(sample_issued("DEAD")).has_value());
    REQUIRE(store.revoke("DEAD", "x").value_or(false));

    uint64_t seen_number = 0;
    std::size_t seen_revoked = 0;
    auto build = [&](uint64_t n, const std::vector<IssuedCertRecord>& revoked)
        -> std::optional<CaStore::BuiltCrl> {
        seen_number = n;
        seen_revoked = revoked.size();
        return fake_crl(n, revoked);
    };

    auto v1 = store.publish_next_crl(build, "FP1", "KID1");
    REQUIRE(v1);
    CHECK(v1->version == 1);
    CHECK(seen_number == 1);
    CHECK(seen_revoked == 1); // build saw the revoked DEAD cert
    CHECK(v1->issuer_fingerprint == "FP1");
    CHECK(v1->issuer_key_id == "KID1");
    CHECK(v1->this_update == 1000 + 1);
    CHECK(v1->next_update == 2000 + 1);
    CHECK(v1->revoked_count == 1);

    auto v2 = store.publish_next_crl(build, "FP1");
    REQUIRE(v2);
    CHECK(v2->version == 2);
    CHECK(seen_number == 2);
    CHECK(store.next_crl_number().value() == 3);

    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->version == 2);
    CHECK(latest->der == v2->der);
    CHECK(latest->this_update == v2->this_update);

    // A build that aborts (nullopt or empty DER) rolls back and does NOT consume a number.
    auto aborted = store.publish_next_crl(
        [](uint64_t, const std::vector<IssuedCertRecord>&) -> std::optional<CaStore::BuiltCrl> {
            return std::nullopt;
        });
    REQUIRE_FALSE(aborted);
    CHECK(aborted.error().kind == CaStore::PublishError::Failed);
    CHECK(aborted.error().reason == CaStore::PublishFailReason::BuildFailed); // #4830
    CHECK_FALSE(store.publish_next_crl(
        [](uint64_t, const std::vector<IssuedCertRecord>&) -> std::optional<CaStore::BuiltCrl> {
            return CaStore::BuiltCrl{};
        }));
    CHECK(store.next_crl_number().value() == 3);
}

// HA WS-6 6.1 (#4126): two CaStore instances on separate pools stand in for two server replicas
// sharing one database. Every concurrent publish must succeed with a distinct number, and the
// numbers must be exactly 1..N: no duplicate-key failure, no gap.
TEST_CASE("CaStore: concurrent publishers across replicas get distinct gap-free CRL numbers",
          "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool_a{{.conninfo = db.dsn(), .size = 4}};
    PgPool pool_b{{.conninfo = db.dsn(), .size = 4}};
    CaStore replica_a{pool_a};
    CaStore replica_b{pool_b};
    REQUIRE(replica_a.is_open());
    REQUIRE(replica_b.is_open());
    REQUIRE(replica_a.set_root(sample_root("FPX")).has_value());

    constexpr int kThreadsPerReplica = 3;
    constexpr int kPublishesPerThread = 8;
    std::atomic<int> failures{0};
    std::mutex seen_mu;
    std::vector<int64_t> seen;
    auto worker = [&](CaStore& store) {
        for (int i = 0; i < kPublishesPerThread; ++i) {
            auto rec = store.publish_next_crl(fake_crl, "FPX");
            if (!rec) {
                failures.fetch_add(1);
                continue;
            }
            std::lock_guard lk(seen_mu);
            seen.push_back(rec->version);
        }
    };
    {
        std::vector<std::thread> threads;
        JoinAll join{threads};
        for (int t = 0; t < kThreadsPerReplica; ++t) {
            threads.emplace_back(worker, std::ref(replica_a));
            threads.emplace_back(worker, std::ref(replica_b));
        }
    }
    constexpr int kTotal = 2 * kThreadsPerReplica * kPublishesPerThread;
    CHECK(failures.load() == 0);
    REQUIRE(seen.size() == static_cast<std::size_t>(kTotal));
    std::sort(seen.begin(), seen.end());
    for (int i = 0; i < kTotal; ++i)
        CHECK(seen[static_cast<std::size_t>(i)] == i + 1);
    CHECK(replica_a.next_crl_number().value() == static_cast<uint64_t>(kTotal + 1));
}

// The superset property: a publish that is waiting on the CRL table lock must see a revocation
// committed by another replica while it waited, because it reads the revoked set only after it
// acquires the lock.
TEST_CASE("CaStore: a publish queued on the lock includes revocations committed while it waited",
          "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool_a{{.conninfo = db.dsn(), .size = 2}};
    PgPool pool_b{{.conninfo = db.dsn(), .size = 2}};
    CaStore replica_a{pool_a};
    CaStore replica_b{pool_b};
    REQUIRE(replica_a.record_issued(sample_issued("AAAA")).has_value());
    REQUIRE(replica_a.record_issued(sample_issued("BBBB")).has_value());
    REQUIRE(replica_a.revoke("AAAA", "x").value_or(false));

    CrlLockHolder holder{db.dsn()};
    std::vector<std::string> serials_in_crl;
    std::optional<CrlVersionRecord> result;
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        auto rec = replica_b.publish_next_crl(
            [&](uint64_t n, const std::vector<IssuedCertRecord>& revoked) {
                for (const auto& r : revoked)
                    serials_in_crl.push_back(r.serial_hex);
                return fake_crl(n, revoked);
            });
        if (rec)
            result = std::move(*rec);
    });

    REQUIRE(wait_for_crl_lock_waiter(db.dsn()));
    REQUIRE(replica_a.revoke("BBBB", "x").value_or(false)); // commits while the publisher waits
    holder.release();
    threads[0].join();

    REQUIRE(result);
    CHECK(result->version == 1);
    std::sort(serials_in_crl.begin(), serials_in_crl.end());
    CHECK(serials_in_crl == std::vector<std::string>{"AAAA", "BBBB"});
}

// sec-1: the lock wait must stay bounded even when the pool sets no lock_timeout of its own (a
// DSN carrying `options=`, or PGOPTIONS). Here the pool-level bounds are disabled outright, so
// only the transaction-scoped set_config can end the wait.
TEST_CASE("CaStore: a publish that cannot get the CRL lock times out without a pool-level bound",
          "[ca_store][pg][crl][ha][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(),
                 .size = 2,
                 .statement_timeout_ms = 0,
                 .lock_timeout_ms = 0}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    CrlLockHolder holder{db.dsn()};
    std::atomic<bool> build_called{false};
    std::optional<std::expected<CrlVersionRecord, CaStore::PublishFailure>> rec;
    std::chrono::steady_clock::duration waited{};
    std::atomic<bool> done{false};
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        const auto start = std::chrono::steady_clock::now();
        rec = store.publish_next_crl([&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
            build_called = true;
            return fake_crl(n, r);
        });
        waited = std::chrono::steady_clock::now() - start;
        done = true;
    });
    // Watchdog: if the bound regresses, fail in 20 s instead of hanging until the shard timeout.
    for (int i = 0; i < 2000 && !done; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const bool bounded = done.load();
    if (!bounded)
        holder.release(); // unblock the publisher so the thread can be joined
    REQUIRE(bounded);
    threads[0].join();
    REQUIRE(rec);
    REQUIRE_FALSE(*rec);
    CHECK(rec->error().kind == CaStore::PublishError::Failed);
    CHECK(rec->error().reason == CaStore::PublishFailReason::LockTimeout); // #4830
    CHECK_FALSE(build_called); // never signed anything without holding the lock
    CHECK(waited >= CaStore::kCrlLockTimeout - std::chrono::milliseconds(500));
    // Generous upper bound: the timer also covers lease acquire and BEGIN on a loaded CI box.
    CHECK(waited < CaStore::kCrlLockTimeout + std::chrono::seconds(10));

    holder.release();
    auto after = store.publish_next_crl(fake_crl);
    REQUIRE(after);
    CHECK(after->version == 1);
}

// UP-2: a subordinate import that swaps the root while a publish waits on the lock must not let
// that publish record a CRL signed under the superseded root.
TEST_CASE("CaStore: a publish whose root was replaced while it waited is refused",
          "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool_a{{.conninfo = db.dsn(), .size = 2}};
    PgPool pool_b{{.conninfo = db.dsn(), .size = 2}};
    CaStore replica_a{pool_a};
    CaStore replica_b{pool_b};
    REQUIRE(replica_a.set_root(sample_root("FP:OLD")).has_value());

    CrlLockHolder holder{db.dsn()};
    bool build_called = false;
    std::optional<CaStore::PublishFailure> error;
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        auto rec = replica_b.publish_next_crl(
            [&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
                build_called = true;
                return fake_crl(n, r);
            },
            "FP:OLD");
        if (!rec)
            error = rec.error();
    });

    REQUIRE(wait_for_crl_lock_waiter(db.dsn()));
    REQUIRE(replica_a.set_root(sample_root("FP:NEW")).has_value()); // the "import"
    holder.release();
    threads[0].join();

    REQUIRE(error);
    CHECK(error->kind == CaStore::PublishError::RootChanged);
    CHECK(error->reason == CaStore::PublishFailReason::RootReadFailed); // #4830
    CHECK_FALSE(build_called);
    CHECK_FALSE(replica_a.latest_crl());

    auto retried = replica_b.publish_next_crl(fake_crl, "FP:NEW");
    REQUIRE(retried);
    CHECK(retried->version == 1);
    CHECK(retried->issuer_fingerprint == "FP:NEW");
}

// safety-1: a second publish in the same process waits on the local mutex (bounded by
// local_wait) instead of parking another pool connection on the table lock; past the bound it
// reports Busy rather than queueing indefinitely.
TEST_CASE("CaStore: a publish that cannot get the per-process lock reports Busy",
          "[ca_store][pg][crl][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    std::atomic<bool> in_builder{false};
    std::atomic<bool> release_builder{false};
    std::optional<int64_t> first_version;
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        auto rec = store.publish_next_crl([&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
            in_builder = true;
            for (int i = 0; i < 400 && !release_builder; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return fake_crl(n, r);
        });
        if (rec)
            first_version = rec->version;
    });
    for (int i = 0; i < 400 && !in_builder; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(in_builder);

    bool second_built = false;
    auto second = store.publish_next_crl(
        [&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
            second_built = true;
            return fake_crl(n, r);
        },
        {}, {}, std::chrono::milliseconds{200});
    release_builder = true;
    threads[0].join();

    REQUIRE_FALSE(second);
    CHECK(second.error().kind == CaStore::PublishError::Busy);
    CHECK(second.error().reason == CaStore::PublishFailReason::Busy); // #4830
    CHECK_FALSE(second_built);
    REQUIRE(first_version);
    CHECK(*first_version == 1);
}

// UP2-2: purging stale default-cert inventory must never delete a revoked row — that would make
// is_revoked() accept the cert again, drop it from every later CRL, and (by shrinking the revoked
// count) let has_unpublished_revocations() miss a revocation elsewhere.
TEST_CASE("CaStore: delete_issued_by keeps revoked rows", "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto leaf = [](const std::string& serial) {
        auto r = sample_issued(serial, "server");
        r.issued_by = "system:default-certs";
        return r;
    };
    REQUIRE(store.record_issued(leaf("AAAA")).has_value());
    REQUIRE(store.record_issued(leaf("BBBB")).has_value());
    REQUIRE(store.revoke("AAAA", "key compromise").value_or(false));
    REQUIRE(store.publish_next_crl(fake_crl));

    REQUIRE(store.delete_issued_by("system:default-certs"));

    CHECK(store.is_revoked("AAAA"));
    auto a = store.get_issued("AAAA");
    REQUIRE(a.has_value());
    CHECK(a->has_value());
    auto b = store.get_issued("BBBB");
    REQUIRE(b.has_value());
    CHECK_FALSE(b->has_value());
    CHECK_FALSE(store.has_unpublished_revocations().value());
}

// Review (PR #4833): the root re-check must also FENCE the root row until the publish commits,
// so a subordinate import cannot swap it between the check and the COMMIT.
TEST_CASE("CaStore: a root swap waits for an in-flight publish to commit",
          "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool_a{{.conninfo = db.dsn(), .size = 2}};
    PgPool pool_b{{.conninfo = db.dsn(), .size = 2}};
    CaStore replica_a{pool_a};
    CaStore replica_b{pool_b};
    REQUIRE(replica_a.set_root(sample_root("FP:OLD")).has_value());

    std::atomic<bool> in_builder{false};
    std::atomic<bool> release_builder{false};
    std::atomic<bool> swap_done{false};
    std::optional<std::string> published_fp;
    std::vector<std::thread> threads;
    JoinAll join{threads};
    threads.emplace_back([&] {
        auto rec = replica_b.publish_next_crl(
            [&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
                in_builder = true;
                for (int i = 0; i < 1000 && !release_builder; ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                return fake_crl(n, r);
            },
            "FP:OLD");
        if (rec)
            published_fp = rec->issuer_fingerprint;
    });
    for (int i = 0; i < 500 && !in_builder; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    REQUIRE(in_builder);

    threads.emplace_back([&] {
        (void)replica_a.set_root(sample_root("FP:NEW")); // the "import"
        swap_done = true;
    });
    // Positive evidence that the swap is WAITING ON A LOCK (not merely slow): its backend shows a
    // Lock wait in this database while the publish sits in its builder.
    bool swap_waiting = false;
    {
        PgConn probe{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(probe.get()) == CONNECTION_OK);
        for (int i = 0; i < 300 && !swap_waiting; ++i) {
            PgResult w{PQexec(probe.get(),
                              "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                              "current_database() AND wait_event_type = 'Lock' "
                              "AND query ILIKE '%INSERT INTO ca_store.ca_root%'")};
            REQUIRE(w.status() == PGRES_TUPLES_OK);
            swap_waiting = std::string(PQgetvalue(w.get(), 0, 0)) != "0";
            if (!swap_waiting)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    CHECK(swap_waiting);    // blocked by the publish's FOR SHARE on the root row
    CHECK_FALSE(swap_done);
    release_builder = true;
    threads[0].join();
    threads[1].join();

    REQUIRE(published_fp);
    CHECK(*published_fp == "FP:OLD"); // committed under the root it signed with
    CHECK(swap_done);
    auto root = replica_a.get_root();
    REQUIRE(root.has_value());
    REQUIRE(root->has_value());
    CHECK((*root)->fingerprint_sha256 == "FP:NEW");
}

// Review blocker (PR #4833): the append-only revoked set must hold in the DATABASE, not just in
// delete_issued_by's WHERE clause — an older binary sharing the migrated schema runs the pre-6.1
// unconditional DELETE. Row triggers must not block TRUNCATE (the documented clean re-root).
TEST_CASE("CaStore: the database rejects deleting or changing a revoked ca_issued row",
          "[ca_store][pg][crl][ha][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    auto leaf = [](const std::string& serial) {
        auto r = sample_issued(serial, "server");
        r.issued_by = "system:default-certs";
        return r;
    };
    REQUIRE(store.record_issued(leaf("AAAA")).has_value());
    REQUIRE(store.record_issued(leaf("BBBB")).has_value());
    REQUIRE(store.revoke("AAAA", "key compromise").value_or(false));

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    // The exact pre-6.1 delete_issued_by statement (no status predicate).
    PgResult old_purge{PQexec(conn.get(), "DELETE FROM ca_store.ca_issued "
                                          "WHERE issued_by = 'system:default-certs'")};
    CHECK(old_purge.status() == PGRES_FATAL_ERROR);
    CHECK(store.is_revoked("AAAA"));
    auto b = store.get_issued("BBBB");
    REQUIRE(b.has_value());
    CHECK(b->has_value()); // the whole statement failed; nothing was deleted

    PgResult unrevoke{PQexec(conn.get(), "UPDATE ca_store.ca_issued SET status = 'active' "
                                         "WHERE serial_hex = 'AAAA'")};
    CHECK(unrevoke.status() == PGRES_FATAL_ERROR);
    CHECK(store.is_revoked("AAAA"));

    // A non-revoked row can still be deleted; the current purge keeps the revoked one.
    REQUIRE(store.delete_issued_by("system:default-certs"));
    CHECK(store.is_revoked("AAAA"));

    // TRUNCATE (clean re-root runbook) is not blocked by the row trigger.
    PgResult trunc{PQexec(conn.get(), "TRUNCATE ca_store.ca_issued")};
    CHECK(trunc.status() == PGRES_COMMAND_OK);
}

// qe-1: a COMMIT that fails after the row was built and inserted must not be reported as
// published. A deferred constraint trigger raises at COMMIT time, after the callback returned.
TEST_CASE("CaStore: a publish whose COMMIT fails is not reported as published",
          "[ca_store][pg][crl][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(conn.get(),
                                "CREATE FUNCTION ca_store.yuzu_test_fail_commit() RETURNS trigger "
                                "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                                "'yuzu_test forced commit failure'; END $$")}
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(PgResult{PQexec(conn.get(),
                                "CREATE CONSTRAINT TRIGGER yuzu_test_fail_commit AFTER INSERT ON "
                                "ca_store.ca_crl_versions DEFERRABLE INITIALLY DEFERRED FOR EACH "
                                "ROW EXECUTE FUNCTION ca_store.yuzu_test_fail_commit()")}
                    .status() == PGRES_COMMAND_OK);
    }
    bool build_called = false;
    auto rec = store.publish_next_crl([&](uint64_t n, const std::vector<IssuedCertRecord>& r) {
        build_called = true;
        return fake_crl(n, r);
    });
    CHECK(build_called); // the row was built and inserted; only the COMMIT failed
    REQUIRE_FALSE(rec);
    CHECK(rec.error().kind == CaStore::PublishError::Failed);
    CHECK(rec.error().reason == CaStore::PublishFailReason::InsertOrCommitFailed); // #4830
    CHECK_FALSE(store.latest_crl());
}

// UP-1: the freshness pass republishes when the latest CRL was not built from the current
// revoked set. The check compares counts, never timestamps from different replicas' clocks.
TEST_CASE("CaStore: has_unpublished_revocations tracks whether the latest CRL covers the set",
          "[ca_store][pg][crl][ha]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.record_issued(sample_issued("AAAA")).has_value());
    REQUIRE(store.record_issued(sample_issued("BBBB")).has_value());

    CHECK(store.has_unpublished_revocations().value()); // no CRL yet
    REQUIRE(store.publish_next_crl(fake_crl));
    CHECK_FALSE(store.has_unpublished_revocations().value());

    // A revoke whose own publish never happened (e.g. it timed out on the lock).
    REQUIRE(store.revoke("AAAA", "x").value_or(false));
    CHECK(store.has_unpublished_revocations().value());
    REQUIRE(store.publish_next_crl(fake_crl));
    CHECK_FALSE(store.has_unpublished_revocations().value());

    // A row without revoked_count (published before migration v3) reads as not covered.
    CrlVersionRecord legacy;
    legacy.version = 10;
    legacy.der = {0x30, 0x00};
    legacy.this_update = now_s();
    legacy.next_update = now_s() + 86400;
    REQUIRE(store.record_crl_for_test(legacy));
    CHECK(store.has_unpublished_revocations().value());
}

TEST_CASE("CaStore: record_crl_for_test rejects version < 1 and silent-clobber duplicates",
          "[ca_store][pg][crl][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    CrlVersionRecord r;
    r.version = 0;
    r.der = {0x30, 0x00};
    r.this_update = now_s();
    r.next_update = now_s() + 86400;
    REQUIRE_FALSE(store.record_crl_for_test(r));
    r.version = 1;
    REQUIRE(store.record_crl_for_test(r));
    r.der = {0x30, 0x01}; // a different CRL claiming the same number
    REQUIRE_FALSE(store.record_crl_for_test(r));
    auto latest = store.latest_crl();
    REQUIRE(latest);
    CHECK(latest->der == std::vector<uint8_t>{0x30, 0x00}); // original preserved
}

// ── Dashboard aggregates (ADR-0070 D13): issuance_stats + list_issued_filtered ──
//
// Fixed timestamps against a pinned as_of, so every window edge is exact: a row ON an edge
// belongs to exactly the side the predicate says, and a count always equals the total of the
// list behind it — kind by kind and revocation bucket by bucket.

namespace {

constexpr int64_t kAsOf = 1'790'000'000; // 2026-09-21 (a Monday, 14:13:20 UTC)
constexpr int64_t kDay = 86400;
constexpr int64_t kWeek = 7 * kDay;

IssuedCertRecord fixed_issued(const std::string& serial, int64_t issued_at, int64_t not_after,
                              int64_t revoked_at = 0, std::string_view reason = {}) {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "CN=" + serial;
    r.purpose = "agent";
    r.issued_at = issued_at;
    r.not_after = not_after;
    r.revoked_at = revoked_at;
    r.status = revoked_at > 0 ? CertStatus::Revoked : CertStatus::Active;
    r.revocation_reason = std::string(reason);
    r.cert_pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
    return r;
}

CaIssuanceStatsRequest stats_request(int weeks, std::optional<int64_t> as_of = kAsOf) {
    CaIssuanceStatsRequest rq;
    rq.as_of = as_of;
    rq.expiring_days = {3, 30};
    rq.expired_days = {7, 30};
    rq.revoked_days = {7, 30};
    rq.issued_days = 7;
    rq.weeks = weeks;
    return rq;
}

bool same_counts(const CaRevokedCounts& c, int64_t superseded, int64_t unpublished, int64_t other) {
    return c.superseded == superseded && c.unpublished == unpublished && c.other == other;
}

} // namespace

TEST_CASE("CaStore: issuance_stats counts every window against as_of, edges exact, three "
          "revocation buckets",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    const std::string sup(kRevokeReasonSuperseded);
    const std::string unp(kRevokeReasonUnpublished);

    std::vector<IssuedCertRecord> rows;
    // Expiring: ON as_of+3d is inside the 3-day window; one second past it is not.
    rows.push_back(fixed_issued("E1", kAsOf - 100 * kDay, kAsOf + 3 * kDay));
    rows.push_back(fixed_issued("E2", kAsOf - 100 * kDay, kAsOf + 3 * kDay + 1));
    // RFC 5280: valid THROUGH notAfter, so expiry exactly AT as_of is still active and
    // expiring, never expired.
    rows.push_back(fixed_issued("F1", kAsOf - 100 * kDay, kAsOf));
    // One second before as_of is expired (inside 7 and 30).
    rows.push_back(fixed_issued("F4", kAsOf - 100 * kDay, kAsOf - 1));
    // Expired exactly 7 days ago: INSIDE the 7-day window (inclusive lower bound) and 30;
    // one second earlier is inside 30 only.
    rows.push_back(fixed_issued("F2", kAsOf - 100 * kDay, kAsOf - 7 * kDay));
    rows.push_back(fixed_issued("F3", kAsOf - 100 * kDay, kAsOf - 7 * kDay - 1));
    // Issued exactly 7 days ago: outside issued_7d; one second later: inside. Both active.
    rows.push_back(fixed_issued("B1", kAsOf - 7 * kDay, kAsOf + 400 * kDay));
    rows.push_back(fixed_issued("B2", kAsOf - 7 * kDay + 1, kAsOf + 400 * kDay));
    // Superseded exactly 7 days ago: outside revoked_7d (strict lower bound), inside 30.
    rows.push_back(
        fixed_issued("D5", kAsOf - 50 * kDay, kAsOf + 200 * kDay, kAsOf - 7 * kDay, sup));
    // Unpublished 2 days ago, issued 3 days ago: in revoked_7d's unpublished bucket, and NOT
    // issued (never delivered).
    rows.push_back(fixed_issued("D6", kAsOf - 3 * kDay, kAsOf + 200 * kDay, kAsOf - 2 * kDay, unp));
    // Revoked exactly AT as_of (the inclusive upper bound) by an operator whose reason collided
    // with a system marker and was stored qualified: the "other" bucket. Issued yesterday.
    rows.push_back(fixed_issued("D7", kAsOf - kDay, kAsOf + 200 * kDay, kAsOf,
                                "operator-supplied: superseded"));
    // Revoked 5 days ago AND expired 3 days ago: counted in its revoked windows ONLY - expiring
    // and expired cover status active only (owner ruling 2026-10-19, ADR-0070 #6125 Gate 8).
    rows.push_back(fixed_issued("D8", kAsOf - 50 * kDay, kAsOf - 3 * kDay, kAsOf - 5 * kDay,
                                "key compromise"));
    // Dated after as_of: in no count at all.
    rows.push_back(fixed_issued("F9", kAsOf - 50 * kDay, kAsOf + 200 * kDay, kAsOf + 1, sup));
    rows.push_back(fixed_issued("FA", kAsOf + 10, kAsOf + 400 * kDay));
    for (const auto& r : rows)
        REQUIRE(store.record_issued(r));

    const auto st = store.issuance_stats(stats_request(3));
    REQUIRE(st.has_value());
    CHECK(st->as_of == kAsOf);
    CHECK(st->active == 5); // E1, E2, F1, B1, B2 (FA is after as_of; F2-F4 expired; D* revoked)
    REQUIRE(st->expiring.size() == 2);
    CHECK(st->expiring[0] == 2); // E1, F1
    CHECK(st->expiring[1] == 3); // E1, E2, F1
    REQUIRE(st->expired.size() == 2);
    CHECK(st->expired[0] == 2); // F4, F2 (D8 is revoked: only in the revoked windows)
    CHECK(st->expired[1] == 3); // F4, F2, F3
    REQUIRE(st->revoked.size() == 2);
    CHECK(same_counts(st->revoked[0], 0, 1, 2)); // D6 | D7, D8
    CHECK(same_counts(st->revoked[1], 1, 1, 2)); // D5 | D6 | D7, D8
    CHECK(st->revoked[0].total() == 3);
    CHECK(st->issued == 2); // B2, D7 (D6 unpublished; FA after as_of)

    // The SQL mirrors the catalogue's ONE expiry definition (RFC 5280): recount every row with
    // crypto_widgets' constexpr predicates and require the store to agree, so neither copy can
    // move without the other.
    namespace cw = crypto_widgets;
    auto expect = [&](auto pred) {
        return static_cast<int64_t>(std::ranges::count_if(rows, pred));
    };
    const auto live = [](const IssuedCertRecord& r) {
        return r.status == CertStatus::Active && r.issued_at <= kAsOf;
    };
    CHECK(st->active == expect([&](const IssuedCertRecord& r) {
              return live(r) && cw::unexpired_at(r.not_after, kAsOf);
          }));
    for (std::size_t i = 0; i < 2; ++i) {
        const int ed = i == 0 ? 3 : 30;
        const int xd = i == 0 ? 7 : 30;
        CHECK(st->expiring[i] == expect([&](const IssuedCertRecord& r) {
                  return live(r) && cw::expiring_within(r.not_after, kAsOf, ed);
              }));
        CHECK(st->expired[i] == expect([&](const IssuedCertRecord& r) {
                  return r.status == CertStatus::Active &&
                         cw::expired_within(r.not_after, kAsOf, xd);
              }));
    }

    // Each count equals the total of the list behind it, at the same pinned as_of.
    using K = CaIssuedFilter::Kind;
    using B = CaRevokeBucket;
    auto list_total = [&](CaIssuedFilter f) {
        auto p = store.list_issued_filtered(f, kAsOf, 100);
        REQUIRE(p.has_value());
        CHECK(p->as_of == kAsOf);
        CHECK(static_cast<int64_t>(p->rows.size()) == p->total);
        return p->total;
    };
    CHECK(list_total({.kind = K::kActive}) == st->active);
    CHECK(list_total({.kind = K::kExpiring, .days = 3}) == st->expiring[0]);
    CHECK(list_total({.kind = K::kExpiring, .days = 30}) == st->expiring[1]);
    CHECK(list_total({.kind = K::kExpired, .days = 7}) == st->expired[0]);
    CHECK(list_total({.kind = K::kExpired, .days = 30}) == st->expired[1]);
    CHECK(list_total({.kind = K::kIssued, .days = 7}) == st->issued);
    for (std::size_t i = 0; i < 2; ++i) {
        const int d = i == 0 ? 7 : 30;
        CHECK(list_total({.kind = K::kRevoked, .days = d}) == st->revoked[i].total());
        CHECK(list_total({.kind = K::kRevoked, .days = d, .revoked_bucket = B::kSuperseded}) ==
              st->revoked[i].superseded);
        CHECK(list_total({.kind = K::kRevoked, .days = d, .revoked_bucket = B::kUnpublished}) ==
              st->revoked[i].unpublished);
        CHECK(list_total({.kind = K::kRevoked, .days = d, .revoked_bucket = B::kOther}) ==
              st->revoked[i].other);
    }
    // The rows carry their reason, so the bucket is visible per row.
    auto other = store.list_issued_filtered(
        {.kind = K::kRevoked, .days = 7, .revoked_bucket = B::kOther}, kAsOf, 10);
    REQUIRE(other.has_value());
    REQUIRE(other->rows.size() == 2);
    CHECK(other->rows[0].serial_hex == "D7"); // newest revocation first
    CHECK(other->rows[0].revocation_reason == "operator-supplied: superseded");
    CHECK(other->rows[1].serial_hex == "D8");
}

TEST_CASE("CaStore: issuance_stats per-week series is zero-filled, half-open, partial at as_of",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    const int64_t w3 = crypto_widgets::week_start_of(kAsOf); // the week containing as_of
    REQUIRE(w3 == kAsOf - 14 * 3600 - 13 * 60 - 20);
    const int64_t w0 = w3 - 3 * kWeek;
    // Issued on week 0's first second, on week 1's first second (NOT week 0), and in week 3.
    REQUIRE(store.record_issued(fixed_issued("A1", w0, kAsOf + 400 * kDay)));
    REQUIRE(store.record_issued(fixed_issued("A2", w0 + kWeek, kAsOf + 400 * kDay)));
    REQUIRE(store.record_issued(fixed_issued("A3", w3 + 5, kAsOf + 400 * kDay, w3 + 60, "x")));
    // Issued before the series: in no week.
    REQUIRE(store.record_issued(fixed_issued("A4", w0 - 1, kAsOf + 400 * kDay)));
    // In as_of's own week but after as_of: the partial week stops at as_of.
    REQUIRE(store.record_issued(fixed_issued("A5", kAsOf + 1, kAsOf + 400 * kDay)));

    const auto st = store.issuance_stats(stats_request(4));
    REQUIRE(st.has_value());
    REQUIRE(st->week_starts.size() == 4);
    CHECK(st->week_starts[0] == w0);
    CHECK(st->week_starts[3] == w3);
    CHECK(st->issued_per_week == std::vector<int64_t>{1, 1, 0, 1});
    REQUIRE(st->revoked_per_week.size() == 4);
    CHECK(st->revoked_per_week[2].total() == 0);
    CHECK(same_counts(st->revoked_per_week[3], 0, 0, 1));

    // The week lists agree with the series.
    using K = CaIssuedFilter::Kind;
    auto week = store.list_issued_filtered({.kind = K::kIssuedWeek, .week_start = w0 + kWeek},
                                           kAsOf, 10);
    REQUIRE(week.has_value());
    REQUIRE(week->rows.size() == 1);
    CHECK(week->rows[0].serial_hex == "A2");
    auto partial = store.list_issued_filtered({.kind = K::kIssuedWeek, .week_start = w3}, kAsOf,
                                              10);
    REQUIRE(partial.has_value());
    CHECK(partial->total == 1); // A3 only — A5 is after as_of
    auto rweek = store.list_issued_filtered(
        {.kind = K::kRevokedWeek, .week_start = w3, .revoked_bucket = CaRevokeBucket::kOther},
        kAsOf, 10);
    REQUIRE(rweek.has_value());
    REQUIRE(rweek->rows.size() == 1);
    CHECK(rweek->rows[0].serial_hex == "A3");
    CHECK(rweek->rows[0].status == CertStatus::Revoked);
    CHECK(rweek->rows[0].cert_pem.empty()); // the list never carries the PEM
}

TEST_CASE("CaStore: the per-week series crosses an ISO year boundary (2027-W02 back to 2026-W52)",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    // 2027-01-13 12:00 UTC, a Wednesday in 2027-W02. 2026 has 53 ISO weeks (1 Jan 2026 was a
    // Thursday), so the four weeks are 2026-W52, 2026-W53, 2027-W01, 2027-W02.
    constexpr int64_t as_of = 1'799'841'600;
    constexpr int64_t w02 = 1'799'625'600; // Monday 2027-01-11
    constexpr int64_t w01 = w02 - kWeek;   // Monday 2027-01-04
    constexpr int64_t w53 = w01 - kWeek;   // Monday 2026-12-28
    constexpr int64_t w52 = w53 - kWeek;   // Monday 2026-12-21
    const std::string unp(kRevokeReasonUnpublished);
    REQUIRE(store.record_issued(fixed_issued("E1", w53 + kDay, as_of + 400 * kDay)));
    REQUIRE(store.record_issued(fixed_issued("E2", w01, as_of + 400 * kDay))); // W01's 1st second
    REQUIRE(store.record_issued(fixed_issued("E3", w02 + kDay, as_of + 400 * kDay)));
    REQUIRE(store.record_issued(fixed_issued("E4", as_of + 60, as_of + 400 * kDay))); // future
    // Recorded in W01 and revoked as unpublished in W01: no issued week, one unpublished.
    REQUIRE(store.record_issued(
        fixed_issued("E5", w01 + 2 * kDay, as_of + 400 * kDay, w01 + 2 * kDay + 5, unp)));
    // Superseded in W53.
    REQUIRE(store.record_issued(fixed_issued("E6", w53, as_of + 400 * kDay, w53 + 3 * kDay,
                                             kRevokeReasonSuperseded)));

    const auto st = store.issuance_stats(stats_request(4, as_of));
    REQUIRE(st.has_value());
    CHECK(st->week_starts == std::vector<int64_t>{w52, w53, w01, w02});
    CHECK(crypto_widgets::iso_week_label(w52) == "2026-W52");
    CHECK(crypto_widgets::iso_week_label(w53) == "2026-W53");
    CHECK(crypto_widgets::iso_week_label(w01) == "2027-W01");
    CHECK(crypto_widgets::iso_week_label(w02) == "2027-W02");
    CHECK(st->issued_per_week == std::vector<int64_t>{0, 2, 1, 1}); // E1+E6 | E2 | E3
    REQUIRE(st->revoked_per_week.size() == 4);
    CHECK(same_counts(st->revoked_per_week[0], 0, 0, 0)); // zero-filled
    CHECK(same_counts(st->revoked_per_week[1], 1, 0, 0));
    CHECK(same_counts(st->revoked_per_week[2], 0, 1, 0));
    CHECK(same_counts(st->revoked_per_week[3], 0, 0, 0));

    using K = CaIssuedFilter::Kind;
    auto w = store.list_issued_filtered({.kind = K::kIssuedWeek, .week_start = w02}, as_of, 10);
    REQUIRE(w.has_value());
    CHECK(w->total == 1); // E3; E4 is after as_of
    auto u = store.list_issued_filtered({.kind = K::kRevokedWeek, .week_start = w01,
                                         .revoked_bucket = CaRevokeBucket::kUnpublished},
                                        as_of, 10);
    REQUIRE(u.has_value());
    CHECK(u->total == 1);
}

TEST_CASE("CaStore: the statement's own ISO-week arithmetic agrees with crypto_widgets::week_start_of",
          "[ca_store][pg][stats]") {
    // as_of and the week starts are computed in the counting statement itself (ADR-0070 R4); the
    // C++ calendar helper stays the definition, so recompute against it on the edges.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    const int64_t monday = crypto_widgets::week_start_of(kAsOf);
    for (const int64_t at : {kAsOf, monday, monday - 1, monday + kWeek - 1, monday + kWeek,
                             int64_t{1'799'841'600} /* 2027-W02 */, int64_t{0}, int64_t{-1},
                             int64_t{-3 * kDay}, int64_t{4 * kDay} /* 1970-01-05, a Monday */}) {
        CAPTURE(at);
        const auto st = store.issuance_stats(stats_request(3, at));
        REQUIRE(st.has_value());
        CHECK(st->as_of == at);
        REQUIRE(st->week_starts.size() == 3);
        CHECK(st->week_starts[2] == crypto_widgets::week_start_of(at));
        CHECK(st->week_starts[1] == st->week_starts[2] - kWeek);
        CHECK(st->week_starts[0] == st->week_starts[2] - 2 * kWeek);
    }
    // Unpinned: the statement's now() in whole seconds, and its week start from that value.
    const int64_t before = now_s();
    const auto live = store.issuance_stats(stats_request(2, std::nullopt));
    REQUIRE(live.has_value());
    CHECK(live->as_of >= before - 5);
    CHECK(live->as_of <= now_s() + 5);
    CHECK(live->week_starts.back() == crypto_widgets::week_start_of(live->as_of));
    auto page = store.list_issued_filtered({.kind = CaIssuedFilter::Kind::kActive}, std::nullopt,
                                           10);
    REQUIRE(page.has_value());
    CHECK(page->as_of >= live->as_of);
}

TEST_CASE("CaStore: an omitted as_of is the database clock, echoed, and pins later pages",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    const int64_t now = now_s();
    for (int i = 0; i < 3; ++i)
        REQUIRE(store.record_issued(
            fixed_issued("D" + std::to_string(i), now - 60 - i, now + 400 * kDay)));

    const auto st = store.issuance_stats(stats_request(2, std::nullopt));
    REQUIRE(st.has_value());
    CHECK(st->as_of >= now - 5);
    CHECK(st->as_of <= now + 5);
    CHECK(st->issued == 3);

    using K = CaIssuedFilter::Kind;
    auto p1 = store.list_issued_filtered({.kind = K::kIssued, .days = 7}, std::nullopt, 2);
    REQUIRE(p1.has_value());
    CHECK(p1->total == 3);
    CHECK(p1->as_of >= now - 5);
    REQUIRE(p1->next.has_value());
    // A certificate issued after the first page's as_of does not shift the pinned second page.
    REQUIRE(store.record_issued(fixed_issued("D9", p1->as_of + 30, now + 400 * kDay)));
    auto p2 = store.list_issued_filtered({.kind = K::kIssued, .days = 7}, p1->as_of, 2, p1->next);
    REQUIRE(p2.has_value());
    CHECK(p2->total == 3);
    CHECK(p2->as_of == p1->as_of);
    REQUIRE(p2->rows.size() == 1);
    CHECK(p2->rows[0].serial_hex == "D2");
    CHECK_FALSE(p2->next.has_value()); // end of the list

    // The 5 s statement_timeout is SET LOCAL: the pooled connection goes back without it.
    auto lease = pool.acquire();
    REQUIRE(lease);
    PgResult t{PQexec(lease.get(), "SELECT current_setting('statement_timeout')")};
    REQUIRE(t.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(t.get(), 0, 0)) != "5s");
}

TEST_CASE("CaStore: issuance_stats on an empty inventory is all zeros, not an error",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    const auto st = store.issuance_stats(stats_request(2));
    REQUIRE(st.has_value());
    CHECK(st->active == 0);
    CHECK(st->expiring == std::vector<int64_t>{0, 0});
    CHECK(st->issued_per_week == std::vector<int64_t>{0, 0});
    REQUIRE(st->revoked_per_week.size() == 2);
    CHECK(st->revoked_per_week[1].total() == 0);
}

TEST_CASE("CaStore: issuance_stats and list_issued_filtered refuse out-of-bounds requests",
          "[ca_store][pg][stats][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    auto refused = [](const auto& r) {
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == CaReadError::Kind::kInvalidRequest);
        CHECK(r.error().message.rfind(kCaDbErrorPrefix, 0) != 0); // a caller defect, not a DB fault
    };
    auto rq = stats_request(1);
    rq.weeks = 0;
    refused(store.issuance_stats(rq));
    rq = stats_request(1);
    rq.expiring_days = {0};
    refused(store.issuance_stats(rq));
    rq = stats_request(1);
    rq.revoked_days.assign(CaStore::kMaxStatsWindows + 1, 7);
    refused(store.issuance_stats(rq));

    using K = CaIssuedFilter::Kind;
    refused(store.list_issued_filtered({.kind = K::kExpiring, .days = 0}, kAsOf, 10));
    refused(store.list_issued_filtered(
        {.kind = K::kActive, .revoked_bucket = CaRevokeBucket::kOther}, kAsOf, 10));
    refused(store.list_issued_filtered(
        {.kind = K::kIssued, .days = 7, .revoked_bucket = CaRevokeBucket::kSuperseded}, kAsOf, 10));
}

TEST_CASE("CaStore: dashboard reads report a lease timeout, a query error and a closed store "
          "distinctly, and the pool stays usable",
          "[ca_store][pg][stats][negative]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    using K = CaIssuedFilter::Kind;
    auto degraded = [](const auto& r, CaReadError::Kind kind) {
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == kind);
        CHECK(r.error().message.rfind(kCaDbErrorPrefix, 0) == 0);
    };
    {
        auto held = pool.acquire(); // the only connection
        REQUIRE(held);
        degraded(store.issuance_stats(stats_request(1)), CaReadError::Kind::kPoolAcquireTimeout);
        degraded(store.list_issued_filtered({.kind = K::kActive}, kAsOf, 10),
                 CaReadError::Kind::kPoolAcquireTimeout);
    }
    REQUIRE(store.issuance_stats(stats_request(1)).has_value());

    PgConn admin{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(admin.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(admin.get(), "ALTER TABLE ca_store.ca_issued RENAME COLUMN "
                                         "revocation_reason TO revocation_reason_x")}
                .ok());
    degraded(store.issuance_stats(stats_request(1)), CaReadError::Kind::kQueryError);
    degraded(store.list_issued_filtered({.kind = K::kActive}, kAsOf, 10),
             CaReadError::Kind::kQueryError);
    REQUIRE(PgResult{PQexec(admin.get(), "ALTER TABLE ca_store.ca_issued RENAME COLUMN "
                                         "revocation_reason_x TO revocation_reason")}
                .ok());
    // The failed transactions were rolled back and their connection returned: the pool serves.
    CHECK(store.issuance_stats(stats_request(1)).has_value());
    CHECK(store.list_issued_filtered({.kind = K::kActive}, kAsOf, 10).has_value());
}

TEST_CASE("CaStore: dashboard reads on a store that never opened are kNotOpen",
          "[ca_store][pg][stats][negative]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(PgResult{PQexec(conn.get(), "CREATE SCHEMA ca_store")}.ok());
        REQUIRE(PgResult{PQexec(conn.get(), "CREATE TABLE ca_store.ca_root (bogus int)")}.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    CaStore store{pool};
    REQUIRE_FALSE(store.is_open());
    auto st = store.issuance_stats(stats_request(1));
    REQUIRE_FALSE(st.has_value());
    CHECK(st.error().kind == CaReadError::Kind::kNotOpen);
    CHECK(st.error().message.rfind(kCaDbErrorPrefix, 0) == 0);
    auto page = store.list_issued_filtered({.kind = CaIssuedFilter::Kind::kActive}, kAsOf, 10);
    REQUIRE_FALSE(page.has_value());
    CHECK(page.error().kind == CaReadError::Kind::kNotOpen);
}

TEST_CASE("CaStore: list_issued_filtered pages with a same-statement total and per-kind order",
          "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    // Five expiring within 30 days, at distinct expiries; inserted out of order.
    for (const int d : {9, 2, 25, 14, 5})
        REQUIRE(store.record_issued(fixed_issued("B" + std::to_string(d), kAsOf - kDay,
                                                 kAsOf + d * kDay)));
    using K = CaIssuedFilter::Kind;
    auto p1 = store.list_issued_filtered({.kind = K::kExpiring, .days = 30}, kAsOf, 2);
    REQUIRE(p1.has_value());
    CHECK(p1->total == 5);
    REQUIRE(p1->rows.size() == 2);
    CHECK(p1->rows[0].serial_hex == "B2"); // soonest expiry first
    CHECK(p1->rows[1].serial_hex == "B5");
    // The cursor is the last row served: (its not_after, its serial).
    REQUIRE(p1->next.has_value());
    CHECK(*p1->next == CaIssuedAfter{kAsOf + 5 * kDay, "B5"});
    auto p2 = store.list_issued_filtered({.kind = K::kExpiring, .days = 30}, kAsOf, 2, p1->next);
    REQUIRE(p2.has_value());
    REQUIRE(p2->rows.size() == 2);
    CHECK(p2->rows[0].serial_hex == "B9");
    CHECK(p2->rows[1].serial_hex == "B14");
    auto p3 = store.list_issued_filtered({.kind = K::kExpiring, .days = 30}, kAsOf, 2, p2->next);
    REQUIRE(p3.has_value());
    REQUIRE(p3->rows.size() == 1);
    CHECK(p3->rows[0].serial_hex == "B25");
    CHECK_FALSE(p3->next.has_value()); // end of the list: no cursor
    // A full last page has no cursor either (the look-ahead row is absent).
    auto exact = store.list_issued_filtered({.kind = K::kExpiring, .days = 30}, kAsOf, 5);
    REQUIRE(exact.has_value());
    CHECK(exact->rows.size() == 5);
    CHECK_FALSE(exact->next.has_value());
    // A cursor past the end still reports the total, with no rows.
    auto past = store.list_issued_filtered({.kind = K::kExpiring, .days = 30}, kAsOf, 2,
                                           CaIssuedAfter{kAsOf + 3000 * kDay, "FF"});
    REQUIRE(past.has_value());
    CHECK(past->total == 5);
    CHECK(past->rows.empty());
    CHECK_FALSE(past->next.has_value());
    // Newest-issued first for the active list.
    auto active = store.list_issued_filtered({.kind = K::kActive}, kAsOf, 10);
    REQUIRE(active.has_value());
    CHECK(active->total == 5);
}

TEST_CASE("CaStore: a revoke of a page-1 row between pages skips no row on page 2 (keyset)",
          "[ca_store][pg][stats]") {
    // H2 / the CH-7 extension: the active list's predicate is status-dependent, so revoking a
    // row already served removes it from the selection. An OFFSET page 2 would then start one
    // row later and silently skip a row; the keyset cursor resumes strictly after the last row
    // served, so every remaining row is listed exactly once.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    const int64_t now = now_s();
    // Six active certificates, issued one second apart (newest first: E5..E0), same not_after.
    for (int i = 0; i < 6; ++i)
        REQUIRE(store.record_issued(
            fixed_issued("E" + std::to_string(i), now - 600 + i, now + 400 * kDay)));
    using K = CaIssuedFilter::Kind;
    auto p1 = store.list_issued_filtered({.kind = K::kActive}, std::nullopt, 3);
    REQUIRE(p1.has_value());
    REQUIRE(p1->rows.size() == 3);
    CHECK(p1->rows[0].serial_hex == "E5");
    CHECK(p1->rows[2].serial_hex == "E3");
    REQUIRE(p1->next.has_value());
    // A concurrent revoke of a row page 1 already served.
    auto revoked = store.revoke("E4", "test");
    REQUIRE(revoked.has_value());
    REQUIRE(*revoked);
    auto p2 = store.list_issued_filtered({.kind = K::kActive}, p1->as_of, 3, p1->next);
    REQUIRE(p2.has_value());
    std::vector<std::string> got;
    for (const auto& r : p2->rows)
        got.push_back(r.serial_hex);
    CHECK(got == std::vector<std::string>{"E2", "E1", "E0"}); // nothing skipped
    CHECK_FALSE(p2->next.has_value());
    CHECK(p2->total == 5); // the total is the selection NOW (E4 is no longer active)
}

TEST_CASE("CaStore: a pinned as_of is bounded on the database clock",
          "[ca_store][pg][stats][negative]") {
    // M2: the window is measured against the DB's now(), read in the read's own transaction.
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    // The database clock, read the way the store reads it.
    int64_t db_now = 0;
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        PgResult clk{PQexec(lease.get(),
                            "SELECT floor(extract(epoch FROM date_trunc('second', now())))::bigint")};
        REQUIRE(clk.status() == PGRES_TUPLES_OK);
        db_now = std::strtoll(PQgetvalue(clk.get(), 0, 0), nullptr, 10);
    }
    const CaAsOfBounds bounds{7 * kDay, 300};
    using K = CaIssuedFilter::Kind;
    auto list_at = [&](int64_t as_of) {
        return store.list_issued_filtered({.kind = K::kActive}, as_of, 10, std::nullopt, bounds);
    };
    CHECK(list_at(db_now).has_value());
    CHECK(list_at(db_now - 7 * kDay + 60).has_value());
    auto ahead = list_at(db_now + 3600);
    REQUIRE_FALSE(ahead.has_value());
    CHECK(ahead.error().kind == CaReadError::Kind::kInvalidRequest);
    CHECK(ahead.error().message.find("as_of") != std::string::npos);
    CHECK(ahead.error().message.find("database clock") != std::string::npos);
    auto old = list_at(db_now - 8 * kDay);
    REQUIRE_FALSE(old.has_value());
    CHECK(old.error().kind == CaReadError::Kind::kInvalidRequest);
    CHECK(old.error().message.find("as_of") != std::string::npos);
    auto rq = stats_request(1, db_now + 3600);
    rq.as_of_bounds = bounds;
    auto st = store.issuance_stats(rq);
    REQUIRE_FALSE(st.has_value());
    CHECK(st.error().kind == CaReadError::Kind::kInvalidRequest);
    // Unbounded (nullopt) - the tests' fixed instants - is never refused on the clock.
    CHECK(store.list_issued_filtered({.kind = K::kActive}, db_now + 3600, 10).has_value());
}

TEST_CASE("CaStore: the aggregate reads leave revoked rows untouched", "[ca_store][pg][stats]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.record_issued(
        fixed_issued("C1", kAsOf - 10 * kDay, kAsOf + 10 * kDay, kAsOf - kDay)));
    REQUIRE(store.issuance_stats(stats_request(2)).has_value());
    REQUIRE(store.list_issued_filtered({.kind = CaIssuedFilter::Kind::kRevoked, .days = 7}, kAsOf,
                                       10)
                .has_value());
    CHECK(store.is_revoked("C1"));
    auto revoked = store.list_revoked_serials();
    REQUIRE(revoked.has_value());
    CHECK(*revoked == std::vector<std::string>{"C1"});
}
