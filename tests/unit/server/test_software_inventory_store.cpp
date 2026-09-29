// SoftwareInventoryStore tests (ADR-0016): the born-on-Postgres typed
// projection for the installed_software daily-sync source — canonical-hash
// cross-pin, hash-skip ingest (full/touched/need_full), atomic replace, fleet
// query, and the shared ingest seam (ingest_inventory_report) end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "inventory_ingestion.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::InventoryIngestOutcome;
using yuzu::server::SoftwareEntry;
using yuzu::server::SoftwareFleetQuery;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace agentpb = yuzu::agent::v1;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations. The two migration-backfill tests (v3 clamp,
// v5 '' backfill) stay on plain YUZU_REQUIRE_PG_DB — they need to stage a
// pre-migration schema by hand.
yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         SoftwareInventoryStore store{pool};
                                         // Throw, don't return: a silently-unmigrated template
                                         // would make every clone fall back to in-test migration —
                                         // correct but slow, defeating the point.
                                         // PgTestTemplate::build records the throw as a fixture
                                         // error.
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "swinv template: store failed to migrate");
                                     }};

// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test. Each
// per-test clone/pool opens several backends, and on Windows Postgres is
// EXEC_BACKEND (a fresh postgres.exe per connection) — the dominant [pg]-shard
// cost. Behaviour-preserving: identical store calls and CHECKs; only the DB
// provisioning/isolation substrate changes. Built lazily; at testRunEnded the
// pool is drained and the clone dropped (keep_until_run_end), leaving both
// function-local static destructors inert.
//
// CARVE-OUTS keep their own per-test database and are NOT converted: tests that
// DROP SCHEMA / rewind public.schema_meta / DROP COLUMN to force a degrade or
// re-migration would poison a shared DB for every later test (TRUNCATE cannot
// undo DDL, and schema_meta lives in `public`, surviving a schema drop). Those
// stay on YUZU_REQUIRE_PG_DB_TPL (clone) or YUZU_REQUIRE_PG_DB (fresh).
struct SwinvShared {
    yuzu::test::PostgresTestDb db{swinv_tpl};
    std::optional<PgPool> pool;
    SwinvShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
SwinvShared& swinv_shared() {
    static SwinvShared s;
    return s;
}

// Restore the shared DB to its fresh-clone state: TRUNCATE every data table and
// re-seed the catalog_rollup_meta singleton. Migration v4 seeds id=1 with
// refreshed_at=0 ("building"); a bare TRUNCATE would drop that row and break the
// pre-refresh reads (the catalogue tests), so re-insert it. public.schema_meta
// is deliberately untouched — the clone stays migrated, so the per-test store
// ctor finds the schema current and skips migration (a cheap SELECT, no new
// backend).
void swinv_reset() {
    auto lease = swinv_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc = pg::exec_params(
        lease.get(),
        "TRUNCATE software_inventory_store.installed_software, "
        "software_inventory_store.inventory_state, software_inventory_store.catalog_rollup, "
        "software_inventory_store.version_rollup, software_inventory_store.catalog_rollup_meta "
        "RESTART IDENTITY CASCADE",
        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
    auto seed =
        pg::exec_params(lease.get(),
                        "INSERT INTO software_inventory_store.catalog_rollup_meta "
                        "(id, refreshed_at, total_titles, total_devices) VALUES (1, 0, 0, 0) "
                        "ON CONFLICT (id) DO NOTHING",
                        std::vector<std::string>{});
    REQUIRE(seed.status() == PGRES_COMMAND_OK);
}

// Preamble for a convertible test: same skip contract as YUZU_REQUIRE_PG_DB_TPL,
// then TRUNCATE-reset the shared DB and bind `pool` (reference to the persistent
// pool) + `store` (fresh; the ctor's migration check is a no-op on the already-
// migrated clone, opening no new backend). `pool` is [[maybe_unused]] — most
// tests only touch `store`.
#define SWINV_SHARED(store, pool)                                                                  \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    swinv_reset();                                                                                 \
    [[maybe_unused]] PgPool& pool = *swinv_shared().pool;                                          \
    SoftwareInventoryStore store{pool};                                                            \
    REQUIRE(store.is_open())

// THE cross-side pin (ADR-0016 §4, blob contract v2 — 12 fields): the agent
// computes the SAME hash for the SAME input (see tests/unit/test_inventory_sync.cpp
// — identical constant). If the agent's and server's canonicalisation ever drift
// by one byte, one of the two assertions fails and the hash-skip optimisation is
// broken before it ships.
constexpr const char* kCrossPinHash =
    "430dc97e02b5d217276a9558393d702366bcd3b5415d5867c9efd4e95a02c848";

// v1-form wire blob for one entry (4 fields 0x1F-separated, entry terminated
// 0x1E). Post-v2 this doubles as the MIXED-VERSION fixture: a v1 agent's
// record must still parse (fields 5–12 default-empty) — see the compat test.
std::string blob1(const std::string& n, const std::string& v, const std::string& p,
                  const std::string& d) {
    return n + '\x1f' + v + '\x1f' + p + '\x1f' + d + '\x1e';
}

// Fully-populated v2 entry (every one of the 12 fields non-empty) for the
// round-trip / hash fixtures.
SoftwareEntry full_v2_entry() {
    SoftwareEntry e;
    e.name = "bash";
    e.version = "5.2.21";
    e.publisher = "Fedora Project";
    e.install_date = "Mon 01 Jan 2026";
    e.kind = "package";
    e.ecosystem = "rpm";
    e.epoch = "0";
    e.release = "3.fc40";
    e.arch = "x86_64";
    e.signature_status = "signed";
    e.distro_id = "fedora";
    e.distro_version = "40";
    return e;
}
} // namespace

TEST_CASE("SoftwareInventoryStore canonical_hash is the cross-pinned value",
          "[software_inventory][hash]") {
    // Deliberately unsorted + a duplicate, and one entry populating ALL 12 v2
    // fields: normalize() must sort + dedup to the same canonical bytes the
    // constant was computed from.
    std::vector<SoftwareEntry> e = {
        {"Zeta", "9", "", ""},
        full_v2_entry(),
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(SoftwareInventoryStore::canonical_hash(e) == kCrossPinHash);
}

TEST_CASE("SoftwareInventoryStore hash-skip ingest round-trip", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);

    std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                       {"Firefox", "120", "Mozilla", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);

    SECTION("full payload stores, reads back name-sorted, fleet-queryable") {
        CHECK(store.apply_installed_software("agent-a", h, rows, 1000) ==
              InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-a");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        CHECK((*got)[0].name == "Chrome");
        CHECK((*got)[1].name == "Firefox");

        SoftwareFleetQuery q;
        q.name = "Chrome";
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value());
        REQUIRE(fl->size() == 1);
        CHECK((*fl)[0].agent_id == "agent-a");
        CHECK((*fl)[0].entry.version == "119");
    }

    SECTION("hash-only matching the stored hash → touched, no row change") {
        REQUIRE(store.apply_installed_software("agent-b", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_installed_software("agent-b", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
        auto b = store.get_agent_software("agent-b");
        REQUIRE(b.has_value());
        CHECK(b->size() == 2);
    }

    SECTION("hash-only with no stored record (cold cache) → need_full") {
        CHECK(store.apply_installed_software("agent-cold", h, std::nullopt, 1000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("hash-only with a different hash (drift) → need_full") {
        REQUIRE(store.apply_installed_software("agent-c", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_installed_software("agent-c", "deadbeef", std::nullopt, 2000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("a changed full payload replaces the agent's rows atomically") {
        REQUIRE(store.apply_installed_software("agent-d", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        std::vector<SoftwareEntry> rows2 = {{"Chrome", "120", "Google", "2026-02-01"}};
        const std::string h2 = SoftwareInventoryStore::canonical_hash(rows2);
        REQUIRE(store.apply_installed_software("agent-d", h2, rows2, 3000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-d");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].version == "120");
    }
}

TEST_CASE("ingest_inventory_report drives the seam + fills need_full",
          "[pg][software_inventory][seam]") {
    SWINV_SHARED(store, pool);

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});

    SECTION("full payload (hash + blob) ingested, ack has no need_full") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-x", rep, ack);
        CHECK(ack.need_full_size() == 0);
        auto x = store.get_agent_software("agent-x");
        REQUIRE(x.has_value());
        CHECK(x->size() == 1);
    }

    SECTION("hash-only on a cold cache → ack.need_full lists the source") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h; // no blob
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-cold2", rep, ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "installed_software");
    }

    SECTION("unknown source key is ignored (slice 1 wires only installed_software)") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["something_else"] = h;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-y", rep, ack);
        CHECK(ack.need_full_size() == 0);
    }

    SECTION("an oversized blob is dropped, nacked, and stores no rows (UP-2/UP-4)") {
        // > 4 MiB per-source cap: the seam must NOT store it (false success) and
        // must nack so the agent resends rather than silently advancing.
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] =
            std::string(5u * 1024 * 1024, 'x'); // no separators → still over the cap
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-oversized", rep, ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "installed_software");
        // Store open + query OK + zero rows = an empty VALUE (a genuine "nothing"),
        // NOT nullopt (which is reserved for a degrade — ADR-0016 §7).
        auto os = store.get_agent_software("agent-oversized");
        REQUIRE(os.has_value());
        CHECK(os->empty());
    }
}

TEST_CASE("blob contract v2: 12-field entry round-trips through store and ingest seam",
          "[pg][software_inventory][v2]") {
    SWINV_SHARED(store, pool);

    const SoftwareEntry e = full_v2_entry();

    SECTION("store round-trip hydrates every v2 column on both read paths") {
        REQUIRE(store.apply_installed_software("agent-v2", "", std::vector<SoftwareEntry>{e},
                                               1000) == InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-v2");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        const auto& g = (*got)[0];
        CHECK(g.kind == "package");
        CHECK(g.ecosystem == "rpm");
        CHECK(g.epoch == "0");
        CHECK(g.release == "3.fc40");
        CHECK(g.arch == "x86_64");
        CHECK(g.signature_status == "signed");
        CHECK(g.distro_id == "fedora");
        CHECK(g.distro_version == "40");

        SoftwareFleetQuery q;
        q.name = "bash";
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value());
        REQUIRE(fl->size() == 1);
        CHECK((*fl)[0].entry.ecosystem == "rpm");
        CHECK((*fl)[0].entry.distro_version == "40");
    }

    SECTION("v2 wire blob (12 fields) through the ingest seam") {
        const std::string rec = e.name + '\x1f' + e.version + '\x1f' + e.publisher + '\x1f' +
                                e.install_date + '\x1f' + e.kind + '\x1f' + e.ecosystem + '\x1f' +
                                e.epoch + '\x1f' + e.release + '\x1f' + e.arch + '\x1f' +
                                e.signature_status + '\x1f' + e.distro_id + '\x1f' +
                                e.distro_version + '\x1e';
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] =
            SoftwareInventoryStore::canonical_hash({e});
        (*rep.mutable_plugin_data())["installed_software"] = rec;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-v2-wire", rep, ack);
        CHECK(ack.need_full_size() == 0);
        auto got = store.get_agent_software("agent-v2-wire");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].signature_status == "signed");
        CHECK((*got)[0].ecosystem == "rpm");
    }
}

TEST_CASE("blob contract v2: a v1 4-field blob still ingests — fields 5-12 empty (mixed-version)",
          "[pg][software_inventory][v2]") {
    // The CHOSEN mixed-version behaviour, pinned so it stays a property, not an
    // accident: an old agent's 4-field records parse with the 8 v2 fields
    // default-empty, store cleanly, and the server hash is the v2-form recomputed
    // over those empties (so the OLD agent's v1 claimed hash will keep
    // mismatching → the documented bounded ~2-RPC/day loop until agent upgrade,
    // never an error loop, never corruption).
    SWINV_SHARED(store, pool);

    const std::string v1_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = v1_hash;
    (*rep.mutable_plugin_data())["installed_software"] =
        blob1("Chrome", "119", "Google", "2026-01-01");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-v1-compat", rep, ack);
    CHECK(ack.need_full_size() == 0); // full payload stores regardless of claimed hash

    auto got = store.get_agent_software("agent-v1-compat");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    const auto& g = (*got)[0];
    CHECK(g.name == "Chrome");
    CHECK(g.version == "119");
    CHECK(g.kind.empty());
    CHECK(g.ecosystem.empty());
    CHECK(g.epoch.empty());
    CHECK(g.release.empty());
    CHECK(g.arch.empty());
    CHECK(g.signature_status.empty());
    CHECK(g.distro_id.empty());
    CHECK(g.distro_version.empty());

    // The stored hash is the v2-form recompute (12-field canon over the parsed
    // rows), NOT the agent's v1 claim: a follow-up hash-only report with the v1
    // claim must nack need_full.
    agentpb::InventoryReport rep2;
    (*rep2.mutable_content_hashes())["installed_software"] = v1_hash;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-v1-compat", rep2, ack2);
    REQUIRE(ack2.need_full_size() == 1);
    CHECK(ack2.need_full(0) == "installed_software");

    // And a hash-only claiming the v2-form recompute is accepted (touched).
    SoftwareEntry expect;
    expect.name = "Chrome";
    expect.version = "119";
    expect.publisher = "Google";
    expect.install_date = "2026-01-01";
    agentpb::InventoryReport rep3;
    (*rep3.mutable_content_hashes())["installed_software"] =
        SoftwareInventoryStore::canonical_hash({expect});
    agentpb::InventoryAck ack3;
    yuzu::server::ingest_inventory_report(store, "agent-v1-compat", rep3, ack3);
    CHECK(ack3.need_full_size() == 0);
}

TEST_CASE("migration v5 backfills '' into v2 columns for pre-existing rows and re-runs "
          "idempotently",
          "[pg][software_inventory][v2]") {
    // Upgrade semantics on a live table: rows written before v5 must read back
    // with '' in every v2 column (the ADD COLUMN ... DEFAULT '' guarantee), and
    // re-running v5 over an already-migrated table (schema_meta rewind, the
    // partial-migration retry case) must succeed (IF NOT EXISTS, v4 precedent).
    //
    // To genuinely reproduce a v4-era table (not just an omitted-column INSERT
    // into an already-v5 table, which would pass for the wrong reason — ordinary
    // SQL column-default semantics, not migration backfill), this DROPs the 8
    // v2 columns after the first construction, seeds the row into that
    // genuinely-4-column table, then rewinds schema_meta and reconstructs so v5
    // re-adds the columns over live pre-existing data.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    { // first construction applies v1..v5
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    { // revert to a genuine v4 shape: drop the 8 v2 columns, seed a legacy row,
      // rewind the recorded version to 4
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(),
                            "ALTER TABLE software_inventory_store.installed_software "
                            "DROP COLUMN kind, DROP COLUMN ecosystem, DROP COLUMN epoch, "
                            "DROP COLUMN release, DROP COLUMN arch, DROP COLUMN signature_status, "
                            "DROP COLUMN distro_id, DROP COLUMN distro_version",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
        pg::PgResult ins =
            pg::exec_params(lease.get(),
                            "INSERT INTO software_inventory_store.installed_software "
                            "(agent_id, name, version, publisher, install_date) "
                            "VALUES ('agent-legacy', 'OldApp', '1.0', 'OldCo', '2025-01-01')",
                            std::vector<std::string>{});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
        pg::PgResult back = pg::exec_params(
            lease.get(),
            "UPDATE public.schema_meta SET version = 4 WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(back.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore store{pool}; // re-runs v5, ADD COLUMN over the live row
    REQUIRE(store.is_open());

    auto got = store.get_agent_software("agent-legacy");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].name == "OldApp");
    CHECK((*got)[0].kind.empty());
    CHECK((*got)[0].ecosystem.empty());
    CHECK((*got)[0].signature_status.empty());
    CHECK((*got)[0].distro_version.empty());
}

TEST_CASE("ingest boundary-truncates an over-long multibyte field so PG accepts it (UP-10)",
          "[pg][software_inventory][seam][pg-smoke]") {
    // Regression for the UTF-8 byte-cut: a raw field whose multibyte codepoint
    // straddles the 1024-byte cap must be truncated on the codepoint boundary, NOT
    // mid-sequence — otherwise the INSERT into the UTF8 TEXT column is rejected by
    // PostgreSQL (22021) → kError → need_full, never storing. The row must STORE.
    SWINV_SHARED(store, pool);

    // name = 1023 'a' + 'é' (0xC3 0xA9) = 1025 bytes; record = name|1|| (0x1F fields,
    // 0x1E terminator; octal \037=0x1F \036=0x1E to avoid greedy \x hex escapes).
    std::string longname = std::string(1023, 'a') + "\xc3\xa9";
    std::string blob = longname + "\0371\037\037\036";
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = "x"; // recomputed on a full payload
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-utf8", rep, ack);
    CHECK(ack.need_full_size() == 0); // STORED, not kError-nacked (PG accepted valid UTF-8)
    auto rows = store.get_agent_software("agent-utf8");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == std::string(1023, 'a')); // boundary-truncated, valid UTF-8
}

TEST_CASE(
    "ingest scrubs invalid UTF-8 to U+FFFD so PG accepts it + hash matches the agent (UP-IN1)",
    "[pg][software_inventory][seam]") {
    // A non-conforming agent (or a future SyncSource that does not pre-scrub) sends a
    // RAW cp1252 byte 0xE9 ("Café" = 43 61 66 E9) in the name. PG's UTF8 TEXT column
    // would reject it (22021) → kError → permanent resend (UP-IN1). The seam must
    // replace it with U+FFFD (EF BF BD) IDENTICALLY to the agent's clamp_field, so the
    // row STORES and the server-recomputed hash equals what the real agent (which
    // scrubs before hashing) would have sent.
    SWINV_SHARED(store, pool);

    // The hash the agent would compute AFTER its own identical scrub of 0xE9.
    const std::string agent_hash = SoftwareInventoryStore::canonical_hash(
        {{std::string("Caf\xef\xbf\xbd"), "1", "Acme", "2020"}});

    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = agent_hash;
    (*rep.mutable_plugin_data())["installed_software"] = blob1("Caf\xe9", "1", "Acme", "2020");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-utf8-scrub", rep, ack);
    CHECK(ack.need_full_size() == 0); // STORED, not 22021-rejected → kError-nacked

    auto rows = store.get_agent_software("agent-utf8-scrub");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == std::string("Caf\xef\xbf\xbd")); // raw 0xE9 scrubbed to U+FFFD
    CHECK((*rows)[0].name.find('\xe9') == std::string::npos);

    // Cross-pin: a hash-only follow-up carrying the agent's hash → touched (no
    // need_full) proves the server-recomputed stored hash equals the agent's, i.e.
    // the two scrubs are byte-coordinated.
    agentpb::InventoryReport rep2;
    (*rep2.mutable_content_hashes())["installed_software"] = agent_hash; // no blob
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-utf8-scrub", rep2, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("ingest scrub: PG-strict edge-branch parity vector (UP-IN1 drift guard)",
          "[pg][software_inventory][seam]") {
    // These two literals are duplicated VERBATIM from the agent suite
    // (test_inventory_sync.cpp kScrubVectorRaw/kScrubVectorExpected). The agent's
    // clamp_field and the server's parse_software_blob MUST scrub identically or the
    // canonical hashes diverge → permanent always-full. Editing one scrub copy without
    // the other fails one of these two tests (gov Gate-8 drift guard).
    const std::string raw = std::string("X") + "\xc0\x80" + "\xed\xa0\x80" + "\xf4\x90\x80\x80" +
                            "\xc3\xa9" + "\xf0\x9f\x98\x80" + "\xf5";
    const std::string expected = std::string("X") + "\xef\xbf\xbd\xef\xbf\xbd" +
                                 "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +
                                 "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" + "\xc3\xa9" +
                                 "\xf0\x9f\x98\x80" + "\xef\xbf\xbd";

    SWINV_SHARED(store, pool);

    // The hash the agent would compute after its identical scrub.
    const std::string agent_hash =
        SoftwareInventoryStore::canonical_hash({{expected, "1", "p", "d"}});
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = agent_hash;
    (*rep.mutable_plugin_data())["installed_software"] = blob1(raw, "1", "p", "d");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-scrub-vec", rep, ack);
    CHECK(ack.need_full_size() == 0); // PG accepted the scrubbed valid UTF-8

    auto rows = store.get_agent_software("agent-scrub-vec");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == expected); // server scrub == agent scrub, byte-for-byte
}

TEST_CASE("ingest_inventory_report nacks need_full when the store ERRORS (UP-2 kError path)",
          "[pg][software_inventory][seam]") {
    // The UP-2 hardening: when apply_installed_software returns kError (a transient
    // store failure, NOT a cold cache), the seam must nack need_full so the agent
    // resends rather than silently advancing past un-stored data. Every other seam
    // test hits kStored/kTouched/kNeedFull/dropped; this is the only one that drives
    // the kError branch (QE Gate-8 coverage gap). Induced by dropping the store's
    // schema out from under an open store so the full-payload transaction's first
    // statement fails (kError, returned not thrown — verified in the store).
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = h;
    (*rep.mutable_plugin_data())["installed_software"] = blob; // FULL payload → exercises apply
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-err", rep, ack);
    REQUIRE(ack.need_full_size() == 1);
    CHECK(ack.need_full(0) == "installed_software");
}

TEST_CASE("reads are AUTHORITATIVE: a degrade returns nullopt, distinct from a true empty "
          "(ADR-0016 §7 / fjarvis HIGH)",
          "[pg][software_inventory]") {
    // The frozen ADR-0016 §7 contract: a read surfaces a store/pool/query failure as
    // nullopt, NEVER a silent empty — else a fleet vuln query reads a transient PG
    // failure as "installed nowhere" (the fail-open A4 violation fjarvis blocked on).
    // A genuine zero-row read stays an empty VALUE.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("a genuine zero-row read is an empty VALUE, not nullopt") {
        SoftwareFleetQuery q;
        q.name = "No Such Package";
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value()); // not a degrade
        CHECK(fl->empty());      // genuinely nothing installed
        auto one = store.get_agent_software("no-such-agent");
        REQUIRE(one.has_value());
        CHECK(one->empty());
    }

    SECTION("a backend failure (schema dropped) returns nullopt, not a silent empty") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult drop =
                pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                std::vector<std::string>{});
            REQUIRE(drop.status() == PGRES_COMMAND_OK);
        }
        SoftwareFleetQuery q;
        q.name = "Chrome";
        CHECK_FALSE(store.query_software(q).has_value());             // degraded → nullopt
        CHECK_FALSE(store.get_agent_software("agent-a").has_value()); // not a silent empty
    }
}

TEST_CASE("ingest rejects a report carrying too many sources (map-cardinality cap)",
          "[pg][software_inventory][seam]") {
    // Defense-in-depth (fjarvis LOW): the framework wires a small fixed number of
    // sources; an implausibly large content_hashes/plugin_data map is malformed or
    // abusive and the whole report is rejected (no per-source processing, no rows).
    SWINV_SHARED(store, pool);

    SECTION("content_hashes map over cap → rejected") {
        agentpb::InventoryReport rep;
        for (int i = 0; i < 100; ++i) // > kMaxSources (64)
            (*rep.mutable_content_hashes())["src-" + std::to_string(i)] = "h";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-flood", rep, ack);
        CHECK(ack.need_full_size() == 0); // whole report dropped, no per-source nack
        auto rows = store.get_agent_software("agent-flood");
        REQUIRE(rows.has_value());
        CHECK(rows->empty()); // nothing ingested
    }

    SECTION("plugin_data map over cap → rejected (the OR's right arm)") {
        agentpb::InventoryReport rep;
        for (int i = 0; i < 100; ++i)
            (*rep.mutable_plugin_data())["src-" + std::to_string(i)] = "blob";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-flood2", rep, ack);
        CHECK(ack.need_full_size() == 0);
        auto rows = store.get_agent_software("agent-flood2");
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("batched insert round-trips a large set, array metacharacters, and empty (#1664)",
          "[pg][software_inventory]") {
    // The per-row INSERT loop is now one `unnest($N::text[])` statement. These
    // exercise it against a real backend: bulk correctness, the text[] literal
    // escaping (to_text_array — unit-tested in test_pg_array.cpp, end-to-end
    // here), and the empty-entries skip.
    SWINV_SHARED(store, pool);

    SECTION("the documented max (kMaxEntries) inserts via one unnest() and reads back complete") {
        // 20 000 rows — the kMaxEntries cap, i.e. the largest payload the ingest
        // accepts. A multi-row VALUES would exceed libpq's 65535-param ceiling
        // here (5 params/row); the unnest path binds a constant 5 params.
        constexpr int kRows = 20000;
        std::vector<SoftwareEntry> rows;
        rows.reserve(kRows);
        for (int i = 0; i < kRows; ++i)
            rows.push_back({"pkg-" + std::to_string(i), std::to_string(i), "Pub", "2026-01-01"});
        const std::string h = SoftwareInventoryStore::canonical_hash(rows);
        REQUIRE(store.apply_installed_software("agent-big", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-big");
        REQUIRE(got.has_value());
        CHECK(got->size() == kRows);
    }

    SECTION("array metacharacters in name/publisher survive the text[] literal round-trip") {
        // Comma, double-quote, backslash, and braces are exactly the bytes
        // to_text_array escapes; a regression would corrupt or 22P02-reject the
        // whole batch. Verified via the exact-name fleet query (collation-stable).
        const std::string meta = "a,b\"c\\d{e}";
        std::vector<SoftwareEntry> rows = {{meta, "1", "Vendor, Inc.", ""}, {"Plain", "2", "", ""}};
        const std::string h = SoftwareInventoryStore::canonical_hash(rows);
        REQUIRE(store.apply_installed_software("agent-meta", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        SoftwareFleetQuery q;
        q.name = meta;
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value());
        REQUIRE(fl->size() == 1);
        CHECK((*fl)[0].agent_id == "agent-meta");
        CHECK((*fl)[0].entry.name == meta); // exact round-trip, not just queryable
        CHECK((*fl)[0].entry.publisher == "Vendor, Inc.");
    }

    SECTION("a full payload with zero entries stores nothing and is a clean empty") {
        std::vector<SoftwareEntry> none;
        const std::string h = SoftwareInventoryStore::canonical_hash(none);
        REQUIRE(store.apply_installed_software("agent-empty", h, none, 1000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-empty");
        REQUIRE(got.has_value());
        CHECK(got->empty());
        // Hash-only follow-up with the same (empty) hash → touched proves the
        // parent row + the empty content_hash persisted.
        CHECK(store.apply_installed_software("agent-empty", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
    }
}

TEST_CASE("read-degrade bumps yuzu_inventory_read_degrade_total by reason (#1675)",
          "[pg][software_inventory]") {
    // The authoritative-read degrade is dashboard-invisible (/readyz stays green
    // under pure saturation), so the counter is the only signal. Dropping the
    // schema under the open store forces a query_error on both reads.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    SoftwareFleetQuery q;
    q.name = "Chrome";
    CHECK_FALSE(store.query_software(q).has_value()); // degraded → nullopt
    CHECK_FALSE(store.get_agent_software("agent-a").has_value());
    CHECK(metrics
              .counter("yuzu_inventory_read_degrade_total",
                       {{"reason", "query_error"}, {"source", "installed_software"}})
              .value() == 2.0);
}

TEST_CASE("count_stale_agents keys on server receipt time, immune to agent collected_at skew "
          "(#1685)",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);

    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    std::vector<SoftwareEntry> rows = {{"Chrome", "1", "", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);

    // A future-skewed (or hostile) agent supplies collected_at far ahead of now.
    // Pre-fix this stamped last_seen into the future, so the agent could go dark
    // and never satisfy `last_seen < cutoff` — hidden from the freshness gauge
    // forever (#1685). Post-fix last_seen is the SERVER receipt time (~now), so the
    // skew is ignored. collected_at is otherwise unobservable from the store, so
    // the gauge is the only lever to assert through.
    const std::int64_t far_future = now + 100'000'000; // ~3 years ahead
    REQUIRE(store.apply_installed_software("agent-skew", h, rows, far_future) ==
            InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("agent-honest", h, rows, now) ==
            InventoryIngestOutcome::kStored);

    // Against a past cutoff neither is stale (both last_seen ≈ now).
    auto fresh = store.count_stale_agents(now - 1'000);
    REQUIRE(fresh.has_value());
    CHECK(*fresh == 0);

    // Against a future cutoff BOTH count — proving agent-skew's last_seen sits at
    // ~now, NOT the far-future collected_at it supplied. Pre-fix this would be 1
    // (the skewed agent hidden above the cutoff); the fix makes it 2.
    auto all_stale = store.count_stale_agents(now + 50'000'000);
    REQUIRE(all_stale.has_value());
    CHECK(*all_stale == 2);

    // Partial-count coverage (preserved from the prior collected_at-based test):
    // backdate one agent's SERVER last_seen 10 days — there is no clock seam, so go
    // direct — and confirm only it falls outside the real 2-day window.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto upd = pg::exec_params(
            lease.get(),
            "UPDATE software_inventory_store.inventory_state SET last_seen = $2::bigint "
            "WHERE agent_id = $1",
            std::vector<std::string>{"agent-honest", std::to_string(now - 10 * 86'400)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }
    auto window = store.count_stale_agents(now - 2 * 86'400);
    REQUIRE(window.has_value());
    CHECK(*window == 1); // only the backdated agent-honest; agent-skew is fresh (~now)
}

TEST_CASE("ingest_inventory_report records the ingest-duration histogram by phase (#1664)",
          "[pg][software_inventory][seam]") {
    // Drives the seam with a LIVE registry (the other seam tests pass nullptr) and
    // asserts the histogram fires once per phase: a full payload → phase=full, a
    // hash-only follow-up → phase=hash_only.
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});

    {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] = blob; // full payload
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-hist", rep, ack, &metrics);
    }
    {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h; // hash-only (no blob)
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-hist", rep, ack, &metrics);
    }

    auto full = metrics
                    .histogram("yuzu_inventory_ingest_duration_seconds",
                               {{"source", "installed_software"}, {"phase", "full"}})
                    .snapshot();
    auto hash_only = metrics
                         .histogram("yuzu_inventory_ingest_duration_seconds",
                                    {{"source", "installed_software"}, {"phase", "hash_only"}})
                         .snapshot();
    CHECK(full.count == 1);
    CHECK(hash_only.count == 1);
}

TEST_CASE("read-degrade store_not_open reason fires when the store failed to open (#1675)",
          "[pg][software_inventory]") {
    // The store_not_open degrade reason (the other testable degrade besides
    // query_error). Force open_=false by wiping the version record after a normal
    // open so a second construction re-runs the v1 DDL against the already-existing
    // tables → migration fails → !is_open(). Then both authoritative reads must
    // bump the store_not_open counter.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    { // first construction creates the schema, tables, and the schema_meta row
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    { // wipe the applied-version record so the runner re-applies v1 over live tables
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult del = pg::exec_params(
            lease.get(), "DELETE FROM public.schema_meta WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(del.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore store{pool};
    REQUIRE_FALSE(store.is_open()); // migration re-run failed → store_not_open
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    SoftwareFleetQuery q;
    q.name = "Chrome";
    CHECK_FALSE(store.query_software(q).has_value());
    CHECK_FALSE(store.get_agent_software("agent-a").has_value());
    CHECK(metrics
              .counter("yuzu_inventory_read_degrade_total",
                       {{"reason", "store_not_open"}, {"source", "installed_software"}})
              .value() == 2.0);
}

TEST_CASE("migration v3 backfill clamps pre-fix future last_seen/first_seen at re-open "
          "(#1685 / governance UP-10)",
          "[pg][software_inventory]") {
    // The forward write fix can't re-stamp a dark agent, so v3 must clamp rows that
    // were ALREADY persisted with a future-skewed timestamp. Reproduce a pre-fix
    // row, roll the recorded schema version back to 2 so a fresh construction
    // re-runs ONLY v3 (a DML, re-run-safe), and prove the clamp moved it back into
    // the freshness window.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t far_future = now + 100'000'000;
    { // first construction creates schema + tables + schema_meta @ v3 (v3 no-ops on empty)
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    { // seed a pre-fix future-skewed row, then roll the recorded version back to 2
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult ins = pg::exec_params(
            lease.get(),
            "INSERT INTO software_inventory_store.inventory_state "
            "(agent_id, source, content_hash, first_seen, last_seen) "
            "VALUES ('agent-future', 'installed_software', 'deadbeef', $1::bigint, $1::bigint)",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
        pg::PgResult back = pg::exec_params(
            lease.get(),
            "UPDATE public.schema_meta SET version = 2 WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(back.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore store{pool}; // re-runs v3 → clamps the future row
    REQUIRE(store.is_open());

    // Discriminator: against a cutoff between now and far_future, the CLAMPED row
    // (last_seen ≈ now) counts stale; an un-clamped row (last_seen = far_future)
    // would sit above the cutoff and count 0.
    auto stale = store.count_stale_agents(now + 50'000'000);
    REQUIRE(stale.has_value());
    CHECK(*stale == 1);

    // first_seen is clamped too (UP-10) — assert it is no longer in the future.
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult sel =
            pg::exec_params(lease.get(),
                            "SELECT first_seen FROM software_inventory_store.inventory_state "
                            "WHERE agent_id = 'agent-future'",
                            std::vector<std::string>{});
        REQUIRE(sel.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(sel.get()) == 1);
        const std::int64_t first_seen = std::stoll(PQgetvalue(sel.get(), 0, 0));
        CHECK(first_seen <= now + 5); // clamped to ~now (small margin for a clock tick)
    }
}

TEST_CASE("read-degrade sampler is data-race-free under concurrent degraded reads "
          "(#1686 DegradeSampler — TSan guard)",
          "[pg][software_inventory]") {
    // The episode WARN sampler's DegradeSampler uses two std::atomics. A regression
    // dropping the atomics would be a data race invisible to a single-threaded test
    // but flagged by ThreadSanitizer here. Drop the schema so every read degrades via
    // the query_error path, then hammer it from many threads. NB: no Catch2 assertion
    // runs INSIDE the threads (Catch2's macros aren't thread-safe — that would flag
    // Catch2, not our code); all assertions run after join on the exact counter.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    constexpr int kThreads = 8;
    constexpr int kPerThread = 50;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                SoftwareFleetQuery q;
                q.name = "Chrome";
                (void)store.query_software(q);             // → query_error degrade
                (void)store.get_agent_software("agent-x"); // → query_error degrade
            }
        });
    }
    for (auto& th : threads)
        th.join();
    // The counter is exact regardless of WARN sampling: every degraded read bumped it
    // exactly once, two reads per iteration.
    const double total = metrics
                             .counter("yuzu_inventory_read_degrade_total",
                                      {{"reason", "query_error"}, {"source", "installed_software"}})
                             .value();
    CHECK(total == static_cast<double>(kThreads * kPerThread * 2));
}

TEST_CASE("count_stale_agents returns nullopt on a backend degrade (freeze-counter trigger)",
          "[pg][software_inventory]") {
    // The server gauge sweep bumps yuzu_inventory_stale_count_unavailable_total in
    // the else-branch of `if (auto stale = count_stale_agents(...))`. Prove the
    // store method returns nullopt (not a false 0) when the backend is unavailable,
    // so the gauge holds its prior value and the freeze counter fires.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    CHECK_FALSE(store.count_stale_agents(1'000'000).has_value()); // degrade → nullopt, never 0
}

TEST_CASE("delete_agent removes both the child rows and the parent state row",
          "[pg][software_inventory]") {
    // delete_agent deletes from installed_software AND inventory_state in one txn.
    // Verify both halves: the child rows are gone (get returns an empty VALUE, not
    // nullopt) AND the parent state row is gone (a hash-only follow-up sees a cold
    // cache → kNeedFull, not kTouched on a stale parent).
    SWINV_SHARED(store, pool);

    std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                       {"Firefox", "120", "Mozilla", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software("agent-del", h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
    // A bystander agent that must SURVIVE the delete — without this, a DELETE
    // missing its `WHERE agent_id=$1` (a whole-table wipe) would pass every other
    // assertion here. This is the minimal proof the delete is agent-scoped.
    std::vector<SoftwareEntry> by_rows = {{"Edge", "120", "Microsoft", ""}};
    const std::string by_h = SoftwareInventoryStore::canonical_hash(by_rows);
    REQUIRE(store.apply_installed_software("agent-bystander", by_h, by_rows, 1000) ==
            InventoryIngestOutcome::kStored);
    {
        auto pre = store.get_agent_software("agent-del");
        REQUIRE(pre.has_value());
        REQUIRE(pre->size() == 2);
    }

    CHECK(store.delete_agent("agent-del")); // committed → true

    auto post = store.get_agent_software("agent-del");
    REQUIRE(post.has_value()); // store still open + query OK → empty VALUE, not a degrade
    CHECK(post->empty());      // child rows gone
    // Parent state row gone: a hash-only report now hits a cold cache.
    CHECK(store.apply_installed_software("agent-del", h, std::nullopt, 2000) ==
          InventoryIngestOutcome::kNeedFull);

    // Cross-agent isolation: the bystander's child rows AND parent state row are
    // untouched (its hash-only follow-up still matches → kTouched, not kNeedFull).
    auto bystander = store.get_agent_software("agent-bystander");
    REQUIRE(bystander.has_value());
    REQUIRE(bystander->size() == 1);
    CHECK((*bystander)[0].name == "Edge");
    CHECK(store.apply_installed_software("agent-bystander", by_h, std::nullopt, 2000) ==
          InventoryIngestOutcome::kTouched);

    // A delete of an unknown agent is a no-op (best-effort), not a throw or a
    // degrade — a 0-row DELETE still commits, so it reports success.
    CHECK(store.delete_agent("agent-never-existed"));
    auto other = store.get_agent_software("agent-never-existed");
    REQUIRE(other.has_value());
    CHECK(other->empty());
}

TEST_CASE("SoftwareInventoryStore catalogue + version aggregates", "[pg][software_inventory]") {
    // Gov F1: the /inventory dashboard's fleet aggregates (software_catalog /
    // software_versions) had no store-level coverage — the GROUP BY SQL, the
    // most-installed ordering, the name filter, and the cap were stubbed at the route.
    SWINV_SHARED(store, pool);

    // 3 devices: Google Chrome on all 3 (versions 126 ×2, 125 ×1); 7-Zip on 1.
    using Rows = std::vector<SoftwareEntry>;
    REQUIRE(store.apply_installed_software(
                "cat-a1", "",
                Rows{{"Google Chrome", "126", "Google", ""}, {"7-Zip", "24", "Igor", ""}},
                1) == InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("cat-a2", "",
                                           Rows{{"Google Chrome", "126", "Google", ""}},
                                           1) == InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("cat-a3", "",
                                           Rows{{"Google Chrome", "125", "Google", ""}},
                                           1) == InventoryIngestOutcome::kStored);

    // The catalogue/version reads are served from the PRECOMPUTED rollup — recompute it
    // from the just-seeded rows before asserting.
    REQUIRE(store.refresh_catalog_rollup());

    SECTION("catalog_rollup_meta carries the freshness stamp + headline counts") {
        auto meta = store.catalog_rollup_meta();
        REQUIRE(meta.has_value());
        CHECK(meta->refreshed_at > 0);  // refreshed → not the "building" sentinel
        CHECK(meta->total_titles == 2); // Google Chrome + 7-Zip
        CHECK(meta->total_devices == 3);
    }

    SECTION("catalogue rolls up device_count + version_count, most-installed first") {
        auto cat = store.software_catalog({});
        REQUIRE(cat.has_value());
        REQUIRE_FALSE(cat->empty());
        CHECK((*cat)[0].name == "Google Chrome"); // 3 devices → sorts first
        CHECK((*cat)[0].device_count == 3);
        CHECK((*cat)[0].version_count == 2);
        bool found_7z = false;
        for (const auto& r : *cat)
            if (r.name == "7-Zip") {
                found_7z = true;
                CHECK(r.device_count == 1);
                CHECK(r.version_count == 1);
            }
        CHECK(found_7z);
    }
    SECTION("name_filter is a case-insensitive substring") {
        yuzu::server::SoftwareCatalogQuery q;
        q.name_filter = "chrome";
        auto cat = store.software_catalog(q);
        REQUIRE(cat.has_value());
        REQUIRE(cat->size() == 1);
        CHECK((*cat)[0].name == "Google Chrome");
    }
    SECTION("name_filter matches on PUBLISHER alone, not just the title (round-3 item 8)") {
        // The store's ILIKE OR spans title AND publisher, one bound param reused in
        // both arms (software_inventory_store.cpp's software_catalog) — a
        // publisher-only substring ("adobe" surfacing every Adobe title) must
        // return every title from that publisher, even when neither title itself
        // contains the substring.
        REQUIRE(store.apply_installed_software(
                    "pub-a1", "", Rows{{"Widget One", "1.0", "Zylofex Systems", ""}}, 1) ==
                InventoryIngestOutcome::kStored);
        REQUIRE(store.apply_installed_software(
                    "pub-a2", "", Rows{{"Widget Two", "2.0", "Zylofex Systems", ""}}, 1) ==
                InventoryIngestOutcome::kStored);
        REQUIRE(store.refresh_catalog_rollup());

        yuzu::server::SoftwareCatalogQuery q;
        q.name_filter = "zylofex"; // substring of the publisher only
        auto cat = store.software_catalog(q);
        REQUIRE(cat.has_value());
        bool found_one = false, found_two = false;
        for (const auto& r : *cat) {
            if (r.name == "Widget One")
                found_one = true;
            if (r.name == "Widget Two")
                found_two = true;
        }
        CHECK(found_one);
        CHECK(found_two);
        // Neither Chrome nor 7-Zip (the outer seed) match "zylofex" — the filter
        // narrows, it does not fall back to matching everything.
        CHECK(cat->size() == 2);
    }
    SECTION("limit caps the returned rows to the most-installed") {
        yuzu::server::SoftwareCatalogQuery q;
        q.limit = 1;
        auto cat = store.software_catalog(q);
        REQUIRE(cat.has_value());
        CHECK(cat->size() == 1);
        CHECK((*cat)[0].name == "Google Chrome");
    }
    SECTION("software_versions = installs per version, most-installed first") {
        auto v = store.software_versions("Google Chrome", 100);
        REQUIRE(v.has_value());
        REQUIRE(v->size() == 2);
        CHECK((*v)[0].version == "126");
        CHECK((*v)[0].device_count == 2);
        CHECK((*v)[1].version == "125");
        CHECK((*v)[1].device_count == 1);
    }
    SECTION("software_versions empty name → empty value (precondition miss, not degrade)") {
        auto v = store.software_versions("", 100);
        REQUIRE(v.has_value());
        CHECK(v->empty());
    }
    SECTION("software_versions unknown title → empty value, not degrade") {
        auto v = store.software_versions("Nonexistent App", 100);
        REQUIRE(v.has_value());
        CHECK(v->empty());
    }
}

TEST_CASE("SoftwareInventoryStore catalogue rollup is empty + 'building' before first refresh",
          "[pg][software_inventory]") {
    // Before any refresh_catalog_rollup(), the rollup tables are empty and the seeded meta
    // row reports refreshed_at==0 ("building") — distinct from a refreshed-but-empty fleet.
    // This is the state the dashboard shows as "catalogue building", not a false empty.
    SWINV_SHARED(store, pool);

    REQUIRE(store.apply_installed_software(
                "pre-a1", "", std::vector<SoftwareEntry>{{"Google Chrome", "126", "Google", ""}},
                1) == InventoryIngestOutcome::kStored);

    // No refresh yet: meta is the building sentinel, reads are empty (NOT degraded/nullopt).
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at == 0);
    auto cat = store.software_catalog({});
    REQUIRE(cat.has_value());
    CHECK(cat->empty());

    // After a refresh the seeded row appears and the stamp advances.
    REQUIRE(store.refresh_catalog_rollup());
    auto meta2 = store.catalog_rollup_meta();
    REQUIRE(meta2.has_value());
    CHECK(meta2->refreshed_at > 0);
    auto cat2 = store.software_catalog({});
    REQUIRE(cat2.has_value());
    REQUIRE(cat2->size() == 1);
    CHECK((*cat2)[0].name == "Google Chrome");
}

TEST_CASE("SoftwareInventoryStore rollup tables carry the multi-instance unique constraints",
          "[pg][software_inventory]") {
    // Regression guard for the ARCH-1 BLOCKING fix (gov Gate-8 architect SHOULD). The
    // UNIQUE constraints are the backstop that makes a racing duplicate INSERT fail; a
    // future migration refactor that drops one would silently reopen the multi-instance
    // duplicate-row bug. Assert both exist so that regression fails loudly here.
    SWINV_SHARED(store, pool);

    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT count(*) FROM pg_constraint "
        "WHERE conname IN ('catalog_rollup_name_key', 'version_rollup_nv_key') AND contype = 'u'",
        std::vector<std::string>{});
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    CHECK(std::string(PQgetvalue(res.get(), 0, 0)) == "2");
}

TEST_CASE("refresh_catalog_rollup skips (success, no recompute) when a peer holds the lock",
          "[pg][software_inventory]") {
    // Regression guard for the ARCH-1 advisory-lock skip path: when another instance holds
    // the cluster-wide rollup lock, refresh must SKIP (return success) without recomputing,
    // so only one instance recomputes the shared rollup at a time.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.apply_installed_software("lock-a1", "",
                                           std::vector<SoftwareEntry>{{"App", "1", "P", ""}},
                                           1) == InventoryIngestOutcome::kStored);

    // Hold the cluster-wide rollup advisory lock on a separate session connection (the "peer").
    auto holder = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(holder);
    pg::PgResult lk = pg::exec_params(
        holder.get(), "SELECT pg_advisory_lock(hashtextextended('software_catalog_rollup', 0))",
        std::vector<std::string>{});
    REQUIRE(lk.status() == PGRES_TUPLES_OK);

    // Lock held by the peer → refresh must skip (return true) and NOT recompute.
    CHECK(store.refresh_catalog_rollup());
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at == 0); // skipped → still the building sentinel

    // Release the lock → a refresh now actually recomputes.
    pg::PgResult ul = pg::exec_params(
        holder.get(), "SELECT pg_advisory_unlock(hashtextextended('software_catalog_rollup', 0))",
        std::vector<std::string>{});
    REQUIRE(ul.status() == PGRES_TUPLES_OK);
    CHECK(store.refresh_catalog_rollup());
    auto meta2 = store.catalog_rollup_meta();
    REQUIRE(meta2.has_value());
    CHECK(meta2->refreshed_at > 0);
}
