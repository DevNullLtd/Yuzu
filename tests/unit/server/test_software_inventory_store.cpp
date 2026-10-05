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
#include "software_catalog_rules.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using yuzu::server::InventoryIngestOutcome;
using yuzu::server::SoftwareEntry;
using yuzu::server::SoftwareCursor;
using yuzu::server::SoftwareFleetQuery;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace agentpb = yuzu::agent::v1;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations. The three migration-backfill tests (v3 clamp,
// v5 '' backfill, v7 extended-row backfill) stay on plain YUZU_REQUIRE_PG_DB — they need to stage a
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

// full_v2_entry() plus the stored extended-tail fields. Wire slots 13-14 (install_location,
// uninstall_string) are reserved and have no member: the server never stores or hashes them.
SoftwareEntry full_extended_entry() {
    SoftwareEntry e = full_v2_entry();
    e.package_id = "bash-5.2.21-3.fc40.x86_64";
    e.source = "installed_apps.list_inventory";
    return e;
}

// Wire record of the first n fields (12 = v2, 16 = extended): 0x1F-separated, 0x1E-terminated.
// Slots 13-14 are written empty (reserved).
std::string wire_record(const SoftwareEntry& e, std::size_t n) {
    static const std::string reserved;
    const std::string* f[] = {
        &e.name,   &e.version,          &e.publisher, &e.install_date, &e.kind,      &e.ecosystem,
        &e.epoch,  &e.release,          &e.arch,      &e.signature_status, &e.distro_id,
        &e.distro_version, &reserved,   &reserved,    &e.package_id,   &e.source};
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        if (i)
            out += '\x1f';
        out += *f[i];
    }
    return out + '\x1e';
}

// A 16-field wire record carrying real values in the reserved slots 13-14.
std::string wire_record_reserved(const SoftwareEntry& e, const std::string& install_location,
                                 const std::string& uninstall_string) {
    std::string r = wire_record(e, 12);
    r.pop_back(); // the 0x1E terminator
    return r + '\x1f' + install_location + '\x1f' + uninstall_string + '\x1f' + e.package_id +
           '\x1f' + e.source + '\x1e';
}

// SERVER CONTRACT PIN (16 fields, slots 13-14 empty). sha256 of wire_record(full_extended_entry(), 16) bytes:
//   printf 'bash\0375.2.21\037Fedora Project\037Mon 01 Jan 2026\037package\037rpm\0370\0373.fc40\037x86_64\037signed\037fedora\03740\037\037\037bash-5.2.21-3.fc40.x86_64\037installed_apps.list_inventory\036' | shasum -a 256
// The agent builder (installed_software_canonical_blob) emits this tail; the identical
// constant and fixture bytes live in tests/unit/test_inventory_sync.cpp, making it the
// live cross-side pin exactly as kCrossPinHash is.
constexpr const char* kCrossPinHashExtended =
    "371b647c95b0f48a039ff98790c6085947ef71fcfd40a399c3cd70d70321291d";

// Ascending tail-order pin: full_extended_entry() and a copy whose source is
// "installed_apps.list_apps" (sorts first), hashed as the two 16-field records in that
// order. This pins the source arm's direction; the order-independence and
// distinctness checks in the hash test prove the other three arms. Recipe as above, two records:
//   printf '<b: fields 1-15 as above>\037installed_apps.list_apps\036<a: as above>' | shasum -a 256
constexpr const char* kTailOrderPinHash =
    "ab2abf993a2b0868b9c69397497799920773fd44c29cde86380e8c4369ccbe8d";

// sha256 of the mixed-shape blob built in the mixed-shape test below (12-field
// "alpha", 16-field full_extended_entry "bash", 16-field source-only "zed"), computed
// over the raw wire bytes.
constexpr const char* kMixedBlobHash =
    "7b37bca935f3ae92a042949ef4280d69b25edc8ee6e518f993ded0eeec7e76f3";

// sha256 of the raw wire bytes a NEWER agent would claim for a 17-field record: the 16-field
// full_extended_entry() record with a 17th token "ignored" before the terminator. The server
// drops the 17th token, so its re-hash differs: a bounded need_full per cycle (ADR-0016's
// inherited mixed-version trait), never an error loop.
constexpr const char* kSeventeenFieldHash =
    "f4a4c78f6118451baca197fb103c1765cf17417429916d0f8a26a45c76082aca";

// sha256 of wire_record_reserved(full_extended_entry(), "/Users/alice/Applications/Bash",
// "bash --uninstall --key=ABC123"): what an agent that fills slots 13-14 would claim.
constexpr const char* kReservedValuesHash =
    "5b66424c685875906e1a9b214bcb5678af4abed07ae3191a3736edc6c008c11f";
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

TEST_CASE("server contract pin: 16-field canonical_hash equals kCrossPinHashExtended",
          "[software_inventory][hash][extended_row]") {
    CHECK(SoftwareInventoryStore::canonical_hash({full_extended_entry()}) ==
          kCrossPinHashExtended);
}

TEST_CASE("hash tail rule: the tail enters the hash only when package_id or source is non-empty",
          "[software_inventory][hash][extended_row]") {
    // Same set as the kCrossPinHash case, tail fields all empty: bytes unchanged. Slots
    // 13-14 are reserved and not stored, so only package_id and source can open the tail.
    const std::vector<SoftwareEntry> v2 = {
        {"Zeta", "9", "", ""},
        full_v2_entry(),
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(SoftwareInventoryStore::canonical_hash(v2) == kCrossPinHash);

    // Source-only tail changes the hash (all four tail slots written, three empty).
    auto with_source = v2;
    with_source[0].source = "installed_apps.list_apps";
    CHECK(SoftwareInventoryStore::canonical_hash(with_source) != kCrossPinHash);

    // package_id ALONE (source empty) must also enter the hash: pins both arms of the
    // "package_id or source non-empty" condition, not just source.
    auto only_pkg = v2;
    only_pkg[0].package_id = "x-1";
    const auto h_pkg = SoftwareInventoryStore::canonical_hash(only_pkg);
    CHECK(h_pkg != kCrossPinHash);
    CHECK(h_pkg != SoftwareInventoryStore::canonical_hash(with_source));

    // Rows differing ONLY in one stored tail field are distinct (entry_equal) and order
    // deterministically (entry_less): for every tail field, {b, a} neither collapses to
    // {a} nor hashes differently from {a, b}.
    const SoftwareEntry base = full_extended_entry();
    const auto one = SoftwareInventoryStore::canonical_hash({base});
    for (auto field : {&SoftwareEntry::package_id, &SoftwareEntry::source}) {
        SoftwareEntry other = base;
        other.*field = "zz-different";
        CHECK(SoftwareInventoryStore::canonical_hash({other, base}) != one);
        CHECK(SoftwareInventoryStore::canonical_hash({other, base}) ==
              SoftwareInventoryStore::canonical_hash({base, other}));
    }
    // ...and an exact duplicate still collapses.
    CHECK(SoftwareInventoryStore::canonical_hash({base, base}) == one);

    // Ascending direction of the tail chain, pinned once (see kTailOrderPinHash).
    SoftwareEntry first = base;
    first.source = "installed_apps.list_apps";
    CHECK(SoftwareInventoryStore::canonical_hash({base, first}) == kTailOrderPinHash);
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

TEST_CASE("blob contract extended tail: 12-field blob ingests with the tail fields empty",
          "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    const SoftwareEntry e = full_v2_entry();
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] =
        SoftwareInventoryStore::canonical_hash({e});
    (*rep.mutable_plugin_data())["installed_software"] = wire_record(e, 12);
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-e12", rep, ack);
    CHECK(ack.need_full_size() == 0);
    auto got = store.get_agent_software("agent-e12");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].distro_version == "40");
    CHECK((*got)[0].package_id.empty());
    CHECK((*got)[0].source.empty());

    // Hash-only report claiming the same hash is a touch, not a need_full.
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] =
        SoftwareInventoryStore::canonical_hash({e});
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-e12", ping, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("blob contract extended tail: 16-field blob ingests and hydrates on both read paths",
          "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    const SoftwareEntry e = full_extended_entry();
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = kCrossPinHashExtended;
    (*rep.mutable_plugin_data())["installed_software"] = wire_record(e, 16);
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-e16", rep, ack);
    CHECK(ack.need_full_size() == 0);

    auto got = store.get_agent_software("agent-e16");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].package_id == "bash-5.2.21-3.fc40.x86_64");
    CHECK((*got)[0].source == "installed_apps.list_inventory");

    SoftwareFleetQuery q;
    q.agent_id = "agent-e16";
    auto fl = store.query_software(q);
    REQUIRE(fl.has_value());
    REQUIRE(fl->size() == 1);
    CHECK((*fl)[0].entry.package_id == "bash-5.2.21-3.fc40.x86_64");
    CHECK((*fl)[0].entry.source == "installed_apps.list_inventory");
    CHECK((*fl)[0].install_id >= 1);

    // Hash-only ping with the pinned literal: the server's re-hash of the stored 16-field
    // rows must equal it (touched, not need_full).
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] = kCrossPinHashExtended;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-e16", ping, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("blob contract extended tail: a 17th token is dropped, the 16 fields survive; a newer "
          "agent's 17-field hash degrades to need_full",
          "[pg][software_inventory][extended_row]") {
    // parse_software_blob lives in an anonymous namespace, so this goes through the
    // ingest seam: a future 17-field row from a newer agent must not break this server.
    SWINV_SHARED(store, pool);
    const std::string rec17 = [] {
        std::string r = wire_record(full_extended_entry(), 16);
        r.insert(r.size() - 1, "\x1f" "ignored");
        return r;
    }();
    // The newer agent claims the hash of ALL 17 fields (kSeventeenFieldHash), not the
    // server's 16-field form. A full payload stores regardless of the claimed hash.
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = kSeventeenFieldHash;
    (*rep.mutable_plugin_data())["installed_software"] = rec17;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-e17", rep, ack);
    CHECK(ack.need_full_size() == 0);
    auto got = store.get_agent_software("agent-e17");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].package_id == "bash-5.2.21-3.fc40.x86_64");
    CHECK((*got)[0].source == "installed_apps.list_inventory");
    CHECK(SoftwareInventoryStore::canonical_hash(*got) ==
          SoftwareInventoryStore::canonical_hash({full_extended_entry()}));

    // Bounded mixed-version degradation, pinned so it stays a property: the stored hash is
    // the server's 16-field recompute, so the 17-field claim never matches and every
    // hash-only report is answered need_full (about one extra full report per cycle until
    // the server learns the 17th field). Never an error loop, never corruption.
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] = kSeventeenFieldHash;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-e17", ping, ack2);
    REQUIRE(ack2.need_full_size() == 1);
    CHECK(ack2.need_full(0) == "installed_software");

    // A hash-only claim of the 16-field form is accepted (touched).
    agentpb::InventoryReport ping16;
    (*ping16.mutable_content_hashes())["installed_software"] = kCrossPinHashExtended;
    agentpb::InventoryAck ack3;
    yuzu::server::ingest_inventory_report(store, "agent-e17", ping16, ack3);
    CHECK(ack3.need_full_size() == 0);
}

TEST_CASE("blob contract extended tail: slots 13-14 are parsed but neither stored nor hashed",
          "[pg][software_inventory][extended_row]") {
    // ADR-0016 section 8 has not been re-opened for install_location / uninstall_string
    // (#5186), so a value an agent sends in those slots must not reach the database or the
    // hash. An agent that does fill them gets need_full until the server accepts them.
    SWINV_SHARED(store, pool);
    const SoftwareEntry e = full_extended_entry();
    const std::string path = "/Users/alice/Applications/Bash";
    const std::string cmd = "bash --uninstall --key=ABC123";
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = kReservedValuesHash;
    (*rep.mutable_plugin_data())["installed_software"] = wire_record_reserved(e, path, cmd);
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-reserved", rep, ack);
    CHECK(ack.need_full_size() == 0);

    // The row stores with the later slots intact, and its re-hash is the reserved-empty form.
    auto got = store.get_agent_software("agent-reserved");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].package_id == e.package_id);
    CHECK((*got)[0].source == e.source);
    CHECK(SoftwareInventoryStore::canonical_hash(*got) == kCrossPinHashExtended);

    // No value reaches storage: the schema has no such columns, and no stored text holds them.
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult cols = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = 'software_inventory_store' "
            "AND column_name IN ('install_location', 'uninstall_string')",
            std::vector<std::string>{});
        REQUIRE(cols.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(cols.get(), 0, 0)) == "0");
        // Positive control: the same catalog query does see this table's real columns, so the
        // zero above is not a vacuous result from a wrong schema or table name.
        pg::PgResult present = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = 'software_inventory_store' "
            "AND table_name = 'installed_software' AND column_name IN ('package_id', 'source')",
            std::vector<std::string>{});
        REQUIRE(present.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(present.get(), 0, 0)) == "2");
        pg::PgResult leak = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM software_inventory_store.installed_software t "
            "WHERE t::text LIKE '%alice%' OR t::text LIKE '%ABC123%'",
            std::vector<std::string>{});
        REQUIRE(leak.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(leak.get(), 0, 0)) == "0");
    }

    // Bounded degradation: the agent's claim includes the values, the server's does not.
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] = kReservedValuesHash;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-reserved", ping, ack2);
    REQUIRE(ack2.need_full_size() == 1);
    CHECK(ack2.need_full(0) == "installed_software");
    // ...while a claim of the reserved-empty form is a touch.
    agentpb::InventoryReport ping_empty;
    (*ping_empty.mutable_content_hashes())["installed_software"] = kCrossPinHashExtended;
    agentpb::InventoryAck ack3;
    yuzu::server::ingest_inventory_report(store, "agent-reserved", ping_empty, ack3);
    CHECK(ack3.need_full_size() == 0);
}

TEST_CASE("blob contract extended tail: values only in slots 13-14 leave the tail unopened",
          "[pg][software_inventory][extended_row]") {
    // package_id and source empty, slots 13-14 filled: the server stores a v2 row and hashes
    // the 12-field form (no tail), so it equals the hash of the same entry with nothing there.
    SWINV_SHARED(store, pool);
    const SoftwareEntry e = full_v2_entry(); // package_id / source empty
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] =
        SoftwareInventoryStore::canonical_hash({e});
    (*rep.mutable_plugin_data())["installed_software"] =
        wire_record_reserved(e, "/opt/x", "rm x");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-slots-only", rep, ack);
    CHECK(ack.need_full_size() == 0);
    auto got = store.get_agent_software("agent-slots-only");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].package_id.empty());
    CHECK((*got)[0].source.empty());
    // The stored hash is the 12-field form: a hash-only claim of that form is a touch.
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] =
        SoftwareInventoryStore::canonical_hash({e});
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-slots-only", ping, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("blob contract extended tail: mixed 12/16-field records in one blob re-hash to the raw "
          "bytes",
          "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    SoftwareEntry a;
    a.name = "alpha";
    a.version = "1.0";
    a.publisher = "AlphaCo";
    a.install_date = "2026-01-01";
    a.kind = "app";
    SoftwareEntry c;
    c.name = "zed";
    c.version = "1";
    c.source = "installed_apps.list_inventory"; // source-only tail
    const std::string mixed =
        wire_record(a, 12) + wire_record(full_extended_entry(), 16) + wire_record(c, 16);

    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = kMixedBlobHash;
    (*rep.mutable_plugin_data())["installed_software"] = mixed;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-mixed", rep, ack);
    CHECK(ack.need_full_size() == 0);
    auto got = store.get_agent_software("agent-mixed");
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 3);

    // Hash-only ping with the raw-bytes hash: the server's re-hash of the stored rows
    // must equal it (touched, not need_full).
    agentpb::InventoryReport ping;
    (*ping.mutable_content_hashes())["installed_software"] = kMixedBlobHash;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-mixed", ping, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("query_software q/kind/ecosystem/source filters", "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    SoftwareEntry chrome;
    chrome.name = "Chrome";
    chrome.publisher = "Google";
    chrome.kind = "app";
    chrome.ecosystem = "windows";
    chrome.source = "installed_apps.list_apps";
    REQUIRE(store.apply_installed_software(
                "agent-f", "", std::vector<SoftwareEntry>{full_extended_entry(), chrome}, 1000) ==
            InventoryIngestOutcome::kStored);
    // Wildcard discriminators: '%' and '_' must match literally, so each term hits one row
    // (an unescaped '100%' also hits "100 Proof"; an unescaped 'a_' also hits "ab").
    REQUIRE(store.apply_installed_software(
                "agent-w", "",
                std::vector<SoftwareEntry>{{"100% Pure", "1", "", ""},
                                           {"100 Proof", "1", "", ""},
                                           {"a_b", "1", "", ""},
                                           {"ab", "1", "", ""}},
                1000) == InventoryIngestOutcome::kStored);

    auto count = [&](const SoftwareFleetQuery& q) {
        auto r = store.query_software(q);
        REQUIRE(r.has_value());
        return r->size();
    };
    SoftwareFleetQuery q;
    q.q = "fedora"; // publisher, case-insensitive
    CHECK(count(q) == 1);
    q.q = "RPM"; // ecosystem, case-insensitive
    CHECK(count(q) == 1);
    q.q = "list_inventory"; // source
    CHECK(count(q) == 1);
    q.q = "list_"; // both sources
    CHECK(count(q) == 2);
    q.q = "no-such-thing";
    CHECK(count(q) == 0);
    q.q = "100%"; // literal percent
    CHECK(count(q) == 1);
    q.q = "a_"; // literal underscore
    CHECK(count(q) == 1);

    q = {};
    q.kind = "app";
    CHECK(count(q) == 1);
    q.kind = "ap"; // exact, not substring
    CHECK(count(q) == 0);
    q = {};
    q.ecosystem = "windows";
    CHECK(count(q) == 1);
    q.ecosystem = "win";
    CHECK(count(q) == 0);
    q = {};
    q.source = "installed_apps.list_apps";
    CHECK(count(q) == 1);
    q.source = "installed_apps";
    CHECK(count(q) == 0);

    q = {};
    q.q = "list_";
    q.name = "Chrome";
    CHECK(count(q) == 1);
    q.agent_id = "nobody";
    CHECK(count(q) == 0);
}

TEST_CASE("query_software keyset paging walks to an empty page in (name, agent_id, install_id) "
          "order",
          "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    auto mk = [](const char* name, const char* ver) {
        SoftwareEntry e;
        e.name = name;
        e.version = ver;
        e.source = "installed_apps.list_inventory";
        return e;
    };
    REQUIRE(store.apply_installed_software(
                "agent-a", "", std::vector<SoftwareEntry>{mk("alpha", "1"), mk("bravo", "1"),
                                                          mk("bravo", "2")},
                1000) == InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software(
                "agent-b", "", std::vector<SoftwareEntry>{mk("alpha", "1"), mk("charlie", "1")},
                1000) == InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("agent-c", "",
                                           std::vector<SoftwareEntry>{mk("bravo", "1")}, 1000) ==
            InventoryIngestOutcome::kStored);

    // install_id is monotone with insertion above, so heap order would mask a missing
    // install_id tiebreak. Push agent-a/bravo version '1' past version '2': the walk must
    // then return '2' before '1'.
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult upd = pg::exec_params(
            lease.get(),
            "UPDATE software_inventory_store.installed_software SET install_id = "
            "install_id + 1000000 WHERE agent_id = 'agent-a' AND name = 'bravo' AND version = '1'",
            std::vector<std::string>{});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Even row count (6): the last non-empty page is FULL, so only the EMPTY page ends the walk.
    auto walk = [&](const std::string& filter, std::size_t& pages) {
        std::vector<yuzu::server::SoftwareFleetRow> seen;
        std::optional<SoftwareCursor> after;
        pages = 0;
        for (;;) {
            SoftwareFleetQuery q;
            q.limit = 2;
            q.q = filter;
            q.after = after;
            auto page = store.query_software(q);
            REQUIRE(page.has_value());
            ++pages;
            REQUIRE(pages <= 8); // 6 rows / limit 2 = 4 pages; a non-advancing cursor must not hang
            if (page->empty())
                break;
            for (auto& r : *page)
                seen.push_back(r);
            const auto& last = page->back();
            after = SoftwareCursor{last.entry.name, last.agent_id, last.install_id};
        }
        return seen;
    };

    std::size_t pages = 0;
    auto seen = walk("", pages);
    REQUIRE(seen.size() == 6);
    CHECK(pages == 4); // 3 full pages + the terminating empty page
    const std::vector<std::pair<std::string, std::string>> expect = {
        {"alpha", "agent-a"}, {"alpha", "agent-b"}, {"bravo", "agent-a"},
        {"bravo", "agent-a"}, {"bravo", "agent-c"}, {"charlie", "agent-b"}};
    for (std::size_t i = 0; i < seen.size(); ++i) {
        CHECK(seen[i].entry.name == expect[i].first);
        CHECK(seen[i].agent_id == expect[i].second);
    }
    // The same-name pair within agent-a is ordered by install_id (the reordered ids put
    // version '2' first) and both rows are seen exactly once.
    CHECK(seen[2].install_id < seen[3].install_id);
    CHECK(seen[2].entry.version == "2");
    CHECK(seen[3].entry.version == "1");

    // Filtered walk yields the filtered set exactly once.
    auto bravo = walk("bravo", pages);
    CHECK(bravo.size() == 3);
}

TEST_CASE("migration v7 backfills '' + install_id into pre-existing rows and re-runs "
          "idempotently",
          "[pg][software_inventory][extended_row]") {
    // Reproduce a v6-era table: DROP the five v7 columns, seed a legacy row, rewind
    // schema_meta to 6, reconstruct so v7 re-adds them over live data. Then rewind again
    // and reconstruct to prove the migration text is idempotent.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    auto rewind = [&] {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult back = pg::exec_params(
            lease.get(),
            "UPDATE public.schema_meta SET version = 6 WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(back.status() == PGRES_COMMAND_OK);
    };
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop = pg::exec_params(
            lease.get(),
            "ALTER TABLE software_inventory_store.installed_software "
            "DROP COLUMN package_id, DROP COLUMN source, DROP COLUMN install_id",
            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
        pg::PgResult ins = pg::exec_params(
            lease.get(),
            "INSERT INTO software_inventory_store.installed_software "
            "(agent_id, name, version, publisher, install_date) "
            "VALUES ('agent-legacy', 'OldApp', '1.0', 'OldCo', '2025-01-01')",
            std::vector<std::string>{});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
    }
    rewind();
    SoftwareInventoryStore store{pool}; // re-runs v7 over the live row
    REQUIRE(store.is_open());

    SoftwareFleetQuery q;
    q.agent_id = "agent-legacy";
    auto rows = store.query_software(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].entry.name == "OldApp");
    CHECK((*rows)[0].entry.package_id.empty());
    CHECK((*rows)[0].entry.source.empty());
    CHECK((*rows)[0].install_id >= 1);

    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult idx = pg::exec_params(
            lease.get(),
            "SELECT indexdef FROM pg_indexes WHERE schemaname = 'software_inventory_store' "
            "AND indexname = 'installed_software_name_idx'",
            std::vector<std::string>{});
        REQUIRE(idx.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(idx.get()) == 1);
        CHECK(std::string(PQgetvalue(idx.get(), 0, 0)).find("install_id") != std::string::npos);
    }

    rewind();
    SoftwareInventoryStore again{pool}; // second run over an already-migrated table
    CHECK(again.is_open());
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult seq = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'software_inventory_store' AND c.relkind = 'S' "
            "AND c.relname LIKE 'installed_software_install_id%'",
            std::vector<std::string>{});
        REQUIRE(seq.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(seq.get()) == 1);
        CHECK(std::string(PQgetvalue(seq.get(), 0, 0)) == "1"); // re-run added no 2nd sequence
    }
}

// Post-migration projection check (postgres-store-playbook "Runner guards"). schema_meta stays
// current while a column a runtime query uses is missing, which models a version stamped by a
// different binary: PgMigrationRunner::run() sees nothing pending and returns true, so only the
// constructor's LIMIT 0 projection can refuse to open. Every column of every table in the store
// schema is renamed away in turn. The columns come from the live catalog, so a column added by a
// later migration but not to the guard fails here instead of silently weakening it. Renaming it
// back must reopen the store, which pins the closure on that column and not on some other failure.
TEST_CASE("SoftwareInventoryStore reports !is_open when any column its queries use is missing "
          "although schema_meta is current",
          "[pg][software_inventory][extended_row]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareInventoryStore intact{pool};
        REQUIRE(intact.is_open()); // control: the guard must not refuse a healthy schema
    }

    std::vector<std::pair<std::string, std::string>> columns; // (table, column)
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r =
            pg::exec_params(lease.get(),
                            "SELECT table_name, column_name FROM information_schema.columns "
                            "WHERE table_schema = 'software_inventory_store' "
                            "ORDER BY table_name, ordinal_position",
                            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        for (int i = 0; i < PQntuples(r.get()); ++i)
            columns.emplace_back(PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1));
    }
    // A catalog read that returned only part of the schema would pass vacuously; name the tables.
    for (const char* table : {"installed_software", "inventory_state", "catalog_rollup",
                              "version_rollup", "catalog_rollup_meta"}) {
        CAPTURE(table);
        REQUIRE(std::any_of(columns.begin(), columns.end(),
                            [&](const auto& c) { return c.first == table; }));
    }

    auto alter = [&](const std::string& sql) {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    };

    for (const auto& [table, column] : columns) {
        CAPTURE(table, column);
        const std::string rename_prefix =
            "ALTER TABLE software_inventory_store.\"" + table + "\" RENAME COLUMN \"";
        alter(rename_prefix + column + "\" TO \"" + column + "_gone\"");
        {
            SoftwareInventoryStore broken{pool};
            CHECK_FALSE(broken.is_open());
        }
        alter(rename_prefix + column + "_gone\" TO \"" + column + "\"");
        {
            SoftwareInventoryStore restored{pool};
            CHECK(restored.is_open());
        }
    }
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
    std::string blob = longname + "\037" "1\037\037\036";
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
    SECTION("q is a case-insensitive substring") {
        yuzu::server::SoftwareCatalogQuery q;
        q.q = "chrome";
        auto cat = store.software_catalog(q);
        REQUIRE(cat.has_value());
        REQUIRE(cat->size() == 1);
        CHECK((*cat)[0].name == "Google Chrome");
    }
    SECTION("q matches on PUBLISHER alone, not just the title (round-3 item 8)") {
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
        q.q = "zylofex"; // substring of the publisher only
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
        auto v = store.software_versions({.name = "Google Chrome", .limit = 100});
        REQUIRE(v.has_value());
        REQUIRE(v->size() == 2);
        CHECK((*v)[0].version == "126");
        CHECK((*v)[0].device_count == 2);
        CHECK((*v)[1].version == "125");
        CHECK((*v)[1].device_count == 1);
    }
    SECTION("software_versions empty name → empty value (precondition miss, not degrade)") {
        auto v = store.software_versions({.name = "", .limit = 100});
        REQUIRE(v.has_value());
        CHECK(v->empty());
    }
    SECTION("software_versions unknown title → empty value, not degrade") {
        auto v = store.software_versions({.name = "Nonexistent App", .limit = 100});
        REQUIRE(v.has_value());
        CHECK(v->empty());
    }
}

namespace {
// Every KPI field of the meta row is 0 (the "building" sentinel and the refreshed-but-empty
// fleet both read this way; refreshed_at tells them apart and is asserted by the caller).
void check_kpis_zero(const yuzu::server::CatalogRollupMeta& m) {
    CHECK(m.total_titles == 0);
    CHECK(m.total_devices == 0);
    CHECK(m.total_publishers == 0);
    CHECK(m.total_installs == 0);
    CHECK(m.installs_windows == 0);
    CHECK(m.installs_macos == 0);
    CHECK(m.installs_linux == 0);
    CHECK(m.installs_other == 0);
    CHECK(m.current_installs == 0);
    CHECK(m.current_total == 0);
    CHECK(m.current_titles == 0);
    CHECK(m.sprawl_titles == 0);
    CHECK(m.rpm_total == 0);
    CHECK(m.rpm_unsigned == 0);
}
} // namespace

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
    check_kpis_zero(*meta);
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
        "WHERE conname IN ('catalog_rollup_grain_key', 'version_rollup_nv_key') AND contype = 'u'",
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

// ── M.9 PR-1: exact-distinct grain rollup, filtered reads, KPIs, refresh bounds ───────────
namespace {
using yuzu::server::CatalogRollupMeta;
using yuzu::server::SoftwareCatalogCursor;
using yuzu::server::SoftwareCatalogQuery;
using yuzu::server::SoftwareCatalogRow;
using yuzu::server::SoftwareVersionsQuery;
using Rows = std::vector<SoftwareEntry>;
namespace sc = yuzu::server::software_catalog;

constexpr const char* kSrcPkg = "pkg_inventory.packages";
constexpr const char* kSrcApps = "installed_apps.list_inventory";

SoftwareEntry ent(std::string name, std::string ver, std::string pub = "", std::string kind = "",
                  std::string eco = "", std::string src = "", std::string sig = "") {
    SoftwareEntry e;
    e.name = std::move(name);
    e.version = std::move(ver);
    e.publisher = std::move(pub);
    e.kind = std::move(kind);
    e.ecosystem = std::move(eco);
    e.source = std::move(src);
    e.signature_status = std::move(sig);
    return e;
}

void put(SoftwareInventoryStore& store, const std::string& agent, Rows rows) {
    REQUIRE(store.apply_installed_software(agent, "", std::move(rows), 1) ==
            InventoryIngestOutcome::kStored);
}

// d1 carries git via brew AND macos_pkgutil (two sources), d2 via brew, d3 via rpm (unsigned);
// d1 also carries Chrome. Finest-grain combos: git 3, so 19 rollup rows; Chrome 8.
void seed_grain_fixture(SoftwareInventoryStore& store) {
    put(store, "d1",
        Rows{ent("git", "2.40", "Git SCM", "package", "brew", kSrcPkg),
             ent("git", "2.40", "Git SCM", "pkg", "macos_pkgutil", kSrcApps),
             ent("Chrome", "126", "Google", "app", "macos", kSrcApps)});
    put(store, "d2", Rows{ent("git", "2.39", "Git SCM", "package", "brew", kSrcPkg)});
    put(store, "d3", Rows{ent("git", "2.41", "Fedora", "package", "rpm", kSrcPkg, "unsigned")});
    REQUIRE(store.refresh_catalog_rollup());
}

std::optional<SoftwareCatalogRow> title(SoftwareInventoryStore& s, const std::string& name,
                                        SoftwareCatalogQuery q = {}) {
    q.limit = 2000;
    auto c = s.software_catalog(q);
    REQUIRE(c.has_value());
    for (const auto& r : *c)
        if (r.name == name)
            return r;
    return std::nullopt;
}

// Lease, run one parameterless statement, REQUIRE it succeeded (rows or a command tag).
pg::PgResult run_sql(PgPool& pool, const std::string& stmt) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), stmt.c_str(), std::vector<std::string>{});
    REQUIRE((r.status() == PGRES_TUPLES_OK || r.status() == PGRES_COMMAND_OK));
    return r;
}

std::int64_t count_rows(PgPool& pool, const char* table) {
    auto r = run_sql(pool, std::string("SELECT count(*) FROM software_inventory_store.") + table);
    return std::stoll(PQgetvalue(r.get(), 0, 0));
}
} // namespace

TEST_CASE("catalogue Installs are exact distinct devices under every filter grain",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);

    struct Case {
        const char *kind, *eco, *src;
        std::int64_t installs, versions;
    };
    const Case cases[] = {
        {"", "", "", 3, 3},                                   // grain 7, d1 counted once
        {"package", "", "", 3, 3},                            // 3
        {"pkg", "", "", 1, 1},                                // 3 (kind)
        {"", "brew", "", 2, 2},                               // 5
        {"", "", kSrcApps, 1, 1},                             // 6
        {"", "", kSrcPkg, 3, 3},                              // 6
        {"package", "brew", "", 2, 2},                        // 1: kind+ecosystem
        {"pkg", "macos_pkgutil", "", 1, 1},                   // 1
        {"package", "", kSrcPkg, 3, 3},                       // 2: kind+source
        {"pkg", "", kSrcApps, 1, 1},                          // 2
        {"", "brew", kSrcPkg, 2, 2},                          // 4: ecosystem+source
        {"pkg", "macos_pkgutil", kSrcApps, 1, 1},             // 0: all three fixed
    };
    for (const auto& c : cases) {
        CAPTURE(c.kind, c.eco, c.src);
        SoftwareCatalogQuery q;
        q.kind = c.kind;
        q.ecosystem = c.eco;
        q.source = c.src;
        auto r = title(store, "git", q);
        REQUIRE(r.has_value());
        CHECK(r->device_count == c.installs);
        CHECK(r->version_count == c.versions);
    }
    auto all = title(store, "git");
    REQUIRE(all.has_value());
    CHECK(all->ecosystems == "brew,macos_pkgutil,rpm");
    CHECK(all->kinds == "package,pkg");
    CHECK(all->newest_version == "2.41");
    SoftwareCatalogQuery kq;
    kq.kind = "package";
    auto slice = title(store, "git", kq);
    REQUIRE(slice.has_value());
    CHECK(slice->ecosystems == "brew,rpm"); // the filtered slice's own lists
    CHECK(slice->kinds == "package");
    // a title absent from a slice is absent, not zero
    SoftwareCatalogQuery cq;
    cq.kind = "package";
    CHECK_FALSE(title(store, "Chrome", cq).has_value());

    // F2: one row per DISTINCT combination per grouping set: git 19, Chrome 8
    CHECK(count_rows(pool, "catalog_rollup") == 27);
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->rpm_total == 1);
    CHECK(meta->rpm_unsigned == 1);
}

TEST_CASE("q is literal, title-level and clamped", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    put(store, "q1",
        Rows{ent("100% Pure", "1"), ent("100 Proof", "1"), ent("a_b", "1"), ent("ab", "1"),
             ent("Widget", "1", "Zylofex Systems"), ent(std::string(128, 'a'), "1")});
    REQUIRE(store.refresh_catalog_rollup());
    auto names = [&](SoftwareCatalogQuery q) {
        auto c = store.software_catalog(q);
        REQUIRE(c.has_value());
        std::vector<std::string> n;
        for (const auto& r : *c)
            n.push_back(r.name);
        std::sort(n.begin(), n.end());
        return n;
    };
    SoftwareCatalogQuery q;
    q.q = "100%";
    CHECK(names(q) == std::vector<std::string>{"100% Pure"}); // % is literal
    q.q = "a_";
    CHECK(names(q) == std::vector<std::string>{"a_b"}); // _ is literal: "ab" would match a wildcard
    q.q = "zylofex"; // publisher-only
    CHECK(names(q) == std::vector<std::string>{"Widget"});
    q.q = "pkgutil"; // matches through the title's sources/ecosystems
    CHECK(names(q) == std::vector<std::string>{"git"});
    auto g = title(store, "git", q);
    REQUIRE(g.has_value());
    CHECK(g->device_count == 3); // a matched title keeps its whole slice
    q.kind = "package"; // the filtered slice has no pkgutil: git is absent
    CHECK(names(q).empty());
    // 300 multibyte bytes are clamped to a valid term, never a degrade
    SoftwareCatalogQuery big;
    for (int i = 0; i < 150; ++i)
        big.q += "\xC3\xA9";
    CHECK(store.software_catalog(big).has_value());
    // The 128-byte clamp is applied on both reads: a title of 128 'a' queried with 128 'a' + 72
    // 'z' is found (the term is cut to the 128 'a'); unclamped the term would match nothing.
    const std::string long_title(128, 'a');
    SoftwareCatalogQuery clamped;
    clamped.q = long_title + std::string(72, 'z');
    CHECK(names(clamped) == std::vector<std::string>{long_title});
    SoftwareFleetQuery raw;
    raw.q = long_title + std::string(72, 'z');
    auto hits = store.query_software(raw);
    REQUIRE(hits.has_value());
    REQUIRE(hits->size() == 1);
    CHECK((*hits)[0].entry.name == long_title);
}

TEST_CASE("catalogue keyset walk is exact, bounded and rejects a negative cursor",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    // A,B on 3 devices; C,D on 2; E,F on 1 (ties inside each count); C on two versions.
    for (const char* d : {"k1", "k2", "k3"}) {
        Rows r{ent("A", "1"), ent("B", "1")};
        if (std::string(d) != "k3") {
            r.push_back(ent("C", std::string(d) == "k1" ? "1" : "2"));
            r.push_back(ent("D", "1"));
        }
        if (std::string(d) == "k1") {
            r.push_back(ent("E", "1"));
            r.push_back(ent("F", "1"));
        }
        put(store, d, std::move(r));
    }
    REQUIRE(store.refresh_catalog_rollup());
    std::vector<std::string> seen;
    std::optional<SoftwareCatalogCursor> after;
    int pages = 0;
    for (;;) {
        REQUIRE(++pages <= 8);
        SoftwareCatalogQuery q;
        q.limit = 2;
        q.after = after;
        auto page = store.software_catalog(q);
        REQUIRE(page.has_value());
        if (page->empty())
            break;
        for (const auto& r : *page)
            seen.push_back(r.name);
        after = SoftwareCatalogCursor{page->back().device_count, page->back().name};
    }
    CHECK(seen == std::vector<std::string>{"A", "B", "C", "D", "E", "F"});
    SoftwareCatalogQuery mv;
    mv.versions_min = 2;
    auto m = store.software_catalog(mv);
    REQUIRE(m.has_value());
    REQUIRE(m->size() == 1);
    CHECK((*m)[0].name == "C");
    for (const std::int64_t bad : {std::int64_t{-1}, std::numeric_limits<std::int64_t>::min()}) {
        SoftwareCatalogQuery q;
        q.after = SoftwareCatalogCursor{bad, ""};
        auto r = store.software_catalog(q);
        REQUIRE(r.has_value()); // precondition miss: empty VALUE, store still open
        CHECK(r->empty());
    }
    CHECK(store.is_open());
}

TEST_CASE("host catalogue view reads one device and shares the q list representation",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    SoftwareCatalogQuery q;
    q.agent_id = "d1";
    auto rows = store.software_catalog(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    const auto& chrome = (*rows)[0]; // name order
    const auto& git = (*rows)[1];
    CHECK(chrome.name == "Chrome");
    CHECK(git.name == "git");
    CHECK(git.device_count == 1);
    CHECK(git.version_count == 1); // d1 carries only 2.40
    CHECK(git.ecosystems == "brew,macos_pkgutil");
    CHECK(git.kinds == "package,pkg");
    CHECK(git.newest_version == "2.41"); // fleet-wide, not d1's
    q.agent_id = "nobody";
    auto none = store.software_catalog(q);
    REQUIRE(none.has_value());
    CHECK(none->empty());

    // F7: the literal list "brew,macos_pkgutil" matches identically on both paths
    SoftwareCatalogQuery fq;
    fq.q = "brew,macos_pkgutil";
    auto fleet = store.software_catalog(fq);
    REQUIRE(fleet.has_value());
    CHECK(fleet->size() == 1);
    fq.agent_id = "d1";
    auto host1 = store.software_catalog(fq);
    REQUIRE(host1.has_value());
    REQUIRE(host1->size() == 1);
    CHECK((*host1)[0].name == "git");
    fq.agent_id = "d2";
    auto host2 = store.software_catalog(fq);
    REQUIRE(host2.has_value());
    CHECK(host2->empty());
}

TEST_CASE("software_versions fleet, filtered and host paths carry the fleet newest mark",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    put(store, "vA",
        Rows{ent("git", "2.40", "", "package", "brew", kSrcPkg),
             ent("git", "2.40", "", "pkg", "macos_pkgutil", kSrcApps)});
    put(store, "vB", Rows{ent("git", "2.40", "", "package", "brew", kSrcPkg)});
    put(store, "vC", Rows{ent("git", "2.41", "", "package", "rpm", kSrcPkg)});
    put(store, "hA", Rows{ent("Host", "1.0")});
    put(store, "hB", Rows{ent("Host", "2.0")});
    put(store, "vD", Rows{ent("NoVer", "")});
    REQUIRE(store.refresh_catalog_rollup());

    auto v = store.software_versions({.name = "git"});
    REQUIRE(v.has_value());
    REQUIRE(v->size() == 2); // vA's two sources count once
    CHECK((*v)[0].version == "2.40");
    CHECK((*v)[0].device_count == 2);
    CHECK_FALSE((*v)[0].newest);
    CHECK((*v)[1].version == "2.41");
    CHECK((*v)[1].newest);

    auto brew = store.software_versions({.name = "git", .ecosystem = "brew"});
    REQUIRE(brew.has_value());
    REQUIRE(brew->size() == 1);
    CHECK((*brew)[0].device_count == 2);
    CHECK_FALSE((*brew)[0].newest); // 2.41 is fleet-newest but outside this slice
    auto rpm = store.software_versions({.name = "git", .ecosystem = "rpm"});
    REQUIRE(rpm.has_value());
    REQUIRE(rpm->size() == 1);
    CHECK((*rpm)[0].newest);

    auto a = store.software_versions({.name = "Host", .agent_id = "hA"});
    REQUIRE(a.has_value());
    REQUIRE(a->size() == 1);
    CHECK((*a)[0].version == "1.0");
    CHECK_FALSE((*a)[0].newest);
    auto b = store.software_versions({.name = "Host", .agent_id = "hB"});
    REQUIRE(b.has_value());
    REQUIRE(b->size() == 1);
    CHECK((*b)[0].newest);
    auto both = store.software_versions({.name = "Host"});
    REQUIRE(both.has_value());
    CHECK(both->size() == 2);

    auto nv = store.software_versions({.name = "NoVer"});
    REQUIRE(nv.has_value());
    REQUIRE(nv->size() == 1);
    CHECK_FALSE((*nv)[0].newest); // '' is never newest
    auto unknown = store.software_versions({.name = "Nope"});
    REQUIRE(unknown.has_value());
    CHECK(unknown->empty());
    auto empty_name = store.software_versions({.name = ""});
    REQUIRE(empty_name.has_value());
    CHECK(empty_name->empty());
}

TEST_CASE("KPI meta is computed by the refresh from one snapshot", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    // d4: one device on two versions of Dual side by side; d5: NoVer has only an unknown version.
    put(store, "d4",
        Rows{ent("Dual", "1.0", "", "package", "brew", kSrcPkg),
             ent("Dual", "2.0", "", "package", "brew", kSrcPkg)});
    put(store, "d5", Rows{ent("NoVer", "", "", "package", "brew", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());
    auto m = store.catalog_rollup_meta();
    REQUIRE(m.has_value());
    CHECK(m->refreshed_at > 0);
    CHECK(m->total_titles == 4);
    CHECK(m->total_devices == 5);
    CHECK(m->total_publishers == 3); // Git SCM, Fedora, Google ('' excluded)
    // git 3 + Chrome 1 + Dual 1 + NoVer 1 (d4's two Dual versions count once)
    CHECK(m->total_installs == 6);
    CHECK(m->installs_windows == 0);
    CHECK(m->installs_macos == 5);
    CHECK(m->installs_linux == 1);
    CHECK(m->installs_other == 0);
    CHECK(m->installs_windows + m->installs_macos + m->installs_linux + m->installs_other ==
          m->total_installs);
    CHECK(m->current_titles == 3);   // NoVer has no known version
    CHECK(m->current_installs == 3); // git 2.41 (d3), Chrome 126 (d1), Dual 2.0 (d4)
    CHECK(m->current_total == 5);    // git 3 + Chrome 1 + Dual 1: side-by-side counts once
    CHECK(m->sprawl_titles == 1);    // git on 3 versions
    CHECK(m->rpm_total == 1);
    CHECK(m->rpm_unsigned == 1);
}

TEST_CASE("Installs-by-OS is exact and the CASE SQL mirrors the C++ table",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    put(store, "o1",
        Rows{ent("git", "1", "", "package", "brew", kSrcPkg),
             ent("git", "1", "", "pkg", "macos_pkgutil", kSrcApps)});
    put(store, "o2", Rows{ent("git", "1", "", "package", "deb", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());
    auto m = store.catalog_rollup_meta();
    REQUIRE(m.has_value());
    CHECK(m->installs_macos == 1); // o1 once, not once per ecosystem
    CHECK(m->installs_linux == 1);
    CHECK(m->installs_windows == 0);
    CHECK(m->total_installs == 2);

    // The generated CASE maps every published ecosystem to its table family and anything else
    // ('' / an unknown spelling) to "other".
    std::string values;
    for (const auto& e : sc::kEcosystemFamilies)
        values += "('" + std::string(e.ecosystem) + "'),";
    values += "(''),('snap')";
    auto r = run_sql(pool, "SELECT ecosystem, " + sc::os_family_case_sql() + " FROM (VALUES " +
                               values + ") v(ecosystem)");
    const int published = static_cast<int>(sc::kEcosystemFamilies.size());
    REQUIRE(PQntuples(r.get()) == published + 2);
    for (int i = 0; i < published; ++i)
        CHECK(std::string(PQgetvalue(r.get(), i, 1)) == sc::kEcosystemFamilies[i].family);
    CHECK(std::string(PQgetvalue(r.get(), published, 1)) == "other");
    CHECK(std::string(PQgetvalue(r.get(), published + 1, 1)) == "other");
}

TEST_CASE("a cancelled refresh keeps the last-good rollup", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    auto before = store.catalog_rollup_meta();
    REQUIRE(before.has_value());
    put(store, "c9", Rows{ent("brand-new", "1")});
    CHECK_FALSE(store.refresh_catalog_rollup([] { return true; }));
    CHECK(count_rows(pool, "catalog_rollup") == 27);
    auto after = store.catalog_rollup_meta();
    REQUIRE(after.has_value());
    CHECK(after->refreshed_at == before->refreshed_at);
    CHECK(store.is_open());
    REQUIRE(store.refresh_catalog_rollup()); // default predicate: not cancellable
    CHECK(title(store, "brand-new").has_value());
}

// The first-poll case above never reaches the DELETE. Cancel at the LAST poll instead (just
// before the meta UPDATE, after catalog_rollup was deleted and re-filled in this transaction):
// everything must roll back to the previous publication. The poll count is measured from an
// uncancelled run, so the case follows the code instead of hard-coding a poll index.
TEST_CASE("a refresh cancelled at its last poll rolls back the delete and re-insert",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    put(store, "c1", Rows{ent("second", "1")});
    int polls = 0;
    REQUIRE(store.refresh_catalog_rollup([&] {
        ++polls;
        return false;
    }));
    REQUIRE(polls > 1);
    const auto published_rows = count_rows(pool, "catalog_rollup");
    auto before = store.catalog_rollup_meta();
    REQUIRE(before.has_value());

    put(store, "c2", Rows{ent("third", "1")});
    int calls = 0;
    const int last = polls;
    CHECK_FALSE(store.refresh_catalog_rollup([&] { return ++calls == last; }));
    CHECK(calls == last);
    CHECK(count_rows(pool, "catalog_rollup") == published_rows);
    CHECK_FALSE(title(store, "third").has_value());
    auto after = store.catalog_rollup_meta();
    REQUIRE(after.has_value());
    CHECK(after->refreshed_at == before->refreshed_at);
    CHECK(after->total_titles == before->total_titles);
    CHECK(store.is_open());
    REQUIRE(store.refresh_catalog_rollup());
    CHECK(title(store, "third").has_value());
}

// One snapshot: a peer commit that lands mid-refresh must be wholly absent from this
// publication (REPEATABLE READ) and wholly present in the next. The cancel predicate is the
// barrier (no sleeps): at its 6th poll — well after the advisory-lock SELECT and the snapshot —
// it commits a new title through another pool lease, then lets the refresh continue.
TEST_CASE("a title committed mid-refresh is absent from this publication and in the next",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    const auto version_rows = count_rows(pool, "version_rollup");
    auto before = store.catalog_rollup_meta();
    REQUIRE(before.has_value());
    int polls = 0;
    bool fired = false;
    REQUIRE(store.refresh_catalog_rollup([&] {
        if (++polls == 6) {
            fired = true;
            put(store, "late-dev", Rows{ent("LateTitle", "9", "Late", "package", "brew", kSrcPkg)});
        }
        return false;
    }));
    REQUIRE(fired); // fails loudly if the poll sequence ever shrinks below the barrier
    CHECK_FALSE(title(store, "LateTitle").has_value());
    CHECK(count_rows(pool, "catalog_rollup") == 27);
    CHECK(count_rows(pool, "version_rollup") == version_rows);
    auto during = store.catalog_rollup_meta();
    REQUIRE(during.has_value());
    CHECK(during->total_devices == before->total_devices);
    CHECK(during->total_titles == before->total_titles);
    CHECK(during->total_installs == before->total_installs);
    REQUIRE(store.refresh_catalog_rollup());
    CHECK(title(store, "LateTitle").has_value());
    auto next = store.catalog_rollup_meta();
    REQUIRE(next.has_value());
    CHECK(next->total_devices == before->total_devices + 1);
    CHECK(next->total_titles == before->total_titles + 1);
}

// Production-threshold case (the unit shards otherwise use tiny fixtures): one agent with
// 10,003 version rows crosses the 10,000-row FETCH boundary and, with 5,001 newest picks, the
// 5,000-pick flush. Title t04999 has three versions so its rows (9,999-10,001) straddle the
// boundary and its newest ("3.0") is the row AFTER it. One bulk put + one 10k-row refresh,
// about a second; no sleeps. kRollupRefreshBudget stays untested by design: it is one
// steady_clock comparison inside the same abort_requested() lambda the cancel cases exercise.
TEST_CASE("fleet-newest fold is correct across the FETCH boundary and a mid-loop flush",
          "[pg][software_inventory]") {
    constexpr int kTitles = 5001;
    constexpr int kStraddle = 4999;
    static_assert(2 * kTitles + 1 > sc::kNewestFetchRows);
    static_assert(kTitles > static_cast<int>(sc::kNewestFlushRows));
    SWINV_SHARED(store, pool);
    Rows rows;
    rows.reserve(2 * kTitles + 1);
    char nm[16];
    for (int i = 0; i < kTitles; ++i) {
        std::snprintf(nm, sizeof nm, "t%05d", i);
        rows.push_back(ent(nm, "1.0"));
        rows.push_back(ent(nm, "2.0"));
        if (i == kStraddle)
            rows.push_back(ent(nm, "3.0"));
    }
    put(store, "big-agent", std::move(rows));
    REQUIRE(store.refresh_catalog_rollup());
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->current_titles == kTitles);
    SoftwareCatalogQuery q;
    q.q = "t04999";
    auto straddling = title(store, "t04999", q);
    REQUIRE(straddling.has_value());
    CHECK(straddling->newest_version == "3.0");
    q.q = "t05000";
    auto last = title(store, "t05000", q);
    REQUIRE(last.has_value());
    CHECK(last->newest_version == "2.0");
    q.q = "t00000";
    auto first = title(store, "t00000", q);
    REQUIRE(first.has_value());
    CHECK(first->newest_version == "2.0");
}

// Equivalent spellings compare equal under the catalogue order; the tie goes to the spelling
// carried by more devices ('1.0' on 5 devices beats '1.0.0' on 1). Plain text order would pick
// '1.0.0', so this is the case that pins the store-side use of newer_than's tie rule.
TEST_CASE("equivalent version spellings: the more-installed spelling is the newest mark",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    for (int i = 1; i <= 5; ++i)
        put(store, "t" + std::to_string(i),
            Rows{ent("Tie", "1.0", "P", "package", "brew", kSrcPkg)});
    put(store, "t6", Rows{ent("Tie", "1.0.0", "P", "package", "brew", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());
    auto row = title(store, "Tie");
    REQUIRE(row.has_value());
    CHECK(row->newest_version == "1.0");
    auto vers = store.software_versions({.name = "Tie"});
    REQUIRE(vers.has_value());
    REQUIRE(vers->size() == 2);
    int marked = 0;
    for (const auto& v : *vers)
        if (v.newest) {
            ++marked;
            CHECK(v.version == "1.0");
        }
    CHECK(marked == 1);
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->current_installs == 5);
    CHECK(meta->current_total == 6);
}

TEST_CASE("refreshing an empty fleet is fresh (refreshed_at > 0) with every KPI zero",
          "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.refresh_catalog_rollup());
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at > 0); // "refreshed but empty", not "building"
    check_kpis_zero(*meta);
    auto cat = store.software_catalog({});
    REQUIRE(cat.has_value());
    CHECK(cat->empty());
}

TEST_CASE("query_software honours version and scope push-down", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    put(store, "s1", Rows{ent("Tool", "1.0")});
    put(store, "s2", Rows{ent("Tool", "2.0")});
    put(store, "s3", Rows{ent("Tool", "")});
    SoftwareFleetQuery q;
    q.name = "Tool";
    auto all = store.query_software(q);
    REQUIRE(all.has_value());
    CHECK(all->size() == 3);
    q.version = "2.0";
    auto two = store.query_software(q);
    REQUIRE(two.has_value());
    REQUIRE(two->size() == 1);
    CHECK((*two)[0].agent_id == "s2");
    q.version = ""; // exact empty bucket, distinct from nullopt
    auto empty_ver = store.query_software(q);
    REQUIRE(empty_ver.has_value());
    REQUIRE(empty_ver->size() == 1);
    CHECK((*empty_ver)[0].agent_id == "s3");

    SoftwareFleetQuery sq;
    sq.agent_ids = std::vector<std::string>{"s1", "s3"};
    sq.limit = 1;
    auto p1 = store.query_software(sq);
    REQUIRE(p1.has_value());
    REQUIRE(p1->size() == 1);
    CHECK((*p1)[0].agent_id == "s1");
    sq.after = SoftwareCursor{(*p1)[0].entry.name, (*p1)[0].agent_id, (*p1)[0].install_id};
    auto p2 = store.query_software(sq);
    REQUIRE(p2.has_value());
    REQUIRE(p2->size() == 1);
    CHECK((*p2)[0].agent_id == "s3");
    sq.after = SoftwareCursor{(*p2)[0].entry.name, (*p2)[0].agent_id, (*p2)[0].install_id};
    auto p3 = store.query_software(sq);
    REQUIRE(p3.has_value());
    CHECK(p3->empty());

    SoftwareFleetQuery deny;
    deny.agent_ids = std::vector<std::string>{}; // present-empty = deny-all
    auto none = store.query_software(deny);
    REQUIRE(none.has_value());
    CHECK(none->empty());
    CHECK(store.is_open());
}

TEST_CASE("migration v8 reshapes a v7-era rollup schema and re-runs idempotently",
          "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
        // Sentinels in the two tables v8 must NOT touch (it only reshapes catalog_rollup/meta).
        put(s1, "sentinel-dev",
            Rows{ent("SentinelApp", "7.7", "Sent", "app", "windows", kSrcApps)});
    }
    auto exec = [&](const char* stmt) { run_sql(pool, stmt); };
    exec("INSERT INTO software_inventory_store.version_rollup (name, version, device_count) "
         "VALUES ('SentinelVR', '1.2.3', 42)");
    auto check_sentinels = [&] {
        auto src = run_sql(pool, "SELECT name, version, publisher FROM "
                                 "software_inventory_store.installed_software WHERE agent_id = "
                                 "'sentinel-dev'");
        REQUIRE(PQntuples(src.get()) == 1);
        CHECK(std::string(PQgetvalue(src.get(), 0, 0)) == "SentinelApp");
        CHECK(std::string(PQgetvalue(src.get(), 0, 1)) == "7.7");
        CHECK(std::string(PQgetvalue(src.get(), 0, 2)) == "Sent");
        auto vr = run_sql(pool, "SELECT device_count FROM software_inventory_store.version_rollup "
                                "WHERE name = 'SentinelVR' AND version = '1.2.3'");
        REQUIRE(PQntuples(vr.get()) == 1);
        CHECK(std::string(PQgetvalue(vr.get(), 0, 0)) == "42");
    };
    auto rewind = [&] {
        exec("UPDATE public.schema_meta SET version = 7 WHERE store = 'software_inventory_store'");
    };
    // Stage the v7 shape by hand: UNIQUE(name) rollup + the 4-column meta with a real stamp.
    exec("DROP TABLE software_inventory_store.catalog_rollup");
    exec("DROP TABLE software_inventory_store.catalog_rollup_meta");
    exec("CREATE TABLE software_inventory_store.catalog_rollup (name TEXT NOT NULL, publisher "
         "TEXT NOT NULL DEFAULT '', device_count BIGINT NOT NULL, version_count BIGINT NOT NULL, "
         "CONSTRAINT catalog_rollup_name_key UNIQUE (name))");
    exec("CREATE INDEX catalog_rollup_rank_idx ON software_inventory_store.catalog_rollup "
         "(device_count DESC, name)");
    exec("CREATE TABLE software_inventory_store.catalog_rollup_meta (id INT PRIMARY KEY, "
         "refreshed_at BIGINT NOT NULL DEFAULT 0, total_titles BIGINT NOT NULL DEFAULT 0, "
         "total_devices BIGINT NOT NULL DEFAULT 0)");
    exec("INSERT INTO software_inventory_store.catalog_rollup_meta VALUES (1, 99999, 1, 1)");
    rewind();
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at == 0); // honest "building" until the next refresh
    check_sentinels();
    {
        auto r = run_sql(
            pool,
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
            "'software_inventory_store' AND ((table_name = 'catalog_rollup' AND column_name IN "
            "('grain', 'newest_version', 'sources')) OR (table_name = 'catalog_rollup_meta' AND "
            "column_name = 'total_installs'))");
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "4");
    }
    rewind();
    SoftwareInventoryStore again{pool}; // idempotent re-run
    REQUIRE(again.is_open());
    check_sentinels();
    // The sentinel title would add its own rollup rows to the fixture's 27; drop it first.
    exec("DELETE FROM software_inventory_store.installed_software WHERE agent_id = 'sentinel-dev'");
    seed_grain_fixture(again);
    CHECK(count_rows(pool, "catalog_rollup") == 27);
    auto built = again.catalog_rollup_meta();
    REQUIRE(built.has_value());
    CHECK(built->refreshed_at > 0);
}
