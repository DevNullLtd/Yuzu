// SoftwareInventoryStore tests (ADR-0016): the born-on-Postgres typed
// projection for the installed_software daily-sync source — canonical-hash
// cross-pin, hash-skip ingest (full/touched/need_full), atomic replace, fleet
// query, and the shared ingest seam (ingest_inventory_report) end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "crypto_library_model.hpp"
#include "install_type_rules.hpp"
#include "inventory_ingestion.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "product_normalize.hpp"
#include "purl_compose.hpp"
#include "software_catalog_rules.hpp"
#include "software_inventory_store.hpp"
#include "software_list_model.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <cstdio>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <tuple>
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
// re-seed the catalog_rollup_meta singleton. Migration v8 seeds id=1 with
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
        "software_inventory_store.version_rollup, software_inventory_store.catalog_rollup_meta, "
        "software_inventory_store.title_triples, software_inventory_store.software_facet_state, "
        "software_inventory_store.software_changes, software_inventory_store.software_components, "
        "software_inventory_store.retention_meta, software_inventory_store.component_rollup, "
        "software_inventory_store.component_rollup_meta "
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
    auto comp_seed = pg::exec_params(
        lease.get(),
        "INSERT INTO software_inventory_store.component_rollup_meta (id, refreshed_at) "
        "VALUES (1, 0) ON CONFLICT (id) DO NOTHING",
        std::vector<std::string>{});
    REQUIRE(comp_seed.status() == PGRES_COMMAND_OK);
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

// full_v2_entry() plus the stored extended-tail fields. Wire slot 14 (uninstall_string) is
// reserved and has no member; slot 13 (install_location) is a member only the v3 `+` record
// fills, so the v2 path neither stores nor hashes either.
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
    // On the v2 path ADR-0016 section 8 has not been re-opened for install_location /
    // uninstall_string (#5186), so a value an agent sends in those slots must not reach the
    // database or the hash. An agent that does fill them gets need_full until the server
    // accepts them. (The v3 `+` record stores slot 13 in the install_location column that
    // migration v10 added; this v2 path never writes it, which is what the checks below pin.)
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

    // No value reaches storage: there is no uninstall_string column, install_location is
    // empty on this path, and no stored text holds either value.
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult cols = pg::exec_params(
            lease.get(),
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = 'software_inventory_store' "
            "AND column_name = 'uninstall_string'",
            std::vector<std::string>{});
        REQUIRE(cols.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(cols.get(), 0, 0)) == "0");
        pg::PgResult loc =
            pg::exec_params(lease.get(),
                            "SELECT count(*) FROM software_inventory_store.installed_software "
                            "WHERE agent_id = 'agent-reserved' AND install_location <> ''",
                            std::vector<std::string>{});
        REQUIRE(loc.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(loc.get(), 0, 0)) == "0");
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

TEST_CASE("query_software skip passes over rows after the keyset position, in SQL",
          "[pg][software_inventory][extended_row]") {
    SWINV_SHARED(store, pool);
    auto mk = [](const char* name) {
        SoftwareEntry e;
        e.name = name;
        e.version = "1";
        e.source = "installed_apps.list_inventory";
        return e;
    };
    for (const char* agent : {"agent-a", "agent-b", "agent-c", "agent-d"})
        REQUIRE(store.apply_installed_software(
                    agent, "", std::vector<SoftwareEntry>{mk("alpha"), mk("bravo")}, 1000) ==
                InventoryIngestOutcome::kStored);
    // order: alpha a b c d, bravo a b c d (8 rows)
    auto ids = [&](const SoftwareFleetQuery& q) {
        auto page = store.query_software(q);
        REQUIRE(page.has_value());
        std::vector<std::string> out;
        for (const auto& r : *page)
            out.push_back(r.entry.name + "/" + r.agent_id);
        return out;
    };
    SoftwareFleetQuery q;
    q.limit = 2;
    q.skip = 3; // from the start: pass alpha a, b, c
    CHECK(ids(q) == std::vector<std::string>{"alpha/agent-d", "bravo/agent-a"});

    auto first = store.query_software(SoftwareFleetQuery{.limit = 1});
    REQUIRE(first.has_value());
    REQUIRE(first->size() == 1);
    const auto& a1 = first->front();
    q.after = SoftwareCursor{a1.entry.name, a1.agent_id, a1.install_id}; // after alpha/agent-a
    q.skip = 2;                                                           // pass b, c
    CHECK(ids(q) == std::vector<std::string>{"alpha/agent-d", "bravo/agent-a"});

    q.skip = 100; // past the end: an empty page, not an error
    CHECK(ids(q).empty());

    q.skip = 1; // composes with the scope push-down: skip counts rows of the filtered set
    q.agent_ids = std::vector<std::string>{"agent-b", "agent-d"};
    CHECK(ids(q) == std::vector<std::string>{"alpha/agent-d", "bravo/agent-b"});

    q.agent_ids.reset(); // ...and with the bounded q arm
    q.q = "bravo";
    q.after.reset();
    q.skip = 3;
    CHECK(ids(q) == std::vector<std::string>{"bravo/agent-d"});
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
                              "version_rollup", "title_triples", "catalog_rollup_meta",
                              "software_facet_state", "software_changes",
                              "software_components", "retention_meta"}) {
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
        // The rewritten catalogue reads degrade the same way (ADR-0016 §7).
        CHECK_FALSE(
            store.software_catalog(yuzu::server::SoftwareCatalogQuery{.q = "x"}).has_value());
        CHECK_FALSE(store
                        .software_versions(yuzu::server::SoftwareVersionsQuery{
                            .name = "x", .ecosystem = "brew"})
                        .has_value());
        CHECK_FALSE(store.catalog_rollup_meta().has_value());
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

namespace {
// Holds the per-agent ingest advisory lock on its own pooled connection until destroyed (an
// in-flight ingest on another replica).
struct HeldIngestLock {
    PgPool::Lease lease;
    HeldIngestLock(PgPool& pool, const std::string& agent) : lease(pool.acquire()) {
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
                PGRES_COMMAND_OK);
        REQUIRE(pg::exec_params(
                    lease.get(),
                    "SELECT pg_advisory_xact_lock(hashtextextended('software_inventory_store:' || "
                    "$1, 0))",
                    std::vector<std::string>{agent})
                    .status() == PGRES_TUPLES_OK);
    }
    void release() {
        if (!std::exchange(held_, false))
            return;
        pg::exec_params(lease.get(), "ROLLBACK", std::vector<std::string>{});
    }
    ~HeldIngestLock() { release(); }

private:
    bool held_{true};
};
} // namespace

TEST_CASE("delete_agent waits on the per-agent ingest lock, gives up inside its bound, and erases "
          "once the lock is free",
          "[pg][software_inventory]") {
    // Without the lock, delete_agent would commit straight past an in-flight ingest and the
    // ingest's rows would resurrect the device afterwards (a ghost). Held lock => the delete
    // cannot commit and nothing is erased; released => it erases.
    SWINV_SHARED(store, pool);

    const std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                             {"Firefox", "120", "Mozilla", ""}};
    REQUIRE(store.apply_installed_software("agent-lock",
                                           SoftwareInventoryStore::canonical_hash(rows), rows,
                                           1000) == InventoryIngestOutcome::kStored);

    HeldIngestLock held(pool, "agent-lock");
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_FALSE(store.delete_agent("agent-lock")); // lock_timeout, not an unbounded wait
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(9));
    {
        auto during = store.get_agent_software("agent-lock");
        REQUIRE(during.has_value());
        CHECK(during->size() == 2); // the failed delete rolled back: rows intact
    }

    held.release();
    CHECK(store.delete_agent("agent-lock"));
    auto after = store.get_agent_software("agent-lock");
    REQUIRE(after.has_value());
    CHECK(after->empty());
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

TEST_CASE("refresh_catalog_rollup rebuilds title_triples with exact distinct triples and device counts",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    // git/Git SCM/brew on d1+d2 (d1 twice via two versions), git/Git SCM/rpm on d3, and the
    // same name with a different publisher on d3: three distinct triples.
    put(store, "d1",
        Rows{ent("git", "2.40", "Git SCM", "package", "brew", kSrcPkg),
             ent("git", "2.41", "Git SCM", "package", "brew", kSrcPkg)});
    put(store, "d2", Rows{ent("git", "2.39", "Git SCM", "package", "brew", kSrcPkg)});
    put(store, "d3",
        Rows{ent("git", "2.41", "Git SCM", "package", "rpm", kSrcPkg),
             ent("git", "1.0", "Other", "package", "rpm", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());

    auto r = run_sql(pool, "SELECT name, publisher, ecosystem, device_count "
                           "FROM software_inventory_store.title_triples "
                           "ORDER BY publisher, ecosystem");
    REQUIRE(PQntuples(r.get()) == 3);
    CHECK(std::string(PQgetvalue(r.get(), 0, 1)) == "Git SCM");
    CHECK(std::string(PQgetvalue(r.get(), 0, 2)) == "brew");
    CHECK(std::string(PQgetvalue(r.get(), 0, 3)) == "2"); // d1 once + d2, not three rows
    CHECK(std::string(PQgetvalue(r.get(), 1, 2)) == "rpm");
    CHECK(std::string(PQgetvalue(r.get(), 1, 3)) == "1");
    CHECK(std::string(PQgetvalue(r.get(), 2, 1)) == "Other");

    // A second refresh replaces the table rather than appending.
    REQUIRE(store.refresh_catalog_rollup());
    CHECK(count_rows(pool, "title_triples") == 3);
}

TEST_CASE("catalogue rollup: origin labels are not publishers and never beat a declared vendor",
          "[pg][software_inventory][vendor]") {
    SWINV_SHARED(store, pool);
    // wget: one device with a declared vendor, one with only a label (the label sorts AFTER an
    // upper-case vendor, so a plain max(publisher) would pick it). curl: label only.
    put(store, "v1", Rows{ent("wget", "1.24", "GNU Project", "pkg", "deb", kSrcApps)});
    put(store, "v2", Rows{ent("wget", "1.24", "via:brew", "pkg", "brew", kSrcPkg),
                          ent("curl", "8.0", "via:brew", "pkg", "brew", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());

    // total_publishers counts declared vendors only.
    const auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->total_publishers == 1);

    const auto cat = store.software_catalog({});
    REQUIRE(cat.has_value());
    std::map<std::string, std::string> pub;
    for (const auto& r : *cat)
        pub[r.name] = r.publisher;
    CHECK(pub["wget"] == "GNU Project"); // the declared vendor wins
    CHECK(pub["curl"] == "via:brew");    // no vendor anywhere: the label is shown
}

TEST_CASE("catalogue search matches the displayed representative publisher on the host and fleet paths",
          "[pg][software_inventory][vendor]") {
    SWINV_SHARED(store, pool);
    // One device carries wget through TWO rows: a declared vendor and an origin label. The label
    // sorts after the capitalised vendor, so a plain max(publisher) would show (and search) the
    // label; the displayed publisher is the vendor, and a search for the vendor must find it.
    put(store, "h1",
        Rows{ent("wget", "1.24", "GNU Project", "pkg", "deb", kSrcApps),
             ent("wget", "1.24", "via:brew", "pkg", "brew", kSrcPkg)});
    put(store, "h2", Rows{ent("curl", "8.0", "via:brew", "pkg", "brew", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());

    const auto names = [&](SoftwareCatalogQuery q) {
        const auto rows = store.software_catalog(q);
        REQUIRE(rows.has_value());
        std::set<std::string> out;
        for (const auto& r : *rows)
            out.insert(r.name);
        return out;
    };
    for (const std::string agent : {"h1", ""}) { // host path, then fleet path
        INFO("agent_id=" << agent);
        SoftwareCatalogQuery q;
        q.agent_id = agent;
        q.q = "GNU";
        CHECK(names(q) == std::set<std::string>{"wget"}); // the declared vendor is searchable
        q.q = "via:";
        // the label is searchable only where it is what the title shows
        CHECK(names(q) == (agent.empty() ? std::set<std::string>{"curl"} : std::set<std::string>{}));
    }
    // ...and the shown publisher is the vendor on the host path too.
    SoftwareCatalogQuery hq;
    hq.agent_id = "h1";
    const auto host = store.software_catalog(hq);
    REQUIRE(host.has_value());
    REQUIRE(host->size() == 1);
    CHECK((*host)[0].publisher == "GNU Project");
}

TEST_CASE("refresh_catalog_rollup leaves an over-wide triple out of title_triples and still succeeds",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    // Ingest clamps each field to 1024 bytes but not their sum. Three incompressible 1024-byte
    // fields exceed the btree entry limit (~2704 bytes) of title_triples' primary key: without
    // the size cap in the rollup INSERT the whole refresh would fail ("index row size ...
    // exceeds btree version 4 maximum") and freeze the catalogue. Deterministic noise, because a
    // repeated character would compress below the limit and not reproduce the failure.
    const auto noise = [](std::uint32_t seed) {
        std::mt19937 gen{seed};
        std::string out;
        for (int i = 0; i < 1024; ++i)
            out += static_cast<char>(33 + gen() % 94);
        return out;
    };
    put(store, "d1",
        Rows{ent(noise(1), "1.0", noise(2), "package", noise(3), kSrcPkg),
             ent("small-title", "1.0", "Pub", "package", "rpm", kSrcPkg)});
    REQUIRE(store.refresh_catalog_rollup());

    // Control: the wide row was ingested, so only the cap kept it out of title_triples.
    CHECK(count_rows(pool, "installed_software") == 2);
    CHECK(count_rows(pool, "title_triples") == 1);
    auto r = run_sql(pool, "SELECT name FROM software_inventory_store.title_triples");
    REQUIRE(PQntuples(r.get()) == 1);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "small-title");
    // The catalogue itself refreshed (it does not depend on the cap).
    auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at > 0);
}

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

TEST_CASE("q is literal and title-level and clamped", "[pg][software_inventory]") {
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
    // Invalid UTF-8 is scrubbed before the clamp: a bare invalid byte is a value (not a degrade
    // -> nullopt via PG 22021), and an all-continuation term filters instead of clamping to ""
    // and returning the whole catalogue.
    SoftwareCatalogQuery bad;
    bad.q = "\xFF";
    auto bad_page = store.software_catalog(bad);
    REQUIRE(bad_page.has_value());
    CHECK(bad_page->empty());
    SoftwareCatalogQuery conts;
    conts.q = std::string(200, '\x80');
    auto conts_page = store.software_catalog(conts);
    REQUIRE(conts_page.has_value());
    CHECK(conts_page->empty()); // filtered, not the unfiltered catalogue
    SoftwareFleetQuery bad_fleet;
    bad_fleet.q = "\xFF";
    CHECK(store.query_software(bad_fleet).has_value());
    SoftwareFleetQuery conts_fleet;
    conts_fleet.q = std::string(200, '\x80'); // same scrub-before-clamp order on this read
    auto conts_fleet_rows = store.query_software(conts_fleet);
    REQUIRE(conts_fleet_rows.has_value());
    CHECK(conts_fleet_rows->empty());
    // An embedded NUL would truncate the bound text at the first NUL (a NUL-first q binding as ""
    // and matching everything); it is scrubbed to U+FFFD on both reads, so each term filters.
    SoftwareCatalogQuery nul_cat;
    nul_cat.q = std::string("\0foo", 4);
    CHECK(names(nul_cat).empty());
    SoftwareFleetQuery nul_fleet;
    nul_fleet.q = std::string("\0foo", 4);
    auto nul_rows = store.query_software(nul_fleet);
    REQUIRE(nul_rows.has_value());
    CHECK(nul_rows->empty());
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

TEST_CASE("catalogue keyset walk is exact and bounded; rejects a negative cursor",
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

TEST_CASE("software_versions fleet/filtered/host paths carry the fleet newest mark",
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
    values += "(''),('zypper')"; // snap is a published spelling; zypper is not
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
    REQUIRE(store.refresh_catalog_rollup([&] {
        if (++polls == 6)
            put(store, "late-dev", Rows{ent("LateTitle", "9", "Late", "package", "brew", kSrcPkg)});
        return false;
    }));
    REQUIRE(polls >= 6); // fails loudly if the poll sequence ever shrinks below the barrier
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
    for (int i = 0; i < kTitles; ++i) {
        const auto nm = std::format("t{:05}", i);
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
    SWINV_SHARED(store, pool);
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
    constexpr const char* kSentinelRowSql =
        "SELECT to_jsonb(i)::text FROM software_inventory_store.installed_software i "
        "WHERE agent_id = 'sentinel-dev'";
    const std::string sentinel_row = [&] {
        auto r = run_sql(pool, kSentinelRowSql);
        REQUIRE(PQntuples(r.get()) == 1);
        return std::string(PQgetvalue(r.get(), 0, 0));
    }();
    auto check_sentinels = [&] {
        auto src = run_sql(pool, kSentinelRowSql);
        REQUIRE(PQntuples(src.get()) == 1);
        CHECK(std::string(PQgetvalue(src.get(), 0, 0)) == sentinel_row); // whole-row identity
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
    {
        // Rollback posture: an OLD binary's refresh INSERT names no grain column. The v8
        // DEFAULT lands it as the title grain (7) instead of failing NOT NULL.
        exec("INSERT INTO software_inventory_store.catalog_rollup (name, publisher, "
             "device_count, version_count) VALUES ('OldShapeTitle', 'p', 3, 1)");
        auto r = run_sql(pool, "SELECT grain FROM software_inventory_store.catalog_rollup "
                               "WHERE name = 'OldShapeTitle'");
        REQUIRE(PQntuples(r.get()) == 1);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "7");
        exec("DELETE FROM software_inventory_store.catalog_rollup WHERE name = 'OldShapeTitle'");
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
    {
        // Rollback posture, the whole loop: the v7 binary's refresh DML, meta upsert and
        // grain-less read, verbatim, against the v8 tables (the fixture is the source data).
        // run_sql REQUIRES each statement to succeed.
        run_sql(pool, "DELETE FROM software_inventory_store.catalog_rollup");
        run_sql(pool, "INSERT INTO software_inventory_store.catalog_rollup "
                      "(name, publisher, device_count, version_count) "
                      "SELECT name, max(publisher), count(DISTINCT agent_id), "
                      "count(DISTINCT version) "
                      "FROM software_inventory_store.installed_software GROUP BY name");
        run_sql(pool, "DELETE FROM software_inventory_store.version_rollup");
        run_sql(pool, "INSERT INTO software_inventory_store.version_rollup "
                      "(name, version, device_count) "
                      "SELECT name, version, count(DISTINCT agent_id) "
                      "FROM software_inventory_store.installed_software GROUP BY name, version");
        run_sql(pool,
                "INSERT INTO software_inventory_store.catalog_rollup_meta "
                "(id, refreshed_at, total_titles, total_devices) "
                "VALUES (1, EXTRACT(EPOCH FROM now())::bigint, "
                "  (SELECT count(*) FROM software_inventory_store.catalog_rollup), "
                "  (SELECT count(DISTINCT agent_id) FROM "
                "software_inventory_store.installed_software)) "
                "ON CONFLICT (id) DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at, "
                "  total_titles = EXCLUDED.total_titles, total_devices = EXCLUDED.total_devices "
                "RETURNING id");
        auto titles = run_sql(pool, "SELECT count(DISTINCT name) FROM "
                                    "software_inventory_store.installed_software");
        const std::int64_t n_titles = std::stoll(PQgetvalue(titles.get(), 0, 0));
        REQUIRE(n_titles > 1);
        CHECK(count_rows(pool, "catalog_rollup") == n_titles); // one row per title
        auto off_grain = run_sql(pool, "SELECT count(*) FROM "
                                       "software_inventory_store.catalog_rollup WHERE grain <> 7");
        CHECK(std::string(PQgetvalue(off_grain.get(), 0, 0)) == "0");
        auto meta_row = run_sql(pool, "SELECT total_titles, refreshed_at FROM "
                                      "software_inventory_store.catalog_rollup_meta WHERE id = 1");
        REQUIRE(PQntuples(meta_row.get()) == 1);
        CHECK(std::stoll(PQgetvalue(meta_row.get(), 0, 0)) == n_titles);
        CHECK(std::stoll(PQgetvalue(meta_row.get(), 0, 1)) > 0);
        auto old_read = run_sql(pool, "SELECT name, publisher, device_count, version_count "
                                      "FROM software_inventory_store.catalog_rollup "
                                      "ORDER BY device_count DESC, name");
        CHECK(PQntuples(old_read.get()) == n_titles);
    }
}

// ── software_catalog_totals ────────────────────────────────────────

TEST_CASE("catalogue totals: unfiltered totals equal the refreshed meta", "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    const auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    const auto t = store.software_catalog_totals({});
    REQUIRE(t.has_value());
    CHECK(t->titles == meta->total_titles);
    CHECK(t->installs == meta->total_installs);
    // d1 carries two titles, so installs (4) exceeds distinct devices (3): sums per title.
    CHECK(t->titles == 2);
    CHECK(t->installs == 4);
}

TEST_CASE("catalogue totals: filtered totals equal the page-walk over the same filters",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    for (const SoftwareCatalogQuery& base :
         {SoftwareCatalogQuery{.q = "git"}, SoftwareCatalogQuery{.ecosystem = "brew"},
          SoftwareCatalogQuery{.source = kSrcApps},
          SoftwareCatalogQuery{.kind = "package", .versions_min = 2},
          // host path: the same predicate, one device
          SoftwareCatalogQuery{.agent_id = "d1"},
          SoftwareCatalogQuery{.kind = "package", .agent_id = "d1"},
          SoftwareCatalogQuery{.ecosystem = "brew", .agent_id = "d1"},
          SoftwareCatalogQuery{.source = kSrcApps, .agent_id = "d1"},
          SoftwareCatalogQuery{.q = "chrom", .agent_id = "d1"}, SoftwareCatalogQuery{}}) {
        std::int64_t titles = 0, installs = 0;
        std::optional<SoftwareCatalogCursor> after;
        for (int page = 0; page < 10; ++page) {
            auto q = base;
            q.limit = 1;
            q.after = after;
            auto rows = store.software_catalog(q);
            REQUIRE(rows.has_value());
            if (rows->empty())
                break;
            titles += static_cast<std::int64_t>(rows->size());
            for (const auto& r : *rows)
                installs += r.device_count;
            after = SoftwareCatalogCursor{rows->back().device_count, rows->back().name};
        }
        CAPTURE(base.q, base.ecosystem, base.kind, base.source, base.agent_id, base.versions_min);
        REQUIRE(titles > 0); // a zero == zero comparison would pass for any totals bug
        const auto t = store.software_catalog_totals(base);
        REQUIRE(t.has_value());
        CHECK(t->titles == titles);
        CHECK(t->installs == installs);
        // limit/after are ignored by totals
        auto paged = base;
        paged.limit = 1;
        paged.after = SoftwareCatalogCursor{1, "zzz"};
        CHECK(store.software_catalog_totals(paged)->titles == titles);
    }
    // The filter really narrows: ecosystem=brew drops the rpm-only/macos-only cases.
    CHECK(store.software_catalog_totals({.ecosystem = "brew"})->installs == 2);
    CHECK(store.software_catalog_totals({.q = "git"})->installs == 3);
    // source=installed_apps.list_inventory: git's pkgutil copy (d1) + Chrome (d1).
    CHECK(store.software_catalog_totals({.source = kSrcApps})->installs == 2);
    CHECK(store.software_catalog_totals({.source = kSrcApps, .agent_id = "d1"})->titles == 2);
    CHECK(store.software_catalog_totals({.source = kSrcPkg, .agent_id = "d1"})->titles == 1);
}

TEST_CASE("catalogue totals + host keyset walk (host `after` lives in HAVING)",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    seed_grain_fixture(store);
    SoftwareCatalogQuery q;
    q.agent_id = "d1";
    const auto t = store.software_catalog_totals(q);
    REQUIRE(t.has_value());
    CHECK(t->titles == 2);
    CHECK(t->installs == 2); // one device: installs == titles by construction

    std::vector<std::string> walked;
    std::optional<SoftwareCatalogCursor> after;
    for (int page = 0; page < 5; ++page) {
        auto pq = q;
        pq.limit = 1;
        pq.after = after;
        auto rows = store.software_catalog(pq);
        REQUIRE(rows.has_value());
        if (rows->empty())
            break;
        walked.push_back(rows->front().name);
        after = SoftwareCatalogCursor{rows->front().device_count, rows->front().name};
    }
    CHECK(walked == std::vector<std::string>{"Chrome", "git"}); // no duplicate, no skip

    q.versions_min = 2; // d1 carries one version of each title
    CHECK(store.software_catalog_totals(q)->titles == 0);
    q.versions_min = 0;
    q.agent_id = "nobody";
    CHECK(store.software_catalog_totals(q)->titles == 0);
}

TEST_CASE("catalogue totals degrade to nullopt and never a zero", "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    SECTION("schema dropped under an open store") {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        SoftwareInventoryStore store{pool};
        REQUIRE(store.is_open());
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        CHECK_FALSE(store.software_catalog_totals({}).has_value());
    }
    SECTION("pool starved (the only lease is held)") {
        PgPool one{{.conninfo = db.dsn(), .size = 1}};
        REQUIRE(one.valid());
        SoftwareInventoryStore store{one};
        REQUIRE(store.is_open());
        auto held = one.acquire();
        CHECK_FALSE(store.software_catalog_totals({}).has_value());
    }
    SECTION("store not open") {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(),
                                    "DELETE FROM public.schema_meta WHERE store = "
                                    "'software_inventory_store'",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        SoftwareInventoryStore store{pool}; // the v1 re-run over live tables fails the open
        REQUIRE_FALSE(store.is_open());
        CHECK_FALSE(store.software_catalog_totals({}).has_value());
        CHECK_FALSE(store.software_catalog_totals({.agent_id = "d1"}).has_value());
    }
}

TEST_CASE("source_last_seen_bulk returns the receipt time per agent and omits the unreported",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software("agent-a", h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("agent-b", h, rows, 2000) ==
            InventoryIngestOutcome::kStored);
    auto b_before = store.source_last_seen("agent-b", "installed_software");
    REQUIRE(b_before.has_value());
    // A hash-only touch never regresses last_seen.
    REQUIRE(store.apply_installed_software("agent-b", h, std::nullopt, 3000) ==
            InventoryIngestOutcome::kTouched);

    auto got = store.source_last_seen_bulk("installed_software",
                                           {"agent-a", "agent-b", "agent-never"});
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2);
    // last_seen is the SERVER receipt time (#1685), never the caller-supplied timestamp.
    CHECK(got->at("agent-a") > 1'000'000'000); // a real wall-clock epoch, not the 1000/2000/3000 passed in
    CHECK(got->at("agent-b") >= *b_before); // the touch never moves it backwards
    CHECK_FALSE(got->contains("agent-never")); // absent, never a 0
    // Same datum the Hardware record shows, read one device at a time.
    for (const char* id : {"agent-a", "agent-b"}) {
        auto one = store.source_last_seen(id, "installed_software");
        REQUIRE(one.has_value());
        CHECK(got->at(id) == *one);
    }
    // Another source is a different row set.
    auto other = store.source_last_seen_bulk("device_ci", {"agent-a"});
    REQUIRE(other.has_value());
    CHECK(other->empty());
}

TEST_CASE("source_last_seen_bulk: empty inputs are a precondition miss, not a degrade",
          "[pg][software_inventory]") {
    SWINV_SHARED(store, pool);
    auto no_ids = store.source_last_seen_bulk("installed_software", {});
    REQUIRE(no_ids.has_value());
    CHECK(no_ids->empty());
    auto no_source = store.source_last_seen_bulk("", {"agent-a"});
    REQUIRE(no_source.has_value());
    CHECK(no_source->empty());
}

TEST_CASE("source_last_seen_bulk degrades to nullopt, never an empty map", "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    SECTION("schema dropped under an open store") {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        SoftwareInventoryStore store{pool};
        REQUIRE(store.is_open());
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        CHECK_FALSE(store.source_last_seen_bulk("installed_software", {"agent-a"}).has_value());
    }
    SECTION("pool starved (the only lease is held)") {
        PgPool one{{.conninfo = db.dsn(), .size = 1}};
        REQUIRE(one.valid());
        SoftwareInventoryStore store{one};
        REQUIRE(store.is_open());
        auto held = one.acquire();
        CHECK_FALSE(store.source_last_seen_bulk("installed_software", {"agent-a"}).has_value());
    }
}

TEST_CASE("source_last_seen_bulk: a store that never opened is a degrade", "[pg][software_inventory]") {
    // DDL, so a private template clone (the macro drops it): nothing to restore if a REQUIRE throws.
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // Rename a column the open-time projection probes, so a store fails closed (the same
    // technique the schema-guard test uses).
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "ALTER TABLE software_inventory_store.inventory_state RENAME COLUMN last_seen TO "
            "last_seen_gone",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore broken{pool};
    REQUIRE_FALSE(broken.is_open());
    CHECK_FALSE(broken.source_last_seen_bulk("installed_software", {"agent-a"}).has_value());
}

// ── Name-pattern reads (the /crypto slice's generic store methods) ───────────

namespace {

SoftwareEntry np_entry(std::string name, std::string version, std::string ecosystem = "deb") {
    SoftwareEntry e;
    e.name = std::move(name);
    e.version = std::move(version);
    e.kind = "package";
    e.ecosystem = std::move(ecosystem);
    return e;
}

void np_seed(SoftwareInventoryStore& store, const std::string& agent,
             std::vector<SoftwareEntry> rows) {
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software(agent, h, std::move(rows), 1000) ==
            InventoryIngestOutcome::kStored);
}

// openssl: a1 (libssl3 + openssl, same version), a2, a3 (older); gnutls: a4; a5 carries neither.
void np_seed_fleet(SoftwareInventoryStore& store) {
    np_seed(store, "a1", {np_entry("libssl3", "3.0.13"), np_entry("openssl", "3.0.13")});
    np_seed(store, "a2", {np_entry("LibSSL3", "3.0.13")});
    np_seed(store, "a3", {np_entry("libssl3", "1.1.1", "rpm")});
    np_seed(store, "a4", {np_entry("libgnutls30", "3.7.9")});
    np_seed(store, "a5", {np_entry("curl", "8.0")});
}

yuzu::server::NamePatternQuery np_query() {
    yuzu::server::NamePatternQuery q;
    q.patterns = {"libssl%", "openssl", "libgnutls%"};
    q.labels = {"openssl", "openssl", "gnutls"};
    return q;
}

// First 3 literal characters (unescaped, lowercase ASCII) of a LIKE pattern: the lead the store
// pre-filters on. Stops at the first unescaped wildcard.
std::string np_lead(const std::string& pat) {
    std::string lit;
    for (std::size_t i = 0; i < pat.size() && lit.size() < 3; ++i) {
        if (pat[i] == '\\' && i + 1 < pat.size())
            ++i;
        else if (pat[i] == '%' || pat[i] == '_')
            break;
        lit.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(pat[i]))));
    }
    return lit;
}

template <class Q>
void np_fill_leads(Q& q) {
    if (q.leads.size() == q.patterns.size())
        return;
    q.leads.clear();
    for (const auto& p : q.patterns)
        q.leads.push_back(np_lead(p));
}

// Force the catalogue's age on the DB clock (the freshness test uses the same clock).
void np_set_catalogue_age(PgPool& pool, long long age_seconds) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "UPDATE software_inventory_store.catalog_rollup_meta SET refreshed_at = "
        "extract(epoch FROM now())::bigint - $1::bigint WHERE id = 1",
        std::vector<std::string>{std::to_string(age_seconds)});
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

// Step 1 takes its names from the catalogue while it is FRESH and from a live skip-scan
// otherwise. Every read in these tests first refreshes the catalogue (the seeding helpers do
// not) so it reads the catalogue path; `stale` then ages it past kCatalogueFreshSeconds so the
// same data is read down the LIVE path. The source reported must match the one requested.
std::optional<yuzu::server::NamePatternRollup> np_rollup(SoftwareInventoryStore& store,
                                                         yuzu::server::NamePatternQuery q,
                                                         bool stale = false) {
    np_fill_leads(q);
    REQUIRE(store.refresh_catalog_rollup());
    if (stale)
        np_set_catalogue_age(*swinv_shared().pool, yuzu::server::kCatalogueFreshSeconds + 60);
    auto r = store.software_name_pattern_rollup(q);
    if (r && q.agent_ids && q.agent_ids->empty())
        return r; // deny-all: no SQL, no source
    if (r)
        CHECK((r->names_as_of == 0) == stale);
    return r;
}

std::optional<yuzu::server::NamePatternDevicesPage>
np_devices(SoftwareInventoryStore& store, yuzu::server::NamePatternDevicesQuery q,
           bool stale = false) {
    np_fill_leads(q);
    REQUIRE(store.refresh_catalog_rollup());
    if (stale)
        np_set_catalogue_age(*swinv_shared().pool, yuzu::server::kCatalogueFreshSeconds + 60);
    auto r = store.software_name_pattern_devices(q);
    if (r && !(q.agent_ids && q.agent_ids->empty()))
        CHECK((r->names_as_of == 0) == stale);
    return r;
}

std::int64_t np_label(const yuzu::server::NamePatternRollup& r, std::string_view label) {
    for (const auto& l : r.label_counts)
        if (l.label == label)
            return l.device_count;
    return -1;
}

} // namespace

TEST_CASE("name-pattern rollup: per-version counts and one device counts once per label",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    np_seed_fleet(store);

    auto r = np_rollup(store, np_query());
    REQUIRE(r.has_value());
    CHECK_FALSE(r->truncated);
    // a1 carries libssl3 AND openssl: still ONE device for the openssl label.
    CHECK(np_label(*r, "openssl") == 3);
    CHECK(np_label(*r, "gnutls") == 1);
    CHECK(r->total_devices == 4);

    const yuzu::server::NamePatternRollupRow* v3013 = nullptr;
    const yuzu::server::NamePatternRollupRow* v111 = nullptr;
    for (const auto& row : r->rows) {
        if (row.label == "openssl" && row.version == "3.0.13" && row.ecosystem == "deb")
            v3013 = &row;
        if (row.label == "openssl" && row.version == "1.1.1" && row.ecosystem == "rpm")
            v111 = &row;
    }
    REQUIRE(v3013);
    CHECK(v3013->device_count == 2); // a1, a2
    CHECK(std::ranges::find(v3013->names, "libssl3") != v3013->names.end());
    CHECK(std::ranges::find(v3013->names, "openssl") != v3013->names.end());
    // matching is case-insensitive: a2's "LibSSL3" is reported under its stored spelling
    CHECK(std::ranges::find(v3013->names, "LibSSL3") != v3013->names.end());
    REQUIRE(v111);
    CHECK(v111->device_count == 1);
    CHECK(r->rows.size() == 3); // (openssl,3.0.13,deb) (openssl,1.1.1,rpm) (gnutls,3.7.9,deb)
    CHECK(r->rows.front().device_count == 2); // most devices first

    SECTION("ecosystem filter narrows every count") {
        auto q = np_query();
        q.ecosystem = "rpm";
        auto f = np_rollup(store, q);
        REQUIRE(f.has_value());
        CHECK(np_label(*f, "openssl") == 1);
        CHECK(np_label(*f, "gnutls") == -1);
        CHECK(f->total_devices == 1);
    }

    SECTION("a pattern set matching nothing is an honest zero, not a degrade") {
        yuzu::server::NamePatternQuery q;
        q.patterns = {"nosuchpkg%"};
        q.labels = {"x"};
        auto f = np_rollup(store, q);
        REQUIRE(f.has_value());
        CHECK(f->rows.empty());
        CHECK(f->label_counts.empty());
        CHECK(f->total_devices == 0);
    }

    SECTION("mismatched parallel arrays are refused, not guessed") {
        auto q = np_query();
        q.labels.pop_back();
        CHECK_FALSE(np_rollup(store, q).has_value());
    }

    SECTION("a lead that is not exactly kNamePatternLeadChars long is refused (a caller bug)") {
        for (const char* bad : {"li", "libs", ""}) {
            auto q = np_query();
            np_fill_leads(q);
            q.leads[0] = bad;
            CHECK_FALSE(store.software_name_pattern_rollup(q).has_value());
            yuzu::server::NamePatternDevicesQuery dq;
            dq.patterns = q.patterns;
            dq.leads = q.leads;
            dq.limit = 10;
            CHECK_FALSE(store.software_name_pattern_devices(dq).has_value());
        }
    }
}

TEST_CASE("name-pattern rollup: scope is pushed before the grouping",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    np_seed_fleet(store);

    auto q = np_query();
    q.agent_ids = std::vector<std::string>{"a1", "a3", "a5"};
    auto r = np_rollup(store, q);
    REQUIRE(r.has_value());
    CHECK(np_label(*r, "openssl") == 2); // a2 is out of scope
    CHECK(np_label(*r, "gnutls") == -1); // a4 is out of scope
    CHECK(r->total_devices == 2);
    for (const auto& row : r->rows)
        CHECK(row.device_count <= 2);

    // present-empty = deny-all: an empty VALUE
    q.agent_ids = std::vector<std::string>{};
    auto none = np_rollup(store, q);
    REQUIRE(none.has_value());
    CHECK(none->rows.empty());
    CHECK(none->total_devices == 0);

    // coverage denominator (the rollup's own subquery - the single definition of "reporting")
    // follows the same scope rule
    CHECK(r->reporting_agents == 3);
    q.agent_ids = std::vector<std::string>{"a1", "zz"};
    auto one = np_rollup(store, q);
    REQUIRE(one.has_value());
    CHECK(one->reporting_agents == 1);
    q.agent_ids = std::nullopt;
    auto all = np_rollup(store, q);
    REQUIRE(all.has_value());
    CHECK(all->reporting_agents == 5);
}

TEST_CASE("name-pattern reads: LIKE metacharacters in a pattern are literal when escaped",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    np_seed(store, "e1", {np_entry("a_b", "1"), np_entry("axb", "1"), np_entry("100%x", "1"),
                          np_entry("100zx", "1"), np_entry("a\\b", "1")});

    yuzu::server::NamePatternQuery q;
    q.patterns = {"a\\_b", "100\\%x", "a\\\\b"};
    q.labels = {"lit", "lit", "lit"};
    auto r = np_rollup(store, q);
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    std::vector<std::string> names = r->rows[0].names;
    std::ranges::sort(names);
    CHECK(names == std::vector<std::string>{"100%x", "a\\b", "a_b"}); // not axb / 100zx

    // an UNescaped underscore would be a wildcard: proves the escape is what keeps it literal.
    // (The 3-character lead is literal, so the wildcard sits after it.)
    np_seed(store, "e2", {np_entry("abcd", "1"), np_entry("abce", "1"), np_entry("abc", "1")});
    q.patterns = {"abc_"};
    q.labels = {"wild"};
    q.leads.clear();
    auto w = np_rollup(store, q);
    REQUIRE(w.has_value());
    REQUIRE(w->rows.size() == 1);
    std::vector<std::string> wn = w->rows[0].names;
    std::ranges::sort(wn);
    CHECK(wn == std::vector<std::string>{"abcd", "abce"}); // `_` matches exactly one char
}

TEST_CASE("name-pattern devices: keyset paging; filters and scope",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    np_seed_fleet(store);
    np_seed(store, "a6", {np_entry("libssl3", "")}); // the empty-version bucket

    yuzu::server::NamePatternDevicesQuery q;
    q.patterns = {"libssl%", "openssl"}; // a1 matches BOTH patterns on different rows

    SECTION("pages walk every row exactly once, in (agent_id, name, install_id) order") {
        q.limit = 2;
        std::vector<std::string> seen;
        int pages = 0;
        for (;;) {
            auto page = np_devices(store, q);
            REQUIRE(page.has_value());
            REQUIRE(page->rows.size() <= 2);
            for (const auto& r : page->rows)
                seen.push_back(r.agent_id + "/" + r.entry.name);
            ++pages;
            if (!page->has_more)
                break;
            const auto& last = page->rows.back();
            q.after = yuzu::server::SoftwareCursor{last.entry.name, last.agent_id, last.install_id};
            REQUIRE(pages < 10);
        }
        CHECK(seen == std::vector<std::string>{"a1/libssl3", "a1/openssl", "a2/LibSSL3",
                                               "a3/libssl3", "a6/libssl3"});
        CHECK(pages == 3);
    }

    SECTION("a row matching two patterns is returned once") {
        q.patterns = {"libssl%", "lib%"};
        auto page = np_devices(store, q);
        REQUIRE(page.has_value());
        CHECK(std::ranges::count_if(page->rows, [](const auto& r) { return r.agent_id == "a1"; }) == 1);
    }

    SECTION("version filter: exact, and present-empty is the empty bucket") {
        q.version = "1.1.1";
        auto page = np_devices(store, q);
        REQUIRE(page.has_value());
        REQUIRE(page->rows.size() == 1);
        CHECK(page->rows[0].agent_id == "a3");
        CHECK(page->rows[0].entry.ecosystem == "rpm");
        CHECK(page->rows[0].entry.kind == "package");

        q.version = "";
        page = np_devices(store, q);
        REQUIRE(page.has_value());
        REQUIRE(page->rows.size() == 1);
        CHECK(page->rows[0].agent_id == "a6");
    }

    SECTION("ecosystem filter") {
        q.ecosystem = "rpm";
        auto page = np_devices(store, q);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 1);
    }

    SECTION("scope: a set narrows the rows AND keeps pages full; empty = deny-all") {
        q.agent_ids = std::vector<std::string>{"a2", "a3", "a4"};
        q.limit = 2;
        auto page = np_devices(store, q);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 2);
        CHECK_FALSE(page->has_more); // a2, a3 only (a4 is gnutls)
        for (const auto& r : page->rows)
            CHECK(r.agent_id != "a1");

        q.agent_ids = std::vector<std::string>{};
        page = np_devices(store, q);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK_FALSE(page->has_more);
    }
}

TEST_CASE("name-pattern rollup: the version-row cap sets truncated; never drops silently",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    std::vector<SoftwareEntry> rows;
    const int n = yuzu::server::kNamePatternRollupRowCap + 5;
    for (int i = 0; i < n; ++i)
        rows.push_back(np_entry("libssl3", "v" + std::to_string(i)));
    np_seed(store, "big", std::move(rows));

    yuzu::server::NamePatternQuery q;
    q.patterns = {"libssl%"};
    q.labels = {"openssl"};
    auto r = np_rollup(store, q);
    REQUIRE(r.has_value());
    CHECK(r->truncated);
    CHECK(r->rows.size() == static_cast<std::size_t>(yuzu::server::kNamePatternRollupRowCap));
    // the totals still count the whole population, not the capped rows
    CHECK(np_label(*r, "openssl") == 1);
    CHECK(r->total_devices == 1);
}

namespace {

// Run one statement on a leased connection and return column 0 of every row.
std::vector<std::string> np_column0(PgPool& pool, const std::string& sql,
                                    const std::vector<std::string>& params = {}) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    REQUIRE((r.status() == PGRES_TUPLES_OK || r.status() == PGRES_COMMAND_OK));
    std::vector<std::string> out;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        out.emplace_back(PQgetvalue(r.get(), i, 0));
    return out;
}

} // namespace

TEST_CASE("name-pattern step 1: only the chosen source runs - the catalogue scan when fresh; the "
          "index skip-scan when stale",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    // Enough rows and distinct names that the planner has a real choice.
    for (int a = 0; a < 60; ++a) {
        std::vector<SoftwareEntry> rows;
        for (int k = 0; k < 40; ++k)
            rows.push_back(np_entry("pkg-" + std::to_string((a * 7 + k) % 300), "1." + std::to_string(k)));
        rows.push_back(np_entry("libssl3", "3.0"));
        np_seed(store, "plan-" + std::to_string(a), std::move(rows));
    }
    REQUIRE(store.refresh_catalog_rollup());
    np_column0(pool, "ANALYZE software_inventory_store.installed_software");
    np_column0(pool, "ANALYZE software_inventory_store.catalog_rollup");

    // EXPLAIN ANALYZE executes the SELECT, so "(never executed)" / loops=0 shows which source
    // the statement really ran. Same session: BEGIN / SET LOCAL / EXPLAIN / ROLLBACK, so the
    // planner setting cannot leak into the pool. seqscan off keeps the assertion about the
    // SHAPE the SQL permits, not about a tiny table's cost estimates.
    auto explain = [&](std::vector<std::string_view> pats = {"libssl%"},
                       std::vector<std::string_view> leads = {"lib"}, bool no_nestloop = false) {
        std::string plan;
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        const std::vector<std::string> none;
        // ROLLBACK on EVERY exit (a failed REQUIRE throws), so SET LOCAL and the open
        // transaction can never ride a pooled connection back into another test.
        struct RollbackGuard {
            PGconn* conn;
            ~RollbackGuard() { pg::exec_params(conn, "ROLLBACK", std::vector<std::string>{}); }
        };
        REQUIRE(pg::exec_params(lease.get(), "BEGIN", none).status() == PGRES_COMMAND_OK);
        const RollbackGuard rollback{lease.get()};
        REQUIRE(pg::exec_params(lease.get(), "SET LOCAL enable_seqscan = off", none).status() ==
                PGRES_COMMAND_OK);
        // The hash-join section pins the planner away from a nested loop the literal-lead form
        // would never choose anyway but a cost-estimate shift could: the non-literal
        // `length(p.lead)` form is NOT hashable, so it still nested-loops and a revert is caught.
        if (no_nestloop)
            REQUIRE(pg::exec_params(lease.get(), "SET LOCAL enable_nestloop = off", none).status() ==
                    PGRES_COMMAND_OK);
        const std::string sql =
            "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) " +
            SoftwareInventoryStore::name_pattern_matched_names_sql();
        pg::PgResult r = pg::exec_params(
            lease.get(), sql.c_str(),
            std::vector<std::string>{pg::to_text_array(pats), pg::to_text_array(leads)});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            plan += PQgetvalue(r.get(), i, 0);
            plan += '\n';
        }
        return plan;
    };
    // The plan lines that scan the given relation (matched by a substring of the node text).
    auto lines_with = [](const std::string& plan, std::string_view what) {
        std::vector<std::string> out;
        std::size_t pos = 0;
        while (pos < plan.size()) {
            auto nl = plan.find('\n', pos);
            if (nl == std::string::npos)
                nl = plan.size();
            const auto line = plan.substr(pos, nl - pos);
            if (line.find(what) != std::string::npos)
                out.push_back(line);
            pos = nl + 1;
        }
        return out;
    };
    auto all_never = [](const std::vector<std::string>& ls) {
        return std::ranges::all_of(
            ls, [](const std::string& l) { return l.find("never executed") != std::string::npos; });
    };

    SECTION("fresh catalogue: the catalogue is scanned, the skip-scan never executes") {
        const auto plan = explain();
        INFO(plan);
        const auto cat = lines_with(plan, "on catalog_rollup c"); // not catalog_rollup_meta
        const auto live = lines_with(plan, "installed_software_name_idx");
        REQUIRE_FALSE(cat.empty());
        REQUIRE_FALSE(live.empty()); // the skip-scan is planned ...
        CHECK_FALSE(all_never(cat)); // ... the catalogue is read ...
        CHECK(all_never(live));      // ... and the skip-scan is never executed
        CHECK(plan.find("Recursive Union") != std::string::npos);
    }

    // The lead comparison must stay a HASH join key: `left(name, <literal>)` is hashable, while
    // `left(name, length(p.lead))` is not, and Postgres then runs a nested loop of patterns x
    // distinct names (a fresh ~1M-name catalogue timed out where the literal form took ~0.3 s).
    SECTION("fresh catalogue: the lead join is a hash join on the literal-length prefix") {
        std::vector<std::string> owned_pats;
        std::vector<std::string> owned_leads;
        for (int i = 0; i < 20; ++i) {
            owned_leads.push_back("li" + std::to_string(i % 10));
            owned_pats.push_back(owned_leads.back() + "%");
        }
        owned_leads.push_back("lib");
        owned_pats.push_back("libssl%");
        const auto plan = explain({owned_pats.begin(), owned_pats.end()},
                                  {owned_leads.begin(), owned_leads.end()}, /*no_nestloop=*/true);
        INFO(plan);
        std::string server_version;
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult v = pg::exec_params(lease.get(), "SELECT version()",
                                             std::vector<std::string>{});
            REQUIRE(v.status() == PGRES_TUPLES_OK);
            server_version = PQgetvalue(v.get(), 0, 0);
        }
        INFO("server: " << server_version); // shown only if an assertion below fails
        const auto hash_cond = lines_with(plan, "Hash Cond");
        REQUIRE_FALSE(hash_cond.empty());
        CHECK(std::ranges::any_of(hash_cond, [](const std::string& l) {
            return l.find("left") != std::string::npos && l.find("lead") != std::string::npos;
        }));
        // The nested-loop form puts the lead comparison in a Join Filter.
        for (const auto& l : lines_with(plan, "Join Filter"))
            CHECK(l.find("left") == std::string::npos);
    }

    SECTION("stale catalogue: the skip-scan walks installed_software_name_idx, the catalogue scan "
            "never executes") {
        np_set_catalogue_age(pool, yuzu::server::kCatalogueFreshSeconds + 60);
        const auto plan = explain();
        INFO(plan);
        const auto cat = lines_with(plan, "on catalog_rollup c"); // not catalog_rollup_meta
        const auto live = lines_with(plan, "installed_software_name_idx");
        REQUIRE_FALSE(cat.empty());
        REQUIRE_FALSE(live.empty());
        CHECK(all_never(cat));
        CHECK_FALSE(all_never(live));
    }

    SECTION("never built: also the live path") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(),
                                    "UPDATE software_inventory_store.catalog_rollup_meta SET "
                                    "refreshed_at = 0 WHERE id = 1",
                                    std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        const auto plan = explain();
        INFO(plan);
        CHECK(all_never(lines_with(plan, "on catalog_rollup c")));
        CHECK_FALSE(all_never(lines_with(plan, "installed_software_name_idx")));
    }
}

TEST_CASE("name-pattern rollup and drill: a confined scope keeps the OFFSET 0 fence and never "
          "seq-scans installed_software",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    // Many agents, each carrying a few matching names among many others, so the planner has a
    // real choice between driving from the matched names and scanning installed_software.
    for (int a = 0; a < 400; ++a) {
        std::vector<SoftwareEntry> rows;
        for (int k = 0; k < 60; ++k)
            rows.push_back(np_entry("pkg-" + std::to_string((a * 7 + k) % 1500), "1." + std::to_string(k)));
        rows.push_back(np_entry("libssl3", "3.0"));
        np_seed(store, "fence-" + std::to_string(a), std::move(rows));
    }
    // Agents that carry NONE of the family: the worst case for an unfenced drill (the planner
    // walks the agent index and filters every row of the table).
    for (int a = 0; a < 5; ++a) {
        std::vector<SoftwareEntry> rows;
        for (int k = 0; k < 60; ++k)
            rows.push_back(np_entry("pkg-" + std::to_string((a * 11 + k) % 1500), "1." + std::to_string(k)));
        np_seed(store, "nolib-" + std::to_string(a), std::move(rows));
    }
    REQUIRE(store.refresh_catalog_rollup());
    np_column0(pool, "ANALYZE software_inventory_store.installed_software");
    np_column0(pool, "ANALYZE software_inventory_store.catalog_rollup");

    // enable_seqscan is deliberately left ON: the assertion is about the plan the planner
    // CHOOSES for a confined scope, not the shape the SQL merely permits.
    auto explain = [&](const std::string& sql, const std::vector<std::string>& params) {
        std::string plan;
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        const std::vector<std::string> none;
        struct RollbackGuard {
            PGconn* conn;
            ~RollbackGuard() { pg::exec_params(conn, "ROLLBACK", std::vector<std::string>{}); }
        };
        REQUIRE(pg::exec_params(lease.get(), "BEGIN", none).status() == PGRES_COMMAND_OK);
        const RollbackGuard rollback{lease.get()};
        pg::PgResult r = pg::exec_params(lease.get(), ("EXPLAIN (COSTS OFF) " + sql).c_str(), params);
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            plan += PQgetvalue(r.get(), i, 0);
            plan += '\n';
        }
        return plan;
    };

    SECTION("rollup") {
        yuzu::server::NamePatternQuery q;
        q.patterns = {"libssl%"};
        q.labels = {"openssl"};
        q.leads = {"lib"};
        q.agent_ids = std::vector<std::string>{"fence-1", "fence-2", "fence-3", "fence-4", "fence-5"};
        q.ecosystem = "deb";
        const auto [sql, params] = SoftwareInventoryStore::name_pattern_rollup_sql(q);

        // The fence is in the SQL text: the name-driven join sits in an OFFSET 0 subquery and
        // the scope and ecosystem filters apply OUTSIDE it, before the GROUP BY.
        const auto off = sql.find("OFFSET 0) j");
        REQUIRE(off != std::string::npos);
        CHECK(sql.find("s.agent_id = ANY") == std::string::npos); // never inside the fence
        CHECK(sql.find("j.agent_id = ANY", off) != std::string::npos);

        const auto plan = explain(sql, params);
        INFO(plan);
        // "Subquery Scan on j" is the DISCRIMINATING assertion: without OFFSET 0 the planner
        // flattens the subquery and the node vanishes (verified by removing the fence). At this
        // data size the planner does not pick a seq scan even unfenced (it does at 15M rows,
        // 2.1 s), so the next line is a guard for the large case, not a proof at this size.
        CHECK(plan.find("Subquery Scan on j") != std::string::npos);
        CHECK(plan.find("Seq Scan on installed_software") == std::string::npos);
        CHECK(plan.find("installed_software_name_idx") != std::string::npos); // exact-name join
        CHECK(plan.find("installed_software_agent_idx") == std::string::npos); // not driven by scope
    }

    SECTION("drill, scope holding none of the family's devices") {
        yuzu::server::NamePatternDevicesQuery q;
        q.patterns = {"libssl%"};
        q.leads = {"lib"};
        q.agent_ids = std::vector<std::string>{"nolib-0", "nolib-1", "nolib-2"};
        q.ecosystem = "deb";
        q.limit = 100;
        const auto [sql, params] = SoftwareInventoryStore::name_pattern_devices_sql(q);

        const auto off = sql.find("OFFSET 0) s");
        REQUIRE(off != std::string::npos);
        CHECK(sql.find("s0.agent_id = ANY") == std::string::npos); // scope applies outside the fence
        CHECK(sql.find("s.agent_id = ANY", off) != std::string::npos);

        const auto plan = explain(sql, params);
        INFO(plan);
        CHECK(plan.find("Subquery Scan on s") != std::string::npos); // the fence survived planning
        CHECK(plan.find("Seq Scan on installed_software") == std::string::npos);
        CHECK(plan.find("installed_software_agent_idx") == std::string::npos); // not driven by scope
        CHECK(plan.find("installed_software_name_idx") != std::string::npos);

        // And the answer is right: an empty drill for those devices, a full one for others.
        auto page = np_devices(store, q);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        q.agent_ids = std::vector<std::string>{"fence-1", "nolib-0"};
        page = np_devices(store, q);
        REQUIRE(page.has_value());
        REQUIRE(page->rows.size() == 1);
        CHECK(page->rows[0].agent_id == "fence-1");
    }
}

TEST_CASE("name-pattern reads: one ASCII-only case-fold rule in SQL and in the classifier",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    // Only the ASCII-foldable spellings are a libssl3; the look-alikes must not match.
    np_seed(store, "f1", {np_entry("libssl3", "3.0")});
    np_seed(store, "f2", {np_entry("LIBSSL3", "3.0")});
    np_seed(store, "f3", {np_entry("l\xC4\xB0" "bssl3", "3.0")});             // lİbssl3
    np_seed(store, "f4", {np_entry("lib\xC5\xBF" "sl3", "3.0")});             // libſsl3
    np_seed(store, "f5", {np_entry("\xEF\xBD\x8C\xEF\xBD\x89\xEF\xBD\x82\xEF\xBD\x93\xEF\xBD\x93"
                                   "\xEF\xBD\x8C\xEF\xBC\x93", "3.0")});     // fullwidth
    np_seed(store, "f6", {np_entry("LibSsL3", "3.0")});

    // The Kelvin sign (U+212A), U+0130 and U+017F fold to ASCII under a Unicode-aware lower():
    // this test is VACUOUS when the database's lower() does not do that (LC_CTYPE C/POSIX),
    // because then the unsafe fold and the ASCII-only fold agree. Skip with the reason rather
    // than pass.
    if (np_column0(pool, "SELECT (lower(U&'\\212A') = 'k')::text").front() != "true")
        SKIP("lower() in this database is not Unicode-aware (LC_CTYPE C/POSIX): the look-alike "
             "folds below would prove nothing");
    np_seed(store, "k1", {np_entry("keyring", "1.0")});
    np_seed(store, "k2", {np_entry("\xE2\x84\xAA" "eyring", "1.0")}); // Kelvin sign + "eyring"

    yuzu::server::NamePatternQuery q;
    q.patterns = {"libssl3%"};
    q.labels = {"openssl"};
    for (const bool stale : {false, true}) { // catalogue names, then live skip-scan names
    INFO("stale=" << stale);
    auto r = np_rollup(store, q, stale);
    REQUIRE(r.has_value());
    CHECK(r->total_devices == 3); // f1, f2, f6
    CHECK(np_label(*r, "openssl") == 3);

    // The summary's count and the devices walk's union agree.
    yuzu::server::NamePatternDevicesQuery dq;
    dq.patterns = q.patterns;
    dq.limit = 100;
    auto page = np_devices(store, dq, stale);
    REQUIRE(page.has_value());
    std::set<std::string> agents;
    for (const auto& row : page->rows)
        agents.insert(row.agent_id);
    CHECK(agents == std::set<std::string>{"f1", "f2", "f6"});
    CHECK(static_cast<std::int64_t>(agents.size()) == r->total_devices);

    // The Kelvin look-alike never matches an ASCII pattern, whatever the database's locale.
    yuzu::server::NamePatternQuery kq;
    kq.patterns = {"keyring%"};
    kq.labels = {"x"};
    auto kr = np_rollup(store, kq, stale);
    REQUIRE(kr.has_value());
    CHECK(kr->total_devices == 1); // k1 only, not k2
    }
}

TEST_CASE("name-pattern reads: the text[] literal parser handles quoting and malformed input",
          "[crypto]") {
    using V = std::vector<std::string>;
    const auto parse = &SoftwareInventoryStore::parse_name_array_for_test;
    CHECK(parse("{}") == V{});
    CHECK(parse("{a}") == V{"a"});
    CHECK(parse("{a,\"b c\"}") == V{"a", "b c"});
    CHECK(parse("{\"x\\\"y\"}") == V{"x\"y"});
    CHECK(parse("{\"p\\\\q\"}") == V{"p\\q"});
    CHECK(parse("{NULL,\"NULL\"}") == V{"NULL"}); // unquoted NULL skipped, quoted kept
    CHECK(parse("{\"\"}") == V{""});
    CHECK(parse("{\"Win64 OpenSSL v3.0, x\"}") == V{"Win64 OpenSSL v3.0, x"});
    const std::string unit_sep = std::string("a") + '\x1F' + "b";
    CHECK(parse("{\"" + unit_sep + "\"}") == V{unit_sep});
    // Malformed input never throws or loops; it yields what parsed so far.
    CHECK(parse("{\"abc}") == V{"abc"});    // unterminated quote: what parsed
    CHECK(parse("{\"ab\\}") == V{"ab\\"});  // trailing backslash is kept literally
    CHECK(parse("a,b") == V{});   // no braces
    CHECK(parse("{a,b") == V{});  // missing closing brace
    CHECK(parse("") == V{});
}

TEST_CASE("name-pattern reads: equal to a plain reference query across scope variants",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    const std::vector<std::string> names = {"libssl3", "LibSSL3", "openssl", "libssl1.1", "libgnutls30",
                                            "gnutls", "nss", "nss-mdns", "curl", "libcrypto3",
                                            "win64 openssl v3", "a_b", "100%"};
    const std::vector<std::string> ecos = {"deb", "rpm", ""};
    for (int a = 0; a < 25; ++a) {
        std::vector<SoftwareEntry> rows;
        for (std::size_t k = 0; k < names.size(); ++k)
            if ((static_cast<std::size_t>(a) + k) % 3 != 0)
                rows.push_back(np_entry(names[k], std::to_string((a + k) % 4) + ".0", ecos[(a + k) % 3]));
        np_seed(store, "q" + std::to_string(100 + a), std::move(rows));
    }
    const std::vector<std::string> pats = {"libssl%", "openssl", "libcrypto%", "win64 openssl%",
                                           "libgnutls%", "gnutls", "nss", "a\\_b"};
    const std::vector<std::string> labs = {"openssl", "openssl", "openssl", "openssl",
                                           "gnutls",  "gnutls",  "nss",     "lit"};
    const std::vector<std::string_view> pv(pats.begin(), pats.end());
    const std::vector<std::string_view> lv(labs.begin(), labs.end());

    const std::vector<std::optional<std::vector<std::string>>> scopes = {
        std::nullopt,
        std::vector<std::string>{"q100", "q105", "q110", "q124", "nope"},
        std::vector<std::string>{"q101"}};
    // Every scope x ecosystem runs down BOTH step-1 sources (fresh catalogue, then stale ->
    // live skip-scan) against the same plain reference: the two paths must be identical.
    for (const bool stale : {false, true})
    for (const auto& scope : scopes) {
        for (const std::optional<std::string>& eco :
             {std::optional<std::string>{}, std::optional<std::string>{"rpm"}}) {
            INFO("stale=" << stale);
            yuzu::server::NamePatternQuery q;
            q.patterns = pats;
            q.labels = labs;
            q.agent_ids = scope;
            q.ecosystem = eco;
            const auto got = np_rollup(store, q, stale);
            REQUIRE(got.has_value());

            std::string ref_where = " WHERE 1=1";
            std::vector<std::string> params{pg::to_text_array(pv), pg::to_text_array(lv)};
            if (eco) {
                params.push_back(*eco);
                ref_where += " AND s.ecosystem = $" + std::to_string(params.size());
            }
            if (scope) {
                const std::vector<std::string_view> ids(scope->begin(), scope->end());
                params.push_back(pg::to_text_array(ids));
                ref_where += " AND s.agent_id = ANY($" + std::to_string(params.size()) + "::text[])";
            }
            const std::string from =
                "FROM software_inventory_store.installed_software s JOIN unnest($1::text[], "
                "$2::text[]) AS p(pat, label) ON lower(s.name COLLATE \"C\") LIKE p.pat ESCAPE '\\'";
            const auto ref_rows = np_column0(
                pool,
                "SELECT p.label || '|' || s.version || '|' || s.ecosystem || '|' || "
                "count(DISTINCT s.agent_id) " + from + ref_where +
                    " GROUP BY p.label, s.version, s.ecosystem ORDER BY 1",
                params);
            const auto ref_labels = np_column0(
                pool,
                "SELECT p.label || '|' || count(DISTINCT s.agent_id) " + from + ref_where +
                    " GROUP BY p.label ORDER BY 1",
                params);
            const auto ref_total = np_column0(
                pool, "SELECT count(DISTINCT s.agent_id) " + from + ref_where, params);

            std::vector<std::string> g_rows;
            for (const auto& r : got->rows)
                g_rows.push_back(r.label + "|" + r.version + "|" + r.ecosystem + "|" +
                                 std::to_string(r.device_count));
            std::ranges::sort(g_rows);
            std::vector<std::string> g_labels;
            for (const auto& l : got->label_counts)
                g_labels.push_back(l.label + "|" + std::to_string(l.device_count));
            std::ranges::sort(g_labels);
            auto sorted = [](std::vector<std::string> v) {
                std::ranges::sort(v);
                return v;
            };
            CHECK(g_rows == sorted(ref_rows));
            CHECK(g_labels == sorted(ref_labels));
            REQUIRE(ref_total.size() == 1);
            CHECK(std::to_string(got->total_devices) == ref_total[0]);

            // Devices walk for one label, paged by 4, equals the reference set in key order.
            yuzu::server::NamePatternDevicesQuery dq;
            dq.patterns = {"libssl%", "openssl", "libcrypto%", "win64 openssl%"};
            dq.agent_ids = scope;
            dq.ecosystem = eco;
            dq.limit = 4;
            std::vector<std::string> walk;
            for (int guard = 0; guard < 200; ++guard) {
                const auto page = np_devices(store, dq, stale);
                REQUIRE(page.has_value());
                for (const auto& r : page->rows)
                    walk.push_back(r.agent_id + "|" + r.entry.name + "|" + std::to_string(r.install_id));
                if (!page->has_more)
                    break;
                const auto& last = page->rows.back();
                dq.after = yuzu::server::SoftwareCursor{.name = last.entry.name,
                                                        .agent_id = last.agent_id,
                                                        .install_id = last.install_id};
            }
            const std::vector<std::string_view> dpv(dq.patterns.begin(), dq.patterns.end());
            std::vector<std::string> dparams{pg::to_text_array(dpv)};
            std::string dwhere;
            if (eco) {
                dparams.push_back(*eco);
                dwhere += " AND s.ecosystem = $" + std::to_string(dparams.size());
            }
            if (scope) {
                const std::vector<std::string_view> ids(scope->begin(), scope->end());
                dparams.push_back(pg::to_text_array(ids));
                dwhere += " AND s.agent_id = ANY($" + std::to_string(dparams.size()) + "::text[])";
            }
            const auto ref_walk = np_column0(
                pool,
                "SELECT s.agent_id || '|' || s.name || '|' || s.install_id FROM "
                "software_inventory_store.installed_software s WHERE lower(s.name COLLATE \"C\") "
                "LIKE ANY($1::text[])" + dwhere + " ORDER BY s.agent_id, s.name, s.install_id",
                dparams);
            CHECK(walk == ref_walk);
        }
    }
}

TEST_CASE("name-pattern rollup: coverage is counted in the same statement as the numerator",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    np_seed_fleet(store);
    auto r = np_rollup(store, np_query());
    REQUIRE(r.has_value());
    CHECK(r->reporting_agents == 5);
    CHECK(r->total_devices <= r->reporting_agents);

    auto q = np_query();
    q.agent_ids = std::vector<std::string>{"a1", "a3", "zz"};
    r = np_rollup(store, q);
    REQUIRE(r.has_value());
    CHECK(r->reporting_agents == 2);
    CHECK(r->total_devices == 2);

    // A pattern set matching nothing still reports the denominator (the grand-total row exists).
    yuzu::server::NamePatternQuery none;
    none.patterns = {"nosuchpkg%"};
    none.labels = {"x"};
    r = np_rollup(store, none);
    REQUIRE(r.has_value());
    CHECK(r->total_devices == 0);
    CHECK(r->reporting_agents == 5);
}

// The per-bucket name list is capped at kNamePatternNamesPerRow (8): one past the cap is read so a
// cut list says names_truncated, and a bucket holding exactly the cap does not (review #6056).
TEST_CASE("name-pattern rollup: the 8-name cap per bucket is flagged; never silent",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    static_assert(yuzu::server::kNamePatternNamesPerRow == 8);
    // bucket (openssl, 3.0, deb): 9 distinct matching names; bucket (openssl, 1.1, deb): exactly 8.
    for (int i = 0; i < 9; ++i)
        np_seed(store, "cap-a" + std::to_string(i), {np_entry("libssl3-n" + std::to_string(i), "3.0")});
    for (int i = 0; i < 8; ++i)
        np_seed(store, "cap-b" + std::to_string(i), {np_entry("libssl1-n" + std::to_string(i), "1.1")});
    yuzu::server::NamePatternQuery q;
    q.patterns = {"libssl%"};
    q.labels = {"openssl"};
    const auto r = np_rollup(store, q);
    REQUIRE(r.has_value());
    bool saw_nine = false, saw_eight = false;
    for (const auto& row : r->rows) {
        INFO(row.version);
        CHECK(row.names.size() <= 8);
        if (row.version == "3.0") {
            saw_nine = true;
            CHECK(row.names.size() == 8);
            CHECK(row.names_truncated);
        } else if (row.version == "1.1") {
            saw_eight = true;
            CHECK(row.names.size() == 8);
            CHECK_FALSE(row.names_truncated);
        }
    }
    CHECK(saw_nine);
    CHECK(saw_eight);
}

// Review #6109: a corpus differential between the SQL the /crypto table generates
// (crypto_library::sql_patterns - escaped LIKE patterns plus 3-character leads) and the C++
// classifier (crypto_library::classify). The CryptoApi seam re-classifies every name it shows,
// which would HIDE an over-matching pattern, so this compares at the STORE: for every family the
// set of names the rollup and the drill return must be exactly the set classify() assigns to it,
// on the catalogue path and on the live path. A wrong pattern (an unescaped `_`, a lost `%`, a
// wrong lead, an exact rule emitted as a prefix) changes one side only and fails here.
TEST_CASE("name-pattern reads: the crypto table's SQL patterns and classify() agree on a corpus",
          "[pg][software_inventory][crypto]") {
    namespace cl = yuzu::server::crypto_library;
    SWINV_SHARED(store, pool);
    std::set<std::string> corpus;
    auto mixed = [](std::string s) { // alternate ASCII case: OpEnSsL
        for (std::size_t i = 0; i < s.size(); i += 2)
            if (s[i] >= 'a' && s[i] <= 'z')
                s[i] = static_cast<char>(s[i] - 'a' + 'A');
        return s;
    };
    for (const auto& r : cl::rules()) {
        const std::string v(r.value);
        corpus.insert(v);
        corpus.insert(mixed(v));
        corpus.insert(v.substr(0, v.size() - 1)); // one short
        corpus.insert("x" + v);                   // not a prefix of anything
        for (const char* suffix : {"-dev", "t64", ".so.3", "-1.2_3", "X", "%", "_", "\\"})
            corpus.insert(v + suffix);
        if (r.kind == cl::MatchKind::kPrefix)
            corpus.insert(mixed(v) + "-Dev");
    }
    for (const char* near : {
             "libcrypto++8", "libcrypto++-dev", "nss-mdns", "nss-pam-ldapd", "libnss3x",
             "libssl-ocaml", "libssl", "libcrypto", "gnutlsx", "mbedtls2", "ab", "op", "x",
             "libopenssl1x1", "openssl-1x1", "openssl-1%1", "%openssl", "_openssl", "o_enssl",
             "lib%ssl3", "libssl_3", "\\openssl", "openssl@", "openssl@3", "OPENSSL@3",
             "l\xC4\xB0" "bssl3",                                 // U+0130: not ASCII-foldable
             "lib\xC5\xBF" "sl3",                                 // U+017F long s
             "\xEF\xBD\x8C\xEF\xBD\x89\xEF\xBD\x82ssl3",          // fullwidth "lib" + ssl3
             "libssl3\xC3\xA9", "\xC3\xA9openssl", "nss\xE2\x80\x8B" // e-acute, zero-width space
         })
        corpus.insert(near);

    // One device; every name in its own version bucket, so no 8-name cut can hide a name.
    std::vector<SoftwareEntry> rows;
    int i = 0;
    for (const auto& n : corpus)
        rows.push_back(np_entry(n, "v" + std::to_string(i++)));
    REQUIRE(rows.size() < static_cast<std::size_t>(yuzu::server::kNamePatternRollupRowCap));
    np_seed(store, "corpus", std::move(rows));

    std::map<std::string, std::set<std::string>> expected;
    std::size_t unmatched = 0;
    for (const auto& n : corpus) {
        if (const auto f = cl::classify(n))
            expected[std::string(*f)].insert(n);
        else
            ++unmatched;
    }
    // Not vacuous: every family has names, and many names belong to none.
    for (const auto& f : cl::families())
        REQUIRE(!expected[std::string(f.id)].empty());
    REQUIRE(unmatched > 100);

    for (const bool stale : {false, true}) { // catalogue names, then live skip-scan names
        INFO("stale=" << stale);
        // The summary path: every rule of every family in one statement.
        const auto all = cl::sql_patterns();
        // The helpers' np_fill_leads fallback rebuilds leads when the counts differ; pin them
        // equal here so it can never mask a lead bug in sql_patterns().
        REQUIRE(all.leads.size() == all.patterns.size());
        yuzu::server::NamePatternQuery q;
        q.patterns = all.patterns;
        q.labels = all.labels;
        q.leads = all.leads;
        const auto r = np_rollup(store, q, stale);
        REQUIRE(r.has_value());
        CHECK_FALSE(r->truncated);
        std::map<std::string, std::set<std::string>> got;
        for (const auto& row : r->rows) {
            CHECK_FALSE(row.names_truncated);
            got[row.label].insert(row.names.begin(), row.names.end());
        }
        for (const auto& f : cl::families()) {
            const std::string id(f.id);
            INFO("rollup family " << id);
            CHECK(got[id] == expected[id]);
        }
        CHECK(got.size() == cl::families().size()); // no label outside the table

        // The drill path: one family's rules at a time.
        for (const auto& f : cl::families()) {
            const std::string id(f.id);
            INFO("drill family " << id);
            const auto fam = cl::sql_patterns(id);
            REQUIRE(fam.leads.size() == fam.patterns.size());
            yuzu::server::NamePatternDevicesQuery dq;
            dq.patterns = fam.patterns;
            dq.leads = fam.leads;
            dq.limit = yuzu::server::kNamePatternPageMax;
            const auto page = np_devices(store, dq, stale);
            REQUIRE(page.has_value());
            CHECK_FALSE(page->has_more);
            std::set<std::string> names;
            for (const auto& row : page->rows)
                names.insert(row.entry.name);
            CHECK(names == expected[id]);
        }
    }
}

// Review #6056 (A7): the drill's keyset predicate is evaluated INSIDE the OFFSET 0 fence, in the
// name-index scan, so a later page does not re-read the rows earlier pages passed. The scope,
// version and ecosystem filters stay outside the fence (the planner-pathology guard above).
TEST_CASE("name-pattern drill: a continuation page reads only rows past its cursor",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    constexpr int kAgents = 300;
    for (int a = 0; a < kAgents; ++a) {
        char id[32];
        std::snprintf(id, sizeof id, "ks-%04d", a);
        np_seed(store, id, {np_entry("libssl3", "3.0"), np_entry("pkg-" + std::to_string(a % 40), "1")});
    }
    np_column0(pool, "ANALYZE software_inventory_store.installed_software");
    yuzu::server::NamePatternDevicesQuery q;
    q.patterns = {"libssl%"};
    np_fill_leads(q);
    q.limit = 100;
    // Walk with cursors: the pages concatenate to every row exactly once, in order.
    std::vector<std::string> walked;
    std::optional<yuzu::server::SoftwareCursor> mid;
    for (int page_no = 0;; ++page_no) {
        const auto page = store.software_name_pattern_devices(q);
        REQUIRE(page.has_value());
        for (const auto& r : page->rows)
            walked.push_back(r.agent_id);
        if (!page->has_more)
            break;
        const auto& last = page->rows.back();
        q.after = yuzu::server::SoftwareCursor{
            .name = last.entry.name, .agent_id = last.agent_id, .install_id = last.install_id};
        if (page_no == 1)
            mid = q.after; // the cursor that starts page 3 (200 rows already passed)
    }
    REQUIRE(walked.size() == static_cast<std::size_t>(kAgents));
    CHECK(std::ranges::is_sorted(walked));
    CHECK(std::ranges::adjacent_find(walked) == walked.end());
    REQUIRE(mid.has_value());

    q.after = mid;
    const auto [sql, params] = SoftwareInventoryStore::name_pattern_devices_sql(q);
    const auto fence = sql.find("OFFSET 0) s");
    const auto keyset = sql.find("(s0.agent_id, s0.name, s0.install_id) >");
    REQUIRE(fence != std::string::npos);
    REQUIRE(keyset != std::string::npos);
    CHECK(keyset < fence); // inside the fence
    CHECK(sql.find("(s.agent_id, s.name, s.install_id) >") == std::string::npos);

    std::string plan;
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(), ("EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF) " + sql).c_str(),
            params);
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            plan += PQgetvalue(r.get(), i, 0);
            plan += '\n';
        }
    }
    INFO(plan);
    CHECK(plan.find("installed_software_agent_idx") == std::string::npos);
    // Rows the scans of installed_software produced: only the ~100 past the cursor, never the
    // 300 the name carries (before the change every page read all 300).
    double scanned = 0;
    bool saw_scan = false;
    std::size_t pos = 0;
    while (pos < plan.size()) {
        auto nl = plan.find('\n', pos);
        if (nl == std::string::npos)
            nl = plan.size();
        const std::string line = plan.substr(pos, nl - pos);
        pos = nl + 1;
        // The step-2 scan of the drill's rows (alias s0); step 1's skip-scan over the same
        // index (aliases i / i_1) reads one entry per distinct name and is not counted.
        const bool is_scan = line.find("Scan") != std::string::npos &&
                             line.find("installed_software s0") != std::string::npos;
        if (!is_scan)
            continue;
        const auto ar = line.find("actual rows=");
        const auto lp = line.find("loops=");
        if (ar == std::string::npos || lp == std::string::npos)
            continue;
        saw_scan = true;
        scanned += std::stod(line.substr(ar + 12)) * std::stod(line.substr(lp + 6));
    }
    CHECK(saw_scan);
    CHECK(scanned <= 110.0);
}

// A catalogue refreshed over an EMPTY fleet (the boot-time refresh, before any agent reported)
// must not count as fresh: it has no title rows, so reading names from it would answer an
// authoritative empty set for up to an hour while agents enrol. total_titles > 0 is part of the
// freshness predicate (review #6056), so the read falls through to the live skip-scan.
TEST_CASE("name-pattern reads: a catalogue refreshed over an empty fleet is not fresh",
          "[pg][software_inventory][crypto]") {
    SWINV_SHARED(store, pool);
    REQUIRE(store.refresh_catalog_rollup()); // empty fleet: refreshed_at > 0, total_titles 0
    const auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    REQUIRE(meta->refreshed_at > 0);
    REQUIRE(meta->total_titles == 0);
    np_seed_fleet(store); // rows arrive after the refresh; no second refresh
    auto q = np_query();
    np_fill_leads(q);
    const auto r = store.software_name_pattern_rollup(q);
    REQUIRE(r.has_value());
    CHECK(r->names_as_of == 0); // the live source answered
    CHECK(np_label(*r, "openssl") == 3);
    CHECK(np_label(*r, "gnutls") == 1);
    yuzu::server::NamePatternDevicesQuery dq;
    dq.patterns = {"libssl%"};
    np_fill_leads(dq);
    const auto page = store.software_name_pattern_devices(dq);
    REQUIRE(page.has_value());
    CHECK(page->names_as_of == 0);
    CHECK(page->rows.size() == 3); // a1, a2 (LibSSL3), a3
}

TEST_CASE("name-pattern reads: a deny-all scope is an empty value with no SQL; a backend "
          "failure is nullopt",
          "[pg][software_inventory][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // A deny-all scope on a healthy store answers an empty value with no SQL (names_as_of 0:
    // nothing was read).
    {
        auto q = np_query();
        np_fill_leads(q);
        q.agent_ids = std::vector<std::string>{};
        const auto r = store.software_name_pattern_rollup(q);
        REQUIRE(r.has_value());
        CHECK(r->rows.empty());
        CHECK(r->names_as_of == 0);
    }
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop = pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    auto q = np_query();
    np_fill_leads(q);
    CHECK_FALSE(store.software_name_pattern_rollup(q).has_value());
    yuzu::server::NamePatternDevicesQuery dq;
    dq.patterns = {"libssl%"};
    np_fill_leads(dq);
    CHECK_FALSE(store.software_name_pattern_devices(dq).has_value());
    // A deny-all scope runs no SQL, so even a broken backend answers it with the empty value
    // (ADR-0033: present-empty is deny-all, not "no filter").
    q.agent_ids = std::vector<std::string>{};
    const auto denied = store.software_name_pattern_rollup(q);
    REQUIRE(denied.has_value());
    CHECK(denied->rows.empty());
    dq.agent_ids = std::vector<std::string>{};
    const auto denied_page = store.software_name_pattern_devices(dq);
    REQUIRE(denied_page.has_value());
    CHECK(denied_page->rows.empty());

    // a store that failed to open degrades too
    SoftwareInventoryStore broken{pool};
    REQUIRE_FALSE(broken.is_open());
    dq.agent_ids = std::nullopt;
    q.agent_ids = std::nullopt;
    CHECK_FALSE(broken.software_name_pattern_rollup(q).has_value());
    CHECK_FALSE(broken.software_name_pattern_devices(dq).has_value());
}

// ═════════════════════════════════════════════════════════════════════════════
// Blob v3 + migration v10 (ADR-0016 Update 2026-11-04)
// ═════════════════════════════════════════════════════════════════════════════

namespace {

using yuzu::server::V3Refusal;
using yuzu::server::V3Report;
using yuzu::server::V3Section;
using yuzu::server::V3SectionOutcome;
using yuzu::server::V3Status;
using SqlTable = std::vector<std::vector<std::string>>;

constexpr const char* kV3Apps = "installed_apps.list_inventory";
constexpr const char* kV3Pkgs = "pkg_inventory.packages";
constexpr const char* kV3Py = "runtimes.python";
constexpr const char* kV3Comp = "component_inventory";

// SHA-256 of the empty byte string: the section hash of an honest-empty full section.
constexpr const char* kEmptySectionHash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

SqlTable sql_rows(PgPool& pool, const std::string& sql,
                  const std::vector<std::string>& params = {}) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    SqlTable t;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        std::vector<std::string> row;
        for (int j = 0; j < PQnfields(r.get()); ++j)
            row.emplace_back(PQgetvalue(r.get(), i, j));
        t.push_back(std::move(row));
    }
    return t;
}

// True iff the statement succeeded (a refusal such as a CHECK or unique violation is false).
bool sql_ok(PgPool& pool, const std::string& sql, const std::vector<std::string>& params = {}) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    pg::PgResult r = pg::exec_params(lease.get(), sql.c_str(), params);
    return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
}

SoftwareEntry v3_entry(const std::string& name, const std::string& source,
                       const std::string& version = "1.0", const std::string& location = "") {
    SoftwareEntry e;
    e.name = name;
    e.version = version;
    e.publisher = "Pub";
    e.install_date = "2026-01-01";
    e.kind = "app";
    e.ecosystem = "windows";
    e.arch = "x64";
    e.install_location = location;
    e.package_id = "pkg-" + name;
    e.source = source;
    return e;
}

V3Section v3_full(const std::string& facet, std::vector<SoftwareEntry> rows) {
    V3Section s;
    s.facet = facet;
    s.status = V3Status::kFull;
    s.rows = std::move(rows);
    s.duration_ms = 11;
    s.bytes_read = 22;
    return s;
}

V3Section v3_status(const std::string& facet, V3Status st, const std::string& token = "") {
    V3Section s;
    s.facet = facet;
    s.status = st;
    s.token = token;
    s.duration_ms = 5;
    s.bytes_read = 6;
    return s;
}

V3Report v3_report(std::vector<V3Section> sections) {
    V3Report r;
    r.sections = std::move(sections);
    return r;
}

std::vector<std::string> names_of(PgPool& pool, const std::string& agent,
                                  const std::string& source) {
    std::vector<std::string> out;
    for (const auto& row : sql_rows(pool,
                                    "SELECT name FROM software_inventory_store.installed_software "
                                    "WHERE agent_id = $1 AND source = $2 ORDER BY name",
                                    {agent, source}))
        out.push_back(row[0]);
    return out;
}

std::string row_count(PgPool& pool, const std::string& agent) {
    return sql_rows(pool,
                    "SELECT count(*) FROM software_inventory_store.installed_software "
                    "WHERE agent_id = $1",
                    {agent})[0][0];
}

std::string facet_count(PgPool& pool, const std::string& agent) {
    return sql_rows(pool,
                    "SELECT count(*) FROM software_inventory_store.software_facet_state "
                    "WHERE agent_id = $1",
                    {agent})[0][0];
}

std::string stored_hash(PgPool& pool, const std::string& agent) {
    const auto t = sql_rows(pool,
                            "SELECT content_hash FROM software_inventory_store.inventory_state "
                            "WHERE agent_id = $1 AND source = 'installed_software'",
                            {agent});
    return t.empty() ? std::string("<no row>") : t[0][0];
}

std::string section_hash_of(const std::vector<SoftwareEntry>& rows) {
    return SoftwareInventoryStore::canonical_section_hash(rows);
}

// Wire builders (ingest-level cases drive the real seam with real bytes).
std::string w_rec(std::initializer_list<std::string> fields) {
    std::string out;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            out += '\x1f';
        out += f;
        first = false;
    }
    return out + '\x1e';
}
std::string w_hdr() {
    return "\037v3\036";
}
std::string w_sec(const std::string& facet, const std::string& status, const std::string& base = "",
                  const std::string& token = "", const std::string& dur = "0",
                  const std::string& bytes = "0") {
    return w_rec({"S", facet, status, base, token, dur, bytes});
}
// A `+` record matching v3_entry(name, source, "1.0", loc) slot for slot (slot 14 empty).
std::string w_plus(const std::string& name, const std::string& source,
                   const std::string& loc = "") {
    return w_rec({"+", name, "1.0", "Pub", "2026-01-01", "app", "windows", "", "", "x64", "", "",
                  "", loc, "", "pkg-" + name, source});
}

} // namespace

TEST_CASE("derive_install_keys: type, scope, identity key and instance key",
          "[software_inventory][v3][keys]") {
    SoftwareEntry a = v3_entry("Alpha", kV3Apps, "1.0", "C:\\Program Files\\Alpha\\");
    SoftwareInventoryStore::derive_install_keys(a);
    CHECK(a.install_type == "installer");
    CHECK(a.install_scope == "machine");
    // identity_key: norm_key(name, publisher) US version US arch US location_norm (lower-cased,
    // trailing separators stripped).
    CHECK(a.identity_key == yuzu::server::norm_key("Alpha", "Pub") + '\x1f' + "1.0" + '\x1f' +
                                "x64" + '\x1f' + "c:\\program files\\alpha");
    // instance_key is the SHA-256 of the row's single canonical record, i.e. the section hash
    // of a one-row section (and the value a `-` record would name).
    CHECK(a.instance_key ==
          section_hash_of({v3_entry("Alpha", kV3Apps, "1.0", "C:\\Program Files\\Alpha\\")}));
    CHECK(a.instance_key.size() == 64);

    // The location's case and trailing separators do not move identity_key; they DO move
    // instance_key (the stored location is part of the row).
    SoftwareEntry b = v3_entry("Alpha", kV3Apps, "1.0", "c:\\PROGRAM FILES\\alpha");
    SoftwareInventoryStore::derive_install_keys(b);
    CHECK(b.identity_key == a.identity_key);
    CHECK(b.instance_key != a.instance_key);
    SoftwareEntry c = v3_entry("Alpha", kV3Apps, "1.0", "/opt/alpha///");
    SoftwareInventoryStore::derive_install_keys(c);
    CHECK(c.identity_key.ends_with(std::string(1, '\x1f') + "/opt/alpha"));

    // A different version or arch is a different identity.
    SoftwareEntry d = v3_entry("Alpha", kV3Apps, "2.0", "C:\\Program Files\\Alpha\\");
    SoftwareInventoryStore::derive_install_keys(d);
    CHECK(d.identity_key != a.identity_key);

    // Deriving twice is stable, and the derived columns never enter the v2 canonical hash.
    SoftwareEntry a2 = a;
    SoftwareInventoryStore::derive_install_keys(a2);
    CHECK(a2.identity_key == a.identity_key);
    CHECK(a2.instance_key == a.instance_key);
    SoftwareEntry ext = full_extended_entry();
    SoftwareInventoryStore::derive_install_keys(ext);
    // An rpm row stamped installed_apps.list_inventory is package_manager, like the same row
    // from a pre-tail agent (empty source).
    CHECK(ext.install_type == "package_manager");
    CHECK(SoftwareInventoryStore::canonical_hash({ext}) == kCrossPinHashExtended);

    // A pre-tail (v2, empty source) row falls back by ecosystem; an unknown one is not derived.
    SoftwareEntry rpm = full_v2_entry();
    SoftwareInventoryStore::derive_install_keys(rpm);
    CHECK(rpm.install_type == "package_manager");
    SoftwareEntry odd;
    odd.name = "x";
    SoftwareInventoryStore::derive_install_keys(odd);
    CHECK(odd.install_type.empty());
    CHECK(odd.install_scope == "machine");
}

TEST_CASE("canonical_section_hash is order and duplicate independent, 16 slots always, pinned",
          "[software_inventory][v3][hash]") {
    // Recipe for the pins (raw wire bytes, slot 14 empty, 0x1F-joined, 0x1E-terminated):
    //   printf
    //   'Alpha\0371.0\037Pub\0372026-01-01\037app\037windows\037\037\037x64\037\037\037\037C:\\Program
    //   Files\\Alpha\037\037pkg-a\037installed_apps.list_inventory\036' | shasum -a 256
    SoftwareEntry a;
    a.name = "Alpha";
    a.version = "1.0";
    a.publisher = "Pub";
    a.install_date = "2026-01-01";
    a.kind = "app";
    a.ecosystem = "windows";
    a.arch = "x64";
    a.install_location = "C:\\Program Files\\Alpha";
    a.package_id = "pkg-a";
    a.source = kV3Apps;
    SoftwareEntry b;
    b.name = "Beta";
    b.version = "2";
    b.kind = "app";
    b.ecosystem = "windows";
    b.source = kV3Apps;

    CHECK(SoftwareInventoryStore::canonical_section_hash({a}) ==
          "c573935d6af97c9deaef2b526cb01a3dabc2d3958b7e69b289968a6e80dbf229");
    // Unsorted input with a duplicate hashes to the sorted, de-duplicated bytes.
    CHECK(SoftwareInventoryStore::canonical_section_hash({b, a, a}) ==
          "4f5f399d1a8f2cb7e94eee0487cf6dbb86b2bcdbb7b266fbc2869bd92b338fdd");
    CHECK(SoftwareInventoryStore::canonical_section_hash({}) == kEmptySectionHash);

    // Every stored field, install_location included, moves the hash; no conditional tail: a
    // row with an empty package_id and source still writes all 16 slots, so it differs from
    // the same row with only the tail changed.
    const auto base = SoftwareInventoryStore::canonical_section_hash({a});
    for (auto field : {&SoftwareEntry::install_location, &SoftwareEntry::package_id,
                       &SoftwareEntry::source, &SoftwareEntry::distro_version}) {
        SoftwareEntry other = a;
        other.*field = "zz";
        CHECK(SoftwareInventoryStore::canonical_section_hash({other}) != base);
    }
    SoftwareEntry bare = a;
    bare.package_id.clear();
    bare.source.clear();
    CHECK(SoftwareInventoryStore::canonical_section_hash({bare}) != base);
    // The server-derived columns never enter it.
    SoftwareEntry derived = a;
    SoftwareInventoryStore::derive_install_keys(derived);
    CHECK(SoftwareInventoryStore::canonical_section_hash({derived}) == base);
}

TEST_CASE("canonical_section_hash pins a row whose publisher is an origin label (via:brew)",
          "[software_inventory][v3][hash][vendor]") {
    // The agent writes `via:<ecosystem>` into slot 3 when a source declares no vendor; the server
    // hashes it like any other publisher (no special case on the hash path). Recipe:
    //   printf 'wget\0371.24\037via:brew\037\037pkg\037brew\037\037\037\037\037\037\037\037\037\037pkg_inventory.packages\036' | shasum -a 256
    SoftwareEntry e;
    e.name = "wget";
    e.version = "1.24";
    e.publisher = "via:brew";
    e.kind = "pkg";
    e.ecosystem = "brew";
    e.source = kV3Pkgs;
    CHECK(SoftwareInventoryStore::canonical_section_hash({e}) ==
          "906ce129e4448180dcee1d554df55367a898b40e73551cf9dbfaa73d26d0c69f");
    // ...and the label is in the hash: the same row with the slot empty hashes differently.
    SoftwareEntry bare = e;
    bare.publisher.clear();
    CHECK(SoftwareInventoryStore::canonical_section_hash({bare}) !=
          SoftwareInventoryStore::canonical_section_hash({e}));
    // The v2 report hash (canonical_hash) is the 12-field form with no tail when no source is set;
    // the agent pins the same two digests in test_inventory_sync.cpp. Recipe:
    //   printf 'wget\0371.24\037via:brew\037\037pkg\037brew\037\037\037\037\037\037\036' | shasum -a 256
    SoftwareEntry v2 = e;
    v2.source.clear();
    CHECK(SoftwareInventoryStore::canonical_hash({v2}) ==
          "3efab992b1c46e477f74297ee3d55e9c1a0cc923aa3d2dd112fe9a074ead29a9");
    // The identity key ignores the label: a labelled row keys like a vendorless one.
    SoftwareEntry labelled = e;
    SoftwareInventoryStore::derive_install_keys(labelled);
    SoftwareInventoryStore::derive_install_keys(bare);
    CHECK(labelled.identity_key == bare.identity_key);
}

TEST_CASE("v3_report_hash sorts by facet in byte order, carries the v3: prefix, pinned",
          "[software_inventory][v3][hash]") {
    const std::string pa(64, 'a');
    const std::string pb(64, 'b');
    //   printf 'installed_apps.list_inventory\037<64 b>\036runtimes.python\037<64 a>\036' | shasum
    //   -a 256
    const std::string expect =
        "v3:ca5bfc4023f484d758323b20edec5362f2d927476067c0c6f31eef389bac4878";
    CHECK(SoftwareInventoryStore::v3_report_hash({{kV3Py, pa}, {kV3Apps, pb}}) == expect);
    CHECK(SoftwareInventoryStore::v3_report_hash({{kV3Apps, pb}, {kV3Py, pa}}) == expect);
    CHECK(SoftwareInventoryStore::v3_report_hash({{kV3Apps, pb}}) ==
          "v3:2026549037aa0802ef3b58c555d0919e8d0f240a8987c88428bfd45e1f06ff60");
    // Byte order, not locale: an upper-case-leading or underscore facet sorts by raw bytes.
    CHECK(SoftwareInventoryStore::v3_report_hash({{"b", pa}, {"B", pb}}) ==
          SoftwareInventoryStore::v3_report_hash({{"B", pb}, {"b", pa}}));
    // A v2 hash is plain hex: the prefix keeps the two families apart.
    CHECK(SoftwareInventoryStore::v3_report_hash({}).starts_with("v3:"));
    CHECK(SoftwareInventoryStore::canonical_hash({}).find("v3:") == std::string::npos);
}

TEST_CASE("migration v10 adds the v3 columns, checks, partial unique index and facet table over "
          "live rows and re-runs idempotently",
          "[pg][software_inventory][v3]") {
    // Reproduce a v9-era schema: drop the v10 additions, seed legacy rows, rewind schema_meta to
    // 9, reconstruct so v10 re-adds them over live data. Then rewind again and reconstruct to
    // prove the migration text is idempotent.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    const auto rewind = [&] {
        REQUIRE(sql_ok(pool, "UPDATE public.schema_meta SET version = 9 "
                             "WHERE store = 'software_inventory_store'"));
    };
    REQUIRE(sql_ok(pool, "DROP TABLE software_inventory_store.software_facet_state"));
    REQUIRE(sql_ok(pool, "ALTER TABLE software_inventory_store.installed_software "
                         "DROP COLUMN install_type, DROP COLUMN install_scope, "
                         "DROP COLUMN install_location, DROP COLUMN identity_key, "
                         "DROP COLUMN instance_key, DROP COLUMN purl"));
    for (const char* v : {"1.0", "2.0"}) {
        REQUIRE(sql_ok(pool,
                       "INSERT INTO software_inventory_store.installed_software "
                       "(agent_id, name, version) VALUES ('agent-legacy', 'OldApp', $1)",
                       {v}));
    }
    rewind();
    SoftwareInventoryStore store{pool}; // re-runs v10 over the live rows
    REQUIRE(store.is_open());

    // The legacy rows read the documented "not derived" values.
    const auto legacy = sql_rows(
        pool, "SELECT install_type, install_scope, install_location, identity_key, instance_key "
              "FROM software_inventory_store.installed_software WHERE agent_id = 'agent-legacy'");
    REQUIRE(legacy.size() == 2);
    for (const auto& row : legacy) {
        CHECK(row[0] == "");
        CHECK(row[1] == "machine");
        CHECK(row[2] == "");
        CHECK(row[3] == "");
        CHECK(row[4] == "");
    }
    for (const auto& row : sql_rows(pool, "SELECT purl FROM "
                                          "software_inventory_store.installed_software "
                                          "WHERE agent_id = 'agent-legacy'")) {
        CHECK(row[0] == "");
    }

    const auto verify_shape = [&] {
        // Both CHECKs exist and are NOT VALID (no scan of existing rows).
        const auto checks = sql_rows(
            pool, "SELECT conname, convalidated::text FROM pg_constraint "
                  "WHERE conrelid = 'software_inventory_store.installed_software'::regclass "
                  "AND contype = 'c' ORDER BY conname");
        REQUIRE(checks.size() == 2);
        CHECK(checks[0][0] == "installed_software_install_scope_chk");
        CHECK(checks[0][1] == "false");
        CHECK(checks[1][0] == "installed_software_install_type_chk");
        CHECK(checks[1][1] == "false");
        // The unique index is partial: pre-v10 rows (instance_key '') are outside it.
        const auto idx = sql_rows(
            pool, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'software_inventory_store' "
                  "AND indexname = 'installed_software_instance_idx'");
        REQUIRE(idx.size() == 1);
        CHECK(idx[0][0].find("UNIQUE") != std::string::npos);
        CHECK(idx[0][0].find("(agent_id, instance_key)") != std::string::npos);
        CHECK(idx[0][0].find("WHERE") != std::string::npos);
        // The purl index is a partial btree: rows without a purl hold no entry.
        const auto pidx = sql_rows(
            pool, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'software_inventory_store' "
                  "AND indexname = 'installed_software_purl_idx'");
        REQUIRE(pidx.size() == 1);
        CHECK(pidx[0][0].find("UNIQUE") == std::string::npos);
        CHECK(pidx[0][0].find("(purl)") != std::string::npos);
        CHECK(pidx[0][0].find("WHERE") != std::string::npos);
        // The facet table has the contracted columns.
        const auto cols = sql_rows(pool, "SELECT column_name FROM information_schema.columns "
                                         "WHERE table_schema = 'software_inventory_store' AND "
                                         "table_name = 'software_facet_state' "
                                         "ORDER BY ordinal_position");
        const std::vector<std::string> want = {"agent_id",
                                               "facet",
                                               "status",
                                               "token",
                                               "section_hash",
                                               "enabled",
                                               "last_confirmed_at",
                                               "duration_ms",
                                               "bytes_read",
                                               "updated_at"};
        REQUIRE(cols.size() == want.size());
        for (std::size_t i = 0; i < want.size(); ++i)
            CHECK(cols[i][0] == want[i]);
    };
    verify_shape();

    // The index enforces uniqueness for derived keys only.
    const std::string ins = "INSERT INTO software_inventory_store.installed_software "
                            "(agent_id, name, instance_key) VALUES ($1, $2, $3)";
    CHECK(sql_ok(pool, ins, {"agent-k", "A", "key-1"}));
    CHECK_FALSE(sql_ok(pool, ins, {"agent-k", "B", "key-1"})); // same agent, same key
    CHECK(sql_ok(pool, ins, {"agent-other", "A", "key-1"}));   // another agent may share it
    CHECK(sql_ok(pool, ins, {"agent-k", "C", ""}));            // '' is outside the index
    CHECK(sql_ok(pool, ins, {"agent-k", "D", ""}));

    rewind();
    SoftwareInventoryStore again{pool}; // second run over an already-migrated table
    CHECK(again.is_open());
    verify_shape();
}

TEST_CASE("install_type and install_scope CHECKs admit exactly the vocabulary and ''",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const std::string ins =
        "INSERT INTO software_inventory_store.installed_software "
        "(agent_id, name, install_type, install_scope) VALUES ('agent-chk', $1, $2, $3)";
    // The frozen CHECK list in migration v10 and kInstallTypes are one vocabulary.
    for (const auto t : yuzu::server::kInstallTypes) {
        CAPTURE(t);
        CHECK(sql_ok(pool, ins, {std::string("n-") + std::string(t), std::string(t), "machine"}));
    }
    CHECK(sql_ok(pool, ins, {"n-empty", "", "machine"})); // "not yet derived"
    CHECK(sql_ok(pool, ins, {"n-user", "installer", "user"}));
    CHECK_FALSE(sql_ok(pool, ins, {"n-bogus", "bogus", "machine"}));
    // A plausible type nothing derives yet: the CHECK is the vocabulary, not "any word that fits".
    CHECK_FALSE(sql_ok(pool, ins, {"n-portable", "portable", "machine"}));
    CHECK_FALSE(sql_ok(pool, ins, {"n-case", "Installer", "machine"}));
    CHECK_FALSE(sql_ok(pool, ins, {"n-scope", "installer", "global"}));
    CHECK_FALSE(sql_ok(pool, ins, {"n-scope-empty", "installer", ""}));
}

TEST_CASE("v2 ingest stamps the derived keys; one MSI product listed twice stores both rows",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    // The same product through msi_packages AND installed_apps (ADR-0016 Update 2026-10-17: not
    // de-duplicated). Identical name/version/publisher/arch, different ecosystem/kind/source.
    SoftwareEntry msi;
    msi.name = "Acme Tool";
    msi.version = "1.0";
    msi.publisher = "Acme";
    msi.kind = "pkg";
    msi.ecosystem = "msi";
    msi.package_id = "{11111111-2222-3333-4444-555555555555}";
    msi.source = "msi_packages.list_inventory";
    SoftwareEntry apps = msi;
    apps.kind = "app";
    apps.ecosystem = "windows";
    apps.package_id.clear();
    apps.source = kV3Apps;
    SoftwareEntry legacy = full_v2_entry(); // pre-tail agent: empty source
    const std::vector<SoftwareEntry> rows = {apps, msi, apps /* exact duplicate */, legacy};

    REQUIRE(store.apply_installed_software("agent-msi",
                                           SoftwareInventoryStore::canonical_hash(rows), rows,
                                           1000) == InventoryIngestOutcome::kStored);
    const auto t = sql_rows(
        pool, "SELECT source, install_type, install_scope, install_location, "
              "identity_key, instance_key FROM software_inventory_store.installed_software "
              "WHERE agent_id = 'agent-msi' ORDER BY ecosystem, source");
    REQUIRE(t.size() == 3); // the exact duplicate collapsed, the MSI twin did not
    std::set<std::string> instance_keys;
    for (const auto& r : t) {
        CHECK(r[2] == "machine");
        CHECK(r[3] == "");
        CHECK(r[4].find('\x1f') != std::string::npos); // identity_key is populated
        CHECK(r[5].size() == 64);
        instance_keys.insert(r[5]);
    }
    CHECK(instance_keys.size() == 3);
    // ORDER BY ecosystem: msi, rpm, windows
    CHECK(t[0][0] == "msi_packages.list_inventory");
    CHECK(t[0][1] == "msi");
    CHECK(t[1][0] == "");
    CHECK(t[1][1] == "package_manager"); // empty source -> ecosystem rpm
    CHECK(t[2][0] == kV3Apps);
    CHECK(t[2][1] == "installer");
    // The two MSI-product rows share an identity (R4's future consolidation key) but not an
    // instance.
    CHECK(t[0][4] == t[2][4]);
    CHECK(t[0][5] != t[2][5]);

    // The v2 hash bytes are untouched by any of it.
    CHECK(stored_hash(pool, "agent-msi") == SoftwareInventoryStore::canonical_hash(rows));
    CHECK(facet_count(pool, "agent-msi") == "0");
}

TEST_CASE("v3: a full section replaces only its own facet and records its facet state",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0", "C:\\Apps\\Alpha");
    const auto a2 = v3_entry("Beta", kV3Apps);
    const auto p1 = v3_entry("libfoo", kV3Pkgs);

    auto res = store.apply_installed_software_v3(
        "agent-v3", v3_report({v3_full(kV3Apps, {a2, a1}), v3_full(kV3Pkgs, {p1})}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].facet == kV3Apps);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(res[1].facet == kV3Pkgs);
    CHECK(res[1].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-v3", kV3Apps) == std::vector<std::string>{"Alpha", "Beta"});
    CHECK(names_of(pool, "agent-v3", kV3Pkgs) == std::vector<std::string>{"libfoo"});

    // Derived columns and the stored location landed.
    SoftwareEntry expect_alpha = a1;
    SoftwareInventoryStore::derive_install_keys(expect_alpha);
    const auto keyed = sql_rows(pool, "SELECT install_type, install_scope, install_location, "
                                      "identity_key, instance_key FROM "
                                      "software_inventory_store.installed_software "
                                      "WHERE agent_id = 'agent-v3' AND name = 'Alpha'");
    REQUIRE(keyed.size() == 1);
    CHECK(keyed[0][0] == "installer");
    CHECK(keyed[0][1] == "machine");
    CHECK(keyed[0][2] == "C:\\Apps\\Alpha");
    CHECK(keyed[0][3] == expect_alpha.identity_key);
    CHECK(keyed[0][4] == expect_alpha.instance_key);

    // Facet state: status, token, the recomputed section hash, a confirmation time.
    const auto fs = sql_rows(pool, "SELECT facet, status, token, section_hash, enabled::text, "
                                   "duration_ms, bytes_read, (last_confirmed_at > 0)::text, "
                                   "(updated_at > 0)::text FROM "
                                   "software_inventory_store.software_facet_state "
                                   "WHERE agent_id = 'agent-v3' ORDER BY facet");
    REQUIRE(fs.size() == 2);
    const std::vector<std::string> apps_state = {
        kV3Apps, "full", "", section_hash_of({a1, a2}), "true", "11", "22", "true", "true"};
    CHECK(fs[0] == apps_state);
    CHECK(fs[1][0] == kV3Pkgs);
    CHECK(fs[1][3] == section_hash_of({p1}));

    // The stored report hash is the v3 aggregate; hash-only claims match it, nothing else.
    const std::string h_apps = section_hash_of({a1, a2});
    const std::string h_pkgs = section_hash_of({p1});
    const std::string agg =
        SoftwareInventoryStore::v3_report_hash({{kV3Pkgs, h_pkgs}, {kV3Apps, h_apps}});
    CHECK(agg.starts_with("v3:"));
    CHECK(stored_hash(pool, "agent-v3") == agg);
    CHECK(store.apply_installed_software("agent-v3", agg, std::nullopt, 0) ==
          InventoryIngestOutcome::kTouched);
    CHECK(store.apply_installed_software("agent-v3", "v3:" + std::string(64, '0'), std::nullopt,
                                         0) == InventoryIngestOutcome::kNeedFull);
    // A v2 (plain hex) claim never matches a v3 state, even one built from the same rows.
    CHECK(store.apply_installed_software("agent-v3",
                                         SoftwareInventoryStore::canonical_hash({a1, a2, p1}),
                                         std::nullopt, 0) == InventoryIngestOutcome::kNeedFull);

    // A second call carrying ONLY the apps facet replaces it and leaves the packages alone.
    const auto a3 = v3_entry("Gamma", kV3Apps);
    res = store.apply_installed_software_v3("agent-v3", v3_report({v3_full(kV3Apps, {a3})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-v3", kV3Apps) == std::vector<std::string>{"Gamma"});
    CHECK(names_of(pool, "agent-v3", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    CHECK(stored_hash(pool, "agent-v3") ==
          SoftwareInventoryStore::v3_report_hash(
              {{kV3Pkgs, h_pkgs}, {kV3Apps, section_hash_of({a3})}}));

    // An honest-empty full section deletes the facet's rows (and only those).
    res = store.apply_installed_software_v3("agent-v3", v3_report({v3_full(kV3Apps, {})}));
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-v3", kV3Apps).empty());
    CHECK(names_of(pool, "agent-v3", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    CHECK(sql_rows(pool,
                   "SELECT section_hash FROM software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-v3' AND facet = $1",
                   {kV3Apps})[0][0] == kEmptySectionHash);

    // Rows a section sends twice collapse; the section hash is over the de-duplicated set.
    res =
        store.apply_installed_software_v3("agent-v3", v3_report({v3_full(kV3Apps, {a1, a1, a2})}));
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-v3", kV3Apps) == std::vector<std::string>{"Alpha", "Beta"});
    CHECK(sql_rows(pool,
                   "SELECT section_hash FROM software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-v3' AND facet = $1",
                   {kV3Apps})[0][0] == h_apps);
}

namespace {

SoftwareEntry v3_linux(const std::string& name, const std::string& ecosystem,
                       const std::string& version, const std::string& release,
                       const std::string& source = kV3Apps) {
    SoftwareEntry e;
    e.name = name;
    e.version = version;
    e.release = release;
    e.kind = "package";
    e.ecosystem = ecosystem;
    e.arch = "amd64";
    e.distro_id = "debian";
    e.distro_version = "12";
    e.source = source;
    return e;
}

std::string purl_of(PgPool& pool, const std::string& agent, const std::string& name) {
    const auto t = sql_rows(pool,
                            "SELECT purl FROM software_inventory_store.installed_software "
                            "WHERE agent_id = $1 AND name = $2",
                            {agent, name});
    return t.size() == 1 ? t[0][0] : std::string("<" + std::to_string(t.size()) + " rows>");
}

} // namespace

TEST_CASE("v3: a full section stores the composed purl; no-type ecosystems and v2 rows store ''",
          "[pg][software_inventory][v3][purl]") {
    SWINV_SHARED(store, pool);
    const auto deb = v3_linux("Curl", "deb", "7.88.1", "10");
    const auto win = v3_entry("Alpha", kV3Apps); // ecosystem windows: no registered purl type
    auto brew = v3_entry("sqlite", kV3Pkgs, "3.43.2");
    brew.ecosystem = "brew";
    brew.kind = "pkg";

    const auto res = store.apply_installed_software_v3(
        "agent-purl", v3_report({v3_full(kV3Apps, {deb, win}), v3_full(kV3Pkgs, {brew})}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(purl_of(pool, "agent-purl", "Curl") ==
          "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12");
    CHECK(purl_of(pool, "agent-purl", "Alpha") == "");
    CHECK(purl_of(pool, "agent-purl", "sqlite") == "pkg:brew/sqlite@3.43.2");

    // The stored purl is exactly what the pure composer returns for the stored row, and it is
    // in neither hash: the section hash is the same with the purl field cleared or set.
    CHECK(purl_of(pool, "agent-purl", "Curl") == compose_purl(deb));
    auto with_purl = deb;
    with_purl.purl = "pkg:deb/other/other@0";
    CHECK(section_hash_of({with_purl}) == section_hash_of({deb}));

    // A v2 report leaves the purl empty (the same coexistence rule as install_location).
    const std::vector<SoftwareEntry> v2rows = {deb};
    REQUIRE(store.apply_installed_software("agent-v2purl",
                                           SoftwareInventoryStore::canonical_hash(v2rows), v2rows,
                                           0) == InventoryIngestOutcome::kStored);
    CHECK(purl_of(pool, "agent-v2purl", "Curl") == "");

    // The device's first v3 report fills it in.
    REQUIRE(store.apply_installed_software_v3("agent-v2purl",
                                              v3_report({v3_full(kV3Apps, {deb})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(purl_of(pool, "agent-v2purl", "Curl") ==
          "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12");
}

TEST_CASE("v3: a re-report with a changed version replaces the purl", "[pg][software_inventory][v3][purl]") {
    SWINV_SHARED(store, pool);
    REQUIRE(store.apply_installed_software_v3(
                "agent-purl-up", v3_report({v3_full(kV3Apps, {v3_linux("curl", "deb", "7.88.1", "10")})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(purl_of(pool, "agent-purl-up", "curl") ==
          "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12");
    REQUIRE(store.apply_installed_software_v3(
                "agent-purl-up", v3_report({v3_full(kV3Apps, {v3_linux("curl", "deb", "7.88.1", "11")})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(purl_of(pool, "agent-purl-up", "curl") ==
          "pkg:deb/debian/curl@7.88.1-11?arch=amd64&distro=debian-12");
    CHECK(row_count(pool, "agent-purl-up") == "1");
    // An honest-empty section removes the purl with its row.
    REQUIRE(store.apply_installed_software_v3("agent-purl-up", v3_report({v3_full(kV3Apps, {})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(store.find_by_purl("pkg:deb/debian/curl@7.88.1-11?arch=amd64&distro=debian-12")
              .value()
              .empty());
}

TEST_CASE("find_by_purl: exact match across agents, ordered, bounded, and served by the index",
          "[pg][software_inventory][v3][purl]") {
    SWINV_SHARED(store, pool);
    const auto curl = v3_linux("curl", "deb", "7.88.1", "10");
    for (const char* agent : {"agent-pb", "agent-pa"}) {
        REQUIRE(store.apply_installed_software_v3(
                    agent, v3_report({v3_full(kV3Apps, {curl, v3_linux("git", "deb", "2.39.2", "1")})}))[0]
                    .outcome == V3SectionOutcome::kStored);
    }
    REQUIRE(store.apply_installed_software_v3(
                "agent-pc", v3_report({v3_full(kV3Apps, {v3_linux("curl", "deb", "7.88.1", "9")})}))[0]
                .outcome == V3SectionOutcome::kStored);

    const std::string target = "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12";
    auto hit = store.find_by_purl(target);
    REQUIRE(hit.has_value());
    REQUIRE(hit->size() == 2); // exact: -9 and git do not match
    CHECK((*hit)[0].agent_id == "agent-pa"); // ordered by agent_id
    CHECK((*hit)[1].agent_id == "agent-pb");
    CHECK((*hit)[0].entry.name == "curl");
    CHECK((*hit)[0].entry.version == "7.88.1");
    CHECK((*hit)[0].entry.ecosystem == "deb");
    CHECK((*hit)[0].entry.purl == target);
    CHECK((*hit)[0].install_id > 0);

    CHECK(store.find_by_purl(target, 1).value().size() == 1);                 // limit honoured
    CHECK(store.find_by_purl(target + "x").value().empty());                  // no prefix matching
    CHECK(store.find_by_purl("PKG:DEB/DEBIAN/CURL@7.88.1-10").value().empty()); // case sensitive
    CHECK(store.find_by_purl("").value().empty()); // '' names "no purl": a precondition miss

    // The statement reaches the partial index (seq scan priced out: the table is tiny).
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    const std::vector<std::string> none;
    struct RollbackGuard {
        PGconn* conn;
        ~RollbackGuard() { pg::exec_params(conn, "ROLLBACK", std::vector<std::string>{}); }
    };
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", none).status() == PGRES_COMMAND_OK);
    const RollbackGuard rollback{lease.get()};
    REQUIRE(pg::exec_params(lease.get(), "SET LOCAL enable_seqscan = off", none).status() ==
            PGRES_COMMAND_OK);
    pg::PgResult plan = pg::exec_params(
        lease.get(), ("EXPLAIN (COSTS OFF) " + SoftwareInventoryStore::find_by_purl_sql()).c_str(),
        std::vector<std::string>{target, "100"});
    REQUIRE(plan.status() == PGRES_TUPLES_OK);
    std::string text;
    for (int i = 0; i < PQntuples(plan.get()); ++i)
        text += std::string(PQgetvalue(plan.get(), i, 0)) + "\n";
    CHECK(text.find("installed_software_purl_idx") != std::string::npos);
}

TEST_CASE("v3: the first v3 call deletes every row the v2 path left, and only that call",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    SoftwareEntry v2_apps = v3_entry("OldApp", kV3Apps);
    SoftwareEntry v2_py = v3_entry("OldPython", kV3Py);
    SoftwareEntry v2_bare = full_v2_entry(); // pre-tail: empty source
    const std::vector<SoftwareEntry> v2rows = {v2_apps, v2_py, v2_bare};
    REQUIRE(store.apply_installed_software("agent-tr",
                                           SoftwareInventoryStore::canonical_hash(v2rows), v2rows,
                                           0) == InventoryIngestOutcome::kStored);
    REQUIRE(row_count(pool, "agent-tr") == "3");
    REQUIRE_FALSE(stored_hash(pool, "agent-tr").starts_with("v3:"));

    // A facet-state row left by an older binary's v2 replace (which does not know the table)
    // must not survive the switch either, or it would stay in the report hash for ever.
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.software_facet_state "
                   "(agent_id, facet, status, section_hash) "
                   "VALUES ('agent-tr', $1, 'full', 'stale-hash')",
                   {kV3Py}));

    // The agent's first v3 contact carries one section only.
    const auto p1 = v3_entry("libfoo", kV3Pkgs);
    auto res = store.apply_installed_software_v3("agent-tr", v3_report({v3_full(kV3Pkgs, {p1})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(row_count(pool, "agent-tr") == "1"); // no v2 leftover of ANY source survives
    CHECK(names_of(pool, "agent-tr", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    CHECK(facet_count(pool, "agent-tr") == "1"); // the stale facet row went too
    CHECK(stored_hash(pool, "agent-tr") ==
          SoftwareInventoryStore::v3_report_hash({{kV3Pkgs, section_hash_of({p1})}}));

    // From then on a section replaces only its own facet: a second call must not wipe the first.
    const auto a1 = v3_entry("Alpha", kV3Apps);
    res = store.apply_installed_software_v3("agent-tr", v3_report({v3_full(kV3Apps, {a1})}));
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(row_count(pool, "agent-tr") == "2");

    // A bystander agent is never touched by another agent's transition.
    REQUIRE(store.apply_installed_software("agent-by",
                                           SoftwareInventoryStore::canonical_hash(v2rows), v2rows,
                                           0) == InventoryIngestOutcome::kStored);
    res = store.apply_installed_software_v3("agent-tr", v3_report({v3_full(kV3Apps, {})}));
    CHECK(row_count(pool, "agent-by") == "3");

    // A first contact that is STATUS-ONLY is the transition too: no v2 row survives it, the
    // facet state records the status, and the report hash carries no section.
    REQUIRE(store.apply_installed_software("agent-st",
                                           SoftwareInventoryStore::canonical_hash(v2rows), v2rows,
                                           0) == InventoryIngestOutcome::kStored);
    REQUIRE(row_count(pool, "agent-st") == "3");
    res = store.apply_installed_software_v3(
        "agent-st", v3_report({v3_status(kV3Apps, V3Status::kConstrained, "windows:apps:tok")}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kStatusOnly);
    CHECK(row_count(pool, "agent-st") == "0");
    CHECK(sql_rows(pool,
                   "SELECT status FROM software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-st' AND facet = $1",
                   {kV3Apps})[0][0] == "constrained");
    CHECK(stored_hash(pool, "agent-st") == SoftwareInventoryStore::v3_report_hash({}));
}

TEST_CASE("v3: a status-only section records the status and leaves rows and confirmation alone",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto p1 = v3_entry("libfoo", kV3Pkgs);
    REQUIRE(store
                .apply_installed_software_v3(
                    "agent-so", v3_report({v3_full(kV3Apps, {a1}), v3_full(kV3Pkgs, {p1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    // Pin last_confirmed_at to a sentinel so "untouched" cannot pass by coincidence of the clock.
    REQUIRE(sql_ok(pool, "UPDATE software_inventory_store.software_facet_state "
                         "SET last_confirmed_at = 12345 WHERE agent_id = 'agent-so'"));

    const auto res = store.apply_installed_software_v3(
        "agent-so",
        v3_report({v3_status(kV3Apps, V3Status::kConstrained, "windows:apps:registry_unreadable"),
                   v3_status(kV3Py, V3Status::kDisabled),
                   v3_status(kV3Pkgs, V3Status::kTimeout, "timeout")}));
    REQUIRE(res.size() == 3);
    for (const auto& r : res)
        CHECK(r.outcome == V3SectionOutcome::kStatusOnly);

    CHECK(names_of(pool, "agent-so", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(names_of(pool, "agent-so", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    const auto fs = sql_rows(pool, "SELECT facet, status, token, section_hash, enabled::text, "
                                   "last_confirmed_at, duration_ms, bytes_read FROM "
                                   "software_inventory_store.software_facet_state "
                                   "WHERE agent_id = 'agent-so' ORDER BY facet");
    REQUIRE(fs.size() == 3);
    // apps: status moved, its last full's hash and confirmation time are still there.
    CHECK(fs[0] ==
          (std::vector<std::string>{kV3Apps, "constrained", "windows:apps:registry_unreadable",
                                    section_hash_of({a1}), "true", "12345", "5", "6"}));
    CHECK(fs[1] == (std::vector<std::string>{kV3Pkgs, "timeout", "timeout", section_hash_of({p1}),
                                             "true", "12345", "5", "6"}));
    // A facet never seen before: no hash, never confirmed, and `disabled` clears `enabled`.
    CHECK(fs[2] == (std::vector<std::string>{kV3Py, "disabled", "", "", "false", "0", "5", "6"}));

    // None of the three is in a full/delta status any more, so the report hash holds no section.
    CHECK(stored_hash(pool, "agent-so") == SoftwareInventoryStore::v3_report_hash({}));

    // The facet comes back: a full section re-confirms it and puts it in the report hash again.
    const auto back =
        store.apply_installed_software_v3("agent-so", v3_report({v3_full(kV3Apps, {a1})}));
    CHECK(back[0].outcome == V3SectionOutcome::kStored);
    CHECK(stored_hash(pool, "agent-so") ==
          SoftwareInventoryStore::v3_report_hash({{kV3Apps, section_hash_of({a1})}}));
    CHECK(sql_rows(pool,
                   "SELECT (last_confirmed_at > 12345)::text, enabled::text, token FROM "
                   "software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-so' AND facet = $1",
                   {kV3Apps})[0] == (std::vector<std::string>{"true", "true", ""}));
}

// ── SAM-14: delta apply, the change ledger, components, retention ────────────────────────────

namespace {

using yuzu::server::SoftwareChange;
using yuzu::server::SoftwareChangeKind;
using yuzu::server::V3Component;

SoftwareEntry keyed(SoftwareEntry e) {
    SoftwareInventoryStore::derive_install_keys(e);
    return e;
}

// A delta section: `-` instance_keys of `removed`, `+` rows `added`, the agent's post-apply hash.
V3Section v3_delta(const std::string& facet, const std::string& base,
                   const std::vector<SoftwareEntry>& after, const std::vector<SoftwareEntry>& removed,
                   std::vector<SoftwareEntry> added) {
    V3Section s;
    s.facet = facet;
    s.status = V3Status::kDelta;
    s.base = base;
    s.expect = section_hash_of(after);
    for (const auto& r : removed)
        s.deletions.push_back(keyed(r).instance_key);
    s.rows = std::move(added);
    s.duration_ms = 3;
    s.bytes_read = 4;
    return s;
}

// Ledger rows of one agent, oldest first: kind, name, from, to, instance_key, observed_at.
SqlTable ledger(PgPool& pool, const std::string& agent) {
    return sql_rows(pool,
                    "SELECT kind, name, from_version, to_version, instance_key, "
                    "observed_at::text FROM software_inventory_store.software_changes "
                    "WHERE agent_id = $1 ORDER BY change_id",
                    {agent});
}

std::string ledger_count(PgPool& pool, const std::string& agent) {
    return sql_rows(pool,
                    "SELECT count(*) FROM software_inventory_store.software_changes "
                    "WHERE agent_id = $1",
                    {agent})[0][0];
}

std::string facet_status(PgPool& pool, const std::string& agent, const std::string& facet) {
    const auto t = sql_rows(pool,
                            "SELECT status || '/' || section_hash FROM "
                            "software_inventory_store.software_facet_state "
                            "WHERE agent_id = $1 AND facet = $2",
                            {agent, facet});
    return t.empty() ? std::string("<none>") : t[0][0];
}

std::string instance_key_of(PgPool& pool, const std::string& agent, const std::string& name) {
    return sql_rows(pool,
                    "SELECT instance_key FROM software_inventory_store.installed_software "
                    "WHERE agent_id = $1 AND name = $2",
                    {agent, name})[0][0];
}

V3Component comp(const std::string& name, const std::string& path, const std::string& version = "1.0",
                 std::int64_t size = 10, std::int64_t mtime = 100) {
    V3Component k;
    k.kind = "jar";
    k.name = name;
    k.version = version;
    k.version_source = "pom";
    k.path = path;
    k.size = size;
    k.mtime = mtime;
    k.anchor_app = "AcmeApp";
    return k;
}

V3Section comp_full(std::vector<V3Component> rows) {
    V3Section s = v3_status(kV3Comp, V3Status::kFull);
    s.components = std::move(rows);
    return s;
}

V3Section comp_delta(const std::string& base, const std::vector<V3Component>& after,
                     const std::vector<V3Component>& removed, std::vector<V3Component> added) {
    V3Section s = v3_status(kV3Comp, V3Status::kDelta);
    s.base = base;
    s.expect = SoftwareInventoryStore::canonical_component_section_hash(after);
    for (const auto& r : removed)
        s.deletions.push_back(SoftwareInventoryStore::component_row_hash(r));
    s.components = std::move(added);
    return s;
}

std::string comp_hash_of(const std::vector<V3Component>& rows) {
    return SoftwareInventoryStore::canonical_component_section_hash(rows);
}

SqlTable comp_rows(PgPool& pool, const std::string& agent) {
    return sql_rows(pool,
                    "SELECT name, version, first_seen::text FROM "
                    "software_inventory_store.software_components WHERE agent_id = $1 "
                    "ORDER BY name, path",
                    {agent});
}

} // namespace

TEST_CASE("v3: a first full section is a baseline: rows written, no ledger rows",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto res = store.apply_installed_software_v3("agent-bl", v3_report({v3_full(kV3Apps, {a1})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(row_count(pool, "agent-bl") == "1");
    CHECK(ledger_count(pool, "agent-bl") == "0");

    // The ledger, component and retention tables exist (migration v11) and start empty.
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.software_components")[0][0] ==
          "0");
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.retention_meta")[0][0] == "0");
}

TEST_CASE("v3: a delta upgrade applies as -old +new, writes one upgrade row and verifies its hash",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    const auto b1 = v3_entry("Beta", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-up",
                                              v3_report({v3_full(kV3Apps, {a1, b1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string base = section_hash_of({a1, b1});
    const std::string after = section_hash_of({a2, b1});

    const auto res = store.apply_installed_software_v3(
        "agent-up", v3_report({v3_delta(kV3Apps, base, {a2, b1}, {a1}, {a2})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-up", kV3Apps) == (std::vector<std::string>{"Alpha", "Beta"}));
    CHECK(sql_rows(pool, "SELECT version FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-up' AND name = 'Alpha'")[0][0] == "2.0");
    CHECK(facet_status(pool, "agent-up", kV3Apps) == "delta/" + after);
    // The report hash is rebuilt from the held section hashes.
    CHECK(stored_hash(pool, "agent-up") ==
          SoftwareInventoryStore::v3_report_hash({{kV3Apps, after}}));
    const auto led = ledger(pool, "agent-up");
    REQUIRE(led.size() == 1);
    CHECK(led[0][0] == "upgrade");
    CHECK(led[0][1] == "Alpha");
    CHECK(led[0][2] == "1.0");
    CHECK(led[0][3] == "2.0");
    CHECK(led[0][4] == instance_key_of(pool, "agent-up", "Alpha")); // the stable row identity
    CHECK_FALSE(led[0][4].empty());

    // A chained delta: the held section hash is now `after`, and a delta on the OLD base asks for
    // a full section.
    const auto stale = store.apply_installed_software_v3(
        "agent-up", v3_report({v3_delta(kV3Apps, base, {b1}, {a2}, {})}));
    CHECK(stale[0].outcome == V3SectionOutcome::kNeedFull);
    const auto chained = store.apply_installed_software_v3(
        "agent-up", v3_report({v3_delta(kV3Apps, after, {a2}, {b1}, {})}));
    CHECK(chained[0].outcome == V3SectionOutcome::kStored);
    const auto led2 = ledger(pool, "agent-up");
    REQUIRE(led2.size() == 2);
    CHECK(led2[1][0] == "remove");
    CHECK(led2[1][1] == "Beta");
    CHECK_FALSE(led2[1][4].empty()); // a remove still names the removed row's instance_key
}

TEST_CASE("v3: a delta on a base the server does not hold is need-full and writes nothing",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-dl", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string held = section_hash_of({a1});
    const std::string before = stored_hash(pool, "agent-dl");

    V3Section stale = v3_delta(kV3Apps, "not-the-held-hash", {a1}, {}, {});
    V3Section unseen = v3_delta(kV3Pkgs, "whatever", {}, {}, {}); // no state for the facet at all
    V3Section empty_base = v3_delta(kV3Py, "", {}, {}, {});       // an empty base matches nothing

    const auto res =
        store.apply_installed_software_v3("agent-dl", v3_report({stale, unseen, empty_base}));
    REQUIRE(res.size() == 3);
    for (const auto& r : res) {
        CHECK(r.outcome == V3SectionOutcome::kNeedFull);
        CHECK(yuzu::server::v3_section_needs_full(r.outcome));
    }
    CHECK(names_of(pool, "agent-dl", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(stored_hash(pool, "agent-dl") == before);
    CHECK(facet_status(pool, "agent-dl", kV3Apps) == "full/" + held);
    CHECK(ledger_count(pool, "agent-dl") == "0");
}

TEST_CASE("v3: a delta that does not verify is rolled back alone and nacked as a mismatch",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    const auto p1 = v3_entry("libfoo", kV3Pkgs, "1.0");
    const auto p2 = v3_entry("libfoo", kV3Pkgs, "2.0");
    REQUIRE(store.apply_installed_software_v3(
                "agent-mm", v3_report({v3_full(kV3Apps, {a1}), v3_full(kV3Pkgs, {p1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string apps_base = section_hash_of({a1});
    const std::string pkgs_base = section_hash_of({p1});
    const std::string agg_before = stored_hash(pool, "agent-mm");
    const auto unchanged = [&] {
        CHECK(names_of(pool, "agent-mm", kV3Apps) == std::vector<std::string>{"Alpha"});
        CHECK(sql_rows(pool, "SELECT version FROM software_inventory_store.installed_software "
                             "WHERE agent_id = 'agent-mm' AND name = 'Alpha'")[0][0] == "1.0");
        CHECK(facet_status(pool, "agent-mm", kV3Apps) == "full/" + apps_base);
    };
    const auto no_ledger = [&] { CHECK(ledger_count(pool, "agent-mm") == "0"); };

    SECTION("a - naming a row the server does not hold (fewer rows than named)") {
        const auto ghost = v3_entry("Ghost", kV3Apps);
        const auto res = store.apply_installed_software_v3(
            "agent-mm", v3_report({v3_delta(kV3Apps, apps_base, {a2}, {a1, ghost}, {a2})}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
        CHECK(yuzu::server::v3_section_needs_full(res[0].outcome));
        unchanged();
        no_ledger();
    }
    SECTION("a + colliding with a held row's instance_key") {
        // a1 is held and not removed: re-adding it violates the per-agent instance uniqueness.
        const auto res = store.apply_installed_software_v3(
            "agent-mm", v3_report({v3_delta(kV3Apps, apps_base, {a1}, {}, {a1})}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
        unchanged();
        no_ledger();
    }
    SECTION("a post-apply hash other than the agent's expect") {
        auto d = v3_delta(kV3Apps, apps_base, {a2}, {a1}, {a2});
        d.expect = std::string(64, '0');
        const auto res = store.apply_installed_software_v3("agent-mm", v3_report({d}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
        unchanged();
        no_ledger();
    }
    SECTION("the other sections of the same call still apply") {
        auto bad = v3_delta(kV3Apps, apps_base, {a2}, {a1}, {a2});
        bad.expect = std::string(64, '1');
        const auto res = store.apply_installed_software_v3(
            "agent-mm",
            v3_report({bad, v3_delta(kV3Pkgs, pkgs_base, {p2}, {p1}, {p2})}));
        REQUIRE(res.size() == 2);
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
        CHECK(res[1].outcome == V3SectionOutcome::kStored);
        unchanged();
        CHECK(facet_status(pool, "agent-mm", kV3Pkgs) == "delta/" + section_hash_of({p2}));
        const auto led = ledger(pool, "agent-mm");
        REQUIRE(led.size() == 1); // only the applied section's ledger row survived
        CHECK(led[0][0] == "upgrade");
        CHECK(led[0][1] == "libfoo");
        // The report hash covers the applied section and the untouched one.
        CHECK(stored_hash(pool, "agent-mm") ==
              SoftwareInventoryStore::v3_report_hash(
                  {{kV3Apps, apps_base}, {kV3Pkgs, section_hash_of({p2})}}));
        CHECK(stored_hash(pool, "agent-mm") != agg_before);
    }
    SECTION("a repeated - names one row: the unique count is what must match") {
        auto d = v3_delta(kV3Apps, apps_base, {a2}, {a1}, {a2});
        d.deletions.push_back(d.deletions[0]);
        const auto res = store.apply_installed_software_v3("agent-mm", v3_report({d}));
        CHECK(res[0].outcome == V3SectionOutcome::kStored);
    }
}

TEST_CASE("v3: yuzu_software_changes_total moves after a committed section and not on a rollback",
          "[pg][software_inventory][v3][ledger][metrics]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    const auto total = [&](const char* kind) {
        return metrics.counter("yuzu_software_changes_total", {{"kind", kind}}).value();
    };
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    REQUIRE(store.apply_installed_software_v3("agent-mc", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(total("upgrade") == 0.0); // a baseline writes no ledger row and counts nothing

    // A delta that does not verify is rolled back: its ledger rows are never counted.
    auto bad = v3_delta(kV3Apps, section_hash_of({a1}), {a2}, {a1}, {a2});
    bad.expect = std::string(64, '0');
    REQUIRE(store.apply_installed_software_v3("agent-mc", v3_report({bad}))[0].outcome ==
            V3SectionOutcome::kMismatch);
    CHECK(total("upgrade") == 0.0);
    CHECK(ledger_count(pool, "agent-mc") == "0");

    REQUIRE(store.apply_installed_software_v3(
                "agent-mc",
                v3_report({v3_delta(kV3Apps, section_hash_of({a1}), {a2}, {a1}, {a2})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(total("upgrade") == 1.0);
    CHECK(total("install") == 0.0);
    CHECK(total("remove") == 0.0);
    CHECK(ledger_count(pool, "agent-mc") == "1");
    store.set_metrics(nullptr);
}

TEST_CASE("v3: a full section on a held facet writes remove/install/upgrade rows",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto alpha1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto alpha2 = v3_entry("Alpha", kV3Apps, "2.0");
    const auto beta = v3_entry("Beta", kV3Apps);
    const auto gamma = v3_entry("Gamma", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-fd",
                                              v3_report({v3_full(kV3Apps, {alpha1, beta})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-fd") == "0");

    // Alpha upgraded, Beta gone, Gamma new.
    REQUIRE(store.apply_installed_software_v3("agent-fd",
                                              v3_report({v3_full(kV3Apps, {alpha2, gamma})}))[0]
                .outcome == V3SectionOutcome::kStored);
    auto led = ledger(pool, "agent-fd");
    REQUIRE(led.size() == 3);
    std::map<std::string, std::vector<std::string>> by_name;
    for (const auto& r : led)
        by_name[r[1]] = r;
    CHECK(by_name["Alpha"][0] == "upgrade");
    CHECK(by_name["Alpha"][2] == "1.0");
    CHECK(by_name["Alpha"][3] == "2.0");
    CHECK(by_name["Beta"][0] == "remove");
    CHECK(by_name["Beta"][2] == "1.0");
    CHECK(by_name["Gamma"][0] == "install");
    CHECK(by_name["Gamma"][3] == "1.0");
    // One apply call = one observed_at (with the agent, the group key of its rows).
    CHECK(by_name["Alpha"][5] == by_name["Beta"][5]);
    CHECK(by_name["Beta"][5] == by_name["Gamma"][5]);

    // An unchanged re-report writes nothing.
    REQUIRE(store.apply_installed_software_v3("agent-fd",
                                              v3_report({v3_full(kV3Apps, {alpha2, gamma})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-fd") == "3");

    // An honest-empty full removes everything; the next populated full installs it all again.
    REQUIRE(store.apply_installed_software_v3("agent-fd", v3_report({v3_full(kV3Apps, {})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-fd") == "5"); // + remove Alpha, remove Gamma
    REQUIRE(store.apply_installed_software_v3("agent-fd",
                                              v3_report({v3_full(kV3Apps, {alpha2, gamma})}))[0]
                .outcome == V3SectionOutcome::kStored);
    led = ledger(pool, "agent-fd");
    REQUIRE(led.size() == 7);
    CHECK(led[5][0] == "install");
    CHECK(led[6][0] == "install");
    // A held facet with zero rows is not a baseline.
    CHECK(facet_status(pool, "agent-fd", kV3Apps) == "full/" + section_hash_of({alpha2, gamma}));
}

TEST_CASE("v3: a status-only section then a full one diffs against the rows left in place; "
          "a disabled facet is a baseline",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);

    SECTION("timeout then a full carrying an upgrade: one upgrade row") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Apps, V3Status::kTimeout, "timeout")}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        CHECK(names_of(pool, "agent-to", kV3Apps) == std::vector<std::string>{"Alpha"}); // in place
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        const auto led = ledger(pool, "agent-to");
        REQUIRE(led.size() == 1);
        CHECK(led[0][0] == "upgrade");
    }
    SECTION("timeout twice keeps the stored hash, and the next full still diffs") {
        for (int i = 0; i < 2; ++i)
            REQUIRE(store.apply_installed_software_v3(
                        "agent-to", v3_report({v3_status(kV3Apps, V3Status::kTimeout, "timeout")}))[0]
                        .outcome == V3SectionOutcome::kStatusOnly);
        CHECK(facet_status(pool, "agent-to", kV3Apps) == "timeout/" + section_hash_of({a1}));
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(ledger_count(pool, "agent-to") == "1");
    }
    SECTION("a never-held facet whose first section is status-only: its first full is a baseline") {
        // kV3Pkgs has no facet_state row yet; the status-only section creates one with no hash.
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Pkgs, V3Status::kTimeout, "timeout")}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        CHECK(facet_status(pool, "agent-to", kV3Pkgs) == "timeout/");
        const auto p1 = v3_entry("libfoo", kV3Pkgs, "1.0");
        const auto p2 = v3_entry("libbar", kV3Pkgs, "1.0");
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Pkgs, {p1, p2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(names_of(pool, "agent-to", kV3Pkgs).size() == 2);
        CHECK(ledger_count(pool, "agent-to") == "0");
        // Once held, the facet diffs like any other.
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Pkgs, {p1})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(ledger_count(pool, "agent-to") == "1");
    }
    SECTION("a device whose first v3 call is status-only: its first full is a baseline") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-fs", v3_report({v3_status(kV3Apps, V3Status::kTimeout, "timeout")}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        REQUIRE(store.apply_installed_software_v3("agent-fs",
                                                  v3_report({v3_full(kV3Apps, {a1, v3_entry("B", kV3Apps)})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(row_count(pool, "agent-fs") == "2");
        CHECK(ledger_count(pool, "agent-fs") == "0");
    }
    SECTION("disabled, then a status-only timeout, then a full: still a baseline; a delta asks for a full") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Apps, V3Status::kDisabled)}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Apps, V3Status::kTimeout, "timeout")}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        // The timeout over a disabled facet cleared the stored hash.
        CHECK(facet_status(pool, "agent-to", kV3Apps) == "timeout/");
        CHECK(store.apply_installed_software_v3(
                  "agent-to",
                  v3_report({v3_delta(kV3Apps, section_hash_of({a1}), {a2}, {a1}, {a2})}))[0]
                  .outcome == V3SectionOutcome::kNeedFull);
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(ledger_count(pool, "agent-to") == "0");
        CHECK(facet_status(pool, "agent-to", kV3Apps) == "full/" + section_hash_of({a2}));
    }
    SECTION("a delta right after a status-only section needs a full: the status is not full|delta") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Apps, V3Status::kConstrained, "c")}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        const auto res = store.apply_installed_software_v3(
            "agent-to",
            v3_report({v3_delta(kV3Apps, section_hash_of({a1}), {a2}, {a1}, {a2})}));
        CHECK(res[0].outcome == V3SectionOutcome::kNeedFull);
    }
    SECTION("disabled then full: a baseline, no events, whatever changed meanwhile") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-to", v3_report({v3_status(kV3Apps, V3Status::kDisabled)}))[0]
                    .outcome == V3SectionOutcome::kStatusOnly);
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(ledger_count(pool, "agent-to") == "0");
        CHECK(facet_status(pool, "agent-to", kV3Apps) == "full/" + section_hash_of({a2}));
        // Once confirmed again the facet diffs like any other.
        REQUIRE(store.apply_installed_software_v3("agent-to", v3_report({v3_full(kV3Apps, {a1})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        CHECK(ledger_count(pool, "agent-to") == "1");
    }
}

TEST_CASE("v3: same title and version with a different instance_key writes no ledger row",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    auto churned = a1;
    churned.install_date = "2026-06-01"; // install_date churn: a new instance_key, the same version
    REQUIRE(keyed(a1).instance_key != keyed(churned).instance_key);
    REQUIRE(store.apply_installed_software_v3("agent-ch", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);

    SECTION("by a full section") {
        REQUIRE(store.apply_installed_software_v3("agent-ch",
                                                  v3_report({v3_full(kV3Apps, {churned})}))[0]
                    .outcome == V3SectionOutcome::kStored);
    }
    SECTION("by a delta") {
        REQUIRE(store.apply_installed_software_v3(
                    "agent-ch",
                    v3_report({v3_delta(kV3Apps, section_hash_of({a1}), {churned}, {a1}, {churned})}))[0]
                    .outcome == V3SectionOutcome::kStored);
    }
    CHECK(ledger_count(pool, "agent-ch") == "0");
    CHECK(sql_rows(pool, "SELECT install_date FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-ch'")[0][0] == "2026-06-01");
}

namespace {
// A distro-package-shaped row: the version column is upstream, release/epoch their own columns.
SoftwareEntry rpm_row(const std::string& name, const std::string& version,
                      const std::string& release, const std::string& epoch = "") {
    auto e = v3_entry(name, kV3Pkgs, version);
    e.kind = "package";
    e.ecosystem = "rpm";
    e.release = release;
    e.epoch = epoch;
    return e;
}
} // namespace

TEST_CASE("v3: a release-only or epoch-only change is an upgrade carrying "
          "[epoch:]version[-release]",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    struct Case {
        const char* agent;
        SoftwareEntry from;
        SoftwareEntry to;
        const char* from_text;
        const char* to_text;
    };
    // flatpak: version '' and the commit in release.
    auto flat1 = rpm_row("org.example.App", "", "3f2a9c1");
    auto flat2 = rpm_row("org.example.App", "", "8be04d7");
    flat1.ecosystem = flat2.ecosystem = "flatpak";
    const Case cases[] = {
        {"agent-rel", rpm_row("openssl", "3.0.7", "24.el9", "1"),
         rpm_row("openssl", "3.0.7", "25.el9", "1"), "1:3.0.7-24.el9", "1:3.0.7-25.el9"},
        {"agent-epo", rpm_row("openssl", "3.0.7", "24.el9", "1"),
         rpm_row("openssl", "3.0.7", "24.el9", "2"), "1:3.0.7-24.el9", "2:3.0.7-24.el9"},
        {"agent-flat", flat1, flat2, "3f2a9c1", "8be04d7"},
        {"agent-vr", rpm_row("curl", "7.76.1", "26.el9"), rpm_row("curl", "8.5.0", "1.el9"),
         "7.76.1-26.el9", "8.5.0-1.el9"},
    };
    for (const auto& c : cases) {
        CAPTURE(c.agent);
        REQUIRE(store.apply_installed_software_v3(c.agent,
                                                  v3_report({v3_full(kV3Pkgs, {c.from})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        // By a full section, then back again by a delta: both paths write one upgrade each.
        REQUIRE(store.apply_installed_software_v3(c.agent, v3_report({v3_full(kV3Pkgs, {c.to})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        REQUIRE(store.apply_installed_software_v3(
                    c.agent, v3_report({v3_delta(kV3Pkgs, section_hash_of({c.to}), {c.from},
                                                 {c.to}, {c.from})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        const auto led = ledger(pool, c.agent);
        REQUIRE(led.size() == 2);
        CHECK(led[0][0] == "upgrade");
        CHECK(led[0][2] == c.from_text);
        CHECK(led[0][3] == c.to_text);
        CHECK(led[1][0] == "upgrade");
        CHECK(led[1][2] == c.to_text);
        CHECK(led[1][3] == c.from_text);
    }

    // An unchanged re-report, and install_date churn at an equal tuple, write nothing.
    const auto p = rpm_row("bash", "5.1.8", "9.el9", "0");
    auto churned = p;
    churned.install_date = "2026-07-07";
    REQUIRE(store.apply_installed_software_v3("agent-same", v3_report({v3_full(kV3Pkgs, {p})}))[0]
                .outcome == V3SectionOutcome::kStored);
    REQUIRE(store.apply_installed_software_v3("agent-same", v3_report({v3_full(kV3Pkgs, {p})}))[0]
                .outcome == V3SectionOutcome::kStored);
    REQUIRE(store.apply_installed_software_v3("agent-same",
                                              v3_report({v3_full(kV3Pkgs, {churned})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-same") == "0");
}

TEST_CASE("v3: a held facet whose stored rows do not hash to its section hash is a baseline",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto b1 = v3_entry("Beta", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-oob",
                                              v3_report({v3_full(kV3Apps, {a1, b1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    // An out-of-band delete (no product path does this) leaves the facet_state hash behind.
    REQUIRE(sql_ok(pool, "DELETE FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-oob' AND name = 'Beta'"));
    REQUIRE(facet_status(pool, "agent-oob", kV3Apps) == "full/" + section_hash_of({a1, b1}));

    REQUIRE(store.apply_installed_software_v3("agent-oob",
                                              v3_report({v3_full(kV3Apps, {a1, b1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-oob") == "0"); // no phantom install of Beta
    CHECK(metrics.counter("yuzu_software_changes_total", {{"kind", "install"}}).value() == 0.0);
    CHECK(names_of(pool, "agent-oob", kV3Apps) == (std::vector<std::string>{"Alpha", "Beta"}));
    CHECK(facet_status(pool, "agent-oob", kV3Apps) == "full/" + section_hash_of({a1, b1}));

    // The rows agree with the hash again, so the next full diffs as usual.
    REQUIRE(store.apply_installed_software_v3("agent-oob", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(ledger_count(pool, "agent-oob") == "1");
    store.set_metrics(nullptr);
}

TEST_CASE("v3: a delta's - set reaches only the calling agent's rows of the section's facet",
          "[pg][software_inventory][v3][ledger]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto p1 = v3_entry("libfoo", kV3Pkgs);
    const auto victim = v3_entry("Victim", kV3Apps);
    const auto vc = comp("victim-core", "/opt/victim/core.jar");
    REQUIRE(store.apply_installed_software_v3(
                    "agent-a", v3_report({v3_full(kV3Apps, {a1}), v3_full(kV3Pkgs, {p1}),
                                          comp_full({comp("own", "/opt/own.jar")})}))[0]
                .outcome == V3SectionOutcome::kStored);
    REQUIRE(store.apply_installed_software_v3(
                    "agent-b", v3_report({v3_full(kV3Apps, {victim}), comp_full({vc})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string a_apps = section_hash_of({a1});
    const std::string b_state = facet_status(pool, "agent-b", kV3Apps);
    const std::string b_comp = facet_status(pool, "agent-b", kV3Comp);
    const std::string a_pkgs = facet_status(pool, "agent-a", kV3Pkgs);

    SECTION("agent A names agent B's row") {
        const auto res = store.apply_installed_software_v3(
            "agent-a", v3_report({v3_delta(kV3Apps, a_apps, {a1}, {victim}, {})}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    }
    SECTION("an apps section names the same agent's pkgs row") {
        const auto res = store.apply_installed_software_v3(
            "agent-a", v3_report({v3_delta(kV3Apps, a_apps, {a1}, {p1}, {})}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    }
    SECTION("agent A's component delta names agent B's component") {
        const auto own = comp("own", "/opt/own.jar");
        const auto res = store.apply_installed_software_v3(
            "agent-a", v3_report({comp_delta(comp_hash_of({own}), {own}, {vc}, {})}));
        CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    }
    CHECK(names_of(pool, "agent-b", kV3Apps) == std::vector<std::string>{"Victim"});
    CHECK(comp_rows(pool, "agent-b").size() == 1);
    CHECK(names_of(pool, "agent-a", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    CHECK(names_of(pool, "agent-a", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(facet_status(pool, "agent-b", kV3Apps) == b_state);
    CHECK(facet_status(pool, "agent-b", kV3Comp) == b_comp);
    CHECK(facet_status(pool, "agent-a", kV3Pkgs) == a_pkgs);
    CHECK(facet_status(pool, "agent-a", kV3Apps) == "full/" + a_apps);
    CHECK(ledger_count(pool, "agent-a") == "0");
    CHECK(ledger_count(pool, "agent-b") == "0");
}

TEST_CASE("v3: a SQL fault in a later section rolls back an earlier section, its ledger rows and "
          "the counter",
          "[pg][software_inventory][v3][ledger]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    REQUIRE(store.apply_installed_software_v3("agent-lf", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string held_report = stored_hash(pool, "agent-lf");

    // Section 1 (the Alpha upgrade) applies and writes its ledger row inside the transaction;
    // section 2's DELETE then fails on the renamed table and the whole call rolls back.
    REQUIRE(sql_ok(pool, "ALTER TABLE software_inventory_store.software_components "
                         "RENAME TO software_components_gone"));
    const auto res = store.apply_installed_software_v3(
        "agent-lf", v3_report({v3_delta(kV3Apps, section_hash_of({a1}), {a2}, {a1}, {a2}),
                               comp_full({comp("x", "/opt/x.jar")})}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].outcome == V3SectionOutcome::kError);
    CHECK(res[1].outcome == V3SectionOutcome::kError);
    CHECK(ledger_count(pool, "agent-lf") == "0");
    CHECK(sql_rows(pool, "SELECT version FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-lf' AND name = 'Alpha'")[0][0] == "1.0");
    CHECK(facet_status(pool, "agent-lf", kV3Apps) == "full/" + section_hash_of({a1}));
    CHECK(stored_hash(pool, "agent-lf") == held_report);
    for (const char* kind : {"install", "remove", "upgrade"})
        CHECK(metrics.counter("yuzu_software_changes_total", {{"kind", kind}}).value() == 0.0);
    store.set_metrics(nullptr);
}

TEST_CASE("diff_changes: pairing, upgrades, churn and leftovers (pure)",
          "[software_inventory][v3][ledger]") {
    const auto row = [](const std::string& name, const std::string& version,
                        const std::string& location = "", const std::string& date = "d") {
        auto e = v3_entry(name, kV3Apps, version, location);
        e.install_date = date;
        return keyed(std::move(e));
    };
    using Kind = SoftwareChangeKind;

    SECTION("nothing changed, or the same set reordered") {
        CHECK(SoftwareInventoryStore::diff_changes({row("A", "1"), row("B", "1")},
                                                   {row("B", "1"), row("A", "1")})
                  .empty());
    }
    SECTION("an upgrade pairs the removed and added row of one stem") {
        const auto ch = SoftwareInventoryStore::diff_changes({row("A", "1")}, {row("A", "2")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].kind == Kind::kUpgrade);
        CHECK(ch[0].from_version == "1");
        CHECK(ch[0].to_version == "2");
        CHECK(ch[0].instance_key == row("A", "2").instance_key); // the new row's
    }
    SECTION("different locations are different installs: remove + install, never an upgrade") {
        const auto ch = SoftwareInventoryStore::diff_changes({row("A", "1", "C:\\one")},
                                                             {row("A", "2", "C:\\two")});
        REQUIRE(ch.size() == 2);
        std::set<Kind> kinds{ch[0].kind, ch[1].kind};
        CHECK(kinds == (std::set<Kind>{Kind::kInstall, Kind::kRemove}));
    }
    SECTION("churn at an equal version is no event") {
        CHECK(SoftwareInventoryStore::diff_changes({row("A", "1", "", "d1")},
                                                   {row("A", "1", "", "d2")})
                  .empty());
    }
    SECTION("two upgrades of one title pair in (epoch, version, release) order, "
            "whatever the input order") {
        // Same stem (name, publisher, arch, location), equal install_date, four distinct
        // instance_keys. The k-th removed row in tuple order pairs the k-th added row in tuple
        // order. The labels are chosen so the added rows' instance_key order is the reverse of
        // their tuple order: pairing by instance_key would give 1 -> 4 and 1.5 -> 3.
        const auto olds = std::vector<SoftwareEntry>{row("A", "1.5"), row("A", "1")};
        const auto news = std::vector<SoftwareEntry>{row("A", "4"), row("A", "3")};
        REQUIRE(row("A", "4").instance_key < row("A", "3").instance_key);
        const auto reversed = [](const std::vector<SoftwareEntry>& v) {
            return std::vector<SoftwareEntry>(v.rbegin(), v.rend());
        };
        for (const auto& [o, n] :
             {std::pair{olds, news}, std::pair{reversed(olds), reversed(news)}}) {
            const auto ch = SoftwareInventoryStore::diff_changes(o, n);
            REQUIRE(ch.size() == 2);
            CHECK(ch[0].kind == Kind::kUpgrade);
            CHECK(ch[0].from_version == "1");
            CHECK(ch[0].to_version == "3");
            CHECK(ch[1].kind == Kind::kUpgrade);
            CHECK(ch[1].from_version == "1.5");
            CHECK(ch[1].to_version == "4");
            CHECK(ch[1].instance_key == row("A", "4").instance_key);
        }
    }
    SECTION("an equal tuple pairs first: churn beside an upgrade is one upgrade, never two") {
        // Removed {1, 2 (date d1)}; added {2 (date d2), 3}: 2 <-> 2 is churn, 1 -> 3 the one
        // upgrade. Pairing the k-th rows without the equal-tuple walk gives 1 -> 2 and 2 -> 3.
        const auto ch = SoftwareInventoryStore::diff_changes(
            {row("A", "1"), row("A", "2", "", "d1")}, {row("A", "2", "", "d2"), row("A", "3")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].kind == Kind::kUpgrade);
        CHECK(ch[0].from_version == "1");
        CHECK(ch[0].to_version == "3");
    }
    SECTION("release and epoch are part of the compared tuple and of the recorded text") {
        const auto rel = [&](const std::string& v, const std::string& r, const std::string& ep) {
            auto e = v3_entry("A", kV3Apps, v);
            e.release = r;
            e.epoch = ep;
            return keyed(std::move(e));
        };
        auto ch =
            SoftwareInventoryStore::diff_changes({rel("1.0", "1", "")}, {rel("1.0", "2", "")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].from_version == "1.0-1");
        CHECK(ch[0].to_version == "1.0-2");
        ch = SoftwareInventoryStore::diff_changes({rel("1.0", "", "3")}, {rel("1.0", "", "4")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].from_version == "3:1.0");
        CHECK(ch[0].to_version == "4:1.0");
        ch = SoftwareInventoryStore::diff_changes({rel("", "abc", "")}, {rel("", "def", "")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].from_version == "abc");
        CHECK(ch[0].to_version == "def");
        ch = SoftwareInventoryStore::diff_changes({rel("1.0", "1", "2")}, {});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].kind == Kind::kRemove);
        CHECK(ch[0].from_version == "2:1.0-1");
    }
    SECTION("a version-only change beside an unrelated install and remove") {
        const auto ch = SoftwareInventoryStore::diff_changes({row("A", "1"), row("Gone", "1")},
                                                             {row("A", "2"), row("New", "1")});
        REQUIRE(ch.size() == 3);
        std::map<std::string, Kind> by_name;
        for (const auto& c : ch)
            by_name[c.name] = c.kind;
        CHECK(by_name["A"] == Kind::kUpgrade);
        CHECK(by_name["Gone"] == Kind::kRemove);
        CHECK(by_name["New"] == Kind::kInstall);
    }
}

TEST_CASE("diff_changes: Windows package rows (appx, chocolatey) (pure)",
          "[software_inventory][v3][ledger]") {
    // The row shapes the Windows pkg_inventory legs emit: the collector declares no vendor for
    // them, so the publisher is the origin label `via:<ecosystem>` (which the pairing key reads as
    // no vendor); no release, no install location; an Appx row is named by the part of its
    // PackageFullName before the first '_' and carries the architecture; a Chocolatey package
    // whose nuspec is unreadable has version ''.
    // One call diffs one collector's rows, so a call never mixes the two ecosystems.
    const auto row = [](const std::string& name, const std::string& version,
                        const std::string& ecosystem, const std::string& arch = "") {
        SoftwareEntry e;
        e.name = name;
        e.version = version;
        e.ecosystem = ecosystem;
        e.publisher = "via:" + ecosystem;
        e.arch = arch;
        const bool choco = ecosystem == "chocolatey";
        e.kind = choco ? "pkg" : "app";
        e.source = choco ? "pkg_inventory.packages" : "pkg_inventory.store_packages";
        return keyed(std::move(e));
    };
    using Kind = SoftwareChangeKind;
    const auto by_name = [](const std::vector<SoftwareChange>& ch) {
        std::map<std::string, SoftwareChange> out;
        for (const auto& c : ch)
            out.emplace(c.name, c);
        REQUIRE(out.size() == ch.size()); // a repeated name would otherwise be dropped silently
        return out;
    };

    SECTION("one Appx name in two architectures is two installs, each upgraded on its own") {
        // x64 goes 1.0 -> 4.0 and x86 goes 3.0 -> 3.5. Without the architecture in the pairing
        // stem the removed {1.0, 3.0} would pair with the added {3.5, 4.0} in tuple order and
        // record 1.0 -> 3.5 and 3.0 -> 4.0.
        const auto ch = SoftwareInventoryStore::diff_changes(
            {row("Contoso.Calc", "1.0", "appx", "x64"), row("Contoso.Calc", "3.0", "appx", "x86")},
            {row("Contoso.Calc", "4.0", "appx", "x64"), row("Contoso.Calc", "3.5", "appx", "x86")});
        REQUIRE(ch.size() == 2);
        std::map<std::string, SoftwareChange> by_to;
        for (const auto& c : ch) {
            CHECK(c.kind == Kind::kUpgrade);
            CHECK(c.name == "Contoso.Calc");
            by_to.emplace(c.to_version, c);
        }
        REQUIRE(by_to.size() == 2);
        CHECK(by_to.at("4.0").from_version == "1.0");
        CHECK(by_to.at("4.0").instance_key ==
              row("Contoso.Calc", "4.0", "appx", "x64").instance_key);
        CHECK(by_to.at("3.5").from_version == "3.0");
        CHECK(by_to.at("3.5").instance_key ==
              row("Contoso.Calc", "3.5", "appx", "x86").instance_key);
    }
    SECTION("the same Appx version in two architectures is two rows: dropping one is a remove") {
        // The two rows differ only in the architecture. If the architecture were left out of
        // the instance key they would be one row and dropping the x86 one would be no event.
        const auto ch = SoftwareInventoryStore::diff_changes(
            {row("Contoso.Calc", "1.0", "appx", "x64"), row("Contoso.Calc", "1.0", "appx", "x86")},
            {row("Contoso.Calc", "1.0", "appx", "x64")});
        REQUIRE(ch.size() == 1);
        CHECK(ch[0].kind == Kind::kRemove);
        CHECK(ch[0].from_version == "1.0");
        CHECK(ch[0].instance_key == row("Contoso.Calc", "1.0", "appx", "x86").instance_key);
    }
    SECTION("an origin label reads as no vendor: label for label is no event, a vendor is new") {
        // The publisher is hashed verbatim (so the instance key changes with it) but the pairing
        // stem reads an origin label `via:<ecosystem>` as no vendor. A label for a label pairs at
        // an equal version and writes nothing; a label becoming a real vendor changes the stem,
        // so the same version is a removal and an install, not an update.
        const auto with = [&](const std::string& publisher, const std::string& version = "2.45") {
            auto e = row("git", version, "chocolatey");
            e.publisher = publisher;
            return keyed(std::move(e));
        };
        CHECK(SoftwareInventoryStore::diff_changes({with("via:chocolatey")}, {with("via:other")})
                  .empty());
        // A ledger row keeps the raw publisher of the row it represents: an upgrade the new row's.
        const auto bumped = SoftwareInventoryStore::diff_changes({with("via:chocolatey")},
                                                                 {with("via:other", "2.46")});
        REQUIRE(bumped.size() == 1);
        CHECK(bumped[0].kind == Kind::kUpgrade);
        CHECK(bumped[0].publisher == "via:other");
        CHECK(bumped[0].from_version == "2.45");
        CHECK(bumped[0].to_version == "2.46");
        const auto ch = SoftwareInventoryStore::diff_changes({with("via:chocolatey")},
                                                             {with("Acme Tools")});
        REQUIRE(ch.size() == 2);
        for (const auto& c : ch) {
            if (c.kind == Kind::kRemove) {
                CHECK(c.publisher == "via:chocolatey");
                CHECK(c.from_version == "2.45");
            } else {
                CHECK(c.kind == Kind::kInstall);
                CHECK(c.publisher == "Acme Tools");
                CHECK(c.to_version == "2.45");
            }
        }
    }
    SECTION("an unreadable Chocolatey version is a version like any other") {
        // The collector writes version '' for a package whose nuspec it cannot read (a junction
        // lib directory does that to every package at once). The pairing rule as it stands does
        // not treat '' as unknown: the flip is one upgrade per package with an empty side, in
        // both directions, and a package that appears beside it is an install. This pins that
        // rule; whether '' should mean unknown is a design question this test does not settle.
        const auto lost = by_name(SoftwareInventoryStore::diff_changes(
            {row("git", "2.45", "chocolatey"), row("nodejs", "20.1", "chocolatey")},
            {row("git", "", "chocolatey"), row("nodejs", "", "chocolatey"),
             row("7zip", "", "chocolatey")}));
        REQUIRE(lost.size() == 3);
        CHECK(lost.at("git").kind == Kind::kUpgrade);
        CHECK(lost.at("git").from_version == "2.45");
        CHECK(lost.at("git").to_version.empty());
        CHECK(lost.at("nodejs").kind == Kind::kUpgrade);
        CHECK(lost.at("nodejs").from_version == "20.1");
        CHECK(lost.at("nodejs").to_version.empty());
        CHECK(lost.at("7zip").kind == Kind::kInstall);
        CHECK(lost.at("7zip").from_version.empty());
        CHECK(lost.at("7zip").to_version.empty());
        const auto back = SoftwareInventoryStore::diff_changes({row("git", "", "chocolatey")},
                                                               {row("git", "2.45", "chocolatey")});
        REQUIRE(back.size() == 1);
        CHECK(back[0].kind == Kind::kUpgrade);
        CHECK(back[0].from_version.empty());
        CHECK(back[0].to_version == "2.45");
    }
}

TEST_CASE("component row hash and component section hash are pinned",
          "[software_inventory][v3][hash][components]") {
    // The agent writer must reproduce these bytes. Recipe (8 fields, 0x1F between, 0x1E ends the
    // record, size and mtime in decimal), with an independent check by python3 hashlib:
    //   printf 'jar\037log4j-core\0372.14.1\037pom\037/opt/app/log4j-core.jar\0371234\0371700000000\037AcmeApp\036' | shasum -a 256
    //   printf 'jar\037guava\03731.0\037manifest\037/opt/app/guava.jar\03756\0377\037\036' | shasum -a 256
    //   printf '<the guava record><the log4j-core record>' | shasum -a 256     (sorted by the record fields)
    V3Component log4j;
    log4j.kind = "jar";
    log4j.name = "log4j-core";
    log4j.version = "2.14.1";
    log4j.version_source = "pom";
    log4j.path = "/opt/app/log4j-core.jar";
    log4j.size = 1234;
    log4j.mtime = 1700000000;
    log4j.anchor_app = "AcmeApp";
    V3Component guava;
    guava.kind = "jar";
    guava.name = "guava";
    guava.version = "31.0";
    guava.version_source = "manifest";
    guava.path = "/opt/app/guava.jar";
    guava.size = 56;
    guava.mtime = 7;

    CHECK(SoftwareInventoryStore::component_row_hash(log4j) ==
          "2a42ddba7479c8a7edbe10b9f64ebe33d35bb294588993515c9313e65bba588f");
    CHECK(SoftwareInventoryStore::component_row_hash(guava) ==
          "ec07687685e447a3fb37bc84a64e94ad9bf5433d20a6b01d2cc6ff3b38a5003a");
    // Order and duplicates do not matter: the guava record sorts first.
    const std::string section = "d9660fb3421ec2ad622c68ad05e58351ece4584d13b29e92cfea9f5c4b8af4cd";
    CHECK(SoftwareInventoryStore::canonical_component_section_hash({guava, log4j}) == section);
    CHECK(SoftwareInventoryStore::canonical_component_section_hash({log4j, guava, log4j}) == section);
    CHECK(SoftwareInventoryStore::canonical_component_section_hash({}) == kEmptySectionHash);
}

TEST_CASE("v3: component sections: full stores rows, delta applies, honest-empty deletes",
          "[pg][software_inventory][v3][components]") {
    SWINV_SHARED(store, pool);
    const auto c1 = comp("log4j-core", "/opt/app/log4j-core.jar", "2.14.1");
    const auto c2 = comp("guava", "/opt/app/guava.jar", "31.0");
    const auto c3 = comp("slf4j", "/opt/app/slf4j.jar", "1.7");
    const auto a1 = v3_entry("Alpha", kV3Apps);

    auto res = store.apply_installed_software_v3(
        "agent-cp", v3_report({v3_full(kV3Apps, {a1}), comp_full({c2, c1})}));
    REQUIRE(res.size() == 2);
    CHECK(res[1].outcome == V3SectionOutcome::kStored);
    auto rows = comp_rows(pool, "agent-cp");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0][0] == "guava");
    CHECK(rows[0][2] != "0"); // first_seen: when the row was written
    // path_hash is the SHA-256 of the exact path bytes and row_hash names the record.
    const auto keys = sql_rows(pool, "SELECT path_hash, row_hash FROM "
                                     "software_inventory_store.software_components "
                                     "WHERE agent_id = 'agent-cp' AND name = 'guava'");
    REQUIRE(keys.size() == 1);
    // path_hash = SHA-256 of the exact path bytes: printf '/opt/app/guava.jar' | shasum -a 256
    CHECK(keys[0][0] == "d255fcd34133e5c73da539533af7be057146e1dc5fe4bc47f3630cd1a719af75");
    CHECK(keys[0][1] == SoftwareInventoryStore::component_row_hash(c2));
    CHECK(facet_status(pool, "agent-cp", kV3Comp) == "full/" + comp_hash_of({c1, c2}));

    // The report hash now includes component_inventory.
    CHECK(stored_hash(pool, "agent-cp") ==
          SoftwareInventoryStore::v3_report_hash(
              {{kV3Apps, section_hash_of({a1})}, {kV3Comp, comp_hash_of({c1, c2})}}));
    CHECK(store.apply_installed_software("agent-cp", stored_hash(pool, "agent-cp"), std::nullopt, 0) ==
          InventoryIngestOutcome::kTouched);
    CHECK(ledger_count(pool, "agent-cp") == "0"); // components never write the install ledger

    // A delta: drop c2, add c3. c1 survives untouched: a delta rewrites only the rows it names.
    sql_ok(pool, "UPDATE software_inventory_store.software_components SET first_seen = 1 "
                 "WHERE agent_id = 'agent-cp'"); // so a rewrite is observable
    res = store.apply_installed_software_v3(
        "agent-cp", v3_report({comp_delta(comp_hash_of({c1, c2}), {c1, c3}, {c2}, {c3})}));
    REQUIRE(res[0].outcome == V3SectionOutcome::kStored);
    rows = comp_rows(pool, "agent-cp");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0][0] == "log4j-core"); // ORDER BY name: log4j-core, slf4j
    CHECK(rows[0][2] == "1");          // the survivor keeps first_seen: it was not rewritten
    CHECK(rows[1][0] == "slf4j");
    CHECK(rows[1][2] != "1");          // the added row was written now
    CHECK(facet_status(pool, "agent-cp", kV3Comp) == "delta/" + comp_hash_of({c1, c3}));

    // A delta that does not verify is a mismatch and changes nothing.
    auto bad = comp_delta(comp_hash_of({c1, c3}), {c1}, {c3}, {});
    bad.expect = std::string(64, '2');
    res = store.apply_installed_software_v3("agent-cp", v3_report({bad}));
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(comp_rows(pool, "agent-cp").size() == 2);
    // A delta on the wrong base needs a full section.
    res = store.apply_installed_software_v3(
        "agent-cp", v3_report({comp_delta(std::string(64, '3'), {c1}, {c3}, {})}));
    CHECK(res[0].outcome == V3SectionOutcome::kNeedFull);

    // Honest-empty full deletes the device's components; its facet holds the empty hash.
    res = store.apply_installed_software_v3("agent-cp", v3_report({comp_full({})}));
    REQUIRE(res[0].outcome == V3SectionOutcome::kStored);
    CHECK(comp_rows(pool, "agent-cp").empty());
    CHECK(facet_status(pool, "agent-cp", kV3Comp) == std::string("full/") + kEmptySectionHash);
}

TEST_CASE("v3: a component PK collision inside one section is a mismatch, rolled back",
          "[pg][software_inventory][v3][components]") {
    SWINV_SHARED(store, pool);
    const auto c1 = comp("one", "/opt/x.jar", "1");
    auto twin = comp("two", "/opt/x.jar", "2"); // the same (kind, path): a producer defect
    const auto keep = comp("keep", "/opt/keep.jar");
    REQUIRE(store.apply_installed_software_v3("agent-pk", v3_report({comp_full({keep})}))[0]
                .outcome == V3SectionOutcome::kStored);

    auto res = store.apply_installed_software_v3("agent-pk", v3_report({comp_full({c1, twin})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(yuzu::server::v3_section_needs_full(res[0].outcome));
    const auto rows = comp_rows(pool, "agent-pk");
    REQUIRE(rows.size() == 1); // the held set is untouched
    CHECK(rows[0][0] == "keep");

    // A delta whose + collides with a held row's path is the same defect.
    twin = comp("dup", "/opt/keep.jar", "9");
    res = store.apply_installed_software_v3(
        "agent-pk", v3_report({comp_delta(comp_hash_of({keep}), {keep, twin}, {}, {twin})}));
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(comp_rows(pool, "agent-pk").size() == 1);

    // A `-` naming a component the server never stored is a mismatch too, and rolls back alone.
    const auto ghost = comp("ghost", "/opt/ghost.jar");
    res = store.apply_installed_software_v3(
        "agent-pk", v3_report({comp_delta(comp_hash_of({keep}), {keep}, {ghost}, {})}));
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(yuzu::server::v3_section_needs_full(res[0].outcome));
    CHECK(comp_rows(pool, "agent-pk").size() == 1);
    CHECK(facet_status(pool, "agent-pk", kV3Comp) == "full/" + comp_hash_of({keep}));
}

TEST_CASE("v3: delete_agent removes the ledger and the components; a bystander keeps its own",
          "[pg][software_inventory][v3][ledger][components]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps, "1.0");
    const auto a2 = v3_entry("Alpha", kV3Apps, "2.0");
    for (const std::string agent : {"agent-del", "agent-keep"}) {
        REQUIRE(store.apply_installed_software_v3(
                    agent, v3_report({v3_full(kV3Apps, {a1}), comp_full({comp("c", "/p")})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        REQUIRE(store.apply_installed_software_v3(agent, v3_report({v3_full(kV3Apps, {a2})}))[0]
                    .outcome == V3SectionOutcome::kStored);
        REQUIRE(ledger_count(pool, agent) == "1");
        REQUIRE(comp_rows(pool, agent).size() == 1);
    }
    CHECK(store.delete_agent("agent-del"));
    CHECK(ledger_count(pool, "agent-del") == "0");
    CHECK(comp_rows(pool, "agent-del").empty());
    CHECK(ledger_count(pool, "agent-keep") == "1");
    CHECK(comp_rows(pool, "agent-keep").size() == 1);
}

TEST_CASE("v3: the first v3 call of a device holding v2 rows that applies a section baselines and "
          "drops stale components",
          "[pg][software_inventory][v3][ledger][components]") {
    SWINV_SHARED(store, pool);
    const std::vector<SoftwareEntry> v2rows = {v3_entry("OldApp", kV3Apps)};
    REQUIRE(store.apply_installed_software("agent-tr", SoftwareInventoryStore::canonical_hash(v2rows),
                                           v2rows, 0) == InventoryIngestOutcome::kStored);
    REQUIRE(sql_ok(pool, "INSERT INTO software_inventory_store.software_components "
                         "(agent_id, kind, path_hash, name, row_hash, first_seen) "
                         "VALUES ('agent-tr', 'jar', 'ph', 'stale', 'rh', 1)"));
    const auto a1 = v3_entry("Alpha", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-tr", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-tr", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(ledger_count(pool, "agent-tr") == "0"); // the v2 rows were not "removed"
    CHECK(comp_rows(pool, "agent-tr").empty());
}

TEST_CASE("run_retention_prune_changes: 400-day window under the clock guard, capped per pass",
          "[pg][software_inventory][v3][ledger][retention]") {
    SWINV_SHARED(store, pool);
    REQUIRE(store.is_open());
    const std::string now_s = "(EXTRACT(EPOCH FROM now()))::bigint";
    const auto insert_at = [&](const std::string& agent, long days_ago) {
        REQUIRE(sql_ok(pool, "INSERT INTO software_inventory_store.software_changes "
                             "(agent_id, facet, kind, name, observed_at) "
                             "VALUES ($1, 'f', 'install', 'n', " + now_s + " - $2::bigint * 86400)",
                       {agent, std::to_string(days_ago)}));
    };
    const auto remaining = [&] { return std::stoll(sql_rows(pool, "SELECT count(*) FROM "
                                    "software_inventory_store.software_changes")[0][0]); };

    insert_at("old", 401);
    insert_at("fresh", 399);
    insert_at("fresh", 1);

    // Part 6: ledger history is not regenerable, so a store with data and no persisted anchor
    // DECLINES its first pass (anchor and settled marker recorded, nothing deleted).
    CHECK(store.run_retention_prune_changes() == 0);
    CHECK(remaining() == 3);
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.retention_meta")[0][0] != "0");

    // The next pass deletes the 401-day row and keeps the 399-day one.
    CHECK(store.run_retention_prune_changes() == 1);
    CHECK(remaining() == 2);
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.software_changes "
                         "WHERE agent_id = 'old'")[0][0] == "0");

    // The cap: at most kChangesPruneCapPerPass rows go in one pass.
    REQUIRE(sql_ok(pool, "INSERT INTO software_inventory_store.software_changes "
                         "(agent_id, facet, kind, name, observed_at) "
                         "SELECT 'bulk', 'f', 'install', 'n', " + now_s +
                         " - 500 * 86400 FROM generate_series(1, $1::int)",
                   {std::to_string(SoftwareInventoryStore::kChangesPruneCapPerPass + 7)}));
    CHECK(store.run_retention_prune_changes() == SoftwareInventoryStore::kChangesPruneCapPerPass);
    CHECK(remaining() == 2 + 7);
    CHECK(store.run_retention_prune_changes() == 7);
    CHECK(remaining() == 2);
}

TEST_CASE("v3: a delta that would leave a facet over the per-call record cap is a mismatch",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    std::vector<SoftwareEntry> rows;
    rows.reserve(yuzu::server::kV3MaxRows);
    for (std::size_t i = 0; i < yuzu::server::kV3MaxRows; ++i)
        rows.push_back(v3_entry("n" + std::to_string(i), kV3Apps));
    std::vector<V3Component> comps;
    comps.reserve(yuzu::server::kV3MaxComponents);
    for (std::size_t i = 0; i < yuzu::server::kV3MaxComponents; ++i)
        comps.push_back(comp("c" + std::to_string(i), "/p/" + std::to_string(i)));
    auto res = store.apply_installed_software_v3(
        "agent-cap", v3_report({v3_full(kV3Apps, rows), comp_full(comps)}));
    REQUIRE(res.size() == 2);
    REQUIRE(res[0].outcome == V3SectionOutcome::kStored);
    REQUIRE(res[1].outcome == V3SectionOutcome::kStored);

    // Both deltas carry the hash the agent would hold, so only the cap refuses them.
    const auto extra = v3_entry("one-too-many", kV3Apps);
    auto after_rows = rows;
    after_rows.push_back(extra);
    const auto extra_c = comp("one-too-many", "/p/extra");
    auto after_comps = comps;
    after_comps.push_back(extra_c);
    res = store.apply_installed_software_v3(
        "agent-cap", v3_report({v3_delta(kV3Apps, section_hash_of(rows), after_rows, {}, {extra}),
                               comp_delta(comp_hash_of(comps), after_comps, {}, {extra_c})}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(res[1].outcome == V3SectionOutcome::kMismatch);
    CHECK(row_count(pool, "agent-cap") == std::to_string(yuzu::server::kV3MaxRows));
    CHECK(facet_status(pool, "agent-cap", kV3Apps) == "full/" + section_hash_of(rows));
    CHECK(facet_status(pool, "agent-cap", kV3Comp) == "full/" + comp_hash_of(comps));
    CHECK(ledger_count(pool, "agent-cap") == "0");
}

TEST_CASE("v3: a delta-only or all-refused call neither wipes v2 rows nor flips the state",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const std::vector<SoftwareEntry> v2rows = {v3_entry("OldApp", kV3Apps)};
    const std::string v2hash = SoftwareInventoryStore::canonical_hash(v2rows);
    REQUIRE(store.apply_installed_software("agent-nf", v2hash, v2rows, 0) ==
            InventoryIngestOutcome::kStored);

    V3Section delta = v3_status(kV3Apps, V3Status::kDelta);
    delta.base = "x";
    V3Section refused;
    refused.facet = kV3Pkgs;
    refused.refusal = V3Refusal::kSourceMismatch;
    const auto res = store.apply_installed_software_v3("agent-nf", v3_report({delta, refused}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].outcome == V3SectionOutcome::kNeedFull);
    CHECK(res[1].outcome == V3SectionOutcome::kRejected);
    CHECK(names_of(pool, "agent-nf", kV3Apps) == std::vector<std::string>{"OldApp"});
    CHECK(stored_hash(pool, "agent-nf") == v2hash);

    const auto only_refused = store.apply_installed_software_v3("agent-nf", v3_report({refused}));
    CHECK(only_refused[0].outcome == V3SectionOutcome::kRejected);
    CHECK(stored_hash(pool, "agent-nf") == v2hash);
    CHECK(facet_count(pool, "agent-nf") == "0");
}

TEST_CASE("v3: a first call whose only writing section is a colliding component section keeps "
          "the v2 rows",
          "[pg][software_inventory][v3][components]") {
    SWINV_SHARED(store, pool);
    const std::vector<SoftwareEntry> v2rows = {v3_entry("OldApp", kV3Apps)};
    const std::string v2hash = SoftwareInventoryStore::canonical_hash(v2rows);
    REQUIRE(store.apply_installed_software("agent-cx", v2hash, v2rows, 0) ==
            InventoryIngestOutcome::kStored);

    // The component section repeats a (kind, path): a mismatch that writes nothing, so the call
    // writes nothing and the switch to v3 does not happen.
    auto res = store.apply_installed_software_v3(
        "agent-cx", v3_report({comp_full({comp("one", "/opt/x.jar", "1"),
                                          comp("two", "/opt/x.jar", "2")})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(names_of(pool, "agent-cx", kV3Apps) == std::vector<std::string>{"OldApp"});
    CHECK(stored_hash(pool, "agent-cx") == v2hash);
    CHECK(facet_count(pool, "agent-cx") == "0");
    // The unchanged v2 report is therefore still a match with its rows behind it.
    CHECK(store.apply_installed_software("agent-cx", v2hash, std::nullopt, 0) ==
          InventoryIngestOutcome::kTouched);

    // A call that does write (a second, sound section) still makes the switch.
    res = store.apply_installed_software_v3(
        "agent-cx", v3_report({comp_full({comp("one", "/opt/x.jar"), comp("two", "/opt/x.jar")}),
                               v3_full(kV3Apps, {v3_entry("Alpha", kV3Apps)})}));
    REQUIRE(res.size() == 2);
    CHECK(res[0].outcome == V3SectionOutcome::kMismatch);
    CHECK(res[1].outcome == V3SectionOutcome::kStored);
    CHECK(names_of(pool, "agent-cx", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(stored_hash(pool, "agent-cx").starts_with("v3:"));
}

TEST_CASE("v3: a first contact split over several calls converges to the single-call hash",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto p1 = v3_entry("libfoo", kV3Pkgs);
    const std::string agg = SoftwareInventoryStore::v3_report_hash(
        {{kV3Apps, section_hash_of({a1})}, {kV3Pkgs, section_hash_of({p1})}});

    // One call with both sections.
    REQUIRE(store
                .apply_installed_software_v3(
                    "agent-one", v3_report({v3_full(kV3Apps, {a1}), v3_full(kV3Pkgs, {p1})}))
                .size() == 2);
    CHECK(stored_hash(pool, "agent-one") == agg);

    // The same sections, one per call, in either order.
    for (const bool apps_first : {true, false}) {
        const std::string agent = apps_first ? "agent-split-a" : "agent-split-b";
        const auto first = apps_first ? v3_full(kV3Apps, {a1}) : v3_full(kV3Pkgs, {p1});
        const auto second = apps_first ? v3_full(kV3Pkgs, {p1}) : v3_full(kV3Apps, {a1});
        REQUIRE(store.apply_installed_software_v3(agent, v3_report({first}))[0].outcome ==
                V3SectionOutcome::kStored);
        // Mid-way the hash is the partial aggregate: a full claim does not match yet.
        CHECK(stored_hash(pool, agent) != agg);
        CHECK(store.apply_installed_software(agent, agg, std::nullopt, 0) ==
              InventoryIngestOutcome::kNeedFull);
        REQUIRE(store.apply_installed_software_v3(agent, v3_report({second}))[0].outcome ==
                V3SectionOutcome::kStored);
        CHECK(stored_hash(pool, agent) == agg);
        CHECK(store.apply_installed_software(agent, agg, std::nullopt, 0) ==
              InventoryIngestOutcome::kTouched);
        CHECK(row_count(pool, agent) == "2");
    }
}

TEST_CASE("v3: a v2 full report supersedes the facet state, and delete_agent cascades it",
          "[pg][software_inventory][v3]") {
    SWINV_SHARED(store, pool);
    const auto a1 = v3_entry("Alpha", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-dg", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    REQUIRE(facet_count(pool, "agent-dg") == "1");

    // The agent is downgraded and sends a v2 full report.
    const std::vector<SoftwareEntry> v2rows = {{"Chrome", "119", "Google", "2026-01-01"}};
    const std::string v2hash = SoftwareInventoryStore::canonical_hash(v2rows);
    REQUIRE(store.apply_installed_software("agent-dg", v2hash, v2rows, 0) ==
            InventoryIngestOutcome::kStored);
    CHECK(facet_count(pool, "agent-dg") == "0");
    CHECK(stored_hash(pool, "agent-dg") == v2hash);
    CHECK(names_of(pool, "agent-dg", kV3Apps).empty()); // the v3 rows were replaced too
    // The v2 hash-only claim now matches again; the old v3 aggregate does not.
    CHECK(store.apply_installed_software("agent-dg", v2hash, std::nullopt, 0) ==
          InventoryIngestOutcome::kTouched);

    // Back to v3, then decommission: the facet rows go with the agent, a bystander keeps its own.
    REQUIRE(store.apply_installed_software_v3("agent-dg", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    REQUIRE(
        store.apply_installed_software_v3("agent-bystander", v3_report({v3_full(kV3Apps, {a1})}))[0]
            .outcome == V3SectionOutcome::kStored);
    CHECK(store.delete_agent("agent-dg"));
    CHECK(facet_count(pool, "agent-dg") == "0");
    CHECK(row_count(pool, "agent-dg") == "0");
    CHECK(stored_hash(pool, "agent-dg") == "<no row>");
    CHECK(facet_count(pool, "agent-bystander") == "1");
    CHECK(row_count(pool, "agent-bystander") == "1");
}

TEST_CASE("v3: a SQL failure rolls the whole call back and answers need-full for every section",
          "[pg][software_inventory][v3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    const auto a1 = v3_entry("Alpha", kV3Apps);
    REQUIRE(store.apply_installed_software_v3("agent-rb", v3_report({v3_full(kV3Apps, {a1})}))[0]
                .outcome == V3SectionOutcome::kStored);
    const std::string before = stored_hash(pool, "agent-rb");

    // Break the facet-state write only; the rows' DELETE/INSERT earlier in the same transaction
    // would succeed on their own, so a leak shows as changed rows.
    REQUIRE(sql_ok(pool, "ALTER TABLE software_inventory_store.software_facet_state "
                         "RENAME TO software_facet_state_gone"));
    V3Section refused;
    refused.facet = kV3Py;
    refused.refusal = V3Refusal::kUnknownRecord;
    const auto res = store.apply_installed_software_v3(
        "agent-rb", v3_report({v3_full(kV3Apps, {v3_entry("Beta", kV3Apps)}),
                               v3_full(kV3Pkgs, {v3_entry("libfoo", kV3Pkgs)}),
                               v3_status(kV3Comp, V3Status::kFull), refused}));
    REQUIRE(res.size() == 4);
    CHECK(res[0].outcome == V3SectionOutcome::kError);
    CHECK(res[1].outcome == V3SectionOutcome::kError);
    CHECK(res[2].outcome == V3SectionOutcome::kError);
    CHECK(res[3].outcome == V3SectionOutcome::kRejected); // refused is refused, not an error
    CHECK(yuzu::server::v3_section_needs_full(V3SectionOutcome::kError));

    // Nothing of the failed call is visible.
    CHECK(names_of(pool, "agent-rb", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(names_of(pool, "agent-rb", kV3Pkgs).empty());
    CHECK(stored_hash(pool, "agent-rb") == before);

    // A store that never opened answers every unrefused section with an error too.
    REQUIRE(sql_ok(pool, "DROP SCHEMA software_inventory_store CASCADE"));
    SoftwareInventoryStore broken{pool};
    REQUIRE_FALSE(broken.is_open());
    const auto none = broken.apply_installed_software_v3(
        "agent-rb", v3_report({v3_full(kV3Apps, {a1}), refused}));
    REQUIRE(none.size() == 2);
    CHECK(none[0].outcome == V3SectionOutcome::kError);
    CHECK(none[1].outcome == V3SectionOutcome::kRejected);
}

TEST_CASE(
    "v3: a SQL failure on the FIRST v3 call rolls the transition delete back; v2 data survives",
    "[pg][software_inventory][v3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // A v2 agent with stored rows and the v2 hash: its first v3 call is a TRANSITION, which
    // deletes every pre-existing row before the section lands.
    const std::vector<SoftwareEntry> v2rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                               {"Firefox", "120", "Mozilla", "2026-01-02"}};
    const std::string v2hash = SoftwareInventoryStore::canonical_hash(v2rows);
    REQUIRE(store.apply_installed_software("agent-rbt", v2hash, v2rows, 0) ==
            InventoryIngestOutcome::kStored);
    REQUIRE(row_count(pool, "agent-rbt") == "2");

    // The transition clears the agent's rows (succeeds) and THEN its facet state (fails on the
    // renamed table), inside the same transaction. If the transition DELETE ran outside it, the
    // v2 rows would be gone and the hash would still be v2: a v2 agent would lose its inventory
    // to a failed v3 call.
    REQUIRE(sql_ok(pool, "ALTER TABLE software_inventory_store.software_facet_state "
                         "RENAME TO software_facet_state_gone"));
    const auto res = store.apply_installed_software_v3(
        "agent-rbt", v3_report({v3_full(kV3Apps, {v3_entry("Alpha", kV3Apps)})}));
    REQUIRE(res.size() == 1);
    CHECK(res[0].outcome == V3SectionOutcome::kError);

    CHECK(row_count(pool, "agent-rbt") == "2");
    CHECK(stored_hash(pool, "agent-rbt") == v2hash);
    CHECK(names_of(pool, "agent-rbt", kV3Apps).empty());
}

TEST_CASE("ingest_inventory_report v3: a refused section nacks only its facet; the rest applies",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;

    const std::string blob =
        w_hdr() + w_sec(kV3Apps, "full") + w_plus("Alpha", kV3Apps, "C:\\Apps\\Alpha") +
        w_sec(kV3Pkgs, "full") +
        w_rec({"-", std::string(64, 'a')}) /* refused: - in a full section */ +
        w_sec(kV3Py, "constrained", "", "tok", "5", "6") + w_sec(kV3Comp, "full") +
        w_rec({"comp", "jar", "log4j-core", "2.14.1", "pom", "/opt/app/log4j.jar", "1", "2", ""}) +
        w_sec("made_up.source", "full");
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = "claimed-and-ignored";
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-seam", rep, ack, &metrics);

    // Exactly the refused and the unknown-facet sections are asked for again: the component
    // section is applied now (SAM-14).
    std::set<std::string> nacks(ack.need_full().begin(), ack.need_full().end());
    CHECK(nacks == (std::set<std::string>{"installed_software:pkg_inventory.packages",
                                          "installed_software:made_up.source"}));
    CHECK(ack.need_full_size() == 2); // no duplicates, and no whole-source nack
    CHECK(comp_rows(pool, "agent-seam").size() == 1);

    // The good section applied; the status-only one recorded its status.
    CHECK(names_of(pool, "agent-seam", kV3Apps) == std::vector<std::string>{"Alpha"});
    CHECK(names_of(pool, "agent-seam", kV3Pkgs).empty());
    CHECK(sql_rows(pool,
                   "SELECT status, token, duration_ms, bytes_read FROM "
                   "software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-seam' AND facet = $1",
                   {kV3Py})[0] == (std::vector<std::string>{"constrained", "tok", "5", "6"}));
    // The location rode in on slot 13.
    CHECK(sql_rows(pool, "SELECT install_location FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-seam'")[0][0] == "C:\\Apps\\Alpha");

    // Metrics: one section counter per section with a CLOSED facet label, the source-level
    // outcome, and the v3 phase of the duration histogram.
    const auto section = [&](const std::string& facet, const std::string& outcome) {
        return metrics
            .counter("yuzu_inventory_section_ingest_total",
                     {{"facet", facet}, {"outcome", outcome}})
            .value();
    };
    CHECK(section(kV3Apps, "stored") == 1.0);
    CHECK(section(kV3Pkgs, "rejected") == 1.0);
    CHECK(section(kV3Py, "status_only") == 1.0);
    CHECK(section(kV3Comp, "stored") == 1.0);
    CHECK(section("unknown", "rejected") == 1.0); // never the agent's raw facet string
    CHECK(metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "installed_software"}, {"outcome", "need_full"}})
              .value() == 1.0);
    CHECK(metrics
              .histogram("yuzu_inventory_ingest_duration_seconds",
                         {{"source", "installed_software"}, {"phase", "v3"}})
              .snapshot()
              .count == 1);
}

TEST_CASE("ingest_inventory_report v3: a full component_inventory section with no records is "
          "stored, not nacked",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;

    // A syntactically complete, honest-empty component section: header line only, no records.
    // The device really has no components, so the report is complete and nothing is resent.
    const std::string blob = w_hdr() + w_sec(kV3Comp, "full");
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = "claimed-and-ignored";
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-seam-cz", rep, ack, &metrics);

    CHECK(ack.need_full().empty());
    CHECK(metrics
              .counter("yuzu_inventory_section_ingest_total",
                       {{"facet", kV3Comp}, {"outcome", "stored"}})
              .value() == 1.0);
    CHECK(metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "installed_software"}, {"outcome", "stored"}})
              .value() == 1.0);
    CHECK(facet_status(pool, "agent-seam-cz", kV3Comp) ==
          "full/" + SoftwareInventoryStore::canonical_component_section_hash({}));
}

TEST_CASE("ingest_inventory_report v3: a section holding a NUL byte is refused, nothing of it is "
          "stored, and the other sections still apply",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    const auto ingest = [&](const std::string& blob) {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = "claimed-and-ignored";
        (*rep.mutable_plugin_data())["installed_software"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-nul", rep, ack, &metrics);
        return std::set<std::string>(ack.need_full().begin(), ack.need_full().end());
    };

    // "AB" and "A\0B" differ on the wire; stored as bound text they would both read "AB" while
    // hashing apart. The whole section is refused instead, and the clean row beside them goes too.
    const std::string nul_name("A\0B", 3);
    const auto nacks = ingest(w_hdr() + w_sec(kV3Apps, "full") + w_plus("AB", kV3Apps) +
                              w_plus(nul_name, kV3Apps) + w_sec(kV3Pkgs, "full") +
                              w_plus("libfoo", kV3Pkgs));
    CHECK(nacks == std::set<std::string>{"installed_software:installed_apps.list_inventory"});
    CHECK(names_of(pool, "agent-nul", kV3Apps).empty());
    CHECK(names_of(pool, "agent-nul", kV3Pkgs) == std::vector<std::string>{"libfoo"});
    // The refused facet has no state row: nothing about it was recorded.
    CHECK(sql_rows(pool,
                   "SELECT count(*) FROM software_inventory_store.software_facet_state "
                   "WHERE agent_id = 'agent-nul' AND facet = $1",
                   {kV3Apps})[0][0] == "0");
    CHECK(metrics
              .counter("yuzu_inventory_section_ingest_total",
                       {{"facet", kV3Apps}, {"outcome", "rejected"}})
              .value() == 1.0);

    // Rows the agent already held for the facet survive a later NUL section untouched.
    CHECK(ingest(w_hdr() + w_sec(kV3Apps, "full") + w_plus("Alpha", kV3Apps)).empty());
    CHECK(names_of(pool, "agent-nul", kV3Apps) == std::vector<std::string>{"Alpha"});
    const auto again = ingest(w_hdr() + w_sec(kV3Apps, "full") + w_plus(nul_name, kV3Apps));
    CHECK(again == std::set<std::string>{"installed_software:installed_apps.list_inventory"});
    CHECK(names_of(pool, "agent-nul", kV3Apps) == std::vector<std::string>{"Alpha"});
}

TEST_CASE("ingest_inventory_report v3: a blob cut off inside its last record refuses that section",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    std::string blob = w_hdr() + w_sec(kV3Pkgs, "full") + w_plus("libfoo", kV3Pkgs) +
                       w_sec(kV3Apps, "full") + w_plus("Alpha", kV3Apps) + w_plus("Beta", kV3Apps);
    blob.pop_back(); // the last record loses its terminator
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = "claimed-and-ignored";
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-cut", rep, ack, &metrics);
    CHECK(std::set<std::string>(ack.need_full().begin(), ack.need_full().end()) ==
          std::set<std::string>{"installed_software:installed_apps.list_inventory"});
    CHECK(names_of(pool, "agent-cut", kV3Apps).empty()); // "Alpha" was whole, but not applied alone
    CHECK(names_of(pool, "agent-cut", kV3Pkgs) == std::vector<std::string>{"libfoo"});
}

TEST_CASE("ingest_inventory_report v3: a clean report is stored, then hash-only claims match",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    const auto a1 = v3_entry("Alpha", kV3Apps);
    const auto p1 = v3_entry("libfoo", kV3Pkgs);
    const std::string agg = SoftwareInventoryStore::v3_report_hash(
        {{kV3Apps, section_hash_of({a1})}, {kV3Pkgs, section_hash_of({p1})}});

    {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = agg;
        (*rep.mutable_plugin_data())["installed_software"] =
            w_hdr() + w_sec(kV3Apps, "full") + w_plus("Alpha", kV3Apps) + w_sec(kV3Pkgs, "full") +
            w_plus("libfoo", kV3Pkgs) + w_sec(kV3Py, "not_collected");
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-clean", rep, ack, &metrics);
        CHECK(ack.need_full_size() == 0);
    }
    CHECK(stored_hash(pool, "agent-clean") == agg);
    CHECK(metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "installed_software"}, {"outcome", "stored"}})
              .value() == 1.0);

    // Hash-only follow-ups: the v3 aggregate matches; a v2-style claim does not.
    const auto hash_only = [&](const std::string& claim) {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = claim;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-clean", rep, ack, &metrics);
        return std::vector<std::string>(ack.need_full().begin(), ack.need_full().end());
    };
    CHECK(hash_only(agg).empty());
    CHECK(hash_only(SoftwareInventoryStore::canonical_hash({a1, p1})) ==
          std::vector<std::string>{"installed_software"});
}

TEST_CASE("ingest_inventory_report v3: a blob that cannot be attributed to sections is dropped "
          "and nacked whole",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    // A v2 state exists; a malformed v3 blob must leave it alone.
    const std::vector<SoftwareEntry> v2rows = {{"Chrome", "119", "Google", "2026-01-01"}};
    REQUIRE(store.apply_installed_software("agent-bad",
                                           SoftwareInventoryStore::canonical_hash(v2rows), v2rows,
                                           0) == InventoryIngestOutcome::kStored);

    for (const std::string& blob :
         {w_hdr(),                                         // a header naming no section at all
          w_hdr() + w_plus("Orphan", kV3Apps),             // a record before any section
          w_hdr() + w_rec({"S", "", "full"}),              // a section header with no facet
          w_hdr() + std::string(4u * 1024 * 1024, 'x')}) { // over the 3 MiB cap
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = "x";
        (*rep.mutable_plugin_data())["installed_software"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-bad", rep, ack, &metrics);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "installed_software"); // the whole source, not a facet
    }
    CHECK(metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "installed_software"}, {"outcome", "dropped"}})
              .value() == 4.0);
    CHECK(names_of(pool, "agent-bad", "") == std::vector<std::string>{"Chrome"});
    CHECK(stored_hash(pool, "agent-bad") == SoftwareInventoryStore::canonical_hash(v2rows));
}

TEST_CASE("ingest_inventory_report: the v2 path is unchanged beside v3",
          "[pg][software_inventory][seam][v3]") {
    SWINV_SHARED(store, pool);
    // A v2 blob whose first product is literally named "v3" is still v2, and slot 13 is still
    // parsed and discarded on that path (its hash and rows are the pre-v3 bytes).
    SoftwareEntry first;
    first.name = "v3";
    first.version = "1.0";
    const SoftwareEntry second = full_extended_entry();
    const std::string blob =
        wire_record(first, 4) + wire_record_reserved(second, "/Users/alice/Bash", "u");
    agentpb::InventoryReport rep;
    const std::string h = SoftwareInventoryStore::canonical_hash({first, second});
    (*rep.mutable_content_hashes())["installed_software"] = h;
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-v2", rep, ack);
    CHECK(ack.need_full_size() == 0);
    CHECK(stored_hash(pool, "agent-v2") == h);
    CHECK_FALSE(stored_hash(pool, "agent-v2").starts_with("v3:"));
    CHECK(facet_count(pool, "agent-v2") == "0");
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.installed_software "
                         "WHERE agent_id = 'agent-v2' AND install_location <> ''")[0][0] == "0");
    CHECK(row_count(pool, "agent-v2") == "2");
}

// ── SAM-17: lookup read surface (migration v12, components rollup, totals, status) ──────────────

namespace {

using yuzu::server::kCatalogRowCap;
using yuzu::server::kRowStatusCaseSql;
using yuzu::server::NameMatch;
using yuzu::server::SoftwareComponentCursor;
using yuzu::server::SoftwareComponentQuery;
using yuzu::server::SoftwareFleetQuery;

// A component-inventory full section for one agent, through the v3 apply path.
void apply_components(SoftwareInventoryStore& store, const std::string& agent,
                      std::vector<V3Component> rows) {
    const auto out = store.apply_installed_software_v3(agent, v3_report({comp_full(std::move(rows))}));
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].outcome == V3SectionOutcome::kStored);
}

} // namespace

TEST_CASE("v12: the lookup objects exist and the meta singleton is seeded building",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    CHECK(sql_rows(pool,
                   "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
                   "'software_inventory_store' AND table_name = 'catalog_rollup' AND column_name "
                   "= 'row_count'")[0][0] == "1");
    CHECK(sql_rows(pool, "SELECT count(*) FROM information_schema.tables WHERE table_schema = "
                         "'software_inventory_store' AND table_name IN ('component_rollup', "
                         "'component_rollup_meta')")[0][0] == "2");
    CHECK(sql_rows(pool, "SELECT count(*) FROM pg_indexes WHERE schemaname = "
                         "'software_inventory_store' AND indexname = "
                         "'software_components_name_idx'")[0][0] == "1");
    const auto meta = store.component_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at == 0); // never computed: "building"
}

TEST_CASE("refresh_component_rollup: grain 0 and 1 counts are exact, devices_unconfirmed counts non-current facets",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    // dev-a: two rows of libfoo 1.0 (two paths) and one of libfoo 2.0; facet full (current).
    apply_components(store, "dev-a",
                     {comp("libfoo", "/a1", "1.0"), comp("libfoo", "/a2", "1.0"),
                      comp("libfoo", "/a3", "2.0")});
    // dev-b: one row; the facet then goes constrained (rows stay, no longer confirmed).
    apply_components(store, "dev-b", {comp("libfoo", "/b", "1.0")});
    REQUIRE(store.apply_installed_software_v3("dev-b", v3_report({v3_status(kV3Comp, V3Status::kConstrained)}))
                .at(0).outcome == V3SectionOutcome::kStatusOnly);
    // dev-c: a row with NO facet state record at all (a hand-made row): unconfirmed.
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.software_components (agent_id, kind, "
                   "path_hash, path, name, version, row_hash, first_seen) VALUES ('dev-c', 'jar', "
                   "'ph', '/c', 'libfoo', '1.0', 'rh', 1)"));

    REQUIRE(store.refresh_component_rollup());
    const auto meta = store.component_rollup_meta();
    REQUIRE(meta.has_value());
    CHECK(meta->refreshed_at > 0);

    const auto grain1 = sql_rows(pool,
                                 "SELECT instances, devices, devices_unconfirmed FROM "
                                 "software_inventory_store.component_rollup WHERE grain = 1");
    REQUIRE(grain1.size() == 1);
    CHECK(grain1[0] == std::vector<std::string>{"5", "3", "2"});
    const auto grain0 = sql_rows(pool,
                                 "SELECT version, instances, devices, devices_unconfirmed FROM "
                                 "software_inventory_store.component_rollup WHERE grain = 0 "
                                 "ORDER BY version");
    REQUIRE(grain0.size() == 2);
    CHECK(grain0[0] == std::vector<std::string>{"1.0", "4", "3", "2"});
    CHECK(grain0[1] == std::vector<std::string>{"2.0", "1", "1", "0"});

    // component_totals without versions IS the grain-1 row; a version set is a live aggregate.
    // The two paths are told apart by a row that lands AFTER the refresh: the rollup answer
    // stays put, the live one moves.
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.software_components (agent_id, kind, "
                   "path_hash, path, name, version, row_hash, first_seen) VALUES ('dev-d', 'jar', "
                   "'ph', '/d', 'libfoo', '1.0', 'rh', 1)"));
    const auto t = store.component_totals("jar", "libfoo", std::nullopt);
    REQUIRE(t.has_value());
    CHECK(t->installs == 5); // the rollup row, not the live table (which now holds 6)
    CHECK(t->devices == 3);
    CHECK(t->devices_unconfirmed == 2);
    // dev-a holds BOTH versions: it counts once in the distinct-device figure; dev-d is live.
    const auto live =
        store.component_totals("jar", "libfoo", std::vector<std::string>{"1.0", "2.0"});
    REQUIRE(live.has_value());
    CHECK(live->installs == 6);
    CHECK(live->devices == 4);
    const auto only_two = store.component_totals("jar", "libfoo", std::vector<std::string>{"2.0"});
    REQUIRE(only_two.has_value());
    CHECK(only_two->installs == 1);
    CHECK(only_two->devices == 1);
    // No kind: live across kinds (distinct devices are not additive), still exact.
    const auto any_kind = store.component_totals("", "libfoo", std::nullopt);
    REQUIRE(any_kind.has_value());
    CHECK(any_kind->devices == 4);
    // An unknown component is a genuine zero, not a degrade.
    const auto none = store.component_totals("jar", "nothing", std::nullopt);
    REQUIRE(none.has_value());
    CHECK(none->installs == 0);
}

TEST_CASE("refresh_component_rollup: a cancelled refresh keeps the last-good rollup and stamp",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    apply_components(store, "dev-a", {comp("libfoo", "/a", "1.0")});
    REQUIRE(store.refresh_component_rollup());
    const auto good = store.component_rollup_meta();
    REQUIRE(good.has_value());
    REQUIRE(good->refreshed_at > 0);

    apply_components(store, "dev-b", {comp("libbar", "/b", "1.0")}); // not in the rollup yet
    CHECK_FALSE(store.refresh_component_rollup([] { return true; })); // cancelled before it starts
    const auto after = store.component_rollup_meta();
    REQUIRE(after.has_value());
    CHECK(after->refreshed_at == good->refreshed_at);
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.component_rollup WHERE "
                         "grain = 1")[0][0] == "1");
    // An idempotent re-run picks the new data up.
    REQUIRE(store.refresh_component_rollup());
    CHECK(sql_rows(pool, "SELECT count(*) FROM software_inventory_store.component_rollup WHERE "
                         "grain = 1")[0][0] == "2");
}

TEST_CASE("query_components: keyset order, scope push-down, prefix and contains escape LIKE metacharacters",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    apply_components(store, "dev-b", {comp("libfoo", "/b1", "1.0"), comp("libfoo", "/b2", "1.0")});
    apply_components(store, "dev-a", {comp("libfoo", "/a", "1.0"), comp("lib_fo", "/x", "1.0"),
                                      comp("libXfo", "/y", "1.0")});
    apply_components(store, "dev-c", {comp("zlib", "/c", "1.0")});

    SoftwareComponentQuery q;
    q.limit = 100;
    auto all = store.query_components(q);
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 6);
    // Ordered (name, agent_id, kind, path_hash) under the DATABASE's collation, so the reference
    // order is read from Postgres itself: byte order differs from en_US.UTF-8, where lib_fo <
    // libfoo < libXfo. Ordering and the keyset predicate share that collation, so paging is
    // self-consistent in any deployment (the name index serves the default collation).
    const auto reference = sql_rows(
        pool, "SELECT agent_id, kind, path_hash, name FROM software_inventory_store."
              "software_components ORDER BY name, agent_id, kind, path_hash");
    REQUIRE(reference.size() == all->size());
    for (std::size_t i = 0; i < all->size(); ++i) {
        CAPTURE(i);
        CHECK((*all)[i].agent_id == reference[i][0]);
        CHECK((*all)[i].kind == reference[i][1]);
        CHECK((*all)[i].path_hash == reference[i][2]);
        CHECK((*all)[i].name == reference[i][3]);
    }
    // Within one name the tail (agent_id, kind, path_hash) is collation-independent here.
    for (std::size_t i = 1; i < all->size(); ++i) {
        const auto& a = (*all)[i - 1];
        const auto& b = (*all)[i];
        if (a.name == b.name)
            CHECK(std::tie(a.agent_id, a.kind, a.path_hash) <
                  std::tie(b.agent_id, b.kind, b.path_hash));
    }

    // Keyset paging: pages of 3 cover every row exactly once.
    std::vector<std::string> walked;
    q.limit = 3;
    for (int guard = 0; guard < 10; ++guard) {
        auto page = store.query_components(q);
        REQUIRE(page.has_value());
        if (page->empty())
            break;
        for (const auto& r : *page)
            walked.push_back(r.agent_id + r.path);
        const auto& last = page->back();
        q.after = SoftwareComponentCursor{last.name, last.agent_id, last.kind, last.path_hash};
    }
    CHECK(walked.size() == 6);
    CHECK(std::set<std::string>(walked.begin(), walked.end()).size() == 6);
    q.after.reset();
    q.limit = 100;

    // Scope push-down: only the listed agents; present-empty is deny-all with no SQL.
    q.agent_ids = std::vector<std::string>{"dev-a", "dev-c"};
    CHECK(store.query_components(q)->size() == 4);
    q.agent_ids = std::vector<std::string>{};
    REQUIRE(store.query_components(q).has_value());
    CHECK(store.query_components(q)->empty());
    q.agent_ids.reset();

    // exact / prefix / contains; `_` and `%` are literal.
    q.name = "libfoo";
    CHECK(store.query_components(q)->size() == 3);
    q.name = "lib_f";
    q.match = NameMatch::kPrefix;
    CHECK(store.query_components(q)->size() == 1); // only lib_fo, not libfoo / libXfo
    q.name = "lib";
    CHECK(store.query_components(q)->size() == 5); // libfoo x3, lib_fo, libXfo; not zlib
    q.name = "LIBFO";
    q.match = NameMatch::kContains;
    CHECK(store.query_components(q)->size() == 3);
    q.name = "%";
    CHECK(store.query_components(q)->empty());
    q.name.clear();
    q.match = NameMatch::kExact;
    // A present-empty version set selects nothing; a set selects its members.
    q.versions = std::vector<std::string>{};
    CHECK(store.query_components(q)->empty());
    q.versions = std::vector<std::string>{"1.0"};
    CHECK(store.query_components(q)->size() == 6);
    q.versions = std::vector<std::string>{"9.9"};
    CHECK(store.query_components(q)->empty());
}

TEST_CASE("query_components: the name-driven plan reaches software_components_name_idx",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    apply_components(store, "dev-a", {comp("libfoo", "/a", "1.0")});
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    const std::vector<std::string> none;
    struct RollbackGuard {
        PGconn* conn;
        ~RollbackGuard() { pg::exec_params(conn, "ROLLBACK", std::vector<std::string>{}); }
    };
    REQUIRE(pg::exec_params(lease.get(), "BEGIN", none).status() == PGRES_COMMAND_OK);
    const RollbackGuard rollback{lease.get()};
    REQUIRE(pg::exec_params(lease.get(), "SET LOCAL enable_seqscan = off", none).status() ==
            PGRES_COMMAND_OK);
    auto plan_of = [&](const std::string& sql, const std::vector<std::string>& params) {
        pg::PgResult plan =
            pg::exec_params(lease.get(), ("EXPLAIN (COSTS OFF) " + sql).c_str(), params);
        REQUIRE(plan.status() == PGRES_TUPLES_OK);
        std::string text;
        for (int i = 0; i < PQntuples(plan.get()); ++i)
            text += std::string(PQgetvalue(plan.get(), i, 0)) + "\n";
        return text;
    };
    const std::string base =
        "SELECT c.agent_id FROM software_inventory_store.software_components c WHERE c.name ";
    const std::string order = " ORDER BY c.name, c.agent_id, c.kind, c.path_hash LIMIT 10";
    CHECK(plan_of(base + "= $1" + order, {"libfoo"}).find("software_components_name_idx") !=
          std::string::npos);
    // A LIKE prefix can use a default-opclass btree only where the database collation is C; on any
    // other collation it is a (limited) filtered scan, which is the documented ceiling.
    const auto coll = sql_rows(pool, "SELECT datcollate FROM pg_database WHERE datname = "
                                     "current_database()")[0][0];
    if (coll == "C" || coll == "POSIX")
        CHECK(plan_of(base + "LIKE $1 ESCAPE '\\'" + order, {"lib%"})
                  .find("software_components_name_idx") != std::string::npos);
}

TEST_CASE("component_versions: distinct versions of one component, capped at kCatalogRowCap",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.component_rollup (kind, name, version, "
                   "grain, instances, devices) SELECT 'jar', 'libfoo', 'v' || g, 0, 1, 1 FROM "
                   "generate_series(1, 2100) g"));
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.component_rollup (kind, name, version, "
                   "grain, instances, devices) VALUES ('jar', 'libfoo', '', 1, 2100, 1), "
                   "('so', 'libfoo', 'v1', 0, 1, 1), ('jar', 'other', 'x', 0, 1, 1)"));
    const auto capped = store.component_versions("jar", "libfoo");
    REQUIRE(capped.has_value());
    CHECK(capped->size() == static_cast<std::size_t>(kCatalogRowCap)); // never more
    // Another kind and another component are separate; an empty kind spans kinds (distinct).
    REQUIRE(store.component_versions("so", "libfoo").has_value());
    CHECK(store.component_versions("so", "libfoo")->size() == 1);
    CHECK(store.component_versions("jar", "other")->size() == 1);
    CHECK(store.component_versions("jar", "").value().empty()); // no name: empty value
}

TEST_CASE("catalog_title_totals counts install ROWS and distinct devices; version-set totals count a device once",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    SoftwareEntry amd = v3_entry("git", kV3Pkgs, "1.9");
    amd.arch = "amd64";
    SoftwareEntry arm = v3_entry("git", kV3Pkgs, "1.9");
    arm.arch = "arm64";
    SoftwareEntry newer = v3_entry("git", kV3Pkgs, "1.10");
    newer.arch = "amd64";
    REQUIRE(store.apply_installed_software_v3("dev-a", v3_report({v3_full(kV3Pkgs, {amd, arm, newer})}))
                .at(0).outcome == V3SectionOutcome::kStored);
    REQUIRE(store.apply_installed_software_v3("dev-b", v3_report({v3_full(kV3Pkgs, {newer})}))
                .at(0).outcome == V3SectionOutcome::kStored);
    REQUIRE(store.refresh_catalog_rollup());

    const auto title = store.catalog_title_totals("git");
    REQUIRE(title.has_value());
    CHECK(title->installs == 4); // rows: a device with two architectures counts twice
    CHECK(title->devices == 2);  // distinct devices
    const auto gone = store.catalog_title_totals("absent");
    REQUIRE(gone.has_value());
    CHECK(gone->installs == 0);
    CHECK(gone->devices == 0);

    // dev-a carries BOTH selected versions: never a sum of per-version distinct counts (2 + 2).
    const auto both = store.installed_software_version_set_totals("git", {"1.9", "1.10"});
    REQUIRE(both.has_value());
    CHECK(both->installs == 4);
    CHECK(both->devices == 2);
    const auto one = store.installed_software_version_set_totals("git", {"1.9"});
    REQUIRE(one.has_value());
    CHECK(one->installs == 2);
    CHECK(one->devices == 1);
    const auto empty = store.installed_software_version_set_totals("git", {});
    REQUIRE(empty.has_value());
    CHECK(empty->installs == 0);
}

TEST_CASE("query_software: selects the install_* columns and facet state; the status predicate matches the shared CASE",
          "[pg][software_inventory][lookup]") {
    SWINV_SHARED(store, pool);
    // Every (status, enabled) pair plus a row with no state record at all.
    const std::vector<std::string> statuses{"full", "delta", "constrained", "timeout", "oversize",
                                            "not_collected", "disabled", ""};
    int n = 0;
    for (const bool enabled : {true, false})
        for (const auto& st : statuses) {
            const std::string agent = "t" + std::to_string(n++);
            REQUIRE(sql_ok(pool,
                           "INSERT INTO software_inventory_store.installed_software (agent_id, "
                           "name, version, source, install_type, install_scope, install_location, "
                           "instance_key) VALUES ($1, 'truth', '1', 'src.x', 'package_manager', "
                           "'machine', '/opt', 'ik-' || $1)",
                           {agent}));
            REQUIRE(sql_ok(pool,
                           "INSERT INTO software_inventory_store.software_facet_state (agent_id, "
                           "facet, status, enabled, last_confirmed_at) VALUES ($1, 'src.x', $2, "
                           "$3::boolean, 77)",
                           {agent, st, enabled ? "true" : "false"}));
        }
    REQUIRE(sql_ok(pool,
                   "INSERT INTO software_inventory_store.installed_software (agent_id, name, "
                   "version, source) VALUES ('t-nostate', 'truth', '1', 'src.x')"));

    // The SQL derivation, read straight from the shared fragment.
    const std::string derive_sql =
        "SELECT i.agent_id, " + std::string(kRowStatusCaseSql) +
        " FROM software_inventory_store.installed_software i LEFT JOIN "
        "software_inventory_store.software_facet_state fs ON fs.agent_id = i.agent_id AND "
        "fs.facet = i.source WHERE i.name = 'truth'";
    std::map<std::string, std::string> sql_status;
    for (const auto& r : sql_rows(pool, derive_sql))
        sql_status[r[0]] = r[1];
    REQUIRE(sql_status.size() == 17);

    SoftwareFleetQuery q;
    q.name = "truth";
    q.limit = 100;
    const auto rows = store.query_software(q);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 17);
    for (const auto& r : *rows) {
        CAPTURE(r.agent_id, r.facet_status, r.facet_enabled);
        // The C++ twin agrees with the SQL on every pair.
        CHECK(std::string(yuzu::server::software_list::derive_status(r.facet_status, r.facet_enabled)) ==
              sql_status.at(r.agent_id));
        if (r.agent_id != "t-nostate") {
            CHECK(r.entry.install_type == "package_manager");
            CHECK(r.entry.install_scope == "machine");
            CHECK(r.entry.install_location == "/opt");
            CHECK(r.entry.instance_key == "ik-" + r.agent_id);
            CHECK(r.last_confirmed_at == 77);
        } else {
            CHECK(r.facet_status.empty());
            CHECK(r.facet_enabled);
            CHECK(r.last_confirmed_at == 0);
        }
    }
    // The status predicate returns exactly the agents the CASE derives.
    for (const char* want : {"current", "unconfirmed", "disabled"}) {
        CAPTURE(want);
        q.status = want;
        const auto got = store.query_software(q);
        REQUIRE(got.has_value());
        std::set<std::string> have;
        for (const auto& r : *got)
            have.insert(r.agent_id);
        std::set<std::string> expect;
        for (const auto& [agent, st] : sql_status)
            if (st == want)
                expect.insert(agent);
        CHECK(have == expect);
        CHECK_FALSE(expect.empty());
    }
    // A version SET narrows like the exact version; match=prefix/contains work over name.
    q.status.clear();
    q.versions = std::vector<std::string>{"nope"};
    CHECK(store.query_software(q)->empty());
    q.versions.reset();
    q.name = "tru";
    q.match = NameMatch::kPrefix;
    CHECK(store.query_software(q)->size() == 17);
    q.name = "RUT";
    q.match = NameMatch::kContains;
    CHECK(store.query_software(q)->size() == 17);
}
