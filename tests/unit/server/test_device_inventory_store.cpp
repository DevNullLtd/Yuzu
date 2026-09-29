// DeviceInventoryStore tests (ADR-0016): the born-on-Postgres device-CI
// projection — canonical-hash cross-pin (clean + dirty) with the agent, blob parse
// round-trip, hash-skip ingest (full/touched/need_full), single-row replace,
// roster read, delete, server-receipt-time stamping (#1685), broken-pool degrade,
// oversized-blob nack, and the shared ingest seam end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "device_ci_ingestion.hpp"
#include "device_inventory_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::CiReadError;
using yuzu::server::DeviceCiRecord;
using yuzu::server::DeviceInventoryStore;
using yuzu::server::InventoryIngestOutcome;
using yuzu::server::parse_device_ci_blob;
using yuzu::server::pg::PgPool;
namespace agentpb = yuzu::agent::v1;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations.
yuzu::test::PgTestTemplate device_ci_tpl{"device_ci", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DeviceInventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("device_ci template: store failed to migrate");
}};

// THE cross-side pins (ADR-0016 §4): the agent computes the SAME hash for the SAME
// record (tests/unit/test_device_ci_sync.cpp — identical constants). A one-byte
// drift in either canonicalisation fails one assertion.
constexpr const char* kCrossPinHash =
    "467abd73a70803c5c762a26a4c7ffce536dda060d296ad83aed649473388f975";
constexpr const char* kDirtyCrossPinHash =
    "d569640762613846756047c953a0bc53b8e01c1e05aea4c4c62b68021434d7bc";

std::int64_t clock_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// The 22 canonical fields, in CiRecord order. Clean variant = all clean ASCII.
std::array<std::string, 22> clean_fields() {
    return {"Dell Inc.",
            "Latitude 7420",
            "ABC123",
            "4C4C4544-0042-1234-5678-AABBCCDDEEFF",
            "WS-001",
            "corp.example",
            "OU=Laptops,DC=corp,DC=example",
            "Dell Inc.",
            "1.27.0",
            "2024-03-15",
            "Intel(R) Core(TM) i7-1185G7",
            "4",
            "8",
            "17179869184",
            "Samsung SSD 980 512 SSD",
            "00:11:22:33:44:55",
            "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff",
            "2",
            "Windows 11 Pro",
            "10.0.22631",
            "22631",
            "x86_64"};
}

// Dirty variant — byte-identical to the agent's dirty() (test_device_ci_sync.cpp):
// valid multibyte ü (preserved), an invalid 0xFF byte (→ U+FFFD), and a >1024-byte
// field (clamped). Real manufacturer/model so the skip guard never fires. NO interior
// 0x1F/0x1E (the agent strips those pre-hash, so a real agent never emits one).
std::array<std::string, 22> dirty_fields() {
    auto f = clean_fields();
    f[0] = "M\xC3\xBCller GmbH";
    f[1] = "OptiPlex 7090";
    f[2] = "S\xFF"
           "N123";
    f[10] = std::string(1100, 'Z');
    return f;
}

// Raw positional join (the wire blob): fields 0x1F-separated, one record 0x1E-terminated.
std::string build_blob(const std::array<std::string, 22>& f) {
    std::string b;
    for (std::size_t i = 0; i < f.size(); ++i) {
        if (i)
            b += '\x1f';
        b += f[i];
    }
    b += '\x1e';
    return b;
}

std::string sample_blob() { return build_blob(clean_fields()); }
} // namespace

TEST_CASE("DeviceInventoryStore canonical_hash matches the cross-pin", "[device_ci][hash]") {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    CHECK(DeviceInventoryStore::canonical_hash(r) == kCrossPinHash);
}

TEST_CASE("DeviceInventoryStore dirty-input canonical_hash matches the cross-pin",
          "[device_ci][hash]") {
    // The server parses the raw dirty blob (clamps 0xFF→U+FFFD, truncates the 1100-Z
    // field), then re-hashes — must equal the agent's hash of the SAME dirty record.
    DeviceCiRecord r = parse_device_ci_blob(build_blob(dirty_fields()));
    CHECK(DeviceInventoryStore::canonical_hash(r) == kDirtyCrossPinHash);
}

TEST_CASE("parse_device_ci_blob round-trips fields positionally", "[device_ci][parse]") {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    CHECK(r.manufacturer == "Dell Inc.");
    CHECK(r.serial == "ABC123");
    CHECK(r.cpu_cores == "4");
    CHECK(r.ram_bytes == "17179869184");
    CHECK(r.macs_summary == "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff");
    CHECK(r.arch == "x86_64");

    SECTION("missing trailing fields stay empty (no crash)") {
        DeviceCiRecord p = parse_device_ci_blob("OnlyMfr\x1fOnlyModel\x1e");
        CHECK(p.manufacturer == "OnlyMfr");
        CHECK(p.model == "OnlyModel");
        CHECK(p.serial.empty());
        CHECK(p.arch.empty());
    }
    SECTION("two fields split positionally on the separators") {
        DeviceCiRecord p = parse_device_ci_blob(std::string("a\x1f"
                                                            "b\x1e"));
        CHECK(p.manufacturer == "a");
        CHECK(p.model == "b");
    }
    SECTION("oversized blob → empty record (defence-in-depth)") {
        DeviceCiRecord p = parse_device_ci_blob(std::string(70u * 1024, 'x'));
        CHECK(p.manufacturer.empty());
    }
}

TEST_CASE("DeviceInventoryStore degrades (not empty) on a broken pool", "[device_ci]") {
    // No live PG needed: an unreachable conninfo → the store never opens, and every
    // read reports a degrade (kError / unexpected / nullopt), never a silent empty.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    DeviceInventoryStore store{pool};
    REQUIRE(!store.is_open());

    DeviceCiRecord rec = parse_device_ci_blob(sample_blob());
    CHECK(store.apply_device_ci("a", "h", std::optional<DeviceCiRecord>{rec}, 1) ==
          InventoryIngestOutcome::kError);
    auto g = store.get_device_ci("a");
    CHECK(!g.has_value()); // std::unexpected(kDegraded)
    CHECK(g.error() == CiReadError::kDegraded);
    CHECK(!store.list_device_ci(10).has_value()); // nullopt (degraded), not an empty vector
}

TEST_CASE("DeviceInventoryStore hash-skip ingest round-trip", "[pg][device_ci]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    DeviceCiRecord rec = parse_device_ci_blob(sample_blob());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);

    SECTION("full payload stores, reads back with fields") {
        CHECK(store.apply_device_ci("agent-a", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
              InventoryIngestOutcome::kStored);
        auto r = store.get_device_ci("agent-a");
        REQUIRE(r.has_value());  // not degraded
        REQUIRE(r->has_value()); // found
        const DeviceCiRecord& got = **r;
        CHECK(got.agent_id == "agent-a");
        CHECK(got.manufacturer == "Dell Inc.");
        CHECK(got.serial == "ABC123");
        CHECK(got.cpu_cores == "4");
        CHECK(got.ram_bytes == "17179869184");
        CHECK(got.os_name == "Windows 11 Pro");
        CHECK(got.last_seen > 0);
        CHECK(got.first_seen > 0);
    }

    SECTION("last_seen is server receipt time, not agent collected_at (#1685)") {
        const std::int64_t floor = clock_now_secs();
        const std::int64_t skewed = floor + 10LL * 365 * 86400; // ~10 years future
        REQUIRE(store.apply_device_ci("agent-ts", h, std::optional<DeviceCiRecord>{rec}, skewed) ==
                InventoryIngestOutcome::kStored);
        auto r = store.get_device_ci("agent-ts");
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK((**r).last_seen >= floor);   // stamped from the server clock
        CHECK((**r).last_seen < skewed);   // the future collected_at was ignored
    }

    SECTION("hash-only matching → touched; mismatch / cold → need_full") {
        REQUIRE(store.apply_device_ci("agent-b", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_device_ci("agent-b", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
        CHECK(store.apply_device_ci("agent-b", "deadbeef", std::nullopt, 3000) ==
              InventoryIngestOutcome::kNeedFull);
        CHECK(store.apply_device_ci("agent-cold", h, std::nullopt, 4000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("first_seen preserved across re-store; last_seen advances") {
        REQUIRE(store.apply_device_ci("agent-c", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        auto first = store.get_device_ci("agent-c");
        REQUIRE(first.has_value());
        REQUIRE(first->has_value());
        DeviceCiRecord rec2 = rec;
        rec2.model = "Latitude 9430";
        const std::string h2 = DeviceInventoryStore::canonical_hash(rec2);
        REQUIRE(store.apply_device_ci("agent-c", h2, std::optional<DeviceCiRecord>{rec2}, 5000) ==
                InventoryIngestOutcome::kStored);
        auto second = store.get_device_ci("agent-c");
        REQUIRE(second.has_value());
        REQUIRE(second->has_value());
        CHECK((**second).model == "Latitude 9430");
        CHECK((**second).first_seen == (**first).first_seen);
        CHECK((**second).last_seen >= (**first).last_seen);
    }

    SECTION("non-numeric numeric fields persist as 0 (bigint_param)") {
        DeviceCiRecord bad = rec;
        bad.cpu_cores = "notanumber";
        bad.ram_bytes = "";
        const std::string bh = DeviceInventoryStore::canonical_hash(bad);
        REQUIRE(store.apply_device_ci("agent-num", bh, std::optional<DeviceCiRecord>{bad}, 1) ==
                InventoryIngestOutcome::kStored);
        auto r = store.get_device_ci("agent-num");
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK((**r).cpu_cores == "0");
        CHECK((**r).ram_bytes == "0");
    }

    SECTION("roster list + delete + absent") {
        REQUIRE(store.apply_device_ci("agent-d", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        auto roster = store.list_device_ci(100);
        REQUIRE(roster.has_value());
        bool found = false;
        for (const auto& d : *roster)
            if (d.agent_id == "agent-d")
                found = true;
        CHECK(found);

        CHECK(store.delete_agent("agent-d")); // committed → true
        auto gone = store.get_device_ci("agent-d");
        REQUIRE(gone.has_value());  // read succeeded
        CHECK(!gone->has_value());  // absent
    }

    SECTION("unknown agent reads absent (not degraded)") {
        auto none = store.get_device_ci("nobody");
        REQUIRE(none.has_value());
        CHECK(!none->has_value());
    }
}

TEST_CASE("ingest_device_ci_report end-to-end (all wire shapes)", "[pg][device_ci][ingest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::string blob = sample_blob();
    const std::string h = DeviceInventoryStore::canonical_hash(parse_device_ci_blob(blob));

    SECTION("full report stores; subsequent hash-only matching report does not nack") {
        agentpb::InventoryReport full;
        (*full.mutable_content_hashes())["device_ci"] = h;
        (*full.mutable_plugin_data())["device_ci"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-e", full, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
        auto got = store.get_device_ci("agent-e");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((**got).serial == "ABC123");

        agentpb::InventoryReport hashonly;
        (*hashonly.mutable_content_hashes())["device_ci"] = h; // no plugin_data
        agentpb::InventoryAck ack2;
        yuzu::server::ingest_device_ci_report(store, "agent-e", hashonly, ack2, nullptr);
        CHECK(ack2.need_full_size() == 0); // matched → touched, no resend
    }

    SECTION("hash-only with no stored row nacks (cold cache)") {
        agentpb::InventoryReport hashonly;
        (*hashonly.mutable_content_hashes())["device_ci"] = h;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-cold2", hashonly, ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
    }

    SECTION("oversized blob is dropped + nacked, nothing stored") {
        agentpb::InventoryReport rpt;
        (*rpt.mutable_content_hashes())["device_ci"] = "somehash";
        (*rpt.mutable_plugin_data())["device_ci"] = std::string(70u * 1024, 'x'); // > 64 KiB
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-big", rpt, ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
        auto r = store.get_device_ci("agent-big");
        REQUIRE(r.has_value());
        CHECK(!r->has_value()); // nothing stored
    }

    SECTION("source absent from the report → no-op, no nack") {
        agentpb::InventoryReport other;
        (*other.mutable_content_hashes())["installed_software"] = "x";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-f", other, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
    }
}
