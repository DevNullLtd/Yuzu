// device_ci write pause (#7730): while the collation gate reads Mismatch, the device_ci store
// refuses every write and delete BEFORE touching the pool, the ingest seam refuses BEFORE it
// parses the blob, and the decommission cascade names the pause. The gate is a plain atomic
// flipped by the test (hermetic: no catalog change); only Mismatch pauses (decision D3).

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "agent_decommission.hpp"
#include "device_ci_ingestion.hpp"
#include "device_ci_kinds.hpp"
#include "device_inventory_store.hpp"
#include "pg/pg_collation_check.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AgentDecommission;
using yuzu::server::AgentDecommissionStores;
using yuzu::server::DecommissionOutcome;
using yuzu::server::DeviceCiRecord;
using yuzu::server::DeviceInventoryStore;
using yuzu::server::InventoryIngestOutcome;
using yuzu::server::parse_device_ci_blob;
using yuzu::server::pg::CollationGate;
using yuzu::server::pg::PgPool;
namespace agentpb = yuzu::agent::v1;

namespace {

yuzu::test::PgTestTemplate pause_tpl{"device_ci_pause", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DeviceInventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("device_ci_pause template: store failed to migrate");
}};

// A v1 blob: 22 positional fields, 0x1F-separated, one record 0x1E-terminated.
std::string blob(const std::string& serial = "ABC123") {
    const std::vector<std::string> f = {"Dell Inc.", "Latitude 7420", serial,
                                        "4C4C4544-0042-1234-5678-AABBCCDDEEFF",
                                        "WS-001", "corp.example", "OU=Laptops", "Dell Inc.",
                                        "1.27.0", "2024-03-15", "Intel(R) Core(TM) i7", "4", "8",
                                        "17179869184", "Samsung SSD", "00:11:22:33:44:55",
                                        "00:11:22:33:44:55", "2", "Windows 11 Pro", "10.0.22631",
                                        "22631", "x86_64"};
    std::string b;
    for (std::size_t i = 0; i < f.size(); ++i) {
        if (i)
            b += '\x1f';
        b += f[i];
    }
    b += '\x1e';
    return b;
}

// The whole stored row as text ("" when there is none): any write to it changes the string.
std::string row_text(PgPool& pool, const std::string& agent) {
    auto lease = pool.acquire();
    if (!lease)
        return "<no lease>";
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "SELECT d::text FROM device_inventory_store.device_ci d WHERE agent_id = $1",
        std::vector<std::string>{agent});
    if (res.status() != PGRES_TUPLES_OK)
        return "<query failed>";
    return PQntuples(res.get()) == 0 ? "" : PQgetvalue(res.get(), 0, 0);
}

// Pin last_seen to 1 so a later touch (which stamps the server clock) is unmistakable.
void pin_last_seen(PgPool& pool, const std::string& agent) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(), "UPDATE device_inventory_store.device_ci SET last_seen = 1 WHERE agent_id = $1",
        std::vector<std::string>{agent});
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}

double deferred(yuzu::MetricsRegistry& m, const char* op) {
    return m.counter("yuzu_device_ci_writes_deferred_total", {{"op", op}}).value();
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

} // namespace

TEST_CASE("device_ci store with NO gate wired writes exactly as before", "[pg][device_ci][collation_gate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    // Declared BEFORE the store that later borrows it, so it is destroyed AFTER it.
    std::atomic<CollationGate> gate{CollationGate::Mismatch};
    DeviceInventoryStore store{pool}; // set_write_gate never called: the default
    REQUIRE(store.is_open());
    CHECK_FALSE(store.writes_deferred());

    const DeviceCiRecord rec = parse_device_ci_blob(blob());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);
    CHECK(store.apply_device_ci("a", h, std::optional<DeviceCiRecord>{rec}, 1) ==
          InventoryIngestOutcome::kStored);
    CHECK(store.apply_device_ci("a", h, std::nullopt, 1) == InventoryIngestOutcome::kTouched);
    CHECK(store.delete_agent("a"));

    // A gate set and then withdrawn is the same as none.
    store.set_write_gate(&gate);
    CHECK(store.writes_deferred());
    store.set_write_gate(nullptr);
    CHECK_FALSE(store.writes_deferred());
}

TEST_CASE("device_ci write pause: only Mismatch refuses, and refusal leaves the row byte-unchanged",
          "[pg][device_ci][collation_gate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    // Declared BEFORE the store that borrows it, so it is destroyed AFTER it.
    std::atomic<CollationGate> gate{CollationGate::Trusted};
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    store.set_write_gate(&gate);

    const DeviceCiRecord rec = parse_device_ci_blob(blob());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);
    REQUIRE(store.apply_device_ci("a", h, std::optional<DeviceCiRecord>{rec}, 1) ==
            InventoryIngestOutcome::kStored);
    pin_last_seen(pool, "a");
    const std::string before = row_text(pool, "a");
    REQUIRE_FALSE(before.empty());

    gate.store(CollationGate::Mismatch);
    CHECK(store.writes_deferred());

    SECTION("a hash-only touch is refused and last_seen does not move") {
        CHECK(store.apply_device_ci("a", h, std::nullopt, 1) == InventoryIngestOutcome::kDeferred);
        CHECK(row_text(pool, "a") == before);
    }
    SECTION("a full upsert (changed record) is refused and nothing changes") {
        const DeviceCiRecord other = parse_device_ci_blob(blob("OTHER-SERIAL"));
        CHECK(store.apply_device_ci("a", DeviceInventoryStore::canonical_hash(other),
                                    std::optional<DeviceCiRecord>{other}, 1) ==
              InventoryIngestOutcome::kDeferred);
        CHECK(row_text(pool, "a") == before);
        // A device with no row yet gets none.
        CHECK(store.apply_device_ci("new", h, std::optional<DeviceCiRecord>{rec}, 1) ==
              InventoryIngestOutcome::kDeferred);
        CHECK(row_text(pool, "new").empty());
    }
    SECTION("delete_agent returns false and the row remains") {
        CHECK_FALSE(store.delete_agent("a"));
        CHECK(row_text(pool, "a") == before);
    }
    SECTION("the counter counts each refusal under its own op") {
        CHECK(deferred(metrics, "ingest") == 0.0);
        CHECK(deferred(metrics, "delete") == 0.0);
        (void)store.apply_device_ci("a", h, std::nullopt, 1);
        (void)store.apply_device_ci("a", h, std::optional<DeviceCiRecord>{rec}, 1);
        (void)store.delete_agent("a");
        store.note_ingest_deferred(); // the seam's refusal
        CHECK(deferred(metrics, "ingest") == 3.0);
        CHECK(deferred(metrics, "delete") == 1.0);
    }
    SECTION("Unproven and Trusted never pause: writes succeed again") {
        for (const auto open : {CollationGate::Unproven, CollationGate::Trusted}) {
            gate.store(open);
            CHECK_FALSE(store.writes_deferred());
            CHECK(store.apply_device_ci("a", h, std::nullopt, 1) == InventoryIngestOutcome::kTouched);
            CHECK(row_text(pool, "a") != before); // last_seen moved off the pinned 1
            pin_last_seen(pool, "a");
            CHECK(store.apply_device_ci("a", h, std::optional<DeviceCiRecord>{rec}, 1) ==
                  InventoryIngestOutcome::kStored);
        }
        CHECK(deferred(metrics, "ingest") == 0.0);
        CHECK(store.delete_agent("a"));
        CHECK(row_text(pool, "a").empty());
    }
}

TEST_CASE("device_ci write pause logs once per pause, and again for the next one",
          "[pg][device_ci][collation_gate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    // Declared BEFORE the store that borrows it, so it is destroyed AFTER it.
    std::atomic<CollationGate> gate{CollationGate::Mismatch};
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());
    store.set_write_gate(&gate);
    const DeviceCiRecord rec = parse_device_ci_blob(blob());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);

    yuzu::test::LogCapture cap(spdlog::level::info);
    for (int i = 0; i < 5; ++i) {
        (void)store.apply_device_ci("a", h, std::nullopt, 1);
        (void)store.delete_agent("a");
    }
    gate.store(CollationGate::Trusted);
    (void)store.apply_device_ci("a", h, std::optional<DeviceCiRecord>{rec}, 1); // resumes
    gate.store(CollationGate::Mismatch);
    (void)store.apply_device_ci("a", h, std::nullopt, 1);
    (void)store.apply_device_ci("a", h, std::nullopt, 1);
    cap.stop();
    const std::string text = cap.text();
    CHECK(count_of(text, "device_ci writes are PAUSED") == 2); // one per entry into the pause
    CHECK(count_of(text, "\"PostgreSQL collation version\" section") == 2); // names the runbook
    CHECK(count_of(text, "device_ci writes resumed") == 1);
}

TEST_CASE("decommission cascade reports a paused device_ci removal with a distinct reason",
          "[pg][device_ci][collation_gate][decommission]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    // Declared BEFORE the store that borrows it, so it is destroyed AFTER it.
    std::atomic<CollationGate> gate{CollationGate::Trusted};
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());
    store.set_write_gate(&gate);
    const DeviceCiRecord rec = parse_device_ci_blob(blob());
    REQUIRE(store.apply_device_ci("a", DeviceInventoryStore::canonical_hash(rec),
                                  std::optional<DeviceCiRecord>{rec}, 1) ==
            InventoryIngestOutcome::kStored);

    AgentDecommissionStores stores;
    stores.device_inventory = &store;
    AgentDecommission cascade{stores};

    gate.store(CollationGate::Mismatch);
    const auto paused = cascade.decommission("a");
    REQUIRE_FALSE(paused.ok());
    const yuzu::server::DecommissionStoreResult* line = nullptr;
    for (const auto& s : paused.stores)
        if (s.store == "device_inventory")
            line = &s;
    REQUIRE(line != nullptr);
    CHECK(line->outcome == DecommissionOutcome::Failed);
    CHECK(line->write_paused);
    CHECK(line->error.find("not attempted") != std::string::npos);
    CHECK(line->error.find("paused") != std::string::npos);
    CHECK(line->error.find("collation") != std::string::npos);
    CHECK(line->error.find("did not commit") == std::string::npos); // not the generic text
    CHECK_FALSE(row_text(pool, "a").empty());                       // nothing was erased

    gate.store(CollationGate::Trusted);
    const auto after = cascade.decommission("a");
    CHECK(after.ok());
    for (const auto& s : after.stores)
        CHECK_FALSE(s.write_paused);
    CHECK(row_text(pool, "a").empty());
}

TEST_CASE("decommission: a plain delete failure is NOT reported as a write pause",
          "[device_ci][collation_gate][decommission]") {
    // No live PG: a closed store's delete_agent is false with no gate wired.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    DeviceInventoryStore store{pool};
    REQUIRE_FALSE(store.is_open());
    AgentDecommissionStores stores;
    stores.device_inventory = &store;
    AgentDecommission cascade{stores};
    const auto r = cascade.decommission("a");
    for (const auto& s : r.stores) {
        if (s.store != "device_inventory")
            continue;
        CHECK(s.outcome == DecommissionOutcome::Failed);
        CHECK_FALSE(s.write_paused);
        CHECK(s.error.find("did not commit") != std::string::npos);
    }
}

TEST_CASE("ingest seam refuses a paused fleet BEFORE parsing and reports the deferred label",
          "[pg][device_ci][collation_gate][ingest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    // Declared BEFORE the store that borrows it, so it is destroyed AFTER it.
    std::atomic<CollationGate> gate{CollationGate::Mismatch};
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    store.set_write_gate(&gate);

    const auto outcome = [&](const char* label) {
        return metrics
            .counter("yuzu_inventory_ingest_total", {{"source", "device_ci"}, {"outcome", label}})
            .value();
    };
    const auto report = [](const std::string& hash, std::optional<std::string> data) {
        agentpb::InventoryReport r;
        (*r.mutable_content_hashes())["device_ci"] = hash;
        if (data)
            (*r.mutable_plugin_data())["device_ci"] = *data;
        return r;
    };

    SECTION("a well-formed full report: deferred, need_full, nothing stored") {
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "a", report("h", blob()), ack, &metrics);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
        CHECK(outcome("deferred") == 1.0);
        CHECK(outcome("error") == 0.0);
        CHECK(outcome("stored") == 0.0);
        CHECK(row_text(pool, "a").empty());
        CHECK(deferred(metrics, "ingest") == 1.0);
    }
    SECTION("a hash-only report is deferred too") {
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "a", report("h", std::nullopt), ack, &metrics);
        CHECK(ack.need_full_size() == 1);
        CHECK(outcome("deferred") == 1.0);
    }
    SECTION("the check precedes the blob handling: garbage and over-cap blobs are 'deferred', "
            "not 'dropped' or a parse outcome") {
        for (const std::string& bad :
             {std::string("\xff\xfe\x01 not a device_ci blob"),
              std::string(yuzu::server::kDeviceCiMaxBlobBytes + 1, 'x')}) {
            agentpb::InventoryAck ack;
            yuzu::server::ingest_device_ci_report(store, "a", report("h", bad), ack, &metrics);
            CHECK(ack.need_full_size() == 1);
        }
        CHECK(outcome("deferred") == 2.0);
        CHECK(outcome("dropped") == 0.0);
        CHECK(outcome("error") == 0.0);
        CHECK(row_text(pool, "a").empty());
    }
    SECTION("a report with no device_ci source is untouched by the pause") {
        agentpb::InventoryReport r;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "a", r, ack, &metrics);
        CHECK(ack.need_full_size() == 0);
        CHECK(deferred(metrics, "ingest") == 0.0);
    }
    SECTION("once the gate is Trusted the same report stores") {
        gate.store(CollationGate::Trusted);
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "a", report("h", blob()), ack, &metrics);
        CHECK(ack.need_full_size() == 0);
        CHECK(outcome("stored") == 1.0);
        CHECK_FALSE(row_text(pool, "a").empty());
    }
}

// Review of #8108, item 4. A throw out of the ingest seam is caught by ReportInventory, which then
// acks without whatever the seam had not yet appended, so every need_full nack is appended BEFORE
// any telemetry. The counter is injected here and made to throw; each refusal path must still
// carry its nack. Kills: moving `ack.add_need_full` back after the counter (the agent would
// advance as if the report had been stored).
TEST_CASE("a throw in the outcome telemetry cannot lose the need_full nack",
          "[pg][device_ci][collation_gate][ingest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, pause_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    std::atomic<CollationGate> gate{CollationGate::Mismatch};
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());
    store.set_write_gate(&gate);

    std::vector<std::string> emitted;
    const yuzu::server::IngestOutcomeEmitFn throwing = [&](const char* outcome) {
        emitted.emplace_back(outcome);
        throw std::runtime_error("telemetry failed");
    };
    const auto report = [](const std::string& hash, std::optional<std::string> data) {
        agentpb::InventoryReport r;
        (*r.mutable_content_hashes())["device_ci"] = hash;
        if (data)
            (*r.mutable_plugin_data())["device_ci"] = *data;
        return r;
    };
    const auto run = [&](const agentpb::InventoryReport& r, agentpb::InventoryAck& ack) {
        CHECK_THROWS_AS(
            yuzu::server::ingest_device_ci_report_with_emit(store, "a", r, ack, nullptr, throwing),
            std::runtime_error);
    };

    SECTION("the write-pause refusal") {
        agentpb::InventoryAck ack;
        run(report("h", blob()), ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
        CHECK(emitted == std::vector<std::string>{"deferred"});
    }
    SECTION("the over-cap blob refusal") {
        gate.store(CollationGate::Trusted);
        agentpb::InventoryAck ack;
        run(report("h", std::string(yuzu::server::kDeviceCiMaxBlobBytes + 1, 'x')), ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(emitted == std::vector<std::string>{"dropped"});
    }
    SECTION("the store's own need_full answer (a cold hash-only report)") {
        gate.store(CollationGate::Trusted);
        agentpb::InventoryAck ack;
        run(report("h", std::nullopt), ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(emitted == std::vector<std::string>{"need_full"});
    }
}

// qe-2 / ARCH-4. The branch of `ingest_device_ci_report` where `apply_device_ci` returns kDeferred
// AFTER the seam's own check (a pause that races in between them) cannot be reached from outside:
// the gate would have to flip between two adjacent statements. The mapping the seam applies to that
// outcome is therefore ONE pure function shared by every seam, tested over every enumerator; a
// source pin proves both seams use it. Kills: dropping kDeferred from the need_full answer (the
// agent would believe the report was stored and not resend for up to the weekly floor), a label of
// `error` for it, and a seam that goes back to a hand-written ternary chain.
TEST_CASE("ingest outcome mapping: kDeferred is labelled deferred and nacked as need_full",
          "[device_ci][collation_gate][ingest]") {
    using yuzu::server::ingest_outcome_label;
    using yuzu::server::ingest_outcome_needs_full;
    struct Row {
        InventoryIngestOutcome o;
        const char* label;
        bool needs_full;
    };
    static constexpr Row table[] = {
        {InventoryIngestOutcome::kStored, "stored", false},
        {InventoryIngestOutcome::kTouched, "touched", false},
        {InventoryIngestOutcome::kNeedFull, "need_full", true},
        {InventoryIngestOutcome::kError, "error", true},
        {InventoryIngestOutcome::kDeferred, "deferred", true},
    };
    for (const Row& r : table) {
        CHECK(std::string(ingest_outcome_label(r.o)) == r.label);
        CHECK(ingest_outcome_needs_full(r.o) == r.needs_full);
    }
    // An out-of-range value nacks (the safe direction) and reads as an error.
    const auto bogus = static_cast<InventoryIngestOutcome>(99);
    CHECK(std::string(ingest_outcome_label(bogus)) == "error");
    CHECK(ingest_outcome_needs_full(bogus));
}

TEST_CASE("ingest seams map the store outcome through the shared helpers, not a ternary chain",
          "[device_ci][collation_gate][ingest]") {
    const auto read = [](const char* name) {
        std::ifstream in(std::string(YUZU_SERVER_SRC_DIR) + "/" + name, std::ios::binary);
        REQUIRE(in.good());
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    };
    for (const char* file : {"device_ci_ingestion.cpp", "inventory_ingestion.cpp"}) {
        INFO(file);
        const std::string text = read(file);
        CHECK(count_of(text, "ingest_outcome_label(outcome)") == 1);
        CHECK(count_of(text, "ingest_outcome_needs_full(outcome)") == 1);
        // The old shape: a comparison of the outcome against an enumerator in a chain or condition.
        CHECK(count_of(text, "outcome == InventoryIngestOutcome::") == 0);
    }
}
