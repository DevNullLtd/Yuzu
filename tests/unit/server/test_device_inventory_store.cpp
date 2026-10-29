// DeviceInventoryStore tests (ADR-0016): the born-on-Postgres device-CI
// projection — canonical-hash cross-pin (clean + dirty) with the agent, blob parse
// round-trip, hash-skip ingest (full/touched/need_full), single-row replace,
// roster read, delete, server-receipt-time stamping (#1685), broken-pool degrade,
// oversized-blob nack, and the shared ingest seam end-to-end. v2 blob (H.3): version-byte
// parse, scalar-section statuses, list rows + caps + truncation disclosure, the per-version
// hash, the child-table replace transaction, the REPEATABLE READ sections read, the
// populated-v1 migration upgrade, and the mixed-version (old-agent) guarantee.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "device_ci_ingestion.hpp"
#include "device_ci_kinds.hpp"
#include "device_inventory_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "sha256_hex.hpp"

#include "../test_helpers.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::CiReadError;
using yuzu::server::DeviceCiRecord;
using yuzu::server::DeviceCiSection;
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

// ── v2 fixtures ────────────────────────────────────────────────────────────────
// kCrossPinHashV2: sha256 of the fixed v2 blob below. The agent twin
// (tests/unit/test_device_ci_sync.cpp) assembles the SAME bytes from the SAME literal
// fields — the forward contract H.4's device_ci_canonical_blob_v2 must reproduce.
// Placeholder serials only; the DIMM serial is '-'.
constexpr const char* kCrossPinHashV2 = "26037f18de08a8a21facd746eef7ec0a722479ee2009df9b6f14edea35ef0a62";

// One 0x1F-joined, 0x1E-terminated record.
std::string join_rec(const std::vector<std::string>& f) {
    std::string b;
    for (std::size_t i = 0; i < f.size(); ++i) {
        if (i)
            b += '\x1f';
        b += f[i];
    }
    b += '\x1e';
    return b;
}

// 33 scalar positions: the 22 clean v1 fields + the 11 appended identity scalars.
std::vector<std::string> v2_scalars() {
    auto base = clean_fields();
    std::vector<std::string> f(base.begin(), base.end());
    for (const char* v : {"laptop", "CHS-0001", "AT-0001", "dmi", "Dell Inc.", "0K3CM7",
                          "BRD-0001", "dmi",
                          "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                          "sha256-hmac", "etc_machine_id"})
        f.emplace_back(v);
    return f;
}

// Status records for the three scalar sections + every list kind, and one row per list
// kind (the swap row has exactly 3 fields — no used_mb).
std::vector<std::vector<std::string>> v2_records() {
    return {
        {"status", "chassis", "ok", ""},
        {"status", "baseboard", "ok", ""},
        {"status", "machine_id", "ok", ""},
        {"status", "cpu", "ok", ""},
        {"cpu", "0", "Intel(R) Core(TM) i7-1185G7", "4", "8", "2800", "U3E1", "1"},
        {"status", "dimm", "ok", ""},
        {"dimm", "DIMM0", "8192", "DDR4", "3200", "Samsung", "M471A1K43", "-"},
        {"status", "disk", "ok", ""},
        {"disk", "0", "Samsung SSD 980", "512", "SSD", "NVMe"},
        {"status", "swap", "ok", ""},
        {"swap", "/swapfile", "2048", "proc_swaps"},
        {"status", "volume", "ok", ""},
        {"volume", "C:", "C:\\", "\\\\?\\Volume{1}", "NTFS", "511705088", "-"},
        {"status", "partition", "ok", ""},
        {"partition", "0", "1", "536870912", "EFI", "-", "-"},
        {"status", "topology", "ok", ""},
        {"topology", "lvm", "vg0", "uuid-0001", "sda2", "-"},
    };
}

std::string build_blob_v2(const std::vector<std::string>& scalars,
                          const std::vector<std::vector<std::string>>& recs) {
    std::string b(1, '\x02');
    b += join_rec(scalars);
    for (const auto& r : recs)
        b += join_rec(r);
    return b;
}

std::string fixture_blob_v2() { return build_blob_v2(v2_scalars(), v2_records()); }

const DeviceCiSection* find_section(const DeviceCiRecord& r, const std::string& kind) {
    for (const auto& s : r.sections)
        if (s.kind == kind)
            return &s;
    return nullptr;
}
const DeviceCiSection* find_section(const std::vector<DeviceCiSection>& v, const std::string& kind) {
    for (const auto& s : v)
        if (s.kind == kind)
            return &s;
    return nullptr;
}

// A hand-built v2 record (bypasses the parser): `cpu_rows` cpu rows tagged with `reason`,
// optionally one dimm row. content_hash is the caller's tag, so replace tests can tell
// generations apart.
DeviceCiRecord make_v2_record(const std::string& tag, int cpu_rows, bool with_dimm) {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    r.blob_version = 2;
    r.content_hash = "hash-" + tag;
    r.chassis_serial = "CHS-" + tag;
    DeviceCiSection cpu;
    cpu.kind = "cpu";
    cpu.level = "ok";
    cpu.reason = tag;
    for (int i = 0; i < cpu_rows; ++i)
        cpu.rows.push_back({std::to_string(i), "Model-" + tag, "4", "8", "2800", "U3E1", "1"});
    r.sections.push_back(std::move(cpu));
    if (with_dimm) {
        DeviceCiSection dimm;
        dimm.kind = "dimm";
        dimm.level = "ok";
        dimm.rows.push_back({"DIMM0", "8192", "DDR4", "3200", "Samsung", "M471A1K43", "-"});
        r.sections.push_back(std::move(dimm));
    }
    return r;
}

std::string count_sql(const std::string& sql_tail) { return "SELECT count(*) FROM " + sql_tail; }

// COUNT(*) via a fresh lease; -1 on any failure.
long long count_rows(PgPool& pool, const std::string& sql) {
    auto lease = pool.acquire();
    if (!lease)
        return -1;
    auto res = yuzu::server::pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
        return -1;
    return std::atoll(PQgetvalue(res.get(), 0, 0));
}
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

TEST_CASE("v1 blobs parse unchanged: version 1, no sections, v1 pins hold (old agent / new server)",
          "[device_ci][parse][v2]") {
    // R3: a v1 agent's hash must stay byte-identical so it never loops on need_full.
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    CHECK(r.blob_version == 1);
    CHECK(r.sections.empty());
    CHECK(r.content_hash.empty());
    CHECK(r.chassis_serial.empty());
    CHECK(DeviceInventoryStore::canonical_hash(r) == kCrossPinHash);
    CHECK(DeviceInventoryStore::canonical_hash(parse_device_ci_blob(build_blob(dirty_fields()))) ==
          kDirtyCrossPinHash);
}

TEST_CASE("v2 canonical hash is the sha256 of the received blob (kCrossPinHashV2)",
          "[device_ci][hash][v2]") {
    const std::string blob = fixture_blob_v2();
    DeviceCiRecord r = parse_device_ci_blob(blob);
    REQUIRE(r.blob_version == 2);
    const auto expect = yuzu::server::sha256_hex(blob);
    REQUIRE(expect.has_value());
    CHECK(r.content_hash == *expect);
    CHECK(DeviceInventoryStore::canonical_hash(r) == *expect);
    CHECK(DeviceInventoryStore::canonical_hash(r) == kCrossPinHashV2);

    SECTION("a v2 record without a pinned hash has no canonical hash (store nacks)") {
        DeviceCiRecord bare;
        bare.blob_version = 2;
        CHECK(DeviceInventoryStore::canonical_hash(bare).empty());
    }
}

TEST_CASE("v2 scalars land positionally in the 33 fields", "[device_ci][parse][v2]") {
    DeviceCiRecord r = parse_device_ci_blob(fixture_blob_v2());
    CHECK(r.blob_version == 2);
    CHECK(r.manufacturer == "Dell Inc.");
    CHECK(r.arch == "x86_64");
    CHECK(r.chassis_type == "laptop");
    CHECK(r.chassis_serial == "CHS-0001");
    CHECK(r.chassis_asset_tag == "AT-0001");
    CHECK(r.chassis_source == "dmi");
    CHECK(r.board_vendor == "Dell Inc.");
    CHECK(r.board_product == "0K3CM7");
    CHECK(r.board_serial == "BRD-0001");
    CHECK(r.board_source == "dmi");
    CHECK(r.machine_id_hash.size() == 64);
    CHECK(r.machine_id_algorithm == "sha256-hmac");
    CHECK(r.machine_id_source == "etc_machine_id");

    SECTION("a v2 blob with only the 22 base fields leaves the appended scalars blank") {
        auto base = clean_fields();
        DeviceCiRecord p = parse_device_ci_blob(
            build_blob_v2(std::vector<std::string>(base.begin(), base.end()), {}));
        CHECK(p.blob_version == 2);
        CHECK(p.arch == "x86_64");
        CHECK(p.chassis_type.empty());
        CHECK(p.machine_id_source.empty());
        CHECK(p.sections.empty());
    }
    SECTION("the version byte alone is an empty v2 record") {
        DeviceCiRecord p = parse_device_ci_blob(std::string(1, '\x02'));
        CHECK(p.blob_version == 2);
        CHECK(p.manufacturer.empty());
        CHECK(p.sections.empty());
        CHECK(p.content_hash.size() == 64);
    }
    SECTION("extra scalar positions are ignored") {
        auto f = v2_scalars();
        f.emplace_back("extra");
        DeviceCiRecord p = parse_device_ci_blob(build_blob_v2(f, {}));
        CHECK(p.machine_id_source == "etc_machine_id");
    }
}

TEST_CASE("v2 scalar-section statuses round-trip independently of any list kind",
          "[device_ci][parse][v2]") {
    auto recs = std::vector<std::vector<std::string>>{
        {"status", "chassis", "unsupported", "macos:planned"},
        {"status", "baseboard", "constrained", "linux:no_dmi"},
        {"status", "machine_id", "ok", ""},
        {"status", "nosuchsection", "ok", "ignored"},
    };
    DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
    REQUIRE(r.sections.size() == 3); // the unregistered section is ignored
    const auto* ch = find_section(r, "chassis");
    REQUIRE(ch != nullptr);
    CHECK(ch->level == "unsupported");
    CHECK(ch->reason == "macos:planned");
    CHECK(ch->rows.empty());
    const auto* bb = find_section(r, "baseboard");
    REQUIRE(bb != nullptr);
    CHECK(bb->level == "constrained");
    CHECK(bb->reason == "linux:no_dmi");
    const auto* mi = find_section(r, "machine_id");
    REQUIRE(mi != nullptr);
    CHECK(mi->level == "ok");
    CHECK(find_section(r, "nosuchsection") == nullptr);
}

TEST_CASE("v2 list rows attach by kind; short rows pad, long rows truncate, unknown kinds drop",
          "[device_ci][parse][v2]") {
    DeviceCiRecord r = parse_device_ci_blob(fixture_blob_v2());
    REQUIRE(r.sections.size() == 10);
    // Registry order, deterministic.
    for (std::size_t i = 0; i < r.sections.size(); ++i)
        CHECK(r.sections[i].kind == yuzu::server::kDeviceCiSections[i].section);
    const auto* cpu = find_section(r, "cpu");
    REQUIRE(cpu != nullptr);
    CHECK(cpu->level == "ok");
    REQUIRE(cpu->rows.size() == 1);
    CHECK(cpu->rows[0][1] == "Intel(R) Core(TM) i7-1185G7");
    CHECK(cpu->rows[0][6] == "1");
    const auto* swap = find_section(r, "swap");
    REQUIRE(swap != nullptr);
    REQUIRE(swap->rows.size() == 1);
    CHECK(swap->rows[0].size() == 3); // no used_mb
    CHECK(swap->rows[0][2] == "proc_swaps");
    const auto* part = find_section(r, "partition"); // keyed 'partition', not 'partitions'
    REQUIRE(part != nullptr);
    CHECK(part->rows.size() == 1);
    CHECK(find_section(r, "dimm")->rows[0][6] == "-");
    CHECK(find_section(r, "chassis")->rows.empty()); // status-only: zero rows

    SECTION("short row padded blank, long row truncated, unknown kind and status-only row ignored") {
        auto recs = std::vector<std::vector<std::string>>{
            {"cpu", "0", "OnlyModel"},
            {"swap", "/s", "1", "src", "extra1", "extra2"},
            {"mystery", "a", "b"},
            {"chassis", "a", "b"}, // rows for a status-only section are ignored
        };
        DeviceCiRecord p = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(p, "cpu");
        REQUIRE(c != nullptr);
        REQUIRE(c->rows.size() == 1);
        CHECK(c->rows[0].size() == 7);
        CHECK(c->rows[0][1] == "OnlyModel");
        CHECK(c->rows[0][2].empty());
        CHECK(c->level.empty()); // rows without a status record: blank level
        const auto* sw = find_section(p, "swap");
        REQUIRE(sw != nullptr);
        CHECK(sw->rows[0].size() == 3);
        CHECK(sw->rows[0][2] == "src");
        CHECK(find_section(p, "mystery") == nullptr);
        CHECK(find_section(p, "chassis") == nullptr);
    }
}

TEST_CASE("v2 rows past the kind cap are dropped and disclosed as constrained",
          "[device_ci][parse][v2]") {
    const int cap = yuzu::server::kDeviceCiSections[3].row_cap; // cpu
    REQUIRE(std::string(yuzu::server::kDeviceCiSections[3].section) == "cpu");
    REQUIRE(cap == 32);
    const auto cpu_row = [](int i) {
        return std::vector<std::string>{"cpu", std::to_string(i), "M", "1", "1", "1", "s", "1"};
    };

    SECTION("incoming ok with empty reason -> constrained / server_cap:32") {
        std::vector<std::vector<std::string>> recs = {{"status", "cpu", "ok", ""}};
        for (int i = 0; i < cap + 5; ++i)
            recs.push_back(cpu_row(i));
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(r, "cpu");
        REQUIRE(c != nullptr);
        CHECK(static_cast<int>(c->rows.size()) == cap);
        CHECK(c->level == "constrained");
        CHECK(c->reason == "server_cap:32");
    }
    SECTION("an incoming reason is kept and the cap appended with ';'") {
        std::vector<std::vector<std::string>> recs = {{"status", "cpu", "ok", "x"}};
        for (int i = 0; i < cap + 1; ++i)
            recs.push_back(cpu_row(i));
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(r, "cpu");
        REQUIRE(c != nullptr);
        CHECK(c->reason == "x;server_cap:32");
    }
    SECTION("exactly at the cap is untouched") {
        std::vector<std::vector<std::string>> recs = {{"status", "cpu", "ok", ""}};
        for (int i = 0; i < cap; ++i)
            recs.push_back(cpu_row(i));
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(r, "cpu");
        REQUIRE(c != nullptr);
        CHECK(c->level == "ok");
        CHECK(c->reason.empty());
    }
}

TEST_CASE("v2 fields get the same scrub + clamp as v1", "[device_ci][parse][v2]") {
    std::vector<std::vector<std::string>> recs = {
        {"status", "cpu", "ok", std::string("bad\xFF") + "reason"},
        {"cpu", "0", std::string("M\xFF") + "odel", "4", "8", "2800", std::string(1100, 'Z'), "1"},
    };
    DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
    const auto* c = find_section(r, "cpu");
    REQUIRE(c != nullptr);
    CHECK(c->reason == "bad\xEF\xBF\xBD"
                       "reason"); // 0xFF -> U+FFFD
    REQUIRE(c->rows.size() == 1);
    CHECK(c->rows[0][1] == "M\xEF\xBF\xBD"
                           "odel");
    CHECK(c->rows[0][5].size() == 1024);

    SECTION("a 1100-byte multibyte field clamps on a codepoint boundary") {
        // 'ü' is 2 bytes: 550 of them = 1100 bytes; the clamp must not split one.
        std::string u;
        for (int i = 0; i < 550; ++i)
            u += "\xC3\xBC";
        std::vector<std::vector<std::string>> r2 = {{"cpu", "0", u, "1", "1", "1", "s", "1"}};
        DeviceCiRecord p = parse_device_ci_blob(build_blob_v2(v2_scalars(), r2));
        const auto* cc = find_section(p, "cpu");
        REQUIRE(cc != nullptr);
        REQUIRE(cc->rows.size() == 1);
        CHECK(cc->rows[0][1].size() == 1024);
        CHECK(cc->rows[0][1].size() % 2 == 0);
    }
}

TEST_CASE("device_ci section registry self-check", "[device_ci][v2]") {
    using yuzu::server::kDeviceCiSectionCount;
    using yuzu::server::kDeviceCiSections;
    CHECK(kDeviceCiSectionCount == 10);
    int status_only = 0;
    for (const auto& d : kDeviceCiSections) {
        if (d.table == nullptr) {
            ++status_only;
            CHECK(d.n_fields == 0);
            CHECK(d.row_cap == 0);
            continue;
        }
        int names = 1;
        for (const char* p = d.columns; *p; ++p)
            if (*p == ',')
                ++names;
        CHECK(names == d.n_fields);
        CHECK(d.row_cap > 0);
    }
    CHECK(status_only == 3);
    CHECK(std::string(kDeviceCiSections[0].section) == "chassis");
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
    auto sec = store.get_device_ci_sections("a");
    REQUIRE(!sec.has_value()); // unexpected(kDegraded), never an empty success
    CHECK(sec.error() == CiReadError::kDegraded);
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

// ── v2 store (PG) ─────────────────────────────────────────────────────────────

TEST_CASE("v2 full ingest stores the scalars, every section and the rows", "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    DeviceCiRecord rec = parse_device_ci_blob(fixture_blob_v2());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);
    REQUIRE(!h.empty());
    REQUIRE(store.apply_device_ci("agent-v2", h, std::optional<DeviceCiRecord>{rec}, 1) ==
            InventoryIngestOutcome::kStored);

    auto got = store.get_device_ci("agent-v2");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((**got).blob_version == 2);
    CHECK((**got).chassis_serial == "CHS-0001");
    CHECK((**got).board_product == "0K3CM7");
    CHECK((**got).machine_id_source == "etc_machine_id");
    CHECK((**got).serial == "ABC123");

    auto secs = store.get_device_ci_sections("agent-v2");
    REQUIRE(secs.has_value());
    REQUIRE(secs->size() == 10);
    for (std::size_t i = 0; i < secs->size(); ++i)
        CHECK((*secs)[i].kind == yuzu::server::kDeviceCiSections[i].section);
    const auto* ch = find_section(*secs, "chassis");
    REQUIRE(ch != nullptr);
    CHECK(ch->level == "ok");
    CHECK(ch->rows.empty());
    const auto* dimm = find_section(*secs, "dimm");
    REQUIRE(dimm != nullptr);
    REQUIRE(dimm->rows.size() == 1);
    CHECK(dimm->rows[0][0] == "DIMM0");
    CHECK(dimm->rows[0][6] == "-");
    const auto* vol = find_section(*secs, "volume");
    REQUIRE(vol != nullptr);
    CHECK(vol->rows[0][1] == "C:\\");

    SECTION("hash-only with the v2 hash is touched; a stale hash and a cold agent need_full") {
        CHECK(store.apply_device_ci("agent-v2", h, std::nullopt, 2) ==
              InventoryIngestOutcome::kTouched);
        CHECK(store.apply_device_ci("agent-v2", "deadbeef", std::nullopt, 3) ==
              InventoryIngestOutcome::kNeedFull);
        CHECK(store.apply_device_ci("agent-cold", h, std::nullopt, 4) ==
              InventoryIngestOutcome::kNeedFull);
    }
    SECTION("a server-capped section stays disclosed across a hash-only ack") {
        std::vector<std::vector<std::string>> recs = {{"status", "cpu", "ok", ""}};
        for (int i = 0; i < 40; ++i)
            recs.push_back({"cpu", std::to_string(i), "M", "1", "1", "1", "s", "1"});
        DeviceCiRecord capped = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const std::string ch2 = DeviceInventoryStore::canonical_hash(capped);
        REQUIRE(store.apply_device_ci("agent-cap", ch2, std::optional<DeviceCiRecord>{capped}, 1) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_device_ci("agent-cap", ch2, std::nullopt, 2) ==
              InventoryIngestOutcome::kTouched);
        auto cs = store.get_device_ci_sections("agent-cap");
        REQUIRE(cs.has_value());
        const auto* cpu = find_section(*cs, "cpu");
        REQUIRE(cpu != nullptr);
        CHECK(cpu->rows.size() == 32);
        CHECK(cpu->level == "constrained");
        CHECK(cpu->reason == "server_cap:32");
    }
    SECTION("an unknown agent has no sections (empty, not degraded)") {
        auto none = store.get_device_ci_sections("nobody");
        REQUIRE(none.has_value());
        CHECK(none->empty());
    }
}

TEST_CASE("v2 full replace swaps the whole child set; v1 <-> v2 transitions", "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const auto put = [&](const DeviceCiRecord& r) {
        return store.apply_device_ci("agent-r", DeviceInventoryStore::canonical_hash(r),
                                     std::optional<DeviceCiRecord>{r}, 1);
    };
    const auto cpu_rows = [&]() -> long long {
        return count_rows(pool, count_sql("device_inventory_store.device_ci_cpu WHERE agent_id = 'agent-r'"));
    };

    REQUIRE(put(make_v2_record("A", 3, true)) == InventoryIngestOutcome::kStored);
    CHECK(cpu_rows() == 3);
    auto first = store.get_device_ci("agent-r");
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());

    SECTION("a smaller v2 set leaves no stale rows or sections") {
        REQUIRE(put(make_v2_record("B", 1, false)) == InventoryIngestOutcome::kStored);
        CHECK(cpu_rows() == 1);
        auto secs = store.get_device_ci_sections("agent-r");
        REQUIRE(secs.has_value());
        CHECK(secs->size() == 1);
        CHECK(find_section(*secs, "dimm") == nullptr);
        const auto* cpu = find_section(*secs, "cpu");
        REQUIRE(cpu != nullptr);
        CHECK(cpu->reason == "B");
        auto again = store.get_device_ci("agent-r");
        REQUIRE(again.has_value());
        REQUIRE(again->has_value());
        CHECK((**again).first_seen == (**first).first_seen); // preserved
    }
    SECTION("a v1 full after v2 replaces the children with the empty set and blanks the scalars") {
        DeviceCiRecord v1 = parse_device_ci_blob(sample_blob());
        REQUIRE(put(v1) == InventoryIngestOutcome::kStored);
        auto secs = store.get_device_ci_sections("agent-r");
        REQUIRE(secs.has_value());
        CHECK(secs->empty());
        auto got = store.get_device_ci("agent-r");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((**got).blob_version == 1);
        CHECK((**got).chassis_serial.empty());
        CHECK((**got).first_seen == (**first).first_seen);

        SECTION("and v1 -> v2 again restores the children") {
            REQUIRE(put(make_v2_record("C", 2, true)) == InventoryIngestOutcome::kStored);
            auto s2 = store.get_device_ci_sections("agent-r");
            REQUIRE(s2.has_value());
            CHECK(s2->size() == 2);
            CHECK(cpu_rows() == 2);
        }
    }
}

TEST_CASE("v2 record without a pinned hash is refused and nothing is stored",
          "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    DeviceCiRecord r = make_v2_record("X", 1, false);
    r.content_hash.clear(); // the sha256-failure shape: v2 + empty hash
    CHECK(store.apply_device_ci("agent-nohash", "whatever", std::optional<DeviceCiRecord>{r}, 1) ==
          InventoryIngestOutcome::kError);
    auto got = store.get_device_ci("agent-nohash");
    REQUIRE(got.has_value());
    CHECK(!got->has_value());
}

TEST_CASE("v2 full replace rolls back whole after a child-insert failure", "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const DeviceCiRecord a = make_v2_record("A", 3, false);
    const DeviceCiRecord b = make_v2_record("B", 1, true);
    const std::string ha = DeviceInventoryStore::canonical_hash(a);
    const std::string hb = DeviceInventoryStore::canonical_hash(b);
    REQUIRE(store.apply_device_ci("agent-rb", ha, std::optional<DeviceCiRecord>{a}, 1) ==
            InventoryIngestOutcome::kStored);

    {
        // Fault injection on this per-test clone: a child table that no longer exists makes
        // the second replace fail partway through the transaction.
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = yuzu::server::pg::exec_params(
            lease.get(), "DROP TABLE device_inventory_store.device_ci_dimm",
            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    CHECK(store.apply_device_ci("agent-rb", hb, std::optional<DeviceCiRecord>{b}, 2) ==
          InventoryIngestOutcome::kError);

    // The previous set is intact: HA is still the stored hash, 3 cpu rows remain.
    CHECK(store.apply_device_ci("agent-rb", ha, std::nullopt, 3) ==
          InventoryIngestOutcome::kTouched);
    CHECK(store.apply_device_ci("agent-rb", hb, std::nullopt, 3) ==
          InventoryIngestOutcome::kNeedFull);
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_cpu WHERE agent_id = 'agent-rb'")) ==
          3);
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_section WHERE agent_id = 'agent-rb'")) ==
          1);
}

TEST_CASE("competing v2 replacements never expose a mixed generation", "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const DeviceCiRecord set_a = make_v2_record("A", 3, false);
    const DeviceCiRecord set_b = make_v2_record("B", 1, false);
    REQUIRE(store.apply_device_ci("agent-cc", "x", std::optional<DeviceCiRecord>{set_a}, 1) ==
            InventoryIngestOutcome::kStored);

    constexpr int kIterations = 50;
    std::atomic<int> writer_failures{0};
    std::atomic<int> torn_reads{0};
    std::atomic<int> degraded_reads{0};
    std::atomic<int> writers_done{0};
    std::atomic<long long> reads{0};

    const auto writer = [&](const DeviceCiRecord& mine, const DeviceCiRecord& other) {
        for (int i = 0; i < kIterations; ++i) {
            const DeviceCiRecord& r = (i % 2 == 0) ? mine : other;
            if (store.apply_device_ci("agent-cc", "x", std::optional<DeviceCiRecord>{r}, 1) !=
                InventoryIngestOutcome::kStored)
                ++writer_failures;
        }
        ++writers_done;
    };
    std::thread w1(writer, std::cref(set_a), std::cref(set_b));
    std::thread w2(writer, std::cref(set_b), std::cref(set_a));
    // Tripwire for a mixed-generation read (separate READ COMMITTED SELECTs could pair
    // generation X's status with generation Y's rows); not a proof of snapshot isolation.
    std::thread reader([&] {
        while (writers_done.load() < 2) {
            auto s = store.get_device_ci_sections("agent-cc");
            if (!s.has_value()) {
                ++degraded_reads;
                continue;
            }
            const auto* cpu = find_section(*s, "cpu");
            if (cpu == nullptr)
                continue;
            ++reads;
            const bool a_ok = cpu->reason == "A" && cpu->rows.size() == 3;
            const bool b_ok = cpu->reason == "B" && cpu->rows.size() == 1;
            if (!a_ok && !b_ok)
                ++torn_reads;
        }
    });
    w1.join();
    w2.join();
    reader.join();

    CHECK(writer_failures.load() == 0);
    CHECK(degraded_reads.load() == 0);
    CHECK(torn_reads.load() == 0);
    CHECK(reads.load() > 0);

    // Final state is one consistent pair.
    auto fin = store.get_device_ci_sections("agent-cc");
    REQUIRE(fin.has_value());
    const auto* cpu = find_section(*fin, "cpu");
    REQUIRE(cpu != nullptr);
    CHECK(((cpu->reason == "A" && cpu->rows.size() == 3) ||
           (cpu->reason == "B" && cpu->rows.size() == 1)));
    auto parent = store.get_device_ci("agent-cc");
    REQUIRE(parent.has_value());
    REQUIRE(parent->has_value());
    CHECK((**parent).chassis_serial == "CHS-" + cpu->reason); // parent matches the children
}

TEST_CASE("populated v1 device_ci upgrades to v2 in place", "[pg][device_ci][migration][v2]") {
    // A private database (not the pre-migrated template): the test rewrites schema_meta and
    // hand-seeds the v1 DDL with a populated row, then lets the constructor run migration 2.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        const auto exec = [&](const char* sql) {
            auto res = yuzu::server::pg::exec_params(lease.get(), sql, std::vector<std::string>{});
            REQUIRE(res.status() == PGRES_COMMAND_OK);
        };
        exec("CREATE TABLE IF NOT EXISTS public.schema_meta ("
             "store TEXT PRIMARY KEY, version INTEGER NOT NULL, upgraded_at BIGINT NOT NULL)");
        exec("CREATE SCHEMA device_inventory_store");
        // The exact v1 shape (migration 1).
        exec("CREATE TABLE device_inventory_store.device_ci ("
             "agent_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL DEFAULT '', "
             "manufacturer TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', "
             "serial TEXT NOT NULL DEFAULT '', system_uuid TEXT NOT NULL DEFAULT '', "
             "hostname TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '', "
             "ou TEXT NOT NULL DEFAULT '', bios_vendor TEXT NOT NULL DEFAULT '', "
             "bios_version TEXT NOT NULL DEFAULT '', bios_date TEXT NOT NULL DEFAULT '', "
             "cpu_model TEXT NOT NULL DEFAULT '', cpu_cores BIGINT NOT NULL DEFAULT 0, "
             "cpu_threads BIGINT NOT NULL DEFAULT 0, ram_bytes BIGINT NOT NULL DEFAULT 0, "
             "disks_summary TEXT NOT NULL DEFAULT '', primary_mac TEXT NOT NULL DEFAULT '', "
             "macs_summary TEXT NOT NULL DEFAULT '', nic_count BIGINT NOT NULL DEFAULT 0, "
             "os_name TEXT NOT NULL DEFAULT '', os_version TEXT NOT NULL DEFAULT '', "
             "os_build TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '', "
             "first_seen BIGINT NOT NULL, last_seen BIGINT NOT NULL)");
        exec("CREATE INDEX device_ci_hostname_idx ON device_inventory_store.device_ci (hostname)");
        exec("INSERT INTO device_inventory_store.device_ci (agent_id, content_hash, manufacturer, "
             "model, hostname, cpu_cores, first_seen, last_seen) "
             "VALUES ('agent-old', 'oldhash', 'Dell Inc.', 'Latitude 7420', 'WS-OLD', 4, 10, 20)");
        exec("INSERT INTO public.schema_meta (store, version, upgraded_at) "
             "VALUES ('device_inventory_store', 1, 0)");
    }

    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto got = store.get_device_ci("agent-old");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((**got).manufacturer == "Dell Inc.");
    CHECK((**got).hostname == "WS-OLD");
    CHECK((**got).cpu_cores == "4");
    CHECK((**got).first_seen == 10);
    CHECK((**got).blob_version == 1);
    CHECK((**got).chassis_serial.empty());
    CHECK((**got).machine_id_hash.empty());

    auto secs = store.get_device_ci_sections("agent-old");
    REQUIRE(secs.has_value());
    CHECK(secs->empty());

    // The old agent's v1 hash still compares equal after the upgrade (no need_full storm).
    CHECK(store.apply_device_ci("agent-old", "oldhash", std::nullopt, 1) ==
          InventoryIngestOutcome::kTouched);
}

TEST_CASE("ingest seam: a full v2 report stores, the next hash-only report does not nack",
          "[pg][device_ci][ingest][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::string blob = fixture_blob_v2();
    // The agent claims the sha256 of its blob; the server derives its own and agrees.
    const std::string h = DeviceInventoryStore::canonical_hash(parse_device_ci_blob(blob));

    agentpb::InventoryReport full;
    (*full.mutable_content_hashes())["device_ci"] = h;
    (*full.mutable_plugin_data())["device_ci"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_device_ci_report(store, "agent-i2", full, ack, nullptr);
    CHECK(ack.need_full_size() == 0);
    auto secs = store.get_device_ci_sections("agent-i2");
    REQUIRE(secs.has_value());
    CHECK(secs->size() == 10);

    agentpb::InventoryReport hashonly;
    (*hashonly.mutable_content_hashes())["device_ci"] = h;
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_device_ci_report(store, "agent-i2", hashonly, ack2, nullptr);
    CHECK(ack2.need_full_size() == 0);

    SECTION("an oversized v2 blob is dropped and nacked") {
        std::string big(1, '\x02');
        big += std::string(70u * 1024, 'x');
        agentpb::InventoryReport rpt;
        (*rpt.mutable_content_hashes())["device_ci"] = "somehash";
        (*rpt.mutable_plugin_data())["device_ci"] = big;
        agentpb::InventoryAck nack;
        yuzu::server::ingest_device_ci_report(store, "agent-big2", rpt, nack, nullptr);
        REQUIRE(nack.need_full_size() == 1);
        auto r = store.get_device_ci("agent-big2");
        REQUIRE(r.has_value());
        CHECK(!r->has_value());
    }
}

TEST_CASE("mixed version: an old 22-field blob and a v2 blob for different agents coexist",
          "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::string old_blob = sample_blob();
    agentpb::InventoryReport old_full;
    (*old_full.mutable_content_hashes())["device_ci"] = kCrossPinHash; // the v1 agent's own hash
    (*old_full.mutable_plugin_data())["device_ci"] = old_blob;
    agentpb::InventoryAck a1;
    yuzu::server::ingest_device_ci_report(store, "agent-old", old_full, a1, nullptr);
    CHECK(a1.need_full_size() == 0);

    agentpb::InventoryReport old_hash;
    (*old_hash.mutable_content_hashes())["device_ci"] = kCrossPinHash;
    agentpb::InventoryAck a2;
    yuzu::server::ingest_device_ci_report(store, "agent-old", old_hash, a2, nullptr);
    CHECK(a2.need_full_size() == 0); // v1 hash matched: no need_full loop

    agentpb::InventoryReport new_full;
    const std::string nb = fixture_blob_v2();
    (*new_full.mutable_content_hashes())["device_ci"] =
        DeviceInventoryStore::canonical_hash(parse_device_ci_blob(nb));
    (*new_full.mutable_plugin_data())["device_ci"] = nb;
    agentpb::InventoryAck a3;
    yuzu::server::ingest_device_ci_report(store, "agent-new", new_full, a3, nullptr);
    CHECK(a3.need_full_size() == 0);

    auto old_secs = store.get_device_ci_sections("agent-old");
    REQUIRE(old_secs.has_value());
    CHECK(old_secs->empty());
    auto new_secs = store.get_device_ci_sections("agent-new");
    REQUIRE(new_secs.has_value());
    CHECK(new_secs->size() == 10);
}
