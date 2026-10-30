// DeviceInventoryStore tests (ADR-0016): the born-on-Postgres device-CI
// projection — canonical-hash cross-pin (clean + dirty) with the agent, blob parse
// round-trip, hash-skip ingest (full/touched/need_full), single-row replace,
// roster read, delete, server-receipt-time stamping (#1685), broken-pool degrade,
// oversized-blob nack, and the shared ingest seam end-to-end. v2 blob: version-byte
// parse, scalar-section statuses, list rows + caps + truncation disclosure, the machine-id
// shape check, the per-version hash, the child-table replace transaction, the REPEATABLE READ
// sections read, the populated-v1 migration upgrade, and the mixed-version (old-agent)
// guarantee.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "device_ci_ingestion.hpp"
#include "device_ci_kinds.hpp"
#include "device_inventory_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "sha256_hex.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <latch>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
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
// fields — the forward contract the agent-side device_ci_canonical_blob_v2 must reproduce.
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

// One statement on a fresh lease: fault injection / hand-seeding on a per-test clone.
void exec_stmt(PgPool& pool, const std::string& sql) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}

// The server blob ceiling (ADR-0016 update "device_ci blob v2"): 96 KiB. An INDEPENDENT literal,
// deliberately not read from device_ci_kinds.hpp (the kCrossPinHash pattern): the agent's
// equal constant is pinned to the same 98304 in tests/unit/test_device_ci_sync.cpp, so a
// one-sided change to either ceiling fails one of the two tests.
constexpr std::size_t kBlobCap = 98304;

// The registry, restated as an independent literal table: per list kind the row cap, the wire
// width (columns per row) and the declared row budget (p99.9 row width in wire bytes). Also
// never read from the registry: if a cap, a width or a budget drifts, this table disagrees.
struct KindExpect {
    const char* kind;
    int cap;
    int width;
    int budget;
};
constexpr KindExpect kKindExpect[] = {{"cpu", 32, 7, 96},       {"dimm", 64, 7, 96},
                                      {"disk", 128, 5, 64},     {"swap", 16, 3, 56},
                                      {"volume", 128, 6, 144},  {"partition", 192, 6, 120},
                                      {"topology", 96, 5, 144}};
// The declared scalar record + status records budget, and the registry-derived total:
// sum(cap x budget) = 73,600, plus 3,072 = 76,672 (78.0% of the ceiling; the build holds <= 80%).
constexpr std::size_t kScalarStatusBudget = 3072;
constexpr std::size_t kRegistryTotal = 76672;

// Comma-separated registry column list -> names.
std::vector<std::string> column_names(const char* columns) {
    std::vector<std::string> out(1);
    for (const char* p = columns; *p; ++p) {
        if (*p == ',')
            out.emplace_back();
        else
            out.back().push_back(*p);
    }
    return out;
}

// Every scalar, status and list column carries a value unique to (generation, field), so a
// blanked, swapped or mis-ordered column cannot round-trip by accident. Two rows per list
// kind; the swap section's level is cleared in generation A (a blank level must read back
// blank). Built by hand, bypassing the parser, so the store is what is under test.
DeviceCiRecord distinct_v2_record(const std::string& g) {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    r.blob_version = 2;
    r.content_hash = "hash-" + g;
    r.model = "model-" + g; // a v1 column changes too (the ON CONFLICT update path)
    r.cpu_cores = g == "A" ? "4" : "6";
    r.chassis_type = "chassis-type-" + g;
    r.chassis_serial = "chassis-serial-" + g;
    r.chassis_asset_tag = "chassis-asset-" + g;
    r.chassis_source = "chassis-source-" + g;
    r.board_vendor = "board-vendor-" + g;
    r.board_product = "board-product-" + g;
    r.board_serial = "board-serial-" + g;
    r.board_source = "board-source-" + g;
    r.machine_id_hash = "machine-id-hash-" + g;
    r.machine_id_algorithm = "machine-id-algo-" + g;
    r.machine_id_source = "machine-id-source-" + g;
    for (const auto& d : yuzu::server::kDeviceCiSections) {
        DeviceCiSection s;
        s.kind = d.section;
        s.level = "level-" + g + "-" + d.section;
        s.reason = "reason-" + g + "-" + d.section;
        if (d.table != nullptr) {
            const auto cols = column_names(d.columns);
            for (int row = 0; row < 2; ++row) {
                std::vector<std::string> cells;
                for (const auto& col : cols)
                    cells.push_back(g + "-" + d.section + "-r" + std::to_string(row) + "-" + col);
                s.rows.push_back(std::move(cells));
            }
        }
        if (g == "A" && s.kind == "swap")
            s.level.clear();
        r.sections.push_back(std::move(s));
    }
    return r;
}

// Every persisted scalar of a record by name (the 22 frozen v1 fields, blob_version and the
// 11 appended ones).
std::vector<std::pair<const char*, std::string>> scalar_fields(const DeviceCiRecord& r) {
    return {{"manufacturer", r.manufacturer},
            {"model", r.model},
            {"serial", r.serial},
            {"system_uuid", r.system_uuid},
            {"hostname", r.hostname},
            {"domain", r.domain},
            {"ou", r.ou},
            {"bios_vendor", r.bios_vendor},
            {"bios_version", r.bios_version},
            {"bios_date", r.bios_date},
            {"cpu_model", r.cpu_model},
            {"cpu_cores", r.cpu_cores},
            {"cpu_threads", r.cpu_threads},
            {"ram_bytes", r.ram_bytes},
            {"disks_summary", r.disks_summary},
            {"primary_mac", r.primary_mac},
            {"macs_summary", r.macs_summary},
            {"nic_count", r.nic_count},
            {"os_name", r.os_name},
            {"os_version", r.os_version},
            {"os_build", r.os_build},
            {"arch", r.arch},
            {"blob_version", std::to_string(r.blob_version)},
            {"chassis_type", r.chassis_type},
            {"chassis_serial", r.chassis_serial},
            {"chassis_asset_tag", r.chassis_asset_tag},
            {"chassis_source", r.chassis_source},
            {"board_vendor", r.board_vendor},
            {"board_product", r.board_product},
            {"board_serial", r.board_serial},
            {"board_source", r.board_source},
            {"machine_id_hash", r.machine_id_hash},
            {"machine_id_algorithm", r.machine_id_algorithm},
            {"machine_id_source", r.machine_id_source}};
}

void check_scalars_equal(const DeviceCiRecord& got, const DeviceCiRecord& want) {
    const auto g = scalar_fields(got);
    const auto w = scalar_fields(want);
    REQUIRE(g.size() == w.size());
    for (std::size_t i = 0; i < w.size(); ++i) {
        INFO("scalar " << w[i].first);
        CHECK(g[i].second == w[i].second);
    }
}

// Full equality, section by section, in order: kind, level, reason and every row cell.
void check_sections_equal(const std::vector<DeviceCiSection>& got,
                          const std::vector<DeviceCiSection>& want) {
    REQUIRE(got.size() == want.size());
    for (std::size_t i = 0; i < want.size(); ++i) {
        INFO("section " << want[i].kind);
        CHECK(got[i].kind == want[i].kind);
        CHECK(got[i].level == want[i].level);
        CHECK(got[i].reason == want[i].reason);
        CHECK(got[i].rows == want[i].rows);
    }
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
        DeviceCiRecord p = parse_device_ci_blob(std::string(kBlobCap + 1, 'x'));
        CHECK(p.manufacturer.empty());
    }
    SECTION("a blob exactly at the 96 KiB ceiling still parses") {
        DeviceCiRecord p = parse_device_ci_blob(std::string(kBlobCap, 'x'));
        CHECK(p.manufacturer.size() == 1024); // one clamped field, not rejected
    }
}

TEST_CASE("v1 blobs parse unchanged: version 1 with no sections; v1 pins hold (old agent / new server)",
          "[device_ci][parse][v2]") {
    // Old agent / new server: a v1 agent's hash must stay byte-identical so it never loops
    // on need_full.
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

TEST_CASE("v2 list rows attach by kind; short rows pad; long rows truncate; unknown kinds drop",
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

TEST_CASE("v2 row caps hold for every list kind (independent literal table)",
          "[device_ci][parse][v2]") {
    // cap+1 rows in -> exactly cap kept, disclosed. The expectations are kKindExpect, NOT the
    // registry: if a registry cap or width drifts, this table disagrees.
    for (const auto& e : kKindExpect) {
        INFO("kind " << e.kind);
        std::vector<std::vector<std::string>> recs = {{"status", e.kind, "ok", ""}};
        for (int i = 0; i < e.cap + 1; ++i) {
            std::vector<std::string> row{e.kind};
            for (int c = 0; c < e.width; ++c)
                row.push_back("r" + std::to_string(i) + "c" + std::to_string(c));
            recs.push_back(std::move(row));
        }
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* sec = find_section(r, e.kind);
        REQUIRE(sec != nullptr);
        CHECK(static_cast<int>(sec->rows.size()) == e.cap);
        CHECK(sec->level == "constrained");
        CHECK(sec->reason == "server_cap:" + std::to_string(e.cap));
        // The kept rows are the FIRST cap rows, full width, in order.
        CHECK(sec->rows.front().size() == static_cast<std::size_t>(e.width));
        CHECK(sec->rows.front()[0] == "r0c0");
        CHECK(sec->rows.back()[0] == "r" + std::to_string(e.cap - 1) + "c0");
    }
}

TEST_CASE("v2 registry budgets and the blob ceiling agree with the independent literal table",
          "[device_ci][parse][v2]") {
    using yuzu::server::kDeviceCiSections;
    // The server ceiling is the literal 98304 (the agent twin pins the same number).
    CHECK(yuzu::server::kDeviceCiMaxBlobBytes == 98304u);
    CHECK(yuzu::server::kDeviceCiMaxBlobBytes == kBlobCap);
    CHECK(yuzu::server::kDeviceCiScalarStatusBudget == kScalarStatusBudget);

    std::size_t rows_sum = 0;
    for (const auto& e : kKindExpect) {
        INFO("kind " << e.kind);
        const auto i = yuzu::server::device_ci_section_index(e.kind);
        REQUIRE(i.has_value());
        const auto& d = kDeviceCiSections[*i];
        CHECK(d.row_cap == e.cap);
        CHECK(d.n_fields == e.width);
        CHECK(d.row_budget == e.budget);
        rows_sum += static_cast<std::size_t>(e.cap) * static_cast<std::size_t>(e.budget);
    }
    // Every registered list kind is in the table (a new kind must be added to it).
    int list_kinds = 0;
    for (const auto& d : kDeviceCiSections)
        list_kinds += d.table != nullptr ? 1 : 0;
    CHECK(list_kinds == static_cast<int>(std::size(kKindExpect)));

    CHECK(rows_sum == 73600);
    CHECK(rows_sum + kScalarStatusBudget == kRegistryTotal);
    CHECK(yuzu::server::device_ci_registry_budget() == kRegistryTotal);
    // Real headroom: the declared worst plausible blob stays within 80% of the ceiling.
    CHECK(kRegistryTotal * 5 <= kBlobCap * 4);
}

namespace {
// One list record of exactly `budget` wire bytes (kind token, separators and terminator
// included) for a kind with `width` columns; column c is filled with letter 'a'+c so a swapped or
// truncated column cannot round-trip by accident.
std::vector<std::string> row_at_budget(const char* kind, int width, int budget) {
    const int total = budget - static_cast<int>(std::string(kind).size()) - width - 1;
    REQUIRE(total >= width);
    std::vector<std::string> row{kind};
    for (int c = 0; c < width; ++c) {
        const int len = total / width + (c < total % width ? 1 : 0);
        row.emplace_back(static_cast<std::size_t>(len), static_cast<char>('a' + c));
    }
    return row;
}
} // namespace

TEST_CASE("v2 blob at the registry-derived maximum fits the ceiling and parses in full",
          "[device_ci][parse][v2]") {
    // Every list kind at its cap, every row exactly its declared budget wide: the heaviest blob
    // the registry plans for. It is past the old 64 KiB bound, under the 96 KiB ceiling, and
    // nothing is dropped or disclosed. Expectations come from kKindExpect, not the registry.
    std::vector<std::vector<std::string>> recs = {
        {"status", "chassis", "ok", ""}, {"status", "baseboard", "ok", ""},
        {"status", "machine_id", "ok", ""}};
    std::size_t rows_bytes = 0;
    for (const auto& e : kKindExpect) {
        recs.push_back({"status", e.kind, "ok", ""});
        for (int i = 0; i < e.cap; ++i) {
            recs.push_back(row_at_budget(e.kind, e.width, e.budget));
            rows_bytes += static_cast<std::size_t>(e.budget);
        }
    }
    REQUIRE(rows_bytes == 73600);
    const std::string blob = build_blob_v2(v2_scalars(), recs);
    // The scalar record and the ten status records are far under their declared 3 KiB budget.
    REQUIRE(blob.size() > 64u * 1024);
    REQUIRE(blob.size() <= kRegistryTotal + 1); // +1: the version byte
    REQUIRE(blob.size() <= kBlobCap);

    DeviceCiRecord r = parse_device_ci_blob(blob);
    CHECK(r.chassis_serial == "CHS-0001"); // the scalar record survived with them
    for (const auto& e : kKindExpect) {
        INFO("kind " << e.kind);
        const auto* sec = find_section(r, e.kind);
        REQUIRE(sec != nullptr);
        CHECK(static_cast<int>(sec->rows.size()) == e.cap);
        CHECK(sec->level == "ok"); // at the cap exactly: untouched, not disclosed
        CHECK(sec->reason.empty());
        const auto want = row_at_budget(e.kind, e.width, e.budget);
        for (const auto& row : sec->rows) {
            REQUIRE(row.size() == static_cast<std::size_t>(e.width));
            CHECK(row[0] == want[1]);
            CHECK(row.back() == want.back());
        }
    }
}

TEST_CASE("v2 duplicate status records: the last wins; a server disclosure still beats it",
          "[device_ci][parse][v2]") {
    SECTION("two conflicting status records around list rows -> the later one") {
        std::vector<std::vector<std::string>> recs = {
            {"status", "cpu", "ok", ""},
            {"cpu", "0", "M", "1", "1", "1", "s", "1"},
            {"status", "cpu", "constrained", "linux:partial"},
        };
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(r, "cpu");
        REQUIRE(c != nullptr);
        CHECK(c->level == "constrained");
        CHECK(c->reason == "linux:partial");
        CHECK(c->rows.size() == 1);
    }
    SECTION("a trailing incoming ok cannot hide a server cap disclosure") {
        std::vector<std::vector<std::string>> recs;
        for (int i = 0; i < 33; ++i)
            recs.push_back({"cpu", std::to_string(i), "M", "1", "1", "1", "s", "1"});
        recs.push_back({"status", "cpu", "ok", ""}); // arrives AFTER the rows
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        const auto* c = find_section(r, "cpu");
        REQUIRE(c != nullptr);
        CHECK(c->rows.size() == 32);
        CHECK(c->level == "constrained");
        CHECK(c->reason == "server_cap:32");
    }
}

TEST_CASE("v2 machine_id_hash must be hex or '-': anything else is blanked and disclosed",
          "[device_ci][parse][v2]") {
    const auto parse_with_hash = [](const std::string& hash,
                                    std::vector<std::vector<std::string>> recs = {}) {
        auto f = v2_scalars();
        f[30] = hash; // machine_id_hash
        return parse_device_ci_blob(build_blob_v2(f, recs));
    };
    const std::string hex64(64, 'a');

    SECTION("lower-case hex, '-' (absent) and empty pass untouched and add no section") {
        for (const std::string& ok : {hex64, std::string("-"), std::string()}) {
            DeviceCiRecord r = parse_with_hash(ok);
            CHECK(r.machine_id_hash == ok);
            CHECK(find_section(r, "machine_id") == nullptr);
        }
    }
    SECTION("a GUID-shaped raw platform id is blanked and the section is constrained") {
        DeviceCiRecord r = parse_with_hash("4C4C4544-0042-1234-5678-AABBCCDDEEFF");
        CHECK(r.machine_id_hash.empty());
        const auto* m = find_section(r, "machine_id");
        REQUIRE(m != nullptr);
        CHECK(m->level == "constrained");
        CHECK(m->reason == "server:machine_id_shape");
        CHECK(m->rows.empty());
    }
    SECTION("upper-case hex and a non-hex tail are blanked too") {
        CHECK(parse_with_hash("ABCDEF0123").machine_id_hash.empty());
        CHECK(parse_with_hash(hex64.substr(0, 63) + "g").machine_id_hash.empty());
    }
    SECTION("the disclosure survives, and composes with, the agent's own machine_id status") {
        DeviceCiRecord ok = parse_with_hash("{GUID}", {{"status", "machine_id", "ok", ""}});
        const auto* a = find_section(ok, "machine_id");
        REQUIRE(a != nullptr);
        CHECK(a->level == "constrained");
        CHECK(a->reason == "server:machine_id_shape");
        DeviceCiRecord why = parse_with_hash("{GUID}", {{"status", "machine_id", "ok", "x"}});
        const auto* b = find_section(why, "machine_id");
        REQUIRE(b != nullptr);
        CHECK(b->reason == "x;server:machine_id_shape");
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
    SECTION("1023 ASCII + a 2-byte codepoint straddling the cap drops the whole codepoint") {
        // The 1024-byte cut lands inside 'ü' (0xC3 0xBC at offsets 1023/1024); a byte
        // truncation would keep the lone lead byte (size 1024), a boundary-safe clamp 1023.
        const std::string field = std::string(1023, 'a') + "\xC3\xBC";
        std::vector<std::vector<std::string>> r2 = {{"cpu", "0", field, "1", "1", "1", "s", "1"}};
        DeviceCiRecord p = parse_device_ci_blob(build_blob_v2(v2_scalars(), r2));
        const auto* cc = find_section(p, "cpu");
        REQUIRE(cc != nullptr);
        REQUIRE(cc->rows.size() == 1);
        CHECK(cc->rows[0][1] == std::string(1023, 'a'));
    }
    SECTION("an embedded NUL is stripped, a tab is kept") {
        const std::string field("a\0b\tc", 5);
        std::vector<std::vector<std::string>> r2 = {{"cpu", "0", field, "1", "1", "1", "s", "1"}};
        DeviceCiRecord p = parse_device_ci_blob(build_blob_v2(v2_scalars(), r2));
        const auto* cc = find_section(p, "cpu");
        REQUIRE(cc != nullptr);
        REQUIRE(cc->rows.size() == 1);
        CHECK(cc->rows[0][1] == "ab\tc");
    }
}

TEST_CASE("v2 parse names what it ignored in ONE debug line per blob, bounded and neutralised",
          "[device_ci][parse][v2]") {
    const auto count_of = [](const std::string& hay, const std::string& needle) {
        std::size_t n = 0;
        for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
            ++n;
        return n;
    };
    const std::string kLine = "ignored unregistered tokens";

    SECTION("unknown kind, unknown status section, a row for a status-only section, extra columns") {
        std::vector<std::vector<std::string>> recs = {
            {"status", "nic", "ok", ""},                                // unregistered section
            {"gpu", "0", "x"},                                          // unknown kind
            {"gpu", "1", "y"},                                          // same token again
            {"chassis", "stray"},                                       // row for a status-only kind
            {"cpu", "0", "M", "1", "1", "1", "s", "1", "extra", "more"}, // 9 columns, cpu has 7
        };
        yuzu::test::LogCapture cap(spdlog::level::debug);
        DeviceCiRecord r = parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        cap.stop();
        const std::string logs = cap.text();
        CHECK(count_of(logs, kLine) == 1); // one line for the whole blob
        CHECK(logs.find("'nic'") != std::string::npos);
        CHECK(logs.find("'gpu'") != std::string::npos);
        CHECK(count_of(logs, "'gpu'") == 1); // a repeated token is named once
        CHECK(logs.find("'chassis'") != std::string::npos);
        CHECK(logs.find("extra columns on kinds [cpu]") != std::string::npos);
        const auto* c = find_section(r, "cpu"); // the row itself still stores, columns clipped
        REQUIRE(c != nullptr);
        CHECK(c->rows.size() == 1);
        CHECK(c->rows[0].size() == 7);
    }
    SECTION("a conforming blob logs nothing") {
        yuzu::test::LogCapture cap(spdlog::level::debug);
        parse_device_ci_blob(fixture_blob_v2());
        cap.stop();
        CHECK(count_of(cap.text(), kLine) == 0);
    }
    SECTION("a hostile blob of many unknown kinds is capped and cannot split the line") {
        std::vector<std::vector<std::string>> recs = {{"bad\nkind\r\ttoken", "v"}};
        for (int i = 0; i < 50; ++i)
            recs.push_back({"k" + std::to_string(i), "v"});
        yuzu::test::LogCapture cap(spdlog::level::debug);
        parse_device_ci_blob(build_blob_v2(v2_scalars(), recs));
        cap.stop();
        const std::string logs = cap.text();
        REQUIRE(count_of(logs, kLine) == 1);
        CHECK(logs.find("'bad_kind__token'") != std::string::npos); // control bytes neutralised
        CHECK(logs.find("'k6'") != std::string::npos);
        CHECK(logs.find("'k7'") == std::string::npos); // at most 8 distinct tokens in the line
        // The one captured record is one physical line: only the logger's own terminator.
        CHECK(count_of(logs, "\n") == 1);
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

    SECTION("oversized blob is dropped + nacked, logged once, counted, nothing stored") {
        // The backstop for a non-conforming sender (a conforming one trims to fit): the ONE
        // existing warn line and the `dropped` outcome are the operator's signal, pinned here.
        yuzu::MetricsRegistry metrics;
        yuzu::test::LogCapture cap(spdlog::level::warn);
        agentpb::InventoryReport rpt;
        (*rpt.mutable_content_hashes())["device_ci"] = "somehash";
        (*rpt.mutable_plugin_data())["device_ci"] = std::string(kBlobCap + 1, 'x'); // > 96 KiB
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-big", rpt, ack, &metrics);
        cap.stop();
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
        auto r = store.get_device_ci("agent-big");
        REQUIRE(r.has_value());
        CHECK(!r->has_value()); // nothing stored
        CHECK(metrics
                  .counter("yuzu_inventory_ingest_total",
                           {{"source", "device_ci"}, {"outcome", "dropped"}})
                  .value() == 1.0);
        const std::string logs = cap.text();
        const std::string needle = "oversized blob from agent=agent-big";
        const auto first = logs.find(needle);
        REQUIRE(first != std::string::npos);
        CHECK(logs.find(needle, first + 1) == std::string::npos); // once per blob
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

TEST_CASE("v2 full ingest stores the scalars and the rows of every section", "[pg][device_ci][v2]") {
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
    SECTION("an empty agent id on an open store is a precondition miss: empty, not degraded") {
        auto blank = store.get_device_ci_sections("");
        REQUIRE(blank.has_value());
        CHECK(blank->empty());
    }
}

TEST_CASE("v2 round trip: every scalar and every list column reads back exactly; then updates",
          "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const DeviceCiRecord a = distinct_v2_record("A");
    const DeviceCiRecord b = distinct_v2_record("B");
    // The fixtures really exercise what this case claims to.
    REQUIRE(a.sections.size() == 10);
    REQUIRE(find_section(a, "swap")->level.empty());   // a cleared level is part of generation A
    REQUIRE(!find_section(b, "swap")->level.empty());
    REQUIRE(find_section(a, "dimm")->rows.size() == 2);

    const auto put = [&](const DeviceCiRecord& r) {
        return store.apply_device_ci("agent-rt", DeviceInventoryStore::canonical_hash(r),
                                     std::optional<DeviceCiRecord>{r}, 1);
    };
    // Exact read-back: parent scalars (get_device_ci) + status/rows (get_device_ci_sections),
    // registry order, every cell; and the stored hash is the record's own.
    const auto verify = [&](const DeviceCiRecord& want) {
        auto got = store.get_device_ci("agent-rt");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((**got).agent_id == "agent-rt");
        check_scalars_equal(**got, want);
        auto secs = store.get_device_ci_sections("agent-rt");
        REQUIRE(secs.has_value());
        check_sections_equal(*secs, want.sections);
        CHECK(store.apply_device_ci("agent-rt", DeviceInventoryStore::canonical_hash(want),
                                    std::nullopt, 2) == InventoryIngestOutcome::kTouched);
    };

    REQUIRE(put(a) == InventoryIngestOutcome::kStored);
    verify(a);
    auto first = store.get_device_ci("agent-rt");
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());

    // Second full payload, every value different: the ON CONFLICT update path replaces the
    // parent scalars and the whole child set; first_seen survives.
    REQUIRE(put(b) == InventoryIngestOutcome::kStored);
    verify(b);
    auto second = store.get_device_ci("agent-rt");
    REQUIRE(second.has_value());
    REQUIRE(second->has_value());
    CHECK((**second).first_seen == (**first).first_seen);
    CHECK((**second).last_seen >= (**first).last_seen);
    // Nothing of generation A lingers in any child table.
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_dimm WHERE agent_id = "
                                     "'agent-rt' AND slot LIKE 'A-%'")) == 0);
}

TEST_CASE("get_device_ci_sections on an open store: broken child read degrades; "
          "a missing or stray status row reconciles",
          "[pg][device_ci][v2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_ci_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const DeviceCiRecord a = make_v2_record("A", 2, false); // one cpu section, two cpu rows
    REQUIRE(store.apply_device_ci("agent-sr", DeviceInventoryStore::canonical_hash(a),
                                  std::optional<DeviceCiRecord>{a}, 1) ==
            InventoryIngestOutcome::kStored);

    SECTION("a failed child SELECT is a degrade, never an empty success") {
        exec_stmt(pool,
                  "ALTER TABLE device_inventory_store.device_ci_cpu RENAME COLUMN idx TO idx_x");
        auto s = store.get_device_ci_sections("agent-sr");
        REQUIRE(!s.has_value());
        CHECK(s.error() == CiReadError::kDegraded);
    }
    SECTION("rows whose status row is gone still surface, with a blank level") {
        exec_stmt(pool, "DELETE FROM device_inventory_store.device_ci_section WHERE kind = 'cpu'");
        auto s = store.get_device_ci_sections("agent-sr");
        REQUIRE(s.has_value());
        REQUIRE(s->size() == 1);
        CHECK((*s)[0].kind == "cpu");
        CHECK((*s)[0].level.empty());
        CHECK((*s)[0].reason.empty());
        CHECK((*s)[0].rows.size() == 2);
    }
    SECTION("a stored status for an unregistered kind is never surfaced") {
        exec_stmt(pool, "INSERT INTO device_inventory_store.device_ci_section "
                        "(agent_id, kind, level, reason) VALUES ('agent-sr', 'bogus', 'ok', 'x')");
        auto s = store.get_device_ci_sections("agent-sr");
        REQUIRE(s.has_value());
        CHECK(s->size() == 1);
        CHECK(find_section(*s, "bogus") == nullptr);
        CHECK(find_section(*s, "cpu") != nullptr);
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
    DeviceCiRecord b = make_v2_record("B", 1, true);
    for (auto& sec : b.sections)
        if (sec.kind == "dimm")
            sec.rows[0][0] = "POISON"; // the one row the injected constraint refuses
    const std::string ha = DeviceInventoryStore::canonical_hash(a);
    const std::string hb = DeviceInventoryStore::canonical_hash(b);
    REQUIRE(store.apply_device_ci("agent-rb", ha, std::optional<DeviceCiRecord>{a}, 1) ==
            InventoryIngestOutcome::kStored);

    // Fault injection on this per-test clone. A CHECK that rejects only the NEW dimm row lets
    // every earlier statement of the replace succeed first: the per-kind DELETE loop, the
    // parent upsert, and the cpu INSERT (registry index 3, before dimm at 4). The failure
    // therefore lands AFTER a successful child INSERT, which is what the rollback must undo.
    exec_stmt(pool, "ALTER TABLE device_inventory_store.device_ci_dimm "
                    "ADD CONSTRAINT yuzu_test_reject CHECK (slot <> 'POISON')");

    CHECK(store.apply_device_ci("agent-rb", hb, std::optional<DeviceCiRecord>{b}, 2) ==
          InventoryIngestOutcome::kError);

    // The previous set is intact: HA is still the stored hash, 3 cpu rows remain.
    CHECK(store.apply_device_ci("agent-rb", ha, std::nullopt, 3) ==
          InventoryIngestOutcome::kTouched);
    CHECK(store.apply_device_ci("agent-rb", hb, std::nullopt, 3) ==
          InventoryIngestOutcome::kNeedFull);
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_cpu WHERE agent_id = 'agent-rb'")) ==
          3);
    // ...and they are generation A's rows, not B's half-applied cpu insert.
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_cpu WHERE agent_id = "
                                     "'agent-rb' AND model = 'Model-A'")) == 3);
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_dimm WHERE agent_id = 'agent-rb'")) ==
          0);
    CHECK(count_rows(pool, count_sql("device_inventory_store.device_ci_section WHERE agent_id = 'agent-rb'")) ==
          1);
    // The old parent scalars survived too (B's upsert was rolled back with the rest).
    auto got = store.get_device_ci("agent-rb");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((**got).chassis_serial == "CHS-A");
    auto secs = store.get_device_ci_sections("agent-rb");
    REQUIRE(secs.has_value());
    REQUIRE(secs->size() == 1);
    CHECK((*secs)[0].reason == "A");
    CHECK((*secs)[0].rows.size() == 3);
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
    constexpr int kMaxReads = 1000; // bounds the reader if the writers are slow
    std::atomic<int> writer_failures{0};
    std::atomic<int> torn_reads{0};
    // Positive controls: a reader that only ever saw one generation proves nothing about
    // torn_reads == 0, so both generations must have been observed while the writers ran.
    std::atomic<int> a_seen{0};
    std::atomic<int> b_seen{0};
    std::atomic<int> degraded_reads{0};
    std::atomic<int> writers_done{0};
    std::atomic<long long> reads{0};
    // Start handshake (a blocking wait, no sleep or poll): the writers do not begin until the
    // reader has completed one successful read, so `reads > 0` cannot depend on how the
    // scheduler orders the three threads.
    std::latch reader_primed{1};

    const auto writer = [&](const DeviceCiRecord& mine, const DeviceCiRecord& other) {
        reader_primed.wait();
        for (int i = 0; i < kIterations; ++i) {
            const DeviceCiRecord& r = (i % 2 == 0) ? mine : other;
            if (store.apply_device_ci("agent-cc", "x", std::optional<DeviceCiRecord>{r}, 1) !=
                InventoryIngestOutcome::kStored)
                ++writer_failures;
        }
        ++writers_done;
    };
    // Tripwire for a mixed-generation read (separate READ COMMITTED SELECTs could pair
    // generation X's status with generation Y's rows); not a proof of snapshot isolation.
    // Started first. A degraded read ends the loop: degraded_reads == 0 is asserted below, so
    // breaking loses nothing and stops a hot spin against a failing store.
    const auto read_loop = [&] {
        bool primed = false;
        for (int n = 0; n < kMaxReads && writers_done.load() < 2; ++n) {
            auto s = store.get_device_ci_sections("agent-cc");
            if (!s.has_value()) {
                ++degraded_reads;
                break;
            }
            const auto* cpu = find_section(*s, "cpu");
            if (cpu == nullptr)
                continue;
            ++reads;
            if (!primed) {
                primed = true;
                reader_primed.count_down();
            }
            const bool a_ok = cpu->reason == "A" && cpu->rows.size() == 3;
            const bool b_ok = cpu->reason == "B" && cpu->rows.size() == 1;
            if (a_ok)
                ++a_seen;
            if (b_ok)
                ++b_seen;
            if (!a_ok && !b_ok)
                ++torn_reads;
        }
        if (!primed)
            reader_primed.count_down(); // never leave the writers blocked on a failed reader
    };
    // The threads are default-constructed so the guard below exists before any of them runs: a
    // throw while starting a later thread (std::system_error) would otherwise destroy a
    // joinable one (std::terminate, taking the whole shard down). The wait is bounded on every
    // path: a writer that never starts leaves writers_done < 2, so the reader stops at
    // kMaxReads, and the reader releases reader_primed if it never primed. No CHECK or REQUIRE
    // sits between the first start and the joins.
    std::thread reader;
    std::thread w1;
    std::thread w2;
    struct JoinOnExit {
        std::thread* ts[3];
        ~JoinOnExit() {
            for (std::thread* t : ts)
                if (t->joinable())
                    t->join();
        }
    } join_all{{&reader, &w1, &w2}};
    reader = std::thread(read_loop);
    w1 = std::thread(writer, std::cref(set_a), std::cref(set_b));
    w2 = std::thread(writer, std::cref(set_b), std::cref(set_a));
    w1.join();
    w2.join();
    reader.join();

    CHECK(writer_failures.load() == 0);
    CHECK(degraded_reads.load() == 0);
    CHECK(torn_reads.load() == 0);
    CHECK(reads.load() > 0);
    CHECK(a_seen.load() > 0);
    CHECK(b_seen.load() > 0);

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

TEST_CASE("ingest seam: a full v2 report stores; the next hash-only report does not nack",
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
        big += std::string(kBlobCap, 'x'); // version byte + cap bytes = cap + 1
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
