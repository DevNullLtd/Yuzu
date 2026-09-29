// Device-CI daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server (tests/unit/server/test_device_inventory_store.cpp — identical constants),
// the dirty-input cross-pin that locks the scrub/clamp copies, the core-identity
// skip guard (UP-1), and the SyncSource idle-when-a-plugin-is-missing contract.

#include <catch2/catch_test_macros.hpp>

#include "sync_canonical.hpp" // yuzu::agent::sha256_hex
#include "sync_source_device_ci.hpp"

#include <chrono>
#include <string>

using yuzu::agent::CiRecord;
using yuzu::agent::core_identity_unavailable;
using yuzu::agent::device_ci_canonical_blob;
using yuzu::agent::make_device_ci_source;
using yuzu::agent::sha256_hex;

namespace {
// THE cross-side pins (ADR-0016 §4): the server computes the SAME hash for the SAME
// record (tests/unit/server/test_device_inventory_store.cpp — identical constants).
// A one-byte drift in either canonicalisation fails one assertion and the hash-skip
// optimisation is broken before it ships.
constexpr const char* kCrossPinHash =
    "467abd73a70803c5c762a26a4c7ffce536dda060d296ad83aed649473388f975";
// Dirty-input pin: locks the UTF-8 scrub + >1024 clamp across the agent's copy and
// the server's shared utf8_sanitize.hpp — the clean pin alone never exercises them
// (gov consensus: security MEDIUM + cpp-expert/architect/quality/consistency SHOULD).
constexpr const char* kDirtyCrossPinHash =
    "d569640762613846756047c953a0bc53b8e01c1e05aea4c4c62b68021434d7bc";

// The fixed cross-pin record. All fields are clean ASCII (no separator/control
// bytes), so the agent clamp is a no-op and the bytes equal the server's raw
// wire-blob → parse round-trip.
CiRecord sample() {
    CiRecord r;
    r.manufacturer = "Dell Inc.";
    r.model = "Latitude 7420";
    r.serial = "ABC123";
    r.system_uuid = "4C4C4544-0042-1234-5678-AABBCCDDEEFF";
    r.hostname = "WS-001";
    r.domain = "corp.example";
    r.ou = "OU=Laptops,DC=corp,DC=example";
    r.bios_vendor = "Dell Inc.";
    r.bios_version = "1.27.0";
    r.bios_date = "2024-03-15";
    r.cpu_model = "Intel(R) Core(TM) i7-1185G7";
    r.cpu_cores = "4";
    r.cpu_threads = "8";
    r.ram_bytes = "17179869184";
    r.disks_summary = "Samsung SSD 980 512 SSD";
    r.primary_mac = "00:11:22:33:44:55";
    r.macs_summary = "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff";
    r.nic_count = "2";
    r.os_name = "Windows 11 Pro";
    r.os_version = "10.0.22631";
    r.os_build = "22631";
    r.arch = "x86_64";
    return r;
}

// The dirty cross-pin record. Real manufacturer/model (so the skip guard never
// fires), with divergence-prone fields: a valid multibyte sequence (must survive),
// an invalid UTF-8 byte (must scrub to U+FFFD), and a >1024-byte field (must clamp
// on a codepoint boundary). NO interior 0x1F/0x1E — the agent strips those before
// hashing, so a real agent never emits one; only the scrub + clamp can diverge.
// The literal field values here MUST be byte-identical to the server twin.
CiRecord dirty() {
    CiRecord r = sample();
    r.manufacturer = "M\xC3\xBCller GmbH"; // valid UTF-8 ü (C3 BC) — preserved
    r.model = "OptiPlex 7090";
    r.serial = "S\xFF"
               "N123";                     // invalid byte 0xFF → U+FFFD
    r.cpu_model = std::string(1100, 'Z');  // > kMaxFieldLen (1024) → truncated
    return r;
}
} // namespace

TEST_CASE("device_ci canonical hash matches the cross-pin", "[sync][device_ci][hash]") {
    CHECK(sha256_hex(device_ci_canonical_blob(sample())) == kCrossPinHash);
}

TEST_CASE("device_ci dirty-input canonical hash matches the cross-pin",
          "[sync][device_ci][hash]") {
    CHECK(sha256_hex(device_ci_canonical_blob(dirty())) == kDirtyCrossPinHash);
}

TEST_CASE("core_identity_unavailable: AND of manufacturer+model unknown", "[sync][device_ci]") {
    CiRecord r = sample();
    CHECK(!core_identity_unavailable(r)); // both real
    r.serial = "unknown";
    r.system_uuid = "unknown";
    CHECK(!core_identity_unavailable(r)); // a serial-less VM (real mfr/model) is NOT skipped
    r.manufacturer = "unknown";
    CHECK(!core_identity_unavailable(r)); // only one of mfr/model unknown → not skipped (AND)
    r.model = "unknown";
    CHECK(core_identity_unavailable(r)); // both unknown → WMI/DMI wholesale down → skip
}

TEST_CASE("build_device_ci_record parses + aggregates plugin outputs", "[sync][device_ci]") {
    using yuzu::agent::build_device_ci_record;
    using yuzu::agent::CiPluginOutputs;
    CiPluginOutputs o;
    o.manufacturer = "manufacturer|Dell Inc.";
    o.model = "model|Latitude 7420";
    o.system = "serial|ABC123\nsystem_uuid|UUID-1";
    o.bios = "bios_vendor|Dell Inc.\nbios_version|1.27.0\nbios_date|2024-03-15";
    o.processors = "cpu|0|Intel i7|4|8|2800\ncpu|1|Intel i7|4|8|2800"; // two sockets → summed
    o.memory = "dimm|DIMM0|8192|DDR4|3200\ndimm|DIMM1|8192|DDR4|3200"; // 16384 MB → bytes
    o.disks = "disk|0|Samsung SSD|512|SSD|NVMe\n"
              "disk|1|unknown|0|unknown|unknown"; // sentinel row skipped
    o.device_name = "device_name|WS-001";
    o.domain = "domain|corp.example";
    o.ou = "ou|OU=Laptops";
    o.os_name = "os_name|Windows 11 Pro";
    o.os_version = "os_version|10.0.22631";
    o.os_build = "os_build|22631";
    o.os_arch = "os_arch|x86_64";
    o.adapters = "adapter|eth0|aa:bb:cc:dd:ee:ff|1000|up\n"
                 "adapter|eth1|00:11:22:33:44:55|1000|up\n"
                 "adapter|eth2|aa:bb:cc:dd:ee:ff|0|down\n"  // duplicate MAC → deduped
                 "adapter|lo|00:00:00:00:00:00|0|up";       // all-zero MAC → dropped

    auto r = build_device_ci_record(o);
    CHECK(r.manufacturer == "Dell Inc.");
    CHECK(r.serial == "ABC123");
    CHECK(r.system_uuid == "UUID-1");
    CHECK(r.cpu_model == "Intel i7");
    CHECK(r.cpu_cores == "8");                                    // 4 + 4
    CHECK(r.cpu_threads == "16");                                 // 8 + 8
    CHECK(r.ram_bytes == std::to_string(16384LL * 1024 * 1024)); // summed DIMMs → bytes
    CHECK(r.disks_summary == "Samsung SSD 512 SSD");             // sentinel skipped
    CHECK(r.nic_count == "2");                                    // dedup + zero-MAC dropped
    CHECK(r.primary_mac == "00:11:22:33:44:55");                 // sorted first
    CHECK(r.macs_summary == "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff");
    CHECK(r.os_name == "Windows 11 Pro");
    CHECK(r.arch == "x86_64");
    CHECK(!core_identity_unavailable(r)); // real manufacturer + model → not skipped

    SECTION("wholesale identity outage → manufacturer+model 'unknown' → skip predicate fires") {
        CiPluginOutputs down;
        down.manufacturer = "manufacturer|unknown";
        down.model = "model|unknown"; // other actions absent → scalar() yields ""
        auto rr = build_device_ci_record(down);
        CHECK(rr.manufacturer == "unknown");
        CHECK(rr.model == "unknown");
        CHECK(core_identity_unavailable(rr));
    }
}

TEST_CASE("device_ci source idles when a required plugin is missing", "[sync][device_ci]") {
    SECTION("all descriptors null → collect returns nullopt (no partial CI record)") {
        auto src = make_device_ci_source(nullptr, nullptr, nullptr, nullptr);
        CHECK(src.name == "device_ci");
        CHECK(src.interval == std::chrono::hours{24});
        CHECK(!src.collect().has_value());
    }
}
