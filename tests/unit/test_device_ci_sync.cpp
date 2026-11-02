// Device-CI daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server (tests/unit/server/test_device_inventory_store.cpp — identical constants),
// the dirty-input cross-pin that locks the scrub/clamp copies, the core-identity
// skip guard (UP-1), the SyncSource idle-when-a-plugin-is-missing contract, and the v2 writer:
// status mapping, failure provenance, row projection, caps, the ceiling trim, and collect()
// through fake plugin descriptors.

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "sync_canonical.hpp" // yuzu::agent::sha256_hex
#include "sync_source_device_ci.hpp"

#include <yuzu/plugin.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

using yuzu::agent::CiActionResult;
using yuzu::agent::CiRecord;
using yuzu::agent::CiSectionInputs;
using yuzu::agent::device_ci_canonical_blob_v2;
using yuzu::agent::kCiV2Sections;
using yuzu::agent::kCiV2TrimOrder;
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

// v2 forward pin (server twin: kCrossPinHashV2 in test_device_inventory_store.cpp). The v2
// agent's canonical bytes ARE the blob: 0x02, a 33-position scalar record (the 22 frozen
// v1 fields + 11 appended chassis/board/machine-id scalars), then a status record per
// registered section and one row per list kind, each 0x1F-joined and 0x1E-terminated. The
// section id is the row-kind token ('partition', never the action name 'partitions').
// Placeholder serials only; the DIMM serial is '-'. The literals here MUST be
// byte-identical to the server twin; this is the layout the agent-side
// device_ci_canonical_blob_v2 must reproduce.
constexpr const char* kCrossPinHashV2 = "e810ec4a9b2db6286a30f7eddc72beb9090ad52f59d5529be769cec2a3acb36d";

std::string rec_bytes(const std::vector<std::string>& f) {
    std::string b;
    for (std::size_t i = 0; i < f.size(); ++i) {
        if (i)
            b += '\x1f';
        b += f[i];
    }
    b += '\x1e';
    return b;
}

std::string v2_blob_by_hand() {
    const CiRecord r = sample();
    std::vector<std::string> scalars = {
        r.manufacturer, r.model,      r.serial,        r.system_uuid, r.hostname,
        r.domain,       r.ou,         r.bios_vendor,   r.bios_version, r.bios_date,
        r.cpu_model,    r.cpu_cores,  r.cpu_threads,   r.ram_bytes,   r.disks_summary,
        r.primary_mac,  r.macs_summary, r.nic_count,   r.os_name,     r.os_version,
        r.os_build,     r.arch,
        // appended positions 22-32
        "laptop", "CHS-0001", "AT-0001", "dmi", "Dell Inc.", "0K3CM7", "BRD-0001", "dmi",
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", "sha256-hmac",
        "etc_machine_id"};
    const std::vector<std::vector<std::string>> recs = {
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
        {"volume", "C:", "C:/", "\\\\?\\Volume{1}", "NTFS", "511705088", "-"},
        {"status", "partition", "ok", ""},
        {"partition", "0", "1", "536870912", "EFI", "-", "-"},
        {"status", "topology", "ok", ""},
        {"topology", "lvm", "vg0", "uuid-0001", "sda2", "-"},
    };
    std::string b(1, '\x02');
    b += rec_bytes(scalars);
    for (const auto& rec : recs)
        b += rec_bytes(rec);
    return b;
}
} // namespace

TEST_CASE("device_ci v2 blob layout hashes to the forward cross-pin", "[sync][device_ci][hash][v2]") {
    // The v1 pins above are untouched; v2 is a NEW pin, hashed over the blob bytes.
    CHECK(sha256_hex(v2_blob_by_hand()) == kCrossPinHashV2);
}

// ── v2 writer fixtures ──────────────────────────────────────────────────────

namespace {
using Rec = std::vector<std::string>;

CiActionResult cap(std::string captured, YuzuResultStatus st = YUZU_RESULT_STATUS_OK,
                   std::string prov = {}) {
    CiActionResult a;
    a.captured = std::move(captured);
    a.status = st;
    a.provenance = std::move(prov);
    return a;
}

// Captures that are exactly the rows v2_blob_by_hand() carries, every action typed OK.
CiSectionInputs all_ok_inputs() {
    CiSectionInputs in;
    in.chassis = cap("chassis|laptop|CHS-0001|AT-0001|dmi");
    in.baseboard = cap("baseboard|Dell Inc.|0K3CM7|BRD-0001|dmi");
    in.machine_id = cap("machine_id|aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                        "|sha256-hmac|etc_machine_id");
    in.processors = cap("cpu|0|Intel(R) Core(TM) i7-1185G7|4|8|2800|U3E1|1");
    in.memory = cap("dimm|DIMM0|8192|DDR4|3200|Samsung|M471A1K43|-");
    in.disks = cap("disk|0|Samsung SSD 980|512|SSD|NVMe");
    in.swap = cap("swap|/swapfile|2048|0|proc_swaps");
    in.volumes = cap("volume|C:|C:/|\\\\?\\Volume{1}|NTFS|511705088|-");
    in.partitions = cap("partition|0|1|536870912|EFI|-|-");
    in.topology = cap("topology|lvm|vg0|uuid-0001|sda2|-");
    in.disk_actions_loaded = true;
    return in;
}

std::vector<Rec> split_records(const std::string& blob) {
    std::vector<Rec> out;
    std::size_t pos = 1; // skip the version byte
    while (pos < blob.size()) {
        std::size_t e = blob.find('\x1e', pos);
        if (e == std::string::npos)
            e = blob.size();
        Rec f;
        std::size_t p = pos;
        for (;;) {
            const std::size_t u = blob.find('\x1f', p);
            if (u == std::string::npos || u >= e) {
                f.push_back(blob.substr(p, e - p));
                break;
            }
            f.push_back(blob.substr(p, u - p));
            p = u + 1;
        }
        out.push_back(std::move(f));
        pos = e + 1;
    }
    return out;
}

struct Parsed {
    Rec scalar;
    std::map<std::string, Rec> status; // section -> {level, reason}
    std::map<std::string, std::vector<Rec>> rows; // kind -> rows (kind token stripped)
};

Parsed parse_blob(const std::string& blob) {
    Parsed p;
    auto recs = split_records(blob);
    REQUIRE(!recs.empty());
    p.scalar = recs[0];
    for (std::size_t i = 1; i < recs.size(); ++i) {
        auto& r = recs[i];
        if (r[0] == "status")
            p.status[r[1]] = Rec{r[2], r[3]};
        else
            p.rows[r[0]].emplace_back(r.begin() + 1, r.end());
    }
    return p;
}

std::string reason_of(const Parsed& p, const std::string& sec) { return p.status.at(sec)[1]; }
std::string level_of(const Parsed& p, const std::string& sec) { return p.status.at(sec)[0]; }
std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}

// `n` plugin rows of `kind` with `cols` columns each: col 0 is a zero-padded index (so the
// lexicographic order is the index order), every other column `width` bytes.
std::string wide_rows(const std::string& kind, int cols, int n, int width, int first = 0) {
    std::string out;
    for (int i = first; i < first + n; ++i) {
        char idx[16];
        std::snprintf(idx, sizeof idx, "%04d", i);
        out += kind + "|" + idx;
        for (int c = 1; c < cols; ++c) {
            // The mount-point column (volume col 1, partition col 4) is a path in real output, and
            // a non-path there is redacted: keep the row's byte width, start it with '/'.
            const bool mount = (kind == "volume" && c == 1) || (kind == "partition" && c == 4);
            if (mount && width > 0)
                out += "|/" + std::string(static_cast<std::size_t>(width - 1),
                                          static_cast<char>('a' + c));
            else
                out += "|" + std::string(static_cast<std::size_t>(width),
                                         static_cast<char>('a' + c));
        }
        out += "\n";
    }
    return out;
}
} // namespace

TEST_CASE("device_ci v2 writer reproduces the forward cross-pin", "[sync][device_ci][hash][v2]") {
    const auto blob = device_ci_canonical_blob_v2(sample(), all_ok_inputs());
    CHECK(blob == v2_blob_by_hand()); // byte-for-byte, readable diff on failure
    CHECK(sha256_hex(blob) == kCrossPinHashV2);
}

TEST_CASE("device_ci v2 scalar record begins with the frozen v1 fields", "[sync][device_ci][v2]") {
    const auto blob = device_ci_canonical_blob_v2(sample(), all_ok_inputs());
    std::string v1 = device_ci_canonical_blob(sample());
    v1.pop_back(); // the 0x1E terminator
    REQUIRE(blob.size() > v1.size() + 2);
    CHECK(blob[0] == '\x02');
    CHECK(blob.compare(1, v1.size(), v1) == 0);
    CHECK(blob[1 + v1.size()] == '\x1f'); // the appended positions follow
    // The v1 pins are untouched and still green.
    CHECK(sha256_hex(device_ci_canonical_blob(sample())) == kCrossPinHash);
    CHECK(sha256_hex(device_ci_canonical_blob(dirty())) == kDirtyCrossPinHash);
}

TEST_CASE("device_ci v2 section registry equals the independent literal table",
          "[sync][device_ci][v2]") {
    struct Lit {
        const char* token;
        int n_fields;
        int row_cap;
    };
    // The same numbers as the server's registry (device_ci_kinds.hpp), typed again here so a
    // one-sided edit of either table fails a test rather than silently drifting.
    constexpr Lit lit[] = {{"chassis", 0, 0},  {"baseboard", 0, 0},   {"machine_id", 0, 0},
                           {"cpu", 7, 32},     {"dimm", 7, 64},        {"disk", 5, 128},
                           {"swap", 3, 16},    {"volume", 6, 128},     {"partition", 6, 192},
                           {"topology", 5, 96}};
    REQUIRE(std::size(kCiV2Sections) == std::size(lit));
    for (std::size_t i = 0; i < std::size(lit); ++i) {
        CHECK(std::string(kCiV2Sections[i].token) == lit[i].token);
        CHECK(kCiV2Sections[i].n_fields == lit[i].n_fields);
        CHECK(kCiV2Sections[i].row_cap == lit[i].row_cap);
    }
    const std::vector<std::string> trim = {"topology", "partition", "volume", "dimm",
                                           "disk",     "cpu",       "swap"};
    REQUIRE(std::size(kCiV2TrimOrder) == trim.size());
    for (std::size_t i = 0; i < trim.size(); ++i)
        CHECK(trim[i] == kCiV2TrimOrder[i]);
    for (const auto& d : lit) { // every row-bearing kind is trimmable
        if (d.row_cap > 0)
            CHECK(std::count(trim.begin(), trim.end(), std::string(d.token)) == 1);
    }
}

TEST_CASE("device_ci v2: a failing section action leaves every other section intact",
          "[sync][device_ci][v2]") {
    const auto base = parse_blob(device_ci_canonical_blob_v2(sample(), all_ok_inputs()));
    auto in = all_ok_inputs();
    in.topology.rc = 1;
    in.topology.captured = "unknown action: topology";
    in.partitions.truncated = true; // three well-formed rows before the cut
    in.partitions.captured = wide_rows("partition", 6, 3, 4);
    in.swap = cap("status|swap|unsupported|linux:planned", YUZU_RESULT_STATUS_UNAVAILABLE,
                  "linux:planned");
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));

    CHECK(p.status.at("topology") == Rec{"unavailable", "agent:action_absent"});
    CHECK(p.status.at("partition") == Rec{"unavailable", "agent:truncated"});
    CHECK(p.status.at("swap") == Rec{"unavailable", "linux:planned"});
    CHECK(p.rows.count("topology") == 0);
    CHECK(p.rows.count("partition") == 0);
    CHECK(p.rows.count("swap") == 0);
    for (const char* k : {"chassis", "baseboard", "machine_id", "cpu", "dimm", "disk", "volume"})
        CHECK(p.status.at(k) == base.status.at(k));
    for (const char* k : {"cpu", "dimm", "disk", "volume"})
        CHECK(p.rows.at(k) == base.rows.at(k));
    CHECK(p.scalar == base.scalar); // the 22 base fields and the 11 appended are unchanged
}

TEST_CASE("device_ci v2: nothing from a failed capture is projected", "[sync][device_ci][v2]") {
    auto in = all_ok_inputs();
    in.partitions.truncated = true;
    in.partitions.captured = wide_rows("partition", 6, 3, 4);
    in.topology.rc = 1;
    in.topology.captured = wide_rows("topology", 5, 3, 4);
    in.chassis = cap("chassis|laptop|CHS-0001|AT-0001|dmi", YUZU_RESULT_STATUS_PERMISSION_DENIED,
                     "linux:dmi:denied");
    in.volumes = cap(wide_rows("volume", 6, 2, 4), YUZU_RESULT_STATUS_CONSTRAINED, "linux:partial");
    // A refusal on a ROW-bearing section: well-formed rows in the capture, none on the wire.
    in.disks = cap(wide_rows("disk", 5, 3, 4), YUZU_RESULT_STATUS_PERMISSION_DENIED,
                   "linux:disks:denied");
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));

    CHECK(p.status.at("disk") == Rec{"permission_denied", "linux:disks:denied"});
    CHECK(p.rows.count("disk") == 0);
    CHECK(level_of(p, "partition") == "unavailable"); // never promoted to constrained
    CHECK(p.rows.count("partition") == 0);
    CHECK(level_of(p, "topology") == "unavailable");
    CHECK(p.rows.count("topology") == 0);
    CHECK(p.status.at("chassis") == Rec{"permission_denied", "linux:dmi:denied"});
    for (int i = 22; i <= 25; ++i)
        CHECK(p.scalar[static_cast<std::size_t>(i)].empty()); // chassis positions blank
    CHECK(p.scalar[26] == "Dell Inc."); // baseboard unaffected
    // A typed CONSTRAINED capture is still a readable one: rows projected, provenance kept.
    CHECK(p.status.at("volume") == Rec{"constrained", "linux:partial"});
    CHECK(p.rows.at("volume").size() == 2);
}

TEST_CASE("device_ci v2: typed metadata of the three existing actions reaches the writer",
          "[sync][device_ci][v2]") {
    auto in = all_ok_inputs();
    in.processors.status = YUZU_RESULT_STATUS_CONSTRAINED;
    in.processors.provenance = "windows:wmi_partial";
    in.disks.status = YUZU_RESULT_STATUS_OK;
    in.memory.status = YUZU_RESULT_STATUS_UNDECLARED;
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    CHECK(p.status.at("cpu") == Rec{"constrained", "windows:wmi_partial"});
    CHECK(p.rows.at("cpu").size() == 1);
    CHECK(p.status.at("disk") == Rec{"ok", ""});
    CHECK(p.status.at("dimm") == Rec{"ok", ""});
}

TEST_CASE("device_ci v2: an absent disk_actions plugin degrades only its three sections",
          "[sync][device_ci][v2]") {
    const auto base = parse_blob(device_ci_canonical_blob_v2(sample(), all_ok_inputs()));
    auto in = all_ok_inputs();
    in.disk_actions_loaded = false; // the captures below must be ignored
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    for (const char* k : {"volume", "partition", "topology"}) {
        CHECK(p.status.at(k) == Rec{"unavailable", "agent:plugin_not_loaded"});
        CHECK(p.rows.count(k) == 0);
    }
    CHECK(p.status.at("cpu") == base.status.at("cpu"));
    CHECK(p.rows.at("cpu") == base.rows.at("cpu"));
    CHECK(p.scalar == base.scalar);
}

TEST_CASE("device_ci v2 status mapping: level table and reason precedence",
          "[sync][device_ci][v2]") {
    const std::vector<std::pair<YuzuResultStatus, std::string>> levels = {
        {YUZU_RESULT_STATUS_UNDECLARED, "ok"},
        {YUZU_RESULT_STATUS_OK, "ok"},
        {YUZU_RESULT_STATUS_CONSTRAINED, "constrained"},
        {YUZU_RESULT_STATUS_UNAVAILABLE, "unavailable"},
        {YUZU_RESULT_STATUS_PERMISSION_DENIED, "permission_denied"},
    };
    const auto status_of = [](CiActionResult r) {
        auto in = all_ok_inputs();
        in.chassis = std::move(r);
        return parse_blob(device_ci_canonical_blob_v2(sample(), in)).status.at("chassis");
    };
    for (const auto& [st, lvl] : levels)
        CHECK(status_of(cap("chassis|laptop|c|a|dmi", st))[0] == lvl);

    // provenance > the plugin's status-row token > ""
    CHECK(status_of(cap("status|chassis|constrained|row:tok", YUZU_RESULT_STATUS_CONSTRAINED,
                        "typed:prov"))[1] == "typed:prov");
    CHECK(status_of(cap("status|chassis|constrained|row:tok", YUZU_RESULT_STATUS_CONSTRAINED))[1] ==
          "row:tok");
    CHECK(status_of(cap("status|chassis|supported|-", YUZU_RESULT_STATUS_OK))[1] == ""); // '-' -> ""
    CHECK(status_of(cap("chassis|laptop|c|a|dmi"))[1] == "");
    // A status row for a DIFFERENT action does not count.
    CHECK(status_of(cap("status|baseboard|constrained|other", YUZU_RESULT_STATUS_CONSTRAINED))[1] ==
          "");

    // A non-zero rc with ordinary output is agent:rc=<n>; "unknown action" is action_absent.
    CiActionResult bad = cap("some output");
    bad.rc = 3;
    CHECK(status_of(bad) == Rec{"unavailable", "agent:rc=3"});
    bad.captured = "unknown action: chassis";
    bad.rc = 1;
    CHECK(status_of(bad) == Rec{"unavailable", "agent:action_absent"});
}

TEST_CASE("device_ci v2 row projection", "[sync][device_ci][v2]") {
    auto in = all_ok_inputs();

    SECTION("swap drops used_mb; volumes/partitions emit volume/partition kinds") {
        in.swap = cap("swap|/swapfile|2048|777|proc_swaps");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("swap").size() == 1);
        CHECK(p.rows.at("swap")[0] == Rec{"/swapfile", "2048", "proc_swaps"});
        CHECK(p.rows.count("volumes") == 0);
        CHECK(p.rows.at("volume").size() == 1);
        CHECK(p.rows.at("partition").size() == 1);
    }
    SECTION("a 5-column cpu row from an older plugin pads socket/stepping blank") {
        in.processors = cap("cpu|0|Intel i7|4|8|2800");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        CHECK(p.rows.at("cpu")[0] == Rec{"0", "Intel i7", "4", "8", "2800", "", ""});
    }
    SECTION("the hardware disk sentinel and the volume placeholder produce no row") {
        in.disks = cap("disk|0|unknown|0|unknown|unknown");
        in.volumes = cap("status|volumes|constrained|linux:empty\nvolume|-|-|-|-|-|-",
                         YUZU_RESULT_STATUS_CONSTRAINED);
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        CHECK(p.rows.count("disk") == 0);
        CHECK(p.rows.count("volume") == 0); // the status| line never becomes a row either
        CHECK(level_of(p, "volume") == "constrained");
        CHECK(reason_of(p, "volume") == "linux:empty");
    }
    SECTION("the dimm empty-result sentinel is no row; the memory summary row is kept") {
        in.memory = cap("dimm|unknown|0|unknown|0|-|-|-");
        auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        CHECK(p.rows.count("dimm") == 0);
        CHECK(level_of(p, "dimm") == "ok");
        in.memory = cap("dimm|total|16384|unknown|0|-|-|-");
        p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("dimm").size() == 1);
        CHECK(p.rows.at("dimm")[0][0] == "total");
        CHECK(p.rows.at("dimm")[0][1] == "16384");
    }
    SECTION("every column is scrubbed and clamped") {
        std::string euro;
        for (int i = 0; i < 367; ++i)
            euro += "\xE2\x82\xAC"; // 1101 bytes of 3-byte codepoints
        in.disks = cap("disk|0|Mo\x1f"
                       "del|" + euro + "|SSD|NVMe\n");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("disk").size() == 1);
        CHECK(p.rows.at("disk")[0][1] == "Model"); // interior 0x1F stripped
        CHECK(p.rows.at("disk")[0][2].size() == 1023); // 1024 cut back to a codepoint boundary
    }
}

TEST_CASE("device_ci v2: an escaped pipe stays inside its field and shifts no column",
          "[sync][device_ci][v2][pipe]") {
    auto in = all_ok_inputs();

    SECTION("list rows: a pipe in the disk model and in the volume label") {
        in.disks = cap("disk|0|Model\\|X|512|SSD|NVMe");
        in.volumes = cap("volume|My\\|Vol|C:/|//?/Volume{1}/|NTFS|511705088|-");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("disk").size() == 1);
        CHECK(p.rows.at("disk")[0] == Rec{"0", "Model|X", "512", "SSD", "NVMe"});
        REQUIRE(p.rows.at("volume").size() == 1);
        CHECK(p.rows.at("volume")[0] ==
              Rec{"My|Vol", "C:/", "//?/Volume{1}/", "NTFS", "511705088", "-"});
    }
    SECTION("list rows: several escaped pipes in one field stay in that field") {
        in.disks = cap("disk|0|A\\|B\\|C|512|SSD|NVMe");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("disk").size() == 1);
        CHECK(p.rows.at("disk")[0] == Rec{"0", "A|B|C", "512", "SSD", "NVMe"});
    }
    SECTION("scalar rows: a pipe in the chassis serial leaves the later fields in place") {
        in.chassis = cap("chassis|laptop|CHS\\|0001|AT-0001|dmi");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.scalar.size() == 33);
        CHECK(p.scalar[22] == "laptop");
        CHECK(p.scalar[23] == "CHS|0001");
        CHECK(p.scalar[24] == "AT-0001");
        CHECK(p.scalar[25] == "dmi");
    }
    SECTION("scalar rows: two chassis rows give the same record in either order") {
        in.chassis = cap("chassis|laptop|CHS-B|AT-B|dmi\nchassis|desktop|CHS-A|AT-A|dmi");
        const auto a = device_ci_canonical_blob_v2(sample(), in);
        in.chassis = cap("chassis|desktop|CHS-A|AT-A|dmi\nchassis|laptop|CHS-B|AT-B|dmi");
        CHECK(device_ci_canonical_blob_v2(sample(), in) == a);
        CHECK(parse_blob(a).scalar[23] == "CHS-A"); // the row that sorts first
    }
    SECTION("an escaped pipe inside a mount path stays in the mount column and is still redacted") {
        in.volumes = cap("volume|A|/Users/al\\|ice/x|d1|apfs|1|-");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("volume").size() == 1);
        CHECK(p.rows.at("volume")[0][1] == "[redacted]");
        CHECK(level_of(p, "volume") == "constrained");
    }
    SECTION("an unescaped pipe still separates columns") {
        in.disks = cap("disk|0|Model|512|SSD|NVMe");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        CHECK(p.rows.at("disk")[0] == Rec{"0", "Model", "512", "SSD", "NVMe"});
    }
}

TEST_CASE("redact_mount_points: user-profile and /Volumes entries are replaced and system roots kept",
          "[sync][device_ci][v2][mounts]") {
    const auto run = [](std::string_view csv) {
        bool redacted = false;
        auto out = yuzu::agent::redact_mount_points(csv, redacted);
        return std::pair{out, redacted};
    };
    using R = std::pair<std::string, bool>;

    CHECK(run("-") == R{"-", false});
    CHECK(run("") == R{"", false});
    CHECK(run("/") == R{"/", false});
    CHECK(run("C:/") == R{"C:/", false});
    CHECK(run("C:/,D:/") == R{"C:/,D:/", false});
    CHECK(run("C:") == R{"C:", false});
    CHECK(run("/System/Volumes/Data") == R{"/System/Volumes/Data", false});
    CHECK(run("/mnt/data") == R{"/mnt/data", false});
    CHECK(run("D:/Data/vol1") == R{"D:/Data/vol1", false});

    CHECK(run("/Users/alice/vol") == R{"[redacted]", true});
    CHECK(run("/USERS") == R{"[redacted]", true});
    CHECK(run("/home/dave") == R{"[redacted]", true});
    CHECK(run("C:/Users/Bob/mnt") == R{"[redacted]", true});
    CHECK(run("c:\\documents and settings\\bob") == R{"[redacted]", true});
    CHECK(run("/Volumes/Backup") == R{"[redacted]", true});

    // macOS can spell the firmlinked user tree under the Data volume; the bare volume stays.
    CHECK(run("/System/Volumes/Data/Users/alice") == R{"[redacted]", true});
    CHECK(run("/System/Volumes/Data/home/x") == R{"[redacted]", true});
    CHECK(run("/System/Volumes/Data") == R{"/System/Volumes/Data", false});
    CHECK(run("/System/Volumes/Data/Applications") == R{"/System/Volumes/Data/Applications", false});
    CHECK(run("/System/Volumes/DataX/Users/a") == R{"/System/Volumes/DataX/Users/a", false});

    // The root match is on a segment boundary.
    CHECK(run("/Usersx/a") == R{"/Usersx/a", false});
    CHECK(run("/Volumes2") == R{"/Volumes2", false});

    // A list keeps its clean entries and its order.
    CHECK(run("/,/Volumes/Data") == R{"/,[redacted]", true});
    CHECK(run("C:/,D:/Users/x") == R{"C:/,[redacted]", true});

    // A label that held a comma is split into pieces; the tail is not a path, so it goes too.
    CHECK(run("/Volumes/Alice, Backup") == R{"[redacted],[redacted]", true});

    // The flag is only ever raised.
    bool redacted = true;
    CHECK(yuzu::agent::redact_mount_points("/", redacted) == "/");
    CHECK(redacted);
}

TEST_CASE("device_ci v2: a redacted mount point marks the section constrained and is disclosed",
          "[sync][device_ci][v2][mounts]") {
    auto in = all_ok_inputs();

    SECTION("volume: a /Volumes entry, no plugin reason") {
        in.volumes = cap("volume|Data|/,/Volumes/Alice|disk1s5|apfs|1000|-");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("volume").size() == 1);
        CHECK(p.rows.at("volume")[0][1] == "/,[redacted]");
        CHECK(level_of(p, "volume") == "constrained");
        CHECK(reason_of(p, "volume") == "agent:mount_points_redacted");
    }
    SECTION("partition: the mount column is column 5, and the plugin's own reason is kept after the token") {
        in.partitions = cap("partition|0|2|1000|APFS|/Users/alice/x|-", YUZU_RESULT_STATUS_CONSTRAINED,
                            "macos:partial");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("partition").size() == 1);
        CHECK(p.rows.at("partition")[0] == Rec{"0", "2", "1000", "APFS", "[redacted]", "-"});
        CHECK(level_of(p, "partition") == "constrained");
        CHECK(reason_of(p, "partition") == "agent:mount_points_redacted;macos:partial");
    }
    SECTION("a framing byte inside a root segment cannot hide a personal path") {
        in.volumes = cap(std::string("volume|A|/Us\x1f") + "ers/alice|d1|apfs|1|-\n" +
                         "volume|B|/Vol" + '\0' + "umes/x|d2|apfs|1|-");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        REQUIRE(p.rows.at("volume").size() == 2);
        CHECK(p.rows.at("volume")[0][1] == "[redacted]");
        CHECK(p.rows.at("volume")[1][1] == "[redacted]");
        CHECK(level_of(p, "volume") == "constrained");
    }
    SECTION("only the mount column is redacted: the same text elsewhere in a row is untouched") {
        in.volumes = cap("volume|/Volumes/Label|/|disk1s1|apfs|1000|-");
        const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
        CHECK(p.rows.at("volume")[0][0] == "/Volumes/Label");
        CHECK(level_of(p, "volume") == "ok");
    }
    SECTION("the redaction is deterministic: row order does not change the bytes") {
        in.volumes = cap("volume|A|/Volumes/x|d1|apfs|1|-\nvolume|B|C:/|d2|ntfs|2|-");
        const auto a = device_ci_canonical_blob_v2(sample(), in);
        in.volumes = cap("volume|B|C:/|d2|ntfs|2|-\nvolume|A|/Volumes/x|d1|apfs|1|-");
        CHECK(device_ci_canonical_blob_v2(sample(), in) == a);
    }
}

TEST_CASE("device_ci v2: the Windows volumes probe is reported unavailable and not run",
          "[sync][device_ci][v2][windows]") {
    const auto deferred = yuzu::agent::windows_volumes_deferred_result();
    CHECK(deferred.rc == 0);
    CHECK_FALSE(deferred.truncated);
    CHECK(deferred.captured.empty());
    CHECK(deferred.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(deferred.provenance == "agent:windows_volumes_unbounded");

    auto in = all_ok_inputs();
    in.volumes = deferred;
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    CHECK(p.status.at("volume") == Rec{"unavailable", "agent:windows_volumes_unbounded"});
    CHECK(p.rows.count("volume") == 0);
    // Only the volume section is affected.
    CHECK(level_of(p, "partition") == "ok");
    CHECK(level_of(p, "topology") == "ok");
    CHECK(level_of(p, "disk") == "ok");
}

TEST_CASE("device_ci v2: rows are sorted and capped first-N with the cap disclosed",
          "[sync][device_ci][v2]") {
    auto in = all_ok_inputs();
    // 140 topology rows in reverse order -> the first 96 in lexicographic order are kept.
    std::string rows;
    for (int i = 139; i >= 0; --i)
        rows += wide_rows("topology", 5, 1, 3, i);
    in.topology = cap(rows);
    auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    REQUIRE(p.rows.at("topology").size() == 96);
    CHECK(p.rows.at("topology").front()[0] == "0000");
    CHECK(p.rows.at("topology").back()[0] == "0095");
    CHECK(p.status.at("topology") == Rec{"constrained", "agent_cap:96/140"});

    // A non-empty base reason gets the token appended after ';'.
    in.topology = cap(rows, YUZU_RESULT_STATUS_CONSTRAINED, "linux:partial");
    p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    CHECK(p.status.at("topology") == Rec{"constrained", "linux:partial;agent_cap:96/140"});
}

TEST_CASE("device_ci v2: the redaction token survives a maximal plugin reason and a cap",
          "[sync][device_ci][v2][mounts]") {
    auto in = all_ok_inputs();
    // 131 rows, one with a personal mount (it sorts last, so the cap drops it: the section is still
    // constrained because redaction is decided before the cap), and a reason past the clamp.
    in.volumes = cap("volume|zz|/Volumes/x|d|apfs|1|-\n" + wide_rows("volume", 6, 130, 3),
                     YUZU_RESULT_STATUS_CONSTRAINED, std::string(1100, 'p'));
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    const auto& reason = p.status.at("volume")[1];
    CHECK(level_of(p, "volume") == "constrained");
    CHECK(reason.size() <= 1024);
    CHECK(reason.starts_with("agent:mount_points_redacted;"));
    CHECK(reason.ends_with(";agent_cap:128/131"));
}

TEST_CASE("device_ci v2: the cap token always fits the reason field", "[sync][device_ci][v2]") {
    auto in = all_ok_inputs();
    in.volumes = cap(wide_rows("volume", 6, 130, 3), YUZU_RESULT_STATUS_CONSTRAINED,
                     std::string(1100, 'p'));
    const auto p = parse_blob(device_ci_canonical_blob_v2(sample(), in));
    const auto& reason = p.status.at("volume")[1];
    CHECK(reason.size() <= 1024);
    CHECK(reason.ends_with(";agent_cap:128/130"));
    CHECK(reason.starts_with(std::string(100, 'p')));
}

TEST_CASE("device_ci v2: the ceiling trim removes whole kinds in order and discloses it",
          "[sync][device_ci][v2]") {
    // Every kind at (or just over) its cap with wide rows -> far over 96 KiB untrimmed.
    const auto fill = [](int width) {
        auto in = all_ok_inputs();
        in.processors = cap(wide_rows("cpu", 7, 32, width));
        in.memory = cap(wide_rows("dimm", 7, 64, width));
        in.disks = cap(wide_rows("disk", 5, 128, width));
        in.swap = cap(wide_rows("swap", 4, 16, width));
        in.volumes = cap(wide_rows("volume", 6, 128, width));
        in.partitions = cap(wide_rows("partition", 6, 192, width));
        in.topology = cap(wide_rows("topology", 5, 106, width));
        return in;
    };
    const std::map<std::string, std::size_t> caps = {{"topology", 96}, {"partition", 192},
                                                     {"volume", 128},   {"dimm", 64},
                                                     {"disk", 128},     {"cpu", 32},
                                                     {"swap", 16}};
    const auto small = parse_blob(device_ci_canonical_blob_v2(sample(), all_ok_inputs()));
    // The survivors of any trim are the FIRST N rows in wire order (a tail pop, never a head
    // erase): wide_rows() numbers its rows from 0000, so N survivors are 0000..N-1.
    const auto expect_first_n = [](const Parsed& parsed, const char* kind) {
        const auto& rows = parsed.rows.at(kind);
        char last[16];
        std::snprintf(last, sizeof last, "%04zu", rows.size() - 1);
        CHECK(rows.front()[0] == "0000");
        CHECK(rows.back()[0] == last);
    };

    for (const int width : {120, 400}) {
        CAPTURE(width);
        const auto blob = device_ci_canonical_blob_v2(sample(), fill(width));
        REQUIRE(blob.size() <= yuzu::agent::kDeviceCiMaxBlobBytes);
        const auto p = parse_blob(blob);

        // Order: kinds before the first one still holding rows are exhausted (and disclosed), the
        // boundary kind may be partial, and every kind after it still holds all its capped rows.
        bool boundary = false;
        bool any_trimmed = false;
        for (const char* kind : kCiV2TrimOrder) {
            CAPTURE(kind);
            const std::size_t kept = p.rows.count(kind) ? p.rows.at(kind).size() : 0;
            if (kept > 0)
                expect_first_n(p, kind);
            if (boundary) {
                CHECK(kept == caps.at(kind));
                continue;
            }
            if (kept > 0)
                boundary = true;
            if (kept < caps.at(kind)) {
                any_trimmed = true;
                CHECK(level_of(p, kind) == "constrained");
                // Exactly one token, carrying the final kept count.
                const auto& reason = reason_of(p, kind);
                CHECK(count_of(reason, "agent_cap:") == 1);
                CHECK(reason.find("agent_cap:" + std::to_string(kept) + "/") != std::string::npos);
            }
        }
        CHECK(any_trimmed);
        // Swap is last in the order and these inputs never need it.
        CHECK(p.rows.at("swap").size() == 16);
        CHECK(p.status.at("swap") == Rec{"ok", ""});
        // Scalar record and all ten status records survive unchanged.
        CHECK(p.scalar == small.scalar);
        CHECK(p.status.size() == std::size(kCiV2Sections));
    }

    // Width 400: topology, partition, volume and dimm are exhausted, disk is the boundary.
    const auto wide = parse_blob(device_ci_canonical_blob_v2(sample(), fill(400)));
    for (const char* kind : {"topology", "partition", "volume", "dimm"})
        CHECK(wide.rows.count(kind) == 0);
    CHECK(wide.status.at("topology") == Rec{"constrained", "agent_cap:0/106"});
    REQUIRE(wide.rows.count("disk") == 1);
    CHECK(wide.rows.at("disk").size() < 128);
    expect_first_n(wide, "disk");
    CHECK(wide.rows.at("cpu").size() == 32);

    // With no disks at all the trim runs on into cpu; swap (last in the order) is still whole.
    auto no_disk = fill(450);
    no_disk.disks = cap("");
    const auto deep = parse_blob(device_ci_canonical_blob_v2(sample(), no_disk));
    CHECK(deep.rows.count("dimm") == 0);
    REQUIRE(deep.rows.count("cpu") == 1);
    CHECK(deep.rows.at("cpu").size() < 32);
    expect_first_n(deep, "cpu");
    CHECK(count_of(reason_of(deep, "cpu"), "agent_cap:") == 1);
    CHECK(deep.rows.at("swap").size() == 16);
}

TEST_CASE("device_ci v2 is deterministic in the plugin's row order", "[sync][device_ci][v2]") {
    const auto reversed = [](const std::string& rows) {
        std::vector<std::string> lines;
        std::size_t pos = 0;
        while (pos < rows.size()) {
            const std::size_t e = rows.find('\n', pos);
            lines.push_back(rows.substr(pos, e - pos));
            pos = e + 1;
        }
        std::string out;
        for (auto it = lines.rbegin(); it != lines.rend(); ++it)
            out += *it + "\n";
        return out;
    };
    auto a = all_ok_inputs();
    a.topology = cap(wide_rows("topology", 5, 140, 3));
    a.disks = cap(wide_rows("disk", 5, 10, 3));
    auto b = a;
    b.topology.captured = reversed(a.topology.captured);
    b.disks.captured = reversed(a.disks.captured);
    CHECK(device_ci_canonical_blob_v2(sample(), a) == device_ci_canonical_blob_v2(sample(), b));
}

// ── collect() through fake plugin descriptors ───────────────────────────────

namespace {
// Scripted output / rc / typed result per action, one slot per plugin:
// 0 hardware, 1 device_identity, 2 os_info, 3 network_config, 4 disk_actions.
struct CiFake {
    std::map<std::string, std::string> out;
    std::map<std::string, int> rc;
    std::map<std::string, std::pair<YuzuResultStatus, std::string>> typed;
};
CiFake g_ci[5];
std::vector<std::string> g_dispatched;

template <int I>
int ci_fake_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* /*params*/,
                    std::size_t /*param_count*/) {
    g_dispatched.emplace_back(action);
    if (auto it = g_ci[I].out.find(action); it != g_ci[I].out.end())
        yuzu_ctx_write_output(ctx, it->second.c_str());
    if (auto t = g_ci[I].typed.find(action); t != g_ci[I].typed.end())
        yuzu_ctx_set_result_status(ctx, t->second.first, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                                   t->second.second.c_str());
    auto rc = g_ci[I].rc.find(action);
    return rc == g_ci[I].rc.end() ? 0 : rc->second;
}

const char* const kCiHwActions[] = {"manufacturer", "model",     "system",    "bios",
                                    "processors",   "memory",    "disks",     "chassis",
                                    "baseboard",    "swap",      "machine_id", nullptr};
const char* const kCiIdActions[] = {"device_name", "domain", "ou", nullptr};
const char* const kCiOsActions[] = {"os_name", "os_version", "os_build", "os_arch", nullptr};
const char* const kCiNetActions[] = {"adapters", nullptr};
const char* const kCiDiskActions[] = {"volumes", "partitions", "topology", nullptr};

#define YUZU_CI_FAKE_DESC(var, plugin_name, actions, idx)                                      \
    const YuzuPluginDescriptor var = {YUZU_PLUGIN_ABI_VERSION, plugin_name, "1.0.0",          \
                                      "test fake",             actions,     nullptr,           \
                                      nullptr,                 ci_fake_execute<idx>, nullptr}
YUZU_CI_FAKE_DESC(kCiHw, "hardware", kCiHwActions, 0);
YUZU_CI_FAKE_DESC(kCiId, "device_identity", kCiIdActions, 1);
YUZU_CI_FAKE_DESC(kCiOs, "os_info", kCiOsActions, 2);
YUZU_CI_FAKE_DESC(kCiNet, "network_config", kCiNetActions, 3);
YUZU_CI_FAKE_DESC(kCiDisk, "disk_actions", kCiDiskActions, 4);
#undef YUZU_CI_FAKE_DESC

void reset_ci_fakes() {
    for (auto& f : g_ci) {
        f.out.clear();
        f.rc.clear();
        f.typed.clear();
    }
    g_dispatched.clear();
    const auto in = all_ok_inputs();
    g_ci[0].out = {{"manufacturer", "manufacturer|Dell Inc."},
                   {"model", "model|Latitude 7420"},
                   {"system", "serial|ABC123\nsystem_uuid|UUID-1"},
                   {"bios", "bios_vendor|Dell Inc.\nbios_version|1.27.0\nbios_date|2024-03-15"},
                   {"processors", in.processors.captured},
                   {"memory", in.memory.captured},
                   {"disks", in.disks.captured},
                   {"chassis", in.chassis.captured},
                   {"baseboard", in.baseboard.captured},
                   {"swap", in.swap.captured},
                   {"machine_id", in.machine_id.captured}};
    g_ci[1].out = {{"device_name", "device_name|WS-001"},
                   {"domain", "domain|corp.example"},
                   {"ou", "ou|OU=Laptops"}};
    g_ci[2].out = {{"os_name", "os_name|Windows 11 Pro"},
                   {"os_version", "os_version|10.0.22631"},
                   {"os_build", "os_build|22631"},
                   {"os_arch", "os_arch|x86_64"}};
    g_ci[3].out = {{"adapters", "adapter|eth0|aa:bb:cc:dd:ee:ff|1000|up"}};
    g_ci[4].out = {{"volumes", in.volumes.captured},
                   {"partitions", in.partitions.captured},
                   {"topology", in.topology.captured}};
}

std::optional<std::pair<std::string, std::string>> collect_ci(bool with_disk_actions = true) {
    auto src = make_device_ci_source(&kCiHw, &kCiId, &kCiOs, &kCiNet,
                                     with_disk_actions ? &kCiDisk : nullptr);
    return src.collect();
}

bool dispatched(const std::string& action) {
    return std::find(g_dispatched.begin(), g_dispatched.end(), action) != g_dispatched.end();
}
} // namespace

TEST_CASE("device_ci collect(): all actions ok yields a v2 blob and its hash",
          "[sync][device_ci][v2][collect]") {
    reset_ci_fakes();
    const auto r = collect_ci();
    REQUIRE(r.has_value());
    CHECK(r->first[0] == '\x02');
    CHECK(r->second == sha256_hex(r->first));
    const auto p = parse_blob(r->first);
    REQUIRE(p.status.size() == std::size(kCiV2Sections));
    for (const auto& [sec, st] : p.status) {
        CAPTURE(sec);
#ifdef _WIN32
        if (sec == "volume") // the Windows volumes probe is not run on the sync thread
            continue;
#endif
        CHECK(st == Rec{"ok", ""});
    }
    CHECK(p.scalar[0] == "Dell Inc.");
    CHECK(p.scalar[23] == "CHS-0001"); // chassis serial reached the scalar record
    CHECK(p.rows.at("cpu").size() == 1);
    CHECK(p.rows.at("topology").size() == 1);
}

TEST_CASE("device_ci collect(): the volumes action is dispatched off Windows and never on it",
          "[sync][device_ci][v2][collect][windows]") {
    reset_ci_fakes();
    const auto r = collect_ci();
    REQUIRE(r.has_value());
    const auto p = parse_blob(r->first);
#ifdef _WIN32
    CHECK_FALSE(dispatched("volumes"));
    CHECK(p.status.at("volume") == Rec{"unavailable", "agent:windows_volumes_unbounded"});
    CHECK(p.rows.count("volume") == 0);
#else
    CHECK(dispatched("volumes"));
    CHECK(p.status.at("volume") == Rec{"ok", ""});
    CHECK(p.rows.at("volume").size() == 1);
#endif
    // partitions and topology are status-only on Windows and always run.
    CHECK(dispatched("partitions"));
    CHECK(dispatched("topology"));
}

TEST_CASE("device_ci collect(): a failing section action never aborts the cycle",
          "[sync][device_ci][v2][collect]") {
    reset_ci_fakes();
    const auto base = parse_blob(collect_ci()->first);

    reset_ci_fakes();
    g_ci[4].rc["topology"] = 1;
    g_ci[4].out["topology"] = "unknown action: topology";
    g_ci[0].typed["chassis"] = {YUZU_RESULT_STATUS_PERMISSION_DENIED, "linux:dmi:denied"};
    const auto r = collect_ci();
    REQUIRE(r.has_value());
    const auto p = parse_blob(r->first);
    CHECK(p.status.at("topology") == Rec{"unavailable", "agent:action_absent"});
    CHECK(p.status.at("chassis") == Rec{"permission_denied", "linux:dmi:denied"});
    CHECK(Rec(p.scalar.begin(), p.scalar.begin() + 22) ==
          Rec(base.scalar.begin(), base.scalar.begin() + 22)); // the 22 base fields unchanged
    for (int i = 22; i <= 25; ++i)
        CHECK(p.scalar[static_cast<std::size_t>(i)].empty());
    for (const char* k : {"baseboard", "machine_id", "cpu", "dimm", "disk", "swap", "volume",
                          "partition"}) {
        CAPTURE(k);
        CHECK(p.status.at(k) == base.status.at(k));
        if (base.rows.count(k))
            CHECK(p.rows.at(k) == base.rows.at(k));
    }
}

TEST_CASE("device_ci collect(): a required action failing still aborts before any section action",
          "[sync][device_ci][v2][collect]") {
    reset_ci_fakes();
    g_ci[0].rc["model"] = 1;
    CHECK(!collect_ci().has_value());
    for (const char* a : {"chassis", "baseboard", "swap", "machine_id", "volumes", "partitions",
                          "topology"})
        CHECK(!dispatched(a));
}

TEST_CASE("device_ci collect(): the existing actions' typed metadata reaches the writer",
          "[sync][device_ci][v2][collect]") {
    // One row of each of the three pre-existing section actions, each with its own provenance.
    struct Existing {
        const char* action;
        const char* section;
        const char* provenance;
    };
    constexpr Existing kExisting[] = {{"processors", "cpu", "windows:wmi_partial"},
                                      {"memory", "dimm", "linux:meminfo_only"},
                                      {"disks", "disk", "macos:iokit_partial"}};
    const auto& e = kExisting[GENERATE(0, 1, 2)];
    CAPTURE(e.action);
    reset_ci_fakes();
    g_ci[0].typed[e.action] = {YUZU_RESULT_STATUS_CONSTRAINED, e.provenance};
    const auto r = collect_ci();
    REQUIRE(r.has_value());
    const auto p = parse_blob(r->first);
    CHECK(p.status.at(e.section) == Rec{"constrained", e.provenance});
    CHECK(p.rows.at(e.section).size() == 1); // a CONSTRAINED capture is still projected
    for (const auto& k : kExisting) { // the other two stay ok, with no provenance bleed
        if (std::string(k.section) != e.section)
            CHECK(p.status.at(k.section) == Rec{"ok", ""});
    }
}

TEST_CASE("device_ci collect(): an UNAVAILABLE section action puts no rows on the wire",
          "[sync][device_ci][v2][collect]") {
    reset_ci_fakes();
    // The capture still carries a well-formed swap row; the typed UNAVAILABLE result outranks it.
    REQUIRE(g_ci[0].out.at("swap").starts_with("swap|"));
    g_ci[0].typed["swap"] = {YUZU_RESULT_STATUS_UNAVAILABLE, "linux:swap_unreadable"};
    const auto r = collect_ci();
    REQUIRE(r.has_value());
    const auto p = parse_blob(r->first);
    CHECK(p.status.at("swap") == Rec{"unavailable", "linux:swap_unreadable"});
    CHECK(p.rows.count("swap") == 0);
    CHECK(p.status.at("cpu") == Rec{"ok", ""}); // the other sections are unaffected
}

TEST_CASE("device_ci collect(): a null disk_actions descriptor reports plugin_not_loaded",
          "[sync][device_ci][v2][collect]") {
    reset_ci_fakes();
    const auto r = collect_ci(/*with_disk_actions=*/false);
    REQUIRE(r.has_value());
    const auto p = parse_blob(r->first);
    for (const char* k : {"volume", "partition", "topology"})
        CHECK(p.status.at(k) == Rec{"unavailable", "agent:plugin_not_loaded"});
    CHECK(p.status.at("cpu") == Rec{"ok", ""});
    for (const char* a : {"volumes", "partitions", "topology"})
        CHECK(!dispatched(a));
}

TEST_CASE("device_ci blob ceiling is the literal 96 KiB, equal to the server's",
          "[sync][device_ci][v2]") {
    // The agent and the server share no header, so each side pins its own constant to the SAME
    // literal (the server twin is in tests/unit/server/test_device_inventory_store.cpp). A
    // one-sided change fails one of the two; the server accepts everything the agent can send.
    CHECK(yuzu::agent::kDeviceCiMaxBlobBytes == 98304u);
}

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

TEST_CASE("build_device_ci_record tolerates appended cpu/dimm columns", "[sync][device_ci]") {
    // The hardware plugin appends `socket_designation|stepping` to cpu rows and
    // `manufacturer|part_number|serial` to dimm rows (always `-` until a leg reads them).
    // The device-CI parse reads cpu rows positionally (>= 5 fields) and dimm rows (>= 3):
    // pinned here so a stricter width check fails in this suite, not in the fleet.
    using yuzu::agent::build_device_ci_record;
    using yuzu::agent::CiPluginOutputs;
    CiPluginOutputs o;
    o.processors = "cpu|0|Intel i7|4|8|2800|-|-\ncpu|1|Intel i7|4|8|2800|-|-";
    o.memory = "dimm|DIMM0|8192|DDR4|3200|-|-|-\ndimm|DIMM1|8192|DDR4|3200|-|-|-";

    auto r = build_device_ci_record(o);
    CHECK(r.cpu_model == "Intel i7");
    CHECK(r.cpu_cores == "8");
    CHECK(r.cpu_threads == "16");
    CHECK(r.ram_bytes == std::to_string(16384LL * 1024 * 1024));
}

TEST_CASE("build_device_ci_record keeps the raw pipe split of the frozen v1 positions",
          "[sync][device_ci][pipe]") {
    // The v2 projections split on an UNESCAPED pipe; the 22 v1 positions deliberately do not, because
    // their bytes (and so the hash of every fielded device) are frozen. A disk model holding an
    // escaped pipe is therefore still cut at it here. Switching the v1 loops to the unescaped split
    // would change disks_summary for such a device and must be a coordinated, versioned change.
    using yuzu::agent::build_device_ci_record;
    using yuzu::agent::CiPluginOutputs;
    CiPluginOutputs o;
    o.disks = "disk|0|Model\\|X|512|SSD|NVMe";
    CHECK(build_device_ci_record(o).disks_summary == "Model\\ X 512");
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
        auto src = make_device_ci_source(nullptr, nullptr, nullptr, nullptr, nullptr);
        CHECK(src.name == "device_ci");
        CHECK(src.interval == std::chrono::hours{24});
        CHECK(!src.collect().has_value());
    }
}
