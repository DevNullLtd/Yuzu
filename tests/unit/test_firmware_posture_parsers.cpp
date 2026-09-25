/**
 * test_firmware_posture_parsers.cpp -- unit coverage for firmware_posture_parsers.hpp. Pure
 * decoders and decisions, no OS header: runs on every OS, no platform guard.
 * Input provenance, per group:
 *   - macOS device-tree bytes: REAL CAPTURE this Mac 2026-09-21 (fixtures/wave8/firmware_posture/
 *     macos/, raw CFData hex exactly as IORegistryEntryCreateCFProperty returns it).
 *   - Linux DMI: dmi_absent.txt is a REAL CAPTURE (no DMI in the Docker VM); the populated host is
 *     an in-code ASSUMED SHAPE, not a capture.
 *   - SMBIOS type 0: byte-exact pins use a RECONSTRUCTION built by smbios_blob() from the DMTF
 *     type-0 layout; windows/rsmb.bin (the-rig REAL CAPTURE, a sibling fixture) is parsed
 *     structurally and fuzzed by truncation.
 *   - fwupd a{sv} maps, the Win32_BIOS row, Intel /rom keys: RECONSTRUCTIONS / ASSUMED SHAPE.
 * Each group names the mutation it fails under.
 */
#include <catch2/catch_test_macros.hpp>

#include "firmware_posture_parsers.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::firmware_posture;
namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

namespace {

fs::path fixture(const char* sub, const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "firmware_posture" / sub / name;
    REQUIRE(fs::exists(p));
    return p;
}

std::vector<std::string> read_lines(const fs::path& p) {
    std::ifstream f(p);
    std::vector<std::string> lines;
    for (std::string l; std::getline(f, l);)
        if (!l.empty()) lines.push_back(l);
    return lines;
}

Bytes from_hex(const std::string& h) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

// node path -> key -> raw bytes, from the macOS capture (an `absent` key is omitted).
std::map<std::string, std::map<std::string, Bytes>> read_dt_capture() {
    std::map<std::string, std::map<std::string, Bytes>> out;
    std::string node;
    for (const auto& line : read_lines(fixture("macos", "iodevicetree_props.txt"))) {
        if (line.rfind("[node ", 0) == 0) {
            node = line.substr(6, line.find(']') - 6);
            out[node];
            continue;
        }
        std::istringstream ss(line);
        std::string key, kind, hex;
        std::getline(ss, key, '\t');
        std::getline(ss, kind, '\t');
        std::getline(ss, hex, '\t');
        if (kind == "data") out[node][key] = from_hex(hex);
    }
    return out;
}

// `lookup_failed` defaults false (a node the capture/shape genuinely reached, however empty);
// pass true to model an IORegistryEntryFromPath call that itself returned MACH_PORT_NULL.
DtNode dt_node(const std::map<std::string, Bytes>* props, bool lookup_failed = false) {
    DtNode n;
    n.lookup_failed = lookup_failed;
    for (const auto& [k, v] : props ? *props : std::map<std::string, Bytes>{}) {
        if (auto s = decode_dt_string(v)) n.props.emplace(k, *s);
        else n.undecodable.push_back(k);
    }
    return n;
}

// An SMBIOS string-set: each string NUL-terminated, then one extra NUL.
std::string strset(std::initializer_list<const char*> strs) {
    std::string out;
    for (const char* x : strs) (out += x).push_back('\0');
    return out + '\0';
}

// RECONSTRUCTION of an RSMB blob: 8-byte RawSMBIOSData header + [type 1 filler] + type 0 +
// type 127. `rom`/`ext` = ROM-size byte / extended-size word; `len0` = type 0 formatted length.
Bytes smbios_blob(std::uint8_t rom = 0x0F, std::uint16_t ext = 0, std::uint8_t len0 = 0x1A,
                  bool filler_first = false) {
    Bytes t;
    auto put = [&](std::uint8_t type, std::uint8_t len, std::string strs, Bytes body) {
        Bytes s{type, len, 0x01, 0x00};
        body.resize(len - 4, 0);
        s.insert(s.end(), body.begin(), body.end());
        if (strs.empty()) strs.assign(2, '\0');
        s.insert(s.end(), strs.begin(), strs.end());
        t.insert(t.end(), s.begin(), s.end());
    };
    if (filler_first) put(1, 8, strset({"Sys"}), {1, 0, 0, 0});
    // type 0 body from offset 4: vendor=1 version=2 segment(2) date=3 rom, characteristics(10),
    // major=1 minor=20 ec major/minor=0xFF, ext rom size word.
    put(0, len0, strset({"Acme Firmware", "v1.2.3", "03/14/2024"}),
        {1, 2, 0x00, 0xE0, 3, rom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 20, 0xFF, 0xFF,
         static_cast<std::uint8_t>(ext & 0xFF), static_cast<std::uint8_t>(ext >> 8)});
    put(127, 4, "", {});
    Bytes blob{0, 3, 3, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) blob[4 + i] = static_cast<std::uint8_t>(t.size() >> (8 * i));
    blob.insert(blob.end(), t.begin(), t.end());
    return blob;
}

// Every strict prefix of the claimed table must be constrained/truncated and never throw.
void require_all_prefixes_constrained(const Bytes& blob) {
    REQUIRE(blob.size() > 8);
    const std::size_t claimed = blob[4] | blob[5] << 8 | blob[6] << 16 | std::size_t{blob[7]} << 24;
    for (std::size_t prefix = 0; prefix < std::min(blob.size(), 8 + claimed); ++prefix) {
        INFO("prefix length " << prefix);
        Smbios0Result r;
        try {
            r = parse_smbios_type0(std::span<const std::uint8_t>(blob.data(), prefix));
        } catch (...) {
            FAIL("parse_smbios_type0 threw on a truncated prefix");
        }
        REQUIRE(r.constrained);
        REQUIRE(r.token == "smbios:truncated");
    }
}

// The header's own Length claim rewritten to match each prefix, so the walk's per-structure bounds
// (not just the header-length check above) decide: a prefix is either the full decode or a
// constrained truncated/no_type0 result, never a partial success and never a throw.
void require_self_consistent_prefixes(const Bytes& blob) {
    const auto full = parse_smbios_type0(blob);
    REQUIRE_FALSE(full.constrained);
    for (std::size_t prefix = 8; prefix < blob.size(); ++prefix) {
        Bytes cut(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(prefix));
        const auto table_len = static_cast<std::uint32_t>(prefix - 8);
        for (int i = 0; i < 4; ++i) cut[4 + i] = static_cast<std::uint8_t>(table_len >> (8 * i));
        INFO("self-consistent prefix " << prefix);
        Smbios0Result r;
        try {
            r = parse_smbios_type0(cut);
        } catch (...) {
            FAIL("parse_smbios_type0 threw on a self-consistent truncated prefix");
        }
        if (r.constrained) {
            CHECK((r.token == "smbios:truncated" || r.token == "smbios:no_type0"));
            CHECK_FALSE(r.data.vendor.value.has_value());
        } else {
            CHECK(r.data.vendor.value == full.data.vendor.value);
            CHECK(r.data.version.value == full.data.version.value);
            CHECK(r.data.release_date.value == full.data.release_date.value);
        }
    }
}

std::string row_str(const FirmwareRow& r) { return format_row(r); }

} // namespace

// ── SMBIOS type 0 ────────────────────────────────────────────────────────
// Fails under: an offset/index off-by-one, the (n+1)*64KiB formula, dropping the 0xFF
// "not specified" rule, or losing the date normalisation.
TEST_CASE("parse_smbios_type0: RECONSTRUCTION type 0 decodes every field", "[firmware_posture][smbios]") {
    const auto r = parse_smbios_type0(smbios_blob());
    REQUIRE_FALSE(r.constrained);
    CHECK((*r.data.vendor.value == "Acme Firmware" && *r.data.version.value == "v1.2.3" &&
           *r.data.release_date.value == "03/14/2024"));
    CHECK(*r.data.rom_size_bytes == 1048576u); // (0x0F + 1) * 64 KiB
    CHECK((*r.data.bios_major == 1u && *r.data.bios_minor == 20u));
    CHECK_FALSE(r.data.ec_major.has_value()); // 0xFF = not specified
    const auto rows = smbios_rows(r.data);
    REQUIRE(rows.size() == 5);
    CHECK(row_str(rows[0]) == "firmware|vendor|Acme Firmware|smbios");
    CHECK(row_str(rows[1]) == "firmware|version|v1.2.3|smbios");
    CHECK(row_str(rows[2]) == "firmware|release_date|2024-03-14|smbios");
    CHECK(row_str(rows[3]) == "firmware|rom_size_bytes|1048576|smbios");
    CHECK(row_str(rows[4]) == "firmware|bios_release|1.20|smbios");
}

TEST_CASE("parse_smbios_type0: extended ROM size, structure order, short structures", "[firmware_posture][smbios]") {
    CHECK(*parse_smbios_type0(smbios_blob(0xFF, 0x0010)).data.rom_size_bytes == 16ull << 20);
    CHECK(*parse_smbios_type0(smbios_blob(0xFF, 0x4001)).data.rom_size_bytes == 1ull << 30);
    CHECK_FALSE(parse_smbios_type0(smbios_blob(0xFF, 0x8001)).data.rom_size_bytes.has_value()); // reserved unit
    CHECK_FALSE(parse_smbios_type0(smbios_blob(0xFF, 0, 0x18)).data.rom_size_bytes.has_value());
    const auto filler = parse_smbios_type0(smbios_blob(0x0F, 0, 0x1A, true)); // type 0 after a type 1
    REQUIRE_FALSE(filler.constrained);
    CHECK(*filler.data.vendor.value == "Acme Firmware");
    const auto old = parse_smbios_type0(smbios_blob(0x0F, 0, 0x12)); // release bytes start at 0x14
    REQUIRE_FALSE(old.constrained);
    CHECK_FALSE(old.data.bios_major.has_value());
}

TEST_CASE("parse_smbios_type0: malformed shapes are constrained, never partial", "[firmware_posture][smbios]") {
    auto blob = smbios_blob();
    blob[8 + 4] = 4; // string index 4 with only three strings
    auto r = parse_smbios_type0(blob);
    CHECK((r.constrained && r.token == "smbios:malformed"));
    CHECK_FALSE(r.data.vendor.value.has_value());
    CHECK(parse_smbios_type0(smbios_blob(0x0F, 0, 0x08)).token == "smbios:malformed"); // too short
    CHECK(parse_smbios_type0(Bytes{0, 3, 3, 0, 6, 0, 0, 0, 127, 4, 1, 0, 0, 0}).token == "smbios:no_type0");
    // One byte under the SMBIOS 2.0 type 0 minimum (0x12) is malformed, not a shorter decode.
    CHECK(parse_smbios_type0(smbios_blob(0x0F, 0, 0x11)).token == "smbios:malformed");
    // A structure declaring a length below its own 4-byte header is malformed, never skipped.
    CHECK(parse_smbios_type0(Bytes{0, 3, 3, 0, 5, 0, 0, 0, 5, 3, 0, 0, 0}).token == "smbios:malformed");
    {
        // Nothing behind the end-of-table marker counts: a type 0 there is not a BIOS structure.
        Bytes table{127, 4, 1, 0, 0, 0};
        const auto real = smbios_blob();
        table.insert(table.end(), real.begin() + 8, real.end());
        Bytes behind{0, 3, 3, 0, 0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) behind[4 + i] = static_cast<std::uint8_t>(table.size() >> (8 * i));
        behind.insert(behind.end(), table.begin(), table.end());
        CHECK(parse_smbios_type0(behind).token == "smbios:no_type0");
    }
    auto big = smbios_blob();
    big[4] = 0xFF; // header claims more table than supplied
    CHECK(parse_smbios_type0(big).token == "smbios:truncated");
    CHECK(parse_smbios_type0({}).token == "smbios:truncated");
}

// Fails under: removing the header-length check (a prefix holding a whole type 0 would parse OK).
TEST_CASE("parse_smbios_type0: every truncated prefix is constrained", "[firmware_posture][smbios][fuzz]") {
    require_all_prefixes_constrained(smbios_blob());
    require_all_prefixes_constrained(smbios_blob(0x0F, 0, 0x1A, true));
}

// Fails under: loosening any of the walk's own bounds (structure header, formatted area, string
// set), which the header-length prefixes above never reach.
TEST_CASE("parse_smbios_type0: a table cut inside a structure is truncated even when its header agrees",
          "[firmware_posture][smbios][fuzz]") {
    require_self_consistent_prefixes(smbios_blob());
    require_self_consistent_prefixes(smbios_blob(0x0F, 0, 0x1A, true));

    // A complete type 1 structure followed by only three bytes: the next structure header is cut.
    const Bytes stray{0, 3, 3, 0, 9, 0, 0, 0, 1, 4, 1, 0, 0, 0, 5, 2, 0};
    const auto r = parse_smbios_type0(stray);
    CHECK(r.constrained);
    CHECK(r.token == "smbios:truncated");
}

TEST_CASE("parse_smbios_type0: the-rig REAL CAPTURE rsmb.bin parses and every prefix is constrained",
          "[firmware_posture][smbios][fuzz]") {
    std::ifstream f(fixture("windows", "rsmb.bin"), std::ios::binary);
    const Bytes raw{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    const auto r = parse_smbios_type0(raw);
    REQUIRE_FALSE(r.constrained);
    CHECK((r.data.vendor.value && r.data.version.value && r.data.release_date.value));
    // The values Win32_BIOS reported on the same host (see rsmb.bin.provenance.txt).
    const auto rows = smbios_rows(r.data);
    REQUIRE(rows.size() == 5);
    CHECK(row_str(rows[0]) == "firmware|vendor|American Megatrends Inc.|smbios");
    CHECK(row_str(rows[1]) == "firmware|version|3801|smbios");
    CHECK(row_str(rows[2]) == "firmware|release_date|2021-07-30|smbios");
    CHECK(row_str(rows[3]) == "firmware|rom_size_bytes|16777216|smbios");
    CHECK(row_str(rows[4]) == "firmware|bios_release|5.17|smbios");
    require_all_prefixes_constrained(raw);
    require_self_consistent_prefixes(raw);
}

// Fails under: the Windows shell's no-RSMB-provider path going back to silently adding no row.
TEST_CASE("smbios_rows: a default (unparsed) Smbios0 -- the shell's absence shape -- is three absent rows",
          "[firmware_posture][smbios]") {
    const auto rows = smbios_rows(Smbios0{});
    REQUIRE(rows.size() == 3); // no rom_size_bytes/bios_release/ec_release row: nothing was specified
    CHECK(row_str(rows[0]) == "firmware|vendor|absent|smbios");
    CHECK(row_str(rows[1]) == "firmware|version|absent|smbios");
    CHECK(row_str(rows[2]) == "firmware|release_date|absent|smbios");
}

// ── Linux sysfs DMI ──────────────────────────────────────────────────────

// ASSUMED SHAPE, not a capture: one raw sysfs file body per key, trailing newline included.
const std::map<std::string, std::string> kDmiPopulated{{"bios_vendor", "American Megatrends International, LLC.\n"},
                                                       {"bios_version", "F.20\n"},
                                                       {"bios_date", "03/14/2024\n"},
                                                       {"bios_release", "5.27\n"}};

// Fails under: not trimming the trailing newline, or mis-splitting bios_release.
TEST_CASE("parse_dmi_sysfs: populated host (ASSUMED SHAPE)", "[firmware_posture][dmi]") {
    const auto d = parse_dmi_sysfs(kDmiPopulated);
    CHECK(*d.vendor.value == "American Megatrends International, LLC.");
    CHECK((*d.version.value == "F.20" && *d.release_date.value == "03/14/2024" && *d.bios_major == 5u &&
           *d.bios_minor == 27u));
    const auto rows = dmi_rows(d);
    REQUIRE(rows.size() == 4);
    CHECK(row_str(rows[2]) == "firmware|release_date|2024-03-14|dmi");
    CHECK(row_str(rows[3]) == "firmware|bios_release|5.27|dmi");
}

// Fails under: mapping a missing key to a failure or to an empty value.
TEST_CASE("parse_dmi_sysfs: REAL CAPTURE no-DMI host is absent, not a failure", "[firmware_posture][dmi]") {
    std::map<std::string, std::string> files; // a `!` value in the capture = the file was ENOENT
    for (const auto& line : read_lines(fixture("linux", "dmi_absent.txt"))) {
        const auto eq = line.find('=');
        REQUIRE(eq != std::string::npos);
        if (line[eq + 1] != '!') files[line.substr(0, eq)] = line.substr(eq + 1) + "\n";
    }
    const auto rows = dmi_rows(parse_dmi_sysfs(files));
    REQUIRE(rows.size() == 3);
    CHECK(row_str(rows[0]) == "firmware|vendor|absent|dmi");
    CHECK(row_str(rows[1]) == "firmware|version|absent|dmi");
    CHECK(row_str(rows[2]) == "firmware|release_date|absent|dmi");
    FirmwareReport rep;
    rep.add_all(rows);
    const auto v = select_verdict(rep.constraints, rep.denied);
    CHECK((v.status == YUZU_RESULT_STATUS_OK && v.completeness == YUZU_RESULT_COMPLETENESS_FULL));
}

// Fails under: an unreadable key falling through to `absent`.
TEST_CASE("parse_dmi_sysfs: unreadable vs malformed", "[firmware_posture][dmi]") {
    auto files = kDmiPopulated;
    files.erase("bios_version");
    CHECK(row_str(dmi_rows(parse_dmi_sysfs(files, {"bios_version"}))[1]) == "firmware|version|unreadable|dmi");
    CHECK(parse_dmi_sysfs({{"bios_release", "abc\n"}}).release_malformed);
    CHECK(parse_dmi_sysfs({{"bios_release", "1.\n"}}).release_malformed);
    CHECK_FALSE(parse_dmi_sysfs({{"bios_release", "1.2\n"}}).release_malformed);
}

// A failed bios_release read (EACCES/oversized) must report the same as the other three DMI
// fields -- a row saying `unreadable`, not silence. Fails under: bios_release's row vanishing
// entirely on a read failure while its sibling fields correctly emit `unreadable`.
TEST_CASE("parse_dmi_sysfs: an unreadable bios_release still gets a row", "[firmware_posture][dmi]") {
    auto files = kDmiPopulated;
    files.erase("bios_release");
    const auto d = parse_dmi_sysfs(files, {"bios_release"});
    CHECK(d.release_unreadable);
    CHECK_FALSE(d.bios_major.has_value());
    const auto rows = dmi_rows(d);
    REQUIRE(rows.size() == 4);
    CHECK(row_str(rows[3]) == "firmware|bios_release|unreadable|dmi");
    // A genuinely absent bios_release (not in unreadable_keys either) still emits no row at all
    // -- the pre-existing, correct "absent" shape for this field is unchanged.
    CHECK(dmi_rows(parse_dmi_sysfs(files)).size() == 3);
}

// RECONSTRUCTED Win32_BIOS row (ASSUMED SHAPE). BIOSVersion is array-typed and never reaches a row.
// Fails under: the Windows shell's WMI namespace/class-absent and empty-result paths going back to
// silently adding no row (the earlier, contract-violating shape: absence must be a row, not silence).
TEST_CASE("wmi_bios_rows: an empty result -- the shell's absence shape -- is three absent rows, not none",
          "[firmware_posture][wmi]") {
    const auto rows = wmi_bios_rows({});
    REQUIRE(rows.size() == 3);
    CHECK(row_str(rows[0]) == "firmware|vendor|absent|wmi");
    CHECK(row_str(rows[1]) == "firmware|version|absent|wmi");
    CHECK(row_str(rows[2]) == "firmware|release_date|absent|wmi");
}

TEST_CASE("wmi_bios_rows: maps the three scalar Win32_BIOS columns", "[firmware_posture][wmi]") {
    const auto rows = wmi_bios_rows({{"Manufacturer", "Acme Corp"},
                                     {"SMBIOSBIOSVersion", "A1B2C3 (1.05)"},
                                     {"ReleaseDate", "20240314000000.000000+000"}});
    REQUIRE(rows.size() == 3);
    CHECK(row_str(rows[0]) == "firmware|vendor|Acme Corp|wmi");
    CHECK(row_str(rows[1]) == "firmware|version|A1B2C3 (1.05)|wmi");
    CHECK(row_str(rows[2]) == "firmware|release_date|2024-03-14|wmi");
}

TEST_CASE("normalize_release_date: one shape, unknown text left alone", "[firmware_posture]") {
    CHECK(normalize_release_date("03/14/2024") == "2024-03-14");
    CHECK(normalize_release_date("20240314000000.000000+000") == "2024-03-14");
    CHECK(normalize_release_date("2024-03-14") == "2024-03-14");
    CHECK(normalize_release_date("03/14/24") == "03/14/24"); // 2-digit year: not guessed
    CHECK(normalize_release_date("garbage") == "garbage");
}

// Fails under: reformatting a shape-matching but non-calendar date into a confidently-wrong
// ISO date instead of passing it through unchanged.
TEST_CASE("normalize_release_date: a shape match with no real calendar date is left alone",
          "[firmware_posture]") {
    CHECK(normalize_release_date("13/40/2024") == "13/40/2024");   // month 13, day 40
    CHECK(normalize_release_date("00/14/2024") == "00/14/2024");   // month 0
    CHECK(normalize_release_date("03/00/2024") == "03/00/2024");   // day 0
    CHECK(normalize_release_date("02/30/2023") == "02/30/2023");   // Feb 30 in a non-leap year
    CHECK(normalize_release_date("02/29/2023") == "02/29/2023");   // Feb 29, 2023 is not a leap year
    CHECK(normalize_release_date("02/29/2024") == "2024-02-29");   // 2024 IS a leap year
    CHECK(normalize_release_date("02/29/2000") == "2000-02-29");   // divisible by 400: leap
    CHECK(normalize_release_date("02/29/1900") == "02/29/1900");   // divisible by 100, not 400: not leap
    CHECK(normalize_release_date("20241340000000.000000+000") == "20241340000000.000000+000"); // month 13
    CHECK(normalize_release_date("20240000000000.000000+000") == "20240000000000.000000+000"); // month 0, day 0
}

// Fails under: matching the CIM-datetime shape on the '.'/sign framing alone and reformatting
// even though the fractional-second or UTC-offset digit block is garbage.
TEST_CASE("normalize_release_date: CIM-datetime fractional-second and UTC-offset digits are validated",
          "[firmware_posture]") {
    CHECK(normalize_release_date("20240314000000.XXXXXX+000") == "20240314000000.XXXXXX+000"); // fractional block garbage
    CHECK(normalize_release_date("20240314000000.000000+XXX") == "20240314000000.000000+XXX"); // offset block garbage
    CHECK(normalize_release_date("20240314000000.000000-000") == "2024-03-14"); // '-' offset still valid
}

// ── read classification and the shared verdict ───────────────────────────

TEST_CASE("classify_errno / win32 / hresult / fwupd pin exact cases", "[firmware_posture]") {
    CHECK(classify_win32_error(2) == ReadOutcome::absent);   // ERROR_FILE_NOT_FOUND
    CHECK(classify_win32_error(3) == ReadOutcome::absent);   // ERROR_PATH_NOT_FOUND
    CHECK(classify_win32_error(5) == ReadOutcome::denied);   // ERROR_ACCESS_DENIED
    CHECK(classify_win32_error(122) == ReadOutcome::failed); // ERROR_INSUFFICIENT_BUFFER
    CHECK(classify_win32_error(267) == ReadOutcome::failed); // ERROR_DIRECTORY: the ENOTDIR analogue, never absence
    CHECK(classify_win32_error(0) == ReadOutcome::ok);
    CHECK(classify_hresult(0) == ReadOutcome::ok);
    CHECK(classify_hresult(0x80041003u) == ReadOutcome::denied);  // WBEM_E_ACCESS_DENIED
    CHECK(classify_hresult(0x80070005u) == ReadOutcome::denied);  // E_ACCESSDENIED
    CHECK(classify_hresult(0x8004100Eu) == ReadOutcome::absent);  // WBEM_E_INVALID_NAMESPACE
    CHECK(classify_hresult(0x80041010u) == ReadOutcome::absent);  // WBEM_E_INVALID_CLASS
    CHECK(classify_hresult(0x80041002u) == ReadOutcome::absent);  // WBEM_E_NOT_FOUND
    CHECK(classify_hresult(0x80004005u) == ReadOutcome::failed);  // E_FAIL
    CHECK(classify_errno(0) == ReadOutcome::ok);
    CHECK(classify_errno(2) == ReadOutcome::absent);  // ENOENT
    CHECK(classify_errno(20) == ReadOutcome::failed); // ENOTDIR: a malformed path, never absence
    CHECK(classify_errno(13) == ReadOutcome::denied); // EACCES
    CHECK(classify_errno(1) == ReadOutcome::denied);  // EPERM
    CHECK(classify_errno(5) == ReadOutcome::failed);  // EIO
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.ServiceUnknown", 0) == FwupdOutcome::unavailable);
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.NameHasNoOwner", 0) == FwupdOutcome::unavailable);
    CHECK(classify_fwupd_error("org.freedesktop.fwupd.NothingToDo", 0) == FwupdOutcome::no_devices);
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.AccessDenied", 0) == FwupdOutcome::denied);
    CHECK(classify_fwupd_error("org.freedesktop.fwupd.PermissionDenied", 0) == FwupdOutcome::denied);
    // An unopenable bus proves only that this process cannot reach it (a container without the
    // bus socket), never that fwupd is absent: only the NAMED replies above are `unavailable`.
    CHECK(classify_fwupd_error("", 2) == FwupdOutcome::failed);  // ENOENT: no bus socket
    CHECK(classify_fwupd_error("", 20) == FwupdOutcome::failed); // ENOTDIR
    CHECK(classify_fwupd_error("", 1) == FwupdOutcome::denied);  // EPERM
    CHECK(classify_fwupd_error("", 13) == FwupdOutcome::denied);
    CHECK(classify_fwupd_error("", 5) == FwupdOutcome::failed);
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.NoReply", 0) == FwupdOutcome::failed);
}

// Fails under: dropping the `dbus_error_name.empty()` guard (a NAMED, unrelated error carrying
// an EACCES errno would read `denied`), or an unnamed non-refusal errno reading as a refusal.
TEST_CASE("classify_fwupd_error: only an UNNAMED failure is judged by its errno", "[firmware_posture]") {
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.NoReply", 13) == FwupdOutcome::failed);
    CHECK(classify_fwupd_error("org.freedesktop.DBus.Error.NoReply", 2) == FwupdOutcome::failed);
    CHECK(classify_fwupd_error("", 111) == FwupdOutcome::failed);
    CHECK(classify_fwupd_error("", 0) == FwupdOutcome::failed);
}

// The outcome -> row/token/status mapping the Linux leg applies to a failed D-Bus call. Fails
// under: an unopenable bus mapping back to the `unavailable` row (the defect an external review
// found), a `failed` outcome recording no token, or `denied` not setting the denial flag.
TEST_CASE("apply_fwupd_failure: an unopenable bus is unreadable plus a token, never unavailable",
          "[firmware_posture]") {
    FirmwareReport rep;
    CHECK_FALSE(apply_fwupd_failure(rep, classify_fwupd_error("", 2), "bus_open", "enoent"));
    REQUIRE(rep.rows.size() == 1);
    CHECK(row_str(rep.rows[0]) == "firmware|update_pending|unreadable|fwupd");
    const auto v = select_verdict(rep.constraints, rep.denied);
    CHECK(v.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(v.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(v.rc == 1);
    CHECK(v.reason == "fwupd:bus_open:enoent");
}

TEST_CASE("apply_fwupd_failure: a refused bus connect is PERMISSION_DENIED with its own token",
          "[firmware_posture]") {
    FirmwareReport rep;
    CHECK_FALSE(apply_fwupd_failure(rep, classify_fwupd_error("", 13), "bus_open", "eacces"));
    REQUIRE(rep.rows.size() == 1);
    CHECK(row_str(rep.rows[0]) == "firmware|update_pending|unreadable|fwupd");
    CHECK(rep.denied);
    const auto v = select_verdict(rep.constraints, rep.denied);
    CHECK(v.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(v.reason == "fwupd:bus_open:permission_denied");
}

// Fails under: the named-reply `unavailable` gaining a failure token, or losing its row.
TEST_CASE("apply_fwupd_failure: a named ServiceUnknown reply is the unavailable state, no token",
          "[firmware_posture]") {
    FirmwareReport rep;
    const auto o = classify_fwupd_error("org.freedesktop.DBus.Error.ServiceUnknown", 0);
    CHECK_FALSE(apply_fwupd_failure(rep, o, "get_devices", "errno_0"));
    REQUIRE(rep.rows.size() == 1);
    CHECK(row_str(rep.rows[0]) == "firmware|update_pending|unavailable|fwupd");
    const auto v = select_verdict(rep.constraints, rep.denied);
    CHECK(v.status == YUZU_RESULT_STATUS_OK);
    CHECK(v.rc == 0);
    CHECK(v.reason.empty());
}

TEST_CASE("apply_fwupd_failure: NothingToDo continues to the row mapper with nothing recorded",
          "[firmware_posture]") {
    FirmwareReport rep;
    const auto o = classify_fwupd_error("org.freedesktop.fwupd.NothingToDo", 0);
    CHECK(apply_fwupd_failure(rep, o, "get_devices", "errno_0"));
    CHECK(rep.rows.empty());
    CHECK_FALSE(rep.constraints.any_failure());
}

// The DMI read-error arm. Fails under: ENOTDIR (a malformed path) reading as a silent absence, or
// ENOENT (no DMI, or no bios_release on this board) gaining a token.
TEST_CASE("record_dmi_read_error: ENOENT is silent absence; ENOTDIR and EACCES are unreadable plus a token",
          "[firmware_posture][dmi]") {
    {
        FirmwareReport rep;
        std::vector<std::string> keys;
        record_dmi_read_error(rep, keys, "bios_release", classify_errno(2), "enoent");
        CHECK(keys.empty());
        CHECK_FALSE(rep.constraints.any_failure());
    }
    {
        FirmwareReport rep;
        std::vector<std::string> keys;
        record_dmi_read_error(rep, keys, "bios_vendor", classify_errno(20), "enotdir");
        REQUIRE(keys.size() == 1);
        CHECK(keys[0] == "bios_vendor");
        CHECK_FALSE(rep.denied);
        const auto v = select_verdict(rep.constraints, rep.denied);
        CHECK(v.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(v.reason == "dmi:bios_vendor:enotdir");
        // Handed to the field mapper, the key's row reads `unreadable`, never `absent`.
        auto files = kDmiPopulated;
        files.erase("bios_vendor");
        CHECK(row_str(dmi_rows(parse_dmi_sysfs(files, keys))[0]) == "firmware|vendor|unreadable|dmi");
    }
    {
        FirmwareReport rep;
        std::vector<std::string> keys;
        record_dmi_read_error(rep, keys, "bios_version", classify_errno(13), "eacces");
        CHECK(keys == std::vector<std::string>{"bios_version"});
        CHECK(rep.denied);
        const auto v = select_verdict(rep.constraints, rep.denied);
        CHECK(v.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(v.reason == "dmi:bios_version:eacces");
    }
}

TEST_CASE("hresult_from_token: extracts only a trailing 0x<8 hex digits>", "[firmware_posture]") {
    CHECK(hresult_from_token("wmi_connect_failed_0x80041003") == std::optional<std::uint32_t>{0x80041003u});
    CHECK(hresult_from_token("x_0x8004100E") == std::optional<std::uint32_t>{0x8004100Eu});
    CHECK_FALSE(hresult_from_token("wmi_deadline_exceeded").has_value());
    CHECK_FALSE(hresult_from_token("com_init_failed").has_value());
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x8004100").has_value()); // 7 digits
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x8004100g").has_value());
    CHECK_FALSE(hresult_from_token("wmi_query_failed_80041002").has_value());    // no 0x
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x80041002_x").has_value()); // not at the tail
    CHECK_FALSE(hresult_from_token("").has_value());
}

// The stage-aware WMI error classification. Fails under: any absence-looking HRESULT reading as a
// definitive `absent` with no token where WMI is not actually answering "missing" (NOT_FOUND
// anywhere, an enumeration-stage NOT_FOUND / INVALID_NAMESPACE, a connect-stage INVALID_CLASS);
// and, in the other direction, under losing the `absent` the earlier governance contract
// (FV-CODEX-01) requires for a MISSING namespace (INVALID_NAMESPACE at connect) or class
// (INVALID_CLASS at query, or at the first Next(): the query is semisynchronous, see
// tests/unit/test_wmi_bounded.cpp, so a missing class can arrive there); and under granting
// `absent` to INVALID_CLASS at a Next() that follows a returned row.
TEST_CASE("classify_wmi_error_token: absent only for the two answers WMI gives when something is missing",
          "[firmware_posture]") {
    // exactly three cells read absent
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x8004100e") == ReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041010") == ReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010") == ReadOutcome::absent);
    // NOT_FOUND is never a "missing" answer here: Microsoft lists it as a repository-corruption symptom
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80041002") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041002") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041002") == ReadOutcome::failed);
    // a namespace answer at a stage that cannot produce it, and a class answer at connect
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80041010") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x8004100e") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x8004100e") == ReadOutcome::failed);
    // INVALID_CLASS at Next() after a row was already returned: the class just answered, so this is
    // a fault, never absence (the token has no iteration index; wmi_bounded records the row count)
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 0) == ReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 1) == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 512) == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041010", 0) == ReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041003", 3) == ReadOutcome::denied);
    // the proxy blanket runs before the query and carries no WBEM schema answer
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x80041002") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x80041010") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x8004100e") == ReadOutcome::failed);
    // A refusal is a refusal at every stage.
    for (const char* stage : {"wmi_connect_failed_", "wmi_query_failed_", "wmi_proxy_blanket_failed_",
                              "wmi_next_failed_"}) {
        INFO(stage);
        CHECK(classify_wmi_error_token(std::string{stage} + "0x80041003") == ReadOutcome::denied);
        CHECK(classify_wmi_error_token(std::string{stage} + "0x80070005") == ReadOutcome::denied);
    }
    // No HRESULT, an unrelated HRESULT, or an HRESULT of 0: always a failed read.
    CHECK(classify_wmi_error_token("wmi_deadline_exceeded") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("com_init_failed") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_no_in_signature") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80004005") == ReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x00000000") == ReadOutcome::failed);
}

// The Windows failed-WMI mapping the leg applies. Fails under: a runtime fault (NOT_FOUND at any
// stage) writing the explicit absent rows with no token (the false absence the governance review
// found), a missing namespace or class no longer writing them (FV-CODEX-01), a class error after
// a returned row writing them, or a refusal not setting the denial flag.
TEST_CASE("apply_wmi_error_token: absent rows only for a missing namespace or class; else unreadable plus a token",
          "[firmware_posture]") {
    {   // a missing CLASS arrives at the first Next() as INVALID_CLASS: explicit absent rows, OK
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_next_failed_0x80041010", 0);
        REQUIRE(rep.rows.size() == 3);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|absent|wmi");
        CHECK_FALSE(rep.constraints.any_failure());
        CHECK_FALSE(rep.denied);
        CHECK(select_verdict(rep.constraints, rep.denied).status == YUZU_RESULT_STATUS_OK);
    }
    {   // one row came back, THEN the enumeration failed with INVALID_CLASS: a fault, never absence
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_next_failed_0x80041010", 1);
        REQUIRE(rep.rows.size() == 1);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|unreadable|wmi");
        const auto v = select_verdict(rep.constraints, rep.denied);
        CHECK(v.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(v.reason == "wmi:wmi_next_failed_0x80041010");
    }
    {   // a missing namespace at connect: explicit absent rows, OK
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_connect_failed_0x8004100e", 0);
        REQUIRE(rep.rows.size() == 3);
        CHECK_FALSE(rep.constraints.any_failure());
        CHECK_FALSE(rep.denied);
    }
    {   // NOT_FOUND at connect (a repository-corruption symptom): one unreadable row and a token
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_connect_failed_0x80041002", 0);
        REQUIRE(rep.rows.size() == 1);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|unreadable|wmi");
        CHECK(select_verdict(rep.constraints, rep.denied).reason == "wmi:wmi_connect_failed_0x80041002");
    }
    {   // a runtime fault at enumeration: one unreadable row and a token, never absent
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_next_failed_0x80041002", 0);
        REQUIRE(rep.rows.size() == 1);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|unreadable|wmi");
        const auto v = select_verdict(rep.constraints, rep.denied);
        CHECK(v.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(v.reason == "wmi:wmi_next_failed_0x80041002");
        CHECK(v.rc == 1);
    }
    {   // a refusal at any stage sets the denial flag and keeps its token
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_next_failed_0x80041003", 0);
        CHECK(rep.denied);
        const auto v = select_verdict(rep.constraints, rep.denied);
        CHECK(v.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(v.reason == "wmi:wmi_next_failed_0x80041003");
    }
    {   // a deadline overrun carries no HRESULT: failed
        FirmwareReport rep;
        apply_wmi_error_token(rep, "wmi_deadline_exceeded", 0);
        CHECK(row_str(rep.rows.at(0)) == "firmware|vendor|unreadable|wmi");
        CHECK(select_verdict(rep.constraints, rep.denied).reason == "wmi:wmi_deadline_exceeded");
    }
}

TEST_CASE("apply_smbios_call_failed: no RSMB provider is an explicit absent row; other errors are unreadable plus a token",
          "[firmware_posture]") {
    {   // ERROR_FILE_NOT_FOUND (2): no provider, explicit absent rows, no token
        FirmwareReport rep;
        apply_smbios_call_failed(rep, 2);
        REQUIRE(rep.rows.size() == 3);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|absent|smbios");
        CHECK_FALSE(rep.constraints.any_failure());
        CHECK_FALSE(rep.denied);
    }
    {   // ERROR_ACCESS_DENIED (5): refusal
        FirmwareReport rep;
        apply_smbios_call_failed(rep, 5);
        REQUIRE(rep.rows.size() == 1);
        CHECK(row_str(rep.rows[0]) == "firmware|vendor|unreadable|smbios");
        CHECK(rep.denied);
        CHECK(select_verdict(rep.constraints, rep.denied).reason == "smbios:win32_5");
    }
    {   // ERROR_INSUFFICIENT_BUFFER (122) and ERROR_DIRECTORY-like (267): failed, never absent
        for (std::uint32_t e : {122u, 267u, 1168u}) {
            FirmwareReport rep;
            apply_smbios_call_failed(rep, e);
            REQUIRE(rep.rows.size() == 1);
            CHECK(row_str(rep.rows[0]) == "firmware|vendor|unreadable|smbios");
            const auto v = select_verdict(rep.constraints, rep.denied);
            CHECK(v.status == YUZU_RESULT_STATUS_CONSTRAINED);
            CHECK(v.reason == "smbios:win32_" + std::to_string(e));
        }
    }
}

// The failed GetUpgrades mapping (one call per updatable device). Fails under: `denied` losing its
// flag, NothingToDo recording a token, or a failure recording none.
// A refusal recorded earlier must survive a later non-refusal failure: the verdict stays
// PERMISSION_DENIED and keeps both tokens. Fails under: `denied` being overwritten instead of OR-ed.
TEST_CASE("FirmwareReport: a refusal stays sticky across a later non-refusal failure", "[firmware_posture]") {
    FirmwareReport rep;
    rep.fail("vendor", kSrcSmbios, "smbios:win32_5", true);
    apply_wmi_error_token(rep, "wmi_next_failed_0x80041002", 0); // a non-refusal fault afterwards
    CHECK(rep.denied);
    const auto v = select_verdict(rep.constraints, rep.denied);
    CHECK(v.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(v.reason == "smbios:win32_5,wmi:wmi_next_failed_0x80041002");
}

TEST_CASE("apply_upgrades_failure: NothingToDo continues; denied and failed record a token",
          "[firmware_posture]") {
    {
        FirmwareReport rep;
        CHECK(apply_upgrades_failure(rep, classify_fwupd_error("org.freedesktop.fwupd.NothingToDo", 0), "errno_0"));
        CHECK_FALSE(rep.constraints.any_failure());
        CHECK(rep.rows.empty());
    }
    {
        FirmwareReport rep;
        CHECK_FALSE(apply_upgrades_failure(rep, classify_fwupd_error("org.freedesktop.DBus.Error.AccessDenied", 0), "errno_0"));
        CHECK(rep.denied);
        CHECK(rep.rows.empty());
        CHECK(select_verdict(rep.constraints, rep.denied).reason == "fwupd:get_upgrades:permission_denied");
    }
    for (const auto o : {FwupdOutcome::failed, FwupdOutcome::unavailable}) {
        FirmwareReport rep;
        CHECK_FALSE(apply_upgrades_failure(rep, o, "etimedout"));
        CHECK_FALSE(rep.denied);
        CHECK(rep.rows.empty()); // the device row comes from the mapper, not from this failure
        CHECK(select_verdict(rep.constraints, rep.denied).reason == "fwupd:get_upgrades:etimedout");
    }
}

// Fails under: any arm swapping status (the one function every leg shares).
TEST_CASE("select_verdict: absent/unavailable stay OK; failures constrain; refusals deny", "[firmware_posture]") {
    FirmwareReport ok;
    ok.add({"vendor", "absent", "dmi"});
    ok.add(fwupd_unavailable_row());
    auto v = select_verdict(ok.constraints, ok.denied);
    CHECK((v.status == YUZU_RESULT_STATUS_OK && v.completeness == YUZU_RESULT_COMPLETENESS_FULL && v.rc == 0));

    FirmwareReport failed;
    failed.fail("version", "dmi", "dmi:bios_version:unreadable");
    failed.note_failure("fwupd:shape");
    failed.note_failure("fwupd:shape"); // exact-string dedupe
    CHECK(row_str(failed.rows[0]) == "firmware|version|unreadable|dmi");
    v = select_verdict(failed.constraints, failed.denied);
    CHECK((v.status == YUZU_RESULT_STATUS_CONSTRAINED && v.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL));
    CHECK(v.reason == "dmi:bios_version:unreadable,fwupd:shape");
    CHECK(v.rc == 1);

    FirmwareReport denied;
    denied.fail("version", "smbios", "smbios:permission_denied", true);
    CHECK(select_verdict(denied.constraints, denied.denied).status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
}

TEST_CASE("format_row escapes untrusted fields; the catch-all row is exact", "[firmware_posture]") {
    CHECK(format_row({"vendor", "a|b\\c", "dmi"}) == "firmware|vendor|a\\|b/c|dmi");
    CHECK(format_internal_error_row() == "constrained|internal_error");
}

// ── fwupd a{sv} mapping (RECONSTRUCTED maps: DeviceId, Name, Version, Flags decimal, and the
// leg-supplied HasUpgrades). Flags: 2 = UPDATABLE, 256 = NEEDS_REBOOT, 1<<20 = beyond named bits.

TEST_CASE("fwupd_device_rows: flags bitmask, update-pending and unmodelled bits", "[firmware_posture][fwupd]") {
    const auto r = fwupd_device_rows(
        {{{"DeviceId", "abc"}, {"Name", "System Firmware"}, {"Version", "1.2.3"}, {"Flags", "258"}, {"HasUpgrades", "true"}},
         {{"DeviceId", "def"}, {"Name", "NVMe"}, {"Version", "9"}, {"Flags", "1"}, {"HasUpgrades", "false"}},
         {{"DeviceId", "ghi"}, {"Name", "Dock"}, {"Version", "4"}, {"Flags", "1048578"}}}); // 1<<20 | 2
    REQUIRE(r.failures.empty());
    REQUIRE(r.rows.size() == 4);
    CHECK(row_str(r.rows[0]) == "firmware|fwupd_device|id=abc;name=System Firmware;version=1.2.3;updatable=yes;"
                                "needs_reboot=yes;update_pending=yes;unmodelled=no|fwupd");
    CHECK(row_str(r.rows[1]) == "firmware|fwupd_device|id=def;name=NVMe;version=9;updatable=no;"
                                "needs_reboot=no;update_pending=no;unmodelled=no|fwupd");
    CHECK(row_str(r.rows[2]) == "firmware|fwupd_device|id=ghi;name=Dock;version=4;updatable=yes;"
                                "needs_reboot=no;update_pending=unknown;unmodelled=yes|fwupd");
    CHECK(row_str(r.rows[3]) == "firmware|update_pending|yes|fwupd");
}

// Fails under: counting non-updatable devices, or treating `unknown` as `no`.
TEST_CASE("fwupd_device_rows: aggregate update_pending", "[firmware_posture][fwupd]") {
    CHECK(fwupd_device_rows({}).update_pending == "no");
    CHECK(fwupd_device_rows({{{"DeviceId", "a"}, {"Flags", "2"}, {"HasUpgrades", "false"}}}).update_pending == "no");
    CHECK(fwupd_device_rows({{{"DeviceId", "a"}, {"Flags", "2"}}}).update_pending == "unknown");
    CHECK(fwupd_device_rows({{{"DeviceId", "a"}, {"Flags", "1"}, {"HasUpgrades", "true"}}}).update_pending == "no");
}

// Fails under: emitting a partial row for a malformed device, or dropping the cap.
TEST_CASE("fwupd_device_rows: malformed devices and the cap are failure tokens", "[firmware_posture][fwupd]") {
    const auto r = fwupd_device_rows({{{"DeviceId", "a"}, {"Flags", "notanumber"}},
                                      {{"Name", "x"}, {"Flags", "2"}},
                                      {{"DeviceId", "b"}}});
    CHECK(r.failures == std::vector<std::string>{"fwupd:shape", "fwupd:shape", "fwupd:shape"});
    REQUIRE(r.rows.size() == 1); // only the aggregate row

    // An empty DeviceId is as malformed as a missing one.
    const auto blank = fwupd_device_rows({{{"DeviceId", ""}, {"Flags", "0"}}});
    CHECK(blank.failures == std::vector<std::string>{"fwupd:shape"});
    REQUIRE(blank.rows.size() == 1);

    std::vector<FwupdDevice> many;
    for (std::size_t i = 0; i < kMaxFwupdDevices + 1; ++i)
        many.push_back({{"DeviceId", std::to_string(i)}, {"Flags", "0"}});
    const auto capped = fwupd_device_rows(many);
    CHECK(capped.failures == std::vector<std::string>{"fwupd:row_cap"});
    CHECK(capped.rows.size() == kMaxFwupdDevices + 1); // 256 devices + the aggregate

    CHECK(row_str(fwupd_unavailable_row()) == "firmware|update_pending|unavailable|fwupd");
}

// ── macOS IODeviceTree ───────────────────────────────────────────────────

TEST_CASE("decode_dt_string: REAL CAPTURE bytes decode; binary and empty do not", "[firmware_posture][macos]") {
    const auto cap = read_dt_capture();
    const auto& chosen = cap.at("IODeviceTree:/chosen");
    CHECK(*decode_dt_string(chosen.at("system-firmware-version")) == "mBoot-18000.161.10");
    REQUIRE(chosen.at("firmware-version").size() == 256); // NUL-padded buffer
    CHECK(*decode_dt_string(chosen.at("firmware-version")) == "mBoot-18000.161.10");
    CHECK_FALSE(decode_dt_string(Bytes{'a', 0x01, 'b', 0}).has_value()); // control byte
    CHECK_FALSE(decode_dt_string(Bytes{'a', 0, 'b', 0}).has_value());    // text after NUL
    CHECK_FALSE(decode_dt_string(Bytes{0, 0, 0}).has_value());           // empty
}

// Fails under: swapping the /rom-before-/chosen preference or the key order.
TEST_CASE("select_macos_firmware: REAL CAPTURE Apple Silicon takes /chosen system-firmware-version",
          "[firmware_posture][macos]") {
    const auto cap = read_dt_capture();
    REQUIRE(cap.at("IODeviceTree:/rom").empty()); // /rom is absent on this host
    Field model;
    model.value = "Mac16,10";
    // /rom's IORegistryEntryFromPath call itself returned MACH_PORT_NULL on this real Apple
    // Silicon host (per the header doc comment) -- lookup_failed=true models that fact.
    // Fails under: losing the hw.model architecture gate and treating this the same as an
    // unexplained failure on /chosen or / (which the next test case covers).
    const auto s = select_macos_firmware(dt_node(nullptr, /*lookup_failed=*/true),
                                         dt_node(&cap.at("IODeviceTree:/chosen")),
                                         dt_node(&cap.at("IODeviceTree:/")), model);
    CHECK(*s.version.value == "mBoot-18000.161.10");
    CHECK(s.version_source == "IODeviceTree:/chosen#system-firmware-version");
    CHECK(*s.vendor.value == "Apple Inc.");
    // The architecturally-expected /rom absence must never surface as unreadable.
    CHECK((!s.release_date.value.has_value() && !s.release_date.unreadable));
    const auto rows = macos_rows(s, model);
    REQUIRE(rows.size() == 5);
    CHECK(row_str(rows[0]) == "firmware|vendor|Apple Inc.|iokit");
    CHECK(row_str(rows[1]) == "firmware|version|mBoot-18000.161.10|iokit");
    CHECK(row_str(rows[2]) == "firmware|release_date|absent|iokit");
    CHECK(row_str(rows[3]) == "firmware|version_source|IODeviceTree:/chosen#system-firmware-version|iokit");
    CHECK(row_str(rows[4]) == "firmware|model|Mac16,10|sysctl");
}

// The reviewer's HIGH finding: a genuine IOKit lookup failure on /chosen or / must never read the
// same as an architecturally-expected absence, on ANY architecture -- those two nodes exist on
// every real Mac. Fails under: dropping the node_absence_is_expected gate so any lookup_failed
// node falls through to plain absent again.
TEST_CASE("select_macos_firmware: a failed /chosen or / lookup is always unreadable, never absent",
          "[firmware_posture][macos]") {
    Field apple_silicon_model;
    apple_silicon_model.value = "Mac16,10";

    // /chosen lookup failure on Apple Silicon: still unreadable, NOT absent -- /chosen is never
    // legitimately missing on any real Mac, so the architecture gate must not cover it.
    {
        const auto s = select_macos_firmware(dt_node(nullptr, /*lookup_failed=*/true),
                                             dt_node(nullptr, /*lookup_failed=*/true), DtNode{},
                                             apple_silicon_model);
        CHECK((!s.version.value.has_value() && s.version.unreadable));
    }
    // / (root) lookup failure: vendor becomes unreadable, not absent, even with a valid /rom
    // vendor fallback absent too.
    {
        DtNode rom;
        rom.props = {{"version", "MBP141.88Z.F000.B00.1904"}};
        const auto s = select_macos_firmware(rom, DtNode{}, dt_node(nullptr, /*lookup_failed=*/true),
                                             Field{});
        CHECK((!s.vendor.value.has_value() && s.vendor.unreadable));
    }
    // /rom lookup failure on an INTEL Mac (or an unreadable/absent hw.model) is NOT
    // architecturally expected -- unlike the Apple Silicon case above, this must be unreadable.
    {
        Field intel_model;
        intel_model.value = "MacBookPro16,1";
        auto s = select_macos_firmware(dt_node(nullptr, /*lookup_failed=*/true), DtNode{}, DtNode{},
                                       intel_model);
        CHECK((!s.version.value.has_value() && s.version.unreadable));
        // hw.model itself unreadable: treated as non-Apple-Silicon (never misclassified as the
        // architecturally-expected case on a signal we don't actually have).
        Field unreadable_model;
        unreadable_model.unreadable = true;
        s = select_macos_firmware(dt_node(nullptr, /*lookup_failed=*/true), DtNode{}, DtNode{},
                                  unreadable_model);
        CHECK((!s.version.value.has_value() && s.version.unreadable));
    }
}

TEST_CASE("is_apple_silicon_model: bare Mac+digits only, not an Intel product family",
          "[firmware_posture][macos]") {
    CHECK(is_apple_silicon_model("Mac16,10"));
    CHECK(is_apple_silicon_model("Mac14,2"));
    CHECK_FALSE(is_apple_silicon_model("MacBookPro16,1")); // Intel: family word before the digits
    CHECK_FALSE(is_apple_silicon_model("Macmini8,1"));     // Intel
    CHECK_FALSE(is_apple_silicon_model("MacPro7,1"));      // Intel
    CHECK_FALSE(is_apple_silicon_model(""));
    CHECK_FALSE(is_apple_silicon_model("Mac"));  // no digits at all
    CHECK_FALSE(is_apple_silicon_model("Macx")); // 4th char not a digit
}

TEST_CASE("node_absence_is_expected: only /rom, only on Apple Silicon", "[firmware_posture][macos]") {
    CHECK(node_absence_is_expected(kDtRom, /*apple_silicon=*/true));
    CHECK_FALSE(node_absence_is_expected(kDtRom, /*apple_silicon=*/false));
    CHECK_FALSE(node_absence_is_expected(kDtChosen, /*apple_silicon=*/true));
    CHECK_FALSE(node_absence_is_expected(kDtRoot, /*apple_silicon=*/true));
}

// ASSUMED SHAPE, not a capture: an Intel Mac's /rom keys (version, release-date, vendor).
TEST_CASE("select_macos_firmware: Intel /rom wins; undecodable and missing are distinct", "[firmware_posture][macos]") {
    DtNode rom, chosen;
    rom.props = {{"version", "MBP141.88Z.F000.B00.1904"}, {"release-date", "04/03/2019"}, {"vendor", "Apple Inc."}};
    chosen.props = {{"system-firmware-version", "mBoot-1"}};
    auto s = select_macos_firmware(rom, chosen, DtNode{}, Field{});
    CHECK(*s.version.value == "MBP141.88Z.F000.B00.1904");
    CHECK(s.version_source == "IODeviceTree:/rom#version");
    CHECK(row_str(macos_rows(s, Field{})[2]) == "firmware|release_date|2019-04-03|iokit");

    // Fails under: a present-but-undecodable key reading as `absent`.
    chosen.props.clear();
    chosen.undecodable = {"system-firmware-version", "firmware-version"};
    s = select_macos_firmware(DtNode{}, chosen, DtNode{}, Field{});
    CHECK(row_str(macos_rows(s, Field{})[1]) == "firmware|version|unreadable|iokit");
    s = select_macos_firmware(DtNode{}, DtNode{}, DtNode{}, Field{});
    CHECK((s.version_source == "absent" && row_str(macos_rows(s, Field{})[1]) == "firmware|version|absent|iokit"));
    // a later readable candidate clears an earlier unreadable one
    chosen.undecodable = {"system-firmware-version"};
    chosen.props = {{"firmware-version", "mBoot-2"}};
    s = select_macos_firmware(DtNode{}, chosen, DtNode{}, Field{});
    CHECK((*s.version.value == "mBoot-2" && !s.version.unreadable));
    CHECK(s.version_source == "IODeviceTree:/chosen#firmware-version");
}

// Definition contract: a REAL captured row splits into exactly the declared columns.
// The column order below is the spec.result.columns order in content/definitions/firmware_posture.yaml.
// The row literal is verbatim from agents/plugins/firmware_posture/docs/samples/macos.txt (this Mac,
// euid 501, 2026-09-21). Literal pins only: nothing is derived from format_row, the column list or
// the sample file at run time.
// Fails under: format_row gaining, losing or reordering a field; the leading tag changing; the
// catch-all row growing to four fields without the definition following.
TEST_CASE("firmware rows map onto the definition's declared columns", "[firmware_posture][definition]") {
    const std::vector<std::string> columns = {"row_kind", "field", "value", "source"};

    // Splits on unescaped '|'; a backslash keeps the next character in the field (the escape
    // safe_output_field emits). The sample row contains none.
    const auto split = [](const std::string& row) {
        std::vector<std::string> out{std::string{}};
        for (std::size_t i = 0; i < row.size(); ++i) {
            if (row[i] == '\\' && i + 1 < row.size()) {
                out.back() += row[i];
                out.back() += row[++i];
            } else if (row[i] == '|') {
                out.emplace_back();
            } else {
                out.back() += row[i];
            }
        }
        return out;
    };

    const std::string real_row = "firmware|version_source|IODeviceTree:/chosen#system-firmware-version|iokit";
    REQUIRE(format_row(FirmwareRow{"version_source", "IODeviceTree:/chosen#system-firmware-version", "iokit"}) ==
            real_row);
    const auto f = split(real_row);
    REQUIRE(f.size() == columns.size());
    CHECK(f[0] == "firmware");                                               // row_kind value
    CHECK(f[1] == "version_source");                                         // field value
    CHECK(f[2] == "IODeviceTree:/chosen#system-firmware-version");           // version-source text
    CHECK(f[3] == "iokit");                                                  // source value

    // The one mixed shape the columns describe: the catch-all row carries only row_kind + reason.
    const auto c = split(format_internal_error_row());
    REQUIRE(c.size() == 2);
    CHECK(c[0] == "constrained");     // row_kind value
    CHECK(c[1] == "internal_error");  // field value
}
