/**
 * test_hardware_estate_parsers.cpp -- the pure half of the hardware-estate legs
 * (agents/plugins/hardware/src/hardware_estate_parsers.hpp): row shapes, the outcome contract,
 * placeholder handling, the stable swap total, the machine_id row, and the appended
 * processors/memory column helpers.
 *
 * Portable: runs on every OS and never reads real hardware. The SMBIOS cases use the scrubbed
 * real capture (tests/unit/fixtures/hardware-estate/smbios/kingsley-rsmb.bin) plus hand-built
 * tables for the shapes a capture cannot hold (placeholder strings, malformed structures).
 */
#include <catch2/catch_test_macros.hpp>

#include "hardware_estate_emit.hpp" // result_code_for (the pure outcome -> typed-result mapping)
#include "hardware_estate_parsers.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace est = yuzu::hardware::estate;
namespace smbios = yuzu::shared::smbios;
namespace fs = std::filesystem;

namespace {

std::vector<std::uint8_t> read_fixture() {
    std::ifstream f(fs::path{YUZU_TEST_FIXTURE_DIR} / "hardware-estate" / "smbios" /
                        "kingsley-rsmb.bin",
                    std::ios::binary);
    std::vector<std::uint8_t> b((std::istreambuf_iterator<char>(f)), {});
    REQUIRE_FALSE(b.empty()); // an unreadable fixture must fail, not feed the tests empty input
    return b;
}

smbios::SmbiosTable table_with_chassis(unsigned type, std::optional<std::string> serial,
                                       std::optional<std::string> asset) {
    smbios::SmbiosTable t;
    t.chassis.status = smbios::Status::ok;
    t.chassis.data.chassis_type = type;
    t.chassis.data.serial = std::move(serial);
    t.chassis.data.asset_tag = std::move(asset);
    return t;
}

} // namespace

// -- status row and outcome mapping ----------------------------------------------------------

TEST_CASE("estate: status row levels map from the outcome", "[hardware_estate]") {
    est::Report r;
    CHECK(est::status_row_for("chassis", r) == "status|chassis|supported|-");
    r = est::Report::failure(est::Outcome::constrained, "smbios:truncated");
    CHECK(est::status_row_for("chassis", r) == "status|chassis|constrained|smbios:truncated");
    r = est::Report::failure(est::Outcome::denied, "smbios:win32_5");
    CHECK(est::status_row_for("chassis", r) == "status|chassis|constrained|smbios:win32_5");
    r = est::Report::failure(est::Outcome::unavailable, "smbios:absent");
    CHECK(est::status_row_for("chassis", r) == "status|chassis|unsupported|smbios:absent");
}

// -- field hygiene --------------------------------------------------------------------------

TEST_CASE("estate: clean_identity turns firmware filler into the absent marker", "[hardware_estate]") {
    CHECK(est::clean_identity("To Be Filled By O.E.M.") == "-");
    CHECK(est::clean_identity("  default string  ") == "-"); // case-insensitive, trimmed
    CHECK(est::clean_identity("") == "-");
    CHECK(est::clean_identity("   ") == "-");
    CHECK(est::clean_identity("Unknown") == "-");
    CHECK(est::clean_identity("CT32G56C46S5.C8BA   ") == "CT32G56C46S5.C8BA"); // right-trimmed
    CHECK(est::clean_identity("a|b") == "a\\|b");                              // pipe escaped
    CHECK(est::clean_identity_opt(std::nullopt) == "-");
    CHECK(est::clean_identity_opt(std::optional<std::string>{"X1"}) == "X1");
}

TEST_CASE("estate: firmware bytes that are not UTF-8 are scrubbed before they reach a row",
          "[hardware_estate]") {
    // SMBIOS strings are raw bytes. A byte outside well-formed UTF-8 would make the receiver reject
    // the whole CommandResponse, so each offending byte becomes '?' and the field keeps its shape.
    CHECK(est::clean_identity(std::string_view{"AB\xFF\xFE" "CD"}) == "AB??CD");
    CHECK(est::clean_identity(std::string_view{"AB\xC0\x80" "CD"}) == "AB??CD"); // overlong NUL
    CHECK(est::clean_identity(std::string("A\0B", 3)) == "A?B");                    // embedded NUL
    CHECK(est::clean_identity(std::string_view{"caf\xC3\xA9"}) == "caf\xC3\xA9");  // valid UTF-8 kept
    // scrubbing happens BEFORE the filler test, so a string that is only bad bytes is data, not filler
    CHECK(est::clean_identity(std::string_view{"\xFF"}) == "?");
    CHECK(est::clean_identity_opt(std::optional<std::string>{"X\x80Y"}) == "X?Y");
}

TEST_CASE("estate: an identity string is capped on a UTF-8 boundary", "[hardware_estate]") {
    // SMBIOS strings are bounded only by the 1 MiB table; the on-demand response is not clamped like
    // the daily record, so the field is capped. The cut never splits a multi-byte scalar.
    const std::string long_ascii(5000, 'A');
    CHECK(est::clean_identity(long_ascii).size() == est::kMaxIdentityBytes);
    std::string multi;
    for (int i = 0; i < 400; ++i) multi += "\xC3\xA9"; // 400 x U+00E9, 800 bytes
    const std::string cut = est::clean_identity(multi);
    CHECK(cut.size() <= est::kMaxIdentityBytes);
    CHECK(cut.size() % 2 == 0);            // whole scalars only
    CHECK(yuzu::shared::count_invalid_wire_bytes(cut) == 0);

    // The two inputs above put a lead byte exactly at offset 256 (256 is even), so the boundary
    // back-up never runs and they cannot tell a correct cut from a naive resize(256). These do:
    // a 1-byte prefix shifts every 2-byte scalar by one, and 3-byte scalars (256 % 3 == 1) always
    // straddle the cut. Each must back up to a scalar boundary and stay valid UTF-8.
    const std::string shifted = est::clean_identity("A" + multi);
    CHECK(yuzu::shared::count_invalid_wire_bytes(shifted) == 0);
    CHECK(shifted.size() == 255); // 'A' + 127 whole 2-byte scalars; the 128th would end at 257
    std::string euro; // U+20AC, 3 bytes
    for (int i = 0; i < 200; ++i) euro += "\xE2\x82\xAC";
    const std::string euro_cut = est::clean_identity(euro);
    CHECK(yuzu::shared::count_invalid_wire_bytes(euro_cut) == 0);
    CHECK(euro_cut.size() == 255); // 85 whole scalars; a naive cut at 256 splits the 86th
    // a 4-byte scalar straddling the cut
    std::string clef = "AB"; // U+1D11E, 4 bytes
    for (int i = 0; i < 100; ++i) clef += "\xF0\x9D\x84\x9E";
    const std::string clef_cut = est::clean_identity(clef);
    CHECK(yuzu::shared::count_invalid_wire_bytes(clef_cut) == 0);
    CHECK(clef_cut.size() <= est::kMaxIdentityBytes);
    // exactly at the cap is untouched
    CHECK(est::clean_identity(std::string(est::kMaxIdentityBytes, 'B')).size() == est::kMaxIdentityBytes);
}

// -- chassis / baseboard from SMBIOS ---------------------------------------------------------

TEST_CASE("estate: chassis from the real kingsley capture", "[hardware_estate]") {
    const auto bytes = read_fixture();
    const auto table = smbios::parse_rsmb(bytes);
    const est::Report r = est::chassis_report(table);
    CHECK(r.outcome == est::Outcome::ok);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].starts_with("chassis|Mini PC|")); // enclosure type 35 on the probe host
    CHECK(r.rows[0].ends_with("|smbios"));
    CHECK(est::status_row_for("chassis", r) == "status|chassis|supported|-");
}

TEST_CASE("estate: baseboard from the real kingsley capture", "[hardware_estate]") {
    const auto bytes = read_fixture();
    const auto table = smbios::parse_rsmb(bytes);
    const est::Report r = est::baseboard_report(table);
    CHECK(r.outcome == est::Outcome::ok);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].starts_with("baseboard|"));
    CHECK(r.rows[0].ends_with("|smbios"));
    // vendor|product|serial|source: exactly four data columns after the kind
    CHECK(std::count(r.rows[0].begin(), r.rows[0].end(), '|') == 4);
}

TEST_CASE("estate: filler in the chassis keeps the section ok and writes '-'", "[hardware_estate]") {
    // Most OEM machines ship filler in the asset tag; that is a definitive "none assigned", not a
    // failed read, so the section must NOT be constrained.
    const auto t = table_with_chassis(3, std::string{"To Be Filled By O.E.M."}, std::string{""});
    const est::Report r = est::chassis_report(t);
    CHECK(r.outcome == est::Outcome::ok);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0] == "chassis|Desktop|-|-|smbios");
}

TEST_CASE("estate: an undefined chassis type is '-', never a guessed name", "[hardware_estate]") {
    CHECK(est::chassis_report(table_with_chassis(0, "S1", "A1")).rows[0] == "chassis|-|S1|A1|smbios");
    CHECK(est::chassis_report(table_with_chassis(99, "S1", "A1")).rows[0] == "chassis|-|S1|A1|smbios");
    CHECK(est::chassis_report(table_with_chassis(35, "S1", "A1")).rows[0] ==
          "chassis|Mini PC|S1|A1|smbios");
    CHECK(est::chassis_report(table_with_chassis(36, "S1", "A1")).rows[0] ==
          "chassis|Stick PC|S1|A1|smbios");
}

TEST_CASE("estate: a malformed structure is constrained with no rows", "[hardware_estate]") {
    smbios::SmbiosTable t;
    t.chassis.status = smbios::Status::malformed;
    const est::Report r = est::chassis_report(t);
    CHECK(r.outcome == est::Outcome::constrained);
    CHECK(r.token == "smbios:chassis_malformed");
    CHECK(r.rows.empty());

    smbios::SmbiosTable b;
    b.baseboard.status = smbios::Status::malformed;
    const est::Report rb = est::baseboard_report(b);
    CHECK(rb.outcome == est::Outcome::constrained);
    CHECK(rb.token == "smbios:baseboard_malformed");
    CHECK(rb.rows.empty());
}

TEST_CASE("estate: an absent structure after a framing fault is that fault, not an absence",
          "[hardware_estate]") {
    smbios::SmbiosTable t;
    t.error = smbios::Error::truncated;
    CHECK(est::chassis_report(t).token == "smbios:truncated");
    CHECK(est::chassis_report(t).outcome == est::Outcome::constrained);
    t.error = smbios::Error::malformed;
    CHECK(est::baseboard_report(t).token == "smbios:malformed");
}

TEST_CASE("estate: a clean table with no such structure is a state, not a failure",
          "[hardware_estate]") {
    smbios::SmbiosTable t; // no error, both entries absent
    const est::Report c = est::chassis_report(t);
    CHECK(c.outcome == est::Outcome::ok);
    REQUIRE(c.rows.size() == 1);
    CHECK(c.rows[0] == "chassis|-|-|-|-");
    const est::Report b = est::baseboard_report(t);
    CHECK(b.outcome == est::Outcome::ok);
    REQUIRE(b.rows.size() == 1);
    CHECK(b.rows[0] == "baseboard|-|-|-|-");
}

TEST_CASE("estate: a decoded structure keeps its row but a later framing fault constrains the section",
          "[hardware_estate]") {
    // The walker's failure model: `error` set means the walk STOPPED, so the table was not fully
    // read and a consumer must surface a constraint token, never present the result as complete.
    // Entries decoded before the fault are valid and are kept.
    auto t = table_with_chassis(3, "S1", "A1");
    t.error = smbios::Error::truncated; // the walk stopped AFTER chassis was decoded
    const est::Report r = est::chassis_report(t);
    CHECK(r.outcome == est::Outcome::constrained);
    CHECK(r.token == "smbios:truncated");
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0] == "chassis|Desktop|S1|A1|smbios");
    CHECK(est::status_row_for("chassis", r) == "status|chassis|constrained|smbios:truncated");

    smbios::SmbiosTable b;
    b.baseboard.status = smbios::Status::ok;
    b.baseboard.data.manufacturer = "V";
    b.baseboard.data.product = "P";
    b.baseboard.data.serial = "S";
    b.error = smbios::Error::malformed;
    const est::Report rb = est::baseboard_report(b);
    CHECK(rb.outcome == est::Outcome::constrained);
    CHECK(rb.token == "smbios:malformed");
    REQUIRE(rb.rows.size() == 1);
    CHECK(rb.rows[0] == "baseboard|V|P|S|smbios");

    // and no fault at all stays ok (the common case)
    auto clean = table_with_chassis(3, "S1", "A1");
    CHECK(est::chassis_report(clean).outcome == est::Outcome::ok);
    CHECK(est::chassis_report(clean).token.empty());
}

TEST_CASE("estate: RSMB call failures", "[hardware_estate]") {
    auto f = est::rsmb_failure_report(est::RsmbFailure::call_failed, 2);
    CHECK(f.outcome == est::Outcome::unavailable);
    CHECK(f.token == "smbios:absent");
    f = est::rsmb_failure_report(est::RsmbFailure::call_failed, 3);
    CHECK(f.outcome == est::Outcome::unavailable);
    f = est::rsmb_failure_report(est::RsmbFailure::call_failed, 5);
    CHECK(f.outcome == est::Outcome::denied);
    CHECK(f.token == "smbios:win32_5");
    f = est::rsmb_failure_report(est::RsmbFailure::call_failed, 1450);
    CHECK(f.outcome == est::Outcome::constrained);
    CHECK(f.token == "smbios:win32_1450");
    CHECK(est::rsmb_failure_report(est::RsmbFailure::oversized, 0).token == "smbios:oversized");
    CHECK(est::rsmb_failure_report(est::RsmbFailure::size_race, 0).token == "smbios:size_race");
    CHECK(est::rsmb_failure_report(est::RsmbFailure::size_race, 0).rows.empty());
}

// -- machine_id -----------------------------------------------------------------------------

TEST_CASE("estate: machine_id row carries a keyed hash and never the raw id", "[hardware_estate]") {
    est::MachineIdRead read;
    read.value = "3f2a9c1e-77b4-4d0a-9a51-0c5be1d2a8f6";
    const est::Report r = est::machine_id_report(read);
    CHECK(r.outcome == est::Outcome::ok);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0] == "machine_id|40ac51d528153ea3962cfd69f25d3a9d8c918da8e824fc223d5c96a1c1a2b51c|"
                       "hmac-sha256-app-v1|registry");
    CHECK(r.rows[0].find("3f2a9c1e") == std::string::npos);
}

TEST_CASE("estate: machine_id failures are typed and carry no row", "[hardware_estate]") {
    est::MachineIdRead gone;
    gone.win32_error = 2;
    auto r = est::machine_id_report(gone);
    CHECK(r.outcome == est::Outcome::unavailable);
    CHECK(r.token == "windows:machine_guid:absent");
    CHECK(r.rows.empty());

    est::MachineIdRead denied;
    denied.win32_error = 5;
    r = est::machine_id_report(denied);
    CHECK(r.outcome == est::Outcome::denied);
    CHECK(r.token == "windows:machine_guid:win32_5");

    est::MachineIdRead other;
    other.win32_error = 13;
    r = est::machine_id_report(other);
    CHECK(r.outcome == est::Outcome::constrained);

    est::MachineIdRead empty;
    empty.value = "  {}  ";
    r = est::machine_id_report(empty);
    CHECK(r.outcome == est::Outcome::unavailable);
    CHECK(r.token == "windows:machine_guid:empty");
    CHECK(r.rows.empty());
}

// -- swap -----------------------------------------------------------------------------------

TEST_CASE("estate: swap total prefers the configured maximum (stable) over the allocation",
          "[hardware_estate]") {
    const std::vector<est::PageFile> files{{"C:\\pagefile.sys", 2048, 310}};
    const std::vector<est::PageFileSetting> fixed{{"C:\\PAGEFILE.SYS", 8192}}; // case-insensitive
    const est::Report r = est::swap_report(files, fixed);
    CHECK(r.outcome == est::Outcome::ok);
    REQUIRE(r.rows.size() == 1);
    // used_mb stays in the on-demand row; the daily writer drops it.
    CHECK(r.rows[0] == "swap|C:/pagefile.sys|8192|310|wmi");
}

TEST_CASE("estate: a system-managed page file falls back to the allocation", "[hardware_estate]") {
    const std::vector<est::PageFile> files{{"C:\\pagefile.sys", 2048, 310}};
    CHECK(est::swap_report(files, {}).rows[0] == "swap|C:/pagefile.sys|2048|310|wmi");
    // a setting with maximum 0 means "system managed" and must not zero the total
    const std::vector<est::PageFileSetting> managed{{"C:\\pagefile.sys", 0}};
    CHECK(est::swap_report(files, managed).rows[0] == "swap|C:/pagefile.sys|2048|310|wmi");
    // a setting for a different file does not apply
    const std::vector<est::PageFileSetting> other{{"D:\\pagefile.sys", 9999}};
    CHECK(est::swap_report(files, other).rows[0] == "swap|C:/pagefile.sys|2048|310|wmi");
}

TEST_CASE("estate: no page file is a definitive answer, not a failure", "[hardware_estate]") {
    const est::Report r = est::swap_report({}, {});
    CHECK(r.outcome == est::Outcome::ok);
    CHECK(r.rows.empty());
    CHECK(est::status_row_for("swap", r) == "status|swap|supported|-");
}

TEST_CASE("estate: a failed setting query constrains the swap section but keeps its rows",
          "[hardware_estate]") {
    const std::vector<est::PageFile> files{{"C:\\pagefile.sys", 2048, 0}};
    const est::Report r = est::swap_report(files, {}, "wmi:pagefile_setting:denied");
    CHECK(r.outcome == est::Outcome::constrained);
    CHECK(r.token == "wmi:pagefile_setting:denied");
    CHECK(r.rows.size() == 1);
}

TEST_CASE("estate: WMI failures map through the shared stage-aware classifier", "[hardware_estate]") {
    // class missing at query stage -> unavailable
    auto r = est::wmi_failure_report("pagefile_usage", "wmi_query_failed_0x80041010", 0);
    CHECK(r.outcome == est::Outcome::unavailable);
    CHECK(r.token == "wmi:pagefile_usage:absent");
    // refusal -> denied
    r = est::wmi_failure_report("pagefile_usage", "wmi_query_failed_0x80041003", 0);
    CHECK(r.outcome == est::Outcome::denied);
    // an ordinary fault -> constrained, and the token names the cause
    r = est::wmi_failure_report("pagefile_usage", "wmi_deadline_exceeded", 0);
    CHECK(r.outcome == est::Outcome::constrained);
    CHECK(r.token == "wmi:pagefile_usage:wmi_deadline_exceeded");
    // INVALID_CLASS delivered AFTER a row was read cannot mean "the class is missing"
    r = est::wmi_failure_report("pagefile_usage", "wmi_next_failed_0x80041010", 3);
    CHECK(r.outcome == est::Outcome::constrained);
}

// -- appended processors / memory columns ------------------------------------------------------

TEST_CASE("estate: stepping is the low nibble of CPUID EAX on x86/x64", "[hardware_estate]") {
    // BFEBFBFF000906EA: EAX = 0x000906EA -> stepping 0xA = 10
    CHECK(est::stepping_field("BFEBFBFF000906EA", est::kArchX64, "") == "10");
    CHECK(est::stepping_field("bfebfbff000906ea", est::kArchX64, "") == "10"); // lower-case hex
    CHECK(est::stepping_field("178BFBFF00A20F10", est::kArchX86, "") == "0");  // AMD, stepping 0
    CHECK(est::stepping_field("0000000000000003", est::kArchX64, "9") == "3"); // id wins over property
}

TEST_CASE("estate: an ABSENT architecture is not x86", "[hardware_estate]") {
    // wmi_row_uint32 returns 0 for a missing property and 0 is kArchX86; the caller must pass
    // nullopt instead, and the CPUID nibble must not be read out of an id of unknown provenance.
    CHECK(est::stepping_field("BFEBFBFF000906EA", std::nullopt, "") == "-");
    CHECK(est::stepping_field("BFEBFBFF000906EA", std::nullopt, "3") == "3");
    CHECK(est::stepping_field("BFEBFBFF000906EA", std::optional<std::uint32_t>{est::kArchX86}, "") == "10");
}

TEST_CASE("estate: stepping falls back to the class property, else '-'", "[hardware_estate]") {
    constexpr std::uint32_t kArm64 = 12;
    CHECK(est::stepping_field("", kArm64, "2") == "2");
    CHECK(est::stepping_field("", kArm64, " 2 ") == "2");
    CHECK(est::stepping_field("", kArm64, "") == "-");
    CHECK(est::stepping_field("", kArm64, "abc") == "-");
    CHECK(est::stepping_field("", kArm64, "12345") == "-"); // implausible width
    // x64 with an unusable ProcessorId (wrong length / not hex) uses the property or '-'
    CHECK(est::stepping_field("BFEBFBFF", est::kArchX64, "7") == "7");
    CHECK(est::stepping_field("ZZEBFBFF000906EA", est::kArchX64, "") == "-");
    CHECK(est::stepping_field("", est::kArchX64, "") == "-");
}

TEST_CASE("estate: socket and DIMM identity columns", "[hardware_estate]") {
    CHECK(est::socket_designation_field("FP8") == "FP8");
    CHECK(est::socket_designation_field("To Be Filled By O.E.M.") == "-");
    CHECK(est::socket_designation_field("") == "-");
    CHECK(est::dimm_identity_field("Micron Technology") == "Micron Technology");
    CHECK(est::dimm_identity_field("Unknown") == "-");
    CHECK(est::dimm_identity_field("CT32G56C46S5.C8BA  ") == "CT32G56C46S5.C8BA");
    CHECK(est::dimm_identity_field("") == "-");
}

TEST_CASE("estate: DIMM identity from the real capture, filler included", "[hardware_estate]") {
    const auto bytes = read_fixture();
    const auto table = smbios::parse_rsmb(bytes);
    REQUIRE(table.memory_devices.size() >= 2);
    // One populated module reports real strings, the other reports "Unknown" filler; the field
    // helper must keep the first and blank the second.
    bool saw_real = false, saw_filler = false;
    for (const auto& m : table.memory_devices) {
        if (m.status != smbios::Status::ok || !m.data.manufacturer) continue;
        const std::string f = est::dimm_identity_field(*m.data.manufacturer);
        if (f == "-") saw_filler = true;
        else saw_real = true;
    }
    CHECK(saw_real);
    CHECK(saw_filler);
}

// -- Windows cpu / dimm row formatters: the escape that closes S-1 ----------------------------------

TEST_CASE("estate: cpu row formatter escapes WMI text so it cannot shift columns or forge a row",
          "[hardware_estate]") {
    // ordinary values are byte-for-byte what the plugin always wrote
    CHECK(est::format_cpu_row(0, "Intel(R) Core(TM) Ultra 5 125H", 14, 18, 1200, "U3E1", "4") ==
          "cpu|0|Intel(R) Core(TM) Ultra 5 125H|14|18|1200|U3E1|4");
    // a '|' in the model would add a column; it is escaped, so the row keeps exactly 8 raw fields
    const std::string r = est::format_cpu_row(1, "Fab|Cpu", 2, 4, 3000, "-", "-");
    CHECK(r == "cpu|1|Fab\\|Cpu|2|4|3000|-|-");
    // a newline would forge a second row
    const std::string nl = est::format_cpu_row(0, "A\nB", 1, 1, 1, "-", "-");
    CHECK(nl.find('\n') == std::string::npos);
    CHECK(nl.find('\r') == std::string::npos);
}

TEST_CASE("estate: dimm row formatter escapes the slot and keeps the column order", "[hardware_estate]") {
    CHECK(est::format_dimm_row("Controller1-ChannelA-DIMM0", 32768, "DDR5", 5600, "Micron Technology",
                               "CT32G56C46S5.C8BA", "0A1B2C3D") ==
          "dimm|Controller1-ChannelA-DIMM0|32768|DDR5|5600|Micron Technology|CT32G56C46S5.C8BA|0A1B2C3D");
    const std::string r = est::format_dimm_row("DIMM|A", 8192, "DDR4", 3200, "-", "-", "-");
    CHECK(r == "dimm|DIMM\\|A|8192|DDR4|3200|-|-|-");
    CHECK(est::format_dimm_row("A\nB", 1, "DDR4", 1, "-", "-", "-").find('\n') == std::string::npos);
}

// -- swap: the constraint precedence the Windows TU delegates here --------------------------------------

TEST_CASE("estate: swap constraint precedence", "[hardware_estate]") {
    const auto none = std::optional<est::Report>{};
    const auto denied = std::optional<est::Report>{est::Report::failure(est::Outcome::denied, "wmi:pagefile_setting:x")};
    const auto missing = std::optional<est::Report>{est::Report::failure(est::Outcome::unavailable, "wmi:pagefile_setting:absent")};
    const auto faulty = std::optional<est::Report>{est::Report::failure(est::Outcome::constrained, "wmi:pagefile_setting:f")};

    CHECK(est::swap_constraint_token(false, none, false).empty());
    // usage cap wins over everything
    CHECK(est::swap_constraint_token(true, faulty, true) == "wmi:pagefile_usage:row_cap");
    // a failed setting query constrains; a MISSING setting class does not (no configured maximum)
    CHECK(est::swap_constraint_token(false, denied, false) == "wmi:pagefile_setting:x");
    CHECK(est::swap_constraint_token(false, faulty, false) == "wmi:pagefile_setting:f");
    CHECK(est::swap_constraint_token(false, missing, false).empty());
    CHECK(est::swap_constraint_token(false, missing, true).empty()); // a failed query has no rows to cap
    // a capped setting list (query succeeded) can miss a configured maximum
    CHECK(est::swap_constraint_token(false, none, true) == "wmi:pagefile_setting:row_cap");
    // a failure outranks a cap
    CHECK(est::swap_constraint_token(false, faulty, true) == "wmi:pagefile_setting:f");
}

// -- the typed result an outcome is reported with ---------------------------------------------------------

TEST_CASE("estate: every outcome maps to the typed result its status-row level promises",
          "[hardware_estate]") {
    using est::Outcome;
    using yuzu::shared::StatusLevel;
    for (Outcome o : {Outcome::ok, Outcome::constrained, Outcome::denied, Outcome::unavailable}) {
        INFO("outcome " << static_cast<int>(o));
        const est::ResultCode rc = est::result_code_for(o);
        switch (est::status_level_of(o)) {
        case StatusLevel::supported:   CHECK(rc.status == YUZU_RESULT_STATUS_OK); break;
        case StatusLevel::unsupported: CHECK(rc.status == YUZU_RESULT_STATUS_UNAVAILABLE); break;
        case StatusLevel::constrained:
            CHECK((rc.status == YUZU_RESULT_STATUS_CONSTRAINED ||
                   rc.status == YUZU_RESULT_STATUS_PERMISSION_DENIED));
            break;
        }
    }
    // exact pairs the writer and the README promise
    CHECK(est::result_code_for(Outcome::ok).status == YUZU_RESULT_STATUS_OK);
    CHECK(est::result_code_for(Outcome::ok).completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK_FALSE(est::result_code_for(Outcome::ok).carries_token); // a clean read records no reason
    CHECK(est::result_code_for(Outcome::constrained).status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(est::result_code_for(Outcome::denied).status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(est::result_code_for(Outcome::denied).completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(est::result_code_for(Outcome::unavailable).status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(est::result_code_for(Outcome::unavailable).completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    for (Outcome o : {Outcome::constrained, Outcome::denied, Outcome::unavailable})
        CHECK(est::result_code_for(o).carries_token); // a degraded read always names why
}
