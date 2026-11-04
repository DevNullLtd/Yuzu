// Pure layer of the Windows disk_actions `partitions` leg (disk_actions_partitions.hpp).
// No OS call: the rows below are the shapes Win32_DiskPartition and Win32_LogicalDiskToPartition
// returned on a real GPT host (bigsenga, Windows 11, one NVMe disk, 2026-11-04), plus hostile and
// degraded variants of them.

#include <catch2/catch_test_macros.hpp>

#include "disk_actions_partitions.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace dp = yuzu::disk_actions::partitions;

namespace {

dp::Row part(const char* disk, const char* index, const char* size, const char* type,
             const char* device_id) {
    return {{"DiskIndex", disk}, {"Index", index}, {"Size", size}, {"Type", type},
            {"DeviceID", device_id}};
}

dp::Row assoc(const char* antecedent_id, const char* dependent_id) {
    return {{"Antecedent", std::string{R"(\\BIGSENGA\root\cimv2:Win32_DiskPartition.DeviceID=")"} +
                               antecedent_id + "\""},
            {"Dependent", std::string{R"(\\BIGSENGA\root\cimv2:Win32_LogicalDisk.DeviceID=")"} +
                              dependent_id + "\""}};
}

// Split on UNESCAPED '|' -- the consumer's rule (inventory_status_row.hpp: it does not unescape).
std::vector<std::string> cols(const std::string& row) {
    std::vector<std::string> out{std::string{}};
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            out.back() += "\\|";
            ++i;
        } else if (row[i] == '|') {
            out.emplace_back();
        } else {
            out.back() += row[i];
        }
    }
    return out;
}

dp::QueryOutcome ok(std::vector<dp::Row> rows) {
    dp::QueryOutcome q;
    q.rows = std::move(rows);
    return q;
}

dp::QueryOutcome failed(const char* token) {
    dp::QueryOutcome q;
    q.error = token;
    return q;
}

std::vector<dp::Row> bigsenga_partitions() {
    return {part("0", "0", "1073741824", "GPT: System", "Disk #0, Partition #0"),
            part("0", "1", "1021818437632", "GPT: Basic Data", "Disk #0, Partition #1"),
            part("0", "2", "1299185664", "GPT: Unknown", "Disk #0, Partition #2")};
}

} // namespace

TEST_CASE("partitions: the measured GPT host produces the expected rows",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()), ok({assoc("Disk #0, Partition #1", "C:")}));
    CHECK(rep.level == dp::Level::Ok);
    CHECK(rep.status_row == "status|partitions|supported|-");
    REQUIRE(rep.data_rows.size() == 3);
    CHECK(rep.data_rows[0] ==
          "partition|PhysicalDrive0|Disk #0, Partition #0|1073741824|GPT: System|-|wmi");
    // The drive letter is spelled the way `volumes` spells it ("C:/" once the backslash is folded).
    CHECK(rep.data_rows[1] ==
          "partition|PhysicalDrive0|Disk #0, Partition #1|1021818437632|GPT: Basic Data|C:/|wmi");
    CHECK(rep.data_rows[2] ==
          "partition|PhysicalDrive0|Disk #0, Partition #2|1299185664|GPT: Unknown|-|wmi");
}

TEST_CASE("partitions: every data row has exactly seven columns", "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()), ok({assoc("Disk #0, Partition #1", "C:")}));
    for (const auto& row : rep.data_rows)
        CHECK(cols(row).size() == 7);
}

TEST_CASE("partitions: row order does not depend on enumeration order", "[disk_actions_partitions]") {
    auto fwd = bigsenga_partitions();
    fwd.push_back(part("1", "0", "500", "Installable File System", "Disk #1, Partition #0"));
    auto rev = fwd;
    std::reverse(rev.begin(), rev.end());
    const auto a = dp::build_report(ok(fwd), ok({}));
    const auto b = dp::build_report(ok(rev), ok({}));
    CHECK(a.data_rows == b.data_rows);
    REQUIRE(a.data_rows.size() == 4);
    CHECK(a.data_rows[3].starts_with("partition|PhysicalDrive1|Disk #1, Partition #0|"));
}

TEST_CASE("partitions: a numeric sort, not a string sort, orders disks and partitions",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(
        ok({part("10", "0", "1", "t", "Disk #10, Partition #0"),
            part("2", "0", "1", "t", "Disk #2, Partition #0"),
            part("2", "10", "1", "t", "Disk #2, Partition #10"),
            part("2", "9", "1", "t", "Disk #2, Partition #9")}),
        ok({}));
    REQUIRE(rep.data_rows.size() == 4);
    CHECK(cols(rep.data_rows[0])[1] == "PhysicalDrive2");
    CHECK(cols(rep.data_rows[1])[2] == "Disk #2, Partition #9");
    CHECK(cols(rep.data_rows[2])[2] == "Disk #2, Partition #10");
    CHECK(cols(rep.data_rows[3])[1] == "PhysicalDrive10");
}

TEST_CASE("partitions: several drive letters are sorted and de-duplicated",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(
        ok({part("0", "1", "9", "t", "Disk #0, Partition #1")}),
        ok({assoc("Disk #0, Partition #1", "E:"), assoc("Disk #0, Partition #1", "c:"),
            assoc("Disk #0, Partition #1", "C:")}));
    REQUIRE(rep.data_rows.size() == 1);
    CHECK(cols(rep.data_rows[0])[5] == "C:/,E:/");
    CHECK(rep.level == dp::Level::Ok);
}

TEST_CASE("partitions: a link to a partition that is not listed is ignored, not an error",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok({part("0", "1", "9", "t", "Disk #0, Partition #1")}),
                                      ok({assoc("Disk #7, Partition #3", "Z:")}));
    CHECK(rep.level == dp::Level::Ok);
    CHECK(cols(rep.data_rows[0])[5] == "-");
}

TEST_CASE("partitions: the association query failing keeps the rows and says mount points are unknown",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()), failed("wmi_query_failed_0x80041001"));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.status_row ==
          "status|partitions|constrained|windows:partitions:mount_points:wmi_query_failed_0x80041001");
    REQUIRE(rep.data_rows.size() == 3);
    for (const auto& row : rep.data_rows) {
        CHECK(cols(row)[5] == "-");
        CHECK(cols(row)[6] == "wmi,mount_points_unread"); // "-" here is UNKNOWN, and the row says so
    }
}

TEST_CASE("partitions: an unparsable association is constrained, not a silent no-mount",
          "[disk_actions_partitions]") {
    dp::Row bad{{"Antecedent", "garbage"}, {"Dependent", R"(x:Win32_LogicalDisk.DeviceID="C:")"}};
    const auto rep = dp::build_report(ok(bigsenga_partitions()), ok({bad}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:mount_points:link_unparsed");
    CHECK(rep.data_rows.size() == 3);
}

TEST_CASE("partitions: a dependent that is not a drive letter is not a mount point",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok({part("0", "1", "9", "t", "Disk #0, Partition #1")}),
                                      ok({assoc("Disk #0, Partition #1", "\\\\?\\Volume{1}")}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(cols(rep.data_rows[0])[5] == "-");
}

TEST_CASE("partitions: a partition query that fails classifies by cause and keeps no rows",
          "[disk_actions_partitions]") {
    SECTION("access denied") {
        const auto rep = dp::build_report(failed("wmi_query_failed_0x80041003"), ok({}));
        CHECK(rep.level == dp::Level::Denied);
        CHECK(rep.data_rows.empty());
        CHECK(rep.status_row ==
              "status|partitions|constrained|windows:partitions:wmi_query_failed_0x80041003");
    }
    SECTION("E_ACCESSDENIED at connect") {
        CHECK(dp::build_report(failed("wmi_connect_failed_0x80070005"), ok({})).level ==
              dp::Level::Denied);
    }
    SECTION("class missing is unavailable, and the row word is unsupported") {
        const auto rep = dp::build_report(failed("wmi_query_failed_0x80041010"), ok({}));
        CHECK(rep.level == dp::Level::Unavailable);
        CHECK(rep.status_row ==
              "status|partitions|unsupported|windows:partitions:wmi_query_failed_0x80041010");
    }
    SECTION("namespace missing is unavailable") {
        CHECK(dp::build_report(failed("wmi_connect_failed_0x8004100E"), ok({})).level ==
              dp::Level::Unavailable);
    }
    SECTION("a deadline is a failed read, never an absence") {
        CHECK(dp::build_report(failed("wmi_deadline_exceeded"), ok({})).level ==
              dp::Level::Constrained);
    }
}

TEST_CASE("partitions: a row that cannot be named is skipped and the section is constrained",
          "[disk_actions_partitions]") {
    auto rows = bigsenga_partitions();
    rows.push_back(part("zero", "0", "1", "t", "Disk #?, Partition #0"));
    rows.push_back(part("0", "-1", "1", "t", "Disk #0, Partition #-1"));
    const auto rep = dp::build_report(ok(rows), ok({}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:row_unparsed");
    CHECK(rep.data_rows.size() == 3);
}

TEST_CASE("partitions: hitting the row cap keeps the rows and is constrained",
          "[disk_actions_partitions]") {
    auto q = ok(bigsenga_partitions());
    q.truncated = true;
    const auto rep = dp::build_report(q, ok({}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:row_cap");
    CHECK(rep.data_rows.size() == 3);
}

TEST_CASE("partitions: a truncated association query is constrained", "[disk_actions_partitions]") {
    auto links = ok({assoc("Disk #0, Partition #1", "C:")});
    links.truncated = true;
    const auto rep = dp::build_report(ok(bigsenga_partitions()), links);
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:mount_points:row_cap");
}

TEST_CASE("partitions: zero partitions with a clean read is a supported, empty section",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok({}), ok({}));
    CHECK(rep.level == dp::Level::Ok);
    CHECK(rep.status_row == "status|partitions|supported|-");
    CHECK(rep.data_rows.empty());
}

TEST_CASE("partitions: missing size and type render as '-' rather than 0 or empty",
          "[disk_actions_partitions]") {
    dp::Row r{{"DiskIndex", "0"}, {"Index", "4"}, {"DeviceID", "Disk #0, Partition #4"}};
    const auto rep = dp::build_report(ok({r}), ok({}));
    REQUIRE(rep.data_rows.size() == 1);
    const auto c = cols(rep.data_rows[0]);
    CHECK(c[3] == "-");
    CHECK(c[4] == "-");
    CHECK(rep.level == dp::Level::Ok);
}

TEST_CASE("partitions: a missing DeviceID is synthesised from the indexes",
          "[disk_actions_partitions]") {
    dp::Row r{{"DiskIndex", "3"}, {"Index", "2"}, {"Size", "5"}, {"Type", "t"}};
    const auto rep = dp::build_report(ok({r}), ok({}));
    REQUIRE(rep.data_rows.size() == 1);
    CHECK(cols(rep.data_rows[0])[2] == "Disk #3, Partition #2");
}

TEST_CASE("partitions: provider text cannot add a column or a row", "[disk_actions_partitions]") {
    auto rows = bigsenga_partitions();
    rows[1]["Type"] = "evil|extra\nnext|partition|PhysicalDrive9";
    rows[1]["DeviceID"] = "Disk #0, Partition #1";
    const auto rep = dp::build_report(ok(rows), ok({}));
    for (const auto& row : rep.data_rows) {
        CHECK(cols(row).size() == 7);
        CHECK(row.find('\n') == std::string::npos);
        CHECK(row.find('\r') == std::string::npos);
    }
    CHECK(rep.data_rows.size() == 3);
}

TEST_CASE("partitions: a hostile reason cannot forge a status column", "[disk_actions_partitions]") {
    const auto rep = dp::build_report(failed("wmi|query\nfailed"), ok({}));
    CHECK(rep.status_row.find('\n') == std::string::npos);
    CHECK(cols(rep.status_row).size() == 4);
}

TEST_CASE("partitions: strict unsigned parsing", "[disk_actions_partitions]") {
    using dp::detail::parse_u64;
    CHECK(parse_u64("0") == 0);
    CHECK(parse_u64("18446744073709551615") == 18446744073709551615ULL);
    CHECK_FALSE(parse_u64("18446744073709551616").has_value());
    CHECK_FALSE(parse_u64("99999999999999999999999").has_value());
    CHECK_FALSE(parse_u64("").has_value());
    CHECK_FALSE(parse_u64("+1").has_value());
    CHECK_FALSE(parse_u64("-1").has_value());
    CHECK_FALSE(parse_u64(" 1").has_value());
    CHECK_FALSE(parse_u64("1 ").has_value());
    CHECK_FALSE(parse_u64("0x10").has_value());
    CHECK_FALSE(parse_u64("1e3").has_value());
}

TEST_CASE("partitions: CIM object-path key extraction", "[disk_actions_partitions]") {
    using dp::detail::path_key_value;
    CHECK(path_key_value(R"(\\H\root\cimv2:Win32_LogicalDisk.DeviceID="C:")", "DeviceID") == "C:");
    CHECK(path_key_value(R"(x:Y.DeviceID="Disk #0, Partition #1")", "DeviceID") ==
          "Disk #0, Partition #1");
    SECTION("escaped quote and backslash are undone") {
        // Hoisted: MSVC's preprocessor mangles a raw string holding \" inside a CHECK argument.
        const std::string path = R"X(x:Y.DeviceID="a\"b\\c")X";
        CHECK(path_key_value(path, "DeviceID") == "a\"b\\c");
    }
    SECTION("an escaped quote does not end the value early") {
        const std::string path = R"X(x:Y.DeviceID="C:\"")X";
        CHECK(path_key_value(path, "DeviceID") == "C:\"");
    }
    SECTION("malformed inputs are nullopt") {
        CHECK_FALSE(path_key_value(R"(x:Y.DeviceID="C:)", "DeviceID").has_value());   // unterminated
        const std::string dangling = R"X(x:Y.DeviceID="C:\)X";
        CHECK_FALSE(path_key_value(dangling, "DeviceID").has_value()); // dangling escape
        CHECK_FALSE(path_key_value(R"(x:Y.Name="C:")", "DeviceID").has_value());      // wrong key
        CHECK_FALSE(path_key_value("", "DeviceID").has_value());
    }
}

TEST_CASE("partitions: drive-letter validation", "[disk_actions_partitions]") {
    using dp::detail::drive_letter_mount;
    CHECK(drive_letter_mount("C:") == "C:\\");
    CHECK(drive_letter_mount("d:") == "D:\\");
    CHECK_FALSE(drive_letter_mount("C").has_value());
    CHECK_FALSE(drive_letter_mount("C:\\").has_value());
    CHECK_FALSE(drive_letter_mount("1:").has_value());
    CHECK_FALSE(drive_letter_mount("").has_value());
    CHECK_FALSE(drive_letter_mount("CC:").has_value());
}
