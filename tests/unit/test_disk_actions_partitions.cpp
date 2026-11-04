// Pure layer of the Windows disk_actions `partitions` leg (disk_actions_partitions.hpp).
// No OS call. The EXPECTED output rows are the ones a real GPT host produced (bigsenga, Windows
// 11, one NVMe disk, 2026-11-04; agents/plugins/disk_actions/docs/samples/windows.txt). The INPUT
// WMI rows are reconstructed from that sample and the documented CIM object-path form, not a raw
// dump; the Windows-only live test in test_disk_actions_local_dispatcher.cpp checks the real
// provider's shapes on a Windows host. Hostile and degraded variants follow.

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

TEST_CASE("partitions: a link to a partition that is not listed means the layout moved between the queries",
          "[disk_actions_partitions]") {
    // The two queries are not a snapshot: an association naming a partition the first query did
    // not return is direct evidence a disk was attached or removed in between (or a layout this
    // class reports differently). The join is not trusted.
    const auto rep = dp::build_report(ok({part("0", "1", "9", "t", "Disk #0, Partition #1")}),
                                      ok({assoc("Disk #7, Partition #3", "Z:")}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:mount_points:unmatched_link");
    REQUIRE(rep.data_rows.size() == 1);
    CHECK(cols(rep.data_rows[0])[5] == "-");
    CHECK(cols(rep.data_rows[0])[6] == "wmi,mount_points_partial");
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
    REQUIRE(rep.data_rows.size() == 3);
    // Every "-" here may be a row we could not read, and each row says so.
    for (const auto& row : rep.data_rows) {
        CHECK(cols(row)[5] == "-");
        CHECK(cols(row)[6] == "wmi,mount_points_partial");
    }
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
    // The classifier is the shared, stage-aware one (agents/shared/wmi_error_token.hpp, whose own
    // matrix is pinned in test_wmi_error_token.cpp); these pin that this leg uses it.
    SECTION("INVALID_CLASS at the connect stage is a fault, not an absence") {
        CHECK(dp::build_report(failed("wmi_connect_failed_0x80041010"), ok({})).level ==
              dp::Level::Constrained);
    }
    SECTION("INVALID_NAMESPACE at the query stage is a fault, not an absence") {
        CHECK(dp::build_report(failed("wmi_query_failed_0x8004100e"), ok({})).level ==
              dp::Level::Constrained);
    }
    SECTION("INVALID_CLASS at the first Next() is an absence, after data came back it is a fault") {
        auto first = failed("wmi_next_failed_0x80041010");
        CHECK(dp::build_report(first, ok({})).level == dp::Level::Unavailable);
        auto later = failed("wmi_next_failed_0x80041010");
        later.rows_before_error = 2;
        CHECK(dp::build_report(later, ok({})).level == dp::Level::Constrained);
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
    REQUIRE(rep.data_rows.size() == 3);
    // The matched partition keeps its letter; EVERY row says the join is incomplete (a second
    // letter on a matched partition could be in the part that was cut off).
    CHECK(cols(rep.data_rows[1])[5] == "C:/");
    for (const auto& row : rep.data_rows)
        CHECK(cols(row)[6] == "wmi,mount_points_partial");
}

TEST_CASE("partitions: a clean read with zero partitions is constrained, never an empty success",
          "[disk_actions_partitions]") {
    // A booted Windows host always has a system partition, so S_OK with nothing is a provider
    // fault. (volumes follows the same rule with a placeholder row; here the status row is the
    // authoritative signal.)
    const auto rep = dp::build_report(ok({}), ok({}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.status_row == "status|partitions|constrained|windows:partitions:no_rows");
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
    rows[1]["DeviceID"] = "Disk #0|x\r\npartition|PhysicalDrive9, Partition #1";
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
    using dp::impl::parse_u64;
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
    using dp::impl::path_key_value;
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
    using dp::impl::drive_letter_mount;
    CHECK(drive_letter_mount("C:") == "C:\\");
    CHECK(drive_letter_mount("d:") == "D:\\");
    CHECK_FALSE(drive_letter_mount("C").has_value());
    CHECK_FALSE(drive_letter_mount("C:\\").has_value());
    CHECK_FALSE(drive_letter_mount("1:").has_value());
    CHECK_FALSE(drive_letter_mount("").has_value());
    CHECK_FALSE(drive_letter_mount("CC:").has_value());
}

TEST_CASE("partitions: ties on (disk, index) sort the same whatever the enumeration order",
          "[disk_actions_partitions]") {
    auto a = part("0", "1", "100", "GPT: Basic Data", "Disk #0, Partition #1");
    auto b = part("0", "1", "200", "GPT: Basic Data", "Disk #0, Partition #1 (dup)");
    const auto fwd = dp::build_report(ok({a, b}), ok({}));
    const auto rev = dp::build_report(ok({b, a}), ok({}));
    CHECK(fwd.data_rows == rev.data_rows);
}

TEST_CASE("partitions: an unusable Size is '-' and a missing DiskIndex skips the row",
          "[disk_actions_partitions]") {
    SECTION("past uint64 and non-numeric sizes render '-', not a wrapped number") {
        const auto rep = dp::build_report(
            ok({part("0", "0", "18446744073709551616", "t", "Disk #0, Partition #0"),
                part("0", "1", "12abc", "t", "Disk #0, Partition #1")}),
            ok({}));
        REQUIRE(rep.data_rows.size() == 2);
        CHECK(cols(rep.data_rows[0])[3] == "-");
        CHECK(cols(rep.data_rows[1])[3] == "-");
    }
    SECTION("Index without DiskIndex cannot be named") {
        dp::Row r{{"Index", "0"}, {"Size", "5"}, {"DeviceID", "Disk #?, Partition #0"}};
        const auto rep = dp::build_report(ok({r}), ok({}));
        CHECK(rep.data_rows.empty());
        CHECK(rep.level == dp::Level::Constrained);
    }
}

TEST_CASE("partitions: one drive letter on two partitions is reported on both",
          "[disk_actions_partitions]") {
    // A spanned or mirrored volume can be associated with more than one partition.
    const auto rep = dp::build_report(
        ok({part("0", "0", "1", "t", "Disk #0, Partition #0"),
            part("1", "0", "1", "t", "Disk #1, Partition #0")}),
        ok({assoc("Disk #0, Partition #0", "D:"), assoc("Disk #1, Partition #0", "D:")}));
    REQUIRE(rep.data_rows.size() == 2);
    CHECK(cols(rep.data_rows[0])[5] == "D:/");
    CHECK(cols(rep.data_rows[1])[5] == "D:/");
}

TEST_CASE("partitions: the Level -> typed result status mapping", "[disk_actions_partitions]") {
    using dp::Level;
    // A clean read declares NOTHING: the agent derives OK with an empty provenance (as smart and
    // volumes do), so the stored section carries no reason and no FULL-completeness claim.
    CHECK_FALSE(dp::typed_status(Level::Ok).declare);
    CHECK(dp::typed_status(Level::Ok).status == YUZU_RESULT_STATUS_UNDECLARED);

    const auto c = dp::typed_status(Level::Constrained);
    CHECK(c.declare);
    CHECK(c.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(c.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);

    const auto d = dp::typed_status(Level::Denied);
    CHECK(d.declare);
    CHECK(d.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(d.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);

    const auto u = dp::typed_status(Level::Unavailable);
    CHECK(u.declare);
    CHECK(u.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(u.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("partitions: path_key_value only matches on a key boundary", "[disk_actions_partitions]") {
    using dp::impl::path_key_value;
    CHECK_FALSE(path_key_value(R"(x:Y.XDeviceID="C:")", "DeviceID").has_value());
    CHECK(path_key_value(R"(x:Y.Name="n",DeviceID="C:")", "DeviceID") == "C:");
    CHECK(path_key_value(R"(DeviceID="C:")", "DeviceID") == "C:");
    // A later boundary match is still found after an earlier non-boundary one.
    CHECK(path_key_value(R"(x:Y.XDeviceID="no",DeviceID="yes")", "DeviceID") == "yes");
}

TEST_CASE("partitions: a non-ASCII byte is never a drive letter", "[disk_actions_partitions]") {
    using dp::impl::drive_letter_mount;
    CHECK_FALSE(drive_letter_mount(std::string{"\xE9:"}).has_value());
    CHECK_FALSE(drive_letter_mount(std::string{"\xC3:"}).has_value());
    CHECK(drive_letter_mount("z:") == "Z:\\");
}

namespace {

dp::Row ldisk(const char* id, const char* drive_type) {
    return {{"DeviceID", id}, {"DriveType", drive_type}};
}

} // namespace

TEST_CASE("partitions: every local fixed drive letter placed by the association is a clean join",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                      ok({assoc("Disk #0, Partition #1", "C:")}),
                                      ok({ldisk("C:", "3")}));
    CHECK(rep.level == dp::Level::Ok);
    CHECK(cols(rep.data_rows[1])[6] == "wmi");
}

TEST_CASE("partitions: a local fixed volume no partition was associated with is not 'no mount point'",
          "[disk_actions_partitions]") {
    // A dynamic disk or Storage Space (unmeasured) would look like this: Windows lists D: as a
    // local fixed disk, but Win32_LogicalDiskToPartition places it on no partition.
    const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                      ok({assoc("Disk #0, Partition #1", "C:")}),
                                      ok({ldisk("C:", "3"), ldisk("D:", "3")}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:mount_points:unplaced_volume");
    REQUIRE(rep.data_rows.size() == 3);
    for (const auto& row : rep.data_rows)
        CHECK(cols(row)[6] == "wmi,mount_points_partial");
}

TEST_CASE("partitions: letters that are not local fixed disks never trip the cross-check",
          "[disk_actions_partitions]") {
    // 2 removable (an empty card reader), 4 network, 5 optical, 6 RAM disk: none has a partition
    // on a physical disk, so none may turn a healthy host constrained.
    const auto rep = dp::build_report(
        ok(bigsenga_partitions()), ok({assoc("Disk #0, Partition #1", "C:")}),
        ok({ldisk("C:", "3"), ldisk("E:", "2"), ldisk("Z:", "4"), ldisk("D:", "5"), ldisk("R:", "6")}));
    CHECK(rep.level == dp::Level::Ok);
}

TEST_CASE("partitions: the logical-disk cross-check failing or truncating is constrained, not skipped",
          "[disk_actions_partitions]") {
    SECTION("failed query") {
        const auto rep = dp::build_report(ok(bigsenga_partitions()), ok({}),
                                          failed("wmi_query_failed_0x80041001"));
        CHECK(rep.level == dp::Level::Constrained);
        CHECK(rep.reason == "windows:partitions:mount_points:logical_disks:wmi_query_failed_0x80041001");
        for (const auto& row : rep.data_rows)
            CHECK(cols(row)[6] == "wmi,mount_points_partial");
    }
    SECTION("truncated query") {
        auto d = ok({ldisk("C:", "3")});
        d.truncated = true;
        const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                          ok({assoc("Disk #0, Partition #1", "C:")}), d);
        CHECK(rep.level == dp::Level::Constrained);
        CHECK(rep.reason == "windows:partitions:mount_points:logical_disks:row_cap");
    }
}

TEST_CASE("partitions: the cross-check is not consulted when the association already failed",
          "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()), failed("wmi_deadline_exceeded"),
                                      ok({ldisk("D:", "3")}));
    CHECK(rep.reason == "windows:partitions:mount_points:wmi_deadline_exceeded");
    for (const auto& row : rep.data_rows)
        CHECK(cols(row)[6] == "wmi,mount_points_unread");
}

TEST_CASE("partitions: an unreadable logical-disk row is constrained, never a vacuous pass",
          "[disk_actions_partitions]") {
    for (const auto& bad : {ldisk("??", "3"), ldisk("D:", "three"), ldisk("E:", "")}) {
        INFO("DeviceID=" << bad.at("DeviceID") << " DriveType=" << bad.at("DriveType"));
        const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                          ok({assoc("Disk #0, Partition #1", "C:")}),
                                          ok({ldisk("C:", "3"), bad}));
        CHECK(rep.level == dp::Level::Constrained);
        CHECK(rep.reason == "windows:partitions:mount_points:logical_disks:row_unparsed");
        for (const auto& row : rep.data_rows)
            CHECK(cols(row)[6] == "wmi,mount_points_partial");
    }
}

TEST_CASE("partitions: an empty logical-disk answer on a host with partitions is a provider fault",
          "[disk_actions_partitions]") {
    // A host that has partitions has a boot volume; WHERE DriveType = 3 returning nothing would
    // let any unplaced letter through unnoticed, so it is itself constrained.
    const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                      ok({assoc("Disk #0, Partition #1", "C:")}), ok({}));
    CHECK(rep.level == dp::Level::Constrained);
    CHECK(rep.reason == "windows:partitions:mount_points:logical_disks:no_rows");
}

TEST_CASE("partitions: no cross-check supplied performs none", "[disk_actions_partitions]") {
    const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                      ok({assoc("Disk #0, Partition #1", "C:")}));
    CHECK(rep.level == dp::Level::Ok);
}

TEST_CASE("partitions: each sort key breaks a tie on its own", "[disk_actions_partitions]") {
    // Equal (disk, index); the pairs differ in exactly one of DeviceID, Size, Type, so dropping
    // any one key from the comparator leaves the output dependent on enumeration order.
    const auto base = [](const char* size, const char* type, const char* id) {
        return part("0", "1", size, type, id);
    };
    SECTION("DeviceID") {
        const auto a = base("5", "t", "Disk #0, Partition #1");
        const auto b = base("5", "t", "Disk #0, Partition #1 b");
        CHECK(dp::build_report(ok({a, b}), ok({})).data_rows == dp::build_report(ok({b, a}), ok({})).data_rows);
    }
    SECTION("Size") {
        const auto a = base("5", "t", "Disk #0, Partition #1");
        const auto b = base("6", "t", "Disk #0, Partition #1");
        CHECK(dp::build_report(ok({a, b}), ok({})).data_rows == dp::build_report(ok({b, a}), ok({})).data_rows);
    }
    SECTION("Type") {
        const auto a = base("5", "t1", "Disk #0, Partition #1");
        const auto b = base("5", "t2", "Disk #0, Partition #1");
        CHECK(dp::build_report(ok({a, b}), ok({})).data_rows == dp::build_report(ok({b, a}), ok({})).data_rows);
    }
}

TEST_CASE("partitions: a truncated logical-disk query marks every row partial", "[disk_actions_partitions]") {
    auto d = ok({ldisk("C:", "3")});
    d.truncated = true;
    const auto rep = dp::build_report(ok(bigsenga_partitions()),
                                      ok({assoc("Disk #0, Partition #1", "C:")}), d);
    REQUIRE(rep.data_rows.size() == 3);
    for (const auto& row : rep.data_rows)
        CHECK(cols(row)[6] == "wmi,mount_points_partial");
}

TEST_CASE("partitions: an unmatched link with a cross-check reports exactly the unmatched link",
          "[disk_actions_partitions]") {
    // The stray letter is still placed by the association, so the cross-check has nothing to add.
    const auto rep = dp::build_report(ok({part("0", "1", "9", "t", "Disk #0, Partition #1")}),
                                      ok({assoc("Disk #7, Partition #3", "Z:")}),
                                      ok({ldisk("Z:", "3")}));
    CHECK(rep.reason == "windows:partitions:mount_points:unmatched_link");
}

TEST_CASE("partitions: a DeviceID with a quote and a backslash joins through an escaped path",
          "[disk_actions_partitions]") {
    // CIM escapes " and \ inside a quoted key value; the join must undo that to match.
    const std::string id = "Disk \"x\\y\", Partition #1";
    dp::Row p{{"DiskIndex", "0"}, {"Index", "1"}, {"Size", "5"}, {"Type", "t"}, {"DeviceID", id}};
    dp::Row l{{"Antecedent", std::string{"\\\\H\\root\\cimv2:Win32_DiskPartition.DeviceID=\"Disk \\\"x\\\\y\\\", Partition #1\""}},
              {"Dependent", std::string{"\\\\H\\root\\cimv2:Win32_LogicalDisk.DeviceID=\"C:\""}}};
    const auto rep = dp::build_report(ok({p}), ok({l}));
    REQUIRE(rep.data_rows.size() == 1);
    CHECK(cols(rep.data_rows[0])[5] == "C:/");
    CHECK(rep.level == dp::Level::Ok);
}

TEST_CASE("partitions: reasons from the association and the cross-check accumulate in order",
          "[disk_actions_partitions]") {
    auto links = ok({assoc("Disk #0, Partition #1", "C:")});
    links.truncated = true;
    auto d = ok({ldisk("C:", "3")});
    d.truncated = true;
    const auto rep = dp::build_report(ok(bigsenga_partitions()), links, d);
    CHECK(rep.reason ==
          "windows:partitions:mount_points:row_cap,windows:partitions:mount_points:logical_disks:row_cap");
}
