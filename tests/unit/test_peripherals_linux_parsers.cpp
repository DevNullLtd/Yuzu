/**
 * test_peripherals_linux_parsers.cpp — pure parser + injected-root walk
 * tests for the peripherals plugin's Linux leg
 * (peripherals_linux_parsers.hpp). Builds and runs on every OS: nothing here
 * touches a real /sys.
 *
 * Walk-case fixture tree (P91-7, Architect respec 2026-09-08 — "Storage
 * re-key", see tests/unit/fixtures/wave9/peripherals/linux/provenance.txt):
 * sysfs device-address paths carry a literal ':' ("0000:00:01.0",
 * "1-0:1.0", "0-0:1.1"), which NTFS cannot represent (ERROR_INVALID_NAME) —
 * a tree tracked path-for-path broke `git checkout` on Windows, the-rig
 * included, and the required Windows MSVC CI checkout job with it. The tree
 * is therefore never tracked as literal paths: every attribute file's real
 * (colon-bearing) relative path and content is one line of the portable
 * `sysfs_tree.manifest` alongside provenance.txt (pci/usb REAL CAPTURE from
 * a debian:12 container, thunderbolt a RECONSTRUCTION citing
 * Documentation/ABI/testing/sysfs-bus-thunderbolt — see provenance.txt for
 * the full record), and each walk-case test materializes it onto disk under
 * a fresh TempDir at run time, restoring the genuine colon names the walk
 * code under test keys on. That materialization only works where the
 * filesystem can hold those names: on Windows the three walk cases below
 * report SKIP() instead of materializing or failing. The four pure-parser
 * cases and the two negative/error cases below never depended on the
 * tracked tree's path shape and are unaffected — they compile and run on
 * every platform, unguarded.
 */
#include <catch2/catch_test_macros.hpp>

#include "peripherals_linux_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

std::filesystem::path manifest_path() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave9" / "peripherals" / "linux" /
          "sysfs_tree.manifest";
#else
    return std::filesystem::path(
        "tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree.manifest");
#endif
}

/// Materializes sysfs_tree.manifest's `<relative-path>\t<content>` lines onto
/// disk under `root`, recreating the real (colon-bearing) sysfs attribute
/// paths the walk code keys on. POSIX only — callers must not invoke this on
/// Windows, where NTFS cannot hold those names; report SKIP() instead. Returns
/// false (with `error` set) on any I/O failure so the caller can REQUIRE with
/// a useful message rather than a downstream "0 rows" mismatch.
bool materialize_sysfs_tree(const std::filesystem::path& root, std::string& error) {
    const auto manifest_file = manifest_path();
    std::ifstream manifest(manifest_file, std::ios::binary);
    if (!manifest) {
        error = "could not open sysfs_tree.manifest at " + manifest_file.string();
        return false;
    }
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') // CRLF-checkout tolerance
            line.pop_back();
        if (line.empty())
            continue;
        const auto tab = line.find('\t');
        if (tab == std::string::npos) {
            error = "malformed sysfs_tree.manifest line (no tab separator): " + line;
            return false;
        }
        const std::string rel = line.substr(0, tab);
        const std::string content = line.substr(tab + 1);
        const auto out_path = root / rel;
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);
        if (ec) {
            error = "create_directories failed for " + out_path.parent_path().string() + ": " +
                    ec.message();
            return false;
        }
        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            error = "could not create fixture file " + out_path.string();
            return false;
        }
        out << content << '\n'; // every captured attribute file ends in exactly one '\n'
    }
    return true;
}

bool row_starts_with(const std::string& row, std::string_view prefix) {
    return row.size() >= prefix.size() && row.compare(0, prefix.size(), prefix) == 0;
}

std::size_t count_rows_with_field(const std::vector<std::string>& rows, int field_index,
                                  std::string_view value) {
    std::size_t n = 0;
    for (const auto& row : rows) {
        std::size_t start = 0;
        int idx = 0;
        while (idx < field_index) {
            auto pos = row.find('|', start);
            REQUIRE(pos != std::string::npos);
            start = pos + 1;
            ++idx;
        }
        auto end = row.find('|', start);
        const std::string field = row.substr(start, end == std::string::npos ? end : end - start);
        if (field == value)
            ++n;
    }
    return n;
}

} // namespace

// ── pure parsers ─────────────────────────────────────────────────────────

TEST_CASE("peripherals linux: parse_hex_attr accepts 0x-prefixed and bare hex",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(parse_hex_attr("0x8086") == std::optional<std::uint32_t>{0x8086});
    CHECK(parse_hex_attr("8086") == std::optional<std::uint32_t>{0x8086});
    CHECK(parse_hex_attr("0X1AF4") == std::optional<std::uint32_t>{0x1af4});
    CHECK(parse_hex_attr("  0x09\n") == std::optional<std::uint32_t>{0x09});
    CHECK_FALSE(parse_hex_attr("").has_value());
    CHECK_FALSE(parse_hex_attr("not-hex").has_value());
    CHECK_FALSE(parse_hex_attr("0x").has_value());
}

TEST_CASE("peripherals linux: parse_pci_class parses a 24-bit class code",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(parse_pci_class("0x0c0330") == std::optional<std::uint32_t>{0x0c0330});
    CHECK_FALSE(parse_pci_class("garbage").has_value());
}

TEST_CASE("peripherals linux: is_usb_interface_entry keys on ':'",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(is_usb_interface_entry("1-0:1.0"));
    CHECK(is_usb_interface_entry("2-1.3:1.1"));
    CHECK_FALSE(is_usb_interface_entry("usb1"));
    CHECK_FALSE(is_usb_interface_entry("1-2.1"));
}

TEST_CASE("peripherals linux: is_tb_domain_entry matches domainN only",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(is_tb_domain_entry("domain0"));
    CHECK(is_tb_domain_entry("domain12"));
    CHECK_FALSE(is_tb_domain_entry("domain"));    // no digits
    CHECK_FALSE(is_tb_domain_entry("domainX"));   // non-digit suffix
    CHECK_FALSE(is_tb_domain_entry("0-0"));
    CHECK_FALSE(is_tb_domain_entry("0-0:1.1"));
}

// ── walks over the fixture tree ─────────────────────────────────────────

TEST_CASE("peripherals linux: usb_rows_at reads the root hubs, skips interfaces",
          "[peripherals][linux][walk]") {
#if defined(_WIN32)
    SKIP("sysfs fixture tree needs ':' path segments (e.g. \"1-0:1.0\"), which NTFS "
         "cannot represent (ERROR_INVALID_NAME) — materialized on POSIX only");
#endif
    using namespace yuzu::peripherals::lnx;
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_usb_"};
    std::string materialize_error;
    REQUIRE(materialize_sysfs_tree(dir.path, materialize_error));
    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 2); // usb1, usb2 -- "1-0:1.0"/"2-0:1.0" interfaces excluded

    for (const auto& row : rows) {
        CHECK(row_starts_with(row, "usb|"));
        CHECK(row.find(":1.0") == std::string::npos); // no interface entry leaked through
    }
    // usb1 is a hub (bDeviceClass 09) with every attribute captured.
    const bool found_usb1 =
        std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
            return r == "usb|usb1|1d6b|0002|09|00|Linux 7.0.12-linuxkit vhci_hcd|"
                        "USB/IP Virtual Host Controller|vhci_hcd.0|480|1";
        });
    CHECK(found_usb1);
    // usb2 is missing manufacturer/product/serial/speed in the fixture --
    // read_attr's ENOENT -> nullopt -> "-" fallback must fill them in, and
    // it must still be recognised as a hub from its real bDeviceClass=09.
    const bool found_usb2 = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "usb|usb2|1d6b|0003|09|00|-|-|-|-|1";
    });
    CHECK(found_usb2);
}

TEST_CASE("peripherals linux: pci_rows_at reads >= 10 virtio devices",
          "[peripherals][linux][walk]") {
#if defined(_WIN32)
    SKIP("sysfs fixture tree needs ':' path segments (e.g. \"0000:00:01.0\"), which NTFS "
         "cannot represent (ERROR_INVALID_NAME) — materialized on POSIX only");
#endif
    using namespace yuzu::peripherals::lnx;
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_pci_"};
    std::string materialize_error;
    REQUIRE(materialize_sysfs_tree(dir.path, materialize_error));
    std::optional<std::string_view> token;
    const auto rows = pci_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() >= 10);
    for (const auto& row : rows)
        CHECK(row_starts_with(row, "pci|"));

    // field index: pci(0)|bus_path(1)|vendor(2)|device(3)|class(4)|...
    CHECK(count_rows_with_field(rows, 2, "1af4") == rows.size());

    // The two "rich" devices captured a `driver` file (the fixture
    // substitution for a symlink); every other minimal device has none and
    // must fall back to "-".
    const auto driver_rows = count_rows_with_field(rows, 7, "virtio-pci");
    CHECK(driver_rows == 2);
    const auto no_driver_rows = count_rows_with_field(rows, 7, "-");
    CHECK(no_driver_rows == rows.size() - 2);
}

TEST_CASE("peripherals linux: thunderbolt_rows_at yields one host_controller "
         "and skips the retimer",
         "[peripherals][linux][walk]") {
#if defined(_WIN32)
    SKIP("sysfs fixture tree needs ':' path segments (e.g. \"0-0:1.1\"), which NTFS "
         "cannot represent (ERROR_INVALID_NAME) — materialized on POSIX only");
#endif
    using namespace yuzu::peripherals::lnx;
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_tb_"};
    std::string materialize_error;
    REQUIRE(materialize_sysfs_tree(dir.path, materialize_error));
    std::optional<std::string_view> token;
    const auto rows = thunderbolt_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 3); // domain0 (host_controller) + 0-0 + 0-1 (devices); 0-0:1.1 skipped

    const auto host_controllers = count_rows_with_field(rows, 2, "host_controller");
    CHECK(host_controllers == 1);
    const auto devices = count_rows_with_field(rows, 2, "device");
    CHECK(devices == 2);

    for (const auto& row : rows)
        CHECK(row.find("Retimer") == std::string::npos); // 0-0:1.1's device_name never surfaces

    const bool found_domain0 = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "thunderbolt|domain0|host_controller|-|-|-|-|-";
    });
    CHECK(found_domain0);
    const bool found_dock = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "thunderbolt|0-1|device|Apple Inc.|Thunderbolt Dock|"
                    "00340000-0055-0000-0000-000000000000|4|1";
    });
    CHECK(found_dock);
}

TEST_CASE("peripherals linux: an absent bus directory is empty, not a failure",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    // Deliberately independent of the materialized sysfs fixture tree (Part
    // A, P91-7 respec): this case only proves a missing bus directory
    // returns empty with no failure token, which needs nothing more than
    // SOME existing, empty root — so it compiles and runs unguarded on
    // every platform, including Windows, where the colon-bearing tree
    // cannot be materialized at all.
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_absent_"};
    std::filesystem::create_directories(dir.path);
    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(dir.path / "sys" / "bus" / "does_not_exist", token);
    CHECK(rows.empty());
    CHECK_FALSE(token.has_value());
}

#if !defined(_WIN32)
TEST_CASE("peripherals linux: an unreadable root reports linux:sysfs:eacces",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_eacces_"};
    std::filesystem::create_directories(dir.path);

    // Skip if the test happens to run as root (uid 0 bypasses the
    // permission bits this test exercises) -- e.g. inside an unprivileged
    // Docker CI runner this never triggers, but a local root shell would.
    if (::geteuid() == 0) {
        SUCCEED("running as root -- permission bits are not enforced, skipping");
        return;
    }

    REQUIRE(::chmod(dir.path.string().c_str(), 0000) == 0);

    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(dir.path, token);
    // Restore permissions before TempDir's destructor tries to remove it.
    ::chmod(dir.path.string().c_str(), 0700);

    CHECK(rows.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "linux:sysfs:eacces");
}
#endif
