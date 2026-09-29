/**
 * test_bitlocker_macos.cpp -- fixture-driven vectors for the macOS
 * bitlocker leg's pure `diskutil apfs list` parser (bitlocker_macos_apfs.hpp,
 * A-1.16, P8).
 *
 * Everything here runs against a captured/synthetic `diskutil apfs list`
 * transcript -- no `diskutil` subprocess, no real APFS container -- because
 * the parser is pure by design (same header-for-testability pattern as
 * installed_apps_inventory.hpp). Pins the honesty contract: a volume whose
 * encryption state can't be determined from the text comes out "unknown",
 * never guessed as encrypted or not.
 */

#include <catch2/catch_test_macros.hpp>

#include <bitlocker_macos_apfs.hpp>

#include <string>

using namespace yuzu::bitlocker::macos;

namespace {

// A trimmed-but-representative `diskutil apfs list` transcript: one
// container with two volumes, one FileVault-encrypted-and-unlocked, one not.
const char* kRealisticTranscript = R"(
+-- Container disk3 A1B2C3D4-0000-0000-0000-000000000000
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      994662584320 B (994.7 GB)
|   Capacity In Use By Volumes:   500000000000 B (500.0 GB) (50.3% used)
|   Capacity Not Allocated:       494662584320 B (49.7% free)
|   |
|   +-> Volume disk3s1 7263F4B6-1234-4321-AAAA-BBBBCCCCDDDD
|   |   ---------------------------------------------------
|   |   APFS Volume Disk (Role):   disk3s1 (Data)
|   |   Name:                      Macintosh HD - Data (Case-insensitive)
|   |   Mount Point:               /System/Volumes/Data
|   |   Capacity Consumed:         499000000000 B (499.0 GB)
|   |   FileVault:                 Yes (Unlocked)
|   |
|   +-> Volume disk3s6 CCCC1111-2222-3333-4444-555566667777
|   |   ---------------------------------------------------
|   |   APFS Volume Disk (Role):   disk3s6 (Preboot)
|   |   Name:                      Preboot
|   |   Mount Point:               Not Mounted
|   |   Capacity Consumed:         500000000 B (500.0 MB)
|   |   FileVault:                 No
)";

} // namespace

TEST_CASE("parse_diskutil_apfs_list parses a realistic two-volume transcript",
          "[bitlocker][macos]") {
    const auto volumes = parse_diskutil_apfs_list(kRealisticTranscript);

    REQUIRE(volumes.size() == 2);

    const auto& data = volumes[0];
    CHECK(data.disk_id == "disk3s1");
    CHECK(data.name == "Macintosh HD - Data (Case-insensitive)");
    CHECK(data.mount_point == "/System/Volumes/Data");
    CHECK(data.role == "Data");
    CHECK(data.encrypted_state == "encrypted");

    const auto& preboot = volumes[1];
    CHECK(preboot.disk_id == "disk3s6");
    CHECK(preboot.name == "Preboot");
    CHECK(preboot.mount_point == "Not Mounted");
    CHECK(preboot.role == "Preboot");
    CHECK(preboot.encrypted_state == "not_encrypted");
}

TEST_CASE("parse_diskutil_apfs_list reports unknown, never guesses, when no "
          "encryption key is present",
          "[bitlocker][macos]") {
    const char* transcript = R"(
+-> Volume disk4s1 11112222-3333-4444-5555-666677778888
|   APFS Volume Disk (Role):   disk4s1 (Data)
|   Name:                      SomeVolume
|   Mount Point:               /Volumes/SomeVolume
)";

    const auto volumes = parse_diskutil_apfs_list(transcript);

    REQUIRE(volumes.size() == 1);
    CHECK(volumes[0].encrypted_state == "unknown");
}

TEST_CASE("parse_diskutil_apfs_list on empty/garbled input yields an empty vector, "
          "never a fabricated record",
          "[bitlocker][macos]") {
    CHECK(parse_diskutil_apfs_list("").empty());
    CHECK(parse_diskutil_apfs_list("this is not diskutil output\nrandom garbage\n").empty());
}

TEST_CASE("parse_diskutil_apfs_list drops a volume header with no extractable disk id",
          "[bitlocker][macos]") {
    // A "Volume" header line with no diskNsM token in it -- have_current is
    // set but disk_id stays empty, so flush() must not emit a bogus record.
    const char* transcript = "+-> Volume with no disk token at all\n"
                              "|   Name: Whatever\n";

    CHECK(parse_diskutil_apfs_list(transcript).empty());
}

TEST_CASE("volume_label prefers name, then mount point, then disk id", "[bitlocker][macos]") {
    ApfsVolumeStatus v;
    v.disk_id = "disk3s1";
    CHECK(volume_label(v) == "disk3s1"); // nothing else set

    v.mount_point = "/Volumes/Data";
    CHECK(volume_label(v) == "/Volumes/Data"); // mount point beats disk id

    v.mount_point = "Not Mounted";
    CHECK(volume_label(v) == "disk3s1"); // "Not Mounted" is not a usable label

    v.name = "My Data Volume";
    CHECK(volume_label(v) == "My Data Volume"); // name wins over everything
}

TEST_CASE("volume_label on a completely empty record is an honest unknown",
          "[bitlocker][macos]") {
    CHECK(volume_label(ApfsVolumeStatus{}) == "unknown");
}

TEST_CASE("volume_type lowercases the raw role, or reports unknown", "[bitlocker][macos]") {
    ApfsVolumeStatus v;
    v.role = "Data";
    CHECK(volume_type(v) == "data");

    v.role.clear();
    CHECK(volume_type(v) == "unknown");
}
