/**
 * test_hardware_disks_macos.cpp — pure macOS disk parser (hardware_disks_macos.hpp).
 *
 * Pins parse_macos_disks() / macos_disk_rows_or_sentinel() against a REAL
 * `system_profiler SPStorageDataType SPNVMeDataType SPSerialATADataType -json`
 * capture from a live Apple-Silicon Mac (one internal NVMe disk, no SATA
 * controller, two SPStorageDataType APFS volumes on that same disk), plus
 * synthetic specimens for failure/resilience/SATA paths that the real
 * fixture cannot exercise.
 *
 * The SATA cases are synthetic — no real SATA/Intel fixture is obtainable on
 * this Apple-Silicon host — and are explicitly UNVERIFIED against real
 * hardware; they are a best-effort smoke test only, not validated parity.
 *
 * This header is platform-agnostic (not __APPLE__-gated) so these tests
 * compile and run on every host, matching the test_dex_macos.cpp precedent.
 */

#include "hardware_disks_macos.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::hardware::macos;

namespace {

// Splits a pipe-delimited row into its fields. Used to assert the downstream
// contract (exact field count, sentinel-skippable shape) without depending on
// the server-side split helper (out of this package's scope).
std::vector<std::string> split_pipe(const std::string& row) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        auto pos = row.find('|', start);
        if (pos == std::string::npos) {
            fields.push_back(row.substr(start));
            break;
        }
        fields.push_back(row.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

} // namespace

// ── Real captured fixture ────────────────────────────────────────────────────
// Captured via `system_profiler SPStorageDataType SPNVMeDataType
// SPSerialATADataType -json` on a live Apple-Silicon Mac: one internal NVMe
// disk (251000193024 bytes), no SATA controller, and two SPStorageDataType
// volumes (Data + Macintosh HD) that both point back at the same physical
// NVMe disk via physical_drive.device_name — proving they must NOT be
// double-counted as separate disks.
static const char* kRealFixture = R"JSON({
  "SPNVMeDataType" : [
    {
      "_items" : [
        {
          "_name" : "APPLE SSD AP0256Z",
          "bsd_name" : "disk0",
          "detachable_drive" : "no",
          "device_model" : "APPLE SSD AP0256Z",
          "device_revision" : "561.100.",
          "device_serial" : "0ba018e4045c5e3e",
          "partition_map_type" : "guid_partition_map_type",
          "removable_media" : "no",
          "size" : "251 GB",
          "size_in_bytes" : 251000193024,
          "smart_status" : "Verified",
          "spnvme_trim_support" : "Yes",
          "volumes" : [
            {
              "_name" : "iSCPreboot",
              "bsd_name" : "disk0s1",
              "iocontent" : "Apple_APFS_ISC",
              "size" : "524.3 MB",
              "size_in_bytes" : 524288000
            },
            {
              "_name" : "Macintosh HD",
              "bsd_name" : "disk0s2",
              "iocontent" : "Apple_APFS",
              "size" : "245.11 GB",
              "size_in_bytes" : 245107195904
            },
            {
              "_name" : "Recovery",
              "bsd_name" : "disk0s3",
              "iocontent" : "Apple_APFS_Recovery",
              "size" : "5.37 GB",
              "size_in_bytes" : 5368664064
            }
          ]
        }
      ],
      "_name" : "Apple SSD Controller"
    }
  ],
  "SPSerialATADataType" : [

  ],
  "SPStorageDataType" : [
    {
      "_name" : "Data",
      "bsd_name" : "disk3s5",
      "file_system" : "APFS",
      "free_space_in_bytes" : 23142219776,
      "ignore_ownership" : "no",
      "mount_point" : "/System/Volumes/Data",
      "physical_drive" : {
        "device_name" : "APPLE SSD AP0256Z",
        "is_internal_disk" : "yes",
        "media_name" : "AppleAPFSMedia",
        "medium_type" : "ssd",
        "partition_map_type" : "unknown_partition_map_type",
        "protocol" : "Apple Fabric",
        "smart_status" : "Verified"
      },
      "size_in_bytes" : 245107195904,
      "volume_uuid" : "6B66F471-BAD0-40FF-BC86-D2EBEC4EDB06",
      "writable" : "yes"
    },
    {
      "_name" : "Macintosh HD",
      "bsd_name" : "disk3s1s1",
      "file_system" : "APFS",
      "free_space_in_bytes" : 23142211584,
      "ignore_ownership" : "no",
      "mount_point" : "/",
      "physical_drive" : {
        "device_name" : "APPLE SSD AP0256Z",
        "is_internal_disk" : "yes",
        "media_name" : "AppleAPFSMedia",
        "medium_type" : "ssd",
        "partition_map_type" : "unknown_partition_map_type",
        "protocol" : "Apple Fabric",
        "smart_status" : "Verified"
      },
      "size_in_bytes" : 245107195904,
      "volume_uuid" : "00E1FB85-0892-4B5B-BCD1-5F492F801A00",
      "writable" : "no"
    }
  ]
})JSON";

TEST_CASE("real fixture yields exactly one internal NVMe disk row", "[hardware_disks_macos]") {
    auto rows = macos_disk_rows_or_sentinel(kRealFixture);
    // 233 = floor(251000193024 / 1024^3) - binary GB, matching the Windows
    // leg's size/(1024ULL*1024*1024) convention.
    REQUIRE(rows == std::vector<std::string>{"disk|0|APPLE SSD AP0256Z|233|SSD|NVMe"});
}

TEST_CASE("real fixture never double-counts SPStorageDataType volumes as disks",
          "[hardware_disks_macos]") {
    auto rows = parse_macos_disks(kRealFixture);
    REQUIRE(rows.size() == 1);
}

// ── Sentinel / empty path (PLAN-04) ──────────────────────────────────────────

TEST_CASE("empty input returns the failure sentinel", "[hardware_disks_macos][sentinel]") {
    auto rows = macos_disk_rows_or_sentinel("");
    REQUIRE(rows == std::vector<std::string>{"disk|0|unknown|0|unknown|unknown"});
}

TEST_CASE("malformed top-level json returns the failure sentinel",
          "[hardware_disks_macos][sentinel]") {
    auto rows = macos_disk_rows_or_sentinel("{ not json");
    REQUIRE(rows == std::vector<std::string>{"disk|0|unknown|0|unknown|unknown"});
    // Confirm the failure sentinel is empty-JSON-safe too - json::parse throws
    // on this input, exercising the top-level try/catch, not the empty-array path.
    REQUIRE(parse_macos_disks("{ not json").empty());
}

TEST_CASE("no physical disks present returns the failure sentinel",
          "[hardware_disks_macos][sentinel]") {
    static const char* kNoDisks = R"JSON({
      "SPNVMeDataType" : [],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = macos_disk_rows_or_sentinel(kNoDisks);
    REQUIRE(rows == std::vector<std::string>{"disk|0|unknown|0|unknown|unknown"});
}

TEST_CASE("failure sentinel row is downstream-skippable", "[hardware_disks_macos][sentinel]") {
    auto rows = macos_disk_rows_or_sentinel("");
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK((t[2] == "unknown" && t[3] == "0"));
}

// ── Per-item resilience (PLAN-05) ────────────────────────────────────────────

TEST_CASE("one broken item does not suppress a valid row (non-object element)",
          "[hardware_disks_macos][resilience]") {
    static const char* kOneBrokenNonObject = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "APPLE SSD AP0256Z",
              "device_model" : "APPLE SSD AP0256Z",
              "size_in_bytes" : 251000193024
            },
            "not an object"
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kOneBrokenNonObject);
    REQUIRE(rows == std::vector<std::string>{"disk|0|APPLE SSD AP0256Z|233|SSD|NVMe"});
}

TEST_CASE("no-capacity item is skipped without suppressing the valid row",
          "[hardware_disks_macos][resilience]") {
    static const char* kOneBrokenNullSize = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "APPLE SSD AP0256Z",
              "device_model" : "APPLE SSD AP0256Z",
              "size_in_bytes" : 251000193024
            },
            {
              "_name" : "Broken Disk",
              "device_model" : "Broken Disk",
              "size_in_bytes" : null
            }
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kOneBrokenNullSize);
    // The no-capacity item is skipped (fail-closed, BR-001) - it must not
    // suppress the valid preceding row.
    REQUIRE(rows == std::vector<std::string>{"disk|0|APPLE SSD AP0256Z|233|SSD|NVMe"});
}

TEST_CASE("item with no capacity at all yields the failure sentinel",
          "[hardware_disks_macos][resilience][sentinel]") {
    static const char* kNoCapacity = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "No Capacity Disk",
              "device_model" : "No Capacity Disk"
            }
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = macos_disk_rows_or_sentinel(kNoCapacity);
    // No usable capacity anywhere - the single item is skipped and the
    // rows-or-sentinel seam falls back to the failure sentinel (BR-001).
    REQUIRE(rows == std::vector<std::string>{"disk|0|unknown|0|unknown|unknown"});
}

// ── Delimiter safety (PLAN-06) ───────────────────────────────────────────────

TEST_CASE("model containing pipe and newline is sanitized to a single valid row",
          "[hardware_disks_macos][delimiter]") {
    static const char* kHostileModel = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "hostile",
              "device_model" : "EVIL|MODEL\nSECOND\rLINE",
              "size_in_bytes" : 251000193024
            }
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kHostileModel);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK(t[2] == "EVIL MODEL SECOND LINE");
    CHECK(t[3] == "233");
    CHECK(t[4] == "SSD");
    CHECK(t[5] == "NVMe");
}

TEST_CASE("model containing an embedded NUL and a control byte is sanitized",
          "[hardware_disks_macos][delimiter]") {
    // The JSON escapes below decode to a literal NUL between "AB" and "C"
    // and a literal SOH (0x01) between "C" and "D" - both are control bytes
    // below 0x20 that sanitize_disk_field must blank out (BR-003), same as
    // it does for CR/LF/pipe.
    static const char* kControlBytesModel = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "control-bytes",
              "device_model" : "AB\u0000C\u0001D",
              "size_in_bytes" : 251000193024
            }
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kControlBytesModel);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK(t[2] == "AB C D");
}

// ── SATA best-effort (PLAN-02) ───────────────────────────────────────────────
// UNVERIFIED against real Intel/SATA hardware - no real SATA fixture is
// obtainable on this Apple-Silicon host. This is a synthetic smoke test of
// the medium_type cross-ref plumbing only, not validated parity.

TEST_CASE("synthetic SATA item resolves medium_type via SPStorageDataType cross-ref",
          "[hardware_disks_macos][sata][unverified]") {
    static const char* kSyntheticSata = R"JSON({
      "SPNVMeDataType" : [],
      "SPSerialATADataType" : [
        {
          "_items" : [
            {
              "_name" : "FAKE SATA SSD",
              "device_model" : "FAKE SATA SSD",
              "size_in_bytes" : 500000000000
            }
          ],
          "_name" : "SATA Controller"
        }
      ],
      "SPStorageDataType" : [
        {
          "_name" : "FakeVolume",
          "physical_drive" : {
            "device_name" : "FAKE SATA SSD",
            "medium_type" : "ssd"
          },
          "size_in_bytes" : 500000000000
        }
      ]
    })JSON";
    auto rows = parse_macos_disks(kSyntheticSata);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK(t[2] == "FAKE SATA SSD");
    CHECK(t[4] == "SSD");
    CHECK(t[5] == "SATA");
}

TEST_CASE("synthetic SATA item with no medium_type match falls back to unknown",
          "[hardware_disks_macos][sata][unverified]") {
    static const char* kSyntheticSataNoMatch = R"JSON({
      "SPNVMeDataType" : [],
      "SPSerialATADataType" : [
        {
          "_items" : [
            {
              "_name" : "UNMATCHED SATA DISK",
              "device_model" : "UNMATCHED SATA DISK",
              "size_in_bytes" : 1000000000000
            }
          ],
          "_name" : "SATA Controller"
        }
      ],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kSyntheticSataNoMatch);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    CHECK(t[4] == "unknown");
    CHECK(t[5] == "SATA");
}

TEST_CASE("SATA lookup keeps scanning past a same-name volume with no medium_type"
          " (PKG01-002)",
          "[hardware_disks_macos][sata][unverified]") {
    // UNVERIFIED against real Intel/SATA hardware - no real SATA fixture is
    // obtainable on this Apple-Silicon host. Two SPStorageDataType volumes
    // share the disk's device_name; the first carries no medium_type at all
    // and the second does. The scan must not bail out on the first match -
    // it must keep looking and pick up the second volume's "ssd".
    static const char* kSyntheticSataTwoVolumes = R"JSON({
      "SPNVMeDataType" : [],
      "SPSerialATADataType" : [
        {
          "_items" : [
            {
              "_name" : "FAKE SATA SSD",
              "device_model" : "FAKE SATA SSD",
              "size_in_bytes" : 500000000000
            }
          ],
          "_name" : "SATA Controller"
        }
      ],
      "SPStorageDataType" : [
        {
          "_name" : "FakeVolumeNoMedium",
          "physical_drive" : {
            "device_name" : "FAKE SATA SSD"
          },
          "size_in_bytes" : 500000000000
        },
        {
          "_name" : "FakeVolumeWithMedium",
          "physical_drive" : {
            "device_name" : "FAKE SATA SSD",
            "medium_type" : "ssd"
          },
          "size_in_bytes" : 500000000000
        }
      ]
    })JSON";
    auto rows = parse_macos_disks(kSyntheticSataTwoVolumes);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK(t[4] == "SSD");
    CHECK(t[5] == "SATA");
}

TEST_CASE("synthetic SATA rotational medium is reported as HDD (PKG01-003)",
          "[hardware_disks_macos][sata][unverified]") {
    // UNVERIFIED against real Intel/SATA hardware - no real SATA fixture is
    // obtainable on this Apple-Silicon host. Exercises the HDD branch of the
    // medium_type classification, which none of the other synthetic SATA
    // specimens above cover.
    static const char* kSyntheticSataHdd = R"JSON({
      "SPNVMeDataType" : [],
      "SPSerialATADataType" : [
        {
          "_items" : [
            {
              "_name" : "FAKE SATA HDD",
              "device_model" : "FAKE SATA HDD",
              "size_in_bytes" : 1000000000000
            }
          ],
          "_name" : "SATA Controller"
        }
      ],
      "SPStorageDataType" : [
        {
          "_name" : "FakeVolume",
          "physical_drive" : {
            "device_name" : "FAKE SATA HDD",
            "medium_type" : "rotational"
          },
          "size_in_bytes" : 1000000000000
        }
      ]
    })JSON";
    auto rows = parse_macos_disks(kSyntheticSataHdd);
    REQUIRE(rows.size() == 1);
    auto t = split_pipe(rows[0]);
    REQUIRE(t.size() == 6);
    CHECK(t[4] == "HDD");
    CHECK(t[5] == "SATA");
}

TEST_CASE("two NVMe items are indexed 0 then 1 in order", "[hardware_disks_macos]") {
    static const char* kTwoNvme = R"JSON({
      "SPNVMeDataType" : [
        {
          "_items" : [
            {
              "_name" : "First Disk",
              "device_model" : "First Disk",
              "size_in_bytes" : 251000193024
            },
            {
              "_name" : "Second Disk",
              "device_model" : "Second Disk",
              "size_in_bytes" : 500107862016
            }
          ],
          "_name" : "Apple SSD Controller"
        }
      ],
      "SPSerialATADataType" : [],
      "SPStorageDataType" : []
    })JSON";
    auto rows = parse_macos_disks(kTwoNvme);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "disk|0|First Disk|233|SSD|NVMe");
    CHECK(rows[1] == "disk|1|Second Disk|465|SSD|NVMe");
}
