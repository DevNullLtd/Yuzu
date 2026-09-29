/**
 * test_hardware_linux_parsers.cpp — pure Linux `dmidecode -t memory` text
 * parser and native `/sys/block` disk-row builder (hardware_linux_parsers.hpp).
 *
 * There is no tests/fixtures/ text-file convention in this tree for these
 * shapes — fixtures are inline C++ raw-string literals, matching this
 * header's own doc comment and the wider pure-parser test convention
 * (test_licensing_parsers.cpp, test_antivirus_parsers.cpp, ...).
 *
 * This header is platform-agnostic (not __linux__-gated) so these tests
 * compile and run on every host, matching the hardware_disks_macos.hpp /
 * test_hardware_disks_macos.cpp precedent — every accessor
 * build_linux_disk_rows() needs is INJECTED, so no real /sys/block is
 * touched.
 */

#include "hardware_linux_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <vector>

using namespace yuzu::hardware::linuxutil;

// ── parse_dmidecode_memory ───────────────────────────────────────────────────

TEST_CASE("parse_dmidecode_memory: two populated DIMM slots", "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(# dmidecode 3.3
Getting SMBIOS data from sysfs.
SMBIOS 3.2.0 present.

Handle 0x0024, DMI type 17, 40 bytes
Memory Device
	Array Handle: 0x0023
	Error Information Handle: Not Provided
	Total Width: 64 bits
	Data Width: 64 bits
	Size: 16384 MB
	Form Factor: SODIMM
	Set: None
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: DDR4
	Type Detail: Synchronous
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 12345678
	Asset Tag: Not Specified
	Part Number: M471A2K43EB1-CWE
	Rank: 1
	Configured Memory Speed: 3200 MT/s

Handle 0x0026, DMI type 17, 40 bytes
Memory Device
	Array Handle: 0x0023
	Error Information Handle: Not Provided
	Total Width: 64 bits
	Data Width: 64 bits
	Size: 16384 MB
	Form Factor: SODIMM
	Set: None
	Locator: ChannelB-DIMM0
	Bank Locator: BANK 2
	Type: DDR4
	Type Detail: Synchronous
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 87654321
	Asset Tag: Not Specified
	Part Number: M471A2K43EB1-CWE
	Rank: 1
	Configured Memory Speed: 3200 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "dimm|ChannelA-DIMM0|16384|DDR4|3200");
    CHECK(rows[1] == "dimm|ChannelB-DIMM0|16384|DDR4|3200");
}

TEST_CASE("parse_dmidecode_memory: empty slot ('No Module Installed') is skipped",
          "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(Handle 0x0024, DMI type 17, 40 bytes
Memory Device
	Locator: ChannelA-DIMM0
	Size: No Module Installed
	Type: Unknown
	Speed: Unknown

Handle 0x0026, DMI type 17, 40 bytes
Memory Device
	Locator: ChannelB-DIMM0
	Size: 8192 MB
	Type: DDR4
	Speed: 2666 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dimm|ChannelB-DIMM0|8192|DDR4|2666");
}

TEST_CASE("parse_dmidecode_memory: EPERM/empty output -> empty (caller falls back to "
          "/proc/meminfo)",
          "[hardware][linux][memory]") {
    CHECK(parse_dmidecode_memory("").empty());
    // Typical unprivileged dmidecode stderr-only failure text (no "Size:" field at all).
    CHECK(parse_dmidecode_memory("# dmidecode 3.3\n/dev/mem: Permission denied\n").empty());
}

TEST_CASE("parse_dmidecode_memory: 'Type Detail:' line does not get mistaken for 'Type:'",
          "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(Memory Device
	Locator: DIMM0
	Size: 4096 MB
	Type: DDR3
	Type Detail: Synchronous Unbuffered (Unregistered)
	Speed: 1600 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dimm|DIMM0|4096|DDR3|1600");
}

TEST_CASE("parse_dmidecode_memory: 'Size: N GB' is converted to MB, not mislabeled "
          "(CDX BR-003)",
          "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(Memory Device
	Locator: DIMM0
	Size: 16 GB
	Type: DDR5
	Speed: 5600 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dimm|DIMM0|16384|DDR5|5600"); // 16 GB -> 16384 MB
}

TEST_CASE("parse_dmidecode_memory: 'Size: N TB' is converted to MB (CDX BR-003)",
          "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(Memory Device
	Locator: DIMM0
	Size: 1 TB
	Type: DDR5
	Speed: 4800 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dimm|DIMM0|1048576|DDR5|4800"); // 1 TB -> 1048576 MB
}

TEST_CASE("parse_dmidecode_memory: unrecognized size unit is skipped, not mislabeled",
          "[hardware][linux][memory]") {
    static constexpr const char* kDmi = R"(Memory Device
	Locator: DIMM0
	Size: 16 KB
	Type: DDR5
	Speed: 5600 MT/s

Memory Device
	Locator: DIMM1
	Size: 8192 MB
	Type: DDR5
	Speed: 5600 MT/s
)";
    auto rows = parse_dmidecode_memory(kDmi);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dimm|DIMM1|8192|DDR5|5600");
}

// ── build_linux_disk_rows ─────────────────────────────────────────────────────

namespace {

// A tiny in-memory fixture for the injected read_file/read_link functions,
// keyed by exact path — mirrors the shape build_linux_disk_rows() queries
// (/sys/block/<name>/size, /sys/block/<name>/device/model,
// /sys/block/<name>/removable, /sys/block/<name>/queue/rotational, and a
// readlink of /sys/block/<name> itself).
struct FakeSysfs {
    std::map<std::string, std::string> files;
    std::map<std::string, std::string> links;

    ReadFileFn reader() const {
        return [this](const std::string& path) -> std::string {
            auto it = files.find(path);
            return it == files.end() ? std::string{} : it->second;
        };
    }
    ReadLinkFn linker() const {
        return [this](const std::string& path) -> std::string {
            auto it = links.find(path);
            return it == links.end() ? std::string{} : it->second;
        };
    }
};

} // namespace

TEST_CASE("build_linux_disk_rows: NVMe SSD, size + model + transport + media type",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    // 500 GB disk: 976773168 sectors x 512 bytes ~= 465 GiB.
    fs.files["/sys/block/nvme0n1/size"] = "976773168\n";
    fs.files["/sys/block/nvme0n1/device/model"] = "Samsung SSD 980 PRO 500GB   \n";
    fs.files["/sys/block/nvme0n1/removable"] = "0\n";
    fs.files["/sys/block/nvme0n1/queue/rotational"] = "0\n";
    fs.links["/sys/block/nvme0n1"] =
        "../devices/pci0000:00/0000:00:1c.0/0000:01:00.0/nvme/nvme0/nvme0n1";

    auto rows = build_linux_disk_rows({"nvme0n1"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|Samsung SSD 980 PRO 500GB|465|SSD|nvme");
}

TEST_CASE("build_linux_disk_rows: rotational SATA HDD via ata symlink -> sata transport, "
          "HDD media",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/sda/size"] = "1953525168"; // ~931 GiB
    fs.files["/sys/block/sda/device/model"] = "ST1000LM035-1RK1  ";
    fs.files["/sys/block/sda/removable"] = "0";
    fs.files["/sys/block/sda/queue/rotational"] = "1";
    fs.links["/sys/block/sda"] =
        "../devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda";

    auto rows = build_linux_disk_rows({"sda"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|ST1000LM035-1RK1|931|HDD|sata");
}

TEST_CASE("build_linux_disk_rows: removable device -> Removable media regardless of "
          "rotational",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/sdz/size"] = "31266816"; // ~14.9 GiB USB stick
    fs.files["/sys/block/sdz/device/model"] = "Cruzer Blade";
    fs.files["/sys/block/sdz/removable"] = "1";
    fs.files["/sys/block/sdz/queue/rotational"] = "0"; // removable wins even though non-rotational
    fs.links["/sys/block/sdz"] =
        "../devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/host3/target3:0:0/block/sdz";

    auto rows = build_linux_disk_rows({"sdz"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|Cruzer Blade|14|Removable|usb");
}

TEST_CASE("build_linux_disk_rows: missing removable/rotational files -> unknown media",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/vdb/size"] = "20971520"; // 10 GiB
    fs.files["/sys/block/vdb/device/model"] = "Virtual Disk";
    // No removable/rotational entries at all.
    auto rows = build_linux_disk_rows({"vdb"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|Virtual Disk|10|unknown|unknown");
}

TEST_CASE("build_linux_disk_rows: loop/ram/zram/dm/md/sr/fd devices are excluded",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    for (const std::string& name :
         {"loop0", "ram0", "zram0", "dm-0", "md0", "sr0", "fd0"}) {
        fs.files["/sys/block/" + name + "/size"] = "2097152"; // nonzero, would otherwise pass
    }
    auto rows =
        build_linux_disk_rows({"loop0", "ram0", "zram0", "dm-0", "md0", "sr0", "fd0"}, fs.reader(),
                              fs.linker());
    CHECK(rows.empty());
}

TEST_CASE("build_linux_disk_rows: zero or missing size is skipped (no size reading at all)",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/sdb/size"] = "0";
    // sdc has no "size" file entry at all -> read_file returns "".
    auto rows = build_linux_disk_rows({"sdb", "sdc"}, fs.reader(), fs.linker());
    CHECK(rows.empty());
}

TEST_CASE("build_linux_disk_rows: a genuine sub-GiB device is RETAINED at size_gb=0, not "
          "dropped (CDX BR-005)",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    // 512 MiB eMMC/USB device: 1048576 sectors x 512 bytes = 512 MiB (< 1 GiB).
    fs.files["/sys/block/mmcblk1/size"] = "1048576";
    fs.files["/sys/block/mmcblk1/device/model"] = "Tiny eMMC";
    fs.files["/sys/block/mmcblk1/removable"] = "0";
    fs.files["/sys/block/mmcblk1/queue/rotational"] = "0";

    auto rows = build_linux_disk_rows({"mmcblk1"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|Tiny eMMC|0|SSD|unknown");
}

TEST_CASE("build_linux_disk_rows: a nonsense-large sector count does not wrap into a "
          "fabricated small capacity (CDX BR-010)",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    // Deliberately huge (larger than any real device, but within unsigned long long range
    // divided safely by sectors-per-GiB rather than multiplied by 512 first).
    fs.files["/sys/block/weird0/size"] = "36028797018963968"; // 2^55 sectors
    fs.files["/sys/block/weird0/device/model"] = "Faulty Reporter";

    auto rows = build_linux_disk_rows({"weird0"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    // 2^55 sectors / (2^30/512) = 2^55 / 2^21 = 2^34 GiB -- large but not wrapped/negative.
    CHECK(rows[0] == "disk|0|Faulty Reporter|17179869184|unknown|unknown");
}

TEST_CASE("build_linux_disk_rows: missing model falls back to the device name",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/vda/size"] = "41943040"; // 20 GiB
    // No .../device/model entry.
    fs.links["/sys/block/vda"] = "../devices/pci0000:00/0000:00:04.0/virtio1/block/vda";

    auto rows = build_linux_disk_rows({"vda"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|vda|20|unknown|virtio");
}

TEST_CASE("build_linux_disk_rows: unresolvable symlink -> unknown transport",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/xvda/size"] = "20971520"; // 10 GiB
    fs.files["/sys/block/xvda/device/model"] = "Xen Virtual Disk";
    // No readlink entry -> read_link returns "".
    auto rows = build_linux_disk_rows({"xvda"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "disk|0|Xen Virtual Disk|10|unknown|unknown");
}

TEST_CASE("build_linux_disk_rows: indices increment only across surviving (non-excluded, "
          "zero-sector-filtered) devices",
          "[hardware][linux][disks]") {
    FakeSysfs fs;
    fs.files["/sys/block/loop0/size"] = "2048"; // excluded by name, must not consume index 0
    fs.files["/sys/block/sda/size"] = "20971520"; // 10 GiB
    fs.files["/sys/block/sdb/size"] = "0"; // zero sectors, skipped, must not consume an index
    fs.files["/sys/block/sdc/size"] = "41943040"; // 20 GiB

    auto rows = build_linux_disk_rows({"loop0", "sda", "sdb", "sdc"}, fs.reader(), fs.linker());
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "disk|0|sda|10|unknown|unknown");
    CHECK(rows[1] == "disk|1|sdc|20|unknown|unknown");
}

TEST_CASE("build_linux_disk_rows: empty device list -> empty", "[hardware][linux][disks]") {
    FakeSysfs fs;
    CHECK(build_linux_disk_rows({}, fs.reader(), fs.linker()).empty());
}
