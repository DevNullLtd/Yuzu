#pragma once

// hardware_linux_parsers.hpp — pure parsers for the Linux legs of the
// "memory" and "disks" actions in hardware_plugin.cpp.
//
//   * parse_dmidecode_memory() — extracts per-DIMM rows from `dmidecode -t
//     memory` text output (do_memory()'s dmidecode branch, unchanged logic,
//     only lifted out of the plugin into a pure/testable function as part of
//     Wave 3's run_bounded_subprocess migration). The unprivileged
//     EPERM -> empty -> /proc/meminfo aggregate-total fallback stays
//     entirely in the plugin -- this header only answers "did dmidecode's
//     text look usable" via a non-empty return.
//   * build_linux_disk_rows() — replaces `lsblk -dno NAME,SIZE,TYPE,MODEL,
//     TRAN` with a native /sys/block walk (do_disks()'s Linux branch). Every
//     filesystem access is INJECTED (read_file / read_link) so this is
//     unit-testable without a real /sys tree.
//
// Platform-agnostic and header-only so it compiles and its unit tests run on
// every host, matching the hardware_disks_macos.hpp precedent, even though
// both functions are only ever invoked from the __linux__ branch of the
// plugin. Named "linuxutil" rather than "linux" for the namespace: `linux`
// is a predefined macro under non-strict-ISO GNU extension modes on some
// toolchains, and this header must compile cleanly wherever it's included.

#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::hardware::linuxutil {

// Parses `dmidecode -t memory` text into "dimm|slot|size_mb|type|speed_mhz"
// rows. Returns {} both when dmi is unusable (empty, or no "Size:" field --
// the same gate do_memory() used inline pre-Wave-3 to decide whether to fall
// back to /proc/meminfo) and when it parses to zero installed-module rows;
// callers distinguish those the same way the original code did (an empty
// result triggers the /proc/meminfo fallback).
inline std::vector<std::string> parse_dmidecode_memory(const std::string& dmi) {
    std::vector<std::string> rows;
    if (dmi.empty() || dmi.find("Size:") == std::string::npos)
        return rows;

    std::istringstream ss(dmi);
    std::string line;
    std::string slot, size, type, speed;
    bool in_device = false;

    auto emit_if_installed = [&]() {
        if (!in_device || size.empty() || size == "No Module Installed")
            return;
        // dmidecode's Size field is "<N> MB" / "<N> GB" / "<N> TB" -- the
        // pre-Wave-3 code took the numeric prefix as-is and mislabeled GB/TB
        // modules as MB (under-reporting by 1024x/1024^2x). Convert every
        // unit to MB explicitly; an unrecognized/missing unit is skipped
        // rather than silently mislabeled.
        auto sp = size.find(' ');
        if (sp == std::string::npos)
            return;
        std::string size_mb;
        try {
            unsigned long long value = std::stoull(size.substr(0, sp));
            auto unit_start = size.find_first_not_of(' ', sp);
            auto unit = unit_start == std::string::npos ? std::string{} : size.substr(unit_start);
            if (unit == "GB")
                value *= 1024ULL;
            else if (unit == "TB")
                value *= 1024ULL * 1024ULL;
            else if (unit != "MB")
                return;
            size_mb = std::to_string(value);
        } catch (...) {
            return;
        }
        std::string speed_mhz = speed;
        sp = speed.find(' ');
        if (sp != std::string::npos)
            speed_mhz = speed.substr(0, sp);
        rows.push_back("dimm|" + slot + "|" + size_mb + "|" + type + "|" + speed_mhz);
    };

    while (std::getline(ss, line)) {
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        if (line == "Memory Device") {
            emit_if_installed();
            slot.clear();
            size.clear();
            type.clear();
            speed.clear();
            in_device = true;
        } else if (in_device) {
            if (line.starts_with("Locator:")) {
                slot = line.substr(line.find(':') + 2);
            } else if (line.starts_with("Size:")) {
                size = line.substr(line.find(':') + 2);
            } else if (line.starts_with("Type:") && !line.starts_with("Type Detail")) {
                type = line.substr(line.find(':') + 2);
            } else if (line.starts_with("Speed:")) {
                speed = line.substr(line.find(':') + 2);
            }
        }
    }
    emit_if_installed(); // last device in the stream

    return rows;
}

// Injected filesystem accessors so the /sys/block walk below is unit-
// testable without a real sysfs tree: return "" for a missing/unreadable
// path, never throw.
using ReadFileFn = std::function<std::string(const std::string& path)>;
using ReadLinkFn = std::function<std::string(const std::string& path)>;

namespace detail {

// Best-effort "is this a whole disk, not a partition/loop/ram/zram/dm/md/
// optical/floppy device" classification from its /sys/block name alone.
// `lsblk`'s kernel-sourced TYPE column gave this natively (the previous
// implementation filtered on `type == "disk"`); the native walk has no
// direct equivalent, so this is a documented, testable name-prefix
// heuristic covering the common Linux block-device naming conventions
// instead. Genuine disks (sd*, hd*, nvme*n*, vd*, xvd*, mmcblk*) all pass.
inline bool looks_like_real_disk(const std::string& name) {
    static constexpr std::string_view kExcludedPrefixes[] = {
        "loop", "ram", "zram", "dm-", "md", "sr", "fd",
    };
    if (name.empty())
        return false;
    for (auto prefix : kExcludedPrefixes) {
        if (name.starts_with(prefix))
            return false;
    }
    return true;
}

// Infers a transport label from a device's /sys/block/<name> symlink target
// (e.g. ".../devices/pci0000:00/.../ata1/host0/target0:0:0/0:0:0:0/block/sda"
// or ".../devices/pci0000:00/.../nvme/nvme0/nvme0n1"), the native
// replacement for lsblk's TRAN column.
inline std::string transport_from_symlink(const std::string& link_target) {
    if (link_target.find("nvme") != std::string::npos)
        return "nvme";
    if (link_target.find("usb") != std::string::npos)
        return "usb";
    if (link_target.find("virtio") != std::string::npos)
        return "virtio";
    if (link_target.find("mmc") != std::string::npos)
        return "mmc";
    if (link_target.find("ata") != std::string::npos)
        return "sata";
    if (link_target.find("scsi") != std::string::npos)
        return "scsi";
    return "unknown";
}

inline std::string rtrim(std::string s) {
    while (!s.empty() &&
           (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s;
}

} // namespace detail

// Builds "disk|idx|model|size_gb|media_type|tran" rows from a caller-supplied
// list of /sys/block entry names, using the injected accessors for every
// file read. Size is a sector-derived GiB integer (/sys/block/<n>/size is
// always in 512-byte sectors regardless of the device's real block size,
// per Documentation/ABI/stable/sysfs-block), normalizing to the same unit
// the macOS (hardware_disks_macos.hpp) and Windows (Win32_DiskDrive) legs
// already report -- lsblk's default SIZE column was a human-readable string
// ("465.8G") with no equivalent from a raw sysfs read. Divides sectors
// directly by sectors-per-GiB (rather than sectors*512 then /2^30) so a
// device reporting nonsense-large sectors cannot wrap the intermediate
// multiplication into a fabricated small capacity. A device with zero
// sectors (no usable size read) is skipped; a genuinely sub-GiB device is
// KEPT at size_gb=0 -- it is distinguishable from the do_disks() failure
// sentinel ("disk|0|unknown|0|unknown|unknown") by a real model/name.
inline std::vector<std::string> build_linux_disk_rows(
    const std::vector<std::string>& block_device_names, const ReadFileFn& read_file,
    const ReadLinkFn& read_link) {
    constexpr unsigned long long kSectorsPerGiB = (1024ULL * 1024ULL * 1024ULL) / 512ULL;
    std::vector<std::string> rows;
    int idx = 0;
    for (const auto& name : block_device_names) {
        if (!detail::looks_like_real_disk(name))
            continue;

        auto size_raw = detail::rtrim(read_file("/sys/block/" + name + "/size"));
        unsigned long long sectors = 0;
        try {
            sectors = size_raw.empty() ? 0ULL : std::stoull(size_raw);
        } catch (...) {
            sectors = 0;
        }
        if (sectors == 0)
            continue;
        const unsigned long long gb = sectors / kSectorsPerGiB;

        auto model = detail::rtrim(read_file("/sys/block/" + name + "/device/model"));
        auto tran = detail::transport_from_symlink(read_link("/sys/block/" + name));

        // Media type from the two dedicated sysfs attributes lsblk itself
        // reads for TYPE/hotplug classification: `removable` (1 = hotpluggable
        // media, e.g. USB) takes precedence over `rotational` (0 = SSD/flash,
        // 1 = spinning HDD). Either file missing/unreadable (returns "") ->
        // "unknown", never a guessed value.
        auto removable = detail::rtrim(read_file("/sys/block/" + name + "/removable"));
        auto rotational = detail::rtrim(read_file("/sys/block/" + name + "/queue/rotational"));
        std::string media = removable == "1"   ? "Removable"
                            : rotational == "0" ? "SSD"
                            : rotational == "1" ? "HDD"
                                                : "unknown";

        rows.push_back("disk|" + std::to_string(idx++) + "|" + (model.empty() ? name : model) +
                        "|" + std::to_string(gb) + "|" + media + "|" + tran);
    }
    return rows;
}

} // namespace yuzu::hardware::linuxutil
