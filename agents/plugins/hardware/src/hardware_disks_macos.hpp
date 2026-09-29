#pragma once

// hardware_disks_macos.hpp — pure parser for macOS `system_profiler -json`
// storage output, producing the cross-platform pipe-delimited disk rows
// consumed by do_disks() in hardware_plugin.cpp.
//
// Platform-agnostic and header-only so it compiles and its unit tests run on
// every host (matching the dex_macos_*.hpp / test_dex_macos.cpp precedent)
// even though it is only ever invoked from the __APPLE__ branch of the plugin.
//
// Scope (PR1.8, PLAN-01/02): INTERNAL NVMe + SATA physical disks only.
// SPStorageDataType entries are per-volume APFS/logical records (mount_point/
// file_system/volume_uuid) whose physical_drive duplicates the internal NVMe
// disk and carries no disk-level size — they are NEVER enumerated as disks.
// SPStorageDataType is read only as a lookup table: physical_drive.medium_type
// keyed by physical_drive.device_name, to classify SATA media type.
//
// The SATA path is best-effort: no real SATA/Intel fixture is obtainable on
// an Apple-Silicon host, so it is exercised only by synthetic specimens in
// the unit test and is NOT validated parity against real hardware.

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yuzu::hardware::macos {

namespace detail {

// Replace pipe and any control byte (including CR/LF and NUL) with a space so
// an odd/hostile model string can never shift the downstream pipe-column
// parse or forge a second row (PLAN-06).
inline std::string sanitize_disk_field(std::string value) {
    for (char& c : value) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '|' || byte < 0x20 || byte == 0x7f)
            c = ' ';
    }
    return value;
}

// Looks up physical_drive.medium_type for a given device_name across every
// SPStorageDataType[] volume record (each a plain object with a nested
// physical_drive object — NOT wrapped in an _items array, unlike
// SPNVMeDataType / SPSerialATADataType). Defensive against missing/odd
// shapes; returns "" when no match is found.
inline std::string sata_medium_type_for(const nlohmann::json& storage_volumes,
                                         const std::string& device_name) {
    if (device_name.empty() || !storage_volumes.is_array())
        return {};

    for (const auto& volume : storage_volumes) {
        if (!volume.is_object())
            continue;
        auto pd_it = volume.find("physical_drive");
        if (pd_it == volume.end() || !pd_it->is_object())
            continue;
        auto name_it = pd_it->find("device_name");
        if (name_it == pd_it->end() || !name_it->is_string())
            continue;
        if (name_it->get<std::string>() != device_name)
            continue;
        auto medium_it = pd_it->find("medium_type");
        if (medium_it != pd_it->end() && medium_it->is_string())
            return medium_it->get<std::string>();
        continue; // this volume matched by name but has no usable medium_type -
                  // keep scanning in case a later volume for the same device
                  // carries it (PKG01-002)
    }
    return {};
}

} // namespace detail

// Enumerates internal physical disks from a `system_profiler SPStorageDataType
// SPNVMeDataType SPSerialATADataType -json` capture: SPNVMeDataType[]._items[]
// then SPSerialATADataType[]._items[], in that order. Returns {} on ANY
// top-level parse/structure failure (the only path that returns {}); a single
// malformed per-disk item is skipped (continue) without discarding
// already-parsed valid rows (PLAN-05).
inline std::vector<std::string> parse_macos_disks(const std::string& system_profiler_json) {
    std::vector<std::string> rows;

    try {
        auto root = nlohmann::json::parse(system_profiler_json);
        if (!root.is_object())
            return {};

        const nlohmann::json empty_array = nlohmann::json::array();
        auto storage_it = root.find("SPStorageDataType");
        const nlohmann::json& storage_volumes =
            (storage_it != root.end() && storage_it->is_array()) ? *storage_it : empty_array;

        int idx = 0;

        auto enumerate = [&](const char* key, bool is_nvme) {
            auto ctrl_it = root.find(key);
            if (ctrl_it == root.end() || !ctrl_it->is_array())
                return;

            for (const auto& controller : *ctrl_it) {
                if (!controller.is_object())
                    continue;
                auto items_it = controller.find("_items");
                if (items_it == controller.end() || !items_it->is_array())
                    continue;

                for (const auto& item : *items_it) {
                    try {
                        if (!item.is_object())
                            continue;

                        std::string raw_model;
                        if (auto it = item.find("device_model");
                            it != item.end() && it->is_string() && !it->get<std::string>().empty()) {
                            raw_model = it->get<std::string>();
                        } else if (auto it2 = item.find("_name");
                                   it2 != item.end() && it2->is_string() &&
                                   !it2->get<std::string>().empty()) {
                            raw_model = it2->get<std::string>();
                        } else {
                            continue; // no usable identity - skip this item only
                        }

                        long long bytes = 0;
                        if (auto it = item.find("size_in_bytes");
                            it != item.end() && it->is_number_integer()) {
                            bytes = it->get<long long>();
                        }
                        const long long gb = bytes / (1024LL * 1024 * 1024);
                        if (gb <= 0)
                            continue; // no positive capacity - fail closed, skip this item only (BR-001)
                        const std::string size_gb = std::to_string(gb);

                        std::string type;
                        std::string iface;
                        if (is_nvme) {
                            // NVMe is solid-state by construction.
                            type = "SSD";
                            iface = "NVMe";
                        } else {
                            iface = "SATA";
                            auto medium = detail::sata_medium_type_for(storage_volumes, raw_model);
                            if (medium == "ssd")
                                type = "SSD";
                            else if (!medium.empty())
                                type = "HDD";
                            else
                                type = "unknown";
                        }

                        rows.push_back("disk|" + std::to_string(idx) + "|" +
                                       detail::sanitize_disk_field(raw_model) + "|" + size_gb + "|" +
                                       type + "|" + iface);
                        ++idx;
                    } catch (...) {
                        continue; // malformed item - never discard already-parsed rows
                    }
                }
            }
        };

        enumerate("SPNVMeDataType", true);
        enumerate("SPSerialATADataType", false);
    } catch (...) {
        return {};
    }

    return rows;
}

// The function do_disks() actually calls: rows-or-sentinel seam (PLAN-04).
// Returns parse_macos_disks() when it finds at least one physical disk, else
// the house failure sentinel the downstream skip
// (t[2]=="unknown" && t[3]=="0") fires on.
inline std::vector<std::string> macos_disk_rows_or_sentinel(const std::string& system_profiler_json) {
    auto rows = parse_macos_disks(system_profiler_json);
    if (!rows.empty())
        return rows;
    return {"disk|0|unknown|0|unknown|unknown"};
}

} // namespace yuzu::hardware::macos
