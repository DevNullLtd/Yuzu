/// @file inventory_ci_join.cpp
/// See inventory_ci_join.hpp.

#include "inventory_ci_join.hpp"

namespace yuzu::server {

void attach_device_ci(std::vector<InventoryDeviceRow>& rows,
                      const std::unordered_map<std::string, DeviceCiRecord>& ci_by_agent) {
    for (auto& row : rows) {
        auto it = ci_by_agent.find(row.agent_id);
        if (it == ci_by_agent.end())
            continue; // no CI synced for this agent yet — leave the ci_* fields blank
        const DeviceCiRecord& ci = it->second;
        row.ci_serial = ci.serial;
        row.ci_model = ci.model;
        row.ci_cpu_cores = ci.cpu_cores;
        row.ci_cpu_threads = ci.cpu_threads;
        row.ci_ram_bytes = ci.ram_bytes;
        row.ci_manufacturer = ci.manufacturer;
        row.ci_cpu_model = ci.cpu_model;
        row.ci_os_name = ci.os_name;
        row.ci_os_version = ci.os_version;
        row.ci_os_build = ci.os_build;
        row.ci_arch = ci.arch;
        row.ci_domain = ci.domain;
        row.ci_primary_mac = ci.primary_mac;
        row.ci_chassis_asset_tag = ci.chassis_asset_tag;
        row.ci_chassis_serial = ci.chassis_serial;
        row.ci_board_serial = ci.board_serial;
    }
}

void apply_ci_read(InventoryDevicesResult& result, const CiKeyedReadFn& read) {
    if (!read) {
        result.ci_degraded = true; // an unwired store reads as a failed one (CiDetailFn contract)
        return;
    }
    if (result.rows.empty())
        return; // nothing to enrich: no read, and no degrade to report
    std::vector<std::string> ids;
    ids.reserve(result.rows.size());
    for (const auto& row : result.rows)
        ids.push_back(row.agent_id);
    auto records = read(ids);
    if (!records) {
        result.ci_degraded = true;
        return;
    }
    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent;
    ci_by_agent.reserve(records->size());
    for (auto& rec : *records) {
        // The key is copied from `rec.agent_id` before `std::move(rec)` empties it (a pair's
        // members initialise in declaration order). Nothing reads the map VALUE's own
        // `.agent_id` afterwards; `attach_device_ci` never does.
        std::string key = rec.agent_id;
        ci_by_agent.emplace(std::move(key), std::move(rec));
    }
    attach_device_ci(result.rows, ci_by_agent);
}

} // namespace yuzu::server
