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
    }
}

} // namespace yuzu::server
