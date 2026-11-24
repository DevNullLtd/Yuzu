#pragma once

/// @file test_fake_ci_keyset_store.hpp
/// An in-memory stand-in for `DeviceInventoryStore::list_device_ci_after`, shared by the model,
/// route and MCP tests of the bulk CI page. Same keyset semantics as the SQL: `agent_id > after`,
/// the optional `agent_id` / `agent_ids` narrowing, then up to `limit` rows, ordered by `agent_id`.
/// The order is BYTE order (`std::string`'s comparison is unsigned-byte lexicographic), which is
/// the SAME contract as the store's `agent_id COLLATE "C"`, not a stand-in for locale order: a
/// test that adds ids the two orders would arrange differently (upper and lower case, `-` and `_`,
/// digits against letters) checks this fake and the real store against one rule. A present-empty
/// `agent_ids` reads nothing. A `limit` of zero or below, or above `kStoreRowCeiling`, reads the
/// ceiling, as the store does (it never answers zero rows for a non-positive limit). `degraded`
/// makes every read fail (nullopt), as a closed store or a query error does.
///
/// It exists so a confinement test can assert the EXACT set of devices that came back: a fake
/// that only recorded the scope it was handed would stay green with the intersection deleted.

#include "device_inventory_types.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

inline DeviceCiRecord make_ci_record(std::string id) {
    DeviceCiRecord r;
    r.agent_id = std::move(id);
    r.hostname = "host-" + r.agent_id;
    r.manufacturer = "Dell Inc.";
    r.model = "Latitude 7420";
    r.serial = "SN-" + r.agent_id;
    r.cpu_cores = "4";
    r.ram_bytes = "17179869184";
    r.first_seen = 100;
    r.last_seen = 200;
    r.blob_version = 2;
    r.content_hash = "hash-" + r.agent_id;
    return r;
}

/// The widest row the wire can carry: every free-text field at the 1024-byte ingest clamp and made
/// of 0x01 bytes, which JSON escapes to the six-byte `\u0001` (the longest form per byte), so one
/// row serves at roughly 180 KB. `fill` picks another byte (a `"` doubles in the row's own JSON and
/// doubles again in the MCP text copy, the worst case for that copy). The numeric fields stay plain
/// decimals. `id` is the agent_id; the byte-bound tests walk and measure rows made with it.
inline DeviceCiRecord make_worst_case_ci_record(std::string id, char fill = '\x01') {
    DeviceCiRecord r;
    const std::string wide(1024, fill);
    r.agent_id = std::move(id);
    for (std::string* f :
         {&r.manufacturer, &r.model, &r.serial, &r.system_uuid, &r.hostname, &r.domain, &r.ou,
          &r.bios_vendor, &r.bios_version, &r.bios_date, &r.cpu_model, &r.disks_summary,
          &r.primary_mac, &r.macs_summary, &r.os_name, &r.os_version, &r.os_build, &r.arch,
          &r.chassis_type, &r.chassis_serial, &r.chassis_asset_tag, &r.chassis_source,
          &r.board_vendor, &r.board_product, &r.board_serial, &r.board_source, &r.machine_id_hash,
          &r.machine_id_algorithm, &r.machine_id_source})
        *f = wide;
    r.cpu_cores = "64";
    r.cpu_threads = "128";
    r.ram_bytes = "17179869184";
    r.nic_count = "8";
    r.first_seen = 1700000000;
    r.last_seen = 1700000999;
    r.blob_version = 2;
    r.content_hash = std::string(64, 'f');
    return r;
}

/// The store's own row ceiling (`kListRowCap` in device_inventory_store.cpp, 100000), which the
/// store's ceiling test reads for real.
inline constexpr int kStoreRowCeiling = 100000;

struct FakeCiKeysetStore {
    std::vector<DeviceCiRecord> rows; // kept sorted by agent_id
    bool degraded = false;
    int reads = 0;
    std::vector<DeviceCiKeysetQuery> queries;

    void add(DeviceCiRecord r) {
        rows.push_back(std::move(r));
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.agent_id < b.agent_id; });
    }
    void add(const std::string& id) { add(make_ci_record(id)); }
    /// Removes the row (a device decommissioned while a walk is in progress).
    void erase(const std::string& id) {
        std::erase_if(rows, [&](const auto& r) { return r.agent_id == id; });
    }

    std::optional<std::vector<DeviceCiRecord>> read(const DeviceCiKeysetQuery& q) {
        ++reads;
        queries.push_back(q);
        if (degraded)
            return std::nullopt;
        std::vector<DeviceCiRecord> out;
        if (q.agent_ids && q.agent_ids->empty())
            return out;
        const int eff = q.limit > 0 && q.limit < kStoreRowCeiling ? q.limit : kStoreRowCeiling;
        std::set<std::string> ids;
        if (q.agent_ids)
            ids.insert(q.agent_ids->begin(), q.agent_ids->end());
        for (const auto& r : rows) {
            if (!q.after.empty() && !(r.agent_id > q.after))
                continue;
            if (q.agent_id && r.agent_id != *q.agent_id)
                continue;
            if (q.agent_ids && !ids.contains(r.agent_id))
                continue;
            if (static_cast<int>(out.size()) >= eff)
                break;
            out.push_back(r);
        }
        return out;
    }

    /// The Reader closure. Captures `this`: the store must outlive the closure's use.
    std::function<std::optional<std::vector<DeviceCiRecord>>(const DeviceCiKeysetQuery&)> reader() {
        return [this](const DeviceCiKeysetQuery& q) { return read(q); };
    }
};

} // namespace yuzu::server::test
