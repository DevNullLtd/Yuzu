#pragma once

/// @file test_fake_ci_keyset_store.hpp
/// An in-memory stand-in for `DeviceInventoryStore::list_device_ci_after`, shared by the model,
/// route and MCP tests of the bulk CI page. Same keyset semantics as the SQL: `agent_id > after`,
/// the optional `agent_id` / `agent_ids` narrowing, then up to `limit` rows, ordered by `agent_id`. A present-empty `agent_ids` reads nothing. `degraded` makes every
/// read fail (nullopt), as a closed store or a query error does.
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

    std::optional<std::vector<DeviceCiRecord>> read(const DeviceCiKeysetQuery& q) {
        ++reads;
        queries.push_back(q);
        if (degraded)
            return std::nullopt;
        std::vector<DeviceCiRecord> out;
        if (q.agent_ids && q.agent_ids->empty())
            return out;
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
            if (static_cast<int>(out.size()) >= q.limit)
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
