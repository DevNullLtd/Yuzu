#include "device_api_local.hpp"

#include "agent_registry.hpp"
#include "tag_store.hpp"

namespace yuzu::server {

/// Store-backed `DeviceApi` implementation (ADR-0031 WS-A4, family=`device`).
/// `list_devices` walks the SAME source `server.cpp`'s `make_device_row`/
/// `to_json_obj()`-based providers use (the registry's own JSON snapshot,
/// which already carries exactly the 5 registry-derived public fields), then joins the
/// heartbeat-derived `guardian_backend` from the health store; `lookup_device`
/// is an O(1) `get_session` point lookup (#3564 — see device_api.hpp's
/// banner), never a linear scan.
///
/// HARD RULE (#2240): `guardian_backend` is EMITTED only by the REST and MCP device serialisers,
/// which sit behind `require_fleet_read` (the dashboard and crypto callers of this seam discard it).
/// It must never be added to `AgentRegistry::to_json_obj()`, to `make_device_row`/`devices_fn`
/// in server.cpp, or to the unauthenticated legacy `GET /api/agents`.
class LocalDeviceApi final : public DeviceApi {
public:
    LocalDeviceApi(detail::AgentRegistry& registry, TagStore* tags,
                   const detail::AgentHealthStore& health)
        : registry_(registry), tags_(tags), health_(health) {}

    LocalDeviceApi(const LocalDeviceApi&) = delete;
    LocalDeviceApi& operator=(const LocalDeviceApi&) = delete;

    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override {
        // Lock order: the registry's lock is taken and released inside to_json_obj(), THEN the
        // health store's mutex is taken once for the whole join. Two sequential acquisitions,
        // never nested, so there is no ordering relation with heartbeat ingest (which also
        // touches the two stores separately).
        const auto arr = registry_.to_json_obj();
        std::vector<std::string> ids;
        ids.reserve(arr.size());
        for (const auto& a : arr)
            ids.push_back(a.value("agent_id", ""));
        const auto backends = health_.guardian_backend_for(ids, detail::kAgentHealthStaleness);

        std::vector<DeviceListRow> out;
        out.reserve(arr.size());
        std::size_t i = 0;
        for (const auto& a : arr) {
            DeviceListRow row;
            row.agent_id = std::move(ids[i]);
            row.hostname = a.value("hostname", "");
            row.os = a.value("os", "");
            row.arch = a.value("arch", "");
            row.agent_version = a.value("agent_version", "");
            if (backends[i])
                row.guardian_backend = std::string{*backends[i]};
            out.push_back(std::move(row));
            ++i;
        }
        return out;
    }

    [[nodiscard]] std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string& agent_id) const override {
        // O(1) point lookup — NEVER a linear scan (#3564: a scan whose length
        // distinguishes "exists but out of scope" from "nonexistent" is a
        // timing oracle; see device_api.hpp's banner).
        auto session = registry_.get_session(agent_id);
        if (!session)
            return std::optional<DeviceDetail>{std::nullopt};

        DeviceDetail detail;
        detail.row.agent_id = session->agent_id;
        detail.row.hostname = session->hostname;
        detail.row.os = session->os;
        detail.row.arch = session->arch;
        detail.row.agent_version = session->agent_version;
        // Before the tag read, so a degraded tag store still answers kDegraded as it always has
        // and never a half-populated row. O(1) point lookup: #3564 cost symmetry holds.
        if (const auto backend =
                health_.guardian_backend_of(agent_id, detail::kAgentHealthStaleness))
            detail.row.guardian_backend = std::string{*backend};

        if (tags_) {
            auto t = tags_->get_all_tags(agent_id);
            if (!t)
                return std::unexpected(DeviceReadError::kDegraded);
            detail.tags.reserve(t->size());
            for (const auto& tag : *t)
                detail.tags.push_back(DeviceTagRow{tag.key, tag.value, tag.source});
        }

        return std::optional<DeviceDetail>{std::move(detail)};
    }

private:
    detail::AgentRegistry& registry_;
    TagStore* tags_; ///< nullable — degrades `tags` to empty, never an error
    const detail::AgentHealthStore& health_; ///< borrowed; see device_api_local.hpp LIFETIME
};

std::shared_ptr<DeviceApi> make_local_device_api(detail::AgentRegistry& registry, TagStore* tags,
                                                 const detail::AgentHealthStore& health) {
    return std::make_shared<LocalDeviceApi>(registry, tags, health);
}

} // namespace yuzu::server
