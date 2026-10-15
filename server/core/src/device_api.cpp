#include "device_api_local.hpp"

#include "agent_registry.hpp"
#include "tag_store.hpp"

namespace yuzu::server {

/// Store-backed `DeviceApi` implementation (ADR-0031 WS-A4, family=`device`).
/// `list_devices` walks the SAME source `server.cpp`'s `make_device_row`/
/// `to_json_obj()`-based providers use (the registry's own JSON snapshot,
/// which already carries exactly the 5-field public shape); `lookup_device`
/// is an O(1) `get_session` point lookup (#3564 — see device_api.hpp's
/// banner), never a linear scan.
class LocalDeviceApi final : public DeviceApi {
public:
    LocalDeviceApi(detail::AgentRegistry& registry, TagStore* tags)
        : registry_(registry), tags_(tags) {}

    LocalDeviceApi(const LocalDeviceApi&) = delete;
    LocalDeviceApi& operator=(const LocalDeviceApi&) = delete;

    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override {
        std::vector<DeviceListRow> out;
        const auto arr = registry_.to_json_obj();
        out.reserve(arr.size());
        for (const auto& a : arr) {
            DeviceListRow row;
            row.agent_id = a.value("agent_id", "");
            row.hostname = a.value("hostname", "");
            row.os = a.value("os", "");
            row.arch = a.value("arch", "");
            row.agent_version = a.value("agent_version", "");
            out.push_back(std::move(row));
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
};

std::shared_ptr<DeviceApi> make_local_device_api(detail::AgentRegistry& registry, TagStore* tags) {
    return std::make_shared<LocalDeviceApi>(registry, tags);
}

} // namespace yuzu::server
