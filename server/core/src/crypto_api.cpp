#include "crypto_api_local.hpp"

#include "crypto_library_model.hpp"
#include "device_api.hpp"
#include "software_inventory_store.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

namespace cl = crypto_library;

// The scope as the store's push-down argument: nullopt (TOP) = unfiltered, present-empty =
// deny-all (the store answers that with no SQL), otherwise the whole set.
std::optional<std::vector<std::string>> to_agent_ids(const authz::VisibleSet& scope) {
    if (!scope)
        return std::nullopt;
    return std::vector<std::string>(scope->begin(), scope->end());
}

CryptoReadError degraded() { return {CryptoReadError::Kind::kDegraded, "inventory read degraded"}; }

class LocalCryptoApi final : public CryptoApi {
public:
    LocalCryptoApi(SoftwareInventoryStore& store, const DeviceApi* devices)
        : store_(store), devices_(devices) {}

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        if (q.family && !cl::find_family(*q.family))
            return std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "unknown family"});
        auto pats = cl::sql_patterns(q.family ? std::optional<std::string_view>(*q.family)
                                              : std::nullopt);
        NamePatternQuery sq;
        sq.patterns = std::move(pats.patterns);
        sq.labels = std::move(pats.labels);
        sq.ecosystem = q.ecosystem;
        sq.agent_ids = to_agent_ids(scope);

        const auto rollup = store_.software_name_pattern_rollup(sq);
        if (!rollup)
            return std::unexpected(degraded());
        const auto reporting = store_.count_reporting_agents(sq.agent_ids);
        if (!reporting)
            return std::unexpected(degraded());

        CryptoSummary out;
        out.coverage.devices_reporting_inventory = *reporting;
        out.coverage.devices_with_crypto_library = rollup->total_devices;
        out.result_truncated = rollup->truncated;
        std::unordered_map<std::string, std::size_t> index;
        for (const auto& lc : rollup->label_counts) {
            index.emplace(lc.label, out.families.size());
            CryptoFamilyRow f;
            f.id = lc.label;
            f.device_count = lc.device_count;
            out.families.push_back(std::move(f));
        }
        for (const auto& r : rollup->rows) {
            const auto it = index.find(r.label);
            if (it == index.end())
                continue;
            CryptoVersionRow v;
            v.version = r.version;
            v.ecosystem = r.ecosystem;
            v.device_count = r.device_count;
            // Re-check each name against the table: only names that really classify to the
            // family are shown.
            for (const auto& n : r.names)
                if (cl::classify(n) == std::string_view(r.label))
                    v.package_names.push_back(n);
            out.families[it->second].versions.push_back(std::move(v));
        }
        cl::finish_summary(out);
        return out;
    }

    std::expected<CryptoDevicesPage, CryptoReadError>
    library_devices(const CryptoDevicesQuery& q, const authz::VisibleSet& scope) const override {
        if (!cl::find_family(q.family))
            return std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "unknown family"});
        NamePatternDevicesQuery sq;
        sq.patterns = cl::sql_patterns(q.family).patterns;
        sq.version = q.version;
        sq.ecosystem = q.ecosystem;
        sq.agent_ids = to_agent_ids(scope);
        sq.limit = std::clamp<int>(q.limit, 1, static_cast<int>(cl::kPageMax));
        const std::string fp = cl::devices_fingerprint(q);
        if (!q.cursor.empty()) {
            const auto pos = cl::decode_cursor(q.cursor, fp);
            if (!pos)
                return std::unexpected(CryptoReadError{
                    CryptoReadError::Kind::kInvalid, std::string(cl::cursor_error_message(pos.error()))});
            sq.after = SoftwareCursor{pos->name, pos->agent_id, pos->install_id};
        }

        const auto page = store_.software_name_pattern_devices(sq);
        if (!page)
            return std::unexpected(degraded());

        std::unordered_map<std::string, std::string> hostnames;
        if (devices_ && !page->rows.empty())
            for (auto& d : devices_->list_devices())
                hostnames.emplace(std::move(d.agent_id), std::move(d.hostname));

        CryptoDevicesPage out;
        out.family = q.family;
        out.version = q.version;
        for (const auto& r : page->rows) {
            if (cl::classify(r.entry.name) != std::string_view(q.family))
                continue;
            CryptoDeviceRow d;
            d.agent_id = r.agent_id;
            if (const auto h = hostnames.find(r.agent_id); h != hostnames.end())
                d.hostname = h->second;
            d.package_name = r.entry.name;
            d.version = r.entry.version;
            d.release = r.entry.release;
            d.ecosystem = r.entry.ecosystem;
            d.kind = r.entry.kind;
            out.devices.push_back(std::move(d));
        }
        // The cursor is the last row READ, not the last row shown, so a defensive drop above
        // can never stall or repeat a page.
        if (page->has_more && !page->rows.empty()) {
            const auto& last = page->rows.back();
            out.next_cursor = cl::encode_cursor({last.agent_id, last.entry.name, last.install_id}, fp);
        }
        return out;
    }

private:
    SoftwareInventoryStore& store_;
    const DeviceApi* devices_;
};

} // namespace

std::shared_ptr<CryptoApi> make_local_crypto_api(SoftwareInventoryStore& store,
                                                 const DeviceApi* device_api) {
    return std::make_shared<LocalCryptoApi>(store, device_api);
}

} // namespace yuzu::server
