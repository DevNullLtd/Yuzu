#include "crypto_api_local.hpp"

#include "crypto_library_model.hpp"
#include "crypto_read_gate.hpp"
#include "device_api.hpp"
#include "software_inventory_store.hpp"

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

namespace cl = crypto_library;

// The model's lead length and the store's literal in the step-1 SQL must agree.
static_assert(cl::kLeadChars == kNamePatternLeadChars,
              "crypto lead length must equal the store's literal lead length");

// crypto_ui.cpp's busy banners ("two reads are already running") and crypto.md hard-code the
// admission bound; crypto_ui may not include the gate, so the pin sits here in the seam TU.
static_assert(kMaxConcurrentCryptoReads == 2,
              "update the busy banners in crypto_ui.cpp and the crypto.md wording");

// The scope as the store's push-down argument: nullopt (TOP) = unfiltered, present-empty =
// deny-all (the store answers that with no SQL), otherwise the whole set.
std::optional<std::vector<std::string>> to_agent_ids(const authz::VisibleSet& scope) {
    if (!scope)
        return std::nullopt;
    return std::vector<std::string>(scope->begin(), scope->end());
}

// The store read failed (pool, query, 5 s bound, store not open).
CryptoReadError degraded() {
    return {CryptoReadError::Kind::kDegraded, std::string(cl::degraded_message(CryptoReadCause::kStoreDegraded)),
            CryptoReadCause::kStoreDegraded};
}

// The admission refusal: same kind as a store degrade, so every transport answers it as a 503 +
// retry_after_ms (fragment "temporarily unavailable") - but its own cause, and no store call.
CryptoReadError capacity_in_use() {
    return {CryptoReadError::Kind::kDegraded, std::string(cl::degraded_message(CryptoReadCause::kCapacity)),
            CryptoReadCause::kCapacity};
}

class LocalCryptoApi final : public CryptoApi {
public:
    LocalCryptoApi(SoftwareInventoryStore& store, const DeviceApi* devices, int max_reads)
        : store_(store), devices_(devices), gate_(max_reads) {}

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        if (q.family && !cl::find_family(*q.family))
            return std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "unknown family"});
        auto pats = cl::sql_patterns(q.family ? std::optional<std::string_view>(*q.family)
                                              : std::nullopt);
        NamePatternQuery sq;
        sq.patterns = std::move(pats.patterns);
        sq.labels = std::move(pats.labels);
        sq.leads = std::move(pats.leads);
        sq.ecosystem = q.ecosystem;
        sq.agent_ids = to_agent_ids(scope);

        std::optional<NamePatternRollup> rollup;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease) {
                store_.note_read_shed();
                return std::unexpected(capacity_in_use());
            }
            rollup = store_.software_name_pattern_rollup(sq);
        }
        if (!rollup)
            return std::unexpected(degraded());

        CryptoSummary out;
        // "Reporting" = a device with an installed_software inventory_state row, counted in the
        // SAME statement as the numerator (one snapshot). A device that has package rows but no
        // state row (a partial cascade) is still a device that reported, so the denominator is
        // floored at the numerator: with-library <= reporting always holds.
        out.coverage.devices_reporting_inventory =
            std::max(rollup->reporting_agents, rollup->total_devices);
        out.coverage.devices_with_crypto_library = rollup->total_devices;
        out.result_truncated = rollup->truncated;
        out.names_from_catalogue = rollup->names_as_of > 0;
        out.names_as_of = rollup->names_as_of;
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
        {
            auto pats = cl::sql_patterns(q.family);
            sq.patterns = std::move(pats.patterns);
            sq.leads = std::move(pats.leads);
        }
        sq.version = q.version;
        sq.ecosystem = q.ecosystem;
        sq.agent_ids = to_agent_ids(scope);
        sq.limit = std::clamp<int>(q.limit, 1, static_cast<int>(cl::kPageMax));
        const std::string fp = cl::devices_fingerprint(q);
        std::optional<cl::CursorPos> cursor_pos;
        if (!q.cursor.empty()) {
            const auto pos = cl::decode_cursor(q.cursor, fp);
            if (!pos)
                return std::unexpected(CryptoReadError{
                    CryptoReadError::Kind::kInvalid, std::string(cl::cursor_error_message(pos.error()))});
            cursor_pos = *pos;
            sq.after = SoftwareCursor{
                .name = pos->name, .agent_id = pos->agent_id, .install_id = pos->install_id};
        }

        // The admission lease covers the store read ONLY: it is released before the hostname
        // join below, which holds no pool connection.
        std::optional<NamePatternDevicesPage> page;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease) {
                store_.note_read_shed();
                return std::unexpected(capacity_in_use());
            }
            page = store_.software_name_pattern_devices(sq);
        }
        if (!page)
            return std::unexpected(degraded());
        // Only ONE names-source transition is refused: a page whose cursor was issued on LIVE
        // names, when this page finds the catalogue in use (the catalogue may lack names first
        // reported after its refresh). catalogue -> newer catalogue and catalogue -> live
        // continue (live lists every name). The refusal normally happens once, but it happens
        // again each time the catalogue goes stale (refresh failing past two hours, or a
        // database clock step) and then recovers during the same walk. A newer catalogue lists
        // every name that had rows at ITS refresh; a name with no rows anywhere at that refresh
        // that reappears before the next one is missed for the rest of the walk, as on a fresh
        // walk on that catalogue (the documented catalogue lag). Rows are ordered agent first,
        // so on a continue a name new in the newer source IS listed for devices after the
        // cursor; only its rows on devices already passed are missed. Restart to see them.
        if (cursor_pos && cursor_pos->names_as_of == 0 && page->names_as_of > 0)
            return std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid,
                                                   std::string(cl::names_source_changed_message())});

        std::unordered_map<std::string, std::string> hostnames;
        if (devices_ && !page->rows.empty())
            for (auto& d : devices_->list_devices())
                hostnames.emplace(std::move(d.agent_id), std::move(d.hostname));

        CryptoDevicesPage out;
        out.family = q.family;
        out.version = q.version;
        out.ecosystem = q.ecosystem;
        out.names_from_catalogue = page->names_as_of > 0;
        out.names_as_of = page->names_as_of;
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
            out.next_cursor = cl::encode_cursor(
                {.agent_id = last.agent_id, .name = last.entry.name,
                 .install_id = last.install_id, .names_as_of = page->names_as_of},
                fp);
        }
        return out;
    }

private:
    SoftwareInventoryStore& store_;
    const DeviceApi* devices_;
    // Per-process bound on in-flight store reads, shared by both methods. The lease is a scoped
    // RAII block around the store call, so every path - and any throw - releases it.
    mutable CryptoReadGate gate_;
};

} // namespace

std::shared_ptr<CryptoApi> make_local_crypto_api(SoftwareInventoryStore& store,
                                                 const DeviceApi* device_api,
                                                 int max_concurrent_reads) {
    return std::make_shared<LocalCryptoApi>(store, device_api, max_concurrent_reads);
}

} // namespace yuzu::server
