#include "crypto_api_local.hpp"

#include "ca_store.hpp"
#include "crypto_dashboard_layout_store.hpp"
#include "crypto_library_model.hpp"
#include "crypto_read_gate.hpp"
#include "crypto_widget_catalogue.hpp"
#include "device_api.hpp"
#include "software_inventory_store.hpp"

#include <algorithm>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

namespace cl = crypto_library;
namespace cw = crypto_widgets;

// The model's lead length and the store's literal in the step-1 SQL must agree.
static_assert(cl::kLeadChars == kNamePatternLeadChars,
              "crypto lead length must equal the store's literal lead length");

// crypto_ui.cpp's busy banners ("two reads are already running") and crypto.md hard-code the
// admission bound; crypto_ui may not include the gate, so the pin sits here in the seam TU.
static_assert(kMaxConcurrentCryptoReads == 2,
              "update the busy banners in crypto_ui.cpp and the crypto.md wording");

// The layout store's defence-in-depth bounds may never be tighter than the catalogue's: a layout
// the catalogue accepts must always be storable. The pin sits here because the seam lint keeps
// the store header out of every TU that sees only the catalogue.
static_assert(CryptoDashboardLayoutStore::kMaxIds >= cw::kMaxLayoutWidgets,
              "the layout store must hold every layout the catalogue accepts");
static_assert(CryptoDashboardLayoutStore::kMaxIdBytes >= cw::kWidgetIdMaxBytes,
              "the layout store must hold every catalogue id");

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

// A Yuzu-issued or layout read that could not be answered: the store failed or is not wired.
// Same kind and cause as a library degrade (503 + retry everywhere), its own wording.
CryptoReadError unavailable(std::string_view what) {
    return {CryptoReadError::Kind::kDegraded, std::string(what), CryptoReadCause::kStoreDegraded};
}

constexpr std::string_view kCaUnavailable = "Yuzu CA read degraded";
constexpr std::string_view kLayoutUnavailable = "dashboard layout read degraded";

CryptoReadError invalid(std::string message) {
    return {CryptoReadError::Kind::kInvalid, std::move(message)};
}

CaIssuedFilter::Kind to_filter_kind(CaCertKind k) {
    using F = CaIssuedFilter::Kind;
    switch (k) {
    case CaCertKind::kActive:
        return F::kActive;
    case CaCertKind::kExpiring:
        return F::kExpiring;
    case CaCertKind::kExpired:
        return F::kExpired;
    case CaCertKind::kRevoked:
        return F::kRevoked;
    case CaCertKind::kIssued:
        return F::kIssued;
    case CaCertKind::kIssuedWeek:
        return F::kIssuedWeek;
    case CaCertKind::kRevokedWeek:
        return F::kRevokedWeek;
    }
    return F::kActive; // unreachable: every enumerator returns above
}

std::vector<CaWindowCount> window_counts(std::span<const int> days,
                                         const std::vector<std::int64_t>& counts) {
    std::vector<CaWindowCount> out;
    for (std::size_t i = 0; i < days.size() && i < counts.size(); ++i)
        out.push_back({days[i], counts[i]});
    return out;
}

class LocalCryptoApi final : public CryptoApi {
public:
    explicit LocalCryptoApi(const LocalCryptoApiDeps& d)
        : store_(d.software), devices_(d.devices), ca_(d.ca), layouts_(d.layouts),
          gate_(d.max_concurrent_reads) {}

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        if (q.family && !cl::find_family(*q.family))
            return std::unexpected(CryptoReadError{CryptoReadError::Kind::kInvalid, "unknown family"});
        if (!store_)
            return std::unexpected(degraded());
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
                store_->note_read_shed();
                return std::unexpected(capacity_in_use());
            }
            rollup = store_->software_name_pattern_rollup(sq);
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
            v.package_names_truncated = r.names_truncated;
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
        if (!store_)
            return std::unexpected(degraded());
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
                store_->note_read_shed();
                return std::unexpected(capacity_in_use());
            }
            page = store_->software_name_pattern_devices(sq);
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
        // that reappears before the next one is missed until a later refresh lists it, as on a
        // fresh walk on that catalogue (the documented catalogue lag). Rows are ordered agent
        // first and a walk is not a snapshot: on a continue a name new in the newer source IS
        // listed for devices after the cursor, and any row appearing on a device already passed
        // is missed. Restart to see them.
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

    std::expected<CaCertStats, CryptoReadError> ca_stats(std::int64_t as_of) const override {
        if (!ca_)
            return std::unexpected(unavailable(kCaUnavailable));
        CaIssuanceStatsRequest rq;
        rq.as_of = as_of;
        rq.week_start_of = cw::week_start_of;
        rq.expiring_days.assign(cw::kExpiringWindowDays.begin(), cw::kExpiringWindowDays.end());
        rq.expired_days.assign(cw::kExpiredWindowDays.begin(), cw::kExpiredWindowDays.end());
        rq.revoked_days.assign(cw::kRevokedWindowDays.begin(), cw::kRevokedWindowDays.end());
        rq.issued_days = cw::kIssuedWindowDays;
        rq.weeks = cw::kWeeklyBuckets;

        std::optional<std::expected<CaIssuanceStats, CaReadError>> read;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease)
                return std::unexpected(capacity_in_use());
            read = ca_->issuance_stats(rq);
        }
        if (!*read)
            return std::unexpected(unavailable(kCaUnavailable));
        const auto& st = **read;
        CaCertStats out;
        out.as_of = st.as_of;
        out.active = st.active;
        out.expiring = window_counts(cw::kExpiringWindowDays, st.expiring);
        out.expired = window_counts(cw::kExpiredWindowDays, st.expired);
        std::vector<std::int64_t> revoked;
        for (const auto& rc : st.revoked)
            revoked.push_back(rc.total());
        out.revoked = window_counts(cw::kRevokedWindowDays, revoked);
        out.issued = {cw::kIssuedWindowDays, st.issued};
        for (std::size_t i = 0; i < st.week_starts.size(); ++i)
            out.weeks.push_back({st.week_starts[i], cw::iso_week_label(st.week_starts[i]),
                                 i < st.issued_per_week.size() ? st.issued_per_week[i] : 0,
                                 i < st.revoked_per_week.size() ? st.revoked_per_week[i].total()
                                                                : 0});
        return out;
    }

    std::expected<CaCertPage, CryptoReadError> ca_certificates(const CaCertQuery& q,
                                                               std::int64_t as_of) const override {
        if (cw::kind_takes_days(q.kind)) {
            const auto set = cw::windows_for(q.kind);
            if (std::ranges::find(set, q.days) == set.end())
                return std::unexpected(invalid("days is not a window of the closed set for kind " +
                                               std::string(cw::ca_kind_name(q.kind))));
        }
        if (cw::kind_takes_week(q.kind) && cw::week_start_of(q.week_start) != q.week_start)
            return std::unexpected(invalid("week_start must be a Monday 00:00 UTC"));
        if (q.offset < 0 || q.offset > cw::kCertOffsetMax)
            return std::unexpected(invalid("offset out of range"));
        if (!ca_)
            return std::unexpected(unavailable(kCaUnavailable));
        CaCertPage out;
        out.query = q;
        out.query.limit = std::clamp(q.limit, 1, cw::kCertPageMax);
        if (!cw::kind_takes_days(q.kind))
            out.query.days = 0;
        if (!cw::kind_takes_week(q.kind))
            out.query.week_start = 0;
        out.as_of = as_of;
        CaIssuedFilter f;
        f.kind = to_filter_kind(q.kind);
        f.days = out.query.days;
        f.week_start = out.query.week_start;

        std::optional<std::expected<CaIssuedPage, CaReadError>> read;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease)
                return std::unexpected(capacity_in_use());
            read = ca_->list_issued_filtered(f, std::optional<std::int64_t>{as_of}, out.query.limit,
                                            out.query.offset);
        }
        if (!*read)
            return std::unexpected(unavailable(kCaUnavailable));
        out.total = (*read)->total;
        for (auto& r : (*read)->rows)
            out.rows.push_back({std::move(r.serial_hex), std::move(r.subject), std::move(r.purpose),
                                r.issued_at, r.not_after, cert_status_to_string(r.status),
                                r.revoked_at});
        out.truncated = out.query.offset + static_cast<std::int64_t>(out.rows.size()) < out.total;
        return out;
    }

    std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const override {
        if (username.empty())
            return std::unexpected(invalid("no operator to read a layout for"));
        if (!layouts_)
            return std::unexpected(unavailable(kLayoutUnavailable));
        std::optional<std::expected<std::optional<StoredCryptoLayout>, CryptoLayoutStoreError>>
            read;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease)
                return std::unexpected(capacity_in_use());
            read = layouts_->get(username);
        }
        if (!*read)
            return std::unexpected(unavailable(kLayoutUnavailable));
        if (!**read)
            return CryptoDashboardLayout{cw::default_layout_ids(), true};
        return CryptoDashboardLayout{cw::known_ids((***read).widget_ids), false};
    }

    std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username,
                         const std::vector<std::string>& widgets) const override {
        if (username.empty())
            return std::unexpected(invalid("no operator to save a layout for"));
        if (const auto bad = cw::layout_error(widgets))
            return std::unexpected(invalid(*bad));
        if (!layouts_)
            return std::unexpected(unavailable("dashboard layout save failed"));
        std::optional<std::expected<std::int64_t, CryptoLayoutStoreError>> wrote;
        {
            const auto lease = gate_.try_acquire(); // released when this block ends, throw included
            if (!lease)
                return std::unexpected(capacity_in_use());
            // Replace whatever is stored now (a corrupt row included): read its version, then
            // write against it.
            const auto cur = layouts_->get(username);
            std::optional<std::int64_t> expected;
            if (cur && *cur)
                expected = (**cur).version;
            else if (!cur && cur.error().kind == CryptoLayoutStoreError::Kind::kCorrupt)
                expected = cur.error().version;
            else if (!cur)
                return std::unexpected(unavailable("dashboard layout save failed"));
            wrote = layouts_->put(username, widgets, expected);
        }
        if (!*wrote)
            return std::unexpected(unavailable("dashboard layout save failed"));
        return CryptoDashboardLayout{widgets, false};
    }

private:
    SoftwareInventoryStore* store_;
    const DeviceApi* devices_;
    CaStore* ca_;
    CryptoDashboardLayoutStore* layouts_;
    // Per-process bound on in-flight store calls, shared by every method. The lease is a scoped
    // RAII block around the store call, so every path - and any throw - releases it.
    mutable CryptoReadGate gate_;
};

} // namespace

std::shared_ptr<CryptoApi> make_local_crypto_api(const LocalCryptoApiDeps& deps) {
    return std::make_shared<LocalCryptoApi>(deps);
}

std::shared_ptr<CryptoApi> make_local_crypto_api(SoftwareInventoryStore& store,
                                                 const DeviceApi* device_api,
                                                 int max_concurrent_reads) {
    return make_local_crypto_api(LocalCryptoApiDeps{
        .software = &store, .devices = device_api, .max_concurrent_reads = max_concurrent_reads});
}

} // namespace yuzu::server
