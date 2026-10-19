#include "crypto_api_local.hpp"

#include "ca_store.hpp"
#include "crypto_dashboard_layout_store.hpp"
#include "crypto_library_model.hpp"
#include "crypto_read_gate.hpp"
#include "crypto_shared_read.hpp"
#include "crypto_widget_catalogue.hpp"
#include "device_api.hpp"
#include "software_inventory_store.hpp"

#include <algorithm>
#include <chrono>
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

// The layout store's defence-in-depth bounds may never be tighter than the catalogue's: a layout
// the catalogue accepts must always be storable. The pin sits here because the seam lint keeps
// the store header out of every TU that sees only the catalogue.
static_assert(CryptoDashboardLayoutStore::kMaxIds >= cw::kMaxLayoutWidgets,
              "the layout store must hold every layout the catalogue accepts");
static_assert(CryptoDashboardLayoutStore::kMaxIdBytes >= cw::kWidgetIdMaxBytes,
              "the layout store must hold every catalogue id");
// The preserved-unknown merge caps at the store's bound; it must equal the catalogue's so a save
// the catalogue accepts is never truncated below the caller's own ids.
static_assert(CryptoDashboardLayoutStore::kMaxIds == cw::kMaxLayoutWidgets,
              "the preserved-unknown cap assumes the store and catalogue bounds match");

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

// The layout store did not open at boot (server.cpp resets the pointer; ADR-0071's degrade
// posture): not a transient fault, so it carries no retry hint on any transport.
CryptoReadError layouts_unavailable_until_restart() {
    CryptoReadError e = unavailable(
        "dashboard layouts unavailable: the layout store did not open at server start; saved "
        "layouts return after a restart with the store fixed");
    e.unavailable_until_restart = true;
    return e;
}

constexpr std::string_view kCaUnavailable = "Yuzu CA read degraded";
constexpr std::string_view kLayoutUnavailable = "dashboard layout read degraded";
constexpr std::string_view kLayoutSaveFailed = "dashboard layout save failed";
constexpr std::string_view kOutcomeUnknown = "save outcome unknown \u2014 reload to check";
constexpr std::string_view kConflictMessage =
    "the layout changed since it was loaded (another tab or client saved first); reload it and "
    "save again";
constexpr std::string_view kCorruptMessage =
    "the stored layout cannot be read; replace it (Reset, or a save with expected_version set to "
    "this layout's version)";

// The closed metric label values (LocalCryptoApiDeps::note_degrade).
constexpr std::string_view kSourceCa = "ca_issued";
constexpr std::string_view kSourceLayout = "crypto_layout";
constexpr std::string_view kReasonAdmission = "admission_full";

std::string_view degrade_reason(CaReadError::Kind k) {
    switch (k) {
    case CaReadError::Kind::kNotOpen:
        return "store_not_open";
    case CaReadError::Kind::kPoolAcquireTimeout:
        return "pool_acquire_timeout";
    case CaReadError::Kind::kInvalidRequest:
    case CaReadError::Kind::kQueryError:
        break;
    }
    return "query_error";
}

std::string_view degrade_reason(CryptoLayoutStoreError::Kind k) {
    switch (k) {
    case CryptoLayoutStoreError::Kind::kNotOpen:
        return "store_not_open";
    case CryptoLayoutStoreError::Kind::kPoolAcquireTimeout:
        return "pool_acquire_timeout";
    default:
        break;
    }
    return "query_error";
}

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

std::optional<CaRevokeBucket> to_store_bucket(std::optional<RevokedBucket> b) {
    if (!b)
        return std::nullopt;
    switch (*b) {
    case RevokedBucket::kSuperseded:
        return CaRevokeBucket::kSuperseded;
    case RevokedBucket::kUnpublished:
        return CaRevokeBucket::kUnpublished;
    case RevokedBucket::kOther:
        break;
    }
    return CaRevokeBucket::kOther;
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
          ca_refused_(d.pool_size > 0 && d.pool_size < kCryptoCaMinPoolSize),
          library_refused_(d.pool_size > 0 && d.pool_size < kCryptoLibraryMinPoolSize),
          ttl_(d.shared_read_ttl), note_degrade_(d.note_degrade),
          bound_as_of_(d.bound_pinned_as_of),
          gate_(crypto_admission_bound(d.max_concurrent_reads, d.pool_size)) {}

    std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const override {
        // Only the unfiltered, UNCONFINED summary is shared: a confined caller's answer is
        // scope-specific and is always read for that caller.
        if (ttl_.count() > 0 && !scope && !q.family && !q.ecosystem)
            return shared_summary_.get(ttl_, [&] { return read_summary(q, scope); });
        return read_summary(q, scope);
    }

    std::expected<CryptoSummary, CryptoReadError>
    read_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const {
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
            const auto lease = library_lease(); // released when this block ends, throw included
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
            const auto lease = library_lease(); // released when this block ends, throw included
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

    std::expected<CaCertStats, CryptoReadError>
    ca_stats(std::optional<std::int64_t> as_of) const override {
        // Never shared, never cached: every call reads at request time through the admission
        // gate (ADR-0070, "The CaStore count method": polling is bounded by admission limits,
        // not a cached or stored count).
        return read_stats(as_of);
    }

    std::expected<CaCertPage, CryptoReadError> ca_certificates(const CaCertQuery& q) const override {
        if (cw::kind_takes_days(q.kind)) {
            const auto set = cw::windows_for(q.kind);
            if (std::ranges::find(set, q.days) == set.end())
                return std::unexpected(invalid("days is not a window of the closed set for kind " +
                                               std::string(cw::ca_kind_name(q.kind))));
        }
        if (cw::kind_takes_week(q.kind) && cw::week_start_of(q.week_start) != q.week_start)
            return std::unexpected(invalid("week_start must be a Monday 00:00 UTC"));
        if (q.bucket && !cw::kind_takes_bucket(q.kind))
            return std::unexpected(invalid("bucket does not apply to kind " +
                                           std::string(cw::ca_kind_name(q.kind))));
        if (q.limit < 1 || q.limit > cw::kCertPageMax)
            return std::unexpected(invalid("limit must be an integer from 1 to " +
                                           std::to_string(cw::kCertPageMax)));
        // H2: a continuation page names its position AND its snapshot through the cursor, bound
        // to this filter; a pinned as_of beside it must be that same snapshot.
        const std::string fp = cw::cert_cursor_fingerprint(q);
        std::optional<CaIssuedAfter> after;
        std::optional<std::int64_t> as_of = q.as_of;
        if (!q.cursor.empty()) {
            auto pos = cw::decode_cert_cursor(q.cursor, fp);
            if (!pos)
                return std::unexpected(invalid(std::move(pos.error())));
            if (q.as_of && *q.as_of != pos->as_of)
                return std::unexpected(invalid("as_of does not match the cursor's snapshot; pass "
                                               "the cursor without as_of"));
            as_of = pos->as_of;
            after = CaIssuedAfter{pos->sort_key, std::move(pos->serial_hex)};
        }
        if (!ca_) {
            note(kSourceCa, "store_not_open");
            return std::unexpected(unavailable(kCaUnavailable));
        }
        CaCertPage out;
        out.query = q;
        out.query.as_of = as_of; // a continuation's snapshot comes from its cursor
        if (!cw::kind_takes_days(q.kind))
            out.query.days = 0;
        if (!cw::kind_takes_week(q.kind))
            out.query.week_start = 0;
        CaIssuedFilter f;
        f.kind = to_filter_kind(q.kind);
        f.days = out.query.days;
        f.week_start = out.query.week_start;
        f.revoked_bucket = to_store_bucket(q.bucket);

        std::optional<std::expected<CaIssuedPage, CaReadError>> read;
        {
            const auto lease = ca_lease();
            if (!lease)
                return std::unexpected(capacity_in_use());
            read = ca_->list_issued_filtered(f, as_of, q.limit, std::move(after), as_of_bounds());
        }
        if (!*read)
            return std::unexpected(ca_failure(read->error()));
        out.as_of = (*read)->as_of;
        out.total = (*read)->total;
        for (auto& r : (*read)->rows)
            out.rows.push_back({std::move(r.serial_hex), std::move(r.subject), std::move(r.san),
                                std::move(r.purpose), r.issued_at, r.not_after,
                                cert_status_to_string(r.status), r.revoked_at,
                                std::move(r.revocation_reason), std::move(r.issued_by),
                                std::move(r.issuer_key_id)});
        if (const auto& next = (*read)->next) {
            out.next_cursor = cw::encode_cert_cursor({next->sort_key, next->serial_hex, out.as_of}, fp);
            out.truncated = true;
        }
        return out;
    }

    std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const override {
        if (username.empty())
            return std::unexpected(invalid("no operator to read a layout for"));
        if (!layouts_) {
            note(kSourceLayout, "store_not_open");
            return std::unexpected(layouts_unavailable_until_restart());
        }
        // Not admission-bounded (B9): one short keyed read, bounded by the pool's lease timeout.
        const auto read = layouts_->get(username);
        if (!read)
            return std::unexpected(layout_failure(read.error(), kLayoutUnavailable));
        if (!*read)
            return CryptoDashboardLayout{cw::default_layout_ids(), true, 0, 0};
        const auto& ids = (**read).widget_ids;
        CryptoDashboardLayout out;
        out.widgets = cw::known_ids(ids);
        out.preserved_unknown = cw::unknown_ids(ids).size();
        out.version = (**read).version;
        out.is_default = cw::is_default_layout(out.widgets, out.preserved_unknown);
        return out;
    }

    std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username, const std::vector<std::string>& widgets,
                         std::optional<std::int64_t> expected_version) const override {
        if (username.empty())
            return std::unexpected(invalid("no operator to save a layout for"));
        if (const auto bad = cw::layout_error(widgets))
            return std::unexpected(invalid(*bad));
        if (expected_version && *expected_version < 0)
            return std::unexpected(invalid("expected_version must be a non-negative integer"));
        if (!layouts_) {
            note(kSourceLayout, "store_not_open");
            return std::unexpected(layouts_unavailable_until_restart());
        }
        // Read the stored row once: its version (when the caller named none) and the ids this
        // build does not know, which the save keeps (B7). A corrupt row has no ids to keep; the
        // save replaces it only against its own version (the Reset path).
        std::vector<std::string> stored;
        std::optional<std::int64_t> current; // nullopt = nothing stored
        if (const auto cur = layouts_->get(username); cur) {
            if (*cur) {
                stored = (**cur).widget_ids;
                current = (**cur).version;
            }
        } else if (cur.error().kind == CryptoLayoutStoreError::Kind::kCorrupt) {
            current = cur.error().version;
        } else {
            return std::unexpected(layout_failure(cur.error(), kLayoutSaveFailed));
        }
        // The version the conditional write runs against. Omitting expected_version means
        // "first save only" (owner decision 2026-10-19, ADR-0071): it is read as 0, so a save
        // without a version never replaces a stored row - including a corrupt one - and gets the
        // stored version back in the conflict instead. A caller-named version that already
        // differs is a conflict without a write; a write landing between the read and the
        // write still conflicts in the store.
        const std::optional<std::int64_t> against = current;
        const std::int64_t have = current.value_or(0);
        if (expected_version.value_or(0) != have) {
            CryptoReadError e{CryptoReadError::Kind::kConflict, std::string(kConflictMessage)};
            e.version = have;
            return std::unexpected(std::move(e));
        }
        const auto merged =
            cw::merge_preserved(widgets, stored, CryptoDashboardLayoutStore::kMaxIds);
        const auto wrote = layouts_->put(username, merged.ids, against);
        if (!wrote && wrote.error().kind == CryptoLayoutStoreError::Kind::kConflict)
            return std::unexpected(raced_conflict(username));
        if (!wrote)
            return std::unexpected(layout_failure(wrote.error(), kLayoutSaveFailed));
        CryptoDashboardLayout out;
        out.widgets = widgets;
        out.preserved_unknown = merged.kept;
        out.version = *wrote;
        out.is_default = cw::is_default_layout(out.widgets, out.preserved_unknown);
        return out;
    }

private:
    /// M2: a pinned as_of is bounded on the DATABASE clock, inside the read's own transaction.
    std::optional<CaAsOfBounds> as_of_bounds() const {
        if (!bound_as_of_)
            return std::nullopt;
        return CaAsOfBounds{cw::kAsOfMaxAgeSeconds, cw::kAsOfFutureSkewSeconds};
    }

    void note(std::string_view source, std::string_view reason) const {
        if (note_degrade_)
            note_degrade_(source, reason);
    }

    /// The library admission lease: refused outright on a one-connection pool (M3), so the
    /// mTLS-accept is_revoked check keeps it.
    CryptoReadGate::Lease library_lease() const {
        CryptoReadGate::Lease lease;
        if (!library_refused_)
            lease = gate_.try_acquire();
        return lease;
    }

    /// The Yuzu-issued admission lease: refused outright on a pool too small to spare one.
    CryptoReadGate::Lease ca_lease() const {
        CryptoReadGate::Lease lease;
        if (!ca_refused_)
            lease = gate_.try_acquire();
        if (!lease)
            note(kSourceCa, kReasonAdmission);
        return lease;
    }

    CryptoReadError ca_failure(const CaReadError& e) const {
        if (e.kind == CaReadError::Kind::kInvalidRequest)
            return invalid(e.message);
        note(kSourceCa, degrade_reason(e.kind));
        return unavailable(kCaUnavailable);
    }

    /// A conditional write lost a race (another save landed between the read and the write):
    /// the 409 must name the version NOW stored, so the caller can re-read and retry against
    /// it - never 0. Re-read once: no row = 0 (an erase raced the save), a corrupt row = its
    /// version; a re-read that itself degrades answers that degrade (503), not a guessed version.
    CryptoReadError raced_conflict(const std::string& username) const {
        CryptoReadError c{CryptoReadError::Kind::kConflict, std::string(kConflictMessage)};
        const auto now = layouts_->get(username);
        if (now) {
            c.version = *now ? (**now).version : 0;
            return c;
        }
        if (now.error().kind == CryptoLayoutStoreError::Kind::kCorrupt) {
            c.version = now.error().version;
            return c;
        }
        return layout_failure(now.error(), kLayoutSaveFailed);
    }

    CryptoReadError layout_failure(const CryptoLayoutStoreError& e, std::string_view what) const {
        using LK = CryptoLayoutStoreError::Kind;
        switch (e.kind) {
        case LK::kInvalidInput:
            // Deliberately not the store's message: it never names the username, but the 400
            // must not hint at the store either.
            return invalid("this account's name cannot key a dashboard layout");
        case LK::kConflict: {
            // Only `put` reports it, and set_dashboard_layout answers that through
            // raced_conflict (the stored version, re-read). Defensive: no version to name.
            CryptoReadError c{CryptoReadError::Kind::kConflict, std::string(kConflictMessage)};
            c.version = 0;
            return c;
        }
        case LK::kCorrupt: {
            CryptoReadError c{CryptoReadError::Kind::kCorrupt, std::string(kCorruptMessage)};
            c.version = e.version;
            return c;
        }
        case LK::kOutcomeUnknown:
            note(kSourceLayout, "query_error");
            return {CryptoReadError::Kind::kOutcomeUnknown, std::string(kOutcomeUnknown)};
        case LK::kNotOpen: // the store did not open at boot (same answer as an unwired one)
            note(kSourceLayout, degrade_reason(e.kind));
            return layouts_unavailable_until_restart();
        case LK::kPoolAcquireTimeout:
        case LK::kQueryError:
            break;
        }
        note(kSourceLayout, degrade_reason(e.kind));
        return unavailable(what);
    }

    std::expected<CaCertStats, CryptoReadError> read_stats(std::optional<std::int64_t> as_of) const {
        if (!ca_) {
            note(kSourceCa, "store_not_open");
            return std::unexpected(unavailable(kCaUnavailable));
        }
        CaIssuanceStatsRequest rq;
        rq.as_of = as_of;
        rq.as_of_bounds = as_of_bounds();
        rq.expiring_days.assign(cw::kExpiringWindowDays.begin(), cw::kExpiringWindowDays.end());
        rq.expired_days.assign(cw::kExpiredWindowDays.begin(), cw::kExpiredWindowDays.end());
        rq.revoked_days.assign(cw::kRevokedWindowDays.begin(), cw::kRevokedWindowDays.end());
        rq.issued_days = cw::kIssuedWindowDays;
        rq.weeks = cw::kWeeklyBuckets;

        std::optional<std::expected<CaIssuanceStats, CaReadError>> read;
        {
            const auto lease = ca_lease(); // released when this block ends, throw included
            if (!lease)
                return std::unexpected(capacity_in_use());
            read = ca_->issuance_stats(rq);
        }
        if (!*read)
            return std::unexpected(ca_failure(read->error()));
        const auto& st = **read;
        CaCertStats out;
        out.as_of = st.as_of;
        out.active = st.active;
        out.expiring = window_counts(cw::kExpiringWindowDays, st.expiring);
        out.expired = window_counts(cw::kExpiredWindowDays, st.expired);
        for (std::size_t i = 0; i < cw::kRevokedWindowDays.size() && i < st.revoked.size(); ++i)
            out.revoked.push_back({cw::kRevokedWindowDays[i], st.revoked[i].superseded,
                                   st.revoked[i].unpublished, st.revoked[i].other});
        out.issued = {cw::kIssuedWindowDays, st.issued};
        const std::int64_t current_week = cw::week_start_of(st.as_of);
        for (std::size_t i = 0; i < st.week_starts.size(); ++i) {
            CaWeekCount w;
            w.week_start = st.week_starts[i];
            w.label = cw::iso_week_label(w.week_start);
            w.issued = i < st.issued_per_week.size() ? st.issued_per_week[i] : 0;
            if (i < st.revoked_per_week.size()) {
                w.revoked_superseded = st.revoked_per_week[i].superseded;
                w.revoked_unpublished = st.revoked_per_week[i].unpublished;
                w.revoked_other = st.revoked_per_week[i].other;
            }
            w.partial = w.week_start == current_week;
            out.weeks.push_back(std::move(w));
        }
        return out;
    }

private:
    SoftwareInventoryStore* store_;
    const DeviceApi* devices_;
    CaStore* ca_;
    CryptoDashboardLayoutStore* layouts_;
    const bool ca_refused_;
    const bool library_refused_;
    const std::chrono::seconds ttl_;
    std::function<void(std::string_view, std::string_view)> note_degrade_;
    const bool bound_as_of_;
    mutable SharedRead<CryptoSummary, CryptoReadError> shared_summary_{capacity_in_use(), degraded()};
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
