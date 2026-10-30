#pragma once

/// @file quarantine_visible.hpp
/// The ONE admit-then-filter read of the active quarantine set, shared by the REST
/// `GET /api/v1/quarantine` route and the dashboard fragments (Quarantined panel, list
/// pill) so the surfaces can never disagree on who may see which record. Pure: the store
/// read is an injected callable; no I/O here.
///
/// ADR-0017 (World A): the caller resolves its authority ONCE through the list chokepoint
/// (`fleet_read_fn(req, res, "Security", "Read")`, i.e. `AuthRoutes::require_fleet_read`)
/// and hands the resulting `VisibleSet` here. That scope is pushed into the store query
/// (never applied after the fetch), so a LIMIT applies to the caller's own records, an
/// out-of-scope record costs neither a probe nor an audit row, and one view makes one
/// authority decision whatever the number of active quarantines.
///
/// Contract:
///   * a store read that returns `nullopt` is `StoreDegraded`, NEVER an empty list — a
///     device could still be actively contained while the caller sees "nothing
///     quarantined";
///   * a present-but-empty scope is deny-all (an empty list, no store read);
///   * an unwired list read is `StoreDegraded` — never an unfiltered list.

#include "authz_model.hpp"
#include "quarantine_types.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

/// Per-DEVICE probe (same shape as `RestApiV1::ScopedPermFn`): writes the 401/403/503 body to
/// the Response it is given. Used only for a single-device decision (the containment lens and
/// banner); a LIST never loops over it — that is what the list gate and `VisibleSet` are for.
using QuarantineScopedPermFn =
    std::function<bool(const httplib::Request&, httplib::Response&, const std::string& securable_type,
                       const std::string& operation, const std::string& agent_id)>;

/// The authoritative scoped list read (`QuarantineStore::list_quarantined_in`):
/// `visible_ids == nullptr` = every agent, an empty vector = none; `limit == 0` = no limit.
/// `nullopt` = degraded (store/pool/query failure).
using QuarantineListFn = std::function<std::optional<std::vector<QuarantineRecord>>(
    const std::vector<std::string>* visible_ids, std::size_t limit)>;

enum class QuarantineReadStatus { Ok, StoreDegraded };

struct QuarantineVisible {
    QuarantineReadStatus status{QuarantineReadStatus::Ok};
    std::vector<QuarantineRecord> records; ///< visible records, store order (newest first)
    /// True when `max_visible` cut the list: more visible records exist.
    bool more{false};
};

struct QuarantineVisibleOptions {
    /// 0 = no cap (REST). Otherwise return at most this many visible records.
    std::size_t max_visible{0};
    /// When set, only records whose agent id is in this set are read (the list pill
    /// intersects the scope with the page's rows, so the read is bounded by the page size).
    const std::unordered_set<std::string>* only_ids{nullptr};
};

inline QuarantineVisible quarantine_visible_records(const authz::VisibleSet& scope,
                                                    const QuarantineListFn& list_fn,
                                                    const QuarantineVisibleOptions& opt = {}) {
    QuarantineVisible out;
    if (!list_fn) {
        out.status = QuarantineReadStatus::StoreDegraded;
        return out;
    }
    // The id restriction pushed into the query: nullptr (everyone) only when neither the
    // caller's scope nor the page narrows it.
    std::vector<std::string> ids;
    const std::vector<std::string>* restrict_to = nullptr;
    if (scope || opt.only_ids) {
        restrict_to = &ids;
        if (scope && opt.only_ids) {
            for (const auto& id : *opt.only_ids)
                if (scope->contains(id))
                    ids.push_back(id);
        } else if (scope) {
            ids.assign(scope->begin(), scope->end());
        } else {
            ids.assign(opt.only_ids->begin(), opt.only_ids->end());
        }
    }
    // One row past the cap tells "exactly max_visible" apart from "more".
    const std::size_t limit = opt.max_visible != 0 ? opt.max_visible + 1 : 0;
    auto records = list_fn(restrict_to, limit);
    if (!records) {
        out.status = QuarantineReadStatus::StoreDegraded;
        return out;
    }
    out.records = std::move(*records);
    if (opt.max_visible != 0 && out.records.size() > opt.max_visible) {
        out.records.resize(opt.max_visible);
        out.more = true;
    }
    return out;
}

} // namespace yuzu::server
