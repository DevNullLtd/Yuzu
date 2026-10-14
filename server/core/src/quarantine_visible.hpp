#pragma once

/// @file quarantine_visible.hpp
/// The ONE admit-then-filter read of the active quarantine set, shared by the REST
/// `GET /api/v1/quarantine` route and the dashboard fragments (Quarantined panel, list
/// pill, Containment lens, record banner) so the two surfaces can never disagree on who
/// may see which record. Pure: store and gate are injected callables; no I/O here.
///
/// Contract (extracted verbatim from the REST route, #1788 / ADR-0047):
///   * a store read that returns `nullopt` is `StoreDegraded`, NEVER an empty list — a
///     device could still be actively contained while the caller sees "nothing
///     quarantined";
///   * the per-record gate is the STATUS-BEARING scoped probe: an explicit 403 is a scope
///     denial (the record is filtered out); ANY other non-pass outcome (a bare 401 from a
///     degraded engine-principal lookup, a 503 from an RBAC/tag-store degrade) is
///     anomalous mid-request and fails the WHOLE read closed as `ProbeDegraded`;
///   * an unwired gate is `ScopeUnwired` (REST answers 500) — never an unfiltered list.
///
/// Both the loop (`quarantine_visible_records`) and the single-record case
/// (`quarantine_probe_record`, used by the Containment lens after a point
/// `get_status`) route through ONE per-record probe, so a second copy of the 403-vs-other
/// rule cannot drift.

#include "quarantine_store.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

/// Same shape as `RestApiV1::ScopedPermFn` / `HardwareRoutes::ScopedPermFn`: writes the
/// 401/403/503 body to the Response it is given, so callers pass a throwaway.
using QuarantineScopedPermFn =
    std::function<bool(const httplib::Request&, httplib::Response&, const std::string& securable_type,
                       const std::string& operation, const std::string& agent_id)>;

/// The authoritative list read; `nullopt` = degraded (store/pool/query failure).
using QuarantineListFn = std::function<std::optional<std::vector<QuarantineRecord>>()>;

enum class QuarantineRecordProbe { Visible, Denied, Degraded };

/// One record's `Security:Read` admit probe. Explicit 403 = Denied; any other failing
/// outcome = Degraded (fail closed, see the file banner).
inline QuarantineRecordProbe quarantine_probe_record(const httplib::Request& req,
                                                     const QuarantineScopedPermFn& scoped_perm_fn,
                                                     const std::string& agent_id) {
    httplib::Response probe; // throwaway: per-record admit probe, never sent
    if (scoped_perm_fn(req, probe, "Security", "Read", agent_id))
        return QuarantineRecordProbe::Visible;
    return probe.status == 403 ? QuarantineRecordProbe::Denied : QuarantineRecordProbe::Degraded;
}

enum class QuarantineReadStatus { Ok, StoreDegraded, ProbeDegraded, ScopeUnwired };

struct QuarantineVisible {
    QuarantineReadStatus status{QuarantineReadStatus::Ok};
    std::vector<QuarantineRecord> records; ///< visible records, store order (newest first)
    /// True when `max_visible` stopped the walk before every record was probed: more
    /// visible records MAY exist (never an exact count in that case).
    bool more{false};
};

struct QuarantineVisibleOptions {
    /// 0 = no cap (REST). Otherwise stop probing once this many records are visible.
    std::size_t max_visible{0};
    /// When set, only records whose agent id is in this set are probed (the list pill
    /// intersects the active set with the page's rows BEFORE probing, so the probe count
    /// is bounded by the page size, not by the number of quarantines).
    const std::unordered_set<std::string>* only_ids{nullptr};
};

inline QuarantineVisible quarantine_visible_records(const httplib::Request& req,
                                                    const QuarantineListFn& list_fn,
                                                    const QuarantineScopedPermFn& scoped_perm_fn,
                                                    const QuarantineVisibleOptions& opt = {}) {
    QuarantineVisible out;
    if (!scoped_perm_fn) {
        out.status = QuarantineReadStatus::ScopeUnwired;
        return out;
    }
    auto records = list_fn ? list_fn() : std::nullopt;
    if (!records) {
        out.status = QuarantineReadStatus::StoreDegraded;
        return out;
    }
    for (auto& r : *records) {
        if (opt.only_ids && !opt.only_ids->contains(r.agent_id))
            continue;
        if (opt.max_visible != 0 && out.records.size() >= opt.max_visible) {
            out.more = true;
            break;
        }
        switch (quarantine_probe_record(req, scoped_perm_fn, r.agent_id)) {
        case QuarantineRecordProbe::Visible:
            out.records.push_back(std::move(r));
            break;
        case QuarantineRecordProbe::Denied:
            break;
        case QuarantineRecordProbe::Degraded:
            out.status = QuarantineReadStatus::ProbeDegraded;
            out.records.clear();
            out.more = false;
            return out;
        }
    }
    return out;
}

} // namespace yuzu::server
