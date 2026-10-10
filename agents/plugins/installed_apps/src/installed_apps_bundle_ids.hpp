#pragma once

// installed_apps_bundle_ids.hpp -- pure composition around the agent-core bounded
// bundle-id pass (yuzu::agent::read_bundle_ids_bounded) for the macOS `list`
// action's bundle_id column. Portable and CoreFoundation-free so the unit suite
// pins the warning rows and status mapping on every host.
//
// Two distinct ways a row can end up with "-" are reported rather than left
// implicit (the 7-field `app|` row is frozen by the server splitter, so the
// absent-vs-not-read distinction travels as a leading `warning|` row):
//   - the pass itself was cut short (TimedOut / Busy / Rejected), or
//   - the INPUT was truncated at kMaxEnrichApps before the pass ran (Capped).

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/bundle_id_read.hpp>
#include <yuzu/plugin.h>

#include "installed_apps_parsers.hpp"

namespace yuzu::installed_apps::bundle_ids {

// MEMORY/RUNAWAY guard on how many located apps one `list` submits to the pass;
// far above any real host. Hitting it is reported (capped row), not only logged.
inline constexpr std::size_t kMaxEnrichApps = 5000;

struct BundleIdPassOutcome {
    yuzu::agent::BundleIdPassStatus status = yuzu::agent::BundleIdPassStatus::Completed;
    std::size_t located = 0;   ///< apps with a non-empty install_location
    std::size_t submitted = 0; ///< min(located, kMaxEnrichApps)
    std::size_t read_count = 0;
    std::chrono::seconds deadline{0};
};

struct BundleIdStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string_view provenance;
};

[[nodiscard]] inline bool truncated(const BundleIdPassOutcome& o) noexcept {
    return o.submitted < o.located;
}

struct BundleIdPaths {
    BundleIdPassOutcome outcome;
    std::vector<std::string> paths;      ///< first kMaxEnrichApps located apps' install_location
    std::vector<std::size_t> index_map;  ///< paths[i] belongs to apps[index_map[i]]
};

// Collects the located apps' paths (first kMaxEnrichApps only) and the index of
// each, recording located/submitted. Pure: no reads.
[[nodiscard]] inline BundleIdPaths
collect_bundle_id_paths(const std::vector<parsers::AppRowFields>& apps) {
    BundleIdPaths c;
    for (std::size_t i = 0; i < apps.size(); ++i) {
        if (apps[i].install_location.empty())
            continue;
        ++c.outcome.located;
        if (c.paths.size() < kMaxEnrichApps) {
            c.paths.push_back(apps[i].install_location);
            c.index_map.push_back(i);
        }
    }
    c.outcome.submitted = c.paths.size();
    return c;
}

// ids[i] belongs to the app at index_map[i]; absent stays "" (rendered "-").
// Precondition: index_map came from collect_bundle_id_paths over this same `apps`,
// and `apps` is not mutated between collect and apply (indices are unchecked).
inline void apply_bundle_ids(std::vector<parsers::AppRowFields>& apps,
                             const yuzu::agent::BundleIdPassResult& r,
                             const std::vector<std::size_t>& index_map) {
    // min(): the allocation-failure Rejected path returns ids empty with index_map non-empty.
    const auto n = std::min(r.ids.size(), index_map.size());
    for (std::size_t i = 0; i < n; ++i)
        apps[index_map[i]].bundle_id = r.ids[i];
}

[[nodiscard]] inline std::optional<std::string> bundle_id_warning_row(const BundleIdPassOutcome& o) {
    using S = yuzu::agent::BundleIdPassStatus;
    switch (o.status) {
    case S::TimedOut:
        return "warning|bundle_id_timeout: " + std::to_string(o.read_count) + " of " +
               std::to_string(o.submitted) + " submitted apps read before the " +
               std::to_string(o.deadline.count()) + " s deadline; remaining rows carry -";
    case S::Busy:
        return "warning|bundle_id_busy: another bundle-id pass is in flight on this device (a "
               "concurrent list or an earlier abandoned pass); rows carry -";
    case S::Rejected:
        return "warning|bundle_id_rejected: bounded-call ceiling refused the pass or its "
               "admission allocation failed; rows carry -";
    case S::Completed:
        break;
    }
    if (truncated(o))
        return "warning|bundle_id_capped: " + std::to_string(o.submitted) + " of " +
               std::to_string(o.located) + " located apps submitted (cap " +
               std::to_string(kMaxEnrichApps) + "); remaining rows carry -";
    return std::nullopt;
}

// A non-Completed pass outranks input truncation (a TimedOut pass over a
// truncated input reports bundle_id_timeout).
[[nodiscard]] inline BundleIdStatus bundle_id_status(const BundleIdPassOutcome& o) noexcept {
    using S = yuzu::agent::BundleIdPassStatus;
    constexpr auto C = YUZU_RESULT_STATUS_CONSTRAINED;
    constexpr auto P = YUZU_RESULT_COMPLETENESS_PARTIAL;
    switch (o.status) {
    case S::TimedOut:
        return {C, P, "installed_apps:bundle_id_timeout"};
    case S::Busy:
        return {C, P, "installed_apps:bundle_id_busy"};
    case S::Rejected:
        return {C, P, "installed_apps:bundle_id_rejected"};
    case S::Completed:
        break;
    }
    if (truncated(o))
        return {C, P, "installed_apps:bundle_id_capped"};
    return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {}};
}

} // namespace yuzu::installed_apps::bundle_ids
