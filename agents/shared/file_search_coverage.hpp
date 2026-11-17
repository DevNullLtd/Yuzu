/**
 * file_search_coverage.hpp -- the coverage envelope of the on-demand file search: what was
 * searched, what was not, and why, so an empty answer is never confusable with a search that
 * did not run. Pure value types and a row formatter; no I/O, no clock.
 *
 * Scope. The agent keeps no state between slices, so the volume and gap ROWS describe THIS
 * slice only; a caller that wants the full gap list keeps every slice's rows. The VERDICT on the
 * final coverage row is cumulative: prior_gaps is the running count the resume cursor carries
 * (Cursor::prior_gaps) and any non-zero value makes the search partial. A search of more than
 * one slice is not a point-in-time snapshot and says so (consistency=not_a_snapshot).
 *
 * GapCause spells its first six tokens exactly as OrderedGap::Cause in component_walk.hpp so the
 * plugin maps one to one; permission_denied covers a refused user directory.
 */
#pragma once

#include "file_search_names.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::shared::file_search {

enum class VolumeState { complete, partial, not_searched };

enum class Reason {
    none,
    budget_entries,
    budget_time,
    budget_rows,
    cancelled,
    fstype_not_allowed,
    network_mount,
    mount_table_unreadable,
    permission_denied,
    private_namespace,
    other_device,
    stalled,
    unstable,
    unsupported
};

enum class GapCause {
    depth,
    dir_unreadable,
    dir_truncated,
    other_device,
    network_mount,
    memory_cap,
    permission_denied,
    dataless,
    private_namespace
};

// Extents arrive in a later PR; the field lets the envelope already say a volume cannot report them.
enum class Extents { not_collected, collected, unsupported };

[[nodiscard]] constexpr const char* to_token(VolumeState s) noexcept {
    switch (s) {
    case VolumeState::complete:
        return "complete";
    case VolumeState::partial:
        return "partial";
    case VolumeState::not_searched:
        return "not_searched";
    }
    return "unknown";
}

[[nodiscard]] constexpr const char* to_token(Reason r) noexcept {
    switch (r) {
    case Reason::none:
        return "none";
    case Reason::budget_entries:
        return "budget_entries";
    case Reason::budget_time:
        return "budget_time";
    case Reason::budget_rows:
        return "budget_rows";
    case Reason::cancelled:
        return "cancelled";
    case Reason::fstype_not_allowed:
        return "fstype_not_allowed";
    case Reason::network_mount:
        return "network_mount";
    case Reason::mount_table_unreadable:
        return "mount_table_unreadable";
    case Reason::permission_denied:
        return "permission_denied";
    case Reason::private_namespace:
        return "private_namespace";
    case Reason::other_device:
        return "other_device";
    case Reason::stalled:
        return "stalled";
    case Reason::unstable:
        return "unstable";
    case Reason::unsupported:
        return "unsupported";
    }
    return "unknown";
}

[[nodiscard]] constexpr const char* to_token(GapCause c) noexcept {
    switch (c) {
    case GapCause::depth:
        return "depth";
    case GapCause::dir_unreadable:
        return "dir_unreadable";
    case GapCause::dir_truncated:
        return "dir_truncated";
    case GapCause::other_device:
        return "other_device";
    case GapCause::network_mount:
        return "network_mount";
    case GapCause::memory_cap:
        return "memory_cap";
    case GapCause::permission_denied:
        return "permission_denied";
    case GapCause::dataless:
        return "dataless";
    case GapCause::private_namespace:
        return "private_namespace";
    }
    return "unknown";
}

[[nodiscard]] constexpr const char* to_token(Extents e) noexcept {
    switch (e) {
    case Extents::not_collected:
        return "not_collected";
    case Extents::collected:
        return "collected";
    case Extents::unsupported:
        return "unsupported";
    }
    return "unknown";
}

struct VolumeCoverage {
    std::string mount_point;
    std::string fstype;
    VolumeState state{VolumeState::not_searched};
    Reason reason{Reason::none};
    Extents extents{Extents::not_collected};
    std::uint64_t entries{0};
};

struct Gap {
    std::string path;
    GapCause cause;
};

inline constexpr std::size_t kMaxGaps = 1000;

struct CoverageEnvelope {
    std::vector<VolumeCoverage> volumes;
    std::vector<Gap> gaps;
    std::size_t gaps_dropped{0};
    std::uint32_t slices{1};
    std::uint32_t prior_gaps{0}; // running count carried by the cursor (Cursor::prior_gaps)
    bool has_cursor{false};      // a continuation cursor remains: the search is not finished

    void add_gap(Gap g) {
        if (gaps.size() < kMaxGaps)
            gaps.push_back(std::move(g));
        else
            ++gaps_dropped;
    }

    // A complete volume carries no reason; a non-complete volume must say why.
    [[nodiscard]] bool valid() const noexcept {
        for (const auto& v : volumes) {
            if ((v.state == VolumeState::complete) != (v.reason == Reason::none))
                return false;
        }
        return true;
    }

    // True only for a finished search that saw every volume completely. Zero volumes is never
    // complete: an empty answer must not be confusable with a search that did not run.
    [[nodiscard]] bool complete() const noexcept {
        if (volumes.empty() || !gaps.empty() || gaps_dropped != 0 || prior_gaps != 0 || has_cursor)
            return false;
        for (const auto& v : volumes) {
            if (v.state != VolumeState::complete)
                return false;
        }
        return true;
    }
};

[[nodiscard]] inline std::vector<std::string> format_coverage_rows(const CoverageEnvelope& e) {
    std::vector<std::string> rows;
    rows.reserve(e.volumes.size() + e.gaps.size() + 2);
    for (const auto& v : e.volumes) {
        rows.push_back("volume|" + encode_name(v.mount_point) + "|" + encode_name(v.fstype) + "|" +
                       to_token(v.state) + "|" + to_token(v.reason) +
                       "|extents=" + to_token(v.extents) + "|entries=" + std::to_string(v.entries));
    }
    for (const auto& g : e.gaps)
        rows.push_back("gap|" + encode_name(g.path) + "|" + to_token(g.cause));
    if (e.gaps_dropped != 0)
        rows.push_back("gaps_dropped|" + std::to_string(e.gaps_dropped));
    rows.push_back(std::string("coverage|") + (e.complete() ? "complete" : "partial") +
                   "|slices=" + std::to_string(e.slices) +
                   "|prior_gaps=" + std::to_string(e.prior_gaps) + "|consistency=" +
                   (e.slices > 1 ? "not_a_snapshot" : "single_pass"));
    return rows;
}

} // namespace yuzu::shared::file_search
