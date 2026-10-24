#pragma once

/// #4990: the membership computation the result-set materializer runs for a pending set.
///
/// Membership is a function of the producing execution's stored responses through the pending
/// row's matcher (`rs_matcher::response_matches`: status, and for the column/op/value and
/// `tar_rows_ge` kinds the CONTENT of the output). A set is readable by its owner afterwards, so
/// matching over a Forensics-tier plugin's rows would be a content-membership oracle over data the
/// owner may not hold the Forensics tier for. The materializer is a background thread with no
/// request, so the creating principal's Forensics visibility cannot be resolved here: the read
/// excludes the Forensics plugins outright (`deny_all()`), and an unwired set refuses every row.
/// A Forensics-sourced set therefore materializes empty, for every creator.

#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "response_store.hpp"
#include "response_tier_filter.hpp"
#include "result_set_matcher.hpp"
#include "result_set_store.hpp"

namespace yuzu::server {

/// The agent ids that satisfy `pending`'s matcher, in order of first appearance in the store's read
/// (which is newest row first, `timestamp DESC`, not first-response order); `std::nullopt` when the
/// store read degraded (the caller skips this pending set for this tick rather than materialize a
/// false-empty membership, ADR-0039).
[[nodiscard]] inline std::optional<std::vector<std::string>>
result_set_members(ResponseStore& responses, const ForensicsPluginSet* plugins,
                   const PendingSet& pending) {
    const auto tier = plugins ? ResponseTierFilter::exclude(*plugins, authz::deny_all())
                              : ResponseTierFilter::refuse_unwired();
    auto rows = responses.query_by_execution(pending.source_execution_id, tier);
    if (!rows)
        return std::nullopt;
    std::vector<std::string> members;
    std::unordered_set<std::string> seen;
    for (const auto& r : *rows) {
        if (!rs_matcher::response_matches(pending.matcher, r.status, r.output))
            continue;
        if (seen.insert(r.agent_id).second)
            members.push_back(r.agent_id);
    }
    return members;
}

} // namespace yuzu::server
