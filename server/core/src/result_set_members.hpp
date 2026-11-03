#pragma once

/// #4990: the membership computation the result-set materializer runs for a pending set.
///
/// Membership is a function of the producing execution's stored responses through the pending
/// row's matcher (`rs_matcher::response_matches`: status, and for the column/op/value and
/// `echo_rows_ge` kinds the CONTENT of the output). A set is readable by its owner afterwards, so
/// matching over a Forensics-tier plugin's rows would be a content-membership oracle over data the
/// owner may not hold the Forensics tier for. The materializer is a background thread with no
/// request, so the creating principal's Forensics visibility cannot be resolved here: the read
/// excludes the Forensics plugins outright (`deny_all()`), and an unwired set refuses every row.
/// A Forensics-sourced set therefore materializes empty, for every creator.

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "response_store.hpp"
#include "response_tier_filter.hpp"
#include "result_set_matcher.hpp"
#include "result_set_store.hpp"

namespace yuzu::server {

/// The membership of a pending set: the agent ids that satisfy the matcher, plus how many agents
/// are absent from it because their query failed. Derives from the id vector so a caller that only
/// needs the members (the forensics tier tests) reads it exactly as before.
struct ResultSetMembers : std::vector<std::string> {
    /// Distinct agents with NO row satisfying the matcher and at least one failed row (status not
    /// success, or output starting `error|`). Matching decides first: an agent with any matching
    /// row is a member and is never counted here, so under the default matcher a success-status
    /// `error|` answer is a member, and the count only moves for an agent whose every row failed
    /// or failed to match while at least one failed.
    int64_t agents_failed{0};
};

/// The agent ids that satisfy `pending`'s matcher, in order of first appearance in the store's read
/// (which is newest row first, `timestamp DESC`, not first-response order), plus `agents_failed`;
/// `std::nullopt` when the store read degraded (the caller skips this pending set for this tick
/// rather than materialize a false-empty membership, ADR-0039).
[[nodiscard]] inline std::optional<ResultSetMembers>
result_set_members(ResponseStore& responses, const ForensicsPluginSet* plugins,
                   const PendingSet& pending) {
    const auto tier = plugins ? ResponseTierFilter::exclude(*plugins, authz::deny_all())
                              : ResponseTierFilter::refuse_unwired();
    auto rows = responses.query_by_execution(pending.source_execution_id, tier);
    if (!rows)
        return std::nullopt;
    ResultSetMembers members;
    std::unordered_set<std::string> seen;
    std::unordered_set<std::string> failed;
    for (const auto& r : *rows) {
        if (!rs_matcher::response_matches(pending.matcher, r.status, r.output)) {
            if (r.status != rs_matcher::kStatusSuccess || r.output.starts_with("error|"))
                failed.insert(r.agent_id);
            continue;
        }
        if (seen.insert(r.agent_id).second)
            members.push_back(r.agent_id);
    }
    for (const auto& id : failed)
        if (!seen.contains(id))
            ++members.agents_failed;
    return members;
}

} // namespace yuzu::server
