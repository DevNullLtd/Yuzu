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
/// A Forensics-sourced set therefore materializes empty, for every creator, while the execution
/// tracker (which reads no rows) still says every agent answered: a complete-empty set. The async
/// producers refuse such a source before they dispatch (`plugin_may_seed_result_set`).

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "response_store.hpp"
#include "response_tier_filter.hpp"
#include "result_set_matcher.hpp"
#include "result_set_store.hpp"

namespace yuzu::server {

/// The 400 / -32602 message for a refused Forensics-tier source (REST and MCP share it).
inline constexpr std::string_view kSourceNotSupportedMessage =
    "RESULT_SET_SOURCE_NOT_SUPPORTED: a result set cannot be built from a Forensics-tier plugin "
    "because its stored responses are withheld from result-set membership";

/// False when `plugin` is Forensics-tier: its stored responses never reach a result set's
/// membership, so a set built from it would read as complete and empty. `forensics` is the set the
/// response reads use; null (an unwired test harness) refuses nothing, since the server refuses to
/// boot without the set and every production surface carries it.
[[nodiscard]] inline bool plugin_may_seed_result_set(std::string_view plugin,
                                                     const ForensicsPluginSet* forensics) {
    return forensics == nullptr || !forensics->contains(plugin);
}

/// The membership of a pending set: the agent ids that satisfy the matcher, plus how many agents
/// are absent from it because their query failed. Derives from the id vector so a caller that only
/// needs the members (the forensics tier tests) reads it exactly as before.
struct ResultSetMembers : std::vector<std::string> {
    /// Distinct agents with NO row satisfying the matcher and at least one failed row (status not
    /// success, output starting `error|`, a success answer whose `__schema__` header lacks the
    /// column matcher's column, or an answer the plugin reported CONSTRAINED when the definition
    /// sets `partialWhenConstrained`: `rs_matcher::constrained_answer_is_unresolved`, search_dir
    /// only today; it reads the stored status of rows this read already returned and adds no
    /// member). Matching decides first: an agent with any matching row is a
    /// member and is never counted here, so under the default matcher a success-status `error|`
    /// answer is a member, and the count only moves for an agent whose every row failed or failed
    /// to match while at least one failed. Agents that never answered are not counted: the read
    /// sees stored rows only.
    int64_t agents_failed{0};
    /// True when the store holds more rows for the execution than `max_rows`: the membership is
    /// incomplete in a way `agents_failed` cannot express, so the caller fails the set closed
    /// instead of materializing it. A store holding exactly `max_rows` rows is not truncated.
    bool truncated{false};
};

/// Rows the members read takes per store query. The read pages until a page comes back short.
inline constexpr int kResultSetMembersPageRows = 500;

/// Quantified membership tests the agent's entire answer. A RUNNING frame can end in the
/// middle of its table and the terminal status is backfilled on each stored frame. Walk
/// by (agent_id, insertion id) across page boundaries, holding only one answer in memory.
inline std::optional<ResultSetMembers> quantified_result_set_members(
    ResponseStore& responses, const ResponseTierFilter& tier, const PendingSet& pending,
    const rs_matcher::ParsedMatcher& matcher, int page_rows, int max_rows) {
    // Above this bound absence cannot be established. Fail just the affected agent closed.
    constexpr std::size_t max_answer_bytes = 2 * 1024 * 1024;
    ResultSetMembers members;
    ResponseQuery page;
    page.frames_after.emplace("", 0);
    std::string agent, output;
    int status = rs_matcher::kStatusSuccess;
    int plugin_status = 0;
    bool exceeded = false;
    auto finish_agent = [&] {
        if (agent.empty())
            return;
        const auto verdict = exceeded ? rs_matcher::RowMatch::RowBound
                                      : matcher.evaluate(status, output, plugin_status);
        if (verdict == rs_matcher::RowMatch::True)
            members.push_back(agent);
        else if (verdict != rs_matcher::RowMatch::False || status != rs_matcher::kStatusSuccess)
            ++members.agents_failed;
    };
    for (int read = 0;;) {
        page.limit = std::min(page_rows, max_rows - read + 1);
        auto rows = responses.query_by_execution(pending.source_execution_id, tier, page);
        if (!rows)
            return std::nullopt;
        for (const auto& frame : *rows) {
            if (++read > max_rows) {
                members.truncated = true;
                return members;
            }
            if (agent != frame.agent_id) {
                finish_agent();
                agent = frame.agent_id;
                output.clear();
                status = rs_matcher::kStatusSuccess;
                plugin_status = 0;
                exceeded = false;
            }
            if (frame.status != rs_matcher::kStatusSuccess)
                status = frame.status;
            if (frame.plugin_result_status > 1)
                plugin_status = frame.plugin_result_status;
            if (frame.output.empty() || exceeded)
                continue;
            if (frame.output.size() + !output.empty() > max_answer_bytes - output.size() ||
                frame.output.find(kResponseIngestTruncation) != std::string::npos ||
                frame.output.find(kResponseRowsTruncation) != std::string::npos) {
                exceeded = true;
                continue;
            }
            if (!output.empty())
                output.push_back('\n');
            output.append(frame.output);
        }
        if (rows->size() < static_cast<std::size_t>(page.limit))
            break;
        page.frames_after.emplace(rows->back().agent_id, rows->back().id);
    }
    finish_agent();
    return members;
}

/// The agent ids that satisfy `pending`'s matcher, in order of first appearance in the store's read
/// (which is newest row first, `timestamp DESC, id DESC`, not first-response order), plus
/// `agents_failed`; `std::nullopt` when the store read degraded (the caller skips this pending set
/// for this tick rather than materialize a false-empty membership, ADR-0039). The read pages
/// through every stored row of the execution by keyset (`ResponseQuery::continue_after`, never
/// `offset`: rows sharing a timestamp, or a row reaped between two pages, cannot skip a row),
/// `page_rows` at a time, up to `max_rows` (default: the store's per-set member cap, one row per
/// agent at least); a row past that bound sets `truncated`.
[[nodiscard]] inline std::optional<ResultSetMembers>
result_set_members(ResponseStore& responses, const ForensicsPluginSet* plugins,
                   const PendingSet& pending, int page_rows = kResultSetMembersPageRows,
                   int max_rows = ResultSetStore::kMaxMembersPerSet) {
    const auto tier = plugins ? ResponseTierFilter::exclude(*plugins, authz::deny_all())
                              : ResponseTierFilter::refuse_unwired();
    ResultSetMembers members;
    std::unordered_set<std::string> seen;
    std::unordered_set<std::string> failed;
    ResponseQuery page;
    page.limit = page_rows;
    // The matcher is one text for the whole set: parsed once here, asked about every row below.
    const rs_matcher::ParsedMatcher matcher(pending.matcher);
    if (matcher.quantified())
        return quantified_result_set_members(responses, tier, pending, matcher, page_rows, max_rows);
    for (int read = 0;;) {
        auto rows = responses.query_by_execution(pending.source_execution_id, tier, page);
        if (!rows)
            return std::nullopt;
        if (read >= max_rows) {
            // This page lies past the bound: any row in it means the read is incomplete.
            members.truncated = !rows->empty();
            break;
        }
        for (const auto& r : *rows) {
            const auto verdict = matcher.evaluate(r.status, r.output, r.plugin_result_status);
            if (verdict != rs_matcher::RowMatch::True) {
                if (verdict != rs_matcher::RowMatch::False || r.status != rs_matcher::kStatusSuccess || r.output.starts_with("error|") ||
                    matcher.answer_lacks_matcher_column(r.output) ||
                    matcher.constrained_answer_is_unresolved(r.plugin_result_status))
                    failed.insert(r.agent_id);
                continue;
            }
            if (seen.insert(r.agent_id).second)
                members.push_back(r.agent_id);
        }
        read += static_cast<int>(rows->size());
        if (static_cast<int>(rows->size()) < page_rows)
            break;
        page.continue_after = {rows->back().timestamp, rows->back().id};
    }
    for (const auto& id : failed)
        if (!seen.contains(id))
            ++members.agents_failed;
    return members;
}

} // namespace yuzu::server
