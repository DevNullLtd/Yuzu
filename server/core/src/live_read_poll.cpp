#include "live_read_poll.hpp"

#include <algorithm>
#include <thread>
#include <utility>

namespace yuzu::server::live {

LiveRowsVerdict reduce_rows(std::span<const StoredResponse> rows, std::string_view agent_id) {
    // Only this agent's rows, ordered ascending by (timestamp, id) so equal timestamps join in
    // the order the store assigned them.
    std::vector<const StoredResponse*> mine;
    mine.reserve(rows.size());
    for (const auto& r : rows) {
        if (r.agent_id == agent_id)
            mine.push_back(&r);
    }
    std::ranges::sort(mine, [](const StoredResponse* a, const StoredResponse* b) {
        return a->timestamp != b->timestamp ? a->timestamp < b->timestamp : a->id < b->id;
    });

    LiveRowsVerdict v;
    std::string joined;
    bool failed = false;
    bool success_terminal = false;
    std::string failure_text;
    for (const auto* r : mine) {
        joined += r->output; // empty output joins as nothing
        if (r->status >= 2) {
            failed = true;
            failure_text = r->error_detail; // the latest failing row speaks last
        } else if (r->status == 1) {
            success_terminal = true;
        }
    }

    // FAILURE WINS: a failed row answers a failure even when partial output is also present.
    if (failed) {
        v.outcome = LiveOutcome::kDeviceFailed;
        v.detail = failure_text.substr(0, kLiveDetailMaxBytes);
        return v;
    }
    if (!joined.empty()) {
        if (joined.rfind("error|", 0) == 0) {
            v.outcome = LiveOutcome::kDeviceError;
            v.detail = joined.substr(6, kLiveDetailMaxBytes);
            return v;
        }
        v.outcome = LiveOutcome::kOk;
        v.output = std::move(joined);
        return v;
    }
    if (success_terminal) {
        v.outcome = LiveOutcome::kOk; // success terminal, no output: an empty result, not a timeout
        return v;
    }
    return v; // kTimeout: nothing decided yet
}

namespace {

/// Apply the byte cap to a successful answer. Returns false when the answer must be refused.
bool apply_output_cap(LivePollOutcome& out, const LivePollLimits& limits) {
    if (out.output.size() <= limits.max_output_bytes)
        return true;
    if (limits.over_cap == OverCapPolicy::kRefuse)
        return false;
    // Cut at the last newline inside the cap so no row is split; with no newline inside the cap
    // nothing whole fits and the answer is empty and truncated.
    const std::string_view head(out.output.data(), limits.max_output_bytes);
    const auto nl = head.rfind('\n');
    out.output.resize(nl == std::string_view::npos ? 0 : nl);
    out.truncated = true;
    return true;
}

} // namespace

LivePollOutcome poll_live_output(const LiveRowsFn& read_rows, std::string_view agent_id,
                                 const LivePollLimits& limits, const LiveSleepFn& sleep_fn) {
    int degraded = 0;
    int polls = 0;
    for (int i = 0; i < limits.max_polls; ++i) {
        if (i > 0) { // read first; back off only after a miss
            if (sleep_fn)
                sleep_fn(limits.interval);
            else
                std::this_thread::sleep_for(limits.interval);
        }
        ++polls;
        // A degraded read is empty for this iteration; the bounded loop retries (deny-or-benign).
        const auto rows = read_rows ? read_rows() : std::nullopt;
        if (!rows) {
            ++degraded;
            continue;
        }
        auto verdict = reduce_rows(*rows, agent_id);
        LivePollOutcome out;
        switch (verdict.outcome) {
        case LiveOutcome::kOk:
            out.outcome = LiveOutcome::kOk;
            out.output = std::move(verdict.output);
            if (!apply_output_cap(out, limits)) {
                out.outcome = LiveOutcome::kOutputTooLarge;
                out.output.clear();
            }
            return out;
        case LiveOutcome::kDeviceFailed:
        case LiveOutcome::kDeviceError:
            out.outcome = verdict.outcome;
            out.detail = std::move(verdict.detail);
            return out;
        default: // kTimeout: undecided, read again
            break;
        }
    }
    LivePollOutcome out;
    out.outcome = (polls > 0 && degraded == polls) ? LiveOutcome::kStoreDegraded : LiveOutcome::kTimeout;
    return out;
}

LivePollOutcome poll_live_output(const ResponseStore& store, const std::string& command_id,
                                 std::string_view agent_id, const ForensicsPluginSet* forensics_plugins,
                                 const LivePollLimits& limits, const LiveSleepFn& sleep_fn) {
    // #4990: this poll reads back a command the caller dispatched itself from the fixed live
    // kinds (device info plugins, none Forensics-tier), so the Forensics tier is excluded
    // outright rather than derived from the caller. A null set refuses every row.
    const auto tier = ResponseTierFilter::for_fixed_plugin_poll(forensics_plugins);
    ResponseQuery q;
    q.agent_id = std::string(agent_id); // scoped in SQL, before the LIMIT
    q.limit = kLivePollRowLimit;
    return poll_live_output(
        [&]() { return store.query(command_id, tier, q); }, agent_id, limits, sleep_fn);
}

} // namespace yuzu::server::live
