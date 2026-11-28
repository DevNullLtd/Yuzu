#pragma once

// recount_coalescer.hpp -- #2673: one recount per run at a time, with a bounded runner.
// Pure bookkeeping, thread-safe; it runs no recount itself.
//
// A caller that gets a `Turn` from `join` recounts `turn.agents`, then calls `next` and repeats
// while it returns true. A caller that gets nothing has been covered: the runner (or a later
// successor) starts another recount that includes its agent.
//
// Bounded: after `kRoundsBeforeHandoff` further batches the runner asks to be relieved, and the
// next caller to `join` takes the run over, with whatever is pending. If nobody joins, nothing is
// pending and the runner stops. So one caller does at most kRoundsBeforeHandoff + 1 recounts.

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class RecountCoalescer {
public:
    static constexpr int kRoundsBeforeHandoff = 4;

    struct Turn {
        std::string run;
        std::vector<std::string> agents; ///< the batch to recount now
        std::uint64_t token{0};
        int rounds{0};
    };

    /// A reply for `agent` in `run` has committed.
    [[nodiscard]] std::optional<Turn> join(const std::string& run, const std::string& agent) {
        std::lock_guard lock(mu_);
        const auto [it, created] = runs_.try_emplace(run);
        Entry& entry = it->second;
        entry.pending.push_back(agent);
        if (!created && !entry.wants_successor)
            return std::nullopt;
        entry.wants_successor = false;
        entry.token = ++last_token_;
        return Turn{run, std::exchange(entry.pending, {}), entry.token, 0};
    }

    /// The runner finished a recount. True: recount `turn.agents` (a new batch) next. False: it
    /// is done, because nothing is pending or somebody else has taken the run over.
    [[nodiscard]] bool next(Turn& turn) {
        std::lock_guard lock(mu_);
        const auto it = runs_.find(turn.run);
        if (it == runs_.end() || it->second.token != turn.token)
            return false;
        Entry& entry = it->second;
        if (entry.pending.empty()) {
            runs_.erase(it);
            return false;
        }
        turn.agents = std::exchange(entry.pending, {});
        if (++turn.rounds >= kRoundsBeforeHandoff)
            entry.wants_successor = true;
        return true;
    }

    /// The runner is giving up (its recount threw): release the run unless it was taken over.
    void abandon(const Turn& turn) {
        std::lock_guard lock(mu_);
        const auto it = runs_.find(turn.run);
        if (it != runs_.end() && it->second.token == turn.token)
            runs_.erase(it);
    }

private:
    struct Entry {
        std::vector<std::string> pending;
        std::uint64_t token{0};
        bool wants_successor{false};
    };
    std::mutex mu_;
    std::unordered_map<std::string, Entry> runs_; ///< present = being recounted
    std::uint64_t last_token_{0};                 ///< never reused, so a stale turn stays stale
};

} // namespace yuzu::server
