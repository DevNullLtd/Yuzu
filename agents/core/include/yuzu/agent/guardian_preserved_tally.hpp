#pragma once

/**
 * guardian_preserved_tally.hpp - the per-push record of Spark rules a full_sync left in place
 * (#4415), and the one log line that reports it.
 *
 * Why it exists: a rule the push still carries is skipped by GuardianSparkRuntime::attach_core
 * when it is healthy and unchanged, so it logs no `arm committed` line and no `guard.compliant`
 * event. Without a record of WHICH rules were skipped, a reader (the fullsync_blackout_diag.py
 * driver) can only infer them by count, and a kept rule that failed to re-arm is indistinguishable
 * from a skipped one. The line names them, bounded, so the reader can account for every rule in
 * the push: re-armed (an `arm committed` line), preserved (named here) or neither (a failure).
 *
 * Two kinds of skip are kept apart. PRESERVED: the rule is healthy and COMMITTED (ArmOutcomeKind::
 * Armed). PENDING-REUSED: the push's identical arm is still IN FLIGHT and was re-observed
 * (ArmOutcomeKind::Accepted); it has not confirmed yet and may still fail or commit, so a reader
 * must keep waiting for it rather than treat it as accounted for.
 *
 * Line format (one per full_sync that reaches the end of its rule loop; N may be 0; best-effort
 * under allocation failure, and absent when apply_rules returns early on a persist failure):
 *   Guardian: full_sync preserved <N> rule(s) (skipped re-arm) ids=[<id>,<id>,...] more=<M>
 * and, ONLY when at least one arm was pending-reused, the same line continues with
 *   ... more=<M> pending_reused <P> ids=[<id>,...] more=<Q>
 * so a line with no pending reuse is byte-identical to the pre-pending format. ids are
 * log_id_token()-sanitised (CWE-117; ',' and ' ' cannot appear inside one), each list capped at
 * kMaxIds entries and kMaxIdBytes in total; M = N - listed, so M > 0 means the list is incomplete
 * and the reader must not treat an unlisted rule as failed (likewise Q for the pending list).
 *
 * Threading: used only by GuardianEngine under its mtx_, from apply_rules / reconcile_rule_locked.
 * It is never touched from a mechanism worker or callback and logs nothing itself.
 */

#include <yuzu/log_token.hpp>

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

class GuardianPreservedTally {
public:
    static constexpr std::size_t kMaxIds = 128;
    static constexpr std::size_t kMaxIdBytes = 4096; // sum of the sanitised ids listed (per list)

    void reset() noexcept {
        committed_ = {};
        pending_ = {};
    }

    /// Records one rule skipped while healthy and committed. noexcept: the count is always kept,
    /// and an allocation failure only costs the id its place in the list (it then shows up in
    /// `more`).
    void note(const std::string& rule_id) noexcept { committed_.add(rule_id); }

    /// Records one rule whose identical arm is still in flight (re-observed, not yet confirmed).
    void note_pending(const std::string& rule_id) noexcept { pending_.add(rule_id); }

    [[nodiscard]] std::size_t count() const noexcept { return committed_.count; }
    [[nodiscard]] const std::vector<std::string>& ids() const noexcept { return committed_.ids; }
    [[nodiscard]] std::size_t pending_count() const noexcept { return pending_.count; }
    [[nodiscard]] const std::vector<std::string>& pending_ids() const noexcept {
        return pending_.ids;
    }

    /// May throw (allocation); the caller guards its logging.
    [[nodiscard]] std::string format() const {
        std::string out = "Guardian: full_sync preserved " + std::to_string(committed_.count) +
                          " rule(s) (skipped re-arm) ids=[";
        committed_.append_ids(out);
        out += "] more=" + std::to_string(committed_.count - committed_.ids.size());
        if (pending_.count != 0) {
            out += " pending_reused " + std::to_string(pending_.count) + " ids=[";
            pending_.append_ids(out);
            out += "] more=" + std::to_string(pending_.count - pending_.ids.size());
        }
        return out;
    }

private:
    struct Bounded {
        std::size_t count{0};
        std::size_t id_bytes{0};
        std::vector<std::string> ids;

        void add(const std::string& rule_id) noexcept {
            ++count;
            try {
                if (ids.size() >= kMaxIds)
                    return;
                std::string tok = ::yuzu::log_id_token(rule_id);
                if (id_bytes + tok.size() > kMaxIdBytes)
                    return;
                const std::size_t tok_bytes = tok.size();
                ids.push_back(std::move(tok));
                id_bytes += tok_bytes; // after push_back: a throwing push leaves the byte count true
            } catch (...) {
            }
        }
        void append_ids(std::string& out) const {
            for (std::size_t i = 0; i < ids.size(); ++i) {
                if (i != 0)
                    out += ',';
                out += ids[i];
            }
        }
    };

    Bounded committed_;
    Bounded pending_;
};

} // namespace yuzu::agent
