#include "collection_settings_push.hpp"

#include <utility>

namespace yuzu::server::collection_settings {

std::shared_ptr<const CollectionSettingsPusher::Snapshot>
CollectionSettingsPusher::snapshot(std::int64_t now) {
    {
        std::lock_guard lock(mu_);
        // A clock that stepped back (now before the last attempt) counts as due: the age would
        // otherwise stay negative and freeze the snapshot until the clock caught up.
        const bool due = !attempted_at_ || now < *attempted_at_ ||
                         now - *attempted_at_ >= kSnapshotTtlSecs;
        if (!due || refreshing_)
            return snapshot_; // fresh enough, or another heartbeat is already refreshing
        refreshing_ = true;
        attempted_at_ = now; // a failed refresh is retried after the TTL, not on every heartbeat
    }

    // Single refresher from here. Every read runs outside the mutex; the flag is released on
    // every exit, including a throwing read.
    struct Release {
        CollectionSettingsPusher& self;
        bool armed{true};
        ~Release() {
            if (armed) {
                std::lock_guard lock(self.mu_);
                self.refreshing_ = false;
            }
        }
    } release{*this};

    auto next = std::make_shared<Snapshot>();
    bool ok = false;
    if (auto docs = deps_.read_docs()) {
        if (auto tree = deps_.read_tree()) {
            if (auto killed = deps_.read_killed()) {
                next->docs = std::move(*docs);
                next->tree = std::move(*tree);
                next->killed = std::move(*killed);
                ok = true;
            }
        }
    }
    if (!ok) {
        degrade("snapshot"); // the previous snapshot keeps serving
        std::lock_guard lock(mu_);
        return snapshot_;
    }

    std::lock_guard lock(mu_);
    next->epoch = (snapshot_ ? snapshot_->epoch : 0) + 1;
    for (auto it = memos_.begin(); it != memos_.end();) {
        if (now - it->second.seen_at >= kMemoEvictSecs)
            it = memos_.erase(it);
        else
            ++it;
    }
    snapshot_ = std::move(next);
    return snapshot_;
    // `release` clears refreshing_ after this lock_guard (declared later) is destroyed.
}

PushVerdict CollectionSettingsPusher::decide_and_claim_locked(Memo& memo, const std::string& tag,
                                                              Claim& claim) {
    const auto now = deps_.now();
    const auto verdict =
        decide_push(tag, memo.version, memo.is_fleet_default, memo.last_push, now);
    if (verdict == PushVerdict::Push) {
        memo.last_push = LastPush{memo.version, now}; // stamped before the send, kept if it fails
        claim = Claim{memo.version, memo.document};
    }
    return verdict;
}

void CollectionSettingsPusher::on_heartbeat(const std::string& agent_id,
                                            const std::string& reported_tag) {
    const auto now = deps_.now();
    const auto snap = snapshot(now);
    if (!snap)
        return; // no snapshot yet: nothing is pushed

    Claim claim;
    PushVerdict verdict = PushVerdict::UpToDate;
    std::optional<std::vector<std::string>> cached_groups;
    std::int64_t cached_membership_at = 0;
    bool decided = false;
    bool membership_cooling = false;
    {
        std::lock_guard lock(mu_);
        if (const auto it = memos_.find(agent_id); it != memos_.end()) {
            Memo& m = it->second;
            m.seen_at = now;
            // A negative age (the clock stepped back) is expired, like the snapshot's.
            if (const auto age = now - m.membership_at; age >= 0 && age < kMembershipTtlSecs) {
                if (m.epoch >= snap->epoch) {
                    verdict = decide_and_claim_locked(m, reported_tag, claim);
                    decided = true;
                } else {
                    cached_groups = m.groups;
                    cached_membership_at = m.membership_at;
                }
            }
        }
        // This heartbeat needs a membership read. After a failed one none is attempted, for any
        // agent, until the retry gap has passed (a clock that stepped back ends the gap).
        if (!decided && !cached_groups && membership_failed_at_) {
            const auto since = now - *membership_failed_at_;
            membership_cooling = since >= 0 && since < kMembershipRetrySecs;
        }
    }
    if (membership_cooling) {
        degrade("membership");
        return;
    }

    if (!decided) {
        // Recompute outside the mutex: the epoch moved, the membership read expired, or this is
        // the first heartbeat from the agent.
        std::vector<std::string> groups;
        std::int64_t membership_at = cached_membership_at;
        if (cached_groups) {
            groups = std::move(*cached_groups);
        } else {
            auto read = deps_.read_membership(agent_id);
            if (!read) {
                {
                    std::lock_guard lock(mu_);
                    membership_failed_at_ = now;
                }
                degrade("membership");
                return;
            }
            groups = std::move(*read);
            membership_at = now;
        }
        auto resolved = resolve(groups, snap->tree, snap->docs, snap->killed);
        if (!resolved) {
            degrade("resolve");
            return;
        }

        std::lock_guard lock(mu_);
        Memo& m = memos_[agent_id];
        // Monotonic: a computation from an older epoch never replaces a newer memo. The newer one
        // is then the one decided on.
        if (m.epoch <= snap->epoch) {
            m.epoch = snap->epoch;
            m.groups = std::move(groups);
            m.membership_at = membership_at;
            m.version = std::move(resolved->version);
            m.document = canonical_text(resolved->effective);
            m.is_fleet_default = resolved->effective == kFleetDefault.effective();
        }
        m.seen_at = now;
        verdict = decide_and_claim_locked(m, reported_tag, claim);
    }

    if (verdict == PushVerdict::Suppressed) {
        result("suppressed");
    } else if (verdict == PushVerdict::Push) {
        // Outside the mutex: a send may block on the registry or re-enter on_heartbeat.
        result(deps_.send(agent_id, claim.version, claim.document) ? "sent" : "undelivered");
    }
}

} // namespace yuzu::server::collection_settings
