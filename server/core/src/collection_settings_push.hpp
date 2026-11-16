#pragma once

/// @file collection_settings_push.hpp
/// Heartbeat-driven delivery of the effective software collection settings (SAM-39).
///
/// An agent reports the version of the settings document it applied in the heartbeat status tag
/// `yuzu.inv_settings_version` (a 64-character lower-case hex digest, or the literal `none`).
/// `CollectionSettingsPusher::on_heartbeat` resolves what applies to that agent, and when the two
/// differ sends the document once through the injected `send`. There is no push-on-save and no
/// background job: a saved change reaches an agent on its next heartbeat after the 60 s snapshot
/// TTL (10 minutes for a membership change). All state is in memory and rebuilt from heartbeats
/// after a restart; a lost send is repaired by the next heartbeat that still reports the old
/// version, no sooner than the re-push gap; a replay is idempotent because the agent compares
/// versions.
///
/// Locking: one mutex guards the maps. No store read and no send runs while it is held. Three
/// publication rules keep that safe without holding it across I/O:
///   1. the snapshot is published under the mutex by the single refresher with epoch = previous
///      + 1;
///   2. a per-agent memo is written monotonically: a computation that started from epoch E is
///      discarded when the stored memo already carries a later epoch;
///   3. decide and claim are one critical section: the memo is re-read, `decide_push` runs and,
///      on Push, `last_push` is stamped BEFORE unlocking, so a concurrent heartbeat for the same
///      agent meets the stamp and is Suppressed. A send that returns false keeps its stamp. A late
///      send of an older claim can still arrive after a newer one; the agent then reports the
///      older version and the next heartbeat after the gap repairs it.

#include "collection_settings_resolve.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::collection_settings {

/// The tag value of an agent that has applied no pushed document.
inline constexpr std::string_view kNoSettingsTag = "none";

/// The same version is not re-sent to one agent inside this gap.
inline constexpr std::int64_t kMinRepushGapSecs = 300;
/// The store snapshot (documents, tree, kill switches) is re-read when older than this.
inline constexpr std::int64_t kSnapshotTtlSecs = 60;
/// An agent's group membership is re-read when the cached read is older than this.
inline constexpr std::int64_t kMembershipTtlSecs = 600;
/// After a failed membership read no membership read is attempted, for any agent, for this long:
/// a degraded pool then costs one acquire timeout per gap, not one per heartbeat (a gateway batch
/// ingests its heartbeats one after another on one thread).
inline constexpr std::int64_t kMembershipRetrySecs = 60;
/// A memo not seen for this long is evicted during a snapshot refresh.
inline constexpr std::int64_t kMemoEvictSecs = 3600;

enum class PushVerdict { UpToDate, Push, Suppressed };

struct LastPush {
    std::string version;
    std::int64_t at{0};
};

/// Pure. `reported_tag` is `none` or a version (the caller has validated the shape).
/// Equal versions are UpToDate; `none` while the effective document is the built-in fleet default
/// is UpToDate (defaults are never pushed fleet-wide); otherwise Push, except Suppressed when THIS
/// SAME effective version was already sent to the agent inside the gap. A document that changed
/// since the last push is sent at once.
[[nodiscard]] inline PushVerdict decide_push(std::string_view reported_tag,
                                             std::string_view effective_version,
                                             bool effective_is_fleet_default,
                                             const std::optional<LastPush>& last_push,
                                             std::int64_t now) {
    if (reported_tag == effective_version)
        return PushVerdict::UpToDate;
    if (reported_tag == kNoSettingsTag && effective_is_fleet_default)
        return PushVerdict::UpToDate;
    if (last_push && last_push->version == effective_version) {
        const auto age = now - last_push->at;
        if (age >= 0 && age < kMinRepushGapSecs)
            return PushVerdict::Suppressed;
    }
    return PushVerdict::Push;
}

/// The shape an agent may report: `none` or a 64-character lower-case hex version.
[[nodiscard]] inline bool is_reportable_tag(std::string_view tag) {
    return tag == kNoSettingsTag || is_version_text(tag);
}

class CollectionSettingsPusher {
public:
    /// Each read returns nullopt when the underlying store degraded.
    struct Deps {
        std::function<std::optional<std::vector<StoredDocument>>()> read_docs;
        std::function<std::optional<std::vector<GroupNode>>()> read_tree;
        /// plugin -> kill-switched, for every kCollectionPlugins entry.
        std::function<std::optional<std::map<std::string, bool>>()> read_killed;
        std::function<std::optional<std::vector<std::string>>(const std::string& agent_id)>
            read_membership;
        std::function<std::int64_t()> now; ///< epoch seconds
        /// True when the frame was accepted for the agent. Called outside the mutex.
        std::function<bool(const std::string& agent_id, const std::string& version,
                           const std::string& document)>
            send;
        /// Optional counters: reason is snapshot | membership | resolve.
        std::function<void(std::string_view reason)> on_degrade;
        /// Optional counter: result is sent | undelivered | suppressed.
        std::function<void(std::string_view result)> on_result;
    };

    explicit CollectionSettingsPusher(Deps deps) : deps_(std::move(deps)) {}
    CollectionSettingsPusher(const CollectionSettingsPusher&) = delete;
    CollectionSettingsPusher& operator=(const CollectionSettingsPusher&) = delete;

    /// `reported_tag` has been validated with `is_reportable_tag`.
    void on_heartbeat(const std::string& agent_id, const std::string& reported_tag);

    /// Agents with a memo (tests; eviction is otherwise invisible).
    [[nodiscard]] std::size_t tracked_agents() {
        std::lock_guard lock(mu_);
        return memos_.size();
    }

private:
    struct Snapshot {
        std::vector<StoredDocument> docs;
        std::vector<GroupNode> tree;
        std::map<std::string, bool> killed;
        std::uint64_t epoch{0};
    };
    /// What applies to one agent. `groups` is the membership read, reused until it is older than
    /// kMembershipTtlSecs; a new snapshot epoch re-resolves from it without re-reading.
    struct Memo {
        std::uint64_t epoch{0};
        std::vector<std::string> groups;
        std::int64_t membership_at{0};
        std::string version;
        std::string document;
        bool is_fleet_default{false};
        std::int64_t seen_at{0};
        std::optional<LastPush> last_push;
    };
    struct Claim {
        std::string version;
        std::string document;
    };

    [[nodiscard]] std::shared_ptr<const Snapshot> snapshot(std::int64_t now);
    /// Caller holds `mu_`. Decide against the current clock and, on Push, stamp the claim.
    [[nodiscard]] PushVerdict decide_and_claim_locked(Memo& memo, const std::string& tag,
                                                      Claim& claim);
    void degrade(std::string_view reason) const {
        if (deps_.on_degrade)
            deps_.on_degrade(reason);
    }
    void result(std::string_view r) const {
        if (deps_.on_result)
            deps_.on_result(r);
    }

    Deps deps_;
    std::mutex mu_;
    std::shared_ptr<const Snapshot> snapshot_;         // guarded by mu_
    std::optional<std::int64_t> attempted_at_;         // guarded by mu_: start of the last refresh
    std::optional<std::int64_t> membership_failed_at_; // guarded by mu_: the last failed read
    bool refreshing_{false};                           // guarded by mu_
    std::map<std::string, Memo> memos_;                // guarded by mu_
};

} // namespace yuzu::server::collection_settings
