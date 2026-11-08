#pragma once

/**
 * guardian_rebuild_tally.hpp - the per-push record of WHY a Spark rule a full_sync carried was
 * rebuilt instead of skipped (#5719 item 1), and the one log line that reports it.
 *
 * Why it exists: GuardianSparkRuntime::attach_core skips a rule that is healthy and unchanged
 * (#4415) and the engine reports those on the `full_sync preserved` line
 * (guardian_preserved_tally.hpp). A rule the push carries that is NOT skipped is rebuilt, and until
 * this line existed nothing said why: a reader could tell that the ruleset paid a re-arm, not which
 * condition forced it. This line names the cause per rule so a rebuild storm can be attributed.
 *
 * Reasons and precedence. When several rebuild conditions hold at once, the FIRST of these wins
 * (this is the declaration order of GuardianRebuildReason after None):
 *   key_busy, first_attach, faulted_key, dead_key, health_unknown, subscription_replaced,
 *   unknown_episode, content_changed, baseline_empty, baseline_differs, other.
 * Health terms outrank content terms on purpose: a rule on a broken key must be reported as a
 * broken key even when its content also changed.
 *
 * Line format (one per full_sync that reaches the end of its rule loop; best-effort under
 * allocation failure; absent when apply_rules returns early on a persist failure). Counts are
 * always printed so the token set is stable; ` ids=[a,b]` follows an id-bearing group only when its
 * count is above zero:
 *   Guardian: full_sync rebuilt <N> rule(s) (rebuild attempted): first_attach=<A> content_changed=<B>
 *   key_busy=<C> [ids=[..]] faulted_key=<D> [ids=[..]] dead_key=<E> [ids=[..]] health_unknown=<F>
 *   [ids=[..]] subscription_replaced=<G> [ids=[..]] unknown_episode=<H> [ids=[..]]
 *   baseline_empty=<I> [ids=[..]] baseline_differs=<J> [ids=[..]] other=<K> [ids=[..]] more=<M>
 * (a single physical line). N is total() and equals the sum of the eleven bucket counts. ids are
 * log_id_token()-sanitised (CWE-117; ',' and ' ' cannot appear inside one). The nine id-bearing
 * groups share ONE budget (kMaxIds entries, kMaxIdBytes in total); M is the sum of the counts of
 * all id-bearing groups minus the ids listed, so M > 0 means a list is incomplete and the reader
 * must not treat an unlisted rule as failed. first_attach and content_changed are COUNT-ONLY: on
 * a first push or a rename every rule lands there and an id list would only repeat the push.
 * The line deliberately matches none of the fullsync_blackout_diag.py driver patterns.
 *
 * Contract a reader of this file must keep:
 *   (a) note() and format() run on the engine apply thread under GuardianEngine::mtx_, never
 *       under GuardianSparkRuntime::registry_mu_ and never on a mechanism worker or callback.
 *   (b) The precedence order above is the order reuse_existing_locked evaluates its terms.
 *   (c) first_attach means no committed arm and no scoped-detach record. That INCLUDES a rule the
 *       heartbeat poll backstop (on_subscription_lost) lost between pushes, which looks the same
 *       to the attach path as a rule never armed.
 *   (d) A genuinely new rule queued behind a forced disarm of the same key reports key_busy with
 *       its id, not first_attach.
 *   (e) The count includes Pending and Accepted outcomes that may still fail. There is no
 *       pending/committed split, hence "rebuild attempted".
 *   (f) A wedge re-observation (a retained wedged arm seen again) appears in NEITHER this line nor
 *       the preserved line: it carries no rebuild reason.
 *   (g) On a legacy-path agent (prefer_spark_ false, the production default) the attach path is
 *       never reached, so this line is always `rebuilt 0` and every counter stays zero.
 *
 * Threading: see (a). It logs nothing itself.
 */

#include <yuzu/log_token.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Why a rule the push carried was rebuilt instead of skipped. The declaration order after None is
/// the documented precedence order (first match wins); do not reorder without updating the header
/// comment above, the runtime's evaluation order and the golden fixture.
enum class GuardianRebuildReason : std::uint8_t {
    None = 0,
    KeyBusy,
    FirstAttach,
    KeyFaulted,
    KeyDead,
    HealthUnknown,
    SubscriptionReplaced,
    UnknownEpisode,
    ContentChanged,
    BaselineEmpty,
    BaselineDiffers,
    Other,
};

/// Unique lower-case log token: no space, comma or bracket. `none` is never printed.
[[nodiscard]] constexpr std::string_view guardian_rebuild_reason_token(GuardianRebuildReason r) noexcept {
    switch (r) {
    case GuardianRebuildReason::None:
        return "none";
    case GuardianRebuildReason::KeyBusy:
        return "key_busy";
    case GuardianRebuildReason::FirstAttach:
        return "first_attach";
    case GuardianRebuildReason::KeyFaulted:
        return "faulted_key";
    case GuardianRebuildReason::KeyDead:
        return "dead_key";
    case GuardianRebuildReason::HealthUnknown:
        return "health_unknown";
    case GuardianRebuildReason::SubscriptionReplaced:
        return "subscription_replaced";
    case GuardianRebuildReason::UnknownEpisode:
        return "unknown_episode";
    case GuardianRebuildReason::ContentChanged:
        return "content_changed";
    case GuardianRebuildReason::BaselineEmpty:
        return "baseline_empty";
    case GuardianRebuildReason::BaselineDiffers:
        return "baseline_differs";
    case GuardianRebuildReason::Other:
        return "other";
    }
    return "other";
}

class GuardianRebuildTally {
public:
    static constexpr std::size_t kMaxIds = 64;
    static constexpr std::size_t kMaxIdBytes = 2048; // sum of the sanitised ids listed, all groups

    void reset() noexcept {
        counts_ = {};
        ids_ = {};
        listed_ = 0;
        id_bytes_ = 0;
    }

    /// Records one rebuilt rule. noexcept: the count is always kept, and an allocation failure
    /// (or an exhausted budget) only costs the id its place in the list, so it shows in `more`.
    /// GuardianRebuildReason::None is a no-op.
    void note(const std::string& rule_id, GuardianRebuildReason why) noexcept {
        const auto i = index(why);
        if (i == 0 || i >= kReasons)
            return;
        ++counts_[i];
        if (!id_bearing(why))
            return;
        try {
            if (listed_ >= kMaxIds)
                return;
            std::string tok = ::yuzu::log_id_token(rule_id);
            if (id_bytes_ + tok.size() > kMaxIdBytes)
                return;
            const std::size_t tok_bytes = tok.size();
            ids_[i].push_back(std::move(tok));
            ++listed_; // after push_back: a throwing push leaves the budget true
            id_bytes_ += tok_bytes;
        } catch (...) {
        }
    }

    /// Sum of the eleven bucket counts.
    [[nodiscard]] std::size_t total() const noexcept {
        std::size_t n = 0;
        for (std::size_t i = 1; i < kReasons; ++i)
            n += counts_[i];
        return n;
    }

    [[nodiscard]] std::size_t count(GuardianRebuildReason why) const noexcept {
        const auto i = index(why);
        return i < kReasons ? counts_[i] : 0;
    }

    [[nodiscard]] const std::vector<std::string>& ids(GuardianRebuildReason why) const noexcept {
        static const std::vector<std::string> kEmpty;
        const auto i = index(why);
        return i < kReasons ? ids_[i] : kEmpty;
    }

    /// May throw (allocation); the caller guards its logging.
    [[nodiscard]] std::string format() const {
        std::string out = "Guardian: full_sync rebuilt " + std::to_string(total()) +
                          " rule(s) (rebuild attempted):";
        std::size_t id_bearing_total = 0;
        for (const auto why : kLineOrder) {
            const auto i = index(why);
            out += ' ';
            out += guardian_rebuild_reason_token(why);
            out += '=';
            out += std::to_string(counts_[i]);
            if (!id_bearing(why))
                continue;
            id_bearing_total += counts_[i];
            if (counts_[i] == 0)
                continue;
            out += " ids=[";
            for (std::size_t k = 0; k < ids_[i].size(); ++k) {
                if (k != 0)
                    out += ',';
                out += ids_[i][k];
            }
            out += ']';
        }
        out += " more=" + std::to_string(id_bearing_total - listed_);
        return out;
    }

private:
    static constexpr std::size_t kReasons = static_cast<std::size_t>(GuardianRebuildReason::Other) + 1;

    [[nodiscard]] static constexpr std::size_t index(GuardianRebuildReason why) noexcept {
        return static_cast<std::size_t>(why);
    }
    [[nodiscard]] static constexpr bool id_bearing(GuardianRebuildReason why) noexcept {
        return why != GuardianRebuildReason::None && why != GuardianRebuildReason::FirstAttach &&
               why != GuardianRebuildReason::ContentChanged;
    }

    // Print order: the two count-only groups first, then the id-bearing groups. This is NOT the
    // enum (precedence) order, which puts key_busy and first_attach first.
    static constexpr std::array<GuardianRebuildReason, kReasons - 1> kLineOrder{
        GuardianRebuildReason::FirstAttach,           GuardianRebuildReason::ContentChanged,
        GuardianRebuildReason::KeyBusy,               GuardianRebuildReason::KeyFaulted,
        GuardianRebuildReason::KeyDead,               GuardianRebuildReason::HealthUnknown,
        GuardianRebuildReason::SubscriptionReplaced,  GuardianRebuildReason::UnknownEpisode,
        GuardianRebuildReason::BaselineEmpty,         GuardianRebuildReason::BaselineDiffers,
        GuardianRebuildReason::Other};

    std::array<std::size_t, kReasons> counts_{};
    std::array<std::vector<std::string>, kReasons> ids_{};
    std::size_t listed_{0};   // ids listed across all id-bearing groups
    std::size_t id_bytes_{0}; // sum of those ids' bytes
};

} // namespace yuzu::agent
