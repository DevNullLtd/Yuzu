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
 * Reasons and precedence. When several rebuild conditions hold at once, one reason is reported:
 * the first that GuardianSparkRuntime::reuse_existing_locked evaluates, in the order below. That
 * order is NOT the declaration order of GuardianRebuildReason and NOT the print order of the line.
 *   1. The key has any claim: this rule's own live arm with other content, spec or ownership
 *      reports content_changed (even if the key is also unhealthy); any other claim reports
 *      key_busy. (This rule's own live arm with identical content is a skip, not a rebuild.)
 *   2. No committed entry for the rule or the key, or the rule's live arm is mapped to a different
 *      key than the one it now targets (a retarget onto a key another rule holds): first_attach.
 *   3. Committed path, health before content: the key's recorded faulted bit (reports the cause
 *      recorded with it, else faulted_key); an absent health probe (health_unknown); a probe of a
 *      different subscription (subscription_replaced); a Dead probe (dead_key); any other
 *      non-Healthy probe (faulted_key); an Unknown evaluation episode (unknown_episode).
 *   4. Content: a changed content id (content_changed), then, for a file-hash rule, an empty
 *      (baseline_empty) or differing (baseline_differs) pushed hash.
 *   5. Defensive invariants that no public path violates: other.
 * So on the committed path (steps 3 and 4) a rule on a broken key is reported as a broken key even
 * when its content also changed, but step 1 comes first: a changed rule that still has its own
 * arm in flight is content_changed even when the key is unhealthy. For a kept rule that a
 * full_sync's scoped detach tore down because its key was faulted, dead or unreadable, the engine
 * reports the key's recorded cause instead of what the later attach observes (see (h)).
 *
 * Line format (one per full_sync that reaches the end of its rule loop; best-effort under
 * allocation failure; absent when apply_rules returns early on a persist failure). Counts are
 * always printed so the token set is stable; ` ids=[a,b]` follows an id-bearing group only when its
 * count is above zero:
 *   Guardian: full_sync rebuilt <N> rule(s) (rebuild attempted): path=<legacy|spark>
 *   first_attach=<A> content_changed=<B>
 *   key_busy=<C> [ids=[..]] faulted_key=<D> [ids=[..]] dead_key=<E> [ids=[..]] health_unknown=<F>
 *   [ids=[..]] subscription_replaced=<G> [ids=[..]] unknown_episode=<H> [ids=[..]]
 *   baseline_empty=<I> [ids=[..]] baseline_differs=<J> [ids=[..]] other=<K> [ids=[..]] more=<M>
 * (a single physical line). N is total() and equals the sum of the eleven bucket counts. ids are
 * log_id_token()-sanitised (CWE-117; ',' and ' ' cannot appear inside one). The nine id-bearing
 * groups share ONE budget (kMaxIds entries, kMaxIdBytes in total); M is the sum of the counts of
 * all id-bearing groups minus the ids listed, so M > 0 means a list is incomplete and the reader
 * must not treat an unlisted rule as failed. Once the budget is spent the ids that were listed are
 * the first ones noted, in the order the engine reconciled the rules (the push's rule order, not
 * grouped by reason); an id that no longer fits in the remaining bytes is left off while a later,
 * shorter one can still be listed. first_attach and content_changed are COUNT-ONLY: on
 * a first push or a rename every rule lands there and an id list would only repeat the push.
 * The line deliberately matches none of the fullsync_blackout_diag.py log-line patterns that
 * tests/test_spark_evidence_format_lockstep.py lists in DRIVER_REGEX_NAMES (a new driver line
 * pattern is added there in the same change).
 *
 * Contract a reader of this file must keep:
 *   (a) note() and format() run under GuardianEngine::mtx_ (apply_rules, or start_local's boot
 *       re-arm loop for note()), never under GuardianSparkRuntime::registry_mu_ and never on a
 *       mechanism worker or callback.
 *   (b) The precedence order above is the order reuse_existing_locked evaluates its terms. It is
 *       not the enum order; the two differ in the health block (the code tests the recorded bit,
 *       then an absent probe, then subscription_replaced, then Dead, then any other non-Healthy
 *       state).
 *   (c) first_attach means no committed rule, or no entry for the key the rule now targets (a
 *       retarget: the rule is committed on its old key), and no scoped-detach record. That
 *       INCLUDES a rule on_subscription_lost detached between pushes (a Lost event, or the
 *       convergence scheduler's dead-key poll check), which looks the same to the attach path
 *       as a rule never armed.
 *   (d) A genuinely new rule queued behind a forced disarm of the same key reports key_busy with
 *       its id, not first_attach.
 *   (e) The count includes Pending and Accepted outcomes that may still fail. There is no
 *       pending/committed split, hence "rebuild attempted". A rule whose attach is refused
 *       synchronously (the `spark arm failed` warning) appears in neither this line nor the
 *       preserved line, and any cause recorded for it by the scoped detach is lost.
 *   (f) A wedge re-observation (a retained wedged arm seen again) appears in NEITHER this line nor
 *       the preserved line: both retained-wedge re-observation returns in attach_core leave the
 *       rebuild reason None, and the engine consults the scoped detach's recorded cause only for an attach that
 *       reported a reason, so even a kept rule on a faulted key is not tallied for one.
 *   (g) path=legacy means the Spark attach path was not used for this push, so the tally was not
 *       fed and the line reads `rebuilt 0`. On a legacy-path agent (prefer_spark_ false, the
 *       production default) that does NOT mean nothing was rebuilt: every legacy guard is stopped
 *       and every carried rule that has a legacy guard is armed again on each full push (a
 *       disabled or invalid rule, or one whose guard cannot start on the host, has none). (With prefer_spark_ set but Spark
 *       Unwired or SparkFailed the carried rules are withdrawn and armed on neither backend, and
 *       the line still reads path=legacy.) The runtime's three failure counters are not all
 *       confined to the Spark attach path: see the accessors in guardian_spark_runtime.hpp.
 *   (h) The cause recorded on a key (PerKey::unhealthy_why) is first-cause-wins for the backend
 *       health sweep and the attach probe repair, but the mechanism's own Faulted/Recovered event
 *       is authoritative: it overwrites a sweep-recorded cause and a Recovered event clears it.
 *       The tally is fed from exactly one place, reconcile_rule_locked's Spark branch; the line
 *       itself is logged by every full_sync that reaches the end of its rule loop, fed or not.
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
/// NOT the precedence order (reuse_existing_locked's evaluation order is, see the header comment
/// above) and NOT the print order (kLineOrder); it fixes the bucket index, so adding or reordering
/// an enumerator needs kReasons, kLineOrder, the token table, the unit tests and the golden
/// fixture updated together.
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

/// Which arm path the push took: the Spark path (prefer_spark_ true and Spark Available), where the
/// skip/rebuild decision applies, or the legacy label for every other case, where the tally is never
/// fed. In production (prefer_spark_ false) the legacy guards are all stopped and every carried rule
/// that has a legacy guard is armed again on each full_sync; with prefer_spark_ set but Spark Unwired or SparkFailed the carried
/// rules are armed on neither backend. Printed as `path=legacy|spark`.
enum class GuardianRebuildPath : std::uint8_t { Legacy = 0, Spark };

[[nodiscard]] constexpr std::string_view guardian_rebuild_path_token(GuardianRebuildPath p) noexcept {
    return p == GuardianRebuildPath::Spark ? "spark" : "legacy";
}

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

    /// May throw (allocation); the caller guards its logging. `path` is the arm path the push took
    /// (the same expression reconcile_rule_locked uses to choose it).
    [[nodiscard]] std::string format(GuardianRebuildPath path) const {
        std::string out = "Guardian: full_sync rebuilt " + std::to_string(total()) +
                          " rule(s) (rebuild attempted): path=" +
                          std::string{guardian_rebuild_path_token(path)};
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

    /// True when the print order lists every non-None reason exactly once (checked at compile time
    /// below the class: a new enumerator missing from the line, or listed twice, fails the build).
    [[nodiscard]] static constexpr bool line_order_is_complete() noexcept {
        std::array<unsigned, kReasons> seen{};
        for (const auto why : kLineOrder) {
            const auto i = index(why);
            if (i == 0 || i >= kReasons)
                return false;
            ++seen[i];
        }
        for (std::size_t i = 1; i < kReasons; ++i)
            if (seen[i] != 1)
                return false;
        return true;
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

static_assert(GuardianRebuildTally::line_order_is_complete(),
              "kLineOrder must list every non-None GuardianRebuildReason exactly once");

// The engine apply thread must never see these throw (note() is called inside reconcile).
static_assert(noexcept(std::declval<GuardianRebuildTally&>().reset()));
static_assert(noexcept(std::declval<GuardianRebuildTally&>().note(std::declval<const std::string&>(),
                                                                  GuardianRebuildReason::KeyBusy)));

} // namespace yuzu::agent
