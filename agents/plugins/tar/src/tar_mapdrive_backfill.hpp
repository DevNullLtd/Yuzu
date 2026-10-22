#pragma once

/**
 * tar_mapdrive_backfill.hpp -- pure per-profile retry state for TAR's mapped-drive HISTORICAL
 * backfill (related issue #5291). windows.h-free by design: tar_plugin.cpp and
 * tar_mapdrive_collector.cpp are the impure shell around these functions.
 *
 * Persisted value (ONE tar_config key, `mapdrive_backfill_pending`): the text
 * `<last_attempt_ts>;sid:attempts;sid:attempts...`. The timestamp and the list are always written
 * together in one autocommit write (commit_first_pass; the retry's own two set_config calls in
 * tar_plugin.cpp), so no crash boundary can separate "when we last tried" from "who is still
 * pending" -- a second key for the timestamp would open exactly that window.
 *
 * Domain: a SID is `S-1-` followed by one or more of `[0-9-]`; an attempt count is a decimal
 * integer in [0, kMapDriveBackfillMaxAttempts] (0 = listed but not yet tried: the first pass
 * could not reach it); a malformed segment (bad SID shape, non-numeric/negative count, empty
 * segment) is DROPPED, never thrown on -- a hand-edited or
 * corrupt value degrades to "nothing pending", not a crash; a count above the max is clamped;
 * duplicate SIDs collapse to the highest count.
 *
 * kMapDriveBackfillMaxAttempts is the TOTAL number of acquisitions per SID, first pass included
 * (the init-time backfill's attempt is attempt 1) -- so the default of 7 means six further
 * retries, kMapDriveBackfillRetryIntervalS apart, before an entry is abandoned WITHOUT a further
 * acquisition attempt: retry_sids never selects an exhausted entry, and apply_outcomes abandons
 * one on sight, whether or not this run's outcome set says anything about it.
 */

#include <user_profile_model.hpp> // yuzu::profiles::HiveAccessStatus

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

inline constexpr int kMapDriveBackfillMaxAttempts = 7;
inline constexpr std::int64_t kMapDriveBackfillRetryIntervalS = 86400;

// Mirrored Win32 codes (classify_subkey_enum's three-line mirror,
// privacy_permissions_win_parsers.hpp:187-195) -- named here, not pulled from windows.h, so this
// header stays windows.h-free.
inline constexpr long kErrorSuccess = 0;
inline constexpr long kErrorFileNotFound = 2;
inline constexpr long kErrorNoMoreItems = 259;

/// One profile still pending acquisition (or retry).
struct PendingProfile {
    std::string sid;
    int attempts = 0;
};

/// The ONE persisted value, parsed. `last_ts` is the epoch second of the last ATTEMPT (claim),
/// not the last success -- retry_due reads it directly.
struct PendingState {
    std::int64_t last_ts = 0;
    std::vector<PendingProfile> profiles;
};

/// One profile's outcome from a mapdrive-history walk (first pass or retry). `token` is the
/// collector's rendering of `status` (yuzu::profiles::hive_access_token, with a not_found-cause
/// or read_failed:win32_<rc> suffix where applicable) -- this header never re-derives it.
/// `complete` is false when the hive mounted and read fine but this profile's own walk was cut by
/// kMapDriveHistoryCap (read ok, just not ALL of it); `read_ok` is false when the hive mounted but
/// an inner registry key open or enumeration failed with a code other than not-found/no-more-
/// items (the hive was readable; this one key wasn't). `attempted` is false when no mount was
/// actually tried for this profile in this run (the shared outstanding-call ceiling refused the
/// call, or an earlier profile's mount timed out and the walk stopped mounting): such an outcome
/// is never a failed attempt, so apply_outcomes keeps the entry unchanged instead of bumping it.
struct ProfileHiveOutcome {
    std::string sid;
    yuzu::profiles::HiveAccessStatus status{yuzu::profiles::HiveAccessStatus::ok};
    std::string token;
    bool complete = true;
    bool read_ok = true;
    bool attempted = true;
};

/// How a bounded mount-and-read call ended (the collector maps bounded_call_ex's status here so
/// this header stays free of the shared bounded-wait primitive).
enum class MountCallResult { completed, timed_out, rejected };

/// What the per-profile walk does with a bounded call's result. A timed-out mount is abandoned,
/// not cancelled: its thread keeps running, still holding the process-wide offline-hive mutex,
/// so every later offline mount would queue behind it and time out too -- the walk stops mounting
/// (`halt_walk`) and the remaining profiles are recorded as not attempted. A rejected call never
/// ran the mount at all (the ceiling was full): it is not an attempt, and the next call would be
/// refused the same way, so it halts too. (The plugin module is pinned before the FIRST mount, in
/// the collector, not here: even a call that completes leaves its worker thread destroying plugin
/// code after the result is published.)
struct MountCallDecision {
    bool attempted = true;
    bool halt_walk = false;
};

/// Whether a walk may start mounting at all. A walk that cannot pin the plugin module must not
/// spawn a worker; a walk that starts while an earlier walk's ABANDONED worker is still running
/// would only queue behind that worker's offline-hive mutex, time out, and charge its first
/// profile an attempt it never made -- every run, for as long as the worker stays stuck. Either
/// way no mount is tried and every requested profile is recorded as not attempted.
enum class WalkGate { open, pin_failed, prior_mount_running };

[[nodiscard]] constexpr WalkGate decide_walk_gate(bool pinned, int mount_workers_in_flight) noexcept {
    if (!pinned)
        return WalkGate::pin_failed;
    return mount_workers_in_flight > 0 ? WalkGate::prior_mount_running : WalkGate::open;
}

/// The token an unattempted profile carries for the cause that stopped the walk.
[[nodiscard]] constexpr const char* walk_gate_token(WalkGate g) noexcept {
    switch (g) {
    case WalkGate::open:
        return "";
    case WalkGate::pin_failed:
        return "pin_failed";
    case WalkGate::prior_mount_running:
        return "prior_mount_still_running";
    }
    return "";
}

[[nodiscard]] constexpr MountCallDecision decide_mount_call(MountCallResult r) noexcept {
    switch (r) {
    case MountCallResult::completed:
        return {true, false};
    case MountCallResult::timed_out:
        return {true, true};
    case MountCallResult::rejected:
        return {false, true};
    }
    return {true, true}; // unreachable; a corrupt value is treated as a stop
}

/// sid abandoned this run without a further acquisition attempt, with the token that explains
/// why: "exhausted" (already at the cap when this apply ran) or the triggering outcome's own
/// token (the bump that reached the cap).
struct RetryAbandoned {
    std::string sid;
    std::string token;
};

/// sid retained unchanged (no bump) because this run did not try it: `cause` is
/// "profile_list_incomplete" when the ProfileList walk itself was cut short (absence proves
/// nothing about this profile), or the token of an outcome with attempted == false (the mount
/// was refused by the ceiling or skipped after an earlier timeout).
struct RetryRetained {
    std::string sid;
    std::string cause;
};

/// Every retryable outcome this run actually observed, with the attempt count AFTER the bump.
struct RetryFailure {
    std::string sid;
    int attempts = 0;
    std::string token;
};

struct RetryResult {
    PendingState next;
    std::vector<RetryAbandoned> abandoned;
    std::vector<std::string> vanished; // no outcome, and the walk was complete: the profile is gone
    std::vector<RetryRetained> retained;
    std::vector<RetryFailure> failed;
};

/// Mirrors privacy_permissions_win_parsers.hpp's classify_subkey_enum (plugin-local there, so
/// mirrored here as three lines rather than shared): a ProfileList walk is complete when it ended
/// on a genuine ERROR_NO_MORE_ITEMS, or ended at the kMaxProfiles cap (last_rc == SUCCESS) AND the
/// one extra cap probe also found nothing further (probe_rc == ERROR_NO_MORE_ITEMS). Any other
/// combination -- a terminating error, or a cap probe that found another entry or itself failed
/// -- is incomplete: a vanished-vs-retained decision made from an incomplete walk can never be
/// trusted to mean "this profile is gone".
[[nodiscard]] constexpr bool profile_list_complete(long root_rc, long last_rc, long probe_rc) {
    return root_rc == kErrorSuccess &&
           (last_rc == kErrorNoMoreItems ||
            (last_rc == kErrorSuccess && probe_rc == kErrorNoMoreItems));
}

/// Why a profile's own HKU\<SID> hive was not_found: the specific cause, closed vocabulary,
/// checked in this fixed order (a failed SID-key open outranks everything else it also implies).
[[nodiscard]] inline std::string not_found_cause(bool path_unreadable,
                                                 std::optional<long> key_open_rc,
                                                 long live_open_rc) {
    if (key_open_rc)
        return "profile_key_win32_" + std::to_string(*key_open_rc);
    if (path_unreadable)
        return "profile_image_path_unreadable";
    if (live_open_rc != kErrorFileNotFound)
        return "hku_open_win32_" + std::to_string(live_open_rc);
    return "no_profile_image_path";
}

namespace detail {

[[nodiscard]] inline bool is_valid_sid_shape(std::string_view sid) {
    if (!sid.starts_with("S-1-") || sid.size() == 4) // "S-1-" alone has no suffix to validate
        return false;
    for (char c : sid.substr(4)) {
        if (!(std::isdigit(static_cast<unsigned char>(c)) || c == '-'))
            return false;
    }
    return true;
}

// Parses a decimal integer occupying the WHOLE of `sv`; nullopt on any malformed input (never
// throws) -- std::from_chars itself never throws, but a caller must still reject a partial parse
// (trailing garbage) and a non-decimal-errc result explicitly.
[[nodiscard]] inline std::optional<std::int64_t> parse_whole_i64(std::string_view sv) {
    std::int64_t v = 0;
    const auto res = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    if (res.ec != std::errc{} || res.ptr != sv.data() + sv.size())
        return std::nullopt;
    return v;
}

} // namespace detail

/// Parses the persisted `<last_ts>;sid:attempts;sid:attempts...` value. A missing or unparsable
/// leading timestamp parses as 0 (due). Every later segment is validated independently: a
/// malformed SID, a non-numeric/negative/unparsable count, or an empty segment is dropped,
/// never thrown on; a count above `max_attempts` is clamped to it; duplicate SIDs collapse to the
/// highest count seen.
[[nodiscard]] inline PendingState parse_pending_state(std::string_view text, int max_attempts) {
    PendingState st;
    const std::size_t first_semi = text.find(';');
    const std::string_view ts_part =
        first_semi == std::string_view::npos ? text : text.substr(0, first_semi);
    const auto parsed_ts = detail::parse_whole_i64(ts_part);
    st.last_ts = parsed_ts.value_or(0);
    if (first_semi == std::string_view::npos)
        return st;

    std::string_view rest = text.substr(first_semi + 1);
    while (!rest.empty()) {
        const std::size_t next = rest.find(';');
        const std::string_view seg = next == std::string_view::npos ? rest : rest.substr(0, next);
        rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 1);
        if (seg.empty())
            continue;
        const std::size_t colon = seg.find(':');
        if (colon == std::string_view::npos)
            continue;
        const std::string_view sid = seg.substr(0, colon);
        const std::string_view count_sv = seg.substr(colon + 1);
        if (!detail::is_valid_sid_shape(sid))
            continue;
        const auto parsed_count = detail::parse_whole_i64(count_sv);
        if (!parsed_count || *parsed_count < 0)
            continue;
        int count = static_cast<int>(std::min<std::int64_t>(*parsed_count, max_attempts));
        bool merged = false;
        for (auto& p : st.profiles) {
            if (p.sid == sid) {
                if (count > p.attempts)
                    p.attempts = count;
                merged = true;
                break;
            }
        }
        if (!merged)
            st.profiles.push_back(PendingProfile{std::string{sid}, count});
    }
    return st;
}

/// Inverse of parse_pending_state (round-trips the timestamp and the list together).
[[nodiscard]] inline std::string format_pending_state(const PendingState& st) {
    std::string out = std::to_string(st.last_ts);
    for (const auto& p : st.profiles) {
        out += ';';
        out += p.sid;
        out += ':';
        out += std::to_string(p.attempts);
    }
    return out;
}

/// SIDs still eligible for a further acquisition attempt -- an entry at or above max_attempts is
/// never selected again (review P5: exhausted is abandoned, not re-acquired).
[[nodiscard]] inline std::vector<std::string>
retry_sids(const PendingState& st, int max_attempts = kMapDriveBackfillMaxAttempts) {
    std::vector<std::string> out;
    for (const auto& p : st.profiles) {
        if (p.attempts < max_attempts)
            out.push_back(p.sid);
    }
    return out;
}

/// Seeds the pending LIST after the first pass (the caller pairs it with that pass's own
/// timestamp to build the first PendingState): every outcome this run could not fully resolve
/// (any non-ok status, an ok mount with a failed inner read, or an ok-and-read-ok walk the cap
/// cut short) starts at attempt 1 -- the first pass itself is attempt 1, not attempt 0.
/// A profile the first pass did not try (`attempted` false) is seeded at 0: it is listed so it is
/// retried, but no attempt is charged for a mount that was never made.
[[nodiscard]] inline std::vector<PendingProfile>
initial_pending(const std::vector<ProfileHiveOutcome>& outcomes) {
    std::vector<PendingProfile> out;
    for (const auto& o : outcomes) {
        const bool resolved = o.attempted &&
                              (o.status == yuzu::profiles::HiveAccessStatus::ok) && o.read_ok &&
                              o.complete;
        if (!resolved)
            out.push_back(PendingProfile{o.sid, o.attempted ? 1 : 0});
    }
    return out;
}

/// Applies one retry run's outcomes to the pending state. `complete` is the OVERALL ProfileList
/// walk's completeness (profile_list_complete) for this run -- it governs ONLY the no-outcome
/// case below, never a per-profile one (a per-profile outcome's own `complete` field is a
/// separate fact, the kMapDriveHistoryCap cut, unrelated to whether the WALK reached every
/// profile).
///
/// Per pending entry, in order:
///  1. Already at max_attempts (a clamped or hand-edited persisted value): abandoned with token
///     "exhausted", whether or not this run has an outcome for it -- never re-acquired.
///  2. No matching outcome: `complete` true means the walk covered every profile and this one is
///     simply gone (vanished, dropped); `complete` false means the walk never reached it, so its
///     absence proves nothing (retained unchanged, cause "profile_list_incomplete").
///  3. An outcome with attempted == false (the mount was never tried this run: the shared ceiling
///     refused it, an earlier profile's mount timed out, the plugin could not be pinned, or an
///     earlier walk's abandoned worker is still running -- tokens mount_rejected,
///     skipped_after_timeout, skipped_after_rejection, pin_failed, prior_mount_still_running):
///     retained unchanged, no bump, cause = the outcome's token. It was not a failed attempt.
///  3a. ok + read_ok + complete: fully resolved, dropped silently (no longer pending).
///  4. ok + read_ok + !complete: the hive read fine, just not completely (cap-cut). That is a
///     real acquisition, so it counts like any other attempt -- bump, then abandon if the bump
///     reaches max_attempts, else retain at the bumped count. (Retaining it unchanged retried a
///     cap-cut profile forever, against the "total number of acquisitions" contract above.)
///  5. Anything else (a non-ok status, or ok with !read_ok): a real failed attempt -- bump, then
///     abandon (with this outcome's own token) if the bump reaches max_attempts, else retain at
///     the bumped count; either way logged in `failed` with the post-bump count.
[[nodiscard]] inline RetryResult
apply_outcomes(const PendingState& state, const std::vector<ProfileHiveOutcome>& outcomes,
               bool complete, int max_attempts = kMapDriveBackfillMaxAttempts) {
    RetryResult r;
    r.next.last_ts = state.last_ts;
    for (const auto& p : state.profiles) {
        if (p.attempts >= max_attempts) {
            r.abandoned.push_back(RetryAbandoned{p.sid, "exhausted"});
            continue;
        }
        const ProfileHiveOutcome* o = nullptr;
        for (const auto& cand : outcomes) {
            if (cand.sid == p.sid) {
                o = &cand;
                break;
            }
        }
        if (!o) {
            if (complete)
                r.vanished.push_back(p.sid);
            else {
                r.next.profiles.push_back(p);
                r.retained.push_back(RetryRetained{p.sid, "profile_list_incomplete"});
            }
            continue;
        }
        if (!o->attempted) {
            r.next.profiles.push_back(p); // never tried this run: not a failed attempt
            r.retained.push_back(RetryRetained{p.sid, o->token});
            continue;
        }
        const bool ok_status = (o->status == yuzu::profiles::HiveAccessStatus::ok);
        if (ok_status && o->read_ok && o->complete)
            continue; // fully resolved
        const int bumped = p.attempts + 1;
        if (bumped >= max_attempts)
            r.abandoned.push_back(RetryAbandoned{p.sid, o->token});
        else
            r.next.profiles.push_back(PendingProfile{p.sid, bumped});
        r.failed.push_back(RetryFailure{p.sid, bumped, o->token});
    }
    return r;
}

/// now - last_ts >= interval (or last_ts == 0, never tried).
[[nodiscard]] constexpr bool retry_due(std::int64_t now, std::int64_t last_ts,
                                       std::int64_t interval) {
    return last_ts == 0 || (now - last_ts) >= interval;
}

/// Commits the first pass's two tar_config keys in order: pending (skipped when the list is
/// empty -- nothing to persist), then done. `set` is `(std::string_view key, std::string_view
/// value) -> bool`; a failing pending write never writes done (short-circuit `&&`), so a crash or
/// store failure between the two is never observable as "done but nothing pending".
template <class Set>
[[nodiscard]] bool commit_first_pass(Set&& set, std::string_view pending_text,
                                     std::string_view done_text) {
    return (pending_text.empty() || set("mapdrive_backfill_pending", pending_text)) &&
           set("mapdrive_backfill_done", done_text);
}

} // namespace yuzu::tar
