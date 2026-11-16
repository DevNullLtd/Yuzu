#pragma once

/// @file sync_scheduler.hpp
/// Agent-side daily-sync framework (ADR-0016). Drives per-source periodic
/// pushes of endpoint state to the server over `ReportInventory`, kind to the
/// network: a source that hasn't changed since its last successful sync sends
/// only its content hash, not the full payload (hash-skip).
///
/// The scheduler is deliberately free of gRPC and SQLite dependencies — the RPC
/// (`SenderFn`), the persistent `__sync__` KV state (`KvGetFn`/`KvSetFn`), and
/// the current time are all injected, so it unit-tests without a network or a
/// real KvStore. The owning thread in `agent.cpp` wires those to the real
/// channel/stub + `kv_store_`.

#include <yuzu/plugin.h> // YUZU_EXPORT (agent-core DLL export macro)

#include "plugin_heartbeat_tags.hpp" // kPluginHeartbeatMaxValueBytes (heartbeat tag value bound)
#include "sync_window.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// One synced data source (e.g. `installed_software`). The cadence is a
/// compile-time constant per source (ADR-0016 §3 — operator-tunable cadence is a
/// follow-on).
struct SyncSource {
    std::string name;              ///< data-type key, also the `plugin_data`/`content_hashes` key
    std::chrono::seconds interval; ///< per-source cadence

    /// Collect the current full payload. Returns the canonical wire blob and its
    /// content hash (`hash == SHA-256 hex of blob`), or `std::nullopt` to skip
    /// this cycle (collect failed / source unavailable — e.g. the backing plugin
    /// isn't loaded). Must produce the SAME canonical bytes the server expects
    /// (ADR-0016 §4) so the server-recomputed hash matches this one.
    std::function<std::optional<std::pair<std::string, std::string>>()> collect;

    /// Why the most recent collect() returned nullopt — a bounded token the
    /// scheduler persists as sync.<name>.last_skip; sources that cannot classify
    /// leave it unset. No in-tree source sets it at present, and emit_sync_skip_tags
    /// publishes the skip tags only with a reason, so none are published.
    std::function<std::string()> skip_reason;

    /// Retry a skipped cycle on the bounded phase-aligned backoff
    /// (SyncScheduler::kSkipRetryBase) instead of one full interval; opt in ONLY
    /// when a re-run is a handful of in-process dispatches — device_ci dispatches
    /// up to fifteen actions and software_licensing runs license_scan.list before
    /// it can skip (sync_source_device_ci.cpp, sync_source_software_licensing.cpp),
    /// so they stay off.
    bool skip_backoff{false};

    /// Maintenance window in machine-local time. When set, every successful sync
    /// and every skip-ladder cap lands at the agent's stable moment inside the
    /// window (next_window_fire) instead of the next phase slot of `interval`.
    /// Unset (the default) keeps the interval/phase-slot cadence unchanged. A
    /// compile-time default per source: no settings channel pushes it yet.
    std::optional<SyncWindow> window;

    /// Exempt this source from the weekly forced full (kFullFloor). Only for a source whose
    /// payload heals divergence by itself, section by section: installed_software (blob v3)
    /// names the facets it holds in its report hash, and the server refuses a delta over a base
    /// that no longer matches (`installed_software:<facet>` nack -> that facet is resent in
    /// full), so a weekly blanket resend of every facet would only add load. A force, a
    /// whole-source nack and a never-acknowledged hash still send full (decide_full).
    bool no_full_floor{false};

    /// A source that keeps its own per-section state (installed_software, blob v3) is told when
    /// the scheduler is about to send FULL regardless of what it collects: the operator forced
    /// the source (request_now), the server nacked the whole source (force_full), or the weekly
    /// floor is due (never for a no_full_floor source). Called on the ticking thread immediately
    /// BEFORE collect(), in both tick passes, so a forced send always carries a full payload.
    /// A never-acknowledged hash does NOT call it: the blob still goes (decide_full), and a
    /// section the source holds no acknowledged set for is full by the source's own rule, so a
    /// per-section nack in that window cannot re-force the sections already acknowledged.
    /// Unset for every other source.
    std::function<void()> on_force_full;

    /// OR-ed into the full decision after the hash comparison: true when the payload this
    /// source just collected must reach the server even though its content hash did not move
    /// (a section whose status or token changed). A source that returns true MUST have put
    /// something the server can parse in the blob. Unset = the hash alone decides.
    std::function<bool()> wants_blob;

    /// The acknowledgement of one report that carried this source: the `need_full` tokens that
    /// name it (the source name itself, or `<name>:<detail>`), empty on a clean acknowledgement.
    /// Called on the ticking thread BEFORE the scheduler persists its own state, on both the
    /// clean and the nacked branch. Unset = nothing to commit.
    std::function<void(const std::vector<std::string>&)> on_ack;

    /// True when the last collect() deliberately left part of the payload for the next one
    /// (a first contact split over several calls). A clean acknowledgement then re-fires the
    /// source after kMinTickSeconds instead of at its next regular slot. Unset = false.
    std::function<bool()> has_more;
};

/// Sanitise a skip reason for the KV / heartbeat tag: keep [A-Za-z0-9_.:=,-],
/// replace any other byte with '_', truncate to kPluginHeartbeatMaxValueBytes
/// (64) bytes.
YUZU_EXPORT std::string sanitize_skip_reason(std::string_view reason);

/// True for a non-empty run of ASCII digits, at most `max_len` long, with a value above zero
/// (leading zeros allowed). Gates every KV counter that is published as a heartbeat tag.
inline bool positive_digits(std::string_view s, std::size_t max_len) {
    return s.size() <= max_len && s.find_first_not_of("0123456789") == std::string_view::npos &&
           s.find_first_not_of('0') != std::string_view::npos;
}

/// The installed_software `__sync__` KV field holding the completeness-unknown count: written by
/// the collector, read by emit_sync_completeness_unknown_tag.
inline constexpr char kCompletenessUnknownTotalKey[] = "completeness_unknown_total";

class YUZU_EXPORT SyncScheduler {
public:
    /// Performs one `ReportInventory` RPC. `hashes` is sent for every due source
    /// (always); `blobs` carries the full payload only for sources sending full.
    /// Returns the `ack.need_full` source names on success, or `std::nullopt` on
    /// RPC failure (the scheduler then does not advance state — retry next pass).
    using SenderFn = std::function<std::optional<std::vector<std::string>>(
        const std::vector<std::pair<std::string, std::string>>& hashes,
        const std::vector<std::pair<std::string, std::string>>& blobs)>;

    /// `__sync__` KV accessors. `kv_get` returns "" when the key is absent.
    using KvGetFn = std::function<std::string(const std::string& key)>;
    using KvSetFn = std::function<void(const std::string& key, const std::string& value)>;

    /// `clock` converts epoch seconds to and from local civil time for windowed
    /// sources; tests inject a fake zone, production uses the C library's.
    SyncScheduler(std::string agent_id, KvGetFn kv_get, KvSetFn kv_set, SenderFn sender,
                  LocalClock clock = system_local_clock());

    void add_source(SyncSource src);

    /// Evaluate all sources at `now_secs`: collect + decide hash-skip-vs-full for
    /// each due source, send one RPC, persist state. Returns the number of
    /// seconds to sleep before the next pass (min time-to-next-due, clamped to
    /// [`kMinTickSeconds`, `kMaxTickSeconds`]).
    std::chrono::seconds tick(std::int64_t now_secs);

    /// Operator-triggered sync-on-demand (the `__sync__.now` reserved command).
    /// `sources_csv_or_all` is `kAllSources`, one source name, or a comma-separated
    /// list of names; all-or-nothing — any unknown name arms nothing and returns
    /// empty. Thread-safe: it only touches the mutex-guarded pending list — never
    /// sources_/states_/kv/sender — so it may be called from a thread other than
    /// the one that ticks (the command read loop). Returns the source names that
    /// will be forced, in registration order. Drained at the top of the next
    /// tick(). With `delay_max` zero: next_fire = now, force_full = true,
    /// needfull_streak = 0, persisted, and that same tick fires them. With
    /// `delay_max` > 0 the same state is armed but next_fire = now + a stable
    /// per-(agent,source) offset in [0, delay_max), or the fire already armed sooner,
    /// whichever is earlier, and the batch pass fires the source once that is due, so a
    /// fleet-wide click does not stampede the server. A source requested twice keeps
    /// the smaller delay. `add_source` must not be
    /// called after the ticking thread starts (sources_ is read here without the
    /// mutex — append-only before publication, as agent.cpp does).
    [[nodiscard]] std::vector<std::string>
    request_now(std::string_view sources_csv_or_all,
                std::chrono::seconds delay_max = std::chrono::seconds{0});

    /// Registered source names, in registration order (for the agent's error text, and
    /// the heartbeat thread's emit_sync_skip_tags). Like request_now(), safe from another
    /// thread only because sources_ is append-only and complete before the scheduler is
    /// published (agent.cpp).
    [[nodiscard]] std::vector<std::string> source_names() const;

    static constexpr std::string_view kAllSources{"all"};

    /// Hard floor: even with hash-skip, send a full payload at least this often
    /// (defense-in-depth against server cold-cache / agent hash bugs — ADR-0016 §4), except
    /// for a source that sets SyncSource::no_full_floor. A
    /// windowed source fires at a local-time moment, so across a spring-forward the 7th
    /// day's fire is an hour short of this floor and the full send lands on the 8th.
    static constexpr std::chrono::seconds kFullFloor{7 * 24 * 60 * 60};
    /// First-run catch-up is delayed by a stable per-(agent,source) offset in
    /// [0, this) so a mass-enroll / site power-on does not herd.
    static constexpr std::chrono::seconds kStartupJitterWindow{10 * 60};
    /// Catch-up (a persisted next_fire more than kMaxTickSeconds in the past: the agent
    /// was off, the machine slept, or the server was unreachable for longer than that and
    /// the failed send left the state unadvanced; or more than two days in the future: a
    /// clock stepped back, or a corrupt value) is re-armed over [0, this) from now by a
    /// stable per-(agent,source) offset, so a Monday-morning power-on, or the server
    /// coming back after an outage, is gentle.
    static constexpr std::chrono::seconds kCatchUpWindow{30 * 60};
    /// A server `need_full` resend is delayed by `kMinTickSeconds` + a stable
    /// per-(agent,source) offset in [0, this), so a mass cold-cache event (e.g. a
    /// server DB restore that nacks the whole fleet at once) does not stampede
    /// full payloads back simultaneously.
    static constexpr std::chrono::seconds kNeedFullJitterWindow{5 * 60};
    static constexpr std::chrono::seconds kMinTickSeconds{30};
    static constexpr std::chrono::seconds kMaxTickSeconds{15 * 60};
    /// Skip backoff (opt-in per source, SyncSource::skip_backoff): the retry delay is
    /// kSkipRetryBase << (streak - 1), capped at the next phase slot, while
    /// streak <= kSkipRetryBudget; afterwards one attempt per slot. The cap gives an
    /// outage at most four retries that are not themselves slot attempts; whether the
    /// fifth delay (16 h) is capped depends on where in the day the streak started.
    /// Operator-facing wording: docs/user-manual/inventory.md.
    static constexpr std::chrono::seconds kSkipRetryBase{60 * 60};
    static constexpr int kSkipRetryBudget{5};

    /// KV key for a source's persisted field (`sync.<source>.<field>`); public so
    /// the heartbeat emitter reads the same keys the scheduler writes.
    static std::string kv_key(const std::string& source, const char* field);

private:
    struct State {
        std::int64_t next_fire{0};      ///< epoch s of the next scheduled sync
        std::int64_t last_full{0};      ///< epoch s of the last FULL payload sent — advances
                                        ///< only on a full send, NOT on a hash-only kTouched
                                        ///< cycle; the sentinel for kFullFloor (don't "reset
                                        ///< on touch" or the weekly-full guarantee breaks)
        std::string last_hash;          ///< last successfully-synced content hash
        bool force_full{false};         ///< server asked for a resend (need_full)
        int needfull_streak{0};         ///< consecutive need_full nacks (backoff, UP-5)
        int skip_streak{0};             ///< consecutive batch-path skips since the last successful
                                        ///< collect — NOT capped (the backoff exponent is bounded
                                        ///< by kSkipRetryBudget; the count is the diagnostic)
        std::string last_skip;          ///< sanitised SyncSource::skip_reason of the last skip
        bool loaded{false};
    };

    /// Apply every pending request_now() arm to its State (on the ticking thread).
    /// Returns the (validated, in-bounds) indices armed for an IMMEDIATE fire — round-3 item 4:
    /// tick() sends each of these in its OWN immediate RPC (see apply_ack) so an
    /// operator-forced source is never queued behind an unrelated cadence-due
    /// source's collect() in the same tick.
    [[nodiscard]] std::vector<std::size_t> drain_pending(std::int64_t now_secs);

    State& load_state(std::size_t idx, std::int64_t now_secs);
    void save_state(const SyncSource& src, const State& st);
    /// Record one skipped (nullopt) batch-path collect: bumps skip_streak, stores the
    /// sanitised skip_reason and picks the next fire per skip_backoff. Not called on the
    /// forced path — drain_pending left next_fire = now, so the batch pass re-collects
    /// next tick and records the skip once (one click never spends two budget slots).
    void note_skip(std::size_t idx, std::int64_t now_secs);
    /// A collect succeeded: clear skip state and persist BEFORE the send, so an RPC
    /// failure never leaves a stale reason.
    void note_collected(std::size_t idx);
    /// Stable per-(agent,source) phase offset in [0, interval).
    std::int64_t phase_offset(const std::string& source, std::int64_t interval) const;
    /// The next regular fire after `now_secs`: the source's window placement when it
    /// has one, else the next phase-aligned slot of its interval.
    std::int64_t next_due(std::size_t idx, std::int64_t now_secs) const;
    /// Re-arm a LOADED source whose next_fire is more than kMaxTickSeconds in the
    /// past (a live agent never is: it wakes at least every clamped sleep) OR more than
    /// two days in the future (no interval plus window reaches that) to now + a stable
    /// offset in [0, kCatchUpWindow), and persist it. last_hash and force_full are
    /// left untouched.
    void catch_up_if_overdue(std::size_t idx, std::int64_t now_secs);
    /// The blanket part of the full decision that does not depend on the collected hash: an
    /// operator force or a whole-source nack, or the weekly floor. Computed BEFORE collect() so a
    /// source can be told (SyncSource::on_force_full) and therefore produces a full payload for
    /// every one of these. decide_full also sends the blob when no hash has ever been
    /// acknowledged, which is not part of this blanket (see the definition).
    bool forced_full_due(std::size_t idx, const State& st, std::int64_t now_secs) const;
    /// Hash-skip decision for one source at `now_secs`, given its freshly
    /// collected `hash` — factored out of tick() so the forced-source (pass 1)
    /// and batched (pass 2) paths make the identical decision.
    bool decide_full(std::size_t idx, const State& st, const std::string& hash,
                     std::int64_t now_secs) const;
    /// Apply one source's ReportInventory outcome (a name lookup against the
    /// ack's need_full list) to its persisted State — the exact success/nack
    /// state-transition tick() ran inline before this factor-out, now shared by
    /// both the per-forced-source immediate send (pass 1) and the batched
    /// cadence-due send (pass 2) so they can never drift on the backoff/jitter
    /// math. `need_full` is the SenderFn's return value for the RPC that just
    /// carried this source — a caller only invokes this when that RPC actually
    /// succeeded (returned a value); an RPC failure is handled by the caller
    /// leaving the source's persisted state untouched so it retries next tick.
    void apply_ack(std::size_t idx, const std::string& hash, bool sent_full,
                   const std::vector<std::string>& need_full, std::int64_t now_secs);

    std::string agent_id_;
    KvGetFn kv_get_;
    KvSetFn kv_set_;
    SenderFn sender_;
    LocalClock clock_;
    std::vector<SyncSource> sources_;
    std::vector<State> states_; // parallel to sources_

    // request_now() (any thread) -> drain_pending() (ticking thread). {index into
    // sources_, delay_max seconds}; deduplicated on index on insert, keeping the
    // smaller delay. The ONLY cross-thread state in this class.
    std::mutex pending_mu_;
    std::vector<std::pair<std::size_t, std::int64_t>> pending_;
};

/// Publish the persisted skip state of each source as heartbeat tags
/// `yuzu.sync.<source>.skip_streak` / `.last_skip`. Reads the `__sync__` KV (the
/// cross-thread seam; never the scheduler's in-memory state, which belongs to the
/// ticking thread). Emits nothing for a source unless the streak is 1-6 ASCII
/// digits with value > 0 AND a non-empty reason that is already in sanitised form
/// (sanitize_skip_reason: at most kPluginHeartbeatMaxValueBytes (64) bytes of
/// [A-Za-z0-9_.:=,-]) exists — a stored value that is not (corruption, a hand edit)
/// is never put on the wire.
/// This tag, not a monotonic counter, is the "equivalent heartbeat tag" for the
/// skip-visibility requirement (#5327); no protobuf field is added (#1567).
template <typename TagMap>
void emit_sync_skip_tags(TagMap& tags, const std::vector<std::string>& sources,
                         const std::function<std::optional<std::string>(const std::string& key)>&
                             get_fn) {
    for (const auto& name : sources) {
        const auto streak = get_fn(SyncScheduler::kv_key(name, "skip_streak"));
        const auto reason = get_fn(SyncScheduler::kv_key(name, "last_skip"));
        if (!streak || !reason || reason->empty() || sanitize_skip_reason(*reason) != *reason)
            continue;
        if (!positive_digits(*streak, 6))
            continue;
        tags["yuzu.sync." + name + ".skip_streak"] = *streak;
        tags["yuzu.sync." + name + ".last_skip"] = *reason;
    }
}

/// Publish the installed_software collector's count of answers that declared no completeness
/// as the heartbeat tag `yuzu.sync.installed_software.completeness_unknown_total`, read from the
/// `__sync__` KV the collector persists it in. Emitted only for a positive value of at most nine
/// ASCII digits; no protobuf field is added (#1567), the same pattern as emit_sync_skip_tags.
template <typename TagMap>
void emit_sync_completeness_unknown_tag(
    TagMap& tags,
    const std::function<std::optional<std::string>(const std::string& key)>& get_fn) {
    const auto total =
        get_fn(SyncScheduler::kv_key("installed_software", kCompletenessUnknownTotalKey));
    if (total && positive_digits(*total, 9))
        tags["yuzu.sync.installed_software.completeness_unknown_total"] = *total;
}

} // namespace yuzu::agent
