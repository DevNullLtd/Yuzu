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
};

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

    SyncScheduler(std::string agent_id, KvGetFn kv_get, KvSetFn kv_set, SenderFn sender);

    void add_source(SyncSource src);

    /// Evaluate all sources at `now_secs`: collect + decide hash-skip-vs-full for
    /// each due source, send one RPC, persist state. Returns the number of
    /// seconds to sleep before the next pass (min time-to-next-due, clamped to
    /// [`kMinTickSeconds`, `kMaxTickSeconds`]).
    std::chrono::seconds tick(std::int64_t now_secs);

    /// Operator-triggered sync-on-demand (the `__sync__.now` reserved command).
    /// `source_or_all` is one source name or `kAllSources`. Thread-safe: it only
    /// touches the mutex-guarded pending list — never sources_/states_/kv/sender —
    /// so it may be called from a thread other than the one that ticks (the
    /// command read loop). Returns the source names that will be forced (empty =
    /// unknown name). Drained at the top of the next tick(): next_fire = now,
    /// force_full = true, needfull_streak = 0, persisted; that same tick then
    /// fires them. `add_source` must not be called after the ticking thread
    /// starts (sources_ is read here without the mutex — append-only before
    /// publication, as agent.cpp does).
    [[nodiscard]] std::vector<std::string> request_now(std::string_view source_or_all);

    /// Registered source names, in registration order (for the agent's error text).
    [[nodiscard]] std::vector<std::string> source_names() const;

    static constexpr std::string_view kAllSources{"all"};

    /// Hard floor: even with hash-skip, send a full payload at least this often
    /// (defense-in-depth against server cold-cache / agent hash bugs — ADR-0016 §4).
    static constexpr std::chrono::seconds kFullFloor{7 * 24 * 60 * 60};
    /// First-run / overdue catch-up is delayed by a stable per-(agent,source)
    /// offset in [0, this) so a mass-enroll / site power-on does not herd.
    static constexpr std::chrono::seconds kStartupJitterWindow{10 * 60};
    /// A server `need_full` resend is delayed by `kMinTickSeconds` + a stable
    /// per-(agent,source) offset in [0, this), so a mass cold-cache event (e.g. a
    /// server DB restore that nacks the whole fleet at once) does not stampede
    /// full payloads back simultaneously.
    static constexpr std::chrono::seconds kNeedFullJitterWindow{5 * 60};
    static constexpr std::chrono::seconds kMinTickSeconds{30};
    static constexpr std::chrono::seconds kMaxTickSeconds{15 * 60};

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
        bool loaded{false};
    };

    /// Apply every pending request_now() arm to its State (on the ticking thread).
    /// Returns the (validated, in-bounds) indices just armed — round-3 item 4:
    /// tick() sends each of these in its OWN immediate RPC (see apply_ack) so an
    /// operator-forced source is never queued behind an unrelated cadence-due
    /// source's collect() in the same tick.
    [[nodiscard]] std::vector<std::size_t> drain_pending(std::int64_t now_secs);

    std::string kv_key(const std::string& source, const char* field) const;
    State& load_state(std::size_t idx, std::int64_t now_secs);
    void save_state(const SyncSource& src, const State& st);
    /// Stable per-(agent,source) phase offset in [0, interval).
    std::int64_t phase_offset(const std::string& source, std::int64_t interval) const;
    /// Hash-skip decision for one source at `now_secs`, given its freshly
    /// collected `hash` — factored out of tick() so the forced-source (pass 1)
    /// and batched (pass 2) paths make the identical decision.
    bool decide_full(const State& st, const std::string& hash, std::int64_t now_secs) const;
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
    std::vector<SyncSource> sources_;
    std::vector<State> states_; // parallel to sources_

    // request_now() (any thread) -> drain_pending() (ticking thread). Indices into
    // sources_; deduplicated on insert. The ONLY cross-thread state in this class.
    std::mutex pending_mu_;
    std::vector<std::size_t> pending_;
};

} // namespace yuzu::agent
