#pragma once

/**
 * echo.db corruption audit gate (#1567).
 *
 * Agents report `yuzu.plugin.echo.db_corruption_total` / `db_quarantine_last`
 * heartbeat tags. AgentHealthStore SURFACES a candidate on every heartbeat whose tags
 * parse (valid tag pair); the gate provides the dedup: ONE map entry per agent
 * (agent_id -> last known quarantine identity + time of the last row this
 * process wrote), bounded by kMaxAgents (one entry is evicted at the cap, never a
 * wholesale clear: the first whose rate-limit window has already elapsed, so an
 * agent still inside its window keeps its limit; an arbitrary entry only when every
 * entry is still inside its window), and, on a miss, ONE lookup of the newest
 * `echo.db.corruption_quarantined` audit row for the agent. Net effect: exactly
 * one audit row per (agent, quarantine identity) across store prunes, server
 * restarts and HA node switches (per server process: another HA node ingesting
 * the same agent can add a second row for the same identity); a failed write is
 * retried after the degraded window, and a candidate skipped because that
 * agent's lookup was already in flight, or because the in-flight set was at its
 * bound, is retried on the next heartbeat (the pair is only marked once the row
 * is durable).
 *
 * The identity is agent-asserted and only shape-validated, so the gate also
 * bounds a rotating identity: at most one row per agent per
 * kEchoCorruptionAuditMinRowInterval seconds PER SERVER PROCESS (in-memory; a
 * restart or another HA node opens a fresh window). Intermediate quarantines
 * inside one window collapse to the newest identity, which persists in the
 * agent's `last` tag and logs on the first heartbeat after the window. Once a
 * lookup or write has failed, no lookup runs until
 * kEchoCorruptionAuditDegradedRetry seconds have passed (gate-wide: a failing
 * store is a store property). Three failures open the window: a lookup that answers
 * "degraded", a lookup that THROWS (so a throwing store is not retried on every
 * heartbeat; the exception still propagates to the caller), and a failed audit
 * write. The window is dated from the failure, not from admission (a lookup that
 * blocked for a minute and then threw still opens a full window), and it only ever
 * extends: a late completion never shortens a window a newer failure opened. There
 * is no separate half-open probe: the probes that follow a window are at most
 * kMaxInFlight (below), which is already a bound, and the first one to fail that
 * is not a remembered agent (next paragraph) re-opens the window.
 *
 * One exception bounds the blast radius of agents whose own lookup or write keeps
 * failing. The gate remembers each agent whose last lookup or write failed, up to
 * kMaxFailing (16) of them, until that agent succeeds (its row is written, or its
 * lookup finds the row durable). A failure by a remembered agent opens no gate-wide
 * window: only that agent waits out its own window, dated from its failure. So an
 * agent that fails every time pauses every agent once, on its first failure (which
 * cannot be told from a store fault), and not again while it is remembered, however
 * many other agents fail in between. A failure by an agent that is not remembered
 * opens the window as above, so a real store outage still closes the gate. Two
 * limits follow from the bound. More than kMaxFailing agents failing with none of
 * them succeeding cannot be told from a store fault: at the cap the remembered agent
 * whose wait ends earliest is forgotten to make room, a forgotten agent's next
 * failure opens the window again, and with that many failing the gate behaves as it
 * did before it remembered anyone (healthy agents are audited only between windows;
 * their rows are delayed, not lost). And while the store really is failing, each
 * remembered agent still tries once per retry period, so a failing store sees up to
 * kMaxFailing such lookups per period beside those that follow a window (never more
 * than kMaxInFlight at once). An entry has no time limit: an agent that stops
 * reporting stays remembered until the cap forgets it. Every failure, a contained
 * one included, is reported to the optional DegradedFn observer (after the lock is
 * released), so a gate that fails is not silent.
 *
 * Reservation contract: a true from should_log() reserves that AGENT's
 * in-flight slot (a set of agent ids, bounded by kMaxInFlight: at the bound a
 * new agent is refused, never an in-flight entry evicted); the caller completes
 * it with exactly one of mark_logged() (row durable) or mark_failed(agent_id)
 * (write failed) -- or, more safely, via the nested Reservation RAII type, whose
 * destructor completes an abandoned reservation as failed() so a throw between
 * the reservation and the write cannot strand the slot, and whose logged() and
 * failed() are idempotent (the first completion wins). While an agent's slot
 * is held every other should_log() for THAT agent returns false (retried on a
 * later heartbeat); other agents are admitted, so a burst of distinct agents
 * (a mass quarantine) is not serialised to one row per heartbeat (#5033).
 * Concurrency is bounded by kMaxInFlight (4): the lookup and the write run
 * synchronously on the calling thread, each holding one lease of the shared
 * PostgreSQL pool (default 16, --postgres-pool-size), so the gate holds at most
 * four leases however many ingest threads race a mass quarantine; the rest are
 * refused and retried on their next heartbeat. A pool-exhaustion failure is a
 * lookup or write failure like any other, so it opens the window.
 *
 * Durability choice, stated for a future third case: this gate round-trips
 * the audit store itself so dedup survives a restart/HA switch, unlike the
 * sibling rotation_warn_dedup.hpp, which is deliberately process-local and
 * treats a restart-forfeits-state re-emission as correct, not merely
 * tolerable. The difference is scale and risk shape (fleet-agent cardinality
 * + an agent-asserted, rotating identity here vs. a small fixed rotation-pair
 * set there) -- pick per-case, don't copy whichever file you find first.
 *
 * A throw between a true should_log() and its completion is turned into
 * mark_failed(agent_id), which itself takes a lock and reads the injected clock.
 * Inside ~Reservation an exceedingly rare failure there (OS mutex-resource
 * exhaustion, or an injected clock that throws, which the production steady clock
 * never does) terminates the process rather than silently stranding the slot; on
 * the direct mark_failed(), logged() and failed() calls and the lookup-catch paths
 * it would propagate (a mutex failure would also strand that agent's slot until
 * restart). Not producible on the supported platforms.
 *
 * The lookup and the write are synchronous audit-store calls on the heartbeat
 * ingest thread, outside AgentHealthStore's mutex. Once the row is durable the
 * map answers with a hash lookup. If candidates ever become frequent this must
 * move to a queue.
 *
 * Pure: the audit-store query and the clock are injected.
 */

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server::detail {

/// Heartbeat tags produced by the agent's plugin bridge for the echo plugin's
/// `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last` KV keys.
inline constexpr const char* kEchoTagCorruptionTotal = "yuzu.plugin.echo.db_corruption_total";
inline constexpr const char* kEchoTagQuarantineLast = "yuzu.plugin.echo.db_quarantine_last";

/// Audit-row verb and target type for an echo.db quarantine (documented in
/// docs/user-manual/audit-log.md). Shared by the dedup query and the emit.
inline constexpr const char* kEchoCorruptionAuditAction = "echo.db.corruption_quarantined";
inline constexpr const char* kEchoCorruptionAuditTargetType = "Agent";

/// Minimum seconds between two rows for one agent (bounds a rotating,
/// agent-asserted identity to 144 rows/day/agent).
inline constexpr int64_t kEchoCorruptionAuditMinRowInterval = 600;
/// While the audit store answers "degraded", skip lookups for this long.
inline constexpr int64_t kEchoCorruptionAuditDegradedRetry = 60;

/// Parse `yuzu.plugin.echo.db_corruption_total`: digits only, <= 18 chars, > 0.
/// Also the shape rule for the #5332 sync-skip gauge (agent_registry.cpp recompute_metrics):
/// keep digits-only / > 0 if this changes.
[[nodiscard]] inline std::optional<int64_t> parse_echo_corruption_total(std::string_view raw) noexcept {
    if (raw.empty() || raw.size() > 18)
        return std::nullopt;
    int64_t v = 0;
    for (char c : raw) {
        if (c < '0' || c > '9')
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    if (v <= 0)
        return std::nullopt;
    return v;
}

/// `<epoch>:<basename>` as published by the agent: 1-18 digits, one ':', then a
/// 1-60 char basename from [A-Za-z0-9._-] (the real name is
/// echo.db.corrupt-<epoch>[-<n>]); no path separators; total <= 80.
[[nodiscard]] inline bool valid_echo_quarantine_last(std::string_view q) noexcept {
    if (q.empty() || q.size() > 80)
        return false;
    const auto colon = q.find(':');
    if (colon == std::string_view::npos || colon < 1 || colon > 18)
        return false;
    for (std::size_t i = 0; i < colon; ++i)
        if (q[i] < '0' || q[i] > '9')
            return false;
    const auto base = q.substr(colon + 1);
    if (base.empty() || base.size() > 60)
        return false;
    for (char c : base) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/// Audit-row detail contract shared by the server sink (encode) and the
/// durable-dedup lookup (decode).
[[nodiscard]] inline std::string encode_echo_corruption_detail(int64_t total,
                                                              std::string_view quarantine) {
    return "corruption_total=" + std::to_string(total) + " quarantine=" + std::string(quarantine);
}

[[nodiscard]] inline std::optional<std::string>
decode_echo_quarantine_from_detail(std::string_view detail) {
    constexpr std::string_view kKey = "quarantine=";
    const auto pos = detail.find(kKey);
    if (pos == std::string_view::npos)
        return std::nullopt;
    return std::string(detail.substr(pos + kKey.size()));
}

/// Why the gate recorded a failure (closed set; the token is a metric label). Each one opens
/// the degraded window, except a failure by an agent the gate already remembers as failing,
/// which only that agent waits out.
enum class DegradedCause : uint8_t { lookup_degraded, lookup_threw, write_failed };

[[nodiscard]] inline const char* echo_corruption_degraded_cause_token(DegradedCause c) noexcept {
    switch (c) {
    case DegradedCause::lookup_degraded:
        return "lookup_degraded";
    case DegradedCause::lookup_threw:
        return "lookup_threw";
    case DegradedCause::write_failed:
        return "write_failed";
    }
    return "unknown";
}

class EchoCorruptionAuditGate {
public:
    /// Newest logged quarantine identity for the agent. Outer nullopt = the
    /// audit store is degraded/unqueryable; inner nullopt = no prior row.
    using LatestFn =
        std::function<std::optional<std::optional<std::string>>(const std::string& agent_id)>;
    using NowFn = std::function<int64_t()>;
    /// Observer called on every lookup or write failure, a contained repeat included (which
    /// opens no gate-wide window). Runs on the calling thread after the gate's lock is
    /// released; an exception from it is swallowed.
    using DegradedFn = std::function<void(DegradedCause)>;

    /// Most agents that may hold a lookup/write slot at once. The lookup and the write run on
    /// the ingest thread with one lease of the shared PostgreSQL pool each, so this bounds the
    /// leases the gate can take from the pool; an agent refused here is retried next heartbeat.
    static constexpr std::size_t kMaxInFlight = 4;
    /// Bound on the per-agent identity map (one entry is evicted at the cap).
    static constexpr std::size_t kMaxAgents = 65536;
    /// Most failing agents remembered at once: a remembered agent's failure opens no gate-wide
    /// window. At the cap the one whose wait ends earliest is forgotten. It is also the most
    /// contained lookups a failing store sees per retry period.
    static constexpr std::size_t kMaxFailing = 16;

    /// The production clock (the default NowFn): monotonic seconds.
    static int64_t steady_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    explicit EchoCorruptionAuditGate(LatestFn latest, NowFn now_s = &steady_seconds,
                                     DegradedFn on_degraded = {})
        : latest_(std::move(latest)), now_s_(std::move(now_s)),
          on_degraded_(std::move(on_degraded)) {}

    /// True iff a new audit row should be written for (agent, quarantine).
    /// A true return holds the agent's in-flight slot: complete it with mark_logged or mark_failed.
    [[nodiscard]] bool should_log(const std::string& agent_id, const std::string& quarantine) {
        const auto now = now_s_();
        {
            std::lock_guard lock(mu_);
            if (now < degraded_until_)
                return false; // degraded store: no lookup until the window ends
            if (const auto it = failing_.find(agent_id); it != failing_.end() && now < it->second)
                return false; // this agent failed on its last try: it alone waits out its window
            if (in_flight_.contains(agent_id))
                return false; // this agent's lookup is in flight; retried next heartbeat
            if (const auto it = agents_.find(agent_id); it != agents_.end()) {
                if (it->second.identity == quarantine)
                    return false; // already durable
                if (it->second.last_row_at &&
                    now - *it->second.last_row_at < kEchoCorruptionAuditMinRowInterval)
                    return false; // rotating identity: rate-limited, retried later
            }
            if (in_flight_.size() >= kMaxInFlight)
                return false; // bounded: refuse, never evict an in-flight entry
            // The only allocation on the admit path. Inside the lock and before the slot
            // counts as held: a throw here leaves nothing inserted (strong guarantee).
            in_flight_.insert(agent_id);
        }
        std::optional<std::optional<std::string>> latest;
        try {
            latest = latest_(agent_id); // outside mu_: a store round-trip
        } catch (...) {
            // Date the window from the failure, not from admission: the lookup may have
            // blocked for a long time before it threw. If the clock itself throws, fall back
            // to the entry time so the lookup's own exception is the one that propagates.
            int64_t failed_at = now;
            try {
                failed_at = now_s_();
            } catch (...) {
            }
            {
                std::lock_guard lock(mu_); // never strand the slot on a throwing lookup
                in_flight_.erase(agent_id);
                note_failure_locked(agent_id, failed_at);
            }
            notify_degraded(DegradedCause::lookup_threw);
            throw;
        }
        std::unique_lock lock(mu_);
        if (!latest) {
            in_flight_.erase(agent_id);
            note_failure_locked(agent_id, now_s_());
            lock.unlock();
            notify_degraded(DegradedCause::lookup_degraded);
            return false; // no write, not marked -> retried after the window
        }
        if (*latest && **latest == quarantine) {
            in_flight_.erase(agent_id);
            remember_locked(agent_id, quarantine, now, false); // durable (prior run / other node)
            return false;
        }
        return true; // slot stays held for the caller's write
    }

    /// RAII completion token for a should_log() that returned true. Construct
    /// one immediately after the true return, then complete it with exactly
    /// one of logged() (row durable) or failed() (write failed). If neither
    /// runs — including a throw unwinding through the reservation's scope —
    /// the destructor completes it as failed(), so an exception between the
    /// reservation and the write can never strand the agent's in-flight slot (which
    /// would otherwise wedge should_log() false for that agent forever). The
    /// first completion wins: a second logged()/failed() is a no-op, and a
    /// completion that throws is not retried by the destructor.
    ///
    /// Lifetime rule: `agent_id` is referenced, not copied (the constructor stays
    /// noexcept and non-allocating), so it must outlive the Reservation. At the one
    /// production site (the server.cpp corruption sink) it is the sink lambda's
    /// parameter, which outlives the scoped reservation. A non-const rvalue (a string
    /// literal, a std::string&&) is rejected at compile time (the deleted rvalue
    /// overload below); a const prvalue would still bind the const-lvalue overload,
    /// so the lifetime rule is the caller's to keep.
    class Reservation {
    public:
        Reservation(EchoCorruptionAuditGate& gate, const std::string& agent_id) noexcept
            : gate_(&gate), agent_(&agent_id) {}
        Reservation(EchoCorruptionAuditGate&, std::string&&) = delete;
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&&) = delete;
        Reservation& operator=(Reservation&&) = delete;
        ~Reservation() {
            if (auto* gate = std::exchange(gate_, nullptr))
                gate->mark_failed(*agent_);
        }
        void logged(const std::string& quarantine) {
            if (auto* gate = std::exchange(gate_, nullptr))
                gate->mark_logged(*agent_, quarantine);
        }
        void failed() {
            if (auto* gate = std::exchange(gate_, nullptr))
                gate->mark_failed(*agent_);
        }

    private:
        EchoCorruptionAuditGate* gate_;
        const std::string* agent_;
    };

    void mark_logged(const std::string& agent_id, const std::string& quarantine) {
        std::lock_guard lock(mu_);
        in_flight_.erase(agent_id); // released first: a throwing clock still frees the slot
        remember_locked(agent_id, quarantine, now_s_(), true);
    }

    /// The caller's audit write failed: release the agent's slot and record the failure: the
    /// (gate-wide: a failing store is a store property) degraded window opens, unless the gate
    /// already remembers this agent as failing, when only it waits.
    void mark_failed(const std::string& agent_id) {
        {
            std::lock_guard lock(mu_);
            in_flight_.erase(agent_id);
            note_failure_locked(agent_id, now_s_());
        }
        notify_degraded(DegradedCause::write_failed);
    }

private:
    struct Entry {
        std::string identity;
        std::optional<int64_t> last_row_at; // set only for rows this process wrote
    };
    /// The one place a failure is recorded. A failure by a remembered agent (failing_) only extends
    /// that agent's own wait; any other opens the gate-wide window and is remembered. max(): a late
    /// completion stamped earlier than a newer failure never shortens the wait that failure set.
    void note_failure_locked(const std::string& agent_id, int64_t at) noexcept {
        const int64_t until = at + kEchoCorruptionAuditDegradedRetry;
        if (const auto it = failing_.find(agent_id); it != failing_.end()) {
            it->second = std::max(it->second, until);
            return;
        }
        degraded_until_ = std::max(degraded_until_, until);
        try {
            // ponytail: kMaxFailing remembered agents, O(kMaxFailing) scan under mu_ at the cap
            // only. More agents than that failing at once re-open the window whenever a forgotten
            // one fails (the behaviour before the table); raising the cap is the upgrade if that is
            // ever seen, at the price of more lookups against a store that really is failing.
            if (failing_.size() >= kMaxFailing)
                failing_.erase(std::min_element(
                    failing_.begin(), failing_.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; }));
            failing_.emplace(agent_id, until);
        } catch (...) {
            // An allocation failure leaves the agent unremembered; the window is already open.
        }
    }
    void notify_degraded(DegradedCause cause) noexcept {
        if (!on_degraded_)
            return;
        try {
            on_degraded_(cause);
        } catch (...) {
        }
    }
    /// `wrote_row`: this process wrote the row (starts the rate-limit window at `now`); false
    /// when the identity was only found durable by the lookup (no window).
    void remember_locked(const std::string& agent_id, const std::string& quarantine, int64_t now,
                         bool wrote_row) {
        failing_.erase(agent_id); // a success forgets it: its next failure opens the window again
        if (agents_.size() >= kMaxAgents && !agents_.contains(agent_id)) {
            // Prefer an entry whose rate-limit window has elapsed (or that never had one), so
            // an agent still inside its window keeps its limit; fall back to the first entry
            // only when every entry is inside its window. The lookup backs an evicted entry.
            // ponytail: O(n) scan under mu_, at the cap only; an LRU list if the cap is hit
            // routinely.
            auto victim = agents_.begin();
            for (auto it = agents_.begin(); it != agents_.end(); ++it) {
                const auto& at = it->second.last_row_at;
                if (!at || now - *at >= kEchoCorruptionAuditMinRowInterval) {
                    victim = it;
                    break;
                }
            }
            agents_.erase(victim);
        }
        agents_[agent_id] = Entry{quarantine, wrote_row ? std::optional<int64_t>{now} : std::nullopt};
    }
    LatestFn latest_;
    NowFn now_s_;
    DegradedFn on_degraded_;
    std::mutex mu_;
    std::unordered_map<std::string, Entry> agents_;
    int64_t degraded_until_{0};
    // Agents whose last lookup or write failed (each until it succeeds), with the end of each
    // one's own wait. Bounded by kMaxFailing.
    std::unordered_map<std::string, int64_t> failing_;
    // Agents holding a true should_log() that is awaiting mark_logged / mark_failed.
    std::unordered_set<std::string> in_flight_;
};

/// The corruption sink's whole decision in one pure place (#7486): admit via the gate, write,
/// complete the reservation. `write` returns true iff the audit row is durable. Returns true
/// iff a row was written, i.e. once per (agent, quarantine identity) this process records, so
/// a caller counting quarantines counts exactly the rows. A refusal (rate limit, durable
/// lookup hit, degraded window, cap) and a failed write return false. A throw from `write`
/// completes the reservation as failed and propagates.
template <typename WriteFn>
[[nodiscard]] bool log_echo_corruption_once(EchoCorruptionAuditGate& gate,
                                            const std::string& agent_id,
                                            const std::string& quarantine, WriteFn&& write) {
    if (!gate.should_log(agent_id, quarantine))
        return false;
    EchoCorruptionAuditGate::Reservation res(gate, agent_id);
    if (!write()) {
        res.failed();
        return false;
    }
    res.logged(quarantine);
    return true;
}

} // namespace yuzu::server::detail
