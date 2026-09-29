#pragma once

/**
 * command_dedup_store.hpp -- Durable agent-side command idempotency + outcome replay
 *
 * HA delivery-matrix WS-0 (ADR-2002). Replaces the process-lifetime, in-memory
 * `dedup_current_`/`dedup_previous_` sets (cleared on every reconnect) with a
 * SQLite-backed store, file at {data_dir}/command_dedup.db, that survives an
 * agent restart AND remembers each command's TERMINAL outcome so a duplicate
 * replays the ORIGINAL result rather than a bare REJECTED.
 *
 * Why replay matters: the server's at-least-once delivery (and, later, the WS-1
 * transactional outbox) can redeliver a command whose first terminal ack was
 * lost. Without outcome replay the honest guarantee is only "effect-once,
 * result-maybe-lost": the side effect ran once, but the operator sees REJECTED
 * and the real SUCCESS/output is gone. This store closes that. It is
 * effectively-once, NOT exactly-once (ADR-2002 §Guarantees): a command claimed
 * but not yet resolved when the agent crashes is answered INDETERMINATE
 * (RUNNING) on redelivery and never silently re-executed — re-running a
 * destructive command is the one failure the whole HA design forbids.
 *
 * Durability: the store opens with `journal_mode=WAL` AND `synchronous=FULL`.
 * FULL (not the WAL default NORMAL) fsyncs each commit, so a claim/terminal
 * record survives a HOST failure (power-loss), not only a process crash — which
 * is the failure mode HA actually cares about. The write rate is one row per
 * command, not a hot path, so the fsync cost is negligible against command
 * latency.
 *
 * Lifecycle (one claim resolves exactly once):
 *   claim(id)  -> Claimed   : first sighting; the caller owns the in-flight
 *                             record and MUST resolve it via record_terminal()
 *                             (executed to a terminal outcome) or release()
 *                             (never executed — e.g. the dispatch queue was
 *                             full, a transient condition that must re-attempt).
 *              -> Duplicate : already known — the caller must NOT execute. If
 *                             Terminal, replay `response`; if InFlight, answer
 *                             RUNNING (indeterminate).
 *              -> Error     : store write failed; the caller proceeds WITHOUT
 *                             dedup for this one command — a DELIBERATE fail-OPEN
 *                             to availability (ADR-2002): the chosen degradation
 *                             is at-least-once (a redelivery may re-execute)
 *                             rather than refusing the command and dropping the
 *                             endpoint out of remote-control reach. Fail-open is a
 *                             POLICY CHOICE, not a necessity (the old in-memory
 *                             sets needed no disk); a per-instruction-class fail-
 *                             closed option is a tracked follow-up. This is
 *                             degraded, not wrong, and the caller MUST make it
 *                             OBSERVABLE (a counter/tag), never silent.
 *
 * Retention is a clock-free rowid ring over TERMINAL rows only (keep the most
 * recent kMaxDedupRows). Deliberately NOT a wall-clock delete, so it sidesteps
 * the clock-guarded-retention hazard (routed concern #2360/#2361) entirely on an
 * endpoint whose clock the user controls; `claimed_at` is diagnostic ONLY and
 * MUST NEVER become a retention cutoff. IN-FLIGHT rows are NEVER evicted by the
 * ring: a live command's claim can never be pruned out from under its still-
 * running worker (the double-execution that would otherwise occur under high
 * volume). The only cost is that a crashed-mid-execution in-flight row (response
 * is NULL, so ~tens of bytes) persists until the agent is reinstalled; bounding
 * that with a stale-in-flight reconciliation is a tracked follow-up, not a
 * slice-1 concern (crash-looping is the larger problem, and the rows are tiny).
 *
 * Thread-safe: a std::mutex serialises every sqlite3* operation. The reader
 * thread calls claim()/release() and the bounded dispatch-pool workers call
 * record_terminal() concurrently; the DB is the synchronisation point.
 * claim()/record_terminal()/release() are noexcept: a store failure degrades
 * durability, it never propagates into the command hot path.
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

struct sqlite3; // Forward declaration — avoids exposing sqlite3.h in the header

namespace yuzu::agent {

struct CommandDedupError {
    std::string message;
};

/// Durable state of a known command_id.
enum class DedupState {
    InFlight, ///< claimed, not yet resolved (executing now, or crashed mid-execution)
    Terminal, ///< reached a terminal outcome; `response` holds the replayable frame
};

/// Outcome of claim().
enum class ClaimStatus {
    Claimed,   ///< first sighting; caller owns the in-flight record and must resolve it
    Duplicate, ///< already known; see `state` (+ `response` when Terminal)
    Error,     ///< store write failed; caller proceeds WITHOUT dedup for this command
};

/// Outcome of record_terminal() — lets the caller observe the "0 rows updated"
/// case, which is the signal that a re-execution is about to be permitted
/// (the row was evicted or never claimed) and must be counted, not swallowed.
enum class RecordOutcome {
    Recorded, ///< an in-flight row was flipped to terminal (the normal path)
    Miss,     ///< no in-flight row matched (evicted, never claimed, or already terminal)
    Error,    ///< store write failed
};

/// Outcome of release() — a failed DELETE leaks a claim (the command answers
/// RUNNING to every redelivery, never re-runs), so it MUST be observable, not a
/// void that swallows the error (invariant 1).
enum class ReleaseOutcome {
    Released, ///< the in-flight row was deleted (or was already gone)
    Error,    ///< store write failed — the claim may be leaked; count it
};

struct ClaimResult {
    ClaimStatus status = ClaimStatus::Error;
    DedupState state = DedupState::InFlight; ///< meaningful only when status==Duplicate
    /// Serialized terminal CommandResponse (CommandResponse::SerializeAsString()); populated
    /// only when status==Duplicate && state==Terminal. Bytes are exact (blob column), so an
    /// embedded NUL in the proto survives. Default member initializer so a designated-init
    /// that omits it does not warn (-Wmissing-field-initializers, warning_level=3).
    std::string response{};
};

class YUZU_EXPORT CommandDedupStore {
public:
    /**
     * Open (or create) the store at the given path. Sets WAL + synchronous=FULL
     * + busy_timeout=5000 and creates the schema if absent. Fails only on an
     * unusable path/DB — the caller treats a failure as "durable dedup
     * unavailable" and runs degraded (fail-open), which it MUST surface.
     */
    static std::expected<CommandDedupStore, CommandDedupError>
    open(const std::filesystem::path& db_path);

    ~CommandDedupStore();

    CommandDedupStore(CommandDedupStore&& other) noexcept;
    CommandDedupStore& operator=(CommandDedupStore&& other) noexcept;

    CommandDedupStore(const CommandDedupStore&) = delete;
    CommandDedupStore& operator=(const CommandDedupStore&) = delete;

    /**
     * Atomically claim `command_id` for first-time execution. On Claimed the
     * caller owns the in-flight record; on Duplicate the caller replays/answers
     * per `state`. An empty id or a closed store returns Error (proceed without
     * dedup). noexcept: never throws into the command path.
     */
    ClaimResult claim(std::string_view command_id) noexcept;

    /**
     * Flip a claimed in-flight record to its terminal outcome so a later
     * duplicate replays `serialized_response` (= CommandResponse::SerializeAsString()).
     * FIRST-WRITE-WINS: only an in-flight row is flipped, so a second terminal
     * (e.g. a spurious post-terminal throw) is a Miss, never an overwrite. A Miss
     * means the terminal matched no in-flight row — the command ran
     * undeduplicated (its claim had failed, fail-open) OR this is a duplicate
     * terminal. It is NOT a measure of the eviction-driven double-execute: an
     * outcome aged out of the ring produces a fresh Claimed on redelivery, not a
     * Miss, so that path is not separately detectable here (it is bounded by
     * kMaxDedupRows exceeding the server's retry horizon, not observed). Best-
     * effort + noexcept: a failure only degrades durability. Miss on an empty id /
     * closed store returns Miss / Error respectively.
     */
    RecordOutcome record_terminal(std::string_view command_id,
                                  std::string_view serialized_response) noexcept;

    /**
     * Drop a claimed in-flight record that produced NO memoizable outcome (the
     * dispatch queue was full — transient), so a redelivery can be executed.
     * Only deletes a still-in-flight row — never a terminal one. Returns Error
     * on a store-write failure so the caller can count a possibly-leaked claim
     * (invariant 1); noexcept. Released on an empty id / closed store (nothing to
     * leak), Error only on an actual failed DELETE.
     */
    ReleaseOutcome release(std::string_view command_id) noexcept;

    /** Row count (TEST/observability). nullopt on error/closed store. */
    [[nodiscard]] std::optional<std::int64_t> count() const;

    /**
     * TEST-ONLY: lower the terminal-ring bound so retention tests exercise the
     * real prune path without driving kMaxDedupRows (20000) fsync'd commits.
     * Production never calls this; the default is kMaxDedupRows. Clamped to >= 1
     * (a non-positive bound would make the ring's LIMIT delete everything).
     */
    void set_max_dedup_rows_for_test(std::int64_t n);

    /**
     * The most recent kMaxDedupRows TERMINAL commands are retained; older
     * terminal rows are evicted by rowid (insert order), never by clock, never
     * touching in-flight rows. Exceeding this between a command's execution and a
     * possible redelivery is what would let a duplicate re-execute, so it MUST
     * stay well above the server's max retry/outbox horizon (WS-1/WS-3).
     * Substrate-tuned; do not copy the number elsewhere.
     */
    static constexpr std::int64_t kMaxDedupRows = 20000;

    /**
     * Prune cadence: prune after this many claims, so eviction is O(rows)
     * amortised rather than per-claim. Bounds terminal rows at kMaxDedupRows +
     * kPruneInterval. Public so tests can assert the bound without hardcoding it.
     */
    static constexpr std::uint64_t kPruneInterval = 512;

private:
    explicit CommandDedupStore(sqlite3* db);

    /// Clock-free ring eviction over TERMINAL rows only. Caller holds mu_.
    void prune_locked() noexcept;

    sqlite3* db_{nullptr};
    mutable std::mutex mu_;
    /// Prune is triggered from record_terminal() (a worker thread), NOT claim()
    /// (the latency-critical reader): the ring evicts TERMINAL rows, which only
    /// record_terminal creates, and this keeps the reader off the prune DELETE.
    std::uint64_t records_since_prune_{0};
    std::int64_t max_dedup_rows_{kMaxDedupRows}; ///< effective ring bound (test-lowerable)
};

} // namespace yuzu::agent
