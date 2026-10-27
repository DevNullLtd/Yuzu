#pragma once

// Guardian boot-epoch claim (UP-14).
//
// boot_epoch is the high half of the (boot_epoch, emit_seq) event-order pair
// (guardian_emit_seq.hpp). emit_seq restarts at 1 every process, so the server can only
// order events ACROSS restarts if boot_epoch strictly increases from one boot to the
// next (given an intact row; see the DOCUMENTED RESIDUAL below; at the 2^62 ceiling the
// next boot re-claims from the clock). It is claimed once at agent boot, before the
// GuardianEngine is built, and passed to the engine as a constructor argument so the
// engine stays I/O-free.
//
// The value is the HYBRID  max(persisted + 1, clock):
//   * persisted + 1  - the floor. It makes the epoch strictly increase across restarts
//                      even when the wall clock steps backward between boots.
//   * clock          - boot_unix_s. It makes a lost, wiped or stale KV row recover to a
//                      value that is almost certainly ahead of every earlier epoch, so
//                      the floor is a floor and not the only defence.
// Both terms are needed: the counter alone restarts at 1 after a wipe (below every
// prior epoch), and the clock alone is not strictly increasing across two boots in one
// second or after a backward clock step.
//
// FAILURE RULES. A claim that cannot be made durably is 0 ("unordered"), and nothing is
// invented in memory: an in-memory epoch would not be persisted, so the next boot would
// repeat it. Epoch 0 makes the engine emit the pair as 0/0, which a pair-comparing
// server treats as unordered and orders by the timestamp key instead. 0 is returned for:
// a null store, a read error (including an unreadable synchronous pragma), a write failure,
// a clock term at or above the ceiling, a store that REPORTS a durability level below FULL
// (see below), and, for the three-argument overload, an instance lock this process does not
// hold (see SINGLE-WRITER GUARD).
//
// DURABILITY. The epoch write must be durable, or the next boot could re-issue an equal or
// lower epoch for events already emitted under this one. Below FULL (PRAGMA synchronous OFF
// or NORMAL; NORMAL in WAL can lose a committed transaction on power loss) SQLite gives no
// such guarantee, so before writing the claim reads IJournalStore::pragma_synchronous() and
// refuses (Outcome::DurabilityBelowFull, epoch 0, nothing written) when it reports 0 or 1.
// 2 (FULL) and 3 (EXTRA) proceed. -1 means the store could not read the pragma; that is a
// failed read, not a durability fact, so it is Outcome::ReadFailed, as is a pragma read that
// throws. "Durable" here means durable at the level SQLite reports: on macOS an fsync does
// not flush the drive cache unless PRAGMA fullfsync is on, which is outside this check.
// KvStore::open sets synchronous=FULL explicitly and reads it back, so the shipped store does
// not rely on SQLite's compile-time default and DurabilityBelowFull is effectively unreachable
// for it. It is a defensive safeguard that fires if a store reports a level below FULL (a
// different IJournalStore implementation or a test double). If it ever appears in the log,
// treat it as a defect and report it; there is no agent-side setting for it.
//
// A stored value that is present but unusable (unparseable, trailing bytes, embedded
// NUL, out of range, at or above the ceiling, or one whose successor would reach the
// ceiling) carries no more information than a wiped row, so it is RE-CLAIMED as
// max(1, clock) and overwritten (Outcome::Recovered, error-level log) rather than left
// to degrade every later boot to epoch 0.
//
// CEILING. Every epoch is strictly below 2^62. The persisted value is checked against
// the ceiling BEFORE any "+ 1", so the arithmetic can never wrap: a persisted value of
// 2^62 - 1 or more is unusable (its successor would reach the ceiling), so 2^62 - 1 is
// the last epoch that can be claimed from a persisted value.
//
// SINGLE-WRITER GUARD. The claim is a plain read followed by a plain set(), so two processes
// that both read N would both claim N + 1 and draw emit_seq from 1: equal epochs and
// overlapping sequences that the server cannot tell apart (UP-9). The KV file is in WAL mode,
// which admits a second process, so the store alone does not exclude one. The agent therefore
// takes an exclusive, non-blocking advisory lock on `<data_dir>/guardian_boot_epoch.lock`
// (GuardianInstanceLock below) and passes it to the three-argument claim overload, which
// refuses (Outcome::InstanceLockNotHeld, epoch 0, nothing read or written) unless this
// process holds it. The loser keeps running with epoch 0, so its events are unordered (0/0)
// rather than colliding with the holder's. The lock is held for the life of the process and
// the kernel drops it at exit, so a crash leaves no stale lock; acquisition retries for a
// short bounded time so a service restart that overlaps the old process's shutdown still
// claims. Limits: it excludes only processes that run this code (an older agent binary
// sharing the data directory does not take it, so a mixed-version pair is still unguarded);
// a file system that does not support the lock reports the claim as unordered (epoch 0)
// rather than guessing; and the lock guards the epoch claim only, not the rest of the data
// directory (the identity and command-dedup stores have never been exclusive).
//
// DOCUMENTED RESIDUAL. If the KV row is wiped AND the agent restarts within the same
// wall-clock second as the previous boot, the new epoch equals the previous one (both
// are that second). The server cannot see this as a regression. Accepted: closing it
// needs a sub-second clock term, which changes the epoch's definition. Two further
// consequences of the same hybrid: a clock wrongly AHEAD at boot pins the epoch ahead and
// does not self-heal (the claim tracks the persisted value, not the clock), and a lost or
// corrupt row after such a pin re-claims from the clock and can land BELOW epochs already
// issued. A VM memory-snapshot revert continues with the same epoch and a lower emit_seq
// and involves no boot, so no claim runs.
//
// COUNTER EXHAUSTION. A single boot drawing 2^62 emit_seq values is not supported.
//
// The store is BORROWED for the duration of the call and nothing is retained.

#include <yuzu/agent/kv_store.hpp> // IJournalStore
#include <yuzu/plugin.h>           // YUZU_EXPORT

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string_view>

namespace yuzu::agent {

/// KV namespace and key holding the persisted epoch, decimal text. The namespace is the
/// Guardian's own; the key follows the "meta:" convention of meta:policy_generation.
inline constexpr std::string_view kGuardianBootEpochNamespace = "__guardian__";
inline constexpr std::string_view kGuardianBootEpochKey = "meta:boot_epoch";

/// Every claimed epoch is strictly below this.
inline constexpr std::uint64_t kGuardianBootEpochCeiling = std::uint64_t{1} << 62;

struct GuardianBootEpochClaim {
    enum class Outcome {
        Claimed,     ///< persisted (or absent) value read; new epoch written and returned
        Recovered,   ///< persisted value unusable; re-claimed as max(1, clock) and overwritten
        NoStore,     ///< null store; epoch 0, nothing written
        ReadFailed,  ///< get_entry or the synchronous pragma read failed; epoch 0, nothing written
        WriteFailed, ///< set() failed; epoch 0
        OutOfRange,  ///< clock term at or above the ceiling; epoch 0, nothing written
        DurabilityBelowFull, ///< store reports synchronous 0 or 1; epoch 0, nothing written
        InstanceLockNotHeld, ///< another process holds the data-dir lock (or it could not be
                             ///< taken); epoch 0, nothing read or written
    };

    std::uint64_t boot_epoch = 0; ///< 0 means unordered (any outcome except Claimed/Recovered)
    Outcome outcome = Outcome::NoStore;
    std::uint64_t persisted = 0; ///< the parsed stored value; 0 when absent or unusable
};

/// Process-lifetime exclusive advisory lock on a file, the single-writer guard for the boot
/// epoch claim (see SINGLE-WRITER GUARD above). Move-only RAII: the handle is closed, and the
/// lock dropped, on destruction. POSIX uses flock(LOCK_EX | LOCK_NB) on an O_CLOEXEC
/// descriptor, so a spawned plugin never inherits and outlives it; Windows opens the file with
/// share mode 0. Never throws. The handle is stored as an integer so the header carries no
/// platform type.
class YUZU_EXPORT GuardianInstanceLock {
public:
    enum class State {
        NotAcquired, ///< default-constructed; no attempt made
        Held,        ///< this object holds the lock
        Contended,   ///< another holder (a second agent process, or another object) has it
        Failed,      ///< the lock file could not be opened or locked for another reason
    };

    GuardianInstanceLock() noexcept = default;
    GuardianInstanceLock(const GuardianInstanceLock&) = delete;
    GuardianInstanceLock& operator=(const GuardianInstanceLock&) = delete;
    GuardianInstanceLock(GuardianInstanceLock&& other) noexcept;
    GuardianInstanceLock& operator=(GuardianInstanceLock&& other) noexcept;
    ~GuardianInstanceLock();

    /// Take the lock at `path`, creating the file if needed. When it is Contended, retry
    /// every 100 ms until `wait` has elapsed (0 = a single attempt). Never throws.
    [[nodiscard]] static GuardianInstanceLock
    acquire(const std::filesystem::path& path,
            std::chrono::milliseconds wait = std::chrono::milliseconds{0}) noexcept;

    [[nodiscard]] State state() const noexcept { return state_; }
    [[nodiscard]] bool held() const noexcept { return state_ == State::Held; }

private:
    void release() noexcept;

    std::intptr_t handle_ = -1; ///< POSIX fd or Windows HANDLE; -1 = none
    State state_ = State::NotAcquired;
};

/// Claim this boot's epoch. `now_unix_s` is the wall clock in whole seconds; a value
/// <= 0 contributes 0 to the clock term. Never throws; logs one structured line.
[[nodiscard]] YUZU_EXPORT GuardianBootEpochClaim
claim_guardian_boot_epoch(IJournalStore* store, std::int64_t now_unix_s) noexcept;

/// Production form: as above, but refuses (InstanceLockNotHeld, epoch 0, the store is not
/// touched) unless `lock.held()`. A null store is NoStore regardless of the lock.
[[nodiscard]] YUZU_EXPORT GuardianBootEpochClaim claim_guardian_boot_epoch(
    IJournalStore* store, std::int64_t now_unix_s, const GuardianInstanceLock& lock) noexcept;

} // namespace yuzu::agent
