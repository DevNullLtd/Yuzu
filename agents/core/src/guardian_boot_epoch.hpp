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
// a null store, a read error, a write failure, and a clock term at or above the ceiling.
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
// SINGLE-WRITER ASSUMPTION. The claim is a plain read followed by a plain set(). It
// assumes ONE agent process uses the KV file at a time. Nothing in the agent enforces
// this: there is no instance lock, pidfile or data-directory mutex, and the KV file is in
// WAL mode, which admits a second process. Each service manager starts one instance per
// unit, but a manual run against the same --data-dir is not excluded. Two processes that
// both read N would both claim N + 1 and draw emit_seq from 1, so their events carry equal
// epochs and overlapping sequences that the server cannot tell apart. Accepted (the UP-14
// residual-acceptance ruling) and recorded with the documented residual below; this
// module adds no second mechanism.
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

#include <cstdint>
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
        ReadFailed,  ///< get_entry failed; epoch 0, nothing written
        WriteFailed, ///< set() failed; epoch 0
        OutOfRange,  ///< clock term at or above the ceiling; epoch 0, nothing written
    };

    std::uint64_t boot_epoch = 0; ///< 0 means unordered (any outcome except Claimed/Recovered)
    Outcome outcome = Outcome::NoStore;
    std::uint64_t persisted = 0; ///< the parsed stored value; 0 when absent or unusable
};

/// Claim this boot's epoch. `now_unix_s` is the wall clock in whole seconds; a value
/// <= 0 contributes 0 to the clock term. Never throws; logs one structured line.
[[nodiscard]] YUZU_EXPORT GuardianBootEpochClaim
claim_guardian_boot_epoch(IJournalStore* store, std::int64_t now_unix_s) noexcept;

} // namespace yuzu::agent
