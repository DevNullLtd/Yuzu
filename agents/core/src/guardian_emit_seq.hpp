#pragma once

// Guardian emit-order stamp (UP-14).
//
// The event timestamp is the agent wall clock, so after a backward clock step an older
// compliant event can carry a later stamp than a newer errored one; the server's census
// ordering key then may hold or flag the pair, but cannot reliably order it. The remedy is an
// agent-assigned ordinal drawn where QUEUE ORDER IS DECIDED, carried on the wire as the
// pair (boot_epoch, emit_seq); a server that compares it orders lexicographically, one
// that does not ignores it and keeps ordering by the census ordering key.
//
// GuardianEmitSeqSource is that ordinal. One instance is owned (by shared_ptr) by the
// GuardianEngine and handed to every producer that decides queue order, so the legacy
// sink executor and the Spark runtime draw from ONE sequence. It is shared by shared_ptr
// rather than by pointer to an engine member because the runtime and the executor's
// detached worker can outlive the engine's stack frame.
//
// draw() is 1-based (0 is the "unset" wire value) and strictly increasing across threads.
// Relaxed ordering is sufficient: the value is an ordinal identity, not a publication
// edge, and every caller that needs the order to match its queue order draws under the
// lock that decides that queue order. A caller that draws and then refuses the event
// simply leaves a gap; consumers compare, they never assume consecutive values.
//
// boot_epoch is fixed at construction. 0 means the epoch could not be claimed (see
// guardian_boot_epoch.hpp); a source with boot_epoch 0 still draws, so internal ordering
// keys keep working, but stamp_emit_pair() puts NOTHING on the wire for it.
//
// Pure and I/O-free.

#include "guaranteed_state.pb.h" // ::yuzu::guardian::v1::GuaranteedStateEvent

#include <atomic>
#include <cstdint>

namespace yuzu::agent {

struct GuardianEmitSeqSource {
    explicit GuardianEmitSeqSource(std::uint64_t epoch) noexcept : boot_epoch(epoch) {}

    GuardianEmitSeqSource(const GuardianEmitSeqSource&) = delete;
    GuardianEmitSeqSource& operator=(const GuardianEmitSeqSource&) = delete;

    /// 1-based, strictly increasing across threads. Never returns 0 in practice: it wraps to
    /// 0 after 2^64 draws, which is unreachable. The stated per-boot limit is 2^62 draws,
    /// because the epoch ceiling is 2^62 (guardian_boot_epoch.hpp).
    [[nodiscard]] std::uint64_t draw() noexcept {
        return last.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    const std::uint64_t boot_epoch;
    std::atomic<std::uint64_t> last{0};
};

static_assert(std::atomic<std::uint64_t>::is_always_lock_free,
              "draw() is called under admission locks and must never take a hidden lock");

/// Stamp the ordering pair on a wire event. The pair is both-or-neither: it is written
/// only when BOTH `boot_epoch` and `seq` are nonzero; otherwise both fields are left
/// untouched at their unset value 0, so a pair-comparing server falls back to the
/// census ordering key instead of ordering on half a pair.
inline void stamp_emit_pair(::yuzu::guardian::v1::GuaranteedStateEvent& ev,
                            std::uint64_t boot_epoch, std::uint64_t seq) noexcept {
    if (boot_epoch == 0 || seq == 0)
        return;
    ev.set_boot_epoch(boot_epoch);
    ev.set_emit_seq(seq);
}

} // namespace yuzu::agent
