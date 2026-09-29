#pragma once

/// @file ota_transfer_rules.hpp
///
/// The terminal-outcome decision for one OTA `DownloadUpdate` chunk write
/// (issues #911, #934, #941), extracted as a PURE free function.
///
/// WHY THIS IS A SEPARATE HEADER. The decision it encodes — what a failed or
/// slow write MEANS, and whether the peer should be charged for it — is the
/// load-bearing half of the slow-link lockout fix, and inside the handler it was
/// unreachable by any test: exercising it needs a real package on disk, which
/// needs an `UpdateRegistry`, which needs a `PgPool`. Hoisting it here makes
/// every branch testable with no gRPC, no Postgres, and no I/O, leaving the
/// handler a thin caller. Same shape as `principal_quota_gate.hpp`'s
/// `apply_engine_quota_gate`, and it sits alongside the other server-side pure
/// decision headers (`body_cap_policy.hpp`, `network_perf_rules.hpp`,
/// `rbac_generation_rules.hpp`).
///
/// Deliberately free of gRPC types: the caller maps `TransferOutcome` onto a
/// `grpc::StatusCode`. That keeps this header compilable and testable off the
/// gRPC stack entirely, and keeps the wire vocabulary in one place at the call
/// site rather than smeared across a policy header.

#include <chrono>

namespace yuzu::server::ota {

/// What one chunk write turned out to mean.
enum class TransferOutcome {
    kContinue,         ///< wrote, and inside the per-chunk budget — keep streaming
    kPeerDisconnected, ///< write failed and the watchdog had NOT cancelled: the peer went away
    kTransferDeadline, ///< write failed because our watchdog cancelled the RPC
    kChunkStalled,     ///< write succeeded but took longer than the per-chunk budget
};

/// Classify one write.
///
/// ORDERING IS THE CONTRACT, not an implementation detail:
///
///  1. A failed write is examined FIRST, and `watchdog_cancelled` decides which
///     kind it was. At the `Write` return value a peer hanging up and our own
///     `TryCancel` are INDISTINGUISHABLE — only the watchdog knows.
///  2. When the peer disconnects at the same instant the watchdog fires, both
///     conditions are true and this deliberately reports `kTransferDeadline`,
///     i.e. it BIASES TOWARD REFUNDING. Over-refunding costs at most one token
///     on a genuinely stalled transfer; under-refunding is the failure mode that
///     locked agents out for hours on #934 and #941, so the tie is broken in the
///     direction whose worst case is benign.
///  3. Only a SUCCESSFUL write is tested against the per-chunk budget. A failed
///     write that also happened to be slow is a failure, not a stall — reporting
///     it as a stall would attribute the abort to the wrong cause and emit the
///     wrong metric phase.
///
/// A non-positive `chunk_deadline` disables the per-chunk check (never stalls),
/// so a caller can turn that layer off without a separate flag.
[[nodiscard]] constexpr TransferOutcome classify_write(bool wrote, bool watchdog_cancelled,
                                                       std::chrono::nanoseconds write_elapsed,
                                                       std::chrono::nanoseconds chunk_deadline) {
    if (!wrote)
        return watchdog_cancelled ? TransferOutcome::kTransferDeadline
                                  : TransferOutcome::kPeerDisconnected;
    if (chunk_deadline > std::chrono::nanoseconds::zero() && write_elapsed > chunk_deadline)
        return TransferOutcome::kChunkStalled;
    return TransferOutcome::kContinue;
}

/// Whether this outcome ends the transfer.
[[nodiscard]] constexpr bool is_terminal(TransferOutcome o) {
    return o != TransferOutcome::kContinue;
}

/// Whether the peer gets its rate token back.
///
/// The rule is "refund what the SERVER caused, charge what the PEER caused". A
/// deadline we imposed is ours; a peer that hung up is not — and a completed
/// transfer obviously is not, since the peer consumed the capacity the bucket
/// exists to meter.
[[nodiscard]] constexpr bool refunds(TransferOutcome o) {
    return o == TransferOutcome::kTransferDeadline || o == TransferOutcome::kChunkStalled;
}

/// Metric `reason` label for the refund counter, or nullptr when no refund is
/// due. Values match the pre-seeded label set in `server.cpp`.
[[nodiscard]] constexpr const char* refund_reason(TransferOutcome o) {
    switch (o) {
    case TransferOutcome::kTransferDeadline:
        return "transfer_deadline";
    case TransferOutcome::kChunkStalled:
        return "chunk_deadline";
    case TransferOutcome::kContinue:
    case TransferOutcome::kPeerDisconnected:
        return nullptr;
    }
    return nullptr;
}

/// Metric `phase` label for the deadline counter, or nullptr when this outcome
/// is not a deadline abort.
[[nodiscard]] constexpr const char* deadline_phase(TransferOutcome o) {
    switch (o) {
    case TransferOutcome::kTransferDeadline:
        return "transfer";
    case TransferOutcome::kChunkStalled:
        return "write";
    case TransferOutcome::kContinue:
    case TransferOutcome::kPeerDisconnected:
        return nullptr;
    }
    return nullptr;
}

} // namespace yuzu::server::ota
