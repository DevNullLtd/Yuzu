/**
 * test_ota_transfer_rules.cpp — the OTA chunk-write terminal-outcome decision
 * (issues #911 UP-101, #934, #941).
 *
 * WHAT THIS FILE EXISTS FOR. These branches — the per-chunk stall abort, and
 * which failures refund the peer's rate token — are the load-bearing half of the
 * slow-link lockout fix, and until the decision was hoisted into
 * `ota_transfer_rules.hpp` NO test could reach them: they sit inside
 * `DownloadUpdate`'s streaming loop, which needs a real package on disk, which
 * needs an `UpdateRegistry`, which needs a `PgPool`. A gate-1 review flagged
 * them as shipped-but-unproven. They are pure now, so every branch is reachable
 * here with no gRPC, no Postgres, no I/O and no clock.
 *
 * The handler's wiring of this decision is covered separately in
 * `test_ota_download_bound.cpp`; what is proven HERE is the decision itself.
 */

#include "ota_transfer_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using namespace std::chrono_literals;
using yuzu::server::ota::classify_write;
using yuzu::server::ota::deadline_phase;
using yuzu::server::ota::is_terminal;
using yuzu::server::ota::refund_reason;
using yuzu::server::ota::refunds;
using yuzu::server::ota::TransferOutcome;

namespace {
constexpr auto kChunkBudget = std::chrono::nanoseconds(30s);
} // namespace

// The decision is constexpr — evaluated here at COMPILE time, which is the
// strongest possible statement that it reads no clock, touches no I/O and has
// no hidden state. If someone later reaches for a syscall in here, this stops
// compiling rather than silently becoming impure.
static_assert(classify_write(true, false, 1s, kChunkBudget) == TransferOutcome::kContinue);
static_assert(classify_write(false, true, 0s, kChunkBudget) == TransferOutcome::kTransferDeadline);
static_assert(refunds(TransferOutcome::kChunkStalled));
static_assert(!refunds(TransferOutcome::kPeerDisconnected));

TEST_CASE("OTA write classify: a fast successful write continues the transfer",
          "[ota][rules]") {
    CHECK(classify_write(/*wrote=*/true, /*cancelled=*/false, 1s, kChunkBudget) ==
          TransferOutcome::kContinue);
    CHECK_FALSE(is_terminal(TransferOutcome::kContinue));
    CHECK_FALSE(refunds(TransferOutcome::kContinue));
}

TEST_CASE("OTA write classify: a failed write with no cancellation is the peer hanging up",
          "[ota][rules]") {
    const auto o = classify_write(/*wrote=*/false, /*cancelled=*/false, 0s, kChunkBudget);
    CHECK(o == TransferOutcome::kPeerDisconnected);
    CHECK(is_terminal(o));
    // The peer consumed capacity and then left; it is not the server's failure,
    // so no refund. This is the branch that keeps the bucket meaningful against
    // a peer that repeatedly opens and aborts transfers.
    CHECK_FALSE(refunds(o));
    CHECK(refund_reason(o) == nullptr);
    CHECK(deadline_phase(o) == nullptr);
}

TEST_CASE("OTA write classify: a failed write after our watchdog cancelled is our deadline",
          "[ota][rules]") {
    const auto o = classify_write(/*wrote=*/false, /*cancelled=*/true, 0s, kChunkBudget);
    CHECK(o == TransferOutcome::kTransferDeadline);
    CHECK(is_terminal(o));
    CHECK(refunds(o));
    CHECK(std::string(refund_reason(o)) == "transfer_deadline");
    CHECK(std::string(deadline_phase(o)) == "transfer");
}

TEST_CASE("OTA write classify: a slow but successful write aborts as a chunk stall",
          "[ota][rules]") {
    const auto o = classify_write(/*wrote=*/true, /*cancelled=*/false,
                                  std::chrono::nanoseconds(31s), kChunkBudget);
    CHECK(o == TransferOutcome::kChunkStalled);
    CHECK(is_terminal(o));
    // #934: a deadline the SERVER imposed must not be charged to the peer, or a
    // genuinely slow link spends itself into a lockout.
    CHECK(refunds(o));
    CHECK(std::string(refund_reason(o)) == "chunk_deadline");
    CHECK(std::string(deadline_phase(o)) == "write");
}

TEST_CASE("OTA write classify: exactly at the budget is not yet a stall", "[ota][rules]") {
    // Strictly greater-than, so a write that lands precisely on the budget is
    // allowed. A boundary flipped to >= would abort transfers on a link tuned
    // exactly to the operator's configured deadline.
    CHECK(classify_write(true, false, kChunkBudget, kChunkBudget) == TransferOutcome::kContinue);
    CHECK(classify_write(true, false, kChunkBudget + std::chrono::nanoseconds(1), kChunkBudget) ==
          TransferOutcome::kChunkStalled);
}

TEST_CASE("OTA write classify: the disconnect/deadline race biases toward refunding",
          "[ota][rules]") {
    // Both true: the peer went away at the same instant the watchdog cancelled.
    // The two are indistinguishable at the Write return value, so the tie has to
    // be broken by policy. It breaks toward the DEADLINE, i.e. toward refunding:
    // over-refunding costs at most one token on an already-stalled transfer,
    // whereas under-refunding is the lockout recorded on #934 and #941.
    const auto o = classify_write(/*wrote=*/false, /*cancelled=*/true,
                                  std::chrono::nanoseconds(99s), kChunkBudget);
    CHECK(o == TransferOutcome::kTransferDeadline);
    CHECK(refunds(o));
}

TEST_CASE("OTA write classify: a FAILED write is never reported as a stall", "[ota][rules]") {
    // Slow AND failed, with no cancellation. The per-chunk budget is only
    // consulted for a write that actually succeeded — a failed write is a
    // failure, not a stall. Reporting it as a stall would attribute the abort to
    // the wrong cause, emit phase="write" instead of the correct disconnect
    // accounting, and refund a peer that simply hung up.
    const auto o = classify_write(/*wrote=*/false, /*cancelled=*/false,
                                  std::chrono::nanoseconds(99s), kChunkBudget);
    CHECK(o == TransferOutcome::kPeerDisconnected);
    CHECK_FALSE(refunds(o));
}

TEST_CASE("OTA write classify: a non-positive budget disables the per-chunk check",
          "[ota][rules]") {
    // Lets an operator turn the chunk layer off without a separate flag; the
    // whole-transfer watchdog still bounds the call.
    CHECK(classify_write(true, false, std::chrono::nanoseconds(10'000s), 0s) ==
          TransferOutcome::kContinue);
    CHECK(classify_write(true, false, std::chrono::nanoseconds(10'000s), -1s) ==
          TransferOutcome::kContinue);
}

TEST_CASE("OTA write classify: refund and phase labels match the pre-seeded metric label sets",
          "[ota][rules]") {
    // These strings are the metric label VALUES pre-seeded in server.cpp. A
    // rename here without a matching pre-seed silently creates an un-seeded
    // series, which breaks absent()-based alerting.
    CHECK(std::string(refund_reason(TransferOutcome::kTransferDeadline)) == "transfer_deadline");
    CHECK(std::string(refund_reason(TransferOutcome::kChunkStalled)) == "chunk_deadline");
    CHECK(refund_reason(TransferOutcome::kContinue) == nullptr);
    CHECK(refund_reason(TransferOutcome::kPeerDisconnected) == nullptr);

    CHECK(std::string(deadline_phase(TransferOutcome::kTransferDeadline)) == "transfer");
    CHECK(std::string(deadline_phase(TransferOutcome::kChunkStalled)) == "write");
    CHECK(deadline_phase(TransferOutcome::kContinue) == nullptr);
    CHECK(deadline_phase(TransferOutcome::kPeerDisconnected) == nullptr);
}
