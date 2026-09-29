#pragma once

/**
 * guardian_rule_eval.hpp - the per-type Guardian rule evaluators for the spark
 * consumer (ADR-0021 Stage 2 rung 2).
 *
 * Each evaluator takes a rule's proto-free assertion, a tri-state live-state
 * READ (Known snapshot | Unknown read-error), and the rule's mutable eval
 * state, and returns an EvalOutcome the runtime acts on:
 *
 *   - Emit      -> a GuardDrift (a compliant edge OR a drift) to publish, packed
 *                  with the legacy detected/expected token vocabulary so
 *                  GuardianEngine::emit_guard_event produces the SAME wire event
 *                  as the legacy guards (the parity gate).
 *   - Silent    -> steady compliant / debounce-suppressed drift: nothing to emit.
 *   - Unhealthy -> the read was Unknown (could not determine live state). The
 *                  evaluator leaves EmitDeciderState UNTOUCHED - it does NOT turn
 *                  "can't tell" into a false compliant/drift - and hands back the
 *                  read-error detail. Emitting guard.unhealthy (edge-triggered +
 *                  rate-limited) and mapping status -> errored is the runtime's
 *                  job (a later rung); here we only refuse to commit a verdict.
 *
 * Unknown is distinct from a legitimately-absent target (a missing file / deleted
 * service is a Known snapshot that drifts). It is reserved for "could not tell":
 * a transient I/O error, or a file that mutated during hashing past the reader's
 * bounded retry. On recovery (the first Known read after an Unknown), the
 * evaluator FORCES a real verdict even when the value equals its pre-error value,
 * so the server re-learns compliance after an errored gap (see `pack`).
 *
 * Proto-free (operates on RuleAssertion, extracted from the rule at arm time by
 * GuardianEngine) and platform-agnostic (the platform I/O that produces the read
 * lives in the StateReader seam, not here), so every branch is unit-tested
 * off-platform against synthetic reads.
 */

#include <yuzu/guardian_file_hash_limits.hpp> // kMaxFileHashBytes, clamp_max_hash_bytes (#2233 item 6)
#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/guard.hpp> // GuardDrift
#include <yuzu/agent/spark.hpp> // ServiceRunState

#include "guardian_emit_decider.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

namespace yuzu::agent {

/// The rule's desired-state check, proto-free (GuardianEngine extracts it from the
/// GuaranteedStateRule at arm time so the consumer never sees the proto).
enum class AssertionKind {
    FileExists,     ///< file-exists: presence vs expect_present
    FileHashEquals, ///< file-hash-equals: SHA-256 vs expected_hash (empty = baseline-on-arm)
    RegistryEquals, ///< registry-value-equals: value vs expected_value
    ServiceRunning, ///< service-running: desired Running
    ServiceStopped, ///< service-stopped: desired Stopped
};

/// The guard_type wire token ("file" | "registry" | "service") for an assertion kind.
/// Health and Lifecycle events derive guard_type from the assertion this way; the
/// Compliance path carries it inside GuardDrift instead. Matches the "registry" |
/// "file" | "service" vocabulary GuardDrift::guard_type uses.
[[nodiscard]] constexpr const char* guard_type_for(AssertionKind k) noexcept {
    switch (k) {
    case AssertionKind::FileExists:
    case AssertionKind::FileHashEquals:
        return "file";
    case AssertionKind::RegistryEquals:
        return "registry";
    case AssertionKind::ServiceRunning:
    case AssertionKind::ServiceStopped:
        return "service";
    }
    return "unknown";
}

struct RuleAssertion {
    AssertionKind kind{AssertionKind::FileExists};
    std::string rule_id;
    std::string rule_name;
    std::uint64_t debounce_ms{1000};
    // file-exists
    bool expect_present{true};
    // file-hash-equals
    std::string expected_hash;                     ///< lowercase hex SHA-256; empty = baseline-on-arm
    std::uint64_t max_bytes{64ull * 1024 * 1024};  ///< hash-DoS cap; size over it -> "<oversize>" for THIS
                                                   ///< rule (legacy default 64 MiB). oversize is projected
                                                   ///< per-rule because one key-relative snapshot serves
                                                   ///< rules with different caps. 0 => everything oversize;
                                                   ///< the arm-time construction site normalises 0 -> default
                                                   ///< (matching legacy), so the evaluator stays a pure
                                                   ///< function of its inputs.
    // registry-value-equals
    std::string expected_value;
    std::string value_name;  ///< the registry value the reader reads + memoises per key across rules that
                             ///< watch the same value_name; NOT part of the compliance verdict here.
};

/// #2233 item 6: hard ceiling on an AUTHORED max_bytes, applied (after the existing
/// 0->default normalisation above) on both the spark (guardian_spark_bridge.hpp) and
/// legacy (guardian_engine.cpp) file-hash-equals arm paths, AND at authoring time on
/// the server (guardian_rule_spec.cpp) - single-sourced in
/// common/include/yuzu/guardian_file_hash_limits.hpp so none of the three can drift
/// apart on the ceiling the way independent hand-rolled clamps would (this repo's
/// established pattern for exactly this class of bug; see #3388's jitter fix for
/// precedent). Re-exported into yuzu::agent here so existing agent-side call sites
/// stay unqualified.
using yuzu::guardian::clamp_max_hash_bytes;
using yuzu::guardian::kMaxFileHashBytes;

/// Intrinsic file state read once per spark_key from a single owned handle (the
/// #807 handle-scoped read, a later rung). Compliance is key-relative EXCEPT
/// oversize, which each rule projects from its own `max_bytes` vs `size`. `hash`
/// is the full-file SHA-256 computed once at the largest admitting cap; it is
/// present whenever at least one watching rule admits the file's size, and a rule
/// whose own cap is smaller than `size` reports "<oversize>" and ignores it.
struct FileSnapshot {
    bool exists{false};
    bool readable{true};        ///< false -> "<unreadable>" drift: the file exists but a genuine
                                ///< permission/lock/type issue makes it unverifiable. A TRANSIENT read
                                ///< failure (mutation-during-hash, retries exhausted) is NOT this - the
                                ///< reader returns Unknown for that. Legacy conflated the two into one
                                ///< "<unreadable>" token; spark splits persistent (Known drift) from
                                ///< transient (Unknown).
    std::uint64_t size{0};      ///< byte size; each rule compares vs its own max_bytes for oversize
    std::string identity;       ///< reader change-detection token (dev+inode / volume+file-index); not
                                ///< part of the verdict - convergence uses it to detect replace-in-place
    std::int64_t mtime_ns{0};   ///< reader convergence size+mtime skip input; not part of the verdict
    std::string hash;           ///< full-file lowercase hex SHA-256 (empty when not hashed / n/a)
};

/// Registry value read once per (key, value_name) by the reader.
struct RegistrySnapshot {
    bool present{false};   ///< false -> "<absent>" drift
    bool supported{true};  ///< false -> "<unsupported-type>" drift
    std::string value;     ///< G4-encoded live value string
};

/// A live-state read that can fail to determine the value. `known == false`
/// (Unknown) means "could not tell" (transient I/O, retries exhausted), distinct
/// from a Known snapshot that reports an absent/stopped target. The evaluator maps
/// Unknown to an Unhealthy outcome and never to a compliance verdict.
template <typename Snapshot>
struct ReadResult {
    bool known{true};
    Snapshot snapshot{};  ///< valid iff `known`
    std::string error;    ///< read-error detail iff `!known` (guard.unhealthy detail)
};

template <typename S>
[[nodiscard]] ReadResult<S> read_known(S s) {
    return ReadResult<S>{true, std::move(s), {}};
}
template <typename S>
[[nodiscard]] ReadResult<S> read_unknown(std::string why) {
    return ReadResult<S>{false, S{}, std::move(why)};
}

/// Per-rule mutable eval state kept by the consumer, keyed by rule_id.
struct RuleEvalState {
    EmitDeciderState emit;
    std::string baseline_hash;  ///< file-hash baseline-on-arm capture
    bool baseline_set{false};
    bool in_unknown{false};     ///< the last eval was Unknown; the next Known eval FORCES a verdict even
                                ///< if the value is unchanged, so the server re-learns compliance after an
                                ///< errored gap. Set on Unknown (EmitDeciderState otherwise untouched),
                                ///< cleared by the forced verdict in `pack`.
    /// M1 item (a), runtime-owned (not touched by eval_file/eval_registry/eval_service):
    /// the clock reading at the last guard.unhealthy EMISSION for this rule, edge or
    /// refresh. Default-constructed (epoch) so the FIRST edge always fires regardless
    /// of errored_refresh_ms - only a later refresh check needs a real timestamp to
    /// compare against. Mutated by GuardianSparkRuntime's commit section alongside the
    /// scratch-then-commit pattern every other field here already follows.
    std::chrono::steady_clock::time_point last_unhealthy_emit{};
};

/// What an evaluation decided.
enum class EvalStatus {
    Silent,     ///< nothing to emit (steady compliant, or a debounce-folded drift)
    Emit,       ///< publish `drift` (a drift OR a compliant edge)
    Unhealthy,  ///< the read was Unknown; runtime emits guard.unhealthy - EmitDeciderState was left untouched
};

struct EvalOutcome {
    EvalStatus status{EvalStatus::Silent};
    GuardDrift drift{};         ///< meaningful iff status == Emit
    std::string health_detail;  ///< read-error detail iff status == Unhealthy
    bool recovered{false};      ///< this Known outcome is the FIRST after an Unknown gap; the runtime
                                ///< also emits guard.healthy so the health stream leaves the errored
                                ///< state even when the verdict itself is Silent (systemd steady-compliant)
    bool unhealthy_edge{false}; ///< iff status == Unhealthy: this is the FIRST Unknown of an errored
                                ///< episode (in_unknown was false going in). The runtime emits
                                ///< guard.unhealthy ONLY on this edge; a repeat Unknown while already
                                ///< errored is suppressed + counted, so a rule stuck Unknown (unreadable
                                ///< file, EACCES hive, unqueryable service) does not re-mint a fresh
                                ///< health event on every ~5s convergence re-eval (M1 flood guard).
};

/// Evaluate a file rule against a tri-state read. Returns Emit / Silent / Unhealthy.
[[nodiscard]] YUZU_EXPORT EvalOutcome
eval_file(const RuleAssertion& a, const ReadResult<FileSnapshot>& read, RuleEvalState& state,
          std::chrono::steady_clock::time_point now, bool emit_compliant_edge = true);

/// Evaluate a registry rule. `detection_latency_us` is the measured read time
/// (registry is the one type that records it, for parity); ignored on Unknown.
[[nodiscard]] YUZU_EXPORT EvalOutcome
eval_registry(const RuleAssertion& a, const ReadResult<RegistrySnapshot>& read, RuleEvalState& state,
              std::uint64_t detection_latency_us, std::chrono::steady_clock::time_point now,
              bool emit_compliant_edge = true);

/// Evaluate a service rule against the live run-state the reader resolved. A
/// deleted service folds into Stopped at the reader (R5, accepted - the verdict is
/// identical, only detected_value differs from legacy); a service that could not be
/// queried is Unknown, distinct from Stopped.
[[nodiscard]] YUZU_EXPORT EvalOutcome
eval_service(const RuleAssertion& a, const ReadResult<ServiceRunState>& read, RuleEvalState& state,
             std::chrono::steady_clock::time_point now, bool emit_compliant_edge = true);

} // namespace yuzu::agent
