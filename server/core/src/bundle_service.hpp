#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Live-query bundle — server-side core (ADR-0011: server-side async fan-out).
//
// One operator instruction carries a list of {plugin, action, params} steps. The
// server expands it into N ORDINARY plugin commands on one device (each its own
// command_id, all sharing one correlation id), then collates the responses on
// demand. The agent is unchanged — it only ever sees ordinary single commands.
//
// This header holds the PURE, testable pieces: step-list validation and the
// collate/aggregate logic (which matches response rows to the dispatched-step
// map by command_id). The dispatch fan-out + persistence + REST/MCP wiring live
// in the handler/orchestration layer.

namespace yuzu::server {

/// Upper bound on steps in one bundle. A bundle expands into N concurrent
/// ordinary commands on the agent; the cap bounds that fan-out.
inline constexpr std::size_t kMaxBundleSteps = 32;

/// Per-step parameter bounds. A bundle fans out up to kMaxBundleSteps commands,
/// so an unbounded param payload is amplified ×N at dispatch (UP-7 governance) —
/// these caps keep the fan-out's memory bounded without constraining real use
/// (live-query params are short flags). Values above the cap are rejected at
/// validation, before any dispatch.
inline constexpr std::size_t kMaxParamCountPerStep = 32;
inline constexpr std::size_t kMaxParamKeyLen = 256;
inline constexpr std::size_t kMaxParamValueLen = 64 * 1024; // 64 KiB

/// One validated step from the instruction's step list.
struct BundleStepSpec {
    std::string plugin;
    std::string action;
    std::vector<std::pair<std::string, std::string>> params; // ordered; values are strings
};

/// Validate the JSON `steps` array. Shape:
///   [ {"plugin":"os_info","action":"uptime","params":{"k":"v"}}, ... ]
/// `plugin` and `action` are lower-cased and required to be a non-empty
/// `[a-z0-9_]` identifier of at most 64 bytes (agent plugin/action matching is
/// case-sensitive and registered lower-case; the validated identifiers are also
/// used to build per-step audit verbs, so they must be injection-safe). Param
/// values are coerced to strings (non-strings JSON-dumped). Returns the parsed
/// steps, or a human-readable error. Rejects: malformed JSON, non-array, empty,
/// > max_steps, non-object element, missing/invalid plugin or action,
/// non-object `params`, oversized params. Duplicate `(plugin, action)` steps are
/// ALLOWED and preserved in request order (ADR-0011 §61-64 — demux is by
/// command_id, so duplicates with different params are unambiguous).
/// A rejected steps document: the human-readable message and a TYPED kind, so a caller that audits or
/// counts a refusal by cause (`param_key_invalid`) never classifies it by matching message text.
struct BundleStepsError {
    enum class Kind { kOther, kParamKeyInvalid };
    std::string message;
    Kind kind{Kind::kOther};
};

/// `validate_bundle_steps` with the typed error (the ingress surfaces that count by cause use this).
[[nodiscard]] std::expected<std::vector<BundleStepSpec>, BundleStepsError>
validate_bundle_steps_typed(std::string_view steps_json, std::size_t max_steps = kMaxBundleSteps);

[[nodiscard]] std::expected<std::vector<BundleStepSpec>, std::string>
validate_bundle_steps(std::string_view steps_json, std::size_t max_steps = kMaxBundleSteps);

/// A step as actually dispatched — its minted `command_id` (empty if the
/// dispatch did not reach any agent) plus its identity. This ordered list is the
/// bundle's step↔command_id map, persisted at dispatch and read back at collate.
struct DispatchedStep {
    std::string command_id; ///< empty ⇒ dispatch failed (never reached the agent)
    std::string plugin;
    std::string action;
};

enum class BundleStepState { Pending, Responded, DispatchFailed };

/// One step's collated result.
struct BundleStepResult {
    std::string plugin;
    std::string action;
    BundleStepState state{BundleStepState::Pending};
    int status{0}; ///< CommandResponse::Status enum value, when Responded
    std::string output;
};

/// The collated bundle.
struct BundleAggregate {
    std::vector<BundleStepResult> steps; ///< request order
    std::size_t expected{0};
    std::size_t received{0};  ///< steps that have a response (any terminal status)
    std::size_t succeeded{0}; ///< steps responded with status == SUCCESS (1)
    bool complete{false};     ///< no step is still Pending (all responded or dispatch-failed)
};

/// One response row, decoupled from `StoredResponse` so the aggregator is pure
/// and DB-free. The collate handler maps `StoredResponse{instruction_id, status,
/// output}` → this (a bundle step's `command_id` is the response's
/// `instruction_id`).
struct BundleResponseRow {
    std::string command_id;
    int status{0};
    std::string output;
};

/// Build the collated aggregate by matching response rows to the ordered
/// dispatched-step map by `command_id`. Pure — no DB, no proto. A step with an
/// empty `command_id` is `DispatchFailed`; a step with a matching row is
/// `Responded`; otherwise `Pending`. `complete` is true once no step is Pending.
[[nodiscard]] BundleAggregate aggregate_bundle(const std::vector<DispatchedStep>& steps,
                                               const std::vector<BundleResponseRow>& rows);

/// Serialize the aggregate to the caller-facing result JSON:
///   {"complete":bool,"received":N,"succeeded":S,"expected":M,
///    "steps":[{"plugin","action","state","status","output"}, ...]}
/// `state` is one of "pending" | "responded" | "dispatch_failed".
/// NOTE: `complete` means terminal, NOT success — a bundle to an offline device
/// completes with received=0, succeeded=0 and every step dispatch_failed. A
/// caller deciding "did it work" must check `succeeded == expected` (or inspect
/// per-step `state`/`status`), never `complete` alone.
[[nodiscard]] std::string aggregate_to_json(const BundleAggregate& agg);

} // namespace yuzu::server
