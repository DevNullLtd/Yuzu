#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "guaranteed_state.pb.h"
#include "guaranteed_state_store.hpp"  // GuaranteedStateRuleRow

namespace yuzu {
class MetricsRegistry;
}

// Pure helpers for building the per-agent Guardian push (M4 / #1209). Kept out
// of server.cpp's push lambda so the rule-filtering + spec_json→proto marshal is
// unit-testable without a live AgentRegistry or gRPC stream (M7).
namespace yuzu::server::guardian {

// True iff a rule with os_target `target` should be enforced on an agent
// reporting platform `agent_os`. Empty target = applies to all OSes. An empty
// `agent_os` (unknown OS — e.g. a disconnect race or partial registration) also
// returns true: fail OPEN so a guard is never silently dropped, matching the
// pre-M4 send-all posture (the agent marks an inapplicable guard errored). Match
// is otherwise by canonical OS token: BOTH sides are normalised (`normalize_os` —
// lower-cased and darwin mapped to macos) and then compared for EQUALITY, so a
// short/ambiguous target like "win" can never spuriously match "darwin" (a raw
// substring test would admit it). NOTE: `agent_os` is always the RAW kAgentOs
// token ("windows" | "linux" | "darwin"), never verbose free text —
// `normalize_os` does NOT parse a string like "Windows 11 Pro" down to
// "windows"; it only lower-cases and maps darwin to macos. An earlier version
// of this comment claimed otherwise; that claim was false (#4252).
bool os_target_matches(std::string_view target, std::string_view agent_os);

// True iff the agent-side Guardian engine actually ARMS a guard of spark type
// `spark_type` on `agent_os`. NOT a blanket OS check — support is PER GUARD
// TYPE (#4252 fixed a dashboard double-count caused by treating it as one):
//   registry-change / file-change  -> Windows only. RegistryGuard::start() /
//                                      FileGuard::start() are compiled no-ops
//                                      on macOS and Linux
//                                      (agents/core/src/guard_registry.cpp,
//                                      guard_file.cpp).
//   service-status-change          -> Windows AND Linux. SystemdServiceGuard
//                                      (agents/core/src/guard_systemd.cpp's
//                                      make_service_guard()) arms on Linux
//                                      today (observe-only; enforce is
//                                      deliberately deferred) — NOT a no-op,
//                                      unlike Registry/File on Linux. macOS
//                                      still falls to the no-op ServiceGuard
//                                      stub. See docs/os-capability-matrix.md's
//                                      Guardian rows and docs/user-manual/
//                                      guaranteed-state.md's Service section.
//   unknown / missing / non-string  -> falls back to the Windows-only rule,
//   spark_type                         so a malformed row or a guard type
//                                      this function doesn't yet recognise
//                                      can never silently regress
//                                      Registry/File support.
// The server must therefore report an unsupported (agent, rule) pair as "not
// yet implemented" rather than letting it fold into the offline "unknown"
// bucket and read as armed — an operator must never mistake a no-op platform
// for a protected one. Just as important, a caller MUST first check whether
// the pair already owns a REAL status row before treating "unsupported" as
// "the agent never reported" — Linux Service now legitimately reports real
// status, so skipping that check double-counts the pair (the #4252 bug); see
// the shared exclusion predicate in guardian_routes.cpp. `agent_os` is the RAW
// token the agent reports (kAgentOs: "windows" | "linux" | "darwin"); it is
// normalised before comparison. An empty `agent_os` (unknown — disconnect
// race / partial registration) returns true so we never mislabel it
// unimplemented, for any spark_type. THIS is the single place to extend as
// more guard types/platforms gain support.
bool guardian_guard_supported_on_platform(std::string_view agent_os,
                                          std::string_view spark_type);

// The 3 guard-type ("spark.type") tokens this matrix explicitly distinguishes.
// Single source shared with guardian_routes.cpp's platform-matrix-stale
// detectability counter's closed Prometheus label set (that counter now
// aliases this array directly — no third copy), and cross-checked against the
// published schema catalog's "spark"-kind entries by
// test_guardian_resilience_schema.cpp's CROSS-CHECK test (governance Gate 4
// finding, #4252 consolidated round) — so the schema catalog and this array
// can no longer drift out of sync silently.
//
// What that cross-check does NOT bind (governance Gate 8 re-review,
// architect + consistency-auditor): guardian_guard_supported_on_platform's
// if-chain above is a set of STRING LITERALS, not a lookup over this array —
// adding a 4th entry here and to the schema catalog, with no corresponding
// branch in that function, leaves the cross-check green while the actual
// platform-support decision silently falls through to the Windows-only
// default. test_guardian_push_builder.cpp's platform test pins this array's
// entries against that function's literal branches directly (an
// unrecognised entry there fails loudly); update BOTH tests, and this
// function's branch, when adding a spark type — the schema-registry side is
// guardian_schema_registry.cpp's build_catalog().
inline constexpr std::array<std::string_view, 3> kKnownGuardSparkTypes = {
    "registry-change", "file-change", "service-status-change"};

// Human-facing label for a raw agent platform token, for dashboard copy:
// "darwin" -> "macOS", "windows" -> "Windows", "linux" -> "Linux"; an
// unknown/empty token -> "unknown". (The canonical wire/author token stays
// "macos" per #1209; this only governs display.)
std::string platform_display_name(std::string_view agent_os);

// The Baseline gate. Returns the subset of `rules` whose rule_id is in
// `deployed_rule_ids` — the union of member Guards across all *deployed*
// Baselines. A Guard reaches an agent ONLY as a member of a deployed Baseline
// (docs/guardian-baseline-model.md); this filter is applied to the push/reconcile
// rule source so an enabled-but-undeployed Guard never enforces. Order preserved.
// An empty `deployed_rule_ids` yields an empty result — correct by model (with
// nothing deployed, a full_sync push converges agents to zero guards).
std::vector<GuaranteedStateRuleRow>
filter_deployed_members(const std::vector<GuaranteedStateRuleRow>& rules,
                        const std::unordered_set<std::string>& deployed_rule_ids);

// Per-rule, LRU-bounded, time-based log-rate sampler for the depth-guard
// exclusion path (#4497/#4499 - replaces the single shared count+episode
// sampler #4478 originally shipped). One process-wide instance is still
// shared by every push call site in this process (same posture as before),
// but state is now keyed by rule_id instead of being one global clock, so a
// persistently-poisoned rule can no longer mask, or reset, a DIFFERENT
// poisoned rule's own log cadence - the #4497 "cross-rule masking" defect.
//
// THE RECORDED DESIGN DECISION (#4497 acceptance criterion 1 - this decision
// followed an external architecture consultation; this comment is the
// complete record of that outcome, not one option among several, and no
// separate transcript or linked artifact exists beyond it):
//
//   - A rule_id absent from the cache logs immediately, then enters the
//     cache.
//   - A cached rule_id logs again only once at least kRepeatInterval has
//     elapsed since its LAST PERMITTED log (steady_clock, so a wall-clock
//     step/NTP correction cannot affect it), regardless of how many
//     intervening exclusions for it were suppressed. Measuring time since
//     the last EXCLUSION instead (rather than the last permitted log) would
//     let continuous traffic on one rule suppress its own reminders
//     indefinitely - deliberately not done.
//   - Every exclusion (permitted or suppressed) refreshes that rule_id's LRU
//     recency; only a PERMITTED exclusion advances its logging deadline.
//   - Inserting a rule_id beyond kCapacity evicts the least-recently-OBSERVED
//     entry, NOT the least-recently-PERMITTED-TO-LOG one - the two differ in
//     general: every observation, permitted or not, splices an entry to the
//     front, so a rule under continuous exclusion pressure normally stays
//     "hot" even while its own log line stays silenced by kRepeatInterval.
//     It is evicted only when it is the least-recently-observed entry AT THE
//     MOMENT a new distinct rule_id is inserted into a full cache - i.e. when
//     kCapacity distinct OTHER rule_ids intervene between two of its own
//     observations. That precondition is rare in normal operation but is
//     exactly what happens, on every pass, in limitation (1) below.
//     An evicted rule_id subsequently encountered is therefore treated as a
//     fresh first-observation and logs immediately again.
//   - This deliberately fixes #4497's OTHER symptom too (throughput-scaling
//     log volume): a single persistently-poisoned rule now logs at most once
//     per kRepeatInterval, full stop, independent of how often the push
//     fan-out reconciles it.
//
// ACCEPTED, DOCUMENTED LIMITATION (do not "fix" this silently - it is a
// tradeoff, not a gap): a 256-entry LRU is bounded PER-RULE pacing, not a
// GLOBAL log-rate limit. Two cases are explicitly out of scope:
//   (1) a stable set of MORE than kCapacity distinct poisoned rules cycling
//       through the cache IN A REPEATING ORDER is a HARD CLIFF, not a mild
//       leak: at exactly kCapacity+1 such rules, every rule is evicted right
//       before its own next turn in the SAME pass that re-admits it, so
//       EVERY rule logs on EVERY pass - a 0% suppression rate, not merely
//       "somewhat more often than once per kRepeatInterval". Verified
//       directly against this class (see test_guardian_push_builder.cpp's
//       kCapacity+1 cliff test: 257 rule_ids, 5 consecutive passes, 257/257
//       logged every pass). This is worse in this one regime than the
//       pre-#4497 shared sampler's 1-in-100 log floor, and is an accepted
//       design tradeoff (a per-rule backstop for this regime was out of
//       scope for #4497/#4499) rather than a defect in this class;
//   (2) a simultaneous first-observation burst across many distinct rules
//       (all new to the cache at once) is unbounded - every one of them logs
//       immediately, by design (the point of per-rule keying is that a FIRST
//       observation is never suppressed).
// See docs/user-manual/guaranteed-state.md's yuzu_guardian_push_rule_excluded_total
// entry for the operator-facing version of this same tradeoff.
//
// Unlike RuntimeConfigStore's note_read_degrade (docs/observability-conventions.md),
// this deliberately does NOT also take a MetricsRegistry* and increment a
// counter itself: the counter has its own always-fires condition (every
// exclusion, not just permitted-to-log ones), so the caller increments it
// separately, unconditionally, right before calling should_log() - a reader
// porting this pattern elsewhere should not assume the two responsibilities
// are bundled the way they are in that precedent. The metric's `reason` label
// stays the only label: rule_id is deliberately never added to it (an open,
// unbounded set would reopen the exact cardinality problem this in-process
// map is scoped to avoid - the map's keys never leave this process).
//
// Independently instantiable (default-constructible + set_clock_for_test) so
// tests exercise it directly with deterministic injected timestamps, never a
// singleton the tests must reset; the process-wide instance used by
// build_agent_push lives in guardian_push_builder.cpp's anonymous namespace.
class RuleExclusionSampler {
public:
    // Injectable monotonic clock for deterministic tests (mirrors
    // OtaTransferWatchdog::set_clock_for_test); only the *difference* between
    // calls is meaningful. Defaults to the real steady_clock in production.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    // Bounded state: at most this many distinct rule_ids are tracked at once.
    // See the eviction-exception note above.
    static constexpr std::size_t kCapacity = 256;

    // Once a rule_id has been PERMITTED to log, it will not log again until
    // this much time has elapsed since that permitted log.
    static constexpr std::chrono::seconds kRepeatInterval{60};

    RuleExclusionSampler() = default;

    // TEST ONLY. An empty fn restores the real steady clock.
    void set_clock_for_test(ClockFn fn);

    // True iff THIS call should emit a fresh log line for `rule_id`. Always
    // refreshes `rule_id`'s LRU recency; a suppressed (false-returning) call
    // never advances its logging deadline. Thread-safe: the whole decision is
    // made under one internal mutex, so concurrent calls for the SAME
    // rule_id are fully serialized and exactly one wins any given interval.
    // Reserve the lock only for this decision - format/emit the log line
    // AFTER this returns, never while holding it.
    [[nodiscard]] bool should_log(const std::string& rule_id);

    // TEST ONLY. Number of distinct rule_ids currently tracked (<= kCapacity).
    [[nodiscard]] std::size_t tracked_count_for_test() const;

private:
    using LruEntry = std::pair<std::string, std::chrono::steady_clock::time_point>;

    mutable std::mutex mu_;
    ClockFn clock_{[] { return std::chrono::steady_clock::now(); }};
    // Front = most-recently-observed rule_id, back = least. Entries are OWNED
    // rule_id copies (never a borrowed view into a push row - the row need
    // not outlive this sampler entry) paired with the last-PERMITTED-log
    // timestamp.
    std::list<LruEntry> lru_;
    std::unordered_map<std::string, std::list<LruEntry>::iterator> index_;
};

// Build the GuaranteedStatePush addressed to a SINGLE agent. Includes only
// enabled rules that (a) target this agent's OS and (b) name this agent in their
// scope — an empty rule scope_expr means fleet-wide and always matches. The
// `in_scope` oracle is supplied by the caller (which owns the scope engine and
// registry), keeping this function pure. Without M4's filtering, every agent
// received every enabled rule, so a Linux box was handed Windows registry guards
// (wasted bandwidth + G11 "errored" noise).
//
// Total over arbitrary stored bytes: a rule row with a malformed (present but
// non-string) spark/assertion/remediation `type` marshals to an inert empty
// type rather than throwing — the fan-out never aborts on one bad row (#1946).
// A row whose spec_json nests past kMcpMaxJsonDepth is excluded from the push
// entirely (logged, not silently dropped) rather than reaching the marshal at
// all: fill_block's dump() is unboundedly recursive, and the malformed-type
// backstop above does not cover an oversized document, only a wrong-typed one.
// The exclusion also increments `yuzu_guardian_push_rule_excluded_total{reason}`
// when `metrics` is non-null (nullable/defaulted so existing callers/tests need
// no change), UNCONDITIONALLY on every exclusion regardless of whether the
// paired log line fires. The log line itself is rate-limited per rule_id via
// RuleExclusionSampler (above) since the row persists in the store and this
// function runs on every heartbeat reconcile for every connected agent - an
// unrated log would flood at fleet scale for as long as the poisoned row
// exists.
::yuzu::guardian::v1::GuaranteedStatePush
build_agent_push(const std::vector<GuaranteedStateRuleRow>& rules, std::string_view agent_os,
                 const std::function<bool(const std::string& scope_expr)>& in_scope,
                 bool full_sync, std::uint64_t generation,
                 ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server::guardian
