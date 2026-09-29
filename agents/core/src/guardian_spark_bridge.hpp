#pragma once

/**
 * guardian_spark_bridge.hpp - the Guardian-rule <-> spark vocabulary bridge
 * (ADR-0021 Stage 2 rung 2 slice 2b, extended rung 7). Converts a
 * GuaranteedStateRule's typed blocks into the SparkSpec the SparkEngine arms,
 * and classifies a rule's spark type against this host's mechanism capability.
 *
 * Source-of-truth note: the spark block carries only the type discriminator
 * ("file-change" / "service-status-change" / "registry-change"); the watch
 * TARGET (path / service_name / hive+key) lives in the ASSERTION params. This
 * mirrors exactly how the legacy guards read it in
 * start_guard_for_rule_locked() (guardian_engine.cpp) - the two paths must
 * resolve the same target or a rule would watch one thing and assert over
 * another.
 *
 * SINGLE-SOURCED token recognition (rung 7 fix): spark_type_from_token() is the
 * ONE place the three recognized spark-type strings are listed. Both
 * spark_spec_from_rule() and classify() call it, so they cannot silently drift
 * apart (previously each had its own separate copy of the same three strings -
 * an agreement that held by coincidence, not by construction). A caller that
 * already has a spark_spec_from_rule() Some result never needs classify()'s
 * Unrecognized branch - Some already proves the token was recognized - so
 * classify() exists for the cases that still need the FULL three-way split
 * (platform-capability decisions made independently of building a SparkSpec),
 * and its own unit tests document the taxonomy.
 *
 * INLINE by design (not a .cpp in the DLL): a proto Map<string,string> lookup
 * must run in the SAME image that populated the map, or it hits the #501
 * abseil-seed-across-DLL hash mismatch on MSVC debug (see
 * guardian_engine.hpp's guardian_dispatch_push_bytes_for_test rationale). Inline
 * keeps populate+find co-located - the DLL both parses the wire rule and calls
 * this; a unit test both builds the rule and calls this - so neither crosses the
 * boundary. classify() and spark_type_from_token() touch no proto Map, so this
 * constraint doesn't strictly apply to them, but they stay in this header
 * (still inline, still trivial) rather than splitting into a second file for
 * two small pure functions.
 *
 * rule_assertion_from_rule() (rung 7) is the RuleAssertion-side counterpart to
 * spark_spec_from_rule(): together they give the reconcile op everything
 * attach_rule() needs, having faithfully re-derived the SAME normalization the
 * legacy start_guard_for_rule_locked() (guardian_engine.cpp) already applies -
 * hash lowercasing, whole-string max_bytes parsing + zero-normalization, the
 * file-exists/absent default, and the debounce window sourced from
 * parse_resilience_params over the remediation block. It does NOT carry the
 * watch TARGET (that is spark_spec_from_rule's job) or an enforce/remediation
 * mode - the spark evaluators are detection-only through this rung (rung 3 is
 * when spark gains enforcement), so RuleAssertion has no field for it yet.
 * `settle_ms` (file-hash-equals' mid-write notification coalescing window) is a
 * FileGuard-mechanism-level concern with no RuleAssertion field and no spark
 * FileSparkParams equivalent - an ACCEPTED behavioral delta from legacy
 * (spark's convergence scheduler dead-reckons via size+mtime skip + a forced
 * periodic re-hash instead of debouncing kernel notifications), flagged here
 * for the rung-9 design-doc rewrite and the rung-10 parity/durability matrix.
 */

#include <yuzu/agent/resilience_strategy.hpp> // parse_resilience_params, ResilienceConfig
#include <yuzu/agent/spark.hpp>               // SparkSpec, SparkType, *SparkParams

#include "guardian_rule_eval.hpp" // RuleAssertion, AssertionKind
#include "guaranteed_state.pb.h"

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

/// The ONE place the Guardian rule spark-type tokens (the server-side
/// Guaranteed-State DSL) map to the spark vocabulary. These three are the
/// event-driven Guardian types today, matching the dispatch in
/// start_guard_for_rule_locked() (guardian_engine.cpp). A token outside this
/// set is not a platform miss - it is an authored spark type the agent does
/// not implement at all, i.e. an authoring error.
[[nodiscard]] inline std::optional<SparkType> spark_type_from_token(std::string_view token) noexcept {
    if (token == "file-change") return SparkType::File;
    if (token == "service-status-change") return SparkType::Service;
    if (token == "registry-change") return SparkType::Registry;
    return std::nullopt;
}

/// Where a Guardian rule lands when classified against the mechanisms
/// available on THIS host. The Unsupported/Unrecognized split is the whole
/// point of the platform-rejection design (ADR-0021): a cross-platform
/// Baseline reaching a host that structurally lacks the mechanism (Registry or
/// File off Windows, Service off Linux/macOS) is ROUTINE and terminal-states to
/// `unsupported`, NOT an authoring fault. Only an unknown spark type is
/// `errored`/page-worthy.
enum class RulePlacement {
    Arm,          ///< known event-driven type WITH an armable mechanism on this host: arm it
    Unsupported,  ///< known type, NO mechanism registered here, OR registered but boot-inert
                  ///< (#4685): either way, routine, terminal-state unsupported
    Unrecognized, ///< spark type token not understood: an authoring error (errored)
};

/// Classify a rule's spark type against the mechanisms available on this host.
/// PURE and side-effect-free. `supported` is the set of event-driven types the
/// SparkEngine has a registered, ARMABLE mechanism for - registered AND NOT
/// boot-inert (#4685). This is DELIBERATELY NARROWER than
/// spark_heartbeat.hpp's own inert-filtering, which excludes the UNION of
/// boot-inert and runtime-degraded: a mechanism mid a TRANSIENT runtime-degraded
/// episode (Registry's sweeper / File's worker, three consecutive failed passes,
/// cleared on the next success) still accepts watch() and serves it once a pass
/// next succeeds, so it must stay armable here even though the heartbeat CSV
/// stops advertising it as a capability for that same window. Filtering it here
/// too would strand every rule of that type Unsupported for the whole episode,
/// with nothing to proactively re-reconcile once the mechanism recovers (the bug
/// #4685 exists to close - see guardian_engine.cpp's reconcile_rule_locked for
/// the caller). Callers therefore pass the BOOT-INERT-filtered set, never the
/// heartbeat's own (union) inert-filtered set. CRITICAL: the discriminator is
/// capability membership, NEVER the text of an arm() rejection message
/// (ADR-0021 platform-rejection) - a string match would silently misfile a
/// rejection the day the message wording changes.
[[nodiscard]] inline RulePlacement classify(std::string_view spark_type_token,
                                            const std::set<SparkType>& supported) noexcept {
    const std::optional<SparkType> type = spark_type_from_token(spark_type_token);
    if (!type) return RulePlacement::Unrecognized;
    return supported.contains(*type) ? RulePlacement::Arm : RulePlacement::Unsupported;
}

namespace detail {
/// One assertion param by key, or empty. Local to this header (inline linkage).
[[nodiscard]] inline std::string
guardian_assertion_param(const yuzu::guardian::v1::GuardianSpecBlock& assertion, const char* key) {
    const auto it = assertion.params().find(key);
    return it != assertion.params().end() ? it->second : std::string{};
}
} // namespace detail

/// Build the SparkSpec that watches what `rule` asserts over. Returns nullopt
/// for an unrecognized spark type (see spark_type_from_token) OR a recognized
/// type whose required target param is empty (no path / service_name /
/// hive|key) - the caller treats nullopt as "not armable" (an authoring error,
/// distinct from the platform-Unsupported outcome classify() reports for a
/// RECOGNIZED type this host merely lacks a mechanism for).
[[nodiscard]] inline std::optional<SparkSpec>
spark_spec_from_rule(const yuzu::guardian::v1::GuaranteedStateRule& rule) {
    const yuzu::guardian::v1::GuardianSpecBlock& assertion = rule.assertion();
    const std::optional<SparkType> type = spark_type_from_token(rule.spark().type());
    if (!type)
        return std::nullopt;

    switch (*type) {
    case SparkType::File: {
        std::string path = detail::guardian_assertion_param(assertion, "path");
        if (path.empty()) return std::nullopt;
        return SparkSpec{SparkType::File, FileSparkParams{std::move(path)}};
    }
    case SparkType::Service: {
        std::string service_name = detail::guardian_assertion_param(assertion, "service_name");
        if (service_name.empty()) return std::nullopt;
        return SparkSpec{SparkType::Service, ServiceSparkParams{std::move(service_name)}};
    }
    case SparkType::Registry: {
        std::string hive = detail::guardian_assertion_param(assertion, "hive");
        std::string key = detail::guardian_assertion_param(assertion, "key");
        // `key` may legitimately be empty - it means "watch the hive root",
        // which the legacy RegistryGuard has always accepted (guard_registry.cpp's
        // resolver passes an empty subkey as NULL to RegOpenKeyExW/RegCreateKeyExW,
        // opening `root` itself) and the spark mechanism accepts identically
        // (spark_registry.cpp's `p.empty() ? nullptr : wp.c_str()`). Rejecting it
        // here made this validation - which runs unconditionally, before the
        // prefer_spark_ check - STRICTER than legacy ever was, silently disarming
        // an already-working hive-root rule on the very next agent restart even
        // with spark fully inert (governance Gate 4/6 finding, this PR: confirmed
        // independently by three reviewers). Only `hive` is actually required.
        if (hive.empty()) return std::nullopt;
        return SparkSpec{SparkType::Registry, RegistrySparkParams{std::move(hive), std::move(key)}};
    }
    default:
        return std::nullopt; // Interval/Startup/Disk are not Guardian spark types
    }
}

/// Build the proto-free RuleAssertion the spark evaluators (guardian_rule_eval.hpp)
/// compare live state against. Returns an error for: an unrecognized spark type
/// (see spark_type_from_token); an assertion `type()` that does not match the
/// rule's spark type (e.g. a file-change rule asserting service-running) - this
/// is validated BEFORE any platform-capability question, so a malformed rule is
/// never mistaken for a routine cross-platform gap. Every field is normalized
/// EXACTLY as start_guard_for_rule_locked() (guardian_engine.cpp) already does,
/// re-derived here rather than shared because the legacy path fills a
/// guard-specific Config struct, not RuleAssertion.
[[nodiscard]] inline std::expected<RuleAssertion, std::string>
rule_assertion_from_rule(const yuzu::guardian::v1::GuaranteedStateRule& rule) {
    const yuzu::guardian::v1::GuardianSpecBlock& assertion = rule.assertion();
    const std::optional<SparkType> spark_type = spark_type_from_token(rule.spark().type());
    if (!spark_type)
        return std::unexpected("unrecognized spark type: " + rule.spark().type());

    RuleAssertion out;
    out.rule_id = rule.rule_id();
    out.rule_name = rule.name();

    // debounce_ms: single-sourced via parse_resilience_params over the
    // remediation block's params - identical to every legacy guard branch. The
    // returned ResilienceConfig itself (remediation MODE) is intentionally
    // discarded: spark is detection-only through this rung (enforcement lands
    // rung 3), so only the debounce window applies here.
    //
    // Fallback default (#3388): legacy's 1000ms default suits its notification-
    // driven model (no scheduled re-evaluation). Spark's convergence scheduler
    // re-evaluates every armed rule on a fixed per-type cadence, so a 1000ms
    // debounce expires before every single sweep, and a persistently-drifted
    // rule re-emits drift.detected on every sweep of its lane - jitter-adjusted
    // worst case ~1800/day on the 60s service/registry lanes, ~180/day on the
    // 600s file lane (naive no-jitter figures of 1440/144 understate the worst
    // case; full jitter-floor derivation in docs/spark-legacy-delta-registry.md's
    // D3 row).
    // Interim fix (owner decision, pending a possible full M1-shaped
    // edge+refresh redesign later): default to the rule's own lane
    // cadence plus the scheduler's own jitter span, so debounce reliably
    // survives at least one full sweep even at the jitter-shortened extreme -
    // roughly halves steady-state re-emission frequency. Reuses the SAME
    // cadence/jitter constants AND the same jitter-span formula the convergence
    // scheduler itself uses (guardian_jitter_span_ms, spark.hpp), so the two
    // can't silently drift apart on either axis.
    const auto& rem = rule.remediation();
    auto get = [&rem](std::string_view k) -> std::string {
        const auto it = rem.params().find(std::string(k));
        return it != rem.params().end() ? it->second : std::string{};
    };
    // No `default:` label below, deliberately: that keeps -Wswitch live as a build-time
    // SIGNAL if SparkType ever gains an enumerator this switch doesn't handle - not a
    // guaranteed compile-time BLOCK, since this project builds with werror=false and
    // MSVC's equivalent (C4062) is off even at /W4. The std::optional (rather than a
    // pre-seeded 1000ms literal) is the RUNTIME net for
    // the same gap (#3531) - a future unhandled case must be caught and logged, not
    // silently fall back to the exact 1000ms default that reintroduces #3388's flood.
    std::optional<std::uint64_t> default_debounce_ms;
    switch (*spark_type) {
    case SparkType::File:
        default_debounce_ms =
            kGuardianFileLaneCadenceMs + guardian_jitter_span_ms(kGuardianFileLaneCadenceMs,
                                                                 kGuardianLaneJitterPct);
        break;
    case SparkType::Registry:
        default_debounce_ms =
            kGuardianRegistryLaneCadenceMs + guardian_jitter_span_ms(kGuardianRegistryLaneCadenceMs,
                                                                     kGuardianLaneJitterPct);
        break;
    case SparkType::Service:
        default_debounce_ms =
            kGuardianServiceLaneCadenceMs + guardian_jitter_span_ms(kGuardianServiceLaneCadenceMs,
                                                                    kGuardianLaneJitterPct);
        break;
    case SparkType::Interval:
    case SparkType::Startup:
    case SparkType::Disk:
        break; // unreachable here (spark_type_from_token already rejected these above)
    }
    if (!default_debounce_ms) {
        // Unreachable today - kept as a loud, logged degrade rather than a silent one
        // (#3531). No assert: this project leaves b_ndebug unset, so asserts are LIVE
        // in release builds, and aborting here is exactly what the #3388 ledger ruled
        // out in favor of safe degrade. Falling back to the legacy default is safe (it
        // just re-admits the per-sweep flood for this one rule until the switch above
        // is updated for the new SparkType), but it must never be silent. Reuses
        // parse_resilience_params' own kGuardianLegacyDebounceMs rather than repeating
        // the literal, so a future change to the legacy default can't leave this
        // fallback silently stale.
        default_debounce_ms = kGuardianLegacyDebounceMs;
        spdlog::error("Guardian: rule '{}' has spark type '{}' unhandled by the debounce-"
                      "default switch - falling back to the legacy {}ms default (#3531)",
                      log_id_token(out.rule_id), spark_type_token(*spark_type),
                      *default_debounce_ms);
    }
    (void)parse_resilience_params(get, out.debounce_ms, *default_debounce_ms);

    const std::string& atype = assertion.type();
    switch (*spark_type) {
    case SparkType::File:
        if (atype == "file-hash-equals") {
            out.kind = AssertionKind::FileHashEquals;
            out.expected_hash = detail::guardian_assertion_param(assertion, "expected_hash");
            for (auto& c : out.expected_hash) // normalise to the lowercase hex sha256 emits
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            const std::uint64_t default_max_bytes = out.max_bytes;
            const std::string mb = detail::guardian_assertion_param(assertion, "max_bytes");
            if (!mb.empty()) {
                std::uint64_t parsed = default_max_bytes;
                const auto [p, ec] = std::from_chars(mb.data(), mb.data() + mb.size(), parsed);
                // Whole-string only: "123abc" -> default, not 123 (M1 - symmetric with
                // the server validator and resilience_strategy::to_u64).
                out.max_bytes = (ec == std::errc{} && p == mb.data() + mb.size())
                                    ? parsed
                                    : default_max_bytes;
            }
            // A 0 cap would report every covered file as <oversize> (never hashed,
            // perpetual false compliant/drift) - treat 0 as unset and keep the default.
            if (out.max_bytes == 0)
                out.max_bytes = default_max_bytes;
            // #2233 item 6: hard ceiling on an authored value - see
            // clamp_max_hash_bytes's own doc for why and the exact bound.
            if (const auto clamped = clamp_max_hash_bytes(out.max_bytes); clamped != out.max_bytes) {
                spdlog::warn("Guardian: rule '{}' authored max_bytes={} exceeds the {}-byte "
                            "ceiling - clamped (#2233 item 6)",
                            log_id_token(out.rule_id), out.max_bytes, kMaxFileHashBytes);
                out.max_bytes = clamped;
            }
            return out;
        }
        if (atype == "file-exists") {
            out.kind = AssertionKind::FileExists;
            // "absent" -> drift when the file EXISTS; anything else (default
            // "present", including empty/unset) -> drift when the file is missing.
            out.expect_present = (detail::guardian_assertion_param(assertion, "expected") != "absent");
            return out;
        }
        return std::unexpected("unrecognized file assertion type: " + atype);
    case SparkType::Service:
        if (atype == "service-running") {
            out.kind = AssertionKind::ServiceRunning;
            return out;
        }
        if (atype == "service-stopped") {
            out.kind = AssertionKind::ServiceStopped;
            return out;
        }
        return std::unexpected("unrecognized service assertion type: " + atype);
    case SparkType::Registry:
        if (atype != "registry-value-equals")
            return std::unexpected("unrecognized registry assertion type: " + atype);
        out.kind = AssertionKind::RegistryEquals;
        out.expected_value = detail::guardian_assertion_param(assertion, "expected");
        out.value_name = detail::guardian_assertion_param(assertion, "value_name");
        return out;
    default:
        return std::unexpected("spark type has no assertion mapping"); // Interval/Startup/Disk
    }
}

} // namespace yuzu::agent
