#pragma once

// guardian_generation_raise.hpp - request parsing and result shaping for the supported
// "raise the Guardian policy generation to N" operation, and the response shape of its
// read-only twin (`GET /api/v1/guaranteed-state/policy-generation`, MCP
// `get_guardian_policy_generation`), which is how an operator reads the server's value
// before deciding on a target.
//
// The policy generation is a single fleet-wide monotonic counter in
// guaranteed_state_store.guardian_meta. Every agent persists the last generation it
// converged to and treats a lower server value as stale, so a server whose counter was
// restored below what its agents already hold stops converging them. Raising the counter
// is the recovery, and it is not a neutral act: once raised, every agent behind it is
// converged to the rule set the server holds AT THAT MOMENT, replacing whatever rules the
// agent held under the higher number. The request therefore carries an explicit
// acknowledgement of that, and the handlers refuse a request that does not.
//
// This header is the one place the REST routes and the MCP tools share, so the two
// transports cannot drift on the accepted range, the acknowledgement, the audit detail
// text or the response shapes. It is pure: no httplib, no store, no I/O.
//
// Error strings returned here are operator-facing text. They contain no control bytes and
// never echo a raw field value, so a caller-supplied string cannot reach a log line or an
// audit row through them.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>

#include <nlohmann/json.hpp>

namespace yuzu::server::guardian {

/// Largest accepted target: 2^53 - 1, the largest integer a JSON number round-trips
/// exactly through an IEEE-754 double (which is what most JSON clients use). It is about
/// three orders of magnitude below the BIGINT maximum, so the counter's ordinary `value + 1`
/// bumps cannot overflow after a raise to the ceiling.
inline constexpr std::int64_t kMaxPolicyGenerationTarget = 9'007'199'254'740'991;

/// Audit action for the raise. The target is ("GuaranteedState", "policy_generation").
inline constexpr const char* kRaiseAuditAction = "guaranteed_state.policy_generation.raise";

/// Parse `{"target_generation": <integer 1..kMaxPolicyGenerationTarget>,
///         "acknowledge_rule_set_replaced": true}`.
///
/// Rejects a non-object body, a missing or non-integer target (floats, strings, booleans
/// and null included), a target below 1 or above the ceiling, and any acknowledgement that
/// is not the JSON boolean `true`.
[[nodiscard]] inline std::expected<std::int64_t, std::string>
parse_raise_request(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));

    const auto target_it = body.find("target_generation");
    if (target_it == body.end())
        return std::unexpected(std::string("target_generation is required"));
    // is_number_integer() is true for both signed and unsigned integers and false for
    // floats, strings, booleans and null. An unsigned value above INT64_MAX is an integer
    // too, so it is range-checked before any narrowing below.
    if (!target_it->is_number_integer())
        return std::unexpected(std::string("target_generation must be a JSON integer"));

    if (target_it->is_number_unsigned()) {
        if (target_it->get<std::uint64_t>() > static_cast<std::uint64_t>(kMaxPolicyGenerationTarget))
            return std::unexpected(std::string("target_generation exceeds the maximum of ") +
                                   std::to_string(kMaxPolicyGenerationTarget));
    }
    const std::int64_t target = target_it->get<std::int64_t>();
    if (target < 1)
        return std::unexpected(std::string("target_generation must be at least 1"));
    if (target > kMaxPolicyGenerationTarget)
        return std::unexpected(std::string("target_generation exceeds the maximum of ") +
                               std::to_string(kMaxPolicyGenerationTarget));

    const auto ack_it = body.find("acknowledge_rule_set_replaced");
    if (ack_it == body.end() || !ack_it->is_boolean() || !ack_it->get<bool>())
        return std::unexpected(
            std::string("acknowledge_rule_set_replaced must be the JSON boolean true: raising "
                        "the generation converges every agent behind it to the rule set this "
                        "server holds now, replacing the rules those agents hold"));
    return target;
}

/// Audit detail text:
/// "target=N; previous=P; resulting=R; raised=true|false; rules=X; deployed_baselines=Y".
/// Every field is a number or a fixed word, never caller-controlled text.
[[nodiscard]] inline std::string raise_audit_detail(std::int64_t target, std::uint64_t previous,
                                                    std::uint64_t resulting, bool raised,
                                                    std::size_t rules,
                                                    std::size_t deployed_baselines) {
    return "target=" + std::to_string(target) + "; previous=" + std::to_string(previous) +
           "; resulting=" + std::to_string(resulting) +
           "; raised=" + std::string(raised ? "true" : "false") +
           "; rules=" + std::to_string(rules) +
           "; deployed_baselines=" + std::to_string(deployed_baselines);
}

/// Response body shared by the REST route and the MCP tool.
[[nodiscard]] inline nlohmann::json raise_result_json(std::uint64_t previous,
                                                      std::uint64_t resulting, bool raised,
                                                      std::size_t rules,
                                                      std::size_t deployed_baselines) {
    return nlohmann::json{{"previous_generation", previous},
                          {"generation", resulting},
                          {"raised", raised},
                          {"rules", rules},
                          {"deployed_baselines", deployed_baselines},
                          {"ceiling", kMaxPolicyGenerationTarget}};
}

/// Response body of the read-only twins: the stored generation and the largest target a
/// raise accepts. Shared by the REST route and the MCP tool. A caller holding a degraded
/// read (no value) must refuse the request instead of calling this with 0: a missing value
/// is never a generation of zero.
///
/// `stored` is `GuaranteedStateStore::current_policy_generation()`, which reinterprets the
/// BIGINT column as unsigned. A negative stored value can only come from an out-of-band edit
/// and arrives here as a number above INT64_MAX; it is reported as 0, as the raise reports
/// its `previous_generation`, so the two operations never disagree about what is stored.
[[nodiscard]] inline nlohmann::json generation_read_json(std::uint64_t stored) {
    const std::uint64_t generation =
        stored > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ? 0 : stored;
    return nlohmann::json{{"generation", generation}, {"ceiling", kMaxPolicyGenerationTarget}};
}

} // namespace yuzu::server::guardian
