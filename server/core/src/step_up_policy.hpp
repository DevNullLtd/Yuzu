#pragma once

#include <array>
#include <cstddef>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

/// @file step_up_policy.hpp
/// The ONE table classifying every mutating HTTP route by its MFA step-up
/// requirement. `step_up_gate.cpp`'s chokepoint looks a request up here by the
/// exact `(method, registered pattern)` pair httplib matched; the in-handler
/// `StepUpFn` calls that predate the table are kept in step with it.
///
/// EXTEND this table, never fork it. A second list of step-up routes is the
/// same drift `body_cap_policy.hpp` and `authz_topology_floor.hpp` exist to
/// prevent for their own chokepoints.
///
/// KEYS: `pattern` is the registered route string byte-for-byte, as passed to
/// `HttpRouteSink::Post/Put/Delete/Patch` (a raw-string pattern is written as
/// the same raw string here). It is compared for equality with httplib's
/// `Request::matched_route`, which is `matcher->pattern()` verbatim, so there is
/// no prefix matching, no wildcard and no segment-boundary rule to get wrong:
/// a prefix exemption would silently cover a future route registered under it.
/// GET and OPTIONS never appear.
///
/// CLASSES (`StepUpClass`):
///   kRequired       - the chokepoint evaluates `decide_step_up` before the
///                     handler runs; a stale or absent proof is refused.
///   kStrong         - reserved for a stricter assurance level; no row carries
///                     it yet and the chokepoint fails CLOSED on one rather than
///                     treating it as kRequired.
///   kOwnGate        - the handler owns a stricter, order-sensitive gate; the
///                     chokepoint skips it. Closed to the three elevation routes.
///   kExempt         - reviewed and deliberately not gated; `reason` names why.
///   kPendingRuling  - not yet classified; treated as kExempt by the chokepoint,
///                     but the row count is pinned by `kPendingRulingMax` below,
///                     which may only go DOWN, so "pending" is not a free pass.
///
/// `action_label` is the audit `target_id` of the `mfa.step_up.required` row and
/// is kept identical to the label the in-handler call has always used, so
/// evidence queries keyed on it keep working.
///
/// Self-checks (`consteval`, so a bad edit is a BUILD FAILURE): no duplicate
/// `(method, pattern)` key, a non-empty `reason` on every kExempt / kOwnGate row,
/// a non-empty `action_label` on every kRequired row, and the kPendingRuling
/// ceiling.

namespace yuzu::server {

enum class StepUpClass : unsigned char {
    kRequired,
    kStrong,
    kOwnGate,
    kExempt,
    kPendingRuling,
};

/// Rollout state of a row. kOriginal rows are the set that refused a stale proof
/// before the table existed; kPromoted is reserved for rows added later behind
/// a rollout control. Nothing is kPromoted yet.
enum class Rollout : unsigned char {
    kOriginal,
    kPromoted,
};

struct StepUpPolicyEntry {
    std::string_view method;  // "POST" | "PUT" | "DELETE" | "PATCH"
    std::string_view pattern; // EXACT registered pattern text
    StepUpClass cls;
    Rollout rollout;
    std::string_view reason;       // mandatory for kExempt / kOwnGate: the review record
    std::string_view action_label; // audit target_id; the label the in-handler call used
};

namespace step_up_detail {
inline constexpr std::string_view kElevationReason =
    "handler owns a stricter elevation gate with a minimum window";
inline constexpr std::string_view kNoReason = "";
} // namespace step_up_detail

// clang-format off
inline constexpr StepUpPolicyEntry kStepUpPolicy[] = {
    // -- kRequired: routes that already carry an in-handler step-up call ----------------------
    // REST (rest_api_v1.cpp)
    {"POST",   R"(/api/v1/users/me/password)",                                  StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/users/me/password"},
    {"POST",   R"(/api/v1/users/([^/]+)/password)",                             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/users/{name}/password"},
    {"POST",   R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles)",             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/roles"},
    {"DELETE", R"(/api/v1/engine-principals/([a-z0-9._-]+)/roles/([^/]+))",     StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/engine-principals/{id}/roles/{role}"},
    {"POST",   R"(/api/v1/tokens)",                                             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/tokens"},
    {"DELETE", R"(/api/v1/tokens/(.+))",                                        StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/tokens/{id}"},
    {"POST",   R"(/api/v1/tokens/([^/]+)/rotate)",                              StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/tokens/{id}/rotate"},
    {"POST",   R"(/api/v1/tokens/([^/]+)/confirm)",                             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/tokens/{id}/confirm"},
    {"POST",   R"(/api/v1/engine-principals)",                                  StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals"},
    {"DELETE", R"(/api/v1/engine-principals/([^/]+))",                          StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/engine-principals/{id}"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials)",              StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/rotate)",       StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials/rotate"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/credentials/confirm)",      StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/credentials/confirm"},
    {"POST",   R"(/api/v1/engine-principals/([^/]+)/transfer-owner)",           StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/engine-principals/{id}/transfer-owner"},
    {"DELETE", R"(/api/v1/sessions)",                                           StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/sessions"},
    {"POST",   R"(/api/v1/users/([^/]+)/unlock)",                               StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/users/{name}/unlock"},
    {"POST",   R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments)",           StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/rbac/roles/{name}/assignments"},
    {"DELETE", R"(/api/v1/rbac/roles/([A-Za-z0-9._-]+)/assignments/([A-Za-z0-9._-]+))", StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/rbac/roles/{name}/assignments/{principal_id}"},
    {"PUT",    R"(/api/v1/rbac/enforcement)",                                   StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "PUT /api/v1/rbac/enforcement"},
    {"POST",   R"(/api/v1/software-packages)",                                  StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/software-packages"},
    {"POST",   R"(/api/v1/software-deployments/([a-f0-9]+)/start)",             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/software-deployments/{id}/start"},
    {"POST",   R"(/api/v1/guaranteed-state/rules)",                             StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/guaranteed-state/rules"},
    {"PUT",    R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",          StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "PUT /api/v1/guaranteed-state/rules/{id}"},
    {"DELETE", R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))",          StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/v1/guaranteed-state/rules/{id}"},
    {"POST",   R"(/api/v1/guaranteed-state/push)",                              StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/v1/guaranteed-state/push"},
    // Dashboard (guardian_routes.cpp)
    {"POST",   R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/update)",        StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /fragments/guardian/guard/{id}/update"},
    {"POST",   R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/delete)",        StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /fragments/guardian/guard/{id}/delete"},
    // Dashboard (settings_routes.cpp)
    {"DELETE", R"(/api/settings/users/(.+))",                                   StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/settings/users/{username}"},
    {"POST",   R"(/api/settings/users/(.+)/role)",                              StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/settings/users/{username}/role"},
    {"POST",   R"(/api/settings/api-tokens)",                                   StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "POST /api/settings/api-tokens"},
    {"DELETE", R"(/api/settings/api-tokens/(.+))",                              StepUpClass::kRequired, Rollout::kOriginal, step_up_detail::kNoReason, "DELETE /api/settings/api-tokens/{id}"},

    // -- kOwnGate: the handler's own elevation gate is stricter and order-sensitive -----------
    // (auth_routes.cpp `elevation_step_up`; the chokepoint skips these.)
    {"POST",   R"(/api/v1/users/([^/]+)/elevation-eligibility)",                StepUpClass::kOwnGate,  Rollout::kOriginal, step_up_detail::kElevationReason, "POST /api/v1/users/{name}/elevation-eligibility"},
    {"POST",   R"(/api/v1/users/elevation-eligibility)",                        StepUpClass::kOwnGate,  Rollout::kOriginal, step_up_detail::kElevationReason, "POST /api/v1/users/{name}/elevation-eligibility"},
    {"POST",   R"(/api/v1/elevate)",                                            StepUpClass::kOwnGate,  Rollout::kOriginal, step_up_detail::kElevationReason, "POST /api/v1/elevate"},

    // -- APPEND-ONLY REGION ------------------------------------------------------------------
    // Rows for the remaining mutating routes (kExempt with a named reason, or
    // kPendingRuling with the literal "classification pending") are appended below this line.
    // Keep `kPendingRulingMax` equal to the count of kPendingRuling rows.
};
// clang-format on

/// Ceiling on the number of kPendingRuling rows. May only be LOWERED: a new
/// route cannot be parked as pending, it needs a real class.
inline constexpr std::size_t kPendingRulingMax = 0;

inline constexpr std::size_t kStepUpPolicyCount = std::size(kStepUpPolicy);

/// Exact-key lookup. Returns nullptr when `(method, pattern)` is unclassified.
[[nodiscard]] constexpr const StepUpPolicyEntry* step_up_policy_for(std::string_view method,
                                                                    std::string_view pattern) {
    for (const auto& e : kStepUpPolicy) {
        if (e.method == method && e.pattern == pattern)
            return &e;
    }
    return nullptr;
}

/// True when `method` is one of the verbs the table classifies.
[[nodiscard]] constexpr bool is_step_up_table_method(std::string_view method) {
    return method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH";
}

/// Which of the registered mutating routes in `routes` (method, pattern) have no row in the
/// table. Pure. Not yet called at boot: a sweep over the real registrations needs the route
/// inventory, which lands separately (TODO(stage 3): wire once the route inventory exists).
[[nodiscard]] inline std::vector<std::pair<std::string_view, std::string_view>>
step_up_unclassified_routes(
    const std::vector<std::pair<std::string_view, std::string_view>>& routes) {
    std::vector<std::pair<std::string_view, std::string_view>> missing;
    for (const auto& [method, pattern] : routes) {
        if (!is_step_up_table_method(method))
            continue;
        if (step_up_policy_for(method, pattern) == nullptr)
            missing.emplace_back(method, pattern);
    }
    return missing;
}

namespace step_up_detail {

[[nodiscard]] consteval bool table_is_well_formed() {
    std::size_t pending = 0;
    for (std::size_t i = 0; i < kStepUpPolicyCount; ++i) {
        const auto& a = kStepUpPolicy[i];
        if (!is_step_up_table_method(a.method) || a.pattern.empty())
            return false;
        if ((a.cls == StepUpClass::kExempt || a.cls == StepUpClass::kOwnGate) && a.reason.empty())
            return false;
        if (a.cls == StepUpClass::kRequired && a.action_label.empty())
            return false;
        if (a.cls == StepUpClass::kPendingRuling)
            ++pending;
        for (std::size_t j = i + 1; j < kStepUpPolicyCount; ++j) {
            const auto& b = kStepUpPolicy[j];
            if (a.method == b.method && a.pattern == b.pattern)
                return false; // duplicate key
        }
    }
    return pending <= kPendingRulingMax;
}

[[nodiscard]] consteval std::size_t count_class(StepUpClass c) {
    std::size_t n = 0;
    for (const auto& e : kStepUpPolicy)
        n += (e.cls == c) ? 1 : 0;
    return n;
}

} // namespace step_up_detail

static_assert(step_up_detail::table_is_well_formed(),
              "step_up_policy.hpp: duplicate (method, pattern) key, missing reason/label, or more "
              "kPendingRuling rows than kPendingRulingMax");
static_assert(step_up_detail::count_class(StepUpClass::kStrong) == 0,
              "no consumer evaluates kStrong rows yet");
static_assert(step_up_detail::count_class(StepUpClass::kOwnGate) == 3,
              "kOwnGate is closed to the three elevation routes");

} // namespace yuzu::server
