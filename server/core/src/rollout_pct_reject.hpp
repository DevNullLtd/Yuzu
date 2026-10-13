#pragma once

// The ONE response a rejected OTA `rollout_pct` gets, shared by BOTH routes that read it: the
// package UPLOAD route (multipart, which the unit-test route sink cannot drive), which rejects a
// malformed percentage, and the ROLLOUT route, which also rejects an empty or above-100 one
// (`parse_rollout_pct_strict`). A rejected percentage must never fall back to the 100% default
// (a full-fleet rollout nobody asked for), so both answer 400 with nothing stored or changed. Sharing the response
// means the toast + A4 body are unit-testable without a multipart request, and the two sites
// cannot drift apart (#4644).
//
// The toast text is built only from the enum below, never from request input: it is a header
// value, so a caller-supplied string here would be header injection.

#include "rest_a4_envelope_http.hpp"

#include <httplib.h>

namespace yuzu::server {

/// What the rejected request would otherwise have done, for the operator-facing toast.
enum class RolloutRejectEffect { kStored, kChanged };

inline void reject_bad_rollout_pct(httplib::Response& res, RolloutRejectEffect effect) {
    res.status = 400;
    res.set_header(
        "HX-Trigger",
        effect == RolloutRejectEffect::kStored
            ? R"({"showToast":{"message":"Invalid rollout percentage - nothing was stored","level":"error"}})"
            : R"({"showToast":{"message":"Invalid rollout percentage - nothing was changed","level":"error"}})");
    res.set_content(detail::a4_error(res, "invalid numeric parameter: rollout_pct"),
                    "application/json");
}

} // namespace yuzu::server
