/**
 * mgmt_posture_macos.cpp -- macOS leg: MDM enrolment via
 * `/usr/bin/profiles status -type enrollment` (rung 2 argv, bounded runner).
 *
 * No public API exposes enrolment state and /var/db/ConfigurationProfiles/Store is not
 * permitted, so the tool is the mechanism. This TU is only the runner binding; the
 * classification is `posture_macos` in mgmt_posture_legs.hpp: a tool that could not be
 * started is UNAVAILABLE (an `unsupported` row); any other runner failure, a nonzero exit,
 * truncation or unrecognised output is CONSTRAINED; neither carries data rows. AD binding
 * is device_identity.domain.
 */
#include "mgmt_posture_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::mgmt_posture {

int run_macos(yuzu::CommandContext& ctx) {
    report_posture(ctx, posture_macos([](const auto& argv, const auto& opts) {
        // sink: mgmt_posture/run_macos#1 -- /usr/bin/profiles status -type enrollment (rung 2 argv; no public API, /var/db/ConfigurationProfiles/Store is not permitted)
        return yuzu::agent::run_bounded_subprocess(argv, opts);
    }));
    return 0;
}

} // namespace yuzu::mgmt_posture

#endif // defined(__APPLE__)
