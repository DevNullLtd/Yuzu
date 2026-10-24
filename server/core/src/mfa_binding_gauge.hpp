#pragma once

/**
 * mfa_binding_gauge.hpp -- the binding-enforcement health gauge (#6079).
 *
 * `yuzu_auth_mfa_binding_enforcement_ok{store="auth"|"session"}` is 1 while the factor-generation
 * trigger (`auth`) and the session rebind guard (`session`) have not been observed failing, and
 * 0 once a validation has seen either missing, disabled, replica-only or altered. Both flags are
 * STICKY until restart (a re-enabled trigger cannot reconstruct the changes it missed), so the
 * gauge never returns to 1 on its own; a restart whose boot check passes is the way back.
 *
 * The gauge reads the in-process flags, it does not run a validation. Validation is
 * request-driven (`AuthDB::mfa_status`, `SessionStore::find`, behind a 60 s memo), so a tamper
 * that no request has observed yet still reads 1. While it reads 0, every local MFA binding
 * decision (the central step-up check, the in-handler gate, the approver gate) answers
 * store-unavailable with `reason=mfa_binding_unenforced`.
 *
 * Pure decision plus a metrics write: no I/O, no store access beyond the two atomic reads.
 */

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>

#include "session_store.hpp"

namespace yuzu::server {

inline constexpr const char* kMfaBindingEnforcementGauge = "yuzu_auth_mfa_binding_enforcement_ok";

/// Registers the HELP/TYPE text. The series are published by `publish_mfa_binding_gauges`.
inline void describe_mfa_binding_gauge(yuzu::MetricsRegistry& metrics) {
    metrics.describe(kMfaBindingEnforcementGauge,
                     "1 while the MFA factor-generation binding is enforced for the store "
                     "(auth: the users generation trigger; session: the session rebind guard), "
                     "0 once a validation observed it not in force (sticky until restart; "
                     "local MFA binding decisions then fail closed with 503)",
                     "gauge");
}

/// Samples both flags. A null store publishes nothing for its label (no false healthy value).
inline void publish_mfa_binding_gauges(yuzu::MetricsRegistry& metrics, const AuthDB* auth_db,
                                       const SessionStore* session_store) {
    if (auth_db) {
        metrics.gauge(kMfaBindingEnforcementGauge, {{"store", "auth"}})
            .set(auth_db->mfa_binding_enforced() ? 1.0 : 0.0);
    }
    if (session_store) {
        metrics.gauge(kMfaBindingEnforcementGauge, {{"store", "session"}})
            .set(session_store->rebind_guard_ok() ? 1.0 : 0.0);
    }
}

} // namespace yuzu::server
