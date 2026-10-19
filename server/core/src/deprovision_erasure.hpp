#pragma once

/// @file deprovision_erasure.hpp
///
/// The post-deprovision personal-data erasure hook (ADR-0071; Gate 6 comp-4). A deprovision seam
/// (SCIM `active:false` / `DELETE .../Users/{id}` / create-with-`active:false` in
/// `scim_routes.cpp`, and the dashboard `DELETE /api/settings/users/{username}` in
/// `settings_routes.cpp`) calls `run_deprovisioned_hook` ONCE, AFTER its own outcome is decided
/// and committed, with the principal set it resolved through `deprovision_revoke.hpp`
/// (the slug plus every linked `oidc:`/`saml:` principal - each one can key a session, and so a
/// per-operator row such as a /crypto dashboard layout).
///
/// DELIBERATELY OUTSIDE the ADR-2001 revoke chokepoint (`deprovision_revoke.{hpp,cpp}`): the
/// hook is a best-effort side effect and can NEVER change a revoke or deprovision outcome. It
/// runs after the seam has already committed (and never on a refused or failed deprovision), it
/// returns nothing, it never throws (an exception is caught and logged here), and whatever the
/// callback does on failure it does by logging at warn and counting - never by failing the
/// request. A seam with no hook wired (tests, a server without the consuming store) skips it.
///
/// The callback must never log a principal at info or above (a principal is a username or an
/// IdP identifier - personal data).
///
/// LATENCY: the hook runs SYNCHRONOUSLY on the deprovisioning request's thread, before its
/// response is sent. The /crypto layout erasure is one keyed DELETE per principal, each waiting
/// at most the layout store's 2 s lease bound when the pool is saturated - so a degraded
/// database can add up to 2 s per principal (slug + linked identities) to the deprovision's
/// response time, never a failure. A consumer whose erasure could take longer must not run
/// inline here.
///
/// RESIDUAL (ADR-0071): a layout save already in flight when the erasure runs can re-insert the
/// row after it (the session that made it is being revoked by the same deprovision, but its
/// request may already be past authentication). The remedy is the periodic check documented in
/// docs/user-manual/crypto.md, "Deprovision erasure".

#include <spdlog/spdlog.h>

#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Receives the deprovisioned principal set. Best-effort: see the file comment.
using DeprovisionedFn = std::function<void(const std::vector<std::string>& principals)>;

/// Run `fn` (when set) over `principals`, swallowing and logging any exception so a broken
/// erasure can never reach the deprovision's response.
inline void run_deprovisioned_hook(const DeprovisionedFn& fn,
                                   const std::vector<std::string>& principals) noexcept {
    if (!fn || principals.empty())
        return;
    try {
        fn(principals);
    } catch (const std::exception& e) {
        spdlog::warn("deprovision erasure hook threw ({}); the deprovision outcome is unchanged",
                     e.what());
    } catch (...) {
        spdlog::warn("deprovision erasure hook threw a non-standard exception; the deprovision "
                     "outcome is unchanged");
    }
}

} // namespace yuzu::server
