// Test-only definition of EngineLivenessTestAccess::revalidate (#2367).
//
// EnginePrincipalStore::get_for_auth_revalidate is private, reachable in
// production ONLY through the friend AuthRoutes::engine_credential_state (the
// per-tick stream liveness re-check). Tests need to drive the cached path
// directly, so the header declares a friend `struct EngineLivenessTestAccess`
// with a static forwarder -- but the forwarder is DEFINED here, in a TU that
// links only into the test binary, not into server_core. A production caller
// that references it therefore fails to LINK, which is what upgrades the
// cached/uncached split from a doc-comment convention to a structural,
// compile/link-time-enforced control (governance architect finding).
//
// Keep this file minimal: it exists solely to host that one definition off the
// production link line.

#include "engine_principal_store.hpp"

namespace yuzu::server {

EngineRevalidate EngineLivenessTestAccess::revalidate(const EnginePrincipalStore& store,
                                                      const std::string& principal_id) {
    return store.get_for_auth_revalidate(principal_id);
}

} // namespace yuzu::server
