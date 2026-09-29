// Test-only definition of ClassifiedCommandTestAccess::make (#2367 pattern).
//
// ClassifiedCommand's constructor is private; the private ctor has no public
// trampoline in server_core — production reaches it ONLY through the friend
// ServerImpl::build_classified_command (the one dispatch-chokepoint builder,
// server.cpp). Tests need to construct fixture ClassifiedCommand values
// directly, so the header declares a friend `struct ClassifiedCommandTestAccess`
// with a static forwarder -- but the forwarder is DEFINED here, in a TU that
// links only into the test binary, not into server_core. A production caller
// that references it therefore fails to LINK, which is what upgrades the
// production/test split from a doc-comment convention to a structural,
// compile/link-time-enforced control (mirrors #2367's EngineLivenessTestAccess,
// engine_principal_store.cpp — identical rationale).
//
// Keep this file minimal: it exists solely to host that one definition off the
// production link line.

#include "agent_registry.hpp"

namespace yuzu::server::detail {

ClassifiedCommand ClassifiedCommandTestAccess::make(pb::CommandRequest cmd) {
    return ClassifiedCommand(std::move(cmd));
}

} // namespace yuzu::server::detail
