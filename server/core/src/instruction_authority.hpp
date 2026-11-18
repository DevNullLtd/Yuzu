#pragma once

/// @file instruction_authority.hpp
/// The request principal's authority over ONE instruction id, shared by every surface that stores
/// a policy fragment (`POST /api/policy-fragments`, `POST /api/product-packs`). A fragment's
/// check / postCheck / fix instruction later runs through the evaluator as the SYSTEM caller, so
/// per-action RBAC, the `ExecuteGate` and per-device visibility are not consulted at fire time.
/// The closure resolves the instruction id to its (plugin, action), runs the SHARED
/// `authorize_dispatch` dry run for the request's principal as a NON-system caller, and reports the
/// principal's execution visibility. server.cpp defines it ONCE and hands the same closure to every
/// storing surface; an unwired closure REFUSES (fail closed). A new route that stores a fragment
/// must take this closure and pass the resulting pairs to `PolicyStore::create_fragment`, which
/// has no default for them.

#include "authz_model.hpp"

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {

struct InstructionAuthority {
    bool ok{false};
    int status{403};           ///< HTTP status to answer when !ok (401/403/400/503)
    std::string message;       ///< operator-facing refusal text when !ok
    std::string plugin_action; ///< "plugin.action" the instruction id resolved to (when ok)
    authz::VisibleSet visible{authz::deny_all()}; ///< exec visibility (nullopt = unrestricted)
};

using AuthorizeInstructionFn =
    std::function<InstructionAuthority(const httplib::Request&, const std::string& instruction_id)>;

} // namespace yuzu::server
