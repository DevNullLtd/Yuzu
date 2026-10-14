#pragma once

/// @file deployments_render.hpp
/// PURE state vocabulary and fragment renderers for the read-only deployment
/// list and detail (`GET /fragments/auto/deployments[/detail]`). The REST v1 and
/// MCP twins share the same `deployment_state()` through the JSON builders in
/// deployment_routes.hpp, so the three surfaces cannot disagree about a state.
///
/// Vocabulary only: the live `/auto` engine has exactly two lifecycle states,
/// `running` and `complete`. There is no staged, cancelled or rolled-back state
/// in this model, and none is invented here. Every dynamic string is escaped.

#include "deployment_run_store.hpp"

#include <string>
#include <vector>

namespace yuzu::server {

/// A deployment's display state: a stable machine `code`, the operator-facing
/// `label`, and a pill `tone` (ok | warn | info | idle).
struct DeploymentState {
    std::string code;
    std::string label;
    std::string tone;
};

/// PURE. `status` is the store's lifecycle token. A finished deployment that had
/// failures reads "Complete, N failed" (failures take priority over skips), one
/// with only skips reads "Complete, N skipped"; an unknown token is "Unknown",
/// never a guess.
DeploymentState deployment_state(const std::string& status, int failed, int skipped);

/// The list table. `target_labels` is parallel to `rows` (the source pre-flight
/// run's scope label); an empty entry means the run aged out of retention and
/// reads "Run no longer kept", never blank. Empty `rows` renders the empty copy.
std::string render_deployments_list(const std::vector<DeploymentRow>& rows,
                                    const std::vector<std::string>& target_labels);

/// The read-only detail for one deployment: summary, exact counts from the run row,
/// and the device grid (a note says so when it shows fewer rows than `dep.total`).
std::string render_deployment_detail(const DeploymentRow& dep,
                                     const std::vector<DeploymentDeviceRow>& devices);

/// A store fault: never an empty table. `what` is fixed server text, not user input.
std::string render_deployments_failbox(const std::string& what);

} // namespace yuzu::server
