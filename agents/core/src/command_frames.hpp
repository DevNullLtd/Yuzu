#pragma once

// CommandResponse frame construction, kept in one header so a test can include it and pin the stamp
// itself (the agent's call sites are not reachable from a unit test). Why `action` rides on the
// wire: see CommandResponse.action in proto/yuzu/agent/v1/agent.proto.

#include <string>
#include <utility>

#include "agent.pb.h" // ::yuzu::agent::v1::CommandResponse

namespace yuzu::agent {

/// An ordinary RUNNING output frame. An empty `action` is the proto3 default (unset on the wire).
[[nodiscard]] inline ::yuzu::agent::v1::CommandResponse
make_output_frame(const std::string& command_id, const std::string& action, std::string output) {
    ::yuzu::agent::v1::CommandResponse resp;
    resp.set_command_id(command_id);
    resp.set_status(::yuzu::agent::v1::CommandResponse::RUNNING);
    resp.set_output(std::move(output));
    resp.set_action(action);
    return resp;
}

/// The terminal frame. SUCCESS iff rc == 0, FAILURE otherwise; carries the exit code and the
/// dispatched action (an empty action is the proto3 default, unset on the wire).
[[nodiscard]] inline ::yuzu::agent::v1::CommandResponse
make_final_frame(const std::string& command_id, const std::string& action, int rc) {
    ::yuzu::agent::v1::CommandResponse resp;
    resp.set_command_id(command_id);
    resp.set_status(rc == 0 ? ::yuzu::agent::v1::CommandResponse::SUCCESS
                            : ::yuzu::agent::v1::CommandResponse::FAILURE);
    resp.set_exit_code(rc);
    resp.set_action(action);
    return resp;
}

} // namespace yuzu::agent
