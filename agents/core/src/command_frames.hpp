#pragma once

// CommandResponse frame construction, kept in one header so a test can include it and pin the stamp
// itself (the agent's call sites are not reachable from a unit test). Why `action` rides on the
// wire: see CommandResponse.action in proto/yuzu/agent/v1/agent.proto.

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include "agent.pb.h" // ::yuzu::agent::v1::CommandResponse

namespace yuzu::agent {

/// The largest single plugin output line sent in one frame. The server's stock gRPC receive limit is
/// 4 MiB and a message over it answers RESOURCE_EXHAUSTED, which ends the whole Subscribe stream
/// (protective commands included), so one plugin line is cut here with a marker instead.
inline constexpr std::size_t kMaxOutputLineBytes = 2ull * 1024 * 1024;
inline constexpr std::string_view kOutputLineTruncatedMarker = "...[truncated: output line over 2 MiB]";

/// `text` cut to at most `kMaxOutputLineBytes` (marker included) at a UTF-8 character boundary, so
/// the proto string field stays valid UTF-8. A line within the cap is returned unchanged.
[[nodiscard]] inline std::string clamp_output_line(std::string_view text) {
    if (text.size() <= kMaxOutputLineBytes)
        return std::string{text};
    std::size_t cut = kMaxOutputLineBytes - kOutputLineTruncatedMarker.size();
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80)
        --cut; // never end inside a multi-byte sequence
    std::string out{text.substr(0, cut)};
    out.append(kOutputLineTruncatedMarker);
    return out;
}

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
