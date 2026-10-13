#pragma once

/// @file gateway_peer_flags.hpp
/// The flag and environment-variable spellings of the gateway-upstream peer
/// authorization knobs, as plain string constants with NO dependencies.
///
/// They live apart from `server_gateway_peer_options.hpp` (which registers the
/// options with CLI11 and needs `server.hpp`) so that code which only has to NAME a
/// flag in a message, such as the boot resolution, does not pull the command-line
/// library into its translation unit. The names are contract: they appear in the
/// operator documentation, in the boot refusal messages and in every shipped rig,
/// and `test_server_gateway_peer_options.cpp` pins them.

#include <string_view>

namespace yuzu::server {

inline constexpr std::string_view kGatewayPeerPinFlag = "--gateway-peer-pin";
inline constexpr std::string_view kGatewayPeerPinFileFlag = "--gateway-peer-pin-file";
inline constexpr std::string_view kInsecureGatewayPeerFlag = "--insecure-gateway-peer";

inline constexpr std::string_view kGatewayPeerPinEnv = "YUZU_GATEWAY_PEER_PINS";
inline constexpr std::string_view kGatewayPeerPinFileEnv = "YUZU_GATEWAY_PEER_PIN_FILE";
inline constexpr std::string_view kInsecureGatewayPeerEnv = "YUZU_INSECURE_GATEWAY_PEER";

} // namespace yuzu::server
