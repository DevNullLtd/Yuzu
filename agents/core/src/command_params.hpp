#pragma once

/// @file command_params.hpp
/// `command_params_have_nul`: the ONE pure predicate the agent applies to a command's parameter map
/// before it dedups, sleeps a stagger, or builds the plugin's `YuzuParam` array (sg10 / UP-1).
///
/// The agent hands every key and value to a plugin as a C string (`c_str()`) and the SDK compares C
/// strings, so a key `targets\0x` is read by the plugin as `targets` while a server gate keyed on
/// the exact name misses it. The server refuses such a parameter at its ingress; this is the
/// agent-side defence in depth, and it must run BEFORE the dedup claim and the stagger sleep so a
/// refused command neither leaves an in-flight record nor holds a worker. EXTEND this, never copy
/// the loop at a call site. Works on any map-like of string pairs (protobuf `Map`, `std::map`).

#include <string>

namespace yuzu::agent {

template <typename Map>
[[nodiscard]] bool command_params_have_nul(const Map& params) {
    for (const auto& [k, v] : params) {
        if (k.find('\0') != std::string::npos || v.find('\0') != std::string::npos)
            return true;
    }
    return false;
}

} // namespace yuzu::agent
