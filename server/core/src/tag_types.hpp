#pragma once

/// @file tag_types.hpp
/// Plain value types for device tags (`DeviceTag`, `TagReadError`), split out of
/// `tag_store.hpp` so the hardware read model and the MCP registry lane can name a tag
/// row without including a store header (ADR-0031 seam closure, #6558).
/// `tag_store.hpp` re-includes this header, so existing includers are unaffected. No
/// behaviour lives here — the store keeps its class and every query.

#include <cstdint>
#include <string>

namespace yuzu::server {

struct DeviceTag {
    std::string agent_id;
    std::string key;
    std::string value;
    std::string source;    // "agent", "server", "api", "mcp"
    int64_t updated_at{0}; // epoch seconds
};

/// Error type for the authoritative reads. The success type is an
/// `std::optional<T>`/container: a value == found, absent/empty == the read
/// succeeded and there is genuinely nothing there. `std::unexpected(kDegraded)`
/// == store/pool/query failure — the caller MUST NOT treat this the same as
/// "not found"/"no tags" on any path that feeds a scope/dispatch/confinement
/// decision (`tag:<key>` resolution, service-scoped token confinement).
enum class TagReadError { kDegraded };

} // namespace yuzu::server
