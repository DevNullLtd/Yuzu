#pragma once

/// @file content_etag.hpp
///
/// The one content-derived strong ETag used by the cacheable catalogue routes (the discovery
/// documents, the Guardian schema registry and the OpenAPI document). Three TU-local copies of
/// this function existed; they computed the same value, so sharing it changes no ETag.

#include <cstdint>
#include <cstdio>
#include <string>

namespace yuzu::server {

/// FNV-1a 64-bit over `body`, rendered as a quoted lowercase-hex strong ETag, so an edit to the
/// body invalidates caches with no manual version bump.
[[nodiscard]] inline std::string content_etag(const std::string& body) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : body) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[19];
    const int n = std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return std::string(buf, static_cast<std::size_t>(n));
}

} // namespace yuzu::server
