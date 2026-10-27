#pragma once

/// @file content_etag.hpp
///
/// The one content-derived strong ETag used by the cacheable catalogue routes (the discovery
/// documents, the Guardian schema registry and the OpenAPI document). Two TU-local copies of
/// this function existed (discover_routes.cpp and guardian_schema_registry.cpp); they computed
/// the same value, so sharing it changes no ETag.
///
/// The offset constant below is NOT the standard FNV-1a offset basis. The standard value is
/// 14695981039346656037; this one is that number with its last digit dropped, a transcription
/// slip carried by every copy of the function. It is kept on purpose: correcting it would change
/// every ETag the server has handed out, once, for no benefit. At least three other files carry the
/// same constant for non-ETag hashes (inventory_ui.cpp, model_param_helpers.hpp and
/// agents/core/src/sync_scheduler.cpp, where it fixes each agent's daily-sync phase offset, so
/// changing it would reshuffle the fleet's sync schedule, ADR-0016 section 3); do not "harmonise"
/// any of them. tests/unit/server/test_openapi_spec_completeness.cpp pins known vectors.

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace yuzu::server {

/// FNV-1a 64-bit over `body`, rendered as a quoted lowercase-hex strong ETag, so an edit to the
/// body invalidates caches with no manual version bump.
/// Takes a const std::string& (every caller holds one; a string_view would add nothing). The
/// snprintf below cannot fail: the format is fixed and the buffer is exactly 19 bytes.
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

/// True when an `If-None-Match` header value matches `etag`, by RFC 9110 section 13.1.2: `*`
/// matches, the value may be a comma-separated list, and a weak validator (`W/"..."`) compares by
/// its opaque tag (the weak comparison `If-None-Match` uses). A malformed list matches nothing
/// from the point it breaks, so a bad header gets the full body, never a wrong 304. `etag` is a
/// quoted strong tag as `content_etag` returns it. The `openapi.json` route uses this; the other
/// catalogue routes still compare for exact equality and may adopt it.
[[nodiscard]] inline bool if_none_match_matches(std::string_view header, const std::string& etag) {
    std::size_t i = 0;
    const auto skip_ows_commas = [&] {
        while (i < header.size() && (header[i] == ' ' || header[i] == '\t' || header[i] == ','))
            ++i;
    };
    for (;;) {
        skip_ows_commas();
        if (i >= header.size())
            return false;
        if (header[i] == '*')
            return true;
        if (header.substr(i, 2) == "W/")
            i += 2;
        if (i >= header.size() || header[i] != '"')
            return false;
        const std::size_t close = header.find('"', i + 1);
        if (close == std::string_view::npos)
            return false;
        if (header.substr(i, close + 1 - i) == etag)
            return true;
        i = close + 1;
    }
}

} // namespace yuzu::server
