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

#include <cstddef>
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

/// True when an `If-None-Match` header value matches `etag`, by RFC 9110 section 13.1.2: the value
/// is either `*` alone, or a comma-separated list of entity-tags, where a weak validator
/// (`W/"..."`) compares by its opaque tag (the weak comparison `If-None-Match` uses). Empty list
/// elements and optional whitespace around the commas are accepted, as the RFC asks of a recipient.
/// The header is parsed as a whole: if any part of it is not a valid entity-tag list (`*` with
/// anything else, a missing comma between tags, an unquoted or unterminated tag, text after a tag),
/// nothing matches, so a bad header gets the full body, never a 304. The characters inside a quoted
/// tag are not validated beyond the closing quote (a tag holding a space still parses): only the
/// header's overall shape is checked. `etag` is a quoted strong tag as `content_etag` returns it.
/// The `openapi.json` route uses this; the other catalogue routes still compare for exact equality
/// and may adopt it. Linear in the header length.
[[nodiscard]] inline bool if_none_match_matches(std::string_view header, const std::string& etag) {
    const std::size_t n = header.size();
    std::size_t i = 0;
    const auto skip_ows = [&] {
        while (i < n && (header[i] == ' ' || header[i] == '\t'))
            ++i;
    };
    skip_ows();
    if (i < n && header[i] == '*') {
        ++i;
        skip_ows();
        return i == n;
    }
    bool matched = false;
    for (;;) {
        while (i < n && (header[i] == ' ' || header[i] == '\t' || header[i] == ','))
            ++i;
        if (i >= n)
            return matched;
        if (header.substr(i, 2) == "W/")
            i += 2;
        if (i >= n || header[i] != '"')
            return false;
        const std::size_t close = header.find('"', i + 1);
        if (close == std::string_view::npos)
            return false;
        if (header.substr(i, close + 1 - i) == etag)
            matched = true;
        i = close + 1;
        skip_ows();
        if (i < n && header[i] != ',')
            return false;
    }
}

} // namespace yuzu::server
