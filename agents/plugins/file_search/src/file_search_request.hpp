/**
 * file_search_request.hpp -- the parameters of one search call, parsed and validated. Pure: it touches no
 * OS and opens no path, so every refusal here costs no syscall. The agent is the trust boundary:
 * direct command dispatch bypasses the definition's schema, so this runs before anything else.
 *
 * PARAMETERS (a missing parameter reads as ""):
 *   root     mandatory. The POSIX form (normalise_root): absolute, at most kMaxRootBytes, no NUL, no "//",
 *            no "." or ".." component. One trailing '/' is stripped; "/" is the whole filesystem. The
 *            Windows form is the OS shell's own normaliser (file_search_win_rules.hpp), handed to
 *            parse_request: it answers the same canonical '/'-joined label shape. A root that is a link,
 *            missing or not a directory is the driver's to answer, from the leg, because that needs the
 *            filesystem.
 *   pattern  mandatory. The leaf-name glob of file_search_query.hpp ('*' and '?', no regex), compiled with
 *            the leg's name rule.
 *   kinds    files (default), directories or both.
 *   cursor   the token of the previous slice; empty for the first. Its length is bounded here, its
 *            content is decoded (and refused if forged) by the driver, which holds the query hash.
 *
 * ERROR TOKENS are a closed set: they are what the `search` trailer says on an invalid call, including
 * the three root tokens the driver emits from the leg's answer.
 */
#pragma once

#include <file_search_query.hpp>

#include "file_search_rows.hpp"

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::file_search {

enum class RequestError {
    missing_root,
    root_not_absolute,
    root_too_long,
    root_bad_component,
    root_unc,         // Windows: a UNC or network root, never searched
    root_device_path, // Windows: a device or NT-namespace root other than a volume GUID path
    missing_pattern,
    pattern_too_long,
    pattern_too_many_stars,
    pattern_too_few_literals,
    pattern_forbidden_byte,
    bad_kinds,
    bad_cursor,
    // emitted by the driver from the leg's root_state, never by parse_request
    root_is_link,
    root_not_found,
    root_not_a_directory
};

[[nodiscard]] constexpr const char* to_token(RequestError e) noexcept {
    switch (e) {
    case RequestError::missing_root:
        return "missing_root";
    case RequestError::root_not_absolute:
        return "root_not_absolute";
    case RequestError::root_too_long:
        return "root_too_long";
    case RequestError::root_bad_component:
        return "root_bad_component";
    case RequestError::root_unc:
        return "root_unc";
    case RequestError::root_device_path:
        return "root_device_path";
    case RequestError::missing_pattern:
        return "missing_pattern";
    case RequestError::pattern_too_long:
        return "pattern_too_long";
    case RequestError::pattern_too_many_stars:
        return "pattern_too_many_stars";
    case RequestError::pattern_too_few_literals:
        return "pattern_too_few_literals";
    case RequestError::pattern_forbidden_byte:
        return "pattern_forbidden_byte";
    case RequestError::bad_kinds:
        return "bad_kinds";
    case RequestError::bad_cursor:
        return "bad_cursor";
    case RequestError::root_is_link:
        return "root_is_link";
    case RequestError::root_not_found:
        return "root_not_found";
    case RequestError::root_not_a_directory:
        return "root_not_a_directory";
    }
    return "bad_cursor";
}

/// The longest cursor token accepted: the fs1 token plus the volume prefix around it.
inline constexpr std::size_t kMaxRequestCursorBytes = fsr::kMaxCursorTokenBytes + 128;
static_assert(kMaxRequestCursorBytes <= 64 * 1024,
              "a cursor longer than the server's per-parameter cap (kMaxParamValueLen, bundle_service.hpp) "
              "could not be passed back on any surface");

struct Request {
    fsr::Query query;   // pattern (compiled), kinds, root (normalised)
    std::string cursor; // empty for the first slice
};

/// The root a request may carry, normalised, or the reason it may not (the POSIX rule).
[[nodiscard]] inline std::expected<std::string, RequestError> normalise_root(std::string_view raw) {
    if (raw.empty())
        return std::unexpected(RequestError::missing_root);
    if (raw.front() != '/')
        return std::unexpected(RequestError::root_not_absolute);
    if (raw.size() > kMaxRootBytes)
        return std::unexpected(RequestError::root_too_long);
    if (raw.find('\0') != std::string_view::npos || raw.find("//") != std::string_view::npos)
        return std::unexpected(RequestError::root_bad_component);
    std::string root(raw);
    if (root.size() > 1 && root.back() == '/')
        root.pop_back();
    for (std::size_t pos = 1; pos < root.size();) {
        std::size_t end = root.find('/', pos);
        if (end == std::string::npos)
            end = root.size();
        const std::string_view comp = std::string_view{root}.substr(pos, end - pos);
        if (comp.empty() || comp == "." || comp == "..")
            return std::unexpected(RequestError::root_bad_component);
        pos = end + 1;
    }
    return root;
}

/// The root normaliser of an OS: the POSIX rule above, or the Windows one in file_search_win_rules.hpp.
using RootNormaliser = std::expected<std::string, RequestError> (*)(std::string_view);

[[nodiscard]] inline std::expected<Request, RequestError>
parse_request(std::string_view root, std::string_view pattern, std::string_view kinds, std::string_view cursor,
              const fsr::NameSemantics& semantics, RootNormaliser normalise = &normalise_root) {
    auto r = normalise(root);
    if (!r)
        return std::unexpected(r.error());

    auto p = fsr::Pattern::compile(pattern, semantics);
    if (!p) {
        switch (p.error()) {
        case fsr::PatternError::empty:
            return std::unexpected(RequestError::missing_pattern);
        case fsr::PatternError::too_long:
            return std::unexpected(RequestError::pattern_too_long);
        case fsr::PatternError::too_many_stars:
            return std::unexpected(RequestError::pattern_too_many_stars);
        case fsr::PatternError::too_few_literals:
            return std::unexpected(RequestError::pattern_too_few_literals);
        case fsr::PatternError::forbidden_byte:
            return std::unexpected(RequestError::pattern_forbidden_byte);
        }
        return std::unexpected(RequestError::pattern_forbidden_byte);
    }

    fsr::Kinds k = fsr::Kinds::files;
    if (kinds.empty() || kinds == "files")
        k = fsr::Kinds::files;
    else if (kinds == "directories")
        k = fsr::Kinds::directories;
    else if (kinds == "both")
        k = fsr::Kinds::both;
    else
        return std::unexpected(RequestError::bad_kinds);

    if (cursor.size() > kMaxRequestCursorBytes)
        return std::unexpected(RequestError::bad_cursor);

    return Request{fsr::Query{std::move(*p), k, std::move(*r)}, std::string(cursor)};
}

} // namespace yuzu::file_search
