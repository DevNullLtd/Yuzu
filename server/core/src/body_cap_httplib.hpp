#pragma once

/// Header-derived arguments of the pre-auth body-cap decision that cannot be read through
/// `httplib::Request`'s own accessors, because httplib reads them with a different rule than
/// `get_header_value` (which returns the FIRST header line).
///
/// This lives apart from `web_utils.hpp` and `body_cap_policy.hpp` on purpose: those two stay
/// httplib-free (their request type is a template parameter), and the helper below must call
/// httplib's own function rather than re-implement it, so that the gate and httplib's body reader
/// cannot disagree about the same bytes. See `evaluate_body_cap` (body_cap_policy.hpp) for the
/// rule that every header-derived argument is the value httplib acts on.

#include <string>

#include <httplib.h>

namespace yuzu::server {

/// The `content_encoding` argument `evaluate_body_cap` is given: the SAME combined value httplib's
/// body reader decodes against (`prepare_content_receiver`, httplib.h 0.59.0), which joins every
/// non-empty `Content-Encoding` line with ", ". `get_header_value` reads only the first line, so
/// a request sent as an empty `Content-Encoding:` line followed by `Content-Encoding: br` reads
/// as "no encoding" through it while httplib still decodes. 0.37.1 read the first line in both
/// places; 0.59.0 does not, so this accessor is part of the bump. A future httplib bump must
/// re-check that `prepare_content_receiver` still decodes against this combined value.
[[nodiscard]] inline std::string content_encoding_for_body_cap(const httplib::Request& req) {
    return httplib::detail::get_combined_header_value(req.headers, "Content-Encoding");
}

} // namespace yuzu::server
