#pragma once

/// THE one header that touches httplib internals for the pre-auth body cap: the header-derived
/// arguments of the cap decision that `httplib::Request`'s own accessors cannot give (httplib
/// reads them with a different rule than `get_header_value`, which returns the FIRST header
/// line), and the close rule that reads a request member httplib sets.
///
/// This lives apart from `web_utils.hpp` and `body_cap_policy.hpp` on purpose: those two stay
/// httplib-free (their request type is a template parameter), and everything below must call
/// httplib's own function or member rather than re-implement it, so that the gate and httplib's
/// body reader cannot disagree about the same bytes. See `evaluate_body_cap` (body_cap_policy.hpp)
/// for the rule that every header-derived argument is the value httplib acts on.
///
/// BUMP CHECKLIST (cpp-httplib): re-check `httplib::detail::get_combined_header_value`,
/// `httplib::detail::is_chunked_transfer_encoding` and `Request::body_consumed_` still exist with
/// the meaning stated at each helper, and that `prepare_content_receiver` still decodes against
/// the combined `Content-Encoding` value.

#include <string>

#include <httplib.h>

#include "web_utils.hpp"

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

/// The `has_content_length` argument `evaluate_body_cap` is given: whether the request carries ANY
/// `Content-Length` line, answered from the header map itself (the value comes from
/// `content_length_for_body_cap`). The body is pinned lexically by test_body_cap_policy.cpp.
[[nodiscard]] inline bool has_content_length_for_body_cap(const httplib::Request& req) {
    const auto cl_range = req.headers.equal_range("Content-Length");
    return cl_range.first != cl_range.second;
}

/// The `is_chunked` argument `evaluate_body_cap` is given: httplib's own decision about whether the
/// request body is chunked (`is_chunked_transfer_encoding`, which reads the final coding of the
/// combined `Transfer-Encoding` list, httplib.h v0.59.0:8441-8470), never a reading of the header
/// text made here. A future httplib bump must re-check the rule has not changed.
[[nodiscard]] inline bool is_chunked_for_body_cap(const httplib::Request& req) {
    return httplib::detail::is_chunked_transfer_encoding(req.headers);
}

/// THE close rule for a response written without reading the request's declared body. The main
/// listener's POST-ROUTING handler calls it on every response (httplib runs that hook for each one,
/// including a pre-routing `Handled` answer), so a new early return cannot forget it; it is the
/// single copy. Nothing happens when the body was consumed (`body_consumed_`), when the status is
/// 400 or more, or when no body was declared. The plaintext redirect listener closes
/// unconditionally instead (health_routes.cpp): its redirect answer closes with or without a
/// declared body.
///
/// DEPENDS ON an httplib 0.59.0 public member: `body_consumed_` is set after the request body is
/// read (httplib.h ~13745). A future httplib bump must re-check that it is still set there and
/// still public. It is set only by `Server::read_content`, not by the content-receiver path: a
/// route taking a `ContentReader` that drained its body would get a spurious close (none exists
/// today).
///
/// WHY: a pre-routing handler answers before httplib reads the request body. From httplib 0.59 a
/// response below 400 that leaves a declared request body unread must carry `Connection: close`
/// (httplib.h v0.59.0:14797-14806); the response therefore closes the connection. httplib sets that
/// header itself for a status of 400 or more (13455-13461), so only a status below 400 is left to
/// us. A request with no declared body is left alone so ordinary keep-alive GETs keep their
/// connection.
inline void close_if_unread_framed_body(const httplib::Request& req, httplib::Response& res) {
    if (res.status >= 400 || req.body_consumed_)
        return;
    if (declares_framed_body(req))
        res.set_header("Connection", "close");
}

} // namespace yuzu::server
