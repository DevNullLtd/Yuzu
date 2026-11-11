#pragma once

/// @file http_response_policy.hpp
/// Two response rules applied to every handler `HttplibRouteSink` registers (after the post-read
/// stage, around the handler), kept in one unit so the sink header stays small.
///
/// HEAD. httplib routes a HEAD request to the GET table, so a HEAD on a dynamic route would run the
/// whole handler (a store read, a render) only to discard the body. Outside the pre-session exempt
/// paths a HEAD is answered `405` with `Allow: GET` and the handler is not run. This is a deliberate
/// deviation from RFC 9110 section 9.1 (a general-purpose server MUST support HEAD), which that RFC
/// allows only for a resource that does not answer GET; and section 15.5.6 says an `Allow` header
/// lists every method the resource supports, while this one names GET only (listing the others would
/// mean reading the route table from inside the step-up chokepoint for a rarely hit answer). Probes,
/// static assets, sign-in pages and the public CA files keep answering HEAD.
///
/// Compression. httplib encodes a dynamic body with brotli at quality 11, which costs seconds of one
/// worker's CPU for a multi-megabyte page. A body httplib would brotli-encode is encoded here first,
/// at `kDynamicBrotliQuality`; the body then carries `Content-Encoding: br`, which makes httplib skip
/// its own pass. The set of responses that are compressed does not change (the decision is httplib's
/// own `encoding_type`). Chunked and ranged responses and file-backed content still take httplib's
/// own path.

#include <httplib.h>

#include <string>
#include <string_view>

namespace yuzu::server {

/// Brotli quality for a dynamic body. Measured on one Apple M4 core with a 2.5 MB server-rendered Apps
/// page and a 2.5 MB JSON body (best of three, ms for the whole body: bytes at that quality):
///   quality  4:  4 ms /  153,569 and 11 ms / 443,603    quality  9:  18 ms / 133,201 and  57 ms / 450,329
///   quality  5:  9 ms /  138,803 and 26 ms / 466,539    quality 10: 636 ms / 126,208 and 1,054 ms / 395,258
///   quality  6: 11 ms /  137,009 and 26 ms / 460,110    quality 11: 2,465 ms / 110,473 and 2,748 ms / 367,465
/// No quality below 10 is within 10 percent of quality 11's size, and quality 10 and above cost 70 to 120
/// times as much worker time; quality 5 is the cheap end of the plateau (qualities 5 to 9 differ in size
/// by under 6 percent, and 9 costs twice as much). The output is about 25 percent larger than quality 11's.
inline constexpr int kDynamicBrotliQuality = 5;

/// True for the paths that keep answering HEAD: the unauthenticated probes, static assets, sign-in
/// pages and the public CA files (`health::is_probe_path` or `is_login_exempt_path`).
[[nodiscard]] bool head_runs_handler(std::string_view path);

/// Brotli-encodes `in` at `quality` (window 22, generic mode) into `out`. False leaves `out`
/// untouched.
[[nodiscard]] bool brotli_compress(std::string_view in, int quality, std::string& out);

/// Encodes `res.body` with brotli when httplib itself would (same negotiation) and the response is a
/// plain body: not empty, no content provider or file content, no Range request. Sets
/// `Content-Encoding: br` and `Vary: Accept-Encoding`. On failure does nothing (httplib then encodes
/// as before).
void apply_dynamic_compression(const httplib::Request& req, httplib::Response& res);

/// `h` behind the two rules above: HEAD on a path that does not run the handler answers 405 with
/// `Allow: GET` and returns without calling `h`; otherwise `h` runs and the body is then encoded.
[[nodiscard]] httplib::Server::Handler with_response_policy(httplib::Server::Handler h);

} // namespace yuzu::server
