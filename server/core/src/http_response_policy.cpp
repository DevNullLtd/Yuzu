#include "http_response_policy.hpp"

#include "health_routes.hpp" // health::is_probe_path
#include "web_utils.hpp"     // is_login_exempt_path

#include <brotli/encode.h>

#include <utility>

namespace yuzu::server {

namespace {
constexpr int kBrotliWindow = 22;
} // namespace

bool head_runs_handler(std::string_view path) {
    return health::is_probe_path(path) || is_login_exempt_path(path);
}

bool brotli_compress(std::string_view in, int quality, std::string& out) {
    size_t cap = BrotliEncoderMaxCompressedSize(in.size());
    if (cap == 0) // the input is too large for the one-shot bound
        return false;
    std::string buf(cap, '\0');
    size_t n = cap;
    if (!BrotliEncoderCompress(quality, kBrotliWindow, BROTLI_MODE_GENERIC, in.size(),
                               reinterpret_cast<const uint8_t*>(in.data()), &n,
                               reinterpret_cast<uint8_t*>(buf.data())))
        return false;
    buf.resize(n);
    out = std::move(buf);
    return true;
}

void apply_dynamic_compression(const httplib::Request& req, httplib::Response& res) {
    if (res.body.empty() || res.content_provider_ || !res.file_content_path_.empty() ||
        !req.ranges.empty())
        return;
    // httplib's own negotiation (Accept-Encoding, content type, an existing Content-Encoding), so the
    // set of compressed responses is exactly the one httplib would have produced.
    if (httplib::detail::encoding_type(req, res) != httplib::detail::EncodingType::Brotli)
        return;
    std::string encoded;
    if (!brotli_compress(res.body, kDynamicBrotliQuality, encoded))
        return;
    res.body = std::move(encoded);
    res.set_header("Content-Encoding", "br");
    res.set_header("Vary", "Accept-Encoding");
}

httplib::Server::Handler with_response_policy(httplib::Server::Handler h) {
    return [h = std::move(h)](const httplib::Request& req, httplib::Response& res) {
        if (req.method == "HEAD" && !head_runs_handler(req.path)) {
            res.status = httplib::StatusCode::MethodNotAllowed_405;
            res.set_header("Allow", "GET");
            return;
        }
        h(req, res);
        apply_dynamic_compression(req, res);
    };
}

} // namespace yuzu::server
