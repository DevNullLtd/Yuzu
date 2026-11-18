#pragma once

/**
 * http_client_get_output.hpp -- pure decision layer for what `get` / `head` may write.
 *
 * `get` returns a fetched body through write_output(), which carries C strings: a NUL in the body
 * silently truncates the row, and other control bytes break the pipe-delimited framing. The
 * client does not decode (`set_decompress(false)`), so a peer that answers with a Content-Encoding
 * anyway would otherwise put raw compressed bytes into that row. This header decides, with no I/O:
 *   - a Content-Encoding other than `identity` is refused, naming the token (restricted to
 *     [A-Za-z0-9,-] so the peer cannot inject framing through it);
 *   - a body (or header block) containing NUL or a control byte other than TAB/CR/LF is refused.
 * Raw fetched bytes never reach write_output. Extend these helpers for any new path that writes a
 * fetched body to output; do not fork a second copy.
 */

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::http_client {

/// The Content-Encoding value reduced to [A-Za-z0-9,-] (everything else dropped).
[[nodiscard]] inline std::string encoding_token(std::string_view ce) {
    std::string out;
    for (const char c : ce) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == ',' || c == '-')
            out.push_back(c);
        if (out.size() >= 64)
            break;
    }
    return out;
}

/// True when the header is absent/empty or names only `identity` (case-insensitive, trimmed).
[[nodiscard]] inline bool is_identity_encoding(std::string_view ce) {
    while (!ce.empty() && std::isspace(static_cast<unsigned char>(ce.front())))
        ce.remove_prefix(1);
    while (!ce.empty() && std::isspace(static_cast<unsigned char>(ce.back())))
        ce.remove_suffix(1);
    if (ce.size() != 8)
        return ce.empty();
    constexpr std::string_view kId = "identity";
    for (std::size_t i = 0; i < kId.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(ce[i])) != kId[i])
            return false;
    return true;
}

/// NUL, or a control byte (< 0x20 or 0x7F) other than TAB, CR and LF.
[[nodiscard]] inline bool has_unsafe_bytes(std::string_view s) noexcept {
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u == 0 || u == 0x7F || (u < 0x20 && u != '\t' && u != '\r' && u != '\n'))
            return true;
    }
    return false;
}

struct GetOutput {
    std::vector<std::string> lines;
    int rc{1};
};

/// The rows `get` writes. `status` 0 means no HTTP response (`body` then carries the plugin's own
/// error text, which is trusted and written as before).
[[nodiscard]] inline GetOutput build_get_output(int status, std::string_view content_encoding,
                                                std::string_view body) {
    GetOutput out;
    out.lines.push_back("status|" + std::to_string(status));
    if (status != 0) {
        if (!is_identity_encoding(content_encoding)) {
            out.lines.push_back("error|peer sent Content-Encoding " +
                                encoding_token(content_encoding) + "; body not decoded");
            return out;
        }
        if (has_unsafe_bytes(body)) {
            out.lines.push_back("error|response body contains NUL or control bytes");
            return out;
        }
    }
    out.lines.push_back("body|" + std::string{body});
    out.rc = (status >= 200 && status < 400) ? 0 : 1;
    return out;
}

} // namespace yuzu::http_client
