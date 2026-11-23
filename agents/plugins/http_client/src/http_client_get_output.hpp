#pragma once

/**
 * http_client_get_output.hpp -- pure decision layer for what `get` does with a peer Content-Encoding.
 *
 * The client does not decode (`set_decompress(false)`) and `get` asks for `Accept-Encoding:
 * identity`, but a peer may answer with a Content-Encoding anyway. The raw (still-encoded) bytes
 * would then be scrubbed into a `body|` row that looks like text. So `get` refuses such a body and
 * names the token. The body's own bytes (NUL, control, invalid UTF-8) are the business of
 * `prepare_get_body` in http_client_download.hpp; this header never looks at them.
 *
 * A response may carry several Content-Encoding header lines; the caller joins ALL of them with
 * ',' and `is_identity_encoding` accepts only when every listed coding is `identity`. Extend these
 * helpers for any new path that writes a fetched body to output; do not fork a second copy.
 */

#include <cctype>
#include <string>
#include <string_view>

namespace yuzu::http_client {

/// The Content-Encoding value reduced to [A-Za-z0-9,-] (everything else dropped), at most 64 bytes.
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

/// True when every comma-separated coding is empty or `identity` (case-insensitive, trimmed); an
/// absent header (empty string) is identity.
[[nodiscard]] inline bool is_identity_encoding(std::string_view ce) {
    constexpr std::string_view kId = "identity";
    while (true) {
        const auto comma = ce.find(',');
        auto part = ce.substr(0, comma);
        while (!part.empty() && std::isspace(static_cast<unsigned char>(part.front())))
            part.remove_prefix(1);
        while (!part.empty() && std::isspace(static_cast<unsigned char>(part.back())))
            part.remove_suffix(1);
        if (!part.empty()) {
            if (part.size() != kId.size())
                return false;
            for (std::size_t i = 0; i < kId.size(); ++i)
                if (std::tolower(static_cast<unsigned char>(part[i])) != kId[i])
                    return false;
        }
        if (comma == std::string_view::npos)
            return true;
        ce.remove_prefix(comma + 1);
    }
}

/// The `error|` row `get` writes in place of a body, or an empty string when the encoding is fine.
[[nodiscard]] inline std::string encoding_refusal_row(std::string_view content_encodings) {
    if (is_identity_encoding(content_encodings))
        return {};
    return "error|peer sent Content-Encoding " + encoding_token(content_encodings) +
           "; body not decoded";
}

} // namespace yuzu::http_client
