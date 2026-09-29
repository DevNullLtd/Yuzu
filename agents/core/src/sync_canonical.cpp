#include "sync_canonical.hpp"

#include <openssl/evp.h>

namespace yuzu::agent {

std::string sanitize_utf8_strict(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    const std::size_t n = s.size();
    const auto cont = [&](std::size_t j) -> bool {
        return j < n && (static_cast<unsigned char>(s[j]) & 0xC0) == 0x80;
    };
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const unsigned char c1 = i + 1 < n ? static_cast<unsigned char>(s[i + 1]) : 0;
        std::size_t len = 0;
        bool ok = false;
        if (c < 0x80) {
            ok = true;
            len = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            ok = cont(i + 1);
            len = 2;
        } else if (c == 0xE0) {
            ok = c1 >= 0xA0 && c1 <= 0xBF && cont(i + 2); // reject overlong 80..9F
            len = 3;
        } else if (c >= 0xE1 && c <= 0xEC) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xED) {
            ok = c1 >= 0x80 && c1 <= 0x9F && cont(i + 2); // reject surrogates A0..BF
            len = 3;
        } else if (c >= 0xEE && c <= 0xEF) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xF0) {
            ok = c1 >= 0x90 && c1 <= 0xBF && cont(i + 2) && cont(i + 3); // reject overlong 80..8F
            len = 4;
        } else if (c >= 0xF1 && c <= 0xF3) {
            ok = cont(i + 1) && cont(i + 2) && cont(i + 3);
            len = 4;
        } else if (c == 0xF4) {
            ok = c1 >= 0x80 && c1 <= 0x8F && cont(i + 2) && cont(i + 3); // reject > U+10FFFF
            len = 4;
        }
        if (ok) {
            out.append(s.data() + i, len);
            i += len;
        } else {
            out.append("\xEF\xBF\xBD", 3); // U+FFFD, advance one byte
            i += 1;
        }
    }
    return out;
}

std::string clamp_field(std::string_view raw, std::size_t max_field_len) {
    // 1. Scrub to valid UTF-8 FIRST (order is load-bearing for the agent/server
    //    hash coordination — see sync_canonical.hpp).
    std::string f = sanitize_utf8_strict(raw);
    // 2. Truncate on a UTF-8 codepoint boundary, never mid-sequence. After the
    //    scrub the field is valid UTF-8, so backing up over trailing continuation
    //    bytes (0b10xxxxxx) lands on a codepoint start.
    if (f.size() > max_field_len) {
        std::size_t end = max_field_len;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    // 3. Strip the canonical framing separators (and NUL) so a value can never
    //    corrupt the wire blob's structure (0x1F field / 0x1E record separators) —
    //    the server splits on exactly those bytes. U+FFFD contains none of them.
    std::string out;
    out.reserve(f.size());
    for (char c : f) {
        if (c == '\x1f' || c == '\x1e' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

std::string sha256_hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

} // namespace yuzu::agent
