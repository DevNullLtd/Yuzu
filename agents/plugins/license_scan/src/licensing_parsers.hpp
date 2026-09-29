/**
 * licensing_parsers.hpp — PURE parsers/classifiers for the license_scan
 * plugin (SLE roadmap §5 PR1 file-table row 5; ADR-0024 Decision 2).
 *
 * Deliberately platform-free (no windows.h, no POSIX, no subprocesses) so
 * tests/unit/test_licensing_parsers.cpp exercises the exact code the plugin
 * ships on every OS (pattern: #1662 / installed_apps_inventory.hpp).
 *
 * Vocabulary discipline: every classifier returns ONLY values from the
 * closed vocabularies in licensing_record.hpp (§3.2) — unknown-preserving,
 * never fabricating. Dates are pure civil-calendar arithmetic (Howard
 * Hinnant's days_from_civil), no gmtime/localtime, so results are identical
 * on every platform and trivially unit-testable.
 *
 * SHA-256 is a small local implementation: key_hint derivation must never
 * echo raw key material (ADR-0024 Decision 2) and this file stays free of
 * an external crypto dependency — pinned against NIST's "abc" vector in the
 * tests. "Platform-free" (above) is the invariant this header actually
 * protects; it DOES include licensing_record.hpp for ProbeOutcome/LicRecord
 * (also platform-free, same plugin's own pure data layer), so a decision
 * that classifies into those types — e.g. entitlement_certs_outcome() below
 * — belongs here rather than duplicating the shape locally.
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_PARSERS_HPP
#define YUZU_LICENSE_SCAN_LICENSING_PARSERS_HPP

#include "licensing_record.hpp" // ProbeOutcome (platform-free; entitlement_certs_outcome() below)

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

// ── small string helpers ────────────────────────────────────────────────────

namespace parse_detail {

inline std::string to_lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    return out;
}

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

inline std::vector<std::string> split_ws(std::string_view s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
            ++i;
        std::size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t')
            ++i;
        if (i > start)
            out.emplace_back(s.substr(start, i - start));
    }
    return out;
}

// ── SHA-256 (local, minimal; pinned against NIST vectors in the tests) ─────

struct Sha256 {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    unsigned char buf[64] = {};
    std::size_t buf_len = 0;
    std::uint64_t total = 0;

    static constexpr std::uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

    static std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

    void process_block(const unsigned char* p) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(p[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(p[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = hh + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    void update(const void* data, std::size_t len) {
        const auto* p = static_cast<const unsigned char*>(data);
        total += len;
        while (len > 0) {
            const std::size_t take = (64 - buf_len) < len ? (64 - buf_len) : len;
            std::memcpy(buf + buf_len, p, take);
            buf_len += take;
            p += take;
            len -= take;
            if (buf_len == 64) {
                process_block(buf);
                buf_len = 0;
            }
        }
    }

    std::string hex_digest() {
        const std::uint64_t bit_len = total * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        const unsigned char zero = 0x00;
        while (buf_len != 56)
            update(&zero, 1);
        unsigned char len_be[8];
        for (int i = 0; i < 8; ++i)
            len_be[i] = static_cast<unsigned char>(bit_len >> (56 - i * 8));
        // update() counts these framing bytes into `total`, but bit_len was
        // latched before padding began, so the encoded length is correct.
        update(len_be, 8);
        static constexpr char hexc[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (std::uint32_t v : h) {
            for (int shift = 28; shift >= 0; shift -= 4)
                out += hexc[(v >> shift) & 0xF];
        }
        return out;
    }
};

inline std::string sha256_hex(std::string_view data) {
    Sha256 s;
    s.update(data.data(), data.size());
    return s.hex_digest();
}

} // namespace parse_detail

/// First 12 hex chars of SHA-256 — the key_hint hash-prefix form.
inline std::string sha256_hex12(std::string_view data) {
    return parse_detail::sha256_hex(data).substr(0, 12);
}

// ── key_hint derivation (ADR-0024 Decision 2) ──────────────────────────────

/// OS-provided partial key verbatim when present; otherwise a 12-hex SHA-256
/// prefix of the raw key material. The raw material is NEVER echoed — the
/// only transformations are "already-partial passthrough" and one-way hash.
inline std::string derive_key_hint(std::string_view os_partial_key,
                                   std::string_view raw_key_material) {
    if (!os_partial_key.empty())
        return std::string(os_partial_key);
    if (!raw_key_material.empty())
        return sha256_hex12(raw_key_material);
    return {};
}

// ── civil-date helpers (pure arithmetic; no gmtime) ────────────────────────

namespace parse_detail {

// Howard Hinnant's days_from_civil / civil_from_days.
inline long long days_from_civil(long long y, unsigned m, unsigned d) {
    y -= m <= 2;
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

struct CivilDate {
    long long y;
    unsigned m;
    unsigned d;
};

inline CivilDate civil_from_days(long long z) {
    z += 719468;
    const long long era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const long long y = static_cast<long long>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    return {y + (m <= 2), m, d};
}

} // namespace parse_detail

/// UTC epoch seconds for a civil date (00:00:00 UTC).
inline long long epoch_from_civil(long long year, unsigned month, unsigned day) {
    return parse_detail::days_from_civil(year, month, day) * 86400LL;
}

/// Epoch seconds → the `expires_at` wire encoding: the epoch truncated to UTC
/// midnight, rendered as a decimal string (roadmap §3.1 field-encoding pins —
/// the store column is BIGINT epoch and the evaluator compares epochs, NOT a
/// YYYY-MM-DD string). "" for epoch <= 0 (no expiry / perpetual / unknown —
/// e.g. the FlexLM parser's `expiry_epoch == 0` sentinel). Truncating to
/// midnight keeps a grace countdown converted to an absolute time stable
/// across collects on a fixed collection day (ADR-0024 D3 blob-stability).
inline std::string expiry_wire_from_epoch(long long epoch) {
    if (epoch <= 0)
        return {};
    return std::to_string(epoch - (epoch % 86400));
}

/// Grace countdown → the ABSOLUTE `expires_at` wire value (ADR-0024 D3
/// blob-stability rule): expires_at = collection_time + remaining_minutes,
/// truncated to UTC midnight. Deterministic for a fixed collection_epoch —
/// two calls with the same collection_time yield the identical midnight-epoch
/// string, so a ticking minute counter cannot change the record between syncs.
inline std::string grace_expiry_date(long long collection_epoch, long long remaining_minutes) {
    if (remaining_minutes <= 0 || collection_epoch <= 0)
        return {};
    return expiry_wire_from_epoch(collection_epoch + remaining_minutes * 60);
}

/// CIM_DATETIME ("20261231000000.000000+000") → the `expires_at` wire value
/// (UTC-midnight epoch seconds, decimal string). Returns "" for malformed
/// input or the 1601-01-01 "no date" sentinel WMI uses for unset
/// EvaluationEndDate.
inline std::string parse_wmi_datetime_to_expiry(std::string_view cim) {
    if (cim.size() < 8)
        return {};
    for (int i = 0; i < 8; ++i) {
        if (cim[static_cast<std::size_t>(i)] < '0' || cim[static_cast<std::size_t>(i)] > '9')
            return {};
    }
    const int year = (cim[0] - '0') * 1000 + (cim[1] - '0') * 100 + (cim[2] - '0') * 10 +
                     (cim[3] - '0');
    const int month = (cim[4] - '0') * 10 + (cim[5] - '0');
    const int day = (cim[6] - '0') * 10 + (cim[7] - '0');
    if (year <= 1601 || month < 1 || month > 12 || day < 1 || day > 31)
        return {};
    return expiry_wire_from_epoch(
        epoch_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day)));
}

/// `openssl x509 -noout -enddate` output → the `expires_at` wire value
/// (UTC-midnight epoch seconds, decimal string). Accepts both the `-dateopt
/// iso_8601` form ("notAfter=2027-03-04 12:00:00Z") and the default form
/// ("notAfter=Mar  4 12:00:00 2027 GMT"). Returns "" when unparsable.
inline std::string parse_openssl_enddate(std::string_view line) {
    line = parse_detail::trim(line);
    constexpr std::string_view prefix = "notAfter=";
    if (line.substr(0, prefix.size()) != prefix)
        return {};
    const auto value = parse_detail::trim(line.substr(prefix.size()));
    // ISO form: YYYY-MM-DD...
    if (value.size() >= 10 && value[4] == '-' && value[7] == '-') {
        bool digits = true;
        for (std::size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u})
            digits = digits && value[i] >= '0' && value[i] <= '9';
        if (digits) {
            const long long y = (value[0] - '0') * 1000 + (value[1] - '0') * 100 +
                                (value[2] - '0') * 10 + (value[3] - '0');
            const unsigned mo = static_cast<unsigned>((value[5] - '0') * 10 + (value[6] - '0'));
            const unsigned d = static_cast<unsigned>((value[8] - '0') * 10 + (value[9] - '0'));
            return expiry_wire_from_epoch(epoch_from_civil(y, mo, d));
        }
    }
    // Default form: "Mon dd HH:MM:SS yyyy GMT"
    static constexpr std::array<std::string_view, 12> months = {
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"};
    const auto tokens = parse_detail::split_ws(value);
    if (tokens.size() < 4)
        return {};
    const std::string mon = parse_detail::to_lower(tokens[0]);
    unsigned month = 0;
    for (std::size_t i = 0; i < months.size(); ++i) {
        if (mon == months[i]) {
            month = static_cast<unsigned>(i + 1);
            break;
        }
    }
    if (month == 0)
        return {};
    int day = 0;
    for (char c : tokens[1]) {
        if (c < '0' || c > '9')
            return {};
        day = day * 10 + (c - '0');
    }
    int year = 0;
    for (char c : tokens[3]) {
        if (c < '0' || c > '9')
            return {};
        year = year * 10 + (c - '0');
    }
    if (year < 1900 || day < 1 || day > 31)
        return {};
    return expiry_wire_from_epoch(epoch_from_civil(year, month, static_cast<unsigned>(day)));
}

// ── SLP LicenseStatus → §3.2 status (ADR-0024 D2; surface table row 1) ─────

/// WMI SoftwareLicensingProduct.LicenseStatus:
///   0 = Unlicensed                → unlicensed
///   1 = Licensed                  → licensed
///   2 = OOB grace                 → grace
///   3 = OOT grace                 → grace
///   4 = Non-genuine grace         → grace
///   5 = Notification              → unlicensed (post-grace nag state — the
///                                   licence is no longer in effect)
///   6 = Extended grace            → grace
/// Anything else is unknown-preserving, never guessed.
inline std::string slp_status_to_status(long code) {
    switch (code) {
    case 0:
        return "unlicensed";
    case 1:
        return "licensed";
    case 2:
    case 3:
    case 4:
    case 6:
        return "grace";
    case 5:
        return "unlicensed";
    default:
        return "unknown";
    }
}

// ── channel classifier (KMS/MAK/OEM/retail) ────────────────────────────────

/// Classify from SLP ProductKeyChannel ("Volume:GVLK", "Volume:MAK",
/// "OEM:DM", "OEM:SLP", "OEM:NONSLP", "Retail", ...) with the licence
/// Description string ("... VOLUME_KMSCLIENT channel", "... VOLUME_MAK
/// channel", "... OEM_SLP channel", "... RETAIL channel") as fallback.
/// Returns "kms" | "mak" | "oem" | "retail" | "" (empty = unknown).
inline std::string classify_channel(std::string_view product_key_channel,
                                    std::string_view description) {
    const std::string pkc = parse_detail::to_lower(product_key_channel);
    if (pkc.find("gvlk") != std::string::npos || pkc.find("csvlk") != std::string::npos ||
        pkc.find("kms") != std::string::npos)
        return "kms";
    if (pkc.find("mak") != std::string::npos)
        return "mak";
    if (pkc.find("oem") != std::string::npos)
        return "oem";
    if (pkc.find("retail") != std::string::npos)
        return "retail";
    const std::string desc = parse_detail::to_lower(description);
    if (desc.find("kmsclient") != std::string::npos ||
        desc.find("volume_kms") != std::string::npos || desc.find("kms channel") != std::string::npos)
        return "kms";
    if (desc.find("mak") != std::string::npos)
        return "mak";
    if (desc.find("oem") != std::string::npos)
        return "oem";
    if (desc.find("retail") != std::string::npos)
        return "retail";
    return {};
}

// ── declared-licence classification (rpm %{LICENSE} / DEP-5 / SPDX) ────────

/// Classify a declared licence string into license_type
/// `open_source | freeware | unknown` (§3.2 subset — classification only,
/// no lapse; roadmap surface table Linux row 1). Token-based so short
/// markers ("MIT", "ISC") cannot fire inside unrelated words.
inline std::string classify_license_string(std::string_view lic) {
    const std::string lower = parse_detail::to_lower(lic);

    // Phrase markers (substring match is safe for multi-word phrases).
    static constexpr std::array<std::string_view, 8> open_phrases = {
        "public domain",   "apache license", "mozilla public", "creative commons",
        "gnu general",     "gnu lesser",     "gnu affero",     "open source",
    };
    for (auto p : open_phrases) {
        if (lower.find(p) != std::string::npos)
            return "open_source";
    }
    static constexpr std::array<std::string_view, 4> freeware_phrases = {
        "freeware", "free for personal", "free for non-commercial", "donationware",
    };
    for (auto p : freeware_phrases) {
        if (lower.find(p) != std::string::npos)
            return "freeware";
    }

    // Token markers (split on non-alphanumeric so "MIT" != "coMMITted";
    // SPDX ids like "GPL-2.0-or-later" / "BSD-3-Clause" split into tokens).
    static constexpr std::array<std::string_view, 32> open_tokens = {
        "gpl",   "gplv2", "gplv3", "lgpl",  "lgplv2", "lgplv3", "agpl",  "agplv3",
        "mit",   "bsd",   "apache", "mpl",  "isc",    "artistic", "zlib", "cc0",
        "unlicense", "wtfpl", "boost", "bsl", "x11",  "ofl",    "epl",   "cddl",
        "psf",   "expat", "openssl", "curl", "vim",   "ruby",   "php",   "postgresql",
    };
    std::size_t i = 0;
    while (i < lower.size()) {
        while (i < lower.size() && !(std::isalnum(static_cast<unsigned char>(lower[i]))))
            ++i;
        std::size_t start = i;
        while (i < lower.size() && std::isalnum(static_cast<unsigned char>(lower[i])))
            ++i;
        if (i > start) {
            const std::string_view tok(lower.data() + start, i - start);
            for (auto t : open_tokens) {
                if (tok == t)
                    return "open_source";
            }
        }
    }
    return "unknown";
}

// ── dpkg DEP-5 copyright detection ──────────────────────────────────────────

/// True when the content looks like a machine-readable DEP-5
/// debian/copyright file (Format: header naming copyright-format/1.0).
inline bool is_dep5_copyright(std::string_view content) {
    const std::size_t probe_len = content.size() < 512 ? content.size() : 512;
    const std::string head = parse_detail::to_lower(content.substr(0, probe_len));
    if (head.find("format:") == std::string::npos)
        return false;
    return head.find("copyright-format/1.0") != std::string::npos ||
           head.find("dep5") != std::string::npos;
}

/// First `License:` field value from a DEP-5 copyright file ("" if absent).
inline std::string dep5_first_license(std::string_view content) {
    std::size_t pos = 0;
    while (pos < content.size()) {
        std::size_t eol = content.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = content.size();
        const auto line = content.substr(pos, eol - pos);
        const std::string lower = parse_detail::to_lower(line.substr(0, 8));
        if (lower.rfind("license:", 0) == 0)
            return std::string(parse_detail::trim(line.substr(8)));
        pos = eol + 1;
    }
    return {};
}

// ── FlexLM `.lic` INCREMENT parser (roadmap surface table Linux row 3) ─────

struct FlexlmIncrement {
    std::string feature;        // licensed feature name
    std::string vendor_daemon;  // vendor daemon name
    std::string version;        // feature version
    long long expiry_epoch = 0; // UTC epoch of expiry date; 0 = permanent
    long seats = 0;             // licence count; 0 = uncounted
};

/// Join FlexLM physical continuation lines (trailing backslash) into logical
/// lines so multi-line INCREMENT entries parse as one.
inline std::string join_flexlm_continuations(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        char c = text[i];
        if (c == '\\') {
            // Trailing backslash (optionally followed by CR) before LF joins.
            std::size_t j = i + 1;
            if (j < text.size() && text[j] == '\r')
                ++j;
            if (j < text.size() && text[j] == '\n') {
                i = j + 1;
                continue;
            }
        }
        out += c;
        ++i;
    }
    return out;
}

namespace parse_detail {

/// FlexLM expiry date: "dd-mmm-yyyy" (e.g. 31-dec-2026, case-insensitive) or
/// the permanent forms ("permanent", year 0 as in "1-jan-0"/"01-jan-0000").
/// Returns epoch (0 = permanent) or nullopt when malformed.
inline std::optional<long long> parse_flexlm_date(std::string_view tok) {
    const std::string lower = to_lower(tok);
    if (lower == "permanent")
        return 0LL;
    // dd-mmm-yyyy
    const auto dash1 = lower.find('-');
    if (dash1 == std::string::npos)
        return std::nullopt;
    const auto dash2 = lower.find('-', dash1 + 1);
    if (dash2 == std::string::npos)
        return std::nullopt;
    const std::string_view day_s(lower.data(), dash1);
    const std::string_view mon_s(lower.data() + dash1 + 1, dash2 - dash1 - 1);
    const std::string_view year_s(lower.data() + dash2 + 1, lower.size() - dash2 - 1);
    if (day_s.empty() || year_s.empty())
        return std::nullopt;
    int day = 0;
    for (char c : day_s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        day = day * 10 + (c - '0');
    }
    long long year = 0;
    for (char c : year_s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        year = year * 10 + (c - '0');
    }
    static constexpr std::array<std::string_view, 12> months = {
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"};
    unsigned month = 0;
    for (std::size_t i = 0; i < months.size(); ++i) {
        if (mon_s == months[i]) {
            month = static_cast<unsigned>(i + 1);
            break;
        }
    }
    if (month == 0)
        return std::nullopt;
    if (year == 0)
        return 0LL; // year 0 = permanent (FlexLM convention)
    if (day < 1 || day > 31)
        return std::nullopt;
    return epoch_from_civil(year, month, static_cast<unsigned>(day)) ;
}

} // namespace parse_detail

/// Parse one logical `INCREMENT` (or legacy `FEATURE`) line:
///   INCREMENT feature vendor_daemon version exp_date num_lic [options...]
/// Returns nullopt for anything else / malformed lines. Signature fields
/// (SIGN=/ck=) are ignored — never emitted (they are not key material we
/// want to ship, and key_hint is derived elsewhere).
inline std::optional<FlexlmIncrement> parse_flexlm_increment(std::string_view line) {
    const auto tokens = parse_detail::split_ws(parse_detail::trim(line));
    if (tokens.size() < 6)
        return std::nullopt;
    const std::string kw = parse_detail::to_lower(tokens[0]);
    if (kw != "increment" && kw != "feature")
        return std::nullopt;
    const auto expiry = parse_detail::parse_flexlm_date(tokens[4]);
    if (!expiry)
        return std::nullopt;
    FlexlmIncrement inc;
    inc.feature = tokens[1];
    inc.vendor_daemon = tokens[2];
    inc.version = tokens[3];
    inc.expiry_epoch = *expiry;
    const std::string count = parse_detail::to_lower(tokens[5]);
    if (count == "uncounted") {
        inc.seats = 0;
    } else {
        long seats = 0;
        for (char c : count) {
            if (c < '0' || c > '9')
                return std::nullopt;
            seats = seats * 10 + (c - '0');
        }
        inc.seats = seats;
    }
    return inc;
}

// ── Office ClickToRun release-id classifier ─────────────────────────────────

/// ProductReleaseIds token → license_type. "O365ProPlusRetail" is a
/// subscription SKU despite the Retail suffix, so the 365 check wins.
inline std::string classify_office_release_id(std::string_view release_id) {
    const std::string lower = parse_detail::to_lower(release_id);
    if (lower.find("365") != std::string::npos)
        return "subscription";
    if (lower.find("volume") != std::string::npos)
        return "volume";
    if (lower.find("retail") != std::string::npos)
        return "retail";
    return "unknown";
}

// ── minimal XML plist reader (macOS Info.plist identity) ────────────────────

/// Value of `<key>NAME</key><string>VALUE</string>` in an XML plist ("" when
/// absent or when the plist is binary). Only what the _MASReceipt identity
/// probe needs — deliberately not a general plist parser.
inline std::string plist_string_value(std::string_view xml, std::string_view key) {
    const std::string needle = "<key>" + std::string(key) + "</key>";
    const auto kpos = xml.find(needle);
    if (kpos == std::string_view::npos)
        return {};
    const auto spos = xml.find("<string>", kpos + needle.size());
    if (spos == std::string_view::npos)
        return {};
    const auto vstart = spos + 8;
    const auto send = xml.find("</string>", vstart);
    if (send == std::string_view::npos)
        return {};
    // Guard against a <string> that belongs to a LATER key: allow only
    // whitespace between </key> and <string>.
    for (std::size_t i = kpos + needle.size(); i < spos; ++i) {
        const char c = xml[i];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            return {};
    }
    std::string value(xml.substr(vstart, send - vstart));
    // Basic XML entity decode.
    static constexpr std::pair<std::string_view, char> ents[] = {
        {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'}, {"&quot;", '"'}, {"&apos;", '\''}};
    for (const auto& [ent, ch] : ents) {
        std::size_t p = 0;
        while ((p = value.find(ent, p)) != std::string::npos)
            value.replace(p, ent.size(), 1, ch);
    }
    return value;
}

// ── entitlement_certs outcome decision (pure seam) ─────────────────────────

/// Classifies the outcome of the Linux `entitlement_certs` surface scan from
/// three plain facts, so the decision is unit-testable without a real
/// `/etc/pki/entitlement` directory or an `openssl` subprocess. Mirrors
/// `run_entitlement_certs_surface`'s (licensing_linux.cpp) four-way branch
/// exactly -- kept here rather than inline so a future refactor of that
/// impure shell can't silently regress either of the two honest-degrade
/// invariants it encodes:
///   - a scan that stopped early (`budget_exhausted`) with certs left
///     unexamined is NEVER reported clean, whatever was parsed before the
///     deadline;
///   - a scan where at least one cert parsed AND at least one failed
///     (`any_parse_failure` with `emitted > 0`) is NEVER reported as a clean
///     success -- a lapsed or corrupt entitlement cert must not silently
///     vanish from this authoritative compliance surface. Kept distinct from
///     the total-failure case (`emitted == 0`) so an operator can tell "some
///     certs unreadable" from "couldn't read any of them".
[[nodiscard]] inline ProbeOutcome entitlement_certs_outcome(bool budget_exhausted,
                                                             std::size_t emitted,
                                                             bool any_parse_failure) {
    if (budget_exhausted)
        return ProbeOutcome{"entitlement_certs", false, emitted, "cert_scan_budget_exhausted"};
    if (emitted == 0 && any_parse_failure)
        return ProbeOutcome{"entitlement_certs", false, 0, "cert_parse_failed"};
    if (any_parse_failure)
        return ProbeOutcome{"entitlement_certs", false, emitted, "cert_parse_partial"};
    return ProbeOutcome{"entitlement_certs", true, emitted, {}};
}

} // namespace yuzu::license_scan

#endif // YUZU_LICENSE_SCAN_LICENSING_PARSERS_HPP
