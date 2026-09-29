/**
 * licensing_record.hpp — the `lic|` wire record for the license_scan plugin
 * (SLE roadmap §3.1; ADR-0024 Decision 2).
 *
 * One record per detected licence, rendered as a single pipe-delimited line:
 *
 *   lic|product|vendor|version|license_type|channel|status|expires_at|source|
 *       confidence|key_hint|exe_hints|user_scope|user_ref
 *
 * 14 wire fields including the `lic` kind prefix. Field semantics:
 *   - license_type / status / source / confidence come from the CLOSED
 *     vocabularies in roadmap §3.2 — the plugin never fabricates a value it
 *     cannot justify; "don't know" is `unknown` (or empty for channel).
 *   - expires_at is UTC epoch seconds truncated to midnight, rendered as a
 *     decimal string (the store column is BIGINT epoch and the evaluator
 *     compares epochs — roadmap §3.1 field-encoding pins), or empty
 *     ("" / "0" = no expiry / perpetual / unknown). Countdowns (e.g. KMS
 *     grace minutes) are converted to an absolute midnight-epoch BEFORE
 *     emission so a ticking counter cannot change the record day-to-day and
 *     defeat the blob hash-skip (ADR-0024 Decision 3 blob-stability rule).
 *   - key_hint is an OS-provided partial key verbatim, or a 12-hex SHA-256
 *     prefix of key material — NEVER raw key bytes (ADR-0024 Decision 2).
 *   - user_ref is a local profile name or EMPTY — never a SID, email, or
 *     directory identity (ADR-0024 Decision 11; the D11 ban binds emission).
 *
 * Sanitisation layer 1 of 3 (roadmap §3.3): every field strips
 * `|` CR LF 0x1F 0x1E NUL and clamps to 1024 bytes, here at the plugin; the
 * sync source re-applies (layer 2) and the server seam re-applies (layer 3).
 * The 1024-byte clamp truncates on a UTF-8 sequence boundary so a multi-byte
 * character is never split (the layer-2 clamp is codepoint-aware; emitting a
 * torn sequence here would make the two layers disagree byte-for-byte).
 *
 * Header-only and platform-free so tests/unit/test_licensing_parsers.cpp
 * exercises the exact rendering the plugin ships (pattern: #1662).
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_RECORD_HPP
#define YUZU_LICENSE_SCAN_LICENSING_RECORD_HPP

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::license_scan {

/// Roadmap §3.3: per-field byte budget (comment-coordinated with the sync
/// source and the server seam — the repo has NO shared agent/server constants,
/// see roadmap C-2).
inline constexpr std::size_t kMaxFieldBytes = 1024;

// ── Closed vocabularies (roadmap §3.2) ─────────────────────────────────────
// The plugin emits ONLY these values (plus empty/`unknown` where noted).
// The server-side C-7 projection whitelist must match these exactly.

inline constexpr std::array<std::string_view, 9> kLicenseTypes = {
    "perpetual", "subscription", "trial",    "volume",  "oem",
    "retail",    "open_source",  "freeware", "unknown",
};

inline constexpr std::array<std::string_view, 7> kStatuses = {
    "licensed", "subscription_active", "trial", "grace", "expired", "unlicensed", "unknown",
};

inline constexpr std::array<std::string_view, 7> kSources = {
    "os_licensing_api", "entitlement_cert", "registry_probe", "license_file",
    "package_metadata", "app_receipt",      "heuristic",
};

inline constexpr std::array<std::string_view, 3> kConfidences = {
    "authoritative", "probable", "heuristic",
};

/// channel is not a §3.2 closed vocabulary but the emitted set is still
/// closed: kms | mak | oem | retail | "" (empty = unknown/not applicable).
inline constexpr std::array<std::string_view, 4> kChannels = {"kms", "mak", "oem", "retail"};

namespace vocab_detail {
template <std::size_t N>
constexpr bool contains(const std::array<std::string_view, N>& set, std::string_view v) {
    for (auto s : set) {
        if (s == v)
            return true;
    }
    return false;
}
} // namespace vocab_detail

inline constexpr bool is_valid_license_type(std::string_view v) {
    return vocab_detail::contains(kLicenseTypes, v);
}
inline constexpr bool is_valid_status(std::string_view v) {
    return vocab_detail::contains(kStatuses, v);
}
inline constexpr bool is_valid_source(std::string_view v) {
    return vocab_detail::contains(kSources, v);
}
inline constexpr bool is_valid_confidence(std::string_view v) {
    return vocab_detail::contains(kConfidences, v);
}
inline constexpr bool is_valid_channel(std::string_view v) {
    return v.empty() || vocab_detail::contains(kChannels, v);
}

// ── The record ──────────────────────────────────────────────────────────────

/// 13 data fields; render_lic_line prepends the `lic` kind for 14 wire fields.
struct LicRecord {
    std::string product;
    std::string vendor;
    std::string version;
    std::string license_type{"unknown"};
    std::string channel;                // kms|mak|oem|retail|"" — empty = unknown
    std::string status{"unknown"};
    std::string expires_at;             // UTC midnight-epoch seconds (decimal), "" = no expiry
    std::string source{"heuristic"};
    std::string confidence{"heuristic"};
    std::string key_hint;               // partial key or 12-hex hash prefix; NEVER raw key
    std::string exe_hints;              // comma-separated bare exe names (R6 usage bridge)
    std::string user_scope{"machine"};  // machine | user
    std::string user_ref;               // local profile name or "" — NEVER a SID (D11)
};

// ── Sanitiser (§3.3 layer 1) ───────────────────────────────────────────────

/// Strip `|` CR LF 0x1F 0x1E NUL, then clamp to kMaxFieldBytes on a UTF-8
/// sequence boundary (scrub-BEFORE-clamp, matching the layer-2/3 ordering).
/// All other bytes — including arbitrary non-ASCII UTF-8 — pass through
/// untouched (R17: registry values arrive as valid UTF-8 via Reg*W +
/// win_str.hpp and must round-trip intact).
inline std::string sanitize_field(std::string_view raw) {
    std::string out;
    out.reserve(raw.size() < kMaxFieldBytes ? raw.size() : kMaxFieldBytes);
    for (char c : raw) {
        const auto u = static_cast<unsigned char>(c);
        if (c == '|' || c == '\r' || c == '\n' || u == 0x1F || u == 0x1E || u == 0x00)
            continue;
        out += c;
    }
    if (out.size() > kMaxFieldBytes) {
        std::size_t cut = kMaxFieldBytes;
        // Never split a multi-byte sequence: back up over continuation bytes.
        while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80)
            --cut;
        out.resize(cut);
    }
    return out;
}

// ── Renderers ───────────────────────────────────────────────────────────────

inline std::string render_lic_line(const LicRecord& r) {
    const std::string* fields[] = {
        &r.product, &r.vendor,     &r.version,  &r.license_type, &r.channel,
        &r.status,  &r.expires_at, &r.source,   &r.confidence,   &r.key_hint,
        &r.exe_hints, &r.user_scope, &r.user_ref,
    };
    std::string line = "lic";
    for (const std::string* f : fields) {
        line += '|';
        line += sanitize_field(*f);
    }
    return line;
}

/// Per-surface diagnostic (roadmap §3.1). LIVE PATH ONLY — the sync source
/// consumes these for the empty-vs-error structural guard (ADR-0024 D3) and
/// for the live `surfaces` dispatch (D-10); they never enter the canonical blob.
struct ProbeOutcome {
    std::string surface;
    bool ok = true;
    std::size_t rows = 0;   // lic records this surface yielded (ok case)
    std::string error;      // reason token/message (error case), e.g. privilege_missing
};

inline std::string render_probe_status_line(const ProbeOutcome& o) {
    std::string line = "probe_status|";
    line += sanitize_field(o.surface);
    if (o.ok) {
        line += "|ok|";
        line += std::to_string(o.rows);
    } else {
        line += "|error|";
        line += sanitize_field(o.error);
    }
    return line;
}

} // namespace yuzu::license_scan

#endif // YUZU_LICENSE_SCAN_LICENSING_RECORD_HPP
