#pragma once

/// @file inventory_blob_v3.hpp
/// Pure parser for the `installed_software` blob contract v3 (ADR-0016 Update 2026-11-04):
/// header, sections, install rows, deletions and component rows. No store, no clock, no I/O,
/// so the whole grammar is unit-tested without Postgres. The v2 parser
/// (`parse_software_blob` in inventory_ingestion.cpp) is untouched and still owns every blob
/// that does not start with the v3 header.
///
/// Wire form (bytes are the contract; the agent writer mirrors it):
///   - record 0 is the header `0x1F "v3" 0x1E`: an empty first field, which the v2 parser drops
///     (it ignores a record with an empty name), so no v2 record can be mistaken for it;
///   - then sections. Every record is 0x1E-terminated, fields 0x1F-separated, first field = the
///     record kind:
///       S    | facet | status | base | token | duration_ms | bytes_read | expect
///                                                                              opens a section
///       +    | name | version | publisher | install_date | kind | ecosystem | epoch | release |
///              arch | signature_status | distro_id | distro_version | install_location |
///              <slot 14, reserved, always empty> | package_id | source      an install row
///       -    | row_hash                                                      a row-hash deletion
///       comp | kind | name | version | version_source | path | size | mtime | anchor_app
///  - `facet` is a `software_catalog::kSoftwareSources` value or `component_inventory`; `status`
///    is full | delta | constrained | timeout | oversize | not_collected | disabled; only full
///    and delta sections carry records.
///  - `expect` is the section hash the agent holds AFTER applying this section (64 lowercase
///    hex). A delta section MUST carry it (refused `bad_record` otherwise): it is the only
///    per-section check the server has that its own apply produced the agent's row set. A full
///    section ignores the field (the server recomputes a full section's hash from its rows) and
///    keeps whatever it carried.
///
/// Two framing rules every record obeys. (1) A record is 0x1E-terminated, the last one too: an
/// unterminated final record is a truncated blob, so it refuses the section it sits in (or the
/// whole blob when it is a section header or precedes every section). (2) A record holds no NUL
/// byte: NUL is valid UTF-8, so the field scrub keeps it, but the text bound to Postgres cannot
/// carry one, so a NUL would be hashed and then stored without it (two rows reading the same
/// with different keys). The section is refused instead; the agent writer must never emit NUL.
///
/// Containment: a grammar violation INSIDE a section refuses that section only (the other
/// sections of the call still apply and the refused facet is nacked). A defect that cannot be
/// attributed to a facet (header, an unreadable section header, a record before any section,
/// a header with no section at all, more than kV3MaxSections sections, an oversized blob) fails
/// the whole blob.
/// Every field is UTF-8-scrubbed and codepoint-clamped exactly like the v2 parser (scrub first,
/// then clamp), so the server-recomputed hashes match the agent's.

#include "software_catalog_rules.hpp"
#include "software_inventory_types.hpp"
#include "utf8_sanitize.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Caps. kV3MaxBlobBytes / kV3MaxRows / kV3MaxFieldLen equal the v2 seam's kMaxBlobBytes /
/// kMaxEntries / kMaxFieldLen (inventory_ingestion.cpp static_asserts it); the agent source's
/// blob cap is the same number, so a one-sided bump is a build failure here, not a tight
/// agent-sends/server-drops loop.
inline constexpr std::size_t kV3MaxBlobBytes = 3u * 1024 * 1024;
inline constexpr std::size_t kV3MaxSections = 32;
inline constexpr std::size_t kV3MaxRows = 20000;       ///< `+` rows per call
inline constexpr std::size_t kV3MaxDeletions = 20000;  ///< `-` records per call
inline constexpr std::size_t kV3MaxComponents = 20000; ///< `comp` records per call
inline constexpr std::size_t kV3MaxFieldLen = 1024;
inline constexpr std::size_t kV3MaxFacetLen = 64;

inline constexpr std::string_view kV3Header = "\037v3\036";
inline constexpr std::string_view kComponentInventoryFacet = "component_inventory";

enum class V3Status {
    kFull,
    kDelta,
    kConstrained,
    kTimeout,
    kOversize,
    kNotCollected,
    kDisabled,
};

[[nodiscard]] constexpr std::string_view v3_status_name(V3Status s) noexcept {
    switch (s) {
    case V3Status::kFull:
        return "full";
    case V3Status::kDelta:
        return "delta";
    case V3Status::kConstrained:
        return "constrained";
    case V3Status::kTimeout:
        return "timeout";
    case V3Status::kOversize:
        return "oversize";
    case V3Status::kNotCollected:
        return "not_collected";
    case V3Status::kDisabled:
        return "disabled";
    }
    return "full"; // unreachable: -Werror=switch keeps the cases exhaustive
}

[[nodiscard]] constexpr std::optional<V3Status> v3_status_parse(std::string_view s) noexcept {
    for (const auto st :
         {V3Status::kFull, V3Status::kDelta, V3Status::kConstrained, V3Status::kTimeout,
          V3Status::kOversize, V3Status::kNotCollected, V3Status::kDisabled}) {
        if (v3_status_name(st) == s)
            return st;
    }
    return std::nullopt;
}

/// Only full and delta sections carry records; every other status is a status-only report.
[[nodiscard]] constexpr bool v3_status_carries_rows(V3Status s) noexcept {
    return s == V3Status::kFull || s == V3Status::kDelta;
}

/// Why a section was refused (kNone = accepted). The facet is still known, so the caller nacks
/// `installed_software:<facet>`.
enum class V3Refusal {
    kNone,
    kUnknownFacet,
    kDuplicateFacet,
    kUnknownStatus,
    kRowsInStatusOnly,    ///< a +, - or comp record in a status-only section
    kDeleteInFull,        ///< a - record in a full section
    kWrongRecordForFacet, ///< + in component_inventory, or comp in any other facet
    kSourceMismatch,      ///< a + row whose source is not the section's facet
    kUnknownRecord,
    kBadRecord,        ///< a record missing a required field
    kBadRowHash,       ///< a - record that is not 64 lowercase hex
    kBadVersionSource, ///< a comp record with a version_source outside the closed set
    kRowCap,           ///< kV3MaxRows / kV3MaxDeletions / kV3MaxComponents exceeded
    kNulByte,          ///< a record holding a NUL byte (it could not be stored as it was hashed)
    kUnterminated,     ///< the last record of the blob lacks its 0x1E terminator (truncated)
};

[[nodiscard]] constexpr std::string_view v3_refusal_name(V3Refusal r) noexcept {
    switch (r) {
    case V3Refusal::kNone:
        return "none";
    case V3Refusal::kUnknownFacet:
        return "unknown_facet";
    case V3Refusal::kDuplicateFacet:
        return "duplicate_facet";
    case V3Refusal::kUnknownStatus:
        return "unknown_status";
    case V3Refusal::kRowsInStatusOnly:
        return "rows_in_status_only";
    case V3Refusal::kDeleteInFull:
        return "delete_in_full";
    case V3Refusal::kWrongRecordForFacet:
        return "wrong_record_for_facet";
    case V3Refusal::kSourceMismatch:
        return "source_mismatch";
    case V3Refusal::kUnknownRecord:
        return "unknown_record";
    case V3Refusal::kBadRecord:
        return "bad_record";
    case V3Refusal::kBadRowHash:
        return "bad_row_hash";
    case V3Refusal::kBadVersionSource:
        return "bad_version_source";
    case V3Refusal::kRowCap:
        return "row_cap";
    case V3Refusal::kNulByte:
        return "nul_byte";
    case V3Refusal::kUnterminated:
        return "unterminated";
    }
    return "none";
}

/// The closed `comp` version_source vocabulary.
inline constexpr std::array<std::string_view, 9> kV3VersionSources{{
    "filename",
    "pom",
    "manifest",
    "metadata",
    "package_json",
    "pe",
    "elf",
    "macho",
    "unreadable",
}};

/// One `comp` record: parsed and validated here, stored by a later change.
struct V3Component {
    std::string kind;
    std::string name;
    std::string version;
    std::string version_source;
    std::string path;
    std::int64_t size{0};
    std::int64_t mtime{0};
    std::string anchor_app;
};

struct V3Section {
    std::string facet;
    V3Status status{V3Status::kNotCollected}; ///< meaningless when refusal == kUnknownStatus
    std::string base;  ///< delta: the section hash the delta applies on top of
    std::string expect; ///< delta: the section hash after the delta (64 lowercase hex, checked)
    std::string token; ///< agent-reported reason token for a non-full status
    std::int64_t duration_ms{0};
    std::int64_t bytes_read{0};
    std::vector<SoftwareEntry> rows;     ///< `+` records, v2-field-parity scrubbed/clamped
    std::vector<std::string> deletions;  ///< `-` row hashes
    std::vector<V3Component> components; ///< `comp` records
    V3Refusal refusal{V3Refusal::kNone}; ///< set => every other member is cleared
};

struct V3Report {
    std::vector<V3Section> sections; ///< at most kV3MaxSections, wire order, facets unique
};

enum class V3ParseErrorKind {
    kNotV3,
    kOversize,
    kTooManySections,
    kBadSectionHeader,
    kRecordBeforeSection,
};

[[nodiscard]] constexpr std::string_view v3_parse_error_name(V3ParseErrorKind k) noexcept {
    switch (k) {
    case V3ParseErrorKind::kNotV3:
        return "not_v3";
    case V3ParseErrorKind::kOversize:
        return "oversize";
    case V3ParseErrorKind::kTooManySections:
        return "too_many_sections";
    case V3ParseErrorKind::kBadSectionHeader:
        return "bad_section_header";
    case V3ParseErrorKind::kRecordBeforeSection:
        return "record_before_section";
    }
    return "not_v3";
}

/// A blob is v3 only when it starts with the exact header bytes. Anything else, including a v2
/// blob whose first product is literally named "v3", is v2.
[[nodiscard]] constexpr bool is_v3_blob(std::string_view blob) noexcept {
    return blob.starts_with(kV3Header);
}

/// A facet the server knows how to name: a collector source or `component_inventory`. Also the
/// closed set the section metric labels with (anything else is labelled "unknown").
[[nodiscard]] constexpr bool is_known_v3_facet(std::string_view s) noexcept {
    if (s == kComponentInventoryFacet)
        return true;
    for (const auto& src : software_catalog::kSoftwareSources) {
        if (src.value == s)
            return true;
    }
    return false;
}

namespace v3_detail {

/// Scrub to valid UTF-8 FIRST, then clamp on a codepoint boundary: identical to the field step
/// of the v2 parser (inventory_ingestion.cpp) and the agent's clamp_field.
[[nodiscard]] inline std::string scrub_and_clamp(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    if (f.size() > kV3MaxFieldLen) {
        std::size_t end = kV3MaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    return f;
}

/// Diagnostic numerics: digits only, no sign; anything else (or overflow) reads as 0.
[[nodiscard]] inline std::int64_t parse_nonneg(std::string_view s) noexcept {
    std::int64_t v = 0;
    if (s.empty() || s.front() < '0' || s.front() > '9')
        return 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    return (ec == std::errc{} && p == s.data() + s.size()) ? v : 0;
}

[[nodiscard]] inline bool is_hex64_lower(std::string_view s) noexcept {
    if (s.size() != 64)
        return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/// Facet names are spliced into need_full strings and metric labels: a short, closed charset.
[[nodiscard]] inline bool facet_name_ok(std::string_view s) noexcept {
    if (s.empty() || s.size() > kV3MaxFacetLen)
        return false;
    for (const char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'))
            return false;
    }
    return true;
}

[[nodiscard]] inline bool version_source_known(std::string_view s) noexcept {
    for (const auto v : kV3VersionSources) {
        if (v == s)
            return true;
    }
    return false;
}

inline void refuse(V3Section& sec, V3Refusal why) {
    sec.refusal = why;
    sec.rows.clear();
    sec.deletions.clear();
    sec.components.clear();
}

} // namespace v3_detail

/// Parse a v3 blob. `std::unexpected` = the whole blob is unusable (see the file comment);
/// otherwise every section the blob named is present, accepted or refused.
[[nodiscard]] inline std::expected<V3Report, V3ParseErrorKind>
parse_v3_blob(std::string_view blob) {
    using K = V3ParseErrorKind;
    if (blob.size() > kV3MaxBlobBytes)
        return std::unexpected(K::kOversize);
    if (!is_v3_blob(blob))
        return std::unexpected(K::kNotV3);

    V3Report rep;
    std::size_t total_rows = 0;
    std::size_t total_deletions = 0;
    std::size_t total_components = 0;

    std::size_t pos = kV3Header.size();
    while (pos < blob.size()) {
        std::size_t rec_end = blob.find('\x1e', pos);
        const bool terminated = rec_end != std::string_view::npos;
        if (!terminated)
            rec_end = blob.size();
        const std::string_view rec = blob.substr(pos, rec_end - pos);
        pos = rec_end + 1;
        if (rec.empty())
            continue;

        // Split into at most 17 fields (kind + the 16 row slots); further tokens are dropped,
        // matching the v2 parser's treatment of a newer agent's extra tail.
        std::array<std::string, 17> f;
        std::size_t nf = 0;
        for (std::size_t p = 0; nf < f.size();) {
            std::size_t f_end = rec.find('\x1f', p);
            if (f_end == std::string_view::npos)
                f_end = rec.size();
            f[nf++] = v3_detail::scrub_and_clamp(rec.substr(p, f_end - p));
            if (f_end >= rec.size())
                break;
            p = f_end + 1;
        }

        // An unterminated final record is a truncated blob. A truncated section header cannot
        // be attributed to a facet; a truncated row belongs to the section it sits in.
        if (!terminated) {
            if (f[0] == "S")
                return std::unexpected(K::kBadSectionHeader);
            if (rep.sections.empty())
                return std::unexpected(K::kRecordBeforeSection);
            if (rep.sections.back().refusal == V3Refusal::kNone)
                v3_detail::refuse(rep.sections.back(), V3Refusal::kUnterminated);
            continue;
        }
        const bool has_nul = rec.find('\0') != std::string_view::npos;

        if (f[0] == "S") {
            if (rep.sections.size() >= kV3MaxSections)
                return std::unexpected(K::kTooManySections);
            if (!v3_detail::facet_name_ok(f[1]))
                return std::unexpected(K::kBadSectionHeader);
            V3Section sec;
            sec.facet = f[1];
            const auto st = v3_status_parse(f[2]);
            if (st)
                sec.status = *st;
            sec.base = std::move(f[3]);
            sec.token = std::move(f[4]);
            sec.duration_ms = v3_detail::parse_nonneg(f[5]);
            sec.bytes_read = v3_detail::parse_nonneg(f[6]);
            sec.expect = std::move(f[7]);
            if (!is_known_v3_facet(sec.facet)) {
                v3_detail::refuse(sec, V3Refusal::kUnknownFacet);
            } else if (has_nul) {
                v3_detail::refuse(sec, V3Refusal::kNulByte);
            } else if (!st) {
                v3_detail::refuse(sec, V3Refusal::kUnknownStatus);
            } else if (*st == V3Status::kDelta && !v3_detail::is_hex64_lower(sec.expect)) {
                v3_detail::refuse(sec, V3Refusal::kBadRecord);
            } else {
                for (const auto& prev : rep.sections) {
                    if (prev.facet == sec.facet) {
                        v3_detail::refuse(sec, V3Refusal::kDuplicateFacet);
                        break;
                    }
                }
            }
            rep.sections.push_back(std::move(sec));
            continue;
        }

        if (rep.sections.empty())
            return std::unexpected(K::kRecordBeforeSection);
        V3Section& sec = rep.sections.back();
        if (sec.refusal != V3Refusal::kNone)
            continue; // the rest of a refused section is skipped to the next S

        if (has_nul) {
            v3_detail::refuse(sec, V3Refusal::kNulByte);
            continue;
        }
        const bool is_component_facet = sec.facet == kComponentInventoryFacet;
        if (f[0] == "+") {
            if (!v3_status_carries_rows(sec.status)) {
                v3_detail::refuse(sec, V3Refusal::kRowsInStatusOnly);
            } else if (is_component_facet) {
                v3_detail::refuse(sec, V3Refusal::kWrongRecordForFacet);
            } else if (total_rows >= kV3MaxRows) {
                v3_detail::refuse(sec, V3Refusal::kRowCap);
            } else if (f[16] != sec.facet) {
                v3_detail::refuse(sec, V3Refusal::kSourceMismatch);
            } else {
                SoftwareEntry e;
                e.name = std::move(f[1]);
                e.version = std::move(f[2]);
                e.publisher = std::move(f[3]);
                e.install_date = std::move(f[4]);
                e.kind = std::move(f[5]);
                e.ecosystem = std::move(f[6]);
                e.epoch = std::move(f[7]);
                e.release = std::move(f[8]);
                e.arch = std::move(f[9]);
                e.signature_status = std::move(f[10]);
                e.distro_id = std::move(f[11]);
                e.distro_version = std::move(f[12]);
                e.install_location = std::move(f[13]);
                // f[14] is the reserved uninstall_string slot: consumed, never kept.
                e.package_id = std::move(f[15]);
                e.source = std::move(f[16]);
                if (!e.name.empty()) { // as the v2 parser: a nameless record is not a row
                    ++total_rows;
                    sec.rows.push_back(std::move(e));
                }
            }
        } else if (f[0] == "-") {
            if (!v3_status_carries_rows(sec.status))
                v3_detail::refuse(sec, V3Refusal::kRowsInStatusOnly);
            else if (sec.status == V3Status::kFull)
                v3_detail::refuse(sec, V3Refusal::kDeleteInFull);
            else if (!v3_detail::is_hex64_lower(f[1]))
                v3_detail::refuse(sec, V3Refusal::kBadRowHash);
            else if (total_deletions >= kV3MaxDeletions)
                v3_detail::refuse(sec, V3Refusal::kRowCap);
            else {
                ++total_deletions;
                sec.deletions.push_back(std::move(f[1]));
            }
        } else if (f[0] == "comp") {
            if (!v3_status_carries_rows(sec.status))
                v3_detail::refuse(sec, V3Refusal::kRowsInStatusOnly);
            else if (!is_component_facet)
                v3_detail::refuse(sec, V3Refusal::kWrongRecordForFacet);
            else if (f[1].empty() || f[2].empty())
                v3_detail::refuse(sec, V3Refusal::kBadRecord);
            else if (!v3_detail::version_source_known(f[4]))
                v3_detail::refuse(sec, V3Refusal::kBadVersionSource);
            else if (total_components >= kV3MaxComponents)
                v3_detail::refuse(sec, V3Refusal::kRowCap);
            else {
                ++total_components;
                V3Component c;
                c.kind = std::move(f[1]);
                c.name = std::move(f[2]);
                c.version = std::move(f[3]);
                c.version_source = std::move(f[4]);
                c.path = std::move(f[5]);
                c.size = v3_detail::parse_nonneg(f[6]);
                c.mtime = v3_detail::parse_nonneg(f[7]);
                c.anchor_app = std::move(f[8]);
                sec.components.push_back(std::move(c));
            }
        } else {
            v3_detail::refuse(sec, V3Refusal::kUnknownRecord);
        }
    }
    // A header with no section names nothing: fail closed like any other unattributable blob.
    if (rep.sections.empty())
        return std::unexpected(K::kBadSectionHeader);
    return rep;
}

} // namespace yuzu::server
