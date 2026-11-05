#pragma once

/// @file device_ci_section_digest.hpp
/// The ONE canonical serialization and digest of a device-CI section's child rows (up2r-up-3).
///
/// The store writes this digest beside the section's status row in the same transaction as the
/// rows (`device_ci_section.content_digest`, migration v3), and the read mapping recomputes it from
/// the rows it read in the same snapshot (`verify_section_content`, hardware_list_model.hpp). A
/// mismatch means the stored rows are not the rows that were stored with the status row: lost,
/// edited, or swapped for another generation, including the same-count cases the row count cannot
/// see. Write and read MUST go through `section_content_digest` - a second serialization is the
/// defect this header exists to prevent.
///
/// SCOPE, stated plainly: this is an integrity check against ACCIDENT and non-malicious drift (a
/// partial restore, a hand-edited table, a bad migration script). It is NOT tamper resistance:
/// anyone able to write the child tables can also rewrite the digest column. The digest covers the
/// rows only, not the section's level or reason columns.
///
/// Pure: no store, no PG, no I/O. The digest provider is OpenSSL's one-shot SHA-256
/// (`sha256_hex`), which reports failure rather than returning a zero digest.

#include "device_ci_kinds.hpp"
#include "sha256_hex.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace detail {

/// 8-byte big-endian length/count. Fixed width, so no value can be read as another's tail.
inline void digest_put_u64(std::string& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<char>((v >> shift) & 0xffU));
}

inline void digest_put_str(std::string& out, std::string_view s) {
    digest_put_u64(out, static_cast<std::uint64_t>(s.size()));
    out.append(s.data(), s.size());
}

} // namespace detail

/// The canonical preimage. Layout (every integer 8-byte big-endian, every string length-prefixed,
/// so cell boundaries cannot shift and an empty cell is distinct from a missing one):
///   "yuzu.device_ci.section.v1" | kind | ncol | nrows | for each row in stored order:
///   ord | for k in [0, ncol): cell k
/// `ncol` is the registry's column count for the kind. A row shorter than `ncol` reads as blank
/// cells (exactly what the writer stores: the column is NOT NULL DEFAULT ''), and cells beyond
/// `ncol` are ignored (the writer never stores them). `ord` is the row's position, not a stored
/// value, so a table whose `ord` values have gaps still verifies against its read order.
[[nodiscard]] inline std::string section_content_preimage(std::string_view kind, std::size_t ncol,
                                                          const std::vector<std::vector<std::string>>& rows) {
    std::string out;
    out.append("yuzu.device_ci.section.v1");
    detail::digest_put_str(out, kind);
    detail::digest_put_u64(out, ncol);
    detail::digest_put_u64(out, rows.size());
    std::uint64_t ord = 0;
    for (const auto& row : rows) {
        detail::digest_put_u64(out, ord++);
        for (std::size_t k = 0; k < ncol; ++k)
            detail::digest_put_str(out, k < row.size() ? std::string_view(row[k]) : std::string_view());
    }
    return out;
}

/// SHA-256 (64 lowercase hex) of `section_content_preimage` for a REGISTERED table-backed kind -
/// the one entry point the writer and the read mapping both call, so the kind name and column
/// count always come from the registry. nullopt when the digest provider fails. Callers treat
/// nullopt as "cannot verify": the writer aborts the ingest (never stores a section without its
/// digest by accident), the reader serves the section as a mismatch.
[[nodiscard]] inline std::optional<std::string>
section_content_digest(const DeviceCiSectionDef& def, const std::vector<std::vector<std::string>>& rows) {
    return sha256_hex(section_content_preimage(def.section, static_cast<std::size_t>(def.n_fields), rows));
}

} // namespace yuzu::server
