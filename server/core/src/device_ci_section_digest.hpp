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
/// STORED FORM: `v1:<64 lowercase hex>` (`kSectionDigestPrefix` + the SHA-256). The prefix names the
/// preimage layout below. What a reader does with the stored column is a CLOSED list
/// (`classify_stored_digest`):
///   - SQL NULL (a pre-feature row, or a status-only kind): UNVERIFIED, served as the count rule left
///     it. Decided by the caller; it never reaches the classifier.
///   - `v1:` first: the current layout, compared with the recomputed digest. Any difference at all
///     (wrong, truncated, extended, case-changed) is a MISMATCH.
///   - a WELL-FORMED digest of a different layout version (`v`, one to six digits that do not start
///     with 0 and are not "1", `:`, a non-empty remainder; e.g. `v2:...`): UNVERIFIED. This build
///     cannot recompute a layout it does not know, so a later layout change, or a registry change
///     that moves a kind's columns, can be rolled out by writing a new prefix instead of raising a
///     false integrity alarm on every stored row.
///   - EVERYTHING ELSE is a MISMATCH: an empty or whitespace-containing value, `V1:`, a bare hex
///     value, garbage, a malformed version (`v:`, `vx:`, `v0:`, `v01:`, `v1` with no colon, more
///     than six digits), a
///     different layout version with nothing after the colon. A damaged column must never read as
///     "unverified" and let a same-count edit through as complete. See the warning in
///     `device_ci_kinds.hpp`.
///
/// Pure: no store, no PG, no I/O. The digest provider is OpenSSL's one-shot SHA-256
/// (`sha256_hex`), which reports failure rather than returning a zero digest.

#include "device_ci_kinds.hpp"
#include "digest_fn.hpp"
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

/// One row cell, in the form the database STORES it. `pg::to_text_array` drops every 0x00 byte on
/// the way in (libpq's text format cannot carry one), so a cell containing NUL is read back
/// shorter than it was written. Hashing the cell with its NULs would then mismatch forever on a
/// hand-built record; hashing the projection that is actually stored verifies. The ingest seam
/// already strips NUL (`clamp_field`), so production cells never contain one - this keeps the
/// public store API consistent with its own storage rule.
inline void digest_put_cell(std::string& out, std::string_view s) {
    if (s.find('\0') == std::string_view::npos) {
        digest_put_str(out, s);
        return;
    }
    std::string stored;
    stored.reserve(s.size());
    for (const char c : s)
        if (c != '\0')
            stored.push_back(c);
    digest_put_str(out, stored);
}

} // namespace detail

/// The canonical preimage. Layout (every integer 8-byte big-endian, every string length-prefixed,
/// so cell boundaries cannot shift and an empty cell is distinct from a missing one):
///   "yuzu.device_ci.section.v1" | kind | ncol | nrows | for each row in stored order:
///   ord | for k in [0, ncol): cell k
/// `ncol` is the registry's column count for the kind. A row shorter than `ncol` reads as blank
/// cells (exactly what the writer stores: the column is NOT NULL DEFAULT ''), and cells beyond
/// `ncol` are ignored (the writer never stores them). 0x00 bytes inside a cell are skipped (the
/// store drops them, see `detail::digest_put_cell`). `ord` is the row's position, not a stored
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
            detail::digest_put_cell(out, k < row.size() ? std::string_view(row[k]) : std::string_view());
    }
    return out;
}

/// The layout version this build writes and recomputes.
inline constexpr std::string_view kSectionDigestPrefix = "v1:";

/// What a non-NULL stored digest is, for the verifier. Only `kOtherLayout` is unverified.
enum class StoredDigestForm {
    kCurrent,     ///< starts with `v1:`: compare it with the recomputed digest
    kOtherLayout, ///< a well-formed digest of a layout version other than 1: unverified
    kMalformed,   ///< anything else: a mismatch
};

/// The most digits a layout version may have. A longer run of digits is damage, not a version.
inline constexpr std::size_t kMaxDigestLayoutDigits = 6;

/// Classifies a stored (non-NULL) digest. Pure and total. A different-layout value is
/// `v<version>:<remainder>` with a version of 1 to 6 ASCII digits, no leading zero (so no `v0`, no
/// `v01`) that is not 1 (that is `kCurrent`), and a NON-EMPTY remainder: a layout bump always
/// writes a digest after the colon, so `v2:` alone is a truncated column, not a future layout. The
/// remainder is otherwise opaque to this build.
[[nodiscard]] inline StoredDigestForm classify_stored_digest(std::string_view stored) noexcept {
    if (stored.substr(0, kSectionDigestPrefix.size()) == kSectionDigestPrefix)
        return StoredDigestForm::kCurrent;
    if (stored.empty() || stored[0] != 'v')
        return StoredDigestForm::kMalformed;
    std::size_t i = 1;
    while (i < stored.size() && stored[i] >= '0' && stored[i] <= '9')
        ++i;
    const std::size_t digits = i - 1;
    if (digits == 0 || digits > kMaxDigestLayoutDigits || stored[1] == '0')
        return StoredDigestForm::kMalformed;
    if (i >= stored.size() || stored[i] != ':')
        return StoredDigestForm::kMalformed;
    if (i + 1 >= stored.size())
        return StoredDigestForm::kMalformed; // nothing after the colon
    return StoredDigestForm::kOtherLayout;
}

/// `v1:` + SHA-256 (64 lowercase hex) of `section_content_preimage` for a REGISTERED table-backed
/// kind - the one entry point the writer and the read mapping both call, so the kind name and
/// column count always come from the registry. nullopt when the digest provider fails. Callers
/// treat nullopt as "cannot verify": the writer aborts the ingest (never stores a section without
/// its digest by accident), the reader serves the section `constrained` with
/// `server:content_digest_unverifiable` (a server-side fault, not a mismatch).
/// `digest` is the provider (#7163): production callers take the default (`sha256_hex`); a test
/// passes a failing one to reach the provider-failure branches.
[[nodiscard]] inline std::optional<std::string>
section_content_digest(const DeviceCiSectionDef& def,
                       const std::vector<std::vector<std::string>>& rows,
                       DigestFn digest = &sha256_hex) {
    auto hex =
        digest(section_content_preimage(def.section, static_cast<std::size_t>(def.n_fields), rows));
    if (!hex)
        return std::nullopt;
    std::string out{kSectionDigestPrefix};
    out += *hex;
    return out;
}

} // namespace yuzu::server
