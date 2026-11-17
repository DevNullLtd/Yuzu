#pragma once

/// @file software_export_xlsx.hpp
/// The XLSX writer behind `format=xlsx` of the installed-software export (SAM-36b). The interface
/// is standard-library only: the spreadsheet library's headers stay in software_export_xlsx.cpp
/// behind a pimpl, so this header (and the pure budget below) builds and tests without it.
///
/// Rules this file owns (each stated once, here):
///  * ONE SHEET, EVERY CELL TEXT. Every cell is written through the library's string-cell call,
///    never as a formula, number or date, so a cell that begins with = + - or @ is inert text by
///    construction (no neutralising prefix is needed or added, unlike the CSV).
///  * CONSTANT MEMORY. The library runs in its constant-memory mode: one row is held at a time and
///    the rest goes to a temporary file in the directory the caller names.
///  * SHEET BYTES, the unit every XLSX size limit uses. `sheet_bytes()` is an UPPER BOUND on the
///    uncompressed worksheet XML the writer has made the library write: per cell the cell text
///    after XML escaping exactly as the library escapes it plus kXlsxCellOverheadBytes, per row
///    kXlsxRowOverheadBytes, plus kXlsxSheetFixedBytes once. `append` computes a row's cost FIRST
///    and writes nothing when it would pass the caller's allowance, so a limit holds for any cell
///    content (short cells and escape-heavy text included). Derivation of the constants:
///    software_export_xlsx.cpp; they are pinned by the accounting test and must be re-derived on
///    a library upgrade.
///  * DISK. One export holds at most kXlsxPeakDiskFactor x its sheet bytes of the data volume at
///    any moment (see the .cpp for the library files that are alive at once). XlsxDiskBudget is the
///    pure arbiter that keeps the SUM over all live exports inside the free space.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server::software_export {

/// Data rows a sheet can hold: the format's 1,048,576 rows minus the header row.
inline constexpr std::int64_t kXlsxMaxDataRows = 1'048'575;
/// One cell's text is cut to this many bytes (at a code-point boundary). The spreadsheet limit is
/// 32,767 CHARACTERS; a byte cap at the same number is never above it.
inline constexpr std::int64_t kXlsxMaxCellBytes = 32'767;

/// Sheet-byte accounting constants (derivation in software_export_xlsx.cpp).
inline constexpr std::int64_t kXlsxCellOverheadBytes = 88;
inline constexpr std::int64_t kXlsxRowOverheadBytes = 64;
inline constexpr std::int64_t kXlsxSheetFixedBytes = std::int64_t{64} << 10;
/// The most one cell's escaped text can cost per source byte (a carriage return becomes `_x000D_`).
inline constexpr std::int64_t kXlsxMaxEscapeFactor = 7;

/// Peak temporary disk of one export, as a multiple of its sheet bytes.
inline constexpr std::int64_t kXlsxPeakDiskFactor = 3;
/// Free space the data volume must keep after every live export's peak.
inline constexpr std::int64_t kXlsxDiskReserveBytes = std::int64_t{1} << 30;
/// The unit an export asks the budget for, in sheet bytes.
inline constexpr std::int64_t kXlsxDiskGrantBytes = std::int64_t{16} << 20;

/// The text a cell carries after cleaning: invalid UTF-8 becomes U+FFFD, the characters XML 1.0
/// forbids (C0 controls except tab, line feed and carriage return; U+FFFE; U+FFFF) are removed,
/// and the result is cut to kXlsxMaxCellBytes at a code-point boundary. `*truncated` is set when
/// the cut happened.
[[nodiscard]] std::string xlsx_clean_cell(std::string_view in, bool* truncated);

/// Sheet bytes one cleaned cell adds: 0 for empty text (the library writes no cell for it), else
/// kXlsxCellOverheadBytes plus the text's length after the library's XML escaping.
[[nodiscard]] std::int64_t xlsx_cell_cost(std::string_view cleaned);

/// Create `path` empty, exclusively and owner-only (O_CREAT | O_EXCL | O_CLOEXEC, mode 0600): an
/// existing path (a link included) is refused and left untouched.
[[nodiscard]] std::expected<void, std::string>
create_owner_only_exclusive(const std::filesystem::path& path);

/// One-sheet workbook writer; move-only. See the file comment.
class XlsxSheetWriter {
public:
    enum class Append { ok, over_budget, failed };

    /// Opens a workbook that will be written to `file` (which may already exist, empty, and is
    /// truncated at close), with its temporary files in `tmp_dir`, and writes the bold, frozen
    /// header row. Nothing is read from or written to disk beyond the library's own files until
    /// close().
    [[nodiscard]] static std::expected<XlsxSheetWriter, std::string>
    open(const std::filesystem::path& file, const std::filesystem::path& tmp_dir,
         std::string_view sheet_name, std::span<const std::string_view> header);

    XlsxSheetWriter(XlsxSheetWriter&&) noexcept;
    XlsxSheetWriter& operator=(XlsxSheetWriter&&) noexcept;
    XlsxSheetWriter(const XlsxSheetWriter&) = delete;
    XlsxSheetWriter& operator=(const XlsxSheetWriter&) = delete;
    /// Closes the workbook if it is still open (the library offers no cheaper release), and never
    /// throws. The caller removes the file.
    ~XlsxSheetWriter();

    /// One data row. `cells` must hold exactly the header's column count. When the row's cost
    /// would take sheet_bytes() past `allowance`, nothing is written and no counter moves
    /// (over_budget). A library error, a wrong cell count or a full sheet is `failed`, after which
    /// the writer accepts nothing more.
    [[nodiscard]] Append append(std::span<const std::string> cells, std::int64_t allowance);

    [[nodiscard]] std::int64_t rows() const noexcept;            ///< data rows written
    [[nodiscard]] std::int64_t sheet_bytes() const noexcept;     ///< the accounted upper bound
    [[nodiscard]] std::int64_t cells_truncated() const noexcept; ///< cells cut to kXlsxMaxCellBytes

    /// Assembles the file; returns its size. A second call, or a call after a failed append,
    /// fails.
    [[nodiscard]] std::expected<std::uintmax_t, std::string> close();

private:
    struct Impl;
    explicit XlsxSheetWriter(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

/// The total sheet bytes granted to every live XLSX export, and the one rule that keeps their
/// worst-case disk use inside the data volume's free space. Pure: the caller reads the free
/// space and passes it in, so concurrent exports cannot each count the same free space (the
/// check runs under this mutex against everything already granted).
class XlsxDiskBudget {
public:
    /// True and counted when the free space less kXlsxDiskReserveBytes covers
    /// kXlsxPeakDiskFactor x (granted + bytes). An unknown free space refuses.
    [[nodiscard]] bool grant(std::int64_t bytes, std::optional<std::uintmax_t> free_now);
    void release(std::int64_t bytes) noexcept;
    [[nodiscard]] std::int64_t granted() const;

private:
    mutable std::mutex mu_;
    std::int64_t granted_{0};
};

} // namespace yuzu::server::software_export
