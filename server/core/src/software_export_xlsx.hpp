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
///  * COMPLETE OR AN ERROR. close() returns a size only for a workbook it has read back and checked
///    (xlsx_verify_workbook), because the library cannot be trusted to say a write failed. Three
///    facts of libxlsxwriter 1.2.4 (the vcpkg port at the repo baseline) are relied on, and a
///    library upgrade must re-read each:
///      1. worksheet.c:2558-2595 (_worksheet_write_optimized_sheet_data, a STATIC void) ignores the
///         results of fflush, fread and fwrite: a failed read of the row file looks like the end of
///         the file and a failed write of the assembled sheet is dropped, so the sheet can come out
///         short or empty while workbook_close returns LXW_NO_ERROR and the zip is well formed.
///      2. xmlwriter.c:53-143 and :380-409 write every tag, row and cell with an unchecked
///         fprintf, so a failed write of the row file leaves only the stream's error flag.
///      3. worksheet.c:2581 and packager.c:2078 rewind the row file and the assembled sheet before
///         reading them, which clears that flag: after workbook_close nothing records the failure.
///    So the row file's error flag is read after every row, the row file is flushed and read once
///    more BEFORE workbook_close, its exact size is taken as the byte length of the sheet's
///    <sheetData> content, and the finished file is read back once through minizip's unzip API in
///    constant memory (one extra read pass, no extra disk): every part reads to a clean CRC, is not
///    empty, begins with the XML declaration and ends with its root element's closing tag,
///    xl/worksheets/sheet1.xml exists, and </sheetData> sits exactly that many bytes after
///    <sheetData>.

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
/// The ZIP64 sentinel: 0xFFFFFFFF (4,294,967,295 bytes, one byte under 4 GiB) is the size value the
/// zip format reserves to mean "see the ZIP64 field", so an entry that can reach it needs the ZIP64
/// extensions (the largest plain size is 0xFFFFFFFE). The route turns ZIP64 on when the byte limit
/// is at or above it.
inline constexpr std::int64_t kXlsxZip64Threshold = 0xFFFFFFFFLL;

/// Which cap a request's row limit resolves to, and what the 413 names as its source.
struct XlsxRowCap {
    std::int64_t rows;
    std::string_view named;
};
[[nodiscard]] constexpr XlsxRowCap xlsx_row_cap(std::int64_t max_rows) noexcept {
    if (max_rows >= kXlsxMaxDataRows)
        return {kXlsxMaxDataRows, "the sheet's own limit"};
    return {max_rows, "--inventory-export-max-rows"};
}

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

/// Reads the finished workbook `file` back once, in constant memory (a 64 KiB buffer), and
/// returns an error naming the first defect: not a readable zip, a part that does not read to a
/// clean CRC, is empty, does not begin with the XML declaration or does not end with its root
/// element's closing tag (trailing white space ignored), no xl/worksheets/sheet1.xml, or
/// `</sheetData>` not exactly `sheet_data_bytes` bytes after the sheet's `<sheetData>`.
/// `sheet_data_bytes` is the size of the library's row file, which is the byte length of the
/// <sheetData> content (see the rules above).
[[nodiscard]] std::expected<void, std::string>
xlsx_verify_workbook(const std::filesystem::path& file, std::int64_t sheet_data_bytes);

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
    /// close(). `zip64` writes a ZIP64 container; it is needed only when one entry can reach the
    /// ZIP64 sentinel (kXlsxZip64Threshold, one byte under 4 GiB), and every small entry of such a
    /// container carries the extra ZIP64 fields, so it stays off otherwise.
    [[nodiscard]] static std::expected<XlsxSheetWriter, std::string>
    open(const std::filesystem::path& file, const std::filesystem::path& tmp_dir,
         std::string_view sheet_name, std::span<const std::string_view> header,
         bool zip64 = false);

    XlsxSheetWriter(XlsxSheetWriter&&) noexcept;
    XlsxSheetWriter& operator=(XlsxSheetWriter&&) noexcept;
    XlsxSheetWriter(const XlsxSheetWriter&) = delete;
    XlsxSheetWriter& operator=(const XlsxSheetWriter&) = delete;
    /// Closes the workbook if it is still open (the library offers no cheaper release), and never
    /// throws. The caller removes the file.
    ~XlsxSheetWriter();

    /// One data row. `cells` must hold exactly the header's column count. When the row's cost
    /// would take sheet_bytes() past `allowance`, nothing is written and no counter moves
    /// (over_budget). `failed` has three causes: a library error, or an error on the library's row
    /// file (a volume that stopped taking writes), makes the writer unusable and close() fail; a
    /// wrong cell count fails that call only and the writer stays usable; a full sheet
    /// (kXlsxMaxDataRows) fails every later append, and close() still succeeds.
    [[nodiscard]] Append append(std::span<const std::string> cells, std::int64_t allowance);

    [[nodiscard]] std::int64_t rows() const noexcept;            ///< data rows written
    [[nodiscard]] std::int64_t sheet_bytes() const noexcept;     ///< the accounted upper bound
    [[nodiscard]] std::int64_t cells_truncated() const noexcept; ///< cells cut to kXlsxMaxCellBytes

    /// Assembles the file, reads it back and checks it (xlsx_verify_workbook), and returns its
    /// size: any failed write the library did not report is an error here, never a short
    /// workbook. A second call, or a call after a failed append, fails.
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
