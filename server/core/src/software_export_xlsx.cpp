/// @file software_export_xlsx.cpp
/// See software_export_xlsx.hpp. The ONLY translation unit that includes the spreadsheet library.
///
/// Derivation of the constants, read from libxlsxwriter 1.2.4 (the vcpkg port at the repo baseline
/// builds exactly that tag; line numbers are that tag's):
///
///  * CELL. Constant-memory mode stores a string as an inline string (worksheet.c:7933
///    worksheet_write_string, optimize branch) and _write_inline_string_cell (worksheet.c:4449)
///    prints, for one cell:
///      <c r="REF" s="N" t="inlineStr"><is><t xml:space="preserve">TEXT</t></is></c>
///    The `s` attribute appears only for a styled cell (the header; at most three digits) and the
///    `xml:space` attribute only when the text starts or ends with white space. The longest REF is
///    ten characters (column XFD, row 1048576). Counting every optional attribute as present:
///      `<c r="` 6 + REF 10 + `"` 1 + ` s="999"` 8 + ` t="inlineStr"` 14 + `>` 1 + `<is>` 4
///      + `<t` 2 + ` xml:space="preserve"` 21 + `>` 1 + `</t>` 4 + `</is>` 5 + `</c>` 4 = 81
///    rounded up to kXlsxCellOverheadBytes = 88.
///  * TEXT. lxw_escape_data (xmlwriter.c:204) rewrites only & (5 bytes), < and > (4 bytes each);
///    lxw_escape_control_characters (xmlwriter.c, called when lxw_has_control_characters finds a
///    byte below 0x20 other than tab and line feed) rewrites each such byte as `_xHHHH_`, 7 bytes.
///    After xlsx_clean_cell the only such byte left is the carriage return. xlsx_cell_cost applies
///    exactly these four expansions; the worst is 7 bytes per source byte (kXlsxMaxEscapeFactor).
///    An empty string without a format is ignored by the library (worksheet.c:7942): no cell, cost 0.
///  * ROW. lxw_worksheet_write_single_row (worksheet.c:4763) writes `<row r="N"` (N at most seven
///    digits), optionally ` x14ac:dyDescent="0.25"` (22 bytes), then `>` and `</row>`. At most 45
///    bytes; rounded up to kXlsxRowOverheadBytes = 64. A row whose cells are all empty is not
///    written at all.
///  * FIXED. The sheet preamble and tail (dimension, one frozen pane, sheetFormatPr, page margins,
///    namespaces: well under 2 KiB) plus the workbook's other parts (styles, theme, workbook, rels,
///    content types, document properties: about 10 KiB uncompressed) are covered by
///    kXlsxSheetFixedBytes = 64 KiB. The finished file holds those parts compressed and the sheet
///    compressed, so it is never above sheet_bytes().
///
/// Derivation of kXlsxPeakDiskFactor: constant-memory mode keeps the rows in ONE temporary file R
/// (worksheet.c:201-217, a file created in the tmpdir and unlinked at once, tmpfileplus.c:244).
/// workbook_close assembles the sheet (packager.c:284 _write_worksheet_files): it creates a second
/// temporary file A, writes the sheet preamble, copies R into it and closes R
/// (worksheet.c:2558 _worksheet_write_optimized_sheet_data), writes the tail, then streams A
/// through deflate into the output file Z (packager.c _add_to_zip, 16 KiB buffer) and closes A.
/// Alive together: R and A at the copy (2 x sheet), then A and Z (1 x sheet plus Z, which is the
/// compressed sheet and cannot pass the sheet). Peak: about 2 x sheet bytes, so the factor 3
/// covers it with a third of margin. Every other temporary file is a part of a few KiB.
///
/// The library's temporary-file helper (tmpfileplus.c:266) tries the directory given, then
/// $TMPDIR, then /tmp, then the working directory: a failed create in the given directory moves
/// the file to another volume without a word. open() refuses a directory that does not exist,
/// which closes the common case; a create that fails inside an existing directory (descriptor
/// limit, permissions) is a residual stated in the Resource Ledger. The helper also seeds a
/// static counter and calls srand/rand without a lock (tmpfileplus.c:136), a data race between
/// two exports in two threads: every call that can create a temporary file (add_worksheet and
/// close) therefore runs under one process-wide mutex.

#include "software_export_xlsx.hpp"

#include "utf8_sanitize.hpp"

#include <xlsxwriter.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server::software_export {

namespace fs = std::filesystem;

namespace {

// ponytail: one lock for every library call that creates a temporary file, so two exports close
// one after the other (a close of a large sheet takes seconds). Per-export locking is not safe
// while the library's name generator shares unlocked static state; replace it with a library that
// takes a caller-supplied file source if closes ever need to overlap.
std::mutex& library_mutex() {
    static std::mutex m;
    return m;
}

} // namespace

std::string xlsx_clean_cell(std::string_view in, bool* truncated) {
    if (truncated)
        *truncated = false;
    const std::string utf8 = sanitize_utf8_strict(in);
    std::string out;
    out.reserve(utf8.size());
    for (std::size_t i = 0; i < utf8.size();) {
        const auto c = static_cast<unsigned char>(utf8[i]);
        if (c < 0x20) { // C0: keep tab, line feed, carriage return; XML 1.0 forbids the rest
            if (c == 0x09 || c == 0x0A || c == 0x0D)
                out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        // U+FFFE and U+FFFF (EF BF BE / EF BF BF) are not XML 1.0 characters either.
        if (c == 0xEF && i + 2 < utf8.size() && static_cast<unsigned char>(utf8[i + 1]) == 0xBF &&
            (static_cast<unsigned char>(utf8[i + 2]) == 0xBE ||
             static_cast<unsigned char>(utf8[i + 2]) == 0xBF)) {
            i += 3;
            continue;
        }
        out.push_back(utf8[i]);
        ++i;
    }
    if (out.size() > static_cast<std::size_t>(kXlsxMaxCellBytes)) {
        std::size_t cut = static_cast<std::size_t>(kXlsxMaxCellBytes);
        // out[cut] exists (size > cut); step back to the start of the sequence it belongs to.
        while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80)
            --cut;
        out.resize(cut);
        if (truncated)
            *truncated = true;
    }
    return out;
}

std::int64_t xlsx_cell_cost(std::string_view cleaned) {
    if (cleaned.empty())
        return 0;
    auto n = static_cast<std::int64_t>(cleaned.size());
    for (const char c : cleaned) {
        switch (c) {
        case '&': n += 4; break;  // &amp;
        case '<':
        case '>': n += 3; break;  // &lt; &gt;
        case '\r': n += 6; break; // _x000D_
        default: break;
        }
    }
    return kXlsxCellOverheadBytes + n;
}

std::expected<void, std::string> create_owner_only_exclusive(const fs::path& path) {
#ifdef _WIN32
    (void)path;
    return std::unexpected("exclusive owner-only creation is not supported on this platform");
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return std::unexpected(std::string("cannot create the export file: ") +
                               std::strerror(errno));
    if (::close(fd) != 0)
        return std::unexpected(std::string("cannot close the export file: ") +
                               std::strerror(errno));
    return {};
#endif
}

struct XlsxSheetWriter::Impl {
    lxw_workbook* workbook{nullptr};
    lxw_worksheet* sheet{nullptr};
    fs::path file;
    std::size_t columns{0};
    std::int64_t rows{0};
    std::int64_t sheet_bytes{kXlsxSheetFixedBytes};
    std::int64_t truncated{0};
    bool failed{false};
    bool closed{false};
    std::vector<std::string> scratch; // the current row's cleaned cells, reused

    // workbook_close frees the workbook on every outcome, so it runs exactly once.
    lxw_error close_workbook() {
        const std::lock_guard lock(library_mutex());
        closed = true;
        const lxw_error e = workbook_close(workbook);
        workbook = nullptr;
        sheet = nullptr;
        return e;
    }

    ~Impl() {
        if (workbook && !closed)
            (void)close_workbook();
    }
};

XlsxSheetWriter::XlsxSheetWriter(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
XlsxSheetWriter::XlsxSheetWriter(XlsxSheetWriter&&) noexcept = default;
XlsxSheetWriter& XlsxSheetWriter::operator=(XlsxSheetWriter&&) noexcept = default;
XlsxSheetWriter::~XlsxSheetWriter() = default;

std::expected<XlsxSheetWriter, std::string>
XlsxSheetWriter::open(const fs::path& file, const fs::path& tmp_dir, std::string_view sheet_name,
                      std::span<const std::string_view> header) {
    if (header.empty())
        return std::unexpected("the sheet needs at least one column");
    std::error_code ec;
    if (!fs::is_directory(tmp_dir, ec))
        return std::unexpected("the temporary directory does not exist or is not a directory");
    const auto parent = file.has_parent_path() ? file.parent_path() : fs::path(".");
    if (!fs::is_directory(parent, ec))
        return std::unexpected("the output directory does not exist or is not a directory");

    const std::string file_s = file.string();
    const std::string tmp_s = tmp_dir.string();
    const std::string name_s(sheet_name);
    lxw_workbook_options options{};
    options.constant_memory = LXW_TRUE;
    options.tmpdir = tmp_s.c_str(); // the library copies it
    options.use_zip64 = LXW_TRUE;   // a sheet past 4 GiB must still be a valid zip

    auto impl = std::make_unique<Impl>();
    impl->file = file;
    impl->columns = header.size();
    impl->workbook = workbook_new_opt(file_s.c_str(), &options);
    if (!impl->workbook)
        return std::unexpected("cannot create the workbook");
    {
        const std::lock_guard lock(library_mutex());
        impl->sheet = workbook_add_worksheet(impl->workbook, name_s.c_str());
    }
    if (!impl->sheet)
        return std::unexpected("cannot create the worksheet"); // ~Impl closes the workbook

    lxw_format* bold = workbook_add_format(impl->workbook);
    if (!bold)
        return std::unexpected("cannot create the header format");
    format_set_bold(bold);
    worksheet_freeze_panes(impl->sheet, 1, 0);
    std::int64_t header_cost = kXlsxRowOverheadBytes;
    for (std::size_t i = 0; i < header.size(); ++i) {
        bool cut = false;
        const std::string text = xlsx_clean_cell(header[i], &cut);
        header_cost += xlsx_cell_cost(text);
        const lxw_error e = worksheet_write_string(impl->sheet, 0, static_cast<lxw_col_t>(i),
                                                   text.c_str(), bold);
        if (e != LXW_NO_ERROR)
            return std::unexpected(std::string("cannot write the header: ") + lxw_strerror(e));
    }
    impl->sheet_bytes += header_cost;
    return XlsxSheetWriter(std::move(impl));
}

XlsxSheetWriter::Append XlsxSheetWriter::append(std::span<const std::string> cells,
                                                std::int64_t allowance) {
    if (!impl_)
        return Append::failed;
    Impl& m = *impl_;
    if (m.failed || m.closed || cells.size() != m.columns || m.rows >= kXlsxMaxDataRows)
        return Append::failed;

    // The row's cost is settled BEFORE the library sees a byte, so over_budget writes nothing.
    m.scratch.resize(cells.size());
    std::int64_t cost = kXlsxRowOverheadBytes;
    std::int64_t cut_cells = 0;
    for (std::size_t i = 0; i < cells.size(); ++i) {
        bool cut = false;
        m.scratch[i] = xlsx_clean_cell(cells[i], &cut);
        cut_cells += cut ? 1 : 0;
        cost += xlsx_cell_cost(m.scratch[i]);
    }
    if (cost > allowance - m.sheet_bytes)
        return Append::over_budget;

    const auto row = static_cast<lxw_row_t>(m.rows + 1); // row 0 is the header
    for (std::size_t i = 0; i < m.scratch.size(); ++i) {
        // Always the string-cell call: never a formula, number or date.
        const lxw_error e = worksheet_write_string(m.sheet, row, static_cast<lxw_col_t>(i),
                                                   m.scratch[i].c_str(), nullptr);
        if (e != LXW_NO_ERROR) {
            m.failed = true; // the row may be half written: nothing more goes in
            return Append::failed;
        }
    }
    ++m.rows;
    m.sheet_bytes += cost;
    m.truncated += cut_cells;
    return Append::ok;
}

std::int64_t XlsxSheetWriter::rows() const noexcept {
    return impl_ ? impl_->rows : 0;
}
std::int64_t XlsxSheetWriter::sheet_bytes() const noexcept {
    return impl_ ? impl_->sheet_bytes : 0;
}
std::int64_t XlsxSheetWriter::cells_truncated() const noexcept {
    return impl_ ? impl_->truncated : 0;
}

std::expected<std::uintmax_t, std::string> XlsxSheetWriter::close() {
    if (!impl_ || impl_->closed || !impl_->workbook)
        return std::unexpected("the workbook is already closed");
    const bool was_failed = impl_->failed;
    const lxw_error e = impl_->close_workbook();
    if (was_failed)
        return std::unexpected("an earlier write failed; the workbook is incomplete");
    if (e != LXW_NO_ERROR)
        return std::unexpected(std::string("cannot assemble the workbook: ") + lxw_strerror(e));
    std::error_code ec;
    const auto size = fs::file_size(impl_->file, ec);
    if (ec)
        return std::unexpected("cannot read the workbook size: " + ec.message());
    return size;
}

bool XlsxDiskBudget::grant(std::int64_t bytes, std::optional<std::uintmax_t> free_now) {
    if (bytes <= 0 || !free_now)
        return false;
    const auto reserve = static_cast<std::uintmax_t>(kXlsxDiskReserveBytes);
    if (*free_now < reserve)
        return false;
    const std::lock_guard lock(mu_);
    // free - reserve >= factor x want, divided through so no product can overflow.
    const auto want = static_cast<std::uintmax_t>(granted_) + static_cast<std::uintmax_t>(bytes);
    if (want > (*free_now - reserve) / static_cast<std::uintmax_t>(kXlsxPeakDiskFactor))
        return false;
    granted_ += bytes;
    return true;
}

void XlsxDiskBudget::release(std::int64_t bytes) noexcept {
    const std::lock_guard lock(mu_);
    granted_ = bytes >= granted_ ? 0 : granted_ - bytes;
}

std::int64_t XlsxDiskBudget::granted() const {
    const std::lock_guard lock(mu_);
    return granted_;
}

} // namespace yuzu::server::software_export
