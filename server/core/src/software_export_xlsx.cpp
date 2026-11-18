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
///
/// Derivation of the completeness check (what close() relies on; line numbers are 1.2.4's):
///  * The library does not report a failed write. _worksheet_write_optimized_sheet_data
///    (worksheet.c:2558-2595) is STATIC void and drops the result of fflush (:2572), of every fread
///    of the row file R and of every fwrite of the assembled sheet A (its own comment: "There is no
///    easy way to raise error"); a failed fread reads as end of file. Every row and cell reaches R
///    through an unchecked fprintf (xmlwriter.c:53-143, :380-409). rewind() clears a stream's error
///    flag, and R and A are both rewound before they are read (worksheet.c:2581, packager.c:2078).
///    A fault therefore leaves a CRC-clean zip whose sheet1.xml is short or empty and a
///    workbook_close that returns LXW_NO_ERROR (reproduced with RLIMIT_FSIZE on 1.2.4: 0 of 5,001
///    rows delivered, no error from 115,023 string writes or from workbook_close).
///  * R can still be inspected BEFORE workbook_close. lxw_worksheet_write_single_row (worksheet.h)
///    is the call the packager makes first (packager.c:304) to push the row still held in memory;
///    made here it leaves the packager's own later call nothing to write, so the bytes are the
///    same. After it, fflush(R) and ferror(R) say whether R took every write, and ftello(R) is the
///    exact byte length of what the library will copy between <sheetData> and </sheetData> (the
///    two tags are written around the copy, worksheet.c:2569 and :2593).
///  * A fault after that point (R unreadable, A or the output file unwritable) is not reported
///    either, so the finished file is read back: each part must read to a clean CRC, be non-empty
///    and be a whole XML document (declaration first, the root's closing tag last), and the sheet
///    must hold </sheetData> exactly ftello(R) bytes after <sheetData>. A write that failed inside
///    A shortens the copy or drops its tail; a read that failed in R ends the copy early; both
///    break the span. Residual: a dropped block inside the sheet preamble alone, with every later
///    write landing, is not seen (the preamble is a few hundred bytes, inside the first stdio
///    block).

#include "software_export_xlsx.hpp"

#include "utf8_sanitize.hpp"

#include <xlsxwriter.h>
#include <minizip/unzip.h>

// The completeness check below depends on facts read from libxlsxwriter 1.2.4's source (listed at
// the top of this file and in the header) and on two of its internals. A library change must be
// re-read against them before this number moves.
static_assert(LXW_VERSION_ID == 124,
              "libxlsxwriter changed: re-derive the completeness check (software_export_xlsx.hpp)");

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
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

// Bounds of the read-back pass (constant memory whatever the sheet's size).
constexpr std::size_t kVerifyBufferBytes = 64 * 1024; // one read of an entry
constexpr std::size_t kVerifyHeadBytes = 512;         // the XML declaration and the root tag
constexpr std::size_t kVerifyTailBytes = 128;         // the root's closing tag and white space
constexpr std::size_t kVerifyPreambleBytes = 64 * 1024; // the most sheet bytes before <sheetData>
constexpr std::string_view kSheetEntry = "xl/worksheets/sheet1.xml";
constexpr std::string_view kSheetDataOpen = "<sheetData>";
constexpr std::string_view kSheetDataClose = "</sheetData>";

// The owner of an open zip: minizip's handle is a void pointer with a close call, nothing more.
struct UnzCloser {
    void operator()(void* zf) const noexcept {
        if (zf)
            unzClose(zf);
    }
};
using UnzHandle = std::unique_ptr<void, UnzCloser>;

// What one entry must look like, from its first and last bytes only.
class EntryShape {
public:
    void feed(const char* data, std::size_t n) {
        total_ += n;
        if (head_.size() < kVerifyHeadBytes)
            head_.append(data, std::min(n, kVerifyHeadBytes - head_.size()));
        if (n >= kVerifyTailBytes) {
            tail_.assign(data + (n - kVerifyTailBytes), kVerifyTailBytes);
        } else {
            tail_.append(data, n);
            if (tail_.size() > kVerifyTailBytes)
                tail_.erase(0, tail_.size() - kVerifyTailBytes);
        }
    }

    // The first thing wrong with the entry, or nothing.
    [[nodiscard]] std::optional<std::string> defect() const {
        if (total_ == 0)
            return "is empty";
        constexpr std::string_view kDeclaration = "<?xml";
        if (!head_.starts_with(kDeclaration))
            return "does not begin with the XML declaration";
        const auto decl_end = head_.find("?>");
        const auto root_open =
            decl_end == std::string::npos ? std::string::npos : head_.find('<', decl_end + 2);
        if (root_open == std::string::npos)
            return "has no root element";
        const auto name_end = head_.find_first_of(" \t\r\n/>", root_open + 1);
        if (name_end == std::string::npos || name_end == root_open + 1)
            return "has no readable root element name";
        const std::string closing =
            "</" + head_.substr(root_open + 1, name_end - root_open - 1) + ">";
        std::string_view tail(tail_);
        while (!tail.empty() && (tail.back() == ' ' || tail.back() == '\t' ||
                                 tail.back() == '\r' || tail.back() == '\n'))
            tail.remove_suffix(1);
        if (!tail.ends_with(closing))
            return "does not end with the closing tag of its root element";
        return std::nullopt;
    }

private:
    std::uint64_t total_{0};
    std::string head_; // the first kVerifyHeadBytes
    std::string tail_; // the last kVerifyTailBytes
};

// Where </sheetData> must be: `data_bytes` after the end of the first <sheetData>. The preamble is
// held until <sheetData> turns up (bounded), then only the 12 bytes at the target are kept.
class SheetSpan {
public:
    explicit SheetSpan(std::uint64_t data_bytes) : data_bytes_(data_bytes) {}

    void feed(const char* data, std::size_t n) {
        if (target_) {
            absorb(consumed_, data, n);
            consumed_ += n;
            return;
        }
        consumed_ += n;
        if (preamble_.size() > kVerifyPreambleBytes) // no <sheetData> in a sane preamble: give up
            return;
        preamble_.append(data, n);
        const auto at = preamble_.find(kSheetDataOpen);
        if (at == std::string::npos)
            return;
        target_ = at + kSheetDataOpen.size() + data_bytes_;
        absorb(0, preamble_.data(), preamble_.size()); // the bytes read before the target was known
        std::string().swap(preamble_);
    }

    [[nodiscard]] bool closes_where_expected() const {
        return target_ && filled_ == kSheetDataClose.size() &&
               std::string_view(window_.data(), filled_) == kSheetDataClose;
    }

private:
    // The bytes of [at, at + n) that fall in the 12 bytes from target_. Calls arrive in order and
    // cover the entry without a gap, so the window fills from its first byte onwards.
    void absorb(std::uint64_t at, const char* data, std::size_t n) {
        const std::uint64_t lo = std::max(at, *target_);
        const std::uint64_t hi = std::min(at + n, *target_ + kSheetDataClose.size());
        for (std::uint64_t p = lo; p < hi; ++p) {
            window_[static_cast<std::size_t>(p - *target_)] = data[p - at];
            ++filled_;
        }
    }

    std::uint64_t data_bytes_;
    std::uint64_t consumed_{0}; // entry bytes fed so far
    std::optional<std::uint64_t> target_;
    std::string preamble_;
    std::array<char, kSheetDataClose.size()> window_{};
    std::size_t filled_{0};
};

// Offset of a stream (the row file's size once flushed); -1 when it cannot be told.
std::int64_t stream_offset(std::FILE* f) {
#ifdef _WIN32
    return static_cast<std::int64_t>(_ftelli64(f));
#else
    return static_cast<std::int64_t>(::ftello(f));
#endif
}

} // namespace

std::expected<void, std::string> xlsx_verify_workbook(const fs::path& file,
                                                      std::int64_t sheet_data_bytes) {
    if (sheet_data_bytes < 0)
        return std::unexpected("the sheet's data length is unknown");
    const UnzHandle zf(unzOpen64(file.string().c_str()));
    if (!zf)
        return std::unexpected("the workbook is not a readable zip archive");
    unz_global_info64 global{};
    if (unzGetGlobalInfo64(zf.get(), &global) != UNZ_OK || global.number_entry == 0)
        return std::unexpected("the workbook's zip directory is unreadable or empty");

    std::vector<char> buffer(kVerifyBufferBytes);
    std::uint64_t entries = 0;
    bool saw_sheet = false;
    int next = unzGoToFirstFile(zf.get());
    for (; next == UNZ_OK; next = unzGoToNextFile(zf.get())) {
        std::array<char, 256> name{};
        unz_file_info64 info{};
        if (unzGetCurrentFileInfo64(zf.get(), &info, name.data(), name.size(), nullptr, 0, nullptr,
                                    0) != UNZ_OK ||
            info.size_filename >= name.size())
            return std::unexpected("a part of the workbook has an unreadable name");
        const std::string part(name.data());
        ++entries;
        if (unzOpenCurrentFile(zf.get()) != UNZ_OK)
            return std::unexpected(part + ": cannot be opened");
        EntryShape shape;
        std::optional<SheetSpan> span;
        if (part == kSheetEntry)
            span.emplace(static_cast<std::uint64_t>(sheet_data_bytes));
        for (;;) {
            const int n =
                unzReadCurrentFile(zf.get(), buffer.data(), static_cast<unsigned>(buffer.size()));
            if (n < 0) {
                unzCloseCurrentFile(zf.get());
                return std::unexpected(part + ": read error " + std::to_string(n));
            }
            if (n == 0)
                break;
            shape.feed(buffer.data(), static_cast<std::size_t>(n));
            if (span)
                span->feed(buffer.data(), static_cast<std::size_t>(n));
        }
        if (unzCloseCurrentFile(zf.get()) != UNZ_OK) // the CRC is checked here
            return std::unexpected(part + ": checksum mismatch");
        if (const auto defect = shape.defect())
            return std::unexpected(part + ": " + *defect);
        if (span) {
            saw_sheet = true;
            if (!span->closes_where_expected())
                return std::unexpected(
                    part + ": </sheetData> is not where the row file's size puts it");
        }
    }
    if (next != UNZ_END_OF_LIST_OF_FILE || entries != global.number_entry)
        return std::unexpected("the workbook's zip directory cannot be walked to its end");
    if (!saw_sheet)
        return std::unexpected(std::string(kSheetEntry) + " is missing");
    return {};
}

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
                      std::span<const std::string_view> header, bool zip64) {
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
    // Only an entry that can reach the ZIP64 sentinel needs it.
    options.use_zip64 = zip64 ? LXW_TRUE : LXW_FALSE;

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
        const std::string text = xlsx_clean_cell(header[i], nullptr);
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
    // The library never reports a failed write of its row file; the stream's error flag is the
    // only trace, and it is read here (and once more in close()) because the library rewinds the
    // file later, which clears it. A volume that has stopped taking writes ends the build now, not
    // after the rest of the result has been read.
    if (std::ferror(m.sheet->optimize_tmpfile) != 0) {
        m.failed = true;
        return Append::failed;
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
    Impl& m = *impl_;

    // Before workbook_close (see the completeness derivation at the top of this file): push the row
    // still held in memory, flush the row file, and read its error flag and its exact size. A
    // failure here still closes the workbook, the library's only release.
    std::string pre_error;
    std::int64_t data_bytes = 0;
    if (m.failed) {
        pre_error = "an earlier write failed; the workbook is incomplete";
    } else if (std::FILE* rows_file = m.sheet ? m.sheet->optimize_tmpfile : nullptr; !rows_file) {
        pre_error = "the library's row file is missing";
    } else {
        lxw_worksheet_write_single_row(m.sheet);
        if (std::fflush(rows_file) != 0 || std::ferror(rows_file) != 0)
            pre_error = "the library's row file did not take every write; the workbook is "
                        "incomplete";
        else if (data_bytes = stream_offset(rows_file); data_bytes < 0)
            pre_error = "the size of the library's row file cannot be read";
    }
    const lxw_error e = m.close_workbook();
    if (!pre_error.empty())
        return std::unexpected(pre_error);
    if (e != LXW_NO_ERROR)
        return std::unexpected(std::string("cannot assemble the workbook: ") + lxw_strerror(e));
    std::error_code ec;
    const auto size = fs::file_size(m.file, ec);
    if (ec)
        return std::unexpected("cannot read the workbook size: " + ec.message());
    // Outside library_mutex (close_workbook released it): the read-back pass is one more read of
    // the finished file and creates no temporary file, so it never needs to hold the lock.
    if (auto checked = xlsx_verify_workbook(m.file, data_bytes); !checked)
        return std::unexpected("the finished workbook failed its check: " + checked.error());
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
