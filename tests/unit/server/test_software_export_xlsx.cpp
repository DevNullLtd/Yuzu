/**
 * test_software_export_xlsx.cpp - the XLSX writer of the installed-software export
 * (software_export_xlsx.hpp): the workbook it produces, the sheet-byte accounting that every XLSX
 * size limit rests on, the read-back check that turns a write the library did not report into an
 * error, the pure disk budget, and the exclusive owner-only file creation.
 *
 * File justification (the unit-test conventions forbid disk in a unit test unless unavoidable):
 * the spreadsheet library writes files by design, the accounting claim is about the bytes it writes
 * and the completeness claim is about what it does when a write fails, so the fixtures are real
 * workbooks. Each is at most a few hundred rows in a `yuzu_test_` directory the TempDir removes at
 * the end, except the sheet-limit case, whose million rows are all-empty cells (the library writes
 * nothing for them, so it costs row bookkeeping only, no disk), and the three fault cases, whose
 * ~1 MB of highly compressible cells give a row file much larger than the finished workbook.
 * The fault is RLIMIT_FSIZE, the only way to make a real write fail without a full volume: a
 * guard ignores SIGXFSZ, sets the soft limit for one narrow window (no assertion inside it) and
 * restores both, so a failure cannot leak into another case. Nothing here sleeps, spawns a process
 * or opens a socket.
 */

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "software_export_xlsx.hpp"

#include <minizip/unzip.h>
#include <minizip/zip.h>

#include <sys/resource.h>
#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace swe = yuzu::server::software_export;
namespace fs = std::filesystem;

namespace {

using Cells = std::vector<std::string>;

constexpr std::array<std::string_view, 3> kHeader{"agent_id", "name", "version"};

struct Fixture {
    yuzu::test::TempDir dir{"yuzu_test_xlsx_"};
    fs::path file;
    Fixture() {
        fs::create_directories(dir.path);
        file = dir.path / "out.xlsx";
    }
    swe::XlsxSheetWriter writer() {
        auto w = swe::XlsxSheetWriter::open(file, dir.path, "Installed software", kHeader);
        REQUIRE(w.has_value());
        return std::move(*w);
    }
};

// The workbook is read back through minizip: a corrupt zip fails here, not silently.
struct ZipView {
    unzFile zf{nullptr};
    explicit ZipView(const fs::path& p) : zf(unzOpen64(p.string().c_str())) {}
    ~ZipView() {
        if (zf)
            unzClose(zf);
    }
    ZipView(const ZipView&) = delete;
    ZipView& operator=(const ZipView&) = delete;
    [[nodiscard]] bool ok() const { return zf != nullptr; }

    [[nodiscard]] std::optional<std::string> read(const char* name) const {
        if (!zf || unzLocateFile(zf, name, 0) != UNZ_OK || unzOpenCurrentFile(zf) != UNZ_OK)
            return std::nullopt;
        std::string out;
        std::array<char, 16384> buf{};
        for (;;) {
            const int n = unzReadCurrentFile(zf, buf.data(), static_cast<unsigned>(buf.size()));
            if (n < 0) {
                unzCloseCurrentFile(zf);
                return std::nullopt;
            }
            if (n == 0)
                break;
            out.append(buf.data(), static_cast<std::size_t>(n));
        }
        unzCloseCurrentFile(zf);
        return out;
    }
    // Uncompressed size from the zip directory, not from reading the entry.
    [[nodiscard]] std::optional<std::uint64_t> usize(const char* name) const {
        unz_file_info64 info{};
        if (!zf || unzLocateFile(zf, name, 0) != UNZ_OK ||
            unzGetCurrentFileInfo64(zf, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK)
            return std::nullopt;
        return static_cast<std::uint64_t>(info.uncompressed_size);
    }
};

constexpr const char* kSheet = "xl/worksheets/sheet1.xml";

std::size_t count_of(const std::string& hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1))
        ++n;
    return n;
}

// A well-formedness stand-in with no XML parser in the unit target: no byte XML 1.0 forbids, and
// every cell and row that opens also closes.
void require_plausible_xml(const std::string& xml) {
    for (const char c : xml) {
        const auto u = static_cast<unsigned char>(c);
        REQUIRE((u >= 0x20 || u == 0x09 || u == 0x0A || u == 0x0D));
    }
    REQUIRE(count_of(xml, "<c ") == count_of(xml, "</c>"));
    REQUIRE(count_of(xml, "<row ") == count_of(xml, "</row>"));
}

std::int64_t row_cost(const Cells& cells) {
    std::int64_t c = swe::kXlsxRowOverheadBytes;
    for (const auto& s : cells) {
        bool cut = false;
        c += swe::xlsx_cell_cost(swe::xlsx_clean_cell(s, &cut));
    }
    return c;
}

// Version-needed-to-extract of the first local zip header (bytes 4-5, little-endian).
unsigned first_entry_version_needed(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::array<unsigned char, 6> b{};
    in.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(b.size()));
    REQUIRE(in.gcount() == 6);
    return static_cast<unsigned>(b[4]) | (static_cast<unsigned>(b[5]) << 8);
}

struct SheetSize {
    std::int64_t actual;    // sheet1.xml, uncompressed, from the zip directory
    std::int64_t accounted; // sheet_bytes() when the last row was appended
};

// Builds a workbook of `rows` (each appended `reps` times) in its own file and reads back what
// the library wrote against what the writer accounted.
SheetSize build_sheet(Fixture& fx, const char* name, const std::vector<Cells>& rows, int reps) {
    const auto file = fx.dir.path / name;
    auto opened = swe::XlsxSheetWriter::open(file, fx.dir.path, "Installed software", kHeader);
    REQUIRE(opened.has_value());
    auto w = std::move(*opened);
    for (int rep = 0; rep < reps; ++rep)
        for (const auto& r : rows)
            REQUIRE(w.append(r, std::int64_t{1} << 30) == swe::XlsxSheetWriter::Append::ok);
    const auto accounted = w.sheet_bytes();
    REQUIRE(w.close().has_value());
    ZipView zip(file);
    REQUIRE(zip.ok());
    const auto actual = zip.usize(kSheet);
    REQUIRE(actual.has_value());
    return {static_cast<std::int64_t>(*actual), accounted};
}

// The sheet's <sheetData> content length: what the writer's row file measures before the close.
std::int64_t data_bytes_of(const std::string& sheet_xml) {
    const auto open = sheet_xml.find("<sheetData>");
    const auto close = sheet_xml.find("</sheetData>");
    REQUIRE(open != std::string::npos);
    REQUIRE(close != std::string::npos);
    return static_cast<std::int64_t>(close - (open + std::string_view("<sheetData>").size()));
}

// Copies `src` to `dst` part by part, with the content of the parts named in `replace` swapped for
// the given text (an empty text empties the part) and the part named `omit` left out. Whole parts
// are held in memory: the fixtures are well under a megabyte.
void rewrite_zip(const fs::path& src, const fs::path& dst,
                 const std::map<std::string, std::string>& replace, const std::string& omit = {}) {
    ZipView in(src);
    REQUIRE(in.ok());
    zipFile out = zipOpen64(dst.string().c_str(), APPEND_STATUS_CREATE);
    REQUIRE(out != nullptr);
    int rc = unzGoToFirstFile(in.zf);
    while (rc == UNZ_OK) {
        std::array<char, 256> name{};
        unz_file_info64 info{};
        REQUIRE(unzGetCurrentFileInfo64(in.zf, &info, name.data(), name.size(), nullptr, 0, nullptr,
                                        0) == UNZ_OK);
        const std::string part(name.data());
        if (part != omit) {
            const auto original = in.read(part.c_str());
            REQUIRE(original.has_value());
            const auto swap = replace.find(part);
            const std::string& body = swap == replace.end() ? *original : swap->second;
            zip_fileinfo zi{};
            REQUIRE(zipOpenNewFileInZip64(out, part.c_str(), &zi, nullptr, 0, nullptr, 0, nullptr,
                                          Z_DEFLATED, Z_DEFAULT_COMPRESSION, 0) == ZIP_OK);
            if (!body.empty())
                REQUIRE(zipWriteInFileInZip(out, body.data(),
                                            static_cast<unsigned>(body.size())) == ZIP_OK);
            REQUIRE(zipCloseFileInZip(out) == ZIP_OK);
        }
        rc = unzGoToNextFile(in.zf);
    }
    REQUIRE(rc == UNZ_END_OF_LIST_OF_FILE);
    REQUIRE(zipClose(out, nullptr) == ZIP_OK);
}

// Makes a real write fail: the soft file-size limit for one narrow window. SIGXFSZ is ignored so
// the failing write returns EFBIG instead of killing the process, and both are restored on every
// path. Hold it only around library calls: no assertion inside the window. (The same guard is in
// test_software_export_routes.cpp; the shared test header is outside this change.)
class FsizeLimit {
public:
    explicit FsizeLimit(std::uintmax_t bytes) {
        if (getrlimit(RLIMIT_FSIZE, &old_) != 0)
            return;
        old_signal_ = std::signal(SIGXFSZ, SIG_IGN);
        rlimit lim = old_;
        lim.rlim_cur = static_cast<rlim_t>(bytes);
        armed_ = setrlimit(RLIMIT_FSIZE, &lim) == 0;
    }
    ~FsizeLimit() {
        if (armed_)
            setrlimit(RLIMIT_FSIZE, &old_);
        if (old_signal_ != SIG_ERR)
            std::signal(SIGXFSZ, old_signal_);
    }
    FsizeLimit(const FsizeLimit&) = delete;
    FsizeLimit& operator=(const FsizeLimit&) = delete;
    [[nodiscard]] bool armed() const { return armed_; }

private:
    rlimit old_{};
    void (*old_signal_)(int){SIG_ERR};
    bool armed_{false};
};

// Rows of three 30,000-byte compressible cells: ~90 KB of row file each, a few KB once zipped.
const Cells kFatRow{std::string(30'000, 'a'), std::string(30'000, 'b'), std::string(30'000, 'c')};
constexpr int kFatRows = 12;

// Builds the fat workbook at `file`; `limit_during_appends` (0 = none) is held across the appends.
// Returns how many appends were accepted and how the first refusal read. No assertion inside the
// window.
struct AppendRun {
    int accepted{0};
    swe::XlsxSheetWriter::Append last{swe::XlsxSheetWriter::Append::ok};
};
AppendRun append_fat(swe::XlsxSheetWriter& w, std::uintmax_t limit_during_appends) {
    AppendRun run;
    std::optional<FsizeLimit> guard;
    if (limit_during_appends != 0)
        guard.emplace(limit_during_appends);
    for (int i = 0; i < kFatRows && run.last == swe::XlsxSheetWriter::Append::ok; ++i) {
        run.last = w.append(kFatRow, std::int64_t{1} << 30);
        if (run.last == swe::XlsxSheetWriter::Append::ok)
            ++run.accepted;
    }
    return run;
}

} // namespace

TEST_CASE("xlsx writer: a three-row fixture is a valid workbook with a frozen header",
          "[software_export_xlsx]") {
    Fixture fx;
    auto w = fx.writer();
    REQUIRE(w.append(Cells{"a1", "Alpha", "1.0"}, 1 << 20) == swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.append(Cells{"a2", "Beta & Co", "2.0"}, 1 << 20) ==
            swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.append(Cells{"a3", "<Gamma>", "3.0"}, 1 << 20) == swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.rows() == 3);
    const auto size = w.close();
    REQUIRE(size.has_value());
    REQUIRE(*size == fs::file_size(fx.file));

    ZipView zip(fx.file);
    REQUIRE(zip.ok());
    const auto xml = zip.read(kSheet);
    REQUIRE(xml.has_value());
    require_plausible_xml(*xml);
    // Header cells in order, then each data cell's text (escaped as the library escapes it).
    const auto h0 = xml->find(">agent_id<");
    const auto h1 = xml->find(">name<");
    const auto h2 = xml->find(">version<");
    REQUIRE(h0 != std::string::npos);
    REQUIRE(h0 < h1);
    REQUIRE(h1 < h2);
    for (const char* t : {">a1<", ">Alpha<", ">1.0<", ">a2<", ">Beta &amp; Co<", ">2.0<", ">a3<",
                          ">&lt;Gamma&gt;<", ">3.0<"})
        REQUIRE(xml->find(t) != std::string::npos);
    REQUIRE(xml->find("<pane") != std::string::npos);
    REQUIRE(xml->find("ySplit=\"1\"") != std::string::npos);
    REQUIRE(xml->find("state=\"frozen\"") != std::string::npos);
    REQUIRE(count_of(*xml, "<row ") == 4); // the header and three data rows
}

TEST_CASE("xlsx writer: the package has one sheet and the parts a reader needs",
          "[software_export_xlsx]") {
    Fixture fx;
    auto w = fx.writer();
    REQUIRE(w.append(Cells{"a1", "Alpha", "1.0"}, 1 << 20) == swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.close().has_value());
    ZipView zip(fx.file);
    REQUIRE(zip.ok());
    const auto workbook = zip.read("xl/workbook.xml");
    REQUIRE(workbook.has_value());
    REQUIRE(count_of(*workbook, "<sheet ") == 1);
    REQUIRE(workbook->find("name=\"Installed software\"") != std::string::npos);
    REQUIRE(zip.read("[Content_Types].xml").has_value());
    REQUIRE(zip.read("_rels/.rels").has_value());
    REQUIRE(zip.read("xl/_rels/workbook.xml.rels").has_value());
    REQUIRE(zip.read(kSheet).has_value());
    REQUIRE_FALSE(zip.read("xl/worksheets/sheet2.xml").has_value());
}

TEST_CASE("xlsx writer: the sheet's own row limit and the library's last row agree",
          "[software_export_xlsx][limit]") {
    Fixture fx;
    auto w = fx.writer();
    constexpr std::int64_t kBig = std::int64_t{1} << 62; // the byte allowance is not under test
    const Cells empty{"", "", ""};
    // All-empty cells: the library writes nothing for them, so the loop costs bookkeeping only.
    // Failures are counted and asserted once, not per iteration.
    std::int64_t not_ok = 0;
    for (std::int64_t i = 0; i < swe::kXlsxMaxDataRows - 1; ++i)
        if (w.append(empty, kBig) != swe::XlsxSheetWriter::Append::ok)
            ++not_ok;
    REQUIRE(not_ok == 0);
    REQUIRE(w.rows() == swe::kXlsxMaxDataRows - 1);
    REQUIRE(w.append(Cells{"last", "", ""}, kBig) == swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.rows() == swe::kXlsxMaxDataRows);
    const auto bytes = w.sheet_bytes();
    REQUIRE(w.append(Cells{"over", "", ""}, kBig) == swe::XlsxSheetWriter::Append::failed);
    REQUIRE(w.rows() == swe::kXlsxMaxDataRows);
    REQUIRE(w.sheet_bytes() == bytes);
    REQUIRE(w.close().has_value()); // a full sheet is not a broken writer
    const auto xml = ZipView(fx.file).read(kSheet);
    REQUIRE(xml.has_value());
    REQUIRE(xml->find("r=\"1048576\"") != std::string::npos); // header row + 1,048,575 data rows
    REQUIRE(xml->find("r=\"1048577\"") == std::string::npos);
    REQUIRE(xml->find(">last<") != std::string::npos);
    REQUIRE(xml->find(">over<") == std::string::npos);
}

TEST_CASE("xlsx row cap: the sheet's own limit unless the flag is lower", "[software_export_xlsx]") {
    // The tie: a flag equal to the sheet's limit makes the sheet name itself.
    const auto def = swe::xlsx_row_cap(swe::kXlsxMaxDataRows);
    REQUIRE(def.rows == 1'048'575);
    REQUIRE(def.named == "the sheet's own limit");
    const auto flag = swe::xlsx_row_cap(1000);
    REQUIRE(flag.rows == 1000);
    REQUIRE(flag.named == "--inventory-export-max-rows");
    const auto below = swe::xlsx_row_cap(swe::kXlsxMaxDataRows - 1);
    REQUIRE(below.rows == swe::kXlsxMaxDataRows - 1);
    REQUIRE(below.named == "--inventory-export-max-rows");
    const auto above = swe::xlsx_row_cap(swe::kXlsxMaxDataRows + 1);
    REQUIRE(above.rows == swe::kXlsxMaxDataRows);
    REQUIRE(above.named == "the sheet's own limit");
    REQUIRE(swe::kXlsxZip64Threshold == 0xFFFFFFFFLL);
}

TEST_CASE("xlsx writer: ZIP64 is off by default and on only when asked", "[software_export_xlsx]") {
    Fixture fx;
    {
        auto w = fx.writer();
        REQUIRE(w.close().has_value());
        REQUIRE(first_entry_version_needed(fx.file) == 20);
        REQUIRE(ZipView(fx.file).ok());
    }
    const auto file64 = fx.dir.path / "zip64.xlsx";
    auto opened = swe::XlsxSheetWriter::open(file64, fx.dir.path, "Installed software", kHeader, true);
    REQUIRE(opened.has_value());
    REQUIRE(opened->append(Cells{"a1", "Alpha", "1.0"}, 1 << 20) ==
            swe::XlsxSheetWriter::Append::ok);
    REQUIRE(opened->close().has_value());
    REQUIRE(first_entry_version_needed(file64) == 45);
    ZipView zip(file64);
    REQUIRE(zip.ok());
    const auto xml = zip.read(kSheet);
    REQUIRE(xml.has_value());
    REQUIRE(xml->find(">Alpha<") != std::string::npos);
}

TEST_CASE("xlsx writer: a cell that begins with = + - or @ is text, never a formula",
          "[software_export_xlsx]") {
    Fixture fx;
    auto w = fx.writer();
    REQUIRE(w.append(Cells{"=1+1", "+SUM(A1:A9)", "-2+3"}, 1 << 20) ==
            swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.append(Cells{"@cmd|' /C calc'!A0", "=HYPERLINK(\"http://x\")", "ok"}, 1 << 20) ==
            swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.close().has_value());
    const auto xml = ZipView(fx.file).read(kSheet);
    REQUIRE(xml.has_value());
    REQUIRE(xml->find("<f>") == std::string::npos);
    REQUIRE(xml->find("<f ") == std::string::npos);
    REQUIRE(xml->find("t=\"inlineStr\"") != std::string::npos);
    REQUIRE(count_of(*xml, "t=\"inlineStr\"") == 3 + 6); // header + data: nothing else is typed
    REQUIRE(xml->find(">=1+1<") != std::string::npos);
    REQUIRE(xml->find(">+SUM(A1:A9)<") != std::string::npos);
    REQUIRE(xml->find(">-2+3<") != std::string::npos);
}

TEST_CASE("xlsx writer: invalid UTF-8, forbidden control bytes and oversized cells",
          "[software_export_xlsx]") {
    SECTION("cleaning") {
        bool cut = true;
        REQUIRE(swe::xlsx_clean_cell(std::string_view("ok\xFF" "z", 4), &cut) ==
                "ok\xEF\xBF\xBD" "z");
        REQUIRE_FALSE(cut);
        REQUIRE(swe::xlsx_clean_cell(std::string_view("a\x01\x02" "b\x0B" "c\x00" "d\x1F", 9),
                                     &cut) == "abcd");
        REQUIRE(swe::xlsx_clean_cell("t\tn\nr\r", &cut) == "t\tn\nr\r"); // allowed by XML 1.0
        REQUIRE(swe::xlsx_clean_cell("x\xEF\xBF\xBE" "y\xEF\xBF\xBF" "z", &cut) == "xyz");
        REQUIRE(swe::xlsx_clean_cell("\xF0\x9F\x98\x80", &cut) == "\xF0\x9F\x98\x80"); // 4-byte ok
    }
    SECTION("cut at a code-point boundary") {
        bool cut = false;
        const auto ascii = swe::xlsx_clean_cell(std::string(40'000, 'x'), &cut);
        REQUIRE(cut);
        REQUIRE(ascii.size() == static_cast<std::size_t>(swe::kXlsxMaxCellBytes));
        // 3-byte characters: 32,767 is not a multiple of 3, so the cut steps back to 32,766.
        std::string euro;
        for (int i = 0; i < 20'000; ++i)
            euro += "\xE2\x82\xAC";
        const auto cut_euro = swe::xlsx_clean_cell(euro, &cut);
        REQUIRE(cut);
        REQUIRE(cut_euro.size() == 32'766);
        REQUIRE(cut_euro.size() % 3 == 0);
        REQUIRE(swe::xlsx_clean_cell(std::string(32'767, 'y'), &cut).size() == 32'767);
        REQUIRE_FALSE(cut);
    }
    SECTION("in a workbook") {
        Fixture fx;
        auto w = fx.writer();
        REQUIRE(w.append(Cells{std::string("bad\xFF\x01 bytes", 11), std::string(40'000, 'q'),
                               "plain"},
                         1 << 22) == swe::XlsxSheetWriter::Append::ok);
        REQUIRE(w.cells_truncated() == 1);
        REQUIRE(w.close().has_value());
        const auto xml = ZipView(fx.file).read(kSheet);
        REQUIRE(xml.has_value());
        require_plausible_xml(*xml);
        REQUIRE(xml->find("bad\xEF\xBF\xBD bytes") != std::string::npos);
        REQUIRE(xml->find(std::string(32'767, 'q') + "<") != std::string::npos);
        REQUIRE(xml->find(std::string(32'768, 'q')) == std::string::npos);
    }
}

TEST_CASE("xlsx writer: an empty result is a workbook with the header row only",
          "[software_export_xlsx]") {
    Fixture fx;
    auto w = fx.writer();
    REQUIRE(w.rows() == 0);
    REQUIRE(w.close().has_value());
    ZipView zip(fx.file);
    REQUIRE(zip.ok());
    const auto xml = zip.read(kSheet);
    REQUIRE(xml.has_value());
    REQUIRE(count_of(*xml, "<row ") == 1);
    REQUIRE(xml->find(">agent_id<") != std::string::npos);
}

TEST_CASE("xlsx writer: the accounted sheet bytes are an upper bound for adversarial rows",
          "[software_export_xlsx][accounting]") {
    Fixture fx;
    auto w = fx.writer();
    const std::vector<Cells> rows{
        {std::string(2'000, '&'), std::string(2'000, '<'), std::string(2'000, '>')},
        {"a", "b", "c"},
        {"", "", ""},
        {"", "x", ""},
        {" lead", "trail ", " both "},
        {"\t", "\n", "\r"},
        {"line1\r\nline2", "tab\there", "cr\rcr\rcr"},
        {std::string(32'767, '&'), std::string(32'767, '\r'), std::string(32'767, '<')},
        {"\xE2\x82\xAC\xE2\x82\xAC", "\xF0\x9F\x98\x80", "&amp;"},
        {"q\"uote", "'apos'", "_x0041_"},
    };
    for (int rep = 0; rep < 3; ++rep)
        for (const auto& r : rows)
            REQUIRE(w.append(r, std::int64_t{1} << 30) == swe::XlsxSheetWriter::Append::ok);
    const auto accounted = w.sheet_bytes();
    const auto size = w.close();
    REQUIRE(size.has_value());

    ZipView zip(fx.file);
    REQUIRE(zip.ok());
    const auto actual = zip.usize(kSheet);
    REQUIRE(actual.has_value());
    REQUIRE(static_cast<std::int64_t>(*actual) <= accounted);
    REQUIRE(static_cast<std::int64_t>(*size) <= accounted);
    // The bound is not absurdly loose: the fixed allowance aside, the per-cell terms are within a
    // small factor of what the library wrote.
    REQUIRE(accounted - swe::kXlsxSheetFixedBytes <=
            3 * static_cast<std::int64_t>(*actual) + swe::kXlsxSheetFixedBytes);
    // Every exact-cost case from the derivation.
    REQUIRE(swe::xlsx_cell_cost("") == 0);
    REQUIRE(swe::xlsx_cell_cost("a") == swe::kXlsxCellOverheadBytes + 1);
    REQUIRE(swe::xlsx_cell_cost("&") == swe::kXlsxCellOverheadBytes + 5);
    REQUIRE(swe::xlsx_cell_cost("<>") == swe::kXlsxCellOverheadBytes + 8);
    REQUIRE(swe::xlsx_cell_cost("\r") == swe::kXlsxCellOverheadBytes + 7);
}

TEST_CASE("xlsx writer: the per-cell and per-row accounting terms bound the markup, on differences",
          "[software_export_xlsx][accounting]") {
    // The fixed allowance (64 KiB) hides the other two constants in a whole-sheet comparison, so
    // compare what each row set adds over a header-only workbook with what the writer accounts
    // for it. A failure here is an accounting defect, not a test to loosen.
    Fixture fx;
    const auto base = build_sheet(fx, "base.xlsx", {}, 0);
    const std::vector<Cells> short_cells{
        {"a", "b", "c"}, {" lead", "trail ", " both "}, {"", "x", ""}, {"", "", ""}};
    const std::vector<Cells> adversarial{
        {std::string(2'000, '&'), std::string(2'000, '<'), std::string(2'000, '>')},
        {"\t", "\n", "\r"},
        {"line1\r\nline2", "tab\there", "cr\rcr\rcr"},
        {std::string(32'767, '&'), std::string(32'767, '\r'), std::string(32'767, '<')},
        {"\xE2\x82\xAC\xE2\x82\xAC", "\xF0\x9F\x98\x80", "&amp;"},
        {"q\"uote", "'apos'", "_x0041_"},
    };
    std::vector<Cells> all = short_cells;
    all.insert(all.end(), adversarial.begin(), adversarial.end());

    const auto shorts = build_sheet(fx, "short.xlsx", short_cells, 200);
    REQUIRE(shorts.actual - base.actual > 0);
    REQUIRE(shorts.actual - base.actual <= shorts.accounted - base.accounted);
    const auto full = build_sheet(fx, "all.xlsx", all, 3);
    REQUIRE(full.actual - base.actual > 0);
    REQUIRE(full.actual - base.actual <= full.accounted - base.accounted);

    // The sum above leaves slack between the two per-term constants (zeroing the row term still
    // passes it), so measure each term on its own: rows of one cell against rows of three.
    REQUIRE(base.actual <= swe::kXlsxSheetFixedBytes);
    constexpr int reps = 200;
    const auto one = build_sheet(fx, "one.xlsx", {{"x", "", ""}}, reps);
    const auto three = build_sheet(fx, "three.xlsx", {{"x", "x", "x"}}, reps);
    const std::int64_t cell_markup = (three.actual - one.actual) / (2 * reps); // text included
    const std::int64_t row_markup = (one.actual - base.actual) / reps - cell_markup;
    REQUIRE(cell_markup > 1);
    REQUIRE(row_markup > 0);
    REQUIRE(cell_markup <= swe::kXlsxCellOverheadBytes + 1); // one character of text
    REQUIRE(row_markup <= swe::kXlsxRowOverheadBytes);
}

TEST_CASE("xlsx writer: append past the allowance writes nothing and moves no counter",
          "[software_export_xlsx]") {
    Fixture fx;
    auto w = fx.writer();
    const Cells row{"agent-1", "Some & name", "1.2.3"};
    const auto cost = row_cost(row);
    const auto before = w.sheet_bytes();
    REQUIRE(w.append(row, before + cost - 1) == swe::XlsxSheetWriter::Append::over_budget);
    REQUIRE(w.rows() == 0);
    REQUIRE(w.sheet_bytes() == before);
    REQUIRE(w.cells_truncated() == 0);
    // The same row with exactly enough allowance is written, and the counter moves by its cost.
    REQUIRE(w.append(row, before + cost) == swe::XlsxSheetWriter::Append::ok);
    REQUIRE(w.rows() == 1);
    REQUIRE(w.sheet_bytes() == before + cost);
    REQUIRE(w.close().has_value());
    const auto xml = ZipView(fx.file).read(kSheet);
    REQUIRE(xml.has_value());
    REQUIRE(count_of(*xml, "<row ") == 2); // the refused row left no trace
}

TEST_CASE("xlsx disk budget: grants only while free space covers three times what is granted",
          "[software_export_xlsx][budget]") {
    constexpr auto kReserve = static_cast<std::uintmax_t>(swe::kXlsxDiskReserveBytes);
    constexpr auto kFactor = static_cast<std::uintmax_t>(swe::kXlsxPeakDiskFactor);
    constexpr std::int64_t kAsk = 1000;

    SECTION("unknown free space refuses") {
        swe::XlsxDiskBudget b;
        REQUIRE_FALSE(b.grant(kAsk, std::nullopt));
        REQUIRE(b.granted() == 0);
    }
    SECTION("under the reserve refuses; exactly enough grants; one byte less refuses") {
        swe::XlsxDiskBudget b;
        REQUIRE_FALSE(b.grant(kAsk, kReserve - 1));
        REQUIRE_FALSE(b.grant(kAsk, kReserve));
        REQUIRE_FALSE(b.grant(kAsk, kReserve + kFactor * kAsk - 1));
        REQUIRE(b.grant(kAsk, kReserve + kFactor * kAsk));
        REQUIRE(b.granted() == kAsk);
    }
    SECTION("a non-positive ask refuses") {
        swe::XlsxDiskBudget b;
        REQUIRE_FALSE(b.grant(0, kReserve * 100));
        REQUIRE_FALSE(b.grant(-5, kReserve * 100));
    }
    SECTION("two exports cannot both be granted what only one fits") {
        swe::XlsxDiskBudget b;
        const auto free_now = kReserve + kFactor * kAsk; // room for exactly one grant of kAsk
        REQUIRE(b.grant(kAsk, free_now));
        REQUIRE_FALSE(b.grant(kAsk, free_now));
        REQUIRE(b.granted() == kAsk);
        b.release(kAsk);
        REQUIRE(b.granted() == 0);
        REQUIRE(b.grant(kAsk, free_now)); // granted again after the release
    }
    SECTION("release never goes below zero") {
        swe::XlsxDiskBudget b;
        REQUIRE(b.grant(kAsk, kReserve * 4));
        b.release(kAsk * 10);
        REQUIRE(b.granted() == 0);
    }
    SECTION("a huge free space and a huge ask cannot overflow") {
        swe::XlsxDiskBudget b;
        REQUIRE_FALSE(b.grant(INT64_MAX / 2, kReserve + 1));
        REQUIRE(b.granted() == 0);
    }
}

TEST_CASE("xlsx file creation: exclusive, owner-only, never overwrites", "[software_export_xlsx]") {
    Fixture fx;
    const auto p = fx.dir.path / "made.xlsx";
    REQUIRE(swe::create_owner_only_exclusive(p).has_value());
    struct stat st{};
    REQUIRE(::stat(p.c_str(), &st) == 0);
    REQUIRE((st.st_mode & 0777) == 0600);
    REQUIRE(st.st_size == 0);

    SECTION("an existing path is refused and left untouched") {
        {
            std::ofstream(p, std::ios::binary) << "keep";
        }
        const auto again = swe::create_owner_only_exclusive(p);
        REQUIRE_FALSE(again.has_value());
        REQUIRE_FALSE(again.error().empty());
        std::ifstream in(p, std::ios::binary);
        std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        REQUIRE(got == "keep");
    }
    SECTION("a link is refused and its target untouched") {
        const auto link = fx.dir.path / "link.xlsx";
        {
            std::ofstream(fx.dir.path / "target.bin", std::ios::binary) << "target";
        }
        fs::create_symlink(fx.dir.path / "target.bin", link);
        REQUIRE_FALSE(swe::create_owner_only_exclusive(link).has_value());
        std::ifstream in(fx.dir.path / "target.bin", std::ios::binary);
        std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        REQUIRE(got == "target");
    }
    SECTION("the writer produces a valid workbook over the pre-created empty file") {
        auto w = swe::XlsxSheetWriter::open(p, fx.dir.path, "Installed software", kHeader);
        REQUIRE(w.has_value());
        REQUIRE(w->append(Cells{"a", "b", "c"}, 1 << 20) == swe::XlsxSheetWriter::Append::ok);
        REQUIRE(w->close().has_value());
        ZipView zip(p);
        REQUIRE(zip.ok());
        REQUIRE(zip.read(kSheet).has_value());
    }
}

TEST_CASE("xlsx writer: misuse fails cleanly", "[software_export_xlsx]") {
    Fixture fx;
    SECTION("the wrong cell count fails and the writer carries on") {
        auto w = fx.writer();
        REQUIRE(w.append(Cells{"only", "two"}, 1 << 20) == swe::XlsxSheetWriter::Append::failed);
        REQUIRE(w.append(Cells{"a", "b", "c", "d"}, 1 << 20) ==
                swe::XlsxSheetWriter::Append::failed);
        REQUIRE(w.rows() == 0);
        REQUIRE(w.append(Cells{"a", "b", "c"}, 1 << 20) == swe::XlsxSheetWriter::Append::ok);
        REQUIRE(w.rows() == 1);
        REQUIRE(w.close().has_value());
        REQUIRE_FALSE(w.close().has_value()); // a second close fails
    }
    SECTION("a missing temporary directory fails with a message") {
        const auto r = swe::XlsxSheetWriter::open(fx.file, fx.dir.path / "no-such-dir",
                                                  "Installed software", kHeader);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("temporary directory") != std::string::npos);
    }
    SECTION("a missing output directory fails with a message") {
        const auto r = swe::XlsxSheetWriter::open(fx.dir.path / "no-such-dir" / "out.xlsx",
                                                  fx.dir.path, "Installed software", kHeader);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("output directory") != std::string::npos);
    }
    SECTION("an empty header fails") {
        const auto r = swe::XlsxSheetWriter::open(fx.file, fx.dir.path, "S",
                                                  std::span<const std::string_view>{});
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a writer destroyed without close() throws nothing and the file can be removed") {
        REQUIRE_NOTHROW([&] {
            auto w = fx.writer();
            (void)w.append(Cells{"a", "b", "c"}, 1 << 20);
        }());
        std::error_code ec;
        fs::remove(fx.file, ec);
        REQUIRE_FALSE(fs::exists(fx.file));
    }
}

namespace {

// A small workbook with adversarial text; returns its path.
fs::path build_checked_workbook(Fixture& fx, const char* name) {
    const auto file = fx.dir.path / name;
    auto opened = swe::XlsxSheetWriter::open(file, fx.dir.path, "Installed software", kHeader);
    REQUIRE(opened.has_value());
    auto w = std::move(*opened);
    for (int rep = 0; rep < 3; ++rep) {
        REQUIRE(w.append(Cells{"a" + std::to_string(rep), "Beta & <Co>", " 1.0 "}, 1 << 20) ==
                swe::XlsxSheetWriter::Append::ok);
        REQUIRE(w.append(Cells{"", "tab\there\r\nline", "=1+1"}, 1 << 20) ==
                swe::XlsxSheetWriter::Append::ok);
    }
    REQUIRE(w.close().has_value()); // close() itself runs the check: a clean build passes it
    return file;
}

} // namespace

TEST_CASE("xlsx verify: a finished workbook passes at its true byte count and at no other",
          "[software_export_xlsx][verify]") {
    Fixture fx;
    const auto file = build_checked_workbook(fx, "v.xlsx");
    const auto xml = ZipView(file).read(kSheet);
    REQUIRE(xml.has_value());
    const auto n = data_bytes_of(*xml);
    REQUIRE(n > 0);
    REQUIRE(swe::xlsx_verify_workbook(file, n).has_value());
    for (const std::int64_t off : {-12, -1, 1, 12}) {
        const auto r = swe::xlsx_verify_workbook(file, n + off);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("</sheetData>") != std::string::npos);
    }
    REQUIRE_FALSE(swe::xlsx_verify_workbook(file, -1).has_value());
    REQUIRE_FALSE(swe::xlsx_verify_workbook(fx.dir.path / "no-such.xlsx", n).has_value());
}

TEST_CASE("xlsx verify: a damaged or half-written workbook is refused, each defect by name",
          "[software_export_xlsx][verify]") {
    Fixture fx;
    const auto good = build_checked_workbook(fx, "good.xlsx");
    const auto sheet = ZipView(good).read(kSheet);
    REQUIRE(sheet.has_value());
    const auto n = data_bytes_of(*sheet);
    const auto damaged = fx.dir.path / "damaged.xlsx";
    const auto styles = ZipView(good).read("xl/styles.xml");
    REQUIRE(styles.has_value());

    const auto expect_refused = [&](const std::map<std::string, std::string>& replace,
                                    std::string_view mentions, const std::string& omit = {}) {
        fs::remove(damaged);
        rewrite_zip(good, damaged, replace, omit);
        const auto r = swe::xlsx_verify_workbook(damaged, n);
        REQUIRE_FALSE(r.has_value());
        INFO(r.error());
        REQUIRE(r.error().find(mentions) != std::string::npos);
    };

    SECTION("the rewrite helper itself keeps a good workbook good") {
        rewrite_zip(good, damaged, {});
        REQUIRE(swe::xlsx_verify_workbook(damaged, n).has_value());
        // Exactly the bytes changed by a replacement of the same text.
        rewrite_zip(good, damaged, {{kSheet, *sheet}});
        REQUIRE(swe::xlsx_verify_workbook(damaged, n).has_value());
    }
    SECTION("an emptied sheet entry") {
        expect_refused({{kSheet, ""}}, "is empty");
    }
    SECTION("an emptied small part") {
        expect_refused({{"xl/styles.xml", ""}}, "xl/styles.xml: is empty");
    }
    SECTION("a part cut before its root element closes") {
        expect_refused({{"xl/styles.xml", styles->substr(0, styles->size() - 6)}},
                       "closing tag of its root");
    }
    SECTION("a part with no XML declaration") {
        expect_refused({{"docProps/app.xml", "<Properties/>"}}, "XML declaration");
    }
    SECTION("a sheet cut short at its end") {
        expect_refused({{kSheet, sheet->substr(0, sheet->size() - 40)}}, "closing tag of its root");
    }
    SECTION("a sheet that lost its last row but kept every closing tag") {
        // The one defect only the span check can see: the file is well formed and every tag closes.
        const auto data_end = sheet->find("</sheetData>");
        const auto last_row = sheet->rfind("<row ", data_end);
        REQUIRE(last_row != std::string::npos);
        std::string cut = *sheet;
        cut.erase(last_row, data_end - last_row);
        expect_refused({{kSheet, cut}}, "</sheetData>");
    }
    SECTION("a sheet with a row too many") {
        const auto data_end = sheet->find("</sheetData>");
        std::string more = *sheet;
        more.insert(data_end,
                    "<row r=\"99\"><c r=\"A99\" t=\"inlineStr\"><is><t>x</t></is></c></row>");
        expect_refused({{kSheet, more}}, "</sheetData>");
    }
    SECTION("no sheet at all") {
        expect_refused({}, "xl/worksheets/sheet1.xml is missing", kSheet);
    }
    SECTION("not a zip") {
        {
            std::ofstream(damaged, std::ios::binary) << "this is not a workbook";
        }
        const auto r = swe::xlsx_verify_workbook(damaged, n);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().find("not a readable zip") != std::string::npos);
    }
    SECTION("an empty file") {
        {
            std::ofstream(damaged, std::ios::binary);
        }
        REQUIRE_FALSE(swe::xlsx_verify_workbook(damaged, n).has_value());
    }
}

TEST_CASE("xlsx verify: a byte flipped inside the compressed sheet fails the CRC or the inflate",
          "[software_export_xlsx][verify]") {
    Fixture fx;
    // Incompressible-ish text, so the compressed sheet is most of the file and its middle is
    // inside the deflate stream (a flip in a header field would prove nothing).
    const auto file = fx.dir.path / "crc.xlsx";
    {
        auto opened = swe::XlsxSheetWriter::open(file, fx.dir.path, "Installed software", kHeader);
        REQUIRE(opened.has_value());
        auto w = std::move(*opened);
        std::uint32_t x = 12345;
        const auto noise = [&x](std::size_t len) {
            std::string out;
            for (std::size_t i = 0; i < len; ++i) {
                x = x * 1664525U + 1013904223U;
                out.push_back(static_cast<char>('a' + ((x >> 24) % 26)));
            }
            return out;
        };
        for (int i = 0; i < 6; ++i)
            REQUIRE(w.append(Cells{noise(4000), noise(4000), noise(4000)}, 1 << 24) ==
                    swe::XlsxSheetWriter::Append::ok);
        REQUIRE(w.close().has_value());
    }
    const auto n = data_bytes_of(*ZipView(file).read(kSheet));
    REQUIRE(swe::xlsx_verify_workbook(file, n).has_value());
    std::string bytes;
    {
        std::ifstream in(file, std::ios::binary);
        bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    bytes[bytes.size() / 2] = static_cast<char>(bytes[bytes.size() / 2] ^ 0x5A);
    const auto flipped = fx.dir.path / "flipped.xlsx";
    {
        std::ofstream(flipped, std::ios::binary).write(bytes.data(),
                                                       static_cast<std::streamsize>(bytes.size()));
    }
    REQUIRE_FALSE(swe::xlsx_verify_workbook(flipped, n).has_value());
}

TEST_CASE("xlsx writer: a volume that stops taking writes during the build ends it at once and "
          "close() reports it",
          "[software_export_xlsx][fault]") {
    Fixture fx;
    auto w = fx.writer();
    // 64 KiB is under one fat row: the row file's flush fails inside the first appends.
    const auto run = append_fat(w, 64 * 1024);
    std::expected<std::uintmax_t, std::string> closed = std::unexpected("not run");
    closed = w.close();
    REQUIRE(run.last == swe::XlsxSheetWriter::Append::failed);
    REQUIRE(run.accepted < kFatRows);
    REQUIRE_FALSE(closed.has_value());
    REQUIRE(closed.error().find("earlier write failed") != std::string::npos);
}

TEST_CASE("xlsx writer: the last buffered rows failing to reach the row file is caught before the "
          "close",
          "[software_export_xlsx][fault]") {
    Fixture fx;
    // The same rows twice: once clean, to measure the row file (the <sheetData> content length),
    // then again with the limit one byte under it, set after the appends and before close().
    std::int64_t span = 0;
    {
        auto w = fx.writer();
        const auto run = append_fat(w, 0);
        REQUIRE(run.accepted == kFatRows);
        REQUIRE(w.close().has_value());
        span = data_bytes_of(*ZipView(fx.file).read(kSheet));
    }
    REQUIRE(span > 1'000'000);
    fs::remove(fx.file);
    auto w = fx.writer();
    REQUIRE(append_fat(w, 0).accepted == kFatRows);
    std::expected<std::uintmax_t, std::string> closed = std::unexpected("not run");
    bool armed = false;
    {
        const FsizeLimit limit(static_cast<std::uintmax_t>(span) - 1);
        armed = limit.armed();
        closed = w.close();
    }
    REQUIRE(armed);
    REQUIRE_FALSE(closed.has_value());
    REQUIRE(closed.error().find("row file did not take every write") != std::string::npos);
}

TEST_CASE("xlsx writer: a copy of the sheet cut short inside the library's own close is caught by "
          "the read-back",
          "[software_export_xlsx][fault]") {
    Fixture fx;
    std::int64_t span = 0;
    std::uintmax_t clean_size = 0;
    {
        auto w = fx.writer();
        REQUIRE(append_fat(w, 0).accepted == kFatRows);
        const auto closed = w.close();
        REQUIRE(closed.has_value());
        clean_size = *closed;
        span = data_bytes_of(*ZipView(fx.file).read(kSheet));
    }
    REQUIRE(static_cast<std::int64_t>(clean_size) < span); // the finished file is far smaller
    fs::remove(fx.file);
    auto w = fx.writer();
    REQUIRE(append_fat(w, 0).accepted == kFatRows);
    // The row file is complete (span bytes fit the limit) but the assembled sheet, which also holds
    // the preamble and the closing tags, is cut 64 bytes past it: the library copies what it can,
    // reports nothing, and the zip around the short sheet is well formed.
    std::expected<std::uintmax_t, std::string> closed = std::unexpected("not run");
    bool armed = false;
    {
        const FsizeLimit limit(static_cast<std::uintmax_t>(span) + 64);
        armed = limit.armed();
        closed = w.close();
    }
    REQUIRE(armed);
    REQUIRE_FALSE(closed.has_value());
    REQUIRE(closed.error().find("failed its check") != std::string::npos);
}
