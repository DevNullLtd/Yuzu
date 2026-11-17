/**
 * test_software_export_xlsx.cpp - the XLSX writer of the installed-software export
 * (software_export_xlsx.hpp): the workbook it produces, the sheet-byte accounting that every XLSX
 * size limit rests on, the pure disk budget, and the exclusive owner-only file creation.
 *
 * File justification (the unit-test conventions forbid disk in a unit test unless unavoidable):
 * the spreadsheet library writes files by design and the accounting claim is about the bytes it
 * writes, so the fixtures are real workbooks. Each is at most 50 rows in a `yuzu_test_` directory
 * the TempDir removes at the end; nothing here sleeps, spawns a process or opens a socket.
 */

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "software_export_xlsx.hpp"

#include <minizip/unzip.h>

#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
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
