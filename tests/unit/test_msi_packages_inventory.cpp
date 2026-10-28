/**
 * test_msi_packages_inventory.cpp -- pure list_inventory builder.
 *
 * Runs on every OS: msi_packages_inventory.hpp has no Windows headers, the OS
 * boundary is injected. The rows come from a committed REAL CAPTURE
 * (tests/unit/fixtures/software-estate/msi_packages/windows/products-system.txt,
 * see provenance.txt next to it) fed through fakes that honour the requested
 * install context, so asking for any context other than machine (4) would
 * surface the per-user row and fail the absence case.
 *
 * Shapes the capture does not contain (an empty publisher, an advertised-only
 * product, an enumeration failure, a failed property read, a pipe/tab/CR/LF in
 * a name) are built in the
 * test and labelled as synthetic where they appear.
 */
#include <catch2/catch_test_macros.hpp>

#include "msi_packages_inventory.hpp"

#include <algorithm>
#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

namespace fs = std::filesystem;
namespace inv = yuzu::msi_packages::inventory;

namespace {

struct FixtureRow {
    std::string code;
    unsigned ctx{};
    std::string name;
    std::string version;
    std::string publisher;
    std::string location;
};

std::vector<std::string> split_raw(std::string_view line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        const auto bar = line.find('|', pos);
        if (bar == std::string_view::npos) {
            out.emplace_back(line.substr(pos));
            return out;
        }
        out.emplace_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

// code|ctx|sid|InstalledProductName|VersionString|Publisher|InstallLocation; `#` lines skipped;
// the sid column is read past, never stored.
std::vector<FixtureRow> load_fixture() {
    const auto path = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "msi_packages" /
                      "windows" / "products-system.txt";
    std::ifstream in(path);
    REQUIRE(in.is_open());
    std::vector<FixtureRow> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.front() == '#')
            continue;
        const auto f = split_raw(line);
        REQUIRE(f.size() == 7);
        rows.push_back({f[0], static_cast<unsigned>(std::stoul(f[1])), f[3], f[4], f[5], f[6]});
    }
    return rows;
}

constexpr const char* kPerUserCode = "{665A0435-D5D5-4A49-9DE0-FBC23C5425ED}";
constexpr const char* kPythonLauncher = "{0B1B5000-3C0E-41C0-83C4-4C914420AE93}";
constexpr const char* kCMake = "{B7526150-1C45-45B5-932D-A4CF5A23403C}";
constexpr const char* kSevenZip = "{23170F69-40C1-2702-2604-000001000000}";

// A source that answers only for the requested context and records every request.
struct FakeSource {
    std::vector<FixtureRow> rows;
    std::optional<std::string> fail_token; // returned by enumerate after `fail_after` codes
    std::size_t fail_after = 0;
    std::set<unsigned> requested_ctx;
    std::set<std::string> requested_props;
    // property overrides: (code, prop) -> nullopt means "the product has no such property"
    std::set<std::pair<std::string, std::string>> not_set;
    bool all_not_set = false;
    // (code, prop) -> the read FAILED (as opposed to "not set"), answered with this token
    std::set<std::pair<std::string, std::string>> failing;

    template <class OnCode> std::optional<std::string> enumerate(unsigned ctx, OnCode&& on_code) {
        requested_ctx.insert(ctx);
        std::size_t n = 0;
        for (const auto& r : rows) {
            if (r.ctx != ctx)
                continue;
            if (fail_token && n == fail_after)
                return fail_token;
            on_code(r.code);
            ++n;
        }
        return std::nullopt;
    }

    std::optional<std::string> property(const std::string& code, unsigned ctx,
                                        std::string_view prop) {
        requested_ctx.insert(ctx);
        requested_props.insert(std::string{prop});
        if (all_not_set || not_set.count({code, std::string{prop}}))
            return std::nullopt;
        for (const auto& r : rows) {
            if (r.code != code || r.ctx != ctx)
                continue;
            if (prop == inv::kPropName)
                return r.name;
            if (prop == inv::kPropVersion)
                return r.version;
            if (prop == inv::kPropPublisher)
                return r.publisher;
        }
        return std::nullopt;
    }
};

inv::Inventory run(FakeSource& src) {
    return inv::collect(
        [&](unsigned c, auto&& on_code) { return src.enumerate(c, on_code); },
        [&](const std::string& code, unsigned c,
            std::string_view p) -> std::expected<std::string, std::string> {
            if (src.failing.count({code, std::string{p}}))
                return std::unexpected(std::string{"windows:msi_prop:1610"});
            return src.property(code, c, p).value_or(std::string{});
        });
}

} // namespace

TEST_CASE("msi inventory: the committed capture pins itself", "[msi_packages][msi_inventory]") {
    const auto rows = load_fixture();
    REQUIRE(rows.size() == 119);
    CHECK(std::count_if(rows.begin(), rows.end(), [](auto& r) { return r.ctx == 4; }) == 118);
    const auto per_user = std::count_if(rows.begin(), rows.end(), [](auto& r) { return r.ctx == 2; });
    REQUIRE(per_user == 1);
    const auto it = std::find_if(rows.begin(), rows.end(), [](auto& r) { return r.ctx == 2; });
    CHECK(it->code == kPerUserCode);
    CHECK(it->name == "Python Launcher");
    CHECK(it->version == "3.12.10150.0");
}

TEST_CASE("msi inventory: collect asks for the machine context and three properties only",
          "[msi_packages][msi_inventory]") {
    FakeSource src;
    src.rows = load_fixture();
    const auto roster = run(src);

    CHECK_FALSE(roster.constraint.has_value());
    REQUIRE(roster.products.size() == 118);
    CHECK(src.requested_ctx == std::set<unsigned>{4});
    CHECK(src.requested_props ==
          std::set<std::string>{"InstalledProductName", "VersionString", "Publisher"});
    // The per-user product is never listed.
    for (const auto& p : roster.products)
        CHECK(p.code != kPerUserCode);
}

TEST_CASE("msi inventory: render emits the status row first then the captured products",
          "[msi_packages][msi_inventory]") {
    FakeSource src;
    src.rows = load_fixture();
    const auto lines = inv::render(run(src));

    REQUIRE(lines.size() == 119);
    CHECK(lines[0] == "status|list_inventory|supported|-");

    const auto find_line = [&](std::string_view prefix) -> std::string {
        for (const auto& l : lines)
            if (l.rfind(prefix, 0) == 0)
                return l;
        return {};
    };
    CHECK(lines[1] ==
          std::string{"inv|"} + kPythonLauncher + "|Python Launcher|3.14.6150.0|Python Software Foundation");
    const auto cmake = find_line(std::string{"inv|"} + kCMake);
    CHECK(cmake == std::string{"inv|"} + kCMake + "|CMake|4.3.4|Kitware");

    for (std::size_t i = 0; i < lines.size(); ++i) {
        // InstallLocation and InstallSource are never emitted.
        CHECK(lines[i].find("C:\\Program Files\\CMake") == std::string::npos);
        if (i == 0)
            continue;
        // The collector splits on RAW '|' with no escape awareness: exactly 5 tokens.
        CHECK(split_raw(lines[i]).size() == 5);
        CHECK(lines[i].find("\\|") == std::string::npos);
    }
    CHECK(find_line(std::string{"inv|"} + kPerUserCode).empty());
}

TEST_CASE("msi inventory: a property that is not set is an empty field",
          "[msi_packages][msi_inventory]") {
    // SYNTHETIC shape: the Kingsley captures contain no empty-publisher product.
    FakeSource src;
    src.rows = load_fixture();
    src.not_set.insert({kSevenZip, std::string{inv::kPropPublisher}});
    auto lines = inv::render(run(src));

    CHECK(lines[0] == "status|list_inventory|supported|-");
    const auto it = std::find_if(lines.begin(), lines.end(), [](const std::string& l) {
        return l.rfind(std::string{"inv|"} + kSevenZip, 0) == 0;
    });
    REQUIRE(it != lines.end());
    CHECK(*it == std::string{"inv|"} + kSevenZip + "|7-Zip 26.04 (x64 edition)|26.04.00.0|");

    // SYNTHETIC, the advertised-only shape: nothing readable at all.
    FakeSource none;
    none.rows = load_fixture();
    none.all_not_set = true;
    const auto adv = inv::render(run(none));
    REQUIRE(adv.size() == 119);
    CHECK(adv[0] == "status|list_inventory|supported|-");
    CHECK(adv[1] == std::string{"inv|"} + kPythonLauncher + "|||");
}

TEST_CASE("msi inventory: an enumeration failure is constrained and keeps the rows read",
          "[msi_packages][msi_inventory]") {
    FakeSource src;
    src.rows = load_fixture();
    src.fail_token = "windows:msi_enum:1610";
    src.fail_after = 2;
    const auto lines = inv::render(run(src));

    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "status|list_inventory|constrained|windows:msi_enum:1610");
    CHECK(lines[1].rfind("inv|{", 0) == 0);
    CHECK(lines[2].rfind("inv|{", 0) == 0);
}

TEST_CASE("msi inventory: a failed property read is constrained, never an absent one",
          "[msi_packages][msi_inventory]") {
    // SYNTHETIC: a read that FAILS (corrupt registration, access denied) must not
    // read as "no such property"; the rows read are kept and the roster says why.
    FakeSource src;
    src.rows = load_fixture();
    src.failing.insert({kSevenZip, std::string{inv::kPropName}});
    const auto roster = run(src);
    REQUIRE(roster.constraint.has_value());
    CHECK(*roster.constraint == "windows:msi_prop:1610");
    const auto lines = inv::render(roster);
    CHECK(lines[0] == "status|list_inventory|constrained|windows:msi_prop:1610");
    CHECK(lines.size() == 119);

    // every read failing (a non-readable identity) is the same answer, not 118
    // silently nameless products under a clean status
    FakeSource all;
    all.rows = load_fixture();
    for (const auto& r : all.rows)
        all.failing.insert({r.code, std::string{inv::kPropName}});
    CHECK(inv::render(run(all))[0] == "status|list_inventory|constrained|windows:msi_prop:1610");

    // the FIRST failure names the roster, and a version or publisher failure counts too
    FakeSource first;
    first.rows = load_fixture();
    first.failing.insert({kPythonLauncher, std::string{inv::kPropPublisher}});
    first.failing.insert({kSevenZip, std::string{inv::kPropVersion}});
    CHECK(inv::render(run(first))[0] == "status|list_inventory|constrained|windows:msi_prop:1610");

    // an enumeration failure takes priority over a property failure
    FakeSource both;
    both.rows = load_fixture();
    // first row: its read happens before the walk fails
    both.failing.insert({kPythonLauncher, std::string{inv::kPropName}});
    both.fail_token = "windows:msi_enum:1610";
    both.fail_after = 2;
    CHECK(inv::render(run(both))[0] == "status|list_inventory|constrained|windows:msi_enum:1610");
}

TEST_CASE("msi inventory: only a missing property reads as empty; any other failure is a token",
          "[msi_packages][msi_inventory]") {
    // Measured on a Windows 11 host: an unknown product answers 1605 and an absent
    // property 1608 (an unset-but-recognised one is success with an empty string).
    for (const unsigned rc : {inv::kErrorUnknownProduct, inv::kErrorUnknownProperty}) {
        const auto r = inv::classify_property_error(rc);
        REQUIRE(r.has_value());
        CHECK(r->empty());
    }
    // 1610 (bad configuration), 1627 (function failed), 5 (access denied), a second
    // ERROR_MORE_DATA: all failures, none an absent property
    for (const unsigned rc : {1610u, 1627u, 5u, inv::kErrorMoreData}) {
        const auto r = inv::classify_property_error(rc);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == "windows:msi_prop:" + std::to_string(rc));
    }
}

TEST_CASE("msi inventory: the retry capacity adds the NUL and refuses an implausible length",
          "[msi_packages][msi_inventory]") {
    // the reported length excludes the NUL (measured: 15 for 'Python Launcher')
    REQUIRE(inv::retry_capacity(15).has_value());
    CHECK(*inv::retry_capacity(15) == 16);
    // boundary: exactly the cap is allowed, one past it is not
    REQUIRE(inv::retry_capacity(inv::kMaxPropertyChars).has_value());
    CHECK(*inv::retry_capacity(inv::kMaxPropertyChars) == inv::kMaxPropertyChars + 1u);
    const auto over = inv::retry_capacity(inv::kMaxPropertyChars + 1);
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error() == "windows:msi_prop:oversized");
    // a wrapped DWORD (0xFFFFFFFF) is refused, not allocated
    CHECK_FALSE(inv::retry_capacity(0xFFFFFFFFu).has_value());
}

TEST_CASE("msi inventory: row breakers are deleted and a backslash is kept",
          "[msi_packages][msi_inventory]") {
    // SYNTHETIC strings: no captured name contains a pipe, tab, CR/LF or non-ASCII.
    inv::Product p;
    p.code = "{11111111-2222-3333-4444-555555555555}";
    p.name = "A|B\nC\tD";
    p.version = "1.0\r";
    p.publisher = "Contoso\\Tools";
    const auto row = inv::format_inventory_row(p);

    CHECK(row == "inv|{11111111-2222-3333-4444-555555555555}|ABCD|1.0|Contoso\\Tools");
    CHECK(split_raw(row).size() == 5);
    CHECK(row.find("\\|") == std::string::npos);

    // a NUL would cut the row at write_output's C string and drop the product
    inv::Product n;
    n.code = "{11111111-2222-3333-4444-555555555555}";
    n.name = std::string("A\0B", 3);
    CHECK(inv::format_inventory_row(n) == "inv|{11111111-2222-3333-4444-555555555555}|AB||");

    inv::Product q;
    q.code = "{AAAAAAAA-|-BBBB}";
    CHECK(inv::format_inventory_row(q) == "inv|{AAAAAAAA--BBBB}|||");
}

TEST_CASE("msi inventory: unsupported status rows and the dash for empty tokens",
          "[msi_packages][msi_inventory]") {
    CHECK(inv::unsupported_status_row("macos:owned_by_installed_apps") ==
          "status|list_inventory|unsupported|macos:owned_by_installed_apps");
    CHECK(inv::unsupported_status_row("linux:no_msi") ==
          "status|list_inventory|unsupported|linux:no_msi");
    CHECK(yuzu::shared::format_status_row("list_inventory", yuzu::shared::StatusLevel::supported,
                                          {}) == "status|list_inventory|supported|-");
}

TEST_CASE("msi inventory: zero products is one status row and no sentinel",
          "[msi_packages][msi_inventory]") {
    FakeSource src; // no rows at all
    const auto lines = inv::render(run(src));
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == "status|list_inventory|supported|-");
}
