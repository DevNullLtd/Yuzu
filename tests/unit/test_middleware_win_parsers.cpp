/**
 * test_middleware_win_parsers.cpp -- tests for the pure half of the middleware Windows leg:
 * WinRegFs (middleware_win_parsers.hpp), the registry Fs behind run_reg_leg. It runs on EVERY OS,
 * unguarded, over a FakeOps: nothing here opens a registry key.
 *
 * SYNTHETIC. No Windows capture exists yet: the value names `FilePath` and `VRMF` come from the
 * vendor's documentation, not a capture, so
 * every installation below is an inline, labelled-synthetic one.
 *
 * MUTATION NOTES (each assertion fails if the named wiring is removed):
 *  - dual-view union: iterating only the 64-bit view fails the "only in the 32-bit view" case.
 *  - de-duplication: dropping the case-insensitive compare fails the "present in both views" case.
 *  - failure never reads as absent: returning `absent` unless both views are `absent` is the rule;
 *    mapping a denied view to absent fails the "absent and denied" cases.
 *  - an answering view's names beside a refused or failed one: returning plain `ok` whenever there
 *    are names (the old rule) fails the "names in one view, the other denied / failed" cases.
 *  - value fall-through: falling through to the 32-bit view on a DENIED first answer fails the
 *    "denied is the answer" case.
 *  - decide_value: treating a non-text value as text fails the REG_DWORD / REG_BINARY case.
 *  - budget: not counting a view's names fails the exhausted() cases.
 */
#include <catch2/catch_test_macros.hpp>

#include "middleware_win_parsers.hpp"

#include <middleware_products.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace mw = yuzu::middleware;
namespace win = yuzu::middleware::win;

namespace {

/// Scripted registry: per view, a key -> listing map and a (key, value) -> text map. A key or value
/// that is not scripted is `absent`.
struct FakeOps {
    std::map<std::pair<win::RegView, std::string>, win::RegListing> lists;
    std::map<std::tuple<win::RegView, std::string, std::string>, win::RegText> values;
    std::vector<std::string> read_log; ///< "<view>|<key>|<value>"

    void put_names(win::RegView v, const std::string& key, std::vector<std::string> names) {
        lists[{v, key}] = win::RegListing{win::RegStatus::ok, std::move(names), false};
    }
    void put_list_status(win::RegView v, const std::string& key, win::RegStatus s) {
        lists[{v, key}] = win::RegListing{s, {}, false};
    }
    void put_text(win::RegView v, const std::string& key, const std::string& value, std::string text) {
        values[{v, key, value}] = win::RegText{win::RegStatus::ok, std::move(text)};
    }
    void put_value_status(win::RegView v, const std::string& key, const std::string& value,
                          win::RegStatus s) {
        values[{v, key, value}] = win::RegText{s, {}};
    }

    win::RegListing list_subkeys(win::RegView v, std::string_view key, std::size_t max) {
        const auto it = lists.find({v, std::string{key}});
        if (it == lists.end())
            return win::RegListing{win::RegStatus::absent, {}, false};
        win::RegListing l = it->second;
        if (l.names.size() > max) {
            l.names.resize(max);
            l.truncated = true;
        }
        return l;
    }
    win::RegText read_sz(win::RegView v, std::string_view key, std::string_view value,
                         std::size_t /*cap*/) {
        read_log.push_back(std::string{v == win::RegView::v64 ? "64" : "32"} + "|" +
                           std::string{key} + "|" + std::string{value});
        const auto it = values.find({v, std::string{key}, std::string{value}});
        if (it == values.end())
            return win::RegText{win::RegStatus::absent, {}};
        return it->second;
    }
};
static_assert(win::RegOps<FakeOps>);

using win::RegStatus;
using win::RegView;

constexpr const char* kKey = "SOFTWARE\\IBM\\WebSphere MQ\\Installation";

/// Copies the fake in and keeps a pointer-free WinRegFs: the fake is value-held so the test inspects
/// `fs`'s own copy through the returned object only via behaviour.
win::WinRegFs<FakeOps> make(FakeOps ops, std::size_t budget = win::kMaxRegEntries) {
    return win::WinRegFs<FakeOps>{std::move(ops), budget};
}

} // namespace

TEST_CASE("middleware windows: WinRegFs satisfies the runner's registry Fs concept", "[middleware]") {
    STATIC_REQUIRE(mw::MiddlewareRegFs<win::WinRegFs<FakeOps>>);
    FakeOps ops;
    auto fs = make(ops);
    CHECK(fs.os() == "windows");
    CHECK_FALSE(fs.exhausted());
}

TEST_CASE("middleware windows: reg_subkeys merges the 64-bit and 32-bit views", "[middleware]") {
    FakeOps ops;
    SECTION("an installation only in the 32-bit view is found") {
        ops.put_names(RegView::v64, kKey, {"Installation1"});
        ops.put_names(RegView::v32, kKey, {"Installation2"});
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::ok);
        CHECK(k.names == std::vector<std::string>{"Installation1", "Installation2"});
    }
    SECTION("one only in the 32-bit view, the 64-bit key absent") {
        ops.put_names(RegView::v32, kKey, {"Installation9"});
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::ok);
        CHECK(k.names == std::vector<std::string>{"Installation9"});
    }
    SECTION("one present in both views appears once, whatever its case") {
        ops.put_names(RegView::v64, kKey, {"Installation1", "Other"});
        ops.put_names(RegView::v32, kKey, {"INSTALLATION1", "Other"});
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::ok);
        CHECK(k.names == std::vector<std::string>{"Installation1", "Other"}); // 64-bit spelling wins
    }
    SECTION("an empty name is never a candidate") {
        ops.put_names(RegView::v64, kKey, {"", "Installation1"});
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).names == std::vector<std::string>{"Installation1"});
    }
}

TEST_CASE("middleware windows: reg_subkeys never reads a failure as absent", "[middleware]") {
    FakeOps ops;
    SECTION("absent in both views is absent") {
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).out == mw::Read::Outcome::absent);
    }
    SECTION("64-bit absent and 32-bit denied is denied") {
        ops.put_list_status(RegView::v32, kKey, RegStatus::denied);
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::denied);
        CHECK(k.names.empty());
    }
    SECTION("64-bit denied and 32-bit absent is denied") {
        ops.put_list_status(RegView::v64, kKey, RegStatus::denied);
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).out == mw::Read::Outcome::denied);
    }
    SECTION("an empty key beside a denied view is denied, not an empty answer") {
        ops.put_names(RegView::v64, kKey, {});
        ops.put_list_status(RegView::v32, kKey, RegStatus::denied);
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).out == mw::Read::Outcome::denied);
    }
    SECTION("64-bit absent and 32-bit failed is failed") {
        ops.put_list_status(RegView::v32, kKey, RegStatus::failed);
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).out == mw::Read::Outcome::failed);
    }
    SECTION("an empty key in one view and absent in the other is ok with no names") {
        ops.put_names(RegView::v64, kKey, {});
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::ok);
        CHECK(k.names.empty());
    }
    SECTION("names in one view, the other denied: denied, and the names are kept") {
        ops.put_names(RegView::v64, kKey, {"Installation1", "Installation2"});
        ops.put_list_status(RegView::v32, kKey, RegStatus::denied);
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::denied);
        CHECK(k.names == std::vector<std::string>{"Installation1", "Installation2"});
    }
    SECTION("names in one view, the other failed: failed, and the names are kept") {
        ops.put_list_status(RegView::v64, kKey, RegStatus::failed);
        ops.put_names(RegView::v32, kKey, {"Installation9"});
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.out == mw::Read::Outcome::failed);
        CHECK(k.names == std::vector<std::string>{"Installation9"});
    }
    SECTION("one view denied and the other failed: a refusal outranks a failure") {
        ops.put_list_status(RegView::v64, kKey, RegStatus::failed);
        ops.put_list_status(RegView::v32, kKey, RegStatus::denied);
        auto fs = make(ops);
        CHECK(fs.reg_subkeys(kKey).out == mw::Read::Outcome::denied);
    }
    SECTION("a refused view's names are never used") {
        win::RegListing bad;
        bad.status = RegStatus::denied;
        bad.names = {"Leaked"};
        ops.lists[{RegView::v64, kKey}] = bad;
        auto fs = make(ops);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.names.empty());
        CHECK(k.out == mw::Read::Outcome::denied);
    }
}

TEST_CASE("middleware windows: reg_value reads the 64-bit view first", "[middleware]") {
    const std::string key = std::string{kKey} + "\\Installation1";
    FakeOps ops;
    SECTION("found in the 64-bit view: the 32-bit view is never asked") {
        ops.put_text(RegView::v64, key, "FilePath", "C:\\mq64");
        ops.put_text(RegView::v32, key, "FilePath", "C:\\mq32");
        auto fs = make(ops);
        const mw::Read r = fs.reg_value(kKey, "Installation1", "FilePath", 4096);
        CHECK(r.out == mw::Read::Outcome::ok);
        CHECK(r.text == "C:\\mq64");
    }
    SECTION("absent in the 64-bit view falls through to the 32-bit view") {
        ops.put_text(RegView::v32, key, "VRMF", "9.3.5.1");
        auto fs = make(ops);
        const mw::Read r = fs.reg_value(kKey, "Installation1", "VRMF", 4096);
        CHECK(r.out == mw::Read::Outcome::ok);
        CHECK(r.text == "9.3.5.1");
    }
    SECTION("absent in both views is absent") {
        auto fs = make(ops);
        CHECK(fs.reg_value(kKey, "Installation1", "VRMF", 4096).out == mw::Read::Outcome::absent);
    }
    SECTION("denied is the answer: the 32-bit view is not tried") {
        ops.put_value_status(RegView::v64, key, "FilePath", RegStatus::denied);
        ops.put_text(RegView::v32, key, "FilePath", "C:\\mq32");
        auto fs = make(ops);
        const mw::Read r = fs.reg_value(kKey, "Installation1", "FilePath", 4096);
        CHECK(r.out == mw::Read::Outcome::denied);
        CHECK(r.text.empty());
    }
    SECTION("failed and oversized map to their own outcomes with no text") {
        ops.put_value_status(RegView::v64, key, "FilePath", RegStatus::failed);
        ops.put_value_status(RegView::v64, key, "VRMF", RegStatus::oversized);
        auto fs = make(ops);
        const mw::Read a = fs.reg_value(kKey, "Installation1", "FilePath", 4096);
        const mw::Read b = fs.reg_value(kKey, "Installation1", "VRMF", 4096);
        CHECK(a.out == mw::Read::Outcome::failed);
        CHECK(a.text.empty());
        CHECK(b.out == mw::Read::Outcome::oversized);
        CHECK(b.text.empty());
    }
}

TEST_CASE("middleware windows: decide_value accepts only text within the cap", "[middleware]") {
    using win::RegValueKind;
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 10, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::expand_sz, 10, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 64, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 65, 64) == RegStatus::oversized);
    // a REG_DWORD or REG_BINARY value (any non-text type) is failed, never text, whatever its size
    STATIC_REQUIRE(win::decide_value(RegValueKind::other, 4, 64) == RegStatus::failed);
    STATIC_REQUIRE(win::decide_value(RegValueKind::other, 9999, 64) == RegStatus::failed);
}

TEST_CASE("middleware windows: the entries budget sets exhausted()", "[middleware]") {
    SECTION("a listing cut at the budget exhausts it") {
        FakeOps ops;
        ops.put_names(RegView::v64, kKey, {"A", "B", "C", "D"});
        auto fs = make(ops, /*budget=*/2);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.names.size() == 2);
        CHECK(fs.exhausted());
    }
    SECTION("a listing within the budget does not") {
        FakeOps ops;
        ops.put_names(RegView::v64, kKey, {"A", "B"});
        auto fs = make(ops, /*budget=*/2);
        CHECK(fs.reg_subkeys(kKey).names.size() == 2);
        CHECK_FALSE(fs.exhausted());
    }
    SECTION("the second view only gets what the first left") {
        FakeOps ops;
        ops.put_names(RegView::v64, kKey, {"A", "B"});
        ops.put_names(RegView::v32, kKey, {"C"});
        auto fs = make(ops, /*budget=*/2);
        const mw::RegKeys k = fs.reg_subkeys(kKey);
        CHECK(k.names == std::vector<std::string>{"A", "B"});
        CHECK(fs.exhausted());
    }
    SECTION("value reads count against the same budget") {
        FakeOps ops;
        auto fs = make(ops, /*budget=*/2);
        (void)fs.reg_value(kKey, "I1", "FilePath", 16); // two views, both absent: two entries
        CHECK_FALSE(fs.exhausted());
        (void)fs.reg_value(kKey, "I1", "VRMF", 16);
        CHECK(fs.exhausted());
    }
}

TEST_CASE("middleware windows: the plugin sources use only the wide registry calls", "[middleware]") {
    // Registry strings are read with Reg*W (win_str.hpp), never Reg*A: an ANSI call mangles a
    // non-ASCII install path. This lexical check keeps one from appearing in the plugin directory.
    namespace fs = std::filesystem;
    const fs::path dir = fs::path{YUZU_PLUGIN_SRC_DIR} / "middleware" / "src";
    REQUIRE(fs::exists(dir));
    bool scanned_win_tu = false; // the one TU that holds the registry calls
    for (const auto& e : fs::directory_iterator{dir}) {
        const auto ext = e.path().extension();
        if (ext != ".hpp" && ext != ".cpp")
            continue;
        std::ifstream in{e.path(), std::ios::binary};
        REQUIRE(in.is_open());
        const std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
        scanned_win_tu = scanned_win_tu || e.path().filename() == "middleware_win.cpp";
        INFO("file: " << e.path().string());
        for (const char* banned : {"RegOpenKeyExA", "RegQueryValueExA", "RegEnumKeyExA", "RegGetValueA"})
            CHECK(text.find(banned) == std::string::npos);
    }
    CHECK(scanned_win_tu);
}
