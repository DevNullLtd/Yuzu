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
 *  - decide_value: treating a non-text value as text fails the REG_DWORD / REG_BINARY case;
 *    answering `failed` for it (the old rule, which made a wrong-typed value and a read failure one
 *    status) fails the same case and the reg_value mapping case.
 *  - budget: not counting a view's names fails the exhausted() cases.
 *  - de-duplication cost: a linear scan of the names so far instead of a hash set is correct but
 *    quadratic; it is not asserted here (no clock), the budget-sized case pins the result only.
 */
#include <catch2/catch_test_macros.hpp>

#include "middleware_win_parsers.hpp"

#include <middleware_products.hpp>

#include <cstddef>
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
    SECTION("failed, oversized and not_text map to their own outcomes with no text") {
        ops.put_value_status(RegView::v64, key, "FilePath", RegStatus::failed);
        ops.put_value_status(RegView::v64, key, "VRMF", RegStatus::oversized);
        ops.put_value_status(RegView::v64, key, "Bin", RegStatus::not_text);
        auto fs = make(ops);
        const mw::Read a = fs.reg_value(kKey, "Installation1", "FilePath", 4096);
        const mw::Read b = fs.reg_value(kKey, "Installation1", "VRMF", 4096);
        const mw::Read c = fs.reg_value(kKey, "Installation1", "Bin", 4096);
        CHECK(a.out == mw::Read::Outcome::failed);
        CHECK(a.text.empty());
        CHECK(b.out == mw::Read::Outcome::oversized);
        CHECK(b.text.empty());
        CHECK(c.out == mw::Read::Outcome::not_text);
        CHECK(c.text.empty());
    }
    SECTION("a wrong-typed 64-bit value is the answer: the 32-bit view is not tried") {
        ops.put_value_status(RegView::v64, key, "FilePath", RegStatus::not_text);
        ops.put_text(RegView::v32, key, "FilePath", "C:\\mq32");
        auto fs = make(ops);
        CHECK(fs.reg_value(kKey, "Installation1", "FilePath", 4096).out ==
              mw::Read::Outcome::not_text);
    }
}

TEST_CASE("middleware windows: decide_value accepts only text within the cap", "[middleware]") {
    using win::RegValueKind;
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 10, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::expand_sz, 10, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 64, 64) == RegStatus::ok);
    STATIC_REQUIRE(win::decide_value(RegValueKind::sz, 65, 64) == RegStatus::oversized);
    // a REG_DWORD or REG_BINARY value (any non-text type) is not_text, never text and never
    // `failed` (a read failure), whatever its size
    STATIC_REQUIRE(win::decide_value(RegValueKind::other, 4, 64) == RegStatus::not_text);
    STATIC_REQUIRE(win::decide_value(RegValueKind::other, 9999, 64) == RegStatus::not_text);
}

TEST_CASE("middleware windows: reg_subkeys fails closed on a status a listing never yields",
          "[middleware]") {
    // a listing never yields oversized or not_text; if an ops did, the merge fails closed
    FakeOps ops;
    ops.put_list_status(RegView::v64, kKey, RegStatus::not_text);
    ops.put_names(RegView::v32, kKey, {"Installation1"});
    auto fs = make(ops);
    const mw::RegKeys k = fs.reg_subkeys(kKey);
    CHECK(k.out == mw::Read::Outcome::failed);
    CHECK(k.names == std::vector<std::string>{"Installation1"});
}

TEST_CASE("middleware windows: names split across the views at the entries budget are merged once",
          "[middleware]") {
    // kMaxRegEntries names, half in each view, the 32-bit half being the 64-bit names in another
    // case: every name is one installation, in the 64-bit spelling, and the budget is met exactly,
    // not exceeded. (The merge is a hash set; a scan per name would be quadratic here. No clock.)
    constexpr std::size_t kHalf = win::kMaxRegEntries / 2;
    std::vector<std::string> lower;
    std::vector<std::string> upper;
    lower.reserve(kHalf);
    upper.reserve(kHalf);
    for (std::size_t i = 0; i < kHalf; ++i) {
        lower.push_back("inst" + std::to_string(i));
        upper.push_back("INST" + std::to_string(i));
    }
    FakeOps ops;
    ops.put_names(RegView::v64, kKey, lower);
    ops.put_names(RegView::v32, kKey, upper);
    auto fs = make(ops);
    const mw::RegKeys k = fs.reg_subkeys(kKey);
    CHECK(k.out == mw::Read::Outcome::ok);
    CHECK(k.names.size() == kHalf);
    CHECK(k.names == lower);
    CHECK_FALSE(fs.exhausted());
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
