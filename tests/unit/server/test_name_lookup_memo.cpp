/**
 * test_name_lookup_memo.cpp — the per-render definition-name memo the Operate pages
 * share (name_lookup_memo.hpp). Pure: the resolver is a counting double, no database.
 */

#include "name_lookup_memo.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using yuzu::server::operate_pages::NameLookupMemo;

namespace {

/// Resolver double: answers from `names`; any id in `fail` is a read failure; every call
/// is recorded so tests can assert how many lookups a render made.
struct Double {
    std::unordered_map<std::string, std::string> names;
    std::vector<std::string> fail;
    std::vector<std::string> calls;

    NameLookupMemo::Resolver resolver() {
        return [this](const std::string& id)
                   -> std::expected<std::optional<std::string>, std::string> {
            calls.push_back(id);
            for (const auto& f : fail)
                if (f == id)
                    return std::unexpected("read failed");
            const auto it = names.find(id);
            if (it == names.end())
                return std::optional<std::string>{};
            return std::optional<std::string>{it->second};
        };
    }
};

} // namespace

TEST_CASE("name_lookup_memo: each distinct id is resolved once per render",
          "[ui][operate][memo]") {
    Double d;
    d.names = {{"a", "Alpha"}, {"b", "Beta"}};
    NameLookupMemo memo(d.resolver());

    CHECK(memo.label("a") == "Alpha");
    CHECK(memo.label("b") == "Beta");
    CHECK(memo.label("a") == "Alpha");
    CHECK(memo.label("a") == "Alpha");
    CHECK(d.calls == std::vector<std::string>{"a", "b"});
    CHECK_FALSE(memo.failed());
}

TEST_CASE("name_lookup_memo: the first read failure stops every later lookup",
          "[ui][operate][memo]") {
    Double d;
    d.names = {{"ok1", "One"}, {"ok2", "Two"}};
    d.fail = {"bad"};
    NameLookupMemo memo(d.resolver());

    CHECK(memo.label("ok1") == "One"); // resolved before the failure keeps its name
    CHECK(memo.label("bad") == "bad"); // the failing id falls back to itself
    CHECK(memo.failed());
    CHECK(memo.label("ok2") == "ok2"); // a perfectly good id is NOT looked up any more
    CHECK(memo.label("another") == "another");
    CHECK(memo.label("ok1") == "One"); // memoised result survives the stop
    CHECK(d.calls == std::vector<std::string>{"ok1", "bad"});
}

TEST_CASE("name_lookup_memo: a definition that is not found falls back and does not stop "
          "the render",
          "[ui][operate][memo]") {
    Double d;
    d.names = {{"known", "Known"}};
    NameLookupMemo memo(d.resolver());

    CHECK(memo.label("missing") == "missing");
    CHECK_FALSE(memo.failed());
    CHECK(memo.label("known") == "Known");
    CHECK(d.calls == std::vector<std::string>{"missing", "known"});
}

TEST_CASE("name_lookup_memo: an empty name reads as not found", "[ui][operate][memo]") {
    Double d;
    d.names = {{"blank", ""}};
    NameLookupMemo memo(d.resolver());
    CHECK(memo.label("blank") == "blank");
}

TEST_CASE("name_lookup_memo: no resolver and an empty id never look anything up",
          "[ui][operate][memo]") {
    NameLookupMemo bare;
    CHECK(bare.label("x") == "x");
    CHECK(bare.label("").empty());

    Double d;
    NameLookupMemo memo(d.resolver());
    CHECK(memo.label("").empty());
    CHECK(d.calls.empty());
}
