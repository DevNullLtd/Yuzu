/**
 * test_asset_tags_parsers.cpp -- asset_tags_parsers.hpp (#232): the pure core of
 * the asset_tags plugin. No files, threads, clocks or processes.
 */
#include "asset_tags_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::asset_tags;

namespace {

// Split on UNESCAPED '|' and undo "\|" -- mirrors the shared server decoder
// (server/core/src/result_parsing.hpp) so a row's field count can be asserted.
std::vector<std::string> split_row(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

CategoryValues vals(std::string role = "", std::string env = "", std::string loc = "",
                    std::string svc = "") {
    return CategoryValues{std::move(role), std::move(env), std::move(loc), std::move(svc)};
}

} // namespace

TEST_CASE("asset_tags cap_value: bounds and codepoint safety", "[agent][asset_tags_parsers]") {
    CHECK(cap_value("") == "");
    CHECK(cap_value("role") == "role");
    CHECK(cap_value(std::string(kMaxValueBytes, 'a')).size() == kMaxValueBytes);
    CHECK(cap_value(std::string(kMaxValueBytes + 1, 'a')) == std::string(kMaxValueBytes, 'a'));

    // 446 x 'a' + U+20AC (3 bytes: E2 82 AC) straddles the 448 limit: dropped whole.
    const std::string euro = "\xE2\x82\xAC";
    const std::string straddle = std::string(446, 'a') + euro;
    REQUIRE(straddle.size() == 449);
    CHECK(cap_value(straddle) == std::string(446, 'a'));

    // A pipe survives capping untouched (escaping is output-only).
    CHECK(cap_value("Rack A|3") == "Rack A|3");
}

TEST_CASE("asset_tags change log is bounded", "[agent][asset_tags_parsers]") {
    std::vector<ChangeRecord> log;
    for (int i = 1; i <= 51; ++i)
        append_change(log, ChangeRecord{"role", "", std::to_string(i), i});
    REQUIRE(log.size() == kMaxChangeLog);
    CHECK(log.front().new_value == "2");
    CHECK(log.back().new_value == "51");

    std::vector<ChangeRecord> big;
    for (int i = 1; i <= 60; ++i)
        big.push_back(ChangeRecord{"role", "", std::to_string(i), i});
    trim_change_log(big);
    REQUIRE(big.size() == kMaxChangeLog);
    CHECK(big.front().new_value == "11");
    CHECK(big.back().new_value == "60");
}

TEST_CASE("asset_tags apply_sync: diff semantics", "[agent][asset_tags_parsers]") {
    AssetTagState st;
    auto changes = apply_sync(st, vals("db", "Production"), 1000);
    CHECK(changes.size() == 2);
    CHECK(st.tags.size() == 2);
    CHECK(st.last_sync_epoch == 1000);
    CHECK_FALSE(st.stale);
    CHECK(st.change_log.size() == 2);

    // Identical sync: no changes, log unchanged.
    changes = apply_sync(st, vals("db", "Production"), 2000);
    CHECK(changes.empty());
    CHECK(st.change_log.size() == 2);
    CHECK(st.last_sync_epoch == 2000);

    // Empty value removes the tag and records old -> "".
    changes = apply_sync(st, vals("", "Production"), 3000);
    REQUIRE(changes.size() == 1);
    CHECK(changes[0].key == "role");
    CHECK(changes[0].old_value == "db");
    CHECK(changes[0].new_value.empty());
    CHECK(st.tags.count("role") == 0);

    // Change records old and new.
    changes = apply_sync(st, vals("db2", "Production"), 4000);
    REQUIRE(changes.size() == 1);
    CHECK(changes[0].old_value.empty());
    CHECK(changes[0].new_value == "db2");
    changes = apply_sync(st, vals("db3", "Production"), 5000);
    REQUIRE(changes.size() == 1);
    CHECK(changes[0].old_value == "db2");
    CHECK(changes[0].new_value == "db3");
}

TEST_CASE("asset_tags row formatters escape every field", "[agent][asset_tags_parsers]") {
    SECTION("value with a pipe stays one 5-field row") {
        ChangeRecord cr{"location", "Rack A|3", "Rack B|4", 42};
        auto row = format_change_row(cr);
        CHECK(row == "change|location|Rack A\\|3|Rack B\\|4|42");
        auto fields = split_row(row);
        REQUIRE(fields.size() == 5);
        CHECK(fields[2] == "Rack A|3");
        CHECK(fields[4] == "42");

        CHECK(format_tag_row("location", "Rack A|3") == "tag|location|Rack A\\|3");
    }
    SECTION("CR/LF fold to space, backslash folds to slash") {
        CHECK(format_tag_row("role", "a\r\nb") == "tag|role|a  b");
        CHECK(format_tag_row("role", "a\\b") == "tag|role|a/b");
    }
    SECTION("the key is escaped too") {
        ChangeRecord cr{"ro|le", "a", "b", 1};
        auto fields = split_row(format_change_row(cr));
        REQUIRE(fields.size() == 5);
        CHECK(fields[1] == "ro|le");
        CHECK(format_change_row(cr).find("ro\\|le") != std::string::npos);
    }
    SECTION("error echo is a single escaped line") {
        auto row = format_error_row("error|unknown category", "x|y\n");
        CHECK(row == "error|unknown category: x\\|y ");
        CHECK(row.find('\n') == std::string::npos);
        CHECK(format_error_row("unknown action", "a|b") == "unknown action: a\\|b");
    }
    SECTION("sync events omit the empty side") {
        CHECK(format_sync_event({"role", "", "db", 1}) == "sync|tag_added|role|db");
        CHECK(format_sync_event({"role", "db", "", 1}) == "sync|tag_removed|role|db");
        CHECK(format_sync_event({"role", "db", "web", 1}) == "sync|tag_changed|role|db|web");
        CHECK(split_row(format_sync_event({"role", "a|b", "c|d", 1})).size() == 5);
    }
    SECTION("timestamp is decimal") {
        CHECK(format_change_row({"role", "a", "b", 1700000000}) ==
              "change|role|a|b|1700000000");
    }
}

TEST_CASE("asset_tags snapshot round trip and caps", "[agent][asset_tags_parsers]") {
    AssetTagState st;
    apply_sync(st, vals("db", "Production", "Rack A|3"), 100);
    apply_sync(st, vals("db2", "Production", "Rack A|3"), 200);

    const auto text = serialize_state(st);
    auto parsed = parse_state(text);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tags == st.tags);
    CHECK(parsed->last_sync_epoch == st.last_sync_epoch);
    CHECK(parsed->stale == st.stale);
    REQUIRE(parsed->change_log.size() == st.change_log.size());
    for (std::size_t i = 0; i < st.change_log.size(); ++i) {
        CHECK(parsed->change_log[i].key == st.change_log[i].key);
        CHECK(parsed->change_log[i].old_value == st.change_log[i].old_value);
        CHECK(parsed->change_log[i].new_value == st.change_log[i].new_value);
        CHECK(parsed->change_log[i].timestamp == st.change_log[i].timestamp);
    }

    SECTION("an oversized on-disk log is trimmed to the newest 50") {
        AssetTagState big;
        for (int i = 1; i <= 60; ++i)
            big.change_log.push_back(ChangeRecord{"role", "", std::to_string(i), i});
        auto p = parse_state(serialize_state(big));
        REQUIRE(p.has_value());
        REQUIRE(p->change_log.size() == kMaxChangeLog);
        CHECK(p->change_log.front().new_value == "11");
        CHECK(p->change_log.back().new_value == "60");
    }
    SECTION("uncapped on-disk values are capped on load") {
        nlohmann::json j;
        j["tags"] = {{"role", std::string(600, 'x')}};
        j["change_log"] = nlohmann::json::array(
            {{{"key", "role"}, {"old_value", std::string(600, 'y')}, {"new_value", "z"}}});
        auto p = parse_state(j.dump());
        REQUIRE(p.has_value());
        CHECK(p->tags.at("role").size() == kMaxValueBytes);
        CHECK(p->change_log.at(0).old_value.size() == kMaxValueBytes);
    }
    SECTION("an unknown extra top-level key is ignored") {
        auto p = parse_state(R"({"future_field":1,"tags":{"role":"db"}})");
        REQUIRE(p.has_value());
        CHECK(p->tags.at("role") == "db");
        CHECK(p->stale);
    }
    SECTION("invalid UTF-8 in a stored value does not throw on serialize") {
        AssetTagState bad;
        bad.tags["role"] = "a\xFF" "b";
        CHECK_NOTHROW(serialize_state(bad));
    }
}

TEST_CASE("asset_tags parse_state rejects the whole snapshot on a schema violation",
          "[agent][asset_tags_parsers]") {
    for (const char* text : {"", "{not json", "[]"}) {
        DYNAMIC_SECTION("not an object: '" << text << "'") {
            auto p = parse_state(text);
            REQUIRE_FALSE(p.has_value());
            CHECK_FALSE(p.error().message.empty());
        }
    }

    struct Bad {
        const char* text;
        const char* field;
    };
    const Bad cases[] = {
        {R"({"tags":[1]})", "tags"},
        {R"({"tags":{"role":5}})", "tags.role"},
        {R"({"last_sync_epoch":"x"})", "last_sync_epoch"},
        {R"({"stale":"yes"})", "stale"},
        {R"({"change_log":{}})", "change_log"},
        {R"({"change_log":[{"key":"role","timestamp":"s"}]})", "change_log[0].timestamp"},
        {R"({"change_log":[{"key":"ro|le"}]})", "change_log[0].key"},
        {R"({"change_log":[{"key":7}]})", "change_log[0].key"},
        // A change record without a category key is not a record this plugin
        // ever writes: rejected whole, never loaded as key="".
        {R"({"change_log":[{"old_value":"a","new_value":"b","timestamp":1}]})",
         "change_log[0].key: missing"},
        {R"({"change_log":[{"key":"role"},5]})", "change_log[1]"},
        {R"({"tags":{"colour":"red"}})", "tags.colour"},
    };
    for (const auto& c : cases) {
        DYNAMIC_SECTION(c.text) {
            std::expected<AssetTagState, ParseError> p;
            REQUIRE_NOTHROW(p = parse_state(c.text));
            REQUIRE_FALSE(p.has_value());
            CHECK(p.error().message.find(c.field) != std::string::npos);
        }
    }
}

TEST_CASE("asset_tags parse_check_interval", "[agent][asset_tags_parsers]") {
    CHECK(parse_check_interval("300") == 300);
    CHECK(parse_check_interval("10") == 30);
    CHECK(parse_check_interval("-5") == 30);
    CHECK_FALSE(parse_check_interval("abc").has_value());
    CHECK_FALSE(parse_check_interval("30x").has_value());
    CHECK_FALSE(parse_check_interval("").has_value());
    CHECK_FALSE(parse_check_interval(" 30").has_value());
}
