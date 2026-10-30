// test_inventory_status_row.cpp -- the shared inventory status row
// (agents/shared/inventory_status_row.hpp): the producer's exact bytes, the
// consumer's grammar, and the format -> parse round trip. Pure and portable:
// no process, file or clock, so it runs identically on every OS leg.
//
// The escaping under test (yuzu::util::safe_output_field) is documented LOSSY:
// a literal backslash folds to '/', CR/LF fold to ' ', and '|' becomes `\|`
// which the raw-pipe consumer then cuts at. The round-trip cases therefore use
// an explicit (input token, expected parsed token) table and never an identity
// loop; the formatter is not changed to make an identity hold, because that
// would change the bytes the plugins put on the wire.

#include <catch2/catch_test_macros.hpp>

#include <inventory_status_row.hpp>

#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using yuzu::shared::StatusLevel;

// Split on every raw '|', as the collector's splitter does (no unescaping).
std::vector<std::string> split_raw(const std::string& line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t bar = line.find('|', pos);
        if (bar == std::string::npos) {
            out.push_back(line.substr(pos));
            return out;
        }
        out.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

std::optional<yuzu::shared::StatusRow> parse(const std::string& line, std::string_view action) {
    const auto fields = split_raw(line);
    const std::vector<std::string_view> views(fields.begin(), fields.end());
    return yuzu::shared::parse_status_row(views, action);
}

constexpr std::array<StatusLevel, 3> kLevels = {StatusLevel::supported, StatusLevel::constrained,
                                                StatusLevel::unsupported};
constexpr std::array<std::string_view, 4> kActions = {"packages", "managers", "store_packages",
                                                      "list_inventory"};

} // namespace

TEST_CASE("inventory_status_row: producer byte pins", "[inventory_status_row]") {
    using yuzu::shared::format_status_row;
    CHECK(format_status_row("managers", StatusLevel::supported, "") ==
          "status|managers|supported|-");
    CHECK(format_status_row("packages", StatusLevel::constrained, "a,b") ==
          "status|packages|constrained|a,b");
    CHECK(format_status_row("list_inventory", StatusLevel::unsupported, "linux:no_msi") ==
          "status|list_inventory|unsupported|linux:no_msi");
    // safe_output_field's documented lossy fold: a literal backslash becomes '/'
    CHECK(format_status_row("packages", StatusLevel::constrained, "a\\") ==
          "status|packages|constrained|a/");
    // an empty token list is "-", never an empty fourth field
    CHECK(format_status_row("packages", StatusLevel::supported, std::string_view{}) ==
          "status|packages|supported|-");
    // the action is escaped like the tokens
    CHECK(format_status_row("a|b", StatusLevel::supported, "-") == "status|a\\|b|supported|-");
}

TEST_CASE("inventory_status_row: format then parse, every level x action x token",
          "[inventory_status_row]") {
    struct Row {
        std::string input;
        std::string parsed; // what the consumer reads back, NOT necessarily the input
    };
    const std::vector<Row> rows = {
        {"", "-"},  // empty list is written as "-"
        {"-", "-"}, // a literal "-" is the same bytes
        {"a", "a"},
        {"a,b", "a,b"},
        {"macos:homebrew_cellar:permission_denied", "macos:homebrew_cellar:permission_denied"},
        {"a\\", "a/"}, // lossy fold, pinned: never an identity
        {"a\\b", "a/b"},
        {"t\tb", "t\tb"}, // tab passes through
        {"a\rb", "a b"},  // CR folds to ' '
        {"a\nb", "a b"},  // LF folds to ' '
        {"a\r\nb", "a  b"},
        {std::string("a\0b", 3), std::string("a\0b", 3)}, // NUL passes the pure function
    };
    for (const auto level : kLevels) {
        for (const auto action : kActions) {
            for (const auto& row : rows) {
                const std::string line = yuzu::shared::format_status_row(action, level, row.input);
                INFO("action=" << action << " level=" << yuzu::shared::status_level_token(level)
                               << " input.size=" << row.input.size());
                CHECK(line.find('\n') == std::string::npos); // one line, always
                CHECK(line.find('\r') == std::string::npos);
                const auto parsed = parse(line, action);
                REQUIRE(parsed.has_value());
                CHECK(parsed->level == level);
                CHECK(parsed->tokens == row.parsed);
            }
        }
    }
}

TEST_CASE("inventory_status_row: a pipe in a token is cut at the escaped pipe",
          "[inventory_status_row]") {
    // The producer writes `a\|b`; the consumer splits on the raw '|' and does not unescape, so it
    // reads field 4 as `a\` and a fifth field `b`. Pre-existing wire behaviour, pinned not fixed.
    const std::string line =
        yuzu::shared::format_status_row("managers", StatusLevel::constrained, "a|b");
    CHECK(line == "status|managers|constrained|a\\|b");
    const auto parsed = parse(line, "managers");
    REQUIRE(parsed.has_value());
    CHECK(parsed->level == StatusLevel::constrained);
    CHECK(parsed->tokens == "a\\");
}

TEST_CASE("inventory_status_row: parse_status_row grammar", "[inventory_status_row]") {
    SECTION("another action's row is not counted") {
        CHECK_FALSE(parse("status|packages|supported|-", "managers").has_value());
        CHECK_FALSE(parse("status|managers|supported|-", "packages").has_value());
        CHECK_FALSE(parse("status|Managers|supported|-", "managers").has_value());
        CHECK_FALSE(parse("status||supported|-", "managers").has_value());
    }
    SECTION("fewer than four fields is not counted") {
        CHECK_FALSE(parse("status", "managers").has_value());
        CHECK_FALSE(parse("status|", "managers").has_value());
        CHECK_FALSE(parse("status|managers", "managers").has_value());
        CHECK_FALSE(parse("status|managers|supported", "managers").has_value());
        CHECK_FALSE(parse("", "managers").has_value());
    }
    SECTION("an unknown level still counts, with no level and the tokens kept") {
        for (const char* level :
             {"bogus", "", "Supported", "supported ", " supported", "SUPPORTED"}) {
            const auto parsed = parse(std::string("status|managers|") + level + "|tok", "managers");
            INFO("level=[" << level << "]");
            REQUIRE(parsed.has_value());
            CHECK_FALSE(parsed->level.has_value());
            CHECK(parsed->tokens == "tok");
        }
    }
    SECTION("field 4 is kept at EVERY level; fields past it are ignored") {
        for (const auto level : kLevels) {
            const std::string name(yuzu::shared::status_level_token(level));
            const auto parsed =
                parse("status|managers|" + name + "|first|second|third", "managers");
            INFO("level=" << name);
            REQUIRE(parsed.has_value());
            CHECK(parsed->level == level);
            CHECK(parsed->tokens == "first");
        }
    }
    SECTION("an empty fourth field is kept verbatim") {
        const auto parsed = parse("status|managers|supported|", "managers");
        REQUIRE(parsed.has_value());
        CHECK(parsed->tokens.empty());
    }
}

TEST_CASE("inventory_status_row: is_status_line", "[inventory_status_row]") {
    const auto is_status = [](const std::string& line) {
        const auto fields = split_raw(line);
        const std::vector<std::string_view> views(fields.begin(), fields.end());
        return yuzu::shared::is_status_line(views);
    };
    CHECK(is_status("status"));
    CHECK(is_status("status|x"));
    CHECK(is_status("status|managers|supported|-"));
    CHECK_FALSE(is_status("package|homebrew|a|1|formula"));
    CHECK_FALSE(is_status("manager|homebrew|present|-|/|-|-"));
    CHECK_FALSE(is_status("Status|managers|supported|-"));
    CHECK_FALSE(is_status("statuses|a"));
    CHECK_FALSE(is_status(""));
    CHECK_FALSE(yuzu::shared::is_status_line(std::span<const std::string_view>{}));
}

TEST_CASE("inventory_status_row: level tokens are inverse over the three values",
          "[inventory_status_row]") {
    for (const auto level : kLevels) {
        const auto token = yuzu::shared::status_level_token(level);
        CHECK(yuzu::shared::status_level_from_token(token) == level);
    }
    CHECK(yuzu::shared::status_level_token(StatusLevel::supported) == "supported");
    CHECK(yuzu::shared::status_level_token(StatusLevel::constrained) == "constrained");
    CHECK(yuzu::shared::status_level_token(StatusLevel::unsupported) == "unsupported");
    // an out-of-range value reads as constrained, never supported
    CHECK(yuzu::shared::status_level_token(static_cast<StatusLevel>(99)) == "constrained");
    for (const std::string_view bad : {"", "Supported", "supported ", " supported", "supported\n",
                                       "unsupport", "constrained2", "ok", "-"}) {
        INFO("token=[" << bad << "]");
        CHECK_FALSE(yuzu::shared::status_level_from_token(bad).has_value());
    }
}
