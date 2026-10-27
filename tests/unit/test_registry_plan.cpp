/**
 * test_registry_plan.cpp -- the registry plugin's pure `apply` layer (registry_plan.hpp): the plan parser with its
 * whole-plan and per-item refusals, the dependent_items rule, the exact-name predicate the undo manifest rests on, and the
 * item / undo / summary row renderers. OS-free: no registry, file, process or clock, so it runs on every host in the agent
 * suite. Expected rows are written out literally, never recomputed with the code under test.
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "registry_plan.hpp"

using namespace yuzu::registry;
using json = nlohmann::json;

namespace {

PlanParse parse(const json& plan) { return parse_plan(plan.dump()); }

json item(std::string op, std::string key, std::string name = {}) {
    json j = {{"op", std::move(op)}, {"key", std::move(key)}};
    if (!name.empty()) j["name"] = std::move(name);
    return j;
}

json set_item(std::string key, std::string name, std::string value) {
    json j = item("set_value", std::move(key), std::move(name));
    j["type"] = "REG_SZ";
    j["value"] = std::move(value);
    return j;
}

/// A test-local oracle for "survives a row cell byte for byte": a strict UTF-8 decoder of its own, so the predicate under
/// test is not checked against itself. A name is spellable when every code point is allowed, it is not the "-" that stands
/// for the empty name and it does not end in a backslash.
bool oracle_spellable(std::string_view s) {
    if (s.empty()) return true;
    if (s == "-" || s.back() == '\\') return false;
    for (std::size_t i = 0; i < s.size();) {
        const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[i + k]); };
        const auto cont = [&](std::size_t k) { return i + k < s.size() && (b(k) & 0xC0) == 0x80; };
        std::uint32_t cp = 0;
        std::size_t n = 0;
        if (b(0) < 0x80) {
            cp = b(0);
            n = 1;
        } else if (b(0) >= 0xC2 && b(0) <= 0xDF && cont(1)) {
            cp = ((b(0) & 0x1Fu) << 6) | (b(1) & 0x3Fu);
            n = 2;
        } else if (b(0) >= 0xE0 && b(0) <= 0xEF && cont(1) && cont(2)) {
            cp = ((b(0) & 0x0Fu) << 12) | ((b(1) & 0x3Fu) << 6) | (b(2) & 0x3Fu);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
            n = 3;
        } else if (b(0) >= 0xF0 && b(0) <= 0xF4 && cont(1) && cont(2) && cont(3)) {
            cp = ((b(0) & 0x07u) << 18) | ((b(1) & 0x3Fu) << 12) | ((b(2) & 0x3Fu) << 6) | (b(3) & 0x3Fu);
            if (cp < 0x10000 || cp > 0x10FFFF) return false;
            n = 4;
        } else {
            return false; // invalid UTF-8
        }
        if (cp == '|' || cp == 0x7F || (cp < 0x20 && cp != 0x09) || (cp >= 0x80 && cp <= 0x9F) || cp == 0x2028 || cp == 0x2029)
            return false;
        i += n;
    }
    return true;
}

} // namespace

// ── the whole plan ───────────────────────────────────────────────────────

TEST_CASE("registry parse_plan: a plan that is not a flat bounded array of objects is refused as a whole",
          "[registry][plan]") {
    const auto error_of = [](std::string_view text) { return parse_plan(text).error; };
    SECTION("not JSON, not an array, empty") {
        CHECK(error_of("not json") == "invalid_plan:not_json");
        CHECK(error_of("") == "invalid_plan:not_json");
        CHECK(error_of("[{\"op\":\"set_value\"") == "invalid_plan:not_json"); // truncated
        CHECK(error_of("{\"op\":\"set_value\"}") == "invalid_plan:not_array");
        CHECK(error_of("\"x\"") == "invalid_plan:not_array");
        CHECK(error_of("42") == "invalid_plan:not_array");
        CHECK(error_of("[]") == "invalid_plan:empty");
        // invalid UTF-8 never gets as far as a name: the JSON layer refuses it
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":\"A\xFF\"}]") == "invalid_plan:not_json");
    }
    SECTION("more than 256 items") {
        json many = json::array();
        for (int i = 0; i < 256; ++i) many.push_back(item("create_key", "Software\\K" + std::to_string(i)));
        CHECK(parse(many).error.empty());
        many.push_back(item("create_key", "Software\\K256"));
        CHECK(parse(many).error == "invalid_plan:too_many_items");
    }
    SECTION("more than 64 KiB") {
        std::string text = "[{\"op\":\"create_key\",\"key\":\"Software\\\\" + std::string(100, 'a') + "\"}]";
        text += std::string(kMaxPlanBytes, ' ');
        CHECK(text.size() > kMaxPlanBytes);
        CHECK(parse_plan(text).error == "invalid_plan:plan_too_large");
        text.resize(kMaxPlanBytes + 1);
        CHECK(parse_plan(text).error == "invalid_plan:plan_too_large"); // one byte past the bound
        text.resize(kMaxPlanBytes);
        CHECK(parse_plan(text).error.empty()); // exactly the bound is allowed (trailing whitespace)
    }
    SECTION("not flat: nested objects and arrays are refused before the parser sees them") {
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":{\"a\":1}}]") == "invalid_plan:not_flat");
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":[\"a\"]}]") == "invalid_plan:not_flat");
        CHECK(error_of("[[{\"op\":\"create_key\"}]]") == "invalid_plan:not_flat");
        CHECK(error_of(std::string(100000, '[')) == "invalid_plan:plan_too_large");
        CHECK(error_of(std::string(60000, '[')) == "invalid_plan:not_flat"); // a deep document never reaches nlohmann
        // brackets inside strings (and escaped quotes) are not nesting
        CHECK(parse_plan("[{\"op\":\"create_key\",\"key\":\"Software\\\\[[[{{{\\\"]]]\"}]").error.empty());
    }
    SECTION("an item that is not an object, a key it should not have, a field that is not a string, an unknown op") {
        CHECK(error_of("[1]") == "invalid_plan:item_not_object:0");
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":\"A\"},\"x\"]") == "invalid_plan:item_not_object:1");
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":\"A\",\"extra\":\"x\"}]") == "invalid_plan:unknown_key:0");
        CHECK(error_of("[{\"op\":\"create_key\",\"Key\":\"A\"}]") == "invalid_plan:unknown_key:0"); // case-sensitive
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":\"A\"},{\"op\":\"set_value\",\"key\":5}]") == "invalid_plan:field_type:1");
        CHECK(error_of("[{\"op\":\"create_key\",\"key\":null}]") == "invalid_plan:field_type:0");
        CHECK(error_of("[{\"op\":true,\"key\":\"A\"}]") == "invalid_plan:field_type:0");
        CHECK(error_of("[{\"op\":\"drop_table\",\"key\":\"A\"}]") == "invalid_plan:invalid_op:0");
        CHECK(error_of("[{\"key\":\"A\"}]") == "invalid_plan:invalid_op:0"); // a missing op is not an op
        CHECK(error_of("[{\"op\":\"SET_VALUE\",\"key\":\"A\"}]") == "invalid_plan:invalid_op:0");
    }
    SECTION("a whole-plan refusal leaves no items") {
        const auto bad = parse_plan("[{\"op\":\"create_key\",\"key\":\"A\"},{\"op\":\"nope\"}]");
        CHECK_FALSE(bad.error.empty());
        CHECK(bad.items.empty());
    }
}

TEST_CASE("registry parse_plan: a valid plan parses every op with its defaults", "[registry][plan]") {
    const auto p = parse(json::array({
        set_item("Software\\Acme", "Ver", "2"),
        {{"op", "set_value"}, {"key", "Software\\Acme"}, {"name", "N"}, {"type", "REG_DWORD"}, {"value", "42"}},
        {{"op", "set_value"}, {"key", "Software\\Acme"}, {"name", "B"}, {"type", "REG_BINARY"}, {"data_hex", ""}},
        {{"op", "set_value"}, {"key", "Software\\Acme"}, {"type", "REG_SZ"}, {"value", "dflt"}},
        item("delete_value", "Software\\Acme", "Gone"),
        item("create_key", "Software\\New"),
        item("delete_key", "Software\\Old"),
    }));
    REQUIRE(p.error.empty());
    REQUIRE(p.items.size() == 7);
    for (const auto& it : p.items) {
        INFO(plan_op_name(it.op) << " " << it.key << " " << it.name);
        CHECK(it.invalid.empty());
        CHECK(it.hive == "HKLM"); // the default and the only hive
    }
    CHECK(p.items[0].op == PlanOp::set_value);
    CHECK(p.items[0].type_name == "REG_SZ"); // the default type
    CHECK(p.items[0].bytes == std::vector<std::uint8_t>{0x32, 0, 0, 0});
    CHECK(p.items[1].bytes == std::vector<std::uint8_t>{42, 0, 0, 0});
    CHECK(p.items[2].bytes.empty()); // an explicit empty data_hex is a zero-byte REG_BINARY
    CHECK(p.items[3].name.empty());  // the default value
    CHECK(p.items[4].op == PlanOp::delete_value);
    CHECK(p.items[5].op == PlanOp::create_key);
    CHECK(p.items[6].op == PlanOp::delete_key);
    CHECK(plan_op_name(PlanOp::create_key) == "create_key");
}

TEST_CASE("registry parse_plan: a per-item refusal rides the item and the plan still parses", "[registry][plan]") {
    struct Case {
        json item;
        const char* token;
        const char* what;
    };
    const Case cases[] = {
        {{{"op", "create_key"}, {"hive", "HKCU"}, {"key", "Software\\A"}}, "invalid_hive", "HKCU"},
        {{{"op", "create_key"}, {"hive", "hklm"}, {"key", "Software\\A"}}, "invalid_hive", "hive is case-sensitive"},
        {{{"op", "create_key"}, {"hive", "HKU"}, {"key", "S-1\\A"}}, "invalid_hive", "HKU"},
        {item("create_key", ""), "invalid_key_path", "an empty key"},
        {item("create_key", "Software\\\\A"), "invalid_key_path", "an empty component"},
        {item("create_key", "Software\\..\\A"), "invalid_key_path", "a dot-dot component"},
        {item("create_key", "HKLM\\Software"), "invalid_key_path", "a hive alias"},
        {item("create_key", "Software\tA"), "invalid_key_path", "a control byte in the key"},
        {item("delete_value", "Software\\A", std::string(kMaxValueNameBytes + 1, 'n')), "invalid_value_name", "a name over 16,383"},
        {item("delete_value", "Software\\A", "tab\there"), "invalid_value_name", "a control byte in the name (a tab too)"},
        {item("delete_value", std::string("Software\\A|B"), "n"), "unrepresentable_name", "a pipe in the key"},
        {item("delete_value", "Software\\A", "a|b"), "unrepresentable_name", "a pipe in the name"},
        {item("delete_value", "Software\\A", "-"), "unrepresentable_name", "the name \"-\""},
        {item("delete_value", "Software\\A", "a\xE2\x80\xA8z"), "unrepresentable_name", "U+2028"},
        {item("delete_value", "Software\\A", "a\xE2\x80\xA9z"), "unrepresentable_name", "U+2029"},
        {item("delete_value", "Software\\A", "a\xC2\x85z"), "unrepresentable_name", "a C1 control (NEL)"},
        {item("delete_value", "Software\\A", "ends\\"), "unrepresentable_name", "a trailing backslash"},
        {item("create_key", "Software\\A\xC2\x9B"), "unrepresentable_name", "a C1 control in the key"},
        {item("create_key", "Software\\A", "name"), "invalid_value_name", "a key op with a name"},
        {{{"op", "delete_key"}, {"key", "Software\\A"}, {"type", "REG_SZ"}}, "invalid_data", "a key op with a type"},
        {{{"op", "create_key"}, {"key", "Software\\A"}, {"value", "x"}}, "invalid_data", "a key op with a value"},
        {{{"op", "delete_key"}, {"key", "Software\\A"}, {"data_hex", ""}}, "invalid_data", "a key op with data_hex"},
        {{{"op", "delete_value"}, {"key", "Software\\A"}, {"name", "n"}, {"value", "x"}}, "invalid_data", "delete_value with a value"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_LINK"}, {"value", "x"}}, "invalid_type", "REG_LINK"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "reg_sz"}, {"value", "x"}}, "invalid_type", "case-sensitive type"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_DWORD"}, {"value", "4294967296"}}, "value_overflow", "overflow"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_DWORD"}, {"value", "x"}}, "invalid_data", "not a number"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_BINARY"}, {"value", "abc"}}, "invalid_data", "odd hex"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_SZ"}, {"value", "x"}, {"data_hex", "7800"}}, "invalid_data", "value and data_hex"},
        {{{"op", "set_value"}, {"key", "Software\\A"}, {"name", "n"}, {"type", "REG_SZ"}, {"data_hex", ""}}, "invalid_data", "an empty REG_SZ shape"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        // the bad item sits between two good ones: the good ones are untouched and the plan is accepted
        const auto p = parse(json::array({item("create_key", "Software\\First"), c.item, item("create_key", "Software\\Last")}));
        REQUIRE(p.error.empty());
        REQUIRE(p.items.size() == 3);
        CHECK(p.items[0].invalid.empty());
        CHECK(p.items[1].invalid == c.token);
        CHECK(p.items[2].invalid.empty());
    }
    SECTION("a trailing NUL in a name is a control byte at the plan level; the predicate is pinned below") {
        const auto p = parse_plan("[{\"op\":\"delete_value\",\"key\":\"Software\\\\A\",\"name\":\"a\\u0000\"}]");
        REQUIRE(p.error.empty());
        CHECK(p.items[0].invalid == "invalid_value_name");
    }
}

// ── the exact-name predicate ─────────────────────────────────────────────

TEST_CASE("registry representable: a name survives a row cell byte for byte or it is refused", "[registry][plan]") {
    SECTION("the cases the manifest depends on") {
        CHECK(representable(""));                       // the key's default value; a row spells it "-"
        CHECK(representable("plain"));
        CHECK(representable("with space"));
        CHECK(representable("tab\there"));              // sanitize_field keeps TAB
        CHECK(representable("caf\xC3\xA9"));            // BMP, non-ASCII
        CHECK(representable("\xF0\x9F\x98\x80"));       // astral
        CHECK(representable("a\\b"));                   // an interior backslash
        CHECK(representable("--"));
        CHECK(representable(std::string(kMaxValueNameBytes, 'x')));
        CHECK_FALSE(representable("-"));                // the row spelling of the empty name
        CHECK_FALSE(representable("a|b"));
        CHECK_FALSE(representable("|"));
        CHECK_FALSE(representable("trailing\\"));       // the server's splitter reads `\|` as an escaped pipe
        CHECK_FALSE(representable("\\"));
        CHECK_FALSE(representable(std::string("a\0b", 3)));
        CHECK_FALSE(representable(std::string("ab\0", 3))); // a trailing NUL
        CHECK_FALSE(representable("a\nb"));
        CHECK_FALSE(representable("a\rb"));
        CHECK_FALSE(representable("a\x1B[0m"));
        CHECK_FALSE(representable("a\x7F" "b"));
        CHECK_FALSE(representable("a\xC2\x85z"));       // NEL
        CHECK_FALSE(representable("a\xE2\x80\xA8z"));   // U+2028
        CHECK_FALSE(representable("a\xE2\x80\xA9z"));   // U+2029
        CHECK_FALSE(representable("\xFF"));             // invalid UTF-8
        CHECK_FALSE(representable("\x80"));
        CHECK_FALSE(representable("\xC0\xAF"));         // overlong
        CHECK_FALSE(representable("\xED\xA0\x80"));     // a UTF-16 surrogate
        CHECK_FALSE(representable("\xF4\x90\x80\x80")); // above U+10FFFF
        CHECK_FALSE(representable("\xE2\x80"));         // truncated
    }
    SECTION("every C1 control and the two separators, one by one; their neighbours pass") {
        for (std::uint32_t cp = 0x80; cp <= 0x9F; ++cp) {
            const std::string s = std::string{"a"} + static_cast<char>(0xC0 | (cp >> 6)) + static_cast<char>(0x80 | (cp & 0x3F)) + "z";
            INFO("U+" << std::hex << cp);
            CHECK_FALSE(representable(s));
        }
        CHECK(representable("a\xC2\xA0z")); // U+00A0 is just past C1
        CHECK(representable("a\xE2\x80\xA7z")); // U+2027
        CHECK(representable("a\xE2\x80\xAAz")); // U+202A
        CHECK(representable("a\xEF\xBB\xBFz")); // U+FEFF
        CHECK(representable("a\xEF\xBF\xBDz")); // U+FFFD
    }
    SECTION("every ASCII byte between two letters, against the oracle") {
        for (int c = 0; c < 256; ++c) {
            const std::string s = std::string{"a"} + static_cast<char>(c) + "b";
            INFO("byte " << c);
            CHECK(representable(s) == oracle_spellable(s));
        }
        // and exactly these ASCII bytes are the ones that may not appear
        for (int c = 1; c < 0x80; ++c) {
            const std::string s = std::string{"a"} + static_cast<char>(c) + "b";
            const bool refused = (c < 0x20 && c != 9) || c == 0x7F || c == '|';
            CHECK(representable(s) == !refused);
        }
    }
    SECTION("all one- and two-byte strings agree with the oracle, and a representable name is a row cell as it stands") {
        std::size_t spellable = 0;
        for (int a = 0; a < 256; ++a) {
            const std::string one(1, static_cast<char>(a));
            CHECK(representable(one) == oracle_spellable(one));
            for (int b = 0; b < 256; ++b) {
                const std::string two{static_cast<char>(a), static_cast<char>(b)};
                const bool ok = representable(two);
                if (ok != oracle_spellable(two)) FAIL("representable and the oracle disagree on bytes " << a << " " << b);
                if (ok) {
                    ++spellable;
                    REQUIRE(row_field(two) == two); // the definition: the cell is the name
                    REQUIRE(two.find('|') == std::string::npos);
                }
            }
        }
        CHECK(spellable > 10000);
    }
}

TEST_CASE("registry row_field: the display fold is lossy by design and empty is \"-\"", "[registry][plan]") {
    CHECK(row_field("") == "-");
    CHECK(row_field("plain") == "plain");
    CHECK(row_field("a|b") == "a_b");
    CHECK(row_field("a\nb") == "a_b");
    CHECK(row_field("a\r\nb") == "a__b");
    CHECK(row_field("tab\there") == "tab\there");
    CHECK(row_field(std::string("ab\0\0", 4)) == "ab??"); // scrubbed to '?' before the fold: never the original
    CHECK(row_field("a\xFF" "b") == "a?b");
    CHECK(row_field("a\xE2\x80\xA8z") == "a_z");
    CHECK(row_field("a\xC2\x85z") == "a_z");
    // a trailing backslash would escape the next separator for the server's splitter (find_unescaped_pipe)
    CHECK(row_field("C:\\Windows\\Installer\\") == "C:\\Windows\\Installer_");
    CHECK(row_field("\\") == "_");
    CHECK(row_field("a\\b") == "a\\b");
}

// ── dependent items ──────────────────────────────────────────────────────

TEST_CASE("registry parse_plan: items whose verdicts would depend on each other are refused as a whole",
          "[registry][plan]") {
    const auto err = [](const json& plan) { return parse(plan).error; };
    SECTION("two value ops on one key and name, whatever the ops") {
        CHECK(err(json::array({set_item("Software\\A", "v", "1"), set_item("Software\\A", "v", "2")})) == "dependent_items:0:1");
        CHECK(err(json::array({set_item("Software\\A", "v", "1"), item("delete_value", "Software\\A", "v")})) == "dependent_items:0:1");
        CHECK(err(json::array({item("delete_value", "Software\\A", "v"), item("delete_value", "Software\\A", "v")})) == "dependent_items:0:1");
        CHECK(err(json::array({item("create_key", "Software\\Z"), set_item("Software\\A", "v", "1"), set_item("Software\\A", "v", "2")})) == "dependent_items:1:2");
    }
    SECTION("ASCII case does not make two keys or two names different") {
        CHECK(err(json::array({set_item("Software\\Acme", "Ver", "1"), set_item("SOFTWARE\\ACME", "VER", "2")})) == "dependent_items:0:1");
    }
    SECTION("two value ops on one key with different names, or on different keys, are independent") {
        CHECK(err(json::array({set_item("Software\\A", "v", "1"), set_item("Software\\A", "w", "2"), set_item("Software\\B", "v", "3")})).empty());
        CHECK(err(json::array({set_item("Software\\A", "", "1"), set_item("Software\\A", "v", "2")})).empty()); // default vs named
    }
    SECTION("two value names on one key are dependent whenever either holds a non-ASCII byte") {
        // mutant: the ASCII fold alone (Windows folds the case of \xC3\x84rger and \xC3\xA4rger into one value name)
        CHECK(err(json::array({item("delete_value", "Software\\A", "\xC3\x84rger"), set_item("Software\\A", "\xC3\xA4rger", "1")})) == "dependent_items:0:1");
        CHECK(err(json::array({set_item("Software\\A", "plain", "1"), set_item("Software\\A", "caf\xC3\xA9", "2")})) == "dependent_items:0:1");
        CHECK(err(json::array({set_item("Software\\A", "caf\xC3\xA9", "1"), set_item("Software\\A", "plain", "2")})) == "dependent_items:0:1"); // non-ASCII first
        CHECK(err(json::array({set_item("Software\\A", "caf\xC3\xA9", "1"), set_item("Software\\B", "caf\xC3\xA9", "2")})).empty()); // other key
        CHECK(err(json::array({set_item("Software\\A", "alpha", "1"), set_item("Software\\A", "beta", "2")})).empty()); // pure ASCII
    }
    SECTION("keys that differ only in the case of a non-ASCII character are dependent, whatever the ops") {
        // mutant: the ASCII fold alone. The kernel folds \xC3\x84 and \xC3\xA4 into one key; apply's handle map does not,
        // so the real run refuses the second spelling (key_is_link) where the dry run said would_apply.
        CHECK(err(json::array({set_item("Software\\\xC3\x84", "v", "1"), set_item("Software\\\xC3\xA4", "v", "2")})) == "dependent_items:0:1");
        CHECK(err(json::array({set_item("Software\\\xC3\x84", "v", "1"), set_item("Software\\\xC3\xA4", "w", "2")})) == "dependent_items:0:1"); // names differ
        CHECK(err(json::array({item("create_key", "Software\\\xC3\x84"), set_item("Software\\\xC3\xA4\\B", "v", "1")})) == "dependent_items:0:1"); // descendant
        CHECK(err(json::array({set_item("Software\\\xC3\xA4\\B", "v", "1"), item("delete_key", "Software\\\xC3\x84")})) == "dependent_items:0:1"); // ancestor
    }
    SECTION("non-ASCII keys the skeleton cannot relate stay independent, and one spelling twice is not a new clash") {
        CHECK(err(json::array({set_item("Software\\\xC3\x84", "v", "1"), set_item("Software\\B", "v", "2")})).empty()); // other component
        CHECK(err(json::array({set_item("Software\\\xC3\x84", "v", "1"), set_item("Other\\\xC3\xA4", "v", "2")})).empty()); // other parent
        CHECK(err(json::array({set_item("Software\\\xC3\x84", "v", "1"), set_item("Software\\\xC3\x84", "w", "2")})).empty()); // same spelling, ASCII names
    }
    SECTION("a key op over an equal, ancestor or descendant key of ANY other item") {
        CHECK(err(json::array({item("delete_key", "Software\\A"), set_item("Software\\A", "v", "1")})) == "dependent_items:0:1");
        CHECK(err(json::array({item("delete_key", "Software\\A"), set_item("Software\\A\\B", "v", "1")})) == "dependent_items:0:1"); // descendant
        CHECK(err(json::array({set_item("Software\\A\\B", "v", "1"), item("delete_key", "Software\\A")})) == "dependent_items:0:1"); // ancestor
        CHECK(err(json::array({item("create_key", "Software\\A"), item("create_key", "Software\\A")})) == "dependent_items:0:1");
        CHECK(err(json::array({item("create_key", "Software\\A"), item("delete_key", "Software\\A\\B\\C")})) == "dependent_items:0:1");
        CHECK(err(json::array({item("delete_key", "software\\a"), item("create_key", "Software\\A\\b")})) == "dependent_items:0:1");
    }
    SECTION("siblings and a shared prefix that is not a path ancestor are independent") {
        CHECK(err(json::array({item("delete_key", "Software\\A"), item("delete_key", "Software\\B"), item("create_key", "Software\\AB")})).empty());
        CHECK(err(json::array({item("delete_key", "Software\\A"), set_item("Software\\AB", "v", "1")})).empty()); // `A` is not `AB`'s parent
    }
    SECTION("an item that is already refused cannot change anything, so it clashes with nothing") {
        json bad = item("delete_key", "Software\\A");
        bad["hive"] = "HKCU";
        const auto p = parse(json::array({bad, set_item("Software\\A", "v", "1")}));
        CHECK(p.error.empty());
        CHECK(p.items[0].invalid == "invalid_hive");
    }
}

// ── the row renderers ────────────────────────────────────────────────────

TEST_CASE("registry render_item_row: 14 cells byte for byte", "[registry][plan]") {
    ItemRow r;
    r.index = 3;
    r.op = "set_value";
    r.hive = "HKLM";
    r.key = "Software\\Acme";
    r.name = "Ver";
    r.verdict = "applied";
    r.verify = "ok";
    r.created = 0;
    r.value_op = true;
    r.old.state = OldState::present;
    r.old.type = yuzu::profiles::kRegDword;
    r.old.bytes = {1, 0, 0, 0};
    r.old.total = 4;
    r.new_len = 4;
    CHECK(render_item_row(r) == "item|3|set_value|HKLM|Software\\Acme|Ver|applied|-|ok|0|present|REG_DWORD|01000000|4");

    SECTION("an absent previous value") {
        r.old = OldValue{};
        r.verdict = "would_apply";
        r.verify.clear();
        r.created = 2;
        CHECK(render_item_row(r) == "item|3|set_value|HKLM|Software\\Acme|Ver|would_apply|-|-|2|absent|-|-|4");
    }
    SECTION("an unreadable previous value carries its state and the refusal") {
        r.old = OldValue{};
        r.old.state = OldState::unreadable;
        r.old.error = "access_denied";
        r.verdict = "refused";
        r.reason = "access_denied";
        r.verify.clear();
        CHECK(render_item_row(r) == "item|3|set_value|HKLM|Software\\Acme|Ver|refused|access_denied|-|0|unreadable|-|-|4");
    }
    SECTION("a previous value cut by the capture cap or the budget keeps its size marker") {
        r.old.bytes = {1, 2};
        r.old.total = 9000;
        CHECK(render_item_row(r) == "item|3|set_value|HKLM|Software\\Acme|Ver|applied|-|ok|0|present|REG_DWORD|0102~9000|4");
        r.old.bytes.clear(); // the budget dropped the bytes
        CHECK(render_item_row(r) == "item|3|set_value|HKLM|Software\\Acme|Ver|applied|-|ok|0|present|REG_DWORD|~9000|4");
    }
    SECTION("a key op has no old or new columns; the default value name is \"-\"") {
        ItemRow k;
        k.index = 0;
        k.op = "create_key";
        k.hive = "HKLM";
        k.key = "Software\\New";
        k.verdict = "applied";
        k.created = 1;
        CHECK(render_item_row(k) == "item|0|create_key|HKLM|Software\\New|-|applied|-|-|1|-|-|-|-");
        k.index = 12;
        k.op = "delete_value";
        k.value_op = true;
        k.verdict = "skipped";
        CHECK(render_item_row(k) == "item|12|delete_value|HKLM|Software\\New|-|skipped|-|-|1|absent|-|-|-");
    }
    SECTION("registry-controlled text is folded in the display columns (a manifest name never reaches this: representable)") {
        ItemRow x = r;
        x.key = "Soft|ware\nX";
        x.name = "a\r\nb";
        x.reason = "bad|reason";
        const auto line = render_item_row(x);
        CHECK(line.find('\n') == std::string::npos);
        CHECK(line.find('\r') == std::string::npos);
        CHECK(line.starts_with("item|3|set_value|HKLM|Soft_ware_X|a__b|applied|bad_reason|ok|0|"));
        CHECK(std::count(line.begin(), line.end(), '|') == 13); // the 14 cells still split cleanly
    }
}

TEST_CASE("registry render_undo_row and render_summary_row: byte for byte", "[registry][plan]") {
    OldValue v;
    v.state = OldState::present;
    v.type = yuzu::profiles::kRegSz;
    v.bytes = {0x61, 0, 0, 0};
    v.total = 4;
    CHECK(render_undo_row(4, "name", v) == "undo|4|name|REG_SZ|61000000|0");
    CHECK(render_undo_row(4, "", v) == "undo|4|-|REG_SZ|61000000|0"); // the default value
    v.bytes = {0x61, 0};
    v.total = 5000;
    CHECK(render_undo_row(10, "big", v) == "undo|10|big|REG_SZ|6100~5000|1"); // cut: truncated=1
    v.type = yuzu::profiles::kRegBinary;
    v.bytes.clear();
    v.total = 0;
    CHECK(render_undo_row(0, "empty", v) == "undo|0|empty|REG_BINARY||0"); // a zero-byte value is an empty hex cell, not "-"

    ApplySummary s;
    s.total = 8;
    s.applied = 5;
    s.refused = 2;
    s.failed = 1;
    s.skipped = 0;
    s.dry_run = true;
    s.undo_complete = false;
    CHECK(render_summary_row(s) == "summary|8|5|2|1|0|1|0");
    s.dry_run = false;
    s.undo_complete = true;
    CHECK(render_summary_row(s) == "summary|8|5|2|1|0|0|1");
}
