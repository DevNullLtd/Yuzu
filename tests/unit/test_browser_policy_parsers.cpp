/**
 * test_browser_policy_parsers.cpp — pure row-model tests plus the Linux
 * injected-root policy walk for the browser_policy plugin
 * (browser_policy_parsers.hpp, browser_policy_linux_parsers.hpp).
 *
 * UNGUARDED (every OS): the wire-row formatter, the JSON -> type-enum
 * mapper (including the literal `unmodelled` outcome) and the JSON failure
 * tokens. Nothing here touches disk.
 *
 * `#if !defined(_WIN32)` (a scoped exception to "never platform-guard a
 * test TU": the walk shell uses posix_dir_walk.hpp/openat, which do not exist
 * on Windows): the tree-manifest cases. They materialize
 * tests/unit/fixtures/wave10/browser_policy/linux/tree.manifest into a
 * `yuzu_test_browser_policy_` temp root and run lnx::linux_policy_rows_at
 * over it. The materializer is COPIED from test_peripherals_linux_parsers.cpp
 * (never included) and extended with one scheme, defined and unit-tested
 * below: line = `<relpath>\t<payload>`, payload `T:<text; \n \t \\>` |
 * `B:<base64>` | `L:<symlink target>`; `#` lines and blanks are comments.
 *
 * Fixture labels: chrome_managed.json / chrome_recommended.json are
 * SYNTHETIC (Alex sign-off 2026-09-21), edge_managed.json is a
 * RECONSTRUCTION; see the directory's provenance.txt. Inline JSON below is
 * likewise hand-written test input (RECONSTRUCTION, not a capture).
 *
 * Mutation notes (each assertion fails if the named wiring is removed):
 *   - exact chrome/edge/recommended rows: drop a vendor or level from
 *     kVendorDirs/kLevelDirs, or the walk itself;
 *   - "kept alongside a failure": swallow parse failures instead of
 *     accumulating them;
 *   - symlink refusals: drop O_NOFOLLOW from open_dir_at / read_file_at;
 *   - command status (run_linux_at through a real CommandContext via
 *     LocalDispatcher): pass "" instead of failure_reason to mark_result_read,
 *     or make it always report OK/FULL -> the CONSTRAINED/PARTIAL + exact-token
 *     assertions fail;
 *   - saturation (WalkLimits shrinks the caps so the boundary is cheap and
 *     machine-independent): drop the `walk.truncated` reporting branch or a
 *     row-cap guard -> the `linux:row_cap` / `linux:entry_cap` cases fail; the exactly-at-cap
 *     controls fail if a cap is tightened to `>` off-by-one;
 *   - NUL: drop the NUL replacement in format_policy_row -> the row is
 *     truncated at the C-string boundary and the `nul_replaced` tail is lost;
 *   - read-to-EOF (Linux only, /proc reports st_size 0): read exactly st_size
 *     -> the /proc read returns empty;
 *   - in-band outcome row: drop the write from mark_result_read, write it on an OK read, or
 *     write it AFTER the rows -> the pairing / first-line check inside run_leg fails on every
 *     constrained (or OK) run that reaches it;
 *   - depth and container guards (max_nesting_depth / scan_json_shape): end the line comment
 *     at LF only, keep the LAST opener instead of the deepest, drop the backslash skip inside a
 *     string, or shift a comparison -> the comment, escape, sibling-order and exact-boundary
 *     cases fail; an undercount against nlohmann's own SAX depth fails the differential case;
 *   - field cap: drop the kMaxFieldBytes cut (or cut after escaping) -> the oversized-field
 *     cases fail;
 *   - UTF-8 (protobuf transport): drop repair_utf8 from wire_field -> the invalid-byte
 *     cases keep the raw bytes and the CommandResponse round trip fails (Linux also has the
 *     real raw-byte-file-name case; no other OS can create such a name);
 *   - aggregate read budget: drop the max_total_bytes check in linux_policy_rows_at ->
 *     the one-under case reads every file and reports OK;
 *   - non-regular objects (root-safe, no chmod): delete the S_ISREG check in
 *     read_file_at -> the FIFO reads as EOF (json_unparseable) and the directory
 *     read fails with EISDIR (read_failed), so the exact not_regular pin fails;
 *   - ENOTDIR (root-safe): delete the ENOTDIR arm of posix::errno_detail ->
 *     the token degrades to open_failed and the exact not_a_directory pin fails.
 */
#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h" // CommandResponse: the transport that rejects invalid UTF-8
#include "browser_policy_parsers.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <type_traits>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include "browser_policy_linux_parsers.hpp"
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (real CommandContext)
#include "test_helpers.hpp"     // yuzu::test::TempDir

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <sstream>
#endif

using namespace yuzu::browser_policy;

namespace {

/// Escape-aware split matching the server decoder (result_parsing.hpp
/// find_unescaped_pipe): a backslash immediately before a pipe is an escaped
/// pipe, not a separator.
std::vector<std::string> split_fields(const std::string& row) {
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

const PolicyRow* find_row(const std::vector<PolicyRow>& rows, std::string_view name) {
    for (const auto& r : rows)
        if (r.name == name)
            return &r;
    return nullptr;
}

JsonPolicyParse parse_inline(std::string_view text) {
    return rows_from_json_policy_text(text, Browser::chrome, Level::mandatory, "machine",
                                      "/etc/opt/chrome/policies/managed/t.json");
}

} // namespace

// ── unguarded: the pure row model ─────────────────────────────────────────

TEST_CASE("browser_policy: a row is nine fields and hostile values cannot shift the count",
          "[browser_policy][parsers]") {
    PolicyRow r;
    r.browser = Browser::edge;
    r.level = Level::recommended;
    r.scope = user_scope("a|b");
    r.name = "Pipe|Name";
    r.value = {PolicyType::String, "C:\\Program Files\\", {}}; // trailing backslash
    r.source = "/etc/opt/edge/policies/recommended/x|y.json";

    const auto fields = split_fields(format_policy_row(r));
    REQUIRE(fields.size() == 9);
    CHECK(fields[0] == "policy");
    CHECK(fields[1] == "edge");
    CHECK(fields[2] == "recommended");
    CHECK(fields[3] == "user:a|b");
    CHECK(fields[4] == "Pipe|Name");
    CHECK(fields[5] == "string");
    CHECK(fields[6] == "C:/Program Files/"); // backslash folded by safe_output_field
    CHECK(fields[7] == "/etc/opt/edge/policies/recommended/x|y.json");
    CHECK(fields[8] == "-"); // empty detail -> "-"
}

TEST_CASE("browser_policy: every JSON type lands on the type enum", "[browser_policy][parsers]") {
    const auto p = parse_inline(R"({"b":true,"i":-3,"u":18446744073709551615,"r":1.5,)"
                                R"("s":"x","l":[1,"a"],"d":{"k":[]},"n":null})");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 8);
    // Rows come out sorted by policy name.
    const std::vector<std::string> names = {"b", "d", "i", "l", "n", "r", "s", "u"};
    for (std::size_t i = 0; i < names.size(); ++i)
        CHECK(p.rows[i].name == names[i]);

    auto check = [&](std::string_view name, PolicyType t, std::string_view value) {
        const auto* row = find_row(p.rows, name);
        REQUIRE(row != nullptr);
        CHECK(row->value.type == t);
        CHECK(row->value.value == value);
    };
    check("b", PolicyType::Bool, "true");
    check("i", PolicyType::Int, "-3");
    check("u", PolicyType::Int, "18446744073709551615");
    check("r", PolicyType::Real, "1.5");
    check("s", PolicyType::String, "x");
    check("l", PolicyType::List, R"([1,"a"])");
    check("d", PolicyType::Dict, R"({"k":[]})");
    check("n", PolicyType::Null, "null");
    // Neither list/dict value above contains a backslash, so neither is folded --
    // detail stays empty. Pinned explicitly since the sibling test below covers
    // the opposite (escaped) case and the two must not be confused.
    CHECK(find_row(p.rows, "l")->value.detail.empty());
    CHECK(find_row(p.rows, "d")->value.detail.empty());
}

TEST_CASE("browser_policy: a list/dict value the wire escaper would fold is flagged json_escaped, "
          "never silently presented as valid JSON",
          "[browser_policy][parsers]") {
    // safe_output_field folds every literal backslash to '/', so a JSON dump
    // containing one (a nested string held a `"`, `\` or control character) is
    // lossy and not trustworthy as the original JSON once written to the wire
    // -- an escaped quote can even make it syntactically invalid, though not
    // every fold does. json_to_policy_value must flag this in `detail` while
    // still keeping the (folded) value -- never blank it to unmodelled, which
    // would throw away otherwise-useful content.
    {
        const auto v = json_to_policy_value(nlohmann::json::parse(R"(["a\"b"])"));
        CHECK(v.type == PolicyType::List);
        // Hoisted out of the CHECK() argument position: MSVC's traditional preprocessor
        // mistokenizes a raw string containing an embedded `\"` when it appears as a
        // macro argument (#4998 review round 2) -- a plain statement isn't a macro
        // argument, so the same literal here compiles everywhere.
        const std::string kEscapedQuoteInList = R"(["a\"b"])";
        CHECK(v.value == kEscapedQuoteInList); // dump_json's own escaping, unfolded at this layer
        CHECK(v.detail == "json_escaped");
    }
    {
        const auto v = json_to_policy_value(nlohmann::json::parse(R"({"k":"line1\nline2"})"));
        CHECK(v.type == PolicyType::Dict);
        CHECK(v.detail == "json_escaped");
    }
    // A value with no backslash anywhere in its dump is never flagged, even
    // when it holds other JSON punctuation (quotes around ordinary strings).
    {
        const auto v = json_to_policy_value(nlohmann::json::parse(R"(["plain","value"])"));
        CHECK(v.type == PolicyType::List);
        CHECK(v.detail.empty());
    }
    // End-to-end through the wire escaper: the folded value on the actual row
    // is lossy and not trustworthy as the original JSON (this particular fold
    // breaks an escaped quote, so it's also syntactically invalid), but the
    // row still carries it, with the flag.
    {
        PolicyRow r;
        r.name = "Escaped";
        r.scope = "machine";
        r.source = "/x";
        r.value = json_to_policy_value(nlohmann::json::parse(R"(["a\"b"])"));
        const std::string wire = format_policy_row(r);
        // Defensively hoisted too: no `\"` in this literal so it doesn't independently
        // trip the MSVC bug above, but it's the same fragile embedded-quote-in-a-raw-
        // string-macro-argument shape, and hoisting costs nothing (#4998 review round 2).
        const std::string kExpectedEscapedListWire =
            R"(policy|chrome|mandatory|machine|Escaped|list|["a/"b"]|/x|json_escaped)";
        CHECK(wire == kExpectedEscapedListWire);
    }
}

TEST_CASE("browser_policy: a value the mapper does not model is the literal unmodelled outcome",
          "[browser_policy][parsers]") {
    // A JSON `binary` cannot come out of a text parse, but the mapper is
    // total: it must land on Unmodelled, never on some other type or a throw.
    const auto v = json_to_policy_value(nlohmann::json::binary({0x01, 0x02}));
    CHECK(v.type == PolicyType::Unmodelled);
    CHECK(type_token(v.type) == "unmodelled");
    CHECK(v.value == "-");
    CHECK(v.detail == "json_type");

    PolicyRow r;
    r.name = "Odd";
    r.scope = "machine";
    r.source = "/x";
    r.value = unmodelled_value("date");
    CHECK(format_policy_row(r) == "policy|chrome|mandatory|machine|Odd|unmodelled|-|/x|date");
}

TEST_CASE("browser_policy: malformed policy JSON is a failure token, never empty success",
          "[browser_policy][parsers]") {
    for (const std::string_view bad : {std::string_view{R"({"HomepageLocation": )"},
                                       std::string_view{""}, std::string_view{"not json"},
                                       std::string_view{"{\"a\":\"\xff\"}"}}) {
        const auto p = parse_inline(bad);
        REQUIRE(p.failure.has_value());
        CHECK(*p.failure == "linux:json_unparseable");
        CHECK(p.rows.empty());
    }
    for (const std::string_view not_object :
         {std::string_view{"[1,2]"}, std::string_view{"\"str\""}, std::string_view{"7"}}) {
        const auto p = parse_inline(not_object);
        REQUIRE(p.failure.has_value());
        CHECK(*p.failure == "linux:json_not_object");
    }
    // A container nested past kMaxNestingDepth is a constraint (bounds dump()).
    std::string deep = R"({"k":)";
    deep.append(static_cast<std::size_t>(kMaxNestingDepth) + 8, '[');
    deep.append(static_cast<std::size_t>(kMaxNestingDepth) + 8, ']');
    deep += "}";
    const auto p = parse_inline(deep);
    REQUIRE(p.failure.has_value());
    CHECK(*p.failure == "linux:json_too_deep");
    CHECK(p.rows.empty());
}

TEST_CASE("browser_policy: comments and a UTF-8 BOM in a policy file are tolerated",
          "[browser_policy][parsers]") {
    const auto p = parse_inline("\xEF\xBB\xBF// header\n/* block */ {\"ShowHomeButton\": true}\n");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].name == "ShowHomeButton");
    CHECK(p.rows[0].value.type == PolicyType::Bool);
}

TEST_CASE("browser_policy: an embedded NUL cannot truncate a wire row",
          "[browser_policy][parsers]") {
    // Valid JSON: \u0000 survives parsing in both a value and a key.
    const auto p = parse_inline(R"({"K":"a\u0000b","N\u0000x":true})");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 2);
    CHECK(p.rows[0].value.value == std::string("a\0b", 3)); // the parser keeps it...

    // ...the wire form must not: CommandContext::write_output takes a C string.
    const auto v = format_policy_row(p.rows[0]);
    CHECK(v.find('\0') == std::string::npos);
    CHECK(v == "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
               "b|/etc/opt/chrome/policies/managed/t.json|nul_replaced");
    CHECK(split_fields(v).size() == 9);

    const auto k = format_policy_row(p.rows[1]);
    CHECK(k.find('\0') == std::string::npos);
    CHECK(k == "policy|chrome|mandatory|machine|N\xEF\xBF\xBD"
               "x|bool|true|/etc/opt/chrome/policies/managed/t.json|nul_replaced");

    // A pre-existing detail keeps its qualifier and gains the NUL flag.
    PolicyRow r;
    r.name = std::string("n\0", 2);
    r.scope = "machine";
    r.source = "/x";
    r.value = unmodelled_value("date");
    CHECK(format_policy_row(r) ==
          "policy|chrome|mandatory|machine|n\xEF\xBF\xBD|unmodelled|-|/x|date,nul_replaced");
}

namespace {

/// The real acceptance test for a row: the command output travels in a proto3 `string` field and
/// the receiver rejects the WHOLE response when it holds invalid UTF-8.
bool survives_transport(const std::string& text) {
    yuzu::agent::v1::CommandResponse out;
    out.set_output(text);
    std::string wire;
    if (!out.SerializeToString(&wire))
        return false;
    yuzu::agent::v1::CommandResponse in;
    return in.ParseFromString(wire) && in.output() == text;
}

std::string fffd(int n) {
    std::string s;
    for (int i = 0; i < n; ++i)
        s += "\xEF\xBF\xBD";
    return s;
}

} // namespace

TEST_CASE("browser_policy: bytes that are not valid UTF-8 are repaired so the row survives the "
          "transport",
          "[browser_policy][parsers]") {
    // A Linux file name is arbitrary bytes and lands in `source`; every case below is rejected
    // by the protobuf `string` field raw. The last four are the forms a lone-byte repair (the
    // sdk's sanitize_utf8) lets through: overlong, surrogate, above U+10FFFF, bad lead byte.
    // Each offending byte becomes one U+FFFD. MUTATION: drop repair_utf8 from wire_field ->
    // the raw bytes reach the row and the round trip (and the exact row) fail.
    struct Case {
        const char* label;
        std::string bytes;
        std::string repaired;
    };
    const std::vector<Case> cases = {
        {"lone 0xFF", "x\xFFz", "x" + fffd(1) + "z"},
        {"stray continuation byte", "x\x80z", "x" + fffd(1) + "z"},
        {"truncated 3-byte sequence at the end", "x\xE2\x82", "x" + fffd(2)},
        {"overlong 2-byte C0 80", "x\xC0\x80z", "x" + fffd(2) + "z"},
        {"overlong 3-byte E0 80 80", "x\xE0\x80\x80z", "x" + fffd(3) + "z"},
        {"overlong 4-byte F0 80 80 80", "x\xF0\x80\x80\x80z", "x" + fffd(4) + "z"},
        {"surrogate ED A0 80", "x\xED\xA0\x80z", "x" + fffd(3) + "z"},
        {"above U+10FFFF, F4 90 80 80", "x\xF4\x90\x80\x80z", "x" + fffd(4) + "z"},
        {"bad lead byte F5", "x\xF5\x80\x80\x80z", "x" + fffd(4) + "z"},
    };
    for (const auto& c : cases) {
        INFO(c.label);
        PolicyRow r;
        r.name = "N";
        r.scope = "machine";
        r.value = PolicyValue{PolicyType::String, "v", {}};
        r.source = "/etc/opt/chrome/policies/managed/" + c.bytes + ".json";
        const auto row = format_policy_row(r);
        CHECK(row == "policy|chrome|mandatory|machine|N|string|v|"
                     "/etc/opt/chrome/policies/managed/" +
                         c.repaired + ".json|utf8_replaced");
        CHECK(survives_transport(row));
        CHECK(split_fields(row).size() == 9);
    }

    // Well-formed sequences at every boundary pass through untouched and are not flagged.
    for (const char* ok : {"\xC2\x80", "\xDF\xBF", "\xE0\xA0\x80", "\xED\x9F\xBF", "\xEE\x80\x80",
                           "\xEF\xBF\xBD", "\xF0\x90\x80\x80", "\xF4\x8F\xBF\xBF", "\xE2\x82\xAC"}) {
        PolicyRow r;
        r.name = "N";
        r.scope = "machine";
        r.value = PolicyValue{PolicyType::String, std::string{"v"} + ok, {}};
        r.source = "/x";
        const auto row = format_policy_row(r);
        CHECK(row == std::string{"policy|chrome|mandatory|machine|N|string|v"} + ok + "|/x|-");
        CHECK(survives_transport(row));
    }

    // Every free-text field is repaired, and both flags are reported (NUL first, then UTF-8).
    PolicyRow r;
    r.name = std::string("n\0\xFF", 3);
    r.scope = "machine";
    r.value = PolicyValue{PolicyType::String, "v\xFF", {}};
    r.source = "/x";
    const auto row = format_policy_row(r);
    CHECK(row == "policy|chrome|mandatory|machine|n" + fffd(2) + "|string|v" + fffd(1) +
                     "|/x|nul_replaced,utf8_replaced");
    CHECK(survives_transport(row));
}

namespace {

// An INDEPENDENT reference for the sweep below: decode by bit arithmetic (a different algorithm
// from repair_utf8's Table 3-7 ranges). The length of the well-formed sequence at s[i], or 0.
std::size_t reference_sequence_length(const std::string& s, std::size_t i) {
    const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned c = b(i);
    if (c < 0x80)
        return 1;
    std::size_t n = 0;
    std::uint32_t cp = 0;
    std::uint32_t min = 0;
    if ((c & 0xE0) == 0xC0) {
        n = 2;
        cp = c & 0x1F;
        min = 0x80;
    } else if ((c & 0xF0) == 0xE0) {
        n = 3;
        cp = c & 0x0F;
        min = 0x800;
    } else if ((c & 0xF8) == 0xF0) {
        n = 4;
        cp = c & 0x07;
        min = 0x10000;
    } else {
        return 0;
    }
    if (i + n > s.size())
        return 0;
    for (std::size_t k = 1; k < n; ++k) {
        if ((b(i + k) & 0xC0) != 0x80)
            return 0;
        cp = (cp << 6) | (b(i + k) & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

std::string reference_repair(const std::string& s, bool& replaced) {
    std::string out;
    for (std::size_t i = 0; i < s.size();) {
        const auto n = reference_sequence_length(s, i);
        if (n == 0) {
            out += "\xEF\xBF\xBD";
            replaced = true;
            ++i;
        } else {
            out.append(s, i, n);
            i += n;
        }
    }
    return out;
}

} // namespace

TEST_CASE("browser_policy: repair_utf8 agrees with an independent reference on every boundary "
          "sequence of one to four bytes",
          "[browser_policy][parsers]") {
    // The 21 bytes that sit on a boundary of Unicode Table 3-7 (ASCII edge, every continuation
    // and lead boundary); every 1..4-byte sequence over them is compared, ~204k inputs.
    // MUTATION: drop the E0/ED/F0/F4 second-byte range, an unchecked continuation byte, or
    // the F1-F3 branch -> some sequence disagrees with the reference.
    const std::array<unsigned char, 21> alphabet = {0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0,
                                                    0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1,
                                                    0xED, 0xEF, 0xF0, 0xF1, 0xF4, 0xF5, 0xFF};
    std::size_t valid_seen = 0;
    std::size_t mismatches = 0;
    const auto check = [&](const std::string& in) {
        bool got_replaced = false;
        bool want_replaced = false;
        const auto got = detail::repair_utf8(in, got_replaced);
        const auto want = reference_repair(in, want_replaced);
        if (got != want || got_replaced != want_replaced)
            ++mismatches;
        if (!want_replaced)
            ++valid_seen;
    };
    for (const auto a : alphabet) {
        std::string s1{static_cast<char>(a)};
        check(s1);
        for (const auto b : alphabet) {
            std::string s2 = s1 + static_cast<char>(b);
            check(s2);
            for (const auto c : alphabet) {
                std::string s3 = s2 + static_cast<char>(c);
                check(s3);
                for (const auto d : alphabet)
                    check(s3 + static_cast<char>(d));
            }
        }
    }
    CHECK(mismatches == 0);
    CHECK(valid_seen > 0); // the sweep does cover well-formed input, not only garbage
}

TEST_CASE("browser_policy: a field longer than the cap is cut on a character boundary and flagged",
          "[browser_policy][parsers]") {
    // One policy value can otherwise make a row larger than the server's per-chunk ingest cap
    // (which drops the row's source and detail fields while the agent reports a complete read).
    // The cut is on the repaired text BEFORE escaping, so it can never strand half an escape in
    // front of the field separator. MUTATION: drop the cut, or cut after escaping.
    PolicyRow r;
    r.name = "N";
    r.scope = "machine";
    r.source = "/x";
    const auto fields_of = [&r](std::string value) {
        r.value = PolicyValue{PolicyType::String, std::move(value), {}};
        return format_policy_row(r);
    };
    // Exactly the cap: untouched. One over: cut, flagged.
    const auto at_cap = fields_of(std::string(kMaxFieldBytes, 'a'));
    CHECK(split_fields(at_cap)[8] == "-");
    CHECK(split_fields(at_cap)[6].size() == kMaxFieldBytes);
    const auto over = fields_of(std::string(kMaxFieldBytes + 1, 'a'));
    CHECK(split_fields(over)[8] == "truncated");
    CHECK(split_fields(over)[6] == std::string(kMaxFieldBytes, 'a'));
    CHECK(split_fields(over).size() == 9);

    // A three-byte character that straddles the cap is dropped whole, never split.
    const auto straddle = fields_of(std::string(kMaxFieldBytes - 1, 'a') + "\xE2\x82\xAC");
    CHECK(split_fields(straddle)[6] == std::string(kMaxFieldBytes - 1, 'a'));
    CHECK(split_fields(straddle)[8] == "truncated");
    CHECK(survives_transport(straddle));

    // Pipes are escaped AFTER the cut: a value of all pipes keeps nine fields and stays far
    // under the ingest cap even at twice the cap.
    const auto pipes = fields_of(std::string(kMaxFieldBytes * 2, '|'));
    CHECK(split_fields(pipes).size() == 9);
    CHECK(split_fields(pipes)[8] == "truncated");
    CHECK(pipes.size() < 2 * kMaxFieldBytes + 1024);

    // The case that actually distinguishes "cut before escaping" from "cut after": a value
    // ending in two pipes, one byte over the cap. Cut-then-escape keeps ONE clean pipe (escaped
    // to `\|`, decodes back whole). MUTATION: escape-then-cut instead -> the field is first
    // turned into `...a\|\|` (each pipe becomes two bytes) and THEN cut to the byte cap, which
    // lands mid-escape and leaves the field ending in a lone `\` -- that backslash then escapes
    // the FOLLOWING field separator instead of a character inside the value, merging two fields
    // into one and dropping the row to 8 fields.
    const auto boundary = fields_of(std::string(kMaxFieldBytes - 1, 'a') + "||");
    const auto boundary_fields = split_fields(boundary);
    REQUIRE(boundary_fields.size() == 9);
    CHECK(boundary_fields[6] == std::string(kMaxFieldBytes - 1, 'a') + "|");
    CHECK(boundary_fields[8] == "truncated");
    CHECK(survives_transport(boundary));

    // Every free-text field is capped, and the flags combine in a fixed order.
    r.name = std::string(kMaxFieldBytes + 5, 'n') + '\xFF';
    r.value = PolicyValue{PolicyType::String, std::string("v\0", 2), {}};
    const auto combined = format_policy_row(r);
    CHECK(split_fields(combined)[8] == "nul_replaced,utf8_replaced,truncated");
    CHECK(split_fields(combined)[4].size() == kMaxFieldBytes);
    CHECK(survives_transport(combined));
}

TEST_CASE("browser_policy: a file with more than the container cap is json_too_complex, exactly at "
          "the cap is not",
          "[browser_policy][parsers]") {
    // Root object + one array + (cap - 2) empty objects = exactly kMaxJsonContainers containers.
    // A parsed container costs ~30x its bytes, so the count (not the file size) bounds the
    // document. MUTATION: shift the comparison by one, or drop the check.
    const auto text_with = [](std::size_t containers) {
        std::string t = R"({"a":[)";
        for (std::size_t i = 0; i + 2 < containers; ++i)
            t += (i ? ",{}" : "{}");
        t += "]}";
        return t;
    };
    const auto parse_text = [](const std::string& t) {
        return rows_from_json_policy_text(t, Browser::chrome, Level::mandatory, "machine", "/x");
    };
    CHECK_FALSE(parse_text(text_with(kMaxJsonContainers)).failure.has_value());
    CHECK(parse_text(text_with(kMaxJsonContainers + 1)).failure == kTokenJsonTooComplex);
    CHECK(detail::scan_json_shape(text_with(kMaxJsonContainers)).containers == kMaxJsonContainers);
    // Too deep is reported in preference to too complex.
    CHECK(parse_text(std::string(kMaxNestingDepth + 1, '[') + std::string(kMaxNestingDepth + 1, ']'))
              .failure == kTokenJsonTooDeep);
}

TEST_CASE("browser_policy: the status row is nine fields, escapes its reason, and never holds a NUL",
          "[browser_policy][parsers]") {
    const auto planned = format_status_row(kStateUnavailable, "macos:planned");
    CHECK(planned == "status|-|-|-|policies|-|unavailable|-|macos:planned");
    CHECK(split_fields(planned).size() == 9);

    const auto constrained =
        format_status_row(kStateConstrained, "linux:permission_denied,linux:json_unparseable");
    CHECK(constrained ==
          "status|-|-|-|policies|-|constrained|-|linux:permission_denied,linux:json_unparseable");
    CHECK(split_fields(constrained).size() == 9);

    // Field 7 is the source: "-" on a summary row, the logical path on a per-path row.
    const auto per_path = format_status_row(
        kStateConstrained, "linux:json_unparseable", "/etc/opt/chrome/policies/managed/a.json");
    CHECK(per_path == "status|-|-|-|policies|-|constrained|/etc/opt/chrome/policies/managed/a.json|"
                      "linux:json_unparseable");
    CHECK(split_fields(per_path).size() == 9);

    // The source goes through the same wire escaper as every free-text field: a pipe in a file
    // name cannot shift the field count, and a source past the 64 KiB cap is cut, never wider.
    const auto piped = format_status_row(kStateConstrained, "linux:oversized", "/etc/a|b.json");
    CHECK(split_fields(piped).size() == 9);
    CHECK(piped.find("a\\|b.json") != std::string::npos);
    const auto huge = format_status_row(kStateConstrained, "linux:oversized",
                                        std::string(kMaxFieldBytes * 2, '|'));
    CHECK(split_fields(huge).size() == 9);
    CHECK(huge.size() < 2 * kMaxFieldBytes + 1024);
    CHECK(survives_transport(huge));

    // The reason is a token list today, but the formatter still owns the wire grammar: a pipe,
    // a NUL or a bad byte in it can neither shift the field count nor truncate the row.
    const auto hostile = format_status_row(kStateConstrained, std::string("a|b\0\xFF", 5));
    CHECK(hostile.find('\0') == std::string::npos);
    CHECK(split_fields(hostile).size() == 9);
    CHECK(survives_transport(hostile));
}

TEST_CASE("browser_policy: max_nesting_depth counts brackets outside strings and comments exactly "
          "as the parser does",
          "[browser_policy][parsers]") {
    using detail::max_nesting_depth;
    CHECK(max_nesting_depth("") == 0);
    CHECK(max_nesting_depth("{}") == 1);
    CHECK(max_nesting_depth(R"({"a":[[1],{"b":[]}]})") == 4);
    // Hoisted out of the CHECK() argument position (not inlined as a raw string literal there):
    // MSVC's traditional preprocessor mistokenizes a raw string containing an embedded `"` when
    // it appears as a macro argument (#4998 review) -- a plain statement isn't a macro argument,
    // so the same literal here compiles everywhere.
    const std::string kNestedQuoteInString = R"({"a":"[[[[ {{{{ \" ]]]] "})";
    CHECK(max_nesting_depth(kNestedQuoteInString) == 1); // brackets inside a string
    CHECK(max_nesting_depth(R"({"a":"\\"}[[)") == 2);               // \\ then the closing quote
    CHECK(max_nesting_depth("{// [[[[\n}") == 1);                   // line comment, ended by LF
    CHECK(max_nesting_depth("/* [[[[ */{}") == 1);                  // block comment
    // nlohmann ends a line comment at CR and at NUL as well as LF (lexer.hpp scan_comment); a
    // scan that waited for LF would hide the brackets after the CR from the depth guard while
    // the parser still builds them. MUTATION: end the comment at LF only -> these read as 1.
    CHECK(max_nesting_depth("{// x\r[[[[") == 5);
    CHECK(max_nesting_depth(std::string_view{"{// x\0[[[[", 10}) == 5);
    CHECK(max_nesting_depth("{/* unterminated [[[[") == 1);        // ends the scan; the parse fails
    CHECK(max_nesting_depth("]]]]{") == 1);                        // closers never go negative
    // The DEEPEST nesting, not the last: a deep container before a shallow sibling. MUTATION:
    // keep the last opener's depth instead of the maximum -> this reads 2.
    CHECK(max_nesting_depth(R"({"a":[[[1]]],"b":[]})") == 4);
    // An escaped quote does not end the string, so the brackets after it are still inside it.
    // MUTATION: drop the backslash skip -> the string ends early and the `[[[[` counts.
    // Hoisted for the same MSVC macro-argument reason as kNestedQuoteInString above.
    const std::string kEscapedQuoteThenBrackets = R"({"a":"x\"[[[["})";
    CHECK(max_nesting_depth(kEscapedQuoteThenBrackets) == 1);
    // Parse level, same two shapes: 33 nested arrays after a shallow key, and after an escaped
    // quote, are still json_too_deep (the guard must see them wherever they sit).
    const auto parse_text = [](const std::string& text) {
        return rows_from_json_policy_text(text, Browser::chrome, Level::mandatory, "machine", "/x");
    };
    const std::string deep = std::string(kMaxNestingDepth, '[') + std::string(kMaxNestingDepth, ']');
    CHECK(parse_text(R"({"a":)" + deep + R"(,"b":[]})").failure == kTokenJsonTooDeep);
    // Hoisted out of the CHECK() argument position: MSVC's traditional preprocessor
    // mistokenizes a raw string containing an embedded `\"` when it appears as a
    // macro argument (governance sweep, #4998 round 3 -- same class as
    // kEscapedQuoteInList/kEscapedQuoteThenBrackets above, missed by round 2's
    // fix because this site nests the literal inside parse_text(...) + deep).
    const std::string kEscapedQuoteThenDeepNesting = R"({"a":"\"","b":)" + deep + "}";
    CHECK(parse_text(kEscapedQuoteThenDeepNesting).failure == kTokenJsonTooDeep);
}

namespace {

/// nlohmann's own view of the nesting: the peak depth its SAX events reach, including the events
/// delivered before a parse error stops it.
struct PeakDepthSax {
    std::size_t depth = 0;
    std::size_t peak = 0;
    bool start_object(std::size_t) { return open(); }
    bool end_object() { return close(); }
    bool start_array(std::size_t) { return open(); }
    bool end_array() { return close(); }
    bool null() { return true; }
    bool boolean(bool) { return true; }
    bool number_integer(nlohmann::json::number_integer_t) { return true; }
    bool number_unsigned(nlohmann::json::number_unsigned_t) { return true; }
    bool number_float(nlohmann::json::number_float_t, const std::string&) { return true; }
    bool string(std::string&) { return true; }
    bool binary(nlohmann::json::binary_t&) { return true; }
    bool key(std::string&) { return true; }
    bool parse_error(std::size_t, const std::string&, const nlohmann::json::exception&) {
        return false;
    }

private:
    bool open() {
        peak = std::max(peak, ++depth);
        return true;
    }
    bool close() {
        --depth;
        return true;
    }
};

} // namespace

TEST_CASE("browser_policy: the container scan never counts less nesting than nlohmann builds",
          "[browser_policy][parsers]") {
    // The depth guard hand-mirrors nlohmann's lexer (comment and string rules). An UNDERCOUNT
    // would let a deep document reach the recursive dump(), so this compares the scan with the
    // parser's own peak depth on a fixed pseudo-random corpus: bracket-heavy random bytes and
    // random token sequences that include every comment form, escapes and NUL. A vcpkg bump of
    // nlohmann that changes a lexer rule fails here. MUTATION: any of the scan's rules changed
    // so it counts less. The deterministic cases above already pin the two mutations that
    // actually produce an undercount here (LF-only comment end, no NUL end, last-opener instead
    // of deepest); this corpus is the general-input backstop for those and any other rule drift
    // (dropping the backslash skip or the comment handling entirely makes the scan OVERcount,
    // which is the safe direction and is not what this case exists to catch).
    std::uint64_t state = 0x9E3779B97F4A7C15ull;
    const auto next = [&state]() {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        return static_cast<std::uint32_t>(state >> 33);
    };
    static const char kChars[] = {'{', '}', '[', ']', '"', '\\', '/', '*', ':', ',', 'a', '1',
                                  ' ', '\n', '\r', '\0'};
    static const std::array<std::string_view, 16> kTokens = {
        "{", "}", "[", "]", "\"a\"", "\"\\\"[[\"", ":", ",", "1", "// x\n", "// x\r", "/* [ */",
        std::string_view{"\0", 1}, "\"", "/", "*"};
    std::size_t undercounts = 0;
    std::size_t accepted = 0;
    const auto compare = [&](const std::string& text) {
        PeakDepthSax sax;
        const bool ok = nlohmann::json::sax_parse(text.begin(), text.end(), &sax,
                                                  nlohmann::json::input_format_t::json,
                                                  /*strict=*/false, /*ignore_comments=*/true);
        if (detail::max_nesting_depth(text) < sax.peak)
            ++undercounts;
        if (ok)
            ++accepted;
    };
    for (int i = 0; i < 20000; ++i) {
        std::string bytes;
        const auto n = 1 + next() % 40;
        for (std::uint32_t k = 0; k < n; ++k)
            bytes += kChars[next() % sizeof(kChars)];
        compare(bytes);
        std::string tokens;
        const auto m = 1 + next() % 30;
        for (std::uint32_t k = 0; k < m; ++k)
            tokens += kTokens[next() % kTokens.size()];
        compare(tokens);
    }
    CHECK(undercounts == 0);
    CHECK(accepted > 0); // the corpus reaches accepted documents, not only errors
}

TEST_CASE("browser_policy: the depth cap has an exact boundary for arrays AND objects, and holds "
          "with comments",
          "[browser_policy][parsers]") {
    const auto nest = [](char open, char close, int n) {
        std::string s = R"({"k":)"; // the root object is container 1
        for (int i = 0; i < n; ++i) {
            s += open;
            if (open == '{')
                s += "\"k\":";
        }
        s += "1";
        for (int i = 0; i < n; ++i)
            s += close;
        s += "}";
        return s;
    };
    const auto parse = [](const std::string& text) {
        return rows_from_json_policy_text(text, Browser::chrome, Level::mandatory, "machine",
                                          "/x");
    };
    // 32 containers in all parse; a 33rd is json_too_deep. MUTATION: shift the comparison by one
    // in rows_from_json_policy_text -> one of these four flips.
    CHECK_FALSE(parse(nest('[', ']', kMaxNestingDepth - 1)).failure.has_value());
    CHECK(parse(nest('[', ']', kMaxNestingDepth)).failure == kTokenJsonTooDeep);
    CHECK_FALSE(parse(nest('{', '}', kMaxNestingDepth - 1)).failure.has_value());
    CHECK(parse(nest('{', '}', kMaxNestingDepth)).failure == kTokenJsonTooDeep);
    // A CR-ended line comment does not hide the nesting after it from the guard.
    std::string sneaky = "// c\r" + nest('[', ']', kMaxNestingDepth);
    CHECK(parse(sneaky).failure == kTokenJsonTooDeep);
}

TEST_CASE("browser_policy: a wide file of sibling containers parses in linear time, a wider one "
          "is json_too_complex, and rows stop at max_rows",
          "[browser_policy][parsers]") {
    // The shape nlohmann's callback parser handled QUADRATICALLY (minutes for 1 MiB): one key
    // holding a huge list of small objects. The depth guard is now a linear pre-scan and the
    // parse has no callback, so the widest file the container cap admits returns at once; a
    // regression back to the callback parser shows up as a suite that does not finish, not as
    // a timing assertion. A megabyte of the same shape exceeds the container cap and is
    // refused by the pre-scan without being parsed.
    std::string text = R"({"a":[)";
    while (text.size() < 65000 * 8)
        text += R"({"x":1},)";
    text += R"({"x":1}]})";
    const auto p = rows_from_json_policy_text(text, Browser::chrome, Level::mandatory, "machine",
                                              "/x");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].value.type == PolicyType::List);

    std::string huge = R"({"a":[)";
    while (huge.size() < 1024 * 1024)
        huge += R"({"x":1},)";
    huge += R"({"x":1}]})";
    CHECK(rows_from_json_policy_text(huge, Browser::chrome, Level::mandatory, "machine", "/x")
              .failure == kTokenJsonTooComplex);

    // And a file with many keys stops building rows at the budget it is given.
    std::string keys = "{";
    for (int i = 0; i < 5000; ++i)
        keys += (i ? "," : "") + std::string{"\"K"} + std::to_string(i) + "\":1";
    keys += "}";
    const auto capped = rows_from_json_policy_text(keys, Browser::chrome, Level::mandatory,
                                                   "machine", "/x", 3);
    REQUIRE_FALSE(capped.failure.has_value());
    CHECK(capped.rows.size() == 3); // MUTATION: ignore max_rows -> 5000
}

#if !defined(_WIN32)

namespace {

namespace fs = std::filesystem;

// ── tree-manifest materializer (copied from test_peripherals_linux_parsers.cpp,
//    extended with T:/B:/L: payloads; TU-local by design) ──────────────────

bool base64_decode(std::string_view in, std::string& out) {
    static const std::string kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned acc = 0;
    int bits = 0;
    out.clear();
    for (const char c : in) {
        if (c == '=')
            break;
        const auto pos = kAlphabet.find(c);
        if (pos == std::string::npos)
            return false;
        acc = (acc << 6) | static_cast<unsigned>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return true;
}

bool unescape_text(std::string_view in, std::string& out) {
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out += in[i];
            continue;
        }
        if (++i >= in.size())
            return false;
        switch (in[i]) {
        case 'n':  out += '\n'; break;
        case 't':  out += '\t'; break;
        case '\\': out += '\\'; break;
        default:   return false;
        }
    }
    return true;
}

bool materialize(std::istream& manifest, const fs::path& root, std::string& error) {
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') // CRLF-checkout tolerance
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        const auto tab = line.find('\t');
        if (tab == std::string::npos || tab + 2 >= line.size() || line[tab + 2] != ':') {
            error = "malformed manifest line: " + line.substr(0, 80);
            return false;
        }
        const fs::path out_path = root / line.substr(0, tab);
        const char kind = line[tab + 1];
        const std::string_view payload = std::string_view{line}.substr(tab + 3);
        std::error_code ec;
        fs::create_directories(out_path.parent_path(), ec);
        if (ec) {
            error = "create_directories failed: " + ec.message();
            return false;
        }
        if (kind == 'L') {
            fs::create_symlink(std::string{payload}, out_path, ec);
            if (ec) {
                error = "create_symlink failed: " + ec.message();
                return false;
            }
            continue;
        }
        std::string bytes;
        if (kind == 'T' ? !unescape_text(payload, bytes)
                        : (kind == 'B' ? !base64_decode(payload, bytes) : true)) {
            error = "bad payload for " + out_path.string();
            return false;
        }
        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            error = "could not create " + out_path.string();
            return false;
        }
        out << bytes;
    }
    return true;
}

fs::path manifest_path() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "browser_policy" / "linux" / "tree.manifest";
#else
    return fs::path("tests/unit/fixtures/wave10/browser_policy/linux/tree.manifest");
#endif
}

void materialize_fixture(const fs::path& root) {
    std::ifstream in(manifest_path(), std::ios::binary);
    REQUIRE(in.good());
    std::string error;
    REQUIRE(materialize(in, root, error));
}

void write_file(const fs::path& root, const std::string& rel, const std::string& content) {
    const fs::path p = root / rel;
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

std::string read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool has_row(const std::vector<std::string>& rows, std::string_view exact) {
    return std::find(rows.begin(), rows.end(), exact) != rows.end();
}

std::size_t count_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const auto& r) {
        return r.compare(0, prefix.size(), prefix) == 0;
    }));
}

/// Restores a directory's permissions so TempDir's remove_all can run.
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

constexpr std::string_view kChromeManaged = "/etc/opt/chrome/policies/managed/chrome_managed.json";

// ── CommandContext-level harness ─────────────────────────────────────────
// Drives the PRODUCTION leg body (run_linux_at) through a real CommandContext
// via LocalDispatcher (the test_filesystem_posture_local_dispatcher.cpp
// precedent: a synthetic descriptor whose execute() calls the code under
// test), so what is asserted is the emitted rows AND the CC-07 status the
// command actually reports — not just the walk's return values.

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;  // the `policy|` rows only
    std::string status_row;         // the in-band summary `status|` row, or "" when the read completed
    std::vector<std::string> path_rows; // the per-path `status|` rows that follow it
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;
const WalkLimits* g_leg_limits = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return run_linux_at(ctx, *g_leg_root, *g_leg_limits);
}

LegRun run_leg(const fs::path& root, const WalkLimits& limits = {}) {
    g_leg_root = &root;
    g_leg_limits = &limits;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "probe");
    g_leg_root = nullptr;
    g_leg_limits = nullptr;

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    bool first_line = true;
    bool status_row_first = false;
    for (std::string line; std::getline(lines, line);) {
        if (line.empty())
            continue;
        if (line.rfind("status|", 0) == 0) {
            if (out.status_row.empty()) { // the first status row is the summary
                out.status_row = line;
                status_row_first = first_line;
            } else {
                out.path_rows.push_back(line); // per-path rows follow the summary
            }
        } else {
            out.rows.push_back(line);
        }
        first_line = false;
    }
    // The pairing invariant, checked on EVERY leg run in this file: a CONSTRAINED read carries
    // exactly one `constrained` status row, FIRST in the output, naming the same tokens as the
    // typed provenance; a completed read (OK/FULL, populated or empty) carries none. MUTATION:
    // drop the row write from mark_result_read, write it on an OK read, or move it after
    // write_rows -> the runs that reach the changed branch fail here.
    if (!out.status_row.empty()) {
        CHECK(status_row_first);
    }
    if (out.status == YUZU_RESULT_STATUS_CONSTRAINED) {
        CHECK(out.status_row == "status|-|-|-|policies|-|constrained|-|" + out.provenance);
    } else {
        CHECK(out.status_row.empty());
        CHECK(out.path_rows.empty());
    }
    return out;
}

} // namespace

TEST_CASE("browser_policy tree: the manifest materializer handles T:, B:, L: and rejects garbage",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mat_"};
    fs::create_directories(dir.path);
    std::istringstream in("# comment\n\n"
                          "a/b.txt\tT:l1\\nl2\\ttab\\\\end\n"
                          "a/bin.dat\tB:AAH/\n"
                          "a/link\tL:b.txt\n");
    std::string error;
    REQUIRE(materialize(in, dir.path, error));
    CHECK(read_all(dir.path / "a" / "b.txt") == "l1\nl2\ttab\\end");
    CHECK(read_all(dir.path / "a" / "bin.dat") == std::string("\x00\x01\xff", 3));
    CHECK(fs::is_symlink(dir.path / "a" / "link"));
    CHECK(fs::read_symlink(dir.path / "a" / "link") == "b.txt");

    std::istringstream bad("a/x\tno-kind-prefix\n");
    CHECK_FALSE(materialize(bad, dir.path, error));
    CHECK_FALSE(error.empty());
}

TEST_CASE("browser_policy linux: the fixture tree yields chrome, edge and recommended rows",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_tree_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);

    std::string reason = "sentinel";
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(reason.empty()); // complete read: no constraint

    CHECK(count_prefix(rows, "policy|chrome|mandatory|machine|") == 8);
    CHECK(count_prefix(rows, "policy|chrome|recommended|machine|") == 2);
    CHECK(count_prefix(rows, "policy|edge|mandatory|machine|") == 4);
    CHECK(rows.size() == 14);

    // Exact rows: a value flowing from the file to the wire (mutation: drop a
    // vendor/level/dir from the walk and the matching row disappears).
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|HomepageLocation|string|"
                        "https://intranet.example.com/|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|RestoreOnStartup|int|4|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|PasswordManagerEnabled|bool|false|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|ExtensionSettings|dict|"
                        "{\"*\":{\"installation_mode\":\"blocked\"}}|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|recommended|machine|BookmarkBarEnabled|bool|true|"
                        "/etc/opt/chrome/policies/recommended/chrome_recommended.json|-"));
    CHECK(has_row(rows, "policy|edge|mandatory|machine|InPrivateModeAvailability|int|1|"
                        "/etc/opt/edge/policies/managed/edge_managed.json|-"));
    CHECK(has_row(rows, "policy|edge|mandatory|machine|ExtensionInstallBlocklist|list|[\"*\"]|"
                        "/etc/opt/edge/policies/managed/edge_managed.json|-"));

    // Every row is exactly nine fields.
    for (const auto& r : rows)
        CHECK(split_fields(r).size() == 9);
}

TEST_CASE("browser_policy linux: fixtures carry the sign-off / reconstruction headers",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_hdr_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    constexpr std::string_view kHeader = "SYNTHETIC \xE2\x80\x94 not a real capture "
                                         "(Alex sign-off 2026-09-21)";
    CHECK(read_all(dir.path / "etc/opt/chrome/policies/managed/chrome_managed.json").find(kHeader) !=
          std::string::npos);
    CHECK(read_all(dir.path / "etc/opt/chrome/policies/recommended/chrome_recommended.json")
              .find(kHeader) != std::string::npos);
    const auto edge = read_all(dir.path / "etc/opt/edge/policies/managed/edge_managed.json");
    CHECK(edge.find("RECONSTRUCTION") != std::string::npos);
    CHECK(edge.find("learn.microsoft.com/deployedge/microsoft-edge-policies") != std::string::npos);
}

TEST_CASE("browser_policy linux: an absent root or no managed policy is zero rows and complete",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_absent_"};
    std::string reason = "sentinel";

    // Root does not exist at all.
    auto rows = lnx::linux_policy_rows_at(dir.path / "no_such_root", reason);
    CHECK(rows.empty());
    CHECK(reason.empty());

    // Root exists, no browser installed.
    fs::create_directories(dir.path / "etc" / "opt");
    reason = "sentinel";
    rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason.empty());
}

TEST_CASE("browser_policy linux: chromium's directory is walked and non-json files are ignored",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_chromium_"};
    write_file(dir.path, "etc/chromium/policies/managed/c.json", R"({"IncognitoModeAvailability": 1})");
    write_file(dir.path, "etc/chromium/policies/managed/README.txt", "not a policy file");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(reason.empty());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "policy|chromium|mandatory|machine|IncognitoModeAvailability|int|1|"
                     "/etc/chromium/policies/managed/c.json|-");
}

TEST_CASE("browser_policy linux: malformed JSON is constrained and never hides its siblings",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_bad_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a_bad.json", R"({"HomepageLocation": )");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b_good.json", R"({"ShowHomeButton": true})");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    // The good sibling is kept...
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    // ...and the bad one is reported, not absorbed into an unqualified success.
    CHECK(reason.find("linux:json_unparseable") != std::string::npos);

    // Only a bad file: zero rows but STILL constrained (failure != absent).
    yuzu::test::TempDir only_bad{"yuzu_test_browser_policy_onlybad_"};
    write_file(only_bad.path, "etc/opt/edge/policies/recommended/x.json", "{ nope");
    const auto none = lnx::linux_policy_rows_at(only_bad.path, reason);
    CHECK(none.empty());
    CHECK(reason == "linux:json_unparseable");
}

TEST_CASE("browser_policy linux leg: a failing file gets one per-path status row, after the summary",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_perpath_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a_good.json", R"({"ShowHomeButton": true})");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b_bad.json", "{ nope");
    write_file(dir.path, "etc/opt/chrome/policies/managed/c_good.json", R"({"HomepageIsNewTabPage": false})");
    const auto run = run_leg(dir.path);
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.rows.size() == 2); // both siblings' policy rows stand
    CHECK(run.status_row == "status|-|-|-|policies|-|constrained|-|linux:json_unparseable");
    REQUIRE(run.path_rows.size() == 1);
    // The LOGICAL path: the injected temp root never appears.
    CHECK(run.path_rows[0] == "status|-|-|-|policies|-|constrained|"
                              "/etc/opt/chrome/policies/managed/b_bad.json|linux:json_unparseable");
    CHECK(run.path_rows[0].find(dir.path.string()) == std::string::npos);
}

// MUTATION: raise the push guard in linux_policy_rows_at's `fail` (or drop the cap in
// mark_result_read) -> more than 64 per-path rows, or no `status_rows_capped` token.
TEST_CASE("browser_policy linux leg: per-path status rows are capped, and the summary says so",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_pathcap_"};
    const auto write_bad = [&](std::size_t count) {
        for (std::size_t i = 0; i < count; ++i) {
            char name[32];
            std::snprintf(name, sizeof name, "bad_%03zu.json", i);
            write_file(dir.path, std::string{"etc/opt/chrome/policies/managed/"} + name, "{ nope");
        }
    };
    write_bad(kMaxPathFailureRows); // exactly the cap: every file is named, nothing is dropped
    auto run = run_leg(dir.path);
    CHECK(run.path_rows.size() == kMaxPathFailureRows);
    CHECK(run.provenance == "linux:json_unparseable");

    write_bad(kMaxPathFailureRows + 1); // one over: 64 rows, and the summary says rows were cut
    run = run_leg(dir.path);
    CHECK(run.path_rows.size() == kMaxPathFailureRows);
    CHECK(run.provenance == "linux:json_unparseable,linux:status_rows_capped");
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("browser_policy linux: an unreadable policy directory is constrained, siblings survive",
          "[browser_policy][linux][tree]") {
    // Skip if the test happens to run as root (uid 0 / CAP_DAC_OVERRIDE bypass
    // the permission bits this test exercises).
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_browser_policy_eacces_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    const fs::path locked = dir.path / "etc/opt/chrome/policies/managed";
    PermRestore restore{locked};
    REQUIRE(::chmod(locked.c_str(), 0000) == 0);

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    // Listing the locked directory must fail loudly, not read as "no policy".
    CHECK(reason.find("linux:permission_denied") != std::string::npos);
    CHECK(count_prefix(rows, "policy|chrome|mandatory|") == 0);
    // The other directories still read.
    CHECK(count_prefix(rows, "policy|chrome|recommended|") == 2);
    CHECK(count_prefix(rows, "policy|edge|mandatory|") == 4);
}

TEST_CASE("browser_policy linux: an unreadable policy FILE is constrained",
          "[browser_policy][linux][tree]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_browser_policy_fileacces_"};
    write_file(dir.path, "etc/opt/edge/policies/managed/locked.json", R"({"A": 1})");
    const fs::path locked = dir.path / "etc/opt/edge/policies/managed/locked.json";
    PermRestore restore{locked};
    REQUIRE(::chmod(locked.c_str(), 0000) == 0);

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:permission_denied");
}

TEST_CASE("browser_policy linux: symlinks below the root are refused, the root itself may be one",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_symlink_"};
    fs::create_directories(dir.path);

    // (a) a symlinked policy DIRECTORY component is not followed.
    write_file(dir.path, "elsewhere/policies/managed/p.json", R"({"HomepageLocation": "x"})");
    fs::create_directories(dir.path / "root_a" / "etc" / "opt");
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "root_a" / "etc" / "opt" / "chrome");
    std::string reason;
    auto rows = lnx::linux_policy_rows_at(dir.path / "root_a", reason);
    CHECK(rows.empty());
    // O_DIRECTORY|O_NOFOLLOW on a symlink is ENOTDIR on Linux AND macOS, so open_dir_at looks
    // again (fstatat, no follow) to name it. MUTATIONS: drop O_NOFOLLOW -> rows appear; drop the
    // fstatat look -> the token degrades to linux:not_a_directory.
    CHECK(reason == "linux:symlink_refused");

    // (a2) the same at the LEVEL hop: `managed` itself is a symlink.
    fs::create_directories(dir.path / "root_a2" / "etc" / "opt" / "chrome" / "policies");
    fs::create_directory_symlink(dir.path / "elsewhere" / "policies" / "managed",
                                 dir.path / "root_a2" / "etc" / "opt" / "chrome" / "policies" / "managed");
    rows = lnx::linux_policy_rows_at(dir.path / "root_a2", reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:symlink_refused");

    // (b) a symlinked policy FILE is not followed.
    write_file(dir.path, "target.json", R"({"A": 1})");
    fs::create_directories(dir.path / "root_b" / "etc" / "opt" / "edge" / "policies" / "managed");
    fs::create_symlink(dir.path / "target.json",
                       dir.path / "root_b" / "etc" / "opt" / "edge" / "policies" / "managed" / "l.json");
    rows = lnx::linux_policy_rows_at(dir.path / "root_b", reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:symlink_refused");

    // (c) the injected root itself may be a symlink (e.g. /tmp -> /private/tmp).
    materialize_fixture(dir.path / "real_root");
    fs::create_directory_symlink(dir.path / "real_root", dir.path / "root_link");
    rows = lnx::linux_policy_rows_at(dir.path / "root_link", reason);
    CHECK(reason.empty());
    CHECK(rows.size() == 14);
}

TEST_CASE("browser_policy linux: an oversized policy file is constrained, not truncated",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_big_"};
    std::string big = "{\"K\": \"";
    big.append(kMaxPolicyFileBytes + 1, 'a');
    big += "\"}";
    write_file(dir.path, "etc/opt/chrome/policies/managed/big.json", big);
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:oversized");
}

TEST_CASE("browser_policy linux: a non-regular object at a policy-file path is constrained, never read",
          "[browser_policy][linux][tree]") {
    // Root-safe (no chmod, so no euid-0 SKIP): a FIFO and a directory are both
    // refused by the S_ISREG check after the O_NONBLOCK open, whoever runs the
    // suite. MUTATION: delete the S_ISREG check in posix::read_file_at -> the
    // writer-less FIFO reads as EOF (zero bytes -> linux:json_unparseable) and
    // the directory read fails with EISDIR (linux:read_failed): the exact pin
    // below fails either way. Dropping O_NONBLOCK would block in open() on the
    // FIFO: the future below is a deadlock guard (the healthy path returns in
    // microseconds), not a timing assumption.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_fifo_"};
    const fs::path managed = dir.path / "etc/opt/chrome/policies/managed";
    fs::create_directories(managed);
    REQUIRE(::mkfifo((managed / "fifo.json").c_str(), 0644) == 0);
    fs::create_directories(managed / "dir.json"); // a DIRECTORY named like a policy file
    write_file(dir.path, "etc/opt/chrome/policies/managed/ok.json", R"({"ShowHomeButton": true})");

    // The walk under the deadlock guard: a hang becomes a named failure, and the blocked open()
    // is released so the worker (and this process) can exit.
    const auto walk_guarded = [](const fs::path& root, const fs::path& fifo, std::string& reason) {
        std::vector<std::string> rows;
        auto fut = std::async(std::launch::async,
                              [&] { rows = lnx::linux_policy_rows_at(root, reason); });
        if (fut.wait_for(std::chrono::seconds(20)) != std::future_status::ready) {
            posix::Fd release{::open(fifo.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC)};
            fut.wait();
            FAIL("linux_policy_rows_at blocked in open() on a writer-less FIFO");
        }
        return rows;
    };

    std::string reason;
    const auto rows = walk_guarded(dir.path, managed / "fifo.json", reason);
    // The regular sibling still reads; both non-regular objects collapse to ONE
    // token (the accumulator dedupes exact strings).
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    CHECK(reason == "linux:not_regular");

    // A FIFO where a DIRECTORY hop belongs: O_DIRECTORY refuses it at once (ENOTDIR). MUTATION:
    // drop O_DIRECTORY from open_dir_at -> the open blocks on the writer-less FIFO, the guard
    // above fires, and the case fails by name instead of wedging the suite.
    yuzu::test::TempDir hop{"yuzu_test_browser_policy_fifohop_"};
    fs::create_directories(hop.path / "etc/opt");
    REQUIRE(::mkfifo((hop.path / "etc/opt/chrome").c_str(), 0644) == 0);
    std::string hop_reason;
    const auto hop_rows = walk_guarded(hop.path, hop.path / "etc/opt/chrome", hop_reason);
    CHECK(hop_rows.empty());
    CHECK(hop_reason == "linux:not_a_directory");
}

TEST_CASE("browser_policy linux: a regular file where a policy directory is expected is constrained",
          "[browser_policy][linux][tree]") {
    // Root-safe: openat(O_DIRECTORY) on a regular file is ENOTDIR whoever runs
    // the suite. Exercised at BOTH hops: a vendor component (open_dir_chain) and
    // a level directory (open_dir_at). MUTATION: delete the ENOTDIR arm of
    // posix::errno_detail -> the token degrades to linux:open_failed and the
    // exact pin below fails.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_notdir_"};
    write_file(dir.path, "etc/opt/edge", "not a directory");             // vendor hop is a FILE
    write_file(dir.path, "etc/chromium/policies/managed", "nor is this"); // level hop is a FILE
    write_file(dir.path, "etc/opt/chrome/policies/managed/ok.json", R"({"ShowHomeButton": true})");

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    REQUIRE(rows.size() == 1); // chrome still reads: a failed sibling never hides it
    CHECK(rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    CHECK(reason == "linux:not_a_directory"); // both hops dedupe to the one token
}

#if defined(__linux__)
TEST_CASE("browser_policy linux: a policy file whose NAME is not valid UTF-8 is read and its row "
          "survives the transport",
          "[browser_policy][linux][tree]") {
    // Linux file names are arbitrary bytes (macOS and Windows refuse to create one), so only
    // this leg can meet one, and it lands verbatim in `source`. MUTATION: drop repair_utf8 from
    // wire_field -> the row keeps the raw 0xFF, so the exact source and the round trip fail.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_utf8name_"};
    const fs::path managed = dir.path / "etc/opt/chrome/policies/managed";
    fs::create_directories(managed);
    posix::Fd file{::open((managed / "corp_\xFF.json").c_str(), O_CREAT | O_WRONLY | O_CLOEXEC,
                          0644)};
    if (!file.valid()) {
        SKIP("this filesystem refuses a file name that is not valid UTF-8");
    }
    const std::string body = R"({"ShowHomeButton": true})";
    REQUIRE(::write(file.get(), body.data(), body.size()) == static_cast<ssize_t>(body.size()));
    file.reset(); // close before the walk reads it

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    REQUIRE(rows.size() == 1);
    CHECK(reason.empty()); // the file read fine; only its name needed repair
    CHECK(rows[0] == "policy|chrome|mandatory|machine|ShowHomeButton|bool|true|"
                     "/etc/opt/chrome/policies/managed/corp_\xEF\xBF\xBD.json|utf8_replaced");
    CHECK(survives_transport(rows[0]));
}
#endif

// ── failure -> command status (the seam every degraded read reports through) ──

TEST_CASE("browser_policy linux leg: acquisition failure reaches the command as CONSTRAINED/PARTIAL",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_bad_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a_bad.json", R"({"HomepageLocation": )");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b_good.json", R"({"ShowHomeButton": true})");

    const auto run = run_leg(dir.path);
    CHECK(run.rc == 0); // a degraded read is not a failed command
    // The good sibling was emitted...
    REQUIRE(run.rows.size() == 1);
    CHECK(run.rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    // ...and the failure is on the wire status with the exact token, not OK/FULL.
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:json_unparseable");

    // Only a bad file: zero rows but STILL constrained — a failure never reads as absent.
    yuzu::test::TempDir only_bad{"yuzu_test_browser_policy_leg_onlybad_"};
    write_file(only_bad.path, "etc/opt/edge/policies/recommended/x.json", "{ nope");
    const auto none = run_leg(only_bad.path);
    CHECK(none.rows.empty());
    CHECK(none.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(none.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(none.provenance == "linux:json_unparseable");
}

TEST_CASE("browser_policy linux leg: a genuinely absent or complete read is OK/FULL",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_ok_"};

    // Absent root: zero rows, no placeholder, complete.
    auto run = run_leg(dir.path / "no_such_root");
    CHECK(run.rc == 0);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());

    // Populated fixture: every row emitted, still complete.
    materialize_fixture(dir.path / "fixture_root");
    run = run_leg(dir.path / "fixture_root");
    CHECK(run.rows.size() == 14);
    CHECK(count_prefix(run.rows, "policy|chrome|mandatory|machine|") == 8);
    CHECK(count_prefix(run.rows, "policy|edge|") == 4);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("browser_policy linux leg: a NUL in a policy value reaches the command whole",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_nul_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/n.json", R"({"K":"a\u0000b"})");
    const auto run = run_leg(dir.path);
    REQUIRE(run.rows.size() == 1);
    // Truncating at the NUL would drop the source and detail fields.
    CHECK(run.rows[0] == "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
                         "b|/etc/opt/chrome/policies/managed/n.json|nul_replaced");
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
}

// ── saturation: row cap, directory cap, file cap (WalkLimits, exactly-at-cap controls) ──

TEST_CASE("browser_policy linux leg: the row cap is reported, and exactly-at-cap is complete",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_rowcap_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", R"({"A": 1, "B": 2})");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b.json", R"({"C": 3, "D": 4})");

    WalkLimits limits;
    limits.max_rows = 4; // exactly the row count: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 4);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_rows = 3; // one over: capped, reported, lower bound
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:row_cap");

    // The cap is per leg, not per file: it also stops the next vendor/level.
    write_file(dir.path, "etc/opt/edge/policies/managed/e.json", R"({"E": 5})");
    limits.max_rows = 4;
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 4);
    CHECK(run.provenance == "linux:row_cap");
}

TEST_CASE("browser_policy linux leg: a truncated directory listing is reported, never complete",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_dircap_"};
    for (const char* name : {"a.json", "b.json", "c.json"})
        write_file(dir.path, std::string{"etc/opt/chrome/policies/managed/"} + name,
                   std::string{"{\""} + name + "\": true}");

    WalkLimits limits;
    limits.max_entries_per_dir = 3; // exactly the entry count: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_entries_per_dir = 2; // an entry remains unread: must not read as complete
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2); // only the examined entries
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:entry_cap"); // the per-directory bound, not the per-leg row cap
}

TEST_CASE("browser_policy linux leg: the file-size cap is exact and reported",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_filecap_"};
    const std::string body = R"({"A": 1})";
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", body);

    WalkLimits limits;
    limits.max_file_bytes = body.size(); // exactly the size: read
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 1);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);

    limits.max_file_bytes = body.size() - 1; // one byte over: constrained
    run = run_leg(dir.path, limits);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.provenance == "linux:oversized");
}

TEST_CASE("browser_policy linux leg: the total read budget is exact and reported",
          "[browser_policy][linux][cap]") {
    // Every file is far below the per-file cap and the tree far below the row and entry caps:
    // only the aggregate budget can stop this walk. MUTATION: drop the max_total_bytes check in
    // linux_policy_rows_at -> the one-under case reads all three files and reports OK.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_bytecap_"};
    const std::string a = R"({"A": 1})";
    const std::string b = R"({"B": 2})";
    const std::string c = R"({"C": 3})";
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", a);
    write_file(dir.path, "etc/opt/chrome/policies/managed/b.json", b);
    write_file(dir.path, "etc/opt/chrome/policies/managed/c.json", c);

    WalkLimits limits;
    limits.max_total_bytes = a.size() + b.size() + c.size(); // exactly the total: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_total_bytes = a.size() + b.size() + c.size() - 1; // the last file crosses it
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2); // rows read before the budget ran out stand; c.json is not parsed
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:byte_cap"); // the run-wide read bound, not the per-file cap
}

TEST_CASE("browser_policy linux leg: a cap stops the walk, so a later sibling adds no failure token",
          "[browser_policy][linux][cap]") {
    // MUTATION: turn either `return finish()` at a cap into `continue` -> the rows stay the same
    // but the later sibling is still visited and adds its own token, so the exact pin fails.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_capstop_"};
    const std::string body = R"({"A": 1})";
    for (const char* name : {"a", "b", "c"})
        write_file(dir.path, std::string{"etc/opt/chrome/policies/managed/"} + name + ".json", body);
    // Sorted after c.json: would add linux:symlink_refused if the walk reached it.
    fs::create_symlink("nowhere", dir.path / "etc/opt/chrome/policies/managed/d.json");
    WalkLimits limits;
    limits.max_total_bytes = 2 * body.size();
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2);
    CHECK(run.provenance == "linux:byte_cap");

    yuzu::test::TempDir dir2{"yuzu_test_browser_policy_leg_capstop2_"};
    write_file(dir2.path, "etc/opt/chrome/policies/managed/a.json", R"({"A": 1, "B": 2, "C": 3})");
    write_file(dir2.path, "etc/opt/chrome/policies/managed/b.json", "{ nope"); // json_unparseable if reached
    WalkLimits row_limits;
    row_limits.max_rows = 2;
    run = run_leg(dir2.path, row_limits);
    CHECK(run.rows.size() == 2);
    CHECK(run.provenance == "linux:row_cap");
}

TEST_CASE("browser_policy linux leg: an unlimited row budget builds every row, not none",
          "[browser_policy][linux][cap]") {
    // The parser is handed the budget that is left plus one; a max_rows of SIZE_MAX must
    // saturate, not wrap to "build no rows" (which would read as an empty, complete OK).
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_unlimited_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", R"({"A": 1, "B": 2})");
    WalkLimits limits;
    limits.max_rows = std::numeric_limits<std::size_t>::max();
    const auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
}

TEST_CASE("browser_policy linux leg: rows come out in sorted file order, whatever readdir returns",
          "[browser_policy][linux][tree]") {
    // MUTATION: drop the std::sort in list_names -> readdir order (newest-first on tmpfs, hash
    // order on ext4) leaks into the rows.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_order_"};
    for (char c = 'a'; c <= 'p'; ++c)
        write_file(dir.path, std::string{"etc/opt/chrome/policies/managed/"} + c + ".json",
                   std::string{"{\"P_"} + c + "\": 1}");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    REQUIRE(rows.size() == 16);
    for (std::size_t i = 0; i < rows.size(); ++i)
        CHECK(rows[i].find(std::string{"|P_"} + static_cast<char>('a' + i) + "|") !=
              std::string::npos);
}

TEST_CASE("browser_policy linux leg: a root that is not a directory is constrained, never absent",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_fileroot_"};
    write_file(dir.path, "iamafile", "x");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path / "iamafile", reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:not_a_directory");
}

TEST_CASE("browser_policy linux leg: the README's statements about Chromium's looser reader hold",
          "[browser_policy][linux][tree]") {
    // Caveat 1 says: a trailing comma is unparseable here; a file without a .json suffix is
    // skipped SILENTLY (the one fail-wrong direction); two files setting one policy give two
    // rows, one per file. Each is pinned so the README cannot drift from the behaviour.
    yuzu::test::TempDir trailing{"yuzu_test_browser_policy_leg_comma_"};
    write_file(trailing.path, "etc/opt/chrome/policies/managed/a.json", R"({"A": 1,})");
    auto run = run_leg(trailing.path);
    CHECK(run.rows.empty());
    CHECK(run.provenance == "linux:json_unparseable");

    yuzu::test::TempDir suffix{"yuzu_test_browser_policy_leg_suffix_"};
    write_file(suffix.path, "etc/opt/chrome/policies/managed/00-defaults", R"({"A": 1})");
    write_file(suffix.path, "etc/opt/chrome/policies/managed/b.json.bak", R"({"B": 2})");
    run = run_leg(suffix.path);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_OK); // silent: Chromium would load both
    CHECK(run.provenance.empty());

    yuzu::test::TempDir twice{"yuzu_test_browser_policy_leg_twice_"};
    write_file(twice.path, "etc/opt/chrome/policies/managed/00-base.json",
               R"({"HomepageLocation": "https://a.example/"})");
    write_file(twice.path, "etc/opt/chrome/policies/managed/90-override.json",
               R"({"HomepageLocation": "https://b.example/"})");
    run = run_leg(twice.path);
    REQUIRE(run.rows.size() == 2);
    CHECK(run.rows[0].find("https://a.example/|/etc/opt/chrome/policies/managed/00-base.json|") !=
          std::string::npos);
    CHECK(run.rows[1].find("https://b.example/|/etc/opt/chrome/policies/managed/90-override.json|") !=
          std::string::npos);
}

TEST_CASE("browser_policy linux leg: a valid file longer than one read chunk is read whole",
          "[browser_policy][linux][read]") {
    // MUTATION: `append` -> `assign` in read_file_at keeps only the last 16 KiB chunk.
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_bigvalid_"};
    std::string body = "{";
    for (int i = 0; i < 3000; ++i)
        body += (i ? "," : "") + std::string{"\"K"} + std::to_string(i) + "\": " + std::to_string(i);
    body += "}";
    REQUIRE(body.size() > 2 * 16384);
    write_file(dir.path, "etc/opt/chrome/policies/managed/big.json", body);
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(reason.empty());
    CHECK(rows.size() == 3000);
}

namespace {
int open_fd_count() {
    int n = 0;
    for (int fd = 0; fd < 1024; ++fd)
        if (::fcntl(fd, F_GETFD) != -1)
            ++n;
    return n;
}
bool fd_is_open(int fd) {
    return ::fcntl(fd, F_GETFD) != -1;
}
} // namespace

TEST_CASE("browser_policy linux leg: the walk leaks no file descriptor on the happy path or any "
          "failure path",
          "[browser_policy][linux][tree]") {
    // LeakSanitizer sees heap only, so an unclosed fd is invisible to the sanitizer legs: count
    // the process's descriptors around the walk. MUTATION: drop closedir in ~Dir, or the close in
    // the fd owner -> the count grows. (No FIFO here: a lost O_NONBLOCK would hang this case
    // instead of failing it; the FIFO case above carries the deadlock guard.)
    yuzu::test::TempDir ok{"yuzu_test_browser_policy_leg_fdleak_"};
    for (char c = 'a'; c <= 'e'; ++c)
        write_file(ok.path, std::string{"etc/opt/chrome/policies/managed/"} + c + ".json", R"({"K": 1})");
    write_file(ok.path, "etc/opt/edge/policies/recommended/x.json", "{ nope");             // unparseable
    write_file(ok.path, "etc/chromium/policies/managed/big.json", std::string(2048, 'a'));  // oversized below
    fs::create_symlink("nowhere", ok.path / "etc/opt/chrome/policies/managed/l.json");      // symlink leaf
    WalkLimits limits;
    limits.max_file_bytes = 1024;
    yuzu::test::TempDir bad{"yuzu_test_browser_policy_leg_fdleak_bad_"};
    write_file(bad.path, "etc/opt/edge", "a file where a directory belongs");
    fs::create_directories(bad.path / "etc" / "opt" / "chrome" / "policies");
    fs::create_directory_symlink(bad.path / "etc", bad.path / "etc" / "opt" / "chrome" / "policies" / "managed");

    const int before = open_fd_count();
    for (int i = 0; i < 3; ++i) {
        std::string reason;
        (void)lnx::linux_policy_rows_at(ok.path, reason, limits);
        (void)lnx::linux_policy_rows_at(bad.path, reason);
        (void)lnx::linux_policy_rows_at(bad.path / "no_such_root", reason);
    }
    CHECK(open_fd_count() == before);
}

TEST_CASE("browser_policy posix: dir_from_fd closes the fd itself when fdopendir fails",
          "[browser_policy][linux][tree]") {
    // fdopendir leaves the fd open on failure; the owner must close it exactly once (the guard,
    // never by hand). /dev/null is not a directory, so fdopendir fails with ENOTDIR.
    const int raw = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(raw >= 0);
    const auto r = posix::dir_from_fd(posix::Fd{raw}, 0);
    CHECK(r.status == posix::OpenStatus::failed);
    CHECK(r.detail == "not_a_directory");
    CHECK_FALSE(fd_is_open(raw));
}

TEST_CASE("browser_policy posix: Dir is move-only and a moved-from owner closes nothing",
          "[browser_policy][linux][tree]") {
    static_assert(!std::is_copy_constructible_v<posix::Dir> && !std::is_copy_assignable_v<posix::Dir>);
    static_assert(std::is_nothrow_move_constructible_v<posix::Dir> &&
                  std::is_nothrow_move_assignable_v<posix::Dir>);
    posix::Dir a{::opendir("/")};
    REQUIRE(a.get() != nullptr);
    const int a_fd = a.fd();
    posix::Dir b{std::move(a)};
    CHECK(a.get() == nullptr);
    CHECK(fd_is_open(a_fd)); // the move transferred it; nothing closed it

    posix::Dir c{::opendir("/")};
    REQUIRE(c.get() != nullptr);
    const int c_old_fd = c.fd();
    c = std::move(b); // must close c's previous directory and adopt a's
    CHECK_FALSE(fd_is_open(c_old_fd));
    CHECK(fd_is_open(a_fd));
    CHECK(b.get() == nullptr);
}

TEST_CASE("browser_policy posix: errno_detail maps every documented errno to its token",
          "[browser_policy][linux][tree]") {
    static_assert(posix::errno_detail(EACCES) == "permission_denied");
    static_assert(posix::errno_detail(EPERM) == "permission_denied");
    static_assert(posix::errno_detail(ELOOP) == "symlink_refused");
    static_assert(posix::errno_detail(ENOTDIR) == "not_a_directory");
    static_assert(posix::errno_detail(EMFILE) == "open_failed");
    SUCCEED();
}

#if defined(__linux__)
TEST_CASE("browser_policy linux: a file is read to EOF, not to its fstat size",
          "[browser_policy][linux][read]") {
    // /proc reports st_size 0 for a non-empty regular file: reading exactly
    // st_size would return an empty (and "successful") body — the same shape
    // as a file that grew between fstat and read.
    posix::Fd proc_self{::open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    REQUIRE(proc_self.valid());
    const auto whole = posix::read_file_at(proc_self.get(), "status");
    REQUIRE(whole.status == posix::OpenStatus::ok);
    CHECK(whole.bytes.find("Name:") != std::string::npos);

    // Growth past the cap is `oversized` even though st_size (0) was under it.
    const auto capped = posix::read_file_at(proc_self.get(), "status", 16);
    CHECK(capped.status == posix::OpenStatus::failed);
    CHECK(capped.detail == "oversized");
}
#endif // defined(__linux__)

#endif // !defined(_WIN32)
