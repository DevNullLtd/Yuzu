/**
 * test_scope_yaml.cpp — the scope-walking YAML DSL surface (PR-E).
 *
 * Covers parse_scope_block / validate_scope_block / lower_scope_block: the
 * `spec.scope` parsing, the design §7 validation rules, and lowering to a
 * scope-engine expression string (including the round-trip back through
 * yuzu::scope::parse). The dispatch-time alias/owner-check helpers
 * (resolve_scope_aliases, scope_refs_failing_owner_check) are exercised in
 * test_scope_walking_authz.cpp where a live ResultSetStore is available.
 */

#include "instruction_store.hpp"
#include "scope_engine.hpp"
#include "scope_yaml.hpp"
#include "yaml_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// A full definition document wrapping a `spec.scope` block, so parse_scope_block
// exercises the real spec.scope path.
std::string doc(const std::string& scope_and_assignment) {
    return "apiVersion: yuzu.io/v1alpha1\n"
           "kind: InstructionDefinition\n"
           "metadata:\n"
           "  name: t\n"
           "spec:\n" +
           scope_and_assignment;
}

} // namespace

TEST_CASE("scope_yaml: lower fromResultSet alone", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "rs_abc";
    CHECK(lower_scope_block(sb) == "from_result_set:rs_abc");
}

TEST_CASE("scope_yaml: lower alias passes through verbatim", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "windows-chrome-suspects";
    // Aliases are resolved later, at dispatch; lowering keeps the raw ref.
    CHECK(lower_scope_block(sb) == "from_result_set:windows-chrome-suspects");
}

TEST_CASE("scope_yaml: lower selector.platform lower-cases the value", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_selector = true;
    sb.selector_platform = "Windows";
    CHECK(lower_scope_block(sb) == "ostype == \"windows\"");
}

TEST_CASE("scope_yaml: lower selector.tags as EXISTS (presence, not == true)", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_selector = true;
    sb.selector_tags = {"prod", "edge"};
    CHECK(lower_scope_block(sb) == "EXISTS tag:prod AND EXISTS tag:edge");
}

TEST_CASE("scope_yaml: lower full composition AND-joins fromResultSet + platform + tags",
          "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "rs_x";
    sb.has_selector = true;
    sb.selector_platform = "windows";
    sb.selector_tags = {"prod"};
    CHECK(lower_scope_block(sb) ==
          "from_result_set:rs_x AND ostype == \"windows\" AND EXISTS tag:prod");
}

TEST_CASE("scope_yaml: lower empty block yields empty string", "[scope][dsl]") {
    CHECK(lower_scope_block(ScopeBlock{}).empty());
}

TEST_CASE("scope_yaml: parse a fromResultSet + selector mapping", "[scope][dsl]") {
    auto sb = parse_scope_block(doc("  scope:\n"
                                    "    fromResultSet: rs_abc\n"
                                    "    selector:\n"
                                    "      platform: windows\n"
                                    "      tags:\n"
                                    "        - prod\n"
                                    "        - edge\n"));
    CHECK(sb.has_from_result_set);
    CHECK(sb.from_result_set == "rs_abc");
    CHECK(sb.has_selector);
    CHECK(sb.selector_platform == "windows");
    REQUIRE(sb.selector_tags.size() == 2);
    CHECK(sb.selector_tags[0] == "prod");
    CHECK(sb.selector_tags[1] == "edge");
}

TEST_CASE("scope_yaml: parse a quoted alias", "[scope][dsl]") {
    auto sb = parse_scope_block(doc("  scope:\n"
                                    "    fromResultSet: \"windows-chrome-suspects\"\n"));
    CHECK(sb.has_from_result_set);
    CHECK(sb.from_result_set == "windows-chrome-suspects");
    CHECK_FALSE(sb.has_selector);
}

TEST_CASE("scope_yaml: a scalar scope: is NOT a block (backward compat)", "[scope][dsl]") {
    // The common form — a raw scope-engine expression — must yield an empty
    // block so the caller uses the scalar verbatim.
    auto sb = parse_scope_block(doc("  scope: tag:env == \"prod\"\n"));
    CHECK_FALSE(sb.has_from_result_set);
    CHECK_FALSE(sb.has_selector);
    CHECK(lower_scope_block(sb).empty());
}

TEST_CASE("scope_yaml: validate accepts selector-only / empty blocks", "[scope][dsl]") {
    CHECK_FALSE(validate_scope_block(ScopeBlock{}, "", false).has_value());

    ScopeBlock selector_only;
    selector_only.has_selector = true;
    selector_only.selector_platform = "linux";
    CHECK_FALSE(validate_scope_block(selector_only, "", false).has_value());
}

TEST_CASE("scope_yaml: validate rule 1 — fromResultSet + managementGroups is rejected",
          "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "rs_x";
    auto err = validate_scope_block(sb, /*mode=*/"static", /*has_mgmt=*/true);
    REQUIRE(err.has_value());
    // Pin the full discriminator, not just the word (qe-1).
    CHECK(err->find("cannot be combined with assignment.managementGroups") != std::string::npos);
}

TEST_CASE("scope_yaml: validate rule 2 — fromResultSet requires static mode", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "rs_x";

    SECTION("dynamic is rejected") {
        auto err = validate_scope_block(sb, "dynamic", false);
        REQUIRE(err.has_value());
        CHECK(err->find("requires assignment.mode: static") != std::string::npos);
    }
    SECTION("static is accepted") {
        CHECK_FALSE(validate_scope_block(sb, "static", false).has_value());
    }
    SECTION("an omitted mode defaults to static (accepted)") {
        CHECK_FALSE(validate_scope_block(sb, "", false).has_value());
    }
}

TEST_CASE("scope_yaml: validate rejects an empty or over-long fromResultSet", "[scope][dsl]") {
    ScopeBlock empty_ref;
    empty_ref.has_from_result_set = true; // key present, value blank
    CHECK(validate_scope_block(empty_ref, "", false).has_value());

    ScopeBlock long_ref;
    long_ref.has_from_result_set = true;
    long_ref.from_result_set = std::string(129, 'a');
    CHECK(validate_scope_block(long_ref, "", false).has_value());
}

TEST_CASE("scope_yaml: validate rejects selector/ref values that would inject or break grammar",
          "[scope][dsl]") {
    // sec-L1 / dsl-S1: selector and ref values are interpolated into the lowered
    // scope string; anything outside the scope-ident charset is rejected so the
    // result is a single well-formed token, never injectable or unparseable.
    SECTION("platform with an embedded quote (injection) is rejected") {
        ScopeBlock sb;
        sb.has_selector = true;
        sb.selector_platform = "windows\" OR ostype == \"linux";
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("selector.platform") != std::string::npos);
    }
    SECTION("a tag with a space (would break EXISTS tag:) is rejected") {
        ScopeBlock sb;
        sb.has_selector = true;
        sb.selector_tags = {"my tag"};
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("selector.tags") != std::string::npos);
    }
    SECTION("a fromResultSet ref with a space (alias dsl-S2) is rejected") {
        ScopeBlock sb;
        sb.has_from_result_set = true;
        sb.from_result_set = "my suspects";
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("fromResultSet") != std::string::npos);
    }
    SECTION("clean selector + ref values pass") {
        ScopeBlock sb;
        sb.has_selector = true;
        sb.selector_platform = "windows";
        sb.selector_tags = {"prod", "edge-1"};
        sb.has_from_result_set = true;
        sb.from_result_set = "windows-chrome-suspects";
        CHECK_FALSE(validate_scope_block(sb, "static", false).has_value());
    }
}

TEST_CASE("scope_yaml: rule 3 — a definition carrying an expired-looking ref is valid YAML",
          "[scope][dsl]") {
    // Resolution is deferred to dispatch; load-time only checks shape. An id
    // that may have been GC'd is still structurally valid.
    auto sb = parse_scope_block(doc("  scope:\n"
                                    "    fromResultSet: rs_0deadbeef\n"));
    CHECK_FALSE(validate_scope_block(sb, "", false).has_value());
}

TEST_CASE("scope_yaml: lowered expression re-parses through the scope engine", "[scope][dsl]") {
    ScopeBlock sb;
    sb.has_from_result_set = true;
    sb.from_result_set = "rs_x";
    sb.has_selector = true;
    sb.selector_platform = "windows";
    sb.selector_tags = {"prod", "edge"};
    auto lowered = lower_scope_block(sb);
    auto parsed = yuzu::scope::parse(lowered);
    INFO("lowered = " << lowered);
    CHECK(parsed.has_value());
}

// ── #2123 regression pins: the fail-open shape end to end ───────────────────
//
// A blank or comment line inside `selector:` used to end the block early
// under CRLF/lone-CR endings (and for comment lines, under LF too), dropping
// `tags:` and lowering to `ostype == "windows"`: every Windows device instead
// of Windows devices tagged prod.

namespace {

std::string with_eol(const std::string& lf, const std::string& eol) {
    std::string out;
    for (char c : lf) {
        if (c == '\n')
            out += eol;
        else
            out += c;
    }
    return out;
}

const std::string kWant = "ostype == \"windows\" AND EXISTS tag:prod";

} // namespace

TEST_CASE("scope_yaml: a blank line inside selector keeps every predicate (#2123)",
          "[scope][dsl]") {
    const std::string lf = doc("  scope:\n"
                               "    selector:\n"
                               "      platform: windows\n"
                               "\n"
                               "      tags:\n"
                               "        - prod\n");
    SECTION("LF") {
        CHECK(lower_scope_block(parse_scope_block(lf)) == kWant);
    }
    SECTION("CRLF") {
        CHECK(lower_scope_block(parse_scope_block(with_eol(lf, "\r\n"))) == kWant);
    }
    SECTION("lone CR") {
        CHECK(lower_scope_block(parse_scope_block(with_eol(lf, "\r"))) == kWant);
    }
    SECTION("mixed: one CRLF blank line in an LF document") {
        std::string mixed = lf;
        mixed.replace(mixed.find("windows\n\n"), 9, "windows\n\r\n");
        CHECK(lower_scope_block(parse_scope_block(mixed)) == kWant);
    }
    SECTION("whitespace-then-CR blank line shallower than the block") {
        std::string d = lf;
        d.replace(d.find("windows\n\n"), 9, "windows\n  \r\n");
        CHECK(lower_scope_block(parse_scope_block(d)) == kWant);
    }
}

TEST_CASE("scope_yaml: a comment line inside selector keeps every predicate (#2123)",
          "[scope][dsl]") {
    const std::string d = doc("  scope:\n"
                              "    selector:\n"
                              "      platform: windows\n"
                              "# narrow to prod\n"
                              "      tags:\n"
                              "        - prod\n");
    CHECK(lower_scope_block(parse_scope_block(d)) == kWant);
}

TEST_CASE("scope_yaml: a commented-out tags key does not replace the real one (#2123)",
          "[scope][dsl]") {
    const std::string d = doc("  scope:\n"
                              "    selector:\n"
                              "      platform: windows\n"
                              "      # tags: [lab]\n"
                              "      tags: [prod]\n");
    CHECK(lower_scope_block(parse_scope_block(d)) == kWant);
}

TEST_CASE("scope_yaml: CRLF blank line inside spec.assignment keeps rule 1 enforced (#2123)",
          "[scope][dsl]") {
    // Pre-fix the truncated assignment block hid managementGroups from
    // validate_scope_block, so fromResultSet + managementGroups passed.
    const std::string d = with_eol(doc("  scope:\n"
                                       "    fromResultSet: rs_abc\n"
                                       "  assignment:\n"
                                       "    mode: static\n"
                                       "\n"
                                       "    managementGroups:\n"
                                       "      - g1\n"),
                                   "\r\n");
    auto sb = parse_scope_block(d);
    REQUIRE(sb.has_from_result_set);
    auto asn = yuzu::server::yaml_scan::extract_yaml_section(d, "spec.assignment");
    auto err = validate_scope_block(
        sb, yuzu::server::yaml_scan::extract_yaml_value(asn, "mode"),
        !yuzu::server::yaml_scan::extract_yaml_list(asn, "managementGroups").empty());
    CHECK(err.has_value());
}

TEST_CASE("scope_yaml: a misindented tag item is rejected and never lowered without it (#2123)",
          "[scope][dsl]") {
    // Governance G2-SEC-F1 / G3-DSL-F1: the scanner keeps a misplaced `- prod`
    // as a raw item; validation must reject it rather than lower the scope to
    // the platform alone.
    for (const std::string items : {
             "     - prod\n",                  // shallower than tags:
             "        - a\n       - prod\n",   // between columns
             "        - a\n          - prod\n" // deeper - line
         }) {
        INFO("items:\n" << items);
        auto sb = parse_scope_block(doc("  scope:\n"
                                        "    selector:\n"
                                        "      platform: windows\n"
                                        "      tags:\n" +
                                        items));
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("tags") != std::string::npos);
        CHECK(err->find("indentation") != std::string::npos);
    }
}

TEST_CASE("scope_yaml: an unclosed inline tag list names the opening bracket (#2123)",
          "[scope][dsl]") {
    auto sb = parse_scope_block(doc("  scope:\n"
                                    "    selector:\n"
                                    "      platform: windows\n"
                                    "      tags: [prod,\n"
                                    "        staging]\n"));
    auto err = validate_scope_block(sb, "", false);
    REQUIRE(err.has_value());
    CHECK(err->find("same line") != std::string::npos);
}

// ── #2123 governance Gate 5 CH-1: metamorphic differential over the scope block ──
//
// For every seed selector, two families of mutation:
//   - meaning-PRESERVING (YAML reads the same thing): CRLF / lone-CR / mixed line
//     endings, a blank line or a comment line inserted at every line boundary
//     and every indent. The lowered scope must equal the seed's exactly.
//   - meaning-BREAKING (invalid or different YAML): a `-` item moved one column
//     either way, a flow list wrapped across lines. The scope must then be
//     REJECTED, or still carry every seed tag — never lowered without one,
//     because a dropped tag widens the policy to more devices.
// No YAML library is needed: the oracle is the seed's own lowering.

namespace {

std::vector<std::string> lines_of(const std::string& lf) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : lf) {
        if (c == '\n') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty())
        out.push_back(cur);
    return out;
}

std::string join_lines(const std::vector<std::string>& ls, const std::string& eol) {
    std::string out;
    for (const auto& l : ls)
        out += l + eol;
    return out;
}

struct Seed {
    std::string scope; // the `  scope:` block, LF
    std::vector<std::string> tags;
};

const Seed kSeeds[] = {
    {"  scope:\n    selector:\n      platform: windows\n      tags:\n        - prod\n"
     "        - pci\n",
     {"prod", "pci"}},
    {"  scope:\n    selector:\n      tags:\n        - a\n        - b\n        - c\n"
     "      platform: linux\n",
     {"a", "b", "c"}},
    {"  scope:\n    selector:\n      platform: darwin\n      tags: [edge, lab]\n", {"edge", "lab"}},
    {"  scope:\n    selector:\n      tags:\n      - compact\n      - form\n", {"compact", "form"}},
};

} // namespace

TEST_CASE("scope_yaml: meaning-preserving mutations lower exactly like the seed (#2123 CH-1)",
          "[scope][dsl]") {
    int checked = 0;
    for (const auto& seed : kSeeds) {
        const auto want = lower_scope_block(parse_scope_block(doc(seed.scope)));
        REQUIRE(want.find("tag:" + seed.tags.front()) != std::string::npos);
        const auto ls = lines_of(seed.scope);
        std::vector<std::string> variants;
        for (const std::string eol : {"\n", "\r\n", "\r"})
            variants.push_back(join_lines(ls, eol));
        {
            std::string mixed;
            for (std::size_t i = 0; i < ls.size(); ++i)
                mixed += ls[i] + (i % 3 == 0 ? "\r\n" : i % 3 == 1 ? "\r" : "\n");
            variants.push_back(mixed);
        }
        // A blank or comment line after line i (i >= 1, so it never precedes
        // `scope:` itself), at every indent from 0 to 10.
        for (std::size_t i = 1; i < ls.size(); ++i) {
            for (std::size_t indent = 0; indent <= 10; indent += 1) {
                for (const std::string body : {"", "# note - with a hyphen, and: a colon"}) {
                    auto m = ls;
                    m.insert(m.begin() + static_cast<std::ptrdiff_t>(i) + 1,
                             std::string(indent, ' ') + body);
                    for (const std::string eol : {"\n", "\r\n", "\r"})
                        variants.push_back(join_lines(m, eol));
                }
            }
        }
        for (const auto& v : variants) {
            INFO("variant:\n" << v);
            auto sb = parse_scope_block(doc(v));
            CHECK_FALSE(validate_scope_block(sb, "", false).has_value());
            CHECK(lower_scope_block(sb) == want);
            ++checked;
        }
    }
    CHECK(checked > 500);
}

TEST_CASE("scope_yaml: meaning-breaking mutations are rejected or keep every tag (#2123 CH-1)",
          "[scope][dsl]") {
    int checked = 0;
    for (const auto& seed : kSeeds) {
        const auto ls = lines_of(seed.scope);
        std::vector<std::string> variants;
        for (std::size_t i = 0; i < ls.size(); ++i) {
            const auto fc = ls[i].find_first_not_of(' ');
            if (fc == std::string::npos || ls[i][fc] != '-')
                continue;
            for (int shift : {-1, +1}) {
                if (shift < 0 && fc == 0)
                    continue;
                auto m = ls;
                m[i] = shift > 0 ? " " + ls[i] : ls[i].substr(1);
                for (const std::string eol : {"\n", "\r\n", "\r"})
                    variants.push_back(join_lines(m, eol));
            }
        }
        // Wrap an inline list across two lines.
        for (std::size_t i = 0; i < ls.size(); ++i) {
            const auto comma = ls[i].find(", ");
            if (ls[i].find('[') == std::string::npos || comma == std::string::npos)
                continue;
            auto m = ls;
            m[i] = ls[i].substr(0, comma + 1);
            m.insert(m.begin() + static_cast<std::ptrdiff_t>(i) + 1,
                     std::string(8, ' ') + ls[i].substr(comma + 2));
            for (const std::string eol : {"\n", "\r\n", "\r"})
                variants.push_back(join_lines(m, eol));
        }
        for (const auto& v : variants) {
            INFO("variant:\n" << v);
            auto sb = parse_scope_block(doc(v));
            if (validate_scope_block(sb, "", false).has_value()) {
                ++checked;
                continue; // rejected: the safe outcome
            }
            // A wrapped inline list is never valid input: it must not be accepted.
            CHECK(v.find("[") == std::string::npos);
            const auto got = lower_scope_block(sb);
            for (const auto& t : seed.tags)
                CHECK(got.find("tag:" + t) != std::string::npos);
            ++checked;
        }
    }
    CHECK(checked > 20);
}

TEST_CASE("validate_definition_scope: CRLF blank and comment lines keep rule 1 enforced (#2123)",
          "[scope][dsl]") {
    // Governance G3-ARCH-F3: the instruction-store validation path had no
    // line-ending test. A blank line used to hide managementGroups from rule 1
    // (fromResultSet + managementGroups is forbidden) on a CRLF definition.
    std::string lf = doc("  scope:\n"
                         "    fromResultSet: rs_abc\n"
                         "  assignment:\n"
                         "    mode: static\n"
                         "\n"
                         "# groups follow\n"
                         "    managementGroups:\n"
                         "      - g1\n");
    for (const std::string eol : {"\n", "\r\n", "\r"}) {
        std::string d;
        for (char c : lf)
            d += (c == '\n') ? eol : std::string(1, c);
        INFO("eol size " << eol.size() << (eol == "\r" ? " (CR)" : ""));
        auto err = validate_definition_scope(d);
        REQUIRE(err.has_value());
        CHECK(err->find("managementGroups") != std::string::npos);
    }
}

TEST_CASE("scope_yaml: a list item outside selector.tags is refused (#2123 Gate 8)",
          "[scope][dsl]") {
    // A `- prod` misindented to selector's own column falls outside the selector
    // block, so tags never saw it and the scope lowered to the platform alone
    // (governance Gate 8 security-guardian F7).
    for (const std::string tail : {"    - prod\n", "   - prod\n"}) {
        INFO("tail: " << tail);
        auto sb = parse_scope_block(doc("  scope:\n"
                                        "    selector:\n"
                                        "      platform: windows\n"
                                        "      tags:\n" +
                                        tail));
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("spec.scope") != std::string::npos);
    }
    // The ordinary block list is untouched.
    auto ok = parse_scope_block(doc("  scope:\n    selector:\n      tags:\n        - prod\n"));
    CHECK_FALSE(validate_scope_block(ok, "", false).has_value());
}

TEST_CASE(
    "scope_yaml: a scalar tags value is refused, never lowered without the tag (#2123 Gate 8)",
    "[scope][dsl]") {
    for (const std::string v :
         {"prod", "\"prod\"", "&t [prod]", "!!seq [prod]", "prod, pci", "\"\""}) {
        INFO("value: " << v);
        auto sb = parse_scope_block(doc("  scope:\n    selector:\n      tags: " + v + "\n"));
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("selector.tags") != std::string::npos);
    }
    // A YAML null is no tags at all, as YAML means.
    auto none = parse_scope_block(
        doc("  scope:\n    selector:\n      platform: windows\n      tags: null\n"));
    CHECK_FALSE(validate_scope_block(none, "", false).has_value());
    CHECK(lower_scope_block(none) == "ostype == \"windows\"");
}

TEST_CASE("scope_yaml: tags null followed by list lines is refused (#2123 Gate 8)",
          "[scope][dsl]") {
    for (const std::string tail :
         {"      tags: null\n        - prod\n", "      tags: [a]\n        - prod\n"}) {
        INFO("tail: " << tail);
        auto sb =
            parse_scope_block(doc("  scope:\n    selector:\n      platform: windows\n" + tail));
        auto err = validate_scope_block(sb, "", false);
        REQUIRE(err.has_value());
        CHECK(err->find("selector.tags") != std::string::npos);
    }
}

TEST_CASE("scope_yaml: the leading-space raw item names the list form to use (#2123 Gate 8)",
          "[scope][dsl]") {
    // Pins the hint text (round 4 consistency-auditor CON-R4-3).
    auto sb = parse_scope_block(doc("  scope:\n    selector:\n      tags: prod\n"));
    auto err = validate_scope_block(sb, "", false);
    REQUIRE(err.has_value());
    CHECK(err->find("write the list as '- item' lines or an inline [a, b] list") !=
          std::string::npos);
}

TEST_CASE("scope_yaml: an item with a space names the single-token rule (#2123 Gate 8)",
          "[scope][dsl]") {
    // Pins the round-5 hint text (round 5 quality-engineer Q5-1: reverting it
    // survived every other test).
    auto sb = parse_scope_block(doc("  scope:\n    selector:\n      tags:\n        - foo bar\n"));
    auto err = validate_scope_block(sb, "", false);
    REQUIRE(err.has_value());
    CHECK(err->find("an item must be a single token") != std::string::npos);
}
