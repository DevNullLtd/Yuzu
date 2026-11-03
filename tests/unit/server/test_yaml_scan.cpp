/**
 * test_yaml_scan.cpp — the runtime YAML line-scanners (yaml_scan.{hpp,cpp}).
 *
 * These hand-rolled scanners were moved verbatim out of policy_store.cpp's
 * anonymous namespace in PR-E and are now load-bearing for scope_yaml's
 * parse_scope_block. They previously had only indirect coverage; these cases
 * pin the behaviour directly, including the adversarial inputs (governance
 * qe-SHOULD-2) that the scope-block parser relies on the scanners to handle.
 */

#include "yaml_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server::yaml_scan;

namespace {

// Re-terminate every LF line with `eol` ("\r\n" or "\r"), so one LF fixture
// yields its CRLF and lone-CR twins byte-for-byte (#2123).
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

// A selector with a blank line between its two children: the #2123 shape.
const std::string kSelectorWithBlank = "spec:\n"
                                       "  scope:\n"
                                       "    selector:\n"
                                       "      platform: windows\n"
                                       "\n"
                                       "      tags:\n"
                                       "        - prod\n";

std::vector<std::string> selector_tags(const std::string& yaml) {
    return extract_yaml_list(extract_yaml_section(yaml, "spec.scope.selector"), "tags");
}

} // namespace

TEST_CASE("yaml_scan: extract_yaml_value scalar / quoted / mapping", "[yaml_scan]") {
    CHECK(extract_yaml_value("name: hello\n", "name") == "hello");
    CHECK(extract_yaml_value("name: \"quoted value\"\n", "name") == "quoted value");
    CHECK(extract_yaml_value("name: 'single'\n", "name") == "single");
    // A key that opens a mapping returns empty (the signal scope_yaml uses to
    // fall through to block parsing).
    CHECK(extract_yaml_value("scope:\n  selector:\n    platform: x\n", "scope").empty());
    // Absent key.
    CHECK(extract_yaml_value("other: y\n", "name").empty());
}

TEST_CASE("yaml_scan: extract_yaml_list block and inline forms", "[yaml_scan]") {
    auto block = extract_yaml_list("tags:\n  - prod\n  - edge\n", "tags");
    REQUIRE(block.size() == 2);
    CHECK(block[0] == "prod");
    CHECK(block[1] == "edge");

    auto inline_form = extract_yaml_list("tags: [a, b, c]\n", "tags");
    REQUIRE(inline_form.size() == 3);
    CHECK(inline_form[0] == "a");
    CHECK(inline_form[2] == "c");
}

TEST_CASE("yaml_scan: extract_yaml_section walks a dotted path", "[yaml_scan]") {
    std::string yaml = "spec:\n"
                       "  scope:\n"
                       "    fromResultSet: rs_x\n"
                       "  assignment:\n"
                       "    mode: static\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK(extract_yaml_value(scope, "fromResultSet") == "rs_x");
    auto asn = extract_yaml_section(yaml, "spec.assignment");
    CHECK(extract_yaml_value(asn, "mode") == "static");
    // A missing path returns empty.
    CHECK(extract_yaml_section(yaml, "spec.nope").empty());
}

TEST_CASE("yaml_scan: yaml_has_key anchors to line starts", "[yaml_scan]") {
    CHECK(yaml_has_key("  fromResultSet: rs_x\n", "fromResultSet"));
    // Present even when the key opens a mapping (where extract_yaml_value is empty).
    CHECK(yaml_has_key("selector:\n  platform: x\n", "selector"));
    CHECK_FALSE(yaml_has_key("other: y\n", "fromResultSet"));
}

TEST_CASE("yaml_scan: yaml_has_key skips comments and is not fooled by substrings",
          "[yaml_scan]") {
    // A commented-out key must not register.
    CHECK_FALSE(yaml_has_key("  # fromResultSet: rs_x\n", "fromResultSet"));
    // A key that is a prefix of a longer key must not match (the colon guards it).
    CHECK_FALSE(yaml_has_key("modeSwitch: x\n", "mode"));
    CHECK(yaml_has_key("mode: static\n", "mode"));
}

TEST_CASE("yaml_scan: extract_yaml_value skips keys inside comments (#1221 MEDIUM-2)",
          "[yaml_scan]") {
    // A whole-line commented key must not be returned, even though its 'key:'
    // token is preceded by whitespace (the old anchor check alone passed it).
    CHECK(extract_yaml_value("  # fromResultSet: rs_evil\n", "fromResultSet").empty());
    // A real key AFTER a commented decoy line wins; the decoy is skipped, not
    // returned (regression guard for the policy scalar-scope footgun).
    CHECK(extract_yaml_value("  # fromResultSet: rs_evil\n  fromResultSet: rs_real\n",
                             "fromResultSet") == "rs_real");
    // An inline trailing comment that mentions a key-like token is not a key.
    CHECK(extract_yaml_value("selector:    # fromResultSet: rs_evil\n  platform: x\n",
                             "fromResultSet")
              .empty());
    // A '#' inside the value (no preceding whitespace) is NOT a comment marker —
    // a legitimate value containing '#' is still returned intact.
    CHECK(extract_yaml_value("channel: prod#1\n", "channel") == "prod#1");
}

TEST_CASE("yaml_scan: extract_yaml_section anchors to line-leading keys (#1215 H-2)",
          "[yaml_scan]") {
    // A `scope:` substring inside a description value must NOT mis-anchor the
    // section walk. Pre-fix, find() matched the substring, mis-computed the
    // indent, and returned an empty block — dropping the real scope (fail-OPEN
    // for policies). The real `scope:` block must still be returned intact.
    std::string yaml = "spec:\n"
                       "  description: \"see scope: foo for details\"\n"
                       "  scope:\n"
                       "    fromResultSet: rs_x\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK(extract_yaml_value(scope, "fromResultSet") == "rs_x");
    // A commented section header must not be anchored to either.
    std::string yaml2 = "# scope: {fromResultSet: rs_evil}\n"
                        "spec:\n"
                        "  scope:\n"
                        "    fromResultSet: rs_real\n";
    auto scope2 = extract_yaml_section(yaml2, "spec.scope");
    CHECK(extract_yaml_value(scope2, "fromResultSet") == "rs_real");
}

TEST_CASE("yaml_scan: a commented inline-mapping scope: line is not extracted (#1215 H-1)",
          "[yaml_scan]") {
    // validate_definition_scope reads extract_yaml_value(yaml, "scope") to detect
    // the inline flow-mapping form. A *commented* `# scope: {...}` line must not
    // be picked up, or a legitimate definition keeping sample YAML in a comment
    // is falsely rejected. The real mapping scope: opens a block → returns empty.
    std::string yaml = "# scope: {fromResultSet: rs_evil}\n"
                       "spec:\n"
                       "  scope:\n"
                       "    fromResultSet: rs_abc\n";
    CHECK(extract_yaml_value(yaml, "scope").empty());
}

TEST_CASE("yaml_scan: a key inside a quoted value does not leak into a sibling section",
          "[yaml_scan]") {
    // Adversarial: 'fromResultSet' appears inside a description value, NOT as a
    // real scope key. After isolating spec.scope, it must not be visible.
    std::string yaml = "spec:\n"
                       "  description: \"mentions fromResultSet: rs_secret in prose\"\n"
                       "  scope:\n"
                       "    selector:\n"
                       "      platform: windows\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK_FALSE(yaml_has_key(scope, "fromResultSet"));
    CHECK(yaml_has_key(scope, "selector"));
}

// ── #2123: line endings, blank lines, comment lines ─────────────────────────
//
// Every case below asserts the LF result. Pre-fix the scanners split on '\n'
// only, so a CRLF blank line ("\r") read as a non-blank line at column 0 and
// ended the block early. For a policy that drops the later scope predicates
// and the policy targets MORE devices than its YAML says (fail-open).

TEST_CASE("yaml_scan: LF baseline for the #2123 selector shape", "[yaml_scan]") {
    auto tags = selector_tags(kSelectorWithBlank);
    REQUIRE(tags.size() == 1);
    CHECK(tags[0] == "prod");
}

TEST_CASE("yaml_scan: a CRLF blank line does not truncate a section (#2123)", "[yaml_scan]") {
    const auto crlf = with_eol(kSelectorWithBlank, "\r\n");
    CHECK(extract_yaml_value(extract_yaml_section(crlf, "spec.scope.selector"), "platform") ==
          "windows");
    auto tags = selector_tags(crlf);
    REQUIRE(tags.size() == 1);
    CHECK(tags[0] == "prod");
}

TEST_CASE("yaml_scan: one CRLF blank line in an LF document (mixed endings) (#2123)",
          "[yaml_scan]") {
    std::string mixed = kSelectorWithBlank;
    mixed.replace(mixed.find("windows\n\n"), 9, "windows\n\r\n");
    auto tags = selector_tags(mixed);
    REQUIRE(tags.size() == 1);
    CHECK(tags[0] == "prod");
}

TEST_CASE("yaml_scan: a lone CR is a line break (#2123)", "[yaml_scan]") {
    SECTION("whole document with lone-CR endings") {
        auto tags = selector_tags(with_eol(kSelectorWithBlank, "\r"));
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("one lone CR inside an LF document") {
        std::string doc = kSelectorWithBlank;
        doc.replace(doc.find("windows\n\n"), 9, "windows\n\r");
        auto tags = selector_tags(doc);
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
}

TEST_CASE("yaml_scan: a whitespace-then-CR blank line shallower than the block (#2123)",
          "[yaml_scan]") {
    std::string doc = kSelectorWithBlank;
    doc.replace(doc.find("windows\n\n"), 9, "windows\n  \r\n");
    auto tags = selector_tags(doc);
    REQUIRE(tags.size() == 1);
    CHECK(tags[0] == "prod");
}

TEST_CASE("yaml_scan: trailing whitespace is harmless - guard that passes pre-fix", "[yaml_scan]") {
    SECTION("on every content line") {
        auto tags = selector_tags(with_eol(kSelectorWithBlank, "   \n"));
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("a whitespace-only blank line shallower than the block") {
        std::string doc = kSelectorWithBlank;
        doc.replace(doc.find("windows\n\n"), 9, "windows\n  \n");
        auto tags = selector_tags(doc);
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
}

TEST_CASE("yaml_scan: a comment line inside a block does not end it (#2123)", "[yaml_scan]") {
    // YAML comment lines take no part in indentation. Pre-fix these truncate
    // even with plain LF endings.
    SECTION("comment at column 0") {
        std::string doc = kSelectorWithBlank;
        doc.replace(doc.find("windows\n\n"), 9, "windows\n# narrow to prod\n");
        auto tags = selector_tags(doc);
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("comment indented less than the block") {
        std::string doc = kSelectorWithBlank;
        doc.replace(doc.find("windows\n\n"), 9, "windows\n  # prod only\n");
        auto tags = selector_tags(doc);
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("comment at column 0, CRLF") {
        std::string doc = kSelectorWithBlank;
        doc.replace(doc.find("windows\n\n"), 9, "windows\n# narrow to prod\n");
        auto tags = selector_tags(with_eol(doc, "\r\n"));
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
}

TEST_CASE("yaml_scan: extract_yaml_mapping across blank and comment lines (#2123)", "[yaml_scan]") {
    const std::string lf = "spec:\n"
                           "  check:\n"
                           "    instruction: x\n"
                           "    parameters:\n"
                           "      a: 1\n"
                           "\n"
                           "      b: 2\n";
    auto count = [](const std::string& doc) {
        return extract_yaml_mapping(extract_yaml_section(doc, "spec.check"), "parameters").size();
    };
    CHECK(count(lf) == 2);
    CHECK(count(with_eol(lf, "\r\n")) == 2);
    CHECK(count(with_eol(lf, "\r")) == 2);

    std::string commented = lf;
    commented.replace(commented.find("1\n\n"), 3, "1\n# second parameter\n");
    CHECK(count(commented) == 2);
}

TEST_CASE("yaml_scan: extract_yaml_list across blank lines (#2123)", "[yaml_scan]") {
    const std::string between = "groups:\n  - g1\n\n  - g2\n";
    CHECK(extract_yaml_list(between, "groups").size() == 2);
    CHECK(extract_yaml_list(with_eol(between, "\r\n"), "groups").size() == 2);
    CHECK(extract_yaml_list(with_eol(between, "\r"), "groups").size() == 2);

    const std::string before_first = "groups:\n\n  - g1\n";
    CHECK(extract_yaml_list(with_eol(before_first, "\r\n"), "groups").size() == 1);
}

TEST_CASE("yaml_scan: a commented-out key before the real one is not matched (#2123)",
          "[yaml_scan]") {
    // yaml_scan.hpp's SECURITY CONTRACT: lookups anchor to real, line-leading
    // keys. Pre-fix extract_yaml_list and extract_yaml_mapping used a bare
    // find(), so the commented key won and the policy targeted tag:lab.
    SECTION("extract_yaml_list") {
        const std::string sel = "      platform: windows\n"
                                "      # tags: [lab]\n"
                                "      tags: [prod]\n";
        auto tags = extract_yaml_list(sel, "tags");
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("extract_yaml_list, inline comment carrying the key") {
        const std::string sel = "      platform: windows  # tags: [lab]\n"
                                "      tags: [prod]\n";
        auto tags = extract_yaml_list(sel, "tags");
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("extract_yaml_list, key that is a superstring") {
        const std::string sel = "      extratags: [lab]\n"
                                "      tags: [prod]\n";
        auto tags = extract_yaml_list(sel, "tags");
        REQUIRE(tags.size() == 1);
        CHECK(tags[0] == "prod");
    }
    SECTION("extract_yaml_mapping") {
        const std::string check = "    # parameters:\n"
                                  "    #   evil: 1\n"
                                  "    parameters:\n"
                                  "      real: 2\n";
        auto m = extract_yaml_mapping(check, "parameters");
        REQUIRE(m.size() == 1);
        CHECK(m[0].first == "real");
    }
}

// ── #2123 security review: list extent ──────────────────────────────────────
//
// managementGroups is a UNION (an extra id widens targeting) while selector
// tags are AND-ed (an extra tag narrows, a dropped one widens). So a block
// list must neither absorb items from an outer/sibling list nor end early on
// a line that still belongs to it.

namespace {
std::vector<std::string> groups(const std::string& doc) {
    return extract_yaml_list(doc, "managementGroups");
}
using Items = std::vector<std::string>;
} // namespace

TEST_CASE("yaml_scan: a block list does not absorb an outer list's items (#2123)", "[yaml_scan]") {
    SECTION("managementGroups as the last key of an outer list item") {
        CHECK(groups("spec:\n"
                     "  things:\n"
                     "    - name: a\n"
                     "      managementGroups:\n"
                     "        - g1\n"
                     "    - g2\n") == Items{"g1"});
    }
    SECTION("dedented item after a blank line, CRLF") {
        CHECK(groups(with_eol("spec:\n"
                              "  assignment:\n"
                              "    managementGroups:\n"
                              "      - g1\n"
                              "\n"
                              "  - g2\n",
                              "\r\n")) == Items{"g1"});
    }
    SECTION("dedented item after blank and comment lines, LF") {
        CHECK(groups("spec:\n"
                     "  assignment:\n"
                     "    managementGroups:\n"
                     "      - g1\n"
                     "\n"
                     "      # c\n"
                     "  - g2\n") == Items{"g1"});
    }
    SECTION("a document separator ends the list") {
        CHECK(groups("spec:\n"
                     "  assignment:\n"
                     "    managementGroups:\n"
                     "      - g1\n"
                     "---\n"
                     "kind: X\n") == Items{"g1"});
        CHECK(groups("managementGroups:\n- g1\n---\n- g2\n") == Items{"g1"});
        CHECK(groups("managementGroups:\n- g1\n...\n") == Items{"g1"});
    }
}

TEST_CASE("yaml_scan: compact (same-indent) block lists still parse (#2123)", "[yaml_scan]") {
    CHECK(groups("managementGroups:\n- g1\n- g2\nnext: x\n") == Items{"g1", "g2"});
    CHECK(extract_yaml_list("- name: a\n  tags:\n  - x\n- y\n", "tags") == Items{"x"});
}

TEST_CASE("yaml_scan: a block list does not end early inside itself (#2123)", "[yaml_scan]") {
    // Ending early would drop later tags, and a dropped tag widens a scope.
    SECTION("a deeper continuation line is skipped, not a terminator") {
        CHECK(extract_yaml_list("tags:\n  - prod\n    extra\n  - pci\n", "tags") ==
              Items{"prod", "pci"});
    }
    SECTION("an item written -b (no space) is still read (lock: passes pre-fix)") {
        CHECK(extract_yaml_list("tags:\n  - a\n  -b\n  - c\n", "tags") == Items{"a", "b", "c"});
    }
}

TEST_CASE("yaml_scan: an inline list's ] is searched on the key's line only (#2123)",
          "[yaml_scan]") {
    // A comment inside a multi-line flow list, or an unterminated one, must
    // never contribute ids. With no ] on the key's line the raw value is
    // returned as ONE item: a tag containing '[' fails validate_scope_block's
    // charset (the policy is rejected), and a group id containing '[' matches
    // no group. Returning an EMPTY list instead would silently drop every tag.
    SECTION("leading-comma multi-line list with a comment") {
        CHECK(groups("managementGroups: [g1,  # canary, prod\n  , g2]\n") == Items{"[g1,"});
    }
    SECTION("comma inside a comment") {
        CHECK(groups("managementGroups: [g1,  # canary, prod-all,\n  g2]\n") == Items{"[g1,"});
    }
    SECTION("unterminated list followed by another key's inline list") {
        CHECK(groups("spec:\n"
                     "  assignment:\n"
                     "    managementGroups: [g1\n"
                     "  triggers: [x, prod-all]\n") == Items{"[g1"});
    }
    SECTION("single-line list with a trailing comment (lock: passes pre-fix)") {
        CHECK(groups("managementGroups: [g1, g2] # x, y\n") == Items{"g1", "g2"});
    }
}
