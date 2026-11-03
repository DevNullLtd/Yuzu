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

#include "scope_engine.hpp"
#include "scope_yaml.hpp"
#include "yaml_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

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
