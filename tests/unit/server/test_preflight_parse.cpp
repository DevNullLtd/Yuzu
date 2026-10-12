/**
 * test_preflight_parse.cpp — unit coverage for the `/auto` Pre-flight PURE parse +
 * verdict layer (server/core/src/preflight_parse.hpp).
 *
 * This is the durable artifact: the dispatch bypasses the Instruction Engine, so
 * the server reads RAW pipe output by field index and applies the operator's
 * thresholds to it. These tests pin (1) the discriminator + field layout for each
 * check against the EXACT strings the plugins emit, and (2) the threshold→verdict
 * logic, so a plugin output change or an off-by-one threshold fails here instead of
 * rendering a wrong go/no-go.
 */

#include "preflight_parse.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server::preflight;

TEST_CASE("split_pipe / find_row basics", "[preflight][parse]") {
    auto f = split_pipe("disk|C:\\|100|40|60");
    REQUIRE(f.size() == 5);
    CHECK(f[0] == "disk");
    CHECK(f[4] == "60");

    const std::string multi = "os_version|10.0.22631\r\nos_product_version|24H2\r\n";
    auto r = find_row(multi, "os_version");
    REQUIRE(r);
    CHECK((*r)[1] == "10.0.22631"); // NOT the os_product_version sibling row
    CHECK_FALSE(find_row(multi, "absent").has_value());
}

TEST_CASE("cmp_version dotted-numeric semantics", "[preflight][parse]") {
    CHECK(cmp_version("4.2.0", "4.2.0") == 0);
    CHECK(cmp_version("4.1.0", "4.2.0") < 0);
    CHECK(cmp_version("4.2.1", "4.2.0") > 0);
    CHECK(cmp_version("4.2", "4.2.0") == 0);          // missing components = 0
    CHECK(cmp_version("10.0.22631", "10.0.19045") > 0); // Windows build compare
    CHECK(cmp_version("10.0.17763", "10.0.19045") < 0);
}

TEST_CASE("extract_cell display values", "[preflight][parse]") {
    CHECK(extract_cell("osver", "os_version|10.0.22631\nos_product_version|24H2") == "10.0.22631");
    CHECK(extract_cell("osarch", "os_arch|x86_64") == "x86_64");
    CHECK(extract_cell("reboot", "cbs_reboot|true|CBS\nreboot_required|true|CBS") == "yes");
    CHECK(extract_cell("reboot", "reboot_required|false|") == "no");
    CHECK(extract_cell("disk", "disk|C:\\|511056015360|61024096256|87") == "56.8 GiB free (87% used)");
    // app: found + version, or honest "(not installed)"
    CHECK(extract_cell("app", "found|true\napp|AcmeVPN|4.2.0|Acme") == "4.2.0");
    CHECK(extract_cell("app", "found|false") == "(not installed)");
    CHECK_FALSE(extract_cell("disk", "disk|C:\\|100").has_value()); // too few fields
}

TEST_CASE("evaluate app: presence + min version", "[preflight][verdict]") {
    PreflightConfig cfg;
    cfg.app_name = "AcmeVPN";
    cfg.app_min_version = "4.2.0";
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|4.2.0|Acme", cfg) == Verdict::kPass);
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|4.1.0|Acme", cfg) == Verdict::kFail);
    CHECK(evaluate("app", "found|false", cfg) == Verdict::kFail); // not installed
    CHECK(evaluate("app", "", cfg) == Verdict::kUnknown);         // no response yet
    // presence-only when no min set
    cfg.app_min_version.clear();
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|1.0.0|Acme", cfg) == Verdict::kPass);
}

TEST_CASE("evaluate app: max version ceiling", "[preflight][verdict]") {
    PreflightConfig cfg;
    cfg.app_name = "AcmeVPN";
    cfg.app_min_version = "4.2.0";
    cfg.app_max_version = "4.9.99";
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|4.2.0|Acme", cfg) == Verdict::kPass);  // floor
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|4.9.99|Acme", cfg) == Verdict::kPass); // ceiling
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|5.0.0|Acme", cfg) == Verdict::kFail);  // over ceiling
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|4.1.0|Acme", cfg) == Verdict::kFail);  // under floor
    // max-only (no floor): below the ceiling passes, above fails.
    cfg.app_min_version.clear();
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|1.0.0|Acme", cfg) == Verdict::kPass);
    CHECK(evaluate("app", "found|true\napp|AcmeVPN|5.0.0|Acme", cfg) == Verdict::kFail);
}

TEST_CASE("classify_device bucket precedence", "[preflight][verdict]") {
    using V = Verdict;
    // Failed wins over everything.
    CHECK(classify_device({V::kPass, V::kFail, V::kUnknown, V::kWarn}) == Bucket::kFailed);
    // No fail, but an unknown → incomplete (beats a warn).
    CHECK(classify_device({V::kPass, V::kWarn, V::kUnknown}) == Bucket::kIncomplete);
    // No fail / no unknown, a warn → warn-only.
    CHECK(classify_device({V::kPass, V::kWarn, V::kPass}) == Bucket::kWarnOnly);
    // All pass → pass.
    CHECK(classify_device({V::kPass, V::kPass}) == Bucket::kPass);
    // Empty (no checks applicable) → pass (vacuous).
    CHECK(classify_device({}) == Bucket::kPass);
}

TEST_CASE("evaluate os version + arch thresholds", "[preflight][verdict]") {
    PreflightConfig cfg;
    cfg.os_min_version = "10.0.19045";
    CHECK(evaluate("osver", "os_version|10.0.22631", cfg) == Verdict::kPass);
    CHECK(evaluate("osver", "os_version|10.0.17763", cfg) == Verdict::kFail);
    CHECK(evaluate("osver", "garbage|x", cfg) == Verdict::kUnknown);

    cfg.req_arch = "x86_64";
    CHECK(evaluate("osarch", "os_arch|x86_64", cfg) == Verdict::kPass);
    CHECK(evaluate("osarch", "os_arch|arm64", cfg) == Verdict::kFail);
    cfg.req_arch = "any";
    CHECK(evaluate("osarch", "os_arch|arm64", cfg) == Verdict::kPass);
}

TEST_CASE("evaluate free disk threshold (GiB)", "[preflight][verdict]") {
    PreflightConfig cfg;
    cfg.min_free_gib = 20;
    // 61024096256 bytes ≈ 56.8 GiB ≥ 20 → pass
    CHECK(evaluate("disk", "disk|C:\\|511056015360|61024096256|87", cfg) == Verdict::kPass);
    // ~12.1 GiB < 20 → fail
    CHECK(evaluate("disk", "disk|C:\\|511056015360|13000000000|97", cfg) == Verdict::kFail);
    CHECK(evaluate("disk", "disk|C:\\|1", cfg) == Verdict::kUnknown); // malformed
}

TEST_CASE("evaluate pending reboot block vs warn", "[preflight][verdict]") {
    PreflightConfig cfg;
    cfg.reboot_block = true;
    CHECK(evaluate("reboot", "reboot_required|false|", cfg) == Verdict::kPass);
    CHECK(evaluate("reboot", "reboot_required|true|CBS", cfg) == Verdict::kFail);
    cfg.reboot_block = false; // warn-only
    CHECK(evaluate("reboot", "reboot_required|true|CBS", cfg) == Verdict::kWarn);
    CHECK(evaluate("reboot", "reboot_required|false|", cfg) == Verdict::kPass);
    CHECK(evaluate("reboot", "no_summary|x", cfg) == Verdict::kUnknown);
}

TEST_CASE("format_gib / parse_i64 edges", "[preflight][parse]") {
    CHECK(format_gib(1073741824) == "1.0 GiB");
    CHECK(format_gib(-1) == "?");
    CHECK(parse_i64("00042") == 42);
    CHECK(parse_i64("12abc") == 12);
    CHECK(parse_i64("") == 0);
}

TEST_CASE("parse_i64 / format_gib saturate, not overflow (operator input, UP-2)", "[preflight][parse]") {
    constexpr std::int64_t kMax = 9223372036854775807LL; // INT64_MAX
    // A long numeric (operator's min_gib/window/version string) must saturate, not
    // wrap via signed-overflow UB.
    CHECK(parse_i64("99999999999999999999999999") == kMax);
    CHECK(parse_i64("-99999999999999999999999999") == -kMax);
    CHECK(parse_i64("9223372036854775807") == kMax);     // exactly INT64_MAX
    CHECK(parse_i64("9223372036854775808") == kMax);     // one past → clamp
    // format_gib on a huge byte count must not overflow the *10 multiply.
    REQUIRE_NOTHROW(format_gib(kMax));
    CHECK(format_gib(kMax).find(" GiB") != std::string::npos);
}

// #4644: `cmp_version` reads any component it cannot parse as 0, so a version FLOOR of `abc`,
// `v4.2.0` or `4.2.x` was version 0 and every device passed the gate (fail OPEN). A threshold is
// now validated before it is stored: dotted-decimal components with an optional pre-release or
// build suffix. (An EMPTY field means "no threshold" and is handled by the route, not here.)
TEST_CASE("is_valid_version_threshold: dotted-decimal with an optional pre-release suffix",
          "[preflight][parse][numeric_params]") {
    for (const char* ok : {"4", "4.2", "4.2.0", "10.0.19045", "5.5", "4.2.0.1234", "0", "007.1",
                           "4294967297", "999999999999999", "4.2.0-beta", "4.2.0-rc1",
                           "4.2.0+build5", "4.2.0-rc1+build5", "4.2-beta-2", "1-alpha"}) {
        INFO(ok);
        CHECK(is_valid_version_threshold(ok));
    }
    for (const char* bad :
         {"", "abc", "v4.2.0", "4.2.x", "1..2", ".1", "1.", "-1", "+1", "4.2.0-", "4.2.0+",
          "4.2.0-beta.1", "4.2.0 ", " 4.2.0", "4.2.0\n", "4,2", "1e3", "0x10", "null", "true", "[]",
          "4.2.0_beta", "4.2.0-beta!", "1000000000000000", "99999999999999999999",
          "18446744073709551615", "9223372036854775808", "4.2.0/../x"}) {
        INFO(bad);
        CHECK_FALSE(is_valid_version_threshold(bad));
    }
}

TEST_CASE("cmp_version ignores a validated pre-release suffix", "[preflight][parse][numeric_params]") {
    CHECK(cmp_version("4.2.0", "4.2.0-beta") == 0);
    CHECK(cmp_version("4.2.1", "4.2.0-rc1") > 0);
    CHECK(cmp_version("4.1.9", "4.2.0+build5") < 0);
}
