/**
 * test_vuln_rules.cpp — Unit tests for CVE rules and version comparison
 *
 * Covers: compare_versions() from cve_rules.hpp, CveRule data integrity,
 *         and CVE matching logic.
 */

#include "cve_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>

using namespace yuzu::vuln;

// ── compare_versions ────────────────────────────────────────────────────────

TEST_CASE("compare_versions: equal versions", "[vuln][version]") {
    CHECK(compare_versions("1.0.0", "1.0.0") == 0);
    CHECK(compare_versions("3.2.1", "3.2.1") == 0);
    CHECK(compare_versions("10.20.30", "10.20.30") == 0);
}

TEST_CASE("compare_versions: less than", "[vuln][version]") {
    CHECK(compare_versions("1.0.0", "2.0.0") < 0);
    CHECK(compare_versions("1.0.0", "1.1.0") < 0);
    CHECK(compare_versions("1.0.0", "1.0.1") < 0);
}

TEST_CASE("compare_versions: greater than", "[vuln][version]") {
    CHECK(compare_versions("2.0.0", "1.0.0") > 0);
    CHECK(compare_versions("1.1.0", "1.0.0") > 0);
    CHECK(compare_versions("1.0.1", "1.0.0") > 0);
}

TEST_CASE("compare_versions: numeric comparison (not lexicographic)", "[vuln][version]") {
    // 10 > 9 numerically, but "10" < "9" lexicographically
    CHECK(compare_versions("0.10.0", "0.9.0") > 0);
    CHECK(compare_versions("1.2.10", "1.2.9") > 0);
    CHECK(compare_versions("10.0.0", "9.0.0") > 0);
}

TEST_CASE("compare_versions: different segment counts", "[vuln][version]") {
    // Missing segments treated as 0
    CHECK(compare_versions("1.0", "1.0.0") == 0);
    CHECK(compare_versions("1", "1.0.0") == 0);
    CHECK(compare_versions("1.0.0", "1") == 0);
    CHECK(compare_versions("1.0.1", "1.0") > 0);
    CHECK(compare_versions("1.0", "1.0.1") < 0);
}

TEST_CASE("compare_versions: dash-separated segments", "[vuln][version]") {
    CHECK(compare_versions("1.0.0-1", "1.0.0-2") < 0);
    CHECK(compare_versions("1.9.5p2", "1.9.5p2") == 0);
}

TEST_CASE("compare_versions: mixed alpha-numeric segments (lexicographic fallback)",
          "[vuln][version]") {
    // "p2" vs "p3" — both non-numeric, compared lexicographically
    CHECK(compare_versions("1.9.5p2", "1.9.5p3") < 0);
}

TEST_CASE("compare_versions: empty strings", "[vuln][version]") {
    CHECK(compare_versions("", "") == 0);
    CHECK(compare_versions("1.0", "") > 0);
    CHECK(compare_versions("", "1.0") < 0);
}

TEST_CASE("compare_versions: real-world OpenSSL versions", "[vuln][version]") {
    CHECK(compare_versions("1.0.1f", "1.0.1g") < 0);
    CHECK(compare_versions("3.0.6", "3.0.7") < 0);
    CHECK(compare_versions("3.0.8", "3.0.7") > 0);
    CHECK(compare_versions("3.3.1", "3.3.2") < 0);
}

TEST_CASE("compare_versions: real-world curl versions", "[vuln][version]") {
    CHECK(compare_versions("8.3.0", "8.4.0") < 0);
    CHECK(compare_versions("8.7.0", "8.7.1") < 0);
}

TEST_CASE("compare_versions: real-world browser versions", "[vuln][version]") {
    CHECK(compare_versions("120.0.6099.224", "120.0.6099.225") < 0);
    CHECK(compare_versions("124.0.6367.201", "124.0.6367.202") < 0);
    CHECK(compare_versions("131.0.1", "131.0.2") < 0);
}

// ── CveRule data integrity ──────────────────────────────────────────────────

TEST_CASE("CveRule: all rules have non-empty required fields", "[vuln][rules]") {
    for (const auto& rule : kCveRules) {
        CAPTURE(rule.cve_id);
        CHECK_FALSE(rule.cve_id.empty());
        CHECK_FALSE(rule.product.empty());
        CHECK_FALSE(rule.affected_below.empty());
        CHECK_FALSE(rule.fixed_in.empty());
        CHECK_FALSE(rule.severity.empty());
        CHECK_FALSE(rule.description.empty());
    }
}

TEST_CASE("CveRule: all CVE IDs follow CVE-YYYY-NNNNN format", "[vuln][rules]") {
    for (const auto& rule : kCveRules) {
        CAPTURE(rule.cve_id);
        CHECK(rule.cve_id.starts_with("CVE-"));
        CHECK(rule.cve_id.size() >= 13); // CVE-YYYY-NNNNN minimum
    }
}

TEST_CASE("CveRule: all severities are valid", "[vuln][rules]") {
    for (const auto& rule : kCveRules) {
        CAPTURE(rule.cve_id);
        bool valid = (rule.severity == "CRITICAL" || rule.severity == "HIGH" ||
                      rule.severity == "MEDIUM" || rule.severity == "LOW");
        CHECK(valid);
    }
}

TEST_CASE("CveRule: no duplicate CVE IDs", "[vuln][rules]") {
    std::vector<std::string_view> ids;
    ids.reserve(kCveRules.size());
    for (const auto& rule : kCveRules) {
        ids.push_back(rule.cve_id);
    }
    std::sort(ids.begin(), ids.end());
    auto it = std::adjacent_find(ids.begin(), ids.end());
    if (it != ids.end()) {
        CAPTURE(*it);
        FAIL("Duplicate CVE ID found");
    }
}

TEST_CASE("CveRule: expected rule count (sanity check)", "[vuln][rules]") {
    // Current count: 42 rules. Update this if rules are added/removed.
    CHECK(kCveRules.size() >= 40);
}

// ── CVE matching logic ──────────────────────────────────────────────────────

TEST_CASE("CVE matching: vulnerable OpenSSL detected", "[vuln][match]") {
    // OpenSSL 1.0.1f should match CVE-2014-0160 (Heartbleed)
    std::string app_name = "openssl";
    std::string installed_version = "1.0.1f";

    bool matched = false;
    for (const auto& rule : kCveRules) {
        if (app_name.find(rule.product) != std::string::npos &&
            compare_versions(installed_version, rule.affected_below) < 0) {
            if (rule.cve_id == "CVE-2014-0160") {
                matched = true;
            }
        }
    }
    CHECK(matched);
}

TEST_CASE("CVE matching: patched OpenSSL not vulnerable", "[vuln][match]") {
    // OpenSSL 3.0.8 should NOT match CVE-2023-0286 (fixed in 3.0.8)
    std::string installed_version = "3.0.8";

    for (const auto& rule : kCveRules) {
        if (rule.cve_id == "CVE-2023-0286") {
            CHECK_FALSE(compare_versions(installed_version, rule.affected_below) < 0);
        }
    }
}

TEST_CASE("CVE matching: vulnerable curl detected", "[vuln][match]") {
    // curl 8.3.0 should match CVE-2023-38545 (SOCKS5 heap overflow, fixed in 8.4.0)
    std::string installed_version = "8.3.0";

    bool matched = false;
    for (const auto& rule : kCveRules) {
        if (rule.cve_id == "CVE-2023-38545") {
            if (compare_versions(installed_version, rule.affected_below) < 0) {
                matched = true;
            }
        }
    }
    CHECK(matched);
}

TEST_CASE("CVE matching: patched curl not vulnerable", "[vuln][match]") {
    std::string installed_version = "8.4.0";

    for (const auto& rule : kCveRules) {
        if (rule.cve_id == "CVE-2023-38545") {
            CHECK_FALSE(compare_versions(installed_version, rule.affected_below) < 0);
        }
    }
}

TEST_CASE("CVE matching: RegreSSHion vulnerability detected", "[vuln][match]") {
    // OpenSSH 9.7 should match CVE-2024-6387 (fixed in 9.8)
    std::string installed_version = "9.7";

    bool matched = false;
    for (const auto& rule : kCveRules) {
        if (rule.cve_id == "CVE-2024-6387") {
            if (compare_versions(installed_version, rule.affected_below) < 0) {
                matched = true;
            }
        }
    }
    CHECK(matched);
}

TEST_CASE("CVE matching: Log4Shell detected for old log4j", "[vuln][match]") {
    // log4j 2.14.0 should match CVE-2021-44228
    std::string installed_version = "2.14.0";

    bool matched = false;
    for (const auto& rule : kCveRules) {
        if (rule.cve_id == "CVE-2021-44228") {
            if (compare_versions(installed_version, rule.affected_below) < 0) {
                matched = true;
            }
        }
    }
    CHECK(matched);
}

TEST_CASE("CVE matching: unrelated product does not match", "[vuln][match]") {
    // "notepad" should not match any CVE rules (no rules for notepad)
    std::string app_name = "notepad";
    std::string installed_version = "1.0.0";

    int match_count = 0;
    for (const auto& rule : kCveRules) {
        if (app_name.find(rule.product) != std::string::npos &&
            compare_versions(installed_version, rule.affected_below) < 0) {
            ++match_count;
        }
    }
    CHECK(match_count == 0);
}

// ── a numeric segment too large for long long must not overflow (UBSan-clean) ──────────────────

TEST_CASE("compare_versions: an oversized segment saturates instead of overflowing", "[vuln][version]") {
    CHECK(compare_versions("1.99999999999999999999999", "2.0") < 0);
    CHECK(compare_versions("1.99999999999999999999999", "1.5") > 0); // saturated: larger than 5
    CHECK(compare_versions("1.99999999999999999999999", "1.99999999999999999999999") == 0);
    CHECK(compare_versions("3.9.6", "3.10.0") < 0); // ordinary versions are unchanged
}

TEST_CASE("version_has_overflowing_segment", "[vuln][version]") {
    CHECK_FALSE(version_has_overflowing_segment("1.2.3"));
    CHECK_FALSE(version_has_overflowing_segment(""));
    CHECK_FALSE(version_has_overflowing_segment("999999999999999999")); // 18 digits
    CHECK(version_has_overflowing_segment("1000000000000000000"));     // 19 digits
    CHECK(version_has_overflowing_segment("1.2.99999999999999999999"));
    CHECK_FALSE(version_has_overflowing_segment("000000000000000000000001")); // leading zeros
    CHECK_FALSE(version_has_overflowing_segment("1.99999999999999999999x")); // not all digits
}
