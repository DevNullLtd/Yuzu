/**
 * test_email_redaction.cpp -- proves the shared e-mail redaction symbols
 * are reachable from a TU that includes only the shared header. The
 * matching logic itself is covered by test_browser_inventory_parsers.cpp.
 */
#include <email_redaction.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

TEST_CASE("email_redaction: address is detected", "[email_redaction]") {
    CHECK(yuzu::shared::looks_like_email_address("account@example.com"));
}

TEST_CASE("email_redaction: plain name is not an address", "[email_redaction]") {
    CHECK_FALSE(yuzu::shared::looks_like_email_address("Default"));
}

TEST_CASE("email_redaction: placeholder value", "[email_redaction]") {
    CHECK(yuzu::shared::kRedactedEmailPlaceholder == "[redacted-email]");
}

// F67 / #4836: many '@' each followed by an unterminated '(' made the CFWS skip re-scan to the end
// of the value per '@' (~n^2/4 steps, minutes at 1 MiB). A value past kEmailScanMaxBytes that
// contains '@' is now a match without scanning: linear, and over-match is the safe direction.
TEST_CASE("email_redaction: pathological long value is bounded and over-matches",
          "[email_redaction]") {
    std::string evil;
    while (evil.size() < 256 * 1024)
        evil += "@(";
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(yuzu::shared::looks_like_email_address(evil));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < std::chrono::seconds(2));
}

TEST_CASE("email_redaction: the length cap does not redact a long value with no '@'",
          "[email_redaction]") {
    CHECK_FALSE(yuzu::shared::looks_like_email_address(
        std::string(yuzu::shared::kEmailScanMaxBytes + 1, 'x')));
    CHECK(yuzu::shared::looks_like_email_address("a@example.com"));
}
