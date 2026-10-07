/**
 * test_email_redaction.cpp -- proves the shared e-mail redaction symbols
 * are reachable from a TU that includes only the shared header. The
 * matching logic itself is covered by test_browser_inventory_parsers.cpp.
 */
#include <email_redaction.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("email_redaction: address is detected", "[email_redaction]") {
    CHECK(yuzu::shared::looks_like_email_address("account@example.com"));
}

TEST_CASE("email_redaction: plain name is not an address", "[email_redaction]") {
    CHECK_FALSE(yuzu::shared::looks_like_email_address("Default"));
}

TEST_CASE("email_redaction: placeholder value", "[email_redaction]") {
    CHECK(yuzu::shared::kRedactedEmailPlaceholder == "[redacted-email]");
}
