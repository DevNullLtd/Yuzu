/**
 * test_filesystem_macos_sig.cpp -- pure fixture vectors for
 * filesystem_macos_sig.hpp's classify_codesign_result() and
 * classify_plutil_extract() mappers (A-1.14 get_signature / get_version_info,
 * shared with installed_apps A-1.10's signature_status + bundle_id
 * enrichment).
 *
 * Both mappers take an already-captured exit code + output string, so they
 * run on every CI host without a macOS box or the real codesign/plutil
 * binaries -- only the fixture strings below are macOS-flavoured.
 */

#include <catch2/catch_test_macros.hpp>

#include "filesystem_macos_sig.hpp"

#include <string_view>

using namespace yuzu::filesystem_macos;

// ── classify_codesign_result ────────────────────────────────────────────────

TEST_CASE("classify_codesign_result: exit 0 is valid", "[filesystem][macos][signature]") {
    auto status = classify_codesign_result(/*tool_ran=*/true, /*exit_code=*/0, "");
    CHECK(status == SignatureStatus::valid);
    CHECK(to_string(status) == "valid");
}

TEST_CASE("classify_codesign_result: 'not signed at all' maps to the not_signed sentinel",
         "[filesystem][macos][signature]") {
    // Real codesign --verify stderr for an unsigned binary.
    std::string_view output = "/tmp/App.app: code object is not signed at all\n";
    auto status = classify_codesign_result(true, 1, output);
    CHECK(status == SignatureStatus::not_signed);
    CHECK(to_string(status) == "unsigned");
}

TEST_CASE("classify_codesign_result: a broken-seal diagnostic maps to invalid",
         "[filesystem][macos][signature]") {
    // Real codesign --verify --deep --strict stderr for a tampered bundle.
    std::string_view output =
        "/tmp/App.app: a sealed resource is missing or invalid\n"
        "file added: /tmp/App.app/Contents/Resources/extra\n";
    auto status = classify_codesign_result(true, 3, output);
    CHECK(status == SignatureStatus::invalid);
    CHECK(to_string(status) == "invalid");
}

TEST_CASE("classify_codesign_result: non-zero exit with no output is unknown, not guessed",
         "[filesystem][macos][signature]") {
    auto status = classify_codesign_result(true, 1, "");
    CHECK(status == SignatureStatus::unknown);
    CHECK(to_string(status) == "unknown");
}

TEST_CASE("classify_codesign_result: a trust-chain failure maps to unknown, not invalid",
         "[filesystem][macos][signature]") {
    // BR-005: a CSSMERR_TP_NOT_TRUSTED (or similar policy/notarization)
    // failure means the cert chain/local trust policy rejected an
    // otherwise-intact seal -- it is not tampering. Confirmed reachable on
    // a real host (codesign --verify --deep --strict against an
    // otherwise-signed bundle can exit non-zero this way); mapping it to
    // `invalid` would report a false "tampered" compliance result.
    std::string_view output =
        "/tmp/App.app: CSSMERR_TP_NOT_TRUSTED\n"
        "explicit requirement satisfied, but the certificate chain is not trusted\n";
    auto status = classify_codesign_result(true, 1, output);
    CHECK(status == SignatureStatus::unknown);
    CHECK(to_string(status) == "unknown");
}

TEST_CASE("classify_codesign_result: tool_ran=false is unknown regardless of exit_code/output",
         "[filesystem][macos][signature]") {
    // tool_ran == false models exec() itself failing (codesign missing from
    // PATH) -- never mistaken for the "not signed at all" diagnostic text
    // just because it happens to appear in the (unrelated) captured output.
    auto status =
        classify_codesign_result(/*tool_ran=*/false, 0, "code object is not signed at all");
    CHECK(status == SignatureStatus::unknown);
    CHECK(to_string(status) == "unknown");
}

// ── classify_plutil_extract ─────────────────────────────────────────────────

TEST_CASE("classify_plutil_extract: success yields the trimmed raw value",
         "[filesystem][macos][version]") {
    // `plutil -extract CFBundleShortVersionString raw -o -` prints the bare
    // value plus a trailing newline on success.
    auto result = classify_plutil_extract(/*tool_ran=*/true, /*exit_code=*/0, "  1.2.3 \n");
    CHECK(result.available);
    CHECK(result.value == "1.2.3");
}

TEST_CASE("classify_plutil_extract: a CFBundleIdentifier value round-trips untrimmed content",
         "[filesystem][macos][version]") {
    auto result = classify_plutil_extract(true, 0, "com.apple.Safari\n");
    CHECK(result.available);
    CHECK(result.value == "com.apple.Safari");
}

TEST_CASE("classify_plutil_extract: tool_ran=false is honest not-available",
         "[filesystem][macos][version]") {
    auto result = classify_plutil_extract(/*tool_ran=*/false, 0, "1.2.3\n");
    CHECK_FALSE(result.available);
    CHECK(result.value.empty());
}

TEST_CASE("classify_plutil_extract: non-zero exit is honest not-available",
         "[filesystem][macos][version]") {
    // Real plutil stderr when the key isn't present in the plist.
    std::string_view output =
        "No value at that key path or invalid key path: CFBundleShortVersionString\n";
    auto result = classify_plutil_extract(true, 1, output);
    CHECK_FALSE(result.available);
    CHECK(result.value.empty());
}

TEST_CASE("classify_plutil_extract: whitespace-only stdout is honest not-available",
         "[filesystem][macos][version]") {
    auto result = classify_plutil_extract(true, 0, "   \n");
    CHECK_FALSE(result.available);
    CHECK(result.value.empty());
}

TEST_CASE("classify_plutil_extract: empty stdout is honest not-available",
         "[filesystem][macos][version]") {
    auto result = classify_plutil_extract(true, 0, "");
    CHECK_FALSE(result.available);
    CHECK(result.value.empty());
}
