// test_wmi_error_token.cpp -- the portable, stage-aware classification of wmi_bounded.hpp error
// tokens (agents/shared/wmi_error_token.hpp). Runs on every OS: the header includes no OS header.
//
// The Windows-side coupling (the stage prefixes spelled here as literals must equal
// yuzu::shared::wmi::error_tokens, and the HRESULT values must equal winerror.h) is pinned by
// static_asserts in the Windows TUs that include both headers, not here.

#include <catch2/catch_test_macros.hpp>

#include <wmi_error_token.hpp>

#include <cstdint>
#include <optional>
#include <string>

using namespace yuzu::shared::wmi_token;

TEST_CASE("hresult_from_token: extracts only a trailing 0x<8 hex digits>", "[wmi_error_token]") {
    CHECK(hresult_from_token("wmi_connect_failed_0x80041003") == std::optional<std::uint32_t>{0x80041003u});
    CHECK(hresult_from_token("x_0x8004100E") == std::optional<std::uint32_t>{0x8004100Eu});
    CHECK_FALSE(hresult_from_token("wmi_deadline_exceeded").has_value());
    CHECK_FALSE(hresult_from_token("com_init_failed").has_value());
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x8004100").has_value()); // 7 digits
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x8004100g").has_value());
    CHECK_FALSE(hresult_from_token("wmi_query_failed_80041002").has_value());    // no 0x
    CHECK_FALSE(hresult_from_token("wmi_query_failed_0x80041002_x").has_value()); // not at the tail
    CHECK_FALSE(hresult_from_token("").has_value());
}

TEST_CASE("classify_hresult: refusals, absence-looking and other HRESULTs", "[wmi_error_token]") {
    CHECK(classify_hresult(0) == WmiReadOutcome::ok);
    CHECK(classify_hresult(0x80041003u) == WmiReadOutcome::denied);
    CHECK(classify_hresult(0x80070005u) == WmiReadOutcome::denied);
    CHECK(classify_hresult(0x8004100Eu) == WmiReadOutcome::absent);
    CHECK(classify_hresult(0x80041010u) == WmiReadOutcome::absent);
    CHECK(classify_hresult(0x80041002u) == WmiReadOutcome::absent);
    CHECK(classify_hresult(0x80004005u) == WmiReadOutcome::failed);
}

// Fails under: any absence-looking HRESULT reading as a definitive `absent` where WMI is not
// actually answering "missing" (NOT_FOUND anywhere, an enumeration-stage INVALID_NAMESPACE, a
// connect-stage INVALID_CLASS); under losing the `absent` for a MISSING namespace (INVALID_NAMESPACE
// at connect) or class (INVALID_CLASS at query, or at the FIRST Next(): the query is
// semisynchronous, so a missing class can arrive there); and under granting `absent` to
// INVALID_CLASS at a Next() that follows a returned row.
TEST_CASE("classify_wmi_error_token: absent only for the two answers WMI gives when something is missing",
          "[wmi_error_token]") {
    // exactly three cells read absent
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x8004100e", 0) == WmiReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041010", 0) == WmiReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 0) == WmiReadOutcome::absent);
    // NOT_FOUND is never a "missing" answer here: Microsoft lists it as a repository-corruption symptom
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80041002", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041002", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041002", 0) == WmiReadOutcome::failed);
    // a namespace answer at a stage that cannot produce it, and a class answer at connect
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80041010", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x8004100e", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x8004100e", 0) == WmiReadOutcome::failed); // #4895
    // INVALID_CLASS at Next() after a row was already returned: the class just answered, so this is
    // a fault, never absence (the token has no iteration index; wmi_bounded records the row count)
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 0) == WmiReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 1) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041010", 512) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_0x80041010", 0) == WmiReadOutcome::absent);
    CHECK(classify_wmi_error_token("wmi_next_failed_0x80041003", 3) == WmiReadOutcome::denied);
    // the proxy blanket runs before the query and carries no WBEM schema answer
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x80041002", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x80041010", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_proxy_blanket_failed_0x8004100e", 0) == WmiReadOutcome::failed);
    // a property-enumeration fault is a fault at every HRESULT, at any row count
    for (const char* hr : {"0x8004100e", "0x80041010", "0x80041002", "0x80004005"}) {
        INFO(hr);
        const std::string token = std::string{"wmi_property_enum_failed_"} + hr;
        CHECK(classify_wmi_error_token(token, 0) == WmiReadOutcome::failed);
        CHECK(classify_wmi_error_token(token, 1) == WmiReadOutcome::failed);
    }
    // A refusal is a refusal at every stage.
    for (const char* stage : {"wmi_connect_failed_", "wmi_query_failed_", "wmi_proxy_blanket_failed_",
                              "wmi_next_failed_", "wmi_property_enum_failed_"}) {
        INFO(stage);
        CHECK(classify_wmi_error_token(std::string{stage} + "0x80041003", 0) == WmiReadOutcome::denied);
        CHECK(classify_wmi_error_token(std::string{stage} + "0x80070005", 0) == WmiReadOutcome::denied);
    }
    // No HRESULT, an unrelated HRESULT, or an HRESULT of 0: always a failed read.
    CHECK(classify_wmi_error_token("wmi_deadline_exceeded", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("com_init_failed", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_query_failed_no_in_signature", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x80004005", 0) == WmiReadOutcome::failed);
    CHECK(classify_wmi_error_token("wmi_connect_failed_0x00000000", 0) == WmiReadOutcome::failed);
}
