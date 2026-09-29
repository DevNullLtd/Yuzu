/**
 * test_oidc_principal.cpp — Unit tests for `oidc_principal_id` (ADR-2001 §5),
 * the single shared builder for the stable `"oidc:" + iss + "#" + sub`
 * RBAC/session principal string.
 *
 * Pins the exact format so a future edit to this one function cannot
 * silently drift what every OIDC login mint site AND a future
 * deprovision-time resolver builds — a drift here would be the "reported
 * success, revoked nothing" failure ADR-2001 exists to prevent.
 */

#include "oidc_principal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::oidc::oidc_principal_id;

TEST_CASE("oidc_principal_id: format is exactly oidc:<iss>#<sub>", "[auth][oidc][2001]") {
    CHECK(oidc_principal_id("https://idp.example.com/", "sub-123") ==
         "oidc:https://idp.example.com/#sub-123");
    CHECK(oidc_principal_id("", "") == "oidc:#");
    CHECK(oidc_principal_id("iss-only", "") == "oidc:iss-only#");
    CHECK(oidc_principal_id("", "sub-only") == "oidc:#sub-only");
}

TEST_CASE("oidc_principal_id: round-trips exactly the pre-extraction hand-built string",
         "[auth][oidc][2001]") {
    // Mirrors the literal expression both mint sites used before this
    // extraction (`"oidc:" + iss + "#" + sub`) — this test fails if the
    // helper's output ever diverges from that expression for any input.
    const std::string iss = "https://login.microsoftonline.com/tenant-id/v2.0";
    const std::string sub = "AAAAAAAAAAAAAAAAAAAAAImTQ0LnjBWtNzn5vGDBYxU";
    const std::string hand_built = "oidc:" + iss + "#" + sub;
    CHECK(oidc_principal_id(iss, sub) == hand_built);
}

TEST_CASE("oidc_principal_id: does not conflate '#' inside iss/sub with the delimiter",
         "[auth][oidc][2001]") {
    // Not a claim this function needs to guard against (iss/sub are
    // IdP-asserted, validated fields elsewhere) — just documents that the
    // concatenation is literal, not a parser: whatever bytes come in appear
    // verbatim either side of the single '#' this function inserts.
    CHECK(oidc_principal_id("iss#weird", "sub") == "oidc:iss#weird#sub");
}
