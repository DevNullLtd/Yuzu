/**
 * test_saml_principal.cpp — Unit tests for `saml_principal_id` and
 * `is_valid_saml_component` (ADR-2001 PR4a), the SAML analogue of
 * `test_oidc_principal.cpp` — the single shared builder for the stable
 * `"saml:" + entity_id + "#" + name_id` RBAC/session principal string, plus
 * the sanitation gate that must run before either component enters it.
 *
 * Pins the exact format so a future edit to this one function cannot
 * silently drift what `AuthManager::create_saml_session` (the mint site)
 * AND `deprovision_revoke.cpp` (the resolve site) build — a drift here
 * would be the "reported success, revoked nothing" failure ADR-2001 exists
 * to prevent.
 */

#include "saml_principal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::saml::is_valid_saml_component;
using yuzu::server::saml::saml_principal_id;

TEST_CASE("saml_principal_id: format is exactly saml:<entity_id>#<name_id>", "[auth][saml][2001]") {
    CHECK(saml_principal_id("https://idp.example.com/saml/metadata", "user@example.com") ==
         "saml:https://idp.example.com/saml/metadata#user@example.com");
    CHECK(saml_principal_id("", "") == "saml:#");
    CHECK(saml_principal_id("entity-only", "") == "saml:entity-only#");
    CHECK(saml_principal_id("", "name-only") == "saml:#name-only");
}

TEST_CASE("saml_principal_id: round-trips exactly the equivalent hand-built string",
         "[auth][saml][2001]") {
    // Mirrors the literal expression `"saml:" + entity_id + "#" + name_id`
    // this helper replaces — fails if the helper's output ever diverges
    // from that expression for any input.
    const std::string entity_id = "https://idp.yuzu.test/saml/metadata";
    const std::string name_id   = "alice@example.test";
    const std::string hand_built = "saml:" + entity_id + "#" + name_id;
    CHECK(saml_principal_id(entity_id, name_id) == hand_built);
}

TEST_CASE("saml_principal_id: does not conflate '#' inside entity_id/name_id with the "
         "delimiter",
         "[auth][saml][2001]") {
    // Not a claim this function needs to guard against (entity_id/name_id
    // are validated elsewhere — is_valid_saml_component below) — just
    // documents that the concatenation is literal, not a parser.
    CHECK(saml_principal_id("entity#weird", "name") == "saml:entity#weird#name");
}

TEST_CASE("saml_principal_id: mirrors oidc_principal_id's shape with a different tag",
         "[auth][saml][2001]") {
    // Same construction pattern as oidc_principal_id, just "saml:" instead
    // of "oidc:" — the two principal spaces are disjoint by construction
    // because of this tag (a SAML principal can never collide with an OIDC
    // one at the string level, regardless of entity_id/iss or name_id/sub
    // values).
    CHECK(saml_principal_id("https://idp.example.com/", "sub-123") !=
         "oidc:https://idp.example.com/#sub-123");
}

// ── is_valid_saml_component (the sanitation gate) ────────────────────────

TEST_CASE("is_valid_saml_component: rejects empty", "[auth][saml][2001]") {
    CHECK_FALSE(is_valid_saml_component(""));
}

TEST_CASE("is_valid_saml_component: accepts a normal NameID/entity_id", "[auth][saml][2001]") {
    CHECK(is_valid_saml_component("user@example.com"));
    CHECK(is_valid_saml_component("https://idp.example.com/saml/metadata"));
}

TEST_CASE("is_valid_saml_component: accepts exactly 255 bytes, rejects 256",
         "[auth][saml][2001]") {
    const std::string at_limit(255, 'a');
    const std::string over_limit(256, 'a');
    CHECK(is_valid_saml_component(at_limit));
    CHECK_FALSE(is_valid_saml_component(over_limit));
}

TEST_CASE("is_valid_saml_component: rejects control bytes (<0x20) and DEL (0x7F)",
         "[auth][saml][2001]") {
    CHECK_FALSE(is_valid_saml_component(std::string("user\nname")));
    CHECK_FALSE(is_valid_saml_component(std::string("user\tname")));
    CHECK_FALSE(is_valid_saml_component(std::string("user\rname")));
    CHECK_FALSE(is_valid_saml_component(std::string(1, '\x00') + "user"));
    CHECK_FALSE(is_valid_saml_component(std::string("user") + std::string(1, '\x7F') + "name"));
}

TEST_CASE("is_valid_saml_component: allows the space byte (0x20) and printable ASCII",
         "[auth][saml][2001]") {
    // 0x20 (space) is the boundary — the rule rejects strictly BELOW 0x20,
    // so a display-name-shaped value with an internal space is not rejected
    // by this gate alone (a NameID is not expected to contain a space in
    // practice, but this pins the exact boundary rather than an
    // off-by-one).
    CHECK(is_valid_saml_component("user name"));
}
