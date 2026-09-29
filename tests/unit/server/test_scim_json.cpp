/**
 * test_scim_json.cpp — Unit tests for the SCIM v2 JSON codec + discovery-doc
 * layer (slice 2: pure serialize/parse, no routes, no database).
 *
 * Covers:
 *   - user_to_json shape (schemas/id/userName/meta.version format/location),
 *     externalId omitted when empty
 *   - parse_user: valid body + missing-userName error
 *   - parse_patch: both `active:false` forms (pathless value-object AND
 *     explicit path), unsupported op error
 *   - parse_username_filter: valid extraction, unsupported-filter error,
 *     quote-unescaping
 *   - error()/list_response() envelope shape
 *   - discovery docs (service_provider_config/resource_types/schemas) parse
 *     and carry the right schemas URN
 */

#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/scim_store.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

using namespace yuzu::server;
using namespace yuzu::server::scim;

// ── user_to_json ─────────────────────────────────────────────────────────

TEST_CASE("scim_json: user_to_json shape", "[scim][json]") {
    ScimResource r;
    r.scim_id = "abc123";
    r.external_id = "ext-1";
    r.username = "jdoe";
    r.active = true;
    r.created_at = "2026-01-01 00:00:00";
    r.updated_at = "2026-01-02 00:00:00";
    r.etag_version = 3;

    auto j = user_to_json(r, "https://host/scim/v2/Users");

    REQUIRE(j["schemas"].is_array());
    CHECK(j["schemas"][0] == std::string(kSchemaUser));
    CHECK(j["id"] == "abc123");
    CHECK(j["userName"] == "jdoe");
    CHECK(j["active"] == true);
    CHECK(j["externalId"] == "ext-1");
    CHECK(j["meta"]["resourceType"] == "User");
    CHECK(j["meta"]["created"] == "2026-01-01 00:00:00");
    CHECK(j["meta"]["lastModified"] == "2026-01-02 00:00:00");
    CHECK(j["meta"]["version"] == "W/\"3\"");
    CHECK(j["meta"]["location"] == "https://host/scim/v2/Users/abc123");
}

TEST_CASE("scim_json: user_to_json omits externalId when empty", "[scim][json]") {
    ScimResource r;
    r.scim_id = "abc123";
    r.username = "jdoe";
    r.active = true;
    r.etag_version = 1;

    auto j = user_to_json(r, "https://host/scim/v2/Users");
    CHECK_FALSE(j.contains("externalId"));
}

// ── parse_user ───────────────────────────────────────────────────────────

TEST_CASE("scim_json: parse_user valid body", "[scim][json]") {
    nlohmann::json body = {{"userName", "jdoe"}, {"externalId", "ext-1"}, {"active", false}};
    auto result = parse_user(body);
    REQUIRE(result.has_value());
    CHECK(result->user_name == "jdoe");
    CHECK(result->external_id == "ext-1");
    REQUIRE(result->active.has_value());
    CHECK(result->active.value() == false);
}

TEST_CASE("scim_json: parse_user tolerates unknown fields", "[scim][json]") {
    nlohmann::json body = {{"userName", "jdoe"},
                           {"name", {{"givenName", "J"}, {"familyName", "Doe"}}},
                           {"emails", nlohmann::json::array({{{"value", "j@x.com"}}})}};
    auto result = parse_user(body);
    REQUIRE(result.has_value());
    CHECK(result->user_name == "jdoe");
}

TEST_CASE("scim_json: parse_user missing userName errors", "[scim][json]") {
    nlohmann::json body = {{"externalId", "ext-1"}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_user rejects a non-string userName (FIX-3)", "[scim][json]") {
    // Previously body.value<std::string>("userName", {}) threw
    // nlohmann::json::type_error on a non-string value, escaping the
    // std::expected contract as an unhandled 500 instead of a clean 400.
    nlohmann::json body = {{"userName", 123}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_user rejects a non-string externalId (FIX-3)", "[scim][json]") {
    nlohmann::json body = {{"userName", "jdoe"}, {"externalId", nlohmann::json::array()}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_user rejects an oversized externalId (S-EXTID)", "[scim][json]") {
    nlohmann::json body = {{"userName", "jdoe"},
                           {"externalId", std::string(kMaxExternalIdLength + 1, 'x')}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_user accepts externalId at exactly the max length", "[scim][json]") {
    nlohmann::json body = {{"userName", "jdoe"},
                           {"externalId", std::string(kMaxExternalIdLength, 'x')}};
    auto result = parse_user(body);
    REQUIRE(result.has_value());
    CHECK(result->external_id.size() == kMaxExternalIdLength);
}

// Quality SHOULD (governance hardening round): the Groups displayName
// embedded-NUL guard has an integration test (test_scim_routes.cpp,
// UP-3/#2018), but the identical userName/externalId guards in parse_user
// were untested — lock them in at the parse-boundary layer, same rationale
// (PostgreSQL `text` cannot round-trip an embedded NUL; silently truncating
// "victim\0decoy" to "victim" would collide with a shorter legitimate
// username/externalId).
TEST_CASE("scim_json: parse_user rejects an embedded-NUL userName", "[scim][json][embedded-nul]") {
    std::string nul_name = std::string("victim") + std::string(1, '\0') + std::string("decoy");
    nlohmann::json body = {{"userName", nul_name}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_user rejects an embedded-NUL externalId",
         "[scim][json][embedded-nul]") {
    std::string nul_ext = std::string("ext") + std::string(1, '\0') + std::string("decoy");
    nlohmann::json body = {{"userName", "jdoe"}, {"externalId", nul_ext}};
    auto result = parse_user(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

// ── parse_patch ──────────────────────────────────────────────────────────

TEST_CASE("scim_json: parse_patch pathless value-object active:false", "[scim][json]") {
    nlohmann::json body = {
        {"schemas", nlohmann::json::array({kSchemaPatchOp})},
        {"Operations",
         nlohmann::json::array({{{"op", "replace"}, {"value", {{"active", false}}}}})}};
    auto result = parse_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->active.has_value());
    CHECK(result->active.value() == false);
}

TEST_CASE("scim_json: parse_patch explicit path active:false", "[scim][json]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "Replace"}, {"path", "active"}, {"value", false}}})}};
    auto result = parse_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->active.has_value());
    CHECK(result->active.value() == false);
}

TEST_CASE("scim_json: parse_patch rejects an oversized externalId, both forms (S-EXTID)",
         "[scim][json]") {
    std::string oversized(kMaxExternalIdLength + 1, 'x');

    nlohmann::json explicit_path_body = {
        {"Operations",
         nlohmann::json::array({{{"op", "replace"}, {"path", "externalId"}, {"value", oversized}}})}};
    auto explicit_path_result = parse_patch(explicit_path_body);
    REQUIRE_FALSE(explicit_path_result.has_value());
    CHECK(explicit_path_result.error().status == 400);

    nlohmann::json pathless_body = {
        {"Operations",
         nlohmann::json::array({{{"op", "replace"}, {"value", {{"externalId", oversized}}}}})}};
    auto pathless_result = parse_patch(pathless_body);
    REQUIRE_FALSE(pathless_result.has_value());
    CHECK(pathless_result.error().status == 400);
}

TEST_CASE("scim_json: parse_patch unsupported op errors", "[scim][json]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "move"}, {"path", "active"}, {"value", false}}})}};
    auto result = parse_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
}

TEST_CASE("scim_json: parse_patch empty Operations errors", "[scim][json]") {
    nlohmann::json body = {{"Operations", nlohmann::json::array()}};
    auto result = parse_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_patch missing Operations errors", "[scim][json]") {
    nlohmann::json body = {{"foo", "bar"}};
    auto result = parse_patch(body);
    REQUIRE_FALSE(result.has_value());
}

// ── parse_username_filter ──────────────────────────────────────────────────

TEST_CASE("scim_json: parse_username_filter valid extraction", "[scim][json]") {
    auto result = parse_username_filter(R"(userName eq "jdoe")");
    REQUIRE(result.has_value());
    CHECK(result.value() == "jdoe");
}

TEST_CASE("scim_json: parse_username_filter case-insensitive attr/op", "[scim][json]") {
    auto result = parse_username_filter(R"(USERNAME EQ "jdoe")");
    REQUIRE(result.has_value());
    CHECK(result.value() == "jdoe");
}

TEST_CASE("scim_json: parse_username_filter unescapes quotes/backslashes",
          "[scim][json]") {
    auto result = parse_username_filter(R"(userName eq "j\"doe\\x")");
    REQUIRE(result.has_value());
    CHECK(result.value() == "j\"doe\\x");
}

TEST_CASE("scim_json: parse_username_filter unsupported attribute errors", "[scim][json]") {
    auto result = parse_username_filter(R"(externalId eq "ext-1")");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidFilter");
}

TEST_CASE("scim_json: parse_username_filter unsupported operator errors", "[scim][json]") {
    auto result = parse_username_filter(R"(userName co "jdoe")");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().scim_type == "invalidFilter");
}

// ── error / list_response envelopes ────────────────────────────────────────

TEST_CASE("scim_json: error envelope shape", "[scim][json]") {
    auto j = error(404, "resource not found");
    CHECK(j["schemas"][0] == std::string(kSchemaError));
    CHECK(j["status"] == "404");
    CHECK(j["detail"] == "resource not found");
    CHECK_FALSE(j.contains("scimType"));
}

TEST_CASE("scim_json: error envelope with scimType", "[scim][json]") {
    auto j = error(400, "userName is required", "invalidValue");
    CHECK(j["scimType"] == "invalidValue");
    CHECK(j["status"] == "400");
}

TEST_CASE("scim_json: error(ScimError) overload matches", "[scim][json]") {
    ScimError e{400, "invalidValue", "userName is required"};
    auto j = error(e);
    CHECK(j["status"] == "400");
    CHECK(j["scimType"] == "invalidValue");
    CHECK(j["detail"] == "userName is required");
}

TEST_CASE("scim_json: list_response shape", "[scim][json]") {
    nlohmann::json u1 = {{"id", "1"}};
    nlohmann::json u2 = {{"id", "2"}};
    auto j = list_response({u1, u2}, 2, 1, 2);
    CHECK(j["schemas"][0] == std::string(kSchemaListResponse));
    CHECK(j["totalResults"] == 2);
    CHECK(j["startIndex"] == 1);
    CHECK(j["itemsPerPage"] == 2);
    REQUIRE(j["Resources"].is_array());
    CHECK(j["Resources"].size() == 2);
}

// ── Discovery docs ───────────────────────────────────────────────────────

TEST_CASE("scim_json: service_provider_config shape", "[scim][json]") {
    auto j = service_provider_config();
    CHECK(j["schemas"][0] == std::string(kSchemaServiceProviderConfig));
    CHECK(j["patch"]["supported"] == true);
    CHECK(j["bulk"]["supported"] == false);
    CHECK(j["filter"]["supported"] == true);
    CHECK(j["filter"]["maxResults"] == 200);
    // S-ETAG-FALSE: no If-Match conditional-write enforcement exists yet —
    // advertising etag support would invite a connector to rely on 412
    // semantics that never fire. meta.version/ETag stay informational-only.
    CHECK(j["etag"]["supported"] == false);
    REQUIRE(j["authenticationSchemes"].is_array());
    CHECK(j["authenticationSchemes"][0]["type"] == "oauthbearertoken");
}

TEST_CASE("scim_json: resource_types shape", "[scim][json]") {
    auto j = resource_types();
    CHECK(j["schemas"][0] == std::string(kSchemaListResponse));
    REQUIRE(j["Resources"].is_array());
    // #2021 (Groups->role): now advertises BOTH User and Group resource
    // types.
    REQUIRE(j["Resources"].size() == 2);
    CHECK(j["Resources"][0]["id"] == "User");
    CHECK(j["Resources"][0]["endpoint"] == "/Users");
    CHECK(j["Resources"][0]["schema"] == std::string(kSchemaUser));
    CHECK(j["Resources"][1]["id"] == "Group");
    CHECK(j["Resources"][1]["endpoint"] == "/Groups");
    CHECK(j["Resources"][1]["schema"] == std::string(kSchemaGroup));
}

TEST_CASE("scim_json: schemas shape", "[scim][json]") {
    auto j = schemas();
    CHECK(j["schemas"][0] == std::string(kSchemaListResponse));
    REQUIRE(j["Resources"].is_array());
    // #2021 (Groups->role): now advertises BOTH the User and Group schemas.
    REQUIRE(j["Resources"].size() == 2);
    CHECK(j["Resources"][0]["id"] == std::string(kSchemaUser));
    REQUIRE(j["Resources"][0]["attributes"].is_array());
    CHECK(j["Resources"][1]["id"] == std::string(kSchemaGroup));
    REQUIRE(j["Resources"][1]["attributes"].is_array());
}

// ── group_to_json ────────────────────────────────────────────────────────

TEST_CASE("scim_json: group_to_json shape", "[scim][json][group]") {
    ScimGroup g;
    g.scim_id = "grp123";
    g.external_id = "ext-g1";
    g.display_name = "Admins";
    g.active = true;
    g.created_at = "2026-01-01 00:00:00";
    g.updated_at = "2026-01-02 00:00:00";
    g.etag_version = 4;

    auto j = group_to_json(g, {"u1", "u2"}, "https://host/scim/v2/Groups",
                            "https://host/scim/v2/Users");

    REQUIRE(j["schemas"].is_array());
    CHECK(j["schemas"][0] == std::string(kSchemaGroup));
    CHECK(j["id"] == "grp123");
    CHECK(j["displayName"] == "Admins");
    CHECK(j["externalId"] == "ext-g1");
    CHECK(j["meta"]["resourceType"] == "Group");
    CHECK(j["meta"]["created"] == "2026-01-01 00:00:00");
    CHECK(j["meta"]["lastModified"] == "2026-01-02 00:00:00");
    CHECK(j["meta"]["version"] == "W/\"4\"");
    CHECK(j["meta"]["location"] == "https://host/scim/v2/Groups/grp123");

    REQUIRE(j["members"].is_array());
    REQUIRE(j["members"].size() == 2);
    CHECK(j["members"][0]["value"] == "u1");
    CHECK(j["members"][0]["$ref"] == "https://host/scim/v2/Users/u1");
    CHECK(j["members"][0]["type"] == "User");
    CHECK(j["members"][1]["value"] == "u2");
    CHECK(j["members"][1]["$ref"] == "https://host/scim/v2/Users/u2");
}

TEST_CASE("scim_json: group_to_json omits externalId when empty", "[scim][json][group]") {
    ScimGroup g;
    g.scim_id = "grp123";
    g.display_name = "Admins";
    g.etag_version = 1;

    auto j = group_to_json(g, {}, "https://host/scim/v2/Groups", "https://host/scim/v2/Users");
    CHECK_FALSE(j.contains("externalId"));
    REQUIRE(j["members"].is_array());
    CHECK(j["members"].empty());
}

// ── parse_group ──────────────────────────────────────────────────────────

TEST_CASE("scim_json: parse_group valid body", "[scim][json][group]") {
    nlohmann::json body = {{"displayName", "Admins"},
                           {"externalId", "ext-g1"},
                           {"members", nlohmann::json::array({{{"value", "u1"}}})}};
    auto result = parse_group(body);
    REQUIRE(result.has_value());
    CHECK(result->display_name == "Admins");
    CHECK(result->external_id == "ext-g1");
    REQUIRE(result->member_values.size() == 1);
    CHECK(result->member_values[0] == "u1");
}

TEST_CASE("scim_json: parse_group missing displayName errors", "[scim][json][group]") {
    nlohmann::json body = {{"externalId", "ext-g1"}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_group rejects a non-string displayName", "[scim][json][group]") {
    nlohmann::json body = {{"displayName", 123}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_group rejects a non-string externalId", "[scim][json][group]") {
    nlohmann::json body = {{"displayName", "Admins"}, {"externalId", nlohmann::json::array()}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_group rejects an oversized displayName (sec-L3/UP-9)",
          "[scim][json][group]") {
    nlohmann::json body = {{"displayName", std::string(kMaxDisplayNameLen + 1, 'x')}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_group accepts displayName at exactly the max length",
          "[scim][json][group]") {
    nlohmann::json body = {{"displayName", std::string(kMaxDisplayNameLen, 'x')}};
    auto result = parse_group(body);
    REQUIRE(result.has_value());
    CHECK(result->display_name.size() == kMaxDisplayNameLen);
}

TEST_CASE("scim_json: parse_group rejects an oversized externalId", "[scim][json][group]") {
    nlohmann::json body = {{"displayName", "Admins"},
                           {"externalId", std::string(kMaxExternalIdLength + 1, 'x')}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

TEST_CASE("scim_json: parse_group members array of bare string entries",
          "[scim][json][group]") {
    nlohmann::json body = {{"displayName", "Admins"},
                           {"members", nlohmann::json::array({"u1", "u2"})}};
    auto result = parse_group(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_values.size() == 2);
    CHECK(result->member_values[0] == "u1");
    CHECK(result->member_values[1] == "u2");
}

TEST_CASE("scim_json: parse_group rejects a non-array members", "[scim][json][group]") {
    nlohmann::json body = {{"displayName", "Admins"}, {"members", "not-an-array"}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

// Quality SHOULD (governance hardening round): the displayName embedded-NUL
// guard has an integration test (test_scim_routes.cpp, UP-3/#2018); the
// identical guard on a members[].value entry (`extract_member_values`) was
// untested. Same rationale — a truncated member scim_id could silently
// resolve to a DIFFERENT, shorter existing user id, adding the wrong
// principal to the group.
TEST_CASE("scim_json: parse_group rejects an embedded-NUL members[].value",
         "[scim][json][group][embedded-nul]") {
    std::string nul_value = std::string("u1") + std::string(1, '\0') + std::string("decoy");
    nlohmann::json body = {{"displayName", "Admins"},
                           {"members", nlohmann::json::array({{{"value", nul_value}}})}};
    auto result = parse_group(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidValue");
}

// ── parse_group_patch ────────────────────────────────────────────────────

TEST_CASE("scim_json: parse_group_patch add members (explicit path)", "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "add"},
                                 {"path", "members"},
                                 {"value", nlohmann::json::array({{{"value", "u1"}}})}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::Add);
    REQUIRE(result->member_ops[0].values.size() == 1);
    CHECK(result->member_ops[0].values[0] == "u1");
}

TEST_CASE("scim_json: parse_group_patch remove members (explicit path, no value = remove all)",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations", nlohmann::json::array({{{"op", "remove"}, {"path", "members"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::RemoveAll);
    CHECK(result->member_ops[0].values.empty());
}

TEST_CASE("scim_json: parse_group_patch remove members with an explicit value filter list",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "remove"},
                                 {"path", "members"},
                                 {"value", nlohmann::json::array({{{"value", "u1"}}})}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::Remove);
    REQUIRE(result->member_ops[0].values.size() == 1);
    CHECK(result->member_ops[0].values[0] == "u1");
}

TEST_CASE("scim_json: parse_group_patch remove via members[value eq \"id\"] valueFilter",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "remove"}, {"path", R"(members[value eq "u1"])"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::Remove);
    REQUIRE(result->member_ops[0].values.size() == 1);
    CHECK(result->member_ops[0].values[0] == "u1");
}

TEST_CASE("scim_json: parse_group_patch replace members (explicit path)",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "replace"},
                                 {"path", "members"},
                                 {"value", nlohmann::json::array({{{"value", "u1"}},
                                                                  {{"value", "u2"}}})}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::ReplaceAll);
    REQUIRE(result->member_ops[0].values.size() == 2);
    CHECK(result->member_ops[0].values[0] == "u1");
    CHECK(result->member_ops[0].values[1] == "u2");
}

TEST_CASE("scim_json: parse_group_patch replace members (pathless value-object)",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "replace"},
              {"value", {{"members", nlohmann::json::array({{{"value", "u1"}}})}}}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 1);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::ReplaceAll);
    REQUIRE(result->member_ops[0].values.size() == 1);
    CHECK(result->member_ops[0].values[0] == "u1");
}

TEST_CASE("scim_json: parse_group_patch preserves member-op ORDER across the Operations array "
          "(#2127 review HIGH — the old bucketed design discarded this)",
          "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "add"},
              {"path", "members"},
              {"value", nlohmann::json::array({{{"value", "u1"}}})}},
             {{"op", "remove"}, {"path", R"(members[value eq "u1"])"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE(result.has_value());
    REQUIRE(result->member_ops.size() == 2);
    CHECK(result->member_ops[0].kind == ScimGroupMemberOp::Kind::Add);
    CHECK(result->member_ops[0].values == std::vector<std::string>{"u1"});
    CHECK(result->member_ops[1].kind == ScimGroupMemberOp::Kind::Remove);
    CHECK(result->member_ops[1].values == std::vector<std::string>{"u1"});

    // Reversed order in the body is a DIFFERENT patch (remove-then-add).
    nlohmann::json reversed_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "remove"}, {"path", R"(members[value eq "u1"])"}},
             {{"op", "add"},
              {"path", "members"},
              {"value", nlohmann::json::array({{{"value", "u1"}}})}}})}};
    auto reversed = parse_group_patch(reversed_body);
    REQUIRE(reversed.has_value());
    REQUIRE(reversed->member_ops.size() == 2);
    CHECK(reversed->member_ops[0].kind == ScimGroupMemberOp::Kind::Remove);
    CHECK(reversed->member_ops[1].kind == ScimGroupMemberOp::Kind::Add);
}

TEST_CASE("scim_json: parse_group_patch rejects an oversized displayName — all 3 op shapes "
          "(sec-L3/UP-9)",
          "[scim][json][group]") {
    std::string oversized(kMaxDisplayNameLen + 1, 'x');

    // add, path=displayName
    nlohmann::json add_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "add"}, {"path", "displayName"}, {"value", oversized}}})}};
    auto add_result = parse_group_patch(add_body);
    REQUIRE_FALSE(add_result.has_value());
    CHECK(add_result.error().status == 400);

    // replace, pathless value-object
    nlohmann::json pathless_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "replace"}, {"value", {{"displayName", oversized}}}}})}};
    auto pathless_result = parse_group_patch(pathless_body);
    REQUIRE_FALSE(pathless_result.has_value());
    CHECK(pathless_result.error().status == 400);

    // replace, path=displayName
    nlohmann::json replace_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "replace"}, {"path", "displayName"}, {"value", oversized}}})}};
    auto replace_result = parse_group_patch(replace_body);
    REQUIRE_FALSE(replace_result.has_value());
    CHECK(replace_result.error().status == 400);
}

TEST_CASE("scim_json: parse_group_patch rejects an oversized externalId — all 3 op shapes "
          "(sec-L3/UP-9)",
          "[scim][json][group]") {
    std::string oversized(kMaxExternalIdLength + 1, 'x');

    // add, path=externalId
    nlohmann::json add_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "add"}, {"path", "externalId"}, {"value", oversized}}})}};
    auto add_result = parse_group_patch(add_body);
    REQUIRE_FALSE(add_result.has_value());
    CHECK(add_result.error().status == 400);

    // replace, pathless value-object
    nlohmann::json pathless_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "replace"}, {"value", {{"externalId", oversized}}}}})}};
    auto pathless_result = parse_group_patch(pathless_body);
    REQUIRE_FALSE(pathless_result.has_value());
    CHECK(pathless_result.error().status == 400);

    // replace, path=externalId
    nlohmann::json replace_body = {
        {"Operations",
         nlohmann::json::array(
             {{{"op", "replace"}, {"path", "externalId"}, {"value", oversized}}})}};
    auto replace_result = parse_group_patch(replace_body);
    REQUIRE_FALSE(replace_result.has_value());
    CHECK(replace_result.error().status == 400);
}

TEST_CASE("scim_json: parse_group_patch unsupported op errors", "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "move"}, {"path", "members"}, {"value", "u1"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
}

TEST_CASE("scim_json: parse_group_patch unsupported path errors", "[scim][json][group]") {
    nlohmann::json body = {
        {"Operations",
         nlohmann::json::array({{{"op", "add"}, {"path", "bogusPath"}, {"value", "x"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidPath");
}

TEST_CASE("scim_json: parse_group_patch remove requires a path", "[scim][json][group]") {
    nlohmann::json body = {{"Operations", nlohmann::json::array({{{"op", "remove"}}})}};
    auto result = parse_group_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().status == 400);
    CHECK(result.error().scim_type == "invalidPath");
}

TEST_CASE("scim_json: parse_group_patch empty Operations errors", "[scim][json][group]") {
    nlohmann::json body = {{"Operations", nlohmann::json::array()}};
    auto result = parse_group_patch(body);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().scim_type == "invalidValue");
}
