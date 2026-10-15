/**
 * test_integrations_url_policy.cpp — pure checks shared by the webhook and
 * offload-target create paths (System pages, SYS-5): userinfo and control-byte
 * refusal, scheme+host reduction for the analytics event, and the bounded,
 * line-safe directory mapping audit detail. No store, no network.
 */

#include "integrations_sync_model.hpp"
#include "outbound_url_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cctype>
#include <map>
#include <string>

using namespace yuzu::server;

TEST_CASE("url policy: userinfo is detected in the authority only", "[integrations][url]") {
    CHECK(url_has_userinfo("https://user:pass@host.example/path"));
    CHECK(url_has_userinfo("http://token@host.example"));
    CHECK(url_has_userinfo("https://@host.example"));
    CHECK_FALSE(url_has_userinfo("https://host.example/path"));
    // An '@' after the authority is path/query data, not credentials.
    CHECK_FALSE(url_has_userinfo("https://host.example/a@b"));
    CHECK_FALSE(url_has_userinfo("https://host.example?email=a@b"));
    CHECK_FALSE(url_has_userinfo("https://host.example#a@b"));
    CHECK_FALSE(url_has_userinfo("not a url"));
}

TEST_CASE("url policy: control bytes", "[integrations][url]") {
    CHECK(url_has_control_bytes(std::string("https://h/\r\nX: y")));
    CHECK(url_has_control_bytes(std::string("https://h/\0x", 12)));
    CHECK(url_has_control_bytes("https://h/\x7f"));
    CHECK_FALSE(url_has_control_bytes("https://h/ok path"));
    CHECK_FALSE(url_has_control_bytes(""));
}

TEST_CASE("url policy: scheme+host drops userinfo path query and fragment", "[integrations][url]") {
    CHECK(url_scheme_host("https://hooks.example.invalid/services/T0/B0/SECRET") ==
          "https://hooks.example.invalid");
    CHECK(url_scheme_host("http://u:p@host.example:8443/x?y=1#z") == "http://host.example:8443");
    CHECK(url_scheme_host("https://host.example") == "https://host.example");
    CHECK(url_scheme_host("host.example/path").empty());
}

TEST_CASE("url audit detail: scheme+host and a fingerprint, never the path or query",
          "[integrations][url][security]") {
    const std::string secret = "https://hooks.example.invalid/services/T0/B0/SECRET?key=SECRET2";
    const auto d = url_audit_detail(secret);
    CHECK(d.starts_with("url=https://hooks.example.invalid url_fp="));
    CHECK(d.find("SECRET") == std::string::npos);
    CHECK(d.size() == std::string("url=https://hooks.example.invalid url_fp=").size() + 12);
    // Same URL, same fingerprint; any change to the path or query changes it.
    CHECK(d == url_audit_detail(secret));
    CHECK(d != url_audit_detail(secret + "x"));
    CHECK(url_fingerprint("https://siem.example.com/ingest") == "37e8a3290af1");
    // Control bytes (an unvalidated value) never echo; an unparseable value reports the
    // fingerprint alone.
    CHECK(url_audit_detail(std::string("https://h.example/\r\nforged=1")).starts_with("url_fp="));
    CHECK(url_audit_detail("no-scheme/path").starts_with("url_fp="));
}

TEST_CASE("url delivery parts: the authority ends at '/', '?' or '#'",
          "[integrations][url]") {
    auto parts = url_delivery_parts("https://hooks.example?token=x");
    CHECK(parts.scheme == "https");
    CHECK(parts.host_port == "hooks.example");
    CHECK(parts.path == "/?token=x");
    parts = url_delivery_parts("http://h.example:8080/a/b?c=d#frag");
    CHECK(parts.scheme == "http");
    CHECK(parts.host_port == "h.example:8080");
    CHECK(parts.path == "/a/b?c=d"); // the fragment is never sent
    parts = url_delivery_parts("https://h.example#frag");
    CHECK(parts.host_port == "h.example");
    CHECK(parts.path == "/");
    parts = url_delivery_parts("https://h.example");
    CHECK(parts.path == "/");
    // Validation and delivery agree on where the host ends.
    CHECK(detail::url_authority("https://hooks.example?token=x") ==
          url_delivery_parts("https://hooks.example?token=x").host_port);
}

TEST_CASE("mapping audit detail: pairs, removal marker, count", "[integrations][audit]") {
    const auto d = integrations::mapping_audit_chunks({{"g-1", "Operator"}, {"g-2", ""}});
    REQUIRE(d.size() == 1);
    CHECK(d[0] == "2 mappings updated: g-1=Operator, g-2=(removed)");
    const auto e = integrations::mapping_audit_chunks({});
    REQUIRE(e.size() == 1);
    CHECK(e[0] == "0 mappings updated:");
}

TEST_CASE("mapping read-back: only pairs the store shows are confirmed", "[integrations][audit]") {
    using integrations::MappingChange;
    const std::map<std::string, std::string> stored{{"g-1", "Operator"}, {"g-3", "Viewer"}};
    const auto out = integrations::classify_mapping_changes(
        {{"g-1", "Operator"},  // stored as asked
         {"g-2", "Operator"},  // write swallowed: not stored
         {"g-3", ""},          // removal swallowed: still stored
         {"g-4", ""}},         // removal of an absent mapping is confirmed
        stored);
    REQUIRE(out.confirmed.size() == 2);
    CHECK(out.confirmed[0].group_id == "g-1");
    CHECK(out.confirmed[1].group_id == "g-4");
    REQUIRE(out.unconfirmed.size() == 2);
    CHECK(out.unconfirmed[0].group_id == "g-2");
    CHECK(out.unconfirmed[1].group_id == "g-3");
    const auto d = integrations::mapping_audit_chunks(out.unconfirmed, "not confirmed by read-back");
    REQUIRE(d.size() == 1);
    CHECK(d[0] == "2 mappings not confirmed by read-back: g-2=Operator, g-3=(removed)");
}

TEST_CASE("mapping read-back: a group named twice counts as its last entry", "[integrations][audit]") {
    using integrations::MappingChange;
    const auto last = integrations::last_wins_mapping_changes(
        {{"g-1", "bogus"}, {"g-2", "Viewer"}, {"g-1", "Administrator"}, {"g-2", ""}});
    REQUIRE(last.size() == 2);
    CHECK(last[0].group_id == "g-1");
    CHECK(last[0].role_name == "Administrator");
    CHECK(last[1].group_id == "g-2");
    CHECK(last[1].role_name.empty());

    // The store ends with the last entry, so nothing is falsely unconfirmed.
    const std::map<std::string, std::string> stored{{"g-1", "Administrator"}};
    const auto out = integrations::classify_mapping_changes(
        {{"g-1", "bogus"}, {"g-1", "Administrator"}, {"g-2", "x"}, {"g-2", ""}}, stored);
    CHECK(out.unconfirmed.empty());
    CHECK(out.confirmed.size() == 2);
}

TEST_CASE("mapping read-back: a failed read confirms nothing, removals included",
          "[integrations][audit]") {
    using integrations::MappingChange;
    const auto out = integrations::classify_mapping_changes(
        {{"g-1", "Operator"}, {"g-2", ""}}, std::nullopt);
    CHECK(out.confirmed.empty());
    REQUIRE(out.unconfirmed.size() == 2);
    // An empty (readable) set is different: the removal is shown, the set is not.
    const auto empty = integrations::classify_mapping_changes(
        {{"g-1", "Operator"}, {"g-2", ""}}, std::map<std::string, std::string>{});
    CHECK(empty.confirmed.size() == 1);
    CHECK(empty.confirmed[0].group_id == "g-2");
    CHECK(empty.unconfirmed.size() == 1);
    CHECK(integrations::classify_mapping_changes({}, std::nullopt).confirmed.empty());
}

TEST_CASE("mapping audit detail: control bytes cannot split the row", "[integrations][audit]") {
    const auto d = integrations::mapping_audit_chunks({{"g\r\n1", "Ro\nle"}});
    REQUIRE(d.size() == 1);
    CHECK(d[0].find('\n') == std::string::npos);
    CHECK(d[0].find('\r') == std::string::npos);
    CHECK(d[0] == "1 mappings updated: g??1=Ro?le");
}

TEST_CASE("mapping audit detail: a long list is split, never truncated", "[integrations][audit]") {
    // Padding a request must not push an applied pair out of the trail.
    std::vector<integrations::MappingChange> many;
    for (int i = 0; i < 300; ++i)
        many.push_back({"decoy-group-" + std::to_string(i), "Operator"});
    many.push_back({"the-real-group", "Administrator"});
    const auto chunks = integrations::mapping_audit_chunks(many);
    REQUIRE(chunks.size() > 1);
    std::size_t pairs = 0;
    bool found = false;
    for (const auto& c : chunks) {
        // Every row has the documented shape, continuation rows included.
        CHECK(c.find(" mappings updated: ") != std::string::npos);
        CHECK(c.find(":,") == std::string::npos);
        CHECK(std::isdigit(static_cast<unsigned char>(c.front())));
        CHECK(c.size() <= 1000);
        CHECK(c.find("...") == std::string::npos);
        found = found || c.find("the-real-group=Administrator") != std::string::npos;
        for (std::size_t at = 0; (at = c.find('=', at)) != std::string::npos; ++at)
            ++pairs;
    }
    CHECK(found);
    CHECK(pairs == 301);

    // One oversized value is clipped, not allowed to blow a row past the bound.
    const auto big = integrations::mapping_audit_chunks({{std::string(5000, 'g'), "Operator"}});
    REQUIRE(big.size() == 1);
    CHECK(big[0].size() < 400);
}
