/**
 * test_integrations_url_policy.cpp — pure checks shared by the webhook and
 * offload-target create paths (System pages, SYS-5): userinfo and control-byte
 * refusal, scheme+host reduction for the analytics event, and the bounded,
 * line-safe directory mapping audit detail. No store, no network.
 */

#include "integrations_sync_model.hpp"
#include "outbound_url_policy.hpp"

#include <catch2/catch_test_macros.hpp>

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

TEST_CASE("mapping audit detail: pairs, removal marker, count", "[integrations][audit]") {
    using integrations::MappingChange;
    const auto d = integrations::mapping_audit_detail(
        {{"g-1", "Operator"}, {"g-2", ""}});
    CHECK(d == "2 mappings updated: g-1=Operator, g-2=(removed)");
}

TEST_CASE("mapping audit detail: control bytes cannot split the row", "[integrations][audit]") {
    const auto d = integrations::mapping_audit_detail({{"g\r\n1", "Ro\nle"}});
    CHECK(d.find('\n') == std::string::npos);
    CHECK(d.find('\r') == std::string::npos);
    CHECK(d == "1 mappings updated: g??1=Ro?le");
}

TEST_CASE("mapping audit detail: bounded", "[integrations][audit]") {
    std::vector<integrations::MappingChange> many;
    for (int i = 0; i < 500; ++i)
        many.push_back({"group-" + std::to_string(i), "Operator"});
    const auto d = integrations::mapping_audit_detail(many, 1000);
    CHECK(d.size() <= 1000 + 4);
    CHECK(d.starts_with("500 mappings updated:"));
    CHECK(d.ends_with(" ..."));
}
