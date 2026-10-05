/**
 * test_mgmt_posture_parsers.cpp -- pure tests for the mgmt_posture plugin's INI parser,
 * SSSD active-domain classifier, IPA default.conf check, `profiles status` parser and
 * row formatters. Portable, no I/O.
 *
 * Fixture provenance: the unenrolled `profiles` text is a REAL capture; every other
 * specimen is SYNTHETIC (no AD/IPA-joined Linux host or enrolled Mac was available to
 * capture from), built from the documented layouts, same caveat as
 * device_identity_macos.hpp.
 */
#include <catch2/catch_test_macros.hpp>

#include "mgmt_posture_parsers.hpp"

#include <string>
#include <vector>

using namespace yuzu::mgmt_posture;

namespace {

// SYNTHETIC: modelled on the sssd.conf(5) EXAMPLE section (AD provider).
constexpr const char* kAdConf = R"(# sssd.conf
[sssd]
config_file_version = 2
services = nss, pam
domains = example.com
id_provider = ad

[domain/example.com]
id_provider = ad
access_provider = ad
)";

// SYNTHETIC: modelled on the layout ipa-client-install documents.
constexpr const char* kIpaConf = R"([sssd]
services = nss, sudo, pam, ssh
domains = ipa.example.com

[domain/ipa.example.com]
id_provider = ipa
ipa_server = _srv_, ipa01.ipa.example.com
)";

// SYNTHETIC: [domain/legacy] (ldap) declared BEFORE [domain/corp] (ad).
constexpr const char* kLegacyBeforeCorp = R"([sssd]
domains = corp

[domain/legacy]
id_provider = ldap

[domain/corp]
id_provider = ad
)";

// REAL capture: macOS 26.6.2 (braga), 2026-10-04, `/usr/bin/profiles status -type enrollment`.
constexpr const char* kProfilesUnenrolled = "Enrolled via DEP: No\nMDM enrollment: No\n";

// SYNTHETIC: Apple-documented enrolled shape; the MDM server line is documented, not captured.
constexpr const char* kProfilesEnrolled =
    "Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"
    "MDM server: https://mdm.example.com/devicemanagement/mdm/dep_mdm_enroll";

SssdFacts facts(const char* text) { return sssd_facts(parse_ini(text)); }
Plane plane_of(const char* text) { return classify_linux(facts(text), false); }

} // namespace

TEST_CASE("mgmt_posture: parse_ini basics", "[mgmt_posture]") {
    const auto d = parse_ini("; c\r\n# c\r\n\r\n[a]\r\nk = v1 \r\nk=v2\r\n[b]\r\nx=1\r\n[a]\r\ny = 2\r\n"
                             "stray=1\n[bad\nz=1\n");
    REQUIRE(d.section_order == std::vector<std::string>{"a", "b"});
    CHECK(d.sections.at("a").at("k") == "v2"); // last wins
    CHECK(d.sections.at("a").at("y") == "2");  // re-opened section merges
    CHECK(d.sections.at("b").at("x") == "1");
    CHECK_FALSE(d.sections.at("a").contains("z"));
    CHECK(parse_ini("").sections.empty());
}

TEST_CASE("mgmt_posture: AD and IPA specimens", "[mgmt_posture]") {
    const auto ad = facts(kAdConf);
    CHECK(ad.active_domains == std::vector<std::string>{"example.com"});
    CHECK(ad.id_provider_by_domain.at("example.com") == "ad");
    CHECK(ad.domains_key_present);
    CHECK(plane_of(kAdConf) == Plane::ad);

    const auto ipa = facts(kIpaConf);
    CHECK(ipa.id_provider_by_domain.at("ipa.example.com") == "ipa");
    CHECK(plane_of(kIpaConf) == Plane::ipa);
}

TEST_CASE("mgmt_posture: CRLF variant classifies the same", "[mgmt_posture]") {
    std::string crlf;
    for (const char* p = kAdConf; *p; ++p) {
        if (*p == '\n')
            crlf += '\r';
        crlf += *p;
    }
    CHECK(plane_of(crlf.c_str()) == Plane::ad);
}

TEST_CASE("mgmt_posture: id_provider under [sssd] alone is ignored", "[mgmt_posture]") {
    const auto f = facts("[sssd]\nid_provider=ad\n");
    CHECK(f.active_domains.empty());
    CHECK(classify_linux(f, false) == Plane::none);
}

TEST_CASE("mgmt_posture: F1 legacy ldap before corp ad", "[mgmt_posture]") {
    CHECK(facts(kLegacyBeforeCorp).active_domains == std::vector<std::string>{"corp"});
    CHECK(plane_of(kLegacyBeforeCorp) == Plane::ad);

    const auto both = facts("[sssd]\ndomains = legacy, corp\n[domain/legacy]\nid_provider=ldap\n"
                            "[domain/corp]\nid_provider=ad\n");
    CHECK(both.active_domains == std::vector<std::string>{"legacy", "corp"});
    CHECK(classify_linux(both, false) == Plane::ad);
}

TEST_CASE("mgmt_posture: enabled = false, enabled = true, undeclared names", "[mgmt_posture]") {
    CHECK(plane_of("[sssd]\ndomains = corp\n[domain/corp]\nid_provider=ad\nenabled = false\n") ==
          Plane::none);
    // enabled = true activates a declared domain not listed in domains
    const auto f = facts("[sssd]\ndomains = a\n[domain/a]\nid_provider=ldap\n"
                         "[domain/b]\nid_provider=ad\nenabled = true\n[domain/c]\nid_provider=ipa\n");
    CHECK(f.active_domains == std::vector<std::string>{"a", "b"});
    CHECK(classify_linux(f, false) == Plane::ad);
    // listed but undeclared -> not active
    CHECK(facts("[sssd]\ndomains = ghost\n").active_domains.empty());
}

TEST_CASE("mgmt_posture: conf.d snippet last-wins override", "[mgmt_posture]") {
    const std::string merged = std::string("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ldap\n") +
                               "\n[domain/corp]\nid_provider = ad\n";
    CHECK(plane_of(merged.c_str()) == Plane::ad);
}

TEST_CASE("mgmt_posture: no domains key falls back to file order", "[mgmt_posture]") {
    const auto f = facts("[sssd]\nservices = nss\n[domain/x]\nid_provider=ldap\n"
                         "[domain/y]\nid_provider=ipa\n[domain/z]\nid_provider=ad\nenabled=false\n");
    CHECK_FALSE(f.domains_key_present);
    CHECK(f.active_domains == std::vector<std::string>{"x", "y"});
    CHECK(classify_linux(f, false) == Plane::ipa);
}

TEST_CASE("mgmt_posture: mixed ad+ipa follows query order", "[mgmt_posture]") {
    const char* t = "[sssd]\ndomains = %s\n[domain/a]\nid_provider=ad\n[domain/i]\nid_provider=ipa\n";
    std::string ai = t, ia = t;
    ai.replace(ai.find("%s"), 2, "a, i");
    ia.replace(ia.find("%s"), 2, "i a");
    CHECK(plane_of(ai.c_str()) == Plane::ad);
    CHECK(plane_of(ia.c_str()) == Plane::ipa);
}

TEST_CASE("mgmt_posture: ipa default.conf and classify matrix", "[mgmt_posture]") {
    CHECK(parse_ipa_default_conf_has_realm(parse_ini("[global]\nrealm = IPA.EXAMPLE.COM\n")));
    CHECK_FALSE(parse_ipa_default_conf_has_realm(parse_ini("[global]\nrealm =\n")));
    CHECK_FALSE(parse_ipa_default_conf_has_realm(parse_ini("[global]\nhost = x\n")));

    const auto ad = facts(kAdConf);
    const auto nodom = facts("[sssd]\n");
    CHECK(classify_linux(ad, false) == Plane::ad);
    CHECK(classify_linux(ad, true) == Plane::ad);
    CHECK(classify_linux(nodom, true) == Plane::ipa);
    CHECK(classify_linux(nodom, false) == Plane::none);
    CHECK(classify_linux(std::nullopt, true) == Plane::ipa);
    CHECK(classify_linux(std::nullopt, false) == Plane::none);
}

TEST_CASE("mgmt_posture: parse_profiles_status", "[mgmt_posture]") {
    const auto u = parse_profiles_status(kProfilesUnenrolled);
    CHECK(u.dep_enrolled == false);
    CHECK(u.mdm_enrolled == false);
    CHECK(u.mdm_server_host.empty());
    CHECK(u.recognised());

    const auto e = parse_profiles_status(kProfilesEnrolled);
    CHECK(e.dep_enrolled == true);
    CHECK(e.mdm_enrolled == true);
    CHECK(e.mdm_server_host == "mdm.example.com");

    CHECK(parse_profiles_status("MDM server: https://u:p@h.example.com:8443/x?t=secret\n")
              .mdm_server_host == "h.example.com");
    CHECK_FALSE(parse_profiles_status("").recognised());
    CHECK_FALSE(parse_profiles_status("garbage\nfoo: bar\n").recognised());
}

TEST_CASE("mgmt_posture: profiles yes/no is a whole word, never a prefix", "[mgmt_posture]") {
    // MUTATION: matching with starts_with() reads "Yesterday" as yes and "None"/"Not applicable" as no.
    CHECK(parse_profiles_status("MDM enrollment: Yes (User Approved)\n").mdm_enrolled == true);
    CHECK(parse_profiles_status("MDM enrollment: No\n").mdm_enrolled == false);
    for (const char* v : {"Yesterday", "None", "Not applicable", "Nope", ""}) {
        const auto r = parse_profiles_status(std::string{"MDM enrollment: "} + v + "\n");
        INFO("value: " << v);
        CHECK_FALSE(r.mdm_enrolled.has_value());
    }
}

TEST_CASE("mgmt_posture: conf.d snippet selection", "[mgmt_posture]") {
    CHECK(is_snippet_name("10-ad.conf"));
    CHECK(is_snippet_name("a.conf"));
    CHECK_FALSE(is_snippet_name(".conf"));       // too short: no stem
    CHECK_FALSE(is_snippet_name(".hidden.conf")); // dotfile
    CHECK_FALSE(is_snippet_name("10-ad.confx"));
    CHECK_FALSE(is_snippet_name("10-ad.conf.bak"));
    CHECK_FALSE(is_snippet_name("readme"));

    std::vector<std::string> names{"20-b.conf", "10-a.conf", "15-z.conf"};
    bool too_many = false;
    finalize_snippets(names, 32, too_many);
    CHECK(names == std::vector<std::string>{"10-a.conf", "15-z.conf", "20-b.conf"}); // byte order
    CHECK_FALSE(too_many);

    // MUTATION: dropping the cut (or not flagging it) lets a 33rd snippet be silently ignored
    // or silently read.
    names = {"c.conf", "a.conf", "b.conf", "d.conf"};
    finalize_snippets(names, 2, too_many);
    CHECK(names == std::vector<std::string>{"a.conf", "b.conf"});
    CHECK(too_many);
}

TEST_CASE("mgmt_posture: profiles output without the MDM line is not recognised", "[mgmt_posture]") {
    // MUTATION: accepting a DEP-only text reports supported with mdm_enrolled|- for a changed
    // or localised output.
    CHECK_FALSE(parse_profiles_status("Enrolled via DEP: Yes\n").recognised());
    CHECK(parse_profiles_status("MDM enrollment: No\n").recognised());
}

TEST_CASE("mgmt_posture: the MDM host row carries only valid UTF-8", "[mgmt_posture]") {
    // MUTATION: dropping sanitize_utf8 lets invalid bytes reach the protobuf output row.
    const auto e = parse_profiles_status(std::string("MDM enrollment: Yes\nMDM server: https://h\xff\xfe.example.com/x\n"));
    const auto rows = macos_rows(e);
    for (const auto& r : rows)
        for (unsigned char c : r)
            CHECK(c < 0x80);
}

TEST_CASE("mgmt_posture: row formatters", "[mgmt_posture]") {
    using V = std::vector<std::string>;
    CHECK(plane_token(Plane::ad) == "ad");
    CHECK(plane_token(Plane::unknown) == "unknown");

    CHECK(linux_rows(Plane::ad, Presence::present) ==
          V{"plane|ad", "mdm_enrolled|-", "mdm_provider|-", "tenant_id|-", "krb5_keytab|present"});
    CHECK(linux_rows(Plane::none, Presence::absent).back() == "krb5_keytab|absent");
    CHECK(linux_rows(Plane::unknown, Presence::unknown).back() == "krb5_keytab|-");

    CHECK(macos_rows(parse_profiles_status(kProfilesUnenrolled)) ==
          V{"plane|-", "mdm_enrolled|false", "mdm_provider|-", "tenant_id|-"});
    CHECK(macos_rows(parse_profiles_status(kProfilesEnrolled)) ==
          V{"plane|-", "mdm_enrolled|true", "mdm_provider|mdm.example.com", "tenant_id|-"});
    CHECK(macos_rows(ProfilesEnrollment{})[1] == "mdm_enrolled|-");

    ProfilesEnrollment hostile;
    hostile.mdm_enrolled = true;
    hostile.mdm_server_host = "a|b\nc";
    CHECK(macos_rows(hostile)[2] == "mdm_provider|a\\|b c");

    for (const auto& r : linux_rows(Plane::ad, Presence::present))
        CHECK_FALSE(r.starts_with("status|"));
    for (const auto& r : macos_rows(hostile))
        CHECK_FALSE(r.starts_with("status|"));
}
