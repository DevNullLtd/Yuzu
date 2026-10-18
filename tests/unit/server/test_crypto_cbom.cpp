// /crypto CBOM export: the pure CycloneDX 1.7 shaper (crypto_cbom.hpp). Pins the document shape,
// the "a cut is never silent" truncation properties, the absence of any classification field,
// the identity helpers and MCP's strict argument check. The golden files under
// tests/fixtures/cyclonedx/golden/ are REAL cbom_json output for fixed synthetic inputs: this
// test asserts the exporter still produces those exact bytes, and tests/test_cbom_schema.py
// validates them against the vendored official bom-1.7 schema. Regenerate after an intended
// shape change with YUZU_UPDATE_GOLDEN=1 (writes the files; the test then fails once so the
// update is never silent).

#include "crypto_cbom.hpp"
#include "crypto_library_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace cb = yuzu::server::crypto_cbom;
namespace cl = yuzu::server::crypto_library;
using namespace yuzu::server;
using nlohmann::json;

namespace {

cb::CbomIdentity fixed_identity() {
    return {"urn:uuid:00000000-0000-4000-8000-000000000000", "2026-10-18T00:00:00Z", "0.0.0-test"};
}

CryptoSummary basic_summary() {
    CryptoSummary s;
    CryptoFamilyRow openssl;
    openssl.id = "openssl";
    openssl.display = "OpenSSL";
    openssl.device_count = 7;
    openssl.versions.push_back({"3.0.13", "deb", 5, {"libssl3", "openssl"}});
    openssl.versions.push_back({"", "rpm", 2, {"openssl-libs"}});
    CryptoFamilyRow gnutls;
    gnutls.id = "gnutls";
    gnutls.display = "GnuTLS";
    gnutls.device_count = 3;
    gnutls.versions.push_back({"3.8.3", "", 3, {"libgnutls30"}});
    s.families = {openssl, gnutls};
    s.coverage = {12, 8};
    s.names_from_catalogue = true;
    s.names_as_of = 1760000000;
    return s;
}

CryptoSummary truncated_summary() {
    CryptoSummary s;
    CryptoFamilyRow nss;
    nss.id = "nss";
    nss.display = "NSS";
    nss.device_count = 4;
    nss.versions.push_back({"3.98", "deb", 4, {"libnss3"}});
    nss.versions.back().package_names_truncated = true; // more names than the store lists
    nss.versions_truncated = true; // per-family cap or byte budget
    CryptoFamilyRow botan; // every bucket dropped by the store row cap: no component at all
    botan.id = "botan";
    botan.display = "Botan";
    botan.device_count = 2;
    botan.versions_truncated = true;
    CryptoFamilyRow nettle;
    nettle.id = "nettle";
    nettle.display = "Nettle";
    nettle.device_count = 1;
    nettle.versions.push_back({"3.9.1", "deb", 1, {"libnettle8"}});
    s.families = {nss, botan, nettle};
    s.coverage = {5, 5};
    s.result_truncated = true;
    s.names_from_catalogue = false; // live names: no names_as_of
    return s;
}

std::string pretty(const json& j) { return j.dump(2, ' ', false, json::error_handler_t::replace) + "\n"; }

std::filesystem::path golden_dir() {
    namespace fs = std::filesystem;
    const std::string rel = "tests/fixtures/cyclonedx/golden";
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_SOURCE_ROOT"))
        candidates.emplace_back(fs::path{root} / rel);
    candidates.emplace_back(fs::path{rel});
    fs::path cur = fs::current_path();
    for (int i = 0; i < 6; ++i) {
        candidates.emplace_back(cur / rel);
        if (!cur.has_parent_path() || cur.parent_path() == cur)
            break;
        cur = cur.parent_path();
    }
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::is_directory(c, ec))
            return c;
    }
    return {};
}

// One property's value (first match) from a properties array; nullopt when absent.
std::optional<std::string> prop_value(const json& props, const std::string& name) {
    for (const auto& p : props)
        if (p["name"] == name)
            return p["value"].get<std::string>();
    return std::nullopt;
}

std::vector<std::string> prop_values(const json& props, const std::string& name) {
    std::vector<std::string> out;
    for (const auto& p : props)
        if (p["name"] == name)
            out.push_back(p["value"].get<std::string>());
    return out;
}

void collect_keys(const json& j, std::set<std::string>& out) {
    if (j.is_object())
        for (const auto& [k, v] : j.items()) {
            out.insert(k);
            collect_keys(v, out);
        }
    else if (j.is_array())
        for (const auto& v : j)
            collect_keys(v, out);
}

void check_golden(const std::string& file, const json& doc) {
    const auto dir = golden_dir();
    REQUIRE_FALSE(dir.empty());
    const auto path = dir / file;
    const std::string actual = pretty(doc);
    if (std::getenv("YUZU_UPDATE_GOLDEN") != nullptr) {
        std::ofstream(path, std::ios::binary) << actual;
        FAIL("golden regenerated: " << path << " - unset YUZU_UPDATE_GOLDEN and re-run");
    }
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.good());
    std::stringstream ss;
    ss << in.rdbuf();
    CHECK(ss.str() == actual);
}

} // namespace

TEST_CASE("cbom: document skeleton - CycloneDX 1.7, version 1, injected identity",
          "[crypto][cbom]") {
    const auto d = cb::cbom_json(basic_summary(), fixed_identity());
    CHECK(d["bomFormat"] == "CycloneDX");
    CHECK(d["specVersion"] == "1.7");
    CHECK(d["version"] == 1);
    CHECK(d["serialNumber"] == "urn:uuid:00000000-0000-4000-8000-000000000000");
    CHECK(d["metadata"]["timestamp"] == "2026-10-18T00:00:00Z");
    REQUIRE(d["metadata"]["tools"]["components"].size() == 1);
    const auto& tool = d["metadata"]["tools"]["components"][0];
    CHECK(tool["name"] == "Yuzu");
    CHECK(tool["version"] == "0.0.0-test");
    CHECK(tool["type"] == "application");
    CHECK(cb::kContentType == "application/vnd.cyclonedx+json; version=1.7");
}

TEST_CASE("cbom: one library component per (family, version, ecosystem) bucket",
          "[crypto][cbom]") {
    const auto d = cb::cbom_json(basic_summary(), fixed_identity());
    const auto& c = d["components"];
    REQUIRE(c.size() == 3);
    CHECK(c[0]["type"] == "library"); // a library is NOT a cryptographic-asset
    CHECK(c[0]["name"] == "OpenSSL");
    CHECK(c[0]["version"] == "3.0.13");
    CHECK(c[0]["bom-ref"] == "yuzu-crypto-lib/openssl/3.0.13/deb");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:family_id") == "openssl");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:ecosystem") == "deb");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:device_count") == "5");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:family_device_count") == "7");
    CHECK(prop_values(c[0]["properties"], "yuzu:crypto:package_name") ==
          std::vector<std::string>{"libssl3", "openssl"});
    // A bucket with no version omits the key rather than emitting "".
    CHECK_FALSE(c[1].contains("version"));
    CHECK(c[1]["bom-ref"] == "yuzu-crypto-lib/openssl//rpm");
    // A bucket with no ecosystem keeps the (empty) property: "no ecosystem" is a real value.
    CHECK(prop_value(c[2]["properties"], "yuzu:crypto:ecosystem") == "");
    // No purl: the inventory cannot build a correct one.
    for (const auto& comp : c)
        CHECK_FALSE(comp.contains("purl"));
}

TEST_CASE("cbom: bom-refs are unique and percent-encoded", "[crypto][cbom]") {
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.display = "OpenSSL";
    f.device_count = 2;
    // Two buckets that encode identically cannot come from the store, but refs must stay unique.
    f.versions.push_back({"1.0 beta/x", "deb", 1, {"a"}});
    f.versions.push_back({"1.0 beta/x", "deb", 1, {"b"}});
    s.families.push_back(f);
    const auto d = cb::cbom_json(s, fixed_identity());
    CHECK(d["components"][0]["bom-ref"] == "yuzu-crypto-lib/openssl/1.0%20beta%2Fx/deb");
    CHECK(d["components"][1]["bom-ref"] == "yuzu-crypto-lib/openssl/1.0%20beta%2Fx/deb#2");
}

TEST_CASE("cbom: metadata carries the slice-1 fields under the yuzu:crypto: namespace",
          "[crypto][cbom]") {
    const auto d = cb::cbom_json(basic_summary(), fixed_identity());
    const auto& p = d["metadata"]["properties"];
    CHECK(prop_value(p, "yuzu:crypto:table_version") == std::to_string(cl::kCryptoTableVersion));
    CHECK(prop_value(p, "yuzu:crypto:names_source") == "catalogue");
    CHECK(prop_value(p, "yuzu:crypto:names_as_of") == "1760000000");
    CHECK(prop_value(p, "yuzu:crypto:result_truncated") == "false");
    CHECK(prop_value(p, "yuzu:crypto:truncated_families") == "");
    CHECK(prop_value(p, "yuzu:crypto:devices_reporting") == "12");
    CHECK(prop_value(p, "yuzu:crypto:devices_with_crypto_library") == "8");
    CHECK(prop_value(p, "yuzu:crypto:scope").has_value());
    CHECK_FALSE(prop_value(p, "yuzu:crypto:audit_persisted").has_value());
    for (const auto& pr : p)
        CHECK(pr["name"].get<std::string>().starts_with("yuzu:crypto:"));
}

TEST_CASE("cbom: a cut is never silent - truncated families are flagged everywhere",
          "[crypto][cbom]") {
    const auto d = cb::cbom_json(truncated_summary(), fixed_identity());
    const auto& p = d["metadata"]["properties"];
    CHECK(prop_value(p, "yuzu:crypto:result_truncated") == "true");
    CHECK(prop_value(p, "yuzu:crypto:names_source") == "live");
    CHECK_FALSE(prop_value(p, "yuzu:crypto:names_as_of").has_value()); // absent when live
    // Both the cut family AND the fully emptied one (which has no component) are listed.
    CHECK(prop_value(p, "yuzu:crypto:truncated_families") == "nss,botan");
    const auto& c = d["components"];
    REQUIRE(c.size() == 2); // botan has none
    CHECK(c[0]["name"] == "NSS");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:versions_truncated") == "true");
    CHECK(c[1]["name"] == "Nettle");
    CHECK(prop_value(c[1]["properties"], "yuzu:crypto:versions_truncated") == "false");
    CHECK(prop_value(c[0]["properties"], "yuzu:crypto:package_names_truncated") == "true");
    CHECK(prop_value(c[1]["properties"], "yuzu:crypto:package_names_truncated") == "false");
}

TEST_CASE("cbom: filters are echoed so a filtered BOM is not mistaken for the fleet",
          "[crypto][cbom]") {
    cb::CbomOptions o;
    o.filters.family = "openssl";
    o.filters.ecosystem = "";
    const auto d = cb::cbom_json(basic_summary(), fixed_identity(), o);
    const auto& p = d["metadata"]["properties"];
    CHECK(prop_value(p, "yuzu:crypto:filter_family") == "openssl");
    CHECK(prop_value(p, "yuzu:crypto:filter_ecosystem") == ""); // present-empty is a real filter
    const auto none = cb::cbom_json(basic_summary(), fixed_identity());
    CHECK_FALSE(prop_value(none["metadata"]["properties"], "yuzu:crypto:filter_ecosystem"));
}

TEST_CASE("cbom: a lost access-audit row is flagged in metadata", "[crypto][cbom]") {
    cb::CbomOptions o;
    o.audit_persisted = false;
    const auto d = cb::cbom_json(basic_summary(), fixed_identity(), o);
    CHECK(prop_value(d["metadata"]["properties"], "yuzu:crypto:audit_persisted") == "false");
}

TEST_CASE("cbom: no classification, strength or cryptographic-asset field is ever emitted",
          "[crypto][cbom][security]") {
    for (const auto& s : {basic_summary(), truncated_summary(), CryptoSummary{}}) {
        const auto d = cb::cbom_json(s, fixed_identity());
        std::set<std::string> keys;
        collect_keys(d, keys);
        for (const char* banned :
             {"cryptoProperties", "nistQuantumSecurityLevel", "classicalSecurityLevel",
              "cryptoFunctions", "algorithmProperties", "certificationLevel", "assetType",
              "vulnerabilities", "licenses", "purl"})
            CHECK(keys.count(banned) == 0);
        for (const auto& c : d["components"])
            CHECK(c["type"] == "library");
        const std::string text = pretty(d);
        for (const char* label : {"cryptographic-asset", "insecure", "deprecated", "vulnerable",
                                  "weak", "outdated", "secure"})
            CHECK(text.find(label) == std::string::npos);
    }
}

TEST_CASE("cbom: an empty fleet is a valid BOM with no components", "[crypto][cbom]") {
    const auto d = cb::cbom_json(CryptoSummary{}, fixed_identity());
    CHECK(d["components"].is_array());
    CHECK(d["components"].empty());
    CHECK(prop_value(d["metadata"]["properties"], "yuzu:crypto:devices_reporting") == "0");
}

TEST_CASE("cbom: a stray invalid-UTF-8 byte serialises via dump_safe", "[crypto][cbom]") {
    CryptoSummary s = basic_summary();
    s.families[0].versions[0].package_names[0] = std::string("lib\xFF") + "ssl";
    const auto d = cb::cbom_json(s, fixed_identity());
    CHECK_NOTHROW(cl::dump_safe(d));
}

TEST_CASE("cbom: uuid_urn_v4 forces the version and variant bits", "[crypto][cbom]") {
    std::array<std::uint8_t, 16> ff{};
    ff.fill(0xFF);
    CHECK(cb::uuid_urn_v4(ff) == "urn:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff");
    std::array<std::uint8_t, 16> zero{};
    CHECK(cb::uuid_urn_v4(zero) == "urn:uuid:00000000-0000-4000-8000-000000000000");
}

TEST_CASE("cbom: rfc3339_utc and make_identity", "[crypto][cbom]") {
    CHECK(cb::rfc3339_utc(0) == "1970-01-01T00:00:00Z");
    CHECK(cb::rfc3339_utc(1760000000) == "2025-10-09T08:53:20Z");
    const auto a = cb::make_identity("9.9.9");
    const auto b = cb::make_identity("9.9.9");
    REQUIRE(a);
    REQUIRE(b);
    CHECK(std::regex_match(a->serial_number,
                           std::regex("urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")));
    CHECK(std::regex_match(a->timestamp, std::regex("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ")));
    CHECK(a->serial_number != b->serial_number);
    CHECK(a->tool_version == "9.9.9");
}

TEST_CASE("cbom: strict MCP args - non-object, unknown key, wrong type, unknown family refused",
          "[crypto][cbom][mcp]") {
    CHECK_FALSE(cb::strict_cbom_args_error(json::object()));
    CHECK_FALSE(cb::strict_cbom_args_error(json{{"family", "openssl"}, {"ecosystem", "deb"}}));
    CHECK_FALSE(cb::strict_cbom_args_error(json{{"ecosystem", ""}}));
    for (const json& bad :
         {json(nullptr), json::array(), json::array({"openssl"}), json("openssl"), json(3),
          json(true), json{{"family", 3}}, json{{"family", "notalib"}}, json{{"ecosystem", 5}}, json{{"ecosystem", "notaneco"}},
          json{{"ecosystem", std::string(1025, 'e')}}, json{{"limit", 5}},
          json{{"family", "openssl"}, {"extra", 1}}})
        CHECK(cb::strict_cbom_args_error(bad).has_value());
}

TEST_CASE("cbom: golden output (validated against the official schema by test_cbom_schema.py)",
          "[crypto][cbom][golden]") {
    SECTION("basic") { check_golden("basic.cdx.json", cb::cbom_json(basic_summary(), fixed_identity())); }
    SECTION("truncated") {
        cb::CbomOptions o;
        o.filters.ecosystem = "deb";
        o.audit_persisted = false;
        check_golden("truncated.cdx.json", cb::cbom_json(truncated_summary(), fixed_identity(), o));
    }
    SECTION("empty") { check_golden("empty.cdx.json", cb::cbom_json(CryptoSummary{}, fixed_identity())); }
}
