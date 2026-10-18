// /crypto slice 1: the pure crypto-library model - curated table + classifier, SQL pattern
// derivation, parameter parsing (REST clamps, MCP refuses), filter-bound cursors, JSON shapes.

#include "crypto_library_model.hpp"
#include "utf8_sanitize.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace cl = yuzu::server::crypto_library;
using yuzu::server::CryptoDevicesPage;
using yuzu::server::CryptoDevicesQuery;
using yuzu::server::CryptoFamilyRow;
using yuzu::server::CryptoSummary;
using yuzu::server::CryptoVersionRow;
using nlohmann::json;

namespace {
std::string cls(std::string_view n) {
    const auto f = cl::classify(n);
    return f ? std::string(*f) : std::string("-");
}
// Repo-relative file lookup: $MESON_SOURCE_ROOT, then CWD, then a bounded walk-up from CWD (the
// same order test_dex_obs_table.cpp uses).
std::filesystem::path find_repo_file(const std::string& relative) {
    namespace fs = std::filesystem;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_SOURCE_ROOT"))
        candidates.emplace_back(fs::path{root} / relative);
    candidates.emplace_back(fs::path{relative});
    std::error_code ec;
    fs::path dir = fs::current_path(ec);
    for (int i = 0; !ec && i < 8 && !dir.empty(); ++i) {
        candidates.emplace_back(dir / relative);
        fs::path parent = dir.parent_path();
        if (parent == dir)
            break;
        dir = parent;
    }
    for (const auto& c : candidates) {
        std::error_code e2;
        if (fs::exists(c, e2) && !e2)
            return fs::absolute(c, e2);
    }
    return {};
}

// Every `backticked` token in a table cell.
std::set<std::string> backticked(const std::string& cell) {
    std::set<std::string> out;
    std::size_t i = 0;
    while ((i = cell.find('`', i)) != std::string::npos) {
        const auto j = cell.find('`', i + 1);
        if (j == std::string::npos)
            break;
        out.insert(cell.substr(i + 1, j - i - 1));
        i = j + 1;
    }
    return out;
}

cl::Params P(std::initializer_list<std::pair<const std::string, std::string>> l) {
    return cl::Params(l.begin(), l.end());
}
} // namespace

TEST_CASE("crypto classifier: every family is reachable", "[crypto]") {
    CHECK(cls("openssl") == "openssl");
    CHECK(cls("libssl3") == "openssl");
    CHECK(cls("libssl-dev") == "openssl");
    CHECK(cls("libcrypto3") == "openssl");
    CHECK(cls("openssl@3") == "openssl");
    CHECK(cls("OpenSSL3-libs") == "openssl");
    CHECK(cls("Win64 OpenSSL v3.3.1") == "openssl");
    CHECK(cls("libressl-3.8") == "libressl");
    CHECK(cls("boringssl-fips") == "boringssl");
    CHECK(cls("libgnutls30") == "gnutls");
    CHECK(cls("gnutls") == "gnutls");
    CHECK(cls("gnutls-utils") == "gnutls");
    CHECK(cls("nss") == "nss");
    CHECK(cls("libnss3") == "nss");
    CHECK(cls("nss-softokn-freebl") == "nss");
    CHECK(cls("libmbedtls14") == "mbedtls");
    CHECK(cls("mbedtls") == "mbedtls");
    CHECK(cls("libwolfssl35") == "wolfssl");
    CHECK(cls("libgcrypt20") == "libgcrypt");
    CHECK(cls("libsodium23") == "libsodium");
    CHECK(cls("libnettle8") == "nettle");
    CHECK(cls("nettle") == "nettle");
    CHECK(cls("libbotan-2-19") == "botan");
    CHECK(cls("bouncycastle-prov") == "bouncycastle");
    CHECK(cls("libbcprov-java") == "bouncycastle");
}

TEST_CASE("crypto classifier: negatives and case-insensitivity", "[crypto]") {
    CHECK(cls("nss-mdns") == "-");
    CHECK(cls("nss-pam-ldapd") == "-");
    CHECK(cls("curl") == "-");
    CHECK(cls("") == "-");
    CHECK(cls("OPENSSL") == cls("openssl"));
    CHECK(cls("LibSSL3") == "openssl");
    // Exact rules do not match a longer name.
    CHECK(cls("openssl-devel-extra") == "-");
}

TEST_CASE("crypto classifier: bare libssl/libcrypto prefixes are gone (v2)", "[crypto]") {
    // Negatives: other projects that share the letters.
    for (const char* n : {"libcrypto++8", "libcrypto++-dev", "libcrypto++-utils",
                          "libcryptominisat5-5.8", "libcryptominisat5-dev", "libssl-ocaml",
                          "libssl-ocaml-dev"})
        CHECK(cls(n) == "-");
    // Positives for every rule added in v2.
    CHECK(cls("libssl3t64") == "openssl");
    CHECK(cls("libssl1.1") == "openssl");
    CHECK(cls("libssl0.9.8") == "openssl");
    CHECK(cls("libssl4") == "openssl");
    CHECK(cls("libcrypto0") == "openssl");
    CHECK(cls("libcrypto1.1") == "openssl");
    CHECK(cls("libcrypto3") == "openssl");
    CHECK(cls("libcrypto4") == "openssl");
    CHECK(cls("libssl-dev") == "openssl");
    CHECK(cls("libssl-doc") == "openssl");
    CHECK(cls("openssl-1.1") == "openssl");
    CHECK(cls("openssl-1_1") == "openssl");
    CHECK(cls("openssl-3") == "openssl");
    CHECK(cls("libopenssl1_1") == "openssl");
    CHECK(cls("compat-openssl10") == "openssl");
    CHECK(cls("compat-openssl11") == "openssl");
    CHECK(cls("nss-tools") == "nss");
    CHECK(cls("mozilla-nss") == "nss");
    CHECK(cls("mozilla-nss-tools") == "nss");
    CHECK(cls("libhogweed6") == "nettle");
    CHECK(cls("libbcpkix-java") == "bouncycastle");
    // Unicode look-alikes never fold onto ASCII (one ASCII-only fold rule, same as the SQL).
    CHECK(cls("l\xC4\xB0" "bssl3") == "-");                 // lİbssl3
    CHECK(cls("lib\xC5\xBF" "sl3") == "-");                 // libſsl3
    CHECK(cls("\xEF\xBD\x8C\xEF\xBD\x89\xEF\xBD\x82\xEF\xBD\x93\xEF\xBD\x93"
              "\xEF\xBD\x8C\xEF\xBC\x93") == "-");       // fullwidth libssl3
    CHECK(cls("nss-so\xE2\x84\xAA" "tn") == "-");           // Kelvin sign for the k of nss-softokn
    CHECK(cls("nss-softokn") == "nss");
    // Exact rules stay exact.
    CHECK(cls("libssl-dev-extra") == "-");
    CHECK(cls("nss-tools-extra") == "-");
}

TEST_CASE("crypto table: shape invariants", "[crypto]") {
    const auto rs = cl::rules();
    // Every rule value is lowercase and names a real family.
    for (const auto& r : rs) {
        CHECK(std::ranges::none_of(r.value, [](char c) { return c >= 'A' && c <= 'Z'; }));
        CHECK(cl::find_family(r.family_id) != nullptr);
        CHECK_FALSE(r.value.empty());
    }
    // Sorted by (family_id, kind, value).
    CHECK(std::ranges::is_sorted(rs, [](const cl::MatchRule& a, const cl::MatchRule& b) {
        if (a.family_id != b.family_id)
            return a.family_id < b.family_id;
        if (a.kind != b.kind)
            return a.kind < b.kind;
        return a.value < b.value;
    }));
    // Family ids unique; each family has at least one rule.
    std::set<std::string_view> ids;
    for (const auto& f : cl::families()) {
        CHECK(ids.insert(f.id).second);
        CHECK(std::ranges::any_of(rs, [&](const auto& r) { return r.family_id == f.id; }));
    }
    CHECK(cl::kCryptoTableVersion == 2);
}

TEST_CASE("crypto table: no package name matches two families", "[crypto]") {
    // Every rule's own sample name, plus every probe name used above, matches at most one family.
    std::vector<std::string> names;
    for (const auto& r : cl::rules()) {
        names.emplace_back(r.value);
        names.push_back(std::string(r.value) + "x");
        names.push_back(std::string(r.value) + "-1");
    }
    for (const char* n : {"libssl3", "libcrypto3", "libnss3", "nss-util", "libgnutls30",
                          "libressl", "openssl@3", "libbcprov-java", "libsodium23"})
        names.emplace_back(n);
    for (const auto& n : names) {
        std::set<std::string_view> hit;
        std::string lower = n;
        for (char& c : lower)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        for (const auto& r : cl::rules()) {
            const bool m = r.kind == cl::MatchKind::kExact ? lower == r.value
                                                           : lower.starts_with(r.value);
            if (m)
                hit.insert(r.family_id);
        }
        CHECK(hit.size() <= 1);
    }
}

TEST_CASE("crypto SQL patterns: escaping and shape", "[crypto]") {
    CHECK(cl::like_pattern({"x", cl::MatchKind::kExact, "a_b%c\\d"}) == "a\\_b\\%c\\\\d");
    CHECK(cl::like_pattern({"x", cl::MatchKind::kPrefix, "lib_ssl"}) == "lib\\_ssl%");
    CHECK(cl::like_pattern({"x", cl::MatchKind::kExact, "openssl"}) == "openssl");
    CHECK(cl::like_pattern({"x", cl::MatchKind::kPrefix, "openssl@"}) == "openssl@%");

    const auto all = cl::sql_patterns();
    CHECK(all.patterns.size() == cl::rules().size());
    CHECK(all.labels.size() == all.patterns.size());
    const auto one = cl::sql_patterns("nss");
    REQUIRE(one.patterns.size() == 10);
    CHECK(std::ranges::all_of(one.labels, [](const auto& l) { return l == "nss"; }));
    // nss must not be prefix-matched: no pattern ends in an unescaped %.
    CHECK(std::ranges::none_of(one.patterns, [](const auto& p) { return p.ends_with('%'); }));
    CHECK(cl::sql_patterns("nope").patterns.empty());
}

TEST_CASE("crypto params: summary", "[crypto]") {
    auto ok = cl::parse_summary_params(P({}));
    REQUIRE(ok);
    CHECK_FALSE(ok->family);
    CHECK_FALSE(ok->ecosystem);

    ok = cl::parse_summary_params(P({{"family", "openssl"}, {"ecosystem", "deb"}}));
    REQUIRE(ok);
    CHECK(*ok->family == "openssl");
    CHECK(*ok->ecosystem == "deb");

    // an empty family = no filter; a PRESENT ecosystem, even empty, is the exact (empty) ecosystem
    ok = cl::parse_summary_params(P({{"family", ""}, {"ecosystem", ""}}));
    REQUIRE(ok);
    CHECK_FALSE(ok->family);
    REQUIRE(ok->ecosystem);
    CHECK(ok->ecosystem->empty());
    ok = cl::parse_summary_params(P({{"family", ""}}));
    REQUIRE(ok);
    CHECK_FALSE(ok->ecosystem); // absent = any

    CHECK_FALSE(cl::parse_summary_params(P({{"family", "zzz"}})));
    CHECK_FALSE(cl::parse_summary_params(P({{"family", "openssl"}, {"family", "nss"}})));
    CHECK_FALSE(cl::parse_summary_params(P({{"ecosystem", std::string(cl::kEcosystemMaxBytes + 1, 'a')}})));
    CHECK(cl::parse_summary_params(P({{"ecosystem", std::string(cl::kEcosystemMaxBytes, 'a')}})));
    CHECK_FALSE(cl::parse_summary_params(P({{"ecosystem", "\xff\xfe"}})));
    CHECK_FALSE(cl::parse_summary_params(P({{"ecosystem", std::string("a\0b", 3)}})));
    // unknown keys ignored
    CHECK(cl::parse_summary_params(P({{"bogus", "1"}})));
}

TEST_CASE("crypto params: devices", "[crypto]") {
    CHECK_FALSE(cl::parse_devices_params(P({})));                       // family required
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "zzz"}})));      // unknown
    auto ok = cl::parse_devices_params(P({{"family", "openssl"}}));
    REQUIRE(ok);
    CHECK(ok->limit == 100);
    CHECK_FALSE(ok->version);

    ok = cl::parse_devices_params(P({{"family", "openssl"}, {"version", ""}, {"limit", "5000"}}));
    REQUIRE(ok);
    REQUIRE(ok->version);
    CHECK(ok->version->empty()); // present-empty = exact empty bucket
    CHECK(ok->limit == 1000);    // REST clamps
    ok = cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "-4"}}));
    REQUIRE(ok);
    CHECK(ok->limit == 1);

    // #4644 style: full-consume numeric parsing
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "12abc"}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "1.5"}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "+"}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "99999999999999999999"}})));
    CHECK(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", ""}})));

    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"version", std::string(cl::kVersionMaxBytes + 1, '1')}})));
    // the bound is the ingest bound: a 200-byte version (a real bucket) is drillable
    CHECK(cl::parse_devices_params(P({{"family", "openssl"}, {"version", std::string(200, '1')}})));
    // a present-empty ecosystem is the exact empty bucket on the devices drill too
    {
        const auto e = cl::parse_devices_params(P({{"family", "openssl"}, {"ecosystem", ""}}));
        REQUIRE(e);
        REQUIRE(e->ecosystem);
        CHECK(e->ecosystem->empty());
    }
    // repeats with differing values are refused (identical pairs collapse in the HTTP layer)
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"ecosystem", "a"}, {"ecosystem", "b"}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"cursor", std::string(2049, 'a')}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"version", "\xc3\x28"}})));
    CHECK_FALSE(cl::parse_devices_params(P({{"family", "openssl"}, {"limit", "1"}, {"limit", "2"}})));
}

TEST_CASE("crypto params: MCP strict argument checks", "[crypto]") {
    CHECK_FALSE(cl::strict_summary_args_error(json::object()));
    CHECK_FALSE(cl::strict_summary_args_error(json{{"family", "nss"}, {"ecosystem", "rpm"}}));
    CHECK(cl::strict_summary_args_error(json{{"family", 3}}));
    CHECK(cl::strict_summary_args_error(json{{"family", "nope"}}));
    CHECK(cl::strict_summary_args_error(json{{"ecosystem", std::string(cl::kEcosystemMaxBytes + 1, 'x')}}));
    CHECK_FALSE(cl::strict_summary_args_error(json{{"ecosystem", ""}})); // exact empty ecosystem

    CHECK(cl::strict_devices_args_error(json::object()));          // family required
    CHECK_FALSE(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", 1000}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", 0}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", 1001}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", "5"}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", 1.5}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"limit", 18446744073709551615ULL}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"version", std::string(cl::kVersionMaxBytes + 1, 'v')}}));
    CHECK_FALSE(cl::strict_devices_args_error(json{{"family", "nss"}, {"version", std::string(200, 'v')}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"cursor", std::string(2049, 'c')}}));
    CHECK(cl::strict_devices_args_error(json{{"family", "nss"}, {"version", 3}}));
}

TEST_CASE("crypto cursor: round-trip, tamper and filter binding", "[crypto]") {
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.version = "3.0";
    const auto fp = cl::devices_fingerprint(q);
    CHECK(fp.size() == 16);

    const cl::CursorPos at{"agent:1", std::string("na\x1fme:x", 7), 4242};
    const auto tok = cl::encode_cursor(at, fp);
    const auto back = cl::decode_cursor(tok, fp);
    REQUIRE(back);
    CHECK(back->agent_id == at.agent_id);
    CHECK(back->name == at.name);
    CHECK(back->install_id == 4242);
    CHECK(back->names_as_of == 0); // live

    // The names source rides in the cursor: a catalogue stamp survives the round trip, and a
    // negative or non-numeric stamp is malformed, never a silently "live" cursor.
    const cl::CursorPos cat{"agent:1", "n", 7, 1767225600};
    const auto cat_back = cl::decode_cursor(cl::encode_cursor(cat, fp), fp);
    REQUIRE(cat_back);
    CHECK(cat_back->names_as_of == 1767225600);
    CHECK(cl::names_source_changed_message().find("restart") != std::string_view::npos);
    CHECK(cl::names_source_changed_message().find("names_as_of") != std::string_view::npos);

    // another filter set -> mismatch, never a silent restart
    CryptoDevicesQuery other = q;
    other.family = "nss";
    const auto bad = cl::decode_cursor(tok, cl::devices_fingerprint(other));
    REQUIRE_FALSE(bad);
    CHECK(bad.error() == cl::CursorError::kFilterMismatch);
    other = q;
    other.version = "";
    CHECK(cl::devices_fingerprint(other) != fp);
    other = q;
    other.version.reset();
    CHECK(cl::devices_fingerprint(other) != fp);
    other = q;
    other.ecosystem = "deb";
    CHECK(cl::devices_fingerprint(other) != fp);
    other = q;
    other.limit = 7; // limit is not part of the binding
    CHECK(cl::devices_fingerprint(other) == fp);

    for (const char* junk : {"", "k1:", "k2:0000000000000000:abc", "k1:zzzzzzzzzzzzzzzz:abc",
                             "k1:0000000000000000:!!!"}) {
        const auto r = cl::decode_cursor(junk, fp);
        REQUIRE_FALSE(r);
        CHECK(r.error() == cl::CursorError::kMalformed);
    }
    CHECK_FALSE(cl::decode_cursor(tok.substr(0, tok.size() - 3), fp));
}

TEST_CASE("crypto summary: finish_summary orders, caps and drops empties", "[crypto]") {
    CryptoSummary s;
    CryptoFamilyRow a;
    a.id = "nss";
    a.device_count = 5;
    CryptoFamilyRow b;
    b.id = "openssl";
    b.device_count = 5;
    CryptoFamilyRow z;
    z.id = "botan";
    z.device_count = 0;
    CryptoFamilyRow c;
    c.id = "gnutls";
    c.device_count = 9;
    for (int i = 0; i < 60; ++i)
        c.versions.push_back(CryptoVersionRow{"v" + std::to_string(100 + i), "deb", i, {}});
    s.families = {a, b, z, c};
    cl::finish_summary(s);
    REQUIRE(s.families.size() == 3);
    CHECK(s.families[0].id == "gnutls");
    CHECK(s.families[1].id == "nss"); // ties break on id
    CHECK(s.families[2].id == "openssl");
    CHECK(s.families[0].display == "GnuTLS");
    CHECK(s.families[0].versions.size() == cl::kMaxVersionsPerFamily);
    CHECK(s.families[0].versions_truncated);
    CHECK(s.families[0].versions.front().device_count == 59);
}

TEST_CASE("crypto JSON: summary and devices shapes", "[crypto]") {
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.device_count = 3;
    f.versions.push_back(CryptoVersionRow{"3.0.13", "deb", 3, {"libssl3"}});
    s.families.push_back(f);
    s.coverage = {10, 4};
    cl::finish_summary(s);
    const json j = cl::summary_json(s);
    CHECK(j["table_version"] == 2);
    CHECK(j["families"][0]["id"] == "openssl");
    CHECK(j["families"][0]["display"] == "OpenSSL");
    CHECK(j["families"][0]["device_count"] == 3);
    CHECK(j["families"][0]["versions"][0]["version"] == "3.0.13");
    CHECK(j["families"][0]["versions"][0]["ecosystem"] == "deb");
    CHECK(j["families"][0]["versions"][0]["package_names"][0] == "libssl3");
    CHECK(j["families"][0]["versions_truncated"] == false);
    CHECK(j["coverage"]["devices_reporting_inventory"] == 10);
    CHECK(j["coverage"]["devices_with_crypto_library"] == 4);
    CHECK(j["result_truncated"] == false);

    CryptoDevicesPage p;
    p.family = "openssl";
    p.devices.push_back({"a1", "", "libssl3", "3.0.13", "0ubuntu3.4", "deb", "package"});
    p.devices.push_back({"a2", "host2", "libssl3", "3.0.13", "", "deb", "package"});
    const json d = cl::devices_json(p);
    CHECK(d["family"] == "openssl");
    CHECK(d["version"].is_null());
    CHECK(d["ecosystem"].is_null()); // absent filter echoes null
    CHECK(d["next_cursor"].is_null());
    CHECK(d["count"] == 2);
    CHECK(d["devices"][0]["hostname"].is_null());
    CHECK(d["devices"][1]["hostname"] == "host2");
    CHECK(d["devices"][0]["release"] == "0ubuntu3.4");
    CHECK(d["devices"][0]["kind"] == "package");
    p.version = "";
    p.next_cursor = "k1:x";
    const json d2 = cl::devices_json(p);
    CHECK(d2["version"] == "");
    p.ecosystem = "";
    CHECK(cl::devices_json(p)["ecosystem"] == ""); // present-empty is echoed as the empty string
    p.ecosystem = "deb";
    CHECK(cl::devices_json(p)["ecosystem"] == "deb");
    CHECK(d2["next_cursor"] == "k1:x");

    // never throws on a stray invalid byte
    p.devices[0].package_name = "bad\xff";
    CHECK_NOTHROW(cl::dump_safe(cl::devices_json(p)));
}

TEST_CASE("crypto cursor: bound to the table version, ecosystem presence and filters",
          "[crypto]") {
    CryptoDevicesQuery q;
    q.family = "openssl";
    const auto fp = cl::devices_fingerprint(q);
    // The same query under another table version is a different binding.
    CHECK(cl::devices_fingerprint(q, cl::kCryptoTableVersion - 1) != fp);
    CHECK(cl::devices_fingerprint(q, cl::kCryptoTableVersion) == fp);
    const auto old_tok =
        cl::encode_cursor({.agent_id = "a", .name = "n", .install_id = 1},
                          cl::devices_fingerprint(q, cl::kCryptoTableVersion - 1));
    const auto r = cl::decode_cursor(old_tok, fp);
    REQUIRE_FALSE(r);
    CHECK(r.error() == cl::CursorError::kFilterMismatch);
    CHECK(cl::cursor_error_message(r.error()).find("table version") != std::string_view::npos);
    CHECK(cl::cursor_error_message(r.error()).find("restart") != std::string_view::npos);
    // '' and absent ecosystem are different walks.
    CryptoDevicesQuery e = q;
    e.ecosystem = "";
    CHECK(cl::devices_fingerprint(e) != fp);
}

TEST_CASE("crypto audit detail: one key set, cid optional, src always present", "[crypto]") {
    CHECK(cl::audit_detail("c-1", "openssl", 3, true, false) ==
          "cid=c-1 tv=2 family=openssl rows=3 src=catalogue");
    CHECK(cl::audit_detail("c-1", "openssl", 3, false, true) ==
          "cid=c-1 tv=2 family=openssl rows=3 src=live page=continuation");
    CHECK(cl::audit_detail("", "all", 0, false, false) == "tv=2 family=all rows=0 src=live");
    CHECK(cl::audit_detail_degraded("c-1", yuzu::server::CryptoReadCause::kStoreDegraded) ==
          "cid=c-1 tv=2 store degraded");
    CHECK(cl::audit_detail_degraded("", yuzu::server::CryptoReadCause::kStoreDegraded) == "tv=2 store degraded");
    CHECK(cl::audit_detail_degraded("c-1", yuzu::server::CryptoReadCause::kCapacity) ==
          "cid=c-1 tv=2 capacity in use");
    CHECK(cl::audit_detail_degraded("", yuzu::server::CryptoReadCause::kCapacity) == "tv=2 capacity in use");
}

TEST_CASE("crypto 503 wording: one message per cause, shared by REST and MCP", "[crypto]") {
    CHECK(cl::degraded_message(yuzu::server::CryptoReadCause::kStoreDegraded) == "crypto library read degraded");
    CHECK(cl::degraded_message(yuzu::server::CryptoReadCause::kCapacity) == "crypto read capacity in use; retry");
    CHECK(cl::degraded_message(yuzu::server::CryptoReadCause::kNone) == "crypto library read degraded");
}

TEST_CASE("crypto summary: a hostile many-bucket report stays inside the byte budget and says so",
          "[crypto]") {
    // 12 families x 200 version rows x 8 names x 1 KiB (~20 MB in): far over both the 50-bucket
    // per-family cap and, after it, the byte budget. Larger inputs add nothing - the per-family
    // cap already bounds what reaches the budget - and cost peak RSS.
    CryptoSummary s;
    for (const auto& fam : cl::families()) {
        CryptoFamilyRow f;
        f.id = std::string(fam.id);
        f.device_count = 5;
        for (int i = 0; i < 200; ++i) {
            CryptoVersionRow v;
            v.version = "0." + std::to_string(i);
            v.ecosystem = "deb";
            v.device_count = 1;
            for (int n = 0; n < 8; ++n)
                v.package_names.push_back(std::string(1024, static_cast<char>('a' + n)));
            f.versions.push_back(std::move(v));
        }
        s.families.push_back(std::move(f));
    }
    s.coverage = {100, 5};
    cl::finish_summary(s);
    const std::string body = cl::dump_safe(cl::summary_json(s));
    CHECK(body.size() < cl::kSummaryByteBudget);
    CHECK(s.result_truncated);
    REQUIRE(s.families.size() == 12);
    CHECK(s.families.front().versions.size() <= cl::kMaxVersionsPerFamily);
    for (const auto& f : s.families) {
        CHECK(f.versions_truncated);
        CHECK_FALSE(f.versions.empty()); // every family keeps its first bucket
        for (const auto& v : f.versions)
            for (const auto& n : v.package_names)
                CHECK(n.size() <= cl::kNameMaxBytes);
    }
    CHECK(s.families.front().versions.size() > 1); // the budget admitted more than the floor
}

TEST_CASE("crypto summary: a cut package name is UTF-8 safe and marked", "[crypto]") {
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.device_count = 1;
    // 3-byte code points straddling the 256-byte cut.
    std::string long_name;
    while (long_name.size() < 400)
        long_name += "\xE2\x82\xAC"; // euro sign
    f.versions.push_back(CryptoVersionRow{"1", "deb", 1, {long_name, "libssl3"}});
    s.families.push_back(f);
    cl::finish_summary(s);
    const auto& names = s.families[0].versions[0].package_names;
    REQUIRE(names.size() == 2);
    CHECK(names[0].size() <= cl::kNameMaxBytes);
    CHECK(names[0].ends_with("\xE2\x80\xA6"));
    CHECK(::yuzu::server::sanitize_utf8_strict(names[0]) == names[0]);
    CHECK(names[1] == "libssl3"); // short names untouched
    CHECK_FALSE(s.families[0].versions_truncated);
}

TEST_CASE("crypto summary: a family emptied by the store row cap reports versions_truncated",
          "[crypto]") {
    CryptoSummary s;
    CryptoFamilyRow f;
    f.id = "openssl";
    f.device_count = 4; // the label total survived, every version row was cut
    s.families.push_back(f);
    s.result_truncated = true;
    cl::finish_summary(s);
    REQUIRE(s.families.size() == 1);
    CHECK(s.families[0].versions.empty());
    CHECK(s.families[0].versions_truncated);
    // Without a store cut an empty list is not flagged.
    CryptoSummary t;
    t.families.push_back(f);
    cl::finish_summary(t);
    CHECK_FALSE(t.families[0].versions_truncated);
}

TEST_CASE("crypto JSON: the devices page carries table_version", "[crypto]") {
    CryptoDevicesPage p;
    p.family = "openssl";
    CHECK(cl::devices_json(p)["table_version"] == cl::kCryptoTableVersion);
}

TEST_CASE("crypto table: the families table in crypto.md lists exactly rules()", "[crypto][docs]") {
    const auto path = find_repo_file("docs/user-manual/crypto.md");
    if (path.empty())
        FAIL("docs/user-manual/crypto.md not found - the table pin has nothing to read");
    std::ifstream f(path);
    REQUIRE(f.good());

    struct Cells {
        std::set<std::string> exact, prefix;
        std::string display;
    };
    std::map<std::string, Cells> doc;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.starts_with("| `"))
            continue;
        // | `id` | Display | exact | prefixes |
        std::vector<std::string> cells;
        std::size_t pos = 1;
        while (true) {
            const auto bar = line.find('|', pos);
            if (bar == std::string::npos)
                break;
            cells.push_back(line.substr(pos, bar - pos));
            pos = bar + 1;
        }
        if (cells.size() != 4)
            continue;
        const auto id = backticked(cells[0]);
        if (id.size() != 1 || !cl::find_family(*id.begin()))
            continue; // an endpoint / verb table row, not the family table
        doc[*id.begin()] = {backticked(cells[2]), backticked(cells[3]), cells[1]};
    }

    std::map<std::string, Cells> code;
    for (const auto& r : cl::rules())
        (r.kind == cl::MatchKind::kExact ? code[std::string(r.family_id)].exact
                                         : code[std::string(r.family_id)].prefix)
            .insert(std::string(r.value));
    REQUIRE(doc.size() == cl::families().size());
    for (const auto& fam : cl::families()) {
        const std::string id{fam.id};
        INFO("family " << id);
        REQUIRE(doc.contains(id));
        CHECK(doc[id].exact == code[id].exact);
        CHECK(doc[id].prefix == code[id].prefix);
        CHECK(doc[id].display.find(std::string(fam.display)) != std::string::npos);
    }
}

TEST_CASE("crypto SQL patterns: every rule has a 3-character lowercase lead the pattern starts with",
          "[crypto]") {
    // A rule literal shorter than kLeadChars is a compile error (static_assert in the model);
    // this pins the runtime half: the lead is the literal's first kLeadChars characters.
    const auto pats = cl::sql_patterns();
    REQUIRE(pats.leads.size() == pats.patterns.size());
    REQUIRE(pats.leads.size() == cl::rules().size());
    for (std::size_t i = 0; i < cl::rules().size(); ++i) {
        const auto& r = cl::rules()[i];
        INFO(r.value);
        CHECK(r.value.size() >= cl::kLeadChars);
        CHECK(pats.leads[i].size() == cl::kLeadChars);
        CHECK(pats.leads[i] == std::string(r.value.substr(0, cl::kLeadChars)));
        CHECK(std::ranges::none_of(pats.leads[i], [](char c) { return c >= 'A' && c <= 'Z'; }));
    }
    // A per-family request carries the family's leads only.
    const auto one = cl::sql_patterns("libressl");
    REQUIRE(one.leads.size() == one.patterns.size());
    for (const auto& l : one.leads)
        CHECK(l == "lib");
}

TEST_CASE("crypto JSON: names_source and names_as_of ride on the summary and the devices page",
          "[crypto]") {
    CryptoSummary s;
    s.names_from_catalogue = true;
    s.names_as_of = 1760000000;
    CHECK(cl::summary_json(s)["names_source"] == "catalogue");
    CHECK(cl::summary_json(s)["names_as_of"] == 1760000000);
    CryptoDevicesPage p;
    p.names_from_catalogue = true;
    p.names_as_of = 1760000001;
    CHECK(cl::devices_json(p)["names_source"] == "catalogue");
    CHECK(cl::devices_json(p)["names_as_of"] == 1760000001);
    // Live names: the source says so and names_as_of is null, never 0.
    s.names_from_catalogue = false;
    s.names_as_of = 0;
    CHECK(cl::summary_json(s)["names_source"] == "live");
    CHECK(cl::summary_json(s)["names_as_of"].is_null());
    p.names_from_catalogue = false;
    p.names_as_of = 0;
    CHECK(cl::devices_json(p)["names_source"] == "live");
    CHECK(cl::devices_json(p)["names_as_of"].is_null());
}
