// The pure model behind the fleet certificate read surface (slice-2 PR 2a-2b): ONE parameter
// validator for REST and MCP (every filter valid and every refusal, identical on both twins), the
// filter-bound cursors, the truncation OR rule, the audit detail (names and operators, never
// values - so subjects and SANs never reach an audit row) and the D10 no-verdict lint. No
// database, no routes.

#include "certificate_read_model.hpp"
#include "openapi_spec_access.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace crt = yuzu::server::cert_read;
using Catch::Matchers::ContainsSubstring;
using Json = nlohmann::json;

namespace {

crt::Params P(std::initializer_list<std::pair<const std::string, std::string>> l) {
    return crt::Params(l.begin(), l.end());
}

std::string hex64(char c) { return std::string(64, c); }

// The same arguments through both twins: REST feeds the query string, MCP the JSON arguments
// (type-checked, then converted). A bad value must be refused identically on both.
struct Twin {
    std::string key;
    std::string rest_value;
    Json mcp_value;
};

} // namespace

TEST_CASE("cert read model: every filter parses and normalises", "[certread][model]") {
    const auto q = crt::parse_list_params(P({
        {"store", "LocalMachine\\Root"},
        {"scope", "machine"},
        {"key_alg_oid", "1.2.840.113549.1.1.1"},
        {"sig_alg_oid", "1.2.840.113549.1.1.11"},
        {"ec_curve_oid", "1.2.840.10045.3.1.7"},
        {"not_after_before", "2030-01-01T00:00:00Z"},
        {"not_after_after", "2020-02-29T23:59:59Z"},
        {"not_before_after", "0001-01-01T00:00:00Z"},
        {"rsa_modulus_bits_lt", "2048"},
        {"ec_order_bits_lt", "256"},
        {"is_ca", "true"},
        {"self_signed", "false"},
        {"agent_id", "agent-1"},
        {"issuer_dn", "CN=Test CA"},
        {"issuer_dn_contains", "eMudhra"},
        {"subject_dn_contains", "emSign"},
        {"sha256", std::string(64, 'A')},
        {"spki_sha256", std::string(64, 'B')},
        {"aki_key_id", "aabbcc"},
        {"cursor", "c1:x"},
        {"limit", "250"},
    }));
    REQUIRE(q.has_value());
    CHECK(*q->filter.store == "LocalMachine\\Root");
    CHECK(*q->filter.scope == "machine");
    CHECK(*q->filter.rsa_modulus_bits_lt == 2048);
    CHECK(*q->filter.ec_order_bits_lt == 256);
    CHECK(*q->filter.is_ca == true);
    CHECK(*q->filter.self_signed == false);
    CHECK(*q->filter.issuer_dn_contains == "eMudhra"); // the value is kept verbatim (matched case-insensitively)
    // Hex compares case-insensitively against the STORED case: digests lowercase, key ids upper.
    CHECK(*q->filter.sha256 == hex64('a'));
    CHECK(*q->filter.spki_sha256 == hex64('b'));
    CHECK(*q->filter.aki_key_id == "AABBCC");
    CHECK(q->limit == 250);
    CHECK(q->cursor == "c1:x");
}

TEST_CASE("cert read model: defaults, and an empty issuer is a real value", "[certread][model]") {
    const auto q = crt::parse_list_params(P({}));
    REQUIRE(q.has_value());
    CHECK(q->limit == kCertPageDefault);
    CHECK(q->cursor.empty());
    CHECK_FALSE(q->filter.issuer_dn.has_value());
    const auto e = crt::parse_list_params(P({{"issuer_dn", ""}}));
    REQUIRE(e.has_value());
    REQUIRE(e->filter.issuer_dn.has_value());
    CHECK(e->filter.issuer_dn->empty());
}

TEST_CASE("cert read model: every refusal names the parameter", "[certread][model]") {
    const auto refused = [](const char* key, const std::string& v, const char* names) {
        INFO(key << "=" << v);
        const auto r = crt::parse_list_params(P({{key, v}}));
        REQUIRE_FALSE(r.has_value());
        CHECK_THAT(r.error(), ContainsSubstring(names));
    };
    refused("scope", "user", "scope");
    refused("scope", "", "scope");
    for (const char* k : {"key_alg_oid", "sig_alg_oid", "ec_curve_oid"}) {
        refused(k, "", k);
        refused(k, "1", k);
        refused(k, "3.1.2", k);
        refused(k, "1.2.x", k);
        refused(k, "1..2", k);
        refused(k, "1.2.", k);
        refused(k, " 1.2.3", k);
    }
    for (const char* k : {"not_after_before", "not_after_after", "not_before_after"}) {
        refused(k, "", k);
        refused(k, "2030-01-01", k);
        refused(k, "2030-01-01T00:00:00", k);
        refused(k, "2030-01-01T00:00:00+01:00", k);
        refused(k, "2030-01-01T00:00:00.5Z", k);
        refused(k, "2030-13-01T00:00:00Z", k);
        refused(k, "2030-02-30T00:00:00Z", k);
        refused(k, "2023-02-29T00:00:00Z", k);
        refused(k, "2030-01-01T24:00:00Z", k);
        refused(k, "0000-01-01T00:00:00Z", k);
        refused(k, "2030-01-01t00:00:00z", k);
    }
    for (const char* k : {"rsa_modulus_bits_lt", "ec_order_bits_lt"}) {
        refused(k, "", k);
        refused(k, "0", k);
        refused(k, "65537", k);
        refused(k, "-5", k);
        refused(k, "+5", k);
        refused(k, "abc", k);
        refused(k, "2048.0", k);
    }
    for (const char* k : {"is_ca", "self_signed"}) {
        refused(k, "", k);
        refused(k, "1", k);
        refused(k, "TRUE", k);
        refused(k, "yes", k);
    }
    refused("sha256", "abc", "sha256");
    refused("sha256", std::string(63, 'a'), "sha256");
    refused("sha256", std::string(64, 'g'), "sha256");
    refused("spki_sha256", std::string(65, 'a'), "spki_sha256");
    refused("aki_key_id", "a", "aki_key_id");
    refused("aki_key_id", "abc", "aki_key_id"); // whole bytes only
    refused("aki_key_id", std::string(130, 'a'), "aki_key_id");
    refused("aki_key_id", "zz", "aki_key_id");
    refused("issuer_dn_contains", "ab", "issuer_dn_contains");
    refused("issuer_dn_contains", std::string(257, 'a'), "issuer_dn_contains");
    refused("issuer_dn_contains", std::string("a\xff") + "bc", "issuer_dn_contains");
    refused("issuer_dn", std::string("a\xff"), "issuer_dn");
    refused("agent_id", "", "agent_id");
    refused("store", "", "store");
    refused("limit", "0", "limit");
    refused("limit", "501", "limit");
    refused("limit", "-1", "limit");
    refused("limit", "+5", "limit");
    refused("limit", "ten", "limit");
    refused("nonsense", "x", "nonsense"); // a typo'd filter is never silently ignored
    refused("issuer_dn_contain", "eMudhra", "issuer_dn_contain");
}

TEST_CASE("cert read model: the subject substring needs is_ca=true", "[certread][model]") {
    const auto bare = crt::parse_list_params(P({{"subject_dn_contains", "emSign"}}));
    REQUIRE_FALSE(bare.has_value());
    CHECK_THAT(bare.error(), ContainsSubstring("is_ca"));
    const auto no = crt::parse_list_params(P({{"subject_dn_contains", "emSign"}, {"is_ca", "false"}}));
    REQUIRE_FALSE(no.has_value());
    CHECK_THAT(no.error(), ContainsSubstring("is_ca"));
    CHECK(crt::parse_list_params(P({{"subject_dn_contains", "emSign"}, {"is_ca", "true"}})).has_value());
    // The summary takes the same filter and the same rule.
    const auto s = crt::parse_summary_params(P({{"subject_dn_contains", "emSign"}}));
    REQUIRE_FALSE(s.has_value());
    CHECK_THAT(s.error(), ContainsSubstring("is_ca"));
}

TEST_CASE("cert read model: a repeated parameter with differing values is refused", "[certread][model]") {
    crt::Params p;
    p.emplace("agent_id", "a");
    p.emplace("agent_id", "b");
    const auto r = crt::parse_list_params(p);
    REQUIRE_FALSE(r.has_value());
    CHECK_THAT(r.error(), ContainsSubstring("agent_id"));
}

TEST_CASE("cert read model: summary edges", "[certread][model]") {
    const auto ok = crt::parse_summary_params(
        P({{"not_after_edges", "2026-01-01T00:00:00Z,2027-01-01T00:00:00Z"}}));
    REQUIRE(ok.has_value());
    CHECK(ok->not_after_edges.size() == 2);
    for (const char* bad : {"", "2026-01-01", "2027-01-01T00:00:00Z,2026-01-01T00:00:00Z",
                            "2026-01-01T00:00:00Z,2026-01-01T00:00:00Z",
                            "2026-01-01T00:00:00Z,"}) {
        INFO(bad);
        CHECK_FALSE(crt::parse_summary_params(P({{"not_after_edges", bad}})).has_value());
    }
    std::string many;
    for (int i = 0; i < 33; ++i) {
        char b[32];
        snprintf(b, sizeof b, "%04d-01-01T00:00:00Z", 2000 + i);
        many += (many.empty() ? "" : ",") + std::string(b);
    }
    CHECK_FALSE(crt::parse_summary_params(P({{"not_after_edges", many}})).has_value());
    // The summary has no cursor or limit.
    CHECK_FALSE(crt::parse_summary_params(P({{"limit", "5"}})).has_value());
    CHECK_FALSE(crt::parse_summary_params(P({{"cursor", "x"}})).has_value());
}

TEST_CASE("cert read model: REST and MCP refuse the same bad values", "[certread][model][parity]") {
    // REST feeds the query string; MCP the typed JSON arguments, type-checked and then parsed by
    // the SAME parser. The same bad value is refused on both twins.
    const std::vector<Twin> bad = {
        {"scope", "user", "user"},
        {"key_alg_oid", "1", "1"},
        {"sig_alg_oid", "x.y", "x.y"},
        {"ec_curve_oid", "9.9", "9.9"},
        {"not_after_before", "2030-02-30T00:00:00Z", "2030-02-30T00:00:00Z"},
        {"not_after_after", "tomorrow", "tomorrow"},
        {"not_before_after", "2030-01-01", "2030-01-01"},
        {"rsa_modulus_bits_lt", "70000", 70000},
        {"ec_order_bits_lt", "0", 0},
        {"sha256", "abc", "abc"},
        {"spki_sha256", "abc", "abc"},
        {"aki_key_id", "abc", "abc"},
        {"issuer_dn_contains", "ab", "ab"},
        {"subject_dn_contains", "emSign", "emSign"}, // without is_ca
        {"agent_id", "", ""},
        {"store", "", ""},
        {"limit", "501", 501},
        {"limit", "0", 0},
    };
    const auto mcp_refuses = [](const Json& args) {
        if (crt::strict_list_args_error(args))
            return true;
        return !crt::parse_list_params(crt::params_from_args(args)).has_value();
    };
    for (const auto& t : bad) {
        INFO(t.key << "=" << t.rest_value);
        CHECK_FALSE(crt::parse_list_params(P({{t.key, t.rest_value}})).has_value());
        Json args = Json::object();
        args[t.key] = t.mcp_value;
        CHECK(mcp_refuses(args));
    }
    // A boolean is refused as text on REST and as a non-boolean on MCP.
    CHECK_FALSE(crt::parse_list_params(P({{"is_ca", "maybe"}})).has_value());
    CHECK(mcp_refuses(Json{{"is_ca", "maybe"}}));
    CHECK(mcp_refuses(Json{{"self_signed", 1}}));
    // The same GOOD value is accepted on both.
    const std::vector<Twin> good = {
        {"key_alg_oid", "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1"},
        {"rsa_modulus_bits_lt", "2048", 2048},
        {"aki_key_id", "aabb", "aabb"},
        {"issuer_dn_contains", "eMudhra", "eMudhra"},
        {"limit", "500", 500},
    };
    for (const auto& t : good) {
        INFO(t.key);
        const auto rest = crt::parse_list_params(P({{t.key, t.rest_value}}));
        Json args = Json::object();
        args[t.key] = t.mcp_value;
        REQUIRE(rest.has_value());
        CHECK_FALSE(mcp_refuses(args));
        CHECK(crt::filter_fingerprint(rest->filter) ==
              crt::filter_fingerprint(crt::parse_list_params(crt::params_from_args(args))->filter));
    }
}

TEST_CASE("cert read model: MCP type checks", "[certread][model][mcp]") {
    CHECK(crt::strict_list_args_error(Json::array()).has_value());
    CHECK(crt::strict_list_args_error(Json(nullptr)).has_value());
    CHECK(crt::strict_list_args_error(Json::object()) == std::nullopt);
    CHECK(crt::strict_list_args_error(Json{{"limit", "5"}}).has_value());
    CHECK(crt::strict_list_args_error(Json{{"limit", 5.5}}).has_value());
    CHECK(crt::strict_list_args_error(Json{{"limit", 5}}) == std::nullopt);
    CHECK(crt::strict_list_args_error(Json{{"is_ca", "true"}}).has_value());
    CHECK(crt::strict_list_args_error(Json{{"is_ca", true}}) == std::nullopt);
    CHECK(crt::strict_list_args_error(Json{{"issuer_dn", 5}}).has_value());
    CHECK(crt::strict_list_args_error(Json{{"rsa_modulus_bits_lt", "2048"}}).has_value());
    CHECK(crt::strict_list_args_error(Json{{"unknown", 1}}).has_value());
    CHECK(crt::strict_summary_args_error(Json{{"limit", 5}}).has_value()); // not a summary parameter
    CHECK(crt::strict_summary_args_error(Json{{"not_after_edges", "2026-01-01T00:00:00Z"}}).has_value());
    CHECK(crt::strict_summary_args_error(Json{{"not_after_edges", Json::array({5})}}).has_value());
    CHECK(crt::strict_summary_args_error(
              Json{{"not_after_edges", Json::array({"2026-01-01T00:00:00Z"})}}) == std::nullopt);

    const Json args = {{"is_ca", true}, {"rsa_modulus_bits_lt", 2048}, {"issuer_dn_contains", "eMudhra"},
                       {"limit", 10}};
    const auto q = crt::parse_list_params(crt::params_from_args(args));
    REQUIRE(q.has_value());
    CHECK(*q->filter.is_ca == true);
    CHECK(*q->filter.rsa_modulus_bits_lt == 2048);
    CHECK(q->limit == 10);

    const auto s = crt::parse_summary_params(crt::params_from_args(
        Json{{"not_after_edges", Json::array({"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"})}}));
    REQUIRE(s.has_value());
    CHECK(s->not_after_edges.size() == 2);
}

TEST_CASE("cert read model: a cursor is bound to its filter set", "[certread][model][cursor]") {
    CertReadFilter a, b;
    a.agent_id = "agent-1";
    b.agent_id = "agent-2";
    const auto fa = crt::filter_fingerprint(a);
    CHECK(fa == crt::filter_fingerprint(a));
    CHECK(fa != crt::filter_fingerprint(b));
    CHECK(fa != crt::filter_fingerprint({}));
    CertReadFilter empty_issuer;
    empty_issuer.issuer_dn = "";
    CHECK(crt::filter_fingerprint(empty_issuer) != crt::filter_fingerprint({})); // present-empty differs from absent

    const auto tok = crt::encode_cursor({"agent-1", hex64('c')}, fa);
    const auto back = crt::decode_cursor(tok, fa);
    REQUIRE(back.has_value());
    CHECK(back->agent_id == "agent-1");
    CHECK(back->sha256 == hex64('c'));
    const auto other = crt::decode_cursor(tok, crt::filter_fingerprint(b));
    REQUIRE_FALSE(other.has_value());
    CHECK(other.error() == crt::CursorError::kFilterMismatch);
    for (const char* bad : {"", "x", "c1:", "c1:0123456789abcdef:", "c1:0123456789abcdef:!!!",
                            "k1:0123456789abcdef:AAAA"}) {
        INFO(bad);
        const auto r = crt::decode_cursor(bad, fa);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == crt::CursorError::kMalformed);
    }
}

// ── Truncation: result_truncated is the OR of every cut ─────────────────────────

namespace {
CertReadRow row(const std::string& agent, int n) {
    CertReadRow r;
    r.agent_id = agent;
    r.sha256 = std::string(64 - std::to_string(n).size(), '0') + std::to_string(n);
    r.subject_dn = "CN=h" + std::to_string(n);
    r.last_seen = "2026-10-23T00:00:00Z";
    return r;
}
} // namespace

TEST_CASE("cert read model: result_truncated ORs every cut and never lies", "[certread][model][truncation]") {
    const auto fp = crt::filter_fingerprint({});
    SECTION("a complete last page is not truncated and has no cursor") {
        CertPage p;
        p.rows = {row("a", 1), row("a", 2)};
        p.stores = {{"a", "S", "ok", "", std::nullopt, "t"}};
        crt::finish_page(p, fp);
        CHECK_FALSE(p.result_truncated);
        CHECK(p.truncated_parts.empty());
        CHECK(p.next_cursor.empty());
    }
    SECTION("more rows past the page: page_limit and a cursor") {
        CertPage p;
        p.rows = {row("a", 1)};
        p.has_more = true;
        crt::finish_page(p, fp);
        CHECK(p.result_truncated);
        CHECK(p.truncated_parts == std::vector<std::string>{"page_limit"});
        REQUIRE_FALSE(p.next_cursor.empty());
        CHECK(crt::decode_cursor(p.next_cursor, fp).has_value());
    }
    SECTION("the byte budget stops at a whole certificate and the cursor continues after it") {
        CertPage p;
        for (int i = 1; i <= 6; ++i)
            p.rows.push_back(row("a", i));
        p.stores = {{"a", "S", "ok", "", std::nullopt, "t"}};
        crt::finish_page(p, fp, /*byte_budget=*/600);
        CHECK(p.rows.size() < 6);
        CHECK(p.rows.size() >= 1);
        CHECK(p.result_truncated);
        CHECK(std::ranges::find(p.truncated_parts, "byte_budget") != p.truncated_parts.end());
        const auto at = crt::decode_cursor(p.next_cursor, fp);
        REQUIRE(at.has_value());
        CHECK(at->sha256 == p.rows.back().sha256);
    }
    SECTION("a capped list, a constrained store and a constrained certificate each set the flag") {
        CertPage a;
        a.rows = {row("a", 1)};
        a.rows[0].locations_truncated = true;
        crt::finish_page(a, fp);
        CHECK(a.result_truncated);
        CHECK(a.truncated_parts == std::vector<std::string>{"locations_cap"});

        CertPage b;
        b.rows = {row("a", 1)};
        b.rows[0].sans_truncated = true;
        crt::finish_page(b, fp);
        CHECK(b.truncated_parts == std::vector<std::string>{"sans_cap"});

        CertPage c;
        c.rows = {row("a", 1)};
        c.stores = {{"a", "S", "constrained", "row_cap", std::nullopt, "t"}};
        crt::finish_page(c, fp);
        CHECK(c.result_truncated);
        CHECK(c.truncated_parts == std::vector<std::string>{"constrained_store"});

        CertPage d;
        d.rows = {row("a", 1)};
        d.rows[0].constrained_fields = "utf8_replaced:subject_dn";
        crt::finish_page(d, fp);
        CHECK(d.truncated_parts == std::vector<std::string>{"constrained_certificate"});
    }
    SECTION("an unreadable store is shown in stores[] but is not a cut") {
        CertPage p;
        p.rows = {row("a", 1)};
        p.stores = {{"a", "S", "unreadable", "permission_denied", std::nullopt, "t"}};
        crt::finish_page(p, fp);
        CHECK_FALSE(p.result_truncated);
    }
    SECTION("several cuts are all named") {
        CertPage p;
        p.rows = {row("a", 1)};
        p.has_more = true;
        p.rows[0].sans_truncated = true;
        p.stores = {{"a", "S", "constrained", "", std::nullopt, "t"}};
        crt::finish_page(p, fp);
        CHECK(p.truncated_parts.size() == 3);
        CHECK(p.result_truncated);
    }
    SECTION("a summary is truncated exactly when it names a part") {
        CertSummary s;
        crt::finish_summary(s);
        CHECK_FALSE(s.result_truncated);
        s.truncated_parts = {"row_ceiling"};
        crt::finish_summary(s);
        CHECK(s.result_truncated);
    }
}

// ── Audit: names and operators, never values ───────────────────────────────────

TEST_CASE("cert read model: the audit detail names filters and never carries a value",
          "[certread][model][audit]") {
    CertReadFilter f;
    f.issuer_dn = "CN=Jane Doe,E=jane@example.org";
    f.issuer_dn_contains = "jane.doe@example.org";
    f.subject_dn_contains = "Jane Doe";
    f.is_ca = true;
    f.agent_id = "agent-secret-1";
    f.sha256 = hex64('a');
    f.not_after_before = "2030-01-01T00:00:00Z";
    f.rsa_modulus_bits_lt = 2048;
    const auto d = crt::audit_detail("cid-1", f, 3, true, true, true);
    for (const char* leaked : {"Jane", "jane", "example.org", "agent-secret-1", "2030-01-01",
                               "2048", "aaaaaaaa"}) {
        INFO(leaked);
        CHECK_THAT(d, !ContainsSubstring(leaked));
    }
    CHECK_THAT(d, ContainsSubstring("scope=confined"));
    CHECK_THAT(d, ContainsSubstring("rows=3"));
    CHECK_THAT(d, ContainsSubstring("truncated=true"));
    CHECK_THAT(d, ContainsSubstring("issuer_dn=eq"));
    CHECK_THAT(d, ContainsSubstring("issuer_dn_contains=contains"));
    CHECK_THAT(d, ContainsSubstring("not_after_before=lt"));
    CHECK_THAT(d, ContainsSubstring("rsa_modulus_bits_lt=lt"));
    CHECK_THAT(d, ContainsSubstring("page=continuation"));
    CHECK_THAT(d, ContainsSubstring("cid=cid-1"));
    CHECK(crt::audit_detail("", {}, 0, false, false, false) ==
          "scope=fleet rows=0 truncated=false filters=none");
    const auto deg = crt::audit_detail_degraded("", f, CryptoReadCause::kCapacity, false);
    CHECK_THAT(deg, ContainsSubstring("capacity in use"));
    CHECK_THAT(deg, !ContainsSubstring("Jane"));
    CHECK_THAT(crt::audit_detail_degraded("", {}, CryptoReadCause::kStoreDegraded, true),
               ContainsSubstring("store degraded"));
}

// ── Shapes, personal data and the D10 lint ─────────────────────────────────────

namespace {

CertReadRow full_row() {
    CertReadRow r = row("agent-1", 7);
    r.hostname = "host-7";
    r.sha1 = std::string(40, 'a');
    r.tbs_sha256 = hex64('b');
    r.serial = "0A1B";
    r.issuer_dn = "CN=Test CA";
    r.not_before = "2020-01-01T00:00:00Z";
    r.not_after = "2030-01-01T00:00:00Z";
    r.key_alg_oid = "1.2.840.113549.1.1.1";
    r.rsa_modulus_bits = 2048;
    r.ec_curve_oid = "1.2.840.10045.3.1.7";
    r.ec_order_bits = 256;
    r.sig_alg_oid = "1.2.840.113549.1.1.11";
    r.pss_hash_oid = "2.16.840.1.101.3.4.2.1";
    r.spki_sha256 = hex64('c');
    r.ski = "AABB";
    r.aki_key_id = "CCDD";
    r.is_ca = false;
    r.path_len = 0;
    r.self_signed = false;
    r.key_usage = "Digital Signature, Key Encipherment";
    r.ekus = {"1.3.6.1.5.5.7.3.1"};
    r.sans = {{"rfc822", "jane@example.org"}};
    r.key_association = "none";
    r.key_provider = "";
    r.key_exportable = "unknown";
    r.locations = {{"LocalMachine\Root", "", "ok", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z"}};
    r.constrained_fields = "serial_negative,utf8_replaced:subject_dn";
    return r;
}

} // namespace

TEST_CASE("cert read model: the per-certificate JSON shape", "[certread][model][shape]") {
    CertPage p;
    p.rows = {full_row()};
    p.stores = {{"agent-1", "LocalMachine\Root", "ok", "", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z"}};
    p.coverage = {5, 1, true};
    p.blob_versions = {"1"};
    crt::finish_page(p, crt::filter_fingerprint({}));
    const auto j = crt::list_json(p);
    REQUIRE(j["certificates"].size() == 1);
    const auto& c = j["certificates"][0];
    CHECK(c["hostname"] == "host-7");
    CHECK(c["key_usage"] == Json::array({"Digital Signature", "Key Encipherment"}));
    CHECK(c["eku_oids"] == Json::array({"1.3.6.1.5.5.7.3.1"}));
    CHECK(c["sans"][0]["value"] == "jane@example.org"); // served here, and only here
    CHECK(c["constrained_fields"] == Json::array({"serial_negative", "utf8_replaced:subject_dn"}));
    CHECK(c["is_ca"] == false);
    CHECK(c["locations"][0]["observed_at"] == "2026-10-23T00:00:00Z");
    CHECK_FALSE(c.contains("revocation")); // revocation is not checked by this version: the key is absent
    CHECK(j["blob_versions"] == Json::array({1}));
    CHECK(j["coverage"]["confined"] == true);
    CHECK(j["next_cursor"].is_null());
    CHECK(j["not_read"].is_array());
    CHECK(j["not_read"].size() == crt::not_read().size());
    // A certificate with an unset field reports null, distinct from an empty value.
    CertReadRow bare;
    bare.agent_id = "a";
    bare.sha256 = hex64('d');
    const auto bj = crt::row_json(bare);
    CHECK(bj["subject_dn"].is_null());
    CHECK(bj["rsa_modulus_bits"].is_null());
    CHECK(bj["hostname"].is_null());
    CHECK(bj["key_usage"].is_null());
    bare.issuer_dn = "";
    CHECK(crt::row_json(bare)["issuer_dn"] == "");
    CHECK(crt::row_json(bare).contains("revocation") == false);
}

TEST_CASE("cert read model: the summary never groups on a subject or a SAN", "[certread][model][shape]") {
    CertSummary s;
    s.totals = {2, 5};
    s.key_algorithms = {{"1.2.840.113549.1.1.1", 2048, std::nullopt, {2, 5}}};
    s.signature_algorithms = {{"1.2.840.113549.1.1.11", std::nullopt, {2, 5}}};
    s.ec_curves = {{"1.2.840.10045.3.1.7", {1, 1}}};
    s.issuers = {{"CN=Test CA", {2, 5}}};
    s.stores = {{"LocalMachine\Root", {2, 5}}};
    s.store_statuses = {{"ok", 2, 2}};
    s.not_after_histogram = {{std::nullopt, "2026-01-01T00:00:00Z", false, {1, 1}},
                             {std::nullopt, std::nullopt, true, {1, 1}}};
    crt::finish_summary(s);
    const auto j = crt::summary_json(s);
    for (const auto& [k, v] : j.items()) {
        (void)v;
        CHECK(k != "subjects");
        CHECK(k != "sans");
        CHECK(k != "subject_dn");
    }
    CHECK(j["totals"]["certificate_count"] == 5);
    CHECK(j["not_after_histogram"][1]["unknown"] == true);
    CHECK(j["key_algorithms"][0]["rsa_modulus_bits"] == 2048);
    CHECK(j["key_algorithms"][0]["ec_order_bits"].is_null());
}

TEST_CASE("cert read model: D10 - no verdict-shaped key anywhere in a response", "[certread][model][d10]") {
    CertPage p;
    p.rows = {full_row()};
    p.stores = {{"agent-1", "S", "constrained", "row_cap", "t", "t"}};
    crt::finish_page(p, crt::filter_fingerprint({}));
    CertSummary s;
    s.key_algorithms = {{"1.2.3", 1, 2, {1, 1}}};
    s.not_after_histogram = {{std::nullopt, std::nullopt, true, {}}};
    crt::finish_summary(s);
    CHECK(crt::verdict_shaped_keys(crt::list_json(p)).empty());
    CHECK(crt::verdict_shaped_keys(crt::summary_json(s)).empty());
    CHECK(crt::verdict_shaped_keys(crt::row_json(full_row())).empty());

    // The lint itself catches the closed ADR-0070 D10 list, in any case and as a token of a key.
    for (const char* bad : {"weak", "strong_key", "riskLevel", "score", "expired", "is_expiring",
                            "eol", "supported", "vulnerable", "pqc_ready", "quantum_safe",
                            "approved", "compliant", "WEAK_KEY"}) {
        INFO(bad);
        Json j = Json::object();
        j[bad] = 1;
        CHECK(crt::verdict_shaped_keys(j).size() == 1);
        CHECK(crt::verdict_shaped_keys(Json{{"outer", Json::array({j})}}).size() == 1);
    }
    CHECK(crt::verdict_shaped_keys(Json{{"not_after_before", 1}, {"constrained_fields", 2},
                                        {"key_exportable", 3}}).empty());
}

TEST_CASE("cert read model: the facts-only sentence and the denial text name the permission",
          "[certread][model][d10]") {
    CHECK_THAT(std::string(crt::kFactsOnlySentence), ContainsSubstring("facts only"));
    CHECK_THAT(std::string(crt::kFactsOnlySentence), ContainsSubstring("D13's named rules"));
    CHECK_THAT(std::string(crt::kDeniedMessage), ContainsSubstring("CertificateInventory:Read"));
    CHECK(crt::kPermission == "CertificateInventory:Read");
    const auto nr = crt::not_read();
    CHECK(std::ranges::find(nr, std::string_view("per-user certificate stores")) != nr.end());
    CHECK(std::ranges::find(nr, std::string_view("Java cacerts")) != nr.end());
}

// ── The OpenAPI entries: D10 lint, strict parameters and parity with the model ─────────────────

TEST_CASE("cert read model: the OpenAPI entries are D10-clean and document the model's parameters",
          "[certread][model][d10][openapi]") {
    const auto spec = Json::parse(yuzu::server::openapi_spec_json(), nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    for (const char* path : {"/crypto/certificates", "/crypto/certificates/summary"}) {
        INFO(path);
        REQUIRE(spec["paths"].contains(path));
        const auto& get = spec["paths"][path]["get"];
        // D10's sentence rides on every certificate description.
        CHECK_THAT(get["description"].get<std::string>(),
                   ContainsSubstring("facts only; the only built-in checks are D13's named rules "
                                     "and windows, each shown with its criterion"));
        // Lint every parameter name (the schema's own keys are the OpenAPI vocabulary, not fields).
        std::vector<std::string> names;
        for (const auto& prm : get["parameters"])
            names.push_back(prm["name"].get<std::string>());
        Json named = Json::object();
        for (const auto& n : names)
            named[n] = 1;
        CHECK(crt::verdict_shaped_keys(named).empty());
        // Every parameter the OpenAPI documents is one the model accepts - and the reverse: a closed
        // enum or a documented key the server does not refuse is the #6122 item 2 defect.
        const bool list = std::string(path) == "/crypto/certificates";
        for (const auto& n : names) {
            INFO(n);
            Json args = Json::object();
            if (n == "limit" || n == "rsa_modulus_bits_lt" || n == "ec_order_bits_lt")
                args[n] = 10;
            else if (n == "is_ca" || n == "self_signed")
                args[n] = true;
            else if (n == "not_after_edges")
                args[n] = Json::array({"2026-01-01T00:00:00Z"});
            else
                args[n] = "x";
            // The TYPE check accepts the documented key (the value may still be refused by the parser).
            CHECK_FALSE((list ? crt::strict_list_args_error(args) : crt::strict_summary_args_error(args))
                            .has_value());
        }
        for (const char* mine : {"store", "scope", "key_alg_oid", "sig_alg_oid", "ec_curve_oid",
                                 "not_after_before", "not_after_after", "not_before_after",
                                 "rsa_modulus_bits_lt", "ec_order_bits_lt", "is_ca", "self_signed",
                                 "agent_id", "issuer_dn", "issuer_dn_contains", "subject_dn_contains",
                                 "sha256", "spki_sha256", "aki_key_id"})
            CHECK(std::ranges::find(names, std::string(mine)) != names.end());
        CHECK((std::ranges::find(names, std::string("limit")) != names.end()) == list);
        CHECK((std::ranges::find(names, std::string("not_after_edges")) != names.end()) == !list);
        // `store` is free text: no enum.
        for (const auto& prm : get["parameters"])
            if (prm["name"] == "store")
                CHECK_FALSE(prm["schema"].contains("enum"));
        // The 503 documents the fail-closed audit header.
        CHECK(get["responses"]["503"]["headers"].contains("Sec-Audit-Failed"));
    }
}

// ── The cursor fingerprint covers EVERY filter field ───────────────────────────────────────────

TEST_CASE("cert read model: the cursor fingerprint changes with every single filter field",
          "[certread][model][cursor]") {
    // Tripwire: a new CertReadFilter field breaks this structured binding at COMPILE time, so it
    // cannot be added without also adding it to filter_fingerprint and to the list below.
    {
        CertReadFilter probe;
        auto& [store, scope, key_alg, sig_alg, curve, nab, naa, nba, rsa, ec, is_ca, self_signed,
               agent, issuer, issuer_c, subject_c, sha, spki, aki] = probe;
        (void)store; (void)scope; (void)key_alg; (void)sig_alg; (void)curve; (void)nab; (void)naa;
        (void)nba; (void)rsa; (void)ec; (void)is_ca; (void)self_signed; (void)agent; (void)issuer;
        (void)issuer_c; (void)subject_c; (void)sha; (void)spki; (void)aki;
    }
    const auto base = crt::filter_fingerprint({});
    std::vector<std::pair<std::string, CertReadFilter>> each;
    const auto add = [&](const char* name, auto&& set) {
        CertReadFilter f;
        set(f);
        each.emplace_back(name, std::move(f));
    };
    add("store", [](CertReadFilter& f) { f.store = "s"; });
    add("scope", [](CertReadFilter& f) { f.scope = "machine"; });
    add("key_alg_oid", [](CertReadFilter& f) { f.key_alg_oid = "1.2"; });
    add("sig_alg_oid", [](CertReadFilter& f) { f.sig_alg_oid = "1.2"; });
    add("ec_curve_oid", [](CertReadFilter& f) { f.ec_curve_oid = "1.2"; });
    add("not_after_before", [](CertReadFilter& f) { f.not_after_before = "2030-01-01T00:00:00Z"; });
    add("not_after_after", [](CertReadFilter& f) { f.not_after_after = "2030-01-01T00:00:00Z"; });
    add("not_before_after", [](CertReadFilter& f) { f.not_before_after = "2030-01-01T00:00:00Z"; });
    add("rsa_modulus_bits_lt", [](CertReadFilter& f) { f.rsa_modulus_bits_lt = 2048; });
    add("ec_order_bits_lt", [](CertReadFilter& f) { f.ec_order_bits_lt = 256; });
    add("is_ca", [](CertReadFilter& f) { f.is_ca = true; });
    add("self_signed", [](CertReadFilter& f) { f.self_signed = true; });
    add("agent_id", [](CertReadFilter& f) { f.agent_id = "a"; });
    add("issuer_dn", [](CertReadFilter& f) { f.issuer_dn = "a"; });
    add("issuer_dn_contains", [](CertReadFilter& f) { f.issuer_dn_contains = "abc"; });
    add("subject_dn_contains", [](CertReadFilter& f) { f.subject_dn_contains = "abc"; });
    add("sha256", [](CertReadFilter& f) { f.sha256 = hex64('a'); });
    add("spki_sha256", [](CertReadFilter& f) { f.spki_sha256 = hex64('a'); });
    add("aki_key_id", [](CertReadFilter& f) { f.aki_key_id = "AA"; });
    CHECK(each.size() == 19);
    std::set<std::string> seen{base};
    for (const auto& [name, f] : each) {
        INFO(name);
        const auto fp = crt::filter_fingerprint(f);
        CHECK(fp != base);                       // a cursor from the unfiltered walk is refused under it
        CHECK(seen.insert(fp).second);           // and no two single-field filters share a binding
    }
    // A value change on a present field also changes it, and bool true differs from false.
    CertReadFilter a, b;
    a.is_ca = true;
    b.is_ca = false;
    CHECK(crt::filter_fingerprint(a) != crt::filter_fingerprint(b));
    a = {}; b = {};
    a.sha256 = hex64('a');
    b.sha256 = hex64('b');
    CHECK(crt::filter_fingerprint(a) != crt::filter_fingerprint(b));
}

TEST_CASE("cert read model: decode_cursor refuses random bytes and never throws", "[certread][model][cursor]") {
    const auto fp = crt::filter_fingerprint({});
    std::uint32_t x = 12345;
    for (int i = 0; i < 2000; ++i) {
        std::string tok = (i % 3 == 0) ? "c1:" + fp + ":" : (i % 3 == 1 ? "c1:" : "");
        const int n = static_cast<int>((x = x * 1664525u + 1013904223u) >> 24) % 40;
        for (int k = 0; k < n; ++k)
            tok.push_back(static_cast<char>((x = x * 1664525u + 1013904223u) >> 24));
        const auto r = crt::decode_cursor(tok, fp);
        CHECK_FALSE(r.has_value());
    }
}

TEST_CASE("cert read model: a substring needle with a NUL is refused; a backslash is accepted as text",
          "[certread][model]") {
    for (const char* key : {"issuer_dn_contains", "subject_dn_contains"}) {
        auto params = P({{key, std::string("emS\0ign", 7)}, {"is_ca", "true"}});
        const auto r = crt::parse_list_params(params);
        REQUIRE_FALSE(r.has_value());
        CHECK_THAT(r.error(), ContainsSubstring(key));
        CHECK_FALSE(crt::parse_summary_params(params).has_value());
    }
    const auto ok = crt::parse_list_params(P({{"issuer_dn_contains", "a\\b"}}));
    REQUIRE(ok.has_value());
    CHECK(*ok->filter.issuer_dn_contains == "a\\b");
}

TEST_CASE("cert read model: a page is caller-priced unless unfiltered or key-addressed (#6333)",
          "[certread][model]") {
    using namespace yuzu::server;
    CertReadFilter f;
    CHECK_FALSE(cert_read::caller_priced_page(f));
    f.agent_id = "a";
    f.sha256 = std::string(64, 'a');
    f.scope = "machine";
    CHECK_FALSE(cert_read::caller_priced_page(f)); // key-addressed and closed filters only
    for (auto set : std::vector<std::function<void(CertReadFilter&)>>{
             [](CertReadFilter& x) { x.ec_curve_oid = "1.2.3"; },
             [](CertReadFilter& x) { x.rsa_modulus_bits_lt = 2048; },
             [](CertReadFilter& x) { x.store = "My"; },
             [](CertReadFilter& x) { x.issuer_dn = "CN=X"; },
             [](CertReadFilter& x) { x.issuer_dn_contains = "abc"; },
             [](CertReadFilter& x) { x.is_ca = true; },
             [](CertReadFilter& x) { x.aki_key_id = "AB"; }}) {
        CertReadFilter g;
        set(g);
        CHECK(cert_read::caller_priced_page(g));
    }
}
