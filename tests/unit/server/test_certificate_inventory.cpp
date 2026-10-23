// CertificateInventoryStore + certificate_inventory ingest seam tests (slice-2 PR 2a-2a):
// the blob parse (escape grammar, versions, unknown vs empty, caps, UTF-8, record-level and
// whole-report parse errors), every per-store replace rule, hash-skip and need_full, the
// per-agent lock (an ingest racing delete_agent, in both orders), the cascade registration, the metric's closed set, and the D13 schema
// lint over this store's migration array.
//
// The direct and gateway wiring (ReportInventory / ProxyInventory) is covered in
// test_agent_service_impl.cpp.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "agent_decommission.hpp"
#include "certificate_inventory_ingestion.hpp"
#include "certificate_inventory_store.hpp"
#include "crypto_widget_catalogue.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <initializer_list>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace agentpb = yuzu::agent::v1;

namespace {

constexpr const char* kSource = "certificate_inventory";

// ── Blob builders ────────────────────────────────────────────────────────────

std::string esc(std::string_view s) {
    std::string o;
    for (char c : s) {
        if (c == '\\')
            o += "\\\\";
        else if (c == '|')
            o += "\\|";
        else if (c == '\n')
            o += "\\n";
        else if (c == '\r')
            o += "\\r";
        else
            o.push_back(c);
    }
    return o;
}

std::string line(const std::vector<std::string>& raw_fields) {
    std::string r;
    for (std::size_t i = 0; i < raw_fields.size(); ++i) {
        if (i)
            r += '|';
        r += esc(raw_fields[i]);
    }
    return r + "\n";
}

std::string hexn(int n, std::size_t width = 64) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    for (int v = n; v > 0; v /= 16)
        s.insert(s.begin(), kHex[v % 16]);
    if (s.empty())
        s = "0";
    return std::string(width - s.size(), '0') + s;
}

struct Cert {
    int id{1};
    std::vector<std::pair<std::string, std::string>> locs; // store_id, path
    std::string subject{"CN=host.example"};
    std::string issuer{"CN=Test CA"};
    std::string not_before{"2020-01-01T00:00:00Z"};
    std::string not_after{"2030-01-01T00:00:00Z"};
    std::vector<std::pair<std::string, std::string>> sans;
    std::vector<std::string> ekus, cdps;
    std::string der_b64;
    std::optional<std::string> sha_override;
    std::optional<std::string> sans_field;
    std::string tail_ext; // raw text appended as an extra (unknown) field
    std::string der_omitted, flags;
};

std::string sha_of(const Cert& c) { return c.sha_override.value_or(hexn(c.id)); }

std::string cert_group(const Cert& c) {
    const std::string sha = sha_of(c);
    std::vector<std::string> f = {
        "cert",
        sha,
        std::string(40, 'a'),
        hexn(900 + c.id),
        "3",
        "0A1B",
        c.subject,
        c.issuer,
        hexn(700 + c.id),
        hexn(800 + c.id),
        c.not_before,
        c.not_after,
        "1.2.840.113549.1.1.1", // key_alg_oid
        "2048",                 // rsa_modulus_bits
        "",                     // ec_curve_oid
        "",                     // ec_order_bits
        "1.2.840.113549.1.1.11", // sig_alg_oid
        "",                     // pss_hash_oid
        "",                     // pss_mgf1_hash_oid
        "AABB",                 // ski
        "CCDD",                 // aki_key_id
        "1",                    // is_ca
        "0",                    // path_len
        "Digital Signature, Key Encipherment",
        "0",       // self_signed
        "none",    // key_association
        "",        // key_provider
        "unknown", // key_exportable
        c.sans_field.value_or("sans=" + std::to_string(c.sans.size())),
        "ekus=" + std::to_string(c.ekus.size()),
        "cdps=" + std::to_string(c.cdps.size()),
        c.der_omitted, // der_omitted
        c.flags,       // flags
    };
    if (!c.tail_ext.empty())
        f.push_back(c.tail_ext);
    std::string out = line(f);
    for (const auto& [store, path] : c.locs)
        out += line({"loc", sha, store, path});
    for (const auto& [t, v] : c.sans)
        out += line({"san", sha, t, v});
    for (const auto& e : c.ekus)
        out += line({"eku", sha, e});
    for (const auto& d : c.cdps)
        out += line({"cdp", sha, d});
    if (!c.der_b64.empty())
        out += line({"der", sha, c.der_b64});
    return out;
}

std::string store_rec(const std::string& id, const std::string& status,
                      const std::string& reason = "", const std::string& count = "?",
                      const std::string& scope = "machine") {
    return line({"store", id, scope, status, reason, count});
}

std::string blob(const std::string& stores, const std::vector<Cert>& certs,
                 const std::string& ver = "ver|1\n") {
    std::string b = ver + stores;
    for (const auto& c : certs)
        b += cert_group(c);
    return b;
}

Cert cert(int id, std::initializer_list<std::pair<std::string, std::string>> locs) {
    Cert c;
    c.id = id;
    c.locs.assign(locs.begin(), locs.end());
    return c;
}

agentpb::InventoryReport full_report(const std::string& b) {
    agentpb::InventoryReport r;
    (*r.mutable_content_hashes())[kSource] = "claimed-hash";
    (*r.mutable_plugin_data())[kSource] = b;
    return r;
}

agentpb::InventoryReport hash_only(const std::string& h) {
    agentpb::InventoryReport r;
    (*r.mutable_content_hashes())[kSource] = h;
    return r;
}

bool nacked(const agentpb::InventoryAck& a) {
    return std::find(a.need_full().begin(), a.need_full().end(), kSource) != a.need_full().end();
}

const CertStoreReport* find_store(const CertBlobParse& p, const std::string& id) {
    for (const auto& s : p.data.stores)
        if (s.store_id == id)
            return &s;
    return nullptr;
}

const CertFactRow* find_fact(const CertBlobParse& p, int id) {
    for (const auto& f : p.data.facts)
        if (f.sha256 == hexn(id))
            return &f;
    return nullptr;
}

// ── PG fixture ───────────────────────────────────────────────────────────────

yuzu::test::PgTestTemplate certinv_tpl{"certinv", [](const std::string& dsn) {
                                           PgPool pool{{.conninfo = dsn, .size = 1}};
                                           CertificateInventoryStore store{pool};
                                           if (!store.is_open())
                                               throw std::runtime_error(
                                                   "certinv template: store failed to migrate");
                                       }};

struct CertShared {
    yuzu::test::PostgresTestDb db{certinv_tpl};
    std::optional<PgPool> pool;
    CertShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
CertShared& cert_shared() {
    static CertShared s;
    return s;
}

void cert_reset() {
    auto lease = cert_shared().pool->acquire();
    REQUIRE(lease);
    auto t = pg::exec_params(lease.get(),
                             "TRUNCATE cert_inventory.agent_state CASCADE",
                             std::vector<std::string>{});
    REQUIRE(t.status() == PGRES_COMMAND_OK);
}

#define CERT_SHARED(store, pool)                                                                   \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    cert_reset();                                                                                  \
    [[maybe_unused]] PgPool& pool = *cert_shared().pool;                                           \
    CertificateInventoryStore store{pool};                                                         \
    REQUIRE(store.is_open())

std::string scalar(PgPool& pool, const char* sql, const std::vector<std::string>& params = {}) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto r = pg::exec_params(lease.get(), sql, params);
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    if (PQntuples(r.get()) == 0)
        return "<none>";
    if (PQgetisnull(r.get(), 0, 0))
        return "<null>";
    return PQgetvalue(r.get(), 0, 0);
}

agentpb::InventoryAck ingest(CertificateInventoryStore& store, const std::string& agent,
                             const agentpb::InventoryReport& rpt,
                             yuzu::MetricsRegistry* m = nullptr) {
    agentpb::InventoryAck ack;
    ingest_certificate_inventory_report(store, agent, rpt, ack, m);
    return ack;
}

std::string raw_hash(const std::string& b) { return certificate_inventory_raw_hash(b); }

} // namespace

// ── Parse ────────────────────────────────────────────────────────────────────

TEST_CASE("cert parse: the escape grammar round-trips byte for byte",
          "[certinv][parse]") {
    Cert c = cert(1, {{"LocalMachine\\Root", "/etc/ssl/a|b.pem"}});
    c.subject = "CN=Acme\\, Inc.,O=A|B"; // an RFC 4514 \, escape and a pipe
    c.issuer = "CN=ends with a backslash\\";
    c.sans = {{"dns", "a\\|b"}, {"uri", "x\\\\|y"}, {"dirname", "line1\nline2\r"}};
    const auto b = blob(store_rec("LocalMachine\\Root", "ok", "", "1"), {c});
    const auto p = parse_certificate_inventory_blob(b);
    REQUIRE(p.nack == CertBlobNack::kNone);
    REQUIRE_FALSE(p.any_parse_error);
    REQUIRE(p.data.facts.size() == 1);
    const auto& f = p.data.facts[0];
    CHECK(*f.subject_dn == "CN=Acme\\, Inc.,O=A|B");
    CHECK(*f.issuer_dn == "CN=ends with a backslash\\");
    REQUIRE(f.sans.size() == 3);
    CHECK(f.sans[0].value == "a\\|b");
    CHECK(f.sans[1].value == "x\\\\|y");
    CHECK(f.sans[2].value == "line1\nline2\r");
    REQUIRE(p.data.locations.size() == 1);
    CHECK(p.data.locations[0].store_id == "LocalMachine\\Root");
    CHECK(p.data.locations[0].path == "/etc/ssl/a|b.pem");
}

TEST_CASE("cert parse: an escaped backslash before a real delimiter is not an escaped pipe",
          "[certinv][parse]") {
    // `\\|` is a backslash then a delimiter. A scanner that treats a pipe as escaped whenever the
    // byte before it is a backslash (find_unescaped_pipe) would merge the fields.
    Cert c = cert(1, {{"S", "C:\\dir\\"}}); // path ends in a backslash
    const auto p = parse_certificate_inventory_blob(blob(store_rec("S", "ok", "", "1"), {c}));
    REQUIRE(p.data.locations.size() == 1);
    CHECK(p.data.locations[0].path == "C:\\dir\\");
}

TEST_CASE("cert parse: a trailing unpaired backslash refuses only that record",
          "[certinv][parse]") {
    std::string b = "ver|1\n" + store_rec("S", "ok", "", "?") + store_rec("T", "ok", "", "?");
    b += cert_group(cert(1, {{"S", ""}}));
    // Corrupt cert 2's record: its subject ends with a lone backslash.
    std::string bad = cert_group(cert(2, {{"T", ""}}));
    bad.replace(bad.find("CN=host.example"), 15, "CN=host.example\\");
    b += bad;
    const auto p = parse_certificate_inventory_blob(b);
    CHECK(p.nack == CertBlobNack::kNone); // acked, not nacked
    CHECK(p.any_parse_error);
    CHECK(find_fact(p, 1) != nullptr);
    CHECK(find_fact(p, 2) == nullptr);
    CHECK(find_store(p, "S")->status == "ok");
    CHECK(find_store(p, "T")->status == "constrained");
    CHECK(find_store(p, "T")->reason == "parse_error");
}

TEST_CASE("cert parse: versions", "[certinv][parse]") {
    const auto stores = store_rec("S", "ok", "", "1");
    SECTION("an unknown major nacks") {
        CHECK(parse_certificate_inventory_blob(blob(stores, {}, "ver|2\n")).nack ==
              CertBlobNack::kUnknownVersion);
    }
    SECTION("a newer minor parses and extra fields are ignored") {
        Cert c = cert(1, {{"S", ""}});
        c.tail_ext = "future-field";
        auto b = blob(stores, {c}, "ver|1.7\n");
        b += "future|kind|record\n"; // an unknown record kind is skipped
        const auto p = parse_certificate_inventory_blob(b);
        CHECK(p.nack == CertBlobNack::kNone);
        CHECK_FALSE(p.any_parse_error);
        CHECK(p.data.facts.size() == 1);
        CHECK(p.data.blob_version == "1.7");
    }
    SECTION("a missing or malformed ver line nacks") {
        CHECK(parse_certificate_inventory_blob(stores).nack == CertBlobNack::kBadHeader);
        CHECK(parse_certificate_inventory_blob("ver|x\n" + stores).nack == CertBlobNack::kBadHeader);
    }
}

TEST_CASE("cert parse: header defects nack the blob", "[certinv][parse]") {
    CHECK(parse_certificate_inventory_blob(blob(store_rec("S", "not_observed"), {})).nack ==
          CertBlobNack::kBadHeader);
    CHECK(parse_certificate_inventory_blob(blob(store_rec("S", "ok", "", "?", "user"), {})).nack ==
          CertBlobNack::kBadHeader); // per-user scope is not built
    CHECK(parse_certificate_inventory_blob(blob(store_rec("S", "ok") + store_rec("S", "ok"), {}))
              .nack == CertBlobNack::kBadHeader); // duplicate store
    CHECK(parse_certificate_inventory_blob("ver|1\n").nack == CertBlobNack::kBadHeader); // no store
    CHECK(parse_certificate_inventory_blob(blob("store|S|machine\n", {})).nack ==
          CertBlobNack::kBadHeader);
}

TEST_CASE("cert parse: a status-only blob is valid and carries every failure",
          "[certinv][parse]") {
    const auto p = parse_certificate_inventory_blob(
        blob(store_rec("A", "unreadable", "permission_denied") +
                 store_rec("B", "unreadable", "open_failed:13") + store_rec("C", "absent"),
             {}));
    CHECK(p.nack == CertBlobNack::kNone);
    CHECK(p.data.stores.size() == 3);
    CHECK(p.data.facts.empty());
    CHECK(find_store(p, "A")->reason == "permission_denied");
}

TEST_CASE("cert parse: unknown is distinct from empty", "[certinv][parse]") {
    Cert c = cert(1, {{"S", ""}});
    std::string g = cert_group(c);
    // Replace the subject with `?` (unknown) and the issuer stays a real empty value.
    g.replace(g.find("CN=host.example"), 15, "?");
    g.replace(g.find("CN=Test CA"), 10, "");
    const auto p = parse_certificate_inventory_blob("ver|1\n" + store_rec("S", "ok") + g);
    REQUIRE(p.data.facts.size() == 1);
    CHECK_FALSE(p.data.facts[0].subject_dn.has_value());
    REQUIRE(p.data.facts[0].issuer_dn.has_value());
    CHECK(p.data.facts[0].issuer_dn->empty());
    CHECK(p.data.facts[0].serial == std::optional<std::string>{"0A1B"});
}

TEST_CASE("cert parse: an older agent's short record reads the missing fields as unknown",
          "[certinv][parse]") {
    std::string g = line({"cert", hexn(1), std::string(40, 'a'), hexn(2), "3", "0a1b", "CN=x",
                          "CN=y", hexn(3), hexn(4), "2020-01-01T00:00:00Z",
                          "2030-01-01T00:00:00Z"}) +
                    line({"loc", hexn(1), "S", ""});
    const auto p = parse_certificate_inventory_blob("ver|1\n" + store_rec("S", "ok") + g);
    CHECK_FALSE(p.any_parse_error);
    REQUIRE(p.data.facts.size() == 1);
    CHECK_FALSE(p.data.facts[0].is_ca.has_value());
    CHECK_FALSE(p.data.facts[0].key_provider.has_value());
    CHECK(*p.data.facts[0].serial == "0A1B"); // canonical uppercase
}

TEST_CASE("cert parse: invalid UTF-8 is replaced and the field is marked", "[certinv][parse]") {
    Cert c = cert(1, {{"S", ""}});
    c.subject = std::string("CN=bad\xff\xfe") + "end";
    const auto p = parse_certificate_inventory_blob(blob(store_rec("S", "ok"), {c}));
    REQUIRE(p.data.facts.size() == 1);
    CHECK(p.utf8_replaced);
    CHECK(*p.data.facts[0].subject_dn == "CN=bad\xEF\xBF\xBD\xEF\xBF\xBD"
                                         "end");
    CHECK(p.data.facts[0].constrained_fields.find("utf8_replaced:subject_dn") !=
          std::string::npos);
}

TEST_CASE("cert parse: an over-cap record is refused, never truncated", "[certinv][parse]") {
    const auto stores = store_rec("S", "ok") + store_rec("U", "ok");
    SECTION("65 SANs refuse the certificate and constrain its store") {
        Cert c = cert(1, {{"S", ""}});
        for (int i = 0; i < 65; ++i)
            c.sans.push_back({"dns", "h" + std::to_string(i)});
        Cert ok = cert(2, {{"U", ""}});
        const auto p = parse_certificate_inventory_blob(blob(stores, {c, ok}));
        CHECK(p.any_over_cap);
        CHECK(find_fact(p, 1) == nullptr);
        CHECK(find_fact(p, 2) != nullptr);
        CHECK(find_store(p, "S")->status == "constrained");
        CHECK(find_store(p, "S")->reason == "parse_error");
        CHECK(find_store(p, "U")->status == "ok");
    }
    SECTION("a 257-byte SAN value") {
        Cert c = cert(1, {{"S", ""}});
        c.sans = {{"dns", std::string(257, 'a')}};
        const auto p = parse_certificate_inventory_blob(blob(stores, {c}));
        CHECK(p.any_over_cap);
        CHECK(find_fact(p, 1) == nullptr);
    }
    SECTION("a 1025-byte DN") {
        Cert c = cert(1, {{"S", ""}});
        c.subject = "CN=" + std::string(1022, 'a');
        const auto p = parse_certificate_inventory_blob(blob(stores, {c}));
        CHECK(p.any_parse_error);
        CHECK(find_fact(p, 1) == nullptr);
    }
    SECTION("33 EKUs and 9 CRL DPs") {
        Cert c = cert(1, {{"S", ""}});
        for (int i = 0; i < 33; ++i)
            c.ekus.push_back("1.3.6.1.5.5.7.3." + std::to_string(i));
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) == nullptr);
        Cert d = cert(2, {{"S", ""}});
        for (int i = 0; i < 9; ++i)
            d.cdps.push_back("http://crl.example/" + std::to_string(i));
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {d})), 2) == nullptr);
    }
    SECTION("a blob over 3 MiB nacks") {
        const std::string big = blob(stores, {}) + std::string(3u * 1024 * 1024, 'x');
        CHECK(parse_certificate_inventory_blob(big).nack == CertBlobNack::kBlobTooLarge);
    }
    SECTION("more than 64 stores nacks") {
        std::string many;
        for (int i = 0; i < 65; ++i)
            many += store_rec("S" + std::to_string(i), "absent");
        CHECK(parse_certificate_inventory_blob(blob(many, {})).nack == CertBlobNack::kOverCap);
    }
    SECTION("more than 2,000 certificates in one store") {
        std::vector<Cert> certs;
        for (int i = 1; i <= 2001; ++i)
            certs.push_back(cert(i, {{"S", ""}}));
        const auto p = parse_certificate_inventory_blob(blob(store_rec("S", "ok"), certs));
        CHECK(p.any_over_cap);
        CHECK(p.data.facts.size() == 2000);
        CHECK(find_store(p, "S")->reason == "parse_error");
    }
}

TEST_CASE("cert parse: a record that cannot be tied to a store constrains the whole report",
          "[certinv][parse]") {
    const auto stores = store_rec("S", "ok") + store_rec("T", "ok") + store_rec("V", "unreadable");
    SECTION("a location in a store no header named") {
        const auto p = parse_certificate_inventory_blob(blob(stores, {cert(1, {{"ZZ", ""}})}));
        CHECK(find_store(p, "S")->status == "constrained");
        CHECK(find_store(p, "T")->reason == "parse_error");
        CHECK(find_store(p, "V")->status == "unreadable"); // the more specific status stays
    }
    SECTION("a certificate with no location") {
        const auto p = parse_certificate_inventory_blob(blob(stores, {cert(1, {})}));
        CHECK(find_store(p, "S")->reason == "parse_error");
    }
    SECTION("a child record for another certificate") {
        std::string b = blob(stores, {cert(1, {{"S", ""}})}) + line({"san", hexn(9), "dns", "x"});
        const auto p = parse_certificate_inventory_blob(b);
        CHECK(find_store(p, "T")->reason == "parse_error");
        CHECK(p.data.facts.size() == 1); // the certificate itself still parsed
    }
}

TEST_CASE("cert parse: DER is kept only when it hashes to the row identity", "[certinv][parse]") {
    // sha256("abc") pinned independently of the implementation.
    const std::string abc_sha =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    Cert c = cert(1, {{"S", ""}});
    c.sha_override = abc_sha;
    c.der_b64 = "YWJj"; // "abc"
    const auto stores = store_rec("S", "ok");
    SECTION("matching") {
        const auto p = parse_certificate_inventory_blob(blob(stores, {c}));
        REQUIRE(p.data.facts.size() == 1);
        CHECK(*p.data.facts[0].der_base64 == "YWJj");
    }
    SECTION("mismatching: the certificate is kept, the DER is not, and it is marked") {
        c.sha_override = hexn(77);
        const auto p = parse_certificate_inventory_blob(blob(stores, {c}));
        REQUIRE(p.data.facts.size() == 1);
        CHECK_FALSE(p.data.facts[0].der_base64.has_value());
        CHECK(p.data.facts[0].constrained_fields == "der_sha256_mismatch");
    }
    SECTION("not base64 is refused") {
        c.der_b64 = "!!!!";
        CHECK(parse_certificate_inventory_blob(blob(stores, {c})).data.facts.empty());
    }
}

TEST_CASE("cert parse: declared counts are checked", "[certinv][parse]") {
    SECTION("sans= disagreeing with the san records refuses the certificate") {
        Cert c = cert(1, {{"S", ""}});
        c.sans_field = "sans=2";
        c.sans = {{"dns", "a"}};
        CHECK(parse_certificate_inventory_blob(blob(store_rec("S", "ok"), {c})).data.facts.empty());
    }
    SECTION("an ok store's cert_count must match") {
        const auto p = parse_certificate_inventory_blob(
            blob(store_rec("S", "ok", "", "2"), {cert(1, {{"S", ""}})}));
        CHECK(find_store(p, "S")->reason == "parse_error");
    }
    SECTION("a certificate in an absent store is a contradiction") {
        const auto p = parse_certificate_inventory_blob(
            blob(store_rec("S", "absent"), {cert(1, {{"S", ""}})}));
        CHECK(find_store(p, "S")->status == "constrained");
        CHECK(p.data.facts.empty());
    }
}

TEST_CASE("cert parse: validity dates keep pre-1970 and the year-9999 sentinel; bad dates refuse",
          "[certinv][parse]") {
    Cert c = cert(1, {{"S", ""}});
    c.not_before = "1950-06-01T00:00:00Z";
    c.not_after = "9999-12-31T23:59:59Z";
    const auto p = parse_certificate_inventory_blob(blob(store_rec("S", "ok"), {c}));
    REQUIRE(p.data.facts.size() == 1);
    CHECK(*p.data.facts[0].not_after == "9999-12-31T23:59:59Z");
    c.not_after = "2030-02-30T00:00:00Z";
    CHECK(parse_certificate_inventory_blob(blob(store_rec("S", "ok"), {c})).data.facts.empty());
}

TEST_CASE("cert parse: a certificate in two stores is one fact with two locations",
          "[certinv][parse]") {
    std::string b = "ver|1\n" + store_rec("A", "ok") + store_rec("B", "ok") +
                    cert_group(cert(1, {{"A", "/a"}})) + cert_group(cert(1, {{"B", "/b"}}));
    const auto p = parse_certificate_inventory_blob(b);
    CHECK(p.data.facts.size() == 1);
    CHECK(p.data.locations.size() == 2);
}

// ── Schema lint (ADR-0070 D13 "Mechanical checks") ──────────────────────────

namespace {

std::set<std::string> forbidden_column_names() {
    std::set<std::string> f = {"days_remaining",        "rule_id",    "rule_set_version",
                               "threshold",             "as_of",      "window_set_version",
                               "expiring_within_days",  "expired_within_days",
                               "revoked_within_days",   "issued_within_days"};
    using K = yuzu::server::CaCertKind;
    using B = yuzu::server::RevokedBucket;
    for (K k : {K::kActive, K::kExpiring, K::kExpired, K::kRevoked, K::kIssued, K::kIssuedWeek,
                K::kRevokedWeek}) {
        f.insert(yuzu::server::crypto_widgets::rule_id(k));
        for (B b : yuzu::server::crypto_widgets::kRevokedBuckets)
            f.insert(yuzu::server::crypto_widgets::rule_id(k, b));
    }
    return f;
}

// Every identifier token in the SQL that is a D13 name, or has the shape of a window field.
std::vector<std::string> lint_violations(const std::string& sql) {
    static const auto forbidden = forbidden_column_names();
    std::vector<std::string> bad;
    std::string tok;
    const auto flush = [&] {
        if (tok.empty())
            return;
        const bool window_shape =
            tok.starts_with("yuzu_ca_") || tok.ends_with("_within_days") ||
            tok.ends_with("_days_remaining") ||
            (tok.size() > 3 && tok.back() == 'd' &&
             (tok.starts_with("expiring_") || tok.starts_with("expired_") ||
              tok.starts_with("revoked_") || tok.starts_with("issued_")) &&
             std::isdigit(static_cast<unsigned char>(tok[tok.size() - 2])));
        if (forbidden.contains(tok) || window_shape)
            bad.push_back(tok);
        tok.clear();
    };
    for (char c : sql) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
            tok.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        else
            flush();
    }
    flush();
    return bad;
}

} // namespace

TEST_CASE("cert schema lint: no column is a D13 rule id, window field or days_remaining",
          "[certinv][lint]") {
    SECTION("the lint is not vacuous") {
        CHECK_FALSE(lint_violations("ALTER TABLE t ADD COLUMN days_remaining INT").empty());
        CHECK_FALSE(lint_violations("CREATE TABLE t (expiring_30d INT)").empty());
        CHECK_FALSE(lint_violations("CREATE TABLE t (yuzu_ca_active INT)").empty());
        CHECK_FALSE(lint_violations("CREATE TABLE t (revoked_within_days INT)").empty());
        CHECK(lint_violations("CREATE TABLE t (not_after TIMESTAMPTZ)").empty());
    }
    SECTION("every migration of this store is clean") {
        REQUIRE_FALSE(certificate_inventory_migrations().empty());
        for (const auto& m : certificate_inventory_migrations())
            CHECK(lint_violations(m.sql).empty());
    }
}

// ── Metric ───────────────────────────────────────────────────────────────────

TEST_CASE("cert metric: every (result, reason) pair is seeded and the set is closed",
          "[certinv][metrics]") {
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    const auto text = m.serialize();
    std::set<std::pair<std::string_view, std::string_view>> seen;
    for (const auto& pr : cert_ingest_metric::kPairs) {
        CHECK(seen.insert(pr).second); // no duplicates
        CHECK(text.find(std::string("result=\"") + std::string(pr.first) + "\"") !=
              std::string::npos);
        CHECK(text.find(std::string("reason=\"") + std::string(pr.second) + "\"") !=
              std::string::npos);
    }
    CHECK(seen.contains({"stored", "parse_error"}));
    CHECK(text.find("yuzu_server_cert_inventory_ingest_total") != std::string::npos);
}

// ── Store: round trip ────────────────────────────────────────────────────────

TEST_CASE("CertificateInventoryStore: opens and migrates on a fresh database",
          "[certinv][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    CertificateInventoryStore store{pool};
    CHECK(store.is_open());
    CHECK(scalar(pool,
                 "SELECT count(*) FROM information_schema.tables WHERE table_schema = "
                 "'cert_inventory'") == "7");
}

TEST_CASE("CertificateInventoryStore: a report round-trips facts, children and locations",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"LocalMachine\\Root", ""}, {"LocalMachine\\Root", "/p/q"}});
    c.not_before = "1950-06-01T00:00:00Z";
    c.not_after = "9999-12-31T23:59:59Z";
    c.sans = {{"dns", "b.example"}, {"ip", "10.0.0.1"}, {"dirname", "CN=\xC3\xA9"}};
    c.ekus = {"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"};
    c.cdps = {"http://crl.example/a.crl"};
    const auto ack = ingest(store, "agent-1",
                            full_report(blob(store_rec("LocalMachine\\Root", "ok", "", "1"), {c})));
    CHECK_FALSE(nacked(ack));

    auto rc = store.row_counts("agent-1");
    REQUIRE(rc.has_value());
    CHECK(rc->agent_state == 1);
    CHECK(rc->store_state == 1);
    CHECK(rc->cert_fact == 1);
    CHECK(rc->cert_location == 2);
    CHECK(rc->cert_san == 3);
    CHECK(rc->cert_eku == 2);
    CHECK(rc->cert_cdp == 1);
    CHECK(scalar(pool, "SELECT to_char(not_after AT TIME ZONE 'UTC', "
                       "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM cert_inventory.cert_fact") ==
          "9999-12-31T23:59:59Z");
    CHECK(scalar(pool, "SELECT to_char(not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD') FROM "
                       "cert_inventory.cert_fact") == "1950-06-01");
    CHECK(scalar(pool, "SELECT string_agg(value, ',' ORDER BY ord) FROM cert_inventory.cert_san") ==
          "b.example,10.0.0.1,CN=\xC3\xA9");
    CHECK(scalar(pool, "SELECT rsa_modulus_bits::text || key_alg_oid FROM cert_inventory.cert_fact") ==
          "20481.2.840.113549.1.1.1");
    CHECK(scalar(pool, "SELECT ec_curve_oid IS NULL FROM cert_inventory.cert_fact") == "t"); // n/a -> NULL
    CHECK(scalar(pool, "SELECT content_hash FROM cert_inventory.agent_state") ==
          raw_hash(blob(store_rec("LocalMachine\\Root", "ok", "", "1"), {c})));
    CHECK(scalar(pool, "SELECT cert_count::text FROM cert_inventory.store_state") == "1");
    // Slice 2 reads no per-user store: no row ever carries a user_ref.
    CHECK(scalar(pool, "SELECT count(*) FROM cert_inventory.store_state WHERE user_ref <> ''") ==
          "0");
    CHECK(scalar(pool, "SELECT count(*) FROM cert_inventory.cert_location WHERE user_ref <> ''") ==
          "0");
}

TEST_CASE("CertificateInventoryStore: the stored hash is of the received bytes, never the claim",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const auto b = blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})});
    ingest(store, "agent-1", full_report(b));
    CHECK(scalar(pool, "SELECT content_hash FROM cert_inventory.agent_state") == raw_hash(b));
    CHECK(scalar(pool, "SELECT content_hash FROM cert_inventory.agent_state") != "claimed-hash");
}

// ── Store: the per-store replace rules ───────────────────────────────────────

TEST_CASE("CertificateInventoryStore: every status row of the ingest table", "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const std::string a = "agent-1";
    const auto fact = [&](int id) {
        return scalar(pool, "SELECT count(*) FROM cert_inventory.cert_fact WHERE sha256 = $1",
                      {hexn(id)});
    };
    const auto state = [&](const char* s, const char* col) {
        return scalar(pool,
                      (std::string("SELECT ") + col +
                       " FROM cert_inventory.store_state WHERE store_id = $1")
                          .c_str(),
                      {s});
    };
    const auto observed_after = [&](const char* s, const std::string& before) {
        return scalar(pool,
                      "SELECT observed_at > $2::timestamptz FROM cert_inventory.store_state "
                      "WHERE store_id = $1",
                      {s, before});
    };

    // Report 1: five ok stores.
    const auto b1 = blob(store_rec("S1", "ok") + store_rec("S2", "ok") + store_rec("S3", "ok") +
                             store_rec("S4", "ok") + store_rec("S5", "ok"),
                         {cert(1, {{"S1", "a"}}), cert(2, {{"S1", "b"}}), cert(3, {{"S2", ""}}),
                          cert(4, {{"S3", ""}}), cert(5, {{"S4", ""}}), cert(6, {{"S5", ""}})});
    REQUIRE_FALSE(nacked(ingest(store, a, full_report(b1))));
    CHECK(store.row_counts(a)->cert_fact == 6);
    std::map<std::string, std::string> before;
    for (const char* s : {"S1", "S2", "S3", "S4", "S5"})
        before[s] = state(s, "observed_at::text");

    // Report 2: S1 ok (c2 gone), S2 absent, S3 missing, S4 constrained (c5 kept, c7 new),
    // S5 unreadable (c6 kept).
    const auto b2 = blob(store_rec("S1", "ok") + store_rec("S2", "absent") +
                             store_rec("S4", "constrained", "row_cap") +
                             store_rec("S5", "unreadable", "permission_denied"),
                         {cert(1, {{"S1", "a"}}), cert(7, {{"S4", ""}}), cert(6, {{"S5", ""}})});
    REQUIRE_FALSE(nacked(ingest(store, a, full_report(b2))));

    CHECK(fact(1) == "1");
    CHECK(fact(2) == "0"); // ok: replaced, and the orphaned fact went with it
    CHECK(fact(3) == "0"); // absent: removed
    CHECK(fact(4) == "1"); // missing: untouched
    CHECK(fact(5) == "1"); // constrained: unreported location kept
    CHECK(fact(6) == "1"); // unreadable: untouched
    CHECK(fact(7) == "1"); // constrained: reported location upserted

    CHECK(state("S1", "status") == "ok");
    CHECK(state("S2", "status") == "absent");
    CHECK(state("S3", "status") == "not_observed");
    CHECK(state("S3", "reason") == "missing_from_report");
    CHECK(state("S4", "status") == "constrained");
    CHECK(state("S4", "reason") == "row_cap");
    CHECK(state("S5", "status") == "unreadable");
    CHECK(state("S5", "reason") == "permission_denied");

    CHECK(observed_after("S1", before["S1"]) == "t");
    CHECK(observed_after("S2", before["S2"]) == "t");
    CHECK(state("S3", "observed_at::text") == before["S3"]);
    CHECK(state("S4", "observed_at::text") == before["S4"]);
    CHECK(state("S5", "observed_at::text") == before["S5"]);

    CHECK(state("S1", "cert_count::text") == "1");
    CHECK(state("S4", "cert_count::text") == "2");
    CHECK(state("S2", "cert_count::text") == "0");
}

TEST_CASE("CertificateInventoryStore: a certificate kept in an unreadable store keeps its fact "
          "and is not rewritten by the report",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1",
           full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    // The same certificate is listed in an unreadable store: its location is ignored.
    ingest(store, "agent-1",
           full_report(blob(store_rec("S", "unreadable", "enum_failed"),
                            {cert(1, {{"S", ""}})})));
    CHECK(store.row_counts("agent-1")->cert_fact == 1);
    CHECK(store.row_counts("agent-1")->cert_location == 1);
}

TEST_CASE("CertificateInventoryStore: a parse error keeps the store's rows and stays visible",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1",
           full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}}), cert(2, {{"S", ""}})})));
    // Now certificate 2 arrives corrupt (65 SANs); certificate 1 is not reported at all.
    Cert bad = cert(2, {{"S", ""}});
    for (int i = 0; i < 65; ++i)
        bad.sans.push_back({"dns", "h" + std::to_string(i)});
    const auto b = blob(store_rec("S", "ok"), {bad});
    const auto ack = ingest(store, "agent-1", full_report(b));
    CHECK_FALSE(nacked(ack)); // acked, so the agent does not resend for ever
    CHECK(scalar(pool, "SELECT status || '/' || reason FROM cert_inventory.store_state") ==
          "constrained/parse_error");
    CHECK(store.row_counts("agent-1")->cert_fact == 2); // nothing was lost
    // A hash-skip replay of the same bytes keeps it visibly constrained.
    const auto ack2 = ingest(store, "agent-1", hash_only(raw_hash(b)));
    CHECK_FALSE(nacked(ack2));
    CHECK(scalar(pool, "SELECT status || '/' || reason FROM cert_inventory.store_state") ==
          "constrained/parse_error");
}

TEST_CASE("CertificateInventoryStore: invalid UTF-8 is stored replaced and marked",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.subject = std::string("CN=bad\xff");
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    CHECK(scalar(pool, "SELECT subject_dn FROM cert_inventory.cert_fact") == "CN=bad\xEF\xBF\xBD");
    CHECK(scalar(pool, "SELECT constrained_fields FROM cert_inventory.cert_fact") ==
          "utf8_replaced:subject_dn");
}

TEST_CASE("CertificateInventoryStore: a stored certificate with an over-cap child is refused whole",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert bad = cert(1, {{"S", ""}});
    for (int i = 0; i < 65; ++i)
        bad.sans.push_back({"dns", "h" + std::to_string(i)});
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {bad})));
    CHECK(store.row_counts("agent-1")->cert_fact == 0);
    CHECK(store.row_counts("agent-1")->cert_san == 0); // never truncated to 64
    CHECK(scalar(pool, "SELECT reason FROM cert_inventory.store_state") == "parse_error");
}

// ── Hash-skip and need_full ──────────────────────────────────────────────────

TEST_CASE("CertificateInventoryStore: hash-skip refreshes exactly what the last full report "
          "carried",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const std::string a = "agent-1";
    ingest(store, a,
           full_report(blob(store_rec("S1", "ok") + store_rec("S2", "constrained", "row_cap") +
                                store_rec("S3", "unreadable", "permission_denied"),
                            {cert(1, {{"S1", ""}}), cert(2, {{"S2", ""}})})));
    // Second full report: S2 still constrained but now reports only certificate 9; certificate 2
    // stays on the server as a kept, unreported location.
    const auto b2 = blob(store_rec("S1", "ok") + store_rec("S2", "constrained", "row_cap") +
                             store_rec("S3", "unreadable", "permission_denied"),
                         {cert(1, {{"S1", ""}}), cert(9, {{"S2", ""}})});
    ingest(store, a, full_report(b2));
    REQUIRE(store.row_counts(a)->cert_location == 3);

    const auto loc_seen = [&](int id) {
        return scalar(pool,
                      "SELECT last_seen::text FROM cert_inventory.cert_location WHERE sha256 = $1",
                      {hexn(id)});
    };
    const auto st = [&](const char* s, const char* col) {
        return scalar(pool,
                      (std::string("SELECT ") + col +
                       " FROM cert_inventory.store_state WHERE store_id = $1")
                          .c_str(),
                      {s});
    };
    const std::string l1 = loc_seen(1), l2 = loc_seen(2), l9 = loc_seen(9);
    const std::string obs1 = st("S1", "observed_at::text");
    const std::string sat1 = st("S1", "status_at::text"), sat2 = st("S2", "status_at::text"),
                      sat3 = st("S3", "status_at::text");
    const std::string agent_seen = scalar(pool, "SELECT last_seen::text FROM cert_inventory.agent_state");
    const std::string agent_full = scalar(pool, "SELECT last_full_at::text FROM cert_inventory.agent_state");

    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    const auto ack = ingest(store, a, hash_only(raw_hash(b2)), &m);
    CHECK_FALSE(nacked(ack));

    CHECK(loc_seen(1) != l1);  // carried by the last full report
    CHECK(loc_seen(9) != l9);  // carried
    CHECK(loc_seen(2) == l2);  // kept, unreported: keeps ageing
    CHECK(st("S1", "observed_at::text") != obs1); // ok: observed
    CHECK(st("S1", "status_at::text") != sat1);
    CHECK(st("S2", "status_at::text") != sat2);   // constrained: status_at advances...
    CHECK(st("S2", "observed_at") == "<null>");   // ...observed_at does not
    CHECK(st("S3", "status_at::text") != sat3);   // unreadable: status_at advances...
    CHECK(st("S3", "observed_at") == "<null>");   // ...observed_at does not
    CHECK(scalar(pool, "SELECT last_seen::text FROM cert_inventory.agent_state") != agent_seen);
    CHECK(scalar(pool, "SELECT last_full_at::text FROM cert_inventory.agent_state") == agent_full);
    CHECK(m.serialize().find("touched") != std::string::npos);
}

TEST_CASE("CertificateInventoryStore: cold cache and hash mismatch ask for a full resend",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    // Cold: no state for the agent.
    CHECK(nacked(ingest(store, "cold-agent", hash_only(std::string(64, 'a')), &m)));
    CHECK(scalar(pool, "SELECT count(*) FROM cert_inventory.agent_state") == "0");
    // Mismatch: the stored hash differs from the claim.
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    CHECK(nacked(ingest(store, "agent-1", hash_only(std::string(64, 'b')), &m)));
    CHECK(store.row_counts("agent-1")->cert_fact == 1); // untouched
}

TEST_CASE("CertificateInventoryStore: a nacked blob writes nothing", "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const auto ack = ingest(store, "agent-1", full_report("ver|2\n" + store_rec("S", "ok")));
    CHECK(nacked(ack));
    CHECK(store.row_counts("agent-1")->agent_state == 0);
}

// ── Decommission ─────────────────────────────────────────────────────────────

TEST_CASE("CertificateInventoryStore: delete_agent erases every table for the agent only",
          "[certinv][pg][decommission]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", "p"}});
    c.sans = {{"dns", "a"}};
    c.ekus = {"1.3.6.1.5.5.7.3.1"};
    c.cdps = {"http://x/y.crl"};
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    ingest(store, "bystander", full_report(blob(store_rec("S", "ok"), {cert(2, {{"S", ""}})})));
    REQUIRE(store.row_counts("agent-1")->cert_fact == 1);

    REQUIRE(store.delete_agent("agent-1"));
    const auto rc = store.row_counts("agent-1");
    REQUIRE(rc.has_value());
    CHECK(rc->agent_state + rc->store_state + rc->cert_location + rc->cert_fact + rc->cert_san +
              rc->cert_eku + rc->cert_cdp ==
          0);
    CHECK(store.row_counts("bystander")->cert_fact == 1); // a neighbour is untouched
    CHECK_FALSE(store.delete_agent("")); // refuses the empty id
}

namespace {
// Every table's row count for the agent, as one comparable tuple.
std::vector<std::int64_t> shape(CertificateInventoryStore& s, const std::string& a) {
    const auto r = s.row_counts(a);
    REQUIRE(r.has_value());
    return {r->agent_state, r->store_state, r->cert_location, r->cert_fact,
            r->cert_san,    r->cert_eku,    r->cert_cdp};
}
} // namespace

TEST_CASE("CertificateInventoryStore: an ingest racing delete_agent ends as one whole state, "
          "whichever wins",
          "[certinv][pg][decommission]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.sans = {{"dns", "a"}};
    const auto b = blob(store_rec("S", "ok"), {c});
    // The state a single uncontended report leaves behind.
    ingest(store, "reference", full_report(b));
    const auto whole = shape(store, "reference");
    REQUIRE(whole[3] == 1);

    SECTION("delete_agent starts while the ingest holds the lock: the ingest commits first, the "
            "erase then wins wholly") {
        std::atomic<bool> delete_done{false};
        std::atomic<bool> delete_done_at_hook_return{true};
        bool delete_ok = false;
        std::thread deleter;
        store.set_test_hook_after_lock([&] {
            deleter = std::thread([&] {
                CertificateInventoryStore other{pool}; // a second connection
                delete_ok = other.delete_agent("agent-1");
                delete_done = true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            delete_done_at_hook_return = delete_done.load();
        });
        const auto ack = ingest(store, "agent-1", full_report(b));
        store.set_test_hook_after_lock(nullptr);
        deleter.join();
        CHECK_FALSE(nacked(ack));
        CHECK(delete_ok);
        CHECK_FALSE(delete_done_at_hook_return.load()); // the erase waited for the ingest's lock
        CHECK(shape(store, "agent-1") == std::vector<std::int64_t>(7, 0));
    }

    SECTION("an ingest starts while delete_agent holds the lock: the erase commits first, the "
            "report then wins wholly") {
        ingest(store, "agent-1", full_report(b)); // something to erase
        std::atomic<bool> ingest_done{false};
        std::atomic<bool> ingest_done_at_hook_return{true};
        std::thread reporter;
        CertificateInventoryStore other{pool};
        store.set_test_hook_after_erase([&] {
            reporter = std::thread([&] {
                (void)ingest(other, "agent-1", full_report(b));
                ingest_done = true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            ingest_done_at_hook_return = ingest_done.load();
        });
        REQUIRE(store.delete_agent("agent-1"));
        store.set_test_hook_after_erase(nullptr);
        reporter.join();
        CHECK_FALSE(ingest_done_at_hook_return.load()); // the report waited for the erase's lock
        CHECK(shape(store, "agent-1") == whole);        // no partial rows
    }
}

TEST_CASE("decommission cascade: the certificate inventory store is registered and erased",
          "[certinv][pg][decommission]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    AgentDecommission cascade{AgentDecommissionStores{.certificate_inventory = &store}};
    const auto result = cascade.decommission("agent-1");
    const auto it = std::find_if(result.stores.begin(), result.stores.end(),
                                 [](const auto& s) { return s.store == "certificate_inventory"; });
    REQUIRE(it != result.stores.end());
    CHECK(it->outcome == DecommissionOutcome::Deleted);
    CHECK(store.row_counts("agent-1")->cert_fact == 0);
}

// ── The agent's golden blob (canonical writer contract) ──────────────────────

// `expected` is copied BYTE-FOR-BYTE from the writer's own golden ("inventory blob: GOLDEN bytes",
// tests/unit/test_certificates_inventory.cpp at feat/cert-inventory-agent-linux fc0544c6d, the
// 32-field cert| record). Its DER-carrying certificate uses a placeholder sha256 that is not the
// SHA-256 of its DER, so this seam keeps the certificate but drops the DER and marks it
// `der_sha256_mismatch` (the row identity is the SHA-256 of the DER; it is never stored under a
// different one).
TEST_CASE("cert parse: the agent writer's golden blob lands every field where it belongs",
          "[certinv][parse][golden]") {
    const std::string sha1c = std::string(60, 'a') + "0001";
    const std::string sha2 = std::string(60, 'a') + "0002";
    const std::string expected =
        "ver|1\n"
        "store|/etc/pki/tls/certs|machine|absent||0\n"
        "store|/etc/pki/trust/anchors|machine|unreadable|permission_denied|0\n"
        "store|/etc/ssl/certs|machine|ok||2\n"
        "cert|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001|"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0001|"
        "3|0123|CN=Acme\\\\, Inc.,O=Yuzu|CN=Root\\\\\\\\CA|"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|"
        "2024-01-01T00:00:00Z|9999-12-31T23:59:59Z|1.2.840.113549.1.1.1|2048|||"
        "1.2.840.113549.1.1.11|||AABB|CCDD|1||Digital Signature, Key Encipherment|0|?|?|?|"
        "sans=2|ekus=1|cdps=1||sans_truncated\n"
        "loc|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|/etc/ssl/certs|"
        "/etc/ssl/certs/a\\|x.pem\n"
        "loc|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|/etc/ssl/certs|"
        "/etc/ssl/certs/b.pem\n"
        "san|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|dns|a.example\n"
        "san|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|upn|alice@corp.example\n"
        "eku|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|1.3.6.1.5.5.7.3.1\n"
        "cdp|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|http://crl.example/a.crl\n"
        "der|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001|MAMCAQU=\n"
        "cert|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0002|"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002|"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0002|"
        "3|0123|CN=Beta\\\\, Inc.,O=Yuzu|CN=Root\\\\\\\\CA|"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|"
        "2024-01-01T00:00:00Z|9999-12-31T23:59:59Z|1.2.840.113549.1.1.1|2048|||"
        "1.2.840.113549.1.1.11|||AABB|CCDD|?||Digital Signature, Key Encipherment|1|?|?|?|"
        "sans=0|ekus=0|cdps=0|self_signed|\n"
        "loc|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0002|/etc/ssl/certs|"
        "/etc/ssl/certs/c.pem\n";

    const auto p = parse_certificate_inventory_blob(expected);
    REQUIRE(p.nack == CertBlobNack::kNone);
    CHECK_FALSE(p.any_parse_error);
    CHECK(p.data.blob_version == "1");

    REQUIRE(p.data.stores.size() == 3);
    CHECK(find_store(p, "/etc/pki/tls/certs")->status == "absent");
    CHECK(find_store(p, "/etc/pki/trust/anchors")->status == "unreadable");
    CHECK(find_store(p, "/etc/pki/trust/anchors")->reason == "permission_denied");
    CHECK(find_store(p, "/etc/ssl/certs")->status == "ok");
    CHECK(find_store(p, "/etc/ssl/certs")->scope == "machine");

    REQUIRE(p.data.facts.size() == 2);
    const CertFactRow* a = nullptr;
    const CertFactRow* b = nullptr;
    for (const auto& f : p.data.facts)
        (f.sha256 == sha1c ? a : b) = &f;
    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);

    CHECK(*a->sha1 == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001");
    CHECK(*a->tbs_sha256 == std::string(60, 'c') + "0001");
    CHECK(*a->version == 3);
    CHECK(*a->serial == "0123");
    CHECK(*a->subject_dn == "CN=Acme\\, Inc.,O=Yuzu");
    CHECK(*a->issuer_dn == "CN=Root\\\\CA");
    CHECK(*a->subject_name_sha256 == std::string(64, 'd'));
    CHECK(*a->issuer_name_sha256 == std::string(64, 'e'));
    CHECK(*a->not_before == "2024-01-01T00:00:00Z");
    CHECK(*a->not_after == "9999-12-31T23:59:59Z");
    CHECK(*a->key_alg_oid == "1.2.840.113549.1.1.1");
    CHECK(*a->rsa_modulus_bits == 2048);
    CHECK_FALSE(a->ec_curve_oid.has_value());   // empty = not applicable
    CHECK_FALSE(a->ec_order_bits.has_value());
    CHECK(*a->sig_alg_oid == "1.2.840.113549.1.1.11");
    CHECK_FALSE(a->pss_hash_oid.has_value());
    CHECK_FALSE(a->pss_mgf1_hash_oid.has_value());
    CHECK_FALSE(a->spki_sha256.has_value()); // not on the wire
    CHECK(*a->ski == "AABB");
    CHECK(*a->aki_key_id == "CCDD");
    CHECK(*a->is_ca == true);
    CHECK_FALSE(a->path_len.has_value());
    CHECK(*a->key_usage == "Digital Signature, Key Encipherment");
    CHECK(*a->self_signed == false);
    CHECK_FALSE(a->key_association.has_value()); // ? = unknown
    CHECK_FALSE(a->key_provider.has_value());
    CHECK_FALSE(a->key_exportable.has_value());
    CHECK(*a->der_omitted == "");
    CHECK_FALSE(a->der_base64.has_value()); // placeholder sha: DER dropped, not stored
    CHECK(a->constrained_fields == "sans_truncated,der_sha256_mismatch");
    CHECK(*a->serial_negative == false);
    REQUIRE(a->sans.size() == 2);
    CHECK(a->sans[0].type == "dns");
    CHECK(a->sans[0].value == "a.example");
    CHECK(a->sans[1].type == "upn");
    CHECK(a->sans[1].value == "alice@corp.example");
    REQUIRE(a->ekus.size() == 1);
    CHECK(a->ekus[0] == "1.3.6.1.5.5.7.3.1");
    REQUIRE(a->cdps.size() == 1);
    CHECK(a->cdps[0] == "http://crl.example/a.crl");

    CHECK(*b->subject_dn == "CN=Beta\\, Inc.,O=Yuzu");
    CHECK_FALSE(b->is_ca.has_value()); // ? = unknown
    CHECK(*b->self_signed == true);
    CHECK(*b->der_omitted == "self_signed");
    CHECK_FALSE(b->der_base64.has_value());
    CHECK(b->sans.empty());
    CHECK(b->constrained_fields.empty());

    REQUIRE(p.data.locations.size() == 3);
    std::set<std::string> paths;
    for (const auto& l : p.data.locations) {
        CHECK(l.store_id == "/etc/ssl/certs");
        paths.insert(l.sha256 == sha1c ? l.path : "c:" + l.path);
    }
    CHECK(paths == std::set<std::string>{"/etc/ssl/certs/a|x.pem", "/etc/ssl/certs/b.pem",
                                         "c:/etc/ssl/certs/c.pem"});
}

TEST_CASE("cert parse: hex case is normalised and writer tokens are accepted",
          "[certinv][parse]") {
    Cert c = cert(1, {{"S", ""}});
    c.flags = "serial_negative,issuer_dn_truncated";
    std::string g = cert_group(c);
    // Digests arrive upper-case, serial/ski/aki lower-case: stored lower / UPPER.
    const auto up = [&](const std::string& from) {
        std::string t = from;
        for (auto& ch : t)
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        return t;
    };
    g.replace(g.find(std::string(40, 'a')), 40, up(std::string(40, 'a')));
    g.replace(g.find("|0A1B|"), 6, "|0a1b|");
    g.replace(g.find("|AABB|"), 6, "|aabb|");
    g.replace(g.find("|CCDD|"), 6, "|ccdd|");
    const auto p = parse_certificate_inventory_blob(
        "ver|1\n" + store_rec("S", "constrained", "mountinfo_unreadable,row_cap") +
        store_rec("T", "unreadable", "not_collected") + store_rec("U", "constrained", "cert_malformed") + g);
    REQUIRE(p.data.facts.size() == 1);
    const auto& f = p.data.facts[0];
    CHECK(*f.sha1 == std::string(40, 'a'));
    CHECK(*f.serial == "0A1B");
    CHECK(*f.ski == "AABB");
    CHECK(*f.aki_key_id == "CCDD");
    CHECK(*f.serial_negative == true);
    CHECK(f.constrained_fields == "serial_negative,issuer_dn_truncated");
    CHECK(find_store(p, "T")->reason == "not_collected");
    CHECK(find_store(p, "S")->reason == "mountinfo_unreadable,row_cap");
}

TEST_CASE("cert parse: store reasons are stored verbatim; a reason outside the token charset is a "
          "parse error",
          "[certinv][parse]") {
    const auto p = parse_certificate_inventory_blob(
        blob(store_rec("A", "unreadable", "keychain_not_readable") +
                 store_rec("B", "unreadable", "open_failed:13,timeout") +
                 store_rec("C", "constrained", "cert_unconvertible,link_outside_roots") +
                 store_rec("D", "unreadable", "busy") + store_rec("E", "constrained", "row_cap"),
             {}));
    REQUIRE(p.nack == CertBlobNack::kNone);
    CHECK_FALSE(p.any_parse_error);
    CHECK(find_store(p, "A")->reason == "keychain_not_readable");
    CHECK(find_store(p, "B")->reason == "open_failed:13,timeout");
    CHECK(find_store(p, "C")->reason == "cert_unconvertible,link_outside_roots");

    const auto bad = parse_certificate_inventory_blob(
        blob(store_rec("A", "ok", "has space") + store_rec("B", "constrained", "x,,y") +
                 store_rec("C", "unreadable", "not;a;token"),
             {}));
    CHECK(bad.any_parse_error);
    CHECK(find_store(bad, "A")->status == "constrained");
    CHECK(find_store(bad, "A")->reason == "parse_error");
    CHECK(find_store(bad, "B")->reason == "parse_error");
    CHECK(find_store(bad, "C")->status == "unreadable"); // the specific status stays
    CHECK(find_store(bad, "C")->reason.empty());
}

TEST_CASE("CertificateInventoryStore: a location with an empty path (a keychain has no per-cert "
          "path) round-trips",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1",
           full_report(blob(store_rec("/Library/Keychains/System.keychain", "ok", "", "1"),
                            {cert(1, {{"/Library/Keychains/System.keychain", ""}})})));
    CHECK(scalar(pool, "SELECT count(*) FROM cert_inventory.cert_location WHERE path = ''") == "1");
}
