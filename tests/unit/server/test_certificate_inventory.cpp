// CertificateInventoryStore + certificate_inventory ingest seam tests (slice-2 PR 2a-2a):
// the blob parse (escape grammar, versions, unknown vs empty, caps, UTF-8, record-level and
// whole-report parse errors), every per-store replace rule, hash-skip and need_full, the
// per-agent lock (an ingest racing delete_agent, in both orders), the cascade registration, the metric's closed set, and the D13 schema
// lint over this store's migration array.
//
// The direct and gateway wiring (ReportInventory / ProxyInventory) is covered in
// test_agent_service_impl.cpp.

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include "agent.pb.h"
#include "agent_decommission.hpp"
#include "certificate_inventory_ingestion.hpp"
#include "certificate_inventory_store.hpp"
#include "certificate_read_model.hpp"
#include "crypto_widget_catalogue.hpp"
#include "dn_dict_pass_guard.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "secure_random.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <cctype>
#include <chrono>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
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
    std::string key_usage{"Digital Signature, Key Encipherment"};
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
        hexn(500 + c.id),       // spki_sha256
        "AABB",                 // ski
        "CCDD",                 // aki_key_id
        "1",                    // is_ca
        "0",                    // path_len
        c.key_usage,
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

// Exact value of one (result, reason) series; -1 when the series is absent. Matches the whole
// line, label order either way, so a substring of another series can never satisfy it.
long metric_count(yuzu::MetricsRegistry& m, std::string_view result, std::string_view reason) {
    const std::string text = m.serialize();
    for (const std::string& labels :
         {"reason=\"" + std::string(reason) + "\",result=\"" + std::string(result) + "\"",
          "result=\"" + std::string(result) + "\",reason=\"" + std::string(reason) + "\""}) {
        const std::string prefix = "yuzu_server_cert_inventory_ingest_total{" + labels + "} ";
        const auto at = text.find(prefix);
        if (at != std::string::npos && (at == 0 || text[at - 1] == '\n'))
            return std::stol(text.substr(at + prefix.size(), 20));
    }
    return -1;
}

// The generic per-source family value for source=certificate_inventory (either label order).
long generic_count(yuzu::MetricsRegistry& m, std::string_view outcome) {
    const std::string text = m.serialize();
    for (const std::string& labels :
         {"outcome=\"" + std::string(outcome) + "\",source=\"certificate_inventory\"",
          "source=\"certificate_inventory\",outcome=\"" + std::string(outcome) + "\""}) {
        const std::string prefix = "yuzu_inventory_ingest_total{" + labels + "} ";
        const auto at = text.find(prefix);
        if (at != std::string::npos)
            return std::stol(text.substr(at + prefix.size(), 20));
    }
    return -1;
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
                             "TRUNCATE certificate_inventory_store.agent_state, "
                             "certificate_inventory_store.dn_dict, certificate_inventory_store.dn_dict_state CASCADE",
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

void exec_ok(PgPool& pool, const char* sql) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(), sql, std::vector<std::string>{}).status() ==
            PGRES_COMMAND_OK);
}

// Renames a table away for the scope's lifetime (to force a SQL failure), always restoring it.
struct TableOff {
    PgPool& pool;
    std::string name;
    TableOff(PgPool& p, std::string n) : pool(p), name(std::move(n)) {
        exec_ok(pool, ("ALTER TABLE certificate_inventory_store." + name + " RENAME TO " + name + "_off").c_str());
    }
    ~TableOff() {
        auto l = pool.acquire();
        pg::exec_params(l.get(),
                        ("ALTER TABLE certificate_inventory_store." + name + "_off RENAME TO " + name).c_str(),
                        std::vector<std::string>{});
    }
};

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
        CHECK(find_store(p, "S")->reason == "row_cap"); // a cap, not a parse defect
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
        CHECK(p.any_over_cap);
        CHECK(find_fact(p, 1) == nullptr);
        CHECK(find_store(p, "S")->reason == "row_cap");
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
        CHECK(find_store(p, "S")->reason == "row_cap");
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
    SECTION("mismatching: the certificate is kept, the DER is not, it is marked and counted") {
        c.sha_override = hexn(77);
        const auto p = parse_certificate_inventory_blob(blob(stores, {c}));
        REQUIRE(p.data.facts.size() == 1);
        CHECK_FALSE(p.data.facts[0].der_base64.has_value());
        CHECK(p.data.facts[0].constrained_fields == "der_hash_mismatch");
        CHECK(p.der_hash_mismatch);
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
        CHECK(metric_count(m, pr.first, pr.second) == 0); // seeded, exactly this series, at zero
    }
    // No series outside the closed set exists.
    std::size_t series = 0;
    for (std::size_t at = 0; (at = text.find("yuzu_server_cert_inventory_ingest_total{", at)) !=
                             std::string::npos;
         ++at)
        ++series;
    CHECK(series == cert_ingest_metric::kPairs.size());
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
                 "'certificate_inventory_store'") == "9");
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
                       "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM certificate_inventory_store.cert_fact") ==
          "9999-12-31T23:59:59Z");
    CHECK(scalar(pool, "SELECT to_char(not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD') FROM "
                       "certificate_inventory_store.cert_fact") == "1950-06-01");
    CHECK(scalar(pool, "SELECT string_agg(value, ',' ORDER BY ord) FROM certificate_inventory_store.cert_san") ==
          "b.example,10.0.0.1,CN=\xC3\xA9");
    CHECK(scalar(pool, "SELECT rsa_modulus_bits::text || key_alg_oid FROM certificate_inventory_store.cert_fact") ==
          "20481.2.840.113549.1.1.1");
    CHECK(scalar(pool, "SELECT ec_curve_oid IS NULL FROM certificate_inventory_store.cert_fact") == "t"); // n/a -> NULL
    CHECK(scalar(pool, "SELECT content_hash FROM certificate_inventory_store.agent_state") ==
          raw_hash(blob(store_rec("LocalMachine\\Root", "ok", "", "1"), {c})));
    CHECK(scalar(pool, "SELECT cert_count::text FROM certificate_inventory_store.store_state") == "1");
    // Slice 2 reads no per-user store: no row ever carries a user_ref.
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.store_state WHERE user_ref <> ''") ==
          "0");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_location WHERE user_ref <> ''") ==
          "0");
}

TEST_CASE("CertificateInventoryStore: the stored hash is of the received bytes, never the claim",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const auto b = blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})});
    ingest(store, "agent-1", full_report(b));
    CHECK(scalar(pool, "SELECT content_hash FROM certificate_inventory_store.agent_state") == raw_hash(b));
    CHECK(scalar(pool, "SELECT content_hash FROM certificate_inventory_store.agent_state") != "claimed-hash");
}

// ── Store: the per-store replace rules ───────────────────────────────────────

TEST_CASE("CertificateInventoryStore: every status row of the ingest table", "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const std::string a = "agent-1";
    const auto fact = [&](int id) {
        return scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact WHERE sha256 = $1",
                      {hexn(id)});
    };
    const auto state = [&](const char* s, const char* col) {
        return scalar(pool,
                      (std::string("SELECT ") + col +
                       " FROM certificate_inventory_store.store_state WHERE store_id = $1")
                          .c_str(),
                      {s});
    };
    const auto observed_after = [&](const char* s, const std::string& before) {
        return scalar(pool,
                      "SELECT observed_at > $2::timestamptz FROM certificate_inventory_store.store_state "
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
    CHECK(scalar(pool, "SELECT status || '/' || reason FROM certificate_inventory_store.store_state") ==
          "constrained/row_cap");
    CHECK(store.row_counts("agent-1")->cert_fact == 2); // nothing was lost
    // A hash-skip replay of the same bytes keeps it visibly constrained.
    const auto ack2 = ingest(store, "agent-1", hash_only(raw_hash(b)));
    CHECK_FALSE(nacked(ack2));
    CHECK(scalar(pool, "SELECT status || '/' || reason FROM certificate_inventory_store.store_state") ==
          "constrained/row_cap");
}

TEST_CASE("CertificateInventoryStore: invalid UTF-8 is stored replaced and marked",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.subject = std::string("CN=bad\xff");
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    CHECK(scalar(pool, "SELECT subject_dn FROM certificate_inventory_store.cert_fact") == "CN=bad\xEF\xBF\xBD");
    CHECK(scalar(pool, "SELECT constrained_fields FROM certificate_inventory_store.cert_fact") ==
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
    CHECK(scalar(pool, "SELECT reason FROM certificate_inventory_store.store_state") == "row_cap");
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
                      "SELECT last_seen::text FROM certificate_inventory_store.cert_location WHERE sha256 = $1",
                      {hexn(id)});
    };
    const auto st = [&](const char* s, const char* col) {
        return scalar(pool,
                      (std::string("SELECT ") + col +
                       " FROM certificate_inventory_store.store_state WHERE store_id = $1")
                          .c_str(),
                      {s});
    };
    const std::string l1 = loc_seen(1), l2 = loc_seen(2), l9 = loc_seen(9);
    const std::string obs1 = st("S1", "observed_at::text");
    const std::string sat1 = st("S1", "status_at::text"), sat2 = st("S2", "status_at::text"),
                      sat3 = st("S3", "status_at::text");
    const std::string agent_seen = scalar(pool, "SELECT last_seen::text FROM certificate_inventory_store.agent_state");
    const std::string agent_full = scalar(pool, "SELECT last_full_at::text FROM certificate_inventory_store.agent_state");

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
    CHECK(scalar(pool, "SELECT last_seen::text FROM certificate_inventory_store.agent_state") != agent_seen);
    CHECK(scalar(pool, "SELECT last_full_at::text FROM certificate_inventory_store.agent_state") == agent_full);
    CHECK(m.serialize().find("touched") != std::string::npos);
}

TEST_CASE("CertificateInventoryStore: cold cache and hash mismatch ask for a full resend",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    // Cold: no state for the agent.
    CHECK(nacked(ingest(store, "cold-agent", hash_only(std::string(64, 'a')), &m)));
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.agent_state") == "0");
    // Mismatch: the stored hash differs from the claim.
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    CHECK(nacked(ingest(store, "agent-1", hash_only(std::string(64, 'b')), &m)));
    CHECK(store.row_counts("agent-1")->cert_fact == 1); // untouched
}

TEST_CASE("CertificateInventoryStore: a rejected blob writes nothing and is a TERMINAL ack",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    // The same bytes would be refused again, so asking for them again would loop the agent.
    const auto ack = ingest(store, "agent-1", full_report("ver|2\n" + store_rec("S", "ok")), &m);
    CHECK_FALSE(nacked(ack));
    CHECK(store.row_counts("agent-1")->agent_state == 0);
    CHECK(metric_count(m, "rejected", "unknown_version") == 1);
    CHECK(metric_count(m, "stored", "none") == 0);
    CHECK_FALSE(nacked(ingest(store, "agent-1", full_report("garbage"), &m)));
    CHECK(metric_count(m, "rejected", "bad_header") == 1);
    // The generic per-source family is emitted too.
    CHECK(generic_count(m, "dropped") == 2); // maps to the siblings' over-cap-blob outcome
    CHECK(generic_count(m, "rejected") == -1); // `rejected` is reserved for >64 sources
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
// Joins its thread on scope exit (also on an early REQUIRE/CHECK exit), so a failing assertion can
// never reach std::terminate or leave a thread running against destroyed locals. Declare it AFTER
// every object its thread captures. (std::thread, not jthread: Apple libc++ at the project floor
// has no jthread.)
struct ThreadGuard {
    std::thread t;
    ThreadGuard() = default;
    ThreadGuard(const ThreadGuard&) = delete;
    ThreadGuard& operator=(const ThreadGuard&) = delete;
    ~ThreadGuard() { join(); }
    void join() {
        if (t.joinable())
            t.join();
    }
};
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
        ThreadGuard deleter; // declared after everything its thread captures
        store.set_test_hook_after_lock([&] {
            deleter.t = std::thread([&] {
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

    SECTION("an ingest starts while delete_agent holds the lock: it is DEFERRED (never parked on "
            "a pooled connection), and its retry then wins wholly") {
        ingest(store, "agent-1", full_report(b)); // something to erase
        std::atomic<bool> ingest_done{false};
        std::atomic<bool> deferred_ack_nacked{false};
        std::atomic<bool> ingest_done_at_hook_return{false};
        CertificateInventoryStore other{pool};
        yuzu::MetricsRegistry m;
        cert_ingest_metric::register_metrics(m);
        ThreadGuard reporter;
        store.set_test_hook_after_erase([&] {
            reporter.t = std::thread([&] {
                deferred_ack_nacked = nacked(ingest(other, "agent-1", full_report(b), &m));
                ingest_done = true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            ingest_done_at_hook_return = ingest_done.load();
        });
        REQUIRE(store.delete_agent("agent-1"));
        store.set_test_hook_after_erase(nullptr);
        reporter.join();
        CHECK(ingest_done_at_hook_return.load()); // it did not wait for the erase's lock
        CHECK(deferred_ack_nacked.load());        // the agent is told to resend
        CHECK(metric_count(m, "deferred", "agent_busy") == 1);
        CHECK(shape(store, "agent-1") == std::vector<std::int64_t>(7, 0)); // the erase won wholly
        ingest(store, "agent-1", full_report(b));                          // the retry
        CHECK(shape(store, "agent-1") == whole);                           // no partial rows
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
// tests/unit/test_certificates_inventory.cpp at feat/cert-inventory-agent-linux 89a735644, the
// 33-field cert| record with spki_sha256). The DER-carrying certificate's sha256 is the SHA-256
// of its shipped DER, so the DER is kept.
TEST_CASE("cert parse: the agent writer's golden blob lands every field where it belongs",
          "[certinv][parse][golden]") {
    const std::string sha1c = "417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729";
    const std::string sha2 = "eceda61045db145d209debf0d245e44b5b1cc52e3c04266aa2a486fdb6a2b285";
    const std::string expected =
        "ver|1\n"
        "store|/etc/pki/tls/certs|machine|absent||0\n"
        "store|/etc/pki/trust/anchors|machine|unreadable|permission_denied|0\n"
        "store|/etc/ssl/certs|machine|ok||2\n"
        "cert|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001|"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0001|"
        "3|0123|CN=Acme\\\\, Inc.,O=Yuzu|CN=Root\\\\\\\\CA|"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|"
        "2024-01-01T00:00:00Z|9999-12-31T23:59:59Z|1.2.840.113549.1.1.1|2048|||"
        "1.2.840.113549.1.1.11|||"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0001|AABB|CCDD|1||Digital Signature, Key Encipherment|0|?|?|?|"
        "sans=2|ekus=1|cdps=1||sans_truncated\n"
        "loc|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|/etc/ssl/certs|"
        "/etc/ssl/certs/a\\|x.pem\n"
        "loc|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|/etc/ssl/certs|"
        "/etc/ssl/certs/b.pem\n"
        "san|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|dns|a.example\n"
        "san|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|upn|alice@corp.example\n"
        "eku|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|1.3.6.1.5.5.7.3.1\n"
        "cdp|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|http://crl.example/a.crl\n"
        "der|417c7763c4e320a6b747b3cb0c6d22f93741b29a32b48594b8eb4c144fe6d729|MAMCAQU=\n"
        "cert|eceda61045db145d209debf0d245e44b5b1cc52e3c04266aa2a486fdb6a2b285|"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0002|"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0002|"
        "3|0123|CN=Beta\\\\, Inc.,O=Yuzu|CN=Root\\\\\\\\CA|"
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|"
        "2024-01-01T00:00:00Z|9999-12-31T23:59:59Z|1.2.840.113549.1.1.1|2048|||"
        "1.2.840.113549.1.1.11|||"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0002|AABB|CCDD|?||Digital Signature, Key Encipherment|1|?|?|?|"
        "sans=0|ekus=0|cdps=0|self_signed|\n"
        "loc|eceda61045db145d209debf0d245e44b5b1cc52e3c04266aa2a486fdb6a2b285|/etc/ssl/certs|"
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
    CHECK(*a->spki_sha256 == std::string(60, 'f') + "0001");
    CHECK(*b->spki_sha256 == std::string(60, 'f') + "0002");
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
    CHECK(*a->der_base64 == "MAMCAQU=");
    CHECK(a->constrained_fields == "sans_truncated");
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
    CHECK(b->constrained_fields == "unknown:is_ca"); // `?` is named, not silently NULL

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
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_location WHERE path = ''") == "1");
}

TEST_CASE("cert ingest: a DER that does not hash to its certificate is dropped and COUNTED",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.sha_override = hexn(77);
    c.der_b64 = "YWJj";
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})), &m);
    CHECK(store.row_counts("agent-1")->cert_fact == 1);
    CHECK(scalar(pool, "SELECT der IS NULL FROM certificate_inventory_store.cert_fact") == "t");
    CHECK(scalar(pool, "SELECT constrained_fields FROM certificate_inventory_store.cert_fact") ==
          "der_hash_mismatch");
    CHECK(m.serialize().find("result=\"stored\",reason=\"der_hash_mismatch\"} 1") !=
          std::string::npos);
}

// ── Concurrency, clock, keys, rewrite avoidance, error paths ─────────────────

namespace {
// Holds the per-agent advisory lock on its own connection until destroyed.
struct HeldAgentLock {
    pg::PgPool::Lease lease;
    explicit HeldAgentLock(PgPool& pool, const std::string& agent) : lease(pool.acquire()) {
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "BEGIN", std::vector<std::string>{}).status() ==
                PGRES_COMMAND_OK);
        auto r = pg::exec_params(
            lease.get(), "SELECT pg_advisory_xact_lock(hashtextextended($1::text || $2::text, 0))",
            std::vector<std::string>{std::string(kCertInventoryAgentLockPrefix), agent});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
    }
    ~HeldAgentLock() { pg::exec_params(lease.get(), "ROLLBACK", std::vector<std::string>{}); }
};
} // namespace

TEST_CASE("CertificateInventoryStore: concurrent reports for one agent never park pooled "
          "connections; they are deferred",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const auto b = blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})});
    ingest(store, "agent-1", full_report(b));
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);

    HeldAgentLock held(pool, "agent-1"); // another replica's report is mid-flight
    constexpr int kN = 12;               // more than the shared pool's size (4)
    std::atomic<int> full_nacked{0}, hash_nacked{0};
    std::vector<std::thread> ts;
    struct Joiner {
        std::vector<std::thread>& v;
        ~Joiner() {
            for (auto& t : v)
                if (t.joinable())
                    t.join();
        }
    } joiner{ts};
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kN; ++i)
        ts.emplace_back([&, i] {
            CertificateInventoryStore other{pool};
            if (i % 2 == 0) {
                if (nacked(ingest(other, "agent-1", full_report(b), &m)))
                    ++full_nacked;
            } else if (nacked(ingest(other, "agent-1", hash_only(raw_hash(b)), &m))) {
                ++hash_nacked;
            }
        });
    for (auto& t : ts)
        t.join();
    const auto took = std::chrono::steady_clock::now() - t0;
    CHECK(took < std::chrono::seconds(5)); // nobody waited on the lock
    CHECK(full_nacked == kN / 2);          // a full report is told to resend
    CHECK(hash_nacked == 0);               // a hash-only report just retries next cycle
    CHECK(metric_count(m, "deferred", "agent_busy") == kN);
    CHECK(store.row_counts("agent-1")->cert_fact == 1); // untouched
}

TEST_CASE("CertificateInventoryStore: a DB clock step does not freeze sweeps", "[certinv][pg]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    // Simulate the clock having been AHEAD (or restored from a later snapshot): the stored report
    // time is far in the future of the real DB clock.
    scalar(pool, "UPDATE certificate_inventory_store.agent_state SET last_full_at = "
                 "'2099-01-01'::timestamptz RETURNING 1");
    scalar(pool, "UPDATE certificate_inventory_store.cert_location SET full_report_at = "
                 "'2099-01-01'::timestamptz RETURNING 1");
    // The next ok report no longer carries certificate 1: its location must be swept.
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(2, {{"S", ""}})})));
    CHECK(scalar(pool, "SELECT string_agg(sha256, ',') FROM certificate_inventory_store.cert_location") ==
          hexn(2));
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact") == "1");
    // And last_full_at is the real DB time again, not latched in the future.
    CHECK(scalar(pool, "SELECT last_full_at < now() + interval '1 minute' FROM "
                       "certificate_inventory_store.agent_state") == "t");
}

TEST_CASE("CertificateInventoryStore: a very long path is keyed by its md5, not the btree",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    std::string path = "/";
    unsigned x = 12345;
    while (path.size() < 3500) { // incompressible: defeats TOAST compression
        x = x * 1103515245u + 12345u;
        path.push_back(static_cast<char>('a' + (x >> 16) % 26));
    }
    const auto ack = ingest(store, "agent-1",
                            full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", path}})})));
    CHECK_FALSE(nacked(ack));
    CHECK(store.row_counts("agent-1")->cert_location == 1);
    CHECK(scalar(pool, "SELECT length(path) FROM certificate_inventory_store.cert_location") ==
          "3500");
    // The same report again is an upsert on the md5 key, not a second row.
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", path}})})));
    CHECK(store.row_counts("agent-1")->cert_location == 1);
}

TEST_CASE("CertificateInventoryStore: an unchanged fact is not rewritten", "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.sans = {{"dns", "a"}, {"dns", "b"}};
    const auto b1 = blob(store_rec("S", "ok"), {c});
    ingest(store, "agent-1", full_report(b1));
    const auto fact_x = scalar(pool, "SELECT xmin::text FROM certificate_inventory_store.cert_fact");
    const auto san_x = scalar(pool, "SELECT string_agg(xmin::text, ',') FROM certificate_inventory_store.cert_san");
    // Same facts, different bytes (an extra store), so the report is a real full replace.
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok") + store_rec("T", "absent"), {c})));
    CHECK(scalar(pool, "SELECT xmin::text FROM certificate_inventory_store.cert_fact") == fact_x);
    CHECK(scalar(pool, "SELECT string_agg(xmin::text, ',') FROM certificate_inventory_store.cert_san") == san_x);
    // A changed fact IS rewritten.
    c.subject = "CN=changed";
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    CHECK(scalar(pool, "SELECT subject_dn FROM certificate_inventory_store.cert_fact") == "CN=changed");
}

TEST_CASE("CertificateInventoryStore: a failure mid-transaction rolls everything back and nacks",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    const auto before = shape(store, "agent-1");
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    {
        // Break a LATE write (the cdp insert), after the earlier statements already ran.
        TableOff off(pool, "cert_cdp");
        Cert c2 = cert(2, {{"S", ""}});
        c2.cdps = {"http://x/y.crl"};
        const auto ack = ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c2})), &m);
        CHECK(nacked(ack));
        CHECK(metric_count(m, "error", "store_error") == 1);
    }
    CHECK(shape(store, "agent-1") == before); // the failed full report left no partial rows
    {
        // A hash-only error does not ask for a full resend (a 3 MiB upload for a transient error).
        TableOff off(pool, "agent_state");
        CHECK_FALSE(nacked(ingest(store, "agent-1", hash_only(std::string(64, 'a')), &m)));
        CHECK(metric_count(m, "error", "store_error") == 2);
    }
    CHECK(shape(store, "agent-1") == before);
}

TEST_CASE("cert parse: cap boundaries, N accepted and N+1 refused", "[certinv][parse]") {
    const auto stores = store_rec("S", "ok");
    SECTION("SANs 64 / 65") {
        Cert c = cert(1, {{"S", ""}});
        for (int i = 0; i < 64; ++i)
            c.sans.push_back({"dns", "h" + std::to_string(i)});
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) != nullptr);
    }
    SECTION("SAN value 256 bytes accepted") {
        Cert c = cert(1, {{"S", ""}});
        c.sans = {{"dns", std::string(256, 'a')}};
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) != nullptr);
    }
    SECTION("EKUs 32 / 33") {
        Cert c = cert(1, {{"S", ""}});
        for (int i = 0; i < 32; ++i)
            c.ekus.push_back("1.3.6.1.5.5.7.3." + std::to_string(i));
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) != nullptr);
    }
    SECTION("CRL DPs 8 / 9, 512-byte URI accepted") {
        Cert c = cert(1, {{"S", ""}});
        for (int i = 0; i < 8; ++i)
            c.cdps.push_back("http://c/" + std::string(500, 'a') + std::to_string(i));
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) != nullptr);
    }
    SECTION("DN 1024 bytes accepted") {
        Cert c = cert(1, {{"S", ""}});
        c.subject = "CN=" + std::string(1021, 'a');
        CHECK(find_fact(parse_certificate_inventory_blob(blob(stores, {c})), 1) != nullptr);
    }
    SECTION("64 stores accepted") {
        std::string many;
        for (int i = 0; i < 64; ++i)
            many += store_rec("S" + std::to_string(i), "absent");
        CHECK(parse_certificate_inventory_blob(blob(many, {})).nack == CertBlobNack::kNone);
    }
    SECTION("2,000 certificates in one store accepted") {
        std::vector<Cert> certs;
        for (int i = 1; i <= 2000; ++i)
            certs.push_back(cert(i, {{"S", ""}}));
        const auto p = parse_certificate_inventory_blob(blob(stores, certs));
        CHECK_FALSE(p.any_over_cap);
        CHECK(p.data.facts.size() == 2000);
    }
}

TEST_CASE("cert parse: reason over the cap constrains that store, not the whole blob; `?` flags "
          "and unknown fields are named",
          "[certinv][parse]") {
    const auto p = parse_certificate_inventory_blob(
        blob(store_rec("A", "ok", std::string(300, 'a')) + store_rec("B", "ok"), {}));
    CHECK(p.nack == CertBlobNack::kNone);
    CHECK(find_store(p, "A")->reason == "parse_error");
    CHECK(find_store(p, "B")->status == "ok");

    Cert c = cert(1, {{"B", ""}});
    c.flags = "?";
    const auto q = parse_certificate_inventory_blob(blob(store_rec("B", "ok"), {c}));
    REQUIRE(q.data.facts.size() == 1);
    CHECK(q.data.facts[0].constrained_fields == "flags_unknown");
}

TEST_CASE("cert ingest: a hash-only claim that is not 64 lowercase hex is nacked and never "
          "reaches the store",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    for (const std::string& claim :
         {std::string(), std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'A'),
          std::string(64, 'g'), std::string("claimed-hash")})
        CHECK(nacked(ingest(store, "agent-1", hash_only(claim), &m)));
    CHECK(metric_count(m, "need_full", "bad_claim") == 6);
    CHECK(metric_count(m, "need_full", "hash_mismatch") == 0); // never reached the store compare
    CHECK(metric_count(m, "touched", "none") == 0);
}

TEST_CASE("cert ingest: a transaction over its budget is a distinct counted outcome, rolled back, "
          "and a scaled budget lets a large report finish",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const auto b = blob(store_rec("S", "ok"), {cert(1, {{"S", ""}}), cert(2, {{"S", ""}})});
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    store.set_test_ingest_budget([](std::size_t) { return std::chrono::steady_clock::duration::zero(); });
    const auto ack = ingest(store, "agent-1", full_report(b), &m);
    CHECK_FALSE(nacked(ack)); // terminal ack, not an endless need_full loop
    CHECK(metric_count(m, "error", "budget_exceeded") == 1);
    CHECK(metric_count(m, "error", "store_error") == 0);
    CHECK(store.row_counts("agent-1")->agent_state == 0); // rolled back whole
    // The default budget scales with the report and is generous for a legitimate one.
    store.set_test_ingest_budget(nullptr);
    CertificateInventoryStore fresh{pool};
    CHECK_FALSE(nacked(ingest(fresh, "agent-1", full_report(b), &m)));
    CHECK(fresh.row_counts("agent-1")->cert_fact == 2);
}

TEST_CASE("CertificateInventoryStore: a child-only change (SAN set) is never skipped as unchanged",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.sans = {{"dns", "a"}};
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    c.sans = {{"dns", "a"}, {"dns", "b"}}; // facts identical, only the SAN children differ
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    CHECK(scalar(pool, "SELECT string_agg(value, ',' ORDER BY ord) FROM certificate_inventory_store.cert_san") ==
          "a,b");
    c.sans = {{"dns", "b"}};
    c.ekus = {"1.3.6.1.5.5.7.3.1"};
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {c})));
    CHECK(scalar(pool, "SELECT string_agg(value, ',' ORDER BY ord) FROM certificate_inventory_store.cert_san") == "b");
    CHECK(store.row_counts("agent-1")->cert_eku == 1);
}

TEST_CASE("cert path key: the key is md5(path) computed by Postgres, never by the application",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    const std::string path = "/etc/ssl/certs/\xC3\xA9.pem";
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", path}})})));
    CHECK(scalar(pool, "SELECT path_md5 = md5(path) FROM certificate_inventory_store.cert_location") ==
          "t");
    CHECK(scalar(pool, "SELECT path_md5 FROM certificate_inventory_store.cert_location") ==
          scalar(pool, "SELECT md5($1)", {path}));
}

TEST_CASE("cert ingest: a child-digest failure is an error, never an empty digest",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    store.set_test_child_hash([](std::string_view) { return std::string{}; }); // digest unavailable
    CHECK(nacked(ingest(store, "agent-1",
                        full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})), &m)));
    CHECK(metric_count(m, "error", "store_error") == 1);
    CHECK(store.row_counts("agent-1")->agent_state == 0); // nothing written
}

TEST_CASE("cert ingest: a budget overrun AFTER the facts phase is still budget_exceeded, rolled "
          "back, with no resend",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    Cert c = cert(1, {{"S", ""}});
    c.sans = {{"dns", "a"}};
    c.ekus = {"1.3.6.1.5.5.7.3.1"};
    const auto b = blob(store_rec("S", "ok"), {c});
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    store.set_test_ingest_budget([](std::size_t) { return std::chrono::milliseconds(800); });
    // The facts are written inside the budget, then time runs out before the children.
    store.set_test_hook_after_facts([] { std::this_thread::sleep_for(std::chrono::milliseconds(1200)); });
    const auto ack = ingest(store, "agent-1", full_report(b), &m);
    CHECK_FALSE(nacked(ack));
    CHECK(metric_count(m, "error", "budget_exceeded") == 1);
    CHECK(metric_count(m, "error", "store_error") == 0);
    CHECK(store.row_counts("agent-1")->agent_state == 0);
    CHECK(store.row_counts("agent-1")->cert_fact == 0); // the facts were rolled back too
}

TEST_CASE("cert ingest: two different paths folded by the md5 key are one row, not an error",
          "[certinv][pg]") {
    CERT_SHARED(store, pool);
    // Same (store, sha256) with two distinct paths is two rows; identical paths are one.
    ingest(store, "agent-1",
           full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", "/a"}, {"S", "/b"}, {"S", "/a"}})})));
    CHECK(store.row_counts("agent-1")->cert_location == 2);
}

TEST_CASE("CertificateInventoryStore: delete_agent gives up on a held lock and is counted",
          "[certinv][pg][decommission]") {
    CERT_SHARED(store, pool);
    yuzu::MetricsRegistry m;
    store.set_metrics(&m);
    ingest(store, "agent-1", full_report(blob(store_rec("S", "ok"), {cert(1, {{"S", ""}})})));
    HeldAgentLock held(pool, "agent-1");
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_FALSE(store.delete_agent("agent-1")); // lock_timeout, not an unbounded wait
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(9));
    CHECK(m.serialize().find("yuzu_server_cert_inventory_delete_failed_total 1") != std::string::npos);
}

TEST_CASE("cert ingest: an exception at a call site follows the leg rule (full resends, hash-only "
          "does not), and is counted",
          "[certinv][parse]") {
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    agentpb::InventoryAck full_ack, hash_ack;
    cert_ingest_metric::handle_exception(full_report("ver|1\n"), full_ack, &m);
    cert_ingest_metric::handle_exception(hash_only(std::string(64, 'a')), hash_ack, &m);
    CHECK(nacked(full_ack));
    CHECK_FALSE(nacked(hash_ack));
    CHECK(metric_count(m, "error", "exception") == 2);
}

TEST_CASE("CertificateInventoryStore: every agent gets a server-assigned random sample_key at first "
          "ingest, stable and copied onto its facts",
          "[certinv][pg][samplekey]") {
    CERT_SHARED(store, pool);
    // Agent ids in ascending order: the keys must not follow it.
    std::vector<std::string> agents;
    for (int i = 0; i < 16; ++i)
        agents.push_back("agent-" + std::to_string(i));
    for (const auto& a : agents)
        ingest(store, a, full_report(blob(store_rec("S", "ok", "", "2"), {cert(1, {{"S", ""}}), cert(2, {{"S", ""}})})));

    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.agent_state WHERE sample_key IS NULL") == "0");
    CHECK(scalar(pool, "SELECT count(DISTINCT sample_key) FROM certificate_inventory_store.agent_state") == "16");
    // Every fact row carries its own agent's key.
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact f JOIN "
                       "certificate_inventory_store.agent_state a USING (agent_id) "
                       "WHERE f.sample_key IS DISTINCT FROM a.sample_key") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact") == "32");
    // Not monotone in agent_id (16 random keys ascending by chance is 1 in 16!).
    CHECK(scalar(pool, "SELECT (array_agg(sample_key ORDER BY agent_id) = "
                       "array_agg(sample_key ORDER BY sample_key))::text FROM "
                       "certificate_inventory_store.agent_state") == "false");

    // Stable across a changed full report and a re-report.
    const auto before = scalar(pool, "SELECT string_agg(sample_key::text, ',' ORDER BY agent_id) FROM "
                                     "certificate_inventory_store.agent_state");
    for (const auto& a : agents)
        ingest(store, a, full_report(blob(store_rec("S", "ok", "", "1"), {cert(3, {{"S", ""}})})));
    CHECK(scalar(pool, "SELECT string_agg(sample_key::text, ',' ORDER BY agent_id) FROM "
                       "certificate_inventory_store.agent_state") == before);
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact f JOIN "
                       "certificate_inventory_store.agent_state a USING (agent_id) "
                       "WHERE f.sample_key IS DISTINCT FROM a.sample_key") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact") == "16");

    // A hash-skip report leaves every key unchanged.
    const auto b = blob(store_rec("S", "ok", "", "1"), {cert(3, {{"S", ""}})});
    yuzu::MetricsRegistry m;
    cert_ingest_metric::register_metrics(m);
    for (const auto& a : agents) {
        // Each was last fully reported with exactly this blob, so the claim matches: a touch.
        CHECK_FALSE(nacked(ingest(store, a, hash_only(raw_hash(b)), &m)));
    }
    CHECK(metric_count(m, "touched", "none") == 16);
    CHECK(metric_count(m, "need_full", "hash_mismatch") == 0);
    CHECK(scalar(pool, "SELECT string_agg(sample_key::text, ',' ORDER BY agent_id) FROM "
                       "certificate_inventory_store.agent_state") == before);
}

TEST_CASE("CertificateInventoryStore: a CSPRNG failure fails the first ingest and stores nothing",
          "[certinv][pg][samplekey]") {
    CERT_SHARED(store, pool);
    // Whatever happens, the thread-local force flag never outlives this test.
    struct ClearForced {
        ~ClearForced() {
            if (test_hooks::is_failure_forced_for_this_thread())
                (void)random_hex(1); // consumes (and so clears) the pending forced failure
        }
    } clear_forced;
    const auto rpt = full_report(blob(store_rec("S", "ok", "", "1"), {cert(1, {{"S", ""}})}));
    test_hooks::force_next_failure_for_this_thread();
    const auto ack = ingest(store, "agent-e", rpt);
    CHECK_FALSE(test_hooks::is_failure_forced_for_this_thread()); // the ingest drew, and consumed it
    CHECK(nacked(ack));
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.agent_state") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.cert_fact") == "0");
    // The retry (entropy back) stores it with a key.
    CHECK_FALSE(nacked(ingest(store, "agent-e", rpt)));
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.agent_state WHERE sample_key IS NOT NULL") == "1");
}

TEST_CASE("CertificateInventoryStore: sample_key is NOT NULL on both tables and indexed for the sample",
          "[certinv][pg][samplekey]") {
    CERT_SHARED(store, pool);
    CHECK(scalar(pool, "SELECT string_agg(table_name || ':' || is_nullable, ',' ORDER BY table_name) FROM "
                       "information_schema.columns WHERE table_schema = 'certificate_inventory_store' "
                       "AND column_name = 'sample_key'") == "agent_state:NO,cert_fact:NO");
    CHECK(scalar(pool, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'certificate_inventory_store' "
                       "AND indexname = 'cert_fact_sample_idx'")
              .find("(sha256, sample_key, agent_id)") != std::string::npos);
}

// ── Store: the read half (slice-2 PR 2a-2b) ──────────────────────────────────

namespace {

CertFactRow rfact(int id) {
    CertFactRow f;
    f.sha256 = hexn(id);
    f.subject_dn = "CN=host" + std::to_string(id) + ".example";
    f.issuer_dn = "CN=Test CA";
    f.not_before = "2020-01-01T00:00:00Z";
    f.not_after = "2030-01-01T00:00:00Z";
    f.key_alg_oid = "1.2.840.113549.1.1.1";
    f.rsa_modulus_bits = 2048;
    f.sig_alg_oid = "1.2.840.113549.1.1.11";
    f.spki_sha256 = hexn(500 + id);
    f.ski = "AABB";
    f.aki_key_id = "CCDD";
    f.is_ca = false;
    f.self_signed = false;
    f.key_usage = "Digital Signature, Key Encipherment";
    return f;
}

// One report for `agent`: every fact placed in `store` (status ok unless given).
void put_report(CertificateInventoryStore& st, const std::string& agent,
                std::vector<CertFactRow> facts, const std::string& store_id = "LocalMachine\\Root",
                const std::string& status = "ok", const std::string& blob_version = "1") {
    CertReportData d;
    d.blob_version = blob_version;
    d.stores.push_back({store_id, "machine", status, ""});
    for (const auto& f : facts)
        d.locations.push_back({store_id, "", f.sha256});
    d.facts = std::move(facts);
    REQUIRE(st.ingest_full(agent, d, "hash-" + agent).outcome == CertIngestOutcome::kStored);
}

std::vector<std::string> shas(const CertPage& p) {
    std::vector<std::string> o;
    for (const auto& r : p.rows)
        o.push_back(r.sha256);
    return o;
}

std::vector<std::string> ids_of(std::initializer_list<int> ns) {
    std::vector<std::string> o;
    for (const int n : ns)
        o.push_back(hexn(n));
    return o;
}

CertPage must_list(CertificateInventoryStore& st, const CertReadFilter& f = {},
                   const CertScopeIds& scope = std::nullopt, int limit = 100,
                   const std::optional<CertReadAfter>& after = std::nullopt) {
    auto r = st.list_certificates(f, scope, after, limit);
    REQUIRE(r.has_value());
    return std::move(*r);
}

} // namespace

TEST_CASE("CertificateInventoryStore reads: a page carries facts, children, locations and store status",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    CertReportData d;
    d.blob_version = "1";
    d.stores = {{"LocalMachine\\Root", "machine", "ok", ""},
                {"LocalMachine\\My", "machine", "constrained", "row_cap"}};
    auto f = rfact(1);
    f.sans = {{"dns", "a.example"}, {"rfc822", "p@example.org"}};
    f.ekus = {"1.3.6.1.5.5.7.3.1"};
    f.constrained_fields = "utf8_replaced:subject_dn";
    d.facts = {f};
    d.locations = {{"LocalMachine\\Root", "", f.sha256}, {"LocalMachine\\My", "", f.sha256}};
    REQUIRE(store.ingest_full("agent-1", d, "h").outcome == CertIngestOutcome::kStored);

    const auto p = must_list(store);
    REQUIRE(p.rows.size() == 1);
    const auto& r = p.rows[0];
    CHECK(r.agent_id == "agent-1");
    CHECK(r.sha256 == hexn(1));
    CHECK(*r.subject_dn == "CN=host1.example");
    CHECK(*r.not_after == "2030-01-01T00:00:00Z");
    CHECK(*r.rsa_modulus_bits == 2048);
    CHECK(*r.aki_key_id == "CCDD");
    CHECK(*r.is_ca == false);
    CHECK(r.constrained_fields == "utf8_replaced:subject_dn");
    REQUIRE(r.sans.size() == 2);
    CHECK(r.sans[1].value == "p@example.org");
    CHECK(r.ekus == std::vector<std::string>{"1.3.6.1.5.5.7.3.1"});
    REQUIRE(r.locations.size() == 2);
    CHECK(r.locations[0].store_id == "LocalMachine\\My"); // ordered by store_id
    CHECK(r.locations[0].store_status == "constrained");
    CHECK(r.locations[1].store_status == "ok");
    CHECK(r.locations[1].observed_at.has_value());
    CHECK_FALSE(r.last_seen.empty());
    REQUIRE(p.stores.size() == 2); // every store of the device, so a kept row shows its status
    CHECK(p.blob_versions == std::vector<std::string>{"1"});
    CHECK(p.coverage.devices_reporting == 1);
    CHECK(p.coverage.devices_included == 1);
    CHECK_FALSE(p.coverage.confined);
    CHECK_FALSE(p.has_more);
}

TEST_CASE("CertificateInventoryStore reads: every filter selects exactly its row",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    std::vector<CertFactRow> a;
    a.push_back(rfact(1));
    {
        auto f = rfact(2);
        f.key_alg_oid = "1.2.840.10045.2.1";
        f.rsa_modulus_bits.reset();
        f.ec_curve_oid = "1.2.840.10045.3.1.7";
        f.ec_order_bits = 256;
        f.sig_alg_oid = "1.2.840.10045.4.3.2";
        f.not_after = "2021-06-01T00:00:00Z";
        f.is_ca = true;
        f.self_signed = true;
        f.subject_dn = "CN=Test CA";
        f.issuer_dn = "CN=Test CA";
        f.aki_key_id = "EEFF";
        a.push_back(f);
    }
    {
        auto f = rfact(3);
        f.rsa_modulus_bits = 1024;
        f.not_before = "2024-03-01T00:00:00Z";
        f.issuer_dn = "O=Other";
        a.push_back(f);
    }
    put_report(store, "agent-1", a);
    put_report(store, "agent-2", {rfact(4)}, "/etc/ssl/certs");

    const auto only = [&](const CertReadFilter& f, std::initializer_list<int> want) {
        INFO("filter " << want.size());
        CHECK(shas(must_list(store, f)) == ids_of(want));
    };
    CertReadFilter f;
    f = {}; f.store = "/etc/ssl/certs"; only(f, {4});
    f = {}; f.scope = "machine"; only(f, {1, 2, 3, 4});
    f = {}; f.key_alg_oid = "1.2.840.10045.2.1"; only(f, {2});
    f = {}; f.sig_alg_oid = "1.2.840.10045.4.3.2"; only(f, {2});
    f = {}; f.ec_curve_oid = "1.2.840.10045.3.1.7"; only(f, {2});
    f = {}; f.not_after_before = "2022-01-01T00:00:00Z"; only(f, {2});
    f = {}; f.not_after_after = "2029-12-31T23:59:59Z"; only(f, {1, 3, 4});
    f = {}; f.not_before_after = "2023-01-01T00:00:00Z"; only(f, {3});
    f = {}; f.rsa_modulus_bits_lt = 2048; only(f, {3});
    f = {}; f.ec_order_bits_lt = 384; only(f, {2});
    f = {}; f.is_ca = true; only(f, {2});
    f = {}; f.self_signed = true; only(f, {2});
    f = {}; f.agent_id = "agent-2"; only(f, {4});
    f = {}; f.issuer_dn = "O=Other"; only(f, {3});
    f = {}; f.sha256 = hexn(3); only(f, {3});
    f = {}; f.spki_sha256 = hexn(504); only(f, {4});
    f = {}; f.aki_key_id = "EEFF"; only(f, {2});
    // Strict boundaries: the instant itself is not "before" nor "after".
    f = {}; f.not_after_before = "2021-06-01T00:00:00Z"; only(f, {});
    f = {}; f.not_after_after = "2021-06-01T00:00:00Z"; only(f, {1, 3, 4});
    // A conjunction narrows.
    f = {}; f.key_alg_oid = "1.2.840.113549.1.1.1"; f.agent_id = "agent-1"; only(f, {1, 3});
}

TEST_CASE("CertificateInventoryStore reads: the one-CA substring filters are literal and CA-only",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    std::vector<CertFactRow> a;
    {
        auto f = rfact(1); // a CA certificate named in the CN
        f.is_ca = true;
        f.subject_dn = "CN=emSign Root CA,O=eMudhra Technologies Limited";
        f.issuer_dn = "CN=emSign Root CA,O=eMudhra Technologies Limited";
        a.push_back(f);
    }
    {
        auto f = rfact(2); // an end-entity certificate carrying the same words
        f.subject_dn = "CN=Jane Doe,O=eMudhra Technologies Limited";
        f.issuer_dn = "CN=emSign Issuing CA,O=eMudhra Technologies Limited";
        a.push_back(f);
    }
    {
        auto f = rfact(3);
        f.issuer_dn = "CN=100% Real CA";
        a.push_back(f);
    }
    {
        auto f = rfact(4);
        f.issuer_dn = "CN=1000 Other CA";
        a.push_back(f);
    }
    {
        auto f = rfact(5);
        f.issuer_dn = "CN=a_b CA";
        a.push_back(f);
    }
    {
        auto f = rfact(6);
        f.issuer_dn = "CN=axb CA";
        a.push_back(f);
    }
    {
        auto f = rfact(7);
        f.issuer_dn = "CN=back\\slash CA";
        a.push_back(f);
    }
    put_report(store, "agent-1", a);
    REQUIRE(store.run_dn_dictionary_maintenance()); // the background pass (leader) builds it

    CertReadFilter f;
    SECTION("issuer substring is case-insensitive and finds the CA under any of its names") {
        f.issuer_dn_contains = "EMUDHRA";
        CHECK(shas(must_list(store, f)) == ids_of({1, 2}));
        f.issuer_dn_contains = "emsign issuing";
        CHECK(shas(must_list(store, f)) == ids_of({2}));
    }
    SECTION("a percent sign is a literal, not a pattern") {
        f.issuer_dn_contains = "100%";
        CHECK(shas(must_list(store, f)) == ids_of({3})); // an unescaped % would also match 1000
    }
    SECTION("an underscore is a literal, not a one-character wildcard") {
        f.issuer_dn_contains = "a_b";
        CHECK(shas(must_list(store, f)) == ids_of({5})); // an unescaped _ would also match axb
    }
    SECTION("a backslash is a literal") {
        f.issuer_dn_contains = "back\\slash";
        CHECK(shas(must_list(store, f)) == ids_of({7}));
    }
    SECTION("the subject substring only ever reaches CA certificates") {
        f.subject_dn_contains = "emudhra";
        f.is_ca = true;
        CHECK(shas(must_list(store, f)) == ids_of({1})); // the end-entity row with the same words is not returned
    }
    SECTION("the store refuses a subject substring without is_ca=true, never searching people") {
        f.subject_dn_contains = "Jane";
        auto r = store.list_certificates(f, std::nullopt, std::nullopt, 10);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == CertReadError::Kind::kInvalid);
        f.is_ca = false;
        CHECK_FALSE(store.list_certificates(f, std::nullopt, std::nullopt, 10).has_value());
        CertSummaryQuery sq;
        sq.filter = f;
        CHECK_FALSE(store.summarize_certificates(sq, std::nullopt).has_value());
    }
}

TEST_CASE("CertificateInventoryStore reads: the visible set is pushed into the SQL; present-empty is deny-all",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    put_report(store, "agent-1", {rfact(1), rfact(2)});
    put_report(store, "agent-2", {rfact(3)});
    put_report(store, "agent-3", {rfact(4)});

    SECTION("unfiltered sees the fleet") {
        const auto p = must_list(store);
        CHECK(p.rows.size() == 4);
        CHECK(p.coverage.devices_reporting == 3);
    }
    SECTION("a confined set sees only its devices, and so does the denominator") {
        const auto p = must_list(store, {}, CertScopeIds{std::vector<std::string>{"agent-2", "agent-3"}});
        CHECK(shas(p) == ids_of({3, 4}));
        CHECK(p.coverage.devices_reporting == 2);
        CHECK(p.coverage.confined);
        // A filter naming a device outside the set reaches nothing.
        CertReadFilter f;
        f.agent_id = "agent-1";
        CHECK(must_list(store, f, CertScopeIds{std::vector<std::string>{"agent-2"}}).rows.empty());
    }
    SECTION("present-empty denies everything, with no error and a zero denominator") {
        const auto p = must_list(store, {}, CertScopeIds{std::vector<std::string>{}});
        CHECK(p.rows.empty());
        CHECK(p.coverage.devices_reporting == 0);
        CHECK(p.coverage.confined);
        CertSummaryQuery q;
        auto s = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{}});
        REQUIRE(s.has_value());
        CHECK(s->totals.certificate_count == 0);
        CHECK(s->coverage.confined);
    }
    SECTION("the summary totals are confined (every other figure: the dedicated test below)") {
        CertSummaryQuery q;
        auto s = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{"agent-1"}});
        REQUIRE(s.has_value());
        CHECK(s->totals.device_count == 1);
        CHECK(s->totals.certificate_count == 2);
    }
}

TEST_CASE("CertificateInventoryStore reads: keyset paging walks every row once", "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    put_report(store, "agent-1", {rfact(1), rfact(2), rfact(3)});
    put_report(store, "agent-2", {rfact(4), rfact(5)});
    std::vector<std::string> seen;
    std::optional<CertReadAfter> after;
    int pages = 0;
    for (;;) {
        const auto p = must_list(store, {}, std::nullopt, 2, after);
        ++pages;
        for (const auto& r : p.rows)
            seen.push_back(r.sha256);
        if (!p.has_more)
            break;
        after = CertReadAfter{p.rows.back().agent_id, p.rows.back().sha256};
        REQUIRE(pages < 10);
    }
    CHECK(pages == 3);
    CHECK(seen == ids_of({1, 2, 3, 4, 5}));
    CHECK_FALSE(store.list_certificates({}, std::nullopt, std::nullopt, 0).has_value());
    CHECK_FALSE(store.list_certificates({}, std::nullopt, std::nullopt, kCertPageMax + 1).has_value());
}

TEST_CASE("CertificateInventoryStore reads: the summary groups raw values and buckets the caller's edges",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    auto ec = rfact(3);
    ec.key_alg_oid = "1.2.840.10045.2.1";
    ec.rsa_modulus_bits.reset();
    ec.ec_curve_oid = "1.2.840.10045.3.1.7";
    ec.ec_order_bits = 256;
    ec.not_after = "2021-06-01T00:00:00Z";
    ec.subject_dn = "CN=Alice Person,E=alice@example.org";
    auto unk = rfact(4);
    unk.not_after.reset(); // no known validity end
    put_report(store, "agent-1", {rfact(1), rfact(2), ec});
    put_report(store, "agent-2", {rfact(1), unk}, "LocalMachine\\CA");
    put_report(store, "agent-3", {rfact(5)}, "LocalMachine\\My", "unreadable");

    CertSummaryQuery q;
    q.not_after_edges = {"2022-01-01T00:00:00Z", "2031-01-01T00:00:00Z"};
    auto r = store.summarize_certificates(q, std::nullopt);
    REQUIRE(r.has_value());
    const auto& s = *r;
    CHECK(s.totals.device_count == 2); // agent-3's unreadable store holds no row
    CHECK(s.totals.certificate_count == 4); // 1, 2, 3, 4
    REQUIRE(s.key_algorithms.size() == 2);
    CHECK(s.key_algorithms[0].key_alg_oid == "1.2.840.113549.1.1.1"); // most devices first
    CHECK(*s.key_algorithms[0].rsa_modulus_bits == 2048);
    CHECK(s.key_algorithms[0].counts.device_count == 2);
    CHECK(s.key_algorithms[0].counts.certificate_count == 3);
    REQUIRE(s.ec_curves.size() == 1);
    CHECK(s.ec_curves[0].ec_curve_oid == "1.2.840.10045.3.1.7");
    REQUIRE(s.issuers.size() == 1);
    CHECK(s.issuers[0].issuer_dn == "CN=Test CA");
    CHECK(s.stores.size() == 2);
    REQUIRE_FALSE(s.store_statuses.empty());
    bool saw_unreadable = false;
    for (const auto& g : s.store_statuses)
        if (g.status == "unreadable") {
            saw_unreadable = true;
            CHECK(g.device_count == 1);
        }
    CHECK(saw_unreadable);
    // Edges: [-inf,2022) -> {3}; [2022,2031) -> {1,2}; [2031,inf) -> {}; unknown -> {4}
    REQUIRE(s.not_after_histogram.size() == 4);
    CHECK(s.not_after_histogram[0].counts.certificate_count == 1);
    CHECK_FALSE(s.not_after_histogram[0].from.has_value());
    CHECK(s.not_after_histogram[1].counts.certificate_count == 2);
    CHECK(*s.not_after_histogram[1].from == "2022-01-01T00:00:00Z");
    CHECK(s.not_after_histogram[2].counts.certificate_count == 0);
    CHECK_FALSE(s.not_after_histogram[2].to.has_value());
    CHECK(s.not_after_histogram[3].unknown);
    CHECK(s.not_after_histogram[3].counts.certificate_count == 1);
    CHECK(s.coverage.devices_reporting == 3);
    // Subject DNs and SANs are never a group: no group carries the personal-data subject.
    for (const auto& g : s.issuers)
        CHECK(g.issuer_dn.find("Alice") == std::string::npos);

    SECTION("a filter narrows the rollup, and a histogram needs the caller's edges") {
        CertSummaryQuery f;
        f.filter.key_alg_oid = "1.2.840.10045.2.1";
        auto fr = store.summarize_certificates(f, std::nullopt);
        REQUIRE(fr.has_value());
        CHECK(fr->totals.certificate_count == 1);
        CHECK(fr->not_after_histogram.empty()); // no edges, no histogram
    }
}

TEST_CASE("CertificateInventoryStore reads: a store that is not open degrades, never answers empty",
          "[certinv][read]") {
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=yuzu_test_none",
                .size = 1}};
    CertificateInventoryStore store{bad};
    REQUIRE_FALSE(store.is_open());
    const auto l = store.list_certificates({}, std::nullopt, std::nullopt, 10);
    REQUIRE_FALSE(l.has_value());
    CHECK(l.error().kind == CertReadError::Kind::kNotOpen);
    CHECK_FALSE(store.summarize_certificates({}, std::nullopt).has_value());
    CHECK_FALSE(store.device_status_counts().has_value());
}

TEST_CASE("CertificateInventoryStore reads: device_status_counts is one row per device with the closed statuses",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    put_report(store, "agent-1", {rfact(1)}, "S1", "ok");
    put_report(store, "agent-2", {rfact(2)}, "S2", "constrained");
    auto c = store.device_status_counts();
    REQUIRE(c.has_value());
    REQUIRE(c->size() == 2);
    std::map<std::string, CertDeviceStatusCount> m;
    for (const auto& x : *c)
        m[x.agent_id] = x;
    CHECK(m["agent-1"].ok == 1);
    CHECK(m["agent-1"].constrained == 0);
    CHECK(m["agent-2"].constrained == 1);
    // A wall budget of nothing fails the read (a degrade), never a partial rollup.
    auto none = store.device_status_counts(std::chrono::milliseconds{3000}, std::chrono::milliseconds{0});
    CHECK_FALSE(none.has_value());
}

TEST_CASE("cert read model: the fleet gauge fold buckets by OS, bounds its labels and omits zeros",
          "[certread][model][gauge]") {
    using namespace yuzu::server;
    const std::vector<CertDeviceStatusCount> rows = {
        {"w1", 2, 0, 1, 0, 0}, {"l1", 1, 0, 0, 3, 0}, {"m1", 0, 1, 0, 0, 0},
        {"x1", 1, 0, 0, 0, 0}, {"gone", 0, 0, 0, 0, 4}, {"w2", 1, 0, 0, 0, 0}};
    const std::unordered_map<std::string, std::string> os = {
        {"w1", "windows"}, {"w2", "windows"}, {"l1", "linux"}, {"m1", "darwin"}, {"x1", "freebsd"}};
    const auto f = cert_read::fold_fleet_status(rows, os);
    using K = std::pair<std::string, std::string>;
    CHECK(f.at(K{"windows", "ok"}) == 3);
    CHECK(f.at(K{"windows", "unreadable"}) == 1);
    CHECK(f.at(K{"linux", "constrained"}) == 3);
    CHECK(f.at(K{"darwin", "absent"}) == 1);
    CHECK(f.at(K{"other", "ok"}) == 1);               // an OS outside the three is "other"
    CHECK(f.at(K{"unknown", "not_observed"}) == 4);   // not in the registry snapshot
    CHECK_FALSE(f.contains(K{"windows", "absent"}));  // zero counts are omitted
    for (const auto& [k, n] : f) {
        (void)n;
        CHECK((k.second == "ok" || k.second == "absent" || k.second == "unreadable" ||
               k.second == "constrained" || k.second == "not_observed"));
    }
    CHECK(cert_read::fold_fleet_status({}, {}).empty());
}

TEST_CASE("CertificateInventoryStore reads: EVERY summary figure is confined, foreign values never appear",
          "[certinv][pg][read][confinement]") {
    CERT_SHARED(store, pool);
    // Mine: one ok store, blob version 1, an RSA certificate under "CN=Mine CA".
    auto mine = rfact(1);
    mine.issuer_dn = "CN=Mine CA";
    put_report(store, "mine", {mine}, "MineStore", "ok", "1");
    // Foreign: every dimension differs - status, blob version, store, key algorithm, curve, issuer.
    auto foreign = rfact(2);
    foreign.issuer_dn = "CN=Foreign CA";
    foreign.key_alg_oid = "1.2.840.10045.2.1";
    foreign.rsa_modulus_bits.reset();
    foreign.ec_curve_oid = "1.2.840.10045.3.1.7";
    foreign.ec_order_bits = 256;
    foreign.sig_alg_oid = "1.2.840.10045.4.3.2";
    CertReportData d;
    d.blob_version = "2";
    d.stores = {{"ForeignStore", "machine", "unreadable", "permission_denied"},
                {"ForeignOk", "machine", "ok", ""}};
    d.facts = {foreign};
    d.locations = {{"ForeignOk", "", foreign.sha256}};
    REQUIRE(store.ingest_full("foreign", d, "h-f").outcome == CertIngestOutcome::kStored);

    CertSummaryQuery q;
    q.not_after_edges = {"2025-01-01T00:00:00Z"};
    const auto no_foreign = [&](const CertSummary& s) {
        CHECK(s.totals.device_count == 0);
        for (const auto& g : s.issuers)
            CHECK(g.issuer_dn != "CN=Foreign CA");
        for (const auto& g : s.stores)
            CHECK(g.store_id.rfind("Foreign", 0) != 0);
        for (const auto& g : s.key_algorithms)
            CHECK(g.key_alg_oid != "1.2.840.10045.2.1");
        CHECK(s.ec_curves.empty());
        for (const auto& g : s.store_statuses)
            CHECK(g.status != "unreadable"); // only the foreign device has an unreadable store
        for (const auto& v : s.blob_versions)
            CHECK(v != "2");
    };
    SECTION("a confined set sees only its own figures, in every dimension") {
        auto r = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{"mine"}});
        REQUIRE(r.has_value());
        CHECK(r->totals.device_count == 1);
        CHECK(r->totals.certificate_count == 1);
        CHECK(r->coverage.devices_reporting == 1);
        CHECK(r->blob_versions == std::vector<std::string>{"1"});
        REQUIRE(r->store_statuses.size() == 1);
        CHECK(r->store_statuses[0].status == "ok");
        CHECK(r->store_statuses[0].store_count == 1);
        REQUIRE(r->issuers.size() == 1);
        CHECK(r->issuers[0].issuer_dn == "CN=Mine CA");
        CHECK(r->ec_curves.empty());
        REQUIRE(r->stores.size() == 1);
        CHECK(r->stores[0].store_id == "MineStore");
        // the unfiltered view does see the foreign values (the assertions above are not vacuous)
        auto all = store.summarize_certificates(q, std::nullopt);
        REQUIRE(all.has_value());
        CHECK(all->coverage.devices_reporting == 2);
        CHECK(all->blob_versions.size() == 2);
        CHECK(all->store_statuses.size() >= 2);
    }
    SECTION("present-empty is deny-all in every dimension, and runs no SQL") {
        auto r = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{}});
        REQUIRE(r.has_value());
        no_foreign(*r);
        CHECK(r->totals.certificate_count == 0);
        CHECK(r->coverage.devices_reporting == 0);
        CHECK(r->coverage.confined);
        CHECK(r->blob_versions.empty());
        CHECK(r->store_statuses.empty());
        CHECK(r->issuers.empty());
        CHECK(r->stores.empty());
        CHECK(r->key_algorithms.empty());
        REQUIRE(r->not_after_histogram.size() == 3); // the caller's edges still frame the (empty) buckets
        for (const auto& b : r->not_after_histogram)
            CHECK(b.counts.certificate_count == 0);
    }
    SECTION("a set naming only foreign-free devices sees nothing foreign") {
        auto r = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{"nobody"}});
        REQUIRE(r.has_value());
        no_foreign(*r);
        CHECK(r->coverage.devices_reporting == 0);
    }
}

TEST_CASE("CertificateInventoryStore reads: a SQL fault is a degrade on every read, never empty",
          "[certinv][pg][read]") {
    // Its OWN database: the schema is dropped, which the shared fixture must never see.
    YUZU_REQUIRE_PG_DB_TPL(db, certinv_tpl);
    PgPool own{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(own.valid());
    CertificateInventoryStore store{own};
    REQUIRE(store.is_open());
    put_report(store, "agent-1", {rfact(1)});
    {
        auto lease = own.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "DROP SCHEMA certificate_inventory_store CASCADE",
                                std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    const auto l = store.list_certificates({}, std::nullopt, std::nullopt, 10);
    REQUIRE_FALSE(l.has_value());
    CHECK(l.error().kind == CertReadError::Kind::kQueryError);
    const auto s = store.summarize_certificates({}, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CertReadError::Kind::kQueryError);
    CHECK_FALSE(store.device_status_counts().has_value());
    // deny-all still answers with no SQL
    CHECK(store.list_certificates({}, CertScopeIds{std::vector<std::string>{}}, std::nullopt, 10)
              .has_value());
}

// ── The distinct-DN dictionary behind the substring filters ───────────────────────────────────

namespace {
CertFactRow dn_fact(int id, const std::string& issuer, const std::string& subject, bool ca) {
    auto f = rfact(id);
    f.issuer_dn = issuer;
    f.subject_dn = subject;
    f.is_ca = ca;
    return f;
}
std::string dict_state(PgPool& pool) {
    return scalar(pool, "SELECT obj_description('certificate_inventory_store.dn_dict'::regclass, 'pg_class')");
}
} // namespace

TEST_CASE("CertificateInventoryStore: ingest maintains the DN dictionary and the filters resolve through it",
          "[certinv][pg][read][dict]") {
    CERT_SHARED(store, pool);
    // The build is a background pass: not ready until it has run after this store opened.
    CHECK_FALSE(store.substring_index_available());
    REQUIRE(store.run_dn_dictionary_maintenance());
    REQUIRE(store.substring_index_available());
    CHECK_THAT(dict_state(pool), Catch::Matchers::StartsWith("ready:"));
    put_report(store, "a1",
               {dn_fact(1, "CN=emSign Root,O=eMudhra", "CN=emSign Root,O=eMudhra", true),
                dn_fact(2, "CN=emSign Root,O=eMudhra", "CN=Jane Doe", false),
                dn_fact(3, "CN=100% Real CA", "CN=h3", false)});
    put_report(store, "a2", {dn_fact(4, "CN=emSign Root,O=eMudhra", "CN=h4", false)});
    // Distinct DNs only: the shared issuer is ONE dictionary row, flagged issuer; the CA's subject
    // equals its issuer so the same row also carries the CA-subject role; "Jane Doe" (an end-entity
    // subject) is never in the dictionary at all.
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict") == "2");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn = "
                       "'CN=emSign Root,O=eMudhra' AND is_issuer AND is_ca_subject") == "1");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn LIKE '%Jane%'") == "0");
    // A re-report of unchanged facts writes nothing to the dictionary (xmin does not move).
    const auto xmin = scalar(pool, "SELECT xmin::text FROM certificate_inventory_store.dn_dict WHERE "
                                   "dn = 'CN=emSign Root,O=eMudhra'");
    put_report(store, "a1",
               {dn_fact(1, "CN=emSign Root,O=eMudhra", "CN=emSign Root,O=eMudhra", true),
                dn_fact(2, "CN=emSign Root,O=eMudhra", "CN=Jane Doe", false),
                dn_fact(3, "CN=100% Real CA", "CN=h3", false)});
    CHECK(scalar(pool, "SELECT xmin::text FROM certificate_inventory_store.dn_dict WHERE "
                       "dn = 'CN=emSign Root,O=eMudhra'") == xmin);

    CertReadFilter f;
    f.issuer_dn_contains = "EMUDHRA";
    CHECK(shas(must_list(store, f)) == ids_of({1, 2, 4}));
    f = {};
    f.issuer_dn_contains = "100%";
    CHECK(shas(must_list(store, f)) == ids_of({3}));
    f = {};
    f.is_ca = true;
    f.subject_dn_contains = "emsign";
    CHECK(shas(must_list(store, f)) == ids_of({1}));
    f.subject_dn_contains = "jane"; // an end-entity subject is not searchable
    CHECK(must_list(store, f).rows.empty());
    f = {};
    f.issuer_dn_contains = "no-such-ca";
    CHECK(must_list(store, f).rows.empty());
    // The summary resolves the same way.
    CertSummaryQuery q;
    q.filter.issuer_dn_contains = "emudhra";
    auto sum = store.summarize_certificates(q, std::nullopt);
    REQUIRE(sum.has_value());
    CHECK(sum->totals.certificate_count == 3);
    // The exact filters now ride the same btree indexes.
    CHECK(scalar(pool, "SELECT count(*) FROM pg_indexes WHERE schemaname = 'certificate_inventory_store' "
                       "AND indexname IN ('cert_fact_issuer_dn_idx', 'cert_fact_subject_ca_dn_idx')") == "2");
}

TEST_CASE("CertificateInventoryStore: the background pass backfills an existing store (migration v2 only creates the table)",
          "[certinv][pg][read][dict]") {
    YUZU_REQUIRE_PG_DB(db); // fresh: this test runs the migrations itself
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        // A store frozen at v1 (the 2a-2a schema) that already holds facts.
        auto lease = pool.acquire();
        REQUIRE(lease);
        const auto& all = certificate_inventory_migrations();
        REQUIRE(pg::PgMigrationRunner::run(lease.get(), "certificate_inventory_store",
                                           std::vector<pg::PgMigration>{all[0]}));
        const auto exec = [&](const char* sql) {
            REQUIRE(pg::exec_params(lease.get(), sql, std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
        };
        exec("INSERT INTO certificate_inventory_store.agent_state (agent_id, content_hash, blob_version, "
             "first_seen, last_seen, last_full_at, sample_key) VALUES ('a1','h','1',now(),now(),now(),7)");
        exec("INSERT INTO certificate_inventory_store.cert_fact (agent_id, sha256, issuer_dn, subject_dn, is_ca, sample_key) VALUES "
             "('a1','" "0000000000000000000000000000000000000000000000000000000000000001" "','CN=Old CA','CN=Old CA',true,7),"
             "('a1','" "0000000000000000000000000000000000000000000000000000000000000002" "','CN=Old CA','CN=leaf',false,7)");
    }
    CertificateInventoryStore store{pool}; // runs v2: an EMPTY table, nothing built, boot immediate
    REQUIRE(store.is_open());
    CHECK_FALSE(store.substring_index_available());
    CHECK(dict_state(pool) == "building");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict") == "0");
    CHECK(scalar(pool, "SELECT count(*) FROM pg_indexes WHERE schemaname = 'certificate_inventory_store' AND "
                       "indexname LIKE 'cert_fact_%dn_idx'") == "0");
    REQUIRE(store.run_dn_dictionary_maintenance()); // the leader's background pass
    CHECK(store.substring_index_available());
    CHECK_THAT(dict_state(pool), Catch::Matchers::StartsWith("ready:"));
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn = 'CN=Old CA' "
                       "AND is_issuer AND is_ca_subject") == "1");
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict") == "1");
    CertReadFilter f;
    f.issuer_dn_contains = "old ca";
    CHECK(shas(must_list(store, f)) == ids_of({1, 2}));
}

TEST_CASE("CertificateInventoryStore: a failed dictionary build never fails boot and refuses the filters, "
          "with the real error recorded",
          "[certinv][pg][read][dict]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        REQUIRE(pg::PgMigrationRunner::run(lease.get(), "certificate_inventory_store",
                                           std::vector<pg::PgMigration>{certificate_inventory_migrations()[0]}));
        const auto exec = [&](const std::string& sql) {
            REQUIRE(pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
        };
        exec("INSERT INTO certificate_inventory_store.agent_state (agent_id, content_hash, "
             "blob_version, first_seen, last_seen, last_full_at, sample_key) VALUES ('a1','h','1',now(),now(),now(),7)");
        // A DN far past the btree entry limit: the CREATE INDEX inside the protected unit fails.
        exec("INSERT INTO certificate_inventory_store.cert_fact (agent_id, sha256, issuer_dn, sample_key) VALUES ('a1','" +
             std::string(63, '0') + "1', (SELECT string_agg(md5(i::text), '') FROM generate_series(1, 400) i), 7)");
    }
    CertificateInventoryStore store{pool};
    REQUIRE(store.is_open()); // boot is NOT refused (and builds nothing)
    CHECK_FALSE(store.run_dn_dictionary_maintenance()); // the CONCURRENTLY build fails: real error
    CHECK_FALSE(store.substring_index_available());
    CHECK_THAT(dict_state(pool), Catch::Matchers::StartsWith("failed: "));
    CHECK_THAT(dict_state(pool), Catch::Matchers::ContainsSubstring("index row requires"));
    // A failed CONCURRENTLY build leaves an INVALID index behind; the retry must drop and rebuild it.
    CHECK(scalar(pool, "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE "
                       "c.relname = 'cert_fact_issuer_dn_idx' AND NOT i.indisvalid") == "1");
    // The migration did not roll back the rest: the dictionary table exists, ingest keeps filling it.
    put_report(store, "a2", {dn_fact(7, "CN=New CA", "CN=h7", false)});
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn = 'CN=New CA'") == "1");
    // Substring filters are refused, non-retryable; every other filter still answers.
    CertReadFilter f;
    f.issuer_dn_contains = "new ca";
    auto r = store.list_certificates(f, std::nullopt, std::nullopt, 10);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == CertReadError::Kind::kSubstringIndexMissing);
    CertSummaryQuery q;
    q.filter = f;
    auto s = store.summarize_certificates(q, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CertReadError::Kind::kSubstringIndexMissing);
    CertReadFilter exact;
    exact.issuer_dn = "CN=New CA";
    CHECK(store.list_certificates(exact, std::nullopt, std::nullopt, 10).has_value());
    // The repair is the same background pass: remove the offender, run it again; it drops the
    // INVALID leftover, rebuilds, reconciles and marks ready.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(), "TRUNCATE certificate_inventory_store.agent_state CASCADE",
                                std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
    }
    REQUIRE(store.run_dn_dictionary_maintenance());
    CHECK(store.substring_index_available());
    put_report(store, "a2", {dn_fact(7, "CN=New CA", "CN=h7", false)});
    CHECK(shas(must_list(store, f)) == ids_of({7}));
    // A DIFFERENT process (a fresh store object, started later) is not ready until a reconcile
    // completes after ITS start - the rollback / re-upgrade guard.
    CertificateInventoryStore later{pool};
    CHECK_FALSE(later.substring_index_available());
    REQUIRE(later.run_dn_dictionary_maintenance());
    CHECK(later.substring_index_available());
}

TEST_CASE("CertificateInventoryStore: a read past its wall budget is classified by SQLSTATE/deadline, "
          "and a summary's is a non-retryable scale limit",
          "[certinv][pg][read]") {
    CERT_SHARED(store, pool);
    put_report(store, "a1", {rfact(1)});
    store.set_read_budget_for_test(std::chrono::milliseconds{0});
    const auto l = store.list_certificates({}, std::nullopt, std::nullopt, 10);
    REQUIRE_FALSE(l.has_value());
    CHECK(l.error().kind == CertReadError::Kind::kQueryError); // a page: a retryable degrade
    CHECK(l.error().timed_out);
    const auto s = store.summarize_certificates({}, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CertReadError::Kind::kScaleLimit);  // a summary: do not retry
    CHECK(s.error().timed_out);
    // A real server-side cancel carries SQLSTATE 57014, whatever lc_messages says.
    store.set_read_budget_for_test(std::chrono::milliseconds{15000});
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::exec_params(lease.get(), "SET lc_messages = 'C'", std::vector<std::string>{});
    }
    store.set_read_budget_for_test(std::chrono::milliseconds{1});
    // 1 ms is long enough to send the statement; pg_sleep inside a filter-free page is not
    // injectable, so this case asserts only that SOME timeout shape is flagged, not which.
    const auto t = store.list_certificates({}, std::nullopt, std::nullopt, 10);
    if (!t.has_value())
        CHECK(t.error().timed_out);
}

TEST_CASE("cert parse: the legacy key_usage display sentinels never become a fact",
          "[certinv][parse]") {
    const auto key_usage_of = [](const std::string& ku) {
        Cert c = cert(1, {{"S", ""}});
        c.key_usage = ku;
        const auto p = parse_certificate_inventory_blob(blob(store_rec("S", "ok"), {c}));
        REQUIRE(p.data.facts.size() == 1);
        return p.data.facts[0].key_usage;
    };
    CHECK_FALSE(key_usage_of("(none)").has_value());                  // also means "extraction failed": UNKNOWN
    CHECK_FALSE(key_usage_of("(unknown)").has_value());               // unparsable: UNKNOWN
    CHECK(key_usage_of("") == std::optional<std::string>{""});        // what the 2a-2e writer sends
    CHECK(key_usage_of("Digital Signature") == std::optional<std::string>{"Digital Signature"});
    CHECK(key_usage_of("(none), Digital Signature") ==
          std::optional<std::string>{"(none), Digital Signature"});   // only the whole-field sentinel
}

TEST_CASE("CertificateInventoryStore reads: a substring matching more than 20,000 distinct names is refused as input",
          "[certinv][pg][read][dict]") {
    CERT_SHARED(store, pool);
    REQUIRE(store.run_dn_dictionary_maintenance());
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        REQUIRE(pg::exec_params(lease.get(),
                                "INSERT INTO certificate_inventory_store.dn_dict (dn, is_issuer) SELECT "
                                "'CN=bulk ' || i, true FROM generate_series(1, 20001) i",
                                std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
    }
    CertReadFilter f;
    f.issuer_dn_contains = "bulk";
    auto r = store.list_certificates(f, std::nullopt, std::nullopt, 10);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == CertReadError::Kind::kInvalid);
    CHECK_THAT(r.error().message, Catch::Matchers::ContainsSubstring("longer"));
    // A longer substring that matches few names answers normally.
    f.issuer_dn_contains = "bulk 20001";
    CHECK(store.list_certificates(f, std::nullopt, std::nullopt, 10).has_value());
}

TEST_CASE("CertificateInventoryStore reads: a substring filter never reaches a device outside the scope",
          "[certinv][pg][read][dict][confinement]") {
    CERT_SHARED(store, pool);
    // A and B share an issuer DN (the dictionary is fleet-wide and shared); B also has a private one.
    put_report(store, "A", {dn_fact(1, "CN=Shared CA,O=Org", "CN=a1", false)});
    put_report(store, "B", {dn_fact(2, "CN=Shared CA,O=Org", "CN=b2", false),
                            dn_fact(3, "CN=B Private CA", "CN=b3", false)});
    REQUIRE(store.run_dn_dictionary_maintenance());
    CertReadFilter f;
    f.issuer_dn_contains = "shared ca";
    // Unconfined: both. Scope = {A}: only A's certificate, B is ABSENT from rows, stores and coverage.
    CHECK(shas(must_list(store, f)) == ids_of({1, 2}));
    const auto p = must_list(store, f, CertScopeIds{std::vector<std::string>{"A"}});
    CHECK(shas(p) == ids_of({1}));
    CHECK(p.coverage.devices_reporting == 1);
    for (const auto& r : p.rows)
        CHECK(r.agent_id == "A");
    for (const auto& st : p.stores)
        CHECK(st.agent_id == "A");
    // A name only B holds resolves in the dictionary but reaches nothing for scope {A}.
    f.issuer_dn_contains = "private";
    CHECK(shas(must_list(store, f)) == ids_of({3}));
    CHECK(must_list(store, f, CertScopeIds{std::vector<std::string>{"A"}}).rows.empty());
    // The summary honours the same rule.
    CertSummaryQuery q;
    q.filter.issuer_dn_contains = "shared ca";
    auto s = store.summarize_certificates(q, CertScopeIds{std::vector<std::string>{"A"}});
    REQUIRE(s.has_value());
    CHECK(s->totals.device_count == 1);
    CHECK(s->totals.certificate_count == 1);
}

TEST_CASE("CertificateInventoryStore: concurrent multi-chunk reports sharing issuers never deadlock",
          "[certinv][pg][dict][chaos]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    (void)GENERATE(range(0, 25)); // run 25x: the deadlocks this guards against were intermittent
    constexpr int kThreads = 8, kRounds = 2, kFacts = 1100; // 3 chunks of kChunkRows (500) per report
    // Its OWN pool (>= one connection per thread): starving the shared 4-connection pool would turn
    // pool-acquire timeouts into a false failure unrelated to lock ordering.
    PgPool pool{{.conninfo = cert_shared().db.dsn(), .size = kThreads + 2}};
    REQUIRE(pool.valid());
    CertificateInventoryStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.run_dn_dictionary_maintenance());
    const auto deadlocks = [&] {
        return std::stoll(scalar(pool, "SELECT deadlocks FROM pg_stat_database WHERE datname = "
                                       "current_database()"));
    };
    std::this_thread::sleep_for(std::chrono::milliseconds{1500}); // stats flush is idle-driven
    const auto dl_before = deadlocks();
    std::atomic<int> failures{0}, stored{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t)
        ts.emplace_back([&, t] {
            for (int r = 0; r < kRounds; ++r) {
                std::vector<CertFactRow> facts;
                for (int i = 0; i < kFacts; ++i) {
                    auto f = rfact(t * 100000 + r * 2000 + i + 1);
                    // 90% share 60 roots (chunk membership differs per device), the rest are new.
                    // Rotating the order per thread makes the per-chunk DN sets disjoint between reports.
                    const int root = (i * (t + 3)) % 60;
                    f.issuer_dn = i % 10 == 0 ? "CN=Fresh " + std::to_string(t) + "-" + std::to_string(r) + "-" +
                                                    std::to_string(i)
                                              : "CN=Root " + std::to_string(root);
                    f.subject_dn = "CN=leaf " + std::to_string(f.sha256.size() + i);
                    f.is_ca = i % 7 == 0;
                    facts.push_back(f);
                }
                CertReportData d;
                d.blob_version = "1";
                d.stores.push_back({"S", "machine", "ok", ""});
                for (const auto& f : facts)
                    d.locations.push_back({"S", "", f.sha256});
                d.facts = std::move(facts);
                // At most kMaxConcurrentFull (4) long ingests run at once; the rest are deferred
                // (kBusy) by design (2a-2a), so retry the deferral as the agent's next cycle would.
                CertIngestResult res;
                for (int attempt = 0; attempt < 200; ++attempt) {
                    res = store.ingest_full("agent-" + std::to_string(t), d,
                                            "h" + std::to_string(t) + "-" + std::to_string(r));
                    if (res.outcome != CertIngestOutcome::kBusy)
                        break;
                    std::this_thread::sleep_for(std::chrono::milliseconds{50});
                }
                if (res.outcome == CertIngestOutcome::kStored)
                    ++stored;
                else
                    ++failures;
            }
        });
    for (auto& th : ts)
        th.join();
    // Assert ONLY on deadlocks (40P01) - the server's own counter, read after the idle stats flush.
    std::this_thread::sleep_for(std::chrono::milliseconds{1500});
    CHECK(deadlocks() == dl_before);
    // Contention is 4-way, not 8-way: 2a-2a caps concurrent full ingests at 4 and the loop above
    // retries the by-design kBusy deferral, so every report must end up stored.
    CHECK(failures.load() == 0);
    CHECK(stored.load() == kThreads * kRounds);
    // Every referenced name is in the dictionary exactly once, with its role flags.
    CHECK(scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn LIKE 'CN=Root %'") ==
          "60");
    CHECK(scalar(pool, "SELECT count(*) FROM (SELECT DISTINCT issuer_dn FROM certificate_inventory_store.cert_fact "
                       "EXCEPT SELECT dn FROM certificate_inventory_store.dn_dict) x") == "0");
}

TEST_CASE("CertificateInventoryStore: the dictionary does not outlive the facts (prune and decommission)",
          "[certinv][pg][dict]") {
    CERT_SHARED(store, pool);
    REQUIRE(store.run_dn_dictionary_maintenance());
    put_report(store, "A", {dn_fact(1, "CN=Only A", "CN=a1", false), dn_fact(2, "CN=Shared", "CN=a2", false)});
    put_report(store, "B", {dn_fact(3, "CN=Shared", "CN=b3", false)});
    const auto has = [&](const char* dn) {
        return scalar(pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn = $1", {dn}) == "1";
    };
    REQUIRE(has("CN=Only A"));
    REQUIRE(has("CN=Shared"));
    SECTION("decommission erases a name only that device referenced; a shared name stays") {
        REQUIRE(store.delete_agent("A"));
        CHECK_FALSE(has("CN=Only A"));
        CHECK(has("CN=Shared")); // B still holds it
        REQUIRE(store.delete_agent("B"));
        CHECK_FALSE(has("CN=Shared"));
    }
    SECTION("the background prune removes names nothing references (a fact removed other than by decommission)") {
        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            // What a store prune (PR 2a-2d) or a replace-away does: the fact goes, the name stays.
            REQUIRE(pg::exec_params(lease.get(),
                                    "DELETE FROM certificate_inventory_store.cert_fact WHERE sha256 = $1",
                                    std::vector<std::string>{hexn(1)}).status() == PGRES_COMMAND_OK);
        }
        CHECK(has("CN=Only A"));
        REQUIRE(store.prune_dn_dictionary());
        CHECK_FALSE(has("CN=Only A"));
        CHECK(has("CN=Shared"));
        // And a name that a certificate DOES reference is never pruned, nor is a flag-only role lost.
        CHECK(has("CN=Shared"));
    }
    SECTION("a name pruned in the instant an ingest referenced it is healed by the next reconcile") {
        {
            auto lease = pool.acquire();
            REQUIRE(lease);
            REQUIRE(pg::exec_params(lease.get(),
                                    "DELETE FROM certificate_inventory_store.dn_dict WHERE dn = 'CN=Shared'",
                                    std::vector<std::string>{}).status() == PGRES_COMMAND_OK);
        }
        CHECK_FALSE(has("CN=Shared"));
        REQUIRE(store.run_dn_dictionary_maintenance()); // the reconcile adds back what facts name
        CHECK(has("CN=Shared"));
    }
}

TEST_CASE("CertificateInventoryStore: a prune racing ingest never deletes a still-referenced name",
          "[certinv][pg][dict][chaos]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    PgPool pool{{.conninfo = cert_shared().db.dsn(), .size = 6}};
    REQUIRE(pool.valid());
    CertificateInventoryStore store{pool};
    REQUIRE(store.is_open());
    std::atomic<bool> done{false};
    std::atomic<int> pruned_runs{0};
    std::thread pruner([&] {
        while (!done.load()) {
            (void)store.prune_dn_dictionary();
            ++pruned_runs;
        }
    });
    int missing = 0;
    for (int round = 0; round < 150; ++round) {
        std::vector<CertFactRow> facts;
        for (int i = 0; i < 20; ++i) {
            auto f = dn_fact(round * 100 + i + 1, "CN=Race " + std::to_string(i % 8), "CN=race-leaf", false);
            facts.push_back(f);
        }
        CertReportData d;
        d.blob_version = "1";
        d.stores.push_back({"S", "machine", "ok", ""});
        for (const auto& f : facts)
            d.locations.push_back({"S", "", f.sha256});
        d.facts = std::move(facts);
        const auto res = store.ingest_full("race", d, "h" + std::to_string(round));
        if (res.outcome != CertIngestOutcome::kStored)
            continue;
        // NO reconcile in between: the ingest's own txn must have left every name present.
        if (scalar(pool, "SELECT count(*) FROM (SELECT DISTINCT issuer_dn FROM "
                         "certificate_inventory_store.cert_fact EXCEPT SELECT dn FROM "
                         "certificate_inventory_store.dn_dict) x") != "0")
            ++missing;
        // Drop the facts but keep the names, so the pruner has something to chew on next round.
        exec_ok(pool, "DELETE FROM certificate_inventory_store.cert_fact");
    }
    done = true;
    pruner.join();
    CHECK(missing == 0);
    CHECK(pruned_runs.load() > 0);
}

TEST_CASE("pg background build helper: a changed index spec is dropped and rebuilt; stop is typed",
          "[certinv][pg][dict]") {
    CERT_SHARED(store, pool);
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::BuildCancel cancel;
    const auto stamp = [&] {
        auto r = pg::exec_params(lease.get(),
                                 "SELECT obj_description('certificate_inventory_store.hlp_idx'::regclass, "
                                 "'pg_class')",
                                 std::vector<std::string>{});
        return r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 ? std::string(PQgetvalue(r.get(), 0, 0))
                                                                         : std::string("?");
    };
    pg::IndexSpec spec{"certificate_inventory_store", "hlp_idx", "cert_fact", "btree", "issuer_dn", ""};
    REQUIRE(pg::ensure_index_concurrently(lease.get(), spec, &cancel).ok);
    const auto first = stamp();
    CHECK(first == spec.spec_text());
    // Same name, DIFFERENT definition: never kept via IF NOT EXISTS - rebuilt to the new spec.
    spec.columns = "subject_dn";
    REQUIRE(pg::ensure_index_concurrently(lease.get(), spec, &cancel).ok);
    CHECK(stamp() == spec.spec_text());
    CHECK(stamp() != first);
    CHECK(pg::index_is_valid(lease.get(), "certificate_inventory_store", "hlp_idx"));
    // A stop requested before the build is a TYPED stopped result, not an error-string match.
    cancel.cancel();
    spec.name = "hlp_idx2";
    auto r = pg::ensure_index_concurrently(lease.get(), spec, &cancel);
    CHECK_FALSE(r.ok);
    CHECK(r.stopped);
    exec_ok(pool, "DROP INDEX IF EXISTS certificate_inventory_store.hlp_idx");
}

namespace {
// A fresh store over its OWN pool (no shared-fixture starvation) for interleave tests.
struct OwnStore {
    PgPool pool;
    CertificateInventoryStore store;
    explicit OwnStore(std::size_t size = 6)
        : pool{PgPool::Options{.conninfo = cert_shared().db.dsn(), .size = size}}, store{pool} {}
};
CertReportData one_report(std::vector<CertFactRow> facts) {
    CertReportData d;
    d.blob_version = "1";
    d.stores.push_back({"S", "machine", "ok", ""});
    for (const auto& f : facts)
        d.locations.push_back({"S", "", f.sha256});
    d.facts = std::move(facts);
    return d;
}
} // namespace

TEST_CASE("CertificateInventoryStore: reports raising opposite role flags on shared names never deadlock",
          "[certinv][pg][dict][chaos]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    OwnStore o;
    REQUIRE(o.store.is_open());
    // A and B are both issuers already. Report 1 raises ONLY B's CA-subject flag (and carries A);
    // report 2 raises ONLY A's CA-subject flag (and carries B). Both hold their flag-UPDATE lock
    // before either pins: a lock mode that conflicts with the other's key-share pin is a 40P01.
    exec_ok(o.pool, "INSERT INTO certificate_inventory_store.dn_dict (dn, is_issuer, is_ca_subject) VALUES "
                    "('CN=A', true, false), ('CN=B', true, false)");
    // Rendezvous at BOTH points: the dictionary INSERT of one report waits for an uncommitted flag
    // UPDATE of the same row by the other (ON CONFLICT checks the conflicting tuple), so the cycle
    // only exists if both reports finish their inserts before either raises a flag, and both hold
    // their flag locks before either pins.
    std::atomic<int> at_insert{0}, at_update{0};
    const auto rendezvous = [](std::atomic<int>& n) {
        ++n;
        for (int i = 0; i < 400 && n.load() < 2; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
    };
    o.store.set_test_hook_dict([&](std::string_view point) {
        if (point == "after_dict_insert")
            rendezvous(at_insert);
        else if (point == "after_flag_update")
            rendezvous(at_update);
    });
    CertIngestResult r1, r2;
    std::thread t1([&] {
        r1 = o.store.ingest_full("a1", one_report({dn_fact(1, "CN=A", "CN=x", false), dn_fact(2, "CN=B", "CN=B", true)}), "h1");
    });
    std::thread t2([&] {
        r2 = o.store.ingest_full("a2", one_report({dn_fact(3, "CN=A", "CN=A", true), dn_fact(4, "CN=B", "CN=y", false)}), "h2");
    });
    t1.join();
    t2.join();
    CHECK(at_insert.load() == 2);
    CHECK(at_update.load() == 2);
    CHECK(r1.outcome == CertIngestOutcome::kStored);
    CHECK(r2.outcome == CertIngestOutcome::kStored);
    CHECK(scalar(o.pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE is_issuer AND "
                         "is_ca_subject") == "2");
}

TEST_CASE("CertificateInventoryStore: a prune or decommission interleaved with an ingest never strands a name",
          "[certinv][pg][dict][chaos]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    OwnStore o;
    REQUIRE(o.store.is_open());
    const auto present = [&](const char* dn) {
        return scalar(o.pool, "SELECT count(*) FROM certificate_inventory_store.dn_dict WHERE dn = $1", {dn}) ==
               "1";
    };
    SECTION("a prune BEFORE the pin: the ingest re-inserts the name it finds missing") {
        exec_ok(o.pool, "INSERT INTO certificate_inventory_store.dn_dict (dn, is_issuer, is_ca_subject) VALUES "
                        "('CN=Z', true, false)");
        bool fired = false;
        o.store.set_test_hook_dict([&](std::string_view point) {
            if (point == "after_dict_insert" && !fired) {
                fired = true;
                // Z is committed and unreferenced (our fact is not committed): the prune deletes it.
                REQUIRE(o.store.prune_dn_dictionary());
            }
        });
        REQUIRE(o.store.ingest_full("a1", one_report({dn_fact(1, "CN=Z", "CN=l", false)}), "h").outcome ==
                CertIngestOutcome::kStored);
        CHECK(fired);
        CHECK(present("CN=Z")); // dropping the re-insert leaves a committed fact naming an absent name
    }
    SECTION("a prune AFTER the pin: the key-share lock makes it skip the name") {
        exec_ok(o.pool, "INSERT INTO certificate_inventory_store.dn_dict (dn, is_issuer, is_ca_subject) VALUES "
                        "('CN=Z', true, false)");
        bool fired = false;
        o.store.set_test_hook_dict([&](std::string_view point) {
            if (point == "after_pin" && !fired) {
                fired = true;
                REQUIRE(o.store.prune_dn_dictionary());
                // Still there while the ingest is open: the prune skipped the locked row.
                CHECK(present("CN=Z"));
            }
        });
        REQUIRE(o.store.ingest_full("a1", one_report({dn_fact(1, "CN=Z", "CN=l", false)}), "h").outcome ==
                CertIngestOutcome::kStored);
        CHECK(fired);
        CHECK(present("CN=Z")); // dropping FOR KEY SHARE lets the prune delete it from under the ingest
    }
    SECTION("a decommission AFTER the pin: the name another device still needs survives") {
        put_report(o.store, "other", {dn_fact(9, "CN=Z", "CN=o", false)});
        // The indexes the decommission's erasure needs must exist for it to run its prune.
        REQUIRE(o.store.run_dn_dictionary_maintenance());
        bool fired = false;
        o.store.set_test_hook_dict([&](std::string_view point) {
            if (point == "after_pin" && !fired) {
                fired = true;
                REQUIRE(o.store.delete_agent("other"));
            }
        });
        REQUIRE(o.store.ingest_full("a1", one_report({dn_fact(1, "CN=Z", "CN=l", false)}), "h").outcome ==
                CertIngestOutcome::kStored);
        CHECK(fired);
        CHECK(present("CN=Z"));
    }
}

TEST_CASE("BuildCancel: a stop requested before the arm refuses the arm and cancels nothing late",
          "[certinv][pg][dict]") {
    CERT_SHARED(store, pool);
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::BuildCancel cancel;
    {
        pg::BuildCancel::ScopedArm arm{cancel, lease.get()};
        CHECK(arm.armed()); // nothing requested yet
        cancel.cancel();    // a stop while armed PQcancels the (idle) statement slot, harmlessly
    }
    CHECK(cancel.stop_requested());
    // The stop-before-arm race: the caller's own check can pass just before cancel() lands; the arm
    // re-checks under the same mutex and refuses, so the statement is never started unbounded.
    pg::BuildCancel::ScopedArm late{cancel, lease.get()};
    CHECK_FALSE(late.armed());
    // The pooled connection is still sound (the cancel above hit no running statement).
    CHECK(scalar(pool, "SELECT 1") == "1");
}

TEST_CASE("CertificateInventoryStore: marker states decide retryable vs failed readiness",
          "[certinv][pg][dict]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    OwnStore o;
    REQUIRE(o.store.is_open());
    const auto set_marker = [&](const std::string& m) {
        exec_ok(o.pool, ("COMMENT ON TABLE certificate_inventory_store.dn_dict IS '" + m + "'").c_str());
        (void)o.store.refresh_substring_index_state();
    };
    CertReadFilter f;
    f.issuer_dn_contains = "anything";
    SECTION("`building` / an earlier process's ready: is a RETRYABLE wait, flagged reconciling") {
        set_marker("building");
        CHECK(o.store.substring_state() == SubstringState::kReconciling);
        auto r = o.store.list_certificates(f, std::nullopt, std::nullopt, 10);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().reconciling);
        CHECK(r.error().kind != CertReadError::Kind::kSubstringIndexMissing);
        set_marker("ready:1");
        CHECK(o.store.substring_state() == SubstringState::kReconciling);
    }
    SECTION("an earlier process's ready: WITH a recorded failure is FAILED, not an endless wait") {
        // A replica that started after the leader's last good pass, while the leader's passes fail.
        set_marker("ready:1;last_failure:reconcile: 54000 index row size exceeds");
        CHECK(o.store.substring_state() == SubstringState::kFailed);
        auto r = o.store.list_certificates(f, std::nullopt, std::nullopt, 10);
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().reconciling);
        CHECK(r.error().kind == CertReadError::Kind::kSubstringIndexMissing);
    }
    SECTION("a failed pass on a usable ready: records last_failure and keeps THIS process ready") {
        REQUIRE(o.store.run_dn_dictionary_maintenance());
        REQUIRE(o.store.substring_index_available());
        // A certificate naming a DN the dictionary lacks, and a trigger that rejects dictionary
        // inserts: the next reconcile fails.
        exec_ok(o.pool, "INSERT INTO certificate_inventory_store.agent_state (agent_id, "
                        "content_hash, blob_version, first_seen, last_seen, last_full_at, sample_key) VALUES "
                        "('a1','h','1',now(),now(),now(),7)");
        exec_ok(o.pool, ("INSERT INTO certificate_inventory_store.cert_fact (agent_id, sha256, issuer_dn, "
                         "sample_key) VALUES ('a1','" + std::string(63, '0') + "1', 'CN=Missing', 7)").c_str());
        exec_ok(o.pool, "CREATE FUNCTION certificate_inventory_store.dd_reject() RETURNS trigger LANGUAGE "
                        "plpgsql AS $$ BEGIN RAISE EXCEPTION 'dictionary insert rejected'; END $$");
        exec_ok(o.pool, "CREATE TRIGGER dd_reject BEFORE INSERT ON certificate_inventory_store.dn_dict FOR "
                        "EACH ROW EXECUTE FUNCTION certificate_inventory_store.dd_reject()");
        CHECK_FALSE(o.store.run_dn_dictionary_maintenance());
        const auto m = scalar(o.pool, "SELECT obj_description('certificate_inventory_store.dn_dict'::regclass, "
                                      "'pg_class')");
        CHECK_THAT(m, Catch::Matchers::StartsWith("ready:"));
        CHECK_THAT(m, Catch::Matchers::ContainsSubstring(";last_failure:"));
        CHECK(o.store.substring_index_available()); // this process's working dictionary is not flipped off
        exec_ok(o.pool, "DROP TRIGGER dd_reject ON certificate_inventory_store.dn_dict");
        exec_ok(o.pool, "DROP FUNCTION certificate_inventory_store.dd_reject()");
    }
}

TEST_CASE("pg background build: a stop cancels a CIC blocked behind an old snapshot",
          "[certinv][pg][dict]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    PgPool pool{{.conninfo = cert_shared().db.dsn(), .size = 3}};
    REQUIRE(pool.valid());
    auto holder = pool.acquire();
    auto builder = pool.acquire();
    REQUIRE(holder);
    REQUIRE(builder);
    // An old REPEATABLE READ snapshot: a CREATE INDEX CONCURRENTLY (timeouts lifted) waits on it.
    for (const char* sql : {"BEGIN ISOLATION LEVEL REPEATABLE READ",
                            "SELECT count(*) FROM certificate_inventory_store.cert_fact"})
        REQUIRE(pg::exec_params(holder.get(), sql, std::vector<std::string>{}).status() != PGRES_FATAL_ERROR);
    pg::BuildCancel cancel;
    pg::BuildResult res;
    const auto t0 = std::chrono::steady_clock::now();
    std::thread th([&] {
        res = pg::ensure_index_concurrently(
            builder.get(),
            pg::IndexSpec{"certificate_inventory_store", "blocked_idx", "cert_fact", "btree", "sha256", ""},
            &cancel);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds{600});
    // Watchdog: if the stop does NOT cancel the build (a regression), release the old snapshot after
    // 6 s so the test fails instead of hanging.
    std::atomic<bool> finished{false};
    std::thread dog([&] {
        for (int i = 0; i < 60 && !finished.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (!finished.load())
            (void)pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{});
    });
    cancel.cancel();
    th.join();
    finished = true;
    dog.join();
    const auto took = std::chrono::steady_clock::now() - t0;
    CHECK_FALSE(res.ok);
    CHECK(res.stopped);
    CHECK(took < std::chrono::seconds{5});
    (void)pg::exec_params(holder.get(), "ROLLBACK", std::vector<std::string>{});
    // The lifted timeouts are back on the connection the builder leased.
    builder.reset();
    auto again = pool.acquire();
    REQUIRE(again);
    auto t = pg::exec_params(again.get(), "SELECT current_setting('statement_timeout') <> '0'",
                             std::vector<std::string>{});
    REQUIRE(t.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(t.get(), 0, 0)) == "t");
    exec_ok(pool, "DROP INDEX IF EXISTS certificate_inventory_store.blocked_idx");
}

TEST_CASE("pg background build: a cancel burst never returns a connection with the timeouts lifted",
          "[certinv][pg][dict]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    PgPool pool{{.conninfo = cert_shared().db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    int lifted = 0;
    for (int iter = 0; iter < 60; ++iter) {
        std::atomic<bool> stop{false};
        int pid = 0;
        {
            auto l = pool.acquire();
            REQUIRE(l);
            auto p = pg::exec_params(l.get(), "SELECT pg_backend_pid()", std::vector<std::string>{});
            pid = std::stoi(PQgetvalue(p.get(), 0, 0));
            auto killer_lease = pool.acquire();
            REQUIRE(killer_lease);
            std::thread killer([&] {
                while (!stop.load())
                    (void)pg::exec_params(killer_lease.get(), "SELECT pg_cancel_backend($1::int)",
                                          std::vector<std::string>{std::to_string(pid)});
            });
            {
                pg::UnboundedSession lift{l.get()};
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            } // RESET races the cancel spam
            stop = true;
            killer.join();
        }
        auto again = pool.acquire();
        REQUIRE(again);
        auto t = pg::exec_params(again.get(), "SELECT current_setting('statement_timeout') = '0'",
                                 std::vector<std::string>{});
        if (t.status() == PGRES_TUPLES_OK && std::string(PQgetvalue(t.get(), 0, 0)) == "t")
            ++lifted;
    }
    CHECK(lifted == 0);
}

TEST_CASE("pg background build: a failed RESET discards the session; a doubtful one is terminated",
          "[certinv][pg][dict]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    PgPool pool{{.conninfo = cert_shared().db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    struct Reset {
        ~Reset() { pg::UnboundedSession::force_reset_failure_for_test = 0; }
    } reset_flag;
    SECTION("RESET failed: PQreset opens a fresh session with the pool's timeouts") {
        auto l = pool.acquire();
        REQUIRE(l);
        {
            pg::UnboundedSession lift{l.get()};
            REQUIRE(lift.armed());
            pg::UnboundedSession::force_reset_failure_for_test = 1;
        }
        pg::UnboundedSession::force_reset_failure_for_test = 0;
        REQUIRE(PQstatus(l.get()) == CONNECTION_OK);
        auto t = pg::exec_params(l.get(), "SELECT current_setting('statement_timeout') <> '0'",
                                 std::vector<std::string>{});
        REQUIRE(t.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(t.get(), 0, 0)) == "t"); // not left lifted
    }
    SECTION("verification doubtful too: the backend is terminated so the pool discards it") {
        auto l = pool.acquire();
        REQUIRE(l);
        {
            pg::UnboundedSession lift{l.get()};
            REQUIRE(lift.armed());
            pg::UnboundedSession::force_reset_failure_for_test = 2;
        }
        pg::UnboundedSession::force_reset_failure_for_test = 0;
        CHECK(PQstatus(l.get()) != CONNECTION_OK);
        l.reset(); // the pool finishes the BAD connection rather than reusing it
        auto again = pool.acquire();
        REQUIRE(again);
        auto t = pg::exec_params(again.get(), "SELECT current_setting('statement_timeout') <> '0'",
                                 std::vector<std::string>{});
        REQUIRE(t.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(t.get(), 0, 0)) == "t");
    }
}

TEST_CASE("DnDictPassGuard: a throw out of the pass still joins the watcher and runs done()",
          "[certinv][dict]") {
    std::atomic<int> cancels{0};
    std::atomic<bool> done_called{false};
    bool threw = false;
    try {
        yuzu::server::DnDictPassGuard guard([] { return false; }, // leadership already lost
                                            [&] { ++cancels; }, [&] { done_called = true; });
        std::this_thread::sleep_for(std::chrono::milliseconds{250});
        throw std::bad_alloc{}; // the pass throws: the guard's dtor must join, not terminate
    } catch (const std::bad_alloc&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(done_called.load());
    CHECK(cancels.load() >= 1);
}

TEST_CASE("CertificateInventoryStore: the reconcile's flag UPDATE does not wait on an ingest's key-share pin",
          "[certinv][pg][dict][chaos]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    cert_reset();
    OwnStore o;
    REQUIRE(o.store.is_open());
    // "other" holds a committed CA certificate whose SUBJECT is CN=Z2; the dictionary row lost its
    // ca flag, so the reconcile wants to raise it. A concurrent ingest naming CN=Z2 only as an issuer
    // pins the row FOR KEY SHARE; a reconcile locking FOR UPDATE would wait on that pin.
    put_report(o.store, "other", {dn_fact(9, "CN=Root", "CN=Z2", true)});
    exec_ok(o.pool, "UPDATE certificate_inventory_store.dn_dict SET is_ca_subject = false WHERE dn = 'CN=Z2'");
    exec_ok(o.pool, "INSERT INTO certificate_inventory_store.dn_dict (dn, is_issuer) VALUES ('CN=Z2', true) "
                    "ON CONFLICT (dn) DO UPDATE SET is_issuer = true");
    // Build the indexes FIRST: a CREATE INDEX CONCURRENTLY inside the hook would wait for the open
    // ingest transaction (this very thread) for ever.
    REQUIRE(o.store.run_dn_dictionary_maintenance());
    exec_ok(o.pool, "UPDATE certificate_inventory_store.dn_dict SET is_ca_subject = false WHERE dn = 'CN=Z2'");
    bool fired = false, pass_ok = false;
    const auto t0 = std::chrono::steady_clock::now();
    o.store.set_test_hook_dict([&](std::string_view point) {
        if (point == "after_pin" && !fired) {
            fired = true;
            pass_ok = o.store.run_dn_dictionary_maintenance();
        }
    });
    REQUIRE(o.store.ingest_full("a1", one_report({dn_fact(1, "CN=Z2", "CN=leaf", false)}), "h").outcome ==
            CertIngestOutcome::kStored);
    CHECK(fired);
    CHECK(pass_ok);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds{8}); // not the 10 s lock timeout
    CHECK(scalar(o.pool, "SELECT is_ca_subject::text FROM certificate_inventory_store.dn_dict WHERE dn = "
                         "'CN=Z2'") == "true");
}

TEST_CASE("CertificateInventoryStore: the maintenance schedule, nudge and observer", "[certinv][pg][dict]") {
    CERT_SHARED(store, pool);
    std::vector<std::pair<std::string, std::string>> seen;
    std::mutex mu;
    store.set_dn_dict_observer([&](std::string_view step, std::string_view result) {
        std::lock_guard<std::mutex> lk(mu);
        seen.emplace_back(step, result);
    });
    // Never pruned: due. A first pass stamps the prune, so the schedule says "not due" afterwards.
    auto before = store.read_dn_dictionary_schedule();
    REQUIRE(before);
    CHECK(before->last_prune_ms == 0);
    REQUIRE(store.run_dn_dictionary_maintenance());
    auto after = store.read_dn_dictionary_schedule();
    REQUIRE(after);
    CHECK(after->last_prune_ms > 0);
    CHECK(after->last_pass_start_ms > 0);
    CHECK(store.dn_dict_last_prune_unix_s() == after->last_prune_ms / 1000);
    {
        std::lock_guard<std::mutex> lk(mu);
        const auto has = [&](const char* st, const char* r) {
            return std::find(seen.begin(), seen.end(), std::make_pair(std::string(st), std::string(r))) !=
                   seen.end();
        };
        CHECK(has("index", "ok"));
        CHECK(has("reconcile", "ok"));
        CHECK(has("prune", "ok"));
        CHECK(has("marker", "ok"));
        seen.clear();
    }
    // A second pass inside the hour does NOT prune again (DB-clock schedule).
    REQUIRE(store.run_dn_dictionary_maintenance());
    {
        std::lock_guard<std::mutex> lk(mu);
        CHECK(std::none_of(seen.begin(), seen.end(), [](const auto& p) { return p.first == "prune"; }));
    }
    auto again = store.read_dn_dictionary_schedule();
    REQUIRE(again);
    CHECK(again->last_prune_ms == after->last_prune_ms);
    // The nudge: recorded once, rate-limited (a second request within 20 s does not move it).
    CHECK(again->reconcile_requested_ms == 0);
    store.request_dn_reconcile();
    auto nudged = store.read_dn_dictionary_schedule();
    REQUIRE(nudged);
    CHECK(nudged->reconcile_requested_ms > 0);
    store.request_dn_reconcile();
    auto nudged2 = store.read_dn_dictionary_schedule();
    REQUIRE(nudged2);
    CHECK(nudged2->reconcile_requested_ms == nudged->reconcile_requested_ms);
}

// Opt-in measurement (hidden: `yuzu_server_tests "[.certperf]"` with CERTPERF_DSN naming a database that
// already holds a LARGE v1-shaped store with schema_meta at version 1). Runs the background DN-dictionary
// build while concurrent ingests keep going, and reports the figures. Not part of any suite.
TEST_CASE("certperf: background dictionary build over a large store keeps ingest working",
          "[.certperf]") {
    const char* dsn = std::getenv("CERTPERF_DSN");
    if (!dsn)
        SKIP("CERTPERF_DSN not set");
    PgPool pool{{.conninfo = dsn, .size = 6}};
    REQUIRE(pool.valid());
    using clk = std::chrono::steady_clock;
    const auto t_open = clk::now();
    CertificateInventoryStore store{pool}; // runs migration v2: creates the EMPTY table only
    const auto open_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t_open).count();
    REQUIRE(store.is_open());
    std::printf("PERF store open (boot path, includes migration v2): %lld ms; substring ready=%d\n",
                static_cast<long long>(open_ms), store.substring_index_available() ? 1 : 0);
    std::atomic<bool> stop{false};
    std::vector<double> lat_ms;
    std::mutex mu;
    std::atomic<int> errs{0};
    std::thread ingester([&] {
        int n = 0;
        while (!stop.load()) {
            CertReportData d;
            d.blob_version = "1";
            d.stores.push_back({"S", "machine", "ok", ""});
            for (int i = 0; i < 300; ++i) {
                auto f = rfact(900000000 + n * 1000 + i);
                f.issuer_dn = i % 3 == 0 ? "CN=perf fresh " + std::to_string(n) + "-" + std::to_string(i)
                                         : "CN=perf shared root " + std::to_string(i % 50);
                d.facts.push_back(f);
                d.locations.push_back({"S", "", f.sha256});
            }
            const auto t0 = clk::now();
            const auto r = store.ingest_full("perf-live-" + std::to_string(n % 20), d, "h" + std::to_string(n));
            const double ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count();
            if (r.outcome != CertIngestOutcome::kStored)
                ++errs;
            std::lock_guard<std::mutex> lk(mu);
            lat_ms.push_back(ms);
            ++n;
        }
    });
    const auto t0 = clk::now();
    const bool ok = store.run_dn_dictionary_maintenance();
    const double build_s = std::chrono::duration<double>(clk::now() - t0).count();
    stop = true;
    ingester.join();
    std::sort(lat_ms.begin(), lat_ms.end());
    const auto pc = [&](double p) { return lat_ms.empty() ? 0.0 : lat_ms[std::min(lat_ms.size() - 1, static_cast<std::size_t>(p * lat_ms.size()))]; };
    std::printf("PERF maintenance ok=%d took %.1f s; ready=%d\n", ok ? 1 : 0, build_s,
                store.substring_index_available() ? 1 : 0);
    std::printf("PERF concurrent ingest during the build: %zu reports, errors=%d, p50=%.0f ms p95=%.0f ms "
                "p99=%.0f ms max=%.0f ms\n",
                lat_ms.size(), errs.load(), pc(.5), pc(.95), pc(.99), lat_ms.empty() ? 0.0 : lat_ms.back());
    CHECK(ok);
    CHECK(errs.load() == 0);
}

TEST_CASE("CertificateInventoryStore reads: the internal sample_key never appears in any read or export",
          "[certinv][pg][read][samplekey]") {
    CERT_SHARED(store, pool);
    REQUIRE(store.run_dn_dictionary_maintenance());
    put_report(store, "a1",
               {dn_fact(1, "CN=Sample Root", "CN=Sample Root", true),
                dn_fact(2, "CN=Sample Root", "CN=leaf2", false)});
    put_report(store, "a2", {dn_fact(1, "CN=Sample Root", "CN=Sample Root", true)});

    // Every per-agent key the database holds; none may reach any output, by name or by value.
    const auto keys = scalar(pool, "SELECT string_agg(sample_key::text, ',') FROM "
                                   "certificate_inventory_store.agent_state");
    REQUIRE_FALSE(keys.empty());
    std::vector<std::string> key_values;
    for (std::size_t p = 0; p <= keys.size();) {
        const auto e = keys.find(',', p);
        key_values.push_back(keys.substr(p, e == std::string::npos ? std::string::npos : e - p));
        if (e == std::string::npos)
            break;
        p = e + 1;
    }
    const auto clean = [&](const std::string& out, const char* what) {
        INFO(what);
        CHECK(out.find("sample_key") == std::string::npos);
        for (const auto& k : key_values)
            CHECK(out.find(k) == std::string::npos);
    };

    CertReadFilter issuer;       // the selective path: materialised CTE
    issuer.issuer_dn_contains = "sample root";
    CertReadFilter subject;
    subject.subject_dn_contains = "sample root";
    subject.is_ca = true;
    for (const auto& [name, f] : std::vector<std::pair<const char*, CertReadFilter>>{
             {"unfiltered page", CertReadFilter{}}, {"issuer substring", issuer},
             {"subject substring", subject}}) {
        const auto page = must_list(store, f);
        REQUIRE_FALSE(page.rows.empty());
        for (const auto& r : page.rows)
            clean(cert_read::row_json(r).dump(), name);
        clean(cert_read::list_json(page).dump(), name);
        clean(cert_read::audit_detail("cid", f, page.rows.size(), false, false, false), name);
        clean(cert_read::filter_names(f), name);
    }

    CertSummaryQuery q;
    q.not_after_edges = {"2025-01-01T00:00:00Z", "2035-01-01T00:00:00Z"};
    const auto summary = store.summarize_certificates(q, std::nullopt);
    REQUIRE(summary.has_value());
    clean(cert_read::summary_json(*summary).dump(), "summary");
}
