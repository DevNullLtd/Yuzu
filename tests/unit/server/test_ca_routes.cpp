/**
 * test_ca_routes.cpp — HTTP-level coverage for the internal-CA REST surface
 * under /api/v1/ca/ (PKI PR4). Registers CaRoutes against an in-process
 * TestRouteSink (no socket, no acceptor thread — TSan-safe, #438) and
 * dispatches synthesized requests directly into the captured handlers.
 *
 * Coverage: root PEM (200 / 404 no-root), issued inventory (200 shape +
 * 403 perm-denied), revoke (200 + audit + CRL republish, 400 missing serial,
 * 404 already-revoked, 403 perm-denied), CRL (build-on-first then serve-latest),
 * and 503 when the CA store is unavailable.
 */

#include "ca_routes.hpp"
#include "ca_store.hpp"
#include "crypto_api_local.hpp"
#include "crypto_widget_catalogue.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <expected>
#include <memory>
#include <set>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

// Shared with test_ca_store.cpp's "castore" key — identical setup, replay-verified by the
// PgTestTemplate registry (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate ca_routes_store_tpl{
    "castore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        CaStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("ca_store template: store failed to migrate");
    }};

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// Wires CaRoutes against an in-process sink with a real CaStore + fakes for
// perm/audit/CRL. `perm_allow` toggles the permission gate; audit rows are
// captured; `crl_calls` counts publish_crl_fn invocations. Owns its own PgPool
// (fixture-owned std::optional<PgPool> per the playbook's high-volume-file pattern) so every
// TEST_CASE's `Harness h;` gets an independent, freshly-cloned `ca_store` schema.
struct Harness {
    // Declared FIRST (constructed first, destroyed LAST): the cloned database must outlive
    // pool_holder/store, which hold live connections to it. A constructor-LOCAL PostgresTestDb
    // would be destroyed at the end of the constructor body — its destructor drops the database
    // WITH (FORCE), which terminates every connection still open on it, including pool_holder's
    // — silently breaking the store immediately after construction (#observed: every request
    // returned 503 as if the store had never opened).
    std::optional<yuzu::test::PostgresTestDb> db_holder;
    std::optional<pg::PgPool> pool_holder;
    std::unique_ptr<CaStore> store;
    test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    bool perm_allow{true};
    bool unauthenticated{false}; // perm_fn answers 401 as production's does with no session
    // Operation-aware denial: an operation named here ("Read", "Delete", "Write") is refused
    // while the others pass, so a role that holds Delete or Write without Read can be modelled.
    std::set<std::string> deny_ops;
    // false leaves the CaRoutes read probe unset (the wrappers must then fail closed).
    bool probe_wired{true};
    bool crl_succeeds{true};   // when false, publish_crl_fn returns nullopt (GAP-2)
    bool audit_succeeds{true}; // when false, AuditFn returns false (#1240 Sec-Audit-Failed)
    int crl_calls{0};
    std::string last_perm_type; // captured (securable, op) of the last perm check
    std::string last_perm_op;
    // PR6 subordinate-CA fakes. export_csr_result==nullopt → export 500; the
    // import fn records its args and returns the configurable import_outcome (the
    // crypto validation itself is unit-tested at the engine level — this exercises
    // the handler's body-validation, outcome→status mapping, and audit).
    std::optional<std::string> export_csr_result{
        "-----BEGIN CERTIFICATE REQUEST-----\nFAKECSR\n-----END CERTIFICATE REQUEST-----\n"};
    CaRoutes::ImportOutcome import_outcome{CaRoutes::ImportOutcome::Ok};
    std::string last_import_intermediate;
    std::string last_import_chain;
    int import_calls{0};

    // gap-matrix #10: code-signing leaf issuance fake. Defaults to a
    // successful, fixed issuance so happy-path tests need not set anything;
    // `issue_result` overrides for a failure-classification test.
    std::expected<CodeSigningIssuance, std::string> issue_result{
        CodeSigningIssuance{.certificate_pem = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END "
                                               "CERTIFICATE-----\n",
                           .chain_pem = "-----BEGIN CERTIFICATE-----\nROOT\n-----END "
                                        "CERTIFICATE-----\n",
                           .serial_hex = "C5C1FEED",
                           .not_after = "2027-01-01T00:00:00Z"}};
    int issue_calls{0};
    // ADR-0070 R2-2: the filtered /ca/issued. `wire_filtered` false = the deps are unset (503);
    // `standing` is the confinement probe's answer.
    bool wire_filtered{true};
    yuzu::server::crypto_widgets::Access standing{yuzu::server::crypto_widgets::Access::kAvailable};
    int standing_calls{0};
    std::string last_issue_csr;
    std::string last_issue_label;
    std::optional<int> last_issue_validity_days;
    std::string last_issue_issued_by;

    Harness() {
        // Hand-expanded YUZU_REQUIRE_PG_DB_TPL (that macro declares its own function-local
        // `var`, which cannot become a class member — see db_holder's doc comment above for
        // why this must persist past construction).
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_holder.emplace(ca_routes_store_tpl);
        INFO("[Harness] fixture status (blank == database came up OK): " << db_holder->error());
        REQUIRE(db_holder->available());
        pool_holder.emplace(pg::PgPool::Options{.conninfo = db_holder->dsn(), .size = 4});
        store = std::make_unique<CaStore>(*pool_holder);
    }

    void wire(bool null_store = false) {
        CaRoutes routes;
        CaRoutes::AuthFn auth = [](const httplib::Request&,
                                   httplib::Response&) -> std::optional<auth::Session> {
            return std::nullopt;
        };
        CaRoutes::PermFn perm = [this](const httplib::Request&, httplib::Response& res,
                                       const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (unauthenticated) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"authentication required"}})",
                                "application/json");
                return false;
            }
            if (!perm_allow || deny_ops.count(op) != 0) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
                return false;
            }
            return true;
        };
        CaRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                         const std::string& r, const std::string& tt,
                                         const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds; // #1240: AuditFn now returns bool (observe persist failure)
        };
        CaRoutes::PublishCrlFn crl = [this]() -> std::optional<std::vector<std::uint8_t>> {
            ++crl_calls;
            if (!crl_succeeds)
                return std::nullopt;
            return std::vector<std::uint8_t>{0x30, 0x03, 0x01, 0x02}; // fake DER
        };
        CaRoutes::ExportCsrFn export_csr = [this]() { return export_csr_result; };
        CaRoutes::ImportChainFn import_chain = [this](const std::string& im,
                                                      const std::string& ch) {
            ++import_calls;
            last_import_intermediate = im;
            last_import_chain = ch;
            return import_outcome;
        };
        IssueCodeSigningFn issue_code_signing =
            [this](const std::string& csr_pem, const std::string& label,
                  std::optional<int> validity_days,
                  const std::string& issued_by) -> std::expected<CodeSigningIssuance, std::string> {
            ++issue_calls;
            last_issue_csr = csr_pem;
            last_issue_label = label;
            last_issue_validity_days = validity_days;
            last_issue_issued_by = issued_by;
            return issue_result;
        };
        if (wire_filtered)
            routes.set_filtered_issued(CaRoutes::FilteredIssuedDeps{
                .api = make_local_crypto_api(LocalCryptoApiDeps{.ca = null_store ? nullptr : store.get()}),
                .confinement_fn = [this](const httplib::Request&) {
                    ++standing_calls;
                    return standing;
                }});
        if (probe_wired)
            routes.set_read_probe([this](const httplib::Request&) {
                return perm_allow && deny_ops.count("Read") == 0;
            });
        routes.register_routes(sink, auth, perm, audit, null_store ? nullptr : store.get(), crl,
                               export_csr, import_chain, issue_code_signing);
    }
};

CaRoot sample_root() {
    CaRoot r;
    r.cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBfakeRootPEM\n-----END CERTIFICATE-----\n";
    r.key_ref = "/tmp/ca-routes-test-does-not-resolve.key";
    r.algo = "EcP384";
    r.not_before = 1000;
    r.not_after = 9999999999;
    r.fingerprint_sha256 = "AB:CD:EF";
    r.mode = CaMode::Builtin;
    return r;
}

IssuedCertRecord sample_issued(const std::string& serial) {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "agent-" + serial;
    r.san = "URI:yuzu://inst/agent/" + serial;
    r.purpose = "agent";
    r.not_after = 9999999999;
    r.cert_pem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
    r.issued_by = "agent:" + serial;
    return r;
}

} // namespace

TEST_CASE("ca_routes: GET /ca/root serves PEM, 404 with no root", "[ca_routes][pki][pg]") {
    Harness h;
    h.wire();
    auto r404 = h.sink.Get("/api/v1/ca/root");
    REQUIRE(r404);
    REQUIRE(r404->status == 404); // no root yet

    REQUIRE(h.store->set_root(sample_root()));
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->body.find("BEGIN CERTIFICATE") != std::string::npos);
    REQUIRE(ok->get_header_value("Content-Type") == "application/x-pem-file");
}

TEST_CASE("ca_routes: GET /ca/root is public (no perm gate)", "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.perm_allow = false; // would block a gated route
    h.wire();
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200); // root is public — perm_fn is never consulted
}

TEST_CASE("ca_routes: GET /ca/issued requires Security:Read", "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    REQUIRE(h.store->record_issued(sample_issued("BEEF")));
    h.wire();

    auto ok = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    auto j = json::parse(ok->body);
    REQUIRE(j["count"] == 2);
    REQUIRE(j["items"].size() == 2);
    REQUIRE(j["meta"]["api_version"] == "v1");
    // GAP-1: the inventory must NOT leak the full cert PEM or the enrollment ref
    // (security property — confirm a future refactor can't silently expose them).
    for (const auto& item : j["items"]) {
        REQUIRE_FALSE(item.contains("cert_pem"));
        REQUIRE_FALSE(item.contains("enrollment_request_id"));
    }

    h.perm_allow = false;
    auto denied = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: POST /ca/revoke flow", "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Missing serial → 400.
    auto bad = h.sink.Post("/api/v1/ca/revoke", R"({})");
    REQUIRE(bad);
    REQUIRE(bad->status == 400);

    // Valid revoke → 200, audited, CRL republished.
    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD","reason":"compromised"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    auto j = json::parse(ok->body);
    REQUIRE(j["revoked"] == true);
    REQUIRE(j["crl_republished"] == true);
    REQUIRE(h.crl_calls == 1);
    REQUIRE(h.store->is_revoked("DEAD"));

    bool saw_revoke = false, saw_crl = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success" && a.target_id == "DEAD")
            saw_revoke = true;
        if (a.action == "ca.crl.published" && a.result == "success")
            saw_crl = true;
    }
    REQUIRE(saw_revoke);
    REQUIRE(saw_crl);

    // Re-revoke an already-revoked serial → 404 + a "denied" audit row (#1240:
    // reject-without-state-change uses "denied" like every destructive sibling;
    // "failure" is reserved for an authorized-but-errored op). This is also the
    // idempotency case — a retry of a successful revoke must not log a false error.
    auto again = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(again);
    REQUIRE(again->status == 404);
    bool saw_denied = false;
    for (const auto& a : h.audits)
        if (a.action == "ca.cert.revoked" && a.result == "denied")
            saw_denied = true;
    REQUIRE(saw_denied);

    // Perm denied → 403, no revoke attempted, and NO audit row emitted by the
    // handler (#1240: the perm gate runs before any audit_fn call; the denied
    // audit is the perm layer's responsibility, not the route's — asserting zero
    // new rows here proves the route doesn't double-audit or leak a row on 403).
    const std::size_t audits_before = h.audits.size();
    h.perm_allow = false;
    auto denied = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"BEEF"})");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
    REQUIRE(h.audits.size() == audits_before); // handler emitted no audit row on 403
}

// gov B2 (F1: arch-1 + compliance HIGH): the `ca.cert.revoked` target_type must
// come from the cert's OWN recorded purpose, never a hardcoded
// "AgentCertificate" — now that code-signing certs (gap-matrix #10) are
// revocable through this same route, the old hardcode would durably mis-audit
// a code-signing revocation.
TEST_CASE("ca_routes: POST /ca/revoke derives target_type from the cert's own purpose",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("FACE01"))); // purpose="agent"

    IssuedCertRecord cs_rec;
    cs_rec.serial_hex = "C0DE51";
    cs_rec.subject = "build-signer-01";
    cs_rec.purpose = "code-signing";
    cs_rec.not_after = 9999999999;
    cs_rec.cert_pem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
    cs_rec.issued_by = "operator:tester";
    REQUIRE(h.store->record_issued(cs_rec));
    h.wire();

    // A code-signing revocation audits CodeSigningCertificate — the headline
    // regression this finding closes.
    auto revoked_cs =
        h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"C0DE51","reason":"key_compromise"})");
    REQUIRE(revoked_cs);
    REQUIRE(revoked_cs->status == 200);
    bool saw_code_signing = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success" && a.target_id == "C0DE51") {
            saw_code_signing = true;
            REQUIRE(a.target_type == "CodeSigningCertificate");
        }
    }
    REQUIRE(saw_code_signing);

    // An agent-cert revocation still audits AgentCertificate — regression guard
    // proving the derivation didn't just flip the hardcode the other way.
    h.audits.clear();
    auto revoked_agent =
        h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"FACE01","reason":"key_compromise"})");
    REQUIRE(revoked_agent);
    REQUIRE(revoked_agent->status == 200);
    bool saw_agent = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success" && a.target_id == "FACE01") {
            saw_agent = true;
            REQUIRE(a.target_type == "AgentCertificate");
        }
    }
    REQUIRE(saw_agent);

    // A never-issued serial (no record to derive purpose from) falls back to
    // the neutral "Certificate", not a guess.
    h.audits.clear();
    auto not_found =
        h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"BAADF00D","reason":"x"})");
    REQUIRE(not_found);
    REQUIRE(not_found->status == 404);
    bool saw_denied = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "denied") {
            saw_denied = true;
            REQUIRE(a.target_type == "Certificate");
        }
    }
    REQUIRE(saw_denied);
}

TEST_CASE("ca_routes: GET /ca/crl serves latest-or-503, never builds on the public path",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // No published CRL yet → 503 (Hermes M1: the public path must NOT load the CA
    // key to build+sign — that is the server's startup/republish job).
    auto none = h.sink.Get("/api/v1/ca/crl");
    REQUIRE(none);
    REQUIRE(none->status == 503);
    REQUIRE(h.crl_calls == 0); // publish_crl_fn never invoked from the public GET

    // Record a CRL version (as the startup pre-publish / a revoke would) → served.
    CrlVersionRecord rec;
    rec.version = 5;
    rec.der = {0x30, 0x01, 0x00};
    rec.this_update = 1;
    rec.next_update = 2;
    REQUIRE(h.store->record_crl_for_test(rec));
    auto served = h.sink.Get("/api/v1/ca/crl");
    REQUIRE(served);
    REQUIRE(served->status == 200);
    REQUIRE(served->get_header_value("Content-Type") == "application/pkix-crl");
    REQUIRE(served->get_header_value("Cache-Control").find("no-cache") != std::string::npos);
    REQUIRE(h.crl_calls == 0); // still served from latest_crl, no build
    REQUIRE(served->body.size() == 3);
}

TEST_CASE("ca_routes: /ca/root sets download + cache headers", "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Disposition").find("attachment") != std::string::npos);
    REQUIRE(ok->get_header_value("Cache-Control").find("max-age") != std::string::npos);
}

TEST_CASE("ca_routes: revoke validates serial + bounds the body", "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Non-hex serial → 400 (Hermes M4).
    auto nonhex = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"zzzz"})");
    REQUIRE(nonhex);
    REQUIRE(nonhex->status == 400);

    // Unknown field → 400 (Hermes BFLA-M2 mass-assignment guard); the revoke must
    // NOT proceed.
    auto extra = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD","is_admin":true})");
    REQUIRE(extra);
    REQUIRE(extra->status == 400);
    REQUIRE_FALSE(h.store->is_revoked("DEAD"));

    // Over-length serial (>64) → 400.
    auto long_serial = std::string(65, 'A');
    auto toolong = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":")" + long_serial + R"("})");
    REQUIRE(toolong);
    REQUIRE(toolong->status == 400);

    // Oversized body → 413 (Hermes M3), before JSON parse.
    std::string big = R"({"serial_hex":"DEAD","reason":")" + std::string(70000, 'x') + R"("})";
    auto big_res = h.sink.Post("/api/v1/ca/revoke", big);
    REQUIRE(big_res);
    REQUIRE(big_res->status == 413);

    // Lowercase hex is normalized to the canonical uppercase ca.db form → matches.
    auto lower = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"dead","reason":"lc"})");
    REQUIRE(lower);
    REQUIRE(lower->status == 200);
    REQUIRE(h.store->is_revoked("DEAD"));
}

TEST_CASE("ca_routes: revoke succeeds but CRL republish fails is audited", "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.crl_succeeds = false; // GAP-2: publish_crl_fn returns nullopt
    h.wire();

    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200); // revocation still stands
    auto j = json::parse(ok->body);
    REQUIRE(j["revoked"] == true);
    REQUIRE(j["crl_republished"] == false);
    REQUIRE(h.store->is_revoked("DEAD")); // enforced server-side regardless

    bool revoke_ok = false, crl_fail = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success")
            revoke_ok = true;
        if (a.action == "ca.crl.published" && a.result == "failure")
            crl_fail = true;
    }
    REQUIRE(revoke_ok);
    REQUIRE(crl_fail); // the republish FAILURE is on the evidence chain
}

TEST_CASE("ca_routes: a dropped audit row on a successful revoke sets Sec-Audit-Failed (#1240 M2)",
          "[ca_routes][pki][security][pg]") {
    // The AuditFn is bool-returning; a privileged revoke whose audit row fails to
    // persist must signal the evidence-chain gap to the operator (Sec-Audit-Failed)
    // while the revoke itself still stands. Without a test, a regression in the
    // header wiring would silently break that signal.
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.audit_succeeds = false; // simulate an audit-store write failure
    h.wire();

    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);                       // the revoke still succeeded
    REQUIRE(json::parse(ok->body)["revoked"] == true);
    REQUIRE(h.store->is_revoked("DEAD"));             // enforced regardless
    REQUIRE(ok->get_header_value("Sec-Audit-Failed") == "true"); // gap surfaced
}

TEST_CASE("ca_routes: /ca/issued pagination params are accepted + clamped", "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("AA01")));
    h.wire();
    // limit=0 (→clamped to 1) and an absurd limit (→clamped) both 200, no error: a
    // well-formed integer out of range is CLAMPED, never rejected.
    for (const char* q : {"/api/v1/ca/issued?limit=0", "/api/v1/ca/issued?limit=999999",
                          "/api/v1/ca/issued?offset=-5"}) {
        auto r = h.sink.Get(q);
        REQUIRE(r);
        REQUIRE(r->status == 200);
    }
    // #4644: a MALFORMED integer is not "out of range", it is not a number. It used
    // to fall back to the default page silently (`limit=abc` -> 200, 200 rows).
    for (const char* q : {"/api/v1/ca/issued?limit=abc", "/api/v1/ca/issued?limit=50x",
                          "/api/v1/ca/issued?limit=1e2", "/api/v1/ca/issued?offset=0x10",
                          "/api/v1/ca/issued?limit=", "/api/v1/ca/issued?limit=99999999999999999999"}) {
        INFO(q);
        auto r = h.sink.Get(q);
        REQUIRE(r);
        REQUIRE(r->status == 400);
        CHECK(r->body.find("invalid numeric query parameter") != std::string::npos);
    }
}

TEST_CASE("ca_routes: dashboard fragment renders, gated, and HTML-escapes (PR4b)",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    // A cert whose subject carries an XSS payload — must be escaped in the table.
    IssuedCertRecord evil = sample_issued("CAFE");
    evil.subject = "<script>alert(1)</script>";
    REQUIRE(h.store->record_issued(evil));
    h.wire();

    auto frag = h.sink.Get("/fragments/settings/ca");
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    REQUIRE(frag->get_header_value("Content-Type").find("text/html") != std::string::npos);
    // Root info + download links present.
    REQUIRE(frag->body.find("/api/v1/ca/root") != std::string::npos);
    REQUIRE(frag->body.find("/api/v1/ca/crl") != std::string::npos);
    REQUIRE(frag->body.find(sample_root().fingerprint_sha256) != std::string::npos);
    // XSS payload is escaped, not raw.
    REQUIRE(frag->body.find("<script>alert(1)</script>") == std::string::npos);
    REQUIRE(frag->body.find("&lt;script&gt;") != std::string::npos);
    // A revoke control for the active cert is present.
    REQUIRE(frag->body.find("/api/settings/ca/revoke") != std::string::npos);

    // Gated on Security:Read.
    h.perm_allow = false;
    auto denied = h.sink.Get("/fragments/settings/ca");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

// An unrevoked certificate past not_after reads Expired, in the neutral colour a revoked one
// wears, never Active and never the green OK colour (role-ok). A certificate still in date
// stays Active, and a revoked one reads Revoked even once it has also lapsed.
TEST_CASE("ca_routes: an expired certificate is listed as Expired and never as Active",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    IssuedCertRecord lapsed = sample_issued("E0D1");
    lapsed.not_after = 1; // long past
    REQUIRE(h.store->record_issued(lapsed));
    REQUIRE(h.store->record_issued(sample_issued("F00D"))); // in date (not_after 9999999999)
    IssuedCertRecord both = sample_issued("B07A");
    both.not_after = 1;
    REQUIRE(h.store->record_issued(both));
    REQUIRE(h.store->revoke("B07A", "test").value());
    h.wire();

    auto frag = h.sink.Get("/fragments/settings/ca");
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    // The pill that follows a row's serial cell.
    const auto pill_of = [&](const std::string& serial) {
        const auto row = frag->body.find("title=\"" + serial + "\"");
        REQUIRE(row != std::string::npos);
        const auto pill = frag->body.find("role-badge ", row);
        REQUIRE(pill != std::string::npos);
        return frag->body.substr(pill, frag->body.find("</span>", pill) - pill);
    };
    CHECK(pill_of("E0D1") == "role-badge role-user\">Expired");
    CHECK(pill_of("F00D") == "role-badge role-admin\">Active");
    CHECK(pill_of("B07A") == "role-badge role-user\">Revoked");
    CHECK(frag->body.find("role-ok") == std::string::npos);
}

TEST_CASE("ca_routes: dashboard revoke wrapper revokes + re-renders (PR4b)",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Same-origin headers so the (now mandatory) CSRF gate passes; the handler
    // reads serial/reason from params (HTMX hx-vals → form body in production; the
    // TestRouteSink parses the query string into req.params, and the handler reads
    // get_param_value either way). → 200 HTML.
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};
    auto ok = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=dead&reason=panel", "",
                              "application/x-www-form-urlencoded", same_origin);
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Type").find("text/html") != std::string::npos);
    REQUIRE(h.store->is_revoked("DEAD")); // lowercase input normalised + matched
    REQUIRE(ok->body.find("Revoked") != std::string::npos); // re-rendered with the new status
    REQUIRE(h.crl_calls == 1);                              // republished via revoke_core

    // Invalid serial → 400 HTML, full panel re-rendered (not a bare span).
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz", "",
                               "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad);
    REQUIRE(bad->status == 400);
    REQUIRE(bad->body.find("<table") != std::string::npos); // inline error + full fragment

    // Gated on Security:Delete (CSRF passes via same-origin headers, then perm denies).
    h.perm_allow = false;
    auto denied = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD", "",
                                  "application/x-www-form-urlencoded", same_origin);
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: /ca/issued reports has_more + next_offset across pages",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    // Three distinct issued certs; page through them two at a time.
    REQUIRE(h.store->record_issued(sample_issued("AA01")));
    REQUIRE(h.store->record_issued(sample_issued("AA02")));
    REQUIRE(h.store->record_issued(sample_issued("AA03")));
    h.wire();

    // Page 1: limit=2 of 3 → has_more=true, next_offset=2, exactly 2 items
    // returned (the probe row must be trimmed, not leaked into the page).
    auto p1 = h.sink.Get("/api/v1/ca/issued?limit=2");
    REQUIRE(p1);
    REQUIRE(p1->status == 200);
    auto j1 = json::parse(p1->body);
    REQUIRE(j1["items"].size() == 2);
    REQUIRE(j1["count"] == 2);
    REQUIRE(j1["meta"]["has_more"] == true);
    REQUIRE(j1["meta"]["next_offset"] == 2);
    REQUIRE(j1["meta"]["limit"] == 2);
    REQUIRE(j1["meta"]["offset"] == 0);

    // Page 2: offset=2 → the last record, has_more=false, no next_offset.
    auto p2 = h.sink.Get("/api/v1/ca/issued?limit=2&offset=2");
    REQUIRE(p2);
    REQUIRE(p2->status == 200);
    auto j2 = json::parse(p2->body);
    REQUIRE(j2["items"].size() == 1);
    REQUIRE(j2["meta"]["has_more"] == false);
    REQUIRE(j2["meta"].contains("next_offset") == false);

    // Exactly at the boundary: limit==total → has_more=false (the probe found
    // no extra row), no spurious extra page.
    auto exact = h.sink.Get("/api/v1/ca/issued?limit=3");
    REQUIRE(exact);
    auto je = json::parse(exact->body);
    REQUIRE(je["items"].size() == 3);
    REQUIRE(je["meta"]["has_more"] == false);
}

TEST_CASE("ca_routes: 503 when CA store unavailable", "[ca_routes][pki][pg]") {
    Harness h;
    h.wire(/*null_store=*/true);
    for (const char* path : {"/api/v1/ca/root", "/api/v1/ca/crl", "/api/v1/ca/issued",
                             "/api/v1/ca/root-csr"}) {
        auto r = h.sink.Get(path);
        REQUIRE(r);
        REQUIRE(r->status == 503);
    }
    auto rev = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(rev);
    REQUIRE(rev->status == 503);
    auto imp = h.sink.Post("/api/v1/ca/import-chain",
                           R"({"intermediate_pem":"x","chain_pem":"y"})");
    REQUIRE(imp);
    REQUIRE(imp->status == 503);
    auto issue = h.sink.Post("/api/v1/ca/issue-code-signing",
                             R"({"csr_pem":"x","label":"y"})");
    REQUIRE(issue);
    REQUIRE(issue->status == 503);
}

// ── PR6 subordinate-CA REST ─────────────────────────────────────────────────

TEST_CASE("ca_routes: GET /ca/root-csr exports a CSR, gated Security:Read, audited",
          "[ca_routes][pki][subordinate][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    auto ok = h.sink.Get("/api/v1/ca/root-csr");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Type") == "application/pkcs10");
    REQUIRE(ok->body.find("CERTIFICATE REQUEST") != std::string::npos);
    REQUIRE(h.last_perm_type == "Security");
    REQUIRE(h.last_perm_op == "Read");
    bool saw_export = false;
    for (const auto& a : h.audits)
        if (a.action == "ca.root_csr.exported" && a.result == "success")
            saw_export = true;
    REQUIRE(saw_export);

    // export fn returning nullopt → 500.
    h.export_csr_result = std::nullopt;
    auto err = h.sink.Get("/api/v1/ca/root-csr");
    REQUIRE(err);
    REQUIRE(err->status == 500);

    // Security:Read gate.
    h.perm_allow = false;
    auto denied = h.sink.Get("/api/v1/ca/root-csr");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: POST /ca/import-chain validates body + maps outcomes + audits",
          "[ca_routes][pki][subordinate][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // Happy path: Ok outcome → 200, forwards the parsed PEMs, republishes CRL.
    h.import_outcome = CaRoutes::ImportOutcome::Ok;
    auto ok = h.sink.Post("/api/v1/ca/import-chain",
                          R"({"intermediate_pem":"INT","chain_pem":"PARENT"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(h.last_perm_type == "Security");
    REQUIRE(h.last_perm_op == "Write"); // import is a mutation
    REQUIRE(h.last_import_intermediate == "INT");
    REQUIRE(h.last_import_chain == "PARENT");
    auto j = json::parse(ok->body);
    REQUIRE(j["imported"] == true);
    REQUIRE(j["mode"] == "subordinate");
    REQUIRE(j["crl_republished"] == true); // CRL refreshed under the new issuer
    REQUIRE(h.crl_calls == 1);
    bool saw_import = false;
    bool saw_crl_published = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.subordinate.imported" && a.result == "success")
            saw_import = true;
        // #4829: the import-chain path previously wrote NO ca.crl.published row at all —
        // symmetric with revoke's own pair, and carries reason=import_chain to distinguish it.
        if (a.action == "ca.crl.published" && a.result == "success" &&
            a.detail.find("reason=import_chain") != std::string::npos)
            saw_crl_published = true;
    }
    REQUIRE(saw_import);
    REQUIRE(saw_crl_published);

    // Body validation: invalid JSON → 400; missing fields → 400.
    auto badjson = h.sink.Post("/api/v1/ca/import-chain", "{not json");
    REQUIRE(badjson);
    REQUIRE(badjson->status == 400);
    auto missing = h.sink.Post("/api/v1/ca/import-chain", R"({"intermediate_pem":"INT"})");
    REQUIRE(missing);
    REQUIRE(missing->status == 400);

    // Oversized body → 413 (bounded before the JSON parser).
    std::string big(300 * 1024, 'A');
    auto toobig = h.sink.Post("/api/v1/ca/import-chain", big);
    REQUIRE(toobig);
    REQUIRE(toobig->status == 413);

    // Outcome → status mapping, each a "denied" security event (StoreError =
    // "failure"). Validation rejections must NOT change state.
    struct Case {
        CaRoutes::ImportOutcome outcome;
        int status;
        const char* result;
    };
    const Case cases[] = {
        {CaRoutes::ImportOutcome::NoRoot, 409, "denied"},
        {CaRoutes::ImportOutcome::BadIntermediate, 400, "denied"},
        {CaRoutes::ImportOutcome::NotCa, 422, "denied"},
        {CaRoutes::ImportOutcome::KeyMismatch, 422, "denied"},
        {CaRoutes::ImportOutcome::ChainInvalid, 422, "denied"},
        {CaRoutes::ImportOutcome::StoreError, 500, "failure"},
    };
    for (const auto& c : cases) {
        h.audits.clear();
        h.import_outcome = c.outcome;
        auto r = h.sink.Post("/api/v1/ca/import-chain",
                             R"({"intermediate_pem":"INT","chain_pem":"PARENT"})");
        REQUIRE(r);
        REQUIRE(r->status == c.status);
        bool saw = false;
        for (const auto& a : h.audits)
            if (a.action == "ca.subordinate.imported" && a.result == c.result)
                saw = true;
        REQUIRE(saw);
    }

    // Security:Write gate.
    h.perm_allow = false;
    auto denied = h.sink.Post("/api/v1/ca/import-chain",
                              R"({"intermediate_pem":"INT","chain_pem":"PARENT"})");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: dashboard fragment shows trust mode + subordinate controls (PR6)",
          "[ca_routes][pki][subordinate][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root())); // builtin
    h.wire();
    auto frag = h.sink.Get("/fragments/settings/ca");
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    REQUIRE(frag->body.find("Built-in") != std::string::npos);
    REQUIRE(frag->body.find("/api/v1/ca/root-csr") != std::string::npos);          // CSR export link
    REQUIRE(frag->body.find("/api/settings/ca/import-chain") != std::string::npos); // import form
    REQUIRE(frag->body.find("intermediate_pem") != std::string::npos);
}

TEST_CASE("ca_routes: dashboard import wrapper enforces CSRF + Security:Write (PR6)",
          "[ca_routes][pki][subordinate][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};

    // Same-origin + Ok outcome → 200 HTML, import_chain_fn received the form PEMs.
    h.import_outcome = CaRoutes::ImportOutcome::Ok;
    auto ok = h.sink.dispatch("POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                              "", "application/x-www-form-urlencoded", same_origin);
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Type").find("text/html") != std::string::npos);
    REQUIRE(h.last_import_intermediate == "INT");
    REQUIRE(h.last_import_chain == "PAR");
    // #4829: the dashboard import-chain path previously wrote NO ca.crl.published row.
    {
        bool saw = false;
        for (const auto& a : h.audits)
            if (a.action == "ca.crl.published" && a.result == "success" &&
                a.detail.find("reason=import_chain") != std::string::npos &&
                a.detail.find("via=dashboard") != std::string::npos)
                saw = true;
        REQUIRE(saw);
    }

    // Hermes 6c LOW: a CRL-republish failure on a successful dashboard import is
    // SURFACED (the import stands, but the panel warns the CRL is stale).
    h.audits.clear();
    h.crl_succeeds = false;
    auto crlfail = h.sink.dispatch("POST",
                                   "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                                   "", "application/x-www-form-urlencoded", same_origin);
    REQUIRE(crlfail);
    REQUIRE(crlfail->status == 200);                            // import still succeeded
    REQUIRE(crlfail->body.find("CRL could not be republished") != std::string::npos);
    {
        bool saw = false;
        for (const auto& a : h.audits)
            if (a.action == "ca.crl.published" && a.result == "failure" &&
                a.detail.find("reason=import_chain") != std::string::npos)
                saw = true;
        REQUIRE(saw);
    }
    h.crl_succeeds = true;

    // Cross-origin → 403 + csrf.denied, and import_chain_fn must NOT be called.
    const int calls_before = h.import_calls;
    const std::unordered_map<std::string, std::string> cross = {
        {"Host", "yuzu.example"}, {"Origin", "https://evil.example"}};
    auto xo = h.sink.dispatch("POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                              "", "application/x-www-form-urlencoded", cross);
    REQUIRE(xo);
    REQUIRE(xo->status == 403);
    REQUIRE(h.import_calls == calls_before); // gate ran before the import fn
    bool saw_csrf = false;
    for (const auto& a : h.audits)
        if (a.action == "csrf.denied" && a.result == "denied")
            saw_csrf = true;
    REQUIRE(saw_csrf);

    // Both Origin AND Referer absent → also refused (header-stripping proxy/WebView).
    auto noh = h.sink.dispatch("POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                               "", "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"}});
    REQUIRE(noh);
    REQUIRE(noh->status == 403);

    // Same-origin but a validation rejection (KeyMismatch) → 422 with the panel
    // re-rendered (not a bare span).
    h.import_outcome = CaRoutes::ImportOutcome::KeyMismatch;
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                               "", "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad);
    REQUIRE(bad->status == 422);
    REQUIRE(bad->body.find("<table") != std::string::npos); // full fragment re-rendered
}

// ── PR4b dashboard panel (#1241) ────────────────────────────────────────────

TEST_CASE("ca_routes: dashboard revoke refuses a cross-origin POST (H-1 CSRF)",
          "[ca_routes][pki][security][pg]") {
    // H-1: the dashboard revoke is cookie-authed; SameSite=Lax does not block a
    // top-level cross-site form POST, so a forged revoke (= fleet-lockout DoS)
    // must be refused by the Origin/Referer gate + audited csrf.denied, and the
    // cert must NOT be revoked.
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    auto res = h.sink.dispatch(
        "POST", "/api/settings/ca/revoke?serial_hex=DEAD", "", "application/x-www-form-urlencoded",
        {{"Host", "yuzu.example"}, {"Origin", "https://attacker.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(h.store->is_revoked("DEAD")); // not revoked — gate fired first
    bool saw_csrf = false;
    for (const auto& a : h.audits)
        if (a.action == "csrf.denied")
            saw_csrf = true;
    REQUIRE(saw_csrf);
    // The CSRF gate runs BEFORE perm_fn (no perm/role oracle to a cross-site
    // probe), so perm is never consulted on a refused cross-origin request.
    REQUIRE(h.last_perm_type.empty());
}

TEST_CASE("ca_routes: dashboard revoke with NO Origin/Referer is refused (destructive endpoint)",
          "[ca_routes][pki][security][pg]") {
    // Hermes PR4b M: a browser HTMX POST always carries Origin (or Referer), so a
    // request with NEITHER on this DESTRUCTIVE cookie endpoint is treated as
    // cross-site — closing the both-empty gap a header-stripping proxy could ride.
    // (Token automation must use the REST endpoint.)
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("BEEF")));
    h.wire();
    auto res = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=BEEF", "",
                               "application/x-www-form-urlencoded", {{"Host", "yuzu.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(h.store->is_revoked("BEEF"));
}

TEST_CASE("ca_routes: dashboard revoke proceeds for a same-origin POST + re-renders the panel",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    auto res = h.sink.dispatch(
        "POST", "/api/settings/ca/revoke?serial_hex=DEAD&reason=decommissioned", "",
        "application/x-www-form-urlencoded",
        {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.store->is_revoked("DEAD"));                          // revoked
    REQUIRE(res->body.find("Revoked") != std::string::npos);      // panel re-rendered
    REQUIRE(res->body.find("<table") != std::string::npos);       // full fragment, not a bare span
    // The revoke route gates on Security:Delete (not Read) — asserted on the
    // path that actually reaches perm_fn (same-origin).
    REQUIRE(h.last_perm_type == "Security");
    REQUIRE(h.last_perm_op == "Delete");
    // The reason was recorded (UP-7).
    auto rec = h.store->get_issued("DEAD");
    REQUIRE(rec.has_value());
    REQUIRE(rec->has_value());
    REQUIRE((*rec)->revocation_reason == "decommissioned");
}

// The panel's paging hint must not be copy-pasteable as a present-but-empty `offset=` (a 400 since
// #4644). The 500-row cap that triggers it is too costly to seed, so the wording is a free function.
TEST_CASE("ca_issued_paging_hint shows an escaped placeholder and never a bare offset=",
          "[ca_routes][pki][numeric_params]") {
    const auto hint = yuzu::server::ca_issued_paging_hint(500);
    CHECK(hint.find("Showing the first 500 certificates") != std::string::npos);
    CHECK(hint.find("offset=&lt;n&gt;") != std::string::npos);
    CHECK(hint.find("offset=</code>") == std::string::npos);
    CHECK(hint.find("offset=<") == std::string::npos);
}

TEST_CASE("ca_routes: dashboard fragment renders empty-CA + no-root states without crashing",
          "[ca_routes][pki][pg]") {
    {
        Harness h; // no root set
        h.wire();
        auto res = h.sink.Get("/fragments/settings/ca");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(res->body.find("No internal CA") != std::string::npos);
    }
    {
        Harness h;
        h.wire(/*null_store=*/true); // CA store unavailable
        auto res = h.sink.Get("/fragments/settings/ca");
        REQUIRE(res);
        REQUIRE(res->body.find("unavailable") != std::string::npos);
    }
}

// ── gap-matrix #10: code-signing leaf issuance ──────────────────────────────

TEST_CASE("ca_routes: POST /ca/issue-code-signing issues, returns the JSON shape, audits",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    auto ok = h.sink.Post("/api/v1/ca/issue-code-signing",
                          R"({"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nFAKE\n-----END )"
                          R"(CERTIFICATE REQUEST-----\n","label":"build-signer-01",)"
                          R"("validity_days":90})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(h.last_perm_type == "Security");
    REQUIRE(h.last_perm_op == "Write");
    REQUIRE(h.issue_calls == 1);
    REQUIRE(h.last_issue_label == "build-signer-01");
    REQUIRE(h.last_issue_validity_days.has_value());
    REQUIRE(*h.last_issue_validity_days == 90);
    REQUIRE(h.last_issue_csr.find("FAKE") != std::string::npos);

    auto j = json::parse(ok->body);
    REQUIRE(j["certificate_pem"] == h.issue_result->certificate_pem);
    REQUIRE(j["chain_pem"] == h.issue_result->chain_pem);
    REQUIRE(j["serial_hex"] == "C5C1FEED");
    REQUIRE(j["not_after"] == "2027-01-01T00:00:00Z");
    REQUIRE(j["purpose"] == "code-signing");
    REQUIRE(j["meta"]["api_version"] == "v1");

    bool saw_issue = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.issued" && a.result == "success") {
            saw_issue = true;
            REQUIRE(a.target_type == "CodeSigningCertificate");
            REQUIRE(a.target_id == "C5C1FEED");
        }
    }
    REQUIRE(saw_issue);

    // validity_days is optional.
    h.issue_calls = 0;
    auto no_validity = h.sink.Post("/api/v1/ca/issue-code-signing",
                                   R"({"csr_pem":"CSR","label":"another-signer"})");
    REQUIRE(no_validity);
    REQUIRE(no_validity->status == 200);
    REQUIRE(h.issue_calls == 1);
    REQUIRE_FALSE(h.last_issue_validity_days.has_value());
}

// gov HIGH-2 (ADR-1005 "mutations fail closed on audit failure"): a dropped
// ca.cert.issued audit row must withhold the freshly issued certificate — the
// leaf is already durably recorded via record_issued (mirrored here by
// issue_calls==1, since this harness's fake IssueCodeSigningFn stands in for
// that step), but the RESPONSE must never hand back certificate_pem/chain_pem
// on an unaudited 200. Mirrors the #2466/#2406 engine-credential-mint REST
// precedent (`rest_api_v1.cpp`) exactly.
TEST_CASE("ca_routes: POST /ca/issue-code-signing fails closed and withholds the certificate "
          "on a dropped audit row (gov HIGH-2)",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.audit_succeeds = false; // simulate the ca.cert.issued audit write failing
    h.wire();

    auto res = h.sink.Post("/api/v1/ca/issue-code-signing",
                           R"({"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\nFAKE\n-----END )"
                           R"(CERTIFICATE REQUEST-----\n","label":"failclose-signer"})");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    // The certificate is WITHHELD — neither PEM key ever appears in the body,
    // even though issuance itself (the fake fn) was called and "succeeded".
    REQUIRE(h.issue_calls == 1);
    REQUIRE(res->body.find("certificate_pem") == std::string::npos);
    REQUIRE(res->body.find("chain_pem") == std::string::npos);
    REQUIRE(res->body.find("could not be persisted") != std::string::npos);

    bool saw_issue = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.issued" && a.result == "success") {
            saw_issue = true;
            REQUIRE(a.target_type == "CodeSigningCertificate");
        }
    }
    REQUIRE(saw_issue); // the attempt WAS audited (as a row) — persisting it is what failed
}

TEST_CASE("ca_routes: POST /ca/issue-code-signing gates on Security:Write",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.perm_allow = false;
    h.wire();

    auto denied = h.sink.Post("/api/v1/ca/issue-code-signing",
                              R"({"csr_pem":"CSR","label":"signer"})");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
    REQUIRE(h.issue_calls == 0); // gate fired BEFORE the injected fn ran
}

TEST_CASE("ca_routes: POST /ca/issue-code-signing rejects an invalid label",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // Empty, too long (65 chars), and containing a DN-metacharacter / space —
    // none of these ever reach the injected issuance fn.
    const std::string too_long(65, 'a');
    for (const std::string& bad_label :
        {std::string(""), too_long, std::string("has space"), std::string("cn=evil"),
         std::string("yuzu://inst/agent/x")}) {
        h.issue_calls = 0;
        auto j = json::object();
        j["csr_pem"] = "CSR";
        j["label"] = bad_label;
        auto r = h.sink.Post("/api/v1/ca/issue-code-signing", j.dump());
        REQUIRE(r);
        REQUIRE(r->status == 400);
        REQUIRE(h.issue_calls == 0);
    }

    // A conforming label (letters, digits, '.', '_', '-') is accepted.
    auto ok = h.sink.Post("/api/v1/ca/issue-code-signing",
                          R"({"csr_pem":"CSR","label":"build.signer_01-x"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
}

TEST_CASE("ca_routes: POST /ca/issue-code-signing rejects unknown fields + missing csr_pem + "
          "oversized body",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // Mass-assignment guard: an unknown field 400s before the fn runs.
    auto extra = h.sink.Post(
        "/api/v1/ca/issue-code-signing",
        R"({"csr_pem":"CSR","label":"signer","is_admin":true})");
    REQUIRE(extra);
    REQUIRE(extra->status == 400);
    REQUIRE(h.issue_calls == 0);

    // csr_pem is required.
    auto missing = h.sink.Post("/api/v1/ca/issue-code-signing", R"({"label":"signer"})");
    REQUIRE(missing);
    REQUIRE(missing->status == 400);
    REQUIRE(h.issue_calls == 0);

    // Non-integer validity_days is rejected.
    auto bad_validity = h.sink.Post(
        "/api/v1/ca/issue-code-signing",
        R"({"csr_pem":"CSR","label":"signer","validity_days":"90"})");
    REQUIRE(bad_validity);
    REQUIRE(bad_validity->status == 400);
    REQUIRE(h.issue_calls == 0);

    // Oversized body → 413, bounded before the JSON parser (mirrors revoke's
    // Hermes M3 precedent).
    std::string big =
        R"({"csr_pem":")" + std::string(70000, 'x') + R"(","label":"signer"})";
    auto big_res = h.sink.Post("/api/v1/ca/issue-code-signing", big);
    REQUIRE(big_res);
    REQUIRE(big_res->status == 413);
    REQUIRE(h.issue_calls == 0);
}

TEST_CASE("ca_routes: POST /ca/issue-code-signing classifies fn failures via the prefix scheme",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    struct Case {
        std::string error;
        int status;
        const char* result;
    };
    const Case cases[] = {
        {std::string(kCodeSigningNoRootPrefix) + "no CA root", 409, "denied"},
        {std::string(kCodeSigningBadCsrPrefix) + "csr_pem is invalid", 400, "denied"},
        {"failed to record issued certificate", 500, "failure"}, // unprefixed → generic failure
        // gov B1: weak subject key — a distinct classification from bad_csr.
        {std::string(kCodeSigningWeakKeyPrefix) +
             "signing key too weak (RSA must be 2048-16384 bits; EC must be P-256 or "
             "stronger)",
         400, "denied"},
        // gov F6/UP-5/UP-7: business-refusal validity classification — distinct
        // from bad_csr, covering both the range refusal and the CA-expiry
        // refusal (same prefix, two possible detail strings).
        {std::string(kCodeSigningBadValidityPrefix) + "validity_days must be between 1 and 730",
         400, "denied"},
        {std::string(kCodeSigningBadValidityPrefix) + "CA is at or past expiry; cannot issue",
         400, "denied"},
    };
    for (const auto& c : cases) {
        h.audits.clear();
        h.issue_result = std::unexpected(c.error);
        auto r = h.sink.Post("/api/v1/ca/issue-code-signing",
                             R"({"csr_pem":"CSR","label":"signer"})");
        REQUIRE(r);
        REQUIRE(r->status == c.status);
        bool saw = false;
        for (const auto& a : h.audits)
            if (a.action == "ca.cert.issued" && a.result == c.result)
                saw = true;
        REQUIRE(saw);
    }
}

// gov B1/F6: the weak_key/bad_validity messages surfaced to the caller are the
// crafted, caller-safe text AFTER the prefix — never the generic "csr_pem is
// invalid" bad_csr message.
TEST_CASE("ca_routes: POST /ca/issue-code-signing surfaces the weak_key/bad_validity "
          "message verbatim, not the generic bad_csr message",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    h.issue_result = std::unexpected(
        std::string(kCodeSigningWeakKeyPrefix) +
        "signing key too weak (RSA must be 2048-16384 bits; EC must be P-256 or stronger)");
    auto weak = h.sink.Post("/api/v1/ca/issue-code-signing",
                            R"({"csr_pem":"CSR","label":"signer"})");
    REQUIRE(weak);
    REQUIRE(weak->status == 400);
    auto weak_j = json::parse(weak->body);
    const std::string weak_msg = weak_j["error"]["message"].get<std::string>();
    REQUIRE(weak_msg.find("too weak") != std::string::npos);
    REQUIRE(weak_msg.find("csr_pem") == std::string::npos);

    h.issue_result =
        std::unexpected(std::string(kCodeSigningBadValidityPrefix) +
                        "validity_days must be between 1 and 730");
    auto bv = h.sink.Post("/api/v1/ca/issue-code-signing",
                          R"({"csr_pem":"CSR","label":"signer"})");
    REQUIRE(bv);
    REQUIRE(bv->status == 400);
    auto bv_j = json::parse(bv->body);
    const std::string bv_msg = bv_j["error"]["message"].get<std::string>();
    REQUIRE(bv_msg == "validity_days must be between 1 and 730");
}

// gov F6/UP-5/UP-7: the REST handler's OWN pre-check catches an out-of-[1,730]
// validity_days (including a value far outside int32 range) BEFORE the
// injected issuance fn ever runs, and reports the SAME "validity_days must be
// between 1 and 730" message the fn-side classification above produces — not
// the generic bad_csr wording.
TEST_CASE("ca_routes: POST /ca/issue-code-signing rejects an out-of-range validity_days "
          "(0, 731, and a huge value) with the bad_validity message, never bad_csr",
          "[ca_routes][pki][code-signing][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    for (std::string_view validity_days_literal : {"0", "731", "999999999999"}) {
        h.issue_calls = 0;
        const std::string body = R"({"csr_pem":"CSR","label":"signer","validity_days":)" +
                                 std::string(validity_days_literal) + "}";
        auto r = h.sink.Post("/api/v1/ca/issue-code-signing", body);
        REQUIRE(r);
        REQUIRE(r->status == 400);
        REQUIRE(h.issue_calls == 0); // rejected before the injected fn ran
        auto j = json::parse(r->body);
        REQUIRE(j["error"]["message"] == "validity_days must be between 1 and 730");
    }
}


// ── ADR-0070 R2-2: the filtered GET /api/v1/ca/issued (the /crypto Yuzu-issued drill) ─────────

namespace {
std::int64_t wall_now_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

TEST_CASE("ca_routes: filtered /ca/issued lists the rows behind a count, audited, pinned paging",
          "[ca_routes][pki][pg][crypto]") {
    Harness h;
    h.wire();
    const auto now = wall_now_s();
    for (int i = 0; i < 3; ++i) {
        auto r = sample_issued("F" + std::to_string(i));
        r.issued_at = now - 3600;
        r.not_after = now + (i + 1) * 86400;
        REQUIRE(h.store->record_issued(r));
    }
    auto r = sample_issued("AB1");
    r.issued_at = now - 10 * 86400;
    r.status = CertStatus::Revoked;
    r.revoked_at = now - 3600;
    r.revocation_reason = std::string(kRevokeReasonSuperseded);
    REQUIRE(h.store->record_issued(r));

    auto res = h.sink.Get("/api/v1/ca/issued?kind=expiring&days=3&limit=2");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["count"] == 2);
    CHECK(j["meta"]["has_more"] == true);
    CHECK_FALSE(j["meta"].contains("next_offset"));
    REQUIRE(j["next_cursor"].is_string());
    const std::string cursor = j["next_cursor"].get<std::string>();
    CHECK(j["filter"]["total"] == 3);
    CHECK(j["filter"]["kind"] == "expiring");
    CHECK(j["filter"]["rule_id"] == "yuzu_ca_expiring");
    const auto as_of = j["filter"]["as_of"].get<std::int64_t>();
    CHECK(h.last_perm_type == "Security");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.certificates.view");
    CHECK(h.audits[0].result == "success");

    // Page two is the keyset cursor (H2): it carries the same snapshot; the last page's
    // next_cursor is null.
    res = h.sink.Get("/api/v1/ca/issued?kind=expiring&days=3&limit=2&cursor=" + cursor);
    REQUIRE(res->status == 200);
    j = nlohmann::json::parse(res->body);
    CHECK(j["count"] == 1);
    CHECK(j["items"][0]["serial_hex"] == "F2");
    CHECK(j["filter"]["as_of"] == as_of);
    CHECK(j["meta"]["has_more"] == false);
    CHECK(j["next_cursor"].is_null());
    CHECK_THAT(h.audits.back().detail, Catch::Matchers::ContainsSubstring("page=continuation"));
    // The cursor bound to another filter, or tampered, is a 400 naming it.
    for (const std::string& q : {"kind=expiring&days=7&cursor=" + cursor,
                                "kind=expiring&days=3&cursor=" + cursor + "A",
                                std::string("kind=expiring&days=3&cursor=c1:nope")}) {
        INFO(q);
        res = h.sink.Get("/api/v1/ca/issued?" + q);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_THAT(nlohmann::json::parse(res->body)["error"]["message"].get<std::string>(),
                   Catch::Matchers::ContainsSubstring("cursor"));
    }

    // Bucket filter: the superseded revocation, with its recorded reason on the row.
    res = h.sink.Get("/api/v1/ca/issued?kind=revoked&days=7&bucket=superseded");
    REQUIRE(res->status == 200);
    j = nlohmann::json::parse(res->body);
    REQUIRE(j["count"] == 1);
    CHECK(j["items"][0]["serial_hex"] == "AB1");
    CHECK(j["items"][0]["revocation_reason"] == "superseded");
    // Expired/expiring cover active only: the revoked row is in no expiry window.
    res = h.sink.Get("/api/v1/ca/issued?kind=expired&days=90");
    CHECK(nlohmann::json::parse(res->body)["count"] == 0);
}

TEST_CASE("ca_routes: filtered /ca/issued refuses each malformed parameter by name (400)",
          "[ca_routes][pki][pg][crypto]") {
    Harness h;
    h.wire();
    const auto now = wall_now_s();
    struct Bad {
        std::string q;
        const char* names;
    };
    const std::vector<Bad> bad{
        {"kind=weak", "kind"},
        {"days=7", "kind"},
        {"kind=expiring&days=45", "days"},
        {"kind=active&days=7", "days"},
        {"kind=issued_week&week=2026-W54", "week"},
        {"kind=active&bucket=other", "bucket"},
        {"kind=active&limit=0", "limit"},
        {"kind=active&limit=501", "limit"},
        {"kind=active&offset=abc", "offset"},
        {"kind=active&offset=2", "offset"}, // keyset paging only (H2)
        {"kind=active&cursor=c1:bogus", "cursor"},
        {"kind=active&as_of=abc", "as_of"},
        {"kind=active&as_of=" + std::to_string(now + 3600), "as_of"},
        {"kind=active&as_of=" + std::to_string(now - 8 * 86400), "as_of"},
    };
    for (const auto& b : bad) {
        INFO(b.q);
        auto res = h.sink.Get("/api/v1/ca/issued?" + b.q);
        REQUIRE(res);
        CHECK(res->status == 400);
        // L6: the PARSED A4 error.message names the offending parameter (not just the body).
        auto err = nlohmann::json::parse(res->body);
        REQUIRE(err["error"]["message"].is_string());
        CHECK_THAT(err["error"]["message"].get<std::string>(),
                   Catch::Matchers::ContainsSubstring(b.names));
        CHECK(err["error"]["retry_after_ms"].is_null());
    }
    CHECK(h.audits.empty());
}

TEST_CASE("ca_routes: /ca/issued without a session is 401, filtered or not, with no read",
          "[ca_routes][pki][pg][crypto]") {
    // L6 (qe-9): the auth answer comes first - no confinement probe, no audit row, no store read.
    Harness h;
    h.unauthenticated = true;
    h.wire();
    for (const char* path : {"/api/v1/ca/issued", "/api/v1/ca/issued?kind=active"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    CHECK(h.standing_calls == 0);
    CHECK(h.audits.empty());
}

TEST_CASE("ca_routes: a confined Security:Read holder is withheld the filtered AND the unfiltered "
          "list, each audited denied",
          "[ca_routes][pki][pg][crypto][security]") {
    Harness h;
    h.standing = yuzu::server::crypto_widgets::Access::kConfined;
    h.wire();
    REQUIRE(h.store->record_issued(sample_issued("C1")));
    auto filtered = h.sink.Get("/api/v1/ca/issued?kind=active");
    REQUIRE(filtered);
    CHECK(filtered->status == 403);
    const auto j = nlohmann::json::parse(filtered->body);
    CHECK_FALSE(j["error"].contains("permission"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "denied");
    // The denied row names the list with its own target, in the one shared detail shape.
    CHECK(h.audits[0].target_id == "filtered");
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("ws="));
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("withheld=confined"));
    // The unfiltered inventory is the same fleet-wide per-agent data: same answer, same verb.
    auto plain = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(plain);
    CHECK(plain->status == 403);
    const auto pj = nlohmann::json::parse(plain->body);
    CHECK_FALSE(pj["error"].contains("permission"));
    CHECK(plain->body.find("agent-C1") == std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "crypto.ca.certificates.view");
    CHECK(h.audits[1].result == "denied");
}

TEST_CASE("ca_routes: an unconfined unfiltered /ca/issued is served and audited success; a "
          "dropped audit row is reported, not fatal",
          "[ca_routes][pki][pg][crypto][security]") {
    Harness h;
    h.wire();
    REQUIRE(h.store->record_issued(sample_issued("C2")));
    auto ok = h.sink.Get("/api/v1/ca/issued?limit=5");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("Sec-Audit-Failed").empty());
    CHECK_FALSE(nlohmann::json::parse(ok->body).contains("audit_persisted"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "crypto.ca.certificates.view");
    CHECK(h.audits[0].result == "success");
    CHECK_THAT(h.audits[0].detail,
               Catch::Matchers::ContainsSubstring("inventory rows=1 limit=5 offset=0"));
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("cid="));
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("standing=available"));

    // The filtered list's policy, mirrored: the page is served and the response is marked.
    h.audit_succeeds = false;
    auto marked = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(marked);
    CHECK(marked->status == 200);
    CHECK(marked->get_header_value("Sec-Audit-Failed") == "true");
    const auto mj = nlohmann::json::parse(marked->body);
    CHECK(mj["audit_persisted"] == false);
    CHECK(mj["count"] == 1);
}

TEST_CASE("ca_routes: the FILTERED list names its standing on the success row",
          "[ca_routes][pki][pg][crypto][security]") {
    // The detective control for a list served to a caller the access check admitted nobody for
    // is a token on the success row; assert it on the filtered REST form too, not only the
    // unfiltered one.
    using yuzu::server::crypto_widgets::Access;
    Harness h;
    h.wire();
    REQUIRE(h.store->record_issued(sample_issued("C5")));
    auto avail = h.sink.Get("/api/v1/ca/issued?kind=active");
    REQUIRE(avail);
    CHECK(avail->status == 200);
    h.standing = Access::kRefused;
    auto refused = h.sink.Get("/api/v1/ca/issued?kind=active");
    REQUIRE(refused);
    CHECK(refused->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "success");
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("standing=available"));
    CHECK(h.audits[1].result == "success");
    CHECK_THAT(h.audits[1].detail, Catch::Matchers::ContainsSubstring("standing=refused"));
}

namespace {

// Make CaStore::list_issued fail by renaming its table away through a separate connection,
// restored on scope exit (the harness database is a private clone, so nothing else sees it).
class IssuedTableGone {
public:
    explicit IssuedTableGone(const std::string& dsn) : dsn_(dsn) {
        run("ALTER TABLE ca_store.ca_issued RENAME TO ca_issued_r2_gone");
    }
    ~IssuedTableGone() { run("ALTER TABLE ca_store.ca_issued_r2_gone RENAME TO ca_issued"); }
    IssuedTableGone(const IssuedTableGone&) = delete;
    IssuedTableGone& operator=(const IssuedTableGone&) = delete;

private:
    void run(const char* sql) {
        pg::PgConn conn{PQconnectdb(dsn_.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(), sql)};
        REQUIRE(r.ok());
    }
    std::string dsn_;
};

} // namespace

TEST_CASE("ca_routes: the unfiltered list answers a retryable 503 and a failure row when the "
          "store read fails",
          "[ca_routes][pki][pg][crypto][security]") {
    Harness h;
    h.wire();
    REQUIRE(h.store->record_issued(sample_issued("C6")));
    {
        IssuedTableGone gone(h.db_holder->dsn());
        auto res = h.sink.Get("/api/v1/ca/issued");
        REQUIRE(res);
        CHECK(res->status == 503);
        const auto j = nlohmann::json::parse(res->body);
        CHECK(j["error"]["retry_after_ms"] == 5000);
        CHECK(res->body.find("agent-C6") == std::string::npos);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "crypto.ca.certificates.view");
        CHECK(h.audits[0].result == "failure");
        CHECK(h.audits[0].target_id == "inventory");
        CHECK_THAT(h.audits[0].detail,
                   Catch::Matchers::ContainsSubstring("inventory store unavailable"));
        CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("cid="));
    }
    // Restored: the same call is served again.
    auto back = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(back);
    CHECK(back->status == 200);
}

TEST_CASE("ca_routes: filtered /ca/issued fails closed when unwired or degraded",
          "[ca_routes][pki][pg][crypto]") {
    {
        Harness h;
        h.wire_filtered = false;
        h.wire();
        auto res = h.sink.Get("/api/v1/ca/issued?kind=active");
        CHECK(res->status == 503);
        // L3: a wiring fault lasts until a restart - no retry hint.
        CHECK(nlohmann::json::parse(res->body)["error"]["retry_after_ms"].is_null());
        // The unfiltered inventory needs the same probe: it fails closed too, never open.
        auto plain = h.sink.Get("/api/v1/ca/issued");
        CHECK(plain->status == 503);
        CHECK(nlohmann::json::parse(plain->body)["error"]["retry_after_ms"].is_null());
    }
    {
        Harness h;
        h.standing = yuzu::server::crypto_widgets::Access::kDegraded;
        h.wire();
        CHECK(h.sink.Get("/api/v1/ca/issued?kind=active")->status == 503);
        CHECK(h.sink.Get("/api/v1/ca/issued")->status == 503);
        // Both forms audit the access-check failure, each under its own target.
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "failure");
        CHECK(h.audits[0].target_id == "filtered");
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].target_id == "inventory");
    }
    {
        Harness h;
        h.perm_allow = false;
        h.wire();
        CHECK(h.sink.Get("/api/v1/ca/issued?kind=active")->status == 403);
        CHECK(h.standing_calls == 0); // Security:Read first
    }
}
// ── System > Certificates and secrets: the `?view=pki` shape (SYS-3) ─────────
//
// The default shape (`render_ca_fragment`) is exercised by the cases above and is
// deliberately unchanged; these pin that `view=pki` selects the artboard panels, that the
// two wrappers re-render in the shape they were called from, and that every non-2xx
// wrapper branch reaches the operator through an HX-Trigger toast (htmx drops 4xx/5xx
// bodies, so before this a failed revoke or import showed nothing).

TEST_CASE("ca_routes: ?view=pki renders the artboard panels; the default shape is unchanged",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    IssuedCertRecord evil = sample_issued("CAFE");
    evil.subject = "<script>alert(1)</script>";
    REQUIRE(h.store->record_issued(evil));
    IssuedCertRecord lapsed = sample_issued("E0D1");
    lapsed.not_after = 1;
    REQUIRE(h.store->record_issued(lapsed));
    h.wire();

    auto pki = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(pki);
    REQUIRE(pki->status == 200);
    CHECK(pki->body.find("class=\"grid2\"") != std::string::npos);
    CHECK(pki->body.find("<h2>Revocation</h2>") != std::string::npos);
    CHECK(pki->body.find("name=\"view\" value=\"pki\"") != std::string::npos);
    CHECK(pki->body.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
    CHECK(pki->body.find("<script>alert(1)") == std::string::npos);
    // The lapsed leaf is Expired in the new shape...
    CHECK(pki->body.find(">Expired</span>") != std::string::npos);
    // ...and no CRL has been published in this fixture: honest sentence, no dead link.
    CHECK(pki->body.find("None published, or the store could not be read") != std::string::npos);
    CHECK(pki->body.find("href=\"/api/v1/ca/crl\"") == std::string::npos);

    // Without the parameter, byte-for-byte the Settings panel: none of the new markup.
    auto old = h.sink.Get("/fragments/settings/ca");
    REQUIRE(old);
    CHECK(old->body.find("grid2") == std::string::npos);
    CHECK(old->body.find("user-table") != std::string::npos);
    CHECK(old->body.find("name=\"view\"") == std::string::npos);
    CHECK(old->body.find("role-badge role-admin\">Active") != std::string::npos);
}

TEST_CASE("ca_routes: ?view=pki is gated on Security:Read like the default shape",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    h.perm_allow = false;
    auto r = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("ca_routes: a published CRL shows its figures and the download link in view=pki",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x03, 0x01, 0x02, 0x03};
    crl.this_update = 1'800'000'000;
    crl.next_update = 1'800'086'400;
    crl.published_at = 1'800'000'000;
    crl.revoked_count = 0;
    REQUIRE(h.store->record_crl_for_test(crl));
    h.wire();

    auto r = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(r);
    CHECK(r->body.find("2027-01-15 08:00 UTC") != std::string::npos);
    CHECK(r->body.find("version 1") != std::string::npos);
    CHECK(r->body.find("href=\"/api/v1/ca/crl\"") != std::string::npos);
    // A count of 0 that WAS recorded is "0"; only a missing count is "Not recorded".
    CHECK(r->body.find("<span>Revoked entries</span><b>0</b>") != std::string::npos);
}

TEST_CASE("ca_routes: wrapper errors carry a toast trigger and re-render the shape asked for",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};

    // pki view: invalid serial -> 400, toast header, panel re-rendered in the pki shape.
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz&view=pki", "",
                               "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad);
    CHECK(bad->status == 400);
    const auto trig = bad->get_header_value("HX-Trigger");
    REQUIRE_FALSE(trig.empty());
    const auto toast = json::parse(trig);
    CHECK(toast["showToast"]["level"] == "error");
    CHECK(toast["showToast"]["message"] == "Invalid certificate serial.");
    CHECK(bad->body.find("grid2") != std::string::npos);

    // Default view: same trigger (the Settings page has the listener), old shape kept.
    auto bad_old = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz", "",
                                   "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad_old);
    CHECK(bad_old->status == 400);
    CHECK_FALSE(bad_old->get_header_value("HX-Trigger").empty());
    CHECK(bad_old->body.find("grid2") == std::string::npos);
    CHECK(bad_old->body.find("<table") != std::string::npos);

    // An unknown serial is a 404 toast, not a silent success.
    auto missing = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=FEED&view=pki", "",
                                   "application/x-www-form-urlencoded", same_origin);
    REQUIRE(missing);
    CHECK(missing->status == 404);
    CHECK_FALSE(missing->get_header_value("HX-Trigger").empty());
}

TEST_CASE("ca_routes: a successful revoke in view=pki re-renders the pki shape without a toast",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    auto ok = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD&view=pki", "",
                              "application/x-www-form-urlencoded",
                              {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->get_header_value("HX-Trigger").empty());
    CHECK(ok->body.find("grid2") != std::string::npos);
    CHECK(ok->body.find(">Revoked</span>") != std::string::npos);
    CHECK(h.store->is_revoked("DEAD"));
}

TEST_CASE("ca_routes: a permission refusal on a wrapper carries a toast; a form body selects the pki shape",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};

    // htmx drops a 4xx body, so the permission refusal must reach the operator as a toast.
    h.perm_allow = false;
    auto denied = h.sink.dispatch("POST", "/api/settings/ca/revoke", "serial_hex=DEAD&view=pki",
                                  "application/x-www-form-urlencoded", same_origin);
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK_FALSE(denied->get_header_value("HX-Trigger").empty());
    CHECK_FALSE(h.store->is_revoked("DEAD"));
    auto denied_imp = h.sink.dispatch("POST", "/api/settings/ca/import-chain",
                                      "intermediate_pem=X&chain_pem=Y&view=pki",
                                      "application/x-www-form-urlencoded", same_origin);
    REQUIRE(denied_imp);
    CHECK(denied_imp->status == 403);
    CHECK_FALSE(denied_imp->get_header_value("HX-Trigger").empty());
    CHECK(h.import_calls == 0);

    // The forms POST their fields in the body, not the query string.
    h.perm_allow = true;
    auto rv = h.sink.dispatch("POST", "/api/settings/ca/revoke", "serial_hex=DEAD&view=pki",
                              "application/x-www-form-urlencoded", same_origin);
    REQUIRE(rv);
    CHECK(rv->status == 200);
    CHECK(rv->body.find("grid2") != std::string::npos);
    CHECK(h.store->is_revoked("DEAD"));
    auto imp = h.sink.dispatch("POST", "/api/settings/ca/import-chain",
                               "intermediate_pem=X&chain_pem=Y&view=pki",
                               "application/x-www-form-urlencoded", same_origin);
    REQUIRE(imp);
    CHECK(imp->status == 200);
    CHECK(imp->body.find("grid2") != std::string::npos);
    CHECK(h.import_calls == 1);
}

TEST_CASE("ca_routes: the cross-origin refusal keeps its bare body and never re-renders",
          "[ca_routes][pki][security][pg]") {
    // Re-rendering the inventory here would hand a cross-site probe a view of it before the
    // permission check; a toast header would also suggest the request was processed.
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    auto res = h.sink.dispatch(
        "POST", "/api/settings/ca/revoke?serial_hex=DEAD&view=pki", "",
        "application/x-www-form-urlencoded",
        {{"Host", "yuzu.example"}, {"Origin", "https://attacker.example"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body == "<span class=\"feedback-error\">Cross-origin request refused.</span>");
    CHECK(res->get_header_value("HX-Trigger").empty());
    CHECK_FALSE(h.store->is_revoked("DEAD"));
}

TEST_CASE("ca_routes: import wrapper in view=pki re-renders the pki shape and toasts failures",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};

    // Missing PEMs: 400 with the toast and the pki shape.
    auto none = h.sink.dispatch("POST", "/api/settings/ca/import-chain?view=pki", "",
                                "application/x-www-form-urlencoded", same_origin);
    REQUIRE(none);
    CHECK(none->status == 400);
    CHECK_FALSE(none->get_header_value("HX-Trigger").empty());
    CHECK(none->body.find("grid2") != std::string::npos);

    // Success: the pki shape is re-rendered (the import fake returns Ok by default).
    auto ok = h.sink.dispatch(
        "POST", "/api/settings/ca/import-chain?view=pki&intermediate_pem=X&chain_pem=Y", "",
        "application/x-www-form-urlencoded", same_origin);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.import_calls == 1);
    CHECK(ok->body.find("grid2") != std::string::npos);
    CHECK(ok->get_header_value("HX-Trigger").empty());
}

TEST_CASE("ca_routes: /ca/issued meta and the MCP-shared figures carry the CRL fields",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // No CRL yet: every figure present and null, stale true (no list covers anything).
    auto none = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(none);
    auto m = json::parse(none->body)["meta"];
    for (const char* k : {"crl_version", "crl_published_at", "crl_next_update", "crl_revoked_count"}) {
        INFO(k);
        REQUIRE(m.contains(k));
        CHECK(m[k].is_null());
    }
    REQUIRE(m.contains("crl_stale"));

    CrlVersionRecord crl;
    crl.version = 3;
    crl.der = {0x30, 0x03, 0x01, 0x02, 0x03};
    crl.this_update = 1000;
    crl.next_update = 2000;
    crl.published_at = 1000;
    crl.revoked_count = 0;
    REQUIRE(h.store->record_crl_for_test(crl));
    auto some = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(some);
    auto m2 = json::parse(some->body)["meta"];
    CHECK(m2["crl_version"] == 3);
    CHECK(m2["crl_published_at"] == 1000);
    CHECK(m2["crl_next_update"] == 2000);
    CHECK(m2["crl_revoked_count"] == 0);
    CHECK(m2["crl_stale"] == false);

    // The shared builder is what the MCP twin merges: same keys, same values.
    const auto figs = crl_figures_json(*h.store);
    CHECK(figs["crl_version"] == 3);
    CHECK(figs["crl_stale"] == false);
}

TEST_CASE("ca_routes: no key path, key material or PEM reaches the pki fragment, the inventory or an error body",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    CaRoot root = sample_root();
    root.key_ref = "/var/lib/yuzu/SENTINEL-ca-signing.key";
    root.cert_pem = "-----BEGIN CERTIFICATE-----\nSENTINELCERTBODY\n-----END CERTIFICATE-----\n";
    REQUIRE(h.store->set_root(root));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};

    std::vector<std::string> bodies;
    auto grab = [&](const httplib::Response* r) {
        REQUIRE(r != nullptr);
        bodies.push_back(r->body);
        for (const auto& hd : r->headers)
            bodies.push_back(hd.first + ": " + hd.second);
    };
    auto frag = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(frag);
    grab(&*frag);
    auto inv = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(inv);
    grab(&*inv);
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz&view=pki", "",
                               "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad);
    grab(&*bad);
    auto none = h.sink.dispatch("POST", "/api/settings/ca/import-chain?view=pki", "",
                                "application/x-www-form-urlencoded", same_origin);
    REQUIRE(none);
    grab(&*none);

    REQUIRE(bodies.size() > 4);
    for (const auto& b : bodies) {
        CHECK(b.find("SENTINEL") == std::string::npos); // key_ref path and the stored PEM body
        CHECK(b.find("PRIVATE KEY") == std::string::npos);
        CHECK(b.find("passphrase") == std::string::npos);
    }
}

TEST_CASE("ca_routes: the revocation pill follows the revoked set and the list's own expiry",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    REQUIRE(h.store->revoke("DEAD", "test"));
    h.wire();

    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x03, 0x01, 0x02, 0x03};
    crl.this_update = 1000;
    crl.next_update = 9'999'999'999; // far future
    crl.published_at = 1000;
    crl.revoked_count = 0; // built before the revocation: it is not on the list
    REQUIRE(h.store->record_crl_for_test(crl));
    auto stale = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(stale);
    CHECK(stale->body.find("Out of date") != std::string::npos);
    CHECK(stale->body.find(">Current</span>") == std::string::npos);
    CHECK(json::parse(h.sink.Get("/api/v1/ca/issued")->body)["meta"]["crl_stale"] == true);

    // A list covering the revoked set is Current while it is within its validity...
    crl.version = 2;
    crl.revoked_count = 1;
    REQUIRE(h.store->record_crl_for_test(crl));
    auto current = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(current);
    CHECK(current->body.find(">Current</span>") != std::string::npos);
    CHECK(json::parse(h.sink.Get("/api/v1/ca/issued")->body)["meta"]["crl_stale"] == false);

    // ...and never once its next update has passed, even with matching counts.
    crl.version = 3;
    crl.next_update = 2000;
    REQUIRE(h.store->record_crl_for_test(crl));
    auto lapsed = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(lapsed);
    CHECK(lapsed->body.find("Expired list") != std::string::npos);
    CHECK(lapsed->body.find(">Current</span>") == std::string::npos);
}

TEST_CASE("ca_routes: a lapsed list reads Expired even when it is also behind the revoked set",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    REQUIRE(h.store->revoke("DEAD", "test"));
    h.wire();
    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x03, 0x01, 0x02, 0x03};
    crl.this_update = 1000;
    crl.next_update = 2000; // long past
    crl.published_at = 1000;
    crl.revoked_count = 0; // behind the revoked set as well
    REQUIRE(h.store->record_crl_for_test(crl));
    auto page = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(page);
    CHECK(page->body.find("Expired list") != std::string::npos);
    CHECK(page->body.find("Out of date") == std::string::npos);

    // Same for a row with no recorded count (the "not confirmed" arm).
    crl.version = 2;
    crl.revoked_count.reset();
    REQUIRE(h.store->record_crl_for_test(crl));
    auto page2 = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(page2);
    CHECK(page2->body.find("Expired list") != std::string::npos);
    CHECK(page2->body.find("Not confirmed current") == std::string::npos);
}

TEST_CASE("ca_routes: a pre-count CRL row reports a null revoked count, not 0",
          "[ca_routes][pki][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    CrlVersionRecord crl;
    crl.version = 1;
    crl.der = {0x30, 0x03, 0x01, 0x02, 0x03};
    crl.this_update = 1'800'000'000;
    crl.next_update = 1'800'086'400;
    crl.published_at = 1'800'000'000;
    // revoked_count left nullopt: a list published before counts were recorded.
    REQUIRE(h.store->record_crl_for_test(crl));
    h.wire();

    auto r = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(r);
    CHECK(json::parse(r->body)["meta"]["crl_revoked_count"].is_null());
    auto page = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(page);
    CHECK(page->body.find("Not recorded") != std::string::npos);
    CHECK(page->body.find("Not confirmed current") != std::string::npos);
}

// ── Wrapper replies carry the CA panel only for a caller who may read it ────────────────────

namespace {

// Strings that only the rendered panel can contain: the seeded cert's serial and subject, the
// panel's own table, and the CRL figures block.
void check_no_inventory(const std::string& body) {
    CHECK(body.find("agent-DEAD") == std::string::npos);
    CHECK(body.find("DEAD</") == std::string::npos);
    CHECK(body.find("<table") == std::string::npos);
    CHECK(body.find("Revocation") == std::string::npos);
    CHECK(body.find("Fingerprint") == std::string::npos);
}

const std::unordered_map<std::string, std::string> kSameOrigin = {{"Host", "yuzu.example"},
                                                                  {"Origin", "https://yuzu.example"}};

} // namespace

TEST_CASE("ca_routes: revoke wrapper without Security:Read confirms the revoke and never shows the panel",
          "[ca_routes][pki][security][pg]") {
    for (const char* view : {"", "&view=pki"}) {
        Harness h;
        REQUIRE(h.store->set_root(sample_root()));
        REQUIRE(h.store->record_issued(sample_issued("DEAD")));
        h.deny_ops = {"Read"};
        h.wire();
        const std::string v = view;

        // Error path: invalid serial -> 400, toast kept, banner only.
        auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz" + v, "",
                                   "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(bad);
        CHECK(bad->status == 400);
        CHECK(bad->body.find("Invalid certificate serial.") != std::string::npos);
        CHECK_FALSE(bad->get_header_value("HX-Trigger").empty());
        check_no_inventory(bad->body);
        CHECK(bad->body.find("alert-success") == std::string::npos); // an error is not confirmed
        CHECK_THAT(bad->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("\"level\":\"error\""));

        // Success path: still revokes (Delete is held), reply is not the panel, but the
        // mutation is confirmed (banner + success toast) so the caller is not left guessing.
        auto ok = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD" + v, "",
                                  "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(h.store->is_revoked("DEAD"));
        check_no_inventory(ok->body);
        CHECK(ok->body.find("alert-success") != std::string::npos);
        CHECK(ok->body.find("Certificate revoked.") != std::string::npos);
        CHECK(ok->body.find("not shown to this account") != std::string::npos);
        CHECK(ok->body.find("see the note below") == std::string::npos);
        CHECK_THAT(ok->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("\"level\":\"success\""));
        CHECK_THAT(ok->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("Certificate revoked."));
        CHECK(ok->get_header_value("HX-Trigger").find("below") == std::string::npos);
    }
}

TEST_CASE("ca_routes: import wrapper without Security:Read confirms the import, never the inventory",
          "[ca_routes][pki][subordinate][security][pg]") {
    for (const char* view : {"", "&view=pki"}) {
        Harness h;
        REQUIRE(h.store->set_root(sample_root()));
        REQUIRE(h.store->record_issued(sample_issued("DEAD")));
        h.deny_ops = {"Read"};
        h.wire();
        const std::string v = view;

        auto none = h.sink.dispatch("POST", "/api/settings/ca/import-chain?x=1" + v, "",
                                    "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(none);
        CHECK(none->status == 400);
        CHECK(none->body.find("required") != std::string::npos);
        CHECK_FALSE(none->get_header_value("HX-Trigger").empty());
        check_no_inventory(none->body);

        h.import_outcome = CaRoutes::ImportOutcome::Ok;
        auto ok = h.sink.dispatch(
            "POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR" + v, "",
            "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(h.import_calls == 1);
        check_no_inventory(ok->body);
        CHECK(ok->body.find("alert-success") != std::string::npos);
        CHECK(ok->body.find("Signed chain imported") != std::string::npos);
        CHECK(ok->body.find("not shown to this account") != std::string::npos);
        CHECK(ok->body.find("see the note below") == std::string::npos);
        CHECK_THAT(ok->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("\"level\":\"success\""));
        CHECK(ok->get_header_value("HX-Trigger").find("below") == std::string::npos);
    }
}

TEST_CASE("ca_routes: wrappers with a Read-holding caller still return the panel; no-store set",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz&view=pki", "",
                               "application/x-www-form-urlencoded", kSameOrigin);
    REQUIRE(bad);
    CHECK(bad->body.find("agent-DEAD") != std::string::npos);
    CHECK(bad->get_header_value("Cache-Control") == "no-store");
    h.import_outcome = CaRoutes::ImportOutcome::Ok;
    auto imp = h.sink.dispatch(
        "POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR&view=pki", "",
        "application/x-www-form-urlencoded", kSameOrigin);
    REQUIRE(imp);
    CHECK(imp->body.find("agent-DEAD") != std::string::npos);
    CHECK(imp->get_header_value("Cache-Control") == "no-store");
}

TEST_CASE("ca_routes: wrappers fail closed when no read probe is wired",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.probe_wired = false;
    h.wire();
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz", "",
                               "application/x-www-form-urlencoded", kSameOrigin);
    REQUIRE(bad);
    CHECK(bad->status == 400);
    check_no_inventory(bad->body);
}

TEST_CASE("ca_routes: the CA fragment is no-store, and refuses a caller without Security:Read",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();
    for (const char* path : {"/fragments/settings/ca", "/fragments/settings/ca?view=pki"}) {
        auto frag = h.sink.Get(path);
        REQUIRE(frag);
        CHECK(frag->status == 200);
        CHECK(frag->get_header_value("Cache-Control") == "no-store");
    }
    h.deny_ops = {"Read"};
    auto denied = h.sink.Get("/fragments/settings/ca?view=pki");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    check_no_inventory(denied->body);
}

// ── The Security:Read inventory is fleet-wide: confined callers are withheld (no Postgres) ────
//
// These register CaRoutes with NO CaStore. A confined or degraded caller must be answered before
// the store is touched, so the answers below hold with none, and no `failure` row for an
// unavailable store may appear beside the `denied` row.

namespace {

struct ProbeHarness {
    test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    yuzu::server::crypto_widgets::Access standing{yuzu::server::crypto_widgets::Access::kAvailable};
    bool wire_probe{true};
    bool audit_succeeds{true};
    bool can_read{true};   // perm_fn (every securable)
    bool probe_read{true}; // the quiet Security:Read probe the wrappers ask
    int standing_calls{0};
    int perm_calls{0};

    void wire() {
        CaRoutes routes;
        CaRoutes::AuthFn auth = [](const httplib::Request&,
                                   httplib::Response&) -> std::optional<auth::Session> {
            return std::nullopt;
        };
        CaRoutes::PermFn perm = [this](const httplib::Request&, httplib::Response& res,
                                       const std::string&, const std::string&) {
            ++perm_calls;
            if (!can_read) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
                return false;
            }
            return true;
        };
        CaRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                         const std::string& r, const std::string& tt,
                                         const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        if (wire_probe)
            routes.set_filtered_issued(CaRoutes::FilteredIssuedDeps{
                .api = nullptr, .confinement_fn = [this](const httplib::Request&) {
                    ++standing_calls;
                    return standing;
                }});
        routes.set_read_probe([this](const httplib::Request&) { return probe_read; });
        routes.register_routes(
            sink, auth, perm, audit, /*ca_store=*/nullptr,
            []() -> std::optional<std::vector<std::uint8_t>> { return std::nullopt; },
            []() -> std::optional<std::string> { return std::nullopt; },
            [](const std::string&, const std::string&) { return CaRoutes::ImportOutcome::Ok; },
            [](const std::string&, const std::string&, std::optional<int>,
               const std::string&) -> std::expected<CodeSigningIssuance, std::string> {
                return std::unexpected(std::string("unused"));
            });
    }
};

constexpr std::string_view kWithheld = yuzu::server::crypto_widgets::kConfinedWithheldMessage;

} // namespace

TEST_CASE("ca_routes: a confined caller is withheld the unfiltered /ca/issued before any parameter "
          "or store is read, and the denial is audited",
          "[ca_routes][pki][crypto][security]") {
    ProbeHarness h;
    h.standing = yuzu::server::crypto_widgets::Access::kConfined;
    h.wire();
    // The malformed limit would be a 400 if the parameters were read first.
    for (const char* path : {"/api/v1/ca/issued", "/api/v1/ca/issued?limit=5&offset=2",
                             "/api/v1/ca/issued?limit=abc"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->get_header_value("Cache-Control") == "no-store, private");
        const auto j = json::parse(res->body);
        CHECK(j["error"]["message"] == std::string(kWithheld));
        CHECK_FALSE(j["error"].contains("permission")); // none would admit this caller
        CHECK(res->body.find("items") == std::string::npos);
    }
    REQUIRE(h.audits.size() == 3);
    for (const auto& a : h.audits) {
        CHECK(a.action == "crypto.ca.certificates.view");
        CHECK(a.result == "denied");
        CHECK(a.target_type == "Security");
        // One detail shape across surfaces (audit_detail_ca_withheld, as crypto.ca.stats.view
        // writes it) and a target, so a refused unfiltered call is distinguishable from a
        // refused filtered one.
        CHECK(a.target_id == "inventory");
        CHECK_THAT(a.detail, Catch::Matchers::ContainsSubstring("withheld=confined"));
        CHECK_THAT(a.detail, Catch::Matchers::ContainsSubstring("cid="));
        CHECK_THAT(a.detail, Catch::Matchers::ContainsSubstring("ws="));
    }
}

TEST_CASE("ca_routes: the unfiltered /ca/issued fails closed when the standing probe is degraded or "
          "unwired, and asks Security:Read first",
          "[ca_routes][pki][crypto][security]") {
    {
        ProbeHarness h;
        h.standing = yuzu::server::crypto_widgets::Access::kDegraded;
        h.wire();
        auto res = h.sink.Get("/api/v1/ca/issued");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(json::parse(res->body)["error"]["retry_after_ms"] == 5000);
        // The access check could not be completed: audited failure, as crypto.ca.stats.view does
        // (a gate that cannot answer is evidence an auditor needs), naming the access check.
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "crypto.ca.certificates.view");
        CHECK(h.audits[0].result == "failure");
        CHECK(h.audits[0].target_id == "inventory");
        CHECK_THAT(h.audits[0].detail,
                   Catch::Matchers::ContainsSubstring("access check unavailable"));
        CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("cid="));
    }
    {
        ProbeHarness h;
        h.wire_probe = false;
        h.wire();
        auto res = h.sink.Get("/api/v1/ca/issued");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(json::parse(res->body)["error"]["retry_after_ms"].is_null());
        CHECK(h.audits.empty());
    }
    {
        ProbeHarness h;
        h.can_read = false;
        h.wire();
        auto res = h.sink.Get("/api/v1/ca/issued");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.standing_calls == 0); // Security:Read first
        CHECK(h.audits.empty());
    }
}

TEST_CASE("ca_routes: an unconfined or grant-less caller passes the probe; an unreadable store is "
          "audited failure",
          "[ca_routes][pki][crypto][security]") {
    using yuzu::server::crypto_widgets::Access;
    for (const Access a : {Access::kAvailable, Access::kRefused}) {
        ProbeHarness h;
        h.standing = a;
        h.wire();
        auto res = h.sink.Get("/api/v1/ca/issued");
        REQUIRE(res);
        CHECK(res->status == 503); // no store wired here: past the probe, into the store check
        CHECK(h.standing_calls == 1);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "failure");
        CHECK(h.audits[0].action == "crypto.ca.certificates.view");
    }
}

TEST_CASE("ca_routes: a revoke wrapper never answers an empty body, whoever the caller",
          "[ca_routes][pki][crypto][security]") {
    using yuzu::server::crypto_widgets::Access;
    // No store: the wrapper answers its 503 banner plus the panel (here the store-unavailable
    // note); a caller without Security:Read gets a plain note instead of the panel.
    auto body_for = [](Access standing, bool probe_wired, bool can_read) {
        ProbeHarness h;
        h.standing = standing;
        h.wire_probe = probe_wired;
        h.probe_read = can_read;
        h.wire();
        auto res = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD", "",
                                   "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(res);
        return res->body;
    };
    for (const auto& body : {body_for(Access::kAvailable, true, true),
                             body_for(Access::kConfined, true, true),
                             body_for(Access::kDegraded, true, true),
                             body_for(Access::kAvailable, false, true)}) {
        CHECK(body.find("Certificate authority unavailable.</div>") != std::string::npos);
        CHECK(body.find("Certificate authority unavailable.</span>") != std::string::npos);
    }
    const auto no_read = body_for(Access::kAvailable, true, false);
    CHECK(no_read.find("Certificate authority unavailable.</div>") != std::string::npos);
    CHECK(no_read.find("not shown to this account") != std::string::npos);
}

// ── The panel and its wrappers withhold ONLY the inventory (Postgres) ─────────────────────────
//
// A confined, degraded or unwired caller keeps the CA metadata, the root / CSR / CRL links and
// the import form; the issued-certificate inventory (and its per-row revoke forms) is replaced by
// a note. After a successful revoke or import the wrapper answers a NON-EMPTY body: htmx swaps
// the body into #ca-section, so an empty 200 would blank the panel with no confirmation.

namespace {

void check_inventory_withheld_panel_intact(const std::string& body) {
    CHECK(body.find("agent-DEAD") == std::string::npos);
    CHECK(body.find("agent-BEEF") == std::string::npos);
    CHECK(body.find("DEAD</") == std::string::npos);
    CHECK(body.find("<table") == std::string::npos);
    CHECK(body.find("/api/settings/ca/revoke") == std::string::npos); // no per-row forms
    CHECK(body.find("AB:CD:EF") != std::string::npos);                // the root fingerprint
    CHECK(body.find("/api/v1/ca/root") != std::string::npos);         // the root download
    CHECK(body.find("/api/settings/ca/import-chain") != std::string::npos); // the import form
}

} // namespace

TEST_CASE("ca_routes: the Settings CA panel withholds ONLY the inventory from a confined, degraded "
          "or unwired caller",
          "[ca_routes][pki][crypto][security][pg]") {
    using yuzu::server::crypto_widgets::Access;
    struct Case {
        Access standing;
        bool wire_filtered;
        std::string note;
    };
    const std::vector<Case> cases = {
        {Access::kConfined, true, std::string(kWithheld)},
        {Access::kDegraded, true, "Certificate inventory unavailable (access check failed)."},
        {Access::kAvailable, false,
         "Certificate inventory unavailable (access check not configured)."}};
    for (const char* path : {"/fragments/settings/ca", "/fragments/settings/ca?view=pki"}) {
        for (const auto& c : cases) {
            INFO(path << " / " << c.note);
            Harness h;
            REQUIRE(h.store->set_root(sample_root()));
            REQUIRE(h.store->record_issued(sample_issued("DEAD")));
            h.standing = c.standing;
            h.wire_filtered = c.wire_filtered;
            h.wire();
            auto res = h.sink.Get(path);
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->get_header_value("Cache-Control") == "no-store");
            CHECK(res->body.find(c.note) != std::string::npos);
            check_inventory_withheld_panel_intact(res->body);
            // Both shapes keep the trailing "replace the default certificates" hint after the
            // note (the pki shape used to drop it).
            CHECK(res->body.find("TLS / mTLS Configuration") != std::string::npos);
        }
        // An unconfined caller still gets the inventory. A kRefused caller (no Inventory
        // grant, or a failed read inside the access check: the answer cannot tell them apart)
        // is shown it too, as the API list serves it; pinned so a tri-state change flips this
        // deliberately.
        for (const Access a : {Access::kAvailable, Access::kRefused}) {
            Harness h;
            REQUIRE(h.store->set_root(sample_root()));
            REQUIRE(h.store->record_issued(sample_issued("DEAD")));
            h.standing = a;
            h.wire();
            auto res = h.sink.Get(path);
            REQUIRE(res);
            CHECK(res->body.find("agent-DEAD") != std::string::npos);
            CHECK(res->body.find(std::string(kWithheld)) == std::string::npos);
        }
    }
}

TEST_CASE("ca_routes: a confined caller's revoke wrapper answers the panel without the inventory, "
          "never an empty body",
          "[ca_routes][pki][crypto][security][pg]") {
    for (const char* view : {"", "&view=pki"}) {
        INFO("view=" << view);
        Harness h;
        REQUIRE(h.store->set_root(sample_root()));
        REQUIRE(h.store->record_issued(sample_issued("DEAD")));
        REQUIRE(h.store->record_issued(sample_issued("BEEF")));
        h.standing = yuzu::server::crypto_widgets::Access::kConfined;
        h.wire();
        const std::string v = view;
        auto post = [&](const std::string& query) {
            return h.sink.dispatch("POST", "/api/settings/ca/revoke?" + query + v, "",
                                   "application/x-www-form-urlencoded", kSameOrigin);
        };

        // Success: the revoke happened, and the operator sees the panel with the note.
        auto ok = post("serial_hex=DEAD&reason=test");
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(h.store->is_revoked("DEAD"));
        CHECK_FALSE(ok->body.empty());
        CHECK(ok->body.find(std::string(kWithheld)) != std::string::npos);
        check_inventory_withheld_panel_intact(ok->body);
        // The panel shows nothing of the mutation (the inventory is withheld), so the reply
        // confirms it on its own: banner in the body and a success toast.
        CHECK(ok->body.find("alert-success") != std::string::npos);
        CHECK(ok->body.find("Certificate revoked.") != std::string::npos);
        CHECK_THAT(ok->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("\"level\":\"success\""));

        // 400 / 404 error paths keep the panel too.
        auto bad = post("serial_hex=zz");
        REQUIRE(bad);
        CHECK(bad->status == 400);
        CHECK(bad->body.find("Invalid certificate serial.") != std::string::npos);
        CHECK(bad->body.find(std::string(kWithheld)) != std::string::npos);
        check_inventory_withheld_panel_intact(bad->body);
        CHECK(bad->body.find("alert-success") == std::string::npos); // an error is not confirmed

        auto gone = post("serial_hex=DEAD"); // already revoked
        REQUIRE(gone);
        CHECK(gone->status == 404);
        CHECK(gone->body.find(std::string(kWithheld)) != std::string::npos);
        check_inventory_withheld_panel_intact(gone->body);
    }
}

TEST_CASE("ca_routes: a confined caller's import-chain wrapper answers the panel without the "
          "inventory, never an empty body",
          "[ca_routes][pki][subordinate][crypto][security][pg]") {
    for (const char* view : {"", "&view=pki"}) {
        INFO("view=" << view);
        Harness h;
        REQUIRE(h.store->set_root(sample_root()));
        REQUIRE(h.store->record_issued(sample_issued("DEAD")));
        h.standing = yuzu::server::crypto_widgets::Access::kConfined;
        h.import_outcome = CaRoutes::ImportOutcome::Ok;
        h.wire();
        auto ok = h.sink.dispatch(
            "POST", std::string("/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR") + view,
            "", "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(h.import_calls == 1);
        CHECK_FALSE(ok->body.empty());
        CHECK(ok->body.find(std::string(kWithheld)) != std::string::npos);
        check_inventory_withheld_panel_intact(ok->body);
        // An irreversible re-root must be confirmed without the inventory: banner + toast.
        CHECK(ok->body.find("alert-success") != std::string::npos);
        CHECK(ok->body.find("Signed chain imported") != std::string::npos);
        CHECK_THAT(ok->get_header_value("HX-Trigger"),
                   Catch::Matchers::ContainsSubstring("\"level\":\"success\""));
    }
}

TEST_CASE("ca_routes: a degraded or unwired caller's wrappers confirm success without the "
          "inventory; an unconfined caller's reply is unchanged",
          "[ca_routes][pki][crypto][security][pg]") {
    using yuzu::server::crypto_widgets::Access;
    struct Case {
        Access standing;
        bool wire_filtered;
        bool expect_confirmation;
    };
    for (const Case c : {Case{Access::kDegraded, true, true}, Case{Access::kAvailable, false, true},
                         Case{Access::kAvailable, true, false}, Case{Access::kRefused, true, false}}) {
        INFO("standing=" << static_cast<int>(c.standing) << " wired=" << c.wire_filtered);
        Harness h;
        REQUIRE(h.store->set_root(sample_root()));
        REQUIRE(h.store->record_issued(sample_issued("DEAD")));
        h.standing = c.standing;
        h.wire_filtered = c.wire_filtered;
        h.import_outcome = CaRoutes::ImportOutcome::Ok;
        h.wire();
        auto rv = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD", "",
                                  "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(rv);
        CHECK(rv->status == 200);
        auto imp = h.sink.dispatch(
            "POST", "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR", "",
            "application/x-www-form-urlencoded", kSameOrigin);
        REQUIRE(imp);
        CHECK(imp->status == 200);
        CHECK((rv->body.find("Certificate revoked.") != std::string::npos) == c.expect_confirmation);
        CHECK((imp->body.find("Signed chain imported") != std::string::npos) ==
              c.expect_confirmation);
        CHECK((rv->get_header_value("HX-Trigger").empty()) == !c.expect_confirmation);
        if (c.expect_confirmation) {
            check_inventory_withheld_panel_intact(rv->body);
        } else {
            // Unconfined: the inventory is re-rendered and shows the result itself.
            CHECK(rv->body.find("alert-success") == std::string::npos);
            CHECK(rv->body.find("agent-DEAD") != std::string::npos);
        }
    }
}

TEST_CASE("ca_routes: a wrapper caller without Security:Read gets a confirmation and a plain note, "
          "never an empty body",
          "[ca_routes][pki][security][pg]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.deny_ops = {"Read"};
    h.wire();
    auto ok = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD", "",
                              "application/x-www-form-urlencoded", kSameOrigin);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.store->is_revoked("DEAD"));
    CHECK(ok->body.find("not shown to this account") != std::string::npos);
    CHECK(ok->body.find("Certificate revoked.") != std::string::npos);
    check_no_inventory(ok->body);
    h.import_outcome = CaRoutes::ImportOutcome::Ok;
    auto imp = h.sink.dispatch("POST",
                               "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR", "",
                               "application/x-www-form-urlencoded", kSameOrigin);
    REQUIRE(imp);
    CHECK(imp->body.find("not shown to this account") != std::string::npos);
    CHECK(imp->body.find("Signed chain imported") != std::string::npos);
    check_no_inventory(imp->body);
}

// ── Standing, audit shape and serving order (Postgres) ──────────────────────────────────────

TEST_CASE("ca_routes: KNOWN RESIDUAL - kRefused serves the unfiltered list and the success row "
          "says standing=refused (tracked by the to-be-filed issue)",
          "[ca_routes][pki][crypto][security][pg]") {
    // kRefused = the access check admitted nobody and did not answer 503: no Inventory grant at
    // all, OR a read failure partway through the check (the answer cannot tell them apart). The
    // list is SERVED to both. This test pins that so a future tri-state fix (a read failure
    // answering 503) flips it DELIBERATELY, in the same change that updates the docs, rather
    // than by accident. When that lands, the read-failure half of this case must become 503.
    using yuzu::server::crypto_widgets::Access;
    Harness h;
    h.standing = Access::kRefused;
    h.wire();
    REQUIRE(h.store->record_issued(sample_issued("C3")));
    auto res = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = json::parse(res->body);
    CHECK(j["count"] == 1);
    CHECK(j["items"][0]["subject"] == "agent-C3");
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
    CHECK_THAT(h.audits[0].detail, Catch::Matchers::ContainsSubstring("standing=refused"));

    // The unrestricted standing is told apart in the same row.
    h.standing = Access::kAvailable;
    auto avail = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(avail);
    CHECK(avail->status == 200);
    REQUIRE(h.audits.size() == 2);
    CHECK_THAT(h.audits[1].detail, Catch::Matchers::ContainsSubstring("standing=available"));
}

TEST_CASE("ca_routes: a sanitised subject is served with exactly one success row",
          "[ca_routes][pki][security][pg]") {
    // This does NOT exercise the serialise-before-audit order: CaStore sanitises free text at
    // the write boundary (sanitize_pg_text), so a stored subject never reaches the read path as
    // invalid UTF-8 and this passes identically on the old audit-before-dump code. It pins what
    // is observable: a subject submitted with invalid bytes is stored sanitised, served 200,
    // and written as one success row. The order itself is held by the handler's comment and by
    // review; an injected unserialisable row would need a seam on the list read.
    Harness h;
    h.wire();
    auto rec = sample_issued("C4");
    rec.subject = std::string("agent-C4-\xC3\x28");
    REQUIRE(h.store->record_issued(rec));
    auto res = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(res);
    CHECK(res->status == 200);
    const auto j = json::parse(res->body);
    CHECK(j["count"] == 1);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "success");
}

// ── Wiring order tripwire (source text; no Postgres) ──────────────────────────────────────────

namespace {

// Repo-relative file lookup: $MESON_SOURCE_ROOT, then CWD, then a bounded walk-up from CWD (the
// same order test_crypto_library_model.cpp uses).
std::filesystem::path find_repo_file_for_ca(const std::string& relative) {
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

} // namespace

TEST_CASE("ca_routes: server.cpp wires the confinement probe and the read probe BEFORE "
          "register_routes",
          "[ca_routes][pki][security]") {
    // register_routes copies the probe into every handler capture, so a probe wired after it
    // never reaches them: the unfiltered list would then answer 503 to EVERYONE and every
    // revoke / import panel would withhold its inventory. Every other test injects its own
    // probe, so none of them can see the production order. This reads the source, and fails
    // loudly (never skips) when it cannot find it.
    const auto path = find_repo_file_for_ca("server/core/src/server.cpp");
    REQUIRE_FALSE(path.empty());
    std::ifstream in(path);
    REQUIRE(in);
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string src = ss.str();
    const auto filtered = src.find("ca_routes_->set_filtered_issued(");
    const auto probe = src.find("ca_routes_->set_read_probe(");
    const auto reg = src.find("ca_routes_->register_routes(");
    REQUIRE(filtered != std::string::npos);
    REQUIRE(probe != std::string::npos);
    REQUIRE(reg != std::string::npos);
    CHECK(filtered < reg);
    CHECK(probe < reg);
    // Exactly one registration site, so the ordering above is about THE site.
    CHECK(src.find("ca_routes_->register_routes(", reg + 1) == std::string::npos);
}
