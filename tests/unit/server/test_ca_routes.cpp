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
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <memory>
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
            if (!perm_allow) {
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
    // limit=0 (→clamped to 1) and an absurd limit (→clamped) both 200, no error.
    for (const char* q : {"/api/v1/ca/issued?limit=0", "/api/v1/ca/issued?limit=999999",
                          "/api/v1/ca/issued?offset=-5", "/api/v1/ca/issued?limit=abc"}) {
        auto r = h.sink.Get(q);
        REQUIRE(r);
        REQUIRE(r->status == 200);
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
    for (const auto& a : h.audits)
        if (a.action == "ca.subordinate.imported" && a.result == "success")
            saw_import = true;
    REQUIRE(saw_import);

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

    // Hermes 6c LOW: a CRL-republish failure on a successful dashboard import is
    // SURFACED (the import stands, but the panel warns the CRL is stale).
    h.crl_succeeds = false;
    auto crlfail = h.sink.dispatch("POST",
                                   "/api/settings/ca/import-chain?intermediate_pem=INT&chain_pem=PAR",
                                   "", "application/x-www-form-urlencoded", same_origin);
    REQUIRE(crlfail);
    REQUIRE(crlfail->status == 200);                            // import still succeeded
    REQUIRE(crlfail->body.find("CRL could not be republished") != std::string::npos);
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
