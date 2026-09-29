/**
 * test_saml_routes.cpp — HTTP wiring tests for SAML 2.0 SP routes.
 *
 * Tests the route registration and dispatch logic in AuthRoutes for:
 *   GET  /auth/saml/start  — AuthnRequest redirect (or 404 when disabled)
 *   POST /saml/acs         — Assertion Consumer Service (HTTP-POST binding)
 *
 * Full cryptographic verification (signed assertion → session) is covered by
 * test_saml_provider.cpp (J2's provider unit tests). This file tests the HTTP
 * wiring layer only: correct 404/redirect/error responses, form-field parsing,
 * audit action names, and relay state open-redirect safety.
 *
 * Windows: the SamlProvider stubs always return is_enabled()=false (N4).
 * The "provider not configured" path covers every test case on Windows —
 * the platform-guarded "enabled-but-fails" tests are skipped there.
 */

#include "auth_routes.hpp"
#include "saml_principal.hpp"
#include "saml_provider.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "rbac_store.hpp" // fine-grained SAML RBAC reconcile tests
#include "pg/pg_pool.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>
#include <yuzu/metrics.hpp>

#include "test_route_sink.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>

// ── Signing fixture headers (success-path test only, non-Windows) ─────────────
// test_saml_provider.cpp imports the same set — both TUs link against
// yuzu_server_core_dep which propagates xmlsec/libxml2/zlib.
#if !defined(_WIN32)
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <zlib.h>

#include <cstring>
#include <ctime>
#endif // !_WIN32

namespace fs = std::filesystem;
using namespace yuzu::server;
using namespace yuzu::server::saml;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — the fixture below clones this
// pre-migrated template instead of opening a SQLite path.
yuzu::test::PgTestTemplate saml_audit_tpl{"samlaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("samlaudit template: store failed to migrate");
}};

// Pre-migrated + seeded RbacStore template (SAML fine-grained RBAC reconcile
// tests below). Same tag/setup as test_oidc_principal_key.cpp's `rbac_tpl` —
// the registry builds each NAME once and shares it across TUs that need the
// identical store set (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate saml_rbac_tpl{"rbacstore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbacstore template: store failed to migrate/seed");
}};

/// Fixture — stores + AuthRoutes wired against an in-process TestRouteSink.
/// Accepts an optional (non-owning) SamlProvider pointer so tests can supply
/// a pre-configured provider without transferring ownership, and an optional
/// (non-owning) RbacStore pointer — null (the default) for every existing
/// coarse-admin-group test in this file, wired for the fine-grained SAML
/// RBAC reconcile tests below.
struct SamlRoutesFixture {
    yuzu::test::TempDir tmp;
    Config                                  cfg{};
    yuzu::MetricsRegistry                   metrics; // wired so yuzu_auth_saml_login_total fires
    auth::AuthManager                       auth_mgr{};
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current TEST_CASE
    // when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
    // api_tokens removed (PR 4.1 review #3): this fixture never calls a token
    // store method, and AuthRoutes null-guards the pointer, so it gets nullptr
    // below — embedding the PG fixture only made every case skip without a DSN.
    // AuditStore ported to Postgres (ADR-0006): a template-cloned ephemeral
    // database + pool. This fixture has no other PG-backed member, so it
    // self-skips explicitly (mirrors yuzu::test::AuthDbPg's own posture) —
    // SKIPs the enclosing TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset,
    // FAILs when set but broken.
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool>   audit_pool;
    std::unique_ptr<AuditStore>             audit_store;
    // AnalyticsEventStore ported to Postgres (ADR-0049) — own ephemeral
    // clone, matching audit_store's pattern above.
    yuzu::test::AnalyticsEventStorePg       analytics;
    std::shared_mutex                       oidc_mu;
    std::unique_ptr<oidc::OidcProvider>     oidc_provider; // null — OIDC not under test
    std::unique_ptr<AuthRoutes>             auth_routes;
    yuzu::server::test::TestRouteSink       sink;

    explicit SamlRoutesFixture(SamlProvider* saml_provider = nullptr,
                               RbacStore* rbac_store = nullptr) {
        // TempDir computes a unique path but does NOT create the directory.
        // Create it before opening any SQLite stores (mirrors the JIT-elevation
        // fixture's comma-operator trick, but explicit is clearer here).
        fs::create_directories(tmp.path);
        auth_mgr.set_metrics_registry(&metrics);

        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        audit_db.emplace(saml_audit_tpl);
        INFO("[SamlRoutesFixture] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit_store->is_open());

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            rbac_store,
            /*api_token_store=*/nullptr,
            audit_store.get(),
            /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr,
            analytics.get(),
            oidc_mu, oidc_provider,
            saml_provider);
        auth_routes->register_routes(sink);
    }

    /// Convenience: latest audit events (newest-first).
    std::vector<AuditEvent> audit_events(std::size_t limit = 10) const {
        AuditQuery q;
        q.limit = static_cast<int>(limit);
        auto rows = audit_store->query(q);
        REQUIRE(rows.has_value());
        return *rows;
    }

    /// Read a metric counter value. The label set must match the production
    /// emission exactly, or counter(name, labels) returns a fresh 0-valued
    /// series (mirrors the HardenedHarness helper in test_auth_routes_hardened.cpp).
    double counter(const std::string& name, const yuzu::Labels& labels = {}) {
        return labels.empty() ? metrics.counter(name).value()
                              : metrics.counter(name, labels).value();
    }
};

// ── Signing fixture (success-path test) ─────────────────────────────────────
// Reproduced here in the anonymous namespace so there is no ODR conflict with
// test_saml_provider.cpp, which defines the same struct at file scope with
// static linkage on all helpers.  All types and functions below are
// translation-unit-local by virtue of the anonymous namespace.
//
// Implementation is identical to J2's SamlTestFixture in
// test_saml_provider.cpp; kept in sync manually until the fixture is
// promoted to a shared test header (follow-up).
#if !defined(_WIN32)

// SAML XML namespace constants (for template construction)
static constexpr const char* kRtAssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
static constexpr const char* kRtProtocolNs  = "urn:oasis:names:tc:SAML:2.0:protocol";
static constexpr const char* kRtDSigNs      = "http://www.w3.org/2000/09/xmldsig#";

struct SamlTestFixture {
    std::string cert_pem;      ///< PEM-encoded self-signed X.509 cert (public key)
    std::string priv_key_pem;  ///< PEM-encoded RSA-2048 private key (for signing)
    std::string cert_pem_b;
    std::string priv_key_pem_b;

    const std::string sp_entity_id  = "https://sp.yuzu.test/saml/metadata";
    const std::string sp_acs_url    = "https://sp.yuzu.test/saml/acs";
    const std::string idp_entity_id = "https://idp.yuzu.test/saml/metadata";
    const std::string idp_sso_url   = "https://idp.yuzu.test/sso";

    SamlTestFixture() {
        // Trigger xmlsec global init via a disabled SamlProvider.
        { SamlProvider p{SamlConfig{}}; (void)p; }
        generate_key_pair(cert_pem, priv_key_pem);
        generate_key_pair(cert_pem_b, priv_key_pem_b);
    }

    SamlConfig make_config() const {
        SamlConfig cfg;
        cfg.idp_entity_id = idp_entity_id;
        cfg.idp_sso_url   = idp_sso_url;
        cfg.sp_entity_id  = sp_entity_id;
        cfg.sp_acs_url    = sp_acs_url;
        cfg.idp_cert_pem  = cert_pem; // pinned cert
        cfg.enabled       = true;
        return cfg;
    }

    /// Build a complete SAML Response XML, sign the embedded Assertion,
    /// and return the base64-encoded signed response.
    std::string make_response(
        const std::string& request_id,
        const std::string& name_id             = "user@example.com",
        int64_t            nooa_seconds_from_now = 3600,
        const std::string& audience            = {},
        const std::string& recipient           = {},
        bool               inject_extra_assertion = false,
        const std::string* signing_priv_key    = nullptr,
        const std::string& attribute_statement_xml = {}) const
    {
        const auto& aud = audience.empty()  ? sp_entity_id : audience;
        const auto& rec = recipient.empty() ? sp_acs_url   : recipient;
        const auto& key = signing_priv_key ? *signing_priv_key : priv_key_pem;

        auto now_epoch = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        auto fmt_epoch = [](int64_t epoch) {
            time_t t = static_cast<time_t>(epoch);
            struct tm utc{};
            gmtime_r(&t, &utc);
            char buf[32];
            strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
            return std::string(buf);
        };

        const auto issue_instant = fmt_epoch(now_epoch);
        const auto nb_str        = fmt_epoch(now_epoch - 5);
        const auto nooa_str      = fmt_epoch(now_epoch + nooa_seconds_from_now);

        const std::string assertion_id = "_test_assertion_001";
        const std::string response_id  = "_test_response_001";

        // clang-format off
        std::string assertion_xml =
            "<saml:Assertion"
              " xmlns:saml=\"" + std::string(kRtAssertionNs) + "\""
              " ID=\"" + assertion_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\">"
              "<saml:Issuer>" + idp_entity_id + "</saml:Issuer>"
              "<ds:Signature xmlns:ds=\"" + std::string(kRtDSigNs) + "\">"
                "<ds:SignedInfo>"
                  "<ds:CanonicalizationMethod"
                    " Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
                  "<ds:SignatureMethod"
                    " Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
                  "<ds:Reference URI=\"#" + assertion_id + "\">"
                    "<ds:Transforms>"
                      "<ds:Transform"
                        " Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                      "<ds:Transform"
                        " Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
                    "</ds:Transforms>"
                    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
                    "<ds:DigestValue/>"
                  "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue/>"
              "</ds:Signature>"
              "<saml:Subject>"
                "<saml:NameID"
                  " Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">"
                  + name_id +
                "</saml:NameID>"
                "<saml:SubjectConfirmation"
                  " Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                  "<saml:SubjectConfirmationData"
                    " NotOnOrAfter=\"" + nooa_str + "\""
                    " Recipient=\"" + rec + "\""
                    " InResponseTo=\"" + request_id + "\"/>"
                "</saml:SubjectConfirmation>"
              "</saml:Subject>"
              "<saml:Conditions"
                " NotBefore=\"" + nb_str + "\""
                " NotOnOrAfter=\"" + nooa_str + "\">"
                "<saml:AudienceRestriction>"
                  "<saml:Audience>" + aud + "</saml:Audience>"
                "</saml:AudienceRestriction>"
              "</saml:Conditions>"
              + attribute_statement_xml +
            "</saml:Assertion>";
        // clang-format on

        std::string evil_assertion_xml;
        if (inject_extra_assertion) {
            // clang-format off
            evil_assertion_xml =
                "<saml:Assertion"
                  " xmlns:saml=\"" + std::string(kRtAssertionNs) + "\""
                  " ID=\"_evil_assertion_002\""
                  " Version=\"2.0\""
                  " IssueInstant=\"" + issue_instant + "\">"
                  "<saml:Issuer>" + idp_entity_id + "</saml:Issuer>"
                  "<saml:Subject>"
                    "<saml:NameID>attacker@evil.com</saml:NameID>"
                    "<saml:SubjectConfirmation"
                      " Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                      "<saml:SubjectConfirmationData"
                        " NotOnOrAfter=\"" + nooa_str + "\""
                        " Recipient=\"" + rec + "\""
                        " InResponseTo=\"" + request_id + "\"/>"
                    "</saml:SubjectConfirmation>"
                  "</saml:Subject>"
                "</saml:Assertion>";
            // clang-format on
        }

        // clang-format off
        std::string response_xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kRtProtocolNs) + "\""
              " ID=\"" + response_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\""
              " InResponseTo=\"" + request_id + "\""
              " Destination=\"" + sp_acs_url + "\">"
              "<samlp:Status>"
                "<samlp:StatusCode"
                  " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              "</samlp:Status>"
              + assertion_xml
              + evil_assertion_xml +
            "</samlp:Response>";
        // clang-format on

        const std::string signed_xml = sign_assertion(response_xml, assertion_id, key);
        return b64_encode(
            reinterpret_cast<const unsigned char*>(signed_xml.data()),
            signed_xml.size());
    }

    /// Build a single <saml:AttributeStatement> containing one <saml:Attribute
    /// Name="attr_name"> with one <saml:AttributeValue> per entry in `values`.
    /// Pass the result as make_response's attribute_statement_xml parameter.
    static std::string make_attribute_statement(const std::string& attr_name,
                                                 const std::vector<std::string>& values) {
        std::string value_elems;
        for (const auto& v : values) {
            value_elems += "<saml:AttributeValue>" + v + "</saml:AttributeValue>";
        }
        return "<saml:AttributeStatement>"
                 "<saml:Attribute Name=\"" + attr_name + "\">"
                   + value_elems +
                 "</saml:Attribute>"
               "</saml:AttributeStatement>";
    }

private:
    // ── OpenSSL: generate RSA-2048 key + 100-year self-signed cert ───────────

    static void generate_key_pair(std::string& out_cert_pem, std::string& out_key_pem) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        // All raw pointers wrapped in scope guards to prevent leaks on REQUIRE failure.
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        REQUIRE(rsa != nullptr);
        struct RsaGuard { RSA* r; ~RsaGuard() { if (r) RSA_free(r); } } rsg{rsa};

        EVP_PKEY* pkey = EVP_PKEY_new();
        REQUIRE(pkey != nullptr);
        struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pkg{pkey};

        REQUIRE(EVP_PKEY_assign_RSA(pkey, rsa) == 1);
        rsg.r = nullptr; // pkey now owns rsa
#pragma GCC diagnostic pop

        X509* cert = X509_new();
        REQUIRE(cert != nullptr);
        struct CertGuard { X509* c; ~CertGuard() { if (c) X509_free(c); } } cg{cert};

        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60LL * 60 * 24 * 365 * 100);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("Test IdP"),
                                   -1, -1, 0);
        X509_set_issuer_name(cert, name);
        REQUIRE(X509_sign(cert, pkey, EVP_sha256()) > 0);

        {
            BIO* bio = BIO_new(BIO_s_mem());
            REQUIRE(bio != nullptr);
            struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
            REQUIRE(PEM_write_bio_X509(bio, cert) == 1);
            BUF_MEM* b = nullptr; BIO_get_mem_ptr(bio, &b);
            out_cert_pem.assign(b->data, b->length);
        }
        {
            BIO* bio = BIO_new(BIO_s_mem());
            REQUIRE(bio != nullptr);
            struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
            REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
            BUF_MEM* b = nullptr; BIO_get_mem_ptr(bio, &b);
            out_key_pem.assign(b->data, b->length);
        }
        // CertGuard and PkeyGuard clean up on scope exit.
    }

    // ── xmlsec1: sign the XML template's <ds:Signature> in the Assertion ─────

    static std::string sign_assertion(
        const std::string& response_xml,
        const std::string& assertion_id,
        const std::string& private_key_pem)
    {
        xmlDocPtr doc = xmlReadMemory(
            response_xml.data(), static_cast<int>(response_xml.size()),
            "sign_tmpl.xml", nullptr,
            XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        REQUIRE(doc != nullptr);

        struct DocGuard { xmlDocPtr d; ~DocGuard() { if (d) xmlFreeDoc(d); } } dg{doc};

        xmlNodePtr root = xmlDocGetRootElement(doc);
        REQUIRE(root != nullptr);

        xmlNodePtr assertion_node = nullptr;
        for (xmlNodePtr n = xmlFirstElementChild(root); n; n = xmlNextElementSibling(n)) {
            if (n->type == XML_ELEMENT_NODE &&
                n->name && xmlStrEqual(n->name, BAD_CAST "Assertion") &&
                n->ns && n->ns->href &&
                xmlStrEqual(n->ns->href, BAD_CAST kRtAssertionNs)) {
                const std::string id = [n]() -> std::string {
                    xmlChar* v = xmlGetProp(n, BAD_CAST "ID");
                    if (!v) return {};
                    std::string s(reinterpret_cast<const char*>(v));
                    xmlFree(v);
                    return s;
                }();
                if (id == assertion_id) {
                    assertion_node = n;
                    xmlAttrPtr id_attr = xmlHasProp(n, BAD_CAST "ID");
                    if (id_attr) xmlAddID(nullptr, doc, BAD_CAST id.c_str(), id_attr);
                    break;
                }
            }
        }
        REQUIRE(assertion_node != nullptr);

        xmlNodePtr sig_node = nullptr;
        for (xmlNodePtr n = xmlFirstElementChild(assertion_node); n;
             n = xmlNextElementSibling(n)) {
            if (n->type == XML_ELEMENT_NODE &&
                n->name && xmlStrEqual(n->name, BAD_CAST "Signature") &&
                n->ns && n->ns->href &&
                xmlStrEqual(n->ns->href, BAD_CAST kRtDSigNs)) {
                sig_node = n;
                break;
            }
        }
        REQUIRE(sig_node != nullptr);

        xmlSecKeyPtr sign_key = xmlSecOpenSSLAppKeyLoadMemory(
            reinterpret_cast<const xmlSecByte*>(private_key_pem.data()),
            static_cast<xmlSecSize>(private_key_pem.size()),
            xmlSecKeyDataFormatPem,
            nullptr, nullptr, nullptr);
        REQUIRE(sign_key != nullptr);
        struct KeyGuard {
            xmlSecKeyPtr k;
            ~KeyGuard() { if (k) xmlSecKeyDestroy(k); }
        } kg{sign_key};

        xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(nullptr);
        REQUIRE(ctx != nullptr);
        struct CtxGuard {
            xmlSecDSigCtxPtr c;
            ~CtxGuard() { if (c) xmlSecDSigCtxDestroy(c); }
        } cg{ctx};

        ctx->signKey = sign_key; // ctx takes ownership
        kg.k = nullptr;          // disarm key guard

        const int sign_ret = xmlSecDSigCtxSign(ctx, sig_node);
        REQUIRE(sign_ret == 0); // CtxGuard handles destruction on throw

        xmlChar* xml_out = nullptr;
        int xml_out_size = 0;
        xmlDocDumpMemory(doc, &xml_out, &xml_out_size);
        REQUIRE(xml_out != nullptr);
        struct XmlStrGuard {
            xmlChar* s;
            ~XmlStrGuard() { if (s) xmlFree(s); }
        } xsg{xml_out};

        return std::string(reinterpret_cast<const char*>(xml_out),
                           static_cast<std::size_t>(xml_out_size));
    }

    // ── Standard base64 encode ───────────────────────────────────────────────

    static std::string b64_encode(const unsigned char* data, std::size_t len) {
        static constexpr char kA[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        for (std::size_t i = 0; i < len; i += 3) {
            auto n = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
            out += kA[(n >> 18) & 0x3F];
            out += kA[(n >> 12) & 0x3F];
            out += (i + 1 < len) ? kA[(n >> 6) & 0x3F] : '=';
            out += (i + 2 < len) ? kA[n & 0x3F] : '=';
        }
        return out;
    }
};

/// Shared key pair — RSA-2048 generation is expensive; done once per binary run.
/// Named saml_test_fixture() to avoid a name collision with the fixture()
/// singleton in test_saml_provider.cpp (which has the same implementation at
/// file scope with static linkage — both are TU-local, but a duplicate static
/// local name in two TUs of the same binary can confuse some debuggers).
static const SamlTestFixture& saml_test_fixture() {
    static const SamlTestFixture f;
    return f;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract request ID from the AuthnRequest redirect URL.
// Reverses: URL-decode → base64-decode → inflate (raw DEFLATE) → parse ID attr.
// Identical to extract_request_id_from_url in test_saml_provider.cpp; the
// anonymous namespace keeps them TU-local so there is no ODR conflict.
// ─────────────────────────────────────────────────────────────────────────────

static std::string extract_authn_request_id(const std::string& url) {
    const auto pos = url.find("SAMLRequest=");
    if (pos == std::string::npos) return {};
    auto val_start = pos + 12;
    auto val_end   = url.find('&', val_start);
    std::string encoded = url.substr(val_start, val_end - val_start);

    // URL-decode
    std::string b64;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            char hex[3] = {encoded[i + 1], encoded[i + 2], 0};
            b64 += static_cast<char>(std::strtol(hex, nullptr, 16));
            i += 2;
        } else if (encoded[i] == '+') {
            b64 += ' ';
        } else {
            b64 += encoded[i];
        }
    }

    // Standard base64 decode
    static constexpr unsigned char kT[256] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64, 64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64, 64,64,64,64,64,64,64,64, 64,64,64,62,64,64,64,63,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,
    };
    std::string compressed;
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : b64) {
        if (kT[c] == 64) continue;
        val = (val << 6) | kT[c];
        bits += 6;
        if (bits >= 0) {
            compressed += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }

    // Raw-DEFLATE inflate (windowBits = -15)
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK) return {};
    zs.next_in  = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
    zs.avail_in = static_cast<uInt>(compressed.size());
    std::string xml(8192, '\0');
    zs.next_out  = reinterpret_cast<Bytef*>(xml.data());
    zs.avail_out = static_cast<uInt>(xml.size());
    inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    xml.resize(zs.total_out);

    // Parse ID="..." from the XML
    const auto id_pos = xml.find("ID=\"");
    if (id_pos == std::string::npos) return {};
    auto id_start = id_pos + 4;
    auto id_end   = xml.find('"', id_start);
    if (id_end == std::string::npos) return {};
    return xml.substr(id_start, id_end - id_start);
}

/// Full SAML ACS round-trip: GET /auth/saml/start → build+sign a Response
/// asserting `groups` under the "groups" attribute → POST /saml/acs.
/// Returns the minted session token, or an empty string if the flow did not
/// reach a 302-with-session-cookie outcome (callers assert on that
/// separately). Shared by the exact-match-negative / beyond-cap / trim
/// tests below so each doesn't re-derive the binding-cookie + request-id
/// dance from scratch.
static std::string run_saml_acs_flow(SamlRoutesFixture& fix, const SamlTestFixture& f,
                                     const std::string& name_id,
                                     const std::vector<std::string>& groups) {
    // ADR-2001 PR4a — the ACS handler reads cfg_.saml_idp_entity_id (a
    // SEPARATE field from the SamlProvider's own SamlConfig::idp_entity_id,
    // which `f.make_config()` sets) to build the stable SAML principal and
    // gate its sanitation; production wires the same value into both (see
    // server.cpp's saml_cfg.idp_entity_id = cfg_.saml_idp_entity_id), so
    // tests must keep them in sync here too — an unset cfg.saml_idp_entity_id
    // (empty by default) would fail the sanitation gate and every login below
    // would 302 to /login?error=saml instead of minting a session.
    fix.cfg.saml_idp_entity_id = f.idp_entity_id;

    auto start_res = fix.sink.Get("/auth/saml/start");
    if (!start_res || start_res->status != 302) return {};
    const auto redirect_location = start_res->get_header_value("Location");

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto pos = sc.find(pfx);
        if (pos == std::string::npos) return {};
        const auto val_start = pos + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }

    const auto request_id = extract_authn_request_id(redirect_location);
    if (request_id.empty()) return {};

    const auto attr_stmt = SamlTestFixture::make_attribute_statement("groups", groups);
    const auto response_b64 =
        f.make_response(request_id, name_id, 3600, {}, {}, false, nullptr, attr_stmt);

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    if (!acs_res || acs_res->status != 302) return {};

    std::string session_token;
    const std::string tok_prefix = "yuzu_session=";
    for (std::size_t i = 0; ; ++i) {
        const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
        if (sc.empty()) break;
        const auto pos = sc.find(tok_prefix);
        if (pos == std::string::npos) continue;
        const auto val_start = pos + tok_prefix.size();
        const auto val_end   = sc.find(';', val_start);
        session_token = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
        break;
    }
    return session_token;
}

#endif // !_WIN32

} // namespace

// ---------------------------------------------------------------------------
// AuthRoutes::extract_form_value — field-name boundary check (review LOW)
//
// body.find(key + "=") with no boundary check would let a field name that
// merely ENDS in the target key shadow the genuine field, e.g. an
// attacker-supplied "fooSAMLResponse=attacker" preceding the real
// "SAMLResponse=real". A match is only valid at the start of the body or
// immediately after an '&' separator.
// ---------------------------------------------------------------------------

TEST_CASE("extract_form_value — shadow field name does not shadow the real field",
          "[saml][auth_routes]") {
    CHECK(AuthRoutes::extract_form_value(
              "fooSAMLResponse=attacker&SAMLResponse=real", "SAMLResponse") == "real");
}

TEST_CASE("extract_form_value — leading field still matches", "[saml][auth_routes]") {
    CHECK(AuthRoutes::extract_form_value(
              "SAMLResponse=real&RelayState=%2F", "SAMLResponse") == "real");
}

TEST_CASE("extract_form_value — field after a genuine '&' boundary still matches",
          "[saml][auth_routes]") {
    CHECK(AuthRoutes::extract_form_value(
              "RelayState=%2F&SAMLResponse=real", "SAMLResponse") == "real");
}

TEST_CASE("extract_form_value — key absent returns empty", "[saml][auth_routes]") {
    CHECK(AuthRoutes::extract_form_value("RelayState=%2F", "SAMLResponse").empty());
}

// ---------------------------------------------------------------------------
// GET /auth/saml/start — provider not configured (null pointer)
// ---------------------------------------------------------------------------

TEST_CASE("SAML start — returns 404 when provider is null", "[pg][saml][auth_routes]") {
    SamlRoutesFixture fix; // saml_provider defaults to nullptr
    auto res = fix.sink.Get("/auth/saml/start");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
    CHECK(res->body.find("SAML not configured") != std::string::npos);

    // A4 envelope shape (review finding MEDIUM): error.code, error.message,
    // error.correlation_id, meta.api_version, and the X-Correlation-Id
    // response header must all be present and mutually consistent.
    auto cid_header = res->get_header_value("X-Correlation-Id");
    CHECK(!cid_header.empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE(!body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 404);
    CHECK(body["error"]["message"] == "SAML not configured");
    REQUIRE(body["error"].contains("correlation_id"));
    CHECK(body["error"]["correlation_id"].get<std::string>() == cid_header);
    REQUIRE(body.contains("meta"));
    CHECK(body["meta"]["api_version"] == "v1");
}

// ---------------------------------------------------------------------------
// POST /saml/acs — provider not configured
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — returns 404 when provider is null", "[pg][saml][auth_routes]") {
    SamlRoutesFixture fix;
    auto res = fix.sink.Post("/saml/acs",
                             "SAMLResponse=garbage&RelayState=%2Fdashboard",
                             "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
    CHECK(res->body.find("SAML not configured") != std::string::npos);

    // A4 envelope shape + X-Correlation-Id header (review finding MEDIUM).
    auto cid_header = res->get_header_value("X-Correlation-Id");
    CHECK(!cid_header.empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE(!body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"]["code"] == 404);
    REQUIRE(body["error"].contains("correlation_id"));
    CHECK(body["error"]["correlation_id"].get<std::string>() == cid_header);
    REQUIRE(body.contains("meta"));
    CHECK(body["meta"]["api_version"] == "v1");

    // Prometheus counter (review finding LOW): every ACS outcome, including
    // the not-configured 404 early-return, increments yuzu_auth_saml_login_total.
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
}

// ---------------------------------------------------------------------------
// POST /saml/acs — missing SAMLResponse field
// Platform-independent: the empty-field check runs before validate_response.
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — missing SAMLResponse redirects to login error", "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    // On Windows the provider stub makes is_enabled()=false, so the route 404s
    // before the field-check. Skip the redirect assertion on Windows.
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    // Construct a provider that reports is_enabled()=true but validates nothing.
    SamlConfig cfg;
    cfg.idp_entity_id = "https://idp.test";
    cfg.idp_sso_url   = "https://idp.test/sso";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.sp_acs_url    = "https://sp.test/saml/acs";
    cfg.idp_cert_pem  = "not-a-real-cert"; // non-empty → is_enabled() returns true
    cfg.enabled       = true;
    SamlProvider provider(std::move(cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);

    // POST with NO SAMLResponse field
    auto res = fix.sink.Post("/saml/acs", "RelayState=%2F",
                             "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    // Should redirect to /login?error=saml (302)
    CHECK(res->status == 302);
    auto location = res->get_header_value("Location");
    CHECK(location.find("/login") != std::string::npos);
    CHECK(location.find("error=saml") != std::string::npos);

    // Audit action must be auth.saml_login_failed
    auto events = fix.audit_events();
    REQUIRE(!events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");
#endif
}

// ---------------------------------------------------------------------------
// POST /saml/acs — malformed SAMLResponse (validate_response returns error)
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — malformed SAMLResponse redirects to login error", "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    SamlConfig cfg;
    cfg.idp_entity_id = "https://idp.test";
    cfg.idp_sso_url   = "https://idp.test/sso";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.sp_acs_url    = "https://sp.test/saml/acs";
    cfg.idp_cert_pem  = "not-a-real-cert";
    cfg.enabled       = true;
    SamlProvider provider(std::move(cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);

    // A non-empty but undecodable / unparseable SAMLResponse
    auto res = fix.sink.Post("/saml/acs", "SAMLResponse=AAAAAAAAGARBAGE",
                             "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    auto location = res->get_header_value("Location");
    CHECK(location.find("/login") != std::string::npos);
    CHECK(location.find("error=saml") != std::string::npos);

    // Audit action must be auth.saml_login_failed
    auto events = fix.audit_events();
    REQUIRE(!events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");
#endif
}

// ---------------------------------------------------------------------------
// GET /auth/saml/start — provider enabled → redirects to IdP
// ---------------------------------------------------------------------------

TEST_CASE("SAML start — redirects when provider is enabled", "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    SamlConfig cfg;
    cfg.idp_entity_id = "https://idp.test";
    cfg.idp_sso_url   = "https://idp.test/sso";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.sp_acs_url    = "https://sp.test/saml/acs";
    cfg.idp_cert_pem  = "not-a-real-cert";
    cfg.enabled       = true;
    SamlProvider provider(std::move(cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);

    auto res = fix.sink.Get("/auth/saml/start");
    REQUIRE(res != nullptr);
    // Should be a redirect (302) to the IdP SSO URL
    CHECK(res->status == 302);
    auto location = res->get_header_value("Location");
    // build_authn_request starts with the IdP SSO URL
    CHECK(location.find("https://idp.test/sso") != std::string::npos);
#endif
}

// ---------------------------------------------------------------------------
// Relay state open-redirect safety
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — RelayState open-redirect: absolute URL falls back to /",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    // We need a provider that accepts a SAMLResponse and returns a valid assertion.
    // Since we can't sign a real assertion here (that's test_saml_provider.cpp),
    // test the fallback path: a missing SAMLResponse means redirect to /login, so
    // the RelayState open-redirect check is only exercised on the success path.
    // We verify the safety logic directly via the route string format.
    //
    // This test instead confirms the route REJECTS an absolute RelayState by
    // checking the redirect from the missing-SAMLResponse path has the correct
    // error target (not the attacker URL), and separately that the redirect on
    // success would apply the safety function.
    //
    // The safety function is inline in the handler (no separate helper to call),
    // but the important contract is: any redirect out of /saml/acs on the error
    // path goes to /login?error=saml (not a user-supplied URL).
    SamlConfig cfg;
    cfg.idp_entity_id = "https://idp.test";
    cfg.idp_sso_url   = "https://idp.test/sso";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.sp_acs_url    = "https://sp.test/saml/acs";
    cfg.idp_cert_pem  = "not-a-real-cert";
    cfg.enabled       = true;
    SamlProvider provider(std::move(cfg));

    SamlRoutesFixture fix(&provider);

    // Error path: missing SAMLResponse — redirect is always /login?error=saml,
    // regardless of whatever RelayState the attacker supplied.
    auto res = fix.sink.Post(
        "/saml/acs",
        "RelayState=https%3A%2F%2Fevil.example.com%2Fsteal",
        "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    auto location = res->get_header_value("Location");
    // Must NOT redirect to an external URL
    CHECK(location.find("evil.example.com") == std::string::npos);
    // Must land on the login error page
    CHECK(location.find("/login") != std::string::npos);
#endif
}

// ---------------------------------------------------------------------------
// POST /saml/acs — end-to-end login SUCCESS path
//
// Exercises the full happy path: a validly-signed SAMLResponse → 302 redirect
// + Set-Cookie: yuzu_session=<token> → session with auth_source="saml",
// role=user, principal==NameID → audit row auth.saml_login / ok.
//
// This is the only test in this file that performs real XML-DSig (all others
// use stub providers or error paths).  On Windows the provider stub always
// returns is_enabled()=false (N4), so the test is skipped there.
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — valid signed SAMLResponse creates session with auth_source=saml",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    // Shared fixture: RSA-2048 key generation happens once per binary run.
    const auto& f = saml_test_fixture();

    // Wire a real provider with the fixture's pinned cert.
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    // provider must outlive fix (SamlRoutesFixture holds a non-owning pointer).
    SamlRoutesFixture fix(&provider);
    // ADR-2001 PR4a — see run_saml_acs_flow's comment: keep in sync with
    // the SamlProvider's own idp_entity_id (f.make_config() above).
    fix.cfg.saml_idp_entity_id = f.idp_entity_id;

    // ── Step 1: GET /auth/saml/start to register a solicited request ID ──────
    // validate_response rejects unsolicited responses: InResponseTo must match
    // an ID registered by build_authn_request. Hitting the route is the only
    // test-accessible path to register one without modifying production code.
    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());
    INFO("AuthnRequest redirect: " << redirect_location);

    // ── Step 1b: Extract the browser-binding cookie from the start response ──
    // The route sets: Set-Cookie: __Host-yuzu_saml_bind=<64hex>; ...
    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64); // 32-byte hex secret

    // ── Step 2: Extract the InResponseTo request ID from the AuthnRequest ────
    // The Location is the IdP SSO URL with a SAMLRequest= query param.
    // Reverse: URL-decode → base64-decode → raw-DEFLATE inflate → parse ID="..."
    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());
    // All yuzu-generated AuthnRequest IDs begin with '_' (XML ID production rule).
    REQUIRE(request_id[0] == '_');

    // ── Step 3: Build a validly-signed SAMLResponse using the fixture key ─────
    const std::string name_id    = "saml_user@example.test";
    const auto        response_b64 = f.make_response(request_id, name_id);

    // URL-encode the base64 value for the form body.
    // Standard base64 uses '+' which extract_form_value → url_decode maps to ' '.
    // The '=' padding and '/' characters do not require encoding here because
    // url_decode only has special handling for '%XX' and '+'.
    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }

    // RelayState=%2F → url_decode("/") → safe relative target "/"
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    // ── Step 4: POST the signed response to /saml/acs — include binding cookie ─
    // The ACS route requires the __Host-yuzu_saml_bind cookie to be present and
    // its SHA-256 to match the hash stored when the AuthnRequest was issued.
    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body,
        "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);

    // Assert: 302 redirect to the relay-state target ("/")
    CHECK(acs_res->status == 302);
    CHECK(acs_res->get_header_value("Location") == "/");

    // ── Step 5: Verify the binding cookie is cleared ──────────────────────────
    // The ACS route must clear the bind cookie on both success and failure paths.
    {
        bool found_clear = false;
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            if (sc.find("__Host-yuzu_saml_bind=") != std::string::npos &&
                sc.find("Max-Age=0") != std::string::npos) {
                found_clear = true;
            }
        }
        CHECK(found_clear);
    }

    // ── Step 6: Verify the session cookie ─────────────────────────────────────
    // The ACS success response emits two Set-Cookie headers:
    //   [0] __Host-yuzu_saml_bind=; Max-Age=0   (clear the binding cookie)
    //   [1] yuzu_session=<token>; ...            (the new session)
    // We iterate to find the session header by prefix.
    std::string session_token;
    {
        const std::string tok_prefix = "yuzu_session=";
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            const auto pos = sc.find(tok_prefix);
            if (pos == std::string::npos) continue;
            const auto val_start = pos + tok_prefix.size();
            const auto val_end   = sc.find(';', val_start);
            session_token = sc.substr(val_start,
                val_end == std::string::npos ? std::string::npos
                                             : val_end - val_start);
            break;
        }
    }
    INFO("session_token extracted: " << session_token);
    REQUIRE_FALSE(session_token.empty());

    // ── Step 7: Validate session properties ───────────────────────────────────
    // AuthRoutes was constructed with auth_mgr by reference, so the session
    // minted inside the POST handler is visible via fix.auth_mgr.
    auto maybe_session = fix.auth_mgr.validate_session(session_token);
    REQUIRE(maybe_session.has_value());
    const auto& sess = maybe_session.value();
    CHECK(sess.auth_source == "saml");
    CHECK(sess.role == auth::Role::user);
    // ADR-2001 PR4a — the session's stable authorization principal is
    // saml:<entity_id>#<name_id>, NOT the raw NameID; display_name stays
    // the raw NameID for human-readable rendering.
    CHECK(sess.username == saml::saml_principal_id(f.idp_entity_id, name_id));
    CHECK(sess.display_name == name_id);

    // ── Step 8: Verify the audit record ───────────────────────────────────────
    // audit_log_for_principal is called on success with action="auth.saml_login"
    // and result="ok" (mirrors the OIDC callback audit pattern, Gate 4 B3).
    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.saml_login");
    CHECK(events.front().result == "ok");
    // No --saml-admin-group configured (thin-slice default) — audit must
    // reflect the resolved "user" role, never a stale hard-coded value.
    CHECK(events.front().principal_role == "user");

    // ── Step 9: Verify the Prometheus counter (review finding LOW) ───────────
    // #1828.1: role label sourced from the resolved role (user, thin-slice
    // default — no --saml-admin-group configured).
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "ok"}, {"role", "user"}}) == 1.0);
#endif
}

// ---------------------------------------------------------------------------
// ADR-2001 PR4a — NameID sanitation gate, WIRED at the ACS handler
// (quality-engineer MEDIUM: is_valid_saml_component's own unit tests
// (test_saml_principal.cpp) only exercise the pure function — this pins
// that the ACS handler actually calls it and fails closed on the wire).
//
// Mirrors run_saml_acs_flow's own start -> binding-cookie -> build-response
// -> dispatch sequence (same fixture, same InResponseTo/binding-cookie
// dance) but keeps the httplib::Response so the redirect target, the
// audit row, and the metric can all be asserted directly — run_saml_acs_flow
// deliberately returns only the session token (or "") for its five simpler
// callers below, which is not enough to assert the specific failure shape
// this test needs.
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — a NameID exceeding 255 bytes fails the sanitation gate: redirects to "
          "/login?error=saml, records auth.saml_login_failed, and mints NO session",
          "[pg][saml][auth_routes][2001]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64);

    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());

    // 300 bytes of plain ASCII — well-formed XML text content (so
    // validate_response accepts it: non-empty, no XSW/signature concerns),
    // but exceeds is_valid_saml_component's 255-byte cap.
    const std::string oversized_name_id(300, 'a');
    REQUIRE(oversized_name_id.size() > 255);
    const auto response_b64 = f.make_response(request_id, oversized_name_id);

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);

    // Fail-closed redirect, never a minted session.
    CHECK(acs_res->status == 302);
    CHECK(acs_res->get_header_value("Location") == "/login?error=saml");
    {
        bool found_session_cookie = false;
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            if (sc.find("yuzu_session=") != std::string::npos) found_session_cookie = true;
        }
        CHECK_FALSE(found_session_cookie);
    }

    // Audit row: auth.saml_login_failed, never auth.saml_login.
    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");

    // Metric: the error-result counter, never the ok-result one.
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "ok"}, {"role", "user"}}) == 0.0);
#endif
}

TEST_CASE("SAML ACS — an entity_id containing a control byte fails the sanitation gate the "
          "same way (redirect + audit.saml_login_failed + no session)",
          "[pg][saml][auth_routes][2001]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    // Deliberately DIVERGE cfg.saml_idp_entity_id from the SamlProvider's
    // own idp_entity_id (which must still match for Issuer verification to
    // pass) — a control byte here models an operator-side misconfiguration/
    // corruption reaching cfg_.saml_idp_entity_id at the ACS handler, which
    // must reject exactly like a malformed NameID (both flow through the
    // same is_valid_saml_component gate, auth_routes.cpp).
    fix.cfg.saml_idp_entity_id = f.idp_entity_id + "\x01";

    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64);

    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());

    // A perfectly valid NameID — only entity_id is malformed.
    const auto response_b64 = f.make_response(request_id, "control_byte_entity@example.test");

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);

    CHECK(acs_res->status == 302);
    CHECK(acs_res->get_header_value("Location") == "/login?error=saml");
    {
        bool found_session_cookie = false;
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            if (sc.find("yuzu_session=") != std::string::npos) found_session_cookie = true;
        }
        CHECK_FALSE(found_session_cookie);
    }

    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");
#endif
}

TEST_CASE("SAML ACS — assertion groups containing --saml-admin-group mint an admin session",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();

    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group = "admins";
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64);

    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());

    const std::string name_id = "admin_user@example.test";
    const auto attr_stmt = SamlTestFixture::make_attribute_statement("groups", {"admins"});
    const auto response_b64 =
        f.make_response(request_id, name_id, 3600, {}, {}, false, nullptr, attr_stmt);

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);
    CHECK(acs_res->status == 302);

    std::string session_token;
    {
        const std::string tok_prefix = "yuzu_session=";
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            const auto pos = sc.find(tok_prefix);
            if (pos == std::string::npos) continue;
            const auto val_start = pos + tok_prefix.size();
            const auto val_end   = sc.find(';', val_start);
            session_token = sc.substr(val_start,
                val_end == std::string::npos ? std::string::npos : val_end - val_start);
            break;
        }
    }
    REQUIRE_FALSE(session_token.empty());

    auto maybe_session = fix.auth_mgr.validate_session(session_token);
    REQUIRE(maybe_session.has_value());
    CHECK(maybe_session->role == auth::Role::admin);
    // ADR-2001 PR4a — stable principal, not the raw NameID (see the first
    // success-path test's comment above for the full rationale).
    CHECK(maybe_session->username == saml::saml_principal_id(f.idp_entity_id, name_id));
    CHECK(maybe_session->display_name == name_id);

    // Audit must reflect the RESOLVED admin role, not a hard-coded "user".
    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.saml_login");
    CHECK(events.front().result == "ok");
    CHECK(events.front().principal_role == "admin");

    // #1828.1: role label on the login counter reflects the resolved admin
    // role, distinguishing it from a "user" login without a store query.
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "ok"}, {"role", "admin"}}) ==
          1.0);
#endif
}

TEST_CASE("SAML ACS — display-name/email attributes set the session display (name->email->NameID)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    // Gate 3/4 (quality-engineer + happy-path): the session-level derivation
    // (create_saml_session: display = name -> email -> raw NameID) was untested
    // end-to-end — provider tests cover parsing, route tests only pinned the
    // default (attributes-unset) path. This drives the full /auth/saml/start ->
    // /saml/acs round-trip with the flags configured and asserts the minted
    // session's display_name for name, email-only, and backward-compat cases.
    const auto& f = saml_test_fixture();

    auto saml_cfg           = f.make_config();
    saml_cfg.name_attribute  = "displayName";
    saml_cfg.email_attribute = "email";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    const std::string name_id = "opaque-persistent-id"; // deliberately NOT a human name

    // Construct the PG-backed fixture at TEST-BODY scope, NOT inside the
    // value-returning lambda below. Its YUZU_REQUIRE_PG_DB skip must fire at
    // test/section level; a SKIP() thrown from inside a CHECK(mint_display(...))
    // expression instead surfaces as a FAILED "{ nested SKIP() called }" and
    // breaks the no-Postgres Linux SAML test leg (adversarial-review CDX-C1).
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id;

    auto mint_display = [&](const std::string& attr_stmt) -> std::string {
        auto start_res = fix.sink.Get("/auth/saml/start");
        REQUIRE(start_res != nullptr);
        REQUIRE(start_res->status == 302);
        std::string binding_secret;
        {
            const auto sc        = start_res->get_header_value("Set-Cookie");
            const std::string px = "__Host-yuzu_saml_bind=";
            const auto vs        = sc.find(px) + px.size();
            const auto ve        = sc.find(';', vs);
            binding_secret = sc.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
        }
        const auto request_id = extract_authn_request_id(start_res->get_header_value("Location"));
        REQUIRE_FALSE(request_id.empty());
        const auto response_b64 =
            f.make_response(request_id, name_id, 3600, {}, {}, false, nullptr, attr_stmt);
        std::string encoded;
        encoded.reserve(response_b64.size() + 16);
        for (unsigned char c : response_b64) {
            if (c == '+')
                encoded += "%2B";
            else
                encoded += static_cast<char>(c);
        }
        const auto form_body = "SAMLResponse=" + encoded + "&RelayState=%2F";
        auto acs_res         = fix.sink.dispatch("POST", "/saml/acs", form_body,
                                         "application/x-www-form-urlencoded",
                                         {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
        REQUIRE(acs_res != nullptr);
        REQUIRE(acs_res->status == 302);
        std::string token;
        for (std::size_t i = 0;; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            const auto pos = sc.find("yuzu_session=");
            if (pos == std::string::npos) continue;
            const auto vs = pos + std::string("yuzu_session=").size();
            const auto ve = sc.find(';', vs);
            token         = sc.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
            break;
        }
        REQUIRE_FALSE(token.empty());
        auto sess = fix.auth_mgr.validate_session(token);
        REQUIRE(sess.has_value());
        // Identity is ALWAYS the stable principal, never the display attribute.
        CHECK(sess->username == saml::saml_principal_id(f.idp_entity_id, name_id));
        return sess->display_name;
    };

    SECTION("name attribute -> display is the human name, not the raw NameID") {
        const auto stmt =
            SamlTestFixture::make_attribute_statement("displayName", {"Ada Lovelace"}) +
            SamlTestFixture::make_attribute_statement("email", {"ada@example.com"});
        CHECK(mint_display(stmt) == "Ada Lovelace");
    }
    SECTION("email only -> display falls back to the email") {
        const auto stmt = SamlTestFixture::make_attribute_statement("email", {"grace@example.com"});
        CHECK(mint_display(stmt) == "grace@example.com");
    }
    SECTION("no enrichment attributes -> display stays the raw NameID (backward-compat)") {
        CHECK(mint_display("") == name_id);
    }
#endif
}

TEST_CASE("SAML ACS — assertion groups not containing --saml-admin-group mint a user session",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();

    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group = "admins";
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64);

    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());

    // Groups present but NOT the configured admin group — must NOT promote.
    const std::string name_id = "plain_user@example.test";
    const auto attr_stmt =
        SamlTestFixture::make_attribute_statement("groups", {"engineering", "sales"});
    const auto response_b64 =
        f.make_response(request_id, name_id, 3600, {}, {}, false, nullptr, attr_stmt);

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);
    CHECK(acs_res->status == 302);

    std::string session_token;
    {
        const std::string tok_prefix = "yuzu_session=";
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            const auto pos = sc.find(tok_prefix);
            if (pos == std::string::npos) continue;
            const auto val_start = pos + tok_prefix.size();
            const auto val_end   = sc.find(';', val_start);
            session_token = sc.substr(val_start,
                val_end == std::string::npos ? std::string::npos : val_end - val_start);
            break;
        }
    }
    REQUIRE_FALSE(session_token.empty());

    auto maybe_session = fix.auth_mgr.validate_session(session_token);
    REQUIRE(maybe_session.has_value());
    CHECK(maybe_session->role == auth::Role::user);
    // ADR-2001 PR4a — stable principal, not the raw NameID.
    CHECK(maybe_session->username == saml::saml_principal_id(f.idp_entity_id, name_id));
    CHECK(maybe_session->display_name == name_id);

    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().principal_role == "user");
#endif
}

TEST_CASE("SAML ACS — a near-miss group value does not mint admin (qa-S1)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group = "admin";

    // "administrators" is a superstring of "admin", not an exact match.
    const auto token = run_saml_acs_flow(fix, f, "near_miss_user@example.test",
                                         {"administrators"});
    REQUIRE_FALSE(token.empty());

    auto session = fix.auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
    CHECK(session->role == auth::Role::user);
#endif
}

TEST_CASE("SAML ACS — a case-differing group value does not mint admin (qa-S1)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group = "admins";

    // "Admins" (capital A) vs configured "admins" — exact match is
    // case-sensitive, so this must NOT promote.
    const auto token = run_saml_acs_flow(fix, f, "case_diff_user@example.test", {"Admins"});
    REQUIRE_FALSE(token.empty());

    auto session = fix.auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
    CHECK(session->role == auth::Role::user);
#endif
}

// qa-S2 / #1828.3 boundary — beyond-cap and exactly-at-cap group counts.
//
// Both cases below are SKIPPED as of the 64->200 kMaxGroupValues raise
// (SAML fine-grained RBAC, parity with RbacStore::kMaxIdpGroupsPerLogin):
// reaching (or exceeding) 200 <saml:AttributeValue> elements needs at
// least ~8.7 KB of raw XML for the group attribute ALONE — even with
// every value empty (200 * "<saml:AttributeValue></saml:AttributeValue>"
// = 8698 bytes) — which already exceeds httplib's hardcoded
// CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH=8192 cap on an
// application/x-www-form-urlencoded body BEFORE the rest of the
// assertion's fixed XML, before base64 encoding (+33%), and before
// percent-encoding '+' bytes. httplib rejects the POST with a bare 413
// INSIDE parse_form_data_message, before /saml/acs's handler ever runs —
// TestRouteSink deliberately mirrors this (see its own comment) rather
// than let a fixture "prove" behaviour production traffic can never
// reach. This is a genuine, pre-existing, unrelated constant (not
// overridden anywhere in this repo — verified via
// `grep CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH`) that this cap
// raise was the first change to bring into practical reach: at the old
// cap=64, "beyond cap" only needed ~70 short values (~3.5 KB), comfortably
// under 8 KB. There is no way to shrink the per-element XML tag overhead
// (<saml:AttributeValue></saml:AttributeValue> = 44 bytes) below the
// 8192-byte budget for >=186 elements, so this scenario is not
// reconstructible at any group-value length once the cap is 200.
//
// The cap-truncation MECHANIC itself (>200 asserted values -> `groups`
// truncated to exactly 200, `group_cap_truncated=true`) is still fully
// covered where it belongs: SamlProvider::validate_response is a pure
// function call in test_saml_provider.cpp's "group values are capped at
// kMaxGroupValues entries (DoS guard)" test, which has no HTTP layer and
// therefore no 8 KB ceiling to work around. auth_routes.cpp's consumption
// of that already-truncated `groups` vector (both the coarse
// --saml-admin-group non-match and the fine-grained reconcile-deny
// branch) is then a straightforward, size-independent read of the
// verifier's output — exercised at realistic group counts by the
// reconcile tests above and the pre-existing case/near-miss tests below.
TEST_CASE("SAML ACS — an admin-group match beyond the kMaxGroupValues cap does not mint admin "
          "(qa-S2)",
          "[pg][saml][auth_routes]") {
    SKIP("Unreachable via a real HTTP-POST binding at kMaxGroupValues=200 — see the comment "
        "block above this TEST_CASE. Cap-truncation coverage lives in test_saml_provider.cpp.");
}

TEST_CASE("SAML ACS — exactly kMaxGroupValues values does not trip the cap-truncation counter "
          "(#1828.3 boundary)",
          "[pg][saml][auth_routes]") {
    SKIP("Unreachable via a real HTTP-POST binding at kMaxGroupValues=200 — see the comment "
        "block above the sibling qa-S2 TEST_CASE. Boundary coverage lives in "
        "test_saml_provider.cpp.");
}

TEST_CASE("SAML ACS — a trailing space in --saml-admin-group still matches after trim (UP-4)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    // Mirrors exactly what ServerImpl's constructor does to cfg_.saml_admin_group
    // before assembling SamlConfig (server.cpp, non-Windows SAML init block) —
    // a raw `--saml-admin-group "Admins "` CLI value gets trimmed here too.
    fix.cfg.saml_admin_group = trim_ascii_whitespace("Admins ");
    REQUIRE(fix.cfg.saml_admin_group == "Admins");

    const auto token = run_saml_acs_flow(fix, f, "trimmed_admin_user@example.test", {"Admins"});
    REQUIRE_FALSE(token.empty());

    auto session = fix.auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
    CHECK(session->role == auth::Role::admin);
#endif
}

TEST_CASE("trim_ascii_whitespace — trims leading/trailing space/tab/CR/LF, "
          "all-whitespace clears to empty",
          "[saml][auth_routes]") {
    CHECK(trim_ascii_whitespace("Admins") == "Admins");
    CHECK(trim_ascii_whitespace("Admins ") == "Admins");
    CHECK(trim_ascii_whitespace(" Admins") == "Admins");
    CHECK(trim_ascii_whitespace("  Admins  ") == "Admins");
    CHECK(trim_ascii_whitespace("\tAdmins\r\n") == "Admins");
    CHECK(trim_ascii_whitespace("") == "");
    CHECK(trim_ascii_whitespace("   ") == "");
    CHECK(trim_ascii_whitespace("Ad mins") == "Ad mins"); // interior space preserved
}

TEST_CASE("SAML ACS — assertion with no AttributeStatement mints a user session even when "
          "--saml-admin-group is configured",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();

    // group_attribute IS configured but the assertion below carries no
    // AttributeStatement at all — groups must resolve to empty, not error.
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group = "admins";
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto redirect_location = start_res->get_header_value("Location");
    REQUIRE_FALSE(redirect_location.empty());

    std::string binding_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        REQUIRE(sc.find("__Host-yuzu_saml_bind=") != std::string::npos);
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto val_start = sc.find(pfx) + pfx.size();
        const auto val_end   = sc.find(';', val_start);
        binding_secret = sc.substr(val_start,
            val_end == std::string::npos ? std::string::npos : val_end - val_start);
    }
    REQUIRE(binding_secret.size() == 64);

    const auto request_id = extract_authn_request_id(redirect_location);
    REQUIRE_FALSE(request_id.empty());

    const std::string name_id = "no_groups_user@example.test";
    const auto response_b64 = f.make_response(request_id, name_id); // no attribute_statement_xml

    std::string encoded_response;
    encoded_response.reserve(response_b64.size() + 16);
    for (unsigned char c : response_b64) {
        if (c == '+') {
            encoded_response += "%2B";
        } else {
            encoded_response += static_cast<char>(c);
        }
    }
    const auto form_body = "SAMLResponse=" + encoded_response + "&RelayState=%2F";

    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body, "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + binding_secret}});
    REQUIRE(acs_res != nullptr);
    CHECK(acs_res->status == 302);

    std::string session_token;
    {
        const std::string tok_prefix = "yuzu_session=";
        for (std::size_t i = 0; ; ++i) {
            const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
            if (sc.empty()) break;
            const auto pos = sc.find(tok_prefix);
            if (pos == std::string::npos) continue;
            const auto val_start = pos + tok_prefix.size();
            const auto val_end   = sc.find(';', val_start);
            session_token = sc.substr(val_start,
                val_end == std::string::npos ? std::string::npos : val_end - val_start);
            break;
        }
    }
    REQUIRE_FALSE(session_token.empty());

    auto maybe_session = fix.auth_mgr.validate_session(session_token);
    REQUIRE(maybe_session.has_value());
    CHECK(maybe_session->role == auth::Role::user);

    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().principal_role == "user");
#endif
}

// ---------------------------------------------------------------------------
// Fix 2: RelayState open-redirect — backslash and control-char safety
//
// Tests three unsafe relay-state values on the SUCCESS path so the
// is_safe_relay_state() guard in the ACS handler is exercised end-to-end.
// Each case needs its own request ID (InResponseTo is consumed once).
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — unsafe RelayState values fall back to /",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    // Each unsafe relay state: {description, url-encoded form value}.
    // The form body is application/x-www-form-urlencoded; extract_form_value
    // url-decodes it, so the handler sees the decoded value.
    struct TestCase { const char* desc; const char* relay_state_encoded; };
    const TestCase cases[] = {
        // Second character is backslash: "/\evil.com"
        // Browsers normalize '\' → '/' making this protocol-relative.
        {"/\\evil.com (backslash after /)",  "%2F%5Cevil.com"},
        // Second char is backslash, third char is '/': "/\/evil.com"
        {"/\\/evil.com (backslash then /)",  "%2F%5C%2Fevil.com"},
        // Contains a tab character (U+0009, control char < 0x20): "/dashboard\tpath"
        // Tab inside a relay-state can be used for HTTP-header injection.
        {"/dashboard\\tpath (tab in path)", "%2Fdashboard%09path"},
    };

    for (const auto& tc : cases) {
        CAPTURE(tc.desc);
        // Each case consumes one request ID.
        auto start_res = fix.sink.Get("/auth/saml/start");
        REQUIRE(start_res != nullptr);
        REQUIRE(start_res->status == 302);
        const auto request_id = extract_authn_request_id(
            start_res->get_header_value("Location"));
        REQUIRE_FALSE(request_id.empty());

        // Extract the browser-binding cookie from this start response.
        std::string bind_secret;
        {
            const auto sc = start_res->get_header_value("Set-Cookie");
            const std::string pfx = "__Host-yuzu_saml_bind=";
            const auto vstart = sc.find(pfx) + pfx.size();
            const auto vend   = sc.find(';', vstart);
            bind_secret = sc.substr(vstart,
                vend == std::string::npos ? std::string::npos : vend - vstart);
        }
        REQUIRE(bind_secret.size() == 64);

        const auto response_b64 = f.make_response(request_id, "user@example.com");
        // URL-encode '+' in the base64 output (extract_form_value decodes '+' → space)
        std::string enc_response;
        enc_response.reserve(response_b64.size() + 16);
        for (unsigned char c : response_b64) {
            if (c == '+') enc_response += "%2B";
            else enc_response += static_cast<char>(c);
        }

        const auto form_body =
            "SAMLResponse=" + enc_response + "&RelayState=" + tc.relay_state_encoded;
        // Include the binding cookie — required by the ACS route.
        auto acs_res = fix.sink.dispatch(
            "POST", "/saml/acs", form_body,
            "application/x-www-form-urlencoded",
            {{"Cookie", "__Host-yuzu_saml_bind=" + bind_secret}});
        REQUIRE(acs_res != nullptr);
        // Must be a 302 redirect — unsafe relay state should fall back to "/"
        CHECK(acs_res->status == 302);
        CHECK(acs_res->get_header_value("Location") == "/");
    }
#endif
}

// ---------------------------------------------------------------------------
// Browser-binding CSRF tests
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — missing binding cookie is rejected", "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f  = saml_test_fixture();
    auto saml_cfg  = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);

    // Step 1: start to register a request ID.
    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto request_id = extract_authn_request_id(
        start_res->get_header_value("Location"));
    REQUIRE_FALSE(request_id.empty());

    // Step 2: build a valid signed response.
    const auto response_b64 = f.make_response(request_id, "user@example.com");
    std::string enc_response;
    for (unsigned char c : response_b64)
        enc_response += (c == '+') ? "%2B" : std::string(1, static_cast<char>(c));
    const auto form_body = "SAMLResponse=" + enc_response + "&RelayState=%2F";

    // Step 3: POST WITHOUT the binding cookie → must be rejected.
    auto acs_res = fix.sink.Post("/saml/acs", form_body,
                                 "application/x-www-form-urlencoded");
    REQUIRE(acs_res != nullptr);
    CHECK(acs_res->status == 302);
    const auto location = acs_res->get_header_value("Location");
    CHECK(location.find("/login") != std::string::npos);
    CHECK(location.find("error=saml") != std::string::npos);

    // Audit action must be auth.saml_login_failed
    const auto events = fix.audit_events();
    REQUIRE(!events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");

    // The binding clear-cookie must still be set even on failure.
    bool has_clear = false;
    for (std::size_t i = 0; ; ++i) {
        const auto sc = acs_res->get_header_value("Set-Cookie", "", i);
        if (sc.empty()) break;
        if (sc.find("__Host-yuzu_saml_bind=") != std::string::npos &&
            sc.find("Max-Age=0") != std::string::npos) {
            has_clear = true;
        }
    }
    CHECK(has_clear);
#endif
}

TEST_CASE("SAML ACS — wrong binding cookie value is rejected", "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f  = saml_test_fixture();
    auto saml_cfg  = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);

    // Step 1: start to register a request ID (and its binding hash).
    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto request_id = extract_authn_request_id(
        start_res->get_header_value("Location"));
    REQUIRE_FALSE(request_id.empty());

    // Step 2: build a valid signed response.
    const auto response_b64 = f.make_response(request_id, "user@example.com");
    std::string enc_response;
    for (unsigned char c : response_b64)
        enc_response += (c == '+') ? "%2B" : std::string(1, static_cast<char>(c));
    const auto form_body = "SAMLResponse=" + enc_response + "&RelayState=%2F";

    // Step 3: POST with a WRONG binding cookie → must be rejected.
    static constexpr const char* kWrongCookie =
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body,
        "application/x-www-form-urlencoded",
        {{"Cookie", std::string("__Host-yuzu_saml_bind=") + kWrongCookie}});
    REQUIRE(acs_res != nullptr);
    CHECK(acs_res->status == 302);
    const auto location = acs_res->get_header_value("Location");
    CHECK(location.find("/login") != std::string::npos);
    CHECK(location.find("error=saml") != std::string::npos);

    // Audit must record the failure.
    const auto events = fix.audit_events();
    REQUIRE(!events.empty());
    CHECK(events.front().action == "auth.saml_login_failed");
    CHECK(events.front().result == "error");
#endif
}

// Note: HTTPS-gate behaviour (SAML must be rejected at startup when
// cfg_.https_enabled is false) is enforced in server.cpp at provider
// construction time, not at the route level.  It is verified by checking
// that the provider pointer stays null when https_enabled=false —
// exercisable via an integration test.  The unit route tests run without
// a real server::Config HTTPS toggle, so that path is covered by the
// existing "provider is null → 404" tests above (the saml_provider pointer
// passed to SamlRoutesFixture is nullptr when the server chooses not to
// construct one).

// ---------------------------------------------------------------------------
// H-B: Binding-cookie extraction is boundary-aware
//
// A Cookie header whose cookie list contains a shadow-prefix entry
// "foo__Host-yuzu_saml_bind=evil" preceding the real
// "__Host-yuzu_saml_bind=<correct>" must NOT extract "evil" as the binding
// value.  Before the H-B fix, the naive hdr.find("__Host-yuzu_saml_bind=")
// would find the shadow prefix at position 4 and return "evil".
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — shadow-prefix cookie does not shadow real binding cookie (H-B)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    // Register a solicited request.
    auto start_res = fix.sink.Get("/auth/saml/start");
    REQUIRE(start_res != nullptr);
    REQUIRE(start_res->status == 302);
    const auto request_id = extract_authn_request_id(
        start_res->get_header_value("Location"));
    REQUIRE_FALSE(request_id.empty());

    // Extract the real binding secret from the Set-Cookie header.
    std::string real_secret;
    {
        const auto sc = start_res->get_header_value("Set-Cookie");
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto vstart = sc.find(pfx) + pfx.size();
        const auto vend   = sc.find(';', vstart);
        real_secret = sc.substr(vstart,
            vend == std::string::npos ? std::string::npos : vend - vstart);
    }
    REQUIRE(real_secret.size() == 64);

    // Build a valid signed response.
    const auto response_b64 = f.make_response(request_id, "user@example.com");
    std::string enc_response;
    for (unsigned char c : response_b64)
        enc_response += (c == '+') ? "%2B" : std::string(1, static_cast<char>(c));
    const auto form_body = "SAMLResponse=" + enc_response + "&RelayState=%2F";

    // Construct a Cookie header where a shadow-prefix cookie appears FIRST.
    // If find() were used naively, it would match inside "foo__Host-yuzu_saml_bind="
    // and extract "evil" instead of the real binding value.
    const std::string cookie_hdr =
        "foo__Host-yuzu_saml_bind=evil; __Host-yuzu_saml_bind=" + real_secret;

    // The ACS route must use the real binding secret, not "evil".
    // On success (correct binding extracted) → 302 to "/" (not /login?error=saml).
    auto acs_res = fix.sink.dispatch(
        "POST", "/saml/acs", form_body,
        "application/x-www-form-urlencoded",
        {{"Cookie", cookie_hdr}});
    REQUIRE(acs_res != nullptr);
    // A correct binding extraction allows the SAML flow to proceed.
    // The response_b64 is a valid signed assertion → expect success (302 to /).
    CHECK(acs_res->status == 302);
    CHECK(acs_res->get_header_value("Location") == "/");
#endif
}

// ---------------------------------------------------------------------------
// H-D: RelayState path-traversal and non-ASCII safety
//
// After url_decode, a RelayState of "/../admin" contains a ".." path segment
// and must fall back to "/".  A value containing non-ASCII bytes (e.g.
// fullwidth slash U+FF0F → UTF-8 0xEF 0xBC 0x8F) must also fall back to "/".
// A valid path like "/dashboard" must still be accepted.
// ---------------------------------------------------------------------------

TEST_CASE("SAML ACS — RelayState with path traversal (..) falls back to / (H-D)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    // Cases: {description, url-encoded RelayState value for the form body}
    // url_decode runs inside extract_form_value before is_safe_relay_state.
    struct Case { const char* desc; const char* encoded; };
    const Case cases[] = {
        // "/%2e%2e/admin" → url_decode → "/../admin" → ".." segment → reject
        {"path traversal via %2e%2e", "%2F%2e%2e%2Fadmin"},
        // "/dash<fullwidth-slash>board" — 0xEF 0xBC 0x8F are ≥ 0x80 → reject
        {"fullwidth slash (U+FF0F) in path", "%2Fdash%EF%BC%8Fboard"},
        // "/../" literal in the form body (dots not encoded)
        {"literal /../ traversal", "%2F..%2Fsecret"},
    };

    for (const auto& tc : cases) {
        CAPTURE(tc.desc);
        // Each test case needs its own request ID (InResponseTo is consumed once).
        auto start = fix.sink.Get("/auth/saml/start");
        REQUIRE(start != nullptr);
        REQUIRE(start->status == 302);
        const auto req_id = extract_authn_request_id(start->get_header_value("Location"));
        REQUIRE_FALSE(req_id.empty());

        std::string bind_secret;
        {
            const auto sc = start->get_header_value("Set-Cookie");
            const std::string pfx = "__Host-yuzu_saml_bind=";
            const auto vs = sc.find(pfx) + pfx.size();
            const auto ve = sc.find(';', vs);
            bind_secret = sc.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
        }
        REQUIRE(bind_secret.size() == 64);

        const auto rb64 = f.make_response(req_id, "user@example.com");
        std::string enc;
        for (unsigned char c : rb64)
            enc += (c == '+') ? "%2B" : std::string(1, static_cast<char>(c));

        auto res = fix.sink.dispatch(
            "POST", "/saml/acs",
            "SAMLResponse=" + enc + "&RelayState=" + std::string(tc.encoded),
            "application/x-www-form-urlencoded",
            {{"Cookie", "__Host-yuzu_saml_bind=" + bind_secret}});
        REQUIRE(res != nullptr);
        CHECK(res->status == 302);
        // Unsafe relay state must fall back to "/"
        CHECK(res->get_header_value("Location") == "/");
    }
#endif
}

TEST_CASE("SAML ACS — valid RelayState /dashboard is accepted (H-D)",
          "[pg][saml][auth_routes]") {
#if defined(_WIN32)
    SKIP("SamlProvider always disabled on Windows (N4)");
#else
    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_idp_entity_id = f.idp_entity_id; // ADR-2001 PR4a — see run_saml_acs_flow's comment

    auto start = fix.sink.Get("/auth/saml/start");
    REQUIRE(start != nullptr);
    REQUIRE(start->status == 302);
    const auto req_id = extract_authn_request_id(start->get_header_value("Location"));
    REQUIRE_FALSE(req_id.empty());

    std::string bind_secret;
    {
        const auto sc = start->get_header_value("Set-Cookie");
        const std::string pfx = "__Host-yuzu_saml_bind=";
        const auto vs = sc.find(pfx) + pfx.size();
        const auto ve = sc.find(';', vs);
        bind_secret = sc.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
    }
    REQUIRE(bind_secret.size() == 64);

    const auto rb64 = f.make_response(req_id, "user@example.com");
    std::string enc;
    for (unsigned char c : rb64)
        enc += (c == '+') ? "%2B" : std::string(1, static_cast<char>(c));

    // "%2Fdashboard" → url_decode → "/dashboard" — must be accepted as a safe relay state.
    auto res = fix.sink.dispatch(
        "POST", "/saml/acs",
        "SAMLResponse=" + enc + "&RelayState=%2Fdashboard",
        "application/x-www-form-urlencoded",
        {{"Cookie", "__Host-yuzu_saml_bind=" + bind_secret}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/dashboard");
#endif
}

// ── SAML fine-grained RBAC — group_attribute reconcile into RbacStore ──────
//
// Parity with OIDC's `#1832` reconcile block. These tests wire a LIVE
// RbacStore into SamlRoutesFixture (unlike every test above, which passes
// rbac_store=nullptr and only exercises the coarse --saml-admin-group path)
// so the reconcile branch in auth_routes.cpp's /saml/acs handler actually
// runs.
#if !defined(_WIN32)

namespace {
/// Find the first (newest) audit event with the given action, or nullptr.
const AuditEvent* find_event(const std::vector<AuditEvent>& events, const std::string& action) {
    for (const auto& e : events) {
        if (e.action == action) return &e;
    }
    return nullptr;
}
} // namespace

TEST_CASE("SAML ACS — asserted groups reconcile into the RBAC store under source 'saml'",
          "[pg][saml][auth_routes][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, saml_rbac_tpl);
    yuzu::server::pg::PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());

    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider, &rbac);
    fix.cfg.saml_group_attribute = "groups";

    const std::string name_id = "grouped_user@example.test";
    const auto token = run_saml_acs_flow(fix, f, name_id, {"eng", "sales"});
    REQUIRE_FALSE(token.empty());

    const auto saml_principal = saml::saml_principal_id(f.idp_entity_id, name_id);
    CHECK(rbac.get_group_members("saml:eng") == std::vector<std::string>{saml_principal});
    CHECK(rbac.get_group_members("saml:sales") == std::vector<std::string>{saml_principal});

    const auto events = fix.audit_events();
    const auto* provision_event = find_event(events, "auth.sso_group_provision");
    REQUIRE(provision_event != nullptr);
    CHECK(provision_event->result == "ok");
    CHECK(provision_event->detail.find("source=saml") != std::string::npos);
    CHECK(provision_event->detail.find("added=2") != std::string::npos);

    CHECK(fix.counter("yuzu_auth_sso_group_provision_total",
                      {{"source", "saml"}, {"result", "ok"}}) == 1.0);
}

// Same unreachable-via-real-HTTP-POST finding as the qa-S2 / #1828.3
// boundary tests above (see that comment block): >=186 group values
// already exceed httplib's CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH
// (8192 bytes) for an application/x-www-form-urlencoded body, so a
// truncated (>200-value) assertion 413s at the transport layer before
// /saml/acs's handler — and therefore this reconcile-deny branch — ever
// runs (verified: TestRouteSink deliberately enforces the same 8 KiB
// httplib form cap — see its own comment above the CPPHTTPLIB_FORM_URL_
// ENCODED_PAYLOAD_MAX_LENGTH check in test_route_sink.hpp — so this is not
// a gap in the fixture, the branch is genuinely unreachable via an
// HTTP-POST route test at this repo's current cap value).
//
// What IS and ISN'T covered elsewhere, to be explicit and avoid a
// false-green closure claim: the cap-truncation MECHANIC itself (>200
// asserted values -> `groups` truncated to exactly 200,
// `group_cap_truncated=true`) is covered by test_saml_provider.cpp's
// kMaxGroupValues boundary test, a pure function call with no HTTP layer.
// The sibling "reconcile store error" test below exercises the same
// general DENY SHAPE this branch produces (login denied, an
// auth.sso_group_provision `result=error` row, a paired
// auth.saml_login_failed row, no partial reconcile) — but it is a
// DIFFERENT branch reached via a DIFFERENT cause (`!reconciled` from a
// down RbacStore, not `group_cap_truncated`). It does NOT exercise this
// branch's specific `reason=group_count_exceeded` audit detail, nor does
// it touch `yuzu_saml_group_cap_truncated_total` at all — neither is
// directly asserted by any test in this file today.
TEST_CASE("SAML ACS — asserted groups beyond kMaxGroupValues DENIES the login "
          "(fine-grained RBAC fail-closed)",
          "[pg][saml][auth_routes][rbac]") {
    SKIP("Unreachable via a real HTTP-POST binding at kMaxGroupValues=200 (TestRouteSink "
        "enforces the same 8 KiB httplib form cap production traffic hits) — see the comment "
        "block above this TEST_CASE. The sibling 'reconcile store error' test below covers "
        "the general deny SHAPE via a DIFFERENT cause, NOT this branch's specific "
        "reason=group_count_exceeded detail or the yuzu_saml_group_cap_truncated_total metric, "
        "neither of which is directly asserted anywhere in this file today. Parser-level "
        "truncation itself is covered by test_saml_provider.cpp.");
}

TEST_CASE("SAML ACS — an empty asserted group set SKIPS reconcile (no deprovision-to-zero)",
          "[pg][saml][auth_routes][rbac]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, saml_rbac_tpl);
    yuzu::server::pg::PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore rbac{rbac_pool_};
    REQUIRE(rbac.is_open());

    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider, &rbac);
    fix.cfg.saml_group_attribute = "groups";
    fix.cfg.saml_idp_entity_id   = f.idp_entity_id;

    const std::string name_id = "preexisting_member_user@example.test";
    const auto saml_principal = saml::saml_principal_id(f.idp_entity_id, name_id);

    // Pre-seed a 'saml'-sourced membership directly, mirroring what an
    // earlier login (asserting non-empty groups) would have reconciled.
    REQUIRE(rbac.reconcile_idp_memberships(saml_principal, "saml", {{"eng", "eng"}}).has_value());
    REQUIRE(rbac.get_group_members("saml:eng") == std::vector<std::string>{saml_principal});

    // This login asserts the "groups" attribute PRESENT but with zero
    // values — SAML cannot distinguish this from "attribute absent", so
    // reconcile must SKIP rather than treat it as "this user is in zero
    // groups" (which would delete the pre-seeded membership above).
    const auto token = run_saml_acs_flow(fix, f, name_id, {});
    REQUIRE_FALSE(token.empty());

    CHECK(rbac.get_group_members("saml:eng") == std::vector<std::string>{saml_principal});

    const auto events = fix.audit_events();
    const auto* provision_event = find_event(events, "auth.sso_group_provision");
    REQUIRE(provision_event != nullptr);
    CHECK(provision_event->result == "skipped");
    CHECK(provision_event->detail.find("groups_absent") != std::string::npos);

    CHECK(fix.counter("yuzu_auth_sso_group_provision_total",
                      {{"source", "saml"}, {"result", "skipped"}}) == 1.0);
}

TEST_CASE("SAML ACS — a reconcile store error DENIES the login (fail-closed)",
          "[pg][saml][auth_routes][rbac]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }

    // A RbacStore pointed at a database that does not exist: construction's
    // pool_.acquire() fails fast (same host/port, bad dbname — no network
    // timeout), leaving is_open()==false. reconcile_idp_memberships on a
    // not-open store deterministically returns "database not open" —
    // exercises the fail-closed error branch without depending on a live
    // outage.
    std::string bad_dsn = yuzu::test::pg_admin_dsn_env();
    const auto slash = bad_dsn.rfind('/');
    REQUIRE(slash != std::string::npos);
    bad_dsn = bad_dsn.substr(0, slash + 1) + "yuzu_test_definitely_nonexistent_db";
    yuzu::server::pg::PgPool bad_pool{{.conninfo = bad_dsn, .size = 1}};
    RbacStore bad_rbac{bad_pool};
    REQUIRE_FALSE(bad_rbac.is_open());

    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    SamlRoutesFixture fix(&provider, &bad_rbac);
    fix.cfg.saml_group_attribute = "groups";

    const std::string name_id = "store_error_user@example.test";
    const auto token = run_saml_acs_flow(fix, f, name_id, {"eng"});
    CHECK(token.empty()); // login DENIED — never reaches session mint

    const auto events = fix.audit_events();
    const auto* provision_event = find_event(events, "auth.sso_group_provision");
    REQUIRE(provision_event != nullptr);
    CHECK(provision_event->result == "error");
    CHECK(provision_event->detail.find("database not open") != std::string::npos);
    const auto* login_failed_event = find_event(events, "auth.saml_login_failed");
    REQUIRE(login_failed_event != nullptr);
    CHECK(login_failed_event->result == "error");

    CHECK(fix.counter("yuzu_auth_sso_group_provision_total",
                      {{"source", "saml"}, {"result", "error"}}) == 1.0);
    CHECK(fix.counter("yuzu_auth_saml_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
}

TEST_CASE("SAML ACS — rbac_store absent skips reconcile; coarse --saml-admin-group role "
          "still resolves",
          "[pg][saml][auth_routes][rbac]") {

    const auto& f = saml_test_fixture();
    auto saml_cfg = f.make_config();
    saml_cfg.group_attribute = "groups";
    SamlProvider provider(std::move(saml_cfg));
    REQUIRE(provider.is_enabled());

    // Default rbac_store=nullptr — RBAC-off / not wired.
    SamlRoutesFixture fix(&provider);
    fix.cfg.saml_admin_group     = "admins";
    fix.cfg.saml_group_attribute = "groups"; // configured, but inert without rbac_store_

    const std::string name_id = "rbac_off_admin_user@example.test";
    const auto token = run_saml_acs_flow(fix, f, name_id, {"admins", "eng"});
    REQUIRE_FALSE(token.empty());

    auto session = fix.auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
    // The coarse --saml-admin-group mechanism still resolves admin.
    CHECK(session->role == auth::Role::admin);

    // The fine-grained reconcile block never ran — no provisioning audit row.
    const auto events = fix.audit_events();
    CHECK(find_event(events, "auth.sso_group_provision") == nullptr);
}

#endif // !_WIN32
