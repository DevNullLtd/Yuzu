/**
 * test_saml_provider.cpp — Unit tests for yuzu::server::saml::SamlProvider
 *
 * Coverage (tag [saml]):
 *   - Valid signed assertion + correct pinned cert             → accepted
 *   - Tampered assertion body (post-sign edit)                 → rejected
 *   - Signature-wrapping (XSW): second Assertion injected      → rejected
 *   - Expired NotOnOrAfter                                     → rejected
 *   - Wrong Audience                                           → rejected
 *   - Missing / wrong InResponseTo (replay, unsolicited)       → rejected
 *   - No Signature element present                             → rejected
 *   - Signed by a different cert (not the pinned one)          → rejected
 *   - Provider not enabled                                     → rejected early
 *   - build_authn_request: URL well-formed + relay_state wired → accepted
 *   - cleanup_expired_states removes stale entries             → accepted
 *
 * Fixture generation:
 *   SamlTestFixture generates a fresh RSA-2048 key pair + 100-year
 *   self-signed X.509 cert at construction (OpenSSL C API).  make_response()
 *   builds a SAML Response XML template and signs it with the private key via
 *   xmlsec1's xmlSecDSigCtxSign, returning the base64-encoded signed response.
 *   Test assertions about rejection use this same infrastructure with
 *   controlled mutations.
 *
 *   xmlsec1 requires global init before any operation — the first
 *   SamlProvider construction triggers it via std::call_once in
 *   saml_provider.cpp. The fixture triggers that init by constructing a
 *   disabled SamlProvider before calling any xmlsec function directly.
 */

#include "../test_helpers.hpp"
#include "saml_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <string>

// On Windows the SAML provider is a stub — skip all tests that need real XML-DSig.
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
#include <memory>
#include <sstream>

using namespace yuzu::server::saml;

// ── SAML XML namespace constants (for template construction) ──────────────────
static constexpr const char* kAssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
static constexpr const char* kProtocolNs  = "urn:oasis:names:tc:SAML:2.0:protocol";
static constexpr const char* kDSigNs      = "http://www.w3.org/2000/09/xmldsig#";

// ── SamlTestFixture ───────────────────────────────────────────────────────────

struct SamlTestFixture {
    std::string cert_pem;     ///< PEM-encoded self-signed X.509 cert (public key)
    std::string priv_key_pem; ///< PEM-encoded RSA-2048 private key (for signing)
    std::string cert_pem_b;   ///< Second key pair for "wrong cert" tests
    std::string priv_key_pem_b;

    const std::string sp_entity_id = "https://sp.yuzu.test/saml/metadata";
    const std::string sp_acs_url   = "https://sp.yuzu.test/saml/acs";
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
    ///
    /// @param request_id        Value to put in SubjectConfirmationData.InResponseTo
    /// @param name_id           NameID value
    /// @param nooa_seconds_from_now  Assertion expiry (negative = already expired)
    /// @param audience          Audience value (should match sp_entity_id for happy path)
    /// @param recipient         Recipient URL (should match sp_acs_url for happy path)
    /// @param inject_extra_assertion  If true, inserts a second unsigned Assertion (XSW test)
    /// @param signing_priv_key  Which private key to sign with (default: priv_key_pem)
    /// @param use_sha1_algorithms  If true, the SignedInfo template requests
    ///        rsa-sha1 / sha1 instead of rsa-sha256 / sha256 — used to prove the
    ///        algorithm allowlist rejects a legitimately-pinned-key SHA-1 signature.
    /// @param use_sha1_digest_only  If true, the SignatureMethod stays rsa-sha256
    ///        but the Reference DigestMethod is sha1 — isolates the Reference-digest
    ///        allowlist (proves the digest is restricted, not just the SignatureMethod).
    /// @param evil_attribute_statement_xml  Only used when inject_extra_assertion
    ///        is true: an <saml:AttributeStatement> (e.g. from
    ///        make_attribute_statement) embedded in the UNSIGNED injected
    ///        assertion — qa-S3, proves group extraction never leaks a value
    ///        from the unverified node.
    /// @param name_id_format    ADR-2001 PR4a — the NameID Format attribute
    ///        value. Defaults to the SAML 1.1 emailAddress format (a
    ///        STABLE/linkable format, matching the codebase's original
    ///        hardcoded behaviour). Pass an empty string to omit the
    ///        Format attribute entirely (models an IdP that never sends
    ///        one — the "missing Format" case).
    std::string make_response(
        const std::string& request_id,
        const std::string& name_id        = "user@example.com",
        int64_t nooa_seconds_from_now     = 3600,
        const std::string& audience       = {},
        const std::string& recipient      = {},
        bool inject_extra_assertion       = false,
        const std::string* signing_priv_key = nullptr,
        bool use_sha1_algorithms           = false,
        bool use_sha1_digest_only          = false,
        const std::string& attribute_statement_xml = {},
        const std::string& evil_attribute_statement_xml = {},
        const std::string& name_id_format =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") const
    {
        const auto& aud = audience.empty()  ? sp_entity_id : audience;
        const auto& rec = recipient.empty() ? sp_acs_url   : recipient;
        const auto& key = signing_priv_key ? *signing_priv_key : priv_key_pem;
        const std::string sig_method_uri = use_sha1_algorithms
            ? "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        const std::string digest_method_uri = (use_sha1_algorithms || use_sha1_digest_only)
            ? "http://www.w3.org/2000/09/xmldsig#sha1"
            : "http://www.w3.org/2001/04/xmlenc#sha256";

        // Time stamps
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

        const std::string assertion_id  = "_test_assertion_001";
        const std::string response_id   = "_test_response_001";

        // The assertion XML: Signature template (empty DigestValue / SignatureValue)
        // follows the Issuer element per SAML Core 5.4.1.
        // clang-format off
        std::string assertion_xml =
            "<saml:Assertion"
              " xmlns:saml=\"" + std::string(kAssertionNs) + "\""
              " ID=\"" + assertion_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\">"
              "<saml:Issuer>" + idp_entity_id + "</saml:Issuer>"
              "<ds:Signature xmlns:ds=\"" + std::string(kDSigNs) + "\">"
                "<ds:SignedInfo>"
                  "<ds:CanonicalizationMethod"
                    " Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
                  "<ds:SignatureMethod"
                    " Algorithm=\"" + sig_method_uri + "\"/>"
                  "<ds:Reference URI=\"#" + assertion_id + "\">"
                    "<ds:Transforms>"
                      "<ds:Transform"
                        " Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                      "<ds:Transform"
                        " Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
                    "</ds:Transforms>"
                    "<ds:DigestMethod Algorithm=\"" + digest_method_uri + "\"/>"
                    "<ds:DigestValue/>"
                  "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue/>"
              "</ds:Signature>"
              "<saml:Subject>"
                "<saml:NameID"
                  + (name_id_format.empty() ? std::string{} : " Format=\"" + name_id_format + "\"")
                  + ">"
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

        // Optional second (unsigned) Assertion for XSW test
        std::string evil_assertion_xml;
        if (inject_extra_assertion) {
            // clang-format off
            evil_assertion_xml =
                "<saml:Assertion"
                  " xmlns:saml=\"" + std::string(kAssertionNs) + "\""
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
                  + evil_attribute_statement_xml +
                "</saml:Assertion>";
            // clang-format on
        }

        // Full Response wrapper
        // clang-format off
        std::string response_xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kProtocolNs) + "\""
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

        // Sign the assertion using xmlsec1
        const std::string signed_xml = sign_assertion(response_xml, assertion_id, key);

        // Base64-encode the final signed response
        return b64_encode(
            reinterpret_cast<const unsigned char*>(signed_xml.data()),
            signed_xml.size());
    }

    /// Produce a response without any ds:Signature element in the Assertion.
    std::string make_unsigned_response(
        const std::string& request_id,
        const std::string& name_id = "user@example.com") const
    {
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
        const auto nooa_str      = fmt_epoch(now_epoch + 3600);
        const auto nb_str        = fmt_epoch(now_epoch - 5);
        // clang-format off
        std::string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kProtocolNs) + "\""
              " ID=\"_resp\" Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\""
              " InResponseTo=\"" + request_id + "\""
              " Destination=\"" + sp_acs_url + "\">"
              "<samlp:Status>"
                "<samlp:StatusCode"
                  " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              "</samlp:Status>"
              "<saml:Assertion"
                " xmlns:saml=\"" + std::string(kAssertionNs) + "\""
                " ID=\"_asr\" Version=\"2.0\""
                " IssueInstant=\"" + issue_instant + "\">"
                "<saml:Issuer>idp</saml:Issuer>"
                "<saml:Subject>"
                  "<saml:NameID>" + name_id + "</saml:NameID>"
                  "<saml:SubjectConfirmation"
                    " Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                    "<saml:SubjectConfirmationData"
                      " NotOnOrAfter=\"" + nooa_str + "\""
                      " Recipient=\"" + sp_acs_url + "\""
                      " InResponseTo=\"" + request_id + "\"/>"
                  "</saml:SubjectConfirmation>"
                "</saml:Subject>"
                "<saml:Conditions NotBefore=\"" + nb_str + "\" NotOnOrAfter=\"" + nooa_str + "\">"
                  "<saml:AudienceRestriction>"
                    "<saml:Audience>" + sp_entity_id + "</saml:Audience>"
                  "</saml:AudienceRestriction>"
                "</saml:Conditions>"
              "</saml:Assertion>"
            "</samlp:Response>";
        // clang-format on
        return b64_encode(reinterpret_cast<const unsigned char*>(xml.data()), xml.size());
    }

    // ── Helpers for negative-test variants (mandatory-element tests) ─────────────

    /// Build a signed response whose Assertion carries an incorrect Issuer value.
    std::string make_response_wrong_issuer(const std::string& request_id) const {
        return make_signed_with_body(request_id,
            "wrong-entity-not-" + idp_entity_id, // issuer
            true,  // include_aud_restriction
            true,  // include_scd_recipient
            true); // include_scd_nooa
    }

    /// Build a signed response whose Assertion has no <saml:Issuer> element.
    std::string make_response_no_issuer(const std::string& request_id) const {
        return make_signed_with_body(request_id,
            {},    // empty → omit Issuer element
            true, true, true);
    }

    /// Build a signed response whose Assertion has no <saml:Conditions> element.
    std::string make_response_no_conditions(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            true, true, true, /*include_conditions=*/false);
    }

    /// Build a signed response whose Conditions has no <AudienceRestriction>.
    std::string make_response_no_audience_restriction(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            /*include_aud_restriction=*/false, true, true);
    }

    /// Build a signed response whose SubjectConfirmation has no SCD element.
    std::string make_response_no_scd(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            true, true, true, true, /*include_scd=*/false);
    }

    /// Build a signed response whose SCD element has no Recipient attribute.
    std::string make_response_scd_no_recipient(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            true, /*include_scd_recipient=*/false, true);
    }

    /// Build a signed response whose SCD element has no NotOnOrAfter attribute.
    std::string make_response_scd_no_nooa(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            true, true, /*include_scd_nooa=*/false);
    }

    /// Build a signed response whose Conditions element is present but has NO
    /// NotOnOrAfter attribute (F4 regression test: WebSSO profile requires it).
    std::string make_response_conditions_no_nooa(const std::string& request_id) const {
        return make_signed_with_body(request_id, idp_entity_id,
            true, true, true, /*include_conditions=*/true,
            /*include_scd=*/true, /*include_conditions_nooa=*/false);
    }

    /// Build a base64-encoded response XML that contains a DOCTYPE declaration.
    /// This does NOT need to be signed — DOCTYPE rejection happens before signature
    /// verification (step 2.5 in validate_response).
    std::string make_doctype_response(const std::string& request_id) const {
        auto now_epoch = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto issue_instant = fmt_epoch_fn(now_epoch);
        // clang-format off
        std::string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<!DOCTYPE samlp:Response ["
              "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"
            "]>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kProtocolNs) + "\""
              " ID=\"_resp_dtd\" Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\""
              " InResponseTo=\"" + request_id + "\""
              " Destination=\"" + sp_acs_url + "\">"
              "<samlp:Status>"
                "<samlp:StatusCode"
                  " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              "</samlp:Status>"
            "</samlp:Response>";
        // clang-format on
        return b64_encode(reinterpret_cast<const unsigned char*>(xml.data()), xml.size());
    }

    /// Build a base64-encoded samlp:Response whose body nests `depth` levels of
    /// dummy elements — deeper than the validate_response XSW-walk depth cap.
    /// Rejection happens in collect_assertions (before signature verification),
    /// so it needs no signature. `depth` stays well under libxml2's own 256
    /// parse cap so libxml2 parses it and our own guard is what rejects it.
    std::string make_deeply_nested_response(int depth) const {
        std::string open;
        std::string close;
        for (int i = 0; i < depth; ++i) { open += "<x>"; close += "</x>"; }
        std::string xml =
            "<samlp:Response xmlns:samlp=\"" + std::string(kProtocolNs) + "\">" +
            open + close +
            "</samlp:Response>";
        return b64_encode(reinterpret_cast<const unsigned char*>(xml.data()), xml.size());
    }

    // ── H-E: make_response_with_duplicate_id ─────────────────────────────────
    // Build a signed response that contains a non-Assertion element carrying
    // the same ID value as the signed Assertion.  The attack vector is:
    //
    //   <samlp:Response>
    //     <samlp:Extensions xml:id="_test_assertion_001"/> ← DECOY with same ID
    //     <saml:Assertion ID="_test_assertion_001">       ← signed assertion
    //       <ds:Signature …/>
    //       …
    //     </saml:Assertion>
    //   </samlp:Response>
    //
    // validate_response must reject this document via the duplicate-ID scan.
    // The "xml:id" attribute is used on the decoy element to test that the scan
    // covers both "ID" and "xml:id" attributes (H-E requirement).
    std::string make_response_with_duplicate_id(const std::string& request_id) const {
        auto now_epoch = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto issue_instant = fmt_epoch_fn(now_epoch);
        const auto nb_str        = fmt_epoch_fn(now_epoch - 5);
        const auto nooa_str      = fmt_epoch_fn(now_epoch + 3600);

        const std::string assertion_id = "_test_assertion_001";
        const std::string response_id  = "_test_dup_id_resp_001";

        // clang-format off
        const std::string assertion_xml =
            "<saml:Assertion"
              " xmlns:saml=\"" + std::string(kAssertionNs) + "\""
              " ID=\"" + assertion_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\">"
              "<saml:Issuer>" + idp_entity_id + "</saml:Issuer>"
              "<ds:Signature xmlns:ds=\"" + std::string(kDSigNs) + "\">"
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
                  "user@example.com"
                "</saml:NameID>"
                "<saml:SubjectConfirmation"
                  " Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                  "<saml:SubjectConfirmationData"
                    " NotOnOrAfter=\"" + nooa_str + "\""
                    " Recipient=\"" + sp_acs_url + "\""
                    " InResponseTo=\"" + request_id + "\"/>"
                "</saml:SubjectConfirmation>"
              "</saml:Subject>"
              "<saml:Conditions"
                " NotBefore=\"" + nb_str + "\""
                " NotOnOrAfter=\"" + nooa_str + "\">"
                "<saml:AudienceRestriction>"
                  "<saml:Audience>" + sp_entity_id + "</saml:Audience>"
                "</saml:AudienceRestriction>"
              "</saml:Conditions>"
            "</saml:Assertion>";

        // The decoy element uses xml:id (not plain "ID") so the test exercises
        // the xml:id branch of the duplicate-ID scan.
        const std::string decoy_xml =
            "<samlp:Extensions"
              " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
              " xml:id=\"" + assertion_id + "\""
            "/>";

        const std::string response_xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kProtocolNs) + "\""
              " ID=\"" + response_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\""
              " InResponseTo=\"" + request_id + "\""
              " Destination=\"" + sp_acs_url + "\">"
              "<samlp:Status>"
                "<samlp:StatusCode"
                  " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              "</samlp:Status>"
              + decoy_xml        // decoy with duplicate xml:id before the Assertion
              + assertion_xml +  // signed Assertion
            "</samlp:Response>";
        // clang-format on

        const std::string signed_xml = sign_assertion(response_xml, assertion_id, priv_key_pem);
        return b64_encode(
            reinterpret_cast<const unsigned char*>(signed_xml.data()), signed_xml.size());
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
    // ── OpenSSL: generate RSA-2048 key + 100-year self-signed cert ────────────

    static void generate_key_pair(std::string& out_cert_pem, std::string& out_key_pem) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        // Generate RSA 2048 key pair.
        // All raw pointers are immediately wrapped in scope guards (same RAII
        // idiom as the production DocGuard/DsigGuard) so a failing REQUIRE cannot
        // leak OpenSSL handles on unwind.
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        REQUIRE(rsa != nullptr);
        // rsa guard: released once pkey takes ownership via EVP_PKEY_assign_RSA.
        struct RsaGuard { RSA* r; ~RsaGuard() { if (r) RSA_free(r); } } rsg{rsa};

        EVP_PKEY* pkey = EVP_PKEY_new();
        REQUIRE(pkey != nullptr);
        struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pkg{pkey};

        REQUIRE(EVP_PKEY_assign_RSA(pkey, rsa) == 1);
        rsg.r = nullptr; // pkey now owns rsa; disarm the RSA guard
#pragma GCC diagnostic pop

        // Build self-signed X.509 cert valid for 100 years.
        X509* cert = X509_new();
        REQUIRE(cert != nullptr);
        struct CertGuard { X509* c; ~CertGuard() { if (c) X509_free(c); } } cg{cert};

        X509_set_version(cert, 2); // X509v3
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

        // Valid for 100 years from now
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60LL * 60 * 24 * 365 * 100);

        X509_set_pubkey(cert, pkey);

        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("Test IdP"),
                                   -1, -1, 0);
        X509_set_issuer_name(cert, name);
        REQUIRE(X509_sign(cert, pkey, EVP_sha256()) > 0);

        // Export cert PEM — nested scope so BIO is freed before any throw.
        {
            BIO* bio = BIO_new(BIO_s_mem());
            REQUIRE(bio != nullptr);
            struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
            REQUIRE(PEM_write_bio_X509(bio, cert) == 1);
            BUF_MEM* bptr = nullptr;
            BIO_get_mem_ptr(bio, &bptr);
            out_cert_pem.assign(bptr->data, bptr->length);
        }

        // Export private key PEM.
        {
            BIO* bio = BIO_new(BIO_s_mem());
            REQUIRE(bio != nullptr);
            struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
            REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
            BUF_MEM* bptr = nullptr;
            BIO_get_mem_ptr(bio, &bptr);
            out_key_pem.assign(bptr->data, bptr->length);
        }
        // CertGuard and PkeyGuard clean up on scope exit.
    }

    // ── xmlsec1: sign the XML template's <ds:Signature> in the Assertion ─────

    static std::string sign_assertion(
        const std::string& response_xml,
        const std::string& assertion_id,
        const std::string& private_key_pem)
    {
        // Parse the template
        xmlDocPtr doc = xmlReadMemory(
            response_xml.data(), static_cast<int>(response_xml.size()),
            "sign_tmpl.xml", nullptr,
            XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        REQUIRE(doc != nullptr);

        struct DocGuard { xmlDocPtr d; ~DocGuard() { if (d) xmlFreeDoc(d); } } dg{doc};

        xmlNodePtr root = xmlDocGetRootElement(doc);
        REQUIRE(root != nullptr);

        // Find the Assertion element and register its ID so xmlsec can resolve
        // the Reference URI="#assertion_id" fragment reference.
        xmlNodePtr assertion_node = nullptr;
        for (xmlNodePtr n = xmlFirstElementChild(root); n; n = xmlNextElementSibling(n)) {
            if (n->type == XML_ELEMENT_NODE &&
                n->name && xmlStrEqual(n->name, BAD_CAST "Assertion") &&
                n->ns && n->ns->href &&
                xmlStrEqual(n->ns->href, BAD_CAST kAssertionNs)) {
                const std::string id = [n]() -> std::string {
                    xmlChar* v = xmlGetProp(n, BAD_CAST "ID");
                    if (!v) return {};
                    std::string s(reinterpret_cast<const char*>(v));
                    xmlFree(v);
                    return s;
                }();
                if (id == assertion_id) {
                    assertion_node = n;
                    // Register as XML ID
                    xmlAttrPtr id_attr = xmlHasProp(n, BAD_CAST "ID");
                    if (id_attr) xmlAddID(nullptr, doc, BAD_CAST id.c_str(), id_attr);
                    break;
                }
            }
        }
        REQUIRE(assertion_node != nullptr);

        // Find the <ds:Signature> node (direct child of Assertion)
        xmlNodePtr sig_node = nullptr;
        for (xmlNodePtr n = xmlFirstElementChild(assertion_node); n;
             n = xmlNextElementSibling(n)) {
            if (n->type == XML_ELEMENT_NODE &&
                n->name && xmlStrEqual(n->name, BAD_CAST "Signature") &&
                n->ns && n->ns->href && xmlStrEqual(n->ns->href, BAD_CAST kDSigNs)) {
                sig_node = n;
                break;
            }
        }
        REQUIRE(sig_node != nullptr);

        // Load the private key for signing (xmlSecKeyDataFormatPem = PEM private key).
        // Wrap in a scope guard so a failing REQUIRE cannot leak the key handle.
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

        // Create DSig context — wrap in a guard before transferring key ownership.
        xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(nullptr);
        REQUIRE(ctx != nullptr);
        struct CtxGuard {
            xmlSecDSigCtxPtr c;
            ~CtxGuard() { if (c) xmlSecDSigCtxDestroy(c); }
        } cg{ctx};

        ctx->signKey = sign_key; // ctx takes ownership of sign_key
        kg.k = nullptr;          // disarm key guard — ctx destructor will free it

        const int sign_ret = xmlSecDSigCtxSign(ctx, sig_node);
        // CtxGuard destructs the context whether or not the REQUIRE below throws,
        // so we do not manually call xmlSecDSigCtxDestroy here.
        REQUIRE(sign_ret == 0);

        // Serialize the signed document back to XML string.
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

    // ── fmt_epoch_fn helper (shared by response builders) ─────────────────────

    static std::string fmt_epoch_fn(int64_t epoch) {
        time_t t = static_cast<time_t>(epoch);
        struct tm utc{};
        gmtime_r(&t, &utc);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
        return std::string(buf);
    }

    // ── Generic signed-response builder for negative-test variants ─────────────
    // Builds a response XML with the specified optional elements, signs the
    // assertion, and returns the base64-encoded signed response.
    //
    // @param issuer_text              Assertion Issuer text; empty string → omit element.
    // @param include_aud_restriction  Include AudienceRestriction in Conditions.
    // @param include_scd_recipient    Include Recipient attribute in SCD.
    // @param include_scd_nooa         Include NotOnOrAfter attribute in SCD.
    // @param include_conditions       Include <saml:Conditions> element at all.
    // @param include_scd              Include <saml:SubjectConfirmationData>.
    // @param include_conditions_nooa  Include NotOnOrAfter attribute in Conditions.
    std::string make_signed_with_body(
        const std::string& request_id,
        const std::string& issuer_text,         // "" → omit the Issuer element
        bool include_aud_restriction  = true,
        bool include_scd_recipient    = true,
        bool include_scd_nooa         = true,
        bool include_conditions       = true,
        bool include_scd              = true,
        bool include_conditions_nooa  = true) const
    {
        const auto now_epoch = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const auto issue_instant = fmt_epoch_fn(now_epoch);
        const auto nb_str        = fmt_epoch_fn(now_epoch - 5);
        const auto nooa_str      = fmt_epoch_fn(now_epoch + 3600);

        const std::string assertion_id = "_test_neg_assertion_001";
        const std::string response_id  = "_test_neg_response_001";

        // Optional elements
        const std::string issuer_elem = issuer_text.empty() ? std::string{}
            : ("<saml:Issuer>" + issuer_text + "</saml:Issuer>");

        const std::string recipient_attr = include_scd_recipient
            ? (" Recipient=\"" + sp_acs_url + "\"") : std::string{};
        const std::string nooa_attr = include_scd_nooa
            ? (" NotOnOrAfter=\"" + nooa_str + "\"") : std::string{};

        const std::string scd_elem = include_scd
            ? ("<saml:SubjectConfirmationData"
               + nooa_attr + recipient_attr +
               " InResponseTo=\"" + request_id + "\"/>")
            : std::string{};

        const std::string aud_restr_elem = include_aud_restriction
            ? ("<saml:AudienceRestriction>"
               "<saml:Audience>" + sp_entity_id + "</saml:Audience>"
               "</saml:AudienceRestriction>")
            : std::string{};

        const std::string conditions_nooa_attr = include_conditions_nooa
            ? (" NotOnOrAfter=\"" + nooa_str + "\"") : std::string{};
        const std::string conditions_elem = include_conditions
            ? ("<saml:Conditions NotBefore=\"" + nb_str + "\"" + conditions_nooa_attr + ">"
               + aud_restr_elem +
               "</saml:Conditions>")
            : std::string{};

        // clang-format off
        const std::string assertion_xml =
            "<saml:Assertion"
              " xmlns:saml=\"" + std::string(kAssertionNs) + "\""
              " ID=\"" + assertion_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\">"
              + issuer_elem +
              "<ds:Signature xmlns:ds=\"" + std::string(kDSigNs) + "\">"
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
                "<saml:NameID>user@example.com</saml:NameID>"
                "<saml:SubjectConfirmation"
                  " Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                  + scd_elem +
                "</saml:SubjectConfirmation>"
              "</saml:Subject>"
              + conditions_elem +
            "</saml:Assertion>";

        const std::string response_xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<samlp:Response"
              " xmlns:samlp=\"" + std::string(kProtocolNs) + "\""
              " ID=\"" + response_id + "\""
              " Version=\"2.0\""
              " IssueInstant=\"" + issue_instant + "\""
              " InResponseTo=\"" + request_id + "\""
              " Destination=\"" + sp_acs_url + "\">"
              "<samlp:Status>"
                "<samlp:StatusCode"
                  " Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
              "</samlp:Status>"
              + assertion_xml +
            "</samlp:Response>";
        // clang-format on

        const std::string signed_xml = sign_assertion(response_xml, assertion_id, priv_key_pem);
        return b64_encode(
            reinterpret_cast<const unsigned char*>(signed_xml.data()), signed_xml.size());
    }

    // ── Standard base64 encode (for response wrapper) ─────────────────────────

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

// ── Shared fixture (key generation is expensive; done once per binary run) ────
// Catch2 does not share state between TEST_CASE and TEST_CASE_METHOD for
// non-fixture tests. Use a file-scope singleton seeded on first access.

static const SamlTestFixture& fixture() {
    static const SamlTestFixture f;
    return f;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract request ID from the AuthnRequest URL
// Reverses: URL-decode → base64-decode → inflate (raw DEFLATE) → parse ID attr
// ─────────────────────────────────────────────────────────────────────────────

static std::string extract_request_id_from_url(const std::string& url) {
    // Extract SAMLRequest= parameter
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
        // 128-255: 64
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

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: AuthnRequest signature reconstruction/verification (HTTP-Redirect
// binding detached query-string signature — SAML 2.0 core §3.4.4.1).
// ─────────────────────────────────────────────────────────────────────────────

static std::string url_decode_simple(const std::string& encoded) {
    std::string out;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            char hex[3] = {encoded[i + 1], encoded[i + 2], 0};
            out += static_cast<char>(std::strtol(hex, nullptr, 16));
            i += 2;
        } else if (encoded[i] == '+') {
            out += ' ';
        } else {
            out += encoded[i];
        }
    }
    return out;
}

static std::vector<unsigned char> std_b64_decode(const std::string& b64) {
    static constexpr unsigned char kT[256] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64, 64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64, 64,64,64,64,64,64,64,64, 64,64,64,62,64,64,64,63,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
        // 128-255: 64
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,
    };
    std::vector<unsigned char> out;
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : b64) {
        if (kT[c] == 64) continue;
        val = (val << 6) | kT[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

/// Returns the substring of `url` after '?' and before "&Signature=" — the
/// exact octet-string the production code signs. Empty when the URL carries
/// no "&Signature=" marker.
static std::string extract_signed_base(const std::string& url) {
    const auto q_pos = url.find('?');
    if (q_pos == std::string::npos) return {};
    const auto sig_marker = url.find("&Signature=", q_pos);
    if (sig_marker == std::string::npos) return {};
    return url.substr(q_pos + 1, sig_marker - (q_pos + 1));
}

/// Returns the raw (URL- and base64-decoded) signature bytes from the
/// "&Signature=" parameter of `url`. Empty when absent.
static std::vector<unsigned char> extract_signature_bytes(const std::string& url) {
    static const std::string kMarker = "&Signature=";
    const auto pos = url.find(kMarker);
    if (pos == std::string::npos) return {};
    const auto encoded = url.substr(pos + kMarker.size());
    return std_b64_decode(url_decode_simple(encoded));
}

/// Verify a detached RSA-SHA256 signature (EXPLICIT PKCS#1 v1.5 padding) over
/// `base` using the public component of `priv_key_pem`. Mirrors the exact
/// padding contract of the production rsa_sha256_sign — using a private-key
/// PEM here is fine, OpenSSL verify only consumes the public numbers it
/// carries.
static bool verify_rsa_sha256(const std::string& priv_key_pem, const std::string& base,
                               const std::vector<unsigned char>& sig) {
    BIO* bio = BIO_new_mem_buf(priv_key_pem.data(), static_cast<int>(priv_key_pem.size()));
    REQUIRE(bio != nullptr);
    struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    REQUIRE(pkey != nullptr);
    struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pg{pkey};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    REQUIRE(ctx != nullptr);
    struct CtxGuard { EVP_MD_CTX* c; ~CtxGuard() { EVP_MD_CTX_free(c); } } cg{ctx};

    EVP_PKEY_CTX* pctx = nullptr;
    REQUIRE(EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey) == 1);
    REQUIRE(pctx != nullptr);
    REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) > 0);
    REQUIRE(EVP_DigestVerifyUpdate(ctx, base.data(), base.size()) == 1);
    return EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1;
}

/// Generate a fresh EC (P-256) private key PEM — used to prove a non-RSA
/// signing key is rejected.
static std::string generate_ec_key_pem() {
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    REQUIRE(pkey != nullptr);
    struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
    REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

/// A valid RSA-2048 key, PEM-encoded AES-256-CBC passphrase-encrypted. The
/// provider must reject it WITHOUT prompting for the passphrase (UP-1).
static std::string generate_encrypted_rsa_key_pem() {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    REQUIRE(pkey != nullptr);
    struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
    std::string pass = "test-passphrase";
    REQUIRE(PEM_write_bio_PrivateKey(
                bio, pkey, EVP_aes_256_cbc(),
                reinterpret_cast<unsigned char*>(pass.data()),
                static_cast<int>(pass.size()), nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

/// A valid but WEAK (1024-bit) unencrypted RSA key — below the 2048-bit floor.
static std::string generate_small_rsa_key_pem() {
    EVP_PKEY* pkey = EVP_RSA_gen(1024);
    REQUIRE(pkey != nullptr);
    struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
    REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

/// A valid RSA-PSS key (EVP_PKEY_RSA_PSS base id) — must be rejected by the
/// RSA-only gate, never signed with PKCS#1 v1.5.
static std::string generate_rsa_pss_key_pem() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr);
    REQUIRE(ctx != nullptr);
    struct CtxGuard { EVP_PKEY_CTX* c; ~CtxGuard() { if (c) EVP_PKEY_CTX_free(c); } } cg{ctx};
    REQUIRE(EVP_PKEY_keygen_init(ctx) == 1);
    REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    EVP_PKEY* pkey = nullptr;
    REQUIRE(EVP_PKEY_keygen(ctx, &pkey) == 1);
    REQUIRE(pkey != nullptr);
    struct PkeyGuard { EVP_PKEY* k; ~PkeyGuard() { if (k) EVP_PKEY_free(k); } } pg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    REQUIRE(bio != nullptr);
    struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
    REQUIRE(PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    return std::string(bptr->data, bptr->length);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST CASES
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("SAML: provider not enabled returns false", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = false;
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML: provider enabled but empty cert returns false", "[saml]") {
    SamlConfig cfg;
    cfg.enabled       = true;
    cfg.idp_cert_pem  = {}; // no cert
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML: validate_response on disabled provider returns error", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = false;
    SamlProvider p{cfg};
    auto result = p.validate_response("bm90YWJhc2U2NA==", ""); // valid b64
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("not enabled") != std::string::npos);
}

TEST_CASE("SAML: build_authn_request when disabled returns empty string", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = false;
    SamlProvider p{cfg};
    CHECK(p.build_authn_request("relay").url.empty());
}

TEST_CASE("SAML: build_authn_request generates valid redirect URL", "[saml]") {
    const auto& f    = fixture();
    auto cfg         = f.make_config();
    SamlProvider p{cfg};

    const auto authn = p.build_authn_request("myrelay");
    const auto& url  = authn.url;

    // Must be a URL to the IdP SSO endpoint
    CHECK(url.starts_with(f.idp_sso_url + "?SAMLRequest="));
    CHECK(url.find("RelayState=") != std::string::npos);
    CHECK(url.find("myrelay") != std::string::npos);

    // Must contain SAMLRequest= parameter
    CHECK(url.find("SAMLRequest=") != std::string::npos);

    // The binding cookie secret must be a 64-char hex string (32 bytes CSPRNG).
    CHECK(authn.cookie_secret.size() == 64);
    CHECK(authn.cookie_secret.find_first_not_of("0123456789abcdef") == std::string::npos);

    // Extract and decode the SAMLRequest — must contain our SP entity ID
    const auto request_id = extract_request_id_from_url(url);
    CHECK_FALSE(request_id.empty());
    // Request ID must start with '_' (required for valid XML ID production)
    CHECK(request_id[0] == '_');
}

TEST_CASE("SAML: build_authn_request is unsigned when no SP signing key is configured "
          "(backward-compat)",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    REQUIRE(cfg.sp_signing_key_pem.empty());
    SamlProvider p{cfg};

    const auto authn = p.build_authn_request("myrelay");
    const auto& url  = authn.url;
    REQUIRE_FALSE(url.empty());

    // Matches the existing unsigned shape exactly: "?SAMLRequest=...&RelayState=...".
    CHECK(url.starts_with(f.idp_sso_url + "?SAMLRequest="));
    CHECK(url.find("&RelayState=") != std::string::npos);
    CHECK(url.find("SigAlg=") == std::string::npos);
    CHECK(url.find("Signature=") == std::string::npos);
}

TEST_CASE("SAML: build_authn_request signs the redirect URL when an SP signing key is "
          "configured",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = f.priv_key_pem; // RSA-2048 — exactly our supported type
    SamlProvider p{cfg};

    const auto authn = p.build_authn_request("myrelay");
    const auto& url  = authn.url;
    REQUIRE_FALSE(url.empty());

    CHECK(url.find("&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256") !=
          std::string::npos);
    CHECK(url.find("&Signature=") != std::string::npos);

    const auto base = extract_signed_base(url);
    REQUIRE_FALSE(base.empty());
    CHECK(base.starts_with("SAMLRequest="));
    CHECK(base.find("&RelayState=") != std::string::npos);
    CHECK(base.find("myrelay") != std::string::npos); // "myrelay" is alnum-only, url_encode is a no-op
    CHECK(base.find("&SigAlg=") != std::string::npos);
    CHECK(base.find("&Signature=") == std::string::npos); // extract_signed_base stops there

    const auto sig = extract_signature_bytes(url);
    REQUIRE_FALSE(sig.empty());
    CHECK(verify_rsa_sha256(f.priv_key_pem, base, sig));

    // MUTATION-CHECK: tampering a single byte of the signed base must fail
    // verification — proves the test isn't accidentally verifying against
    // an empty/always-true signature.
    std::string tampered = base;
    tampered[0] = (tampered[0] == 'S') ? 'X' : 'S';
    CHECK_FALSE(verify_rsa_sha256(f.priv_key_pem, tampered, sig));
}

TEST_CASE("SAML: signed AuthnRequest with empty RelayState omits RelayState from the signed "
          "base entirely",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = f.priv_key_pem;
    SamlProvider p{cfg};

    const auto authn = p.build_authn_request(""); // no relay state
    const auto& url  = authn.url;
    REQUIRE_FALSE(url.empty());

    const auto base = extract_signed_base(url);
    REQUIRE_FALSE(base.empty());
    // Never "RelayState=" — omitted entirely, not present-but-empty.
    CHECK(base.find("RelayState=") == std::string::npos);
    CHECK(base.starts_with("SAMLRequest="));
    CHECK(base.find("&SigAlg=") != std::string::npos);

    const auto sig = extract_signature_bytes(url);
    REQUIRE_FALSE(sig.empty());
    CHECK(verify_rsa_sha256(f.priv_key_pem, base, sig));
}

TEST_CASE("SAML: a non-RSA (EC) SP signing key is rejected — signing stays disabled", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = generate_ec_key_pem();
    SamlProvider p{cfg};

    CHECK(p.signing_configured_but_broken());
    CHECK(p.signing_init_error().find("RSA") != std::string::npos);

    // The provider itself may still be otherwise enabled (IdP verification is
    // independent of SP signing) — but the redirect URL must never carry a
    // signature produced from a rejected key. Assert the URL is present
    // UNCONDITIONALLY: a future regression that made is_enabled() false on a
    // broken signing key would otherwise make this check silently vacuous.
    const auto authn = p.build_authn_request("myrelay");
    REQUIRE_FALSE(authn.url.empty());
    CHECK(authn.url.find("SigAlg=") == std::string::npos);
    CHECK(authn.url.find("Signature=") == std::string::npos);
}

TEST_CASE("SAML: a malformed SP signing key PEM is rejected", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = "not a key";
    SamlProvider p{cfg};

    CHECK(p.signing_configured_but_broken());
    CHECK_FALSE(p.signing_init_error().empty());
}

TEST_CASE("SAML: a weak (1024-bit) SP signing key is rejected — below the 2048-bit floor",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = generate_small_rsa_key_pem();
    SamlProvider p{cfg};

    CHECK(p.signing_configured_but_broken());
    CHECK_FALSE(p.signing_init_error().empty());

    const auto authn = p.build_authn_request("myrelay");
    REQUIRE_FALSE(authn.url.empty());
    CHECK(authn.url.find("SigAlg=") == std::string::npos);
    CHECK(authn.url.find("Signature=") == std::string::npos);
}

TEST_CASE("SAML: an RSA-PSS SP signing key is rejected by the RSA-only gate", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = generate_rsa_pss_key_pem();
    SamlProvider p{cfg};

    CHECK(p.signing_configured_but_broken());
    CHECK_FALSE(p.signing_init_error().empty());

    const auto authn = p.build_authn_request("myrelay");
    REQUIRE_FALSE(authn.url.empty());
    CHECK(authn.url.find("SigAlg=") == std::string::npos);
    CHECK(authn.url.find("Signature=") == std::string::npos);
}

TEST_CASE("SAML: an encrypted (passphrase-protected) SP signing key is rejected "
          "without prompting",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.sp_signing_key_pem = generate_encrypted_rsa_key_pem();
    // If the ctor ever fell back to OpenSSL's default password callback this
    // would prompt on /dev/tty and hang the test; the no-op callback makes it
    // fail closed deterministically instead. (UP-1)
    SamlProvider p{cfg};

    CHECK(p.signing_configured_but_broken());
    CHECK_FALSE(p.signing_init_error().empty());

    const auto authn = p.build_authn_request("myrelay");
    REQUIRE_FALSE(authn.url.empty());
    CHECK(authn.url.find("SigAlg=") == std::string::npos);
    CHECK(authn.url.find("Signature=") == std::string::npos);
}

TEST_CASE("SAML: valid signed assertion is accepted", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // Generate a real AuthnRequest to register the pending ID
    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id == "user@example.com");
}

// ── ADR-2001 PR4a — NameID Format extraction (SamlAssertion::name_id_format) ──
//
// Pure extraction coverage: the verifier never rejects on Format — the
// stable-vs-transient decision is entirely the login-site linking
// orchestration's (saml_scim_link.hpp, test_saml_scim_link.cpp). These tests
// pin that the verifier faithfully surfaces whatever Format the verified
// assertion carried (or an empty string when it carried none).

TEST_CASE("SAML: default NameID Format (SAML 1.1 emailAddress) is extracted verbatim",
          "[saml][2001]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // fixture's make_response default Format is the SAML 1.1 emailAddress
    // format — matches the codebase's original hardcoded behaviour.
    const auto response_b64 = f.make_response(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
}

TEST_CASE("SAML: NameID Format persistent is extracted verbatim", "[saml][2001]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, {}, {},
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id_format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
}

TEST_CASE("SAML: NameID Format transient is extracted verbatim (still accepted by the "
          "verifier — the reject-for-linking decision lives at the login-site orchestration)",
          "[saml][2001]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, {}, {},
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id_format == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
}

TEST_CASE("SAML: a NameID with no Format attribute extracts an empty name_id_format — the "
          "login still succeeds",
          "[saml][2001]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Empty name_id_format arg → make_response omits the Format attribute
    // entirely, modelling an IdP that never sends one.
    const auto response_b64 = f.make_response(request_id, "user@example.com", 3600, {}, {}, false,
                                              nullptr, false, false, {}, {}, /*name_id_format=*/"");
    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id == "user@example.com");
    CHECK(result->name_id_format.empty());
}

TEST_CASE("SAML: tampered assertion body after signing is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Build a valid signed response
    auto response_b64 = f.make_response(request_id);

    // Decode, tamper with the NameID, re-encode
    std::string xml_bytes;
    // b64 decode helper
    static constexpr unsigned char kT2[256] = {
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
    {
        unsigned int val = 0;
        int bits = -8;
        for (unsigned char c : response_b64) {
            if (kT2[c] == 64) continue;
            val = (val << 6) | kT2[c];
            bits += 6;
            if (bits >= 0) {
                xml_bytes += static_cast<char>((val >> bits) & 0xFF);
                bits -= 8;
            }
        }
    }

    // Tamper: change the NameID value after signing
    auto pos = xml_bytes.find("user@example.com");
    REQUIRE(pos != std::string::npos);
    xml_bytes.replace(pos, 16, "evil@attacker.com");

    // Re-base64-encode the tampered XML
    const auto tampered_b64 = [&]() {
        static constexpr char kA[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const auto* d = reinterpret_cast<const unsigned char*>(xml_bytes.data());
        const auto  n = xml_bytes.size();
        std::string out;
        out.reserve(((n + 2) / 3) * 4);
        for (std::size_t i = 0; i < n; i += 3) {
            auto v = static_cast<uint32_t>(d[i]) << 16;
            if (i + 1 < n) v |= static_cast<uint32_t>(d[i + 1]) << 8;
            if (i + 2 < n) v |= static_cast<uint32_t>(d[i + 2]);
            out += kA[(v >> 18) & 0x3F];
            out += kA[(v >> 12) & 0x3F];
            out += (i + 1 < n) ? kA[(v >> 6) & 0x3F] : '=';
            out += (i + 2 < n) ? kA[v & 0x3F] : '=';
        }
        return out;
    }();

    // Need a fresh request ID since we already consumed the first one
    const auto authn_result2 = p.build_authn_request("relay");
    (void)authn_result2; // Not needed — verification fails before InResponseTo

    const auto result = p.validate_response(tampered_b64, cookie_secret);
    CHECK_FALSE(result.has_value());
    // Must mention signature failure (not a successful accept)
    const auto& err = result.error();
    CHECK((err.find("signature") != std::string::npos ||
           err.find("verify")    != std::string::npos ||
           err.find("failed")    != std::string::npos));
}

TEST_CASE("SAML: XSW — second injected Assertion is rejected (exactly-1 rule)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // inject_extra_assertion = true → second unsigned Assertion in the document
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, /*inject_extra_assertion=*/true);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("XSW") != std::string::npos);
    CHECK(result.error().find("2") != std::string::npos); // reported count
}

// ── Group attribute parsing (SAML group→role mapping) ──────────────────────

TEST_CASE("SAML: AttributeStatement group values parse into assertion.groups", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto attr_stmt = SamlTestFixture::make_attribute_statement(
        cfg.group_attribute, {"admins", "engineering"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->name_id == "user@example.com");
    REQUIRE(result->groups.size() == 2);
    CHECK(result->groups[0] == "admins");
    CHECK(result->groups[1] == "engineering");
}

TEST_CASE("SAML: AttributeStatement with non-matching Attribute Name yields no groups",
          "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Attribute Name is "department", not the configured "groups" — must be ignored.
    const auto attr_stmt =
        SamlTestFixture::make_attribute_statement("department", {"engineering"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->groups.empty());
}

TEST_CASE("SAML: empty group_attribute parses no groups (thin-slice-compatible default)",
          "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config(); // group_attribute left default-empty
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto attr_stmt = SamlTestFixture::make_attribute_statement("groups", {"admins"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->groups.empty());
}

TEST_CASE("SAML: group values are capped at kMaxGroupValues entries (DoS guard)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // This calls SamlProvider::validate_response DIRECTLY (no HTTP layer —
    // unlike test_saml_routes.cpp's TestRouteSink-mediated tests, there is
    // no httplib CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH=8192 wire
    // cap to fit under here), so this is the right place to exercise the
    // full DoS-cap boundary at kMaxGroupValues=200 (aligned with
    // RbacStore::kMaxIdpGroupsPerLogin — SAML fine-grained RBAC).
    const auto cap = yuzu::server::saml::kMaxGroupValues;
    std::vector<std::string> many_values;
    for (std::size_t i = 0; i < cap + 50; ++i) many_values.push_back("group" + std::to_string(i));
    const auto attr_stmt = SamlTestFixture::make_attribute_statement("groups", many_values);
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    CHECK(result->groups.size() == cap);
    CHECK(result->groups.front() == "group0");
    CHECK(result->groups.back() == "group" + std::to_string(cap - 1));
}

TEST_CASE("SAML: empty <AttributeValue/> is skipped, not pushed (UP-8)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Two genuinely-empty values sandwiched between real ones — an empty
    // value can never match a non-empty admin_group, and must not occupy a
    // slot against the 64-entry DoS cap.
    const auto attr_stmt =
        SamlTestFixture::make_attribute_statement("groups", {"", "admins", "", "engineering"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    REQUIRE(result->groups.size() == 2);
    CHECK(result->groups[0] == "admins");
    CHECK(result->groups[1] == "engineering");
}

TEST_CASE("SAML: a match beyond index 0 still resolves; an XML comment inside an "
          "AttributeValue does not change its resolved text (qa-NICE / UP-6)",
          "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // "Admins" (capital A) is spelled with an inline XML comment splitting the
    // text node — libxml2's xmlNodeGetContent concatenates the surrounding
    // text nodes and drops the comment, so this must resolve to the literal
    // string "Admins", not something the comment could smuggle a bypass into.
    std::string attr_stmt =
        "<saml:AttributeStatement>"
          "<saml:Attribute Name=\"groups\">"
            "<saml:AttributeValue>engineering</saml:AttributeValue>"
            "<saml:AttributeValue>Ad<!--x-->mins</saml:AttributeValue>"
            "<saml:AttributeValue>sales</saml:AttributeValue>"
          "</saml:Attribute>"
        "</saml:AttributeStatement>";
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false, nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE(result.has_value());
    REQUIRE(result->groups.size() == 3);
    CHECK(result->groups[0] == "engineering");
    CHECK(result->groups[1] == "Admins"); // comment dropped, not smuggled
    CHECK(result->groups[2] == "sales");
}

TEST_CASE("SAML: XSW — group values from an unsigned injected Assertion never leak "
          "into result->groups (qa-S3)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // The legit SIGNED assertion carries NO groups. The evil UNSIGNED
    // injected assertion (classic XSW shape) carries the admin group value.
    // Today's exactly-one-Assertion rule already rejects any two-assertion
    // document outright; this test pins that AND makes a future loosening of
    // that rule fail loudly if it ever let a value through carrying the evil
    // group — group extraction must stay scoped to the XSW-verified node,
    // never a document-wide search.
    const auto evil_attr_stmt = SamlTestFixture::make_attribute_statement("groups", {"admins"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, /*inject_extra_assertion=*/true, nullptr,
        false, false, /*attribute_statement_xml=*/{}, evil_attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    if (result.has_value()) {
        CHECK(std::find(result->groups.begin(), result->groups.end(), "admins") ==
              result->groups.end());
    } else {
        CHECK(result.error().find("XSW") != std::string::npos);
    }
}

TEST_CASE("SAML: XSW — second injected Assertion is still rejected when attributes are present",
          "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    cfg.group_attribute = "groups";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto attr_stmt = SamlTestFixture::make_attribute_statement("groups", {"admins"});
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, /*inject_extra_assertion=*/true, nullptr,
        false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("XSW") != std::string::npos);
}

// ── AttributeStatement: display-name / email session-enrichment ─────────────

TEST_CASE("SAML: name/email attributes parse into assertion.display_name/email", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.name_attribute  = "http://schemas.microsoft.com/identity/claims/displayname";
    cfg.email_attribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // One signed AttributeStatement carrying both attributes (extract walks all
    // statements, so concatenated per-attribute statements are equivalent).
    const auto attr_stmt =
        SamlTestFixture::make_attribute_statement(cfg.name_attribute, {"Ada Lovelace"}) +
        SamlTestFixture::make_attribute_statement(cfg.email_attribute, {"ada@example.com"});
    const auto response_b64 = f.make_response(request_id, "ada-nameid", 3600, {}, {}, false,
                                              nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);
    REQUIRE(result.has_value());
    CHECK(result->name_id == "ada-nameid");
    CHECK(result->display_name == "Ada Lovelace");
    CHECK(result->email == "ada@example.com");
}

TEST_CASE("SAML: unset name/email attribute config yields empty display_name/email "
          "(backward-compatible)",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config(); // name_attribute / email_attribute unset (default)
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // The assertion DOES carry attributes; with the flags unset they must be
    // ignored (the session then falls back to the raw NameID, exactly as before).
    const auto attr_stmt = SamlTestFixture::make_attribute_statement(
        "http://schemas.microsoft.com/identity/claims/displayname", {"Ada Lovelace"});
    const auto response_b64 = f.make_response(request_id, "ada-nameid", 3600, {}, {}, false,
                                              nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);
    REQUIRE(result.has_value());
    CHECK(result->display_name.empty());
    CHECK(result->email.empty());
}

TEST_CASE("SAML: name attribute takes the FIRST non-empty value; empty values skipped", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.name_attribute = "displayName";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // First value empty, second the real name, third a decoy — first non-empty wins.
    const auto attr_stmt =
        SamlTestFixture::make_attribute_statement("displayName", {"", "Grace Hopper", "decoy"});
    const auto response_b64 = f.make_response(request_id, "grace-nameid", 3600, {}, {}, false,
                                              nullptr, false, false, attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);
    REQUIRE(result.has_value());
    CHECK(result->display_name == "Grace Hopper");
}

TEST_CASE("SAML: XSW — name/email from an unsigned injected Assertion never leak into "
          "display_name/email (qa-S3 parity)",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.name_attribute  = "displayName";
    cfg.email_attribute = "email";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // The legit SIGNED assertion carries NO enrichment attributes. The evil
    // UNSIGNED injected assertion carries a display name and email. Same
    // guarantee as the group qa-S3 test: extraction is scoped to the
    // XSW-verified node, so an injected value must never reach display_name/
    // email — and today's exactly-one-Assertion rule rejects the doc outright.
    const auto evil_attr_stmt =
        SamlTestFixture::make_attribute_statement("displayName", {"Attacker"}) +
        SamlTestFixture::make_attribute_statement("email", {"attacker@evil.example"});
    const auto response_b64 =
        f.make_response(request_id, "victim-nameid", 3600, {}, {}, /*inject_extra_assertion=*/true,
                        nullptr, false, false, /*attribute_statement_xml=*/{}, evil_attr_stmt);

    const auto result = p.validate_response(response_b64, cookie_secret);
    if (result.has_value()) {
        CHECK(result->display_name != "Attacker");
        CHECK(result->email != "attacker@evil.example");
        CHECK(result->display_name.empty());
        CHECK(result->email.empty());
    } else {
        CHECK(result.error().find("XSW") != std::string::npos);
    }
}

TEST_CASE("SAML: a display-name attribute value is sanitised — control chars stripped, length "
          "clamped (#2396-adjacent Gate 4 UP-1/2/3)",
          "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    cfg.name_attribute = "displayName";
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    SECTION("internal newline is stripped (no log-record forgery)") {
        // A value carrying a newline + a fake log tail — the newline MUST NOT
        // survive into display_name (it would forge a second spdlog line).
        const auto attr_stmt = SamlTestFixture::make_attribute_statement(
            "displayName", {"Alice&#10;SAML session created for 'admin' (role=Administrator)"});
        const auto response_b64 = f.make_response(request_id, "alice-nameid", 3600, {}, {}, false,
                                                  nullptr, false, false, attr_stmt);
        const auto result = p.validate_response(response_b64, cookie_secret);
        REQUIRE(result.has_value());
        CHECK(result->display_name.find('\n') == std::string::npos);
        CHECK(result->display_name.find('\r') == std::string::npos);
        // The visible text survives (concatenated), only the control char is gone.
        CHECK(result->display_name.find("Alice") != std::string::npos);
    }

    SECTION("an over-long ASCII value is clamped") {
        const std::string huge(5000, 'x');
        const auto attr_stmt = SamlTestFixture::make_attribute_statement("displayName", {huge});
        const auto response_b64 = f.make_response(request_id, "big-nameid", 3600, {}, {}, false,
                                                  nullptr, false, false, attr_stmt);
        const auto result = p.validate_response(response_b64, cookie_secret);
        REQUIRE(result.has_value());
        CHECK(result->display_name.size() <= 256);
        CHECK(result->display_name.size() > 0); // not emptied
    }

    SECTION("clamp lands on a UTF-8 codepoint boundary, never mid-sequence (adv-review K4)") {
        // 100 × '€' (U+20AC = E2 82 AC, 3 bytes) = 300 bytes. A naive resize(256)
        // would split the 86th char mid-sequence (byte 256 is a continuation
        // byte); the back-up loop must retreat to byte 255 → 85 whole chars.
        std::string euros;
        for (int i = 0; i < 100; ++i) euros += "\xe2\x82\xac";
        const auto attr_stmt = SamlTestFixture::make_attribute_statement("displayName", {euros});
        const auto response_b64 = f.make_response(request_id, "euro-nameid", 3600, {}, {}, false,
                                                  nullptr, false, false, attr_stmt);
        const auto result = p.validate_response(response_b64, cookie_secret);
        REQUIRE(result.has_value());
        CHECK(result->display_name.size() <= 256);
        CHECK(result->display_name.size() % 3 == 0);   // only whole 3-byte codepoints survive
        CHECK(result->display_name.size() == 255);     // 85 × 3, not a mid-sequence 256
    }
}

TEST_CASE("SAML: expired assertion (NotOnOrAfter in past) is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // nooa_seconds_from_now = -3600 → already expired by 1h (well past the 5m skew)
    const auto response_b64 = f.make_response(request_id, "user@example.com", -3600);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("expired") != std::string::npos ||
           result.error().find("NotOnOrAfter") != std::string::npos));
}

TEST_CASE("SAML: wrong Audience is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, "https://wrong.sp.example.com/");

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Audience") != std::string::npos ||
           result.error().find("audience") != std::string::npos));
}

TEST_CASE("SAML: wrong Recipient in SubjectConfirmationData is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {},
        "https://wrong-acs.example.com/saml");

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Recipient") != std::string::npos ||
           result.error().find("recipient") != std::string::npos ||
           result.error().find("mismatch")  != std::string::npos));
}

TEST_CASE("SAML: missing InResponseTo (unsolicited response) is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // Do NOT call build_authn_request — we pass empty request_id to make_response,
    // which leaves SubjectConfirmationData.InResponseTo absent or empty.
    // "make_response" sets the value from request_id; empty → the attribute
    // value is present but empty, which our parser treats as missing.
    // Build a response with InResponseTo="" (will be in the XML).
    const auto response_b64 = f.make_response("");

    const auto result = p.validate_response(response_b64, "");

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("InResponseTo") != std::string::npos ||
           result.error().find("unsolicited")  != std::string::npos ||
           result.error().find("missing")      != std::string::npos));
}

TEST_CASE("SAML: replayed InResponseTo is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(request_id);

    // First submission → should succeed
    const auto result1 = p.validate_response(response_b64, cookie_secret);
    REQUIRE(result1.has_value());

    // Second submission with the same response → InResponseTo already consumed
    const auto result2 = p.validate_response(response_b64, cookie_secret);
    REQUIRE_FALSE(result2.has_value());
    CHECK((result2.error().find("replayed")     != std::string::npos ||
           result2.error().find("unsolicited")  != std::string::npos ||
           result2.error().find("InResponseTo") != std::string::npos));
}

TEST_CASE("SAML: unknown InResponseTo (never issued) is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // Pass a fabricated request_id that we never called build_authn_request for
    const auto response_b64 = f.make_response("_neverissuedid1234567890abcdef");

    const auto result = p.validate_response(response_b64, "");

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("replayed")     != std::string::npos ||
           result.error().find("unsolicited")  != std::string::npos ||
           result.error().find("InResponseTo") != std::string::npos));
}

TEST_CASE("SAML: response with no Signature element is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // make_unsigned_response constructs an Assertion with no <ds:Signature>
    const auto response_b64 = f.make_unsigned_response(request_id);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Signature") != std::string::npos ||
           result.error().find("signature") != std::string::npos));
}

TEST_CASE("SAML: signed by a different cert (not pinned) is rejected", "[saml]") {
    const auto& f  = fixture();

    // Provider is configured with cert_pem (key pair A)
    auto cfg      = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Response signed with key pair B (the "attacker's" key)
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {}, false,
        &f.priv_key_pem_b); // different private key

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    // Must fail signature verification — not a content-level error
    const auto& err = result.error();
    CHECK((err.find("signature") != std::string::npos ||
           err.find("verify")    != std::string::npos ||
           err.find("failed")    != std::string::npos));
}

TEST_CASE("SAML: assertion signed with RSA-SHA1 under the correct pinned key "
          "is rejected (algorithm downgrade)", "[saml]") {
    const auto& f  = fixture();

    // Provider is configured with the CORRECT pinned cert (key pair A) — N1's
    // key-pinning offers no protection here, since the key is the right one.
    // Only the algorithm allowlist can catch this.
    auto cfg      = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Response signed with the pinned private key, but the SignedInfo
    // template requests rsa-sha1 / sha1 instead of rsa-sha256 / sha256.
    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {},
        /*inject_extra_assertion=*/false,
        /*signing_priv_key=*/nullptr, // the correct pinned key
        /*use_sha1_algorithms=*/true);

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    // Must be rejected for the algorithm being disabled, not some other
    // reason — xmlsec1 raises "transform disabled" (XMLSEC_ERRORS_R_TRANSFORM_DISABLED)
    // when a SignatureMethod/DigestMethod is outside the enabledTransforms /
    // enabledReferenceTransforms allowlist, which surfaces here as a plain
    // signature verification failure (xmlsec cannot even construct the
    // transform, so xmlSecDSigCtxVerify returns < 0 or a failed status).
    const auto& err = result.error();
    CHECK((err.find("signature") != std::string::npos ||
           err.find("verify")    != std::string::npos ||
           err.find("internal")  != std::string::npos ||
           err.find("failed")    != std::string::npos));
}

TEST_CASE("SAML: assertion with an RSA-SHA256 signature but a SHA-1 Reference "
          "digest is rejected (digest allowlist isolated)", "[saml]") {
    const auto& f = fixture();

    // This isolates the *Reference-digest* half of the allowlist: the
    // SignatureMethod is the accepted rsa-sha256, only the DigestMethod is the
    // weak sha1. If only the SignatureMethod were restricted (and the digest
    // left to xmlsec defaults) this would slip through — so it locks the
    // enabledReferenceTransforms restriction against future regressions.
    auto cfg = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result   = p.build_authn_request("relay");
    const auto request_id     = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(
        request_id, "user@example.com", 3600, {}, {},
        /*inject_extra_assertion=*/false,
        /*signing_priv_key=*/nullptr,       // the correct pinned key
        /*use_sha1_algorithms=*/false,      // SignatureMethod stays rsa-sha256
        /*use_sha1_digest_only=*/true);     // but the Reference digest is sha1

    const auto result = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    const auto& err = result.error();
    CHECK((err.find("signature") != std::string::npos ||
           err.find("verify")    != std::string::npos ||
           err.find("internal")  != std::string::npos ||
           err.find("failed")    != std::string::npos));
}

TEST_CASE("SAML: cleanup_expired_states removes expired entries", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // Issue a request
    p.build_authn_request("relay");

    // Calling cleanup on a freshly-issued (not expired) entry should leave it
    p.cleanup_expired_states();

    // A second request with a fabricated ID should still fail (ID never issued)
    const auto response_b64 = f.make_response("_notregistered99");
    const auto result       = p.validate_response(response_b64, "");
    CHECK_FALSE(result.has_value());
}

TEST_CASE("SAML: malformed base64 input is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto result = p.validate_response("!!!notbase64!!!", "");
    CHECK_FALSE(result.has_value());
}

TEST_CASE("SAML: non-XML payload (valid base64) is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // base64("this is not xml")
    const auto result = p.validate_response("dGhpcyBpcyBub3QgeG1s", "");
    CHECK_FALSE(result.has_value());
}

// ── Fix 3: Assertion Issuer validation ────────────────────────────────────────

TEST_CASE("SAML: assertion with wrong Issuer is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_wrong_issuer(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Issuer") != std::string::npos ||
           result.error().find("issuer") != std::string::npos ||
           result.error().find("mismatch") != std::string::npos));
}

TEST_CASE("SAML: assertion with no Issuer element is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_no_issuer(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Issuer") != std::string::npos ||
           result.error().find("issuer") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

// ── Fix 4: Mandatory Conditions / AudienceRestriction / SCD ──────────────────

TEST_CASE("SAML: assertion missing <Conditions> is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_no_conditions(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Conditions") != std::string::npos ||
           result.error().find("conditions") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

TEST_CASE("SAML: assertion missing <AudienceRestriction> is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_no_audience_restriction(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("AudienceRestriction") != std::string::npos ||
           result.error().find("audience") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

TEST_CASE("SAML: assertion missing <SubjectConfirmationData> is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_no_scd(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("SubjectConfirmationData") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

TEST_CASE("SAML: SCD missing Recipient attribute is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_scd_no_recipient(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("Recipient") != std::string::npos ||
           result.error().find("recipient") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

TEST_CASE("SAML: SCD missing NotOnOrAfter attribute is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_scd_no_nooa(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("NotOnOrAfter") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

// ── F4: Conditions NotOnOrAfter is mandatory ──────────────────────────────────

TEST_CASE("SAML: Conditions missing NotOnOrAfter attribute is rejected (F4)", "[saml]") {
    // SAML WebSSO profile §4.1.4.2 requires Conditions/NotOnOrAfter.
    // An absent NotOnOrAfter allows indefinite replay of an assertion.
    // Before F4 this was only validated when present (optional); it is now
    // mandatory, matching the existing SubjectConfirmationData enforcement.
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response_conditions_no_nooa(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("NotOnOrAfter") != std::string::npos ||
           result.error().find("Conditions") != std::string::npos ||
           result.error().find("missing") != std::string::npos));
}

// ── Fix 6: DOCTYPE/DTD rejection ─────────────────────────────────────────────

TEST_CASE("SAML: response with DOCTYPE declaration is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // DOCTYPE rejection happens before signature verification (step 2.5), so we
    // do not need a real request_id in the pending set.
    const auto response_b64 = f.make_doctype_response("_unused_req_id");
    const auto result       = p.validate_response(response_b64, "");

    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("DOCTYPE") != std::string::npos ||
           result.error().find("DTD")     != std::string::npos ||
           result.error().find("rejected") != std::string::npos));
}

// ── DoS: pathologically deep XML nesting is rejected (XSW-walk depth guard) ────

TEST_CASE("SAML: pathologically deep XML nesting is rejected", "[saml]") {
    const auto& f = fixture();
    auto cfg      = f.make_config();
    SamlProvider p{cfg};

    // 200 levels — under libxml2's own 256 parse cap (so it parses), but over
    // the collect_assertions/has_duplicate_id depth guard (100), which runs
    // before signature verification. A shallow (depth 5) document is NOT
    // rejected by the guard, confirming the cap only trips on abuse.
    const auto deep_b64 = f.make_deeply_nested_response(200);
    const auto deep_res = p.validate_response(deep_b64, "");
    REQUIRE_FALSE(deep_res.has_value());
    CHECK(deep_res.error().find("deep") != std::string::npos);

    // A shallow document passes the depth guard and is rejected later for a
    // different reason (no assertion), proving the guard is not over-eager.
    const auto shallow_b64 = f.make_deeply_nested_response(5);
    const auto shallow_res = p.validate_response(shallow_b64, "");
    REQUIRE_FALSE(shallow_res.has_value());
    CHECK(shallow_res.error().find("deep") == std::string::npos);
}

// ── Fix 1: Oversized body is rejected at provider level ───────────────────────

TEST_CASE("SAML: oversized response (>1 MiB decoded) is rejected", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    // Construct a base64-encoded string whose decoded size is just over 1 MiB.
    // A decoded run of 1048577 bytes (1 MiB + 1) is enough to trigger the guard.
    const std::string big_xml(1048577, 'A'); // 1 MiB + 1 byte of junk
    // b64_encode directly using the static helper
    const auto big_b64 = [&]() {
        static constexpr char kA[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const auto* d = reinterpret_cast<const unsigned char*>(big_xml.data());
        const auto  n = big_xml.size();
        std::string out;
        out.reserve(((n + 2) / 3) * 4);
        for (std::size_t i = 0; i < n; i += 3) {
            auto v = static_cast<uint32_t>(d[i]) << 16;
            if (i + 1 < n) v |= static_cast<uint32_t>(d[i + 1]) << 8;
            if (i + 2 < n) v |= static_cast<uint32_t>(d[i + 2]);
            out += kA[(v >> 18) & 0x3F];
            out += kA[(v >> 12) & 0x3F];
            out += (i + 1 < n) ? kA[(v >> 6) & 0x3F] : '=';
            out += (i + 2 < n) ? kA[v & 0x3F] : '=';
        }
        return out;
    }();

    const auto result = p.validate_response(big_b64, "");
    CHECK_FALSE(result.has_value());
    CHECK((result.error().find("size") != std::string::npos ||
           result.error().find("MiB")  != std::string::npos ||
           result.error().find("maximum") != std::string::npos));
}

// ── Browser-binding cookie tests ─────────────────────────────────────────────

TEST_CASE("SAML: validate_response rejected when binding cookie is empty", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result = p.build_authn_request("relay");
    const auto request_id   = extract_request_id_from_url(authn_result.url);
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(request_id);

    // Pass empty string as cookie_secret → binding check must reject
    const auto result = p.validate_response(response_b64, "");
    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("binding") != std::string::npos ||
           result.error().find("cookie")  != std::string::npos ||
           result.error().find("mismatch") != std::string::npos));
}

TEST_CASE("SAML: validate_response rejected when binding cookie has wrong value", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result = p.build_authn_request("relay");
    const auto request_id   = extract_request_id_from_url(authn_result.url);
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(request_id);

    // Pass a wrong (but non-empty) cookie_secret
    const auto result = p.validate_response(response_b64,
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    REQUIRE_FALSE(result.has_value());
    CHECK((result.error().find("binding") != std::string::npos ||
           result.error().find("cookie")  != std::string::npos ||
           result.error().find("mismatch") != std::string::npos));
}

TEST_CASE("SAML: binding cookie mismatch consumes InResponseTo (single-use)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    const auto response_b64 = f.make_response(request_id);

    // First attempt with wrong cookie — entry must be consumed to prevent probing
    const auto bad = p.validate_response(response_b64,
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    REQUIRE_FALSE(bad.has_value());

    // Second attempt with the CORRECT cookie — must also be rejected (already consumed)
    const auto good = p.validate_response(response_b64, cookie_secret);
    REQUIRE_FALSE(good.has_value());
    CHECK((good.error().find("replayed")     != std::string::npos ||
           good.error().find("unsolicited")  != std::string::npos ||
           good.error().find("InResponseTo") != std::string::npos));
}

// ---------------------------------------------------------------------------
// H-E: XSW duplicate-ID injection is rejected
// ---------------------------------------------------------------------------

TEST_CASE("SAML: XSW — duplicate xml:id in Extensions element is rejected (H-E)", "[saml]") {
    const auto& f  = fixture();
    auto cfg       = f.make_config();
    SamlProvider p{cfg};

    const auto authn_result  = p.build_authn_request("relay");
    const auto request_id    = extract_request_id_from_url(authn_result.url);
    const auto& cookie_secret = authn_result.cookie_secret;
    REQUIRE_FALSE(request_id.empty());

    // Build a response where a <samlp:Extensions xml:id="<assertionID>"> decoy
    // appears alongside the correctly-signed Assertion with the same ID.
    const auto response_b64 = f.make_response_with_duplicate_id(request_id);
    const auto result       = p.validate_response(response_b64, cookie_secret);

    REQUIRE_FALSE(result.has_value());
    // Error must mention the XSW/duplicate-ID rejection
    const auto& err = result.error();
    INFO("error: " << err);
    CHECK((err.find("XSW")       != std::string::npos ||
           err.find("duplicate") != std::string::npos ||
           err.find("duplicate") != std::string::npos));
}

// ---------------------------------------------------------------------------
// H-F: is_enabled() requires non-empty entity IDs
// ---------------------------------------------------------------------------

TEST_CASE("SAML: is_enabled returns false when idp_entity_id is empty (H-F)", "[saml]") {
    SamlConfig cfg;
    cfg.enabled      = true;
    cfg.idp_cert_pem = "fake-cert-pem"; // non-empty cert
    cfg.sp_entity_id = "https://sp.test";
    cfg.sp_acs_url   = "https://sp.test/acs";
    cfg.idp_sso_url  = "https://idp.test/sso";
    // idp_entity_id intentionally left empty
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML: is_enabled returns false when sp_entity_id is empty (H-F)", "[saml]") {
    SamlConfig cfg;
    cfg.enabled       = true;
    cfg.idp_cert_pem  = "fake-cert-pem";
    cfg.idp_entity_id = "https://idp.test";
    cfg.sp_acs_url    = "https://sp.test/acs";
    cfg.idp_sso_url   = "https://idp.test/sso";
    // sp_entity_id intentionally left empty
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML: is_enabled returns false when sp_acs_url is empty (H-F)", "[saml]") {
    SamlConfig cfg;
    cfg.enabled       = true;
    cfg.idp_cert_pem  = "fake-cert-pem";
    cfg.idp_entity_id = "https://idp.test";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.idp_sso_url   = "https://idp.test/sso";
    // sp_acs_url intentionally left empty
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML: is_enabled returns false when idp_sso_url is empty (H-F)", "[saml]") {
    SamlConfig cfg;
    cfg.enabled       = true;
    cfg.idp_cert_pem  = "fake-cert-pem";
    cfg.idp_entity_id = "https://idp.test";
    cfg.sp_entity_id  = "https://sp.test";
    cfg.sp_acs_url    = "https://sp.test/acs";
    // idp_sso_url intentionally left empty
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

#else // _WIN32 ─────────────────────────────────────────────────────────────────

// Windows stubs — verify N4 invariants compile and behave correctly.

using namespace yuzu::server::saml;

TEST_CASE("SAML (Windows): is_enabled returns false", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = true;
    cfg.idp_cert_pem = "fake-pem";
    SamlProvider p{cfg};
    CHECK_FALSE(p.is_enabled());
}

TEST_CASE("SAML (Windows): validate_response returns error (never success)", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = true;
    SamlProvider p{cfg};
    auto result = p.validate_response("dGVzdA==", "");
    REQUIRE_FALSE(result.has_value());
    // Must not be empty (error message explains the failure)
    CHECK_FALSE(result.error().empty());
}

TEST_CASE("SAML (Windows): build_authn_request returns empty string", "[saml]") {
    SamlConfig cfg;
    cfg.enabled = true;
    SamlProvider p{cfg};
    CHECK(p.build_authn_request("relay").url.empty());
}

#endif // !_WIN32
