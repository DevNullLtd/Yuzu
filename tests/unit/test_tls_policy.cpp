// test_tls_policy.cpp -- pure tests of common/include/yuzu/tls_policy.hpp.
//
// Registered in the AGENT test executable, not the server one: server
// shards are the bottleneck (CLAUDE.md test-efficiency discipline) and
// this header touches no server/agent state at all — precedent for a
// common/ header tested here is unit/test_shutdown_pipe.cpp.

#include <yuzu/tls_policy.hpp>

#include "scoped_env.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/ssl.h>

#include <cstdlib>
#include <string>

TEST_CASE("tls_policy: kTls12CipherList text is exactly the six-suite allow-list",
          "[tls][tls_policy]") {
    CHECK(yuzu::tls::kTls12CipherList ==
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-"
          "POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-"
          "POLY1305");

    std::string joined;
    for (size_t i = 0; i < yuzu::tls::kTls12CipherNames.size(); ++i) {
        if (i)
            joined += ':';
        joined += yuzu::tls::kTls12CipherNames[i];
    }
    CHECK(joined == yuzu::tls::kTls12CipherList);
}

TEST_CASE("tls_policy: every allow-list entry is ECDHE + AEAD, both ECDSA and RSA present",
          "[tls][tls_policy]") {
    bool saw_ecdsa = false, saw_rsa = false;
    for (auto name : yuzu::tls::kTls12CipherNames) {
        CAPTURE(name);
        CHECK(name.starts_with("ECDHE-"));
        CHECK((name.find("-GCM-") != std::string_view::npos ||
              name.find("CHACHA20") != std::string_view::npos));
        if (name.find("ECDHE-ECDSA-") != std::string_view::npos)
            saw_ecdsa = true;
        if (name.find("ECDHE-RSA-") != std::string_view::npos)
            saw_rsa = true;
    }
    CHECK(saw_ecdsa);
    CHECK(saw_rsa);
}

TEST_CASE("tls_policy: resolve_cipher_policy resolves the default list in order",
          "[tls][tls_policy]") {
    auto r = yuzu::tls::resolve_cipher_policy();
    REQUIRE(r.has_value());

    // OpenSSL drops unknown names silently as long as at least one resolves;
    // pinning this equality is what makes a typo in the constant visible.
    REQUIRE(r->tls12.size() == yuzu::tls::kTls12CipherNames.size());
    for (size_t i = 0; i < r->tls12.size(); ++i) {
        CHECK(r->tls12[i] == yuzu::tls::kTls12CipherNames[i]);
    }

    CHECK_FALSE(r->tls13.empty());
    for (const auto& name : r->tls13) {
        CAPTURE(name);
        CHECK(name.starts_with("TLS_"));
    }
}

TEST_CASE("tls_policy: resolve_cipher_policy rejects an unresolvable or empty list",
          "[tls][tls_policy]") {
    // An unknown cipher name and an empty list are both rejected outright by
    // SSL_CTX_set_cipher_list itself, before any partitioning happens.
    auto no_such = yuzu::tls::resolve_cipher_policy("NO-SUCH-CIPHER");
    REQUIRE_FALSE(no_such.has_value());
    CHECK(no_such.error() == yuzu::tls::CipherPolicyError::list_rejected);

    auto empty = yuzu::tls::resolve_cipher_policy("");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == yuzu::tls::CipherPolicyError::list_rejected);

    // A TLS-1.3-only name is not valid `SSL_CTX_set_cipher_list` syntax at
    // all (TLS 1.3 ciphersuites are configured through the separate
    // SSL_CTX_set_ciphersuites API) -- confirmed against this OpenSSL build,
    // it is rejected outright rather than resolving to an empty TLS 1.2 set.
    auto tls13_only = yuzu::tls::resolve_cipher_policy("TLS_AES_128_GCM_SHA256");
    REQUIRE_FALSE(tls13_only.has_value());
    CHECK(tls13_only.error() == yuzu::tls::CipherPolicyError::list_rejected);
}

TEST_CASE("tls_policy: describe_cipher_policy_error gives each cause a distinct message",
          "[tls_policy]") {
    // Pure mapping test -- context_unavailable is an OOM-class SSL_CTX_new
    // failure that cannot be forced here, so this tests the enum-to-message
    // function directly rather than end-to-end through resolve_cipher_policy().
    using yuzu::tls::CipherPolicyError;
    const auto context_msg = yuzu::tls::describe_cipher_policy_error(
        CipherPolicyError::context_unavailable);
    const auto list_msg =
        yuzu::tls::describe_cipher_policy_error(CipherPolicyError::list_rejected, "SOME-LIST");
    const auto zero_msg = yuzu::tls::describe_cipher_policy_error(
        CipherPolicyError::no_tls12_ciphers, "SOME-LIST");

    CHECK(context_msg.find("could not create an OpenSSL context") != std::string::npos);
    CHECK(list_msg.find("was rejected outright") != std::string::npos);
    CHECK(list_msg.find("SOME-LIST") != std::string::npos);
    CHECK(zero_msg.find("resolves to zero TLS 1.2 ciphers") != std::string::npos);
    CHECK(zero_msg.find("SOME-LIST") != std::string::npos);

    // All three distinct -- the whole point of the enum over a single
    // generic message (an SSL_CTX allocation failure must not be reported
    // as "your cipher list is bad").
    CHECK(context_msg != list_msg);
    CHECK(context_msg != zero_msg);
    CHECK(list_msg != zero_msg);
}

TEST_CASE("tls_policy: tls_policy_report_lines names both protocol versions",
          "[tls][tls_policy]") {
    auto r = yuzu::tls::resolve_cipher_policy();
    REQUIRE(r.has_value());
    auto lines = yuzu::tls::tls_policy_report_lines(*r);

    CHECK(lines[0].find("TLS 1.2") != std::string::npos);
    for (const auto& name : r->tls12) {
        CAPTURE(name);
        CHECK(lines[0].find(name) != std::string::npos);
    }

    CHECK(lines[1].find("TLS 1.3") != std::string::npos);
    CHECK(lines[1].find("OpenSSL") != std::string::npos);
    CHECK(lines[1].find("SSL_CTX_set_ciphersuites") != std::string::npos);
}

TEST_CASE("tls_policy: pin_grpc_cipher_env unconditionally overwrites an inherited value",
          "[tls][tls_policy]") {
    yuzu::test::ScopedEnv guard(std::string(yuzu::tls::kGrpcCipherSuitesEnvVar), "JUNK");
    CHECK(std::getenv(yuzu::tls::kGrpcCipherSuitesEnvVar.data()) == std::string("JUNK"));

    CHECK(yuzu::tls::pin_grpc_cipher_env());

    const char* after = std::getenv(yuzu::tls::kGrpcCipherSuitesEnvVar.data());
    REQUIRE(after != nullptr);
    CHECK(std::string(after) == yuzu::tls::kTls12CipherList);
}
