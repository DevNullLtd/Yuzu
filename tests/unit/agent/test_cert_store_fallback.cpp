/**
 * test_cert_store_fallback.cpp -- the macOS branch of
 * agents/core/src/cert_store.cpp's read_cert_from_store() (A-1.20, P8;
 * revised by the BR-001/BR-003 branch-review fix).
 *
 * A prior revision of cert_store.cpp implemented --cert-store on macOS by
 * reading an identity out of the CURRENT USER's login keychain
 * (SecItemCopyMatching/SecItemExport, resolved via
 * SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, ...)), gated behind
 * a YUZU_HAVE_SECURITY macro that was only defined when Security.framework
 * was found at configure time. That design was backwards for how the agent
 * actually ships: the macOS agent runs as a root LaunchDaemon
 * (docs/agent-privilege-model.md) with no attached user login session, so
 * the login-keychain lookup could only ever resolve root's own (nonexistent)
 * keychain and fail closed at startup (BR-001) — and its private-key export
 * path wrote through CFDataGetBytePtr's read-only pointer via const_cast to
 * "wipe" exported key material, which is undefined behavior on an immutable
 * CFDataRef and could crash while loading mTLS credentials (BR-003).
 *
 * The fix removes that code entirely rather than patching it: macOS
 * unconditionally returns an honest "unsupported" CertStoreResult now, the
 * same way the Linux branch always has, and YUZU_HAVE_SECURITY no longer
 * exists anywhere in the source. This binary (tests/meson.build's
 * cert_store_fallback_test_exe) recompiles the SAME cert_store.cpp source
 * standalone (not linked against the rest of yuzu_agent_core, and pulling in
 * no Security/CoreFoundation frameworks) purely so this contract is checked
 * in isolation, independent of whatever else agent_test_exe happens to link.
 *
 * The PEM-file (--client-cert/--client-key) and cert_auto_discovery
 * (agents/core/src/cert_discovery.cpp) identity paths are untouched by this
 * change -- they never depended on read_cert_from_store() or on
 * YUZU_HAVE_SECURITY -- and remain covered by their own dedicated suite,
 * tests/unit/test_cert_discovery.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/cert_store.hpp>

using yuzu::agent::CertStoreResult;
using yuzu::agent::read_cert_from_store;

TEST_CASE("macOS read_cert_from_store returns an honest unsupported error, never a fabricated "
          "success",
          "[cert_store][macos]") {
    const CertStoreResult result = read_cert_from_store(/*store_name=*/"", "yuzu-agent",
                                                          /*thumbprint=*/"");

    CHECK_FALSE(result.ok());
    CHECK_FALSE(result.error.empty());
    // No PEM material fabricated alongside the error.
    CHECK(result.pem_cert_chain.empty());
    CHECK(result.pem_private_key.empty());

    // The message must actually explain WHY -- root LaunchDaemon, no user
    // login keychain -- and point the operator at what does work, so a
    // --cert-store operator on macOS gets a diagnosable startup failure
    // instead of a bare "no" (this is the honest-unsupported contract
    // BR-001 asked for in place of the old fail-closed-for-the-wrong-reason
    // keychain lookup).
    CHECK(result.error.find("root LaunchDaemon") != std::string::npos);
    CHECK(result.error.find("login keychain") != std::string::npos);
    CHECK(result.error.find("--client-cert") != std::string::npos);
    CHECK(result.error.find("--client-key") != std::string::npos);
}

TEST_CASE("macOS read_cert_from_store errors identically regardless of which selector is given",
          "[cert_store][macos]") {
    // The stub ignores its arguments entirely -- it always reports the
    // platform limitation, not an argument-validation error, whether called
    // by subject, by thumbprint, or with neither.
    const CertStoreResult by_subject = read_cert_from_store("", "some-subject", "");
    const CertStoreResult by_thumbprint =
        read_cert_from_store("", "", "AABBCCDDEEFF00112233445566778899AABBCCDD");
    const CertStoreResult neither = read_cert_from_store("", "", "");

    CHECK_FALSE(by_subject.ok());
    CHECK_FALSE(by_thumbprint.ok());
    CHECK_FALSE(neither.ok());
    CHECK(by_subject.error == neither.error);
    CHECK(by_thumbprint.error == neither.error);
}

TEST_CASE("CertStoreResult::ok() still distinguishes a real success from an error",
          "[cert_store][macos]") {
    // Removing the macOS keychain implementation only changes what
    // read_cert_from_store() returns on macOS -- it must not change the
    // CertStoreResult contract itself, which the still-fully-supported
    // Windows CryptoAPI path (and, transitively, agent.cpp's
    // build_channel(), which branches on store_result.ok() before ever
    // touching the PEM-file fallback) continues to rely on. A populated
    // result with no error is still "ok"; the honest-unsupported result
    // above is still not.
    const CertStoreResult synthetic_success{.pem_cert_chain = "-----BEGIN CERTIFICATE-----\n...",
                                             .pem_private_key = "-----BEGIN PRIVATE KEY-----\n...",
                                             .error = ""};
    CHECK(synthetic_success.ok());

    const CertStoreResult unsupported = read_cert_from_store("", "yuzu-agent", "");
    CHECK_FALSE(unsupported.ok());
}
