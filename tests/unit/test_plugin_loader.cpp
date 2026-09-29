#include <yuzu/agent/plugin_loader.hpp>

// Internal helper exposed for unit testing — see header for contract.
#include "../../agents/core/src/plugin_config_sync.hpp"

#include "test_helpers.hpp"

#include "cms_test_fixtures.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/bio.h>
// pem.h must come before cms.h so the PEM_*_CMS macros are declared
// (cms.h gates them on OPENSSL_PEM_H).
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <system_error>

namespace fs = std::filesystem;

namespace {

#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Locate a fixture plugin shared library (`<base_name><ext>`) built by
// tests/meson.build — e.g. "reserved_name_fixture_plugin" (#453) or
// "invalid_name_fixture_plugin" (#822). Returns empty path if not found —
// tests that require the fixture should SKIP rather than FAIL to keep
// cross-compile / restricted-CI scenarios quiet.
fs::path find_fixture_plugin(std::string_view base_name) {
    const std::string lib_name = std::string{base_name} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "tests" / lib_name);
    }
    // Meson launches tests with CWD=build root; tests/ sits alongside the exe.
    candidates.emplace_back(fs::path{"tests"} / lib_name);
    candidates.emplace_back(fs::path{"."} / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

// ── Code-signing test fixtures ───────────────────────────────────────────────
//
// Generate an in-memory CA + signing leaf at test time (no on-disk fixtures
// to expire / drift) and use OpenSSL CMS_sign to produce the detached PEM
// signature the verifier expects. Returns the temp-dir path holding:
//   * trust-bundle.pem    — the CA cert (verifier trust anchor)
//   * other-trust.pem     — a *different* CA cert (used to test "untrusted")
//   * plugin.bin          — a plugin-shaped file (does not need to be a
//                           valid .so for verifier-only tests)
//   * plugin.bin.sig      — PEM CMS detached sig over plugin.bin
//
// All OpenSSL handles are unique_ptr-owned; an OpenSSL failure inside
// build_signing_fixtures() trips a REQUIRE so the test fails loudly rather
// than producing partial state.

using namespace yuzu::test::cms; // shared CMS signing fixtures

} // namespace

TEST_CASE("PluginLoader returns empty result for nonexistent directory", "[plugin_loader]") {
    auto result = yuzu::agent::PluginLoader::scan("/nonexistent/path");
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());
}

TEST_CASE("PluginLoader returns empty result for empty directory", "[plugin_loader]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_empty_plugins_");
    fs::create_directories(tmp);

    auto result = yuzu::agent::PluginLoader::scan(tmp);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());

    fs::remove(tmp);
}

// ── #453 reserved-name namespace ─────────────────────────────────────────────

TEST_CASE("is_reserved_plugin_name matches the reserved set", "[plugin_loader][reserved_name]") {
    using yuzu::agent::is_reserved_plugin_name;

    REQUIRE(is_reserved_plugin_name("__guard__"));
    REQUIRE(is_reserved_plugin_name("__system__"));
    REQUIRE(is_reserved_plugin_name("__update__"));

    // Match must be exact (case-sensitive, no substring / prefix relaxation).
    REQUIRE_FALSE(is_reserved_plugin_name(""));
    REQUIRE_FALSE(is_reserved_plugin_name("example"));
    REQUIRE_FALSE(is_reserved_plugin_name("__GUARD__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard"));
    REQUIRE_FALSE(is_reserved_plugin_name("_guard_"));
    REQUIRE_FALSE(is_reserved_plugin_name("x__guard__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard__ "));
}

TEST_CASE("kReservedPluginNames covers the exact reserved set",
          "[plugin_loader][reserved_name]") {
    // Sanity-check the exact namespace. If a new reserved name is added,
    // this test is the deliberate trip-wire reminding authors to update
    // docs/cpp-conventions.md and docs/user-manual/metrics.md (the
    // reserved_name rejection-reason row) to match.
    REQUIRE(yuzu::agent::kReservedPluginNames.size() == 6);
    REQUIRE(yuzu::agent::kReservedPluginNames[0] == "__guard__");
    REQUIRE(yuzu::agent::kReservedPluginNames[1] == "__system__");
    REQUIRE(yuzu::agent::kReservedPluginNames[2] == "__update__");
    REQUIRE(yuzu::agent::kReservedPluginNames[3] == "__guardian_journal__");
    REQUIRE(yuzu::agent::kReservedPluginNames[4] == "__guardian__");
    REQUIRE(yuzu::agent::kReservedPluginNames[5] == "__sync__");
}

TEST_CASE("agent-internal kv_store namespaces are reserved plugin names",
          "[plugin_loader][reserved_name]") {
    // #2303 C2 + sec-M/sec-L. yuzu_ctx_storage_* keys KvStore by the plugin's
    // own declared name, on the SAME kv_store connection these subsystems use.
    // A native plugin able to claim one of these names could read, delete, or
    // FORGE the state the subsystem loads as authoritative - Guardian rule
    // state, the arm/disarm audit journal, or the daily-sync scheduler state.
    // Each name is otherwise well-formed, so is_valid_plugin_name alone does
    // NOT stop it - only the reserved-name check does. Both halves are asserted.
    for (const auto* ns : {"__guardian_journal__", "__guardian__", "__sync__"}) {
        INFO("namespace: " << ns);
        REQUIRE(yuzu::agent::is_valid_plugin_name(ns)); // well-formed identifier
        REQUIRE(yuzu::agent::is_reserved_plugin_name(ns)); // ...but reserved
    }

    // Near-miss discipline (same as __guard__): exact, case-sensitive match only.
    REQUIRE_FALSE(yuzu::agent::is_reserved_plugin_name("__GUARDIAN__"));
    REQUIRE_FALSE(yuzu::agent::is_reserved_plugin_name("__guardian_"));
    REQUIRE_FALSE(yuzu::agent::is_reserved_plugin_name("x__guardian__"));
    REQUIRE_FALSE(yuzu::agent::is_reserved_plugin_name("__sync"));
    REQUIRE_FALSE(yuzu::agent::is_reserved_plugin_name("__SYNC__"));
    // __guardian__ and __guardian_journal__ are DISTINCT reserved names, not a
    // prefix match - claiming one must not be read as claiming the other.
    REQUIRE(yuzu::agent::is_reserved_plugin_name("__guardian__"));
    REQUIRE(yuzu::agent::is_reserved_plugin_name("__guardian_journal__"));
}

// ── #822 plugin-name validation ──────────────────────────────────────────────

TEST_CASE("is_valid_plugin_name accepts well-formed identifiers",
          "[plugin_loader][name_validation]") {
    using yuzu::agent::is_valid_plugin_name;

    REQUIRE(is_valid_plugin_name("example"));
    REQUIRE(is_valid_plugin_name("inventory_scan"));
    REQUIRE(is_valid_plugin_name("plugin42"));
    REQUIRE(is_valid_plugin_name("_leading_underscore"));
    REQUIRE(is_valid_plugin_name("CamelCase"));
    REQUIRE(is_valid_plugin_name("ALLCAPS"));

    // Reserved names are themselves valid identifiers — the charset check
    // passes them through; is_reserved_plugin_name is what rejects them.
    REQUIRE(is_valid_plugin_name("__guard__"));
    REQUIRE(is_valid_plugin_name("__system__"));
    REQUIRE(is_valid_plugin_name("__update__"));

    // Exactly at the length bound is allowed.
    REQUIRE(is_valid_plugin_name(std::string(yuzu::agent::kMaxPluginNameLen, 'a')));
}

TEST_CASE("is_valid_plugin_name rejects malformed names",
          "[plugin_loader][name_validation]") {
    using yuzu::agent::is_valid_plugin_name;

    // Empty / over-length.
    REQUIRE_FALSE(is_valid_plugin_name(""));
    REQUIRE_FALSE(is_valid_plugin_name(std::string(yuzu::agent::kMaxPluginNameLen + 1, 'a')));

    // Characters outside [A-Za-z0-9_].
    REQUIRE_FALSE(is_valid_plugin_name("has space"));
    REQUIRE_FALSE(is_valid_plugin_name("has-hyphen"));
    REQUIRE_FALSE(is_valid_plugin_name("has.dot"));
    REQUIRE_FALSE(is_valid_plugin_name("path/separator"));
    REQUIRE_FALSE(is_valid_plugin_name("pipe|delimited")); // server splits output on '|'
    REQUIRE_FALSE(is_valid_plugin_name("bang!"));

    // Control / embedded bytes that would diverge a std::string_view check
    // from a downstream C-string consumer, or forge a log line (#822). The NUL
    // case is sized explicitly so the view spans past the embedded NUL.
    REQUIRE_FALSE(is_valid_plugin_name(std::string_view{"nul\0byte", 8}));
    REQUIRE_FALSE(is_valid_plugin_name("line\nfeed"));
    REQUIRE_FALSE(is_valid_plugin_name("tab\tstop"));

    // Non-ASCII high bytes (negative char on signed-char platforms — the
    // hand-rolled range test must reject these without invoking isalnum UB).
    REQUIRE_FALSE(is_valid_plugin_name("emoji\xF0\x9F\x98\x80"));
    REQUIRE_FALSE(is_valid_plugin_name(std::string_view{"\xFF\xFE", 2}));
}

// ── Code-signing tests (#80) ─────────────────────────────────────────────────

TEST_CASE("verify_plugin_signature accepts a valid CMS signature", "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.trust_bundle);
    INFO(err.value_or(""));
    REQUIRE_FALSE(err.has_value());
}

TEST_CASE("verify_plugin_signature reports kSignatureMissingReason when sig absent",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    fs::remove(fx.sig_file);
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureMissingReason));
}

TEST_CASE("verify_plugin_signature rejects a tampered plugin file", "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    // Append a byte after signing — invalidates the digest.
    {
        std::ofstream pf(fx.artifact_file, std::ios::binary | std::ios::app);
        pf << 'X';
    }
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    // Tampered content fails the digest check, which OpenSSL surfaces as a
    // CMS-level error — kSignatureInvalidReason is the right bucket.
    REQUIRE(err->starts_with(yuzu::agent::kSignatureInvalidReason));
}

TEST_CASE("verify_plugin_signature rejects when chain does not anchor in bundle",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.other_trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureUntrustedReason));
}

TEST_CASE("verify_plugin_signature rejects when trust bundle is unreadable",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.dir / "does-not-exist.pem");
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureUntrustedReason));
}

TEST_CASE("verify_plugin_signature rejects malformed PEM in sig file", "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    {
        std::ofstream sigf(fx.sig_file, std::ios::binary | std::ios::trunc);
        sigf << "not a pem\n";
    }
    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    REQUIRE(err->starts_with(yuzu::agent::kSignatureInvalidReason));
}

TEST_CASE("verify_plugin_signature rejects a leaf without codeSigning EKU",
          "[plugin_loader][signing]") {
    // Governance hardening round 1 negative coverage for sec-LOW-2 / UP-8:
    // a leaf signed by a CA in the bundle but lacking EKU=codeSigning
    // (e.g. a sibling mTLS server cert from the same internal CA) MUST
    // be rejected. Without X509_PURPOSE_CODE_SIGN on the trust store,
    // any leaf chaining to the trust anchor would pass — turning a
    // single PKI into a plugin-signing authority across all its issued
    // certs.
    auto fx = build_signing_fixtures();

    // Re-mint a leaf chained to the SAME CA but with EKU=serverAuth
    // (TLS server) instead of codeSigning. Re-sign the plugin file with it.
    auto ca_key = generate_ec_key();
    auto ca_cert = mint_cert(ca_key.get(), ca_key.get(), nullptr, "Yuzu Test CA EKU", true);
    auto srv_leaf_key = generate_ec_key();
    auto srv_leaf = mint_cert_eku(srv_leaf_key.get(), ca_key.get(), ca_cert.get(),
                                  "TLS server (not a code signer)", "serverAuth");

    // Replace the trust bundle with the new CA, replace the .sig with
    // one minted by the serverAuth leaf.
    write_pem_cert(fx.trust_bundle, ca_cert.get());
    write_cms_signature(fx.sig_file, fx.artifact_file, srv_leaf.get(), srv_leaf_key.get());

    auto err = yuzu::agent::verify_plugin_signature(fx.artifact_file, fx.trust_bundle);
    REQUIRE(err.has_value());
    // Chain is technically valid (CA issued the leaf), but the EKU
    // gate rejects it — surfaces as untrusted-chain via the
    // X509-error classifier.
    REQUIRE(err->starts_with(yuzu::agent::kSignatureUntrustedReason));
}

TEST_CASE("PluginSigningPolicy::enabled flips with bundle path", "[plugin_loader][signing]") {
    yuzu::agent::PluginSigningPolicy off{};
    REQUIRE_FALSE(off.enabled());
    yuzu::agent::PluginSigningPolicy on{"/some/path.pem", false};
    REQUIRE(on.enabled());
}

TEST_CASE("PluginLoader::scan with require_signature on rejects unsigned plugin files",
          "[plugin_loader][signing]") {
    auto fx = build_signing_fixtures();
    auto plugin_dir = fx.dir / "plugins";
    fs::create_directories(plugin_dir);

    // Place an extension-correct file with no .sig sibling. require=true
    // means scan() must reject it before dlopen.
    auto plugin_path = plugin_dir / (std::string{"unsigned"} + kPluginExt);
    {
        std::ofstream pf(plugin_path, std::ios::binary);
        pf << "fake plugin bytes";
    }

    yuzu::agent::PluginSigningPolicy policy{fx.trust_bundle, /*require_signature=*/true};
    auto result = yuzu::agent::PluginLoader::scan(plugin_dir, {}, policy);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.size() == 1);
    REQUIRE(result.errors.front().reason.starts_with(yuzu::agent::kSignatureMissingReason));
}

TEST_CASE("PluginLoader rejects a plugin declaring a reserved name",
          "[plugin_loader][reserved_name]") {
    auto fixture = find_fixture_plugin("reserved_name_fixture_plugin");
    if (fixture.empty()) {
        WARN("reserved_name_fixture_plugin not found — skipping behavioral scan test");
        SUCCEED();
        return;
    }

    // Copy the fixture into an isolated directory so we scan only it —
    // avoids false positives from stray built plugins that may live in a
    // shared tree when run from the build root. Unique per-invocation name
    // is generated from mt19937_64 rather than ::getpid() so the code
    // compiles on MSVC (`_getpid` in <process.h>) and Apple Clang
    // (`<unistd.h>` not transitively available) without per-platform
    // guards. Adopts yuzu::test::unique_temp_path (#482) over the
    // earlier raw mt19937_64 path which lacked the monotonic counter
    // that protects against Defender-induced collision flakes.
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_reserved_plugin_");
    fs::create_directories(tmp);
    auto staged = tmp / fixture.filename();
    std::error_code ec;
    fs::copy_file(fixture, staged, fs::copy_options::overwrite_existing, ec);
    REQUIRE_FALSE(ec);

    auto result = yuzu::agent::PluginLoader::scan(tmp);

    // Must not appear in loaded — nothing under __guard__ may be handed
    // to the dispatcher.
    REQUIRE(result.loaded.empty());

    // Must appear in errors with the stable reason prefix so the agent
    // metric can categorise it.
    REQUIRE(result.errors.size() == 1);
    const auto& err = result.errors.front();
    REQUIRE(err.path == staged.string());
    REQUIRE(err.reason.starts_with(yuzu::agent::kReservedNameReason));
    REQUIRE(err.reason.find("__guard__") != std::string::npos);

    fs::remove_all(tmp);
}

TEST_CASE("PluginLoader rejects a plugin declaring an invalid name",
          "[plugin_loader][name_validation]") {
    auto fixture = find_fixture_plugin("invalid_name_fixture_plugin");
    if (fixture.empty()) {
        WARN("invalid_name_fixture_plugin not found — skipping behavioral scan test");
        SUCCEED();
        return;
    }

    // Scan an isolated copy so the result reflects only this fixture (mirrors
    // the reserved-name behavioral test above).
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_invalid_name_plugin_");
    fs::create_directories(tmp);
    auto staged = tmp / fixture.filename();
    std::error_code ec;
    fs::copy_file(fixture, staged, fs::copy_options::overwrite_existing, ec);
    REQUIRE_FALSE(ec);

    auto result = yuzu::agent::PluginLoader::scan(tmp);

    // A malformed name must not yield a loaded plugin...
    REQUIRE(result.loaded.empty());
    // ...and must surface as a single error tagged with the stable reason so
    // the agent metric can categorise it. The reason is exactly kInvalidNameReason
    // with no suffix — the raw (attacker-controlled) name is deliberately not
    // echoed (#822).
    REQUIRE(result.errors.size() == 1);
    const auto& err = result.errors.front();
    REQUIRE(err.path == staged.string());
    REQUIRE(err.reason == yuzu::agent::kInvalidNameReason);

    fs::remove_all(tmp);
}

// ─── Plugin config-sync (covers agent.cpp post-load sync invariant) ─────────
//
// The fix at agent.cpp ~line 564 (sync_master_config_to_plugins) is the
// only thing that makes agent_actions::info return a populated
// `agent.plugins.count` instead of `(not set)`. A regression — the loop
// silently dropped or restricted to a key subset — would not crash, log,
// or fail any other test. These cases pin the invariant directly.
//
// We exercise the helper through its templated public surface with a
// FakeCtx stub so the test has no dependency on the (anonymous-namespace)
// PluginContextImpl from agent.cpp.

namespace {

struct FakeCtx {
    std::unordered_map<std::string, std::string> config;
};

} // namespace

TEST_CASE("sync_master_config_to_plugins copies every master key into every plugin",
          "[agent][config_sync]") {
    std::unordered_map<std::string, std::string> master = {
        {"agent.id", "abc"},
        {"agent.plugins.count", "3"},
        {"agent.modules.count", "5"},
        {"agent.plugins.0.name", "os_info"},
        {"agent.plugins.1.name", "discovery"},
    };

    std::unordered_map<std::string, std::unique_ptr<FakeCtx>> plugins;
    plugins["os_info"] = std::make_unique<FakeCtx>();
    plugins["discovery"] = std::make_unique<FakeCtx>();
    plugins["status"] = std::make_unique<FakeCtx>();

    yuzu::agent::detail::sync_master_config_to_plugins(master, plugins);

    for (const auto& name : {"os_info", "discovery", "status"}) {
        const auto& cfg = plugins[name]->config;
        REQUIRE(cfg.at("agent.id") == "abc");
        REQUIRE(cfg.at("agent.plugins.count") == "3");
        REQUIRE(cfg.at("agent.modules.count") == "5");
        REQUIRE(cfg.at("agent.plugins.0.name") == "os_info");
        REQUIRE(cfg.at("agent.plugins.1.name") == "discovery");
    }
}

TEST_CASE("sync_master_config_to_plugins overwrites stale snapshot values",
          "[agent][config_sync]") {
    // This is the actual production scenario: per-plugin contexts hold a
    // snapshot taken before the master gained agent.plugins.count, so the
    // pre-sync value is the empty string (or in the test, an old value).
    std::unordered_map<std::string, std::string> master = {
        {"agent.plugins.count", "45"},
    };

    std::unordered_map<std::string, std::unique_ptr<FakeCtx>> plugins;
    auto stale = std::make_unique<FakeCtx>();
    stale->config["agent.plugins.count"] = ""; // empty snapshot — the bug
    plugins["agent_actions"] = std::move(stale);

    yuzu::agent::detail::sync_master_config_to_plugins(master, plugins);

    REQUIRE(plugins["agent_actions"]->config.at("agent.plugins.count") == "45");
}

TEST_CASE("sync_master_config_to_plugins is a no-op on empty master", "[agent][config_sync]") {
    std::unordered_map<std::string, std::string> master;
    std::unordered_map<std::string, std::unique_ptr<FakeCtx>> plugins;
    auto p = std::make_unique<FakeCtx>();
    p->config["agent.id"] = "preserved";
    plugins["x"] = std::move(p);

    yuzu::agent::detail::sync_master_config_to_plugins(master, plugins);

    // Empty master must not erase pre-existing per-plugin keys.
    REQUIRE(plugins["x"]->config.at("agent.id") == "preserved");
}

TEST_CASE("sync_master_config_to_plugins is a no-op on empty plugin set", "[agent][config_sync]") {
    std::unordered_map<std::string, std::string> master = {{"agent.id", "abc"}};
    std::unordered_map<std::string, std::unique_ptr<FakeCtx>> plugins;
    // Must not throw or trip UB on empty target.
    yuzu::agent::detail::sync_master_config_to_plugins(master, plugins);
    REQUIRE(plugins.empty());
}
