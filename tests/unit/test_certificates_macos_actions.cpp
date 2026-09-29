/**
 * test_certificates_macos_actions.cpp -- action-level LocalDispatcher tests
 * proving #4374's two mutation probes (the SecItem `not_available` sentinel
 * on a permission-denied keychain, and the console-owner recheck's
 * `not_available` sentinel on a changed/unresolvable console session) now
 * fail if either is removed or degraded (#4374 fix shape 2 + 3).
 *
 * Loads the ACTUAL built certificates plugin (certificates.dylib, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher -- the same
 * load-real-plugin-by-path + LocalDispatcher pattern
 * test_users_posix_actions.cpp established for the users plugin's POSIX
 * argv migration, applied here to certificates' macOS SecItem/console-owner
 * orchestration instead of a subprocess argv.
 *
 * GUARD IS UNAVOIDABLE, NOT A CONVENIENCE: this file needs Security.framework
 * (SecKeychainCreate/SecItemAdd/SecKeychainDelete for the in-process fixture
 * keychain, and read_keychain_bounded's SecItem-backed precondition probe)
 * AND the orchestration under test -- list_certs_macos/details_cert_macos's
 * SecItem read + console-owner recheck paths -- exists ONLY in
 * certificates_plugin.cpp's `__APPLE__` region. Off that combination there
 * is nothing here to test and nothing to build it against, so
 * Linux/Windows/a Security.framework-less macOS CLT box all compile this TU
 * to an EMPTY Catch2 translation unit (no TEST_CASE at all), exactly the
 * shape tests/unit/test_keychain_read.cpp:299 already uses for its own
 * `__APPLE__`-only cases.
 *
 * WHAT THIS DOES NOT DO: no case here reads the host's real System.keychain
 * or the real console user's real login keychain, and no case causes the
 * plugin to spawn `security`/`sudo`/`launchctl`/`openssl`. System/root reads
 * go through an in-process SecItem fixture keychain (TestKeychain below),
 * reached by redirecting system_keychain_path()/root_keychain_path() via the
 * YUZU_CERTIFICATES_*_KEYCHAIN_PATH_OVERRIDE env seams; the one real
 * subprocess spawn on the login-keychain path (the launchctl-asuser/security
 * read) is replaced by the armed, fixture-controlled
 * YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE sentinel, so "the
 * spawn never happened" and "the spawn was suppressed upstream by the
 * console-owner recheck" are distinguishable from the test side (cases 7-11)
 * without ever letting a real spawn occur. The one real, read-only host
 * access is a single `read_keychain_bounded` call against
 * /System/Library/Keychains/SystemRootCertificates.keychain, BEFORE any
 * override is armed, purely to obtain one real, valid DER certificate (and
 * its thumbprint/subject) to seed the fixture keychain with -- never an
 * invented certificate fixture.
 */

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)

#include <catch2/catch_test_macros.hpp>

#include <certificates_macos_parsers.hpp> // secitem_failure_reason / secitem_provenance
#include <certificates_x509.hpp>          // yuzu::certificates_x509::parse_der_cert
#include <macos_console_user.hpp>         // yuzu::macos::is_valid_username / system_keychain_path

#include <yuzu/agent/keychain_read.hpp>   // yuzu::agent::read_keychain_bounded
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp" // yuzu::test::TempDir
#include "scoped_env.hpp"   // yuzu::test::ScopedEnv

#include <Security/Security.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

// ── Plugin load (mirrors test_users_posix_actions.cpp:47-95) ───────────────

fs::path find_certificates_plugin() {
    const std::string lib_name = "certificates.dylib";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "certificates" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "certificates" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "certificates" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "certificates" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_certificates_plugin() {
    auto plugin_path = find_certificates_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

// ── Small output helpers ────────────────────────────────────────────────────

std::vector<std::string> split_lines(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(cur);
    return out;
}

int count_lines_containing(const std::vector<std::string>& lines, std::string_view needle) {
    int n = 0;
    for (const auto& l : lines)
        if (l.find(needle) != std::string::npos)
            ++n;
    return n;
}

// ── Real certificate, fetched from the host's actual root-cert keychain ────
// (never an invented fixture) BEFORE any override is armed.

struct ExpectedCert {
    std::vector<unsigned char> der;
    std::string thumbprint;
};

std::optional<ExpectedCert> real_root_cert() {
    auto read = yuzu::agent::read_keychain_bounded(
        "/System/Library/Keychains/SystemRootCertificates.keychain", 15s);
    if (!(read.status == yuzu::agent::KeychainReadStatus::Completed ||
         read.status == yuzu::agent::KeychainReadStatus::Truncated))
        return std::nullopt;
    if (read.certs_der.empty())
        return std::nullopt;
    ExpectedCert out;
    out.der = read.certs_der.front();
    auto fields = yuzu::certificates_x509::parse_der_cert(out.der);
    if (!fields.has_value())
        return std::nullopt;
    out.thumbprint = fields->thumbprint;
    return out;
}

// ── TestKeychain: an in-process, real SecKeychain fixture (never the host's
// System/login keychain) ────────────────────────────────────────────────────

struct TestKeychain {
    yuzu::test::TempDir dir{"yuzu_test_certs_kc_"};
    fs::path path{dir.path / "fixture.keychain"};
    yuzu::agent::ScopedCFRef<SecKeychainRef> kc;

    TestKeychain() {
        fs::create_directories(dir.path);
        SecKeychainRef raw = nullptr;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus status =
            SecKeychainCreate(path.c_str(), 0, "", /*promptUser=*/false, nullptr, &raw);
#pragma clang diagnostic pop
        REQUIRE(status == errSecSuccess);
        kc = yuzu::agent::ScopedCFRef<SecKeychainRef>(raw);
    }

    ~TestKeychain() {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (kc.get())
            SecKeychainDelete(kc.get());
#pragma clang diagnostic pop
    }

    TestKeychain(const TestKeychain&) = delete;
    TestKeychain& operator=(const TestKeychain&) = delete;

    void add_cert(const std::vector<unsigned char>& der) {
        yuzu::agent::ScopedCFRef<CFDataRef> data(
            CFDataCreate(nullptr, der.data(), static_cast<CFIndex>(der.size())));
        REQUIRE(data.get() != nullptr);
        yuzu::agent::ScopedCFRef<SecCertificateRef> cert(
            SecCertificateCreateWithData(nullptr, data.get()));
        REQUIRE(cert.get() != nullptr);

        yuzu::agent::ScopedCFRef<CFMutableDictionaryRef> attrs(CFDictionaryCreateMutable(
            nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
        REQUIRE(attrs.get() != nullptr);
        CFDictionarySetValue(attrs.get(), kSecClass, kSecClassCertificate);
        CFDictionarySetValue(attrs.get(), kSecValueRef, cert.get());
        CFDictionarySetValue(attrs.get(), kSecUseKeychain, kc.get());

        OSStatus status = SecItemAdd(attrs.get(), nullptr);
        REQUIRE(status == errSecSuccess);
    }
};

/// A path this process has NEVER opened, permission-denied at the filesystem
/// level -- copied from an already-created (never itself opened by SecItem
/// via THIS path) TestKeychain's file, chmod 000. Deliberately NOT the
/// TestKeychain's own path: this process holds a live SecKeychainRef to that
/// one and Security.framework caches keychain objects per process by path,
/// so a status probe on the ORIGINAL path after chmod may not observe the
/// mode change (the OpenFailed measurement this fixture reproduces was taken
/// on a copy never opened by the measuring process -- see keychain_read.cpp:
/// 173-175). Restores permissions in its destructor before TempDir cleanup.
struct DeniedCopy {
    fs::path path;

    explicit DeniedCopy(const TestKeychain& kc)
        : path(kc.dir.path / "denied.keychain") {
        std::error_code ec;
        fs::copy_file(kc.path, path, ec);
        REQUIRE_FALSE(ec);
        fs::permissions(path, fs::perms::none, ec);
        REQUIRE_FALSE(ec);
    }

    ~DeniedCopy() {
        std::error_code ec;
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, ec);
    }

    DeniedCopy(const DeniedCopy&) = delete;
    DeniedCopy& operator=(const DeniedCopy&) = delete;
};

/// WARN-skips (never a hard SKIP/FAIL) the two denied-copy cases when running
/// as root -- root bypasses DAC, so chmod 000 would not actually deny
/// anything and the case would prove nothing.
[[nodiscard]] bool root_would_bypass_dac() {
    if (::geteuid() == 0) {
        WARN("running as root -- DAC bypasses the chmod-000 denied copy; skipping");
        return true;
    }
    return false;
}

/// The current account's username via getpwuid, for the console-owner cases.
/// WARN-skips (never fails) when running as root ("root" is the
/// no-console-user sentinel, so it cannot stand in for a real console
/// session) or when the resolved name fails yuzu::macos::is_valid_username
/// (the same injection guard the production argv path enforces).
[[nodiscard]] std::optional<std::string> console_username_or_skip() {
    if (::geteuid() == 0) {
        WARN("running as root -- \"root\" is the no-console-user sentinel; skipping "
             "console-owner cases");
        return std::nullopt;
    }
    const auto* pw = ::getpwuid(::getuid());
    if (!pw || !pw->pw_name) {
        WARN("could not resolve own username via getpwuid -- skipping console-owner cases");
        return std::nullopt;
    }
    std::string name = pw->pw_name;
    if (!yuzu::macos::is_valid_username(name)) {
        WARN("own username '" << name << "' fails is_valid_username -- skipping console-owner "
             "cases");
        return std::nullopt;
    }
    return name;
}

/// WARN-skips (never fails) a case that relies on the REAL, un-overridden
/// console-owner check (::stat("/dev/console")) matching this process's own
/// uid -- true on an interactive dev Mac (this process IS the console user),
/// not guaranteed on a headless CI runner, where /dev/console may be owned
/// by a different account or no session at all. Every OTHER console-owner
/// case in this file sidesteps this by explicitly overriding
/// CONSOLE_OWNER_UID_OVERRIDE to std::to_string(::getuid()) rather than
/// relying on the real stat() call -- this helper exists for the one case
/// that deliberately tests the empty-override fall-through path itself,
/// which cannot use that same sidestep (CI failure: PR #4539, macOS leg).
[[nodiscard]] bool real_console_owner_matches_self_or_skip() {
    struct stat console_st {};
    if (::stat("/dev/console", &console_st) != 0) {
        WARN("could not stat /dev/console -- skipping the real-console-owner case");
        return false;
    }
    if (console_st.st_uid != ::getuid()) {
        WARN("this process's uid (" << ::getuid() << ") does not own /dev/console (uid "
             << console_st.st_uid << ") -- skipping the real-console-owner case "
             "(expected on a headless runner, not just an interactive session)");
        return false;
    }
    return true;
}

} // namespace

// ── Cases 1-6: SecItem sentinel vectors, store=System ───────────────────────
// Every case redirects system_keychain_path() at an in-process fixture
// keychain via YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE -- the real
// host System.keychain is never read.

TEST_CASE("list: System.keychain empty -> header only, UNDECLARED/UNKNOWN, no provenance",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    // list_certs_macos() unconditionally resolves the console user before
    // touching any keychain (it needs to know whether store=login would be
    // readable at all) -- without this override that resolution spawns a
    // real /usr/bin/stat, which this file's own banner says never happens.
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       kc.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "System"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == "subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(result.result_provenance.empty());
}

TEST_CASE("list: System.keychain permission-denied -> exactly one not_available line, "
         "CONSTRAINED/PARTIAL",
         "[certificates][macos_actions]") {
    if (root_would_bypass_dac())
        return;
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    DeniedCopy denied(kc);

    // Named precondition: if the fixture's chmod-000 lifecycle ever diverges
    // from the measurement this fixture reproduces, fail loudly HERE rather
    // than via a misleading downstream assertion.
    auto probe = yuzu::agent::read_keychain_bounded(denied.path.string(), 15s);
    REQUIRE(probe.status == yuzu::agent::KeychainReadStatus::OpenFailed);
    INFO("measured KeychainReadStatus of the denied copy: OpenFailed (precondition confirmed)");

    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       denied.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "System"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    const auto expected_reason =
        *yuzu::certificates_macos::secitem_failure_reason(
            yuzu::agent::KeychainReadStatus::OpenFailed, "System.keychain");
    const std::string expected_line = std::format("not_available|{}", expected_reason);
    CHECK(count_lines_containing(lines, expected_line) == 1);
    // No CERTIFICATE DATA row leaked through. Only System.keychain was
    // queried (store=System) and it failed to open, so the only two lines
    // this call can possibly produce are the header and the not_available
    // sentinel -- a real cert row would never literally contain the header's
    // own column-name text, so searching for that text is a no-op check
    // that always passes regardless of what leaked; asserting the exact
    // line count is what actually catches a leaked row.
    REQUIRE(lines.size() == 2);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance ==
         yuzu::certificates_macos::secitem_provenance("System.keychain"));
}

TEST_CASE("list: System.keychain with the real root cert -> exactly one data row, UNDECLARED",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    auto expected = real_root_cert();
    if (!expected) {
        WARN("could not read a real certificate from SystemRootCertificates.keychain -- "
             "skipping");
        return;
    }
    TestKeychain kc;
    kc.add_cert(expected->der);
    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       kc.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "System"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    REQUIRE(lines.size() == 2); // header + exactly one data row
    auto fields = split_fields(lines[1]);
    REQUIRE(fields.size() == 8);
    CHECK(fields[2] == expected->thumbprint);
    CHECK(fields[6] == "System.keychain");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

TEST_CASE("details: real cert present in System.keychain -> the row, no status|not_found",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    auto expected = real_root_cert();
    if (!expected) {
        WARN("could not read a real certificate from SystemRootCertificates.keychain -- "
             "skipping");
        return;
    }
    TestKeychain kc;
    kc.add_cert(expected->der);
    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       kc.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "System"}, {"thumbprint", expected->thumbprint.c_str()}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, expected->thumbprint) == 1);
    CHECK(count_lines_containing(lines, "status|not_found") == 0);
}

TEST_CASE("details: System.keychain permission-denied -> not_available, never status|not_found",
         "[certificates][macos_actions]") {
    if (root_would_bypass_dac())
        return;
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    DeniedCopy denied(kc);

    auto probe = yuzu::agent::read_keychain_bounded(denied.path.string(), 15s);
    REQUIRE(probe.status == yuzu::agent::KeychainReadStatus::OpenFailed);
    INFO("measured KeychainReadStatus of the denied copy: OpenFailed (precondition confirmed)");

    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       denied.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    // A syntactically valid (but arbitrary) 40-hex thumbprint -- the denied
    // read must never get far enough to compare against it.
    std::vector<YuzuParam> params{{"store", "System"},
                                  {"thumbprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "status|not_found") == 0);
    const auto expected_reason =
        *yuzu::certificates_macos::secitem_failure_reason(
            yuzu::agent::KeychainReadStatus::OpenFailed, "System.keychain");
    CHECK(count_lines_containing(lines, std::format("not_available|{}", expected_reason)) == 1);
    // Only System.keychain was queried and it failed to open: header + the
    // sentinel is the only possible output, same reasoning as the list case
    // above.
    REQUIRE(lines.size() == 2);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance ==
         yuzu::certificates_macos::secitem_provenance("System.keychain"));
}

TEST_CASE("details: System.keychain empty -> status|not_found, UNDECLARED",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    yuzu::test::ScopedEnv sys_override("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE",
                                       kc.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "System"},
                                  {"thumbprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "status|not_found") == 1);
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

// ── Cases 7-11: console-owner recheck vectors, store=login ─────────────────
// Every case arms YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE, the
// fixture-controlled observable at the one real spawn site this leg would
// otherwise reach -- so "no evidence of a spawn" in 7-9 means "the armed
// sentinel did not fire" (the recheck suppressed it upstream), not merely
// "nothing was asserted about it", and 10-11 prove the sentinel DOES fire
// when the owner matches (the spawn site is genuinely reachable).

namespace {
constexpr const char* kInjectedLoginFailToken = "yuzu-test-injected-login-read";
constexpr const char* kInjectedLoginFailLine = "login keychain read failed "
                                               "(yuzu-test-injected-login-read)";
} // namespace

TEST_CASE("list: console owner changed mid-action -> not_available sentinel, injected spawn "
         "never fires",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    // A uid guaranteed different from this process's own.
    const std::string other_uid = ::getuid() != 0 ? "0" : "1";
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE", other_uid);
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "not_available|console user changed") == 1);
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 0);
    for (const auto& l : lines) {
        auto fields = split_fields(l);
        if (fields.size() >= 7)
            CHECK(fields[6] != "login.keychain-db");
    }
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "login-keychain");
}

TEST_CASE("details: console owner changed mid-action -> not_available sentinel, no "
         "status|not_found, injected spawn never fires",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    const std::string other_uid = ::getuid() != 0 ? "0" : "1";
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE", other_uid);
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"},
                                  {"thumbprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "not_available|console user changed") == 1);
    CHECK(count_lines_containing(lines, "status|not_found") == 0);
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 0);
}

TEST_CASE("list: console owner recheck itself fails (unparseable uid) -> not_available "
         "sentinel, injected spawn never fires",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE", "nope");
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "not_available|console user recheck failed") == 1);
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 0);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "login-keychain");
}

TEST_CASE("list: an empty CONSOLE_OWNER_UID_OVERRIDE is ignored, falling through to the real "
         "console owner (matches its 4 sibling seams, governance Gate 2 finding)",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    // This case, uniquely among the console-owner cases, relies on the REAL
    // ::stat("/dev/console") answer matching ::getuid() -- every sibling
    // case sidesteps that by overriding CONSOLE_OWNER_UID_OVERRIDE
    // explicitly. Not guaranteed on a headless CI runner (CI failure: PR
    // #4539, macOS leg -- console user reported "changed" there).
    if (!real_console_owner_matches_self_or_skip())
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE", "");
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    // An empty override must behave exactly like the "unchanged" control
    // case below (real ::stat("/dev/console") matches this process's own
    // uid, so the recheck passes and the spawn is reached) -- NOT like the
    // "nope" case above (unparseable -> fail-closed "recheck failed"). Before
    // db52b5a57 this asserted the wrong (fail-closed) outcome: an empty-but-
    // set value activated the override branch and forced std::from_chars to
    // fail, permanently degrading every read.
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 1);
    CHECK(count_lines_containing(lines, "console user changed") == 0);
    CHECK(count_lines_containing(lines, "console user recheck failed") == 0);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "login-keychain");
}

TEST_CASE("list control: console owner unchanged -> the armed injected-failure line fires, "
         "no console-owner sentinel",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE",
                                       std::to_string(::getuid()));
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    // The spawn site IS reached when the owner matches -- 7-9's silence
    // above is suppression by the recheck, not the seam failing to arm.
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 1);
    CHECK(count_lines_containing(lines, "console user changed") == 0);
    CHECK(count_lines_containing(lines, "console user recheck failed") == 0);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "login-keychain");
}

TEST_CASE("details control: console owner unchanged -> the armed injected-failure line fires, "
         "no status|not_found",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE",
                                       std::to_string(::getuid()));
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        kInjectedLoginFailToken);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"},
                                  {"thumbprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, kInjectedLoginFailLine) == 1);
    CHECK(count_lines_containing(lines, "status|not_found") == 0);
}

// ── Root-keychain override, action-level (code-review Gate 1 finding, found
// independently by both external reviewers): cases 1-6 above only ever arm
// YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE with store=System: nothing
// drove store=root through the real plugin with the ROOT override armed, so
// a regression that stopped consulting root_keychain_path() at either call
// site would pass every existing assertion. Mirrors cases 2/5's
// permission-denied shape exactly, just for the root keychain/store.

TEST_CASE("list: SystemRootCertificates.keychain permission-denied -> exactly one "
         "not_available line, CONSTRAINED/PARTIAL",
         "[certificates][macos_actions]") {
    if (root_would_bypass_dac())
        return;
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    DeniedCopy denied(kc);

    auto probe = yuzu::agent::read_keychain_bounded(denied.path.string(), 15s);
    REQUIRE(probe.status == yuzu::agent::KeychainReadStatus::OpenFailed);
    INFO("measured KeychainReadStatus of the denied copy: OpenFailed (precondition confirmed)");

    yuzu::test::ScopedEnv root_override("YUZU_CERTIFICATES_ROOT_KEYCHAIN_PATH_OVERRIDE",
                                        denied.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "root"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    const auto expected_reason =
        *yuzu::certificates_macos::secitem_failure_reason(
            yuzu::agent::KeychainReadStatus::OpenFailed, "SystemRootCertificates.keychain");
    const std::string expected_line = std::format("not_available|{}", expected_reason);
    CHECK(count_lines_containing(lines, expected_line) == 1);
    REQUIRE(lines.size() == 2);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance ==
         yuzu::certificates_macos::secitem_provenance("SystemRootCertificates.keychain"));
}

TEST_CASE("details: SystemRootCertificates.keychain permission-denied -> not_available, "
         "never status|not_found",
         "[certificates][macos_actions]") {
    if (root_would_bypass_dac())
        return;
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    TestKeychain kc;
    DeniedCopy denied(kc);

    auto probe = yuzu::agent::read_keychain_bounded(denied.path.string(), 15s);
    REQUIRE(probe.status == yuzu::agent::KeychainReadStatus::OpenFailed);
    INFO("measured KeychainReadStatus of the denied copy: OpenFailed (precondition confirmed)");

    yuzu::test::ScopedEnv root_override("YUZU_CERTIFICATES_ROOT_KEYCHAIN_PATH_OVERRIDE",
                                        denied.path.string());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "root"},
                                  {"thumbprint", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}};
    auto result = dispatcher.run(plugin->descriptor, "details", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "status|not_found") == 0);
    const auto expected_reason =
        *yuzu::certificates_macos::secitem_failure_reason(
            yuzu::agent::KeychainReadStatus::OpenFailed, "SystemRootCertificates.keychain");
    CHECK(count_lines_containing(lines, std::format("not_available|{}", expected_reason)) == 1);
    REQUIRE(lines.size() == 2);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance ==
         yuzu::certificates_macos::secitem_provenance("SystemRootCertificates.keychain"));
}

// ── Console-user override, positive discrimination (code-review Gate 1
// finding, found independently by both external reviewers): every case
// above arms YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE with the CURRENT real
// account (console_username_or_skip()), so on a single-user host the real
// `stat /dev/console` would resolve to the identical username -- nothing
// asserted the override's value, only its presence. A regression that
// silently stopped consulting the override would pass every case above
// while resuming the real subprocess spawn (the exact #4488 crash path,
// which failed 100% pre-fix). This case uses a syntactically valid but
// certainly-nonexistent username so the assertion can only pass if the
// override's VALUE, not a real ::stat/getpwnam of the actual console user,
// drove resolution.
TEST_CASE("list: console user override with a valid but non-existent username -> "
         "not_available sentinel proves the override value drove resolution",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE",
                                        "yuzu_no_such_test_user");

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    CHECK(count_lines_containing(lines, "not_available|console user has no passwd record") == 1);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "login-keychain");
}

// ── Injected login-read-failure detail truncation boundary (code-review
// Gate 1 finding): injected_login_keychain_read_failure() truncates the env
// value to 200 bytes; every other case supplies a short token, so the
// truncation contract was proven only by implementation inspection.
TEST_CASE("list control: injected login-read failure detail is truncated to 200 bytes",
         "[certificates][macos_actions]") {
    auto plugin = load_certificates_plugin();
    if (!plugin) {
        WARN("certificates plugin library not found -- skipping");
        return;
    }
    auto me = console_username_or_skip();
    if (!me)
        return;

    yuzu::test::ScopedEnv user_override("YUZU_CERTIFICATES_CONSOLE_USER_OVERRIDE", *me);
    yuzu::test::ScopedEnv uid_override("YUZU_CERTIFICATES_CONSOLE_OWNER_UID_OVERRIDE",
                                       std::to_string(::getuid()));
    // 200 'A's is exactly the truncation limit; the trailing 'Z' must never
    // appear in the output if truncation is correct.
    const std::string long_token(200, 'A');
    yuzu::test::ScopedEnv fail_override("YUZU_CERTIFICATES_LOGIN_KEYCHAIN_READ_FAIL_OVERRIDE",
                                        long_token + "Z");

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"store", "login"}};
    auto result = dispatcher.run(plugin->descriptor, "list", params);

    CHECK(result.rc == 0);
    auto lines = split_lines(result.captured);
    const std::string expected_line =
        std::format("not_available|login keychain read failed ({})", long_token);
    CHECK(count_lines_containing(lines, expected_line) == 1);
    for (const auto& l : lines)
        CHECK(l.find('Z') == std::string::npos);
}

#endif // defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)
