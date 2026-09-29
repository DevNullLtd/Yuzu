/**
 * test_new_plugins.cpp — Smoke tests and unit tests for new plugins
 *
 * Covers descriptors (name, version, actions, ABI) and validation logic for:
 *   http_client, content_dist, interaction, agent_logging, storage,
 *   registry, wmi, rdp_control
 *
 * Also covers service name validation (duplicated from TriggerEngine).
 *
 * NOTE: Several validation functions (is_valid_url, is_safe_filename,
 * is_safe_arg, is_valid_wmi_class, is_valid_wmi_namespace) live inside
 * anonymous namespaces in their respective plugin .cpp files and cannot be
 * called from external code. The tests below duplicate the validation logic
 * for coverage purposes. These functions should be refactored into a shared
 * header (e.g. yuzu/validation.hpp) so they can be tested directly and
 * reused across plugins.
 */

#include <yuzu/plugin.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <regex>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;

// ============================================================================
// Helpers — dynamic plugin loading
// ============================================================================

namespace {

/// OS-specific shared library extension
#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

/**
 * Attempt to find and load a plugin shared library from the build directory.
 * Returns a handle (HMODULE or void*) or nullptr on failure.
 */
struct PluginHandle {
    void* handle = nullptr;
    const YuzuPluginDescriptor* desc = nullptr;

    explicit operator bool() const { return handle != nullptr && desc != nullptr; }

    ~PluginHandle() {
        if (handle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(handle));
#else
            dlclose(handle);
#endif
        }
    }

    // Non-copyable, movable
    PluginHandle() = default;
    PluginHandle(const PluginHandle&) = delete;
    PluginHandle& operator=(const PluginHandle&) = delete;
    PluginHandle(PluginHandle&& o) noexcept
        : handle(o.handle), desc(o.desc) {
        o.handle = nullptr;
        o.desc = nullptr;
    }
    PluginHandle& operator=(PluginHandle&& o) noexcept {
        if (this != &o) {
            if (handle) {
#ifdef _WIN32
                FreeLibrary(static_cast<HMODULE>(handle));
#else
                dlclose(handle);
#endif
            }
            handle = o.handle;
            desc = o.desc;
            o.handle = nullptr;
            o.desc = nullptr;
        }
        return *this;
    }
};

/**
 * Try to locate and load a plugin from the build tree.
 * Searches in builddir/agents/plugins/<name>/ for the shared library.
 */
PluginHandle load_plugin(const std::string& name) {
    PluginHandle ph;

    // Build directory is typically <project>/builddir — locate relative to
    // the test executable or via environment.
    // We try several plausible relative paths from the CWD.
    std::vector<fs::path> search_dirs;

    // From builddir root
    search_dirs.push_back(fs::path{"agents"} / "plugins" / name);
    // From builddir/tests
    search_dirs.push_back(fs::path{".."} / "agents" / "plugins" / name);
    // Absolute path using MESON_BUILD_ROOT if set
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        search_dirs.push_back(fs::path{build_root} / "agents" / "plugins" / name);
    }
    // Also try builddir directly
    search_dirs.push_back(fs::path{"builddir"} / "agents" / "plugins" / name);
    // Canonical per-OS build dirs, so the tests-build-* symlink invocation
    // from the project root (CLAUDE.md "Direct binary invocation") finds the
    // plugins instead of silently skipping every descriptor test.
    for (const char* os_dir : {"build-macos", "build-linux", "build-windows"}) {
        search_dirs.push_back(fs::path{os_dir} / "agents" / "plugins" / name);
    }

    std::string lib_name = name + kPluginExt;
    fs::path found_path;

    for (const auto& dir : search_dirs) {
        fs::path candidate = dir / lib_name;
        std::error_code ec;
        if (fs::exists(candidate, ec) && !ec) {
            found_path = candidate;
            break;
        }
    }

    if (found_path.empty()) {
        return ph; // Not found
    }

#ifdef _WIN32
    auto abs_path = fs::absolute(found_path);
    HMODULE hmod = LoadLibraryW(abs_path.wstring().c_str());
    if (!hmod) return ph;
    ph.handle = static_cast<void*>(hmod);

    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        GetProcAddress(hmod, "yuzu_plugin_descriptor"));
#else
    auto abs_path = fs::absolute(found_path);
    void* lib = dlopen(abs_path.c_str(), RTLD_LAZY);
    if (!lib) return ph;
    ph.handle = lib;

    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        dlsym(lib, "yuzu_plugin_descriptor"));
#endif

    if (fn) {
        ph.desc = fn();
    }
    return ph;
}

/// Count the actions in a null-terminated array.
int count_actions(const char* const* actions) {
    if (!actions) return 0;
    int n = 0;
    while (actions[n] != nullptr) ++n;
    return n;
}

/// Check if a specific action is in the null-terminated list.
bool has_action(const char* const* actions, const char* target) {
    if (!actions || !target) return false;
    for (int i = 0; actions[i] != nullptr; ++i) {
        if (std::strcmp(actions[i], target) == 0) return true;
    }
    return false;
}

/// Matches a basic semver pattern: major.minor.patch
bool is_semver(const char* version) {
    if (!version) return false;
    std::regex re(R"(\d+\.\d+\.\d+.*)");
    return std::regex_match(version, re);
}

// ============================================================================
// Duplicated validation functions for testing
//
// These mirror the anonymous-namespace functions inside the plugin source
// files. They SHOULD be refactored into a shared yuzu/validation.hpp header
// for both plugin use and direct unit testing.
// ============================================================================

/// Mirrors http_client_plugin.cpp: is_valid_url
bool test_is_valid_url(std::string_view url) {
    return url.starts_with("http://") || url.starts_with("https://");
}

/// Mirrors content_dist_plugin.cpp: is_safe_filename
bool test_is_safe_filename(std::string_view name) {
    if (name.empty() || name.find("..") != std::string_view::npos) return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_')
            return false;
    }
    return true;
}

/// Mirrors content_dist_plugin.cpp: is_safe_arg
bool test_is_safe_arg(std::string_view arg) {
    for (char c : arg) {
        if (c == ';' || c == '&' || c == '|' || c == '`' || c == '$' ||
            c == '(' || c == ')' || c == '{' || c == '}' || c == '<' ||
            c == '>' || c == '!' || c == '~' || c == '^' || c == '\'' ||
            c == '"' || c == '#' || c == '*' || c == '?' || c == '[' ||
            c == ']' || c == '\n' || c == '\r') {
            return false;
        }
    }
    return true;
}

/// Mirrors wmi_plugin.cpp: is_valid_wmi_class
bool test_is_valid_wmi_class(std::string_view cls) {
    if (cls.empty() || cls.size() > 256) return false;
    for (char c : cls) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return false;
    }
    return true;
}

/// Mirrors wmi_plugin.cpp: is_valid_wmi_namespace
bool test_is_valid_wmi_namespace(std::string_view ns) {
    static const char* allowed[] = {
        "root\\cimv2",
        "root\\wmi",
        "root\\standardcimv2",
    };

    std::string lower;
    lower.reserve(ns.size());
    for (char c : ns) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (const auto* a : allowed) {
        if (lower == a) return true;
    }
    return false;
}

} // namespace

// ============================================================================
// Section 1: Plugin descriptor smoke tests (dynamic loading)
// ============================================================================

// Helper macro to reduce boilerplate for descriptor tests.
// If the plugin DLL is not found (e.g. build_agent=false or plugins not yet
// built), the test is skipped rather than failing.
#define DESCRIPTOR_TEST(plugin_name, expected_name, expected_action_count, ...)           \
    TEST_CASE("descriptor: " plugin_name " plugin loads and has valid metadata",         \
              "[plugins][descriptor][" plugin_name "]") {                                \
        auto ph = load_plugin(plugin_name);                                              \
        if (!ph) {                                                                       \
            WARN(plugin_name " plugin DLL/SO not found in build tree — skipping "        \
                 "descriptor test (build with -Dbuild_agent=true)");                     \
            SUCCEED();                                                                   \
            return;                                                                      \
        }                                                                                \
        const auto* d = ph.desc;                                                         \
        REQUIRE(d != nullptr);                                                           \
                                                                                         \
        SECTION("ABI version is valid") {                                                \
            CHECK(d->abi_version >= YUZU_PLUGIN_ABI_VERSION_MIN);                        \
            CHECK(d->abi_version <= YUZU_PLUGIN_ABI_VERSION);                            \
        }                                                                                \
                                                                                         \
        SECTION("name is non-null and matches expected") {                               \
            REQUIRE(d->name != nullptr);                                                 \
            CHECK(std::strlen(d->name) > 0);                                             \
            CHECK(std::string{d->name} == expected_name);                                \
        }                                                                                \
                                                                                         \
        SECTION("version is semver") {                                                   \
            REQUIRE(d->version != nullptr);                                              \
            CHECK(is_semver(d->version));                                                \
        }                                                                                \
                                                                                         \
        SECTION("description is non-null and non-empty") {                               \
            REQUIRE(d->description != nullptr);                                          \
            CHECK(std::strlen(d->description) > 0);                                      \
        }                                                                                \
                                                                                         \
        SECTION("actions array is valid and null-terminated") {                           \
            REQUIRE(d->actions != nullptr);                                              \
            int n = count_actions(d->actions);                                           \
            CHECK(n == expected_action_count);                                           \
        }                                                                                \
                                                                                         \
        SECTION("expected actions are present") {                                        \
            const char* expected[] = { __VA_ARGS__ };                                    \
            for (const char* act : expected) {                                           \
                CHECK(has_action(d->actions, act));                                      \
            }                                                                            \
        }                                                                                \
                                                                                         \
        SECTION("function pointers are non-null") {                                      \
            CHECK(d->init != nullptr);                                                   \
            CHECK(d->shutdown != nullptr);                                               \
            CHECK(d->execute != nullptr);                                                \
        }                                                                                \
    }

DESCRIPTOR_TEST("http_client", "http_client", 3, "download", "get", "head")
DESCRIPTOR_TEST("content_dist", "content_dist", 5, "stage", "execute_staged", "list_staged", "cleanup", "upload_file")
DESCRIPTOR_TEST("interaction", "interaction", 5, "notify", "message_box", "input", "survey", "set_dnd")
DESCRIPTOR_TEST("agent_logging", "agent_logging", 2, "get_log", "get_key_files")
DESCRIPTOR_TEST("storage", "storage", 5, "set", "get", "delete", "list", "clear")
DESCRIPTOR_TEST("registry", "registry", 9, "get_value", "set_value", "delete_value", "delete_key", "key_exists", "enumerate_keys", "enumerate_values", "get_user_value", "list_profiles")
DESCRIPTOR_TEST("wmi", "wmi", 2, "query", "get_instance")
DESCRIPTOR_TEST("rdp_control", "rdp_control", 2, "set_state", "status")
DESCRIPTOR_TEST("disk_actions", "disk_actions", 2, "smart", "volumes")
DESCRIPTOR_TEST("disk_space", "disk_space", 1, "free")
DESCRIPTOR_TEST("antivirus", "antivirus", 3, "products", "status", "av_exclusions")
DESCRIPTOR_TEST("firewall", "firewall", 2, "state", "rules")

// DESCRIPTOR_TEST has no per-plugin version parameter (shared across ~15
// plugins with unrelated version histories) -- a standalone case pins the
// version bump so a future revert of firewall_plugin.cpp's version()
// string is caught, not just observed once in a manual capture
// (code-review r1, FV-codex-05). The pinned value tracks the highest bump
// merged onto this plugin -- 0.5.0 for the macOS parity-residual work,
// then 0.6.0 once the nftables netlink hardening bump landed on top.
TEST_CASE("firewall: version reflects the parity-residual bump",
          "[plugins][descriptor][firewall]") {
    auto ph = load_plugin("firewall");
    if (!ph) {
        WARN("firewall plugin DLL/SO not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }
    REQUIRE(ph.desc != nullptr);
    REQUIRE(ph.desc->version != nullptr);
    CHECK(std::string_view(ph.desc->version) == "0.6.0");
}

DESCRIPTOR_TEST("windows_updates", "windows_updates", 4, "installed", "missing", "pending_reboot", "patch_connectivity")
DESCRIPTOR_TEST("sccm", "sccm", 2, "client_version", "site")
DESCRIPTOR_TEST("filesystem_posture", "filesystem_posture", 3, "mounts", "quotas", "snapshots")

// ============================================================================
// Section 2: URL validation (mirrors http_client anonymous namespace)
// ============================================================================

TEST_CASE("http_client: URL validation accepts http://",
          "[plugins][http_client][validation]") {
    CHECK(test_is_valid_url("http://example.com"));
    CHECK(test_is_valid_url("http://example.com/path"));
    CHECK(test_is_valid_url("http://example.com:8080/path"));
}

TEST_CASE("http_client: URL validation accepts https://",
          "[plugins][http_client][validation]") {
    CHECK(test_is_valid_url("https://example.com"));
    CHECK(test_is_valid_url("https://example.com/path?query=1"));
}

TEST_CASE("http_client: URL validation rejects non-HTTP schemes",
          "[plugins][http_client][validation]") {
    CHECK_FALSE(test_is_valid_url("ftp://evil.com"));
    CHECK_FALSE(test_is_valid_url("file:///etc/passwd"));
    CHECK_FALSE(test_is_valid_url("gopher://weird.com"));
    CHECK_FALSE(test_is_valid_url("javascript:alert(1)"));
    CHECK_FALSE(test_is_valid_url("data:text/html,<h1>Hi</h1>"));
}

TEST_CASE("http_client: URL validation rejects empty and garbage",
          "[plugins][http_client][validation]") {
    CHECK_FALSE(test_is_valid_url(""));
    CHECK_FALSE(test_is_valid_url("not-a-url"));
    CHECK_FALSE(test_is_valid_url("httpx://nope.com"));
    CHECK_FALSE(test_is_valid_url("ht tp://space.com"));
}

// ============================================================================
// Section 3: SSRF detection (ip_is_private logic)
//
// We cannot directly test hostname_resolves_to_private without network, but
// we can test the is_private_ipv4 logic by verifying the classification of
// well-known RFC 1918 / loopback / link-local ranges.
//
// These tests validate the same bit-arithmetic used in the plugin.
// ============================================================================

namespace {

/// Reproduce the is_private_ipv4 logic from http_client_plugin.cpp for testing
bool test_is_private_ipv4(uint32_t ip_host_order) {
    // 127.0.0.0/8
    if ((ip_host_order >> 24) == 127) return true;
    // 10.0.0.0/8
    if ((ip_host_order >> 24) == 10) return true;
    // 172.16.0.0/12
    if ((ip_host_order & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip_host_order & 0xFFFF0000) == 0xC0A80000) return true;
    // 169.254.0.0/16 (link-local)
    if ((ip_host_order & 0xFFFF0000) == 0xA9FE0000) return true;
    // 0.0.0.0
    if (ip_host_order == 0) return true;
    return false;
}

/// Build a host-order IPv4 from octets
constexpr uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
            static_cast<uint32_t>(d);
}

} // namespace

TEST_CASE("http_client: SSRF detects loopback addresses",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(127, 0, 0, 1)));
    CHECK(test_is_private_ipv4(ip4(127, 255, 255, 255)));
    CHECK(test_is_private_ipv4(ip4(127, 0, 0, 0)));
}

TEST_CASE("http_client: SSRF detects RFC 1918 10.0.0.0/8",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(10, 0, 0, 1)));
    CHECK(test_is_private_ipv4(ip4(10, 255, 255, 255)));
}

TEST_CASE("http_client: SSRF detects RFC 1918 172.16.0.0/12",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(172, 16, 0, 1)));
    CHECK(test_is_private_ipv4(ip4(172, 31, 255, 255)));
    // Just outside the range
    CHECK_FALSE(test_is_private_ipv4(ip4(172, 32, 0, 1)));
}

TEST_CASE("http_client: SSRF detects RFC 1918 192.168.0.0/16",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(192, 168, 0, 1)));
    CHECK(test_is_private_ipv4(ip4(192, 168, 255, 255)));
    CHECK(test_is_private_ipv4(ip4(192, 168, 1, 1)));
}

TEST_CASE("http_client: SSRF detects link-local 169.254.0.0/16",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(169, 254, 0, 1)));
    CHECK(test_is_private_ipv4(ip4(169, 254, 169, 254)));
}

TEST_CASE("http_client: SSRF detects 0.0.0.0",
          "[plugins][http_client][ssrf]") {
    CHECK(test_is_private_ipv4(ip4(0, 0, 0, 0)));
}

TEST_CASE("http_client: SSRF allows public addresses",
          "[plugins][http_client][ssrf]") {
    CHECK_FALSE(test_is_private_ipv4(ip4(8, 8, 8, 8)));       // Google DNS
    CHECK_FALSE(test_is_private_ipv4(ip4(1, 1, 1, 1)));       // Cloudflare
    CHECK_FALSE(test_is_private_ipv4(ip4(93, 184, 216, 34))); // example.com
    CHECK_FALSE(test_is_private_ipv4(ip4(203, 0, 113, 1)));   // TEST-NET-3
}

// ============================================================================
// Section 4: Filename validation (mirrors content_dist anonymous namespace)
// ============================================================================

TEST_CASE("content_dist: safe filename accepts valid names",
          "[plugins][content_dist][validation]") {
    CHECK(test_is_safe_filename("hello.txt"));
    CHECK(test_is_safe_filename("update-1.2.3.exe"));
    CHECK(test_is_safe_filename("script_v2.sh"));
    CHECK(test_is_safe_filename("UPPER.bin"));
    CHECK(test_is_safe_filename("a"));
}

TEST_CASE("content_dist: safe filename rejects path traversal",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_filename("../etc/passwd"));
    CHECK_FALSE(test_is_safe_filename("..\\windows\\system32"));
    CHECK_FALSE(test_is_safe_filename("foo/.."));
    CHECK_FALSE(test_is_safe_filename(".."));
}

TEST_CASE("content_dist: safe filename rejects shell metacharacters",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_filename("hello;rm -rf"));
    CHECK_FALSE(test_is_safe_filename("file name.txt"));  // space not allowed
    CHECK_FALSE(test_is_safe_filename("pipe|char"));
    CHECK_FALSE(test_is_safe_filename("dollar$var"));
    CHECK_FALSE(test_is_safe_filename("back`tick"));
}

TEST_CASE("content_dist: safe filename rejects empty string",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_filename(""));
}

TEST_CASE("content_dist: safe filename rejects path separators",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_filename("path/to/file"));
    CHECK_FALSE(test_is_safe_filename("path\\to\\file"));
}

// ============================================================================
// Section 5: Argument validation (mirrors content_dist anonymous namespace)
// ============================================================================

TEST_CASE("content_dist: safe arg accepts clean arguments",
          "[plugins][content_dist][validation]") {
    CHECK(test_is_safe_arg("--verbose"));
    CHECK(test_is_safe_arg("-o output.txt"));
    CHECK(test_is_safe_arg("--config=/etc/app.conf"));
    CHECK(test_is_safe_arg("simple"));
    CHECK(test_is_safe_arg("path/to/file.txt"));
    CHECK(test_is_safe_arg("C:\\Users\\test\\file.exe"));
}

TEST_CASE("content_dist: safe arg rejects command injection",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_arg("; rm -rf /"));
    CHECK_FALSE(test_is_safe_arg("$(whoami)"));
    CHECK_FALSE(test_is_safe_arg("hello`world`"));
    CHECK_FALSE(test_is_safe_arg("a & b"));
    CHECK_FALSE(test_is_safe_arg("a | b"));
    CHECK_FALSE(test_is_safe_arg("a > /dev/null"));
    CHECK_FALSE(test_is_safe_arg("a < input.txt"));
}

TEST_CASE("content_dist: safe arg rejects quotes and special chars",
          "[plugins][content_dist][validation]") {
    CHECK_FALSE(test_is_safe_arg("it's"));
    CHECK_FALSE(test_is_safe_arg("say \"hello\""));
    CHECK_FALSE(test_is_safe_arg("glob*.txt"));
    CHECK_FALSE(test_is_safe_arg("what?"));
    CHECK_FALSE(test_is_safe_arg("arr[0]"));
    CHECK_FALSE(test_is_safe_arg("{a,b}"));
}

TEST_CASE("content_dist: safe arg allows empty string (vacuously true)",
          "[plugins][content_dist][validation]") {
    // An empty arg has no bad chars
    CHECK(test_is_safe_arg(""));
}

// ============================================================================
// Section 6: WMI class name validation (mirrors wmi_plugin anonymous ns)
// ============================================================================

TEST_CASE("wmi: valid class names accepted",
          "[plugins][wmi][validation]") {
    CHECK(test_is_valid_wmi_class("Win32_OperatingSystem"));
    CHECK(test_is_valid_wmi_class("Win32_Process"));
    CHECK(test_is_valid_wmi_class("Win32_DiskDrive"));
    CHECK(test_is_valid_wmi_class("CIM_DataFile"));
    CHECK(test_is_valid_wmi_class("a"));
}

TEST_CASE("wmi: class names with injection rejected",
          "[plugins][wmi][validation]") {
    CHECK_FALSE(test_is_valid_wmi_class("Win32_Process; DROP TABLE"));
    CHECK_FALSE(test_is_valid_wmi_class("Win32_Process' OR 1=1 --"));
    CHECK_FALSE(test_is_valid_wmi_class("class name"));  // space
    CHECK_FALSE(test_is_valid_wmi_class("Win32-Process")); // hyphen
}

TEST_CASE("wmi: empty class name rejected",
          "[plugins][wmi][validation]") {
    CHECK_FALSE(test_is_valid_wmi_class(""));
}

TEST_CASE("wmi: overly long class name rejected",
          "[plugins][wmi][validation]") {
    std::string long_name(257, 'A');
    CHECK_FALSE(test_is_valid_wmi_class(long_name));
}

// ============================================================================
// Section 7: WMI namespace validation (mirrors wmi_plugin anonymous ns)
// ============================================================================

TEST_CASE("wmi: allowed namespaces accepted",
          "[plugins][wmi][validation]") {
    CHECK(test_is_valid_wmi_namespace("root\\cimv2"));
    CHECK(test_is_valid_wmi_namespace("root\\wmi"));
    CHECK(test_is_valid_wmi_namespace("root\\standardcimv2"));
}

TEST_CASE("wmi: namespace is case-insensitive",
          "[plugins][wmi][validation]") {
    CHECK(test_is_valid_wmi_namespace("ROOT\\CIMV2"));
    CHECK(test_is_valid_wmi_namespace("Root\\CimV2"));
    CHECK(test_is_valid_wmi_namespace("ROOT\\WMI"));
    CHECK(test_is_valid_wmi_namespace("Root\\StandardCimV2"));
}

TEST_CASE("wmi: dangerous namespaces rejected",
          "[plugins][wmi][validation]") {
    CHECK_FALSE(test_is_valid_wmi_namespace("root\\subscription"));
    CHECK_FALSE(test_is_valid_wmi_namespace("root\\default"));
    CHECK_FALSE(test_is_valid_wmi_namespace("root\\security"));
}

TEST_CASE("wmi: empty and garbage namespaces rejected",
          "[plugins][wmi][validation]") {
    CHECK_FALSE(test_is_valid_wmi_namespace(""));
    CHECK_FALSE(test_is_valid_wmi_namespace("not_a_namespace"));
    CHECK_FALSE(test_is_valid_wmi_namespace("root\\cimv2; DROP TABLE"));
}

// ============================================================================
// Section 7b: rdp_control state validation (mirrors rdp_control_plugin
// anonymous ns — keep in sync with is_valid_rdp_state)
// ============================================================================

namespace {

/// Mirror of rdp_control_plugin.cpp: is_valid_rdp_state
bool test_is_valid_rdp_state(std::string_view state) {
    return state == "enable" || state == "disable";
}

/// Mirror of rdp_control_plugin.cpp: derive_rdp_verdict — keep in sync.
/// "on" only when every gate is readable and open; "unknown" when any gate is
/// unreadable; "off" when all readable but at least one closed.
std::string_view test_derive_rdp_verdict(bool deny_known, bool deny_allows, bool fw_known,
                                         bool fw_enabled, bool svc_known, bool svc_running) {
    if (!deny_known || !fw_known || !svc_known)
        return "unknown";
    return (deny_allows && fw_enabled && svc_running) ? "on" : "off";
}

/// Mirror of rdp_control_plugin.cpp: classify_fw_hr — keep in sync. The HRESULT
/// constants are S_OK=0, S_FALSE=1 (we avoid <windows.h> in this TU). The
/// security-critical rule: S_FALSE (group absent) is NOT success — it must map
/// to "group_not_found", never be accepted as a confirmed read (H2).
enum class TestFwResult { Ok, GroupNotFound, Error };
TestFwResult test_classify_fw_hr(long hr) {
    if (hr == 0L) return TestFwResult::Ok;          // S_OK
    if (hr == 1L) return TestFwResult::GroupNotFound; // S_FALSE
    return TestFwResult::Error;
}

} // namespace

TEST_CASE("rdp_control: valid states accepted",
          "[plugins][rdp_control][validation]") {
    CHECK(test_is_valid_rdp_state("enable"));
    CHECK(test_is_valid_rdp_state("disable"));
}

TEST_CASE("rdp_control: invalid states rejected",
          "[plugins][rdp_control][validation]") {
    CHECK_FALSE(test_is_valid_rdp_state(""));
    CHECK_FALSE(test_is_valid_rdp_state("Enable"));   // case-sensitive
    CHECK_FALSE(test_is_valid_rdp_state("DISABLE"));
    CHECK_FALSE(test_is_valid_rdp_state("on"));
    CHECK_FALSE(test_is_valid_rdp_state("off"));
    CHECK_FALSE(test_is_valid_rdp_state("enable; rm -rf /"));
}

TEST_CASE("rdp_control: verdict is 'on' only when all gates readable and open",
          "[plugins][rdp_control][validation]") {
    // all readable + all open -> on
    CHECK(test_derive_rdp_verdict(true, true, true, true, true, true) == "on");
}

TEST_CASE("rdp_control: verdict is 'unknown' when any gate is unreadable",
          "[plugins][rdp_control][validation]") {
    // The security-relevant case: a failed read must NOT report "off"/safe.
    CHECK(test_derive_rdp_verdict(false, true, true, true, true, true) == "unknown");
    CHECK(test_derive_rdp_verdict(true, true, false, true, true, true) == "unknown");
    CHECK(test_derive_rdp_verdict(true, true, true, true, false, true) == "unknown");
    // unknown dominates even when the readable gates look closed
    CHECK(test_derive_rdp_verdict(false, false, true, false, true, false) == "unknown");
}

TEST_CASE("rdp_control: verdict is 'off' when all gates readable but one closed",
          "[plugins][rdp_control][validation]") {
    CHECK(test_derive_rdp_verdict(true, false, true, true, true, true) == "off");   // deny=1
    CHECK(test_derive_rdp_verdict(true, true, true, false, true, true) == "off");   // fw disabled
    CHECK(test_derive_rdp_verdict(true, true, true, true, true, false) == "off");   // svc not running
    CHECK(test_derive_rdp_verdict(true, false, true, false, true, false) == "off"); // all closed
}

TEST_CASE("rdp_control: S_FALSE firewall HRESULT is NOT success (H2 fail-safe)",
          "[plugins][rdp_control][validation]") {
    // S_OK is the only success; S_FALSE (group absent) must classify as
    // group_not_found so an enable is never a silent no-op reported ok and a
    // status read never derives "off" from an unreadable gate.
    CHECK(test_classify_fw_hr(0L) == TestFwResult::Ok);              // S_OK
    CHECK(test_classify_fw_hr(1L) == TestFwResult::GroupNotFound);   // S_FALSE
    CHECK(test_classify_fw_hr(static_cast<long>(0x80004005)) == TestFwResult::Error); // E_FAIL
    CHECK(test_classify_fw_hr(static_cast<long>(0x80070005)) == TestFwResult::Error); // E_ACCESSDENIED
    // The H2 inversion guard: a group-not-found firewall read feeds fw_known=false
    // into the verdict, which must yield "unknown", never "off".
    const bool fw_known = (test_classify_fw_hr(1L) == TestFwResult::Ok); // false
    CHECK(test_derive_rdp_verdict(true, true, fw_known, false, true, true) == "unknown");
}

// ============================================================================
// Section 8: Trigger engine — service name validation
//
// TriggerEngine::is_valid_service_name is a private static method, so we
// duplicate the logic here (same approach as test_trigger_engine.cpp).
// Must be kept in sync with trigger_engine.cpp.
// ============================================================================

namespace {

/// Mirror of TriggerEngine::is_valid_service_name for direct testing.
bool test_is_valid_service_name(const std::string& name) {
    if (name.empty() || name.size() > 256) return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '.' && c != '_' && c != '-' && c != '@') {
            return false;
        }
    }
    return true;
}

} // namespace

TEST_CASE("trigger engine: valid service names accepted",
          "[plugins][trigger][validation]") {
    CHECK(test_is_valid_service_name("sshd"));
    CHECK(test_is_valid_service_name("my-service_1.0"));
    CHECK(test_is_valid_service_name("nginx"));
    CHECK(test_is_valid_service_name("docker.service"));
    CHECK(test_is_valid_service_name("cups"));
    CHECK(test_is_valid_service_name("wuauserv"));
    CHECK(test_is_valid_service_name("com.apple.launchd"));
}

TEST_CASE("trigger engine: service names with injection rejected",
          "[plugins][trigger][validation]") {
    CHECK_FALSE(test_is_valid_service_name("sshd; rm -rf /"));
    CHECK_FALSE(test_is_valid_service_name("sshd && echo pwned"));
    CHECK_FALSE(test_is_valid_service_name("sshd | cat /etc/shadow"));
    CHECK_FALSE(test_is_valid_service_name("$(whoami)"));
    CHECK_FALSE(test_is_valid_service_name("test`id`"));
}

TEST_CASE("trigger engine: empty service name rejected",
          "[plugins][trigger][validation]") {
    CHECK_FALSE(test_is_valid_service_name(""));
}

TEST_CASE("trigger engine: overly long service name rejected",
          "[plugins][trigger][validation]") {
    std::string long_name(257, 'a');
    CHECK_FALSE(test_is_valid_service_name(long_name));
}

TEST_CASE("trigger engine: service name edge cases",
          "[plugins][trigger][validation]") {
    // Single character
    CHECK(test_is_valid_service_name("a"));
    // Dots and underscores (systemd style)
    CHECK(test_is_valid_service_name("some_service.1"));
    // @ is allowed for systemd template instances
    CHECK(test_is_valid_service_name("openvpn@client"));
    // Spaces are NOT allowed
    CHECK_FALSE(test_is_valid_service_name("bad service"));
}

// ============================================================================
// Section 9: Descriptor field cross-checks
//
// These tests verify structural invariants that should hold for ALL plugins.
// ============================================================================

TEST_CASE("all plugins: action strings are non-empty and unique",
          "[plugins][descriptor][invariants]") {
    // Build a list of plugin names to try loading
    std::vector<std::string> plugin_names = {
        "http_client", "content_dist", "interaction", "agent_logging",
        "storage", "registry", "wmi", "rdp_control"
    };

    for (const auto& name : plugin_names) {
        auto ph = load_plugin(name);
        if (!ph) continue; // Skip if not built

        const auto* d = ph.desc;
        REQUIRE(d != nullptr);
        REQUIRE(d->actions != nullptr);

        // Every action string should be non-null and non-empty
        std::vector<std::string> seen;
        for (int i = 0; d->actions[i] != nullptr; ++i) {
            REQUIRE(d->actions[i] != nullptr);
            CHECK(std::strlen(d->actions[i]) > 0);

            // Check uniqueness
            std::string act{d->actions[i]};
            CHECK(std::find(seen.begin(), seen.end(), act) == seen.end());
            seen.push_back(act);
        }
    }
}

TEST_CASE("all plugins: ABI version is exactly YUZU_PLUGIN_ABI_VERSION",
          "[plugins][descriptor][invariants]") {
    std::vector<std::string> plugin_names = {
        "http_client", "content_dist", "interaction", "agent_logging",
        "storage", "registry", "wmi", "rdp_control"
    };

    for (const auto& name : plugin_names) {
        auto ph = load_plugin(name);
        if (!ph) continue;

        // New plugins should always use the current ABI version
        CHECK(ph.desc->abi_version == YUZU_PLUGIN_ABI_VERSION);
    }
}
