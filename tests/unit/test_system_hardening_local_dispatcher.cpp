/**
 * test_system_hardening_local_dispatcher.cpp -- loads the ACTUAL built
 * system_hardening plugin (system_hardening.dylib / .so / .dll) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher, so
 * the real per-OS leg runs on the build host (the peripherals/disk_actions
 * dispatcher-test shape).
 *
 * RUNS ON ALL THREE PLATFORMS -- no platform guard on the TU (a guarded
 * dispatcher TU once hid a never-loaded plugin). Only the two host-specific
 * assertions consult a constexpr: on Linux/macOS the leg reads an allowlist
 * and must emit exactly one row per allowlisted key; the Windows leg emits one
 * row per decoded policy (a host-dependent count), so there only the row
 * grammar and the status/token contract are asserted. The Windows leg's
 * <state> vocabulary is {on, off, default, unmodelled, absent, unreadable} by
 * design (a tri-state override, not a hardening level), so the row-grammar
 * check keys the accepted set on the host. There is no host-specific VALUE
 * assertion anywhere: CI runners are shared and unknown-hardware, and an
 * absent key (no Yama on a Docker kernel, no MitigationOptions on a default
 * Windows install) is a legitimate, modal host answer: it adds no failure
 * token and does not lower the status.
 * Only an UNREADABLE key is a failure. The status test below holds on every
 * host, Windows included, because that contract is the same on all three legs.
 *
 * The exercise_emit_* cases need no plugin load and no OS call: a synthetic
 * descriptor drives emit_posture (the Linux and macOS status writer) through
 * LocalDispatcher on every OS, so the rows-to-status wiring is proven even on
 * a host whose real leg only ever reads values.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "system_hardening_legs.hpp"
#include "system_hardening_parsers.hpp"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::system_hardening;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr bool kAllowlistLeg = false;
constexpr std::size_t kExpectedRows = 0; // unused: Windows rows are per decoded policy, not per allowlisted key
constexpr std::string_view kExpectedOs = "windows";
// Mirrors the Windows leg's ROW contract (the ROW comment in system_hardening_win_parsers.hpp):
// a tri-state override, not a hardening level. If that vocabulary changes this test fails on
// Windows CI, which is the guard.
constexpr std::array<std::string_view, 6> kHostStateTokens{"on",         "off",    "default",
                                                            "unmodelled", "absent", "unreadable"};
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr bool kAllowlistLeg = true;
const std::size_t kExpectedRows = kMacosAllowlist.size();
constexpr std::string_view kExpectedOs = "macos";
const auto& kHostStateTokens = kStateTokens;
#else
constexpr const char* kPluginExt = ".so";
constexpr bool kAllowlistLeg = true;
const std::size_t kExpectedRows = kLinuxAllowlist.size();
constexpr std::string_view kExpectedOs = "linux";
const auto& kHostStateTokens = kStateTokens;
#endif

/// Escape-aware field split: safe_output_field escapes a literal '|' as '\|'.
std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv, as in every sibling *_local_dispatcher.cpp
#endif
/// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("system_hardening plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    WARN("system_hardening plugin library not found -- skipping the LocalDispatcher round-trip");
}

fs::path find_plugin() {
    const std::string lib = std::string{"system_hardening"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "system_hardening" / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "system_hardening" / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "system_hardening" / lib);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "system_hardening" / lib);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
};

std::optional<LoadedPlugin> load_plugin() {
    const auto path = find_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

bool is_state_token(const std::string& s) {
    for (const auto t : kHostStateTokens)
        if (t == s) return true;
    return false;
}

/// The status reason is the comma-joined `<key>:<cause>` failure tokens.
std::vector<std::string> split_tokens(const std::string& reason) {
    std::vector<std::string> out;
    std::istringstream ss(reason);
    std::string tok;
    while (std::getline(ss, tok, ','))
        if (!tok.empty()) out.push_back(tok);
    return out;
}

bool has_token_for(const std::vector<std::string>& tokens, const std::string& key) {
    for (const auto& t : tokens)
        if (t.rfind(key + ":", 0) == 0) return true;
    return false;
}

// Synthetic-descriptor callbacks: each builds rows + accumulator purely and hands them to
// emit_posture. Nothing here reads /proc, calls sysctlbyname or touches the registry.
int exercise_emit_mixed(YuzuCommandContext* raw, const char* /*action*/,
                        const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PostureRow> rows;
    rows.push_back({"linux", "kernel.sysrq", "0", PostureState::enabled});
    rows.push_back(failed_row("linux", "kernel.kptr_restrict", EIO, acc));
    emit_posture(ctx, rows, acc);
    return 0;
}

int exercise_emit_absent_only(YuzuCommandContext* raw, const char* /*action*/,
                              const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PostureRow> rows;
    rows.push_back({"linux", "kernel.sysrq", "0", PostureState::enabled});
    rows.push_back(failed_row("linux", "kernel.yama.ptrace_scope", ENOENT, acc));
    emit_posture(ctx, rows, acc);
    return 0;
}

int exercise_emit_denied(YuzuCommandContext* raw, const char* /*action*/,
                         const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PostureRow> rows;
    rows.push_back(failed_row("macos", "kern.coredump", EPERM, acc));
    emit_posture(ctx, rows, acc);
    return 0;
}

} // namespace

TEST_CASE("system_hardening emit_posture: a mixed value + unreadable run is CONSTRAINED/PARTIAL "
          "with the failed key's token",
          "[system_hardening][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_emit_mixed;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(&descriptor, "probe");
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          std::vector<std::string>{"posture|linux|kernel.sysrq|0|enabled",
                                   "posture|linux|kernel.kptr_restrict|-|unreadable"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "kernel.kptr_restrict:errno_" + std::to_string(EIO));
}

TEST_CASE("system_hardening emit_posture: a value + absent run is OK/FULL with no provenance",
          "[system_hardening][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_emit_absent_only;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(&descriptor, "probe");
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          std::vector<std::string>{"posture|linux|kernel.sysrq|0|enabled",
                                   "posture|linux|kernel.yama.ptrace_scope|-|absent"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(r.result_provenance.empty());
}

TEST_CASE("system_hardening emit_posture: a refused read is PERMISSION_DENIED/PARTIAL, not "
          "CONSTRAINED",
          "[system_hardening][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_emit_denied;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(&descriptor, "probe");
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          std::vector<std::string>{"posture|macos|kern.coredump|-|unreadable"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(r.result_status != YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "kern.coredump:eacces");
}

TEST_CASE("system_hardening plugin: every row is posture|os|key|raw|state with a known state",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "posture");
    CHECK(result.rc == 0); // a missing or unreadable key is a degraded read, never a failed command
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        INFO("row: " << r);
        const auto f = split_fields(r);
        REQUIRE(f.size() == 5);
        CHECK(f[0] == "posture");
        CHECK(f[1] == kExpectedOs);
        CHECK_FALSE(f[2].empty());
        CHECK(is_state_token(f[4]));
        // "-" means "nothing was read": exactly the absent/unreadable rows.
        const bool no_value = (f[4] == "absent" || f[4] == "unreadable");
        CHECK((f[3] == "-") == no_value);
    }
}

TEST_CASE("system_hardening plugin: one row per allowlisted key, in allowlist order (Linux/macOS)",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    if (!kAllowlistLeg) SKIP("allowlist order applies to the Linux/macOS legs; Windows rows are shape-checked above");
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "posture").captured);
    // Rows are emitted for absent/unreadable keys too, so the count is host-independent.
    REQUIRE(rows.size() == kExpectedRows);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        [[maybe_unused]] const auto f = split_fields(rows[i]);
#if defined(__APPLE__)
        CHECK(f[2] == kMacosAllowlist[i].name);
#elif !defined(_WIN32)
        CHECK(f[2] == kLinuxAllowlist[i].key);
#endif
    }
}

TEST_CASE("system_hardening plugin: the typed status agrees with the rows; only an unreadable key is a failure",
          "[system_hardening][status]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "posture");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    std::vector<std::vector<std::string>> unreadable;
    std::vector<std::vector<std::string>> absent;
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        if (f.size() != 5) continue;
        if (f[4] == "unreadable") unreadable.push_back(f);
        else if (f[4] == "absent") absent.push_back(f);
    }
    const bool is_ok = result.result_status == YUZU_RESULT_STATUS_OK;
    const bool is_constrained = result.result_status == YUZU_RESULT_STATUS_CONSTRAINED;
    // Any leg reports PERMISSION_DENIED when a read was refused (EACCES/EPERM,
    // ERROR_ACCESS_DENIED).
    const bool is_denied = result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED;
    REQUIRE((is_ok || is_constrained || is_denied));
    const auto tokens = split_tokens(result.result_provenance);
    if (is_ok) {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(tokens.empty());
    } else {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK_FALSE(result.result_provenance.empty());
    }
    // OK exactly when no key was unreadable -- no silent OK, no phantom failure. An absent key
    // (no Yama on a Docker kernel, no MitigationOptions on a default Windows install) does NOT
    // lower the status. The one exception is the Linux backstop: every key `absent` on a
    // confirmed procfs is CONSTRAINED with provenance exactly `proc_sys:not_visible` and no
    // unreadable row.
    const bool canary = is_constrained && result.result_provenance == "proc_sys:not_visible";
    if (canary) {
        CHECK(kExpectedOs == "linux");
        CHECK(unreadable.empty());
        CHECK(absent.size() == rows.size());
    } else {
        CHECK(is_ok == unreadable.empty());
    }
    // An unreadable key is named by a `<key>:<cause>` token; an absent key has none (the backstop
    // token names `proc_sys`, not a key).
    for (const auto& f : unreadable) {
        INFO("unreadable key: " << f[2]);
        CHECK(has_token_for(tokens, f[2]));
    }
    for (const auto& f : absent) {
        INFO("absent key: " << f[2]);
        CHECK_FALSE(has_token_for(tokens, f[2]));
    }
    // The retired absence tokens must never come back.
    for (const auto& t : tokens) {
        INFO("token: " << t);
        CHECK(t.find(":enoent") == std::string::npos);
        CHECK(t.find(":not_found") == std::string::npos);
        CHECK(t.find(":unsupported") == std::string::npos);
    }
}

TEST_CASE("system_hardening plugin: an unknown action is refused, not silently ignored",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(r.rc != 0);
    CHECK(captured_rows(r.captured) == std::vector<std::string>{"unknown action: no_such_action"});
    // The action name is request-supplied text in a pipe-delimited stream: safe_output_field
    // folds a newline to a space and escapes the pipe.
    const auto escaped = dispatcher.run(plugin->descriptor, "no|such\naction");
    CHECK(captured_rows(escaped.captured) ==
          std::vector<std::string>{"unknown action: no\\|such action"});
}
