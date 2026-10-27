/**
 * test_shares_local_dispatcher.cpp -- loads the ACTUAL built shares plugin via
 * PluginHandle::load and drives `list` through yuzu::agent::LocalDispatcher, so the real
 * per-OS leg executes on the build host. Modelled on test_mgmt_posture_local_dispatcher.cpp.
 *
 * UNGUARDED TU on all three platforms; only the per-OS assertions inside a test body are
 * #if'd. The live-host cases assert shape (status row first, fixed source rows, value
 * vocabularies), never host-specific values: which shares a CI runner serves is unknown.
 * The fault-injection cases live in test_shares_legs.cpp; the [seam] cases here pin
 * execute_list and the status/result pairing without loading the plugin.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "shares_legs.hpp" // execute_list / report_list

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
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

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("shares plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("shares plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_plugin() {
    const std::string lib_name = std::string{"shares"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "shares" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "shares" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "shares" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "shares" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_plugin() {
    auto path = find_plugin();
    if (path.empty())
        return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded)
        return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d)
        return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

/// Seam probes: execute_list over legs that throw / report a refused read.
int throwing_leg(yuzu::CommandContext&) { throw std::runtime_error("probe: the leg threw"); }

int denied_leg(yuzu::CommandContext& ctx) {
    yuzu::shares::report_list(ctx, {}, yuzu::shares::StatusState::permission_denied,
                              "linux:shares:exports:permission_denied");
    return 0;
}

/// Writes its status row, THEN throws while "emitting data": the catch arm appends a second.
int row_then_throw_leg(yuzu::CommandContext& ctx) {
    yuzu::shares::report_list(ctx, {"source|exports|absent|-"}, yuzu::shares::StatusState::supported, "");
    throw std::runtime_error("probe: threw after the status row");
}

template <yuzu::shares::LegFn Leg>
int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::shares::execute_list(ctx, action, Leg, "linux:leg:exception");
}

#if !defined(__APPLE__) // the macOS placeholder emits no share rows
bool share_row_is_wellformed(const std::string& row) {
    std::size_t pipes = 0;
    for (std::size_t i = 0; i < row.size(); ++i)
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\'))
            ++pipes;
    if (pipes != 7) // 8 fields
        return false;
    if (yuzu::shared::count_invalid_wire_bytes(row) != 0 || row.find('\0') != std::string::npos)
        return false;
    std::vector<std::string> f;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\')) {
            f.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    f.push_back(cur);
    const auto in = [](const std::string& v, std::initializer_list<const char*> set) {
        return std::ranges::any_of(set, [&](const char* s) { return v == s; });
    };
    return f[0] == "share" && in(f[1], {"nfs", "smb"}) && in(f[4], {"ro", "rw", "mixed", "-"}) &&
           in(f[5], {"true", "false", "-"}) && in(f[7], {"exports", "exports_d", "smb_conf", "netshareenum"});
}
#endif

} // namespace

// MUTATION: flip a leg's declared support without changing the code behind it (macOS to
// SUPPORTED while it is still the placeholder, Linux or Windows to PLANNED) -> the exact-level
// checks fail. The mechanism/notes prose is not pinned: the capability-matrix check gates it.
TEST_CASE("shares plugin: the descriptor declares Linux and Windows supported and macOS planned",
          "[shares][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    CHECK(std::string_view{plugin->descriptor->name} == "shares");
    CHECK(std::string_view{plugin->descriptor->version} == "1.0.0");
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    REQUIRE(plugin->descriptor->action_descriptor_count == 1);
    const auto& d = plugin->descriptor->action_descriptors[0];
    CHECK(std::string_view{d.action} == "list");
    CHECK(d.linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d.linux_leg.rung == 1);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_PLANNED);
    CHECK(d.macos_leg.rung == 2);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d.windows_leg.rung == 1);
}

TEST_CASE("shares plugin: an unknown action is refused with one non-status line",
          "[shares][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

TEST_CASE("shares plugin: status row first, source rows next, then well-formed share rows",
          "[shares][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    INFO("status row: " << rows[0]);
    REQUIRE(starts_with(rows[0], "status|list|"));

    // The paired result status follows the status row's state.
    if (starts_with(rows[0], "status|list|supported|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else if (starts_with(rows[0], "status|list|constrained|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else if (starts_with(rows[0], "status|list|permission_denied|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else {
        REQUIRE(starts_with(rows[0], "status|list|unsupported|"));
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    }

#if defined(__APPLE__)
    // PLANNED leg (macOS): exactly one row and UNAVAILABLE/UNKNOWN.
    // MUTATION: wiring any read here changes this row.
    constexpr const char* kPlanned = "macos:planned";
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == std::string{"status|list|unsupported|"} + kPlanned);
    CHECK(result.result_provenance == kPlanned);
#elif defined(_WIN32)
    // NetShareEnum leg: status row, then one source row on every arm.
    REQUIRE(rows.size() >= 2);
    CHECK(starts_with(rows[1], "source|netshareenum|"));
    if (starts_with(rows[0], "status|list|unsupported|")) { // stopped Server service: no shares
        INFO("status row: " << rows[0]);
        CHECK(starts_with(rows[0], "status|list|unsupported|windows:shares:netshareenum:server_"));
        CHECK(rows.size() == 2);
        return;
    }
    bool saw_ipc = false;
    for (std::size_t i = 2; i < rows.size(); ++i) {
        INFO("row " << i << ": " << rows[i]);
        REQUIRE(share_row_is_wellformed(rows[i]));
        CHECK(rows[i].starts_with("share|smb|"));
        CHECK(rows[i].ends_with("|netshareenum"));
        if (rows[i].find("|IPC$|") != std::string::npos) {
            saw_ipc = true;
            CHECK(rows[i].find("|ipc,special|") != std::string::npos);
        }
    }
    // A running Server service always publishes IPC$; a constrained or permission_denied
    // answer (status_<n>, no_progress, a budget cut) need not retain it.
    if (starts_with(rows[0], "status|list|supported|"))
        CHECK(saw_ipc);
#else
    REQUIRE(rows.size() >= 4);
    CHECK(starts_with(rows[1], "source|exports|"));
    CHECK(starts_with(rows[2], "source|exports_d|"));
    CHECK(starts_with(rows[3], "source|smb_conf|"));
    constexpr std::size_t kSources = 3;
    for (std::size_t i = 1; i < rows.size(); ++i) {
        INFO("row " << i << ": " << rows[i]);
        if (i <= kSources)
            CHECK(starts_with(rows[i], "source|"));
        else
            CHECK(share_row_is_wellformed(rows[i]));
    }
#endif
}

TEST_CASE("shares execute seam: unknown action is escaped; a throwing leg is contained; a "
          "refused read pairs PERMISSION_DENIED with PARTIAL",
          "[shares][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;

    YuzuPluginDescriptor throwing{};
    throwing.execute = &seam_execute<&throwing_leg>;

    const auto thrown = dispatcher.run(&throwing, "list");
    CHECK(thrown.rc == 0); // contained, never unwound
    const auto trows = captured_rows(thrown.captured);
    REQUIRE(trows.size() == 1);
    CHECK(trows[0] == "status|list|unsupported|linux:leg:exception");
    CHECK(thrown.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(thrown.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(thrown.result_provenance == "linux:leg:exception");

    // The request-supplied name goes through safe_output_field: a pipe and a trailing
    // backslash can neither open a second field nor swallow a delimiter.
    const auto hostile = dispatcher.run(&throwing, "no|such\\");
    CHECK(hostile.rc == 1);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");

    // Invalid UTF-8 bytes are replaced first (scrub_wire_bytes, which also rejects overlong
    // and surrogate forms); a valid sequence survives.
    const auto binary = dispatcher.run(&throwing, "bad\xff!");
    CHECK(binary.rc == 1);
    const auto brows = captured_rows(binary.captured);
    REQUIRE(brows.size() == 1);
    CHECK(brows[0] == "unknown action: bad?!");
    const auto accented = dispatcher.run(&throwing, "caf\xc3\xa9");
    const auto arows = captured_rows(accented.captured);
    REQUIRE(arows.size() == 1);
    CHECK(arows[0] == "unknown action: caf\xc3\xa9");

    YuzuPluginDescriptor denied{};
    denied.execute = &seam_execute<&denied_leg>;
    const auto d = dispatcher.run(&denied, "list");
    CHECK(d.rc == 0);
    const auto drows = captured_rows(d.captured);
    REQUIRE(drows.size() == 1);
    CHECK(drows[0] == "status|list|permission_denied|linux:shares:exports:permission_denied");
    CHECK(d.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(d.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(d.result_provenance == "linux:shares:exports:permission_denied");

    // A leg that wrote its status row and then threw: two status rows, the LAST wins.
    YuzuPluginDescriptor late{};
    late.execute = &seam_execute<&row_then_throw_leg>;
    const auto l = dispatcher.run(&late, "list");
    CHECK(l.rc == 0);
    const auto lrows = captured_rows(l.captured);
    REQUIRE(lrows.size() == 3);
    CHECK(lrows[0] == "status|list|supported|-");
    CHECK(lrows[2] == "status|list|unsupported|linux:leg:exception");
    CHECK(l.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
}
