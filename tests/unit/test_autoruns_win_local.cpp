/**
 * test_autoruns_win_local.cpp — Windows-leg-specific assertions for the
 * autoruns plugin (P12), loading the ACTUAL built plugin the same way
 * test_autoruns_local_dispatcher.cpp does.
 *
 * UNGUARDED on every platform (same precedent that file's own banner
 * documents): a `#ifndef _WIN32` exclusion here would be exactly how a
 * compiled-out Windows leg ships green with no test ever loading it. Every
 * assertion specific to the Windows row shapes lives under `#ifdef _WIN32`;
 * every other OS gets the same "the plugin loads and lists" smoke check
 * test_autoruns_local_dispatcher.cpp already runs, so a build that swaps
 * which OS leg compiles still has SOME coverage from this file.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "autoruns_catalog.hpp"
#include "autoruns_parsers.hpp"
#include "autoruns_win_wmi_join.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

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

#ifdef _WIN32
std::vector<std::string> fields_of(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}
#endif

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("autoruns plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_autoruns_plugin() {
    const std::string lib_name = std::string{"autoruns"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_autoruns_plugin() {
    auto path = find_autoruns_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

#ifdef _WIN32
const std::set<std::string> kWindowsSourceIds = {
    "win_run_hklm",       "win_runonce_hklm",         "win_runonceex_hklm",
    "win_run_hku",        "win_runonce_hku",          "win_startup_approved",
    "win_winlogon_shell", "win_winlogon_userinit",    "win_appinit_dlls",
    "win_ifeo_debugger",  "win_startup_folder_common", "win_startup_folder_user",
    "win_scheduled_tasks", "win_wmi_subscriptions",
};
#endif

} // namespace

TEST_CASE("autoruns plugin: loads and lists on this host", "[autoruns][windows][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    CHECK_FALSE(captured_rows(result.captured).empty());
}

#ifdef _WIN32

TEST_CASE("autoruns plugin windows leg: every win_* source is actually collected, not the "
          "foreign-os stub",
          "[autoruns][windows][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    std::set<std::string> seen_windows_status;
    for (const auto& row : captured_rows(result.captured)) {
        const auto f = fields_of(row);
        if (f.size() >= 3 && f[0] == "source" && kWindowsSourceIds.count(f[1])) {
            seen_windows_status.insert(f[1]);
            // The real leg reports supported/constrained; only the foreign-OS
            // stub (autoruns_legs.hpp) ever reports "unsupported" for a
            // Windows-native source, and this TU only loads on a Windows
            // build of the plugin.
            CHECK(f[2] != "unsupported");
        }
    }
    // Every Windows SourceId gets exactly one source| line -- none silently
    // dropped by this leg.
    CHECK(seen_windows_status.size() == kWindowsSourceIds.size());
}

TEST_CASE("autoruns plugin windows leg: scheduled tasks and WMI subscriptions never omitted",
          "[autoruns][windows][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    bool saw_tasks = false;
    bool saw_wmi = false;
    for (const auto& row : captured_rows(result.captured)) {
        const auto f = fields_of(row);
        if (f.size() >= 3 && f[0] == "source" && f[1] == "win_scheduled_tasks") saw_tasks = true;
        if (f.size() >= 3 && f[0] == "source" && f[1] == "win_wmi_subscriptions") saw_wmi = true;
    }
    CHECK(saw_tasks);
    CHECK(saw_wmi);
}

#endif // _WIN32

// ── autoruns_win_wmi_join.hpp: OS-independent join tests (P12 respec delta 1) ──
//
// The join helper is plain C++ with zero Windows dependency, so these run on
// every OS, exercising the same real capture the leg itself parses on
// Windows: tests/unit/fixtures/wave7/autoruns/windows/subscription_triple.txt
// (A1, 2026-09-06; FilterCount=1 ConsumerCount=1 BindingCount=1).

namespace {

/// Splits `Key : Value` blocks separated by blank lines into ordered maps --
/// a local, test-only re-implementation of the same block grammar
/// parse_wmi_subscription_triple uses, kept separate so this test exercises
/// the join against genuinely independent parsing rather than reusing that
/// parser's own internals.
std::vector<std::map<std::string, std::string>> parse_kv_blocks(std::string_view text) {
    auto trimmed = [](std::string_view s) -> std::string {
        const std::size_t b = s.find_first_not_of(" \t");
        if (b == std::string_view::npos) return {};
        const std::size_t e = s.find_last_not_of(" \t");
        return std::string{s.substr(b, e - b + 1)};
    };
    std::vector<std::map<std::string, std::string>> blocks;
    std::map<std::string, std::string> current;
    std::size_t pos = 0;
    auto flush = [&] {
        if (!current.empty()) blocks.push_back(current);
        current.clear();
    };
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        std::string_view line =
            nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (trimmed(line).empty()) {
            flush();
        } else {
            const std::size_t colon = line.find(':');
            if (colon != std::string_view::npos) {
                const std::string key = trimmed(line.substr(0, colon));
                const std::string val = trimmed(line.substr(colon + 1));
                if (!key.empty()) current[key] = val;
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    flush();
    return blocks;
}

struct WmiFixtureBlocks {
    std::vector<yuzu::autoruns::WmiJoinRow> filters, consumers, bindings;
};

/// Loads A1's real capture and classifies its three blocks by CimClass,
/// same routing order parse_wmi_subscription_triple documents (EventFilter,
/// then Binding, then generic Consumer). REQUIREs existence -- never SKIPs
/// on a missing fixture, per this repo's fixture-coverage convention.
WmiFixtureBlocks load_a1_wmi_fixture() {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "autoruns" / "windows" /
                        "subscription_triple.txt";
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();

    WmiFixtureBlocks out;
    for (const auto& block : parse_kv_blocks(ss.str())) {
        const auto it = block.find("CimClass");
        const std::string cls = it != block.end() ? it->second : std::string{};
        if (cls.find("__EventFilter") != std::string::npos) out.filters.push_back(block);
        else if (cls.find("__FilterToConsumerBinding") != std::string::npos)
            out.bindings.push_back(block);
        else
            out.consumers.push_back(block);
    }
    return out;
}

std::string block_text(const yuzu::autoruns::WmiJoinRow& row) {
    std::string out;
    for (const auto& [k, v] : row) {
        out += k;
        out += " : ";
        out += v;
        out += '\n';
    }
    out += '\n';
    return out;
}

} // namespace

TEST_CASE("autoruns wmi join: wmi_ref_name extracts the quoted CIM reference name",
          "[autoruns][wmi_join]") {
    using yuzu::autoruns::wmi_ref_name;
    // The COM object path run_bounded_wmi_query's variant_to_string produces
    // for a live CIM_REFERENCE (VT_BSTR).
    CHECK(wmi_ref_name(R"(__EventFilter.Name="SCM Event Log Filter")") == "SCM Event Log Filter");
    // A1's PowerShell Format-List capture shape.
    CHECK(wmi_ref_name(R"(__EventFilter (Name = "SCM Event Log Filter"))") ==
          "SCM Event Log Filter");
    CHECK(wmi_ref_name("no quotes here") == "");
}

TEST_CASE("autoruns wmi join: joins the real A1 subscription_triple fixture",
          "[autoruns][wmi_join]") {
    const auto fixture = load_a1_wmi_fixture();
    REQUIRE(fixture.filters.size() == 1);
    REQUIRE(fixture.consumers.size() == 1);
    REQUIRE(fixture.bindings.size() == 1);

    const auto joined =
        yuzu::autoruns::join_wmi_bindings(fixture.filters, fixture.consumers, fixture.bindings);
    REQUIRE(joined.size() == 1);
    CHECK(joined[0].filter_matched);
    CHECK(joined[0].consumer_matched);

    // Feed the joined rows back through format-equivalent text into the
    // real parser -- proves the join resolved the actual matching rows the
    // parser needs, not merely rows present somewhere in the fixture.
    const std::string reformatted =
        block_text(joined[0].filter) + block_text(joined[0].consumer) + block_text(joined[0].binding);
    const auto triple = yuzu::autoruns::parse_wmi_subscription_triple(reformatted);
    CHECK(triple.filter_name == "SCM Event Log Filter");
}

TEST_CASE("autoruns wmi join: N bindings never collapse to one row",
          "[autoruns][wmi_join]") {
    const auto fixture = load_a1_wmi_fixture();
    REQUIRE(fixture.bindings.size() == 1);

    // Derived from the real capture by changing one ref: this tests the
    // join, not the OS output format. The second binding's Filter ref names
    // a filter that was never enumerated.
    auto dangling_binding = fixture.bindings[0];
    dangling_binding["Filter"] = R"(__EventFilter (Name = "Nonexistent Filter"))";

    const std::vector<yuzu::autoruns::WmiJoinRow> bindings = {fixture.bindings[0], dangling_binding};
    const auto joined = yuzu::autoruns::join_wmi_bindings(fixture.filters, fixture.consumers, bindings);
    REQUIRE(joined.size() == 2);
    CHECK(joined[0].filter_matched);
    CHECK_FALSE(joined[1].filter_matched);
}
