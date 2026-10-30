/**
 * test_hardware_local_dispatcher.cpp -- loads the ACTUAL built hardware plugin via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally (the sibling posix-actions test is
 * `#if defined(__APPLE__)`). Assertions are row FAMILIES that hold on ANY host of the OS
 * (a CI VM without DMI or per-DIMM data is legitimate), never host values.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr const char* kPlanned = "windows:planned";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr const char* kPlanned = "macos:planned";
#else
constexpr const char* kPluginExt = ".so";
constexpr const char* kPlanned = "linux:planned";
#endif

constexpr const char* kPlannedActions[] = {"chassis", "baseboard", "swap", "machine_id"};

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Splits on '|'. The rows asserted on here carry only fixed tokens, so no escape handling.
std::vector<std::string> split_pipes(const std::string& row) {
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

// Under `meson test` a missing plugin means the build is broken -- never "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("hardware plugin library not found under meson test -- the plugin did not build, or "
             "link_depends does not order it before this test");
    WARN("hardware plugin library not found -- skipping (run from the build root)");
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_plugin() {
    const fs::path rel =
        fs::path{"agents"} / "plugins" / "hardware" / (std::string{"hardware"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT")) candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-windows", "build-linux"})
        candidates.push_back(fs::path{dir} / rel);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (!fs::exists(p, ec) || ec) continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(p, ec));
        if (!handle.has_value() || !handle->descriptor()) return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

const YuzuActionDescriptor* find_descriptor(const YuzuPluginDescriptor* d, std::string_view name) {
    for (std::size_t i = 0; i < d->action_descriptor_count; ++i)
        if (std::string_view{d->action_descriptors[i].action} == name)
            return &d->action_descriptors[i];
    return nullptr;
}

} // namespace

TEST_CASE("hardware plugin: the four estate actions are declared PLANNED on every leg",
          "[hardware][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    CHECK(plugin->descriptor->action_descriptor_count == 12);
    for (const char* name : kPlannedActions) {
        INFO("action: " << name);
        const auto* d = find_descriptor(plugin->descriptor, name);
        REQUIRE(d != nullptr);
        for (const auto* leg : {&d->linux_leg, &d->macos_leg, &d->windows_leg}) {
            CHECK(leg->support == YUZU_SUPPORT_PLANNED);
            CHECK(leg->rung == 1);
            CHECK(leg->mechanism != nullptr);
            CHECK(leg->fallback != nullptr);
        }
    }
    // The pre-existing reads keep their declared support.
    const auto* proc = find_descriptor(plugin->descriptor, "processors");
    REQUIRE(proc != nullptr);
    CHECK(proc->linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    const auto* mem = find_descriptor(plugin->descriptor, "memory");
    REQUIRE(mem != nullptr);
    CHECK(mem->linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(mem->macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
}

TEST_CASE("hardware plugin: the actions list names exactly the twelve actions",
          "[hardware][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    std::set<std::string> got;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a) got.insert(*a);
    const std::set<std::string> want{"manufacturer", "model",   "bios",      "processors",
                                     "memory",       "disks",   "drivers",   "system",
                                     "chassis",      "baseboard", "swap",    "machine_id"};
    CHECK(got == want);
}

TEST_CASE("hardware plugin: each estate action answers one typed planned status row",
          "[hardware][actions]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* name : kPlannedActions) {
        INFO("action: " << name);
        auto result = dispatcher.run(plugin->descriptor, name);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + name + "|unsupported|" + kPlanned);
        CHECK(rows[0].find("unknown") == std::string::npos);
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
        CHECK(result.result_provenance == kPlanned);
    }
}

TEST_CASE("hardware plugin: cpu and dimm rows carry the appended columns as '-'",
          "[hardware][actions]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;

    auto cpu = dispatcher.run(plugin->descriptor, "processors");
    CHECK(cpu.rc == 0);
    const auto cpu_rows = captured_rows(cpu.captured);
    REQUIRE_FALSE(cpu_rows.empty());
    for (const auto& r : cpu_rows) {
        INFO("cpu row: " << r);
        const auto f = split_pipes(r);
        REQUIRE(f.size() == 8);
        CHECK(f[0] == "cpu");
        CHECK(f[6] == "-");
        CHECK(f[7] == "-");
    }

    auto mem = dispatcher.run(plugin->descriptor, "memory");
    CHECK(mem.rc == 0);
    const auto mem_rows = captured_rows(mem.captured);
    REQUIRE_FALSE(mem_rows.empty());
    for (const auto& r : mem_rows) {
        INFO("dimm row: " << r);
        const auto f = split_pipes(r);
        REQUIRE(f.size() == 8);
        CHECK(f[0] == "dimm");
        CHECK(f[5] == "-");
        CHECK(f[6] == "-");
        CHECK(f[7] == "-");
    }
}

TEST_CASE("hardware plugin: an unknown action is refused with rc 1 and no status row",
          "[hardware][actions]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no|such\naction");
    CHECK(result.rc == 1);
    CHECK(result.captured.find("status|") == std::string::npos);
}
