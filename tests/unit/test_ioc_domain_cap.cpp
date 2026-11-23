/**
 * test_ioc_domain_cap.cpp -- F66: `ioc.check` refuses more than 100 `domains` per command (one
 * typed error row, rc 1, nothing checked) instead of doing unbounded per-domain work. Loads the
 * ACTUAL built ioc plugin and drives it through LocalDispatcher; the cap check precedes any OS
 * leg, so it runs on every host.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kExt = ".dylib";
#else
constexpr const char* kExt = ".so";
#endif

fs::path find_ioc_plugin() {
    const std::string lib = std::string{"ioc"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT")) // NOLINT(concurrency-mt-unsafe)
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "ioc" / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "ioc" / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "ioc" / lib);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "ioc" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::exists(c, ec) && !ec)
            return fs::absolute(c, ec);
    }
    return {};
}

std::string domains(std::size_t n) {
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        if (i)
            s += ',';
        s += "d" + std::to_string(i) + ".invalid";
    }
    return s;
}

} // namespace

TEST_CASE("ioc plugin: domains are capped at 100 per command", "[agent][ioc][domain_cap]") {
    const auto path = find_ioc_plugin();
    if (path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr) // NOLINT(concurrency-mt-unsafe)
            FAIL("ioc plugin library not found under meson test");
        WARN("ioc plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    const auto* d = handle->descriptor();
    REQUIRE(d != nullptr);
    yuzu::agent::LocalDispatcher dispatcher;

    {
        const std::string over = domains(101);
        const YuzuParam p[] = {{"domains", over.c_str()}};
        const auto r = dispatcher.run(d, "check", p);
        CHECK(r.rc == 1);
        CHECK(r.captured.find("error|domains|false|Too many domains (101, max 100)") !=
              std::string::npos);
        CHECK(r.captured.find("type|value|matched|detail") == std::string::npos);
    }
    {
        const std::string at = domains(100);
        const YuzuParam p[] = {{"domains", at.c_str()}};
        const auto r = dispatcher.run(d, "check", p);
        CHECK(r.rc == 0);
        CHECK(r.captured.find("Too many domains") == std::string::npos);
        CHECK(r.captured.find("domain|d99.invalid|") != std::string::npos);
    }
}
