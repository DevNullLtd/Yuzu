/**
 * test_tags_concurrency.cpp -- F37: the tags plugin's process-global tag map is guarded by a
 * mutex, so concurrent dispatch-pool commands cannot rehash/free it under each other. Loads the
 * ACTUAL built tags plugin and drives set/get_all/delete/clear/count from several threads through
 * LocalDispatcher (synchronous, in the calling thread -- the same shape as the agent's pool).
 * The assertion is that nothing crashes and the final state is coherent; the real proof is
 * ThreadSanitizer, which reports the unguarded map as a data race on the old code ([tsan] tag).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
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

fs::path find_tags_plugin() {
    const std::string lib = std::string{"tags"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "tags" / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "tags" / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "tags" / lib);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "tags" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::exists(c, ec) && !ec)
            return fs::absolute(c, ec);
    }
    return {};
}

} // namespace

TEST_CASE("tags plugin: concurrent set/get_all/delete/clear/count stay coherent",
          "[agent][tags_plugin][tsan]") {
    const auto path = find_tags_plugin();
    if (path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("tags plugin library not found under meson test");
        WARN("tags plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    const auto* d = handle->descriptor();
    REQUIRE(d != nullptr);

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 6; ++t) {
        threads.emplace_back([&, t] {
            yuzu::agent::LocalDispatcher dispatcher;
            for (int i = 0; i < 150; ++i) {
                const std::string key = "k" + std::to_string((t * 31 + i) % 40);
                const std::string val = "v" + std::to_string(i);
                const YuzuParam kv[] = {{"key", key.c_str()}, {"value", val.c_str()}};
                const YuzuParam k_only[] = {{"key", key.c_str()}};
                switch ((t + i) % 5) {
                case 0:
                    if (dispatcher.run(d, "set", kv).rc != 0) ++failures;
                    break;
                case 1:
                    if (dispatcher.run(d, "get_all").rc != 0) ++failures;
                    break;
                case 2:
                    if (dispatcher.run(d, "delete", k_only).rc != 0) ++failures;
                    break;
                case 3:
                    if (dispatcher.run(d, "count").rc != 0) ++failures;
                    break;
                default:
                    if (i % 25 == 0) {
                        if (dispatcher.run(d, "clear").rc != 0) ++failures;
                    } else if (dispatcher.run(d, "get", k_only).rc != 0) {
                        ++failures;
                    }
                }
            }
        });
    }
    for (auto& th : threads)
        th.join();
    CHECK(failures.load() == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    REQUIRE(dispatcher.run(d, "clear").rc == 0);
    const auto count = dispatcher.run(d, "count");
    CHECK(count.captured.find("count|0") != std::string::npos);
}
