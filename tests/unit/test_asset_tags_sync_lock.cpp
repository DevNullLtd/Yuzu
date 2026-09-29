/**
 * test_asset_tags_sync_lock.cpp -- TU-inclusion seam over
 * asset_tags_plugin.cpp (#232, code-review F-codex-2): proves the S21 fix --
 * `sync` writes the state file while STILL holding the plugin's state mutex
 * -- without a production test hook and without a timing assumption.
 *
 * Adversarial-review round 1 (finding F1) made the real persistence
 * function's temp name random and unpredictable, which retires the FIFO/
 * PIPE_BUF handshake this file used to rely on (it depended on a fixed,
 * guessable `<dest>.tmp` name). The replacement is a TU-inclusion seam that
 * stands in for `write_state_file_atomic` at its one call site
 * (asset_tags_plugin.cpp:223) only:
 *
 *   1. `asset_tags_store.hpp` is included directly first, so its `#pragma
 *      once` means the include INSIDE asset_tags_plugin.cpp (below) is a
 *      no-op and the real function's own definition is never touched by the
 *      macro in step 2.
 *   2. `write_state_file_atomic` is `#define`d to a local seam function
 *      immediately before `#include "asset_tags_plugin.cpp"`, and `#undef`d
 *      right after -- the preprocessor only rewrites the token at the one
 *      live call site inside that file.
 *   3. The seam records the bytes it was asked to persist, flags "inside
 *      persist" (a condition variable, never a clock or a sleep), waits for
 *      the main thread's release signal, then calls the REAL
 *      `yuzu::asset_tags::write_state_file_atomic` so the observable outcome
 *      (file on disk, the returned WriteWarning/IoError) is unchanged.
 *
 * The main thread waits for EITHER "inside persist" OR "dispatch finished"
 * (the writer thread sets the latter once `dispatcher.run` returns) -- so a
 * regression that stops persisting under the lock FAILS the case instead of
 * hanging the suite. While parked inside the seam, `g_mu.try_lock()` must
 * fail (this is what kills the review's M2 mutant: moving the persist call
 * outside the lock would let it succeed). No fds, no pipes, no PIPE_BUF
 * reasoning, no per-OS mechanism -- the case now runs on all three legs.
 *
 * TU-inclusion precedent: test_execution_artifacts_win_internals.cpp (#4392)
 * and autoruns_macos.cpp's seam. The plugin's C export is renamed away so
 * this executable does not define `yuzu_plugin_descriptor`; the in-TU
 * instance is driven through the real LocalDispatcher via a hand-built
 * descriptor, so execute() runs against a genuine CommandContext.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

// Real definitions first (pragma once keeps them real inside the plugin.cpp
// include below, which the macro right after this never gets to touch).
#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"

#include <condition_variable>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace {

// Standing in for write_state_file_atomic at exactly the do_sync() call site
// below (macro-substituted). Guarded by its own mutex/cv, never the plugin's
// g_mu -- the whole point is to observe g_mu from the OUTSIDE while this is
// parked.
std::mutex g_seam_mu;
std::condition_variable g_seam_cv;
bool g_seam_inside = false;        // set once the seam is about to persist
bool g_seam_proceed = false;       // set by the main thread to release it
bool g_seam_dispatch_done = false; // set by the writer thread after dispatcher.run() returns
std::string g_seam_recorded_bytes;

std::expected<std::optional<yuzu::asset_tags::WriteWarning>, yuzu::asset_tags::IoError>
test_write_state_file_atomic(const std::filesystem::path& dest, std::string_view bytes) {
    {
        std::lock_guard<std::mutex> lock(g_seam_mu);
        g_seam_recorded_bytes.assign(bytes);
        g_seam_inside = true;
    }
    g_seam_cv.notify_all();
    {
        std::unique_lock<std::mutex> lock(g_seam_mu);
        g_seam_cv.wait(lock, [] { return g_seam_proceed; });
    }
    // Defer to the real function so the observable outcome is unchanged.
    return yuzu::asset_tags::write_state_file_atomic(dest, bytes);
}

} // namespace

// TU-inclusion seam: neutralise the C export, rename the one persist call
// site, then pull the plugin in.
#undef YUZU_PLUGIN_EXPORT
#define YUZU_PLUGIN_EXPORT(ClassName) /* no C export in the test executable */
#define write_state_file_atomic test_write_state_file_atomic
#include "asset_tags_plugin.cpp"
#undef write_state_file_atomic
#undef YUZU_PLUGIN_EXPORT

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <array>
#include <thread>

namespace {

using namespace yuzu::asset_tags;

AssetTagsPlugin& tu_plugin() {
    static AssetTagsPlugin p;
    return p;
}

int tu_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* params,
               size_t param_count) {
    yuzu::CommandContext cmd_ctx{ctx};
    yuzu::Params p{{params, param_count}};
    return tu_plugin().execute(cmd_ctx, action, p);
}

const YuzuPluginDescriptor kTuDescriptor{
    .abi_version = YUZU_PLUGIN_ABI_VERSION,
    .name = "asset_tags",
    .version = "0.1.0",
    .description = "asset_tags (TU-inclusion seam)",
    .actions = tu_plugin().actions(),
    .init = nullptr,
    .shutdown = nullptr,
    .execute = tu_execute,
    .sdk_version = YUZU_PLUGIN_SDK_VERSION,
    .action_descriptors = nullptr,
    .action_descriptor_count = 0,
};

} // namespace

TEST_CASE("asset_tags sync writes the state file while holding g_mu (S21)",
          "[agent][asset_tags_sync_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_lock_"};
    const fs::path dest = dir.path / "asset_tags.json";

    // M1: g_state/g_store_path are process-globals shared with every other
    // TEST_CASE that might one day land in this TU. Reset on entry AND on
    // every exit -- including assertion unwind -- via ScopeExit.
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path = dest;
    }
    yuzu::test::ScopeExit reset_globals{[] {
        std::lock_guard<std::mutex> lock(g_mu);
        g_state = {};
        g_store_path.clear();
    }};
    {
        std::lock_guard<std::mutex> lock(g_seam_mu);
        g_seam_inside = false;
        g_seam_proceed = false;
        g_seam_dispatch_done = false;
        g_seam_recorded_bytes.clear();
    }

    const char* value = "a";
    const std::array<YuzuParam, 1> params{{{"role", value}}};
    yuzu::agent::LocalDispatcher::Result result;
    std::thread writer([&] {
        yuzu::agent::LocalDispatcher dispatcher;
        result = dispatcher.run(&kTuDescriptor, "sync", params);
        {
            std::lock_guard<std::mutex> lock(g_seam_mu);
            g_seam_dispatch_done = true;
        }
        g_seam_cv.notify_all();
    });

    bool arrived_parked = false;
    {
        std::unique_lock<std::mutex> lock(g_seam_mu);
        g_seam_cv.wait(lock, [] { return g_seam_inside || g_seam_dispatch_done; });
        arrived_parked = g_seam_inside;
    }
    // false here means the dispatch finished without ever calling the
    // persist seam -- a regression, not a hang.
    CHECK(arrived_parked);

    // No REQUIRE (test-aborting) from here until the writer is joined: it
    // must always be released.
    std::string recorded;
    if (arrived_parked) {
        // THE assertion: the writer is parked inside the seam that stands in
        // for write_state_file_atomic, called from inside do_sync's single
        // critical section, so g_mu must still be held.
        const bool lock_was_free = g_mu.try_lock();
        CHECK_FALSE(lock_was_free);
        if (lock_was_free)
            g_mu.unlock();

        std::lock_guard<std::mutex> lock(g_seam_mu);
        recorded = g_seam_recorded_bytes;
    }

    {
        std::lock_guard<std::mutex> lock(g_seam_mu);
        g_seam_proceed = true;
    }
    g_seam_cv.notify_all();
    writer.join();

    if (arrived_parked) {
        CHECK(result.rc == 0);
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

        std::lock_guard<std::mutex> lock(g_mu);
        CHECK(recorded == serialize_state(g_state));
        CHECK(g_state.tags.at("role") == "a");
    }
}
