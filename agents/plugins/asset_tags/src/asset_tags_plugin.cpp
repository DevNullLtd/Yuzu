/**
 * asset_tags_plugin.cpp — Structured asset tag awareness for Yuzu agents
 *
 * This plugin lets agents learn their server-assigned structured tags
 * (role, environment, location, service) and detect when they change.
 *
 * Actions:
 *   "sync"     — Server pushes the current structured tags. The plugin
 *                stores them locally, detects changes from the previous
 *                state, and reports any diffs.
 *   "status"   — Reports the locally cached tags and sync metadata.
 *   "get"      — Get a specific structured tag value by category key.
 *   "changes"  — Reports the change log (what changed and when).
 *
 * Storage: <data_dir>/asset_tags.json
 *
 * Background: A periodic check thread runs every check_interval seconds
 * (default 300). It marks the local cache as stale if no sync has arrived
 * within that window, writing a stale flag that the "status" action reports.
 */

#include <yuzu/plugin.hpp>

#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
using namespace yuzu::asset_tags;

std::mutex g_mu;
AssetTagState g_state;
fs::path g_store_path;
std::atomic<bool> g_shutdown{false};
std::thread g_check_thread;
std::atomic<int> g_check_interval_s{300}; // default 5 minutes

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Load the persisted snapshot. A missing file is a normal first run; an
// unreadable or schema-violating file is rejected whole (defaults kept, one
// warning naming the reason) and replaced by the next sync's atomic write.
void load_state() {
    std::lock_guard lock(g_mu);
    g_state = {};

    if (g_store_path.empty())
        return;

    auto text = read_state_file(g_store_path);
    if (!text) {
        spdlog::warn("asset_tags: cannot read state file: {}", text.error().message);
        return;
    }
    if (!*text)
        return; // first run

    auto parsed = parse_state(**text);
    if (!parsed) {
        spdlog::warn("asset_tags: ignoring corrupt state file {}: {}", g_store_path.string(),
                     parsed.error().message);
        return;
    }
    g_state = std::move(*parsed);
}

void check_thread_fn() {
    while (!g_shutdown.load(std::memory_order_acquire)) {
        // Sleep in small increments for responsive shutdown
        auto remaining = std::chrono::seconds{g_check_interval_s.load(std::memory_order_relaxed)};
        while (remaining.count() > 0 && !g_shutdown.load(std::memory_order_acquire)) {
            auto sleep_time = std::min(remaining, std::chrono::seconds{5});
            std::this_thread::sleep_for(sleep_time);
            remaining -= sleep_time;
        }
        if (g_shutdown.load(std::memory_order_acquire))
            break;

        // Check if tags are stale (no sync within the check interval)
        std::lock_guard lock(g_mu);
        auto now = now_epoch();
        if (g_state.last_sync_epoch > 0 &&
            (now - g_state.last_sync_epoch) > g_check_interval_s.load(std::memory_order_relaxed)) {
            if (!g_state.stale) {
                g_state.stale = true;
                // In-memory only, deliberately not persisted: `status` reports
                // it live, the next `sync` writes `stale=false` to disk, and
                // after a restart the flag re-derives from `last_sync_epoch`
                // on the next check tick.
            }
        }
    }
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// All 4 actions (including "sync", the server-initiated structured-tag
// push) are pure in-process reads/writes of <data_dir>/asset_tags.json — no
// subprocess on any OS (rung 1, "local_json_store" on all three legs).
const YuzuActionDescriptor kActionDescriptors[] = {
    {"sync", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"status", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"get", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"changes", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
};

} // namespace

class AssetTagsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "asset_tags"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Structured asset tag awareness — syncs server-assigned tags locally and detects "
               "changes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"sync", "status", "get", "changes", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        yuzu::PluginContext pctx{ctx.raw()};
        auto data_dir = pctx.get_config("agent.data_dir");
        if (!data_dir.empty())
            g_store_path = fs::path(std::string{data_dir}) / "asset_tags.json";

        // Read optional check interval from config (default 300s)
        auto interval_str = pctx.get_config("asset_tags.check_interval");
        if (!interval_str.empty()) {
            if (auto v = parse_check_interval(interval_str))
                g_check_interval_s.store(*v, std::memory_order_relaxed);
            else
                spdlog::warn("asset_tags: ignoring malformed asset_tags.check_interval '{}'",
                             std::string{interval_str});
        }

        load_state();

        // Start background staleness check thread
        g_shutdown.store(false, std::memory_order_release);
        g_check_thread = std::thread(check_thread_fn);

        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        g_shutdown.store(true, std::memory_order_release);
        if (g_check_thread.joinable())
            g_check_thread.join();
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "sync")
            return do_sync(ctx, params);
        if (action == "status")
            return do_status(ctx);
        if (action == "get")
            return do_get(ctx, params);
        if (action == "changes")
            return do_changes(ctx);

        ctx.write_output(format_error_row("unknown action", action));
        return 1;
    }

private:
    // Caller holds g_mu.
    static std::string tag_value_locked(std::string_view key) {
        auto it = g_state.tags.find(std::string{key});
        return it != g_state.tags.end() ? it->second : std::string{};
    }

    int do_sync(yuzu::CommandContext& ctx, yuzu::Params params) {
        const auto now = now_epoch();

        CategoryValues values;
        for (std::size_t i = 0; i < kCategoryKeys.size(); ++i)
            values[i] = cap_value(params.get(kCategoryKeys[i]));

        std::vector<ChangeRecord> new_changes;
        CategoryValues current;
        int64_t last_sync = 0;
        bool persisted = true;
        {
            // One critical section: mutate, snapshot, and persist under the
            // same lock so the file is always one consistent state and
            // successive syncs' writes are ordered (S21). Readers
            // (do_status/do_get/do_changes) and the staleness check thread
            // take the same lock, so a stalled data_dir filesystem stalls
            // every action of this plugin, not just sync -- accepted: a
            // small local file, and the alternative serialises the same I/O
            // behind more code (M3).
            std::lock_guard lock(g_mu);
            new_changes = apply_sync(g_state, values, now);

            if (!g_store_path.empty()) {
                auto written = write_state_file_atomic(g_store_path, serialize_state(g_state));
                if (!written) {
                    persisted = false;
                    spdlog::warn("asset_tags: state not persisted: {}", written.error().message);
                } else if (*written) {
                    spdlog::warn("asset_tags: {}", (*written)->message);
                }
            }

            for (std::size_t i = 0; i < kCategoryKeys.size(); ++i)
                current[i] = tag_value_locked(kCategoryKeys[i]);
            last_sync = g_state.last_sync_epoch;
        }

        // Report results
        if (new_changes.empty()) {
            ctx.write_output("sync|no_changes");
        } else {
            for (const auto& cr : new_changes)
                ctx.write_output(format_sync_event(cr));
        }

        // Report current state
        for (std::size_t i = 0; i < kCategoryKeys.size(); ++i)
            ctx.write_output(format_tag_row(kCategoryKeys[i], current[i]));
        ctx.write_output(std::format("last_sync|{}", last_sync));

        // The in-memory state advanced and the rows above are truthful either
        // way; the status tells the caller whether the write reached disk.
        if (persisted)
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL);
        else
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "asset_tags:persist_failed");
        return 0;
    }

    int do_status(yuzu::CommandContext& ctx) {
        std::lock_guard lock(g_mu);

        for (auto cat_key : kCategoryKeys)
            ctx.write_output(format_tag_row(cat_key, tag_value_locked(cat_key)));

        ctx.write_output(std::format("last_sync|{}", g_state.last_sync_epoch));
        ctx.write_output(std::format("stale|{}", g_state.stale ? "true" : "false"));
        ctx.write_output(std::format("check_interval|{}",
                                     g_check_interval_s.load(std::memory_order_relaxed)));
        ctx.write_output(std::format("change_count|{}", g_state.change_log.size()));
        return 0;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }

        if (!is_category_key(key)) {
            ctx.write_output(format_error_row("error|unknown category", key));
            return 1;
        }

        std::lock_guard lock(g_mu);
        ctx.write_output(format_tag_row(key, tag_value_locked(key)));
        return 0;
    }

    int do_changes(yuzu::CommandContext& ctx) {
        std::lock_guard lock(g_mu);

        if (g_state.change_log.empty()) {
            ctx.write_output("changes|none");
            return 0;
        }

        for (const auto& cr : g_state.change_log)
            ctx.write_output(format_change_row(cr));
        ctx.write_output(std::format("total_changes|{}", g_state.change_log.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AssetTagsPlugin)
