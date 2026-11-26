/**
 * file_search_plugin.cpp -- on-demand, resumable search of the local disks by leaf name.
 *
 * Action:
 *   "search" -- root (mandatory, absolute), pattern (mandatory, leaf-name glob), kinds (files, directories
 *               or both), cursor (the token of the previous slice; empty for the first). One call is one
 *               slice of the search: the caller loops on the cursor until a slice answers with none.
 *
 * Wire rows (file_search_rows.hpp): match, extents, volume, gap, coverage and cursor rows, then exactly one
 * `search` trailer last. Names, types, sizes, times and extents only: a matched file is opened for its
 * facts and never read, and no file content is read or hashed.
 *
 * SHIPPED LEGS. Linux, macOS and Windows. All three descriptor legs are declared unconditionally so the
 * capability-matrix generator sees a complete, stable shape. The plugin is ON by default on every OS (the
 * per-plugin kill switch still turns it off).
 *
 * THIS TU holds the descriptors, init (the module pin and the context the heartbeat keys are written
 * through), shutdown (stop and a bounded quiesce) and the two hooks a finished slice triggers: the heartbeat
 * counters and the log line. The execute body and its one try/catch are in file_search_execute.hpp, the
 * state machine in file_search_driver.hpp, the process-wide slot and the worker runner in
 * file_search_shell.cpp and the operating system in file_search_posix.cpp and file_search_win.cpp.
 *
 * THE MODULE PIN. A slice that times out leaves its worker thread running, and that worker runs this
 * plugin's own code (the walk is compiled into it). Unloading the module under it would unmap code that is
 * still executing, so init takes one extra reference on the module and never releases it (POSIX: dlopen with
 * RTLD_NODELETE; Windows: GetModuleHandleExW with the pin flag): the module stays mapped for the life of the
 * process, and the worker can finish on its own time. Init fails if the pin cannot be taken.
 *
 * SHUTDOWN. shutdown() clears the context pointer the heartbeat writes through, sets the stop flag (a
 * running walk ends at its next entry) and waits a short bounded quiesce for a call in flight. On the
 * orderly stop the agent drains its thread pool before it calls shutdown(), so the stop flag never meets a
 * running slice. When shutdown() runs first (the agent's exit path), a call still in flight when the
 * quiesce bound passes finishes on its pool thread, inside the pinned module: it releases the slot, records
 * its abandoned worker and writes its rows. An abandoned worker touches only state it co-owns.
 */

#include <yuzu/plugin.hpp>

#include "file_search_execute.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include <spdlog/spdlog.h>

#if defined(_WIN32)
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

namespace {

namespace fs_plugin = yuzu::file_search;

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "search",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "resumable sorted depth-first search of the requested root, one slice per call, through no-follow "
         "directory opens; the mount table from /proc/<pid>/mountinfo decides which mounts are searched; "
         "the extents of every matched regular file from FIEMAP; matched files are opened and never read",
         "constrained: only local filesystem types on the allow-list are searched and every other mount is "
         "reported by its own row; names compare byte for byte; a directory the agent cannot search is a "
         "gap, and the capability that lets the agent search directories of other accounts is held on the "
         "walking thread only around directory opens, directory listings and the leaf open (hygiene, not a "
         "boundary); the verdict reads partial when any mount, directory or name was not searched"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "resumable sorted depth-first search of the requested root, one slice per call, through no-follow "
         "directory opens; the mount table from getmntinfo_r_np decides which mounts are searched; the "
         "extents of every matched regular file from F_LOG2PHYS_EXT; dataless files are never "
         "materialised; matched files are opened and never read",
         "constrained: names compare by Unicode normalisation and case folding whatever the volume's own "
         "rule, so a case-sensitive volume can over-match; folders protected by the system's privacy "
         "controls are permission-denied gaps; a search rooted at / reaches the data volume through its "
         "firmlinks and reads partial; the verdict reads partial when any mount, directory or name was not "
         "searched"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "resumable sorted depth-first search of one fixed volume through parent-handle-relative no-reparse "
         "opens; the volume type and the drive type decide whether it is searched; the extents of every "
         "matched file from FSCTL_GET_RETRIEVAL_POINTERS on an attribute-only handle, after "
         "FSCTL_GET_EXTERNAL_BACKING rules out an externally backed file; matched files are opened for "
         "their attributes and never read",
         "constrained: fixed NTFS, ReFS, FAT, FAT32 and exFAT volumes only; names compare upper-cased; links, "
         "junctions and mount points are skipped and counted; a populated cloud-synced folder is searched; "
         "placeholder and offline files and folders are never opened, except that each folder of the "
         "operator-named root's own path is opened (never listed) before any listing decision (tracked in "
         "#8755); file ids are reported on NTFS only; a folder the agent's token is refused is a gap; the "
         "search takes no extra privilege; the verdict reads partial when any volume, directory or name was "
         "not searched"},
    },
};

// ---- in-flight calls and the shutdown quiesce ----

std::atomic<int> g_in_flight{0};

struct InFlight {
    InFlight() noexcept { g_in_flight.fetch_add(1, std::memory_order_acq_rel); }
    ~InFlight() { g_in_flight.fetch_sub(1, std::memory_order_acq_rel); }
    InFlight(const InFlight&) = delete;
    InFlight& operator=(const InFlight&) = delete;
};

/// How long shutdown() waits for a call that is running to return. Bounded: a walk blocked in a system call
/// is not waited for; its worker finishes on its own time inside the pinned module.
constexpr std::chrono::milliseconds kShutdownQuiesce{3'000};

// ---- the heartbeat counters and the log line ----

// The plugin's own KV namespace, read by the agent on every heartbeat (docs/observability-conventions.md,
// "Plugin heartbeat-tag bridge"): at most eight keys, each a bounded counter of what slices did since the
// agent started.
constexpr std::array<const char*, 8> kHeartbeatKeys = {
    "heartbeat.slices",    "heartbeat.budget_stops", "heartbeat.stalled", "heartbeat.unstable",
    "heartbeat.timed_out", "heartbeat.rejected",     "heartbeat.failed",  "heartbeat.gaps"};

std::mutex g_heartbeat_mutex;              // guards the totals and the context pointer
std::array<std::uint64_t, 8> g_totals{};   // under g_heartbeat_mutex
YuzuPluginContext* g_plugin_ctx = nullptr; // under g_heartbeat_mutex; null before init and after shutdown

void publish_heartbeat(const fs_plugin::SliceCounters& c) {
    const std::array<std::uint64_t, 8> delta = {c.slices,    c.budget_stops, c.stalled, c.unstable,
                                                c.timed_out, c.rejected,     c.failed,  c.gaps};
    const std::lock_guard<std::mutex> lock(g_heartbeat_mutex);
    for (std::size_t i = 0; i < delta.size(); ++i) {
        if (delta[i] == 0)
            continue;
        g_totals[i] += delta[i];
        if (g_plugin_ctx != nullptr) {
            yuzu::PluginContext pctx{g_plugin_ctx};
            (void)pctx.storage_set(kHeartbeatKeys[i], std::to_string(g_totals[i]));
        }
    }
}

/// One WARN per slice that ended without a result (the query prefix and the reason: never a path or a
/// pattern), one INFO per slice that stopped at a budget. A retryable slice logs here too: the search goes on
/// from the same cursor, and the reason says which kind it was.
void log_slice(const fs_plugin::SliceResult& r) {
    if (r.status == fs_plugin::Status::failed)
        spdlog::warn("file_search: search {} slice failed: {}", r.query, r.reason);
    else if (r.counters.budget_stops != 0)
        spdlog::info("file_search: search {} slice stopped at a budget: {}", r.query, r.reason);
}

void after_slice(const fs_plugin::SliceResult& r) {
    publish_heartbeat(r.counters);
    log_slice(r);
}

void pin_anchor() noexcept {} // an address inside this module

/// Takes one extra reference on this module, once; never released. False if it cannot be taken, in which
/// case init fails and the plugin never runs.
[[nodiscard]] bool pin_module() noexcept {
#if defined(_WIN32)
    static bool pinned = false;
    if (pinned)
        return true;
    HMODULE module = nullptr;
    // With FROM_ADDRESS the "name" argument is an address inside the module, not a string; the pointer is
    // never read as wchar_t. The pin flag makes FreeLibrary unable to unmap the module for the life of the
    // process (the echo plugin's pin, echo_mapdrive_collector.cpp).
    pinned = ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                  reinterpret_cast<LPCWSTR>(&pin_anchor), &module) != 0;
    return pinned;
#else
    static void* handle = nullptr;
    if (handle != nullptr)
        return true;
    Dl_info info{};
    // dladdr takes any address inside this module: the function-to-object pointer conversion is the one POSIX
    // defines for dlsym and dladdr, and nothing is read through it.
    if (::dladdr(reinterpret_cast<const void*>(&pin_anchor), &info) == 0 || info.dli_fname == nullptr)
        return false;
    handle = ::dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    return handle != nullptr;
#endif
}

} // namespace

class FileSearchPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "file_search"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "On-demand, resumable search of the local disks by file or directory name, with the extents "
               "of every matched file; names, types, sizes, times and extents only";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"search", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override { return kActionDescriptors; }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        if (!pin_module())
            return std::unexpected(yuzu::PluginError{1, "file_search: the plugin module could not be pinned"});
        if (!fs_plugin::init_cursor_key())
            return std::unexpected(yuzu::PluginError{1, "file_search: the cursor key could not be drawn"});
        fs_plugin::clear_stop();
        const std::lock_guard<std::mutex> lock(g_heartbeat_mutex);
        g_plugin_ctx = ctx.raw();
        // "Since the agent started": the KV is a file that outlives the process and the totals restart at
        // zero, so a key this process never counts would keep the last process's value. Delete them all: a
        // tag is absent until this process counts something (a counter that never fired is absent, not
        // zero). Through the C entry: init must not throw, and PluginContext::storage_delete builds a
        // std::string.
        g_totals.fill(0);
        for (const char* key : kHeartbeatKeys)
            (void)yuzu_ctx_storage_delete(g_plugin_ctx, key);
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        {
            const std::lock_guard<std::mutex> lock(g_heartbeat_mutex);
            g_plugin_ctx = nullptr; // nothing below writes through a context again
        }
        fs_plugin::request_stop(); // a running walk ends at its next entry
        const auto give_up = std::chrono::steady_clock::now() + kShutdownQuiesce;
        while (g_in_flight.load(std::memory_order_acquire) != 0 && std::chrono::steady_clock::now() < give_up)
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        const InFlight in_flight;
        return fs_plugin::execute_search(ctx, action, params.get("root"), params.get("pattern"),
                                         params.get("kinds"), params.get("cursor"), &fs_plugin::os_name_semantics,
                                         &fs_plugin::run_live_slice, &after_slice, fs_plugin::kExceptionProvenance,
                                         &fs_plugin::os_normalise_root);
    }
};

YUZU_PLUGIN_EXPORT(FileSearchPlugin)
