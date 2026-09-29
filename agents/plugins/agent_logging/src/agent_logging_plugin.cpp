/**
 * agent_logging_plugin.cpp — Remote agent log access plugin for Yuzu
 *
 * Actions:
 *   "get_log"       — Return the last N lines of the agent log file.
 *   "get_key_files" — List important agent files (config, data, logs)
 *                     with sizes and modification times.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 *
 * The agent log file path is read from agent config. Key file paths
 * are discovered from the agent's configured directories.
 */

#include <yuzu/plugin.hpp>

#include <charconv>
#include <chrono>
#include <deque>
#include <filesystem>
#include <format>
#include <fstream>
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
#elif defined(__APPLE__)
#include <cstdint>
#include <cstdlib>
#include <mach-o/dyld.h>
#include <sys/syslimits.h>
#endif

namespace {

namespace fs = std::filesystem;

YuzuPluginContext* g_ctx = nullptr;

/**
 * Helper to read a config value via the raw plugin context.
 */
std::string_view cfg(std::string_view key) {
    if (!g_ctx)
        return {};
    const char* val = yuzu_ctx_get_config(g_ctx, std::string{key}.c_str());
    return val ? std::string_view{val} : std::string_view{};
}

/**
 * Determine the agent log file path. Checks config keys in order:
 *   1. agent.log_file — explicit log file path
 *   2. agent.data_dir + "/yuzu-agent.log" — data directory default
 *   3. Platform default paths
 */
std::string get_log_file_path() {
    // Every fs::exists below uses the noexcept (error_code) overload —
    // the throwing form raises filesystem_error on EACCES (e.g. parent
    // directory unreadable by the agent's effective user), and that
    // exception propagates out of the command handler and crashes the
    // whole agent process. Treat any stat failure as "log file not at
    // this path" rather than fatal. (Observed 2026-05-12: macOS dev box,
    // `/Library/Application Support/Yuzu/yuzu-agent.log` parent had
    // restricted perms; do_get_log brought down the entire agent.)
    std::error_code ec;

    // Try explicit log file config
    auto log_file = cfg("agent.log_file");
    if (!log_file.empty()) {
        return std::string{log_file};
    }

    // Try data_dir + default log name
    auto data_dir = cfg("agent.data_dir");
    if (!data_dir.empty()) {
        fs::path p = fs::path{std::string{data_dir}} / "yuzu-agent.log";
        if (fs::exists(p, ec)) {
            return p.string();
        }
    }

    // Platform default paths
#ifdef _WIN32
    // Check ProgramData
    const char* prog_data = std::getenv("ProgramData");
    if (prog_data) {
        fs::path p = fs::path{prog_data} / "Yuzu" / "yuzu-agent.log";
        if (fs::exists(p, ec))
            return p.string();
    }
#elif defined(__APPLE__)
    {
        fs::path p = "/Library/Application Support/Yuzu/yuzu-agent.log";
        if (fs::exists(p, ec))
            return p.string();
    }
    {
        fs::path p = "/var/log/yuzu/yuzu-agent.log";
        if (fs::exists(p, ec))
            return p.string();
    }
#else // Linux
    {
        fs::path p = "/var/log/yuzu/yuzu-agent.log";
        if (fs::exists(p, ec))
            return p.string();
    }
    {
        fs::path p = "/opt/yuzu/yuzu-agent.log";
        if (fs::exists(p, ec))
            return p.string();
    }
#endif

    return {};
}

/**
 * Read the last N lines from a file using a tail-style approach.
 * Reads the file line-by-line and keeps a sliding window of the
 * last `count` lines in a deque.
 */
std::deque<std::string> tail_file(const std::string& path, int count) {
    std::deque<std::string> lines;
    std::ifstream file(path);
    if (!file.is_open())
        return lines;

    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(std::move(line));
        if (static_cast<int>(lines.size()) > count) {
            lines.pop_front();
        }
    }
    return lines;
}

/**
 * Format a file_time_type as an ISO-like string.
 * Uses system_clock conversion where available.
 */
std::string format_file_time(const fs::file_time_type& ft) {
    // Convert file_clock to system_clock epoch seconds.
    // clock_cast and file_clock::to_sys are not portable across all compilers,
    // so compute via relative offset from "now" in both clock domains.
    auto file_now = fs::file_time_type::clock::now();
    auto sys_now = std::chrono::system_clock::now();
    auto diff = ft - file_now;
    auto sys_tp = sys_now + diff;
    auto epoch_s =
        std::chrono::duration_cast<std::chrono::seconds>(sys_tp.time_since_epoch()).count();
    return std::format("{}", epoch_s);
}

/**
 * Write a file info line: file|<path>|<size>|<modified_epoch>
 */
void emit_file_info(yuzu::CommandContext& ctx, const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec)
        return;

    auto size = fs::file_size(path, ec);
    if (ec)
        size = 0;

    auto mtime = fs::last_write_time(path, ec);
    std::string mtime_str = ec ? "0" : format_file_time(mtime);

    ctx.write_output(std::format("file|{}|{}|{}", path.string(), size, mtime_str));
}

/**
 * Scan a directory (non-recursively) and emit file info for each entry.
 */
void scan_directory(yuzu::CommandContext& ctx, const fs::path& dir) {
    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec))
        return;

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec)
            break;
        if (entry.is_regular_file()) {
            emit_file_info(ctx, entry.path());
        }
    }
}

// ABI4 capability declarations (#2204). Both actions are native, in-process
// filesystem/config reads on every OS — no subprocess anywhere in this
// plugin. "get_key_files"'s own-executable-path lookup differs per OS
// (/proc/self/exe symlink on Linux, _NSGetExecutablePath+realpath on macOS
// — the macOS path further below at ~331-363 — GetModuleFileNameA on
// Windows) but each is a native, in-process OS API call, so all three legs
// are rung 1.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "get_log",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "agent config lookup + std::ifstream tail read", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "agent config lookup + std::ifstream tail read", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "agent config lookup + std::ifstream tail read", nullptr},
    },
    {
        /* .action      = */ "get_key_files",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/proc/self/exe symlink + std::filesystem metadata", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "_NSGetExecutablePath + realpath(3) + std::filesystem metadata", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "GetModuleFileNameA + std::filesystem metadata", nullptr},
    },
};

} // namespace

class AgentLoggingPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "agent_logging"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Remote agent log access — retrieve log tail, list key agent files";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_log", "get_key_files", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "get_log")
            return do_get_log(ctx, params);
        if (action == "get_key_files")
            return do_get_key_files(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_get_log(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Parse lines parameter
        int lines = 50; // default
        auto lines_param = params.get("lines");
        if (!lines_param.empty()) {
            [[maybe_unused]] auto [ptr, ec] =
                std::from_chars(lines_param.data(), lines_param.data() + lines_param.size(), lines);
            if (ec != std::errc{} || lines < 1) {
                ctx.write_output(
                    "status|error|invalid lines parameter: must be a positive integer");
                return 1;
            }
        }

        // Clamp to max 500
        if (lines > 500) {
            lines = 500;
        }

        // Find log file. "No log file on this host" is not an error — it's
        // a legitimate empty result (e.g. agent logging to stderr-only).
        // Report it as status|empty with rc=0 so callers can distinguish
        // empty-set from genuine failures.
        std::string log_path = get_log_file_path();
        if (log_path.empty()) {
            ctx.write_output("status|empty|agent log file not configured on this host");
            ctx.write_output("line_count|0");
            return 0;
        }

        ctx.write_output(std::format("log_file|{}", log_path));

        // Read and output last N lines
        auto tail = tail_file(log_path, lines);
        ctx.write_output(std::format("line_count|{}", tail.size()));

        for (const auto& line : tail) {
            ctx.write_output(std::format("line|{}", line));
        }

        return 0;
    }

    int do_get_key_files(yuzu::CommandContext& ctx) {
        // Agent executable
#ifdef _WIN32
        {
            char exe_path[MAX_PATH]{};
            if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH) > 0) {
                emit_file_info(ctx, fs::path{exe_path});
            }
        }
#elif defined(__linux__)
        {
            std::error_code ec;
            auto exe = fs::read_symlink("/proc/self/exe", ec);
            if (!ec) {
                emit_file_info(ctx, exe);
            }
        }
#elif defined(__APPLE__)
        // _NSGetExecutablePath uses a two-call idiom: the first call passes
        // a zero-length buffer, which always fails and writes the required
        // buffer size (including the terminating NUL) into `size`; allocate
        // exactly that much and call again to actually fill it in. Then
        // resolve symlinks/./.. via realpath so the reported path matches
        // the real on-disk binary, not just wherever it was launched from.
        {
            uint32_t size = 0;
            _NSGetExecutablePath(nullptr, &size);

            std::string raw_path(size, '\0');
            if (size > 0 && _NSGetExecutablePath(raw_path.data(), &size) == 0) {
                // raw_path includes the NUL terminator written by the call;
                // drop it so it doesn't end up embedded in the std::string.
                if (!raw_path.empty() && raw_path.back() == '\0') {
                    raw_path.pop_back();
                }

                char resolved[PATH_MAX];
                if (realpath(raw_path.c_str(), resolved) != nullptr) {
                    emit_file_info(ctx, fs::path{resolved});
                } else if (!raw_path.empty()) {
                    // realpath failed (e.g. dangling component) — fall back
                    // to the unresolved-but-real path rather than fabricate
                    // one.
                    emit_file_info(ctx, fs::path{raw_path});
                }
            }
            // If _NSGetExecutablePath itself fails, honestly report nothing
            // rather than guess at an install location.
        }
#endif

        // Agent log file
        {
            std::string log_path = get_log_file_path();
            if (!log_path.empty()) {
                emit_file_info(ctx, fs::path{log_path});
            }
        }

        // Config file(s) — check common locations
        auto data_dir_sv = cfg("agent.data_dir");
        if (!data_dir_sv.empty()) {
            fs::path data_dir{std::string{data_dir_sv}};

            // Config files
            for (const auto& name : {"yuzu-agent.cfg", "agent.cfg", "config.cfg"}) {
                fs::path p = data_dir / name;
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    emit_file_info(ctx, p);
                }
            }

            // Data files — KV store, etc.
            for (const auto& name : {"kv-store.db", "agent-state.db"}) {
                fs::path p = data_dir / name;
                std::error_code ec;
                if (fs::exists(p, ec)) {
                    emit_file_info(ctx, p);
                }
            }
        }

        // Plugin directory
        auto plugin_dir_sv = cfg("agent.plugin_dir");
        if (!plugin_dir_sv.empty()) {
            scan_directory(ctx, fs::path{std::string{plugin_dir_sv}});
        }

        // TLS certificates
        yuzu::PluginContext pctx{g_ctx};
        for (const auto& key : {"tls.ca_cert", "tls.client_cert", "tls.client_key"}) {
            auto path = pctx.get_config(key);
            if (!path.empty()) {
                emit_file_info(ctx, fs::path{std::string{path}});
            }
        }

        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AgentLoggingPlugin)
