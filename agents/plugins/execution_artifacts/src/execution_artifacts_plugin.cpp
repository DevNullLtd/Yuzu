/**
 * execution_artifacts_plugin.cpp — Windows-only execution-evidence plugin:
 * ShimCache (AppCompatCache), Amcache InventoryApplicationFile, and
 * Prefetch.
 *
 * Actions:
 *   "shimcache" — one row per AppCompatCache entry (path, last-modified,
 *                 data size). Windows 10/11 layout only.
 *   "amcache"   — one row per Root\InventoryApplicationFile subkey (path,
 *                 SHA-1, size, link date, publisher, binary type, product
 *                 name/version).
 *   "prefetch"  — one row per .pf file under C:\Windows\Prefetch (exe name,
 *                 hash, version, run count, last-run timestamps, volume and
 *                 file-reference counts).
 *
 * FORENSICS-CLASS DATA — see content/definitions/execution_artifacts.yaml
 * and this plugin's README (agents/plugins/execution_artifacts/README.md;
 * the docs/user-manual page is a separate follow-up): gated behind the
 * Forensics securable, AdminOrApproval, single-target only, DEFAULT-OFF via the
 * server kill switch. This plugin performs no authz itself (that lives at
 * the server dispatch layer, server/core/src/dispatch_destructive_gate.hpp)
 * — it only ever emits paths and hashes, never file contents.
 *
 * All three actions are independent: a failure reading one artefact never
 * blocks the other two (each has its own `constrained|<token>` outcome and
 * exit code — see this package's spec). This TU is fully portable — no
 * target-OS #if of any kind, matching disk_actions_plugin.cpp's precedent —
 * so the three descriptor legs are always declared in full even on a
 * single-OS build, and execute() branches on _WIN32 only to choose between
 * the real Windows legs (P32's execution_artifacts_win.cpp, declared in
 * execution_artifacts_legs.hpp) and the fixed non-Windows
 * "<action>|unsupported|windows_only_artefact" outcome every action reports there.
 */

#include <yuzu/plugin.hpp>

#include "execution_artifacts_legs.hpp"
#include "execution_artifacts_scratch_sweep.hpp"

#include <yuzu/string_utils.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace {

// The three descriptor legs are FIXED and never wrapped in a preprocessor
// conditional — a single-OS build still declares the full per-OS shape
// (disk_actions_plugin.cpp precedent, #2204's capability-matrix generator).
//
// Mechanism strings and notes below quote A1's the-rig probe findings
// verbatim (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md,
// 2026-09-06) where the spec calls for it.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "shimcache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "RegQueryValueExW HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session "
         "Manager\\AppCompatCache (local bounded reader, 16 MiB)",
         "Windows 10/11 layout only ('win10' header scheme, DWORD 0x34 or 0x30); no exec-flag "
         "bit exists in this layout, so every row's insert_flag is '-'. A1's real capture "
         "(the-rig, 2026-09-06) was 7886 bytes, well under the 16 MiB bound, and parsed with "
         "the header-size DWORD reading 0x34"},
    },
    {
        /* .action      = */ "amcache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "copy Amcache.hve(+.LOG1/.LOG2) then RegLoadAppKeyW; whole sequence serialised by "
         "offline_hive_mutex",
         "A1's the-rig probe (2026-09-06) found the copy succeeds as a PLAIN Copy-Item in every "
         "session tested (admin and LocalSystem) — the sharing violation that would require "
         "CreateFile(FILE_SHARE_READ|WRITE|DELETE, FILE_FLAG_BACKUP_SEMANTICS) + SeBackupPrivilege "
         "was never hit, so that fallback path is unexercised on this hardware. RegLoadAppKeyW "
         "does NOT require SeBackupPrivilege: it succeeded (LSTATUS 0x00000000) with the "
         "privilege explicitly disabled via AdjustTokenPrivileges, in both the admin session and "
         "under LocalSystem, against all 8889 real InventoryApplicationFile subkeys. Reported "
         "CONSTRAINED because the plain-copy path is a best-effort acquisition method not "
         "guaranteed on every host (a locked/exclusively-held hive on another machine could still "
         "need the backup-semantics fallback), not because anything failed on the probe host"},
    },
    {
        /* .action      = */ "prefetch",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CreateFileW read + ntdll RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx"
         "(COMPRESSION_FORMAT_XPRESS_HUFF)",
         "A1's the-rig LocalSystem probe (2026-09-06): GetProcAddress resolved both ntdll "
         "entry points to non-null addresses in every session (admin and LocalSystem); all four "
         "decompression attempts across the three real MAM .pf captures returned NTSTATUS "
         "0x00000000 (STATUS_SUCCESS) from both RtlGetCompressionWorkSpaceSize (workspace size "
         "166495 bytes, format COMPRESSION_FORMAT_XPRESS_HUFF, engine standard) and "
         "RtlDecompressBufferEx, with every decompressed payload's bytes 4-7 reading 'SCCA'. "
         "Real captures parsed as prefetch format version 31 (Windows 10/11), not version 30 as "
         "originally planned — see execution_artifacts_parsers.hpp's file header"},
    },
};

} // namespace

class ExecutionArtifactsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "execution_artifacts"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows execution-evidence sources: ShimCache, Amcache "
               "InventoryApplicationFile, and Prefetch. Forensics-gated, single-target, "
               "default-off";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"shimcache", "amcache", "prefetch", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        // Copied into a std::string immediately -- ctx.get_config returns a
        // string_view over the C ABI's own buffer, not guaranteed to
        // outlive this call (tar_plugin.cpp:569's same precedent).
        data_dir_ = std::string{ctx.get_config("agent.data_dir")};
#ifdef _WIN32
        // A1 (#4390): reclaim any stale scratch directory a crashed/killed
        // prior dispatch left under agent.data_dir before this agent ever
        // runs amcache itself. Never affects init()'s own outcome -- see
        // sweep_scratch_dirs's own try/catch(...).
        sweep_scratch_dirs("startup");
#endif
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
#ifdef _WIN32
        if (action == "shimcache")
            return yuzu::execution_artifacts::collect_shimcache(ctx);
        if (action == "amcache") {
            // Log-only, never an output row (row shapes stay byte-identical)
            // -- reclaims an orphan left by a crashed dispatch at the first
            // amcache dispatch at least kScratchDirStaleAfterSecs after it
            // was left, rather than only at the next agent restart.
            sweep_scratch_dirs("pre-dispatch");
            return yuzu::execution_artifacts::collect_amcache(ctx, data_dir_);
        }
        if (action == "prefetch")
            return yuzu::execution_artifacts::collect_prefetch(ctx);
#else
        if (action == "shimcache" || action == "amcache" || action == "prefetch") {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "windows_only_artefact");
            // `action` is safe to write raw here (unlike the unknown-action row below):
            // this branch is reachable only when it string-equals one of the three
            // literals just checked above, never request-supplied free text.
            ctx.write_output(std::string{action} + "|unsupported|" +
                             std::string{yuzu::execution_artifacts::kUnsupportedWindowsOnly});
            return 1;
        }
#endif

        // `action` is request-supplied and lands in a pipe-delimited stream, so
        // it goes through the shared escaper like any other untrusted field.
        ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
        return 1;
    }

private:
#ifdef _WIN32
    // A1 (#4390): sweep stale execution_artifacts- scratch directories out
    // of agent.data_dir. The ENTIRE body sits inside one try/catch(...):
    // the SDK's init trampoline (sdk/include/yuzu/plugin.hpp's
    // YUZU_PLUGIN_EXPORT _yuzu_init_) calls this->init() with no catch of
    // its own, so an exception escaping from here during the "startup"
    // call would cross the plugin's C ABI boundary. Never throws; never
    // affects this plugin's own result -- init() still returns success
    // unconditionally regardless of what the sweep found, and the
    // "pre-dispatch" call from execute() never produces an output row.
    void sweep_scratch_dirs(const char* trigger) noexcept {
        try {
            // UTF-8-view-based std::filesystem::path construction, NEVER
            // the narrow-string constructor -- the same reasoning as
            // execution_artifacts_win.cpp's ScratchDirGuard banner (a
            // narrow std::string is decoded via the ANSI code page on
            // MSVC, silently mangling a non-ASCII agent.data_dir). This TU
            // stays portable/OS-header-free, so this goes through
            // std::filesystem's own C++20 u8 constructor rather than
            // yuzu::win::to_wide (agents/shared, Windows-only).
            const std::u8string_view data_dir_u8{
                reinterpret_cast<const char8_t*>(data_dir_.data()), data_dir_.size()};
            const std::wstring wide_data_dir = std::filesystem::path{data_dir_u8}.wstring();

            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();

            const auto result = yuzu::execution_artifacts::sweep_stale_scratch_dirs(
                wide_data_dir, static_cast<std::int64_t>(now));

            const std::size_t total = result.removed + result.failed + result.skipped_not_ours +
                                       result.deferred;
            if (total > 0) {
                spdlog::warn(
                    "execution_artifacts: {} scratch sweep under agent.data_dir: removed {} "
                    "failed {} not_ours {} deferred {}",
                    trigger, result.removed, result.failed, result.skipped_not_ours,
                    result.deferred);
            }
            if (result.enumerate_error) {
                spdlog::warn(
                    "execution_artifacts: {} scratch sweep could not enumerate agent.data_dir "
                    "(os_error={})",
                    trigger, result.os_error);
            }
        } catch (...) {
        }
    }
#endif

    // Captured at init() (tar_plugin.cpp:565-581's precedent); only the
    // amcache leg consumes it (execution_artifacts_win.cpp's collect_amcache,
    // as the parent directory for its per-dispatch random scratch
    // directory), empty when agent.data_dir is unset -- collect_amcache
    // hard-fails constrained|data_dir_unset in that case, no fallback.
    std::string data_dir_;
};

YUZU_PLUGIN_EXPORT(ExecutionArtifactsPlugin)
