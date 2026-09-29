/**
 * bitlocker_plugin.cpp — Disk encryption status plugin for Yuzu
 *
 * Actions:
 *   "state" — BitLocker / LUKS / FileVault status per volume.
 *
 * Output is pipe-delimited via write_output().
 *
 * Acquisition, per OS (Wave-3 native/argv migration — this plugin's raw
 * `manage-bde -status` popen was the last raw spawn site in the file):
 *   - windows: Win32_EncryptableVolume WMI query + a per-volume
 *     GetConversionStatus() method call, both in-process (rung 1). No
 *     subprocess at all.
 *   - linux: libblkid TYPE=="crypto_LUKS" enumeration + plain
 *     /sys/class/block/dm-N/dm/uuid reads for open-mapping state (rung 1).
 *     No subprocess at all.
 *   - macos: fdesetup/diskutil stay on the governed bounded-subprocess
 *     runner, now as direct argv (rung 2) instead of a `/bin/sh -c` shell
 *     wrapper (rung 3) — no acquisition-logic change, mechanical only.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-L1)

#include <spdlog/spdlog.h>

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <cstdlib>     // std::free — blkid_get_tag_value's returned string ownership
#include <memory>      // std::unique_ptr
#include <type_traits> // std::remove_pointer_t — blkid_cache/blkid_dev_iterate RAII wrappers
#endif

#ifdef _WIN32
#include <win_str.hpp>   // yuzu::win::to_wide (#1681)
#include <wmi_bounded.hpp> // yuzu::shared::wmi bounded WMI query/method call
                            // (Windows-only; agents/shared, authored in
                            // parallel on PR3.3a — see bitlocker_windows_wmi.hpp)
#include "bitlocker_windows_wmi.hpp"
#elif defined(__linux__)
#include <blkid/blkid.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>

#include "bitlocker_linux_parsers.hpp"
#elif defined(__APPLE__)
#include <chrono>

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (K-7/CDX-07)

#include "bitlocker_macos_apfs.hpp"
#endif

namespace {

#ifdef __APPLE__
// A generous per-call wall-clock bound for the local disk-encryption tools
// (fdesetup/diskutil). Long enough never to fire in practice, short enough
// that a wedged tool cannot pin the instruction worker forever.
constexpr std::chrono::seconds kBitlockerCmdDeadline{20};

// Runs one macOS disk-encryption tool through the bounded, fork-lock-covered
// runner as a direct argv (no shell — rung 2). The `2>/dev/null` redirect
// the old shell-wrapped form relied on is equivalent to merge_stderr=false,
// the runner's default, so stderr is dropped the same way with no shell
// needed to do it.
std::string run_macos_tool(const std::vector<std::string>& argv, std::string_view operation) {
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kBitlockerCmdDeadline});
    // A deadline-killed or exec-failed tool returns empty/partial output that
    // would otherwise parse as a legitimate "FileVault absent / no volumes" —
    // a silent false-negative. Warn so an operator can tell a cut-short scan
    // from a genuinely empty result (sre-M1; mirrors the event_logs pattern).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("bitlocker: degraded {} (timed_out={}, tool_ran={}, truncated={})", operation,
                     res.timed_out, res.tool_ran, res.output_truncated);
    }
    std::string result = res.output;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}
#endif

#ifdef _WIN32

// root\CIMV2\Security\MicrosoftVolumeEncryption requires admin privilege
// (MS docs) — shared by both WMI calls below.
constexpr wchar_t kBitlockerWmiNamespace[] = L"root\\CIMV2\\Security\\MicrosoftVolumeEncryption";

// Returns false on a total acquisition failure (query error) so execute()
// can report a non-zero exit code, matching the pre-migration contract
// (an empty/failed `manage-bde -status` also returned 1). An empty-but-
// successful volume list is NOT a failure — it returns true.
bool report_bitlocker_status(yuzu::CommandContext& ctx) {
    // sink: bitlocker/report_bitlocker_status#1 — rung 1, in-process WMI
    // query (Win32_EncryptableVolume) replacing the raw `manage-bde
    // -status` popen this plugin used to run.
    auto query = yuzu::shared::wmi::run_bounded_wmi_query(
        kBitlockerWmiNamespace,
        L"SELECT DeviceID, DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume");

    if (query.error.has_value()) {
        // Unprivileged runs get a typed sentinel instead of a raw COM
        // failure string or a crash — this namespace is admin-only.
        if (yuzu::bitlocker::windows::is_permission_denied(query.error)) {
            ctx.write_output(
                "error|permission_denied: administrator privilege required to read BitLocker status");
        } else {
            ctx.write_output(
                std::format("error|{}", yuzu::util::safe_output_field(*query.error)));
        }
        return false;
    }

    auto volumes = yuzu::bitlocker::windows::parse_encryptable_volumes(query.rows);
    if (volumes.empty()) {
        ctx.write_output("volume|none|no_encryptable_volumes");
        return true;
    }
    if (query.truncated) {
        // A host with more encryptable volumes than the shared WMI helper's
        // row cap silently dropped the rest -- signal partial completeness
        // rather than let a truncated volume list read as the full picture
        // on this compliance-verification surface (mirrors
        // list_av_products_win's identical handling of the same shared
        // helper's truncation flag; security-guardian gate-2 finding).
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "bitlocker:volume_enumeration_truncated");
    }

    for (const auto& vol : volumes) {
        // sink: bitlocker/report_bitlocker_status#2 and #3 — rung 1,
        // in-process WMI method calls (GetConversionStatus,
        // GetEncryptionMethod), one of each per enumerated volume. Routed
        // through acquire_volume_row's injected-executor seam
        // (bitlocker_windows_wmi.hpp) rather than inlined here, so the
        // wiring itself — does GetEncryptionMethod's result actually reach
        // the output row — is fixture-testable without a live WMI provider
        // (adversarial-review gate 2 finding, PR3.3-b).
        auto row = yuzu::bitlocker::windows::acquire_volume_row(
            vol, [&](const std::string& object_path,
                     const std::string& method_name) -> std::optional<yuzu::bitlocker::windows::WmiRow> {
                auto call = yuzu::shared::wmi::exec_object_method(
                    kBitlockerWmiNamespace, yuzu::win::to_wide(object_path),
                    yuzu::win::to_wide(method_name), {});
                if (call.error.has_value()) {
                    // A per-volume method-call failure degrades only that
                    // one field to an honest "Unknown" rather than
                    // aborting the whole scan or fabricating a value — the
                    // GetConversionStatus and GetEncryptionMethod calls are
                    // independent, so a failure in one never suppresses
                    // the other's already-collected fields.
                    spdlog::warn("bitlocker: {} failed for {}: {}", method_name, vol.device_id,
                                 *call.error);
                    return std::nullopt;
                }
                if (call.rows.empty())
                    return std::nullopt;
                return call.rows.front();
            });
        ctx.write_output(row);
    }
    return true;
}

#elif defined(__linux__)

// Enumerate raw LUKS-formatted block devices via libblkid — a system
// pkg-config library (util-linux), not vcpkg. `blkid_probe_all` forces a
// live device scan rather than trusting a possibly-stale/missing
// /etc/blkid/blkid.tab cache file (the same thing the standalone `blkid`
// CLI does when no cache exists), so this stays a genuine rung-1 read
// rather than a cache hit that could go silently stale.
std::vector<yuzu::bitlocker::linux_dm::LuksBlockDevice> enumerate_luks_devices() {
    std::vector<yuzu::bitlocker::linux_dm::LuksBlockDevice> devices;

    blkid_cache raw_cache = nullptr;
    if (blkid_get_cache(&raw_cache, nullptr) != 0 || !raw_cache)
        return devices;
    // RAII from the moment of acquisition -- mirrors the `uuid` unique_ptr
    // below (adversarial-review gate 2 finding: this cache/iterator pair
    // was released only via ordinary fall-through to the manual
    // blkid_put_cache()/blkid_dev_iterate_end() calls at the bottom of the
    // function, reached only after intervening std::string construction
    // and vector::push_back calls per iteration -- either can throw
    // std::bad_alloc and leak both handles; the RAII-wrapped `uuid` three
    // lines below is proof the pattern was known and applied selectively).
    std::unique_ptr<std::remove_pointer_t<blkid_cache>, decltype(&blkid_put_cache)> cache{
        raw_cache, &blkid_put_cache};
    blkid_probe_all(cache.get());

    blkid_dev_iterate raw_iter = blkid_dev_iterate_begin(cache.get());
    if (!raw_iter)
        return devices;
    std::unique_ptr<std::remove_pointer_t<blkid_dev_iterate>, decltype(&blkid_dev_iterate_end)>
        iter{raw_iter, &blkid_dev_iterate_end};

    blkid_dev_set_search(iter.get(), "TYPE", "crypto_LUKS");
    blkid_dev dev = nullptr;
    while (blkid_dev_next(iter.get(), &dev) == 0) {
        dev = blkid_verify(cache.get(), dev);
        if (!dev)
            continue;
        const char* devname = blkid_dev_devname(dev);
        if (!devname)
            continue;
        // blkid_get_tag_value returns a heap-allocated string the caller
        // owns (util-linux convention — same as g_strdup) — adopt it
        // into a unique_ptr immediately so every path (including the
        // loop's next iteration) frees it; this is a long-lived agent
        // daemon process, so a per-call leak here is cumulative.
        std::unique_ptr<char, decltype(&std::free)> uuid{
            blkid_get_tag_value(cache.get(), "UUID", devname), &std::free};
        if (!uuid)
            continue;

        std::string full{devname};
        auto slash = full.rfind('/');
        std::string base = (slash == std::string::npos) ? full : full.substr(slash + 1);
        devices.push_back({std::move(base), std::string(uuid.get())});
    }
    return devices;
}

// Enumerate currently-open (mapped) dm-crypt devices via plain
// /sys/class/block/dm-*/dm/uuid reads — no subprocess, no cryptsetup.
std::vector<yuzu::bitlocker::linux_dm::DmCryptMapping> enumerate_dm_mappings() {
    std::vector<yuzu::bitlocker::linux_dm::DmCryptMapping> mappings;

    namespace fs = std::filesystem;
    // Error-code form throughout: construction AND every increment take the
    // error_code, so an I/O or permission error mid-walk (hardened/sandboxed
    // host) ends the walk with what was collected so far instead of throwing
    // std::filesystem::filesystem_error out of execute(). Same shape as
    // dex_linux_collector.cpp's /sys/devices/system/cpu walk. No
    // /sys/class/block at all (non-Linux kernel, container without sysfs
    // mounted) fails construction and yields the same honest empty result.
    std::error_code ec;
    for (fs::directory_iterator it{"/sys/class/block", ec}, end; !ec && it != end;
         it.increment(ec)) {
        auto name = it->path().filename().string();
        if (name.rfind("dm-", 0) != 0)
            continue;

        std::ifstream f(it->path() / "dm" / "uuid");
        if (!f)
            continue;
        std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};

        auto parsed = yuzu::bitlocker::linux_dm::parse_dm_uuid(name, content);
        if (parsed)
            mappings.push_back(std::move(*parsed));
    }
    return mappings;
}

void list_luks_volumes(yuzu::CommandContext& ctx) {
    // sink: bitlocker/list_luks_volumes#1 — rung 1, in-process libblkid
    // enumeration replacing the `lsblk` subprocess; open-state comes from a
    // plain /sys read (sink#2 below), replacing `cryptsetup status`.
    auto devices = enumerate_luks_devices();
    if (devices.empty()) {
        ctx.write_output("volume|none|no_encrypted_volumes");
        return;
    }

    // sink: bitlocker/list_luks_volumes#2 — rung 1, plain /sys file reads,
    // no subprocess.
    auto mappings = enumerate_dm_mappings();
    for (const auto& dev : devices) {
        bool active = yuzu::bitlocker::linux_dm::has_open_mapping(dev, mappings);
        ctx.write_output(yuzu::bitlocker::linux_dm::format_volume_row(dev.dev_name, active));
    }
}

#elif defined(__APPLE__)

// Emits the honest per-volume FileVault/encryption status. Two signals:
//  - `fdesetup status` — a global on/off read, retained unconditionally as a
//    corroborating signal AND as the fallback when diskutil parsing below
//    yields no volumes (e.g. diskutil unavailable, unexpected output shape).
//  - `diskutil apfs list` — enumerated per APFS volume, parsed by the pure
//    header so it stays fixture-testable. Encryption is binary
//    (encrypted/not_encrypted/unknown) — APFS has no meaningful
//    percentage-encrypted to report, unlike BitLocker's conversion-in-
//    progress state, so none is fabricated here.
void report_filevault_status(yuzu::CommandContext& ctx) {
    // sink: bitlocker/report_filevault_status#1 — rung 2, clean argv
    // through the bounded runner (no shell).
    auto fdesetup_output = run_macos_tool({"/usr/bin/fdesetup", "status"}, "fdesetup status");
    if (fdesetup_output.find("On") != std::string::npos ||
        fdesetup_output.find("FileVault is On") != std::string::npos) {
        ctx.write_output("filevault|enabled");
    } else if (fdesetup_output.find("Off") != std::string::npos ||
               fdesetup_output.find("FileVault is Off") != std::string::npos) {
        ctx.write_output("filevault|disabled");
    } else {
        // Route the raw fdesetup text through safe_output_field (plg-L1): even
        // though bitlocker is a key|value plugin (a literal '|' stays in the
        // value), a multi-line fdesetup diagnostic would otherwise inject a row
        // past write_output's newline framing.
        ctx.write_output(
            std::format("filevault|unknown|{}", yuzu::util::safe_output_field(fdesetup_output)));
    }

    // sink: bitlocker/report_filevault_status#2 — rung 2, clean argv
    // through the bounded runner (no shell).
    auto diskutil_output = run_macos_tool({"/usr/bin/diskutil", "apfs", "list"}, "diskutil apfs list");
    auto volumes = yuzu::bitlocker::macos::parse_diskutil_apfs_list(diskutil_output);
    for (const auto& vol : volumes) {
        // plg-L1 (round-4 review): escape every dynamic field before the positional
        // `volume|...` protocol — an APFS volume label/type/state with a '|' or
        // newline would otherwise shift columns or inject a row (same fix already
        // applied to the fdesetup diagnostic row above).
        ctx.write_output(
            std::format("volume|{}|{}|{}", yuzu::util::safe_output_field(yuzu::bitlocker::macos::volume_label(vol)),
                        yuzu::util::safe_output_field(yuzu::bitlocker::macos::volume_type(vol)),
                        yuzu::util::safe_output_field(vol.encrypted_state)));
    }
    // If diskutil yielded nothing parseable, the fdesetup row above already
    // served as the fallback signal — no synthetic "no volumes" row needed.
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: Win32_EncryptableVolume WMI query + per-volume
//   GetConversionStatus() method call, both in-process -- rung 1. Zero
//   subprocess (Wave-3 migration; was manage-bde via raw _popen at rung 3).
// linux: libblkid TYPE=="crypto_LUKS" enumeration + /sys/class/block/dm-*
//   uuid reads, both in-process -- rung 1. Zero subprocess (was
//   lsblk+cryptsetup via run_bounded_subprocess shell-c at rung 3).
// macos: fdesetup status + diskutil apfs list via the bounded runner, now
//   direct argv -- rung 2 (was the same two tools via a `/bin/sh -c`
//   shell wrapper at rung 3). Ships via bitlocker_macos_apfs.hpp's pure
//   parser, unchanged by this migration.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"state",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 1, "libblkid+sysfs", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "fdesetup+diskutil", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi_encryptable_volume", nullptr}},
};

} // namespace

class BitlockerPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "bitlocker"; }
    std::string_view version() const noexcept override { return "0.2.0"; }
    std::string_view description() const noexcept override {
        return "Disk encryption status — BitLocker, LUKS, FileVault";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

        if (action == "state") {
#ifdef _WIN32
            if (!report_bitlocker_status(ctx))
                return 1;
#elif defined(__linux__)
            list_luks_volumes(ctx);
#elif defined(__APPLE__)
            report_filevault_status(ctx);
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(BitlockerPlugin)
