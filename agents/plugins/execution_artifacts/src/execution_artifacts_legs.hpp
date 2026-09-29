#pragma once

/**
 * execution_artifacts_legs.hpp — the seam between this plugin's portable TU
 * (execution_artifacts_plugin.cpp) and its Windows-only leg TU (P32's
 * execution_artifacts_win.cpp). Modelled on disk_actions_legs.hpp /
 * filesystem_posture_legs.hpp, the established shape for a plugin whose
 * per-OS collection lives in a separate TU from its dispatch.
 *
 * This package (P31) declares the three entry points below and owns nothing
 * that calls a Windows API — P32 implements them. No Windows header is
 * included from this file, so it compiles unconditionally on every OS the
 * way disk_actions_legs.hpp does.
 *
 * EACH ENTRY POINT IS INDEPENDENT: a failure in one artefact source
 * (shimcache/amcache/prefetch) never blocks the other two — this plugin's
 * three actions are dispatched and gated separately (see this package's
 * spec: "each independently `constrained|<token>` on its own failure").
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::execution_artifacts {

// ── per-OS entry points (defined by P32's execution_artifacts_win.cpp) ────
//
// Each is a READ, gated behind the Forensics securable + AdminOrApproval at
// the server dispatch layer (this plugin performs no authz itself — see
// content/definitions/execution_artifacts.yaml). Each returns 0 on success
// and 1 on any constrained/unavailable outcome; the distinction between
// those two states is carried through ctx.set_result_status, not the return
// code (CC-07 contract, same as every other plugin in this repo).

int collect_shimcache(yuzu::CommandContext& ctx);
// `data_dir` is the agent's configured `agent.data_dir` -- the parent
// directory execution_artifacts_win.cpp's collect_amcache creates its
// per-dispatch random scratch directory under. Empty if unset, which
// collect_amcache reports as constrained|data_dir_unset (no fallback
// location); only the amcache leg needs it, since it's the only one that
// writes a scratch file to disk.
int collect_amcache(yuzu::CommandContext& ctx, std::string_view data_dir);
int collect_prefetch(yuzu::CommandContext& ctx);

// ── row formatters (pure, OS-free — shared by the leg TU and tests) ───────
//
// ROW SCHEMAS. Pipe-delimited, fixed field count per kind, matching this
// package's spec exactly:
//
//   shimcache|<path>|<last_modified_epoch_ms>|<data_size>|<insert_flag>
//   amcache|<lower_case_long_path>|<sha1>|<size>|<link_date>|<publisher>|
//     <binary_type>|<product_name>|<product_version>
//   prefetch|<exe_name>|<hash_hex>|<version>|<run_count>|<last_runs csv>|
//     <volume_count>|<file_ref_count>
//
// Every untrusted string field (paths, publisher/product text, exe names)
// goes through yuzu::util::safe_output_field — the shared escaper every
// other plugin in this repo uses for OS-supplied text in a pipe-delimited
// stream.

inline std::string format_shimcache_row(const std::string& path, int64_t last_modified_epoch_ms,
                                        uint32_t data_size) {
    return "shimcache|" + yuzu::util::safe_output_field(path) + "|" +
           std::to_string(last_modified_epoch_ms) + "|" + std::to_string(data_size) + "|-";
}

inline std::string format_amcache_row(const std::string& lower_case_long_path,
                                      const std::string& sha1, const std::string& size,
                                      const std::string& link_date, const std::string& publisher,
                                      const std::string& binary_type,
                                      const std::string& product_name,
                                      const std::string& product_version) {
    return "amcache|" + yuzu::util::safe_output_field(lower_case_long_path) + "|" + sha1 + "|" +
           yuzu::util::safe_output_field(size) + "|" + yuzu::util::safe_output_field(link_date) +
           "|" + yuzu::util::safe_output_field(publisher) + "|" +
           yuzu::util::safe_output_field(binary_type) + "|" +
           yuzu::util::safe_output_field(product_name) + "|" +
           yuzu::util::safe_output_field(product_version);
}

inline std::string format_prefetch_row(const std::string& exe_name, const std::string& hash_hex,
                                       uint32_t version, uint32_t run_count,
                                       const std::vector<int64_t>& last_runs_epoch_ms,
                                       uint32_t volume_count, uint32_t file_ref_count) {
    std::string last_runs;
    for (size_t i = 0; i < last_runs_epoch_ms.size(); ++i) {
        if (i)
            last_runs += ",";
        last_runs += std::to_string(last_runs_epoch_ms[i]);
    }
    return "prefetch|" + yuzu::util::safe_output_field(exe_name) + "|" + hash_hex + "|" +
           std::to_string(version) + "|" + std::to_string(run_count) + "|" + last_runs + "|" +
           std::to_string(volume_count) + "|" + std::to_string(file_ref_count);
}

// ── constrained/unsupported tokens ─────────────────────────────────────
//
// One named reason per class of failure, shared by the Windows leg and the
// non-Windows branch so a consumer sees the same vocabulary regardless of
// platform.

inline constexpr std::string_view kUnsupportedWindowsOnly = "windows_only_artefact";

} // namespace yuzu::execution_artifacts
