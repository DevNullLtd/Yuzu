/**
 * license_scan_plugin.cpp — software licence detection plugin for Yuzu
 * (SLE capability §27; ADR-0024 Decision 2; roadmap §5 PR1 file-table row 5).
 *
 * Actions:
 *   "list"     — Run every detection surface for this OS and emit the §3.1
 *                `lic|` records, then one `probe_status|` line per surface
 *                attempted. The software_licensing sync source (PR1a step 6)
 *                consumes this via LocalDispatcher: records feed the
 *                canonical blob; the probe_status lines feed the
 *                empty-vs-error structural guard (ADR-0024 D3) and NEVER
 *                enter the blob.
 *   "surfaces" — Emit ONLY the `probe_status|` diagnostics, including
 *                availability reasons (e.g. `privilege_missing` when
 *                SeBackup/SeRestore are stripped — roadmap R15). This is the
 *                live diagnostics path for the /sle/agents/{id} drill
 *                (ADR-0024 D-10); flappy surface state stays live-only.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   lic|product|vendor|version|license_type|channel|status|expires_at|source|
 *       confidence|key_hint|exe_hints|user_scope|user_ref
 *   probe_status|<surface>|ok|<rows>
 *   probe_status|<surface>|error|<message>
 *
 * Every field passes the §3.3 layer-1 sanitiser (strip `|` CR LF 0x1F 0x1E
 * NUL, clamp 1024 B) in licensing_record.hpp before emission. Vocabularies
 * are closed and unknown-preserving (§3.2) — the plugin never fabricates.
 * Licence key material is never persisted or transmitted: key_hint is an
 * OS-provided partial key or a hash prefix (ADR-0024 D2). user_ref is a
 * local profile name or empty — never a SID (ADR-0024 D11).
 *
 * `ent|` entitlement records (FlexLM seat counts, KMS activation counts) are
 * deliberately NOT emitted here — they are PR2 scope (ADR-0024 D12).
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string_view>
#include <vector>

#include "licensing_probes.hpp"
#include "licensing_record.hpp"

namespace {

yuzu::license_scan::SurfaceRun collect_surfaces() {
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    return yuzu::license_scan::run_platform_surfaces();
#else
    yuzu::license_scan::SurfaceRun run;
    run.outcomes.push_back({"platform", false, 0, "unsupported_platform"});
    return run;
#endif
}

// Governance Gate 4 (unhappy-path UP-1): before this, NEITHER do_list() nor
// do_surfaces() ever called ctx.set_result_status() -- every surface could
// error and the call would still report rc 0 with no ABI4 status set at all.
// This is LESS severe than it first looks: the daily-sync consumer
// (sync_source_software_licensing.cpp) deliberately does NOT read the ABI4
// seam for this plugin -- it parses the probe_status| TEXT lines directly
// (ADR-0024 D3's "empty-vs-error structural guard"), and entitlement_certs is
// on its kAuthoritativeSurfaces list, so a genuine failure there already
// correctly blocks a full-replace-to-empty via that path, unaffected by this
// fix. What was missing is the OTHER, machine-readable channel: any consumer
// that reads rc/status directly (a live "Get info" dispatch, a future
// integration) rather than parsing text would see a false-clean result. Added
// for consistency with software_actions' use of the same seam in this same
// PR -- rc intentionally stays 0 either way (ADR-0024 D3: "success" is
// structural, the enumeration sweep itself completed; the existing
// test_license_scan_actions.cpp test already pins rc==0 as part of the
// documented contract, unaffected by this change).
void propagate_surface_status(yuzu::CommandContext& ctx,
                              const std::vector<yuzu::license_scan::ProbeOutcome>& outcomes) {
    for (const auto& outcome : outcomes) {
        if (!outcome.ok) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "license_scan:surface_error");
            return;
        }
    }
}

int do_list(yuzu::CommandContext& ctx) {
    const auto run = collect_surfaces();
    // §3.1 emission order: all lic| records first, then one probe_status|
    // line per surface attempted. No sentinel row on an empty result — zero
    // records with ok statuses IS the legitimate empty state (ADR-0024 D3).
    for (const auto& record : run.records)
        ctx.write_output(yuzu::license_scan::render_lic_line(record));
    for (const auto& outcome : run.outcomes)
        ctx.write_output(yuzu::license_scan::render_probe_status_line(outcome));
    propagate_surface_status(ctx, run.outcomes);
    return 0;
}

int do_surfaces(yuzu::CommandContext& ctx) {
    const auto run = collect_surfaces();
    // Diagnostics only — records are deliberately suppressed (live path,
    // D-10): which surfaces are available and why not.
    for (const auto& outcome : run.outcomes)
        ctx.write_output(yuzu::license_scan::render_probe_status_line(outcome));
    propagate_surface_status(ctx, run.outcomes);
    return 0;
}

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order. Both actions call
// the SAME collect_surfaces() -> run_platform_surfaces() (licensing_probes.cpp
// dispatches by #if defined(_WIN32)/__linux__/__APPLE__), so both share
// identical legs:
//   - Windows (licensing_win.cpp run_platform_surfaces): SLP via the WMI
//     enumerator, registry ProbeSpec rows, and per-user hive/file probes —
//     every one a native, in-process Win32/COM call (rung 1).
//   - Linux (licensing_linux.cpp run_platform_surfaces): pkg_metadata
//     (rpm/dpkg-query) and entitlement_certs (openssl x509) now go through
//     the shared bounded argv runner (rung 2, run_bounded_subprocess) — no
//     shell, no popen (Wave 4 PR4.3b migration). DEMOTED to CONSTRAINED (was
//     SUPPORTED at rung 3) by a deliberate Alex/K-review decision, not a
//     regression in what the surfaces do: pkg_metadata was always a
//     declared-licence CLASSIFICATION only (no lapse detection — a gap
//     independent of the acquisition mechanism, see the file's own header
//     comment), and entitlement_certs' authoritative expiry still depends on
//     the openssl CLI being present on the host.
//   - macOS (licensing_macos.cpp run_platform_surfaces): pure filesystem
//     glob + in-house XML-plist string parsing, no exec at all (rung 1). The
//     header's own doc comment records the real limitation: a BINARY
//     (bplist00) Info.plist is not parsed and falls back to the bundle name
//     with an empty version — CONSTRAINED, not SUPPORTED.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        "list",
        {YUZU_SUPPORT_CONSTRAINED, 2, "rpm/dpkg-query/openssl via bounded argv runner",
         "declared-licence classification only (no lapse detection) for pkg_metadata; "
         "entitlement_certs' authoritative expiry still depends on the openssl CLI being "
         "present"},
        {YUZU_SUPPORT_CONSTRAINED, 1, "filesystem_probe(glob+plist)",
         "binary (bplist00) Info.plist files are not parsed; falls back to the bundle "
         "name with an empty version"},
        {YUZU_SUPPORT_SUPPORTED, 1, "wmi+win32_registry", nullptr},
    },
    {
        "surfaces",
        {YUZU_SUPPORT_CONSTRAINED, 2, "rpm/dpkg-query/openssl via bounded argv runner",
         "declared-licence classification only (no lapse detection) for pkg_metadata; "
         "entitlement_certs' authoritative expiry still depends on the openssl CLI being "
         "present"},
        {YUZU_SUPPORT_CONSTRAINED, 1, "filesystem_probe(glob+plist)",
         "binary (bplist00) Info.plist files are not parsed; falls back to the bundle "
         "name with an empty version"},
        {YUZU_SUPPORT_SUPPORTED, 1, "wmi+win32_registry", nullptr},
    },
};

} // namespace

class LicenseScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "license_scan"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Detects software licences across OS, vendor and per-user surfaces";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "surfaces", nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "surfaces")
            return do_surfaces(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(LicenseScanPlugin)
