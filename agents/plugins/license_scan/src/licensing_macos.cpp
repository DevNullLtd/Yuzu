/**
 * licensing_macos.cpp — macOS detection surfaces for the license_scan plugin
 * (SLE roadmap §5 PR1 detection-surface table; ADR-0024 Decision 2).
 *
 * Surfaces (probe_status tokens):
 *   mas_receipt   — /Applications/*.app/Contents/_MASReceipt/receipt presence
 *                   + Info.plist identity (probable: App Store purchased).
 *                   Identity comes from the XML-plist reader in
 *                   licensing_parsers.hpp; a BINARY Info.plist (bplist00)
 *                   falls back to the .app bundle name with an honest-empty
 *                   version — parsing binary plists without a Mac to verify
 *                   against is not attempted (deliberately lean; recorded in
 *                   the implementation report).
 *   vendor_plists — machine-scope vendor plists via the ProbeSpec table
 *                   (Office volume licence plist, Parallels) — presence
 *                   probes only (probable/heuristic); the payloads are
 *                   binary plists.
 *
 * The receipt itself is a PKCS#7 blob; validating it is Apple-private
 * behaviour and is NOT attempted — presence + bundle identity is the v1
 * yield (surface table: "App Store/retail licensed", probable).
 */

#ifdef __APPLE__

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

namespace {

std::string bundle_name_from_app_path(const std::string& app_path) {
    // ".../Foo.app" -> "Foo"
    const auto last_sep = app_path.find_last_of('/');
    std::string base =
        last_sep == std::string::npos ? app_path : app_path.substr(last_sep + 1);
    if (base.size() > 4 && base.compare(base.size() - 4, 4, ".app") == 0)
        base.resize(base.size() - 4);
    return base;
}

void run_mas_receipt_surface(ProbeHost& host, std::vector<LicRecord>& records,
                             std::vector<ProbeOutcome>& outcomes) {
    std::size_t emitted = 0;
    for (const auto& receipt : host.glob("/Applications/*.app/Contents/_MASReceipt/receipt")) {
        // ".../Foo.app/Contents/_MASReceipt/receipt" -> ".../Foo.app"
        static constexpr std::string_view kSuffix = "/Contents/_MASReceipt/receipt";
        if (receipt.size() <= kSuffix.size())
            continue;
        const std::string app_path = receipt.substr(0, receipt.size() - kSuffix.size());

        LicRecord r;
        r.vendor = ""; // unknown — never synthesised
        const auto info = host.read_file_prefix(app_path + "/Contents/Info.plist", 256 * 1024);
        if (info && info->rfind("bplist00", 0) != 0) {
            // XML plist: read the bundle identity directly.
            r.product = plist_string_value(*info, "CFBundleDisplayName");
            if (r.product.empty())
                r.product = plist_string_value(*info, "CFBundleName");
            r.version = plist_string_value(*info, "CFBundleShortVersionString");
        }
        if (r.product.empty())
            r.product = bundle_name_from_app_path(app_path); // binary-plist fallback
        if (r.product.empty())
            continue;
        r.license_type = "retail"; // an App Store purchase receipt
        r.status = "licensed";
        r.source = "app_receipt";
        r.confidence = "probable";
        records.push_back(std::move(r));
        ++emitted;
    }
    outcomes.push_back({"mas_receipt", true, emitted, {}});
}

} // namespace

// ── the macOS run ───────────────────────────────────────────────────────────

SurfaceRun run_platform_surfaces() {
    SurfaceRun run;
    ProbeHost host; // filesystem defaults; no registry on macOS

    run_mas_receipt_surface(host, run.records, run.outcomes);

    // Machine-scope vendor plists ride the ProbeSpec table (vendor_plists).
    run_probe_specs(host, Platform::macos_os, Scope::machine, run.records, run.outcomes);

    return run;
}

} // namespace yuzu::license_scan

#endif // __APPLE__
