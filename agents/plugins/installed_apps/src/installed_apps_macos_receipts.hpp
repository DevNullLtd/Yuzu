#pragma once

#if defined(__APPLE__)

/**
 * installed_apps_macos_receipts.hpp — in-process macOS installer-receipt
 * (.plist) reads, REPLACING a `pkgutil --pkg-info <id>` subprocess spawn for
 * the common case (round-3 sync-speed fix, item 4). `pkgutil --pkgs` stays
 * the authoritative receipt-id ENUMERATION (one spawn, unchanged) — this
 * header only replaces the PER-ID lookup that follows it, which is the part
 * that fans out to dozens/hundreds of subprocess spawns on a real Mac.
 *
 * Every failure mode (missing file, undecodable plist, wrong value types,
 * missing keys) returns std::nullopt rather than a partial result — the
 * caller (installed_apps_plugin.cpp) falls back to the EXISTING `pkgutil
 * --pkg-info` spawn unconditionally on a miss, so the two paths are
 * guaranteed byte-identical from the caller's point of view: this is a speed
 * optimisation, never a second source of truth for the wire format.
 *
 * CFPropertyListCreateWithData usage mirrors autoruns_macos.cpp's
 * parse_plist_root (the established pattern for this exact API in this
 * codebase) — see that file's own doc comment for the ScopedCFRef contract
 * this relies on.
 */

#include "installed_apps_parsers.hpp" // PkgutilInfo — reused verbatim so a receipt-plist
                                      // read and a pkgutil spawn are indistinguishable to
                                      // the caller.

#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::installed_apps::macos_receipts {

namespace detail {

// Adopts a +1 CFPropertyListRef from CFPropertyListCreateWithData over an
// in-memory buffer — copy of autoruns_macos.cpp's parse_plist_root.
inline bool parse_plist_root(const std::vector<std::uint8_t>& bytes,
                             yuzu::agent::ScopedCFRef<CFPropertyListRef>& out) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(
        CFDataCreate(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size())));
    if (!data)
        return false;
    CFErrorRef raw_error = nullptr;
    out = yuzu::agent::ScopedCFRef<CFPropertyListRef>(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error);
    return static_cast<bool>(out);
}

// CFAbsoluteTime (seconds since 2001-01-01 UTC) -> pkgutil's own
// "install-time" string shape (whole UNIX-epoch seconds, no fractional part).
// TRUNCATES rather than rounds — verified against a real fixture:
// /Library/Apple/System/Library/Receipts/com.apple.pkg.CLTools_Executables.
// plist's InstallDate carries a sub-second fraction that `pkgutil --pkg-info`
// reports as install-time 1787153822 — llround() on that same value gives
// 1787153823, one second later, which does not cross-pin. Truncation matches
// pkgutil's own conversion exactly. `static_cast<long long>` truncates toward
// ZERO, not toward -infinity (floor) — the two diverge only for a negative
// (pre-1970) `unix_secs`, which no real receipt can carry.
inline std::string cfdate_to_unix_epoch_string(CFDateRef date) {
    const CFAbsoluteTime abs_time = CFDateGetAbsoluteTime(date);
    const double unix_secs = abs_time + kCFAbsoluteTimeIntervalSince1970;
    return std::to_string(static_cast<long long>(unix_secs));
}

// Whole-file read via plain stdio (no mmap needed — receipt plists are a few
// hundred bytes to a few KB). Returns an empty vector on any I/O failure.
inline std::vector<std::uint8_t> read_whole_file(const std::string& path) {
    // RAII-owned so a `bad_alloc` out of `out.insert` (or any future early return
    // added to this loop) can never unwind past an open `FILE*` (governance Gate 3
    // policy floor: manual fopen/fclose pairing here previously leaked on that path).
    std::unique_ptr<FILE, decltype(&std::fclose)> f(std::fopen(path.c_str(), "rb"),
                                                     &std::fclose);
    std::vector<std::uint8_t> out;
    if (!f)
        return out;
    std::uint8_t buf[8192];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f.get())) > 0)
        out.insert(out.end(), buf, buf + n);
    return out;
}

} // namespace detail

/// The two directories macOS stores installer receipts in — a package
/// installed by a first-party .pkg lands in the first; one delivered via
/// softwareupdated (e.g. Command Line Tools) lands in the second. Tried in
/// order; the first hit wins.
inline const char* const kReceiptDirs[] = {
    "/var/db/receipts/",
    "/Library/Apple/System/Library/Receipts/",
};

/// Parses an already-in-memory receipt .plist (bytes) into PackageVersion +
/// InstallDate. Pure over its input — no file I/O — so a unit test can feed
/// it a REAL captured receipt's bytes without needing root or a live
/// /var/db/receipts path. Returns nullopt on ANY decode failure: undecodable
/// plist, wrong root type, missing/wrong-typed keys.
[[nodiscard]] inline std::optional<yuzu::installed_apps::parsers::PkgutilInfo>
parse_receipt_plist_bytes(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty())
        return std::nullopt;

    yuzu::agent::ScopedCFRef<CFPropertyListRef> root;
    if (!detail::parse_plist_root(bytes, root))
        return std::nullopt;
    if (CFGetTypeID(root.get()) != CFDictionaryGetTypeID())
        return std::nullopt;
    const auto dict = static_cast<CFDictionaryRef>(root.get());

    // Get Rule (borrowed, not owned) — no ScopedCFRef for these two.
    const auto version_val =
        static_cast<CFStringRef>(CFDictionaryGetValue(dict, CFSTR("PackageVersion")));
    const auto date_val = static_cast<CFDateRef>(CFDictionaryGetValue(dict, CFSTR("InstallDate")));
    if (!version_val || CFGetTypeID(version_val) != CFStringGetTypeID())
        return std::nullopt;
    if (!date_val || CFGetTypeID(date_val) != CFDateGetTypeID())
        return std::nullopt;

    // Real package versions are short ASCII (e.g. "26.6.0.0.1781586589");
    // 512 bytes is generous. A version that somehow doesn't fit is treated
    // as a miss (falls back to the pkgutil spawn), never truncated silently.
    char version_buf[512];
    if (!CFStringGetCString(version_val, version_buf, sizeof(version_buf), kCFStringEncodingUTF8))
        return std::nullopt;

    yuzu::installed_apps::parsers::PkgutilInfo info;
    info.version = version_buf;
    info.install_time = detail::cfdate_to_unix_epoch_string(date_val);
    return info;
}

/// Reads one receipt id's PackageVersion + InstallDate directly from its
/// .plist. `id` MUST already be validated by the caller the way
/// installed_apps_plugin.cpp already does before any pkgutil call (rejecting
/// an option-like id starting with '-') — this function additionally refuses
/// any id containing '/' or ".." so a corrupt `pkgutil --pkgs` listing can
/// never escape the two fixed receipt directories via a crafted id.
[[nodiscard]] inline std::optional<yuzu::installed_apps::parsers::PkgutilInfo>
read_receipt_plist(const std::string& id) {
    if (id.empty() || id.find('/') != std::string::npos || id.find("..") != std::string::npos)
        return std::nullopt;

    for (const char* dir : kReceiptDirs) {
        auto info = parse_receipt_plist_bytes(detail::read_whole_file(dir + id + ".plist"));
        if (info)
            return info;
    }
    return std::nullopt;
}

} // namespace yuzu::installed_apps::macos_receipts

#endif // __APPLE__
