/**
 * update_source_trust_macos_parsers.hpp -- the INJECTED-ROOT read shell for the
 * macOS leg: Software Update policy facts from
 *   <root>/Library/Preferences/com.apple.SoftwareUpdate.plist          (local)
 *   <root>/Library/Managed Preferences/com.apple.SoftwareUpdate.plist  (managed)
 *
 * NOVEL SEAM. The peripherals `_at(root, ...)` precedent is Linux-only
 * (peripherals_macos.cpp has no root seam); `swu_rows_at` is new design, so it
 * carries its own absent / EACCES / unparseable tests in P1d-2's tree suite.
 *
 * PLIST PARSING. A PRIVATE per-plugin copy of the established CoreFoundation
 * template (run-context decision 3; no cross-workstream shared helper):
 *   - agents/plugins/installed_apps/src/installed_apps_macos_receipts.hpp:47-58
 *     (`detail::parse_plist_root` -- CFDataCreate -> CFPropertyListCreateWithData,
 *     ScopedCFRef-owned; its own comment says it copies autoruns), and
 *   - agents/plugins/autoruns/src/autoruns_macos.hpp:113-132 (typed
 *     CFDictionaryGetValueIfPresent + CFGetTypeID getters that leave a
 *     wrong-typed value unmodelled instead of crashing).
 * The root is type-checked with CFDictionaryGetTypeID() before any getter runs.
 * Never a hand-rolled scanner and never os_info_macos.hpp (that one is a
 * substring scanner over trusted flat XML, the wrong tool for MDM-authored
 * content).
 *
 * The plist is read from disk directly, not through cfprefsd, so a value
 * cfprefsd has cached but not yet flushed is not seen; this is a config-file
 * read like every other leg of this plugin (rung 1).
 *
 * PROVENANCE OF WHAT IS VERIFIED. The `local` scope is verified against a REAL
 * CAPTURE of this Mac's com.apple.SoftwareUpdate.plist. The `managed` scope has
 * NEVER run against a real MDM-managed host in this run: it is verified against
 * a RECONSTRUCTION built from Apple's documented Software Update payload keys
 * (see tests/unit/fixtures/wave10/update_source_trust/provenance.txt), which is
 * why the descriptor stays CONSTRAINED.
 *
 * Outcomes (same contract as the Linux leg): a missing plist is zero rows and
 * still supported; a permission/symlink/oversize/read failure or an
 * undecodable plist is a `macos:swu_<scope>:<detail>` token on the
 * ConstraintAccumulator -- failure never reads as absent.
 *
 * On a non-Apple host parse_swu_plist_bytes cannot decode a plist and reports
 * the parse as unavailable (a present file therefore yields `unparseable`,
 * never fabricated facts); the absent/permission paths are host-independent.
 */
#pragma once

#if !defined(_WIN32)

#include "update_source_trust_linux_parsers.hpp" // posix_io read primitives (POSIX, not Linux-only)
#include "update_source_trust_parsers.hpp"

#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <vector>
#endif

#include <constraint_accumulator.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::update_source_trust::mac {

namespace pio = yuzu::update_source_trust::posix_io;

inline constexpr std::string_view kSwuLocalPrefix = "macos:swu_local";
inline constexpr std::string_view kSwuManagedPrefix = "macos:swu_managed";

#if defined(__APPLE__)

namespace detail {

// Adopts a +1 CFPropertyListRef from CFPropertyListCreateWithData over an
// in-memory buffer -- private copy of installed_apps_macos_receipts.hpp's
// parse_plist_root (itself a copy of autoruns_macos.cpp's).
inline bool parse_plist_root(std::string_view bytes,
                             yuzu::agent::ScopedCFRef<CFPropertyListRef>& out) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(CFDataCreate(
        kCFAllocatorDefault, reinterpret_cast<const UInt8*>(bytes.data()),
        static_cast<CFIndex>(bytes.size())));
    if (!data)
        return false;
    CFErrorRef raw_error = nullptr;
    out = yuzu::agent::ScopedCFRef<CFPropertyListRef>(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error);
    return static_cast<bool>(out);
}

inline std::optional<std::string> cfstring_to_utf8(CFStringRef s) {
    if (s == nullptr)
        return std::nullopt;
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max_bytes = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::vector<char> buf(static_cast<std::size_t>(max_bytes));
    if (!CFStringGetCString(s, buf.data(), max_bytes, kCFStringEncodingUTF8))
        return std::nullopt;
    return std::string{buf.data()};
}

/// absent -> unset; CFBoolean -> yes/no; any other CF type -> unmodelled.
inline Tri dict_tri(CFDictionaryRef dict, CFStringRef key) {
    const void* v = nullptr;
    if (!CFDictionaryGetValueIfPresent(dict, key, &v))
        return Tri::unset;
    const auto ref = static_cast<CFTypeRef>(v);
    if (ref == nullptr || CFGetTypeID(ref) != CFBooleanGetTypeID())
        return Tri::unmodelled;
    return CFBooleanGetValue(static_cast<CFBooleanRef>(ref)) != 0 ? Tri::yes : Tri::no;
}

/// absent -> ""; CFString -> its UTF-8 text; any other CF type (or an
/// unconvertible string) -> "unmodelled".
inline std::string dict_string(CFDictionaryRef dict, CFStringRef key) {
    const void* v = nullptr;
    if (!CFDictionaryGetValueIfPresent(dict, key, &v))
        return {};
    const auto ref = static_cast<CFTypeRef>(v);
    if (ref == nullptr || CFGetTypeID(ref) != CFStringGetTypeID())
        return "unmodelled";
    auto s = cfstring_to_utf8(static_cast<CFStringRef>(ref));
    return s ? *s : std::string{"unmodelled"};
}

} // namespace detail

/// Decodes one com.apple.SoftwareUpdate plist (XML or binary) into SwuFacts.
/// nullopt when the bytes are not a decodable plist or the root is not a
/// dictionary. Pure over its input -- no file I/O.
[[nodiscard]] inline std::optional<SwuFacts> parse_swu_plist_bytes(std::string_view bytes) {
    yuzu::agent::ScopedCFRef<CFPropertyListRef> root;
    if (!detail::parse_plist_root(bytes, root))
        return std::nullopt;
    if (CFGetTypeID(root.get()) != CFDictionaryGetTypeID())
        return std::nullopt;
    const auto dict = static_cast<CFDictionaryRef>(root.get());

    SwuFacts f;
    f.catalog_url = detail::dict_string(dict, CFSTR("CatalogURL"));
    f.auto_check = detail::dict_tri(dict, CFSTR("AutomaticCheckEnabled"));
    f.auto_download = detail::dict_tri(dict, CFSTR("AutomaticDownload"));
    f.auto_install_macos = detail::dict_tri(dict, CFSTR("AutomaticallyInstallMacOSUpdates"));
    f.config_data_install = detail::dict_tri(dict, CFSTR("ConfigDataInstall"));
    f.critical_update_install = detail::dict_tri(dict, CFSTR("CriticalUpdateInstall"));
    f.allow_prerelease = detail::dict_tri(dict, CFSTR("AllowPreReleaseInstallation"));
    return f;
}

#else // !__APPLE__ -- no CoreFoundation: a plist cannot be decoded here

[[nodiscard]] inline std::optional<SwuFacts> parse_swu_plist_bytes(std::string_view) {
    return std::nullopt;
}

#endif // __APPLE__

namespace detail_walk {

inline void add_swu_scope(const std::filesystem::path& root, std::string_view logical,
                          SwuScope scope, std::vector<std::string>& rows,
                          yuzu::shared::ConstraintAccumulator& acc) {
    const std::string_view prefix = scope == SwuScope::managed ? kSwuManagedPrefix : kSwuLocalPrefix;
    std::string data;
    std::uint64_t size = 0;
    if (pio::read_file(pio::under(root, logical), pio::kMaxFileBytes, false, data, size, acc,
                       prefix) != pio::Outcome::ok)
        return; // absent -> zero rows for this scope; failed -> token already recorded
    const auto facts = parse_swu_plist_bytes(data);
    if (!facts) {
        pio::note_failure(acc, prefix, "unparseable");
        return;
    }
    rows.push_back(format_swu_row(scope, *facts));
}

} // namespace detail_walk

/// Software Update policy rows under `root`: the local plist first, then the
/// managed (MDM-delivered) one. A host with neither returns zero rows and no
/// failure token.
[[nodiscard]] inline std::vector<std::string>
swu_rows_at(const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> rows;
    detail_walk::add_swu_scope(root, "/Library/Preferences/com.apple.SoftwareUpdate.plist",
                               SwuScope::local, rows, acc);
    detail_walk::add_swu_scope(root, "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist",
                               SwuScope::managed, rows, acc);
    return rows;
}

} // namespace yuzu::update_source_trust::mac

#endif // !defined(_WIN32)
