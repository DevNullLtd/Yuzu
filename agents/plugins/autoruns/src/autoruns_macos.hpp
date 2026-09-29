/**
 * autoruns_macos.hpp — header-only CoreFoundation plist read for the macOS
 * autoruns leg (P14).
 *
 * `plist_to_launchd_fields` is the ONE CF-touching function this leg exposes
 * outside its own dylib TU. `agent_test_exe` already links CoreFoundation
 * directly (tests/meson.build:83) and gets this plugin's include dir wired
 * in (IT-WIRING), so tests/unit/test_autoruns_macos_local.cpp calls this
 * function directly against A2's REAL CAPTURE plist fixtures — a symbol
 * inside the dlopen'd autoruns plugin is NOT reachable from the test binary
 * (tests/meson.build:466/:593 give plugins include dirs + link_depends
 * only, never a callable symbol), so the one function real fixtures must
 * exercise has to live here, inline, rather than in autoruns_macos.cpp.
 *
 * Apple-only body; an always-error stub on every other OS keeps this header
 * includable (and its one declaration checkable) from a portable context
 * without a target guard at every call site.
 */
#pragma once

#include "autoruns_parsers.hpp" // LaunchdFields

#include <cerrno>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <string>
#include <vector>
#endif

namespace yuzu::autoruns {

/// A launchd/emond plist that CFPropertyListCreateWithData could not parse
/// at all, or that parsed to something other than the shape the caller
/// needed. One value: this plugin never tries to distinguish CF's own error
/// reasons (malformed XML vs. truncated binary vs. wrong root type) any
/// further than "not usable" — the caller counts it and moves on; it never
/// crashes and never fabricates a Row from it.
enum class PlistError { unparseable };

/// True when `err` (an errno from open/openat/fdopendir on a path this leg
/// walks) reflects a genuinely-absent location -- not a permission failure,
/// not a symlink refused by O_NOFOLLOW, not a resource limit, not a path
/// component that turned out not to be a directory. Only ENOENT is benign:
/// every other errno is a real constraint the caller must surface via a
/// `constrained` status + reason, never silently folded into "zero rows"
/// (autoruns' own acceptance criterion: an unreadable location yields
/// constrained + reason, never an empty success -- failure != empty).
/// Portable (plain errno arithmetic, no CF dependency) so it is testable
/// without an Apple-only build.
inline bool is_benign_absent_errno(int err) noexcept { return err == ENOENT; }

/// `errno` from a failed `open`/`openat`/`fdopendir` on a directory this leg
/// walks -> a stable reason token for a `constrained` source status. Only
/// called once the caller has already ruled out is_benign_absent_errno --
/// there is no "absent" case here, every value is a real constraint.
/// Portable (plain errno arithmetic, no CF dependency) so it is testable
/// without an Apple-only build.
inline std::string_view dir_open_constraint_token(int err) noexcept {
    switch (err) {
        case EACCES: return "permission_denied";
        case ELOOP: return "symlink_refused";
        case ENOTDIR: return "not_a_directory";
        default: return "dir_open_failed";
    }
}

/// `errno` from a failed `fstat`/`fstatat` metadata read on a directory
/// entry this leg is walking (issue #4241) -> a stable reason token, or
/// nullopt when the failure is benign (ENOENT: the entry vanished between
/// listing and the stat call -- a race, not a real acquisition failure,
/// matching is_benign_absent_errno's own absence contract). A non-benign
/// failure must never be silently folded into "this entry contributed
/// nothing" (AC4: failure != empty) -- the caller routes a non-nullopt
/// result through its constraint accumulator. Distinct token set from
/// dir_open_constraint_token: ENOTDIR does not apply (the entry's own type
/// was never assumed before the stat call), so any other errno maps to the
/// generic "stat_failed" rather than reusing "dir_open_failed". Portable,
/// same reason as dir_open_constraint_token above.
inline std::optional<std::string_view> stat_constraint_token(int err) noexcept {
    if (is_benign_absent_errno(err)) return std::nullopt;
    switch (err) {
        case EACCES: return "permission_denied";
        case ELOOP: return "symlink_refused";
        default: return "stat_failed";
    }
}

#if defined(__APPLE__)

namespace detail {

inline std::string cfstring_to_utf8(CFStringRef s) {
    if (s == nullptr) return {};
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max_bytes = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::vector<char> buf(static_cast<std::size_t>(max_bytes));
    if (!CFStringGetCString(s, buf.data(), max_bytes, kCFStringEncodingUTF8)) return {};
    return std::string{buf.data()};
}

/// The string value of `key` in `dict`, or nullopt when the key is absent OR
/// present with a non-CFString type — a plist field in the "wrong" shape is
/// left unmodelled at the caller, never a crash from an unchecked cast.
inline std::optional<std::string> dict_get_string(CFDictionaryRef dict, CFStringRef key) {
    const void* v = nullptr;
    if (!CFDictionaryGetValueIfPresent(dict, key, &v)) return std::nullopt;
    const auto ref = static_cast<CFTypeRef>(v);
    if (ref == nullptr || CFGetTypeID(ref) != CFStringGetTypeID()) return std::nullopt;
    return cfstring_to_utf8(static_cast<CFStringRef>(ref));
}

inline std::optional<bool> dict_get_bool(CFDictionaryRef dict, CFStringRef key) {
    const void* v = nullptr;
    if (!CFDictionaryGetValueIfPresent(dict, key, &v)) return std::nullopt;
    const auto ref = static_cast<CFTypeRef>(v);
    if (ref == nullptr || CFGetTypeID(ref) != CFBooleanGetTypeID()) return std::nullopt;
    return CFBooleanGetValue(static_cast<CFBooleanRef>(ref)) != 0;
}

/// `ProgramArguments` is an array of strings; a non-array value, or an array
/// element that is not itself a string, is skipped rather than guessed at —
/// an unmodelled shape here degrades to "fewer entries", never a crash.
inline std::vector<std::string> dict_get_string_array(CFDictionaryRef dict, CFStringRef key) {
    std::vector<std::string> out;
    const void* v = nullptr;
    if (!CFDictionaryGetValueIfPresent(dict, key, &v)) return out;
    const auto ref = static_cast<CFTypeRef>(v);
    if (ref == nullptr || CFGetTypeID(ref) != CFArrayGetTypeID()) return out;
    const auto arr = static_cast<CFArrayRef>(ref);
    const CFIndex count = CFArrayGetCount(arr);
    for (CFIndex i = 0; i < count; ++i) {
        const auto elem_ref = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(arr, i));
        if (elem_ref != nullptr && CFGetTypeID(elem_ref) == CFStringGetTypeID())
            out.push_back(cfstring_to_utf8(static_cast<CFStringRef>(elem_ref)));
    }
    return out;
}

} // namespace detail

/// Parses `bytes` (an XML or binary plist — CFPropertyListCreateWithData
/// treats both identically) and extracts the launchd keys P11's LaunchdFields
/// models. A parse failure, or a plist whose root is not a dictionary,
/// returns PlistError::unparseable; any INDIVIDUAL field present in the
/// wrong CF type is left at LaunchdFields' own default rather than aborting
/// the whole read (see the dict_get_* helpers above).
///
/// SCOPE NOTE: the objective also names RunAtLoad/KeepAlive/StartInterval/
/// StartCalendarInterval as keys to read for the enablement judgement.
/// LaunchdFields (autoruns_parsers.hpp, P11, outside this package's
/// `owned_files`) carries no members for them, and this package's boundary
/// forbids extending that header ("No parser changes in P11's header (flag
/// gaps)"). `launchd_row_from_fields` already documents its own enablement
/// rule — Disabled present drives the value, Disabled absent is always
/// `enabled` ("launchd's own documented default") — which those four keys
/// cannot change either way, so their absence from LaunchdFields is not a
/// functional gap for the Enabled column, only a divergence from the
/// objective's literal key list. Flagged here rather than silently dropped.
inline std::expected<LaunchdFields, PlistError>
plist_to_launchd_fields(std::span<const uint8_t> bytes) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(
        CFDataCreate(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size())));
    if (!data) return std::unexpected(PlistError::unparseable);

    CFErrorRef raw_error = nullptr;
    yuzu::agent::ScopedCFRef<CFPropertyListRef> plist(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error); // owns/releases raw_error unconditionally

    if (!plist || CFGetTypeID(plist.get()) != CFDictionaryGetTypeID())
        return std::unexpected(PlistError::unparseable);

    const auto dict = static_cast<CFDictionaryRef>(plist.get());

    LaunchdFields fields;
    if (auto label = detail::dict_get_string(dict, CFSTR("Label"))) fields.label = *label;
    if (auto program = detail::dict_get_string(dict, CFSTR("Program"))) fields.program = *program;
    fields.program_arguments = detail::dict_get_string_array(dict, CFSTR("ProgramArguments"));
    if (auto disabled = detail::dict_get_bool(dict, CFSTR("Disabled"))) {
        fields.disabled_present = true;
        fields.disabled_value = *disabled;
    }
    return fields;
}

#else // !__APPLE__

inline std::expected<LaunchdFields, PlistError> plist_to_launchd_fields(std::span<const uint8_t>) {
    return std::unexpected(PlistError::unparseable);
}

#endif

} // namespace yuzu::autoruns
