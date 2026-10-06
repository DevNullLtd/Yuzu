#pragma once

/**
 * cf_bundle_id.hpp -- header-only CFBundleIdentifier read, shared by agent-core's
 * bounded pass (bundle_id_read.cpp) and the installed_apps plugin's enrich_app().
 * Apple-only: guarded `#if defined(__APPLE__)` like scoped_cfref.hpp.
 */

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>

#include <cstddef>
#include <string>

#include <yuzu/agent/scoped_cfref.hpp>

namespace yuzu::agent {

/// Cap on one converted CFString: equal to installed_apps_parsers.hpp
/// kMaxListFieldBytes, so `list` bytes are identical, and a hostile multi-MiB
/// CFBundleIdentifier costs at most this in State/out.ids/the apps vector (the
/// inv| sync clamps at 1024 B after this).
inline constexpr std::size_t kMaxCFStringBytes = 4096;

/// UTF-8 copy of `s` cut at kMaxCFStringBytes on a character boundary, or "" for
/// null/empty/unconvertible. When CF stops with fewer than 4 bytes free the
/// whole-character prefix is returned; that includes an unconvertible (lone
/// surrogate) character within the last 3 bytes of the buffer, which also yields
/// the in-bound prefix rather than "" (a valid UTF-8 prefix of the same id).
inline std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    const CFIndex len = CFStringGetLength(s);
    if (len <= 0)
        return {};
    std::string out(kMaxCFStringBytes, '\0');
    CFIndex used = 0;
    // reinterpret_cast char* -> UInt8*: byte-type aliasing (the strict-aliasing
    // exemption); `out` is a local that outlives the call and maxBufLen bounds the
    // write (docs/cpp-conventions.md: casts need a local proof).
    const CFIndex converted = CFStringGetBytes(
        s, CFRangeMake(0, len), kCFStringEncodingUTF8, /*lossByte=*/0,
        /*isExternalRepresentation=*/false, reinterpret_cast<UInt8*>(out.data()),
        static_cast<CFIndex>(out.size()), &used);
    // Stopped short with room for a whole 4-byte character (a UTF-8 character is at
    // most 4 bytes): the bound was not the reason, so an unconvertible character is
    // -- empty, as before. With < 4 bytes free CF's stop is not attributable (a 4-byte
    // character did not fit, or a lone surrogate sits in those last bytes), so the
    // whole-character prefix is returned; for the lone-surrogate residual that is a
    // benign valid prefix of the same id, cut again by list_field at 4096 and by the
    // inventory clamp at 1024.
    constexpr CFIndex kMaxUtf8CharBytes = 4;
    if (converted < len && used + kMaxUtf8CharBytes <= static_cast<CFIndex>(out.size()))
        return {};
    out.resize(static_cast<std::size_t>(used));
    out.resize(std::char_traits<char>::length(out.c_str())); // interior NUL cuts, as before
    out.shrink_to_fit(); // release the 4 KiB working capacity: State keeps right-sized ids
    return out;
}

/// CFBundleIdentifier of the bundle at `url` (borrowed: the caller keeps the
/// CFURL), or "" when it is not a readable bundle or carries no identifier.
inline std::string bundle_id_for_url(CFURLRef url) {
    auto* raw_bundle = CFBundleCreate(nullptr, url);
    if (!raw_bundle)
        return {};
    ScopedCFRef<CFBundleRef> bundle(raw_bundle);
    // CFBundleGetIdentifier returns a BORROWED (Get-rule) reference owned by
    // the bundle -- never itself ScopedCFRef-wrapped.
    return cfstring_to_utf8(CFBundleGetIdentifier(bundle.get()));
}

} // namespace yuzu::agent

#endif // __APPLE__
