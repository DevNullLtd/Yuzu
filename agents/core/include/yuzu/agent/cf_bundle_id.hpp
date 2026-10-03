#pragma once

/**
 * cf_bundle_id.hpp -- header-only CFBundleIdentifier read, shared by agent-core's
 * bounded pass (bundle_id_read.cpp) and the installed_apps plugin's enrich_app().
 * Apple-only: guarded `#if defined(__APPLE__)` like scoped_cfref.hpp.
 */

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>

#include <string>

#include <yuzu/agent/scoped_cfref.hpp>

namespace yuzu::agent {

/// UTF-8 copy of `s`, or "" for null/empty/unconvertible.
inline std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    const CFIndex len = CFStringGetLength(s);
    if (len <= 0)
        return {};
    const CFIndex raw_max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    // Documented to return kCFNotFound (-1) if the size cannot be computed; +1
    // would then make a 0-sized buffer handed to CFStringGetCString.
    if (raw_max <= 0)
        return {};
    const CFIndex max_bytes = raw_max + 1;
    std::string out(static_cast<std::size_t>(max_bytes), '\0');
    if (!CFStringGetCString(s, out.data(), max_bytes, kCFStringEncodingUTF8))
        return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
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
