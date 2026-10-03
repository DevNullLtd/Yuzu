// bundle_id_read.cpp -- bounded CFBundleIdentifier pass. See bundle_id_read.hpp
// for why this lives in agent-core rather than in the installed_apps plugin.

#include <yuzu/agent/bundle_id_read.hpp>

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)
#include <CoreFoundation/CoreFoundation.h>

#include <yuzu/agent/scoped_cfref.hpp>
#endif

namespace yuzu::agent {

namespace {

// Process-wide: one pass in flight. Static storage so an abandoned worker's
// releaser never touches a destroyed object.
std::atomic_flag g_pass_in_flight = ATOMIC_FLAG_INIT;

#if defined(__APPLE__) && defined(YUZU_HAVE_SECURITY_FRAMEWORK)

// Copy of installed_apps_macos_enrich.hpp's cfstring_to_utf8 /
// bundle_id_for_url / bundle_id_for (the plugin header keeps its own for
// enrich_app).
std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    const CFIndex len = CFStringGetLength(s);
    if (len <= 0)
        return {};
    const CFIndex raw_max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    if (raw_max <= 0)
        return {};
    const CFIndex max_bytes = raw_max + 1;
    std::string out(static_cast<std::size_t>(max_bytes), '\0');
    if (!CFStringGetCString(s, out.data(), max_bytes, kCFStringEncodingUTF8))
        return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

std::string bundle_id_for(const std::string& app_path) {
    ScopedCFRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
        nullptr, reinterpret_cast<const UInt8*>(app_path.c_str()),
        static_cast<CFIndex>(app_path.size()), /*isDirectory=*/true));
    if (!url)
        return {};
    auto* raw_bundle = CFBundleCreate(nullptr, url.get());
    if (!raw_bundle)
        return {};
    ScopedCFRef<CFBundleRef> bundle(raw_bundle);
    // CFBundleGetIdentifier is Get-rule (borrowed): never wrapped.
    return cfstring_to_utf8(CFBundleGetIdentifier(bundle.get()));
}

#else

std::string bundle_id_for(const std::string&) {
    return {}; // no CoreFoundation on this build; the only consumer is macOS-only
}

#endif

} // namespace

// Lambdas below are TU-local so every byte the detached thread runs is
// agent-core text (see the header).

BundleIdPassResult read_bundle_ids_bounded(const std::vector<std::string>& app_paths,
                                           std::chrono::milliseconds deadline) {
    return detail::bounded_bundle_id_pass(
        g_pass_in_flight, app_paths, deadline,
        [](const std::string& p) -> std::string { return bundle_id_for(p); });
}

BundleIdPassResult read_bundle_ids_bounded_for_test(
    const std::vector<std::string>& app_paths, std::chrono::milliseconds deadline,
    const std::function<std::string(const std::string&)>& per_path_reader) {
    return detail::bounded_bundle_id_pass(
        g_pass_in_flight, app_paths, deadline,
        [per_path_reader](const std::string& p) -> std::string { return per_path_reader(p); });
}

} // namespace yuzu::agent
