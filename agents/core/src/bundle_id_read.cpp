// bundle_id_read.cpp -- bounded CFBundleIdentifier pass. See bundle_id_read.hpp
// for why this lives in agent-core rather than in the installed_apps plugin.

#include <yuzu/agent/bundle_id_read.hpp>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>

#include <yuzu/agent/cf_bundle_id.hpp>
#include <yuzu/agent/scoped_cfref.hpp>
#endif

namespace yuzu::agent {

namespace {

// Process-wide: one pass in flight. Static storage so an abandoned worker's
// releaser never touches a destroyed object.
std::atomic_flag g_pass_in_flight;

#if defined(__APPLE__)

std::string bundle_id_for(const std::string& app_path) {
    ScopedCFRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
        // reinterpret_cast char* -> const UInt8*: byte-type aliasing is the
        // explicit exemption to the strict-aliasing rule, and `app_path` is a
        // caller-owned lvalue that outlives this call, so the buffer stays valid
        // for the whole of CFURLCreateFromFileSystemRepresentation (which copies
        // it).
        nullptr, reinterpret_cast<const UInt8*>(app_path.c_str()),
        static_cast<CFIndex>(app_path.size()), /*isDirectory=*/true));
    if (!url)
        return {};
    return bundle_id_for_url(url.get());
}

#else

std::string bundle_id_for(const std::string&) {
    return {}; // non-Apple build: the only consumer (installed_apps macOS `list`) never calls this
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is
// agent-core text (see the header).

BundleIdPassResult read_bundle_ids_bounded(const std::vector<std::string>& app_paths,
                                           std::chrono::milliseconds deadline) {
    return detail::bounded_bundle_id_pass(g_pass_in_flight, app_paths, deadline, bundle_id_for);
}

BundleIdPassResult read_bundle_ids_bounded_for_test(
    const std::vector<std::string>& app_paths, std::chrono::milliseconds deadline,
    const std::function<std::string(const std::string&)>& per_path_reader) {
    return detail::bounded_bundle_id_pass(g_pass_in_flight, app_paths, deadline, per_path_reader);
}

} // namespace yuzu::agent
