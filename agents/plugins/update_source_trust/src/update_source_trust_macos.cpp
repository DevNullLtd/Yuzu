/**
 * update_source_trust_macos.cpp -- macOS leg entry point.
 *
 * `run_macos` is a one-line wrapper over `run_macos_at`, which takes the
 * filesystem root as a parameter -- production calls it with "/", the unit
 * suite exercises swu_rows_at directly (update_source_trust_macos_parsers.hpp).
 * The plist decode is in-process CoreFoundation (CFPropertyListCreateWithData,
 * rung 1); there is no subprocess.
 */
#include "update_source_trust_legs.hpp"
#include "update_source_trust_macos_parsers.hpp"

#if defined(__APPLE__)

#include <filesystem>
#include <string>
#include <vector>

namespace yuzu::update_source_trust {

namespace {

int run_macos_at(yuzu::CommandContext& ctx, const std::filesystem::path& root) {
    yuzu::shared::ConstraintAccumulator acc;
    const std::vector<std::string> rows = mac::swu_rows_at(root, acc);
    report_sources(ctx, rows, acc);
    return 0;
}

} // namespace

int run_macos(yuzu::CommandContext& ctx) {
    return run_macos_at(ctx, "/");
}

} // namespace yuzu::update_source_trust

#endif // defined(__APPLE__)
