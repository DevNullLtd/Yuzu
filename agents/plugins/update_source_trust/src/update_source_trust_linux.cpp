/**
 * update_source_trust_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * filesystem root as a parameter -- production calls it with "/", the unit
 * suite exercises apt_rows_at/rpm_rows_at directly against a fixture tree
 * (update_source_trust_linux_parsers.hpp) and never links this TU (it only
 * builds on __linux__).
 *
 * One mechanism class for both package families: plain config-file reads
 * (rung 1). apt and rpm are independent families -- a host with only one of
 * them reports zero rows for the other and stays supported.
 */
#include "update_source_trust_legs.hpp"
#include "update_source_trust_linux_parsers.hpp"

#if defined(__linux__)

#include <filesystem>
#include <string>
#include <vector>

namespace yuzu::update_source_trust {

namespace {

int run_linux_at(yuzu::CommandContext& ctx, const std::filesystem::path& root) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows = lnx::apt_rows_at(root, acc);
    for (auto& r : lnx::rpm_rows_at(root, acc))
        rows.push_back(std::move(r));
    report_sources(ctx, rows, acc);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    return run_linux_at(ctx, "/");
}

} // namespace yuzu::update_source_trust

#endif // defined(__linux__)
