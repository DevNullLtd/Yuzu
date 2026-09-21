/**
 * update_source_trust_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * filesystem root as a parameter -- production calls it with "/", the unit
 * suite exercises lnx::linux_rows_at directly against a fixture tree
 * (update_source_trust_linux_parsers.hpp) and never links this TU (it only
 * builds on __linux__).
 *
 * One mechanism class: plain config-file reads (rung 1). Only the apt family
 * (sources and keyrings) is read today. The rpm/dnf `.repo` family follows as
 * its own PR; until then a host whose /etc/yum.repos.d has entries reports
 * constrained with `linux:rpm_repo:planned` (lnx::rpm_family_planned_at), never
 * a clean "no sources" -- a skipped family must not read as an empty one.
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
    const std::vector<std::string> rows = lnx::linux_rows_at(root, acc);
    report_sources(ctx, rows, acc);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    return run_linux_at(ctx, "/");
}

} // namespace yuzu::update_source_trust

#endif // defined(__linux__)
