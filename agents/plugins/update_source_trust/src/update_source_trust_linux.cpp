/**
 * update_source_trust_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `lnx::run_linux_at`
 * (update_source_trust_linux_parsers.hpp), which takes the filesystem root as
 * a parameter: production passes "/", the unit suite drives the same body over
 * a fixture tree through a real CommandContext (this TU only builds on
 * __linux__ and is never linked by the suite).
 *
 * One mechanism class: plain config-file reads (rung 1). Only the apt family
 * (sources and keyrings) is read today. The rpm/dnf `.repo` family is not read
 * yet; a host whose /etc/yum.repos.d has entries reports constrained with
 * `linux:rpm_repo:planned` (lnx::rpm_family_planned_at), never a clean "no
 * sources" -- the skipped rpm/dnf family must not read as an empty one. Other
 * families (zypper, pacman, apk) are not detected at all.
 */
#include "update_source_trust_legs.hpp"
#include "update_source_trust_linux_parsers.hpp"

#if defined(__linux__)

namespace yuzu::update_source_trust {

int run_linux(yuzu::CommandContext& ctx) {
    return lnx::run_linux_at(ctx, "/");
}

} // namespace yuzu::update_source_trust

#endif // defined(__linux__)
