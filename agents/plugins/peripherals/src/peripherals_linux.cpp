/**
 * peripherals_linux.cpp — Linux leg entry point.
 *
 * WAVE 2 (this package, P91-5): real /sys/bus/{usb,pci,thunderbolt}/devices
 * walks, via the injected-root boundary in peripherals_linux_parsers.hpp.
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * sysfs root as a parameter -- production calls it with "/", the unit suite
 * exercises the walks directly against a fixture tree and never links or
 * runs this TU at all (it only builds on __linux__).
 */
#include "peripherals_legs.hpp"
#include "peripherals_linux_parsers.hpp"

#if defined(__linux__)

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::peripherals {

namespace {

int run_linux_at(yuzu::CommandContext& ctx, Kind k, const std::filesystem::path& root) {
    std::optional<std::string_view> failure_token;
    std::vector<std::string> rows;
    switch (k) {
    case Kind::usb:         rows = lnx::usb_rows_at(root, failure_token); break;
    case Kind::pci:         rows = lnx::pci_rows_at(root, failure_token); break;
    case Kind::thunderbolt: rows = lnx::thunderbolt_rows_at(root, failure_token); break;
    }
    for (const auto& row : rows)
        ctx.write_output(row);
    mark_result_read(ctx, k, rows.size(), failure_token);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx, Kind k) {
    return run_linux_at(ctx, k, "/");
}

} // namespace yuzu::peripherals

#endif // defined(__linux__)
