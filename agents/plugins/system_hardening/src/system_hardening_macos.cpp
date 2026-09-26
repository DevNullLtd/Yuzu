/**
 * system_hardening_macos.cpp -- macOS leg: allowlisted sysctlbyname reads
 * (rung 1, no `sysctl` binary).
 *
 * ANCHOR (verified against the tree): agents/plugins/hardware/src/
 * hardware_plugin.cpp:95-107 `sysctl_string` (two-call size-probe idiom) and
 * :109-115 `sysctl_value<T>` (single fixed-size read). Both collapse every
 * failure to {}/nullopt, so this TU re-implements the same idiom with errno
 * captured; the pure collect loop (system_hardening_parsers.hpp) classifies
 * it (ENOENT -> absent, EPERM et al -> unreadable).
 *
 * Only kern.bootargs is a string and needs the size probe; the int keys use
 * one fixed-size read. An EMPTY kern.bootargs is a successful read (probe
 * rc=0 len=1, a lone NUL), not absent and not a failure. kern.nx is not in
 * the allowlist: `unknown oid` on Apple Silicon.
 */
#include "system_hardening_legs.hpp"

#if defined(__APPLE__)

#include <sys/sysctl.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::system_hardening {

namespace {

ReadOutcome read_sysctl(std::string_view name, SysctlKind kind) {
    const std::string n{name};
    if (kind == SysctlKind::integer) {
        std::int32_t v = 0;
        std::size_t len = sizeof v;
        if (sysctlbyname(n.c_str(), &v, &len, nullptr, 0) != 0) return {errno, 0, {}};
        // A width other than the int we asked for means the key is not the
        // integer this table models: report it unreadable, never guess a value.
        if (len != sizeof v) return {EINVAL, 0, {}};
        return {0, v, {}};
    }
    std::size_t len = 0;
    if (sysctlbyname(n.c_str(), nullptr, &len, nullptr, 0) != 0) return {errno, 0, {}};
    std::string buf(len, '\0'); // len == 0 is a legitimate empty value
    if (len != 0 && sysctlbyname(n.c_str(), buf.data(), &len, nullptr, 0) != 0) return {errno, 0, {}};
    buf.resize(len);
    while (!buf.empty() && buf.back() == '\0') buf.pop_back(); // trailing NUL of a string sysctl
    return {0, 0, std::move(buf)};
}

} // namespace

int collect_posture_macos(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = collect_macos_posture(read_sysctl, acc);
    emit_posture(ctx, rows, acc);
    return 0;
}

} // namespace yuzu::system_hardening

#endif // defined(__APPLE__)
