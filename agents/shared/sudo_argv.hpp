/**
 * sudo_argv.hpp — the Decision-8 canonical privileged argv (ADR-3002 :443-464).
 *
 * One builder for every sudo-governed rung-2 site (quarantine, services
 * set_start_mode, network_actions flush_dns):
 *
 *     {"/usr/bin/sudo", "-n", "--", "/abs/path/tool", args...}
 *
 * The FORM is load-bearing: it is what the sudoers grants installed by
 * scripts/install-agent-user.sh match (`sudo -n -- <tool> <args>` — `--` ends
 * sudo's own option parsing and is not part of the matched command), so it is
 * pinned by unit test, not convention. The `euid == 0` skip preserves the
 * behaviour every migrated plugin had via its private `sudo_prefix()` helper:
 * a root agent invokes the tool directly.
 *
 * Pure argv construction — no spawn, no environment, no policy.
 *
 * The two-argument `sudo_wrap` is PORTABLE (pure string work, no syscall), so
 * it is available on every platform. Only the one-argument convenience needs
 * POSIX, because only it calls `geteuid()`. That split exists so a header
 * which must compile under MSVC — `agents/shared/macos_console_user.hpp`, whose
 * pure argv builders are unit-tested on all three platforms — can still use
 * THE canonical form instead of hand-rolling a second copy of it (#3406).
 */
#pragma once

#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace yuzu::shared {

inline constexpr const char* kSudoPath = "/usr/bin/sudo";

// Pure core: wrap `tool_argv` (argv[0] MUST be an absolute tool path — the
// runner rejects relative argv[0], and a relative path under sudo would match
// no sudoers grant anyway) in the canonical sudo form unless already root.
inline std::vector<std::string> sudo_wrap(std::vector<std::string> tool_argv,
                                          bool euid_is_root) {
    if (euid_is_root)
        return tool_argv;
    std::vector<std::string> argv;
    argv.reserve(tool_argv.size() + 3);
    argv.emplace_back(kSudoPath);
    argv.emplace_back("-n");
    argv.emplace_back("--");
    for (auto& a : tool_argv)
        argv.push_back(std::move(a));
    return argv;
}

#ifndef _WIN32
// Thin default: live euid. POSIX-only — `geteuid()` has no Windows analogue,
// and no Windows site is sudo-governed.
inline std::vector<std::string> sudo_wrap(std::vector<std::string> tool_argv) {
    return sudo_wrap(std::move(tool_argv), ::geteuid() == 0);
}
#endif // !_WIN32

} // namespace yuzu::shared
