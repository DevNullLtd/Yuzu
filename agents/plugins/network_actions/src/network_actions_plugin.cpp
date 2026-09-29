/**
 * network_actions_plugin.cpp — Network action plugin for Yuzu
 *
 * Actions:
 *   "flush_dns" — Flush the DNS resolver cache.
 *   "ping"      — Ping a host (params: host, count).
 *
 * Output is pipe-delimited via write_output().
 *
 * ADR-3002 acquisition-ladder migration: every leg now acquires via the
 * shared agent-core bounded argv runner (rung 2) instead of a raw
 * popen()/_popen() shell-out (rung 3) — see run_bounded_subprocess /
 * probe_tool_path (subprocess_runner.hpp), the shared sudo_wrap()
 * (sudo_argv.hpp) and is_safe_host_arg() (host_arg.hpp). A runner-level
 * failure (spawn error / deadline / cancelled / signaled) is always
 * forwarded through the ABI4 result-status seam via forward_runner_failure —
 * never silently reported as status|ok.
 */

#include <yuzu/plugin.hpp>

#include <cctype>
#include <chrono>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure / classify_runner_failure
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path

#include <host_arg.hpp>  // yuzu::shared::is_safe_host_arg
#include <sudo_argv.hpp> // yuzu::shared::sudo_wrap

#include "network_actions_parsers.hpp" // yuzu::network_actions::resolver_flush_flag / decide_dns_flush

namespace {

// Per-call wall-clock bound for these actions: flush_dns and ping are both
// quick, single-shot commands (a cache flush -- including its privileged
// `sudo -n` hop -- or a handful of ICMP probes), so a short ceiling is
// enough — generous enough never to fire on a healthy endpoint, short
// enough that a wedged tool (or an operator-supplied ping `count` large
// enough to run past it) cannot pin the instruction worker indefinitely.
// This is justified on its own terms, not by analogy to a read-only-tool
// ceiling elsewhere: flush_dns is a mutating, privileged action, but still
// a fast local operation with no reason to ever legitimately run long. A
// ping cut short by this deadline is reported honestly via
// forward_runner_failure (CONSTRAINED/PARTIAL), never as a silent success.
constexpr std::chrono::milliseconds kNetworkActionsCmdDeadline{10'000};

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "flush_dns",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "resolvectl/systemd-resolve via bounded argv runner (sudo -n)",
         "requires resolvectl (systemd-resolved) or the legacy systemd-resolve CLI; an honest "
         "failure is reported if neither is present"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "dscacheutil + killall via bounded argv runner (sudo -n)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 2, "ipconfig via bounded argv runner", nullptr},
    },
    {
        /* .action      = */ "ping",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "system ping via bounded argv runner", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "system ping via bounded argv runner", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 2, "system ping.exe via bounded argv runner", nullptr},
    },
};

#if defined(__APPLE__)
// Collapse newlines/pipes so a diagnostic blob can't break the pipe-
// delimited, one-line-per-record output protocol. Only the macOS flush_dns
// leg emits a `detail|...` diagnostic line, so this is guarded to avoid an
// -Wunused-function warning on the other platforms (warning_level=3).
std::string flatten(std::string s) {
    for (char& c : s)
        if (c == '\n' || c == '\r' || c == '|')
            c = ' ';
    return s;
}
#endif

} // namespace

class NetworkActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "network_actions"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Network actions — DNS flush and ping";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"flush_dns", "ping", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "flush_dns") {
#ifdef _WIN32
            // network_actions/flush_dns_windows#1 — ipconfig ships at a fixed
            // System32 location on every supported Windows version; probed
            // (rather than hardcoded) so a missing binary is reported
            // honestly via forward_runner_failure instead of assumed.
            auto tool = yuzu::agent::probe_tool_path({"C:\\Windows\\System32\\ipconfig.exe"});
            std::vector<std::string> argv;
            if (!tool.empty())
                argv = {tool, "/flushdns"};
            auto res = yuzu::agent::run_bounded_subprocess(
                argv, yuzu::agent::SubprocessOptions{.deadline = kNetworkActionsCmdDeadline,
                                                     .merge_stderr = true});
            bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
            bool ok = !status_forwarded && res.tool_ran && res.exit_code == 0;
            ctx.write_output(std::format("status|{}", ok ? "ok" : "error"));
            ctx.write_output(std::format("output|{}", res.output));
            return ok ? 0 : 1;
#elif defined(__linux__)
            // network_actions/flush_dns_linux#1 — resolvectl (systemd-
            // resolved's modern CLI) is tried first; systemd-resolve (the
            // legacy CLI) is tried next on ANY failure of the first attempt
            // -- absent, or present but failing at runtime (service
            // stopped/masked, dbus unreachable). This restores the old
            // `resolvectl ... || systemd-resolve ... || true` shell chain's
            // retry-ON-FAILURE semantics, which a presence-only probe (try
            // resolvectl if the file exists, never retry if it then fails)
            // silently narrowed away (code-review Functional finding, this
            // session). Whichever attempt is used is run via `sudo -n` per
            // the NOPASSWD grants install-agent-user.sh installs; the real
            // exit code of the last attempt is reported -- never a blind
            // status|ok the way `|| true` used to guarantee.
            //
            // The retry/candidate-selection DECISION (which candidate wins,
            // does the loop stop early, what's the final status) is the
            // pure yuzu::network_actions::decide_dns_flush -- fixture-
            // tested in test_network_actions_parsers.cpp without a live
            // resolvectl/systemd-resolve/sudo dependency. Only the probe +
            // subprocess I/O stays here.
            std::vector<yuzu::network_actions::DnsFlushAttemptOutcome> attempts;
            yuzu::agent::SubprocessResult res;
            for (const char* candidate : {"/usr/bin/resolvectl", "/usr/bin/systemd-resolve"}) {
                auto tool = yuzu::agent::probe_tool_path({candidate});
                if (tool.empty()) {
                    attempts.push_back({/*found=*/false, /*succeeded=*/false});
                    continue;
                }
                auto argv = yuzu::shared::sudo_wrap(
                    {tool, std::string(yuzu::network_actions::resolver_flush_flag(tool))});
                res = yuzu::agent::run_bounded_subprocess(
                    argv, yuzu::agent::SubprocessOptions{.deadline = kNetworkActionsCmdDeadline,
                                                         .merge_stderr = true});
                const bool succeeded = res.tool_ran && res.exit_code == 0;
                attempts.push_back({/*found=*/true, succeeded});
                if (succeeded)
                    break; // success -- do not try the next candidate
            }
            const auto decision = yuzu::network_actions::decide_dns_flush(attempts);
            if (!decision.attempted) {
                ctx.write_output("status|error");
                ctx.write_output("output|neither resolvectl nor systemd-resolve found");
                return 1;
            }
            bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
            bool ok = decision.ok && !status_forwarded;
            ctx.write_output(std::format("status|{}", ok ? "ok" : "error"));
            ctx.write_output(std::format("output|{}", res.output));
            return ok ? 0 : 1;
#elif defined(__APPLE__)
            // A real macOS DNS flush is two steps: dscacheutil clears the
            // dscacheutil-visible cache, and the SIGHUP to mDNSResponder is
            // what actually resets the resolver — dscacheutil -flushcache
            // alone is insufficient on modern macOS. Both need root: the
            // production LaunchDaemon runs as root (sudo_wrap's euid==0
            // skip), while the documented unprivileged _yuzu dev account
            // reaches them through the `sudo -n` NOPASSWD grants that
            // install-agent-user.sh installs for exactly these two argv
            // forms. Report status from the real exit codes, never a blind
            // status|ok.
            //
            // network_actions/flush_dns_macos#1
            auto res1 = yuzu::agent::run_bounded_subprocess(
                yuzu::shared::sudo_wrap({"/usr/bin/dscacheutil", "-flushcache"}),
                yuzu::agent::SubprocessOptions{.deadline = kNetworkActionsCmdDeadline,
                                               .merge_stderr = true});
            bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res1);

            // network_actions/flush_dns_macos#2
            auto res2 = yuzu::agent::run_bounded_subprocess(
                yuzu::shared::sudo_wrap({"/usr/bin/killall", "-HUP", "mDNSResponder"}),
                yuzu::agent::SubprocessOptions{.deadline = kNetworkActionsCmdDeadline,
                                               .merge_stderr = true});
            // Never let the second forward_runner_failure overwrite an
            // earlier non-exit failure (matches users_plugin.cpp's
            // status_forwarded discipline — sdk/include/yuzu/plugin.h:287-288).
            if (!status_forwarded)
                status_forwarded = yuzu::agent::forward_runner_failure(ctx, res2);

            bool ok = !status_forwarded && res1.tool_ran && res1.exit_code == 0 &&
                     res2.tool_ran && res2.exit_code == 0;
            ctx.write_output(std::format("status|{}", ok ? "ok" : "error"));
            ctx.write_output(
                std::format("output|dscacheutil rc={} mDNSResponder rc={}", res1.exit_code,
                            res2.exit_code));
            if (!ok) {
                // Surface the captured command output (e.g. "sudo: a
                // password is required" when the _yuzu grant is missing) so
                // a failed flush is diagnosable.
                if (!res1.output.empty())
                    ctx.write_output(std::format("detail|dscacheutil: {}", flatten(res1.output)));
                if (!res2.output.empty())
                    ctx.write_output(
                        std::format("detail|mDNSResponder: {}", flatten(res2.output)));
            }
            return ok ? 0 : 1;
#else
            // Previously reported status|ok on unsupported platforms — a lie.
            ctx.write_output("status|error");
            ctx.write_output("output|unsupported platform");
            return 1;
#endif
        }

        if (action == "ping") {
            auto host = params.get("host");
            if (host.empty()) {
                ctx.write_output("error|missing required parameter: host");
                return 1;
            }
            if (!yuzu::shared::is_safe_host_arg(host)) {
                ctx.write_output("error|invalid host characters");
                return 1;
            }

            auto count = params.get("count", "4");
            // Validate count is numeric and non-empty (an explicitly empty
            // override previously passed the digit-loop vacuously and
            // reached ping with no count argument at all).
            if (count.empty()) {
                ctx.write_output("error|count must be numeric");
                return 1;
            }
            for (char c : count) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    ctx.write_output("error|count must be numeric");
                    return 1;
                }
            }

            // network_actions/ping#1 — the system ping tool, not the shared
            // IcmpSession (icmp_probe.hpp): this action's contract is "run
            // the system ping tool", and unlike IcmpSession, system ping is
            // typically setuid/cap-blessed so it has no
            // net.ipv4.ping_group_range constraint (confirmed design
            // decision, not revisited here).
#ifdef _WIN32
            auto tool = yuzu::agent::probe_tool_path({"C:\\Windows\\System32\\PING.EXE"});
#elif defined(__APPLE__)
            auto tool = yuzu::agent::probe_tool_path({"/sbin/ping"});
#else
            auto tool = yuzu::agent::probe_tool_path({"/usr/bin/ping", "/bin/ping"});
#endif
            std::vector<std::string> argv;
            if (!tool.empty()) {
                argv = {tool,
#ifdef _WIN32
                        "-n",
#else
                        "-c",
#endif
                        std::string(count), std::string(host)};
            }
            auto res = yuzu::agent::run_bounded_subprocess(
                argv, yuzu::agent::SubprocessOptions{.deadline = kNetworkActionsCmdDeadline});
            bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
            for (const auto& line : res.lines) {
                ctx.write_output(std::format("output|{}", line));
            }
            if (status_forwarded)
                return 1;
            return (res.tool_ran && res.exit_code == 0) ? 0 : 1;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(NetworkActionsPlugin)
