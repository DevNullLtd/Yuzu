/**
 * quarantine_plugin.cpp — Device Quarantine (Network Isolation) plugin for Yuzu
 *
 * Actions:
 *   "quarantine"   — Isolate the device from the network, whitelisting
 *                     management server and optional IPs.
 *   "unquarantine" — Remove all quarantine firewall rules and restore access.
 *   "status"       — Check whether quarantine rules are currently active.
 *   "whitelist"    — Add or remove IPs from an active quarantine whitelist.
 *
 * Firewall rules are prefixed with "YuzuQuarantine_" for easy identification.
 * Output is pipe-delimited via write_output().
 *
 * ── Wave-2 ADR-3002 acquisition-ladder migration ─────────────────────────
 *
 * Every spawn site in this file goes through yuzu::agent::run_bounded_subprocess
 * with clean, pre-split argv (no shell, no popen/_popen, no PATH search —
 * argv[0] is always an absolute path). Linux/macOS privilege escalation is
 * yuzu::shared::sudo_wrap's canonical `sudo -n -- <tool> <args>` form;
 * Windows needs none (the YuzuAgent service account's own privilege covers
 * netsh). Every mutating call's real termination reason is forwarded
 * through the ABI4 result-status seam via yuzu::agent::forward_runner_failure
 * — a quarantine/unquarantine/status read never silently reports success
 * when the underlying tool did not genuinely run and exit as expected. This
 * is deliberately careful: an incorrectly-reported quarantine or
 * unquarantine is a containment/availability failure, not a cosmetic one.
 *
 * ── macOS: DO NOT reintroduce a pf anchor ─────────────────────────────────
 *
 * `macos_load_ruleset` writes the ENTIRE main pf ruleset (never an anchor)
 * and loads it with ONE atomic `pfctl -f` call, with `set skip on lo0` as
 * the first line. This is a deliberate fix for a real production incident
 * (commit 672896112, `git log -1 672896112` for the full account): an
 * earlier design used a named anchor (`pfctl -a yuzu-quarantine -f tmp`
 * then a second `pfctl -f -` to attach the anchor to the main ruleset) —
 * that second call REPLACED the whole main ruleset with just the anchor
 * reference, evicting macOS's default rules, and 29 seconds later the
 * agent⇄gateway⇄server loopback TCP connection died mid-flight because the
 * anchor design's rule reload did not preserve pf's loopback connection
 * state. This migration changes ONLY the spawn mechanism (popen → bounded
 * subprocess argv, sudo prefix → yuzu::shared::sudo_wrap) — the ruleset
 * content, the single-atomic-`pfctl -f`-call strategy, and `set skip on
 * lo0` are byte-for-byte unchanged. If you find yourself adding `pfctl -a`
 * anywhere in this file, stop — that is the reverted design.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field — escape attacker/environment-influenced diagnostic text before it reaches a pipe-delimited output row
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (ADR-3002 rung 2)

#ifndef _WIN32
#include <spdlog/spdlog.h>
#include <unistd.h>      // ::access — LinuxV6Env filesystem probing, never tool_ran (#3282 item 3)
#include "sudo_argv.hpp" // yuzu::shared::sudo_wrap — canonical sudo -n -- <tool> <args> form (agents/shared)
#endif

#include "quarantine_parsers.hpp"       // yuzu::quarantine:: pure netsh/iptables/pfctl output parsers
#include "quarantine_serialization.hpp" // yuzu::quarantine::MutationGate (#3286)

#include <chrono>
#include <cstdio>
#include <fstream>
#include <format>
#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "win_str.hpp" // yuzu::win::from_wide (agents/shared, #1681)
#endif

namespace {

using yuzu::quarantine::is_safe_ip;
using yuzu::quarantine::kRulePrefix;
using yuzu::quarantine::QuarStatus;
using yuzu::quarantine::quar_status_token;

// ── Bounded-execution deadlines (ADR-3002 runner-idiom ceiling) ────────────
//
// 15s for mutating firewall-rule changes (task-set convention shared with
// the sibling users/certificates Wave-2 packages); 10s for the read-only
// status/whitelist queries, which should return near-instantly. Both are
// generous enough never to fire in normal operation and short enough that a
// wedged netsh/iptables/pfctl invocation cannot pin the instruction worker
// indefinitely (the popen()-based predecessor had NO bound at all).
constexpr std::chrono::milliseconds kQuarantineMutateDeadline{15000};
constexpr std::chrono::milliseconds kQuarantineReadDeadline{10000};

// ── Mutation serialization (#3286) ──────────────────────────────────────────
//
// Bounds do_quarantine/do_unquarantine/do_whitelist to one in flight at a
// time; do_status deliberately does not take this gate. See
// quarantine_serialization.hpp's header comment for the full concurrency
// rationale, the pool-worker-starvation reasoning behind the 2000ms budget,
// and why excluding status reads is correct rather than an oversight.
constexpr std::chrono::milliseconds kQuarantineLockWait{2000};
yuzu::quarantine::MutationGate g_quarantine_mutation_gate{kQuarantineLockWait};

/// THE call-site binding for the shared gate (CDX-P1-07).
///
/// Every mutating quarantine action acquires the gate through this one
/// function, never by naming `g_quarantine_mutation_gate` itself. That is the
/// whole point: the reviewer's mutation gave `do_quarantine` its own
/// file-static gate and the entire serialization suite stayed green, because
/// nothing tied the three actions to a SHARED lock. A call site now cannot
/// name a different gate without editing this function, and this is the one
/// place to grep when asking "do all the mutating actions share a lock?".
///
/// Honest about what this does NOT do: it does not prove the actions call it.
/// Proving that needs a real firewall mutation, which no unit test may
/// perform. It removes the easy way to get this wrong and makes the hard way
/// visible; code review remains the control for the acquisition itself, and
/// the PR body says so.
[[nodiscard]] inline std::optional<yuzu::quarantine::MutationGate::Guard>
enter_quarantine_mutation() {
    return g_quarantine_mutation_gate.try_enter();
}

// Absolute paths to firewall binaries. These MUST match the paths in the
// sudoers grants — see scripts/install-agent-user.sh
// generate_sudoers_content(). PATH-injection bypass would be possible with
// bare names: an attacker who got code execution as the agent could prepend
// a directory to $PATH containing a malicious `iptables`, and a sudoers
// entry keyed on `/usr/sbin/iptables` would happily run that instead —
// moot now that run_bounded_subprocess never PATH-searches argv[0] at all,
// but the absolute path is also what the sudoers grant itself matches.
#ifdef __APPLE__
constexpr const char* kPfctl = "/sbin/pfctl";
#endif
#ifdef __linux__
constexpr const char* kIptables = "/usr/sbin/iptables";
// ip6tables mirrors kIptables site-for-site (#3282) — same sudoers grant
// shape, VERIFIED already present at scripts/install-agent-user.sh:474.
constexpr const char* kIp6tables = "/usr/sbin/ip6tables";

/// Does this host have an IPv6 stack that could carry traffic?
///
/// NOT just `/proc/net/if_inet6`. That file is absent when the ipv6 module is
/// merely NOT LOADED, which is transient — treating it as "no stack" skips v6
/// containment and reports a clean `quarantined`, and if IPv6 then comes up
/// the host has uncontained v6 egress until something re-derives this. A host
/// that has genuinely disabled IPv6 (`ipv6.disable=1`, or the sysctl set)
/// satisfies neither test below; a host whose module is simply unloaded
/// satisfies the second and is correctly treated as having a stack.
bool linux_ipv6_stack_present() {
    if (::access("/proc/net/if_inet6", F_OK) == 0)
        return true;
    // The sysctl exists only when the ipv6 module is loaded, so its ABSENCE
    // here (with if_inet6 also absent) is the honest "no IPv6 on this host".
    // Present-and-1 means loaded but administratively disabled — also no
    // traffic to contain.
    std::ifstream f("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    if (!f)
        return false;
    // No initializer games: C++11 operator>> zeroes the value on extraction
    // failure, so a truncated or empty sysctl reads as 0 — "not disabled",
    // i.e. a stack IS present. That is the conservative direction (we contain
    // v6 rather than skip it), and stating it beats an initializer the
    // language overwrites.
    int disabled = 0;
    f >> disabled;
    return disabled == 0;
}
#endif

// ── Subprocess helper ────────────────────────────────────────────────────

/// Outcome of run_tool(): the captured output PLUS the raw runner result, so
/// a caller can forward the latter through the ABI4 result seam
/// (report_runner_result / yuzu::agent::forward_runner_failure) itself.
struct ToolOutcome {
    std::string output;
    yuzu::agent::SubprocessResult res;
};

/// Direct-argv replacement for the popen()/_popen() shell-string hop that
/// used to run every command here through a shell (ADR-3002 rung 2): the
/// same bounded runner, but exec'd straight to argv[0] with no shell in
/// between — no shell-quoting/injection surface. `merge_stderr=false`
/// matches this file's old `2>/dev/null` redirections; `merge_stderr=true`
/// matches a call site that used to have no redirection at all (stderr
/// simply wasn't captured) but where capturing it now gives the honest
/// failure message a real diagnostic to quote (the established
/// mutating-action convention — see users_plugin.cpp/certificates_plugin.cpp).
ToolOutcome run_tool(const std::vector<std::string>& argv, std::chrono::milliseconds deadline,
                     bool merge_stderr) {
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = deadline, .merge_stderr = merge_stderr});
#ifndef _WIN32
    // A cut-short/failed tool call can parse as "not quarantined" / "0 rules
    // applied" — a silent false-negative for a security-critical action.
    // Warn so an operator can distinguish a degraded run from a genuinely
    // clean one. spdlog isn't linked on the Windows leg of this plugin
    // today (no other call site here needed it); the ABI4 result-status
    // forward below is the cross-platform channel.
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("quarantine: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated,
                     argv.empty() ? std::string{} : argv.front());
    }
#endif
    std::string output = res.output;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    return ToolOutcome{std::move(output), std::move(res)};
}

/// Forwards a genuine runner failure (spawn_error/deadline/cancelled/
/// signaled — see runner_status.hpp) through the ABI4 result seam AT MOST
/// ONCE per action: `status_forwarded` is a local guard threaded through
/// every call in one do_*/leaf-function entry point so a later, less-
/// specific failure never overwrites an earlier one (mirrors
/// users_plugin.cpp's run_tool/status_forwarded convention). Returns true
/// iff the tool positively ran and exited zero — the mutating call sites
/// that need that (the old `run_command_rc(...) == 0` rules_applied
/// counters) use the return value; read-only call sites (status/whitelist
/// parses, which must not gate on a query command's exit code — a
/// nonexistent chain/rule set is a normal "not quarantined" outcome, not a
/// failure) ignore it and rely solely on the forwarding side effect.
bool report_runner_result(yuzu::CommandContext& ctx, bool& status_forwarded,
                          const yuzu::agent::SubprocessResult& res) {
    if (!status_forwarded && yuzu::agent::forward_runner_failure(ctx, res))
        status_forwarded = true;
    return res.tool_ran && res.exit_code == 0;
}

// ── String splitting ─────────────────────────────────────────────────────

std::vector<std::string> split_ips(std::string_view csv) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{csv}};
    std::string token;
    while (std::getline(iss, token, ',')) {
        // Trim whitespace
        while (!token.empty() && token.front() == ' ')
            token.erase(token.begin());
        while (!token.empty() && token.back() == ' ')
            token.pop_back();
        if (!token.empty() && is_safe_ip(token)) {
            ips.push_back(std::move(token));
        }
    }
    return ips;
}

std::string join_ips(const std::vector<std::string>& ips) {
    std::string result;
    for (size_t i = 0; i < ips.size(); ++i) {
        if (i > 0)
            result += ',';
        result += ips[i];
    }
    return result;
}

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

/// Absolute path to netsh.exe, resolved via GetSystemDirectoryW so this
/// never depends on PATH (same PATH-hijack rationale as
/// tar_mapdrive_collector.cpp's system32_path — that helper returns a
/// shell-quoted string for its own popen()-based caller; run_bounded_subprocess
/// execs argv[0] directly with no shell, so this returns UNQUOTED). Cached
/// on first call — the system directory can't change during the agent's
/// lifetime.
const std::string& netsh_path() {
    static const std::string path = [] {
        wchar_t dir[MAX_PATH]{};
        UINT n = GetSystemDirectoryW(dir, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return std::string{}; // honest empty -> run_bounded_subprocess's
                                   // own empty-argv[0] spawn_error reject
        return yuzu::win::from_wide(dir) + "\\netsh.exe";
    }();
    return path;
}

// state/note: item 7 of #3282 — mechanical bool active -> QuarStatus state
// change. #3285 extends this with a dir=out capture; #3284 branch A extends
// it again with the all-profiles policy read — see win_is_quarantined.
struct StatusReadResult {
    QuarStatus state = QuarStatus::inactive;
    std::string note;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    yuzu::agent::SubprocessResult res;
    /// Set when the listing could not be trusted to be complete — a
    /// truncated capture yields a SHORT list that is indistinguishable from a
    /// genuinely short one. Surfaced on the output line so an operator reading
    /// a whitelist to work out why a device is unreachable is not handed a
    /// silently-partial answer.
    std::string note;
};

// #3284 branch A: renders a captured prior firewall policy for the
// informational `prior_policy|` field. Pure formatting of already-parsed
// (and therefore already-tested, via netsh_firewall_policy) values — not a
// parser itself, so it stays local to the impure shell rather than living in
// quarantine_parsers.hpp. Never empty: an empty `profiles` vector (capture
// failed or was unparseable) still renders as "unknown" rather than an empty
// value, keeping the `prior_policy|<value>` pair's value half non-empty.
std::string format_prior_policy(const std::vector<yuzu::quarantine::ProfilePolicy>& profiles) {
    auto action_str = [](yuzu::quarantine::FirewallAction a) {
        switch (a) {
        case yuzu::quarantine::FirewallAction::block:
            return "Block";
        case yuzu::quarantine::FirewallAction::allow:
            return "Allow";
        case yuzu::quarantine::FirewallAction::unknown:
            return "Unknown";
        }
        return "Unknown"; // unreachable; keeps -Wswitch happy across compilers
    };
    std::string out;
    for (const auto& p : profiles) {
        if (!out.empty())
            out += "; ";
        out += std::format("{}:{}In/{}Out", p.profile, action_str(p.inbound),
                           action_str(p.outbound));
    }
    return out.empty() ? "unknown" : out;
}

/// `report_runner_result` plus the truncation test, for the sites that PARSE a
/// `netsh ... show rule name=all` capture. See `netsh_capture_usable` for why
/// the two questions differ and what each site produces when they are
/// conflated. Still forwards the runner failure through the ABI4 seam, so
/// nothing is lost relative to calling `report_runner_result` directly.
bool netsh_read_usable(yuzu::CommandContext& ctx, bool& status_forwarded,
                       const yuzu::agent::SubprocessResult& res) {
    // Called for the forwarding SIDE EFFECT — a genuine runner failure reaches
    // the ABI4 seam here. Its return value is deliberately discarded: it is
    // `tool_ran && exit_code == 0`, and per `run_tool`'s contract a read-only
    // parse must not gate on a query's exit status.
    (void)report_runner_result(ctx, status_forwarded, res);
    // The real fields, not laundered ones. An earlier version fed the line
    // above into the `tool_ran` slot and hardcoded the other two, which
    // computed the right answer while reading as though it had tested things
    // it never looked at.
    return yuzu::quarantine::netsh_capture_usable(res.tool_ran, res.timed_out,
                                                  res.output_truncated);
}

int win_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips,
                   std::string* prior_policy_serialized_out,
                   const std::function<bool(const std::string&, bool)>& persist_prior_policy) {
    // #3285: attempted-vs-succeeded, not a bare success counter. The old
    // `rules_applied > 0` gate reported `status|quarantined` whenever ANY call
    // landed — so a failed containment step plus two successful loopback Allow
    // rules read as a clean success on a host with nothing blocked.
    yuzu::quarantine::MutationTally tally;
    bool status_forwarded = false;

    auto apply = [&](std::vector<std::string> argv) {
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        const bool ok = report_runner_result(ctx, status_forwarded, out.res);
        tally.record(ok);
        return ok;
    };

    // #3284 branch A: capture the pre-quarantine firewall policy before
    // changing it. This is the RESTORE IMAGE, not just the informational
    // `prior_policy|` field — win_unquarantine replays it per profile, because
    // writing a fixed Windows default there permanently downgraded any host
    // whose admin or GPO had hardened it. Only a COMPLETE capture (all three
    // profiles, both actions known) is persisted; a fragment is discarded so
    // release takes its honest default-restore fallback rather than a partial
    // replay. A failure here does not block quarantining — containment is the
    // point of this action — but it IS reported, because it changes what
    // release will be able to do.
    // sink: quarantine/win_quarantine#1 — rung-2 runner argv, read-only
    auto policy_out = run_tool({netsh_path(), "advfirewall", "show", "allprofiles"},
                               kQuarantineReadDeadline, /*merge_stderr=*/false);
    report_runner_result(ctx, status_forwarded, policy_out.res);
    const auto prior_policy = yuzu::quarantine::netsh_firewall_policy(policy_out.output);

    // THE DISCRIMINATOR a block-both capture cannot supply on its own.
    //
    // `is_quarantine_shaped_policy` refuses to persist an all-profiles
    // block/block capture, because on a re-quarantine that capture IS the
    // policy this plugin installed and replaying it at release strands the
    // host. But block/block is also a legitimate hardened posture — a host
    // whose admin or GPO blocks egress on all three profiles — and for THAT
    // host the same refusal makes release write Microsoft's
    // `blockinbound,allowoutbound` default, silently removing the egress
    // filtering the admin configured. Two opposite wrong answers from one
    // input, which is the signature of a missing input rather than a hard
    // trade-off.
    //
    // The missing input is whether WE contained this host. Our named loopback
    // Allow rule is installed by `win_quarantine` and removed by
    // `win_unquarantine`, so its presence answers exactly that, and it is one
    // read on a path that already performs several.
    //
    // `name=all` and the TESTED parser, not a name-specific probe.
    //
    // The first version of this read asked netsh for our loopback rule BY NAME
    // and treated a non-zero exit as "read failed". `netsh advfirewall firewall
    // show rule name=<specific>` exits NON-ZERO when no rule matches — which is
    // the answer "not ours" — so that probe folded "no match" into "unreadable"
    // and could never return false. Every host looked already-contained, which
    // meant a genuinely block/block-hardened host on its FIRST quarantine had
    // its capture refused as quarantine-shaped, no restore image was stored,
    // and release wrote Microsoft's default over the admin's egress filtering:
    // exactly the outcome this discriminator was added to prevent, still
    // shipping behind a read that always agreed with itself.
    //
    // `name=all` exits 0 on any host with rules to list — which is every real
    // one — and `netsh_base_rules_present` is the same
    // pure, unit-tested parser `win_is_quarantined` and `win_unquarantine`
    // already use for this question. Two mechanisms for one question is how
    // they drift; there is now one.
    //
    // Read failure is still NOT treated as "not ours": an unreadable answer
    // falls back to the conservative refusal, because writing block/block into
    // the restore image on a guess is the stranding outcome, and the fallback
    // is recoverable and declared.
    // sink: quarantine/win_quarantine#2 — rung-2 runner argv, read-only
    auto own_rule_out = run_tool(
        {netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"},
        kQuarantineReadDeadline, /*merge_stderr=*/false);
    // TRUNCATION IS A FAILED READ HERE, not a complete one.
    //
    // `report_runner_result` returns `tool_ran && exit_code == 0`, and a
    // capture that hits the runner's 1 MB blob cap satisfies both: the runner
    // keeps draining, the child exits normally, and only `output_truncated`
    // records that the tail was dropped. Verbose netsh rule output runs about
    // 600 bytes per rule, so roughly 1,600 inbound rules — ordinary on a
    // GPO-managed enterprise host — overflows it, and OUR rules are added last
    // and therefore sit in the dropped tail.
    //
    // Reading that as a complete listing in which our rule is absent answers
    // "not ours" on a host we contained. On the one where the prior-policy
    // record is also missing — the "storage cleared while still contained"
    // case this belt exists for — the block/block capture is then stored AS
    // the restore image, and release replays it: profile policy back to
    // block-in/block-out, our allow rules deleted, device cut off from its own
    // management channel, release reporting success.
    //
    // Note the direction. Before this discriminator existed the belt always
    // held and release fell back to the recoverable Microsoft default; getting
    // truncation wrong here converts a recoverable outcome into an
    // unrecoverable one, which is worse than the defect the discriminator was
    // added to fix.
    const bool own_rule_read_ok = netsh_read_usable(ctx, status_forwarded, own_rule_out.res);
    const bool already_contained_by_us =
        !own_rule_read_ok ||
        yuzu::quarantine::netsh_base_rules_present(own_rule_out.output).allow_lo_in;

    // #3284: hand the captured policy back so the caller can persist it for
    // the release path. Empty when the capture failed or parsed to nothing —
    // the caller stores nothing rather than a placeholder, so unquarantine can
    // tell "we never captured this" from "it was genuinely the default".
    // CDX-P1-03: only a COMPLETE capture is worth persisting. A fragment
    // (truncated or localised `show allprofiles` output) is not a restore
    // image — replaying it would put some profiles back and silently leave
    // the rest on the quarantine policy. An empty out-param makes release
    // take its honest default-restore fallback instead, which says so.
    const std::string prior_serialized =
        yuzu::quarantine::is_complete_profile_policy(prior_policy)
            ? yuzu::quarantine::serialize_profile_policies(prior_policy)
            : std::string{};
    if (prior_policy_serialized_out)
        *prior_policy_serialized_out = prior_serialized;

    // PERSIST BEFORE MUTATING. Not a stylistic ordering — the window between
    // them is a permanent, unrecoverable data-loss window.
    //
    // The capture used to be handed back and written to plugin storage only
    // after this whole function returned. Everything below is up to 25 netsh
    // calls at a 15s deadline apiece — several minutes of wall clock on a host
    // with a large whitelist — and the profile policy is already block/block
    // after the FIRST of them. A reboot, an agent kill or a plugin-host recycle
    // anywhere in that window left the host contained with NO stored image.
    // The next release then read an empty record, took the honest
    // default-restore fallback, and wrote Microsoft's
    // blockinbound,allowoutbound over a GPO-hardened egress posture.
    //
    // And it was unrecoverable by re-quarantine: `already_contained_by_us` is
    // true from then on and the capture is quarantine-shaped, so
    // `store_prior_policy` correctly refuses every later attempt. The only
    // moment this host's real policy is knowable is right here, before the
    // first mutation — so this is where it has to be written.
    //
    // A persist FAILURE is still not fatal to the quarantine (containment
    // matters more than a tidy release); it is reported by the caller, which
    // reads the result through the same out-param it always did.
    bool persisted_prior = false;
    if (persist_prior_policy && !prior_serialized.empty())
        persisted_prior = persist_prior_policy(prior_serialized, already_contained_by_us);
    if (prior_policy_serialized_out && !persisted_prior)
        prior_policy_serialized_out->clear(); // the caller reports "not stored"

    // #3284: docs/quarantine-windows-firewall-precedence.md verified live
    // (2026-08-21) that on Windows BLOCK OVERRIDES ALLOW regardless of rule
    // specificity — a blanket Block rule silently defeated the narrower
    // whitelist/loopback Allow rules below, stranding a quarantined host
    // from its own management channel (the same failure class as the macOS
    // 672896112 incident, reached by a different mechanism). This is
    // branch A: block via the PROFILE DEFAULT policy instead of a rule — a
    // rule always outranks a profile default, so with no Block rule left to
    // outrank them, the Allow rules below finally take effect.
    // sink: quarantine/win_quarantine#2 — rung-2 runner argv, MUTATING.
    // Its result is held separately as well as tallied: since branch A this
    // single call IS the containment, so it must never be outvoted by the
    // Allow rules below, which only carve exceptions out of it.
    const bool policy_applied = apply(yuzu::quarantine::netsh_set_firewall_policy_argv(
        netsh_path(), yuzu::quarantine::kWinFirewallPolicyBlockBoth));

    // sink: quarantine/win_quarantine#3 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackIn", kRulePrefix), "dir=in", "action=allow",
          "enable=yes", "remoteip=127.0.0.1"});

    // sink: quarantine/win_quarantine#4 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackOut", kRulePrefix), "dir=out", "action=allow",
          "enable=yes", "remoteip=127.0.0.1"});

    // IPv6 loopback mirror — the IPv4 rules above only cover 127.0.0.1, so
    // under the branch-A profile-default-block posture ::1 had no matching
    // Allow rule at all. Separately named (not "...LoopbackIn"/"...Out")
    // so netsh_base_rules_present's exact-match read of the v4 rule names
    // stays unambiguous about what it's reporting.
    // sink: quarantine/win_quarantine#3b — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackIn6", kRulePrefix), "dir=in", "action=allow",
          "enable=yes", "remoteip=::1"});

    // sink: quarantine/win_quarantine#4b — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackOut6", kRulePrefix), "dir=out", "action=allow",
          "enable=yes", "remoteip=::1"});

    for (const auto& ip : whitelist_ips) {
        // sink: quarantine/win_quarantine#5 — rung-2 runner argv, MUTATING,
        // operator-supplied IP validated by is_safe_ip before reaching here.
        // Argv construction lives in netsh_allow_in_rule_argv
        // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
        apply(yuzu::quarantine::netsh_allow_in_rule_argv(netsh_path(), ip));

        // sink: quarantine/win_quarantine#6 — rung-2 runner argv, MUTATING,
        // operator-supplied IP validated by is_safe_ip before reaching here
        apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
              std::format("name={}AllowOut_{}", kRulePrefix, ip), "dir=out", "action=allow",
              "enable=yes", std::format("remoteip={}", ip)});
    }

    const auto token = yuzu::quarantine::win_quarantine_token(policy_applied, tally);

    if (token == yuzu::quarantine::kStatusFailed) {
        // Either nothing applied at all, or — the case the old gate missed —
        // the policy set itself failed, so no containment exists no matter how
        // many Allow rules landed.
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  policy_applied
                                      ? "quarantine:win_quarantine all rules failed to apply"
                                      : "quarantine:win_quarantine firewall policy not applied — "
                                        "the device is NOT contained");
        }
        ctx.write_output(std::format("status|failed|rules_applied|{}", tally.succeeded));
        return 1;
    }

    if (token == yuzu::quarantine::kStatusQuarantinedPartial) {
        // Containment IS in force, but at least one loopback/whitelist
        // exception did not apply — the device may be unreachable on a path
        // quarantine was asked to preserve, including the channel its own
        // unquarantine arrives on. Never a clean success (C4).
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:win_quarantine contained, but one or more "
                                  "loopback/whitelist exceptions failed to apply");
        }
        ctx.write_output(std::format(
            "status|quarantined_partial|rules_applied|{}|rules_attempted|{}|prior_policy|{}",
            tally.succeeded, tally.attempted,
            yuzu::util::safe_output_field(format_prior_policy(prior_policy))));
        return 1;
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}|prior_policy|{}",
                                 tally.succeeded,
                                 yuzu::util::safe_output_field(format_prior_policy(prior_policy))));
    return 0;
}

int win_unquarantine(yuzu::CommandContext& ctx, std::string_view stored_prior_policy) {
    bool status_forwarded = false;
    // Tracks a CLEAN failure (tool ran, exited nonzero) on one of the rule
    // deletions or the #3284 policy restore below — distinct from
    // status_forwarded, which only covers a genuine runner-level failure
    // (spawn/deadline/cancel/signal). Every rule in rules_to_delete was just
    // observed present in the show-rule capture, so a delete that runs and
    // refuses is a real signal the release did not fully complete, not
    // routine idempotency noise — discarding it (the pre-fix behaviour) let
    // a partially-failed release still report "released".
    bool teardown_failed = false;

    // netsh does not support wildcards, so we list rules and delete matches.
    // sink: quarantine/win_unquarantine#1 — rung-2 runner argv, read-only
    auto out_in = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                            "dir=in"},
                           kQuarantineReadDeadline, /*merge_stderr=*/false);
    bool delete_list_complete = netsh_read_usable(ctx, status_forwarded, out_in.res);

    // sink: quarantine/win_unquarantine#2 — rung-2 runner argv, read-only
    auto out_out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                             "dir=out"},
                            kQuarantineReadDeadline, /*merge_stderr=*/false);
    delete_list_complete =
        netsh_read_usable(ctx, status_forwarded, out_out.res) && delete_list_complete;

    std::string combined = out_in.output + "\n" + out_out.output;
    auto rules_to_delete = yuzu::quarantine::netsh_matching_rule_names(combined);

    // A capture we could not trust yields a delete list we cannot trust. Left
    // unguarded, an empty list from a truncated read means the loop attempts
    // nothing, `teardown_failed` stays false, and release reports
    // `status|released` rc 0 while every allow rule survives and the stored
    // prior policy is cleared — a release that released nothing, reported as
    // success. `teardown_failed` exists to make exactly that impossible.
    if (!delete_list_complete)
        teardown_failed = true;

    for (const auto& rule : rules_to_delete) {
        // sink: quarantine/win_unquarantine#3 — rung-2 runner argv, MUTATING
        auto del = run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}", rule)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (!report_runner_result(ctx, status_forwarded, del.res))
            teardown_failed = true;
    }

    // #3284 branch A: put back the profile policy quarantine replaced — the
    // genuine release step, since the named-rule delete loop above no longer
    // has a Block rule to remove.
    //
    // Replaying the CAPTURED policy is load-bearing, not a nicety. Writing the
    // Windows default unconditionally (the shape this shipped with) silently
    // and permanently DOWNGRADES a host whose admin or GPO had set block-both,
    // on one quarantine/release cycle — the plugin would weaken the very
    // control it exists to strengthen. The macOS analogy that justified it
    // does not hold: /etc/pf.conf is a FILE the admin owns, so reloading it
    // returns to their configuration; the Windows profile policy is LIVE STATE
    // and overwriting it destroys their choice.
    //
    // Per profile, because Domain/Private/Public may legitimately differ and a
    // single allprofiles write would flatten a mixed host to one value.
    // Anything unparseable is treated as "not captured" and takes the fallback
    // rather than being partially replayed.
    const auto restore_profiles = yuzu::quarantine::parse_profile_policies(stored_prior_policy);
    bool replayed = false;
    // CDX-P1-03: a non-empty record is not automatically a usable one. Only a
    // COMPLETE image (all three profiles, both actions known) can put the host
    // back; anything else takes the honest fallback rather than a partial
    // replay that would leave some profiles contained while reporting release.
    if (yuzu::quarantine::is_complete_profile_policy(restore_profiles)) {
        bool all_ok = true;
        for (const auto& p : restore_profiles) {
            auto argv = yuzu::quarantine::netsh_restore_profile_policy_argv(netsh_path(), p);
            if (argv.empty()) { // unrecognised profile/action — never spawn a half-formed write
                all_ok = false;
                continue;
            }
            // sink: quarantine/win_unquarantine#4 — rung-2 runner argv, MUTATING
            auto one = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            if (!report_runner_result(ctx, status_forwarded, one.res))
                all_ok = false;
        }
        if (!all_ok)
            teardown_failed = true;
        // `replayed` claims the host's own policy is back. That is only true
        // if EVERY profile restore succeeded — a partial replay leaves the
        // remainder on the quarantine policy, so it must not suppress the
        // fallback note below.
        replayed = all_ok;
    } else {
        // Nothing captured, or a value that did not survive validation. Fall
        // back to the Windows default so the host is at least reachable again
        // — but SAY SO on both channels rather than letting a downgrade pass
        // as a clean release (C4).
        // sink: quarantine/win_unquarantine#5 — rung-2 runner argv, MUTATING
        auto restore = run_tool(yuzu::quarantine::netsh_set_firewall_policy_argv(
                                   netsh_path(), yuzu::quarantine::kWinFirewallPolicyDefault),
                               kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (!report_runner_result(ctx, status_forwarded, restore.res))
            teardown_failed = true;
    }

    if (status_forwarded || teardown_failed) {
        // A genuine runner failure (spawn/deadline/cancel/signal), OR a
        // clean failure on one of the rule deletions or the policy restore
        // themselves, occurred somewhere in the release sequence — do NOT
        // claim the device is released when the release commands themselves
        // may not have run to completion. This is the unquarantine-side
        // mirror of the invariant the macOS incident this migration must
        // not reintroduce: a firewalled host must never be silently
        // reported as recovered.
        if (!status_forwarded) {
            ctx.set_result_status(
                YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                "quarantine:win_unquarantine one or more rule deletions or the policy restore failed");
        }
        ctx.write_output("status|release_uncertain");
        return 1;
    }

    if (!replayed) {
        // Released and reachable, but on Microsoft's default rather than
        // whatever this host had before — which may be WEAKER than its
        // pre-quarantine posture. Reporting a bare `released` would hide a
        // security-posture change behind a success, so it is named on the text
        // channel and marked partial on the ABI4 seam. Return 0: the release
        // itself did succeed, and a nonzero here would make an operator retry
        // a release that already worked.
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "quarantine:win_unquarantine restored the Windows default policy — "
                              "no captured pre-quarantine policy was available to replay");
        ctx.write_output("status|released|note|restored the Windows default firewall policy; the "
                         "pre-quarantine policy was not available to replay, so verify this "
                         "host's profile defaults");
        return 0;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult win_is_quarantined(yuzu::CommandContext& ctx, bool& status_forwarded) {
    // #3284 branch A: containment is enforced by the PROFILE DEFAULT policy
    // (no more named Block rules to check) plus the two named loopback
    // Allow rules — see win_quarantine's header comment and
    // docs/quarantine-windows-firewall-precedence.md for the live verdict
    // that put this plugin on branch A.
    // sink: quarantine/win_is_quarantined#1 — rung-2 runner argv, read-only
    auto policy_out = run_tool({netsh_path(), "advfirewall", "show", "allprofiles"},
                               kQuarantineReadDeadline, /*merge_stderr=*/false);
    // CDX-P1-04: same as the Linux path — a failed capture reads identically
    // to a host with nothing applied, so read success has to be carried.
    bool reads_ok = report_runner_result(ctx, status_forwarded, policy_out.res);
    const auto profiles = yuzu::quarantine::netsh_firewall_policy(policy_out.output);
    const bool policy_blocking = yuzu::quarantine::all_profiles_blocking(profiles);

    // sink: quarantine/win_is_quarantined#2 — rung-2 runner argv, read-only
    auto out_in = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                           "dir=in"},
                          kQuarantineReadDeadline, /*merge_stderr=*/false);
    reads_ok = netsh_read_usable(ctx, status_forwarded, out_in.res) && reads_ok;

    // sink: quarantine/win_is_quarantined#3 — rung-2 runner argv, read-only.
    // #3285: dir=in alone can never see an outbound rule -- netsh's dir
    // filter genuinely restricts which rules are returned, so an
    // outbound-only failure (e.g. AllowLoopbackOut failing to apply) was
    // previously invisible to status.
    auto out_out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                            "dir=out"},
                           kQuarantineReadDeadline, /*merge_stderr=*/false);
    reads_ok = netsh_read_usable(ctx, status_forwarded, out_out.res) && reads_ok;

    const std::string combined = out_in.output + "\n" + out_out.output;
    const auto rules = yuzu::quarantine::netsh_base_rules_present(combined);
    const bool loopback_present =
        rules.allow_lo_in && rules.allow_lo_out && rules.allow_lo_in6 && rules.allow_lo_out6;

    // The plugin owns its OWN named rules; the profile policy is host state it
    // does not own and cannot distinguish its own change to from an admin's or
    // a GPO's. So the presence of a YuzuQuarantine_ rule -- not the policy --
    // is what says "we quarantined this host".
    //
    // Deriving `inactive` from `!policy_blocking` instead (the shape this
    // branch shipped with) made a host that merely DEFAULTS to blocking both
    // directions -- a perfectly ordinary hardened posture, and exactly what a
    // security-conscious fleet looks like -- read `partial` forever despite
    // never having been quarantined: a permanent false containment signal on
    // the status channel #3285 exists to make trustworthy.
    //
    // The residual error runs the safe way. If an operator deleted our rules
    // while the policy still blocks, this reads `inactive` when some
    // containment survives -- indistinguishable from an admin-hardened host,
    // and it under-reports containment rather than over-reporting it. A
    // re-quarantine is idempotent; a false `active` is not recoverable by the
    // operator at all.
    const bool any_yuzu_rule =
        rules.allow_lo_in || rules.allow_lo_out || rules.allow_lo_in6 || rules.allow_lo_out6;

    StatusReadResult result;
    if (!reads_ok) {
        // CDX-P1-04: an unreadable host is `uncertain`, never `inactive`.
        result.state = QuarStatus::uncertain;
        result.note = "firewall query failed — containment state could not be determined";
    } else if (policy_blocking && loopback_present) {
        result.state = QuarStatus::active;
    } else if (!any_yuzu_rule) {
        result.state = QuarStatus::inactive;
        if (policy_blocking) {
            // Not our containment -- say so, so a blocking host is never read
            // as evidence that a quarantine is in force.
            result.note = "firewall policy blocks both directions, but no " +
                          std::string{kRulePrefix} +
                          " rule is present -- this is the host's own posture, not an active "
                          "quarantine";
        }
    } else {
        result.state = QuarStatus::partial;
        std::vector<std::string> missing;
        if (!policy_blocking)
            missing.push_back("firewall policy not blocking both directions on every profile");
        if (!rules.allow_lo_in)
            missing.push_back(std::format("{}AllowLoopbackIn", kRulePrefix));
        if (!rules.allow_lo_out)
            missing.push_back(std::format("{}AllowLoopbackOut", kRulePrefix));
        if (!rules.allow_lo_in6)
            missing.push_back(std::format("{}AllowLoopbackIn6", kRulePrefix));
        if (!rules.allow_lo_out6)
            missing.push_back(std::format("{}AllowLoopbackOut6", kRulePrefix));
        std::string note = "missing: ";
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i)
                note += ", ";
            note += missing[i];
        }
        result.note = note;
    }
    return result;
}

WhitelistRead win_get_whitelist() {
    // sink: quarantine/win_get_whitelist#1 — rung-2 runner argv, read-only
    auto out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                        "dir=in"},
                       kQuarantineReadDeadline, /*merge_stderr=*/false);
    WhitelistRead result;
    result.ips = yuzu::quarantine::netsh_whitelist_ips(out.output);
    // A truncated capture yields a SHORT list that looks complete. Lowest-harm
    // of the four sites that parse this command — it is reporting, not a
    // decision — but an operator reading a whitelist to work out why a device
    // is unreachable must not be handed a silently-partial one. This function
    // takes no ctx, so the note is the channel; the caller already forwards
    // `res` through the ABI4 seam.
    if (out.res.output_truncated)
        result.note = "whitelist listing was truncated — the list may be incomplete";
    result.res = std::move(out.res);
    return result;
}

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

// state/note: item 7 of #3282 — QuarStatus/note carry the honest
// active/partial/inactive read vocabulary (see linux_is_quarantined /
// linux_quar_status; `degraded`/`uncertain` are never produced here — those
// two are macOS-only, see QuarStatus's doc comment in
// quarantine_parsers.hpp). No `res` field: like the Windows/macOS
// StatusReadResult above, linux_is_quarantined issues multiple reads (up to
// four, across two families) and forwards each one's failure itself (it
// takes ctx/status_forwarded directly) rather than returning a single result
// for the caller to forward.
struct StatusReadResult {
    QuarStatus state = QuarStatus::inactive;
    std::string note;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    /// Set when the listing could not be trusted to be complete. Present on
    /// all three platform definitions of this struct even though only the
    /// Windows one currently sets it: the emit site reads `wl.note` OUTSIDE
    /// the `#ifdef` chain, so a member added to one definition and not the
    /// others is a compile error on the other two legs — which is exactly how
    /// this was added the first time. Honest-empty elsewhere.
    std::string note;
};

int linux_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips,
                     bool* v6_applied_out = nullptr) {
    bool status_forwarded = false;
    yuzu::quarantine::MutationTally v4;
    yuzu::quarantine::MutationTally v6;
    yuzu::quarantine::FlushOutcome flush;

    // An is_safe_ip-validated literal with neither '.' nor ':' (e.g. a
    // truncated/typo'd entry) is skipped by BOTH the v4 and v6 loops below
    // (ip_family() reports `unknown`) — counted here so the skip is surfaced
    // in the note rather than silently discarded, since an operator whose
    // entry never got attempted deserves to be told, not left believing it
    // was whitelisted.
    int unknown_family_ips = 0;
    for (const auto& ip : whitelist_ips) {
        if (yuzu::quarantine::ip_family(ip) == yuzu::quarantine::IpFamily::unknown)
            ++unknown_family_ips;
    }

    auto apply_v4 = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        v4.record(report_runner_result(ctx, status_forwarded, out.res));
    };
    // #3285 / CDX-P1-05: the flush is a PREREQUISITE, not a containment rule.
    // It stays OUT of the tally (a successful flush installs no containment by
    // itself), but its FAILURE is disqualifying: an unflushed chain keeps
    // whatever it held before — including a stale terminal DROP and a stale
    // whitelist — so every rule appended afterwards lands BEHIND that DROP and
    // is inert, while the tally, which only sees the appends, still reads a
    // clean N/N. Its result is therefore returned and folded via FlushOutcome.
    auto apply_flush_v4 = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        return report_runner_result(ctx, status_forwarded, out.res);
    };
    auto apply_ignore_v4 = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        // Best-effort/idempotent step (create-if-absent, remove-stale-jump)
        // — a nonzero exit here is expected on a fresh chain and was never
        // checked pre-migration. A genuine runner failure is still
        // forwarded so a broken sudoers grant surfaces on the FIRST call
        // that hits it, not silently on a later one. Never fed into the
        // MutationTally: this is not a counting containment rule (see
        // MutationTally's doc comment in quarantine_parsers.hpp).
        report_runner_result(ctx, status_forwarded, out.res);
    };

    // Create the yuzu-quarantine chain (ignore error if it already exists)
    // sink: quarantine/linux_quarantine#1 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_v4({kIptables, "-N", "yuzu-quarantine"});
    // Flush the chain to start fresh. Best-effort/non-counting like `-N`
    // above (pre-migration behaviour, `git show 313031966:...` at the
    // merge-base): a flush that succeeds installs zero containment rules by
    // itself, so it must never contribute to the tally — otherwise a
    // flush-only success with every subsequent ACCEPT/DROP/jump rule failing
    // would report a false-positive partial containment with zero real
    // rules in place.
    // sink: quarantine/linux_quarantine#2 — rung-2 sudo-governed runner argv, MUTATING (non-counting)
    flush.v4_ok = apply_flush_v4({kIptables, "-F", "yuzu-quarantine"});

    // Allow loopback
    // sink: quarantine/linux_quarantine#3 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-A", "yuzu-quarantine", "-i", "lo", "-j", "ACCEPT"});
    // sink: quarantine/linux_quarantine#4 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-A", "yuzu-quarantine", "-o", "lo", "-j", "ACCEPT"});

    // NO blanket "-m state --state ESTABLISHED,RELATED -j ACCEPT" here (site
    // #5, removed) — that accepted ANY pre-existing established/related
    // flow, Yuzu or not, so an attacker's C2/exfil session already open on a
    // host at quarantine time survived containment untouched. The
    // management connection is instead kept alive by the whitelist-based
    // rules just below: do_quarantine always tries to put the Yuzu server's
    // own address into whitelist_ips (operator-supplied server_ip, or the
    // agent's own known agent.server_address when that's already an IP
    // literal) before calling here, and a whitelist rule accepts ANY state
    // (not just established) for that IP, so the return leg of an already-
    // open management connection to a whitelisted peer keeps flowing. A
    // host whose agent.server_address is a hostname AND whose caller never
    // supplied server_ip is a narrower residual gap than before this fix,
    // not a new one -- see mcp_server.cpp's governance note at its one
    // known instance.

    // Allow each whitelisted IPv4 address. IPv6 literals are routed to the
    // ip6tables sequence below via ip_family() — never handed to iptables,
    // and vice versa (#3282).
    for (const auto& ip : whitelist_ips) {
        if (yuzu::quarantine::ip_family(ip) != yuzu::quarantine::IpFamily::v4)
            continue;
        // sink: quarantine/linux_quarantine#6 — rung-2 sudo-governed runner
        // argv, MUTATING, operator-supplied IP validated by is_safe_ip.
        // Argv construction lives in iptables_accept_source_argv
        // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
        apply_v4(yuzu::quarantine::iptables_accept_source_argv(kIptables, ip));
        // sink: quarantine/linux_quarantine#7 — rung-2 sudo-governed runner
        // argv, MUTATING, operator-supplied IP validated by is_safe_ip
        apply_v4({kIptables, "-A", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
    }

    // Drop everything else
    // sink: quarantine/linux_quarantine#8 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-A", "yuzu-quarantine", "-j", "DROP"});

    // Insert jump to our chain at the top of INPUT and OUTPUT
    // Remove any existing jumps first to avoid duplicates
    // sink: quarantine/linux_quarantine#9 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_v4({kIptables, "-D", "INPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#10 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_v4({kIptables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#11 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-I", "INPUT", "1", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#12 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-I", "OUTPUT", "1", "-j", "yuzu-quarantine"});

    // Probe the v6 environment by filesystem, NEVER by tool_ran — every
    // ip6tables call below is sudo_wrap-ed, so a SubprocessResult's
    // tool_ran only tells us sudo itself executed, not ip6tables (VERIFIED
    // at agents/shared/sudo_argv.hpp:34-46 and
    // agents/core/include/yuzu/agent/subprocess_runner.hpp:209-216). See
    // LinuxV6Env's doc comment (quarantine_parsers.hpp) for the three
    // honest outcomes this decides between.
    yuzu::quarantine::LinuxV6Env v6env{.tool_present = (::access(kIp6tables, F_OK) == 0),
                                      .stack_present = linux_ipv6_stack_present()};

    // v6_in_scope, not tool_present: an `ipv6.disable=1` host with the stock
    // iptables package installed has the tool and no stack, so every call
    // below would fail and the verdict would read `quarantined_partial` with
    // a note blaming the flush — on a host whose containment is complete.
    const bool v6_attempted = yuzu::quarantine::v6_in_scope(v6env);
    if (v6_applied_out)
        *v6_applied_out = v6_attempted;
    if (v6_attempted) {
        auto apply_v6 = [&](std::vector<std::string> tool_argv) {
            auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
            auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            v6.record(report_runner_result(ctx, status_forwarded, out.res));
        };
        // Same prerequisite semantics as apply_flush_v4 above.
        auto apply_flush_v6 = [&](std::vector<std::string> tool_argv) {
            auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
            auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            return report_runner_result(ctx, status_forwarded, out.res);
        };
        auto apply_ignore_v6 = [&](std::vector<std::string> tool_argv) {
            auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
            auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            report_runner_result(ctx, status_forwarded, out.res);
        };

        // sink: quarantine/linux_quarantine#13 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
        apply_ignore_v6({kIp6tables, "-N", "yuzu-quarantine"});
        // sink: quarantine/linux_quarantine#14 — rung-2 sudo-governed runner argv, MUTATING (non-counting)
        flush.v6_ok = apply_flush_v6({kIp6tables, "-F", "yuzu-quarantine"});

        // sink: quarantine/linux_quarantine#15 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-A", "yuzu-quarantine", "-i", "lo", "-j", "ACCEPT"});
        // sink: quarantine/linux_quarantine#16 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-A", "yuzu-quarantine", "-o", "lo", "-j", "ACCEPT"});

        // NO blanket ESTABLISHED,RELATED accept here either (site #17,
        // removed) — same reasoning as the IPv4 leg above: it accepted ANY
        // pre-existing established/related flow, not just the Yuzu
        // management connection, so it's the whitelist rules below that
        // must carry connection continuity instead. See the IPv4 comment
        // above for the full rationale.

        for (const auto& ip : whitelist_ips) {
            if (yuzu::quarantine::ip_family(ip) != yuzu::quarantine::IpFamily::v6)
                continue;
            // sink: quarantine/linux_quarantine#18 — rung-2 sudo-governed
            // runner argv, MUTATING, operator-supplied IP validated by
            // is_safe_ip. Argv construction lives in
            // iptables_accept_source_argv (quarantine_parsers.hpp) — the
            // same pure builder as the iptables site above, called with
            // kIp6tables (FN-03).
            apply_v6(yuzu::quarantine::iptables_accept_source_argv(kIp6tables, ip));
            // sink: quarantine/linux_quarantine#19 — rung-2 sudo-governed
            // runner argv, MUTATING, operator-supplied IP validated by
            // is_safe_ip
            apply_v6({kIp6tables, "-A", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
        }

        // sink: quarantine/linux_quarantine#20 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-A", "yuzu-quarantine", "-j", "DROP"});

        // sink: quarantine/linux_quarantine#21 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
        apply_ignore_v6({kIp6tables, "-D", "INPUT", "-j", "yuzu-quarantine"});
        // sink: quarantine/linux_quarantine#22 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
        apply_ignore_v6({kIp6tables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
        // sink: quarantine/linux_quarantine#23 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-I", "INPUT", "1", "-j", "yuzu-quarantine"});
        // sink: quarantine/linux_quarantine#24 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-I", "OUTPUT", "1", "-j", "yuzu-quarantine"});
    }

    const auto token = yuzu::quarantine::linux_quarantine_token(v4, v6, v6env, flush);
    const int succeeded = v4.succeeded + v6.succeeded;
    const int attempted = v4.attempted + v6.attempted;

    // Joins non-empty note fragments with "; " — shared by both branches
    // below so an ipv6_unavailable reason and an unknown-family skip count
    // (or a partial rule count) can coexist on one `note|` field without
    // hand-building the separator at each call site.
    auto join_notes = [](const std::vector<std::string>& parts) {
        std::string out;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i)
                out += "; ";
            out += parts[i];
        }
        return out;
    };
    // CDX-P1-05: name a failed flush explicitly. Without it the operator sees
    // `quarantined_partial` with a full rule count and no way to tell that the
    // chain was never cleared — which is the one fact that explains why the
    // rules that DID apply may be inert behind a stale DROP.
    const std::string flush_note =
        (!flush.v4_ok || (v6env.tool_present && !flush.v6_ok))
            ? std::string{"chain flush failed ("} +
                  (!flush.v4_ok ? "iptables" : "") +
                  ((!flush.v4_ok && v6env.tool_present && !flush.v6_ok) ? ", " : "") +
                  ((v6env.tool_present && !flush.v6_ok) ? "ip6tables" : "") +
                  ") — stale rules may remain in the chain and the rules applied "
                  "after it may be unreachable"
            : std::string{};

    const std::string unknown_note =
        unknown_family_ips > 0
            ? std::format("{} whitelist entr{} skipped (not a valid IPv4/IPv6 literal)",
                          unknown_family_ips, unknown_family_ips == 1 ? "y" : "ies")
            : std::string{};

    if (token == yuzu::quarantine::kStatusQuarantined) {
        std::vector<std::string> notes;
        if (!v6env.tool_present) {
            // Case (ii): IPv6 is off on this host (no ip6tables AND no v6
            // stack) — containment IS complete without it. A v4-only fleet
            // must not cry wolf forever, so this stays the `quarantined`
            // branch (ABI4 OK, rc 0), WITH a note explaining why v6 was
            // skipped rather than a degraded verdict.
            notes.push_back("ipv6_unavailable — no IPv6 stack on this host");
        }
        if (!unknown_note.empty())
            notes.push_back(unknown_note);
        if (notes.empty()) {
            ctx.write_output(std::format("status|quarantined|rules_applied|{}", succeeded));
        } else {
            ctx.write_output(std::format("status|quarantined|rules_applied|{}|note|{}", succeeded,
                                         join_notes(notes)));
        }
        return 0;
    }

    if (!status_forwarded) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "quarantine:linux_quarantine containment incomplete");
    }
    std::vector<std::string> notes;
    if (succeeded != attempted) {
        // Suppressed at succeeded==attempted (only reachable via case iii
        // below with v4 fully applied): "N of N containment rules applied"
        // read alongside `quarantined_partial` is self-contradictory —
        // every ATTEMPTED rule succeeded, the shortfall is entirely rules
        // that were never attempted, which the ipv6_unavailable reason
        // explains on its own.
        notes.push_back(std::format("{} of {} containment rules applied", succeeded, attempted));
    }
    if (!v6env.tool_present && v6env.stack_present) {
        // Case (iii): the IPv6 stack is up but ip6tables is not installed —
        // traffic that should be blocked is not. A structural gap, not a
        // transient failure, so it is named alongside the rule count.
        notes.push_back("ipv6_unavailable — IPv6 stack is up but ip6tables is not installed");
    }
    if (!flush_note.empty())
        notes.push_back(flush_note);
    if (!unknown_note.empty())
        notes.push_back(unknown_note);
    // token is kStatusQuarantinedPartial or kStatusFailed here — never a
    // hardcoded literal, so a total containment failure (0 succeeded) is
    // honestly reported as `failed`, not `quarantined_partial` (#3282
    // item c / acceptance criterion 5).
    ctx.write_output(std::format("status|{}|rules_applied|{}|note|{}", token, succeeded,
                                 join_notes(notes)));
    return 1;
}

int linux_unquarantine(yuzu::CommandContext& ctx, bool v6_was_applied) {
    bool status_forwarded = false;
    // Clean-failure tracker for the genuine teardown steps (flush + delete
    // chain) — see win_unquarantine's identical-purpose comment. Distinct
    // from the -D jump removals below, which stay best-effort/ignored:
    // they are idempotent the same way linux_quarantine's own -D calls are
    // (a jump that's already absent, e.g. on a repeat unquarantine, is not a
    // failure). Flushing/deleting the chain is the actual release action,
    // so a clean (tool-ran, nonzero-exit) failure there must surface.
    bool teardown_failed = false;

    auto apply_ignore_v4 = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        report_runner_result(ctx, status_forwarded, out.res);
    };
    auto apply_v4 = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (!report_runner_result(ctx, status_forwarded, out.res))
            teardown_failed = true;
    };

    // Remove jumps from INPUT and OUTPUT — best-effort/idempotent
    // sink: quarantine/linux_unquarantine#1 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_v4({kIptables, "-D", "INPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_unquarantine#2 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_v4({kIptables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
    // Flush and delete the chain — the genuine release steps
    // sink: quarantine/linux_unquarantine#3 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-F", "yuzu-quarantine"});
    // sink: quarantine/linux_unquarantine#4 — rung-2 sudo-governed runner argv, MUTATING
    apply_v4({kIptables, "-X", "yuzu-quarantine"});

    // Mirror onto ip6tables — driven by v6_was_applied (whether
    // linux_quarantine actually attempted the v6 sequence, persisted across
    // the quarantine->release call boundary), NOT by re-probing the CURRENT
    // stack state here. A fresh stack_present read at release time can
    // disagree with what was true at quarantine time -- e.g. the operator
    // disabled IPv6 in between -- and gating on it left v6 rules installed
    // at quarantine time undeleted (orphaned, reactivating if IPv6 comes
    // back) while still reporting `released`. Deliberate asymmetry (#3282
    // item 5) preserved for the OTHER direction: v6_was_applied false means
    // nothing was ever installed (out of scope at quarantine time, whether
    // for no tool or no stack), so THAT case must still not flip
    // teardown_failed. Applied-but-the-tool-is-gone-now is a genuine
    // "can't verify release" case, not a silent skip.
    const bool v6_tool_present = (::access(kIp6tables, F_OK) == 0);
    if (v6_was_applied && !v6_tool_present) {
        teardown_failed = true;
    } else if (v6_was_applied) {
        auto apply_ignore_v6 = [&](std::vector<std::string> tool_argv) {
            auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
            auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            report_runner_result(ctx, status_forwarded, out.res);
        };
        auto apply_v6 = [&](std::vector<std::string> tool_argv) {
            auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
            auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
            if (!report_runner_result(ctx, status_forwarded, out.res))
                teardown_failed = true;
        };

        // sink: quarantine/linux_unquarantine#5 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
        apply_ignore_v6({kIp6tables, "-D", "INPUT", "-j", "yuzu-quarantine"});
        // sink: quarantine/linux_unquarantine#6 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
        apply_ignore_v6({kIp6tables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
        // sink: quarantine/linux_unquarantine#7 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-F", "yuzu-quarantine"});
        // sink: quarantine/linux_unquarantine#8 — rung-2 sudo-governed runner argv, MUTATING
        apply_v6({kIp6tables, "-X", "yuzu-quarantine"});
    }

    if (status_forwarded || teardown_failed) {
        // See win_unquarantine's identical comment: a genuine runner
        // failure, OR a clean failure to flush/delete a chain, must never
        // be reported as "released".
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:linux_unquarantine chain flush/delete failed");
        }
        ctx.write_output("status|release_uncertain");
        return 1;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult linux_is_quarantined(yuzu::CommandContext& ctx, bool& status_forwarded) {
    // -L is a read-only list operation; depending on the distro and kernel
    // build, iptables will refuse the operation without root even for
    // listing because /proc/net/ip_tables_names is root-readable. So we
    // also use sudo for the read path.
    // sink: quarantine/linux_is_quarantined#1 — rung-2 sudo-governed runner argv, read-only
    auto in_argv = yuzu::shared::sudo_wrap({kIptables, "-L", "INPUT", "-n"});
    auto in_out = run_tool(in_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    // CDX-P1-04: track whether the REQUIRED reads actually succeeded. An
    // empty capture from a failed listing is indistinguishable from a host
    // with no containment, so the flags alone cannot tell `inactive` from
    // `unreadable` — that distinction has to come from the read result.
    bool reads_ok = report_runner_result(ctx, status_forwarded, in_out.res);
    const bool v4_in = yuzu::quarantine::iptables_chain_referenced(in_out.output);

    // sink: quarantine/linux_is_quarantined#2 — rung-2 sudo-governed runner argv, read-only
    auto out_argv = yuzu::shared::sudo_wrap({kIptables, "-L", "OUTPUT", "-n"});
    auto out_out = run_tool(out_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    reads_ok = report_runner_result(ctx, status_forwarded, out_out.res) && reads_ok;
    const bool v4_out = yuzu::quarantine::iptables_chain_referenced(out_out.output);

    // Probe the v6 environment by filesystem, NEVER by tool_ran — see
    // linux_quarantine's identical rationale above. F_OK, not X_OK: every
    // ip6tables call is sudo_wrap'd and runs as ROOT, so the agent account's
    // own execute bit is the wrong principal to test — a CIS/STIG host ships
    // /usr/sbin/ip6tables 0750 root:root, where X_OK reported the tool absent,
    // skipped the entire v6 sequence, and still emitted status|quarantined:
    // #3282's original defect wearing the fix's clothes. Failing the other way
    // is safe — a call sudo refuses is tallied and reported honestly.
    yuzu::quarantine::LinuxV6Env v6env{.tool_present = (::access(kIp6tables, F_OK) == 0),
                                      .stack_present = linux_ipv6_stack_present()};

    bool v6_in = false;
    bool v6_out = false;
    // Same predicate as the mutation path — the read must judge the host by
    // exactly what the mutation attempted, or the two disagree.
    if (yuzu::quarantine::v6_in_scope(v6env)) {
        // sink: quarantine/linux_is_quarantined#3 — rung-2 sudo-governed runner argv, read-only
        auto v6_in_argv = yuzu::shared::sudo_wrap({kIp6tables, "-L", "INPUT", "-n"});
        auto v6_in_out = run_tool(v6_in_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
        reads_ok = report_runner_result(ctx, status_forwarded, v6_in_out.res) && reads_ok;
        v6_in = yuzu::quarantine::iptables_chain_referenced(v6_in_out.output);

        // sink: quarantine/linux_is_quarantined#4 — rung-2 sudo-governed runner argv, read-only
        auto v6_out_argv = yuzu::shared::sudo_wrap({kIp6tables, "-L", "OUTPUT", "-n"});
        auto v6_out_out = run_tool(v6_out_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
        reads_ok = report_runner_result(ctx, status_forwarded, v6_out_out.res) && reads_ok;
        v6_out = yuzu::quarantine::iptables_chain_referenced(v6_out_out.output);
    }

    StatusReadResult result;
    result.state = yuzu::quarantine::linux_quar_status(v4_in, v4_out, v6_in, v6_out, v6env, reads_ok);

    // A jump proves a POINTER exists, not that the chain it points at denies
    // anything — and a referenced-but-empty chain is reachable: release
    // deletes the two jumps as idempotent best-effort cleanups, so under
    // xtables lock contention both can fail past the deadline while the flush
    // succeeds. The host is then jumps-present, chain-empty, policy ACCEPT,
    // and every later poll read `active` on a device blocking nothing. Windows
    // verifies the profile policy and macOS verifies pf is live; this is the
    // Linux equivalent, and it was the leg that had none.
    //
    // Only when the jumps say something IS installed: an `inactive` host has
    // no chain to list, and probing it on every routine poll would spend a
    // subprocess to learn nothing.
    if (result.state == QuarStatus::active || result.state == QuarStatus::partial) {
        // sink: quarantine/linux_is_quarantined#5 — rung-2 sudo-governed runner argv, read-only
        auto v4_chain_argv = yuzu::shared::sudo_wrap({kIptables, "-L", "yuzu-quarantine", "-n"});
        auto v4_chain = run_tool(v4_chain_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
        const bool v4_chain_read_ok = report_runner_result(ctx, status_forwarded, v4_chain.res);
        bool denies = yuzu::quarantine::iptables_chain_denies(v4_chain.output);
        bool chain_reads_ok = v4_chain_read_ok;

        if (yuzu::quarantine::v6_in_scope(v6env)) {
            // sink: quarantine/linux_is_quarantined#6 — rung-2 sudo-governed runner argv, read-only
            auto v6_chain_argv =
                yuzu::shared::sudo_wrap({kIp6tables, "-L", "yuzu-quarantine", "-n"});
            auto v6_chain = run_tool(v6_chain_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
            chain_reads_ok = report_runner_result(ctx, status_forwarded, v6_chain.res) &&
                             chain_reads_ok;
            denies = denies && yuzu::quarantine::iptables_chain_denies(v6_chain.output);
        }

        if (!chain_reads_ok) {
            // Same rule as every other read on this leg: an unreadable answer
            // is `uncertain`, never a clean one.
            result.state = QuarStatus::uncertain;
            reads_ok = false;
        } else if (!denies) {
            result.state = QuarStatus::partial;
            result.note = "the yuzu-quarantine chain is referenced but does not deny — the jump "
                          "rules are present and the chain is empty, so nothing is being blocked";
        }
    }

    if (!reads_ok)
        result.note = "chain listing failed — containment state could not be determined";
    // The note only qualifies an actual containment verdict — an `inactive`
    // device was never quarantined, so an ipv6_unavailable reason has
    // nothing to qualify and would just be noise on every routine poll of
    // every never-quarantined v4-only host.
    if (!v6env.tool_present && result.state != QuarStatus::inactive) {
        result.note = v6env.stack_present
                          ? "ipv6_unavailable — IPv6 stack is up but ip6tables is not installed"
                          : "ipv6_unavailable — no IPv6 stack on this host";
    }
    return result;
}

WhitelistRead linux_get_whitelist(yuzu::CommandContext& ctx, bool& status_forwarded) {
    // sink: quarantine/linux_get_whitelist#1 — rung-2 sudo-governed runner argv, read-only
    auto v4_argv = yuzu::shared::sudo_wrap({kIptables, "-L", "yuzu-quarantine", "-n"});
    auto v4_out = run_tool(v4_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    report_runner_result(ctx, status_forwarded, v4_out.res);
    auto ips = yuzu::quarantine::iptables_whitelist_ips(v4_out.output);

    // Probe the v6 environment by filesystem, NEVER by tool_ran — see
    // linux_quarantine's identical rationale above. F_OK, not X_OK: every
    // ip6tables call is sudo_wrap'd and runs as ROOT, so the agent account's
    // own execute bit is the wrong principal to test — a CIS/STIG host ships
    // /usr/sbin/ip6tables 0750 root:root, where X_OK reported the tool absent,
    // skipped the entire v6 sequence, and still emitted status|quarantined:
    // #3282's original defect wearing the fix's clothes. Failing the other way
    // is safe — a call sudo refuses is tallied and reported honestly. Without this, the IPv6
    // whitelist entries linux_quarantine's ip6tables mirror adds would
    // never appear in `status` (#3282).
    if (::access(kIp6tables, F_OK) == 0) {
        // sink: quarantine/linux_get_whitelist#2 — rung-2 sudo-governed runner argv, read-only
        auto v6_argv = yuzu::shared::sudo_wrap({kIp6tables, "-L", "yuzu-quarantine", "-n"});
        auto v6_out = run_tool(v6_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
        report_runner_result(ctx, status_forwarded, v6_out.res);
        ips = yuzu::quarantine::merge_whitelist_ips(
            std::move(ips), yuzu::quarantine::iptables_whitelist_ips(v6_out.output));
    }

    WhitelistRead result;
    result.ips = std::move(ips);
    return result;
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

// state/note: item 7 of #3282 — mechanical bool active -> QuarStatus state
// change. #3283 extends this with a live pf-enabled verification read — see
// macos_is_quarantined.
struct StatusReadResult {
    QuarStatus state = QuarStatus::inactive;
    std::string note;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    yuzu::agent::SubprocessResult res;
    /// Set when the listing could not be trusted to be complete. Present on
    /// all three platform definitions of this struct even though only the
    /// Windows one currently sets it: the emit site reads `wl.note` OUTSIDE
    /// the `#ifdef` chain, so a member added to one definition and not the
    /// others is a compile error on the other two legs — which is exactly how
    /// this was added the first time. Honest-empty elsewhere.
    std::string note;
};

// Compose-and-load the complete pf ruleset for a quarantine state.
//
// `rules_written_out` is set to the count of rule lines we wrote.
// `error_out` is set to a non-empty operator-actionable string on
// failure; caller writes it to ctx.write_output.
//
// Returns 0 on success, non-zero on failure. Used by both
// macos_quarantine() and the macOS branch of do_whitelist() so the
// "rebuild the ruleset and atomically load it" logic lives in one
// place. See the header comment above (and `git log -1 672896112`) for
// why this MUST stay ONE atomic `pfctl -f` call against the main
// ruleset with `set skip on lo0` — never a named anchor.
int macos_load_ruleset(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips,
                       int* rules_written_out, std::string* error_out,
                       bool* pf_enable_failed_out = nullptr) {
    int rules_written = 0;
    std::string rules;

    rules += "# Yuzu agent quarantine — generated by quarantine_plugin.cpp\n";
    rules += "# DO NOT edit by hand; this file is overwritten on every dispatch.\n";
    rules += "# Restore via `pfctl -f /etc/pf.conf` (macos_unquarantine does this).\n";
    rules += "\n";
    rules += "# Bypass loopback entirely — keeps agent⇄gateway⇄server TCP alive\n";
    rules += "# through the rule reload. See comment in quarantine_plugin.cpp.\n";
    rules += "set skip on lo0\n";
    ++rules_written;

    for (const auto& ip : whitelist_ips) {
        rules += std::format("pass quick from {} to any keep state\n", ip);
        rules += std::format("pass quick from any to {} keep state\n", ip);
        rules_written += 2;
    }

    rules += "block all\n";
    ++rules_written;

    auto tmp_file_result = yuzu::TempFile::create("yuzu-quarantine-", ".conf");
    if (!tmp_file_result) {
        *error_out = "failed to create temp file for pf rules";
        return 1;
    }
    auto tmp_file = std::move(*tmp_file_result);
    {
        // The write is CHECKED, including the close, and a failure is fatal to
        // the action.
        //
        // The previous form discarded both `fputs` and `fclose`. A composed
        // ruleset is a few hundred bytes, so it sits entirely in one stdio
        // buffer and nothing reaches the disk until the close — which is
        // exactly where an ENOSPC/EDQUOT on the temp volume surfaces. That
        // left a ZERO-BYTE file, and an empty pf ruleset is not a rejected
        // ruleset: `pfctl -f` parses it happily and exits 0, because an empty
        // ruleset is a pass-everything ruleset. Every downstream check then
        // agreed the containment was fine — `pfctl -e` succeeded, the #3283
        // verification read returned `Status: Enabled`, and the action
        // reported `status|quarantined|rules_applied|4` with an OK result
        // status on a host where `block all` had never existed. Confirming pf
        // is ENABLED says nothing about whether it is enforcing anything.
        //
        // std::ofstream rather than a checked FILE*: the stream owns the
        // handle, so the early return below cannot leak it, and an explicit
        // close() is what turns a deferred flush failure into a testable bit
        // instead of a discarded return value.
        std::ofstream out(tmp_file.path(), std::ios::binary | std::ios::trunc);
        if (!out) {
            *error_out = "failed to write pf rules";
            return 1;
        }
        out << rules;
        out.close();
        if (!out) {
            // Do NOT fall through to pfctl -f. A partial or empty ruleset that
            // loads cleanly is the false-success this whole change exists to
            // eliminate.
            *error_out = "failed to write pf rules (the ruleset did not reach disk intact)";
            return 1;
        }
    }

    // sink: quarantine/macos_load_ruleset#1 — rung-2 sudo-governed runner
    // argv, MUTATING, single atomic full-ruleset reload
    // (`sudo -n -- /sbin/pfctl -f <tmpfile>`). THE call this migration is
    // bound not to change the shape of — see the header comment on the
    // 672896112 incident: never split this into a named-anchor `pfctl -a`
    // plus a second attach call. Argv construction lives in
    // pfctl_load_ruleset_argv (quarantine_parsers.hpp) — pure and
    // unit-tested (FN-03).
    auto argv = yuzu::shared::sudo_wrap(
        yuzu::quarantine::pfctl_load_ruleset_argv(kPfctl, tmp_file.path()));
    auto load_out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
    if (!(load_out.res.tool_ran && load_out.res.exit_code == 0)) {
        // A quarantine that silently fails to apply is the single most
        // safety-critical failure mode in this file — always mark the ABI4
        // result seam, whether the failure is a genuine runner-level event
        // (spawn/deadline/etc, forwarded below) or a clean exit with a
        // nonzero rc (e.g. a missing sudoers grant, which exits normally
        // from sudo's own perspective — exit-code semantics are the
        // caller's domain per runner_status.hpp, so classify_runner_failure
        // alone would miss this case).
        if (!yuzu::agent::forward_runner_failure(ctx, load_out.res)) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:macos_load_ruleset pfctl exited non-zero");
        }
        int exit_code = load_out.res.tool_ran ? load_out.res.exit_code : -1;
        std::string diag = load_out.output.empty()
                               ? std::string{}
                               : std::format(" pfctl said: {}",
                                             yuzu::util::safe_output_field(load_out.output));
        *error_out = std::format("pfctl load failed (rc={}). Likely the agent account "
                                 "is not in /etc/sudoers.d/yuzu-agent — run "
                                 "`sudo bash scripts/install-agent-user.sh --check` to verify.{}",
                                 exit_code, diag);
        return 1;
    }

    // Enable pf, then VERIFY — and the verification is unconditional, because
    // `pfctl -e`'s exit code answers the wrong question in both directions.
    //
    // Downward: `pfctl -e` on an ALREADY-ENABLED pf calls
    // `errx(1, "pf already enabled")` — it exits 1. Treating that as terminal
    // meant every re-quarantine and every whitelist repair of a contained
    // macOS host reported `quarantined_partial` / `update_uncertain` with rc 1
    // on a host that was fully contained, and skipped the verification read
    // that would have proved it. #3127's already_active re-dispatch makes the
    // second quarantine routine, and `whitelist` repair of a CONTAINED device
    // is the flow the containment exemption exists to keep reachable — on
    // macOS it could never report success.
    //
    // Upward: `-e` exiting 0 does not prove pf came up, which is #3283's own
    // failure mode.
    //
    // So the enable call's exit code decides nothing on its own. `pfctl -s
    // info` does, and it is issued either way. A non-zero `-e` is still
    // forwarded as diagnostic context when the verification ALSO says pf is
    // not enabled — the two together are the honest signal, and neither is
    // one alone.
    // sink: quarantine/macos_load_ruleset#2 — rung-2 sudo-governed runner
    // argv, MUTATING (idempotent enable; verified below, never trusted)
    auto enable_argv = yuzu::shared::sudo_wrap({kPfctl, "-e"});
    auto enable_out = run_tool(enable_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
    const bool enable_exit_ok = enable_out.res.tool_ran && enable_out.res.exit_code == 0;

    // sink: quarantine/macos_load_ruleset#3 — rung-2 sudo-governed
    // runner argv, read-only verification of the enable step above
    auto verify_argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "info"});
    auto verify_out = run_tool(verify_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    const bool pf_confirmed_enabled = yuzu::quarantine::pfctl_status_state(verify_out.output) ==
                                      yuzu::quarantine::PfStatus::enabled;

    if (!pf_confirmed_enabled) {
        // Report the verification's failure first — it is the authoritative
        // one. Fall back to the enable call's own failure only when the
        // verification itself could not be run.
        if (!yuzu::agent::forward_runner_failure(ctx, verify_out.res) &&
            !yuzu::agent::forward_runner_failure(ctx, enable_out.res)) {
            ctx.set_result_status(
                YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                enable_exit_ok
                    ? "quarantine:macos_load_ruleset pfctl -e exited 0 but pf is not actually enabled"
                    : "quarantine:macos_load_ruleset pf is not enabled and pfctl -e failed");
        }
    }

    if (!pf_confirmed_enabled) {
        // The ABI4 result seam above is the durable, server-persisted signal
        // -- but it isn't the channel most customer-facing tooling parses
        // (docs/user-manual/agent-plugins.md documents write_output's
        // pipe-delimited fields as the contract). Surface it there too, via
        // the out-param, so a caller that only reads stdout still learns
        // the ruleset loaded but pf may not be enforcing it.
        if (pf_enable_failed_out)
            *pf_enable_failed_out = true;
    }

    *rules_written_out = rules_written;
    return 0;
}

int macos_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    // rules_written counts the lines we hand to pfctl. The actual number
    // of rules installed in pf is reported back to the operator only if
    // pfctl's load succeeds (see the rc check inside macos_load_ruleset).
    int rules_written = 0;
    std::string error;
    bool pf_enable_failed = false;
    if (macos_load_ruleset(ctx, whitelist_ips, &rules_written, &error, &pf_enable_failed) != 0) {
        ctx.write_output(std::format("error|{}", error));
        return 1;
    }
    if (pf_enable_failed) {
        // #3283: a ruleset that loaded but that pf never actually enforces
        // (pfctl -e failed, or exited 0 without pf coming up — see
        // macos_load_ruleset's verification read) is NOT a successful
        // quarantine. Reporting `status|quarantined` here regardless was the
        // exact #3283 failure: the device is not actually contained, and the
        // caller could not tell.
        ctx.write_output(std::format(
            "status|{}|rules_applied|{}|note|ruleset loaded but pf failed to enable "
            "-- traffic may not actually be blocked, check agent logs",
            yuzu::quarantine::kStatusQuarantinedPartial, rules_written));
        return 1;
    }
    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_written));
    return 0;
}

int macos_unquarantine(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;

    // Restore the system default ruleset by reloading /etc/pf.conf.
    // macOS ships /etc/pf.conf with the platform's default anchors
    // (com.apple/*, etc.). After our quarantine clobbered the main
    // ruleset, this is the cleanest way to get back to "what the OS
    // started with" without trying to remember and replay the prior
    // state ourselves.
    // sink: quarantine/macos_unquarantine#1 — rung-2 sudo-governed runner argv, MUTATING
    auto restore_argv = yuzu::shared::sudo_wrap({kPfctl, "-f", "/etc/pf.conf"});
    auto restore_out = run_tool(restore_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
    bool restore_ok = report_runner_result(ctx, status_forwarded, restore_out.res);

    if (!restore_ok) {
        // /etc/pf.conf might not exist or might fail to parse on a
        // non-default OS install. Fall back to disabling pf entirely —
        // strictly more permissive than what the user wants, but at
        // least the box is reachable for the operator to clean up.
        // sink: quarantine/macos_unquarantine#2 — rung-2 sudo-governed runner argv, MUTATING
        auto disable_argv = yuzu::shared::sudo_wrap({kPfctl, "-d"});
        auto disable_out = run_tool(disable_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
        bool disable_ok = report_runner_result(ctx, status_forwarded, disable_out.res);

        if (!disable_ok) {
            // Neither restoring /etc/pf.conf NOR disabling pf outright
            // succeeded — the host may still be firewalled. Reporting
            // "released" here unconditionally (the pre-migration behaviour
            // — this fallback call's return value was previously discarded
            // entirely) is exactly the silent-failure class this migration
            // must not reintroduce; see the 672896112 incident note at the
            // top of this file.
            if (!status_forwarded) {
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      "quarantine:macos_unquarantine restore and disable both failed");
            }
            ctx.write_output(
                "error|failed to restore /etc/pf.conf and failed to disable pf — host may "
                "still be firewalled, manual `pfctl -F all` may be required");
            return 1;
        }

        ctx.write_output("status|released|note|pf disabled (could not restore /etc/pf.conf)");
        return 0;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult macos_is_quarantined(yuzu::CommandContext& ctx, bool& status_forwarded) {
    // We're quarantined iff the active main ruleset has our `block all`
    // rule (the load-bearing default-deny). Pre-patch this looked at the
    // yuzu-quarantine anchor; the new design writes the rules directly into
    // the main ruleset so we check there instead.
    // sink: quarantine/macos_is_quarantined#1 — rung-2 sudo-governed runner argv, read-only
    auto rules_argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "rules"});
    auto rules_out = run_tool(rules_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    // CDX-P1-04 on the macOS leg: keep the read's own success, do not discard
    // it. An empty capture from a FAILED listing is indistinguishable from a
    // host with no containment, so `rules_blocked` alone reports a contained
    // host as `inactive` the moment the read stops working.
    bool reads_ok = report_runner_result(ctx, status_forwarded, rules_out.res);
    const bool rules_blocked = yuzu::quarantine::pfctl_rules_blocked(rules_out.output);

    // #3283: a blocking ruleset alone does not prove traffic is actually
    // blocked -- pf itself might be loaded but disabled (stock macOS ships
    // pf off). Read `pfctl -s info` so that case reads `degraded`, never a
    // false `active`; a read that returns no recognisable status (e.g. a
    // non-root capture) reads `uncertain`, never `active` and never
    // `inactive`.
    // sink: quarantine/macos_is_quarantined#2 — rung-2 sudo-governed runner
    // argv, read-only
    auto info_argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "info"});
    auto info_out = run_tool(info_argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    reads_ok = report_runner_result(ctx, status_forwarded, info_out.res) && reads_ok;
    const auto pf_status = yuzu::quarantine::pfctl_status_state(info_out.output);

    StatusReadResult result;
    result.state = yuzu::quarantine::macos_quar_status(rules_blocked, pf_status, reads_ok);

    if (result.state == QuarStatus::degraded) {
        result.note = "pf ruleset loaded but pf is disabled -- traffic is NOT being blocked";
        if (!status_forwarded) {
            ctx.set_result_status(
                YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                "quarantine:macos_is_quarantined pf ruleset loaded but pf is disabled");
            status_forwarded = true;
        }
    } else if (result.state == QuarStatus::uncertain) {
        // Two ways to land here, and the operator needs to know which: a read
        // that FAILED outright (revoked sudoers grant, pf device busy), or a
        // read that succeeded and returned nothing recognisable.
        result.note = reads_ok ? "pf status read returned no recognisable status"
                               : "pf state could not be read -- containment can be neither "
                                 "confirmed nor ruled out";
        if (!status_forwarded) {
            // UNAVAILABLE, matching the Linux/Windows `uncertain` paths and
            // macOS's own `degraded` above. Marking it OK here made the durable
            // channel read "fine" for an undetermined macOS host while the same
            // state on the other two legs read UNAVAILABLE — a compliance
            // poller on the seam would see a platform-dependent answer to the
            // same question.
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:macos_is_quarantined pf status unreadable");
            status_forwarded = true;
        }
    }
    return result;
}

WhitelistRead macos_get_whitelist() {
    // sink: quarantine/macos_get_whitelist#1 — rung-2 sudo-governed runner argv, read-only
    auto argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "rules"});
    auto out = run_tool(argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    WhitelistRead result;
    result.ips = yuzu::quarantine::pfctl_whitelist_ips(out.output);
    result.res = std::move(out.res);
    return result;
}

#endif // __APPLE__

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Wave-2 ADR-3002 migration: every leg on every platform now shells out
// through yuzu::agent::run_bounded_subprocess with clean, pre-split argv —
// never popen()/_popen(), never a shell. Linux (sudo-governed iptables) and
// macOS (sudo-governed pfctl) go through yuzu::shared::sudo_wrap's `sudo -n
// -- <tool> <args>` form; Windows (netsh) needs no sudo-equivalent, since
// the YuzuAgent service account's own privilege already covers it. That is
// rung 2 throughout — a bounded direct-argv tool invocation, whether or not
// sudo-governed, is not rung 1 (no native OS API is used; Windows in
// particular has a native COM firewall-rule API — INetFwPolicy2/
// INetFwRule — that this migration deliberately did not evaluate, since the
// task was mechanism-only). quarantine is the endpoint's most disruptive
// action here — it blocks essentially all traffic except the whitelist —
// so it is classified Destructive AND Irreversible. `unquarantine` restores
// reachability — scripts/test/instructions_quarantine_survivor.py verifies
// end-to-end that the box is NOT left locked out — but that is connectivity
// restoration, not STATE restoration: on macOS `macos_load_ruleset` replaces
// the whole active pf ruleset via `pfctl -f`, and `macos_unquarantine`
// deliberately restores only the OS-default /etc/pf.conf rather than replaying
// the prior state, so any runtime pf rules the endpoint had are permanently
// lost. Only Linux (a Yuzu-owned iptables chain) and Windows have a genuine
// undo, so the catalogue row is Irreversible across all platforms — see
// server/core/src/capability_decls/plugin_action_catalogue_c.hpp.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "quarantine",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "unquarantine",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "status",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "whitelist",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
};

} // namespace

// ── Plugin class ─────────────────────────────────────────────────────────────

class QuarantinePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
    std::string_view description() const noexcept override {
        return "Device network isolation (quarantine) with per-IP whitelisting";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"quarantine", "unquarantine", "status", "whitelist", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    // #3284: the Windows release path has to put back the profile policy
    // quarantine replaced, and the two calls are separate command executions —
    // often separate agent PROCESSES, since a host can be quarantined for days.
    // So the captured policy has to outlive the call that captured it, which
    // means durable plugin KV storage. Only PluginContext exposes it, and only
    // init() receives one, so the raw handle is cached here — the ABI documents
    // this exact use ("for caching across calls", plugin.hpp). Non-owning: the
    // host owns the context and outlives the plugin.
    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();
        return {};
    }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "quarantine") {
            return do_quarantine(ctx, params);
        }
        if (action == "unquarantine") {
            return do_unquarantine(ctx);
        }
        if (action == "status") {
            return do_status(ctx);
        }
        if (action == "whitelist") {
            return do_whitelist(ctx, params);
        }

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    static constexpr const char* kName = "quarantine";

    /// Storage key holding the profile policy that was in force when this host
    /// was quarantined, so release can put it back rather than overwriting the
    /// admin's posture with Microsoft's default (#3284). Windows-only in use;
    /// declared unconditionally so the key name has one definition.
    static constexpr const char* kPriorPolicyKey = "win.prior_firewall_policy";

    /// Whether linux_quarantine actually attempted the ip6tables sequence on
    /// the current quarantine cycle — read back by linux_unquarantine so
    /// release-time teardown is driven by what was truly installed, not by
    /// a fresh (and possibly now-disagreeing) stack_present probe. Written
    /// on every quarantine call (never left stale from a prior cycle);
    /// cleared only once release fully succeeds — see do_unquarantine's
    /// clear_prior_policy for the identical retry-safety reasoning on
    /// Windows. Linux-only in use; declared unconditionally so the key name
    /// has one definition.
    static constexpr const char* kLinuxV6AppliedKey = "linux.v6_applied";

    /// Non-owning; the host owns the context and outlives the plugin. Null
    /// only if init() was never called, which the host contract forbids —
    /// every accessor below still tolerates it rather than dereferencing.
    YuzuPluginContext* plugin_ctx_ = nullptr;

    /// WRITE-ONCE until release clears it.
    ///
    /// Re-quarantining an already-contained host captures the QUARANTINE policy
    /// (block/block on all three profiles), which is a structurally VALID and
    /// COMPLETE record — nothing downstream can tell it from a genuine one.
    /// Overwriting the real pre-quarantine policy with it means release replays
    /// block/block, reports `status|released` with no warning, and leaves the
    /// host cut off while the fleet believes it was freed: the 672896112
    /// stranding class reached by a different route. The second quarantine is
    /// not hypothetical — #3127's `already_active` re-dispatch (added in this
    /// same change), an operator re-issue, and a PolicyEvaluator remediation
    /// burst all reach it.
    ///
    /// Refusing the overwrite is correct, not merely cautious: the FIRST
    /// capture is the only one taken before this plugin altered the policy, so
    /// it is the only true restore image. A later capture carries nothing the
    /// first does not.
    /// Three outcomes, not two. `already_present` is a SUCCESS for the caller
    /// and must not be reported as a failure to store.
    ///
    /// Collapsing it into `false` made every re-quarantine of a Windows host
    /// report `COMPLETENESS_PARTIAL` with "the pre-quarantine firewall policy
    /// could not be stored — release will restore the Windows default
    /// instead". Both halves of that were false on the path that reaches it
    /// most often: the record from the first quarantine is intact, and release
    /// will replay it. Telling an operator otherwise invites them to reset the
    /// profile policy by hand, which destroys the very record the write-once
    /// guard was protecting. #3127's `already_active` re-dispatch makes the
    /// second quarantine routine, not exceptional.
    enum class PriorPolicyStore { stored, already_present, refused };

    PriorPolicyStore store_prior_policy(const std::string& serialized,
                                        bool already_contained_by_us) {
        if (!plugin_ctx_ || serialized.empty())
            return PriorPolicyStore::refused;

        // Existence is checked FIRST, before the shape test below. On a
        // re-quarantine the capture IS quarantine-shaped (this plugin put that
        // policy there), so testing shape first would classify the ordinary
        // re-quarantine as `refused` and resurrect the false PARTIAL report.
        // ABI: 0 exists, 1 not found, negative error.
        const int exists = yuzu_ctx_storage_exists(plugin_ctx_, kPriorPolicyKey);
        if (exists == 0)
            return PriorPolicyStore::already_present;
        // An error reading storage is NOT a licence to overwrite: with no
        // record release takes the honest default-restore fallback and says
        // so, which is recoverable; overwriting a good record with a
        // quarantine-shaped one strands the host and reports success.
        if (exists != 1)
            return PriorPolicyStore::refused;

        // Belt: refuse a block/block capture ONLY when it is our own containment
        // policy read back — the case where storage was cleared while the host
        // stayed contained. Such a record is unrestorable by construction, and
        // unlike the `already_present` case above there is nothing good behind
        // it, so this one IS a failure to store and the caller should say so.
        //
        // But block/block is ALSO a legitimate hardened posture, and refusing
        // it there was its own defect: release then wrote Microsoft's
        // `blockinbound,allowoutbound` default and silently removed the egress
        // filtering an admin or GPO had configured. `already_contained_by_us`
        // is what separates the two — see the read in `win_quarantine`. It is
        // conservative on an unreadable answer, so the stranding outcome is
        // never reached on a guess.
        if (already_contained_by_us &&
            yuzu::quarantine::is_quarantine_shaped_policy(
                yuzu::quarantine::parse_profile_policies(serialized)))
            return PriorPolicyStore::refused;

        yuzu::PluginContext pc{plugin_ctx_};
        return pc.storage_set(kPriorPolicyKey, serialized) ? PriorPolicyStore::stored
                                                           : PriorPolicyStore::refused;
    }

    std::string load_prior_policy() {
        if (!plugin_ctx_)
            return {};
        yuzu::PluginContext pc{plugin_ctx_};
        return pc.storage_get(kPriorPolicyKey);
    }

    void clear_prior_policy() {
        if (!plugin_ctx_)
            return;
        yuzu::PluginContext pc{plugin_ctx_};
        pc.storage_delete(kPriorPolicyKey);
    }

    // ORs `applied` into whatever marker is already stored, rather than
    // overwriting it -- a re-quarantine cycle that finds v6 out of scope
    // (IPv6 disabled since the FIRST quarantine, ip6tables uninstalled,
    // etc.) does not itself redo or undo the earlier v6 chain: it just skips
    // the v6 block on this call, leaving whatever the first quarantine
    // installed untouched. Overwriting the marker with this call's own
    // (false) v6_attempted would discard the memory that a real chain from
    // an earlier cycle may still need tearing down at release. Once true,
    // the marker only clears via clear_linux_v6_applied() on a fully clean
    // release. Returns whether the write itself succeeded, so the caller can
    // report an honest partial result rather than silently trusting a
    // storage failure to have recorded anything.
    bool store_linux_v6_applied(bool applied) {
        if (!plugin_ctx_)
            return false;
        yuzu::PluginContext pc{plugin_ctx_};
        const bool combined = applied || load_linux_v6_applied();
        if (combined)
            return pc.storage_set(kLinuxV6AppliedKey, "1");
        return pc.storage_delete(kLinuxV6AppliedKey);
    }

    bool load_linux_v6_applied() {
        if (!plugin_ctx_)
            return false;
        yuzu::PluginContext pc{plugin_ctx_};
        return pc.storage_get(kLinuxV6AppliedKey) == "1";
    }

    void clear_linux_v6_applied() {
        if (!plugin_ctx_)
            return;
        yuzu::PluginContext pc{plugin_ctx_};
        pc.storage_delete(kLinuxV6AppliedKey);
    }
    static constexpr const char* kVersion = "1.0.0";

    // ── quarantine action ────────────────────────────────────────────────────

    int do_quarantine(yuzu::CommandContext& ctx, yuzu::Params params) {
        // #3286: serialize against any other in-flight mutating action on
        // this plugin (quarantine/unquarantine/whitelist all share one
        // gate) — see quarantine_serialization.hpp for the full rationale.
        auto mutation_guard = enter_quarantine_mutation();
        if (!mutation_guard.has_value()) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine: another mutating quarantine action is in progress");
            ctx.write_output("status|busy");
            return 1;
        }

        auto server_ip = params.get("server_ip");
        auto whitelist_csv = params.get("whitelist_ips");

        // Build the full whitelist: always include loopback + management server
        std::vector<std::string> whitelist;

        if (!server_ip.empty() && is_safe_ip(server_ip)) {
            whitelist.emplace_back(server_ip);
        }

        auto add_whitelist_ip = [&whitelist](std::string ip) {
            for (const auto& existing : whitelist) {
                if (existing == ip)
                    return;
            }
            whitelist.push_back(std::move(ip));
        };

        // The operator-supplied server_ip above is not always present — the
        // MCP quarantine_device dispatch path (the ONLY live-isolation
        // trigger; REST only records the intent) never sets it, despite its
        // own tool description promising "whitelisting the management
        // server" (see the governance note and tool description at its
        // call site in mcp_server.cpp). Fall back to the agent's OWN known
        // connection target -- but read it PRE-RESOLVED
        // ("agent.server_address_resolved", computed once at agent startup
        // by agent.cpp via yuzu::agent::resolve_server_address_literals,
        // never here). Deliberately NOT resolved at quarantine-dispatch
        // time: that would let the host BEING quarantined decide, via its
        // own live DNS resolution, which address survives its own
        // containment -- exactly the trust a possibly-already-compromised
        // host must not be given (a poisoned /etc/hosts or local resolver
        // could steer containment around an attacker-controlled address).
        // Resolving once at boot, before quarantine is ever dispatched,
        // narrows that window to "compromised before or at startup" and
        // means this call performs no DNS I/O of its own at all -- comma-
        // joined, so a hostname resolving to multiple addresses whitelists
        // all of them.
        if (plugin_ctx_) {
            yuzu::PluginContext pc{plugin_ctx_};
            auto resolved_csv = pc.get_config("agent.server_address_resolved");
            for (auto& ip : split_ips(resolved_csv))
                add_whitelist_ip(std::move(ip));
        }

        auto extra = split_ips(whitelist_csv);
        for (auto& ip : extra)
            add_whitelist_ip(std::move(ip));

#ifdef _WIN32
        {
            // #3284: persist the pre-quarantine profile policy BEFORE reporting
            // the outcome, so the release path can put it back. Persisted even
            // on a partial quarantine — the policy was already replaced by
            // then, so the host still needs it restored. A storage failure is
            // not fatal to the quarantine (containment matters more than a
            // tidy release), but unquarantine will then take its honest
            // "default restored" fallback rather than silently downgrading.
            std::string prior;
            bool captured_complete = false;
            // The persist runs INSIDE win_quarantine, before its first
            // mutating call — see the ordering comment there. This lambda is
            // the only reason the storage write can happen that early: the
            // storage accessors are members and win_quarantine is a free
            // function.
            const int rc = win_quarantine(
                ctx, whitelist, &prior,
                [this, &captured_complete](const std::string& serialized, bool ours) {
                    captured_complete = true;
                    return store_prior_policy(serialized, ours) != PriorPolicyStore::refused;
                });
            // CDX-P1-03: the persist result was previously discarded, so a
            // storage failure was indistinguishable from a clean capture — and
            // release would then silently take the default-restore fallback
            // with nothing explaining why. Both failure shapes (no complete
            // capture, or a capture that would not persist) are now named on
            // the durable channel. Deliberately NOT fatal to the quarantine:
            // containment is the point of this action, and refusing to contain
            // a possibly-compromised host because its release might be untidy
            // inverts that. The release path stays honest either way.
            // `already_present` counts as persisted: a good restore image from
            // the first quarantine is exactly what release needs, and the
            // write-once guard refusing to overwrite it is the control
            // working, not a storage failure.
            // `prior` is cleared by win_quarantine when the persist did not
            // succeed, so a non-empty value here means the image is durably
            // stored — the storage write already happened, before any
            // mutation.
            const bool persisted = !prior.empty();
            if (!persisted && rc == 0) {
                ctx.set_result_status(
                    YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                    !captured_complete
                        ? "quarantine:win_quarantine contained, but the pre-quarantine firewall "
                          "policy could not be captured completely — release will restore the "
                          "Windows default instead"
                        : "quarantine:win_quarantine contained, but the pre-quarantine firewall "
                          "policy could not be stored — release will restore the Windows default "
                          "instead");
            }
            return rc;
        }
#elif defined(__linux__)
        {
            bool v6_applied = false;
            const int rc = linux_quarantine(ctx, whitelist, &v6_applied);
            const bool marker_stored = store_linux_v6_applied(v6_applied);
            // Same "only touch a clean success" discipline as the Windows
            // branch's persisted_prior check above: rc != 0 already carries
            // its own (worse) status from linux_quarantine, which this must
            // not overwrite with a falsely rosier "contained, but..." one.
            if (rc == 0 && v6_applied && !marker_stored) {
                ctx.set_result_status(
                    YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                    "quarantine:linux_quarantine contained, but the ip6tables-applied "
                    "marker could not be stored — release may not know IPv6 teardown is "
                    "owed");
            }
            return rc;
        }
#elif defined(__APPLE__)
        return macos_quarantine(ctx, whitelist);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
    }

    // ── unquarantine action ──────────────────────────────────────────────────

    int do_unquarantine(yuzu::CommandContext& ctx) {
        // #3286: see do_quarantine's identical gate comment.
        auto mutation_guard = enter_quarantine_mutation();
        if (!mutation_guard.has_value()) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine: another mutating quarantine action is in progress");
            ctx.write_output("status|busy");
            return 1;
        }

#ifdef _WIN32
        {
            const std::string prior = load_prior_policy();
            const int rc = win_unquarantine(ctx, prior);
            // Clear only on a clean release. On release_uncertain the policy
            // may not have been put back, so the record stays for the retry —
            // dropping it would make the next attempt take the default-restore
            // fallback and lose the host's real posture for good. CDX-P1-03:
            // rc == 0 also covers the honest-fallback release, where nothing
            // was replayed; keeping the record there is still correct, because
            // a later retry may yet restore it, and a stale-but-accurate
            // record is strictly better than none.
            if (rc == 0 && !prior.empty() &&
                yuzu::quarantine::is_complete_profile_policy(
                    yuzu::quarantine::parse_profile_policies(prior)))
                clear_prior_policy();
            return rc;
        }
#elif defined(__linux__)
        {
            const bool v6_was_applied = load_linux_v6_applied();
            const int rc = linux_unquarantine(ctx, v6_was_applied);
            // Clear only on a clean release — same retry-safety reasoning
            // as clear_prior_policy above: on release_uncertain the v6
            // chain may not have been fully torn down, so the marker stays
            // for the retry (dropping it would make the next attempt skip
            // the v6 teardown it still owes).
            if (rc == 0)
                clear_linux_v6_applied();
            return rc;
        }
#elif defined(__APPLE__)
        return macos_unquarantine(ctx);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
    }

    // ── status action ────────────────────────────────────────────────────────

    int do_status(yuzu::CommandContext& ctx) {
        // #3286: do_status deliberately does NOT take the mutation gate. A
        // read must never queue behind a multi-step mutation — status is
        // exactly the channel that needs to stay available WHILE a
        // quarantine/unquarantine/whitelist call is in flight, not one more
        // caller waiting on it. A read that lands mid-mutation is now
        // honestly reported as partial/degraded/uncertain by the checks
        // below (#3283/#3285) rather than as a false `active`, so gating
        // this action would only add latency, not correctness.
        bool status_forwarded = false;
        // Ignore the read's own tool exit code where applicable: a nonzero/
        // failed exit from a status query is not itself an error (an
        // absent chain/rule is a normal "not quarantined" outcome) — only a
        // genuine runner-level failure (forwarded below) should mark the
        // ABI4 result seam degraded.
#ifdef _WIN32
        // win_is_quarantined issues multiple reads and forwards each one's
        // failure itself (#3285).
        auto check = win_is_quarantined(ctx, status_forwarded);
#elif defined(__linux__)
        // linux_is_quarantined issues up to four reads across two
        // families and forwards each one's failure itself.
        auto check = linux_is_quarantined(ctx, status_forwarded);
#elif defined(__APPLE__)
        // macos_is_quarantined issues two reads and forwards each one's
        // failure itself (#3283).
        auto check = macos_is_quarantined(ctx, status_forwarded);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        if (check.note.empty()) {
            ctx.write_output(std::format("state|{}", quar_status_token(check.state)));
        } else {
            ctx.write_output(
                std::format("state|{}|note|{}", quar_status_token(check.state), check.note));
        }

        // #3285: the two channels must agree. macos_is_quarantined already
        // forwards its own `degraded`/`uncertain` (and sets status_forwarded,
        // so this cannot double-report), but Linux and Windows were writing
        // `state|partial` to the pipe-delimited text ONLY — leaving the
        // durable, server-persisted ABI4 seam reading clean on a host whose
        // containment is incomplete. A compliance poller reading the seam is
        // exactly the consumer that must not be told everything is fine, and
        // the split between these two channels is the whole reason #3285
        // exists. Not a runner failure, so completeness (not availability) is
        // what degrades: the read itself succeeded, what it found is partial.
        if (check.state == QuarStatus::partial && !status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  check.note.empty()
                                      ? "quarantine:do_status containment is incomplete"
                                      : std::format("quarantine:do_status {}", check.note));
            status_forwarded = true;
        }

        // CDX-P1-04: a state the read could not determine must not exit 0.
        // `uncertain` (and macOS's `degraded`) mean the answer is unknown or
        // the containment is not actually being enforced — a generic
        // success/failure consumer that only inspects the return code would
        // otherwise treat an unreadable or unenforced host as a clean status
        // read. `inactive` and `active` are genuine answers and still return 0.
        const bool undetermined =
            check.state == QuarStatus::uncertain || check.state == QuarStatus::degraded;
        if (undetermined) {
            if (!status_forwarded) {
                ctx.set_result_status(
                    YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                    check.note.empty()
                        ? "quarantine:do_status containment state could not be determined"
                        : std::format("quarantine:do_status {}", check.note));
                status_forwarded = true;
            }
            return 1;
        }

        if (check.state != QuarStatus::inactive) {
#ifdef _WIN32
            auto wl = win_get_whitelist();
            report_runner_result(ctx, status_forwarded, wl.res);
#elif defined(__linux__)
            auto wl = linux_get_whitelist(ctx, status_forwarded);
#elif defined(__APPLE__)
            auto wl = macos_get_whitelist();
            report_runner_result(ctx, status_forwarded, wl.res);
#endif
            if (wl.note.empty()) {
                ctx.write_output(std::format("whitelist|{}", join_ips(wl.ips)));
            } else {
                ctx.write_output(
                    std::format("whitelist|{}|note|{}", join_ips(wl.ips), wl.note));
            }
        }

        return 0;
    }

    // ── whitelist action ─────────────────────────────────────────────────────

    int do_whitelist(yuzu::CommandContext& ctx, yuzu::Params params) {
        // #3286: see do_quarantine's identical gate comment.
        auto mutation_guard = enter_quarantine_mutation();
        if (!mutation_guard.has_value()) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine: another mutating quarantine action is in progress");
            ctx.write_output("status|busy");
            return 1;
        }

        auto action_param = params.get("action");
        auto ips_csv = params.get("ips");

        if (action_param.empty()) {
            ctx.write_output("error|missing required parameter: action (add/remove)");
            return 1;
        }
        if (ips_csv.empty()) {
            ctx.write_output("error|missing required parameter: ips");
            return 1;
        }

        auto new_ips = split_ips(ips_csv);
        if (new_ips.empty()) {
            ctx.write_output("error|no valid IPs provided");
            return 1;
        }

        bool status_forwarded = false;
        // Tracks a CLEAN failure (tool ran, exited nonzero) on any Windows/
        // Linux add/remove mutation below, OR a macOS pf-enable failure
        // during the ruleset rebuild (#3283 — see the two macOS branches
        // below) — distinct from status_forwarded, which only covers a
        // genuine runner-level failure. Discarding this (the pre-fix
        // behaviour) let a whitelist add/remove that the underlying tool
        // refused, or a macOS rebuild whose pf never actually enabled, still
        // report "status|updated".
        bool mutation_failed = false;

        if (action_param == "add") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                // sink: quarantine/do_whitelist#1 — rung-2 runner argv,
                // MUTATING, operator-supplied IP validated by is_safe_ip.
                // Argv construction lives in netsh_allow_in_rule_argv
                // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
                auto out1 = run_tool(yuzu::quarantine::netsh_allow_in_rule_argv(netsh_path(), ip),
                                    kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out1.res))
                    mutation_failed = true;
                // sink: quarantine/do_whitelist#2 — rung-2 runner argv,
                // MUTATING, operator-supplied IP validated by is_safe_ip
                auto out2 = run_tool({netsh_path(), "advfirewall", "firewall", "add", "rule",
                                     std::format("name={}AllowOut_{}", kRulePrefix, ip), "dir=out",
                                     "action=allow", "enable=yes", std::format("remoteip={}", ip)},
                                    kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out2.res))
                    mutation_failed = true;
            }
#elif defined(__linux__)
            {
                for (const auto& ip : new_ips) {
                    // Route to the matching family's tool (#3282) — mirrors
                    // linux_quarantine's per-IP routing so an entry
                    // linux_get_whitelist now surfaces (dual-family) can
                    // actually be managed here in the chain it really lives
                    // in, never handing a v6 literal to iptables or vice
                    // versa. An `unknown`-family entry (is_safe_ip-valid but
                    // neither '.' nor ':') is skipped the same way
                    // linux_quarantine skips one, rather than handed to
                    // either tool to fail on.
                    const auto family = yuzu::quarantine::ip_family(ip);
                    if (family == yuzu::quarantine::IpFamily::unknown)
                        continue;
                    const char* tool =
                        family == yuzu::quarantine::IpFamily::v6 ? kIp6tables : kIptables;
                    // Insert before the DROP rule (second-to-last position)
                    // sink: quarantine/do_whitelist#5 — rung-2 sudo-governed
                    // runner argv, MUTATING, operator-supplied IP validated
                    // by is_safe_ip
                    auto argv1 = yuzu::shared::sudo_wrap(
                        {tool, "-I", "yuzu-quarantine", "-s", ip, "-j", "ACCEPT"});
                    auto out1 = run_tool(argv1, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out1.res))
                        mutation_failed = true;
                    // sink: quarantine/do_whitelist#6 — rung-2 sudo-governed
                    // runner argv, MUTATING, operator-supplied IP validated
                    // by is_safe_ip
                    auto argv2 = yuzu::shared::sudo_wrap(
                        {tool, "-I", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
                    auto out2 = run_tool(argv2, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out2.res))
                        mutation_failed = true;
                }
            }
#elif defined(__APPLE__)
            {
                // The new design (no anchor, rules in main ruleset) means
                // "add" = "rebuild the entire ruleset with the union of
                // current whitelist + new IPs". We get the current
                // whitelist via macos_get_whitelist() and merge.
                auto current = macos_get_whitelist();
                if (!report_runner_result(ctx, status_forwarded, current.res)) {
                    // The prerequisite whitelist read failed — either a
                    // genuine runner failure (already forwarded above) or a
                    // clean nonzero exit (tool ran, refused). Either way
                    // current.ips cannot be trusted as the whitelist
                    // baseline: rebuilding the entire main pf ruleset from
                    // an empty/wrong set would silently drop any real
                    // whitelisted entries (including a possible
                    // management-server IP) — the same impact class as the
                    // 672896112 incident this migration exists to prevent.
                    // Abort instead of rebuilding from an unproven read.
                    if (!status_forwarded) {
                        ctx.set_result_status(
                            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                            "quarantine:do_whitelist macOS whitelist read failed before add");
                    }
                    ctx.write_output("error|whitelist read failed, ruleset not rewritten");
                    return 1;
                }
                for (const auto& ip : new_ips) {
                    bool dup = false;
                    for (const auto& existing : current.ips) {
                        if (existing == ip) {
                            dup = true;
                            break;
                        }
                    }
                    if (!dup)
                        current.ips.push_back(ip);
                }
                int rules_written = 0;
                std::string err;
                bool pf_enable_failed = false;
                if (macos_load_ruleset(ctx, current.ips, &rules_written, &err,
                                       &pf_enable_failed) != 0) {
                    ctx.write_output(std::format("error|{}", err));
                    return 1;
                }
                // #3283: a rebuild whose ruleset loaded but that pf never
                // actually enabled must not report "status|updated" — see
                // this function's mutation_failed doc comment and
                // macos_quarantine's identical fold.
                if (pf_enable_failed)
                    mutation_failed = true;
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else if (action_param == "remove") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                // sink: quarantine/do_whitelist#3 — rung-2 runner argv, MUTATING
                auto out1 =
                    run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}AllowIn_{}", kRulePrefix, ip)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out1.res))
                    mutation_failed = true;
                // sink: quarantine/do_whitelist#4 — rung-2 runner argv, MUTATING
                auto out2 =
                    run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}AllowOut_{}", kRulePrefix, ip)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out2.res))
                    mutation_failed = true;
            }
#elif defined(__linux__)
            {
                for (const auto& ip : new_ips) {
                    // Route to the matching family's tool (#3282) — see the
                    // identical rationale on the "add" branch above.
                    const auto family = yuzu::quarantine::ip_family(ip);
                    if (family == yuzu::quarantine::IpFamily::unknown)
                        continue;
                    const char* tool =
                        family == yuzu::quarantine::IpFamily::v6 ? kIp6tables : kIptables;
                    // sink: quarantine/do_whitelist#7 — rung-2 sudo-governed
                    // runner argv, MUTATING
                    auto argv1 = yuzu::shared::sudo_wrap(
                        {tool, "-D", "yuzu-quarantine", "-s", ip, "-j", "ACCEPT"});
                    auto out1 = run_tool(argv1, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out1.res))
                        mutation_failed = true;
                    // sink: quarantine/do_whitelist#8 — rung-2 sudo-governed
                    // runner argv, MUTATING
                    auto argv2 = yuzu::shared::sudo_wrap(
                        {tool, "-D", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
                    auto out2 = run_tool(argv2, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out2.res))
                        mutation_failed = true;
                }
            }
#elif defined(__APPLE__)
            {
                // "remove" = rebuild the ruleset with current-whitelist
                // minus new_ips. macos_load_ruleset takes the final
                // desired set; we don't manipulate individual rules
                // (which the old anchor design tried to do via string
                // matching, with the well-known false-match risk).
                auto current = macos_get_whitelist();
                if (!report_runner_result(ctx, status_forwarded, current.res)) {
                    // Same rationale as the "add" branch above: a failed
                    // prerequisite read (runner failure OR clean nonzero
                    // exit) must not be treated as an empty whitelist —
                    // that would rebuild the ruleset with nothing
                    // whitelisted at all. Abort rather than rebuild.
                    if (!status_forwarded) {
                        ctx.set_result_status(
                            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                            "quarantine:do_whitelist macOS whitelist read failed before remove");
                    }
                    ctx.write_output("error|whitelist read failed, ruleset not rewritten");
                    return 1;
                }
                std::vector<std::string> filtered;
                for (const auto& ip : current.ips) {
                    bool removed = false;
                    for (const auto& rm : new_ips) {
                        if (ip == rm) {
                            removed = true;
                            break;
                        }
                    }
                    if (!removed)
                        filtered.push_back(ip);
                }
                int rules_written = 0;
                std::string err;
                bool pf_enable_failed = false;
                if (macos_load_ruleset(ctx, filtered, &rules_written, &err, &pf_enable_failed) !=
                    0) {
                    ctx.write_output(std::format("error|{}", err));
                    return 1;
                }
                // #3283: see the identical fold in the "add" branch above.
                if (pf_enable_failed)
                    mutation_failed = true;
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else {
            ctx.write_output(
                std::format("error|invalid action '{}', expected 'add' or 'remove'", action_param));
            return 1;
        }

        // Report current whitelist
#ifdef _WIN32
        auto current_read = win_get_whitelist();
        report_runner_result(ctx, status_forwarded, current_read.res);
#elif defined(__linux__)
        // linux_get_whitelist forwards its own read failures (it merges
        // reads across two families) — see do_status's identical pattern.
        auto current_read = linux_get_whitelist(ctx, status_forwarded);
#elif defined(__APPLE__)
        auto current_read = macos_get_whitelist();
        report_runner_result(ctx, status_forwarded, current_read.res);
#else
        struct { std::vector<std::string> ips; } current_read;
#endif
        if (status_forwarded || mutation_failed) {
            // A genuine runner failure, OR a clean failure on one of the
            // add/remove mutations themselves, occurred — do NOT claim the
            // whitelist is updated when the underlying tool may not have
            // applied every change.
            if (!status_forwarded) {
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      "quarantine:do_whitelist one or more rule mutations failed");
            }
            ctx.write_output(
                std::format("status|update_uncertain|whitelist|{}", join_ips(current_read.ips)));
            return 1;
        }
        ctx.write_output(std::format("status|updated|whitelist|{}", join_ips(current_read.ips)));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(QuarantinePlugin)
