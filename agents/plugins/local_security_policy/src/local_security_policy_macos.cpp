/**
 * local_security_policy_macos.cpp -- macOS leg.
 *
 * password_policy / lockout_policy: `pwpolicy -getaccountpolicies` is the RUNG-2 argv leaf (no
 * public OpenDirectory global-policy API -- ADR-3002 Decision 1's "no interface exists"
 * category; OpenDirectory exposes per-node/per-record policy, never the global set).
 * One spawn per action; the XML goes
 * through CFPropertyListCreateWithData and the pure extractor. The tool prints a non-plist
 * banner line before the XML; strip_to_xml removes it (raw stdout fails to parse on every host).
 *
 * audit_policy / sudoers: file reads via the shared collector. Real capture (macOS 26.6.2,
 * uid 501): /etc/security/audit_control does not exist (only audit_control.example, 0400) ->
 * `absent`; /etc/sudoers is -r--r----- root:wheel -> EACCES -> `unreadable`, PERMISSION_DENIED.
 * Reading it needs root or group wheel; nothing is elevated here.
 */
#include "local_security_policy_legs.hpp"

#if defined(__APPLE__)

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>

namespace yuzu::local_security_policy {

namespace {

Collected constrained(std::string token) {
    return {{}, PolicyStatus::Constrained, std::move(token)};
}

Collected collect_pwpolicy(LocalPolicyAction action) {
    // sink: local_security_policy/do_password_policy#1
    // rung 2 on ADR-3002 Decision 1's "no interface exists" evidence category: OpenDirectory
    // publishes per-node and per-record policy, never the GLOBAL account-policy set this action
    // reports, so there is no rung-1 API to pass over. The tool's XML output is read instead.
    const auto run = yuzu::agent::run_bounded_subprocess(
        {"/usr/bin/pwpolicy", "-getaccountpolicies"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
    if (auto bad = classify_pwpolicy_run(to_run_end(run.termination_reason), run.output_truncated,
                                         run.exit_code);
        !bad.empty())
        return constrained(std::move(bad));
    const auto xml = strip_to_xml(run.output);
    if (!xml) return constrained("pwpolicy:no_plist");
    const auto items = pwpolicy_plist_to_items(*xml);
    if (!items) return constrained("pwpolicy:plist_unparseable");
    return pwpolicy_rows(action, *items); // CONSTRAINED when an item was not in the documented shape
}

} // namespace

int collect_macos_policy(yuzu::CommandContext& ctx, std::string_view action) {
    const auto which = parse_local_policy_action(action);
    const auto prefix = action_row_prefix(which);
    if (which == LocalPolicyAction::Password || which == LocalPolicyAction::Lockout)
        return apply_collected(ctx, collect_pwpolicy(which), prefix);
    return apply_collected(
        ctx, collect_file_policy(FileFlavor::Macos, which, posix_read_file, posix_list_dir), prefix);
}

} // namespace yuzu::local_security_policy

#endif // defined(__APPLE__)
