/**
 * quarantine_parsers.hpp — pure status-read parsing AND pure mutating-argv
 * construction for the quarantine plugin (Wave-2 ADR-3002 acquisition-ladder
 * migration, quarantine package; extended by #3283/#3284/#3285/#3286 for
 * honest containment verification and mutation serialization). Portable and
 * header-only, no platform guard: this file and its test TUs
 * (test_quarantine_parsers.cpp / test_quarantine_argv.cpp) compile and run
 * on every leg. The original status-read parsers are byte-for-byte lifted
 * from the pre-migration parsing logic in quarantine_plugin.cpp; the
 * verification additions below are new logic, not a lift.
 *
 * Status-read consumers in quarantine_plugin.cpp, one group per platform:
 *   - netsh_base_rules_present / netsh_matching_rule_names /
 *     netsh_whitelist_ips / netsh_firewall_policy + all_profiles_blocking
 *     (win_quarantine, win_is_quarantined, win_unquarantine,
 *     win_get_whitelist) — #3284 branch A: containment is a profile-default
 *     policy, not a named Block rule (docs/quarantine-windows-firewall-
 *     precedence.md carries the live verdict)
 *   - iptables_chain_referenced / iptables_whitelist_ips
 *     (linux_is_quarantined, linux_get_whitelist)
 *   - pfctl_rules_blocked / pfctl_whitelist_ips / pfctl_status_state /
 *     macos_quar_status (macos_is_quarantined, macos_get_whitelist,
 *     macos_load_ruleset — #3283: a blocking ruleset alone does not prove pf
 *     is actually enforcing it)
 *
 * None of these functions perform I/O or spawn anything — the plugin
 * captures `netsh advfirewall firewall show rule ...` / `show allprofiles`,
 * `iptables -L ...`, and `pfctl -s rules` / `-s info` output via
 * yuzu::agent::run_bounded_subprocess and hands the captured text here.
 *
 * A second group — netsh_allow_in_rule_argv / netsh_set_firewall_policy_argv
 * / iptables_accept_source_argv / pfctl_load_ruleset_argv — is pure argv
 * CONSTRUCTION for one representative mutating call site per platform (two
 * for Windows, covering both the per-rule and the #3284 branch-A
 * profile-policy mutations), extracted so the argv shape (order, presence,
 * and — for the POSIX two — the caller-applied sudo wrapping) is
 * unit-testable without spawning anything. quarantine_plugin.cpp's mutating
 * actions run iptables/pfctl/netsh against the real host firewall, so they
 * are deliberately NOT exercised end-to-end in a unit test (unlike the
 * read-only users/services LocalDispatcher pattern) — this is the structural
 * substitute: it proves an argument can't be silently dropped, reordered, or
 * de-sudo'd without a test failing, for the pattern every other migrated
 * site in this file follows.
 */
#pragma once

#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::quarantine {

// Firewall rules created by this plugin are prefixed for identification —
// shared by every platform's status read and by the mutating paths in
// quarantine_plugin.cpp.
inline constexpr std::string_view kRulePrefix = "YuzuQuarantine_";

// ── IP validation ────────────────────────────────────────────────────────
//
// Single source of truth for "does this look like an IPv4/IPv6 literal" —
// used both to validate operator-supplied whitelist IPs (quarantine_plugin.
// cpp) and to filter parsed values here so a malformed/adversarial capture
// (e.g. an attacker-controlled RemoteIP-shaped string embedded in a rule
// name) can't smuggle a non-IP token into a whitelist result.
inline bool is_safe_ip(std::string_view ip) {
    if (ip.empty() || ip.size() > 45)
        return false;
    for (char c : ip) {
        const bool ok = (c >= '0' && c <= '9') || c == '.' || c == ':' ||
                        (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

// ── Honest status vocabulary (#3282/#3260/#3285 Linux) ──────────────────────
//
// Shared, portable core for the Linux dual-stack (iptables + ip6tables)
// containment fix and the wave-2 (P4) package that extends the same
// vocabulary to Windows/macOS. Everything below is pure: no I/O, no platform
// guard.

/**
 * Which firewall family an already-is_safe_ip-validated IP literal belongs
 * to. Callers MUST validate with is_safe_ip first — this makes no attempt to
 * reject malformed input, only to route a known-safe literal to the correct
 * tool (iptables vs ip6tables) so a v6 literal is never handed to iptables
 * or vice versa. A bare hex string with neither '.' nor ':' (accepted by
 * is_safe_ip's charset but not a real IP shape) reports `unknown` — callers
 * skip it rather than guess.
 */
enum class IpFamily { v4, v6, unknown };

inline IpFamily ip_family(std::string_view ip) {
    if (ip.find(':') != std::string_view::npos)
        return IpFamily::v6;
    if (ip.find('.') != std::string_view::npos)
        return IpFamily::v4;
    return IpFamily::unknown;
}

/**
 * Honest attempted-vs-succeeded accounting for a sequence of mutating
 * firewall calls, replacing the `rules_applied > 0` success gate (#3282).
 * A caller records every COUNTING mutation attempt (never a best-effort/
 * idempotent one, e.g. `-N`/`-F`/the jump-removal `-D` calls — see
 * quarantine_plugin.cpp's apply vs apply_ignore_* split) via `record`.
 */
struct MutationTally {
    int attempted = 0;
    int succeeded = 0;

    void record(bool ok) {
        ++attempted;
        if (ok)
            ++succeeded;
    }

    // True only at full success over at least one attempt — an empty tally
    // (nothing was ever attempted) is not "complete", it's "nothing
    // happened", and quarantine_status_token below routes that to `failed`
    // via its own succeeded==0 check.
    bool complete() const { return attempted > 0 && succeeded == attempted; }
};

inline constexpr std::string_view kStatusQuarantined = "quarantined";
inline constexpr std::string_view kStatusQuarantinedPartial = "quarantined_partial";
inline constexpr std::string_view kStatusFailed = "failed";

/**
 * Reduces one MutationTally to the honest `status|` wire token: `failed`
 * when nothing succeeded, `quarantined` only at full success, and
 * `quarantined_partial` for every partial outcome in between.
 */
inline std::string_view quarantine_status_token(const MutationTally& t) {
    if (t.succeeded == 0)
        return kStatusFailed;
    if (t.complete())
        return kStatusQuarantined;
    return kStatusQuarantinedPartial;
}

/**
 * The read-side (status-query) counterpart to the tokens above — reported
 * via the `state|` field, distinct from the mutation-side `status|` field
 * emitted by the quarantine/unquarantine actions. `active`/`partial`/
 * `inactive` are produced by Linux (linux_quar_status below) and Windows
 * (the NetshBaseRules/all_profiles_blocking-driven decision in
 * quarantine_plugin.cpp's win_is_quarantined); `degraded` and `uncertain`
 * are produced by macOS only (macos_quar_status below, #3283) — a blocking
 * pf ruleset that is loaded but disabled reads `degraded` (a real
 * containment gap: traffic is NOT actually being blocked), and a pf status
 * read that returns nothing recognisable reads `uncertain` (the read itself
 * is unreliable, which is a different problem from the containment being
 * broken).
 */
enum class QuarStatus { active, partial, degraded, uncertain, inactive };

inline std::string_view quar_status_token(QuarStatus s) {
    switch (s) {
    case QuarStatus::active:
        return "active";
    case QuarStatus::partial:
        return "partial";
    case QuarStatus::degraded:
        return "degraded";
    case QuarStatus::uncertain:
        return "uncertain";
    case QuarStatus::inactive:
        return "inactive";
    }
    return "inactive"; // unreachable; keeps -Wswitch happy across compilers
}

/**
 * The IPv6 environment on a Linux host, probed by the impure shell via
 * filesystem access — NEVER via a SubprocessResult's `tool_ran`, because
 * every ip6tables call is sudo_wrap-ed: argv[0] is `/usr/bin/sudo`, so
 * `tool_ran` reports whether sudo itself executed, not whether ip6tables
 * did (VERIFIED at agents/shared/sudo_argv.hpp and
 * agents/core/include/yuzu/agent/subprocess_runner.hpp). `tool_present` is
 * `::access(kIp6tables, F_OK) == 0` — EXISTENCE, not executability: every call
 * runs as root through sudo, so the probing principal's execute bit is the
 * wrong question and `X_OK` reported a 0750 root-owned ip6tables as absent,
 * which skipped the whole v6 sequence and still emitted `status|quarantined`.
 * `stack_present` asks whether this host has an IPv6 stack that could carry
 * traffic. `/proc/net/if_inet6` alone is not that question: it is absent when
 * the ipv6 module is merely NOT YET LOADED, which is a transient state, not a
 * disabled one. Treating that as "no stack" skips v6 containment and reports a
 * clean `quarantined` — and if IPv6 then comes up, v6 egress is uncontained
 * until something re-derives the predicate. So the probe is the OR of the
 * interface table and the sysctl that actually says "disabled":
 * `/proc/net/if_inet6` present, OR `/proc/sys/net/ipv6/conf/all/disable_ipv6`
 * present and reading `0`. A host that has truly disabled IPv6 satisfies
 * neither; a host whose module is unloaded but not disabled satisfies the
 * second and is correctly contained.
 */
struct LinuxV6Env {
    bool tool_present = false;
    bool stack_present = false;
};

/**
 * THE single predicate for "should this host's v6 chain be touched, and
 * judged?" — used by the mutation sequence, the teardown, the read path, and
 * both verdict functions below, so no two of them can disagree about what was
 * expected of a given host.
 *
 * BOTH halves are required, and the `stack_present` half is not cosmetic. A
 * host booted `ipv6.disable=1` with the stock `iptables` package installed —
 * an ordinary CIS/STIG posture, not an exotic one — has `tool_present` true
 * and no IPv6 stack at all, so every `ip6tables` call fails. Keying on the
 * tool alone made that host attempt the v6 sequence, fail every call, and
 * report `quarantined_partial` with a note blaming a failed chain flush,
 * then report `state|uncertain` forever after — on a host whose containment
 * was in fact complete, and which reported a clean `quarantined` if
 * `ip6tables` happened NOT to be installed. Two hosts with identical IPv6
 * exposure (none) disagreeing about their containment because one has a
 * package installed is the false-reporting class #3282 exists to remove,
 * pointing the other way.
 *
 * The remaining gap case is `!tool_present && stack_present`: a live IPv6
 * stack with no tool to contain it. That is a REAL containment gap and is
 * handled separately below — it forces a partial verdict rather than being
 * skipped.
 */
[[nodiscard]] inline bool v6_in_scope(LinuxV6Env env) {
    return env.tool_present && env.stack_present;
}

/**
 * Read-side dual-family verdict for linux_is_quarantined. v6 jumps are
 * "expected" iff `v6_in_scope(env)` — the SAME predicate linux_quarantine's
 * mutation path uses to decide whether to attempt the v6 sequence at all.
 * The read side judges the jumps that attempt could have left behind by that
 * identical standard: two readings of the same host must not disagree about
 * what was expected of it.
 *
 * A host with no v6 chain in scope therefore reads `active` when both v4
 * jumps are present, never `partial` for jumps it never attempted; the
 * caller (linux_is_quarantined) attaches the `note|ipv6_unavailable` text
 * separately so the reason is still surfaced without touching the verdict.
 * That covers both a host with no ip6tables and a host with no IPv6 stack —
 * in neither case is there IPv6 traffic this plugin failed to contain.
 *
 * The gap case `!tool_present && stack_present` is deliberately NOT
 * special-cased into the verdict here: a real containment gap exists, but it
 * is carried in the note rather than by degrading a state vocabulary this
 * function keeps to active/partial/inactive.
 */
inline QuarStatus linux_quar_status(bool v4_in, bool v4_out, bool v6_in, bool v6_out,
                                    LinuxV6Env env, bool reads_ok = true) {
    // CDX-P1-04: absence of evidence is not evidence of absence. Every
    // "is the jump present" flag is derived from a chain listing, and a
    // listing that FAILED — a revoked sudoers grant, a transient xtables
    // lock, a deadline — yields exactly the same all-false input as a host
    // with no containment at all. Reporting `inactive` there tells an
    // operator (or a compliance poller) that a possibly-contained host is
    // released, which is the false-clean read #3285 exists to eliminate,
    // pointing the other way. An unreadable host is `uncertain`: not active,
    // not inactive, and never a clean success on either channel.
    if (!reads_ok)
        return QuarStatus::uncertain;

    const bool v6_expected = v6_in_scope(env);

    const int expected = 2 + (v6_expected ? 2 : 0);
    const int present = (v4_in ? 1 : 0) + (v4_out ? 1 : 0) +
                        (v6_expected ? (v6_in ? 1 : 0) + (v6_out ? 1 : 0) : 0);

    if (present == 0)
        return QuarStatus::inactive;
    if (present == expected)
        return QuarStatus::active;
    return QuarStatus::partial;
}

/**
 * Mutation-side dual-family verdict for linux_quarantine, combining the v4
 * and v6 MutationTallys per the three honest v6-environment cases (#3282):
 *
 *   (i)   tool AND stack present  → v6 was attempted; combine both tallies
 *         and reduce them exactly like a single-family quarantine would.
 *   (ii)  stack absent (whether or not the tool is installed) → there is no
 *         IPv6 on this host; v6 was correctly skipped, so v4 ALONE decides.
 *         Neither a v4-only fleet nor an `ipv6.disable=1` host may read
 *         `quarantined_partial` forever for traffic that cannot exist.
 *   (iii) tool absent, stack present → a real gap: IPv6 traffic that should
 *         be blocked is not, and containment can never be complete
 *         regardless of how completely v4 applied. Forced to
 *         `quarantined_partial` (or `failed` if v4 itself applied nothing —
 *         `quarantined_partial` would misstate that ANY containment
 *         succeeded), never `quarantined`.
 */
/// Per-family outcome of the chain FLUSH, which is a prerequisite rather than
/// a containment rule. It is deliberately NOT recorded into the MutationTally
/// — a flush installs no containment by itself, so counting a successful one
/// would let a flush-only success with every real rule failing read as partial
/// containment. But a FAILED flush is not merely uncounted, it is
/// DISQUALIFYING: the chain keeps whatever it held before, including a stale
/// terminal DROP and a stale whitelist, so every rule appended afterwards
/// lands BEHIND that DROP and is inert — while the tally, which only sees the
/// appends, reads a clean N/N. `true` also covers "no flush was attempted for
/// this family", which is the correct reading when the family was skipped.
struct FlushOutcome {
    bool v4_ok = true;
    bool v6_ok = true;
};

inline std::string_view linux_quarantine_token(const MutationTally& v4, const MutationTally& v6,
                                               LinuxV6Env env, FlushOutcome flush = {}) {
    // A failed flush invalidates its whole family: the rules that follow it
    // cannot be trusted to be the only ones in the chain, or even to be
    // reachable. Handled BEFORE the tallies so a full N/N append run can
    // never outvote it — the same asymmetry win_quarantine_token applies to
    // the policy set.
    const bool v6_attempted = v6_in_scope(env);
    if (!flush.v4_ok || (v6_attempted && !flush.v6_ok)) {
        // Something did apply on at least one family, so this is not a clean
        // `failed`; but containment is not provably complete either, and the
        // note the caller emits names the flush explicitly.
        const int applied = v4.succeeded + (v6_attempted ? v6.succeeded : 0);
        return applied == 0 ? kStatusFailed : kStatusQuarantinedPartial;
    }

    if (!env.stack_present)
        return quarantine_status_token(v4);

    if (!env.tool_present)
        return v4.succeeded == 0 ? kStatusFailed : kStatusQuarantinedPartial;

    MutationTally combined;
    combined.attempted = v4.attempted + v6.attempted;
    combined.succeeded = v4.succeeded + v6.succeeded;
    return quarantine_status_token(combined);
}

/**
 * Reduces the Windows quarantine outcome to its honest `status|` token.
 *
 * Windows containment is asymmetric in a way a flat tally cannot express, and
 * #3284's branch-A redesign made it more so. The ENTIRE containment is now one
 * call — the all-profiles `firewallpolicy blockinbound,blockoutbound` set. The
 * loopback and whitelist Allow rules that follow contain nothing; they carve
 * exceptions OUT of that containment.
 *
 * So a run where the policy set FAILED but several Allow rules succeeded has
 * installed no containment whatever, and must report `failed`. Feeding those
 * successes through a flat tally would yield `quarantined_partial`, implying
 * partial containment where there is none — the precise false-assurance shape
 * #3285 exists to eliminate, and strictly worse than the pre-redesign code,
 * which at least had two independent Block rules to lose. Only once the policy
 * is genuinely blocking does the tally's partial/full split describe something
 * real: containment holds, but a whitelist or loopback exception may be
 * missing, which is an honest `quarantined_partial`.
 *
 * `policy_applied` is the policy-set call's own success, NOT its presence in
 * the tally — the caller records it in both, and this function reads it
 * separately precisely so a tally majority can never outvote it.
 */
inline std::string_view win_quarantine_token(bool policy_applied, const MutationTally& tally) {
    if (!policy_applied)
        return kStatusFailed;
    return quarantine_status_token(tally);
}

// ── Mutating argv construction (FN-03 structural coverage) ─────────────────
//
// One representative call site per platform. Each returns the exact argv
// vector quarantine_plugin.cpp hands to yuzu::agent::run_bounded_subprocess
// (Linux/macOS: BEFORE yuzu::shared::sudo_wrap — the caller applies that,
// exactly as the production call sites do; sudo_wrap's own form is pinned by
// test_sudo_argv.cpp, not re-tested here). No I/O, no spawn — argv[0] is a
// caller-resolved absolute tool path, never looked up here.

/**
 * netsh argv to add a per-IP inbound ALLOW whitelist rule — the
 * `YuzuQuarantine_AllowIn_<ip>` sink used by both win_quarantine's
 * whitelist loop and do_whitelist's Windows "add" branch. `ip` is expected
 * to already be is_safe_ip-validated by the caller.
 */
inline std::vector<std::string> netsh_allow_in_rule_argv(std::string_view netsh_path,
                                                          std::string_view ip) {
    return {std::string{netsh_path},
            "advfirewall",
            "firewall",
            "add",
            "rule",
            std::format("name={}AllowIn_{}", kRulePrefix, ip),
            "dir=in",
            "action=allow",
            "enable=yes",
            std::format("remoteip={}", ip)};
}

/// The two `firewallpolicy` values win_quarantine (#3284 branch A) sets and
/// win_unquarantine restores — named constants so the set call, the restore
/// call, and win_is_quarantined's own expectation can never drift from each
/// other by a typo in a repeated string literal.
inline constexpr std::string_view kWinFirewallPolicyBlockBoth = "blockinbound,blockoutbound";
inline constexpr std::string_view kWinFirewallPolicyDefault = "blockinbound,allowoutbound";

/**
 * netsh argv to set (at quarantine) or restore (at unquarantine) the
 * all-profiles firewall policy — the #3284 branch-A containment mechanism
 * and its teardown. `policy` is always one of the two constants above;
 * never operator-influenced.
 */
inline std::vector<std::string> netsh_set_firewall_policy_argv(std::string_view netsh_path,
                                                                std::string_view policy) {
    return {std::string{netsh_path}, "advfirewall",   "set",
            "allprofiles",           "firewallpolicy", std::string{policy}};
}


/**
 * UNWRAPPED iptables argv to append a per-IP source ACCEPT rule to the
 * yuzu-quarantine chain — linux_quarantine's whitelist-loop sink. `ip` is
 * expected to already be is_safe_ip-validated by the caller.
 */
inline std::vector<std::string> iptables_accept_source_argv(std::string_view iptables_path,
                                                             std::string_view ip) {
    return {std::string{iptables_path}, "-A", "yuzu-quarantine", "-s", std::string{ip}, "-j",
            "ACCEPT"};
}

/**
 * UNWRAPPED pfctl argv to atomically load a generated ruleset file —
 * macos_load_ruleset's sink, THE call this migration is bound not to change
 * the shape of (see quarantine_plugin.cpp's header comment on the
 * 672896112 incident: single atomic `pfctl -f`, never a named anchor).
 */
inline std::vector<std::string> pfctl_load_ruleset_argv(std::string_view pfctl_path,
                                                         std::string_view ruleset_path) {
    return {std::string{pfctl_path}, "-f", std::string{ruleset_path}};
}

/// Strips a single trailing CR from a line split out of raw subprocess output.
///
/// LOAD-BEARING on Windows. `SubprocessResult::output` is the RAW byte stream;
/// only `SubprocessResult::lines` is CR-stripped by the runner. netsh emits
/// CRLF, so every value these parsers split off a line arrives as `…\r`. The
/// pre-#3285 reader got away with it by substring-matching the rule prefix,
/// which is CR-immune; the exact `==` comparisons that replaced it are not, and
/// on a real Windows host that made every base-rule flag false — reporting
/// `state|inactive`, rc 0, on a device that IS contained. Every parser that
/// splits `output` on '\n' must run its fields through this.
inline std::string_view strip_cr(std::string_view v) {
    if (!v.empty() && v.back() == '\r')
        v.remove_suffix(1);
    return v;
}

// ── Windows: netsh advfirewall firewall show rule ──────────────────────────

/**
 * The four base firewall rules win_quarantine creates under the pre-#3284
 * (branch B) rule shape: the two blanket Block rules plus the two loopback
 * Allow rules. #3285: win_is_quarantined must see ALL FOUR before reporting
 * `active` — checking only the inbound capture (the pre-fix bug) could never
 * detect an outbound-only failure (e.g. BlockAllOutbound failing to apply),
 * because `dir=in`/`dir=out` are genuine netsh FILTERS, not labels on an
 * unfiltered rule list: a dir=in-only capture structurally cannot contain an
 * outbound rule regardless of whether it exists on the host.
 */
struct NetshBaseRules {
    bool block_in = false;
    bool block_out = false;
    bool allow_lo_in = false;
    bool allow_lo_out = false;
    bool allow_lo_in6 = false;
    bool allow_lo_out6 = false;

    bool complete() const {
        return block_in && block_out && allow_lo_in && allow_lo_out && allow_lo_in6 &&
               allow_lo_out6;
    }

    // Comma-joined names of every missing rule, fixed order, for the
    // `note|missing: <names>` field. Empty when complete().
    std::string missing_names() const {
        std::vector<std::string> missing;
        if (!block_in)
            missing.push_back(std::format("{}BlockAllInbound", kRulePrefix));
        if (!block_out)
            missing.push_back(std::format("{}BlockAllOutbound", kRulePrefix));
        if (!allow_lo_in)
            missing.push_back(std::format("{}AllowLoopbackIn", kRulePrefix));
        if (!allow_lo_out)
            missing.push_back(std::format("{}AllowLoopbackOut", kRulePrefix));
        if (!allow_lo_in6)
            missing.push_back(std::format("{}AllowLoopbackIn6", kRulePrefix));
        if (!allow_lo_out6)
            missing.push_back(std::format("{}AllowLoopbackOut6", kRulePrefix));
        std::string joined;
        for (size_t i = 0; i < missing.size(); ++i) {
            if (i)
                joined += ", ";
            joined += missing[i];
        }
        return joined;
    }
};

/**
 * Scans a `netsh advfirewall firewall show rule` capture (caller
 * concatenates the dir=in and dir=out captures — see win_is_quarantined) for
 * the four base rule names by their "Rule Name:" lines. Presence-only
 * (matches netsh_matching_rule_names' line parse); does not check
 * Enabled/Action, on the same "the rule existing under our exact name is the
 * signal" basis the pre-#3285 code already used.
 */
inline NetshBaseRules netsh_base_rules_present(std::string_view show_rule_output) {
    NetshBaseRules result;
    std::istringstream iss{std::string{show_rule_output}};
    std::string line;
    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        if (key != "Rule Name")
            continue;
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());
        val = std::string{strip_cr(val)}; // netsh emits CRLF; `output` is raw bytes

        if (val == std::format("{}BlockAllInbound", kRulePrefix))
            result.block_in = true;
        else if (val == std::format("{}BlockAllOutbound", kRulePrefix))
            result.block_out = true;
        else if (val == std::format("{}AllowLoopbackIn", kRulePrefix))
            result.allow_lo_in = true;
        else if (val == std::format("{}AllowLoopbackOut", kRulePrefix))
            result.allow_lo_out = true;
        else if (val == std::format("{}AllowLoopbackIn6", kRulePrefix))
            result.allow_lo_in6 = true;
        else if (val == std::format("{}AllowLoopbackOut6", kRulePrefix))
            result.allow_lo_out6 = true;
    }
    return result;
}

/**
 * Every "Rule Name:" value in `show_rule_output` whose value starts with
 * kRulePrefix, deduplicated, in first-seen order. Feeds win_unquarantine's
 * delete list — netsh has no wildcard delete, so every matching name must
 * be named individually.
 */
inline std::vector<std::string> netsh_matching_rule_names(std::string_view show_rule_output) {
    std::vector<std::string> names;
    std::istringstream iss{std::string{show_rule_output}};
    std::string line;
    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        if (key != "Rule Name")
            continue;
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());
        val = std::string{strip_cr(val)}; // netsh emits CRLF; `output` is raw bytes
        if (val.starts_with(kRulePrefix)) {
            bool found = false;
            for (const auto& n : names) {
                if (n == val) {
                    found = true;
                    break;
                }
            }
            if (!found)
                names.push_back(val);
        }
    }
    return names;
}

/**
 * Whitelisted IPs from an "Allow"-named YuzuQuarantine rule's RemoteIP
 * field, deduplicated, excluding loopback ("127.0.0.1") and "Any". A CIDR
 * suffix (e.g. "1.2.3.4/32") is stripped before comparison/storage. Mirrors
 * win_get_whitelist's pre-migration state-machine parse (Rule Name: /
 * RemoteIP: key lines) exactly.
 */
inline std::vector<std::string> netsh_whitelist_ips(std::string_view show_rule_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{show_rule_output}};
    std::string line;
    std::string current_rule;

    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());
        val = std::string{strip_cr(val)}; // netsh emits CRLF; `output` is raw bytes

        if (key == "Rule Name") {
            current_rule = val;
        } else if (key == "RemoteIP" && current_rule.starts_with(kRulePrefix) &&
                   current_rule.find("Allow") != std::string::npos) {
            if (val != "127.0.0.1" && val != "::1" && val != "Any") {
                auto slash = val.find('/');
                if (slash != std::string::npos)
                    val = val.substr(0, slash);
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == val) {
                        found = true;
                        break;
                    }
                }
                if (!found && is_safe_ip(val))
                    ips.push_back(val);
            }
        }
    }
    return ips;
}

/**
 * #3284 branch A — Windows Block-vs-Allow precedence
 * (docs/quarantine-windows-firewall-precedence.md, verified live
 * 2026-08-21: BLOCK OVERRIDES ALLOW). win_quarantine no longer creates
 * blanket Block rules that would outrank the whitelist/loopback Allow
 * rules; it blocks via the PROFILE DEFAULT policy instead — a rule always
 * beats a profile default, so with no Block rule left to outrank them, the
 * Allow rules finally take effect. This is that policy's read-side parser.
 */
enum class FirewallAction { block, allow, unknown };

/// One profile's ("Domain"/"Private"/"Public") inbound/outbound default
/// action, as `netsh advfirewall show allprofiles` reports it.
struct ProfilePolicy {
    std::string profile;
    FirewallAction inbound = FirewallAction::unknown;
    FirewallAction outbound = FirewallAction::unknown;
};

/**
 * Parses `netsh advfirewall show allprofiles` output: each "<Name> Profile
 * Settings:" header starts a profile, and that profile's own "Firewall
 * Policy" line (e.g. "BlockInbound,AllowOutbound") supplies its
 * inbound/outbound defaults. A profile without a recognisable "Firewall
 * Policy" line is simply absent from the result — never fabricated as
 * unknown/unknown — so a truncated or malformed capture yields fewer
 * profiles rather than false entries.
 */
inline std::vector<ProfilePolicy> netsh_firewall_policy(std::string_view show_allprofiles_output) {
    std::vector<ProfilePolicy> profiles;
    std::istringstream iss{std::string{show_allprofiles_output}};
    std::string line;
    std::string current_profile;

    auto parse_action = [](std::string_view token) {
        if (token.find("Block") != std::string_view::npos)
            return FirewallAction::block;
        if (token.find("Allow") != std::string_view::npos)
            return FirewallAction::allow;
        return FirewallAction::unknown;
    };

    while (std::getline(iss, line)) {
        auto header_pos = line.find(" Profile Settings:");
        if (header_pos != std::string::npos) {
            current_profile = line.substr(0, header_pos);
            while (!current_profile.empty() && current_profile.front() == ' ')
                current_profile.erase(current_profile.begin());
            continue;
        }
        if (current_profile.empty())
            continue;

        auto policy_pos = line.find("Firewall Policy");
        if (policy_pos == std::string::npos)
            continue;

        auto value = line.substr(policy_pos + std::string_view{"Firewall Policy"}.size());
        while (!value.empty() && value.front() == ' ')
            value.erase(value.begin());
        while (!value.empty() && (value.back() == '\r' || value.back() == ' '))
            value.pop_back();

        auto comma = value.find(',');
        const std::string in_tok = value.substr(0, comma);
        const std::string out_tok =
            comma == std::string::npos ? std::string{} : value.substr(comma + 1);

        ProfilePolicy p;
        p.profile = current_profile;
        p.inbound = parse_action(in_tok);
        p.outbound = parse_action(out_tok);
        profiles.push_back(std::move(p));
        // This profile's policy line is now consumed; a stray second
        // "Firewall Policy" match before the next header must not be
        // misattributed to it.
        current_profile.clear();
    }
    return profiles;
}

// ── #3284: restoring the pre-quarantine profile policy ─────────────────────
//
// Branch A contains by REPLACING the all-profiles firewall policy, so release
// has to put back what was there. Writing a hardcoded default instead — the
// shape this first shipped with — silently DOWNGRADES a host whose admin or
// GPO had deliberately set block-both to Microsoft's allowoutbound default,
// permanently, on one quarantine/release cycle. The macOS analogy that
// justified it does not hold: /etc/pf.conf is a FILE the admin owns, so
// reloading it returns to their configuration, whereas the Windows profile
// policy is LIVE STATE, and overwriting it destroys their choice.
//
// The policy is PER PROFILE (Domain/Private/Public may legitimately differ),
// so a faithful restore is one scoped call each, never a single allprofiles
// write — a mixed-profile host would otherwise be flattened to whichever
// single value was chosen.
//
// The captured value round-trips through plugin KV storage, which means it
// re-enters as UNTRUSTED input on the way back and lands in an argv. Both
// halves below are therefore strict: parsing rejects anything it does not
// recognise outright rather than passing a fragment through, and the caller
// treats a rejected read as "no stored policy" and falls back honestly.

/// netsh's own profile-scope tokens, keyed by the profile name
/// `netsh_firewall_policy` reports. Returns empty for anything unrecognised —
/// never a guess, since the result names the scope a mutation applies to.
inline std::string_view netsh_profile_scope(std::string_view profile) {
    if (profile == "Domain")
        return "domainprofile";
    if (profile == "Private")
        return "privateprofile";
    if (profile == "Public")
        return "publicprofile";
    return {};
}

/// The netsh policy token for one profile's captured pair, e.g.
/// "blockinbound,allowoutbound". Empty when either half is `unknown` — an
/// unknown action must never be materialised into a policy write.
inline std::string netsh_policy_token(FirewallAction inbound, FirewallAction outbound) {
    auto in_s = inbound == FirewallAction::block    ? "blockinbound"
                : inbound == FirewallAction::allow  ? "allowinbound"
                                                    : "";
    auto out_s = outbound == FirewallAction::block   ? "blockoutbound"
                 : outbound == FirewallAction::allow ? "allowoutbound"
                                                     : "";
    if (*in_s == '\0' || *out_s == '\0')
        return {};
    return std::string{in_s} + "," + out_s;
}

/**
 * Serialises a captured policy set for durable storage, e.g.
 * "Domain=block,allow;Private=block,block". Profiles whose actions are not
 * both known are OMITTED rather than written as unknown — on restore they
 * are simply not replayed, which leaves that profile untouched rather than
 * setting it from a value we never actually observed.
 */
inline std::string serialize_profile_policies(const std::vector<ProfilePolicy>& profiles) {
    auto a = [](FirewallAction x) -> std::string_view {
        return x == FirewallAction::block   ? "block"
               : x == FirewallAction::allow ? "allow"
                                            : "";
    };
    std::string out;
    for (const auto& p : profiles) {
        if (netsh_profile_scope(p.profile).empty())
            continue;
        const auto in_s = a(p.inbound);
        const auto out_s = a(p.outbound);
        if (in_s.empty() || out_s.empty())
            continue;
        if (!out.empty())
            out += ';';
        out += p.profile;
        out += '=';
        out += in_s;
        out += ',';
        out += out_s;
    }
    return out;
}

/// True only when `profiles` covers ALL THREE Windows profiles with known
/// actions on both directions — i.e. a restore image that can put the host
/// back exactly as it was.
///
/// CDX-P1-04's sibling: quarantine replaces the policy on ALL profiles at
/// once, so anything less than all three is not a restore image, it is a
/// fragment. Replaying a fragment puts some profiles back and silently leaves
/// the others on the quarantine policy — a host left partly contained while
/// the release reports success. `netsh_firewall_policy` legitimately returns
/// fewer profiles when a capture is truncated or localised, so this is a real
/// input, not a theoretical one. A fragment is therefore never persisted and
/// never replayed; the caller takes the honest default-restore fallback and
/// says so on both channels.
inline bool is_complete_profile_policy(const std::vector<ProfilePolicy>& profiles) {
    bool domain = false, priv = false, pub = false;
    for (const auto& p : profiles) {
        if (p.inbound == FirewallAction::unknown || p.outbound == FirewallAction::unknown)
            return false;
        // A REPEATED profile is not a restore image. Replay walks the vector in
        // order and issues one netsh write per entry, so the LAST record for a
        // profile wins — a record set ending `...;Domain=allow,allow` restores
        // Domain to a policy that was never captured, and still reports a clean
        // release. That is the downgrade #3284 exists to prevent, so a duplicate
        // rejects the whole capture rather than being deduplicated: we cannot
        // know which of two conflicting records was the true one.
        bool* seen = p.profile == "Domain"    ? &domain
                     : p.profile == "Private" ? &priv
                     : p.profile == "Public"  ? &pub
                                              : nullptr;
        if (!seen)
            return false; // an unrecognised profile means the capture is not what we think it is
        if (*seen)
            return false; // duplicate
        *seen = true;
    }
    return domain && priv && pub;
}

/// True when every profile in a capture is blocking BOTH directions — i.e. the
/// capture is indistinguishable from the policy `win_quarantine` itself
/// installs.
///
/// Belt to the write-once guard in the plugin. Re-quarantining an already
/// contained host captures block/block on all three profiles, which is a
/// structurally VALID and COMPLETE record: nothing downstream can tell it from
/// a genuine pre-quarantine image. Replaying it at release leaves the host cut
/// off while release reports success — the 672896112 stranding class by another
/// route.
///
/// THIS PREDICATE IS NOT A DECISION ON ITS OWN, and an earlier revision of this
/// comment claimed otherwise: it said "a host hardened to block-both is
/// restored to block-both by the honest fallback anyway, so refusing it costs
/// nothing". The fallback writes `blockinbound,allowoutbound`, never
/// block-both, so on a genuinely hardened host the refusal is what REMOVES the
/// admin's egress filtering. Block/block is both this plugin's own containment
/// policy and a legitimate hardened posture, and the capture cannot tell them
/// apart — the caller must supply that discriminator (whether this plugin's own
/// loopback rule was already installed; see `store_prior_policy`). Use this
/// predicate only in conjunction with it.
inline bool is_quarantine_shaped_policy(const std::vector<ProfilePolicy>& profiles) {
    if (profiles.empty())
        return false;
    for (const auto& p : profiles) {
        if (p.inbound != FirewallAction::block || p.outbound != FirewallAction::block)
            return false;
    }
    return true;
}

/**
 * Inverse of serialize_profile_policies, applied to a value read back out of
 * storage. STRICT by design: any malformed record — unknown profile name,
 * missing separator, unrecognised action word — yields an EMPTY result for
 * the whole string, not a partial set. A partially-parsed restore would put
 * some profiles back and silently leave others on the quarantine policy,
 * which is a worse outcome than the honest fallback.
 */
inline std::vector<ProfilePolicy> parse_profile_policies(std::string_view stored) {
    std::vector<ProfilePolicy> out;
    if (stored.empty())
        return out;
    size_t pos = 0;
    while (pos <= stored.size()) {
        const auto semi = stored.find(';', pos);
        const auto record = stored.substr(pos, semi == std::string_view::npos ? std::string_view::npos
                                                                             : semi - pos);
        const auto eq = record.find('=');
        const auto comma = record.find(',');
        if (eq == std::string_view::npos || comma == std::string_view::npos || comma < eq)
            return {};
        const auto profile = record.substr(0, eq);
        const auto in_s = record.substr(eq + 1, comma - eq - 1);
        const auto out_s = record.substr(comma + 1);
        if (netsh_profile_scope(profile).empty())
            return {};
        auto act = [](std::string_view s) {
            return s == "block"   ? FirewallAction::block
                   : s == "allow" ? FirewallAction::allow
                                  : FirewallAction::unknown;
        };
        const auto in_a = act(in_s);
        const auto out_a = act(out_s);
        if (in_a == FirewallAction::unknown || out_a == FirewallAction::unknown)
            return {};
        out.push_back(ProfilePolicy{std::string{profile}, in_a, out_a});
        if (semi == std::string_view::npos)
            break;
        pos = semi + 1;
    }
    return out;
}

/**
 * netsh argv restoring ONE profile's captured policy — the per-profile
 * counterpart to netsh_set_firewall_policy_argv's all-profiles set. Returns
 * an empty argv when the profile name or either action is unrecognised, so a
 * caller can never spawn a half-formed policy write.
 */
inline std::vector<std::string> netsh_restore_profile_policy_argv(std::string_view netsh_path,
                                                                   const ProfilePolicy& p) {
    const auto scope = netsh_profile_scope(p.profile);
    const auto token = netsh_policy_token(p.inbound, p.outbound);
    if (scope.empty() || token.empty())
        return {};
    return {std::string{netsh_path}, "advfirewall", "set", std::string{scope}, "firewallpolicy",
            token};
}

/**
 * True iff EVERY profile in `profiles` blocks both inbound and outbound —
 * win_is_quarantined's branch-A containment check. An empty/unparseable
 * capture returns false, never vacuously true: a failed or malformed read
 * must never be mistaken for "every profile blocks", or a genuinely
 * unenforced host could read as contained.
 */
[[nodiscard]] inline bool all_profiles_blocking(const std::vector<ProfilePolicy>& profiles) {
    if (profiles.empty())
        return false;
    for (const auto& p : profiles) {
        if (p.inbound != FirewallAction::block || p.outbound != FirewallAction::block)
            return false;
    }
    return true;
}

// ── Capture-usability gate ──────────────────────────────────────────────────

/**
 * Whether a completed `run_bounded_subprocess` call is trustworthy enough to
 * PARSE — as distinct from whether the tool ran, which is the question
 * `report_runner_result` answers.
 *
 * The two differ on exactly one input, and that input is the whole reason this
 * exists. `netsh advfirewall firewall show rule name=all` on a host with a
 * large rule set overflows the runner's ~1 MB capture cap: the runner keeps
 * draining, the child exits normally, and the result reports `tool_ran=true`,
 * `exit_code=0` — a clean run whose OUTPUT is a prefix. This plugin's own
 * rules are added last and therefore land in the dropped tail, so every
 * `netsh_*` parser then answers "no Yuzu rules here" about a host this plugin
 * contained. What that produces per site:
 *
 *   - `win_is_quarantined` -> `state|inactive` on a contained host, with a
 *     note asserting the blocking policy is the host's own posture and NOT an
 *     active quarantine. The `!reads_ok -> uncertain` guard (CDX-P1-04) exists
 *     to stop precisely this and cannot see it, because the read "succeeded".
 *   - `win_unquarantine` -> the delete list comes back empty, nothing is
 *     attempted, `teardown_failed` stays false, and release reports
 *     `status|released` rc 0 while the allow rules survive and the stored
 *     prior policy is cleared.
 *   - `win_get_whitelist` -> a short whitelist reported as complete.
 *
 * All three are the false-clean class this whole change exists to remove, so
 * the test is spelled ONCE, purely, and applied at every site that parses that
 * command's output. Takes the fields rather than the struct so a plugin-side
 * unit test can reach it without linking agent-core — the same shape
 * `certificates_macos_parsers.hpp::is_usable_capture` uses.
 *
 * DELIBERATELY NOT A TEST ON EXIT CODE, which is where this differs from that
 * sibling. `run_tool`'s contract is explicit that a read-only parse must not
 * gate on a query command's exit status — "this host has no such rule" is a
 * normal answer these callers exist to receive, not a failure. What
 * invalidates a PARSE is a capture that is incomplete or was never really
 * produced, and that is exactly the three fields below. A genuine runner
 * failure (spawn/deadline/signal) is still forwarded through the ABI4 seam by
 * `report_runner_result` at the call site; this decides only whether the TEXT
 * can be trusted.
 *
 * BE PRECISE ABOUT WHAT THAT BUYS AT TODAY'S CALL SITES. Every current one
 * passes `name=all` (a count is not given deliberately — an earlier revision
 * named one and was already wrong by the time it was written). `name=all`
 * exits 0 on any host with rules to list, which is every real one, so at these
 * sites the omission is close to a no-op and an earlier revision overstated it
 * by naming concrete `uncertain` / `release_uncertain` outcomes it cannot
 * produce here.
 *
 * It is kept for two reasons that do hold. It is the contract for the NEXT
 * caller: a site passing `name=<specific>` — the shape that reliably exits
 * non-zero on no match — would otherwise inherit a gate the read-only
 * contract forbids. And even for `name=all` the "always" is practical rather
 * than absolute (a host whose matching set is genuinely empty can exit 1), so
 * not depending on it is simply correct. It fails safe either way: an empty
 * capture parses to "no rules of ours", which is the right answer for a host
 * that has none.
 */
[[nodiscard]] inline bool netsh_capture_usable(bool tool_ran, bool timed_out,
                                               bool output_truncated) {
    return tool_ran && !timed_out && !output_truncated;
}

// ── Linux: iptables -L ──────────────────────────────────────────────────────

/**
 * True iff a `iptables -L yuzu-quarantine -n` listing contains the terminal
 * DROP — i.e. the chain the jumps point at actually denies anything.
 *
 * WHY THE JUMPS ARE NOT ENOUGH. `iptables_chain_referenced` below answers
 * "is there a jump to our chain", which is what the pre-migration code
 * checked and all this leg checked until now. A chain can be REFERENCED and
 * EMPTY: `linux_unquarantine` deletes the two jumps with failures
 * deliberately ignored (they are idempotent cleanups), then flushes and
 * deletes the chain. Under xtables lock contention both deletes can fail
 * past the deadline while the flush succeeds — leaving both jumps in place,
 * the chain empty, and INPUT/OUTPUT policy ACCEPT. Release honestly reports
 * `release_uncertain` for that command, but every subsequent `status` poll
 * then reads `active` on a host that blocks nothing, and a retry reproduces
 * it, so the divergence is durable rather than transient.
 *
 * Windows verifies the profile-default policy and macOS verifies pf is live;
 * this is the Linux equivalent, and it was the one leg of the three that
 * proved only that a pointer existed.
 *
 * Matched on the TARGET COLUMN, not a substring: `find("DROP")` would also
 * match a whitelist entry for a host whose reverse DNS contains it, and
 * `iptables -L -n` is numeric-only precisely so the listing carries no
 * hostnames — but the rule text is still attacker-adjacent data and a
 * column-anchored match costs nothing.
 */
[[nodiscard]] inline bool iptables_chain_denies(std::string_view listing) {
    size_t pos = 0;
    while (pos <= listing.size()) {
        const size_t eol = listing.find('\n', pos);
        std::string_view line =
            listing.substr(pos, eol == std::string_view::npos ? std::string_view::npos : eol - pos);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        // The target is the first whitespace-delimited token on the line.
        const size_t tok_end = line.find_first_of(" \t");
        if (line.substr(0, tok_end) == "DROP")
            return true;
        if (eol == std::string_view::npos)
            break;
        pos = eol + 1;
    }
    return false;
}

/**
 * True iff `list_input_output` (captured from `iptables -L INPUT -n`)
 * references the yuzu-quarantine chain — i.e. the INPUT jump rule is
 * present. Mirrors linux_is_quarantined's pre-migration substring check
 * exactly.
 */
inline bool iptables_chain_referenced(std::string_view list_input_output) {
    return list_input_output.find("yuzu-quarantine") != std::string_view::npos;
}

/**
 * Whitelisted IPs from `iptables -L yuzu-quarantine -n` output: ACCEPT
 * lines, excluding the ESTABLISHED/RELATED state rule, deduplicated.
 * Mirrors linux_get_whitelist's pre-migration column parse, minus the dead
 * "lo" substring exclusion removed by #3260 (see add_if_new's comment for
 * why no interface check is needed at all).
 */
inline std::vector<std::string> iptables_whitelist_ips(std::string_view list_chain_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{list_chain_output}};
    std::string line;

    auto add_if_new = [&](const std::string& v) {
        // is_safe_ip is the ONLY guard needed here: it accepts only
        // '[0-9a-fA-F.:]' (VERIFIED above), so neither the IPv4 wildcard
        // "0.0.0.0/0" nor an IPv6 "::/0" sibling — both contain '/' — can
        // ever reach this point. A dedicated literal comparison for either
        // is provably dead code (#3260); do not re-add one.
        if (v.empty() || !is_safe_ip(v))
            return;
        for (const auto& existing : ips) {
            if (existing == v)
                return;
        }
        ips.push_back(v);
    };

    while (std::getline(iss, line)) {
        if (line.find("ACCEPT") == std::string::npos)
            continue;
        // No interface (-i/-o) check is needed here (#3260): the loopback
        // ACCEPT rules this plugin creates carry wildcard source AND
        // destination ("0.0.0.0/0"), which add_if_new's is_safe_ip guard
        // above already rejects — a wildcard can never become a whitelist
        // entry regardless of what column parsing sees. `iptables -L -n`
        // (without `-v`) does not reliably render -i/-o restrictions as
        // visible text either, so a substring filter here was never a sound
        // way to match what it claimed to guard against; it only ever
        // risked discarding a genuine whitelisted IP whose line happened
        // to contain "lo" elsewhere.
        if (line.find("state") != std::string::npos)
            continue;

        std::istringstream lss(line);
        std::string target, prot, opt, source, dest;
        lss >> target >> prot >> opt >> source >> dest;

        add_if_new(source);
        add_if_new(dest);
    }
    return ips;
}

/**
 * Merges `primary` and `secondary` whitelist-IP lists into one deduplicated
 * list, primary-first, preserving first-seen order — the pure core of
 * linux_get_whitelist's iptables+ip6tables merge (#3282): an IP present in
 * both captures (or repeated within either) appears exactly once.
 */
inline std::vector<std::string> merge_whitelist_ips(std::vector<std::string> primary,
                                                     const std::vector<std::string>& secondary) {
    for (const auto& ip : secondary) {
        bool found = false;
        for (const auto& existing : primary) {
            if (existing == ip) {
                found = true;
                break;
            }
        }
        if (!found)
            primary.push_back(ip);
    }
    return primary;
}

// ── macOS: pfctl -s rules ───────────────────────────────────────────────────

/**
 * True iff the active main ruleset (captured from `pfctl -s rules`) carries
 * the load-bearing default-deny ("block all", or pfctl's canonicalized
 * "block drop all"). This is the ONLY thing macos_is_quarantined checks —
 * post-incident design writes quarantine rules directly into the main
 * ruleset (never a pf anchor); see quarantine_plugin.cpp's header comment
 * on the 672896112 production incident this design fixed.
 */
inline bool pfctl_rules_blocked(std::string_view rules_output) {
    return rules_output.find("block drop all") != std::string_view::npos ||
           rules_output.find("block all") != std::string_view::npos;
}

/**
 * Whitelisted IPs from `pfctl -s rules` output: "pass quick from <ip> to
 * any" / "pass quick from any to <ip>" lines, excluding lo0 and "any",
 * deduplicated. Mirrors macos_get_whitelist's pre-migration parse exactly.
 */
inline std::vector<std::string> pfctl_whitelist_ips(std::string_view rules_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{rules_output}};
    std::string line;

    auto add_if_new = [&](const std::string& v) {
        if (v == "any" || !is_safe_ip(v))
            return;
        for (const auto& existing : ips) {
            if (existing == v)
                return;
        }
        ips.push_back(v);
    };

    while (std::getline(iss, line)) {
        if (line.find("pass") == std::string::npos)
            continue;
        if (line.find("lo0") != std::string::npos)
            continue;

        auto from_pos = line.find("from ");
        if (from_pos != std::string::npos) {
            auto start = from_pos + 5;
            auto end = line.find(' ', start);
            add_if_new(line.substr(start, end - start));
        }
        auto to_pos = line.find("to ");
        if (to_pos != std::string::npos) {
            auto start = to_pos + 3;
            auto end = line.find(' ', start);
            if (end == std::string::npos)
                end = line.size();
            add_if_new(line.substr(start, end - start));
        }
    }
    return ips;
}

/**
 * #3283 — a blocking main ruleset (`pfctl_rules_blocked` above) does not
 * prove traffic is actually being blocked: pf itself can be loaded but
 * disabled (stock macOS ships pf off by default), and `pfctl -e` can exit
 * zero without pf actually coming up. `pfctl_status_state` parses `pfctl -s
 * info`'s first line ("Status: Enabled for …" / "Status: Disabled for …")
 * to answer that separately; anything else, including the empty capture a
 * non-root read produces, is `unknown`.
 *
 * Byte-equivalent to
 * agents/plugins/firewall/src/firewall_parsers.hpp::parse_pf_status —
 * duplicated rather than shared because plugins are independent shared
 * libraries and no plugin in this tree includes another plugin's parser
 * header; consolidating into agents/shared is a possible follow-up, not
 * this PR's scope.
 */
enum class PfStatus { enabled, disabled, unknown };

[[nodiscard]] constexpr PfStatus pfctl_status_state(std::string_view out) {
    if (out.find("Status: Enabled") != std::string_view::npos)
        return PfStatus::enabled;
    if (out.find("Status: Disabled") != std::string_view::npos)
        return PfStatus::disabled;
    return PfStatus::unknown;
}

/**
 * Combines the main-ruleset block check with the live pf-enabled status into
 * one honest QuarStatus (#3283): a blocking ruleset that pf is not actually
 * enforcing must never read `active`.
 *
 *   read failed        -> uncertain (CDX-P1-04, applied to this leg too: an
 *                          EMPTY capture from a FAILED `pfctl -s rules` is
 *                          byte-identical to a clean host's, so `rules_blocked`
 *                          alone cannot tell them apart. Without this, a
 *                          contained macOS host whose sudoers grant was
 *                          revoked reads `state|inactive`, rc 0, ABI4
 *                          OK/COMPLETE — both channels agreeing that a
 *                          network-isolated device is not quarantined. Linux
 *                          and Windows already carried `reads_ok`; macOS was
 *                          the one leg that did not, which is the whole reason
 *                          this parameter exists.)
 *   not blocked        -> inactive (regardless of pf's own status — no
 *                          quarantine ruleset is loaded at all)
 *   blocked + enabled   -> active (the true positive: blocking AND enforced)
 *   blocked + disabled  -> degraded (loaded but NOT enforced — the exact
 *                          #3283 failure: traffic is not actually blocked)
 *   blocked + unknown   -> uncertain (the read itself produced nothing
 *                          recognisable — e.g. a non-root capture — so
 *                          containment can be neither confirmed nor denied)
 */
[[nodiscard]] inline QuarStatus macos_quar_status(bool rules_blocked, PfStatus pf_status,
                                                  bool reads_ok = true) {
    if (!reads_ok)
        return QuarStatus::uncertain;
    if (!rules_blocked)
        return QuarStatus::inactive;
    switch (pf_status) {
    case PfStatus::enabled:
        return QuarStatus::active;
    case PfStatus::disabled:
        return QuarStatus::degraded;
    case PfStatus::unknown:
        return QuarStatus::uncertain;
    }
    return QuarStatus::uncertain; // unreachable; keeps -Wswitch happy across compilers
}

} // namespace yuzu::quarantine
