/**
 * discovery_scan_plan.hpp — the pure decisions behind `scan_subnet`
 * (Wave-2 PR2.1c, WP-C). Portable and header-only: this file and its test TU
 * (test_discovery_scan_plan.cpp) carry no platform guard and run on every leg.
 *
 * `do_scan_subnet` used to bury three honesty-critical decisions inside an
 * untestable shell (a live ICMP socket + a real ARP table + a wall clock), so
 * nothing proved them. They are free functions here instead — the repo's
 * "pure core, thin shell" discipline — leaving the plugin's own code to do
 * only the I/O the unit suites never run:
 *
 *   classify_icmp_session() — the three session states the sweep must handle,
 *       derived from IcmpSession's {ok, permitted} pair.
 *   degrade_for()           — session state -> ABI4 result status, completeness
 *       and machine-readable reason. This is the "never a silent empty result,
 *       never a fake 100% loss" contract: a denied socket must report
 *       CONSTRAINED/PARTIAL, not a successful scan of a dead network.
 *   probe_budget_ms()       — the per-host ICMP budget. The bound that keeps a
 *       /24 sweep finite: 254 hosts * kMaxProbeBudgetMs is the worst case, and
 *       it must stay well inside the caller's overall scan deadline.
 *   arp_hosts_in_subnet()   — confines an ARP-derived fallback host set to the
 *       subnet actually requested, so a degraded scan never reports unrelated
 *       cached neighbours (other subnets, broadcast, multicast) as findings.
 */
#pragma once

#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/plugin.h> // YuzuResultStatus / YuzuResultCompleteness (ABI4)

namespace yuzu::discovery {

// ── ICMP session state ────────────────────────────────────────────────────

/**
 * The three states an IcmpSession construction can land in. Kept as a named
 * enum rather than the raw {ok, permitted} bool pair so the mapping below is
 * exhaustive and a fourth state cannot be added silently.
 */
enum class IcmpAvailability {
    Usable,      // socket created — probe normally
    Denied,      // refused for a permissions reason (Linux ping_group_range)
    Unavailable, // refused for a non-permissions reason (EMFILE/ENOMEM/...)
};

/**
 * Classify IcmpSession's {ok(), permitted} pair. `permitted` is only
 * meaningful when the session is NOT usable: IcmpSession sets it false
 * exclusively for EACCES/EPERM/EPROTONOSUPPORT, so a failed-but-permitted
 * session is an ordinary resource failure, not a policy denial.
 */
inline IcmpAvailability classify_icmp_session(bool ok, bool permitted) {
    if (ok)
        return IcmpAvailability::Usable;
    return permitted ? IcmpAvailability::Unavailable : IcmpAvailability::Denied;
}

// ── ABI4 degrade reporting ────────────────────────────────────────────────

/**
 * How a degraded scan must describe itself to the agent. `reason` is the
 * machine-readable provenance tag; `message` is the operator-facing warning
 * line. Both are static string literals — no ownership to track.
 */
struct DegradeReport {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    const char* reason;
    const char* message;
};

/**
 * The ABI4 result status a scan must report for a given session state.
 * `Usable` degrades to nothing (`has_report == false`) — a normal sweep
 * declares no degradation. Every other state is PARTIAL: the ARP table still
 * yields real hosts, so the result is neither a success nor an empty failure.
 */
struct MaybeDegrade {
    bool has_report{false};
    DegradeReport report{};
};

inline MaybeDegrade degrade_for(IcmpAvailability availability) {
    switch (availability) {
    case IcmpAvailability::Usable:
        return {};
    case IcmpAvailability::Denied:
        return {true,
                {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                 "icmp:ping_group_range",
                 "unprivileged ICMP socket denied by net.ipv4.ping_group_range — "
                 "reporting ARP-table hosts only"}};
    case IcmpAvailability::Unavailable:
        break;
    }
    return {true,
            {YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
             "icmp:socket_error",
             "ICMP socket unavailable — reporting ARP-table hosts only"}};
}

/**
 * Tally of what a completed sweep actually managed to do. `probed` counts
 * hosts we attempted to transmit to; `transmit_blocked` counts attempts that
 * never left the machine (send denied or failed).
 */
struct SweepTally {
    int probed{0};
    int transmit_blocked{0};
    int replied{0};
};

/**
 * The degrade report for a sweep whose probes could not be transmitted.
 *
 * This is the runtime twin of degrade_for(): the session CONSTRUCTED fine, so
 * the pre-flight check passed, but a policy denied transmission afterwards
 * (seatbelt/SELinux/nftables all do this). Without this the sweep marks every
 * unanswered host dead and returns a confidently empty network with an OK
 * status — the agent maps rc==0 plus an undeclared status straight to OK, so
 * no later layer catches it either.
 *
 * Reported only when EVERY probe was blocked: a partially blocked sweep still
 * yields real replies, and the ARP half is independent, so a single blocked
 * probe should not condemn a whole scan.
 */
inline MaybeDegrade degrade_for_sweep(const SweepTally& tally) {
    if (tally.probed == 0 || tally.transmit_blocked < tally.probed)
        return {};
    return {true,
            {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
             "icmp:transmit_blocked",
             "ICMP probes could not be transmitted — reporting ARP-table hosts only"}};
}

/**
 * The degrade report for an ARP half that did not fully run.
 *
 * `scan_subnet` is documented as ARP + ICMP. When the ARP read fails, the ICMP
 * sweep can still find responsive hosts, but everything only ARP could supply
 * is lost — MAC attribution, and any cached neighbour that does not answer
 * ICMP. That is a PARTIAL result, not a clean one, and every leg previously
 * expressed the failure as an empty table, which is indistinguishable from a
 * quiet network.
 *
 * `ok=false` (the read failed) is UNAVAILABLE; a merely truncated parse is
 * CONSTRAINED — we got some of the table, just not all of it.
 */
inline MaybeDegrade degrade_for_arp(bool ok, bool complete) {
    if (!ok)
        return {true,
                {YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                 "arp:read_failed",
                 "ARP table could not be read — reporting ICMP-discovered hosts only, "
                 "without MAC attribution"}};
    if (!complete)
        return {true,
                {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                 "arp:table_truncated",
                 "ARP table was only partially decodable — some cached neighbours "
                 "may be missing"}};
    return {};
}

/**
 * The degrade report for a sweep cut short by its own overall deadline. The
 * hosts already probed are real findings, so this is CONSTRAINED/PARTIAL for
 * the same reason a denied socket is — not a clean success. Separate from
 * degrade_for() because the trigger is the clock, not the session.
 */
inline DegradeReport timeout_degrade() {
    return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, "scan:timeout",
            "scan deadline reached — reporting the hosts probed so far"};
}

/**
 * The degrade report for one or more reverse-DNS lookups that timed out or
 * were throttled by bounded_call's outstanding-call ceiling (Gate 6 SRE
 * finding). CONSTRAINED/PARTIAL for the same reason every other degrade here
 * is: the host itself is a real finding, only its hostname is missing, and
 * "no hostname" must not be silently indistinguishable from a genuine
 * absent-PTR-record answer.
 */
inline DegradeReport hostname_lookup_degraded() {
    return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "dns:hostname_lookup_degraded",
            "one or more reverse-DNS lookups timed out or were throttled — affected hosts "
            "report an unknown hostname"};
}

// ── Merging multiple degrade reports ─────────────────────────────────────

/**
 * `scan_subnet` can independently hit more than one degrade condition in a
 * single call (e.g. the ARP read fails AND the scan later hits its
 * deadline). The ABI4 result seam holds only one {status, completeness,
 * reason} triple, and `yuzu_ctx_set_result_status` is an unconditional
 * overwrite — calling it once per condition as each fires means only the
 * LAST one survives, silently discarding an earlier and sometimes more
 * actionable reason (governance Gate 4 consistency-auditor finding). The
 * caller accumulates every candidate through worst_of() and calls
 * set_result_status exactly once, with the most severe report seen.
 *
 * Severity order, worst first: UNAVAILABLE (the read/session did not run at
 * all) > CONSTRAINED/PERMISSION_DENIED (it ran but was bounded, blocked, or
 * truncated) > no report (a clean scan). This plugin's own conditions never
 * produce PERMISSION_DENIED today; it is ranked with CONSTRAINED so the
 * function stays exhaustive if one ever does.
 */
inline int degrade_severity(YuzuResultStatus status) {
    switch (status) {
    case YUZU_RESULT_STATUS_UNAVAILABLE:
        return 2;
    case YUZU_RESULT_STATUS_PERMISSION_DENIED:
    case YUZU_RESULT_STATUS_CONSTRAINED:
        return 1;
    case YUZU_RESULT_STATUS_OK:
    case YUZU_RESULT_STATUS_UNDECLARED:
        break;
    }
    return 0;
}

/**
 * Secondary tie-break for a same-severity worst_of() merge, consulted ONLY
 * when degrade_severity() ties — every other pair keeps the original
 * "earliest-accumulated report wins" rule unchanged (governance-deferred
 * #3253, extended to the DNS pair in the same governance round).
 *
 * The shared principle behind both named pairs: **a scan-level timeout
 * dominates a data-completeness degrade.** `scan:timeout` says "the back
 * half of the scan didn't run at all", which is strictly more actionable
 * than "the part that did run returned less data than it might have" —
 * and it is the reason an operator needs in order to know the result is
 * not merely thinner but truncated in scope. Plain accumulation order
 * loses it in both cases, because on the path each pair was filed for the
 * data-completeness condition is observed FIRST. (One ordering runs the
 * other way — the probe loop's own timeout is accumulated before the DNS
 * degrade — but those two cannot co-occur: if the probe loop consumed the
 * budget, the hostname loop's deadline check breaks it on its first
 * iteration, so no lookup ever runs to degrade. It is also harmless
 * regardless, since only `scan:timeout` is ever a preferred candidate and
 * it therefore survives as `current` either way.)
 *
 *   - `arp:table_truncated` (Step 1, the ARP read) accumulates before any
 *     `scan:timeout` — the gap #3253 filed.
 *   - `dns:hostname_lookup_degraded` accumulates before the hostname
 *     loop's own `scan:timeout` a few lines later in do_scan_subnet —
 *     the identical defect shape in the same function, closed here rather
 *     than left as new debt behind #3253's fix.
 *
 * Note on which deadline actually fires: the probe loop's own timeout is
 * near-unreachable in practice (its budget ceiling is well under
 * kScanTimeoutSeconds), so the `scan:timeout` that reaches worst_of is
 * almost always the HOSTNAME loop's. That is also why the DNS pair matters
 * more than it looks — see the reachability note in the tests.
 *
 * Known, deliberately NOT closed here: `icmp:transmit_blocked` and
 * `icmp:ping_group_range` can also tie with a later `scan:timeout` and
 * still lose it under earliest-wins. Whether an ICMP-blocked sweep is a
 * "data-completeness" degrade in this principle's sense is a genuine
 * judgment call rather than an oversight, so it is tracked as a follow-up
 * rather than widened silently in the same round.
 *
 * Both are checked as EXPLICIT NAMED PAIRS rather than by ranking the
 * data-completeness reasons below every other reason. A scalar rank would
 * silently demote `arp:table_truncated` against `icmp:ping_group_range`
 * and `dns:hostname_lookup_degraded` — both real CONSTRAINED-severity
 * reasons that can tie with it in the very same scan_subnet call — which
 * neither #3253 nor this extension asked for. Keep extending it one named
 * pair at a time, with the pair's own regression test, rather than
 * inventing a general actionability ordering nobody has asked for yet.
 */
inline bool degrade_tie_prefers_candidate(std::string_view current_reason,
                                          std::string_view candidate_reason) {
    if (candidate_reason != "scan:timeout")
        return false;
    return current_reason == "arp:table_truncated" ||
           current_reason == "dns:hostname_lookup_degraded";
}

/**
 * Keep `current` if it is at least as severe as `candidate`; otherwise adopt
 * `candidate`. A same-severity tie is broken by
 * degrade_tie_prefers_candidate() (#3253); every other tie keeps `current`
 * — the earliest-reported reason — exactly as before.
 */
inline MaybeDegrade worst_of(MaybeDegrade current, const MaybeDegrade& candidate) {
    if (!candidate.has_report)
        return current;
    if (!current.has_report)
        return candidate;

    const int current_sev = degrade_severity(current.report.status);
    const int candidate_sev = degrade_severity(candidate.report.status);
    if (candidate_sev != current_sev)
        return candidate_sev > current_sev ? candidate : current;

    if (degrade_tie_prefers_candidate(current.report.reason, candidate.report.reason))
        return candidate;
    return current;
}

// ── Sweep bounds ──────────────────────────────────────────────────────────

/**
 * Per-host ICMP budget ceiling. A /24 is 254 hosts, so the worst-case sweep
 * is 254 * 300ms ~= 76s — comfortably inside the plugin's overall deadline,
 * which is what makes the migration off 254 `ping` processes strictly faster
 * as well as spawn-free.
 */
constexpr int kMaxProbeBudgetMs = 300;

/**
 * The floor mirrors the caller-parameter clamp: a sub-100ms budget cannot
 * complete a LAN round-trip reliably and would report live hosts as dead.
 */
constexpr int kMinProbeBudgetMs = 100;

/**
 * Per-host ICMP budget for a requested `timeout_ms`.
 *
 * NOTE the deliberate asymmetry, which the action's documented parameter range
 * does not otherwise reveal: a caller asking for MORE than kMaxProbeBudgetMs
 * gets kMaxProbeBudgetMs, because a per-host budget is what multiplies by the
 * host count. `timeout_ms` narrows the per-host budget; it can never widen it
 * past the ceiling, and it is not the overall scan deadline.
 */
inline int probe_budget_ms(int requested_timeout_ms) {
    return std::clamp(requested_timeout_ms, kMinProbeBudgetMs, kMaxProbeBudgetMs);
}

// ── Degraded-scan host confinement ────────────────────────────────────────

/**
 * The hosts a degraded (no-ICMP) scan may report: the intersection of the
 * enumerated subnet with the ARP table, in the subnet's own order.
 *
 * The intersection is the point. An ARP/neighbour table holds entries for
 * other subnets, the link-layer broadcast address and multicast groups; a
 * fallback that returned the raw table would report those as discovered hosts
 * of the requested subnet, which is a false finding rather than a degraded one.
 */
inline std::vector<std::string> arp_hosts_in_subnet(const std::vector<std::string>& subnet_hosts,
                                                    const std::set<std::string>& arp_ips) {
    std::vector<std::string> out;
    for (const auto& ip : subnet_hosts) {
        if (arp_ips.count(ip))
            out.push_back(ip);
    }
    return out;
}

} // namespace yuzu::discovery
