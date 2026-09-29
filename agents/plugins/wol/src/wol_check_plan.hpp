/**
 * wol_check_plan.hpp — pure mechanism-selection logic for wol's `check`
 * action (ADR-3002 acquisition-ladder migration: rung-1 native ICMP +
 * TCP-connect fallback, replacing a popen'd `ping`).
 *
 * `check`'s contract is "is this host now reachable" (polled after a `wake`
 * to see whether the target woke up). Two probe mechanisms can answer that:
 *   - ICMP echo (yuzu::shared::IcmpSession, agents/shared/icmp_probe.hpp) —
 *     the primary, most authoritative signal when available.
 *   - A TCP connect on kFallbackTcpPort (yuzu::shared::tcp_sample, same
 *     header) — the pragmatic fallback for hosts/kernels that drop or deny
 *     unprivileged ICMP (e.g. Linux net.ipv4.ping_group_range), mirroring
 *     netprobe_plugin.cpp's own TCP-fallback shape (do_tcp, default port
 *     443 — the single most commonly-open TCP port across server and
 *     desktop fleets, needing no operator configuration).
 *
 * classify_check() below is the ONE place that decides the reported
 * verdict from what actually happened during a probe attempt. It is pure
 * (no I/O, no context) so it's fixture-testable without a live network hop
 * — the netprobe_stats.hpp pattern. The critical invariant it enforces:
 * a denied/unavailable ICMP session falling back to a usable TCP check is
 * an ordinary, expected degrade (CheckMechanism::tcp_fallback) — but if
 * NEITHER mechanism could even be attempted, the verdict is
 * CheckMechanism::unavailable, which the caller reports as an honest
 * CONSTRAINED/UNAVAILABLE result status, never a fabricated "unreachable".
 * Silently reporting "unreachable" when the truth is "we couldn't check at
 * all" would read to an operator as "the WoL wake failed" when it may well
 * have succeeded.
 */
#pragma once

namespace yuzu::wol {

// TCP port probed as the reachability fallback when ICMP is unusable or
// gets no reply. Matches netprobe_plugin.cpp's kDefaultPort for its own
// TCP action — one well-known port, no per-call configuration.
inline constexpr int kFallbackTcpPort = 443;

// Which mechanism produced the reported verdict.
enum class CheckMechanism {
    icmp,              // a real ICMP echo reply was observed
    tcp_fallback,      // ICMP unusable or no reply; TCP connect succeeded
    tcp_refused,       // ICMP unusable or no reply; TCP connect was actively
                        // refused (RST) — positive evidence the host's
                        // network stack is up, just nothing listening on
                        // the probed port (e.g. a woken desktop with ICMP
                        // also blocked)
    checked_no_reply,  // both mechanisms were genuinely attempted; neither
                        // produced a positive result (an honest negative)
    unavailable,       // neither mechanism could even be attempted — NOT
                        // the same as "checked and got no reply"
};

// Raw facts from one probe attempt, decoupled from the socket work so the
// decision below is pure and fixture-testable.
struct ProbeOutcome {
    // ICMP: a destination resolved AND the IcmpSession itself was usable
    // (constructed successfully / permitted) are separate facts — either
    // one being false means ICMP could not be attempted at all.
    bool icmp_resolved{false};
    bool icmp_session_ok{false};
    bool icmp_replied{false};

    // TCP fallback: a destination resolved is "TCP could be attempted";
    // tcp_connected is a successful connect; tcp_refused is an active RST
    // (yuzu::shared::tcp_sample's TcpSampleResult::refused) — distinct from
    // a genuine no-reply timeout, since a refusal is itself proof the host
    // answered.
    bool tcp_resolved{false};
    bool tcp_connected{false};
    bool tcp_refused{false};
};

struct CheckVerdict {
    bool reachable{false};
    CheckMechanism mechanism{CheckMechanism::unavailable};
};

// Pure decision: given what happened during one host's probe attempts,
// decide the reported verdict.
inline CheckVerdict classify_check(const ProbeOutcome& o) {
    if (o.icmp_session_ok && o.icmp_replied)
        return CheckVerdict{true, CheckMechanism::icmp};
    if (o.tcp_resolved && o.tcp_connected)
        return CheckVerdict{true, CheckMechanism::tcp_fallback};
    // A refused TCP connect (RST) is positive evidence the destination's
    // network stack is up -- reported reachable, distinct from a successful
    // connect so an operator can tell "something is listening" from "the
    // host answered but nothing is listening on this port".
    if (o.tcp_resolved && o.tcp_refused)
        return CheckVerdict{true, CheckMechanism::tcp_refused};

    // Neither mechanism produced a positive reply. "ICMP could be
    // attempted" requires BOTH a resolved destination and a usable
    // session; "TCP could be attempted" requires only a resolved
    // destination (a failed connect is still a genuine attempt).
    const bool icmp_attemptable = o.icmp_resolved && o.icmp_session_ok;
    const bool tcp_attemptable = o.tcp_resolved;
    if (!icmp_attemptable && !tcp_attemptable)
        return CheckVerdict{false, CheckMechanism::unavailable};

    return CheckVerdict{false, CheckMechanism::checked_no_reply};
}

// Renders a mechanism to the short lowercase token written into the
// plugin's supplementary output row.
inline const char* check_mechanism_label(CheckMechanism m) {
    switch (m) {
    case CheckMechanism::icmp:
        return "icmp";
    case CheckMechanism::tcp_fallback:
        return "tcp-fallback";
    case CheckMechanism::tcp_refused:
        return "tcp-refused";
    case CheckMechanism::checked_no_reply:
        return "icmp+tcp-fallback";
    case CheckMechanism::unavailable:
        return "unavailable";
    }
    return "unavailable"; // unreachable; keeps -Wswitch happy across compilers
}

} // namespace yuzu::wol
