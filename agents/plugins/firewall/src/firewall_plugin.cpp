/**
 * firewall_plugin.cpp — Firewall status and rules plugin for Yuzu
 *
 * Actions:
 *   "state" — Return firewall state per profile/backend.
 *   "rules" — List firewall rules (summary).
 *   "quarantine", "release", "quarantine_status", "quarantine_allow" —
 *       device containment (PRQ.1): a Windows Firewall rule group + per-profile
 *       default-block, an own nftables table (iptables fallback) on Linux, a pf
 *       sub-anchor with an enable token on macOS (docs/quarantine-macos-pf-
 *       anchor-design.md). All decisions live in firewall_quarantine_parsers.hpp;
 *       the shell at the end of this file only wires the OS mechanisms to it.
 *
 * Output is pipe-delimited via write_output().
 *
 * Acquisition ladder (ADR-3002):
 *   Windows — rung 1, native INetFwPolicy2 COM (agents/shared/win_com.hpp),
 *             replacing both former `netsh` shell-outs.
 *   macOS   — rung 2, run_bounded_subprocess argv (socketfilterfw/pfctl) —
 *             same 3 sites as before, only the acquisition mechanism
 *             changed (popen -> bounded runner); the pure parsers in
 *             firewall_parsers.hpp are untouched.
 *   Linux   — backend probe order: firewalld -> nftables -> ufw -> iptables
 *             -> none.
 *               firewalld: rung 1, bounded sd-bus (org.fedoraproject.
 *                 FirewallD1), mirroring guardian_state_reader.cpp's
 *                 timeout-budget-re-arm pattern across sequential calls.
 *               nftables:  rung 1, bounded NETLINK_NETFILTER (no libnftnl/
 *                 libmnl dependency — neither is a vcpkg dependency today,
 *                 see PR notes). Read-only table/chain/rule enumeration via
 *                 NLM_F_DUMP requests, deadline-bounded like every other
 *                 backend probe here; a mutating nftables leg is explicitly
 *                 out of scope (ADR-3002 Decision 8). Pure decode lives in
 *                 firewall_parsers.hpp's nft_raw namespace / parse_nft_*.
 *               ufw / iptables: rung 2, run_bounded_subprocess argv, each
 *                 backend now emitting STRUCTURED rows via its own pure
 *                 parser (parse_ufw_rules / parse_iptables_save) — replacing
 *                 the old single opaque `firewall-cmd --list-all || ufw
 *                 status numbered || iptables -L -n --line-numbers` shell
 *                 chain and its `rule|<raw line>` passthrough.
 */

#include <yuzu/plugin.hpp>

#include "firewall_parsers.hpp"
#include "firewall_quarantine_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <spdlog/spdlog.h> // one line per containment state change / non-OK outcome (SRE)

#include <quarantine_serialization.hpp> // MutationGate; PRQ.2 relocates it to agents/shared

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <format>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <netfw.h>
#include <oleauto.h> // SysAllocString / SysFreeString / VARIANT

#include <win_com.hpp> // ComInit / ComPtr<T> / BStr (PR3.3-a shared header)
#include <win_str.hpp> // yuzu::win::from_wide
#endif

#include <icmp_probe.hpp> // tri-state TCP connect probe for verify-after-apply
#ifndef _WIN32
#include <sudo_argv.hpp> // canonical `sudo -n --` wrapper for the Linux/macOS legs
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/time.h>
#endif

#if defined(__linux__)
#include <sys/prctl.h> // PR_GET_NO_NEW_PRIVS: the packaged unit's NoNewPrivileges

#include <yuzu/agent/scoped_fd.hpp>

#include <cerrno>
#include <cstddef>
#include <expected>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace {

using yuzu::agent::run_bounded_subprocess;
using yuzu::agent::SubprocessOptions;

constexpr std::chrono::milliseconds kAcqDeadline{5000};

// BR-05: this used to be a second, byte-identical implementation of
// yuzu::firewall::sanitize_field (hoisted into firewall_parsers.hpp by P1,
// originally to serve only the two nft format_nft_* row formatters) --
// every Windows/firewalld/ufw/iptables call site below kept using this
// local copy instead, leaving it outside the new sanitizer unit test's
// coverage. The header include above is unconditional across every
// platform this file builds for, so the hoisted symbol is reachable here
// with no #ifdef needed.
using yuzu::firewall::sanitize_field;
using yuzu::firewall::subprocess_complete;

#ifdef _WIN32

using yuzu::shared::win::ComInit;
using yuzu::shared::win::ComPtr;

/// Acquire INetFwPolicy2 into an owning ComPtr (only inside a live ComInit).
/// Mirrored from rdp_control_plugin.cpp's get_fw_policy() — same
/// CoCreateInstance(__uuidof(NetFwPolicy2), ...) shape, no hnetcfg.lib.
HRESULT get_fw_policy(ComPtr<INetFwPolicy2>& policy) {
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwPolicy2), reinterpret_cast<void**>(policy.put()));
}

// CRITICAL (mirrored from rdp_control_plugin.cpp's classify_fw_hr and its
// governing comment): INetFwPolicy2::get_FirewallEnabled and the
// INetFwRules enumeration both follow the same Windows Firewall COM
// contract — S_FALSE PASSES SUCCEEDED() but means "not found" / "no more
// items", NOT success. A naive `if (SUCCEEDED(hr))` here would report an
// unreadable profile as enabled (a fail-safe inversion identical to H2 in
// rdp_control_plugin.cpp). S_OK alone is success; S_FALSE is "not found"
// (report unknown, never a false enabled/disabled); anything else is an
// error. The regression test for this exact bug class lives in
// test_firewall_parsers.cpp / test_new_plugins.cpp's mirrored copy.
enum class FwHrResult { Ok, NotFound, Error };
FwHrResult classify_fw_hr(HRESULT hr) {
    if (hr == S_OK)
        return FwHrResult::Ok;
    if (hr == S_FALSE)
        return FwHrResult::NotFound;
    return FwHrResult::Error;
}

const char* profile_name(NET_FW_PROFILE_TYPE2 p) {
    switch (p) {
    case NET_FW_PROFILE2_DOMAIN:
        return "Domain";
    case NET_FW_PROFILE2_PRIVATE:
        return "Private";
    case NET_FW_PROFILE2_PUBLIC:
        return "Public";
    default:
        return "Unknown";
    }
}

void do_state_windows(yuzu::CommandContext& ctx) {
    ComInit com;
    if (!com.ok()) {
        ctx.write_output("error|com_init");
        return;
    }
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|policy2_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    static constexpr NET_FW_PROFILE_TYPE2 kProfiles[] = {
        NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    for (auto profile : kProfiles) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        HRESULT phr = policy->get_FirewallEnabled(profile, &enabled);
        switch (classify_fw_hr(phr)) {
        case FwHrResult::Ok:
            ctx.write_output(std::format("profile|{}|{}", profile_name(profile),
                                         enabled != VARIANT_FALSE ? "enabled" : "disabled"));
            break;
        case FwHrResult::NotFound:
            // Unreadable — report unknown, never a false-safe "disabled"
            // (same fail-safe direction as the CRITICAL note above).
            ctx.write_output(std::format("profile|{}|unknown", profile_name(profile)));
            break;
        case FwHrResult::Error:
            ctx.write_output(std::format("profile|{}|error:0x{:08x}", profile_name(profile),
                                         static_cast<uint32_t>(phr)));
            break;
        }
    }

    // Rule count: INetFwRules::get_Count is locale-independent (unlike
    // shelling out to `netsh` or PowerShell and parsing localized text) and
    // reuses the ComInit already live above. Same S_FALSE-is-not-success
    // contract as classify_fw_hr -- a NotFound or Error classification both
    // read as failure here, per the acceptance contract.
    ComPtr<INetFwRules> rules_for_count;
    HRESULT rules_hr = policy->get_Rules(rules_for_count.put());
    if (SUCCEEDED(rules_hr) && rules_for_count) {
        LONG rule_count = 0;
        HRESULT count_hr = rules_for_count->get_Count(&rule_count);
        if (classify_fw_hr(count_hr) == FwHrResult::Ok) {
            ctx.write_output(std::format("ruleset|{}", static_cast<long long>(rule_count)));
        } else {
            ctx.write_output(
                std::format("error|rules_count:0x{:08x}", static_cast<uint32_t>(count_hr)));
        }
    } else {
        ctx.write_output(
            std::format("error|rules_count:0x{:08x}", static_cast<uint32_t>(rules_hr)));
    }
}

void do_rules_windows(yuzu::CommandContext& ctx) {
    ComInit com;
    if (!com.ok()) {
        ctx.write_output("error|com_init");
        return;
    }
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|policy2_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<INetFwRules> rules;
    hr = policy->get_Rules(rules.put());
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|rules_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<IUnknown> enum_unk;
    hr = rules->get__NewEnum(enum_unk.put());
    if (FAILED(hr) || !enum_unk) {
        ctx.write_output(std::format("error|enum_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<IEnumVARIANT> enum_var;
    hr = enum_unk->QueryInterface(__uuidof(IEnumVARIANT),
                                  reinterpret_cast<void**>(enum_var.put()));
    if (FAILED(hr) || !enum_var) {
        ctx.write_output(std::format("error|enum_variant:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }

    int count = 0;
    bool truncated = false;
    bool enum_failed = false;
    for (;;) {
        VARIANT v;
        VariantInit(&v);
        ULONG fetched = 0;
        // Same S_FALSE-is-not-success contract as classify_fw_hr above:
        // IEnumVARIANT::Next returns S_FALSE (SUCCEEDED, fetched==0) at
        // end-of-enumeration — checked via `fetched == 0`, never a bare
        // SUCCEEDED(hr), so end-of-list is never mistaken for "another rule".
        //
        // FAILED(hr) mid-loop is a DIFFERENT exit than clean end-of-
        // enumeration -- distinguished so the trailing ruleset| row below
        // never presents a partial `count` as though it were the whole
        // list (governance Gate 4 consistency-auditor finding: the two
        // cases used to share one break with no signal, and this diff's
        // new ruleset| line is what first made that ambiguity user-
        // visible and authoritative-looking).
        hr = enum_var->Next(1, &v, &fetched);
        if (FAILED(hr)) {
            VariantClear(&v);
            enum_failed = true;
            break;
        }
        if (fetched == 0) {
            VariantClear(&v);
            break;
        }
        // The cap check happens AFTER a successful fetch, not before: at
        // exactly 100 already-emitted rules, this proves a genuine 101st
        // rule exists (Next() actually returned one) before declaring
        // truncation — checking `count >= 100` up front (the original
        // shape) set truncated|true on a host with EXACTLY 100 rules,
        // none of them actually cut off, because it never called Next()
        // again to find out (governance Gate 4 happy-path finding).
        if (count >= 100) {
            VariantClear(&v);
            truncated = true;
            break;
        }
        if (v.vt != VT_DISPATCH || !v.pdispVal) {
            VariantClear(&v);
            continue;
        }
        ComPtr<INetFwRule> rule;
        HRESULT qhr = v.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                                 reinterpret_cast<void**>(rule.put()));
        VariantClear(&v);
        if (FAILED(qhr) || !rule)
            continue;

        // RAII over the raw BSTR out-param: the shared win_com.hpp BStr type
        // only constructs by ALLOCATING a new BSTR, so it can't adopt one
        // already returned by a COM out-param without an ambiguous overload
        // (BSTR is literally wchar_t*). A manual SysFreeString here would
        // leak on any exception thrown between receipt and free (e.g.
        // std::wstring's allocation) -- unconditional release in the
        // destructor closes that gap.
        struct RuleNameBstr {
            BSTR b = nullptr;
            ~RuleNameBstr() {
                if (b)
                    SysFreeString(b);
            }
            // A user-declared (even deleted) copy constructor suppresses
            // the implicitly-declared default constructor entirely --
            // without this, `} name_bstr;` below fails to compile.
            // Confirmed with a standalone repro (see BusGuard's identical
            // comment further down this file).
            RuleNameBstr() = default;
            RuleNameBstr(const RuleNameBstr&) = delete;
            RuleNameBstr& operator=(const RuleNameBstr&) = delete;
        } name_bstr;
        rule->get_Name(&name_bstr.b);
        std::wstring name_w = name_bstr.b ? name_bstr.b : L"";

        VARIANT_BOOL enabled = VARIANT_FALSE;
        rule->get_Enabled(&enabled);

        // Direction/Action are read as explicitly failure-checked (rather
        // than relying on a sentinel initial value that "happens" not to
        // collide with a real enumerator) so an unreadable field reports
        // honestly as unknown regardless of the underlying enum's numbering.
        NET_FW_RULE_DIRECTION dir{};
        HRESULT dir_hr = rule->get_Direction(&dir);
        std::string dir_s = FAILED(dir_hr)          ? "unknown"
                            : (dir == NET_FW_RULE_DIR_IN)  ? "in"
                            : (dir == NET_FW_RULE_DIR_OUT) ? "out"
                                                            : "unknown";

        NET_FW_ACTION action{};
        HRESULT action_hr = rule->get_Action(&action);
        std::string action_s = FAILED(action_hr)            ? "unknown"
                               : (action == NET_FW_ACTION_ALLOW) ? "allow"
                               : (action == NET_FW_ACTION_BLOCK) ? "block"
                                                                  : "unknown";

        long profiles_mask = 0;
        rule->get_Profiles(&profiles_mask);

        std::string name = sanitize_field(yuzu::win::from_wide(name_w.c_str()));

        ctx.write_output(std::format("rule|{}|{}|{}|{}|{}", name,
                                     enabled != VARIANT_FALSE ? "enabled" : "disabled", dir_s,
                                     action_s, profiles_mask));
        ++count;
    }
    // A mid-enumeration COM failure means `count` is a PARTIAL tally, not
    // the ruleset size -- report it as such (error| + ruleset|unknown)
    // rather than presenting a truncated count as though it were complete.
    // Every `rule|` row already emitted above stayed emitted; this only
    // changes what the trailing summary claims about them.
    if (enum_failed) {
        ctx.write_output(std::format("error|enum_next:0x{:08x}", static_cast<uint32_t>(hr)));
        ctx.write_output("ruleset|unknown");
        return;
    }
    ctx.write_output(std::format("ruleset|{}", count));
    if (truncated)
        ctx.write_output("truncated|true");
}

#elif defined(__APPLE__)

void do_state_macos(yuzu::CommandContext& ctx) {
    // Primary: the macOS Application Firewall — the firewall a Mac admin
    // means. pf is off by default and unrelated, so reporting it as THE
    // state gave false confidence. Unprivileged read.
    auto alf_res = run_bounded_subprocess(
        {"/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"},
        SubprocessOptions{.deadline = kAcqDeadline});
    auto alf = yuzu::firewall::parse_alf_global_state(alf_res.output);
    ctx.write_output("backend|appfirewall");
    ctx.write_output(std::format("state|{}", yuzu::firewall::to_string(alf.state)));
    if (alf.block_all) {
        ctx.write_output("mode|block_all");
    }
    // Secondary: the pf packet filter (reading /dev/pf needs root;
    // unreadable reports as unknown, never a false-safe value). Absolute
    // path per the quarantine plugin's kPfctl discipline.
    auto pf_res =
        run_bounded_subprocess({"/sbin/pfctl", "-s", "info"}, SubprocessOptions{.deadline = kAcqDeadline});
    ctx.write_output(std::format(
        "pf|{}", yuzu::firewall::to_string(yuzu::firewall::parse_pf_status(pf_res.output))));

    // Anchors: emit anchor|<name> rows only from a cleanly-completed read --
    // honour tool_ran/exit_code/timed_out/output_truncated so a refused or
    // partial `pfctl -s Anchors` read yields no anchor rows rather than
    // presenting a partial anchor set as the whole (review R7).
    auto anchors_res = run_bounded_subprocess({"/sbin/pfctl", "-s", "Anchors"},
                                              SubprocessOptions{.deadline = kAcqDeadline});
    if (anchors_res.tool_ran && anchors_res.exit_code == 0 && !anchors_res.timed_out &&
        !anchors_res.output_truncated) {
        for (const auto& anchor : yuzu::firewall::parse_pf_anchors(anchors_res.output)) {
            ctx.write_output(std::format("anchor|{}", sanitize_field(anchor)));
        }
    }

    // Ruleset count: emit the numeric count only under the same
    // completeness gate on `pfctl -s rules` -- count_pf_rules returns 0 for
    // empty input, which a refused/partial read must not be confused with a
    // genuine 0-rule pf (see count_pf_rules's own comment). A failed spawn
    // (tool_ran==false) or non-clean completion reads unknown, never empty.
    auto rules_res = run_bounded_subprocess({"/sbin/pfctl", "-s", "rules"},
                                            SubprocessOptions{.deadline = kAcqDeadline});
    if (rules_res.tool_ran && rules_res.exit_code == 0 && !rules_res.timed_out &&
        !rules_res.output_truncated) {
        ctx.write_output(
            std::format("ruleset|{}", yuzu::firewall::count_pf_rules(rules_res.output)));
    } else {
        ctx.write_output("ruleset|unknown");
    }
}

void do_rules_macos(yuzu::CommandContext& ctx) {
    // App rows: socketfilterfw --listapps is unprivileged; trustworthy only
    // when the read completed cleanly, otherwise emit no app rows rather
    // than presenting a partial app set as the whole (review R7).
    // AlfDecision::unknown is emitted as the literal `unknown` third field,
    // never dropped or coerced (review R6).
    auto listapps_res = run_bounded_subprocess(
        {"/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"},
        SubprocessOptions{.deadline = kAcqDeadline});
    if (listapps_res.tool_ran && listapps_res.exit_code == 0 && !listapps_res.timed_out &&
        !listapps_res.output_truncated) {
        for (const auto& app : yuzu::firewall::parse_alf_listapps(listapps_res.output)) {
            const char* decision = app.decision == yuzu::firewall::AlfDecision::allow ? "allow"
                                   : app.decision == yuzu::firewall::AlfDecision::block ? "block"
                                                                                        : "unknown";
            ctx.write_output(std::format("app|{}|{}", sanitize_field(app.path), decision));
        }
    }

    // rule| rows and the trailing ruleset| count share ONE completeness gate
    // -- a truncated or timed-out pfctl read must not publish whatever
    // partial lines it captured as though they were the whole rule set,
    // with only the trailing sentinel hinting otherwise (adversarial-review
    // r1, C1: rows were previously written unconditionally, ahead of the
    // gate that only protected ruleset|). Matches every other completeness-
    // gated emission in this function (app|, anchor|) and the honest-status
    // invariant documented in README.md's "How it works".
    auto res = run_bounded_subprocess({"/sbin/pfctl", "-s", "rules"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (res.tool_ran && res.exit_code == 0 && !res.timed_out && !res.output_truncated) {
        std::istringstream iss(res.output);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) {
                ctx.write_output(std::format("rule|{}", sanitize_field(line)));
            }
        }
    }

    auto anchors_res = run_bounded_subprocess({"/sbin/pfctl", "-s", "Anchors"},
                                              SubprocessOptions{.deadline = kAcqDeadline});
    if (anchors_res.tool_ran && anchors_res.exit_code == 0 && !anchors_res.timed_out &&
        !anchors_res.output_truncated) {
        for (const auto& anchor : yuzu::firewall::parse_pf_anchors(anchors_res.output)) {
            ctx.write_output(std::format("anchor|{}", sanitize_field(anchor)));
        }
    }

    // Trailing ruleset|<n>-or-unknown under the same completeness gate,
    // reusing the `pfctl -s rules` result already captured above.
    if (res.tool_ran && res.exit_code == 0 && !res.timed_out && !res.output_truncated) {
        ctx.write_output(std::format("ruleset|{}", yuzu::firewall::count_pf_rules(res.output)));
    } else {
        ctx.write_output("ruleset|unknown");
    }
}

#elif defined(__linux__)

#if defined(YUZU_HAVE_LIBSYSTEMD)

// ── firewalld (rung 1, bounded sd-bus) ──────────────────────────────────
//
// RAII guards mirrored from guardian_state_reader.cpp's read_service_blocking
// (same sd_bus_error/sd_bus_message/bus ownership convention).
struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus)
            sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    // A user-declared (even deleted) copy constructor suppresses the
    // implicitly-declared default constructor entirely -- without this,
    // `SdBusErrorGuard err;` below fails to compile ("no default
    // constructor"), not merely "uses the deleted one". Confirmed with a
    // standalone repro on this Mac (Linux-only code, never actually
    // compiled anywhere else in this branch's history).
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m)
            sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};

// Total sd-bus budget for the whole read, split across the sequential calls
// below (getActiveZones, then getServices/getPorts per active zone) — same
// re-arm-with-the-remainder shape as guardian_state_reader.cpp's
// kSdBusTotalBudgetUs, so a wedged firewalld cannot hold this call for an
// unbounded multiple of the per-method timeout.
constexpr std::uint64_t kSdBusTotalBudgetUs = 5'000'000; // 5s

constexpr const char* kFirewalldDest = "org.fedoraproject.FirewallD1";
constexpr const char* kFirewalldPath = "/org/fedoraproject/FirewallD1";
constexpr const char* kFirewalldZoneIface = "org.fedoraproject.FirewallD1.zone";

struct FirewalldZoneInfo {
    std::string name;
    std::vector<std::string> services;
};
struct FirewalldQueryResult {
    bool reachable = false; // false -> caller falls through to the next backend
    std::vector<FirewalldZoneInfo> zones;
    // false whenever the per-zone getServices loop below either hit the
    // remaining-budget==0 break (some zones never queried at all) or saw any
    // individual getServices call return rc<0 (that zone's services are a
    // silent undercount, not a genuine zero) -- a ruleset|<n> count is only
    // ever emitted from a `true` here (#3462-... completeness-gated count).
    // Defaults true: the want_rules=false caller never reaches the loop that
    // would set it false, and has nothing to count anyway.
    bool services_complete = true;
};

// NOTE: getActiveZones()'s "a{sa{sas}}" signature (zone -> {"interfaces":
// [...], "sources": [...]}) and getServices()'s "as" signature are taken
// from firewalld's published D-Bus API and exercised here via the same
// enter_container/exit_container idiom as guardian_state_reader.cpp — this
// leg has not been verified against a live firewalld (no D-Bus broker
// available in this sandbox; see the PR notes). A signature mismatch fails
// the corresponding enter_container/read call (rc < 0), which this code
// treats as "that field unavailable" rather than a crash or a fabricated
// row — so a wrong guess degrades honestly instead of corrupting output.
// getPorts() is deliberately NOT queried here: its per-element termination
// semantics under a manually-entered outer array could not be verified with
// the same confidence (no live firewalld to test against) and a
// speculative implementation risks a subtly wrong read loop rather than an
// honestly-empty one — service enumeration alone is the higher-confidence
// subset. Tracked as a gap for whoever next touches this leg with access to
// a live firewalld.
FirewalldQueryResult query_firewalld(bool want_rules) {
    FirewalldQueryResult r;
    BusGuard bus;
    if (sd_bus_open_system(&bus.bus) < 0 || !bus.bus)
        return r; // D-Bus unreachable -> honest fall-through, never fabricate

    const auto t_start = std::chrono::steady_clock::now();
    sd_bus_set_method_call_timeout(bus.bus, kSdBusTotalBudgetUs);

    auto remaining_budget = [&]() -> std::uint64_t {
        const auto elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_start)
                .count());
        return elapsed_us >= kSdBusTotalBudgetUs ? 0 : kSdBusTotalBudgetUs - elapsed_us;
    };

    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    int rc = sd_bus_call_method(bus.bus, kFirewalldDest, kFirewalldPath, kFirewalldZoneIface,
                                "getActiveZones", &err.err, &reply.m, "");
    if (rc < 0)
        return r; // firewalld not running / not reachable -> fall through
    r.reachable = true;
    if (!want_rules)
        return r;

    if (sd_bus_message_enter_container(reply.m, 'a', "{sa{sas}}") < 0) {
        // Reachable but the active-zones reply didn't decode -- an empty
        // r.zones here is NOT "zero zones", it's "we don't know". Mark
        // incomplete so the caller reports ruleset|unknown, never a
        // fabricated ruleset|0 (BR-01: this early return used to leave the
        // default services_complete=true in place).
        r.services_complete = false;
        return r;
    }
    while (sd_bus_message_enter_container(reply.m, 'e', "sa{sas}") > 0) {
        FirewalldZoneInfo zone;
        const char* zone_name = nullptr;
        sd_bus_message_read(reply.m, "s", &zone_name);
        if (zone_name)
            zone.name = zone_name;
        // interfaces/sources sub-dict — not consumed today; step over it so
        // the message cursor lands correctly for the next zone entry.
        if (sd_bus_message_enter_container(reply.m, 'a', "{sas}") >= 0) {
            while (sd_bus_message_enter_container(reply.m, 'e', "sas") > 0) {
                sd_bus_message_skip(reply.m, "s");
                sd_bus_message_skip(reply.m, "as");
                sd_bus_message_exit_container(reply.m);
            }
            sd_bus_message_exit_container(reply.m);
        }
        sd_bus_message_exit_container(reply.m); // exit this zone's dict-entry
        if (!zone.name.empty())
            r.zones.push_back(std::move(zone));
    }
    sd_bus_message_exit_container(reply.m);

    // Per-zone getServices, each re-arming against the remaining budget —
    // bail out (report what we have so far) once it's exhausted. Either exit
    // here (budget exhausted mid-loop) marks the result incomplete: some
    // zones' services were never queried at all, so a total computed from
    // `r.zones` would be a silent undercount, not a genuine "no services".
    for (auto& zone : r.zones) {
        const auto budget = remaining_budget();
        if (budget == 0) {
            r.services_complete = false;
            break;
        }
        sd_bus_set_method_call_timeout(bus.bus, budget);

        SdBusErrorGuard svc_err;
        SdBusMessageGuard svc_reply;
        const int svc_rc = sd_bus_call_method(bus.bus, kFirewalldDest, kFirewalldPath,
                                              kFirewalldZoneIface, "getServices", &svc_err.err,
                                              &svc_reply.m, "s", zone.name.c_str());
        if (svc_rc < 0) {
            // This zone's services could not be read -- the eventual total
            // is an undercount, not a genuine zero for this zone. Keep
            // trying the remaining zones (best effort) but the OVERALL
            // result is no longer trustworthy as a complete count.
            r.services_complete = false;
        }
        if (svc_rc >= 0) {
            // RAII over the raw strv: a manual free() after
            // zone.services.emplace_back() (which can throw std::bad_alloc)
            // leaks the array and its remaining strings on exception --
            // the same shape as the BSTR leak fixed elsewhere in this file.
            // Unconditional release in the destructor closes that gap.
            struct StrvGuard {
                char** v = nullptr;
                ~StrvGuard() {
                    if (v) {
                        for (char** p = v; *p; ++p)
                            free(*p);
                        free(v);
                    }
                }
                // A user-declared (even deleted) copy constructor
                // suppresses the implicitly-declared default constructor
                // entirely -- without this, `} strv;` below fails to
                // compile. Confirmed with a standalone repro.
                StrvGuard() = default;
                StrvGuard(const StrvGuard&) = delete;
                StrvGuard& operator=(const StrvGuard&) = delete;
            } strv;
            if (sd_bus_message_read_strv(svc_reply.m, &strv.v) >= 0 && strv.v) {
                for (char** p = strv.v; *p; ++p)
                    zone.services.emplace_back(*p);
            } else {
                // The call succeeded but the reply's string-vector didn't
                // decode -- this zone silently contributes zero services to
                // the total without this flag, which is an undercount, not
                // a genuine empty zone (BR-01, mirrors the svc_rc<0 case
                // above).
                r.services_complete = false;
            }
        }
    }
    return r;
}

bool try_firewalld_state(yuzu::CommandContext& ctx) {
    // want_rules=true (not the old false): the state action's ruleset|<n>
    // row needs services actually enumerated -- want_rules=false returns
    // zero services unconditionally, which would misreport as ruleset|0
    // rather than the honest ruleset|unknown/real count this row promises.
    auto q = query_firewalld(/*want_rules=*/true);
    if (!q.reachable)
        return false;
    ctx.write_output("backend|firewalld");
    ctx.write_output("state|running");
    if (q.services_complete) {
        std::size_t total = 0;
        for (const auto& zone : q.zones)
            total += zone.services.size();
        ctx.write_output(std::format("ruleset|{}", total));
    } else {
        ctx.write_output("ruleset|unknown");
    }
    return true;
}

bool try_firewalld_rules(yuzu::CommandContext& ctx) {
    auto q = query_firewalld(/*want_rules=*/true);
    if (!q.reachable)
        return false;
    ctx.write_output("backend|firewalld");
    std::size_t total = 0;
    for (const auto& zone : q.zones) {
        for (const auto& svc : zone.services) {
            ctx.write_output(
                std::format("rule|firewalld|{}|service|{}", sanitize_field(zone.name), svc));
            ++total;
        }
    }
    ctx.write_output(q.services_complete ? std::format("ruleset|{}", total)
                                         : std::string("ruleset|unknown"));
    return true;
}

#else // !YUZU_HAVE_LIBSYSTEMD

bool try_firewalld_state(yuzu::CommandContext&) { return false; }
bool try_firewalld_rules(yuzu::CommandContext&) { return false; }

#endif // YUZU_HAVE_LIBSYSTEMD

// ── nftables (rung 1, netlink) ───────────────────────────────────────────
//
// Read-only ruleset enumeration over NETLINK_NETFILTER/NFNL_SUBSYS_NFTABLES.
// No libnftnl/libmnl dependency — neither is a vcpkg dependency today (see
// PR notes) — just the raw socket plus the documented, VERSIONED UAPI wire
// format (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nf_tables.h). Socket-level types (AF_NETLINK,
// NETLINK_NETFILTER, sockaddr_nl) come from the REAL system headers here —
// unlike the message-body wire structs, which firewall_parsers.hpp
// transcribes by hand so the pure decode stays compilable/testable on every
// host, the socket API itself must match the running kernel's ABI exactly,
// so pulling it from the system's own headers is the safer choice.
//
// Pure decode (nft_raw namespace, parse_nft_table/chain/rules) is the
// tested core; everything below is the thin, impure shell — one bounded-
// deadline NLM_F_DUMP round-trip per query, sent on a fresh socket per
// try_nftables_state/rules() call and fully drained (to NLMSG_DONE) before
// the next request goes out on the same fd, so there is no cross-request
// interleaving to guard against with a sequence-number check.
//
// Read-only by design for this status/listing plugin: only GET* dumps are
// ever sent. A mutating leg would need a separately-approved brokered-
// elevation design and is out of scope here — ADR-3002 Decision 8 governs
// the privileged-execution boundary that design would have to satisfy, not
// a mandate that this plugin stay read-only.
//
// Protocol assumption, now confirmed rather than merely asserted: a
// GETTABLE/GETCHAIN/GETRULE dump with family=NFPROTO_UNSPEC and no further
// selector attributes enumerates every table/chain/rule across every
// address family in one pass, mirroring how `nft list ruleset` walks the
// whole namespace — verified 2026-08-23 against a real kernel (see
// docs/agent-privilege-model.md): correctly returned every ip/ip6/inet
// table on the test host in one pass each, including a manually-added
// inet table alongside Docker's own ip/ip6 chains.

constexpr std::uint16_t kNlmFRequest = 0x1;
constexpr std::uint16_t kNlmFDump = 0x300; // NLM_F_ROOT | NLM_F_MATCH

namespace nft = yuzu::firewall::nft_raw;

// ── Linux-only UAPI cross-check (#3464-1) ───────────────────────────────
//
// firewall_parsers.hpp's nft_raw namespace hand-transcribes the netlink/
// nftables wire structs and constants so the pure decode stays compilable
// and unit-tested on every host, including ones with no Linux UAPI headers
// at all. That transcription is verified HERE instead -- the one place this
// file already requires the real kernel headers -- never in the header
// itself, which must not gain a Linux-only dependency. A failure below means
// the transcription has drifted from the UAPI on THIS build host.
static_assert(sizeof(nft::NlMsgHdr) == sizeof(::nlmsghdr));
static_assert(offsetof(nft::NlMsgHdr, len) == offsetof(::nlmsghdr, nlmsg_len));
static_assert(offsetof(nft::NlMsgHdr, type) == offsetof(::nlmsghdr, nlmsg_type));
static_assert(offsetof(nft::NlMsgHdr, flags) == offsetof(::nlmsghdr, nlmsg_flags));
static_assert(offsetof(nft::NlMsgHdr, seq) == offsetof(::nlmsghdr, nlmsg_seq));
static_assert(offsetof(nft::NlMsgHdr, pid) == offsetof(::nlmsghdr, nlmsg_pid));

static_assert(sizeof(nft::NfGenMsg) == sizeof(::nfgenmsg));
static_assert(offsetof(nft::NfGenMsg, family) == offsetof(::nfgenmsg, nfgen_family));
static_assert(offsetof(nft::NfGenMsg, version) == offsetof(::nfgenmsg, version));
static_assert(offsetof(nft::NfGenMsg, res_id) == offsetof(::nfgenmsg, res_id));

static_assert(sizeof(nft::NlAttr) == sizeof(::nlattr));
static_assert(offsetof(nft::NlAttr, len) == offsetof(::nlattr, nla_len));
static_assert(offsetof(nft::NlAttr, type) == offsetof(::nlattr, nla_type));

// parse_nlmsgerr() decodes an NLMSG_ERROR payload as "the leading 4-byte
// signed error field" -- never accessing ::nlmsgerr directly, but valid only
// because the real struct puts `error` first (offset 0) with `msg`
// immediately after it (offset 4). Pins that implicit layout assumption.
static_assert(offsetof(::nlmsgerr, error) == 0);
static_assert(offsetof(::nlmsgerr, msg) == 4);

static_assert(nft::kNlaTypeMask == static_cast<std::uint16_t>(NLA_TYPE_MASK));
static_assert(nft::kNlaAlignTo == static_cast<std::size_t>(NLA_ALIGNTO));
static_assert(nft::kNlmsgError == static_cast<std::uint16_t>(NLMSG_ERROR));
static_assert(nft::kNlmsgDone == static_cast<std::uint16_t>(NLMSG_DONE));
static_assert(nft::kNlmFDumpIntr == static_cast<std::uint16_t>(NLM_F_DUMP_INTR));

static_assert(nft::kNfnlSubsysNftables == static_cast<std::uint8_t>(NFNL_SUBSYS_NFTABLES));
static_assert(nft::kNftMsgGettable == static_cast<std::uint16_t>(NFT_MSG_GETTABLE));
static_assert(nft::kNftMsgGetchain == static_cast<std::uint16_t>(NFT_MSG_GETCHAIN));
static_assert(nft::kNftMsgGetrule == static_cast<std::uint16_t>(NFT_MSG_GETRULE));
static_assert(nft::kNftMsgNewtable == static_cast<std::uint16_t>(NFT_MSG_NEWTABLE));
static_assert(nft::kNftMsgNewchain == static_cast<std::uint16_t>(NFT_MSG_NEWCHAIN));
static_assert(nft::kNftMsgNewrule == static_cast<std::uint16_t>(NFT_MSG_NEWRULE));

static_assert(nft::kNfprotoUnspec == static_cast<std::uint8_t>(NFPROTO_UNSPEC));
static_assert(nft::kNfprotoInet == static_cast<std::uint8_t>(NFPROTO_INET));
static_assert(nft::kNfprotoIpv4 == static_cast<std::uint8_t>(NFPROTO_IPV4));
static_assert(nft::kNfprotoArp == static_cast<std::uint8_t>(NFPROTO_ARP));
static_assert(nft::kNfprotoNetdev == static_cast<std::uint8_t>(NFPROTO_NETDEV));
static_assert(nft::kNfprotoBridge == static_cast<std::uint8_t>(NFPROTO_BRIDGE));
static_assert(nft::kNfprotoIpv6 == static_cast<std::uint8_t>(NFPROTO_IPV6));

static_assert(nft::kNftaTableName == static_cast<std::uint16_t>(NFTA_TABLE_NAME));
static_assert(nft::kNftaChainTable == static_cast<std::uint16_t>(NFTA_CHAIN_TABLE));
static_assert(nft::kNftaChainName == static_cast<std::uint16_t>(NFTA_CHAIN_NAME));
static_assert(nft::kNftaChainHook == static_cast<std::uint16_t>(NFTA_CHAIN_HOOK));
static_assert(nft::kNftaChainPolicy == static_cast<std::uint16_t>(NFTA_CHAIN_POLICY));
static_assert(nft::kNftaHookHooknum == static_cast<std::uint16_t>(NFTA_HOOK_HOOKNUM));
static_assert(nft::kNftaRuleTable == static_cast<std::uint16_t>(NFTA_RULE_TABLE));
static_assert(nft::kNftaRuleChain == static_cast<std::uint16_t>(NFTA_RULE_CHAIN));
static_assert(nft::kNftaRuleHandle == static_cast<std::uint16_t>(NFTA_RULE_HANDLE));

// Base-chain policy values are the generic netfilter verdicts (NF_DROP/
// NF_ACCEPT from <linux/netfilter.h>), not an nftables-specific enum.
static_assert(nft::kNftPolicyDrop == static_cast<std::uint32_t>(NF_DROP));
static_assert(nft::kNftPolicyAccept == static_cast<std::uint32_t>(NF_ACCEPT));

// The two request flags this file constructs by hand (above, :584-585) are
// transcribed constants too.
static_assert(kNlmFRequest == static_cast<std::uint16_t>(NLM_F_REQUEST));
static_assert(kNlmFDump == static_cast<std::uint16_t>(NLM_F_DUMP));

/// Remaining time until `deadline`, clamped to zero (never negative).
[[nodiscard]] std::chrono::milliseconds
remaining_ms(std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline)
        return std::chrono::milliseconds{0};
    return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
}

/// How an open_nft_socket() failure should be handled by the caller.
enum class OpenNftErrClass {
    fd_exhausted,      // EMFILE/ENFILE -- a system-wide condition worth surfacing
    unsupported,       // EPROTONOSUPPORT/EAFNOSUPPORT -- this kernel has no
                       // NETLINK_NETFILTER at all; not worth a diagnostic row
    permission_denied, // EPERM/EACCES -- socket()/bind() itself was refused
                       // (RestrictAddressFamilies=, seccomp, AppArmor). Distinct
                       // from `other`: this is diagnosable and actionable the
                       // same way the existing dump-level eperm token already is
                       // (governance gate6 sre finding, r2 -- previously fell
                       // into `other` and emitted no row at all, indistinguishable
                       // from "kernel genuinely has no nftables").
    other,
};

[[nodiscard]] OpenNftErrClass classify_open_errno(int err) noexcept {
    if (err == EMFILE || err == ENFILE)
        return OpenNftErrClass::fd_exhausted;
    if (err == EPROTONOSUPPORT || err == EAFNOSUPPORT)
        return OpenNftErrClass::unsupported;
    if (err == EPERM || err == EACCES)
        return OpenNftErrClass::permission_denied;
    return OpenNftErrClass::other;
}

/// Emits a diagnostic row for `sock_err` classes an operator can act on --
/// `fd_exhausted` and `permission_denied` -- shared by all three
/// open_nft_socket() call sites in run_nft_probe() so the check-and-emit
/// pair exists once (code-review finding: it was previously triplicated
/// with only the surrounding control flow differing). `unsupported`/`other`
/// stay silent: `unsupported` means the kernel genuinely has no
/// NETLINK_NETFILTER (not worth a row), and `other` has no known,
/// specifically-actionable cause yet.
void report_open_nft_diagnostic(yuzu::CommandContext& ctx, int sock_err) {
    switch (classify_open_errno(sock_err)) {
    case OpenNftErrClass::fd_exhausted:
        ctx.write_output("error|fd_exhausted");
        return;
    case OpenNftErrClass::permission_denied:
        ctx.write_output("error|nftables:socket:eperm");
        return;
    case OpenNftErrClass::unsupported:
    case OpenNftErrClass::other:
        return;
    }
}

/// Opens and binds a NETLINK_NETFILTER socket for one dump round-trip, with
/// SO_SNDTIMEO bounding the request send() to `send_budget` -- this socket
/// only ever sends one small fixed-size dump request, but an unbounded send()
/// could still stall the command-execution thread past this dump's own
/// deadline if the netlink layer were ever throttled/wedged. Returns the
/// errno on any failure (std::unexpected) rather than an empty ScopedFd, so
/// the caller can classify_open_errno() it (#3462-1, #3462-4) -- EPERM on
/// bind is not special-cased; every errno propagates identically.
[[nodiscard]] std::expected<yuzu::agent::ScopedFd, int>
open_nft_socket(std::chrono::milliseconds send_budget) {
    // Own the fd in a ScopedFd from creation, same discipline as
    // echo_netqual_nstat.cpp's nstat socket open: every early return below
    // closes it automatically via the destructor, so no call site here
    // needs its own raw ::close() -- including any future one added between
    // socket() and the bind check.
    yuzu::agent::ScopedFd sock(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER));
    if (!sock)
        return std::unexpected(errno);

    struct timeval tv {};
    if (send_budget.count() <= 0) {
        // 0/0 means "no timeout" (block forever) on Linux, the opposite of
        // what an already-exhausted budget should do -- use the smallest
        // nonzero bound instead so a send() here still fails fast.
        tv.tv_usec = 1;
    } else {
        tv.tv_sec = static_cast<decltype(tv.tv_sec)>(send_budget.count() / 1000);
        tv.tv_usec = static_cast<decltype(tv.tv_usec)>((send_budget.count() % 1000) * 1000);
    }
    // Checked: this call installs the ONLY thing bounding the send() this
    // socket will do (the doc comment above's whole guarantee rests on it).
    // An unchecked failure here would silently restore the default
    // (blocking-forever) send timeout with nothing downstream able to tell
    // the difference -- exactly the "bounded, never blocks past deadline"
    // contract this function exists to uphold (review finding, both
    // Standards and Functional axes).
    if (::setsockopt(sock.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        return std::unexpected(errno);

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    if (::bind(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        return std::unexpected(errno);
    return sock;
}

constexpr std::size_t kNftRecvBufSize = 64 * 1024;

/// One bounded NLM_F_DUMP request/response round-trip for `msg_type`
/// (NFT_MSG_GETTABLE/GETCHAIN/GETRULE). Accumulates raw reply bytes into
/// `out`. PARTIALLY modeled on network_config_plugin.cpp's fetch_link_dump
/// (grounding-corrected: that function checks only rsa.nl_pid!=0, with no
/// msg_namelen/nl_family check and no size-budget check at all -- only the
/// nl_pid check and the foreign-before-truncation ordering are shared
/// precedent; the namelen/family sub-check and the oversized step are new).
[[nodiscard]] yuzu::firewall::NftDumpResult
nft_dump(int fd, std::uint16_t msg_type, std::vector<std::byte>& out,
         std::chrono::steady_clock::time_point deadline) {
    using yuzu::firewall::NftDumpResult;
    using yuzu::firewall::NftDumpStatus;

    alignas(4) unsigned char req[sizeof(nft::NlMsgHdr) + sizeof(nft::NfGenMsg)];
    nft::NlMsgHdr h{};
    h.len = sizeof(req);
    h.type = nft::nft_msg_type(msg_type);
    h.flags = kNlmFRequest | kNlmFDump;
    h.seq = 1;
    h.pid = 0;
    nft::NfGenMsg g{};
    g.family = nft::kNfprotoUnspec;
    g.version = 0;
    g.res_id = 0;
    std::memcpy(req, &h, sizeof(h));
    std::memcpy(req + sizeof(h), &g, sizeof(g));

    // Same bounded-deadline contract as the poll loop below: when this is the
    // second or third dump on a shared per-call deadline, an earlier dump can
    // already have consumed the whole budget -- sending a request whose
    // reply has no chance of being read before the loop's own deadline check
    // triggers is wasted kernel-side work for no benefit.
    if (std::chrono::steady_clock::now() >= deadline)
        return {NftDumpStatus::timeout, 0};

    // Bounded by `deadline`, not just by errno: an unbounded EINTR retry
    // here would let a signal storm spin past the whole budget before the
    // poll loop below ever gets a chance to time it out (governance gate3
    // cpp-safety / gate6 sre finding, r1 -- converged, same as the recvmsg
    // retry just below).
    ssize_t sent;
    do {
        sent = ::send(fd, req, sizeof(req), 0);
    } while (sent < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline);
    if (sent != static_cast<ssize_t>(sizeof(req))) {
        // The retry loop above can exit two ways: a genuine send() failure
        // (any errno other than EINTR), or the deadline elapsing while still
        // getting EINTR -- the latter is a timeout, not an I/O error, and
        // reporting it as the generic io_error default previously collapsed
        // the distinction (governance gate3 cpp-safety finding, r2).
        if (sent < 0 && errno == EINTR)
            return {NftDumpStatus::timeout, 0};
        return {}; // io_error (NftDumpResult's default status)
    }

    std::vector<std::byte> recv_buf(kNftRecvBufSize);
    int foreign_datagrams = 0;
    std::size_t parsed_off = 0; // how much of `out` earlier iterations already walked

    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return {NftDumpStatus::timeout, 0};
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        const int pr = ::poll(&pfd, 1, static_cast<int>(remaining));
        if (pr == 0)
            return {NftDumpStatus::timeout, 0};
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return {}; // io_error
        }

        sockaddr_nl rsa{};
        iovec riov{recv_buf.data(), recv_buf.size()};
        msghdr rm{};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            // MSG_TRUNC is read from msg_flags below, never passed as a flag
            // here (C2's other, non-negotiable half of the contract).
            // Bounded by `deadline`, same reasoning as the send retry above.
            n = ::recvmsg(fd, &rm, 0);
        } while (n < 0 && errno == EINTR && std::chrono::steady_clock::now() < deadline);
        if (n <= 0)
            return {}; // io_error

        // (1) Sender verification is recvmsg's own msg_name ONLY (C2) --
        // nlmsghdr.pid is attacker-controlled payload, never a trust signal.
        // Netlink unicast between USER sockets is permitted, so a reply
        // arriving here is not necessarily from the kernel; only portid 0
        // is. Bounded discard (count, mirroring network_config_plugin.cpp's
        // fetch_link_dump): an unbounded `continue` would let a local
        // process pin this thread indefinitely by keeping the socket busy.
        // kAcqDeadline (not kNetlinkDiscardDeadline -- that constant belongs
        // to the rtnetlink leg, not this one) already bounds the whole loop,
        // so the count is the only extra bound this leg needs.
        if (rm.msg_namelen < sizeof(rsa) || rsa.nl_family != AF_NETLINK || rsa.nl_pid != 0) {
            if (++foreign_datagrams > yuzu::firewall::kNftMaxForeignDatagrams)
                return {NftDumpStatus::foreign_flood, 0};
            continue; // not from the kernel -- discard, do not parse
        }

        // (2) MSG_TRUNC means the kernel discarded this datagram's tail
        // because it exceeded recv_buf -- checked before any size/parse
        // accounting, same precedent as fetch_link_dump.
        if ((rm.msg_flags & MSG_TRUNC) != 0)
            return {NftDumpStatus::truncated, 0};

        // (3) Oversized check runs on the ACCUMULATED total before this
        // datagram is appended, so an oversized dump is reported as exactly
        // that rather than surfacing as a much-later truncated/timeout.
        if (out.size() + static_cast<std::size_t>(n) > yuzu::firewall::kNftDumpMaxBytes)
            return {NftDumpStatus::oversized, 0};

        // (4) Append and split ONLY the newly-arrived bytes: parsed_off
        // tracks how much of `out` earlier iterations already walked, so
        // this call is O(new bytes) per recv instead of re-walking the
        // whole accumulated buffer every time (was O(n^2) over the dump's
        // life at old :661).
        out.insert(out.end(), recv_buf.data(), recv_buf.data() + n);
        const auto new_msgs =
            nft::split_nlmsgs(std::span<const std::byte>(out).subspan(parsed_off));
        std::size_t consumed = 0;
        for (const auto& m : new_msgs) {
            consumed += (m.hdr.len + (nft::kNlaAlignTo - 1)) & ~(nft::kNlaAlignTo - 1);
            if (m.hdr.type == nft::kNlmsgDone) {
                // A concurrent ruleset mutation mid-dump tears the reply --
                // the kernel flags that on the terminating DONE rather than
                // failing the dump outright, so an unchecked DONE would
                // accept a torn/inconsistent read as if it were complete.
                if ((m.hdr.flags & nft::kNlmFDumpIntr) != 0)
                    return {NftDumpStatus::torn, 0}; // never trusted (code-review: was the
                                                       // misleading default io_error)
                // A completed-but-errored dump is NOT trusted either (R9): a
                // nonzero dump_done_errno means the kernel gave up partway
                // through, even though it still sent a terminating DONE.
                const auto done_errno = nft::parse_nft_done_errno(m.payload);
                if (done_errno && *done_errno != 0)
                    return {NftDumpStatus::kernel_error, *done_errno};
                // nullopt (bare pre-v4.13 DONE) or an explicit zero errno
                // both mean a clean, complete dump.
                return {NftDumpStatus::ok, 0};
            }
            if (m.hdr.type == nft::kNlmsgError) {
                const auto err = nft::parse_nlmsgerr(m.payload);
                return {NftDumpStatus::kernel_error, err.value_or(0)};
            }
        }
        // Clamped the same way split_nlmsgs()'s own internal cursor is
        // (`off = std::min(buf.size(), off + aligned)`): a message whose
        // raw hdr.len fits the subspan but whose ALIGNED length would
        // overshoot it (the recv boundary landing inside the alignment pad
        // rather than mid-message) must not push parsed_off past out.size()
        // -- an unclamped sum here would make the next iteration's
        // subspan(parsed_off) a precondition violation (code-review
        // finding). Unreachable with genuine kernel datagrams (real dumps
        // are always alignment-consistent), defensive for new code
        // regardless.
        parsed_off += std::min(consumed, out.size() - parsed_off);
    }
}

/// Bookkeeping try_nftables_state/rules hand back to their caller when
/// nftables itself could not settle the answer (C4): `tables_seen` says
/// whether GETTABLE at least succeeded (so *something* is managing this
/// ruleset even if chain/rule content couldn't be trusted), and `dump`/
/// `result` identify which follow-up dump failed and how, for the catch-all
/// nft_diag_row() if no downstream backend answers either.
///
/// Passed by reference (not through std::expected/a return value) as a
/// deliberate exception to this file's usual output-parameter avoidance
/// (docs/cpp-conventions.md): it carries clamp bookkeeping ACROSS the
/// existing `bool try_X(ctx) -> caller checks return, moves to next
/// backend` chain that do_state_linux()/do_rules_linux() already use for
/// every other backend, and that chain's shape predates this change --
/// switching only the nftables leg's own signature to return a richer type
/// would make it the one asymmetric link (code-review finding, noted rather
/// than restructured).
struct NftFallthroughInfo {
    bool tables_seen = false;
    std::string_view dump; // "chain" or "rule"
    yuzu::firewall::NftDumpResult result;
};

/// Runs the shared GETTABLE -> GETCHAIN -> GETRULE probe (table/chain/rule
/// deadlines split 1000ms/1500ms/remainder within kAcqDeadline's unchanged
/// 5000ms envelope (C6) — a fresh socket per dump, per UP-1 above). Returns
/// nullopt if GETTABLE itself did not succeed (nftables entirely
/// unreachable — info.tables_seen stays false, caller falls through
/// untouched); otherwise returns the chain/rule buffers alongside whether
/// both were trustworthy, having already populated `info.tables_seen` and,
/// on a chain/rule failure, written the fallthrough row and the rest of
/// `info`.
struct NftProbeResult {
    bool trusted = false;
    std::vector<std::byte> chain_buf;
    std::vector<std::byte> rule_buf;
};

[[nodiscard]] std::optional<NftProbeResult> run_nft_probe(yuzu::CommandContext& ctx,
                                                          NftFallthroughInfo& info) {
    const auto start = std::chrono::steady_clock::now();
    const auto table_deadline = start + std::chrono::milliseconds{1000};
    const auto chain_deadline = start + std::chrono::milliseconds{2500};
    const auto rule_deadline = start + kAcqDeadline; // remainder(>=2500ms)+slack

    auto table_sock = open_nft_socket(remaining_ms(table_deadline));
    if (!table_sock) {
        report_open_nft_diagnostic(ctx, table_sock.error());
        return std::nullopt; // unreachable -- fall through untouched
    }
    std::vector<std::byte> table_buf;
    const auto table_res =
        nft_dump(table_sock->get(), nft::kNftMsgGettable, table_buf, table_deadline);
    table_sock->reset(); // UP-1: fresh fd per dump, no undrained-leftover-bytes risk
    if (table_res.status != yuzu::firewall::NftDumpStatus::ok) {
        // BR-03: this used to discard table_res silently, making the
        // documented troubleshooting token (README: "error|nftables:table:
        // eperm means the netlink read was refused") unreachable in
        // practice -- no no-cap host would ever actually see it. An error|
        // row (not fallthrough|: nftables hasn't committed as the live
        // backend yet, since GETTABLE itself never succeeded) before
        // falling through to firewalld/ufw/iptables.
        ctx.write_output(yuzu::firewall::nft_diag_row("table", table_res));
        return std::nullopt; // unreachable -- fall through untouched
    }

    info.tables_seen = !yuzu::firewall::parse_nft_tables(table_buf).empty();

    NftProbeResult result;
    auto chain_sock = open_nft_socket(remaining_ms(chain_deadline));
    // BR-03: a chain/rule socket-open failure used to silently collapse
    // into the generic default NftDumpResult (reason "io_error"), losing
    // the errno classification the table-socket open already gives —
    // including fd_exhausted, the one that actually needs an operator's
    // attention. Surface it the same way here.
    if (!chain_sock)
        report_open_nft_diagnostic(ctx, chain_sock.error());
    const auto chain_res = chain_sock ? nft_dump(chain_sock->get(), nft::kNftMsgGetchain,
                                                 result.chain_buf, chain_deadline)
                                      : yuzu::firewall::NftDumpResult{};
    if (chain_sock)
        chain_sock->reset();

    auto rule_sock = open_nft_socket(remaining_ms(rule_deadline));
    if (!rule_sock)
        report_open_nft_diagnostic(ctx, rule_sock.error());
    const auto rule_res = rule_sock ? nft_dump(rule_sock->get(), nft::kNftMsgGetrule,
                                               result.rule_buf, rule_deadline)
                                    : yuzu::firewall::NftDumpResult{};
    if (rule_sock)
        rule_sock->reset(); // consistency with table_sock/chain_sock above --
                            // not a leak either way (scope exit closes it),
                            // but this keeps the fresh-fd-per-dump discipline
                            // explicit at every call site.

    const bool chains_ok = chain_res.status == yuzu::firewall::NftDumpStatus::ok;
    const bool rules_ok = rule_res.status == yuzu::firewall::NftDumpStatus::ok;
    // BR-04: call the pure, unit-tested helper rather than re-deriving the
    // same `&&` inline -- nft_dumps_trusted() is the single source of truth
    // for this decision (#3463-2).
    result.trusted = yuzu::firewall::nft_dumps_trusted(chains_ok, rules_ok);
    if (!result.trusted) {
        info.dump = chains_ok ? "rule" : "chain";
        info.result = chains_ok ? rule_res : chain_res;
        ctx.write_output(yuzu::firewall::nft_fallthrough_row(info.dump, info.result));
    }
    return result;
}

/// true iff a trustworthy state| row was written (dispatch should stop);
/// false means the caller continues probing ufw/iptables, clamped per
/// `info.tables_seen` (C4).
bool try_nftables_state(yuzu::CommandContext& ctx, NftFallthroughInfo& info) {
    auto probe = run_nft_probe(ctx, info);
    if (!probe)
        return false;
    if (!probe->trusted)
        return false; // C4 fallthrough row already written by run_nft_probe

    auto chains = yuzu::firewall::parse_nft_chains(probe->chain_buf);
    auto rules = yuzu::firewall::parse_nft_rules(probe->rule_buf);
    ctx.write_output("backend|nftables"); // commits: nftables IS the final answer
    // probe->trusted is already true here (the early return above handles
    // false), so nft_decide_state(true, true, ...) always resolves through
    // its active/inactive branch -- called anyway so the unit-tested
    // decision function is the one dispatch actually runs, not a
    // hand-inlined equivalent (#3463-2).
    const auto verdict = yuzu::firewall::nft_decide_state(/*chains_ok=*/true, /*rules_ok=*/true,
                                                            chains, rules);
    ctx.write_output(std::format("state|{}", yuzu::firewall::nft_verdict_name(verdict)));
    ctx.write_output(std::format("ruleset|{}", rules.size()));
    return true;
}

/// Same contract as try_nftables_state, for the "rules" action.
bool try_nftables_rules(yuzu::CommandContext& ctx, NftFallthroughInfo& info) {
    auto probe = run_nft_probe(ctx, info);
    if (!probe)
        return false;
    if (!probe->trusted)
        return false;

    ctx.write_output("backend|nftables"); // commits

    for (const auto& c : yuzu::firewall::parse_nft_chains(probe->chain_buf)) {
        if (!c.is_base_chain)
            continue; // regular chains carry no hook/policy of their own
        ctx.write_output(yuzu::firewall::format_nft_chain_rule_row(c));
    }
    const auto rules = yuzu::firewall::parse_nft_rules(probe->rule_buf);
    for (const auto& r : rules)
        ctx.write_output(yuzu::firewall::format_nft_rule_handle_row(r));
    ctx.write_output(std::format("ruleset|{}", rules.size()));
    return true;
}

// ── ufw (rung 2, argv) ───────────────────────────────────────────────────
//
// Fixed absolute path, matching every other run_bounded_subprocess call
// site in this file — a distro that installs ufw elsewhere falls through to
// iptables, same as ufw being genuinely absent.

// `tables_seen` (true only when reached via nftables' C4 fallthrough, false
// on the ordinary probe-order path where it's always a no-op) routes this
// backend's own verdict through nft_fallthrough_clamp() before it's written,
// so a "disabled" reading here can't contradict nftables tables already
// known to exist.
bool try_ufw_state(yuzu::CommandContext& ctx, bool tables_seen) {
    auto res = run_bounded_subprocess({"/usr/sbin/ufw", "status", "numbered"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false; // ufw not installed at this path -> try the next backend
    // Mirrors try_iptables_state's exit-code check, but ufw is NOT the last
    // backend before "none" (iptables still follows), so a failed read (e.g.
    // permission denied) falls through to the next backend rather than
    // stopping the probe here and reporting unknown -- an unprivileged host
    // that can read iptables but not ufw must still get a real answer.
    if (res.exit_code != 0)
        return false;
    ctx.write_output("backend|ufw");
    // `status numbered` (not bare `status`): parse_ufw_status still reads
    // the "Status: active/inactive" first line -- `numbered` also emits it
    // -- and parse_ufw_rules can now count the bracketed rows from the same
    // single command, no extra process and no extra time off the 5s budget.
    // state| is gated on subprocess_complete(), the same completeness check
    // ruleset| already used -- a timed-out or output-capped read must not
    // report a parsed status as though it were trustworthy (governance
    // gate2 security-guardian finding, r1). gate_state_on_completeness()
    // is the shared, unit-tested composition of that check.
    auto state = yuzu::firewall::gate_state_on_completeness(
        subprocess_complete(res), tables_seen, yuzu::firewall::parse_ufw_status(res.output));
    ctx.write_output(std::format(
        "state|{}", state == yuzu::firewall::FwState::enabled    ? "active"
                    : state == yuzu::firewall::FwState::disabled ? "inactive"
                                                                  : "unknown"));
    ctx.write_output(subprocess_complete(res)
                          ? std::format("ruleset|{}", yuzu::firewall::parse_ufw_rules(res.output).size())
                          : std::string("ruleset|unknown"));
    return true;
}

bool try_ufw_rules(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/ufw", "status", "numbered"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    // Same fallthrough-not-stop rationale as try_ufw_state: a permission-
    // denied read must not report zero rules as if ufw genuinely had none.
    if (res.exit_code != 0)
        return false;
    ctx.write_output("backend|ufw");
    auto rules = yuzu::firewall::parse_ufw_rules(res.output);
    for (const auto& r : rules) {
        ctx.write_output(std::format("rule|{}|{}|{}|{}", sanitize_field(r.index),
                                     sanitize_field(r.to), sanitize_field(r.action),
                                     sanitize_field(r.from)));
    }
    ctx.write_output(subprocess_complete(res) ? std::format("ruleset|{}", rules.size())
                                              : std::string("ruleset|unknown"));
    return true;
}

// ── iptables (rung 2, argv) — the final backend before "none" ──────────

bool try_iptables_state(yuzu::CommandContext& ctx, bool tables_seen) {
    auto res = run_bounded_subprocess({"/usr/sbin/iptables", "-S"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    ctx.write_output("backend|iptables");
    // A nonzero exit (commonly EPERM -- iptables needs root/CAP_NET_ADMIN,
    // and this is the last backend in the probe order, so there's nowhere
    // left to fall through to) means the read did not actually happen --
    // honest unknown, never a false-safe "inactive" from empty output.
    if (res.exit_code != 0) {
        ctx.write_output("state|unknown");
        ctx.write_output("ruleset|unknown");
        return true;
    }
    auto rules = yuzu::firewall::parse_iptables_save(res.output);
    // iptables has no on/off concept the way ufw/firewalld do: any policy
    // other than the default ACCEPT, or any non-policy entry, counts as
    // "active"; three bare ACCEPT policies and nothing else is "inactive" —
    // matches this leg's pre-migration semantics.
    bool has_content = false;
    int append_count = 0;
    for (const auto& r : rules) {
        if (r.type == yuzu::firewall::IptablesEntryType::policy) {
            if (r.spec != "ACCEPT")
                has_content = true;
        } else {
            has_content = true;
        }
        if (r.type == yuzu::firewall::IptablesEntryType::append)
            ++append_count;
    }
    // state| is gated on subprocess_complete(), the same completeness check
    // ruleset| already used -- exit_code==0 alone doesn't rule out a
    // timed-out or output-capped read, and a parsed verdict off a partial
    // -S dump is not trustworthy (governance gate2 security-guardian
    // finding, r1). gate_state_on_completeness() is the shared,
    // unit-tested composition of that check.
    auto state = yuzu::firewall::gate_state_on_completeness(
        subprocess_complete(res), tables_seen,
        has_content ? yuzu::firewall::FwState::enabled : yuzu::firewall::FwState::disabled);
    ctx.write_output(std::format(
        "state|{}", state == yuzu::firewall::FwState::enabled    ? "active"
                    : state == yuzu::firewall::FwState::disabled ? "inactive"
                                                                  : "unknown"));
    ctx.write_output(subprocess_complete(res) ? std::format("ruleset|{}", append_count)
                                              : std::string("ruleset|unknown"));
    return true;
}

bool try_iptables_rules(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/iptables", "-S"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    ctx.write_output("backend|iptables");
    // Same reasoning as try_iptables_state above: a nonzero exit (commonly
    // EPERM) means the read did not actually happen -- report an honest
    // unknown, never a false-safe empty rule set from unparsed empty output.
    if (res.exit_code != 0) {
        ctx.write_output("rules|unknown");
        ctx.write_output("ruleset|unknown");
        return true;
    }
    int append_count = 0;
    for (const auto& r : yuzu::firewall::parse_iptables_save(res.output)) {
        const char* type_s = r.type == yuzu::firewall::IptablesEntryType::policy      ? "policy"
                             : r.type == yuzu::firewall::IptablesEntryType::new_chain ? "new_chain"
                             : r.type == yuzu::firewall::IptablesEntryType::append    ? "append"
                                                                                       : "unknown";
        ctx.write_output(std::format("rule|{}|{}|{}", type_s, sanitize_field(r.chain),
                                     sanitize_field(r.spec)));
        if (r.type == yuzu::firewall::IptablesEntryType::append)
            ++append_count;
    }
    ctx.write_output(subprocess_complete(res) ? std::format("ruleset|{}", append_count)
                                              : std::string("ruleset|unknown"));
    return true;
}

// ── Linux dispatch (C4-aware) ───────────────────────────────────────────
//
// Not a simple `!try_a() && !try_b() && ...` chain any more: the nftables
// leg's C4 fallthrough needs to thread `tables_seen` into ufw/iptables (to
// clamp their verdict) and needs its own diagnostic row if NEITHER of them
// answers either — bookkeeping a boolean chain can't carry.

void do_state_linux(yuzu::CommandContext& ctx) {
    if (try_firewalld_state(ctx))
        return;

    NftFallthroughInfo info;
    if (try_nftables_state(ctx, info))
        return;

    if (info.tables_seen) {
        // GETTABLE succeeded (something IS managing nftables here) but the
        // chain/rule content couldn't be trusted -- a fallthrough row was
        // already written by try_nftables_state. Probe ufw/iptables next,
        // clamped so neither can report a confident "disabled" that
        // contradicts the tables just seen.
        if (try_ufw_state(ctx, /*tables_seen=*/true))
            return;
        if (try_iptables_state(ctx, /*tables_seen=*/true))
            return;
        // Nothing downstream answered either -- end at nftables' own
        // unknown (not backend|none: nftables DID answer, just not
        // trustworthily) plus the diagnostic for which dump failed.
        ctx.write_output("backend|nftables");
        ctx.write_output("state|unknown");
        ctx.write_output(yuzu::firewall::nft_diag_row(info.dump, info.result));
        // BR-02: the incomplete-read count contract (#3462) says every
        // terminal state applies a ruleset row, never just the successful
        // ones -- an unknown state with no ruleset row silently breaks that
        // promise for a reader parsing this output mechanically.
        ctx.write_output("ruleset|unknown");
        return;
    }

    // nftables was entirely unreachable (GETTABLE itself never succeeded) --
    // fall through exactly as before the C4 restructure, no clamp applies.
    if (try_ufw_state(ctx, /*tables_seen=*/false))
        return;
    if (try_iptables_state(ctx, /*tables_seen=*/false))
        return;
    ctx.write_output("backend|none");
    ctx.write_output("state|unknown");
    ctx.write_output("ruleset|unknown");
}

void do_rules_linux(yuzu::CommandContext& ctx) {
    if (try_firewalld_rules(ctx))
        return;

    NftFallthroughInfo info;
    if (try_nftables_rules(ctx, info))
        return;

    if (try_ufw_rules(ctx))
        return;
    if (try_iptables_rules(ctx))
        return;

    if (info.tables_seen) {
        ctx.write_output("backend|nftables");
        ctx.write_output("rules|unknown");
        ctx.write_output(yuzu::firewall::nft_diag_row(info.dump, info.result));
        ctx.write_output("ruleset|unknown"); // BR-02, mirrors do_state_linux
        return;
    }
    ctx.write_output("backend|none");
    ctx.write_output("rules|unknown");
    ctx.write_output("ruleset|unknown");
}

#endif // platform dispatch

// ── Containment shell (PRQ.1) ───────────────────────────────────────────────
//
// firewall_quarantine_parsers.hpp holds every decision; this section only wires
// the OS mechanisms to its injected seam: the durable record (plugin KV), the
// command runner (sudo + run_bounded_subprocess), the staged ruleset file, the
// TCP probe, and the per-OS Leg. Nothing here decides anything a unit test could
// pin.

namespace fq = yuzu::firewall::quarantine;

/// One in-flight mutating action at a time (quarantine / release /
/// quarantine_allow). `quarantine_status` never takes it: a read must not queue
/// behind a multi-step mutation. Same shape and budget as the legacy plugin's
/// gate (quarantine_serialization.hpp has the rationale for 2 s).
constexpr std::chrono::milliseconds kQuarantineLockWait{2000};
yuzu::quarantine::MutationGate g_quarantine_gate{kQuarantineLockWait};

[[nodiscard]] std::int64_t epoch_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::string config_value(YuzuPluginContext* raw, std::string_view key) {
    if (!raw)
        return {};
    return std::string{yuzu::PluginContext{raw}.get_config(key)};
}

/// A KV key's presence as the C ABI reports it (0 present, 1 absent, negative on
/// error): a fault is `unknown`, never "absent" -- every caller that would act on an
/// absent record or image (start a fresh generation-1 record, skip a re-apply, treat
/// a restore image as missing) must refuse or fail instead.
[[nodiscard]] fq::KvPresence kv_presence(YuzuPluginContext* raw, const std::string& key) {
    return fq::kv_presence(yuzu_ctx_storage_exists(raw, key.c_str()));
}

/// The durable record, in the plugin's KV namespace. A failed write is reported
/// (save() == false), never swallowed: the driver refuses to mutate without one.
class KvStateStore final : public fq::StateStore {
public:
    explicit KvStateStore(YuzuPluginContext* raw) : raw_(raw) {}

    fq::StateLoad load() override {
        fq::StateLoad l;
        if (!raw_)
            return l;
        const std::string key{fq::kStateKey};
        const auto presence = kv_presence(raw_, key);
        if (presence == fq::KvPresence::absent)
            return l;
        if (presence != fq::KvPresence::present) {
            l.kind = fq::StateLoad::Kind::unreadable; // a store fault: never "no record"
            return l;
        }
        const auto parsed = fq::parse_state(yuzu::PluginContext{raw_}.storage_get(key));
        if (!parsed) {
            l.kind = fq::StateLoad::Kind::unreadable;
            return l;
        }
        l.kind = fq::StateLoad::Kind::ok;
        l.state = *parsed;
        return l;
    }

    bool save(const fq::QuarantineState& s) override {
        return raw_ && yuzu::PluginContext{raw_}.storage_set(fq::kStateKey, fq::serialize_state(s));
    }

    bool erase() override {
        if (!raw_)
            return true;
        const std::string key{fq::kStateKey};
        const auto presence = kv_presence(raw_, key);
        if (presence == fq::KvPresence::absent)
            return true;
        if (presence == fq::KvPresence::unknown)
            return false; // cannot tell whether the record is gone: not erased
        return yuzu::PluginContext{raw_}.storage_delete(key);
    }

private:
    YuzuPluginContext* raw_;
};

/// One TCP connect, mapped onto the tri-state the verify decision needs. A
/// refusal (RST) is positive proof the packet arrived, so it is NOT folded into
/// `timeout`. Only ever handed an IP literal the core validated.
[[nodiscard]] fq::ProbeOutcome tcp_probe(const std::string& ip, int port,
                                         std::chrono::milliseconds timeout) {
#ifdef _WIN32
    struct Wsa {
        WSADATA data{};
        bool ok;
        Wsa() : ok(WSAStartup(MAKEWORD(2, 2), &data) == 0) {}
        ~Wsa() {
            if (ok)
                WSACleanup();
        }
        Wsa(const Wsa&) = delete;
        Wsa& operator=(const Wsa&) = delete;
    } wsa;
    if (!wsa.ok)
        return fq::ProbeOutcome::timeout;
#endif
    auto dst = yuzu::shared::resolve_first(ip, AF_UNSPEC);
    if (!dst)
        return fq::ProbeOutcome::timeout;
    yuzu::shared::set_port(*dst, port);
    const auto r = yuzu::shared::tcp_sample(*dst, static_cast<int>(timeout.count()));
    if (r.rtt_ms)
        return fq::ProbeOutcome::connected;
    if (r.refused)
        return fq::ProbeOutcome::refused;
    return fq::ProbeOutcome::timeout;
}

#ifndef _WIN32

/// Runs argv under the canonical `sudo -n --` form (a no-op for root). stderr is
/// merged: the core reads "No such file or directory" from it to treat an
/// already-absent table as a clean release, and quotes a first line of it in
/// failure notes. The one spawn site of the containment legs: sink-manifest
/// IDs firewall/sudo_runner#1..#18, one per argv shape the legs hand it
/// (docs/agent-spawn-sink-manifest.md).
[[maybe_unused]] fq::Runner sudo_runner() {
    return [](const fq::Argv& argv, std::chrono::milliseconds budget) {
        auto res = run_bounded_subprocess(
            yuzu::shared::sudo_wrap(argv),
            SubprocessOptions{.deadline = budget, .merge_stderr = true});
        fq::ToolResult t;
        t.ran = res.tool_ran;
        t.exit_code = res.exit_code;
        t.timed_out = res.timed_out;
        t.truncated = res.output_truncated;
        t.output = std::move(res.output);
        return t;
    };
}

/// The agent-private directory a ruleset is staged in: `<agent.data_dir>/
/// firewall-staging`, mode 0700 and owned by the agent. The privileged `nft -f` /
/// `pfctl -f` reads the file after it is written, so a world-writable temp dir
/// would let another local user swap the content in between. An existing
/// directory is trusted only when it is a real directory (not a link) owned by
/// us with no group/other access. Empty when `agent.data_dir` is unset or the
/// directory cannot be made safe: the apply is then refused, never staged in /tmp.
[[maybe_unused]] std::string private_staging_dir(YuzuPluginContext* raw) {
    const auto data_dir = config_value(raw, "agent.data_dir");
    if (data_dir.empty())
        return {};
    const std::string dir = data_dir + "/firewall-staging";
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
        return {};
    struct stat st{};
    if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() ||
        (st.st_mode & 077) != 0)
        return {};
    return dir;
}

/// Writes a ruleset into a secure temporary file (mkstemps: O_CREAT|O_EXCL, 0600)
/// in the private staging directory; it is removed when the returned handle drops,
/// after the privileged load has finished with it.
[[maybe_unused]] fq::Stage temp_file_stage(YuzuPluginContext* raw) {
    return [raw](std::string_view stem, std::string_view suffix,
                 std::string_view contents) -> std::optional<fq::StagedFile> {
        const auto dir = private_staging_dir(raw);
        if (dir.empty())
            return std::nullopt;
        auto tmp = yuzu::TempFile::create(stem, suffix, dir);
        if (!tmp)
            return std::nullopt;
        {
            std::ofstream f(tmp->path(), std::ios::binary | std::ios::trunc);
            if (!f)
                return std::nullopt;
            f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
            f.flush();
            if (!f)
                return std::nullopt;
        }
        auto holder = std::make_shared<yuzu::TempFile>(std::move(*tmp));
        return fq::StagedFile{holder->path(), holder, dir};
    };
}

[[nodiscard]] std::string read_small_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    std::string buf(64 * 1024, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    return buf;
}

/// The host's DNS resolvers, read at quarantine time. A loopback stub
/// (systemd-resolved's 127.0.0.53) is followed one hop to the real upstream list
/// so the stub can still forward. On macOS /etc/resolv.conf is configd's own
/// list of the primary resolvers (scoped per-interface resolvers in
/// `scutil --dns` are not read).
[[nodiscard]] std::vector<std::string> host_resolvers() {
    return fq::resolver_chain(read_small_file("/etc/resolv.conf"),
                              read_small_file("/run/systemd/resolve/resolv.conf"));
}

#endif // !_WIN32

// ── Linux leg wiring ────────────────────────────────────────────────────────
#if defined(__linux__)

/// Our table over netlink (rung 1). nullopt when the dump is refused -- the
/// unprivileged agent has no CAP_NET_ADMIN (docs/agent-privilege-model.md), so
/// that is the usual case and the core falls back to `sudo nft list table`.
[[nodiscard]] std::optional<fq::NftTableListing> read_quarantine_table_netlink() {
    const auto deadline = std::chrono::steady_clock::now() + kAcqDeadline;
    auto sock = open_nft_socket(remaining_ms(deadline));
    if (!sock)
        return std::nullopt;
    std::vector<std::byte> buf;
    const auto res = nft_dump(sock->get(), nft::kNftMsgGetchain, buf, deadline);
    if (res.status != yuzu::firewall::NftDumpStatus::ok)
        return std::nullopt;
    fq::NftTableListing l;
    for (const auto& c : yuzu::firewall::parse_nft_chains(buf)) {
        if (c.family != nft::kNfprotoInet || c.table != fq::kNftTable)
            continue;
        l.found = true;
        l.chains.push_back({c.name,
                            c.is_base_chain ? yuzu::firewall::nft_hook_name(c.hooknum) : std::string{},
                            c.is_base_chain ? yuzu::firewall::nft_policy_name(c.policy)
                                            : std::string{}});
    }
    return l;
}

/// Does this host have an IPv6 stack that could carry traffic? Three answers:
/// yes (/proc/net/if_inet6 exists, or disable_ipv6 reads 0), no (if_inet6 is
/// absent and disable_ipv6 reads 1: the host turned IPv6 off), and nullopt when
/// neither can be read. The
/// last is NOT "no": the module may simply not be loaded yet (a socket load
/// pulls it in) and an unreadable answer must never be read as "IPv4 is the whole
/// host" (iptables_v6_plan refuses on it when ip6tables is also missing).
[[nodiscard]] std::optional<bool> ipv6_stack_present() {
    if (::access("/proc/net/if_inet6", F_OK) == 0)
        return true;
    std::ifstream f("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    int disabled = 0;
    if (!(f >> disabled))
        return std::nullopt;
    return disabled == 0;
}

/// The Linux leg for `hint` (the backend recorded in the state, so release and
/// update use what applied), or the best available one for a fresh quarantine:
/// nft when `/usr/sbin/nft` exists, else iptables. nullptr: no tool at all.
[[nodiscard]] std::unique_ptr<fq::Leg> make_leg(YuzuPluginContext* raw, fq::BackendKind hint,
                                                bool for_apply) {
    const bool has_nft = ::access("/usr/sbin/nft", X_OK) == 0;
    const bool has_ipt = ::access("/usr/sbin/iptables", X_OK) == 0;
    fq::BackendKind use = hint;
    if (use != fq::BackendKind::nft && use != fq::BackendKind::iptables)
        use = has_nft ? fq::BackendKind::nft
                      : (has_ipt ? fq::BackendKind::iptables : fq::BackendKind::none);
    if (use == fq::BackendKind::nft)
        return std::make_unique<fq::NftLeg>(sudo_runner(), temp_file_stage(raw),
                                            read_quarantine_table_netlink);
    if (use == fq::BackendKind::iptables) {
        // Apply decides IPv6 from the tool AND the stack (iptables_v6_plan refuses a
        // host that may route IPv6 with no ip6tables to cover it); release and
        // status cover v6 wherever the tool exists, so a chain built earlier is
        // never orphaned.
        const bool has_ip6 = ::access("/usr/sbin/ip6tables", X_OK) == 0;
        const auto mode = for_apply ? fq::iptables_v6_plan(has_ip6, ipv6_stack_present())
                                    : (has_ip6 ? fq::V6Mode::cover : fq::V6Mode::v4_only);
        return std::make_unique<fq::IptablesLeg>(sudo_runner(), mode);
    }
    return nullptr;
}

#endif // __linux__

// ── Windows leg (rung 1, INetFwPolicy2 COM) ─────────────────────────────────
#ifdef _WIN32

constexpr NET_FW_PROFILE_TYPE2 kQuarantineProfiles[] = {
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
// The local policy store per profile, same order (StandardProfile is the Private profile).
// The store that `put_Default*Action` writes and `Get-NetFirewallProfile -PolicyStore
// PersistentStore` reads; a missing value there is "not configured".
constexpr const wchar_t* kLocalProfileKeys[] = {
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"};
static_assert(std::size(kLocalProfileKeys) == std::size(kQuarantineProfiles));
// The prior-policy image is indexed by the same profile position.
static_assert(std::tuple_size_v<fq::WinPriorPolicy> == std::size(kQuarantineProfiles));
static_assert(std::tuple_size_v<fq::WinSwitchReading> == std::size(kQuarantineProfiles));

/// A BSTR out-param owner (the shared BStr type only builds by allocating).
struct OwnedBstr {
    BSTR b = nullptr;
    OwnedBstr() = default;
    OwnedBstr(const OwnedBstr&) = delete;
    OwnedBstr& operator=(const OwnedBstr&) = delete;
    ~OwnedBstr() {
        if (b)
            SysFreeString(b);
    }
    [[nodiscard]] std::string str() const {
        return b ? yuzu::win::from_wide(b, static_cast<int>(SysStringLen(b))) : std::string{};
    }
};

[[nodiscard]] std::string rule_name_of(INetFwRule& r) {
    OwnedBstr b;
    r.get_Name(&b.b);
    return b.str();
}
[[nodiscard]] std::string rule_group_of(INetFwRule& r) {
    OwnedBstr b;
    r.get_Grouping(&b.b);
    return b.str();
}
[[nodiscard]] bool rule_enabled(INetFwRule& r) {
    VARIANT_BOOL e = VARIANT_FALSE;
    return r.get_Enabled(&e) == S_OK && e != VARIANT_FALSE;
}

/// One BSTR property of a rule (ports, application, service); empty when it is unset
/// or cannot be read -- the same on the disable and the release side.
[[nodiscard]] std::string rule_text_of(INetFwRule& r, HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(BSTR*)) {
    OwnedBstr b;
    return (r.*get)(&b.b) == S_OK ? b.str() : std::string{};
}

/// Name, group, enabled state and every property the rule key carries (direction,
/// profile mask, protocol, ports, application, service, action): what the disable list
/// and the release match on (fq::win_rule_key). Two rules differing only in addresses,
/// interface types or edge traversal share a key and are re-enabled together (README
/// caveat 3). A property that cannot be read keeps its default (0, -1 or empty) on BOTH
/// the disable and the release side, so a rule is still matched consistently.
[[nodiscard]] fq::WinRuleInfo rule_info_of(INetFwRule& r) {
    fq::WinRuleInfo info;
    info.name = rule_name_of(r);
    info.group = rule_group_of(r);
    info.enabled = rule_enabled(r);
    NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_MAX;
    if (r.get_Direction(&dir) == S_OK)
        info.direction = static_cast<int>(dir);
    long profiles = 0;
    if (r.get_Profiles(&profiles) == S_OK)
        info.profiles = static_cast<int>(profiles);
    long protocol = 0;
    if (r.get_Protocol(&protocol) == S_OK)
        info.protocol = static_cast<int>(protocol);
    NET_FW_ACTION action = NET_FW_ACTION_MAX;
    if (r.get_Action(&action) == S_OK)
        info.action = static_cast<int>(action);
    info.local_ports = rule_text_of(r, &INetFwRule::get_LocalPorts);
    info.remote_ports = rule_text_of(r, &INetFwRule::get_RemotePorts);
    info.application = rule_text_of(r, &INetFwRule::get_ApplicationName);
    info.service = rule_text_of(r, &INetFwRule::get_ServiceName);
    return info;
}

/// Visits every rule. Returns false when the enumeration itself failed part-way,
/// or the deadline expired (checked every 256 rules; a single COM call cannot be
/// cancelled, #1391): the caller must not treat a partial pass as the whole
/// ruleset, and `dl.expired()` tells the two apart. `fn` returns false to stop
/// early, which is a clean exit.
template <class Fn>
[[nodiscard]] bool for_each_rule(INetFwRules& rules, fq::Deadline& dl, Fn&& fn) {
    ComPtr<IUnknown> unk;
    if (FAILED(rules.get__NewEnum(unk.put())) || !unk)
        return false;
    ComPtr<IEnumVARIANT> ev;
    if (FAILED(unk->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(ev.put()))) ||
        !ev)
        return false;
    std::size_t seen = 0;
    for (;;) {
        VARIANT v;
        VariantInit(&v);
        ULONG fetched = 0;
        // S_FALSE with fetched == 0 is end-of-enumeration, never "another rule".
        const HRESULT hr = ev->Next(1, &v, &fetched);
        if (FAILED(hr)) {
            VariantClear(&v);
            return false;
        }
        if (fetched == 0) {
            VariantClear(&v);
            return true;
        }
        ComPtr<INetFwRule> rule;
        if (v.vt == VT_DISPATCH && v.pdispVal &&
            SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                                 reinterpret_cast<void**>(rule.put()))) &&
            rule) {
            VariantClear(&v);
            if (++seen % 256 == 0 && dl.expired())
                return false;
            if (!fn(*rule.get()))
                return true;
        } else {
            VariantClear(&v);
        }
    }
}

/// A pass that returned false: the deadline stopped it, or the enumeration broke.
[[nodiscard]] fq::StepResult enum_fail(const fq::Deadline& dl) {
    return fq::StepResult::fail(dl.expired() ? "deadline_exceeded" : "rule_enumeration_failed");
}

[[nodiscard]] std::string hr_token(const char* what, HRESULT hr) {
    return std::format("{}:0x{:08x}", what, static_cast<std::uint32_t>(hr));
}

[[nodiscard]] fq::WinAction to_win_action(NET_FW_ACTION a) {
    return a == NET_FW_ACTION_ALLOW ? fq::WinAction::allow : fq::WinAction::block;
}

class WinLeg final : public fq::Leg {
public:
    explicit WinLeg(YuzuPluginContext* raw) : raw_(raw) {}

    [[nodiscard]] fq::BackendKind kind() const override { return fq::BackendKind::windows; }

    /// Refuse while the legacy plugin's rules (`YuzuQuarantine_*`) are present.
    /// An unreadable ruleset does not block here: the apply that follows reads
    /// the same ruleset and fails loudly if it truly cannot.
    [[nodiscard]] std::optional<std::string> preflight(fq::Deadline& dl) override {
        ComInit com;
        ComPtr<INetFwPolicy2> policy;
        ComPtr<INetFwRules> rules;
        if (!com.ok() || FAILED(get_fw_policy(policy)) || FAILED(policy->get_Rules(rules.put())) ||
            !rules)
            return std::nullopt;
        bool legacy = false;
        (void)for_each_rule(*rules.get(), dl, [&](INetFwRule& r) {
            if (fq::is_legacy_marker(rule_name_of(r))) {
                legacy = true;
                return false;
            }
            return true;
        });
        if (legacy)
            return std::string{"legacy_quarantine_active"};
        // A profile whose firewall is switched off (or cannot be read) would make every
        // rule below inert, and a profile Group Policy or MDM controls (any of the three)
        // ignores local rules and defaults altogether (`gpo_override:<Profile>`): refuse
        // before anything is touched.
        if (auto why = fq::win_firewall_switch_token(read_verdict(*policy.get())); !why.empty())
            return why;
        return std::nullopt;
    }

    [[nodiscard]] fq::StepResult apply(const fq::AllowSet& next, std::uint32_t gen, std::uint32_t,
                                       fq::OsPayload& os, fq::Deadline& dl,
                                       const fq::PersistOs&) override {
        ComInit com;
        if (!com.ok())
            return fq::StepResult::fail("com_init");
        ComPtr<INetFwPolicy2> policy;
        ComPtr<INetFwRules> rules;
        HRESULT hr = get_fw_policy(policy);
        if (FAILED(hr))
            return fq::StepResult::fail(hr_token("policy2_create", hr));
        hr = policy->get_Rules(rules.put());
        if (FAILED(hr) || !rules)
            return fq::StepResult::fail(hr_token("rules_create", hr));
        yuzu::PluginContext pc{raw_};

        // 0. The master switch and the Group Policy / MDM override, per profile. An init
        //    re-apply and an update do not pass through preflight, and nothing has
        //    been written yet.
        if (const auto why = fq::win_firewall_switch_token(read_verdict(*policy.get()));
            !why.empty())
            return fq::StepResult::fail(why);

        // 1. Read the ruleset once: legacy markers, our group, what to disable.
        std::vector<fq::WinRuleInfo> infos;
        bool legacy = false;
        if (!for_each_rule(*rules.get(), dl, [&](INetFwRule& r) {
                fq::WinRuleInfo info = rule_info_of(r);
                legacy = legacy || fq::is_legacy_marker(info.name);
                infos.push_back(std::move(info));
                return true;
            }))
            return enum_fail(dl);
        if (dl.expired())
            return fq::StepResult::fail("deadline_exceeded");
        if (legacy)
            return fq::StepResult::fail("legacy_quarantine_active");
        std::vector<std::string> ours;
        for (const auto& i : infos)
            if (fq::is_our_win_rule(i.name, i.group))
                ours.push_back(i.name);

        // 2. Capture the prior profile policy, write-once, BEFORE any write.
        fq::WinPriorPolicy prior{};
        // get_Default*Action returns the EFFECTIVE value, so whether a LOCAL value exists is
        // read from the local store: absent = not configured (a release deletes instead of
        // pinning), unreadable = unknown (the image is refused, never guessed).
        for (std::size_t i = 0; i < std::size(kQuarantineProfiles); ++i) {
            const auto capture = [&](const wchar_t* name, bool inbound) {
                const auto local = read_policy_dword(kLocalProfileKeys[i], name);
                if (!local.readable)
                    return fq::WinAction::unknown;
                if (!local.value)
                    return fq::WinAction::not_configured;
                NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
                const HRESULT hr = inbound ? policy->get_DefaultInboundAction(kQuarantineProfiles[i], &act)
                                           : policy->get_DefaultOutboundAction(kQuarantineProfiles[i], &act);
                // S_FALSE passes SUCCEEDED() but means "not found": only S_OK is a reading.
                return hr == S_OK ? to_win_action(act) : fq::WinAction::unknown;
            };
            prior[i].in = capture(L"DefaultInboundAction", true);
            prior[i].out = capture(L"DefaultOutboundAction", false);
        }
        const std::string prior_key{fq::kWinPriorPolicyKey};
        // A KV fault is not "no image": storing the quarantine policy over the real
        // one would make the release restore a block.
        const auto image_presence = kv_presence(raw_, prior_key);
        if (image_presence == fq::KvPresence::unknown)
            return fq::StepResult::fail("storage_unreadable");
        const bool image_exists = image_presence == fq::KvPresence::present;
        switch (fq::decide_prior_store(image_exists, !ours.empty(), prior)) {
        case fq::PriorStore::keep_existing:
            break;
        case fq::PriorStore::refuse_incomplete:
            return fq::StepResult::fail("prior_policy_unreadable");
        case fq::PriorStore::refuse_unrestorable:
            return fq::StepResult::fail("prior_policy_unrestorable");
        case fq::PriorStore::store:
            if (!pc.storage_set(prior_key, fq::serialize_prior_policy(prior)))
                return fq::StepResult::fail("prior_policy_not_persisted");
            break;
        }

        // 3. The disable list, stored BEFORE the first rule is touched: a crash
        //    after disabling must not strand rules nobody remembers. The first
        //    apply writes it; later applies only ever add keys (a rule created
        //    or re-enabled during the quarantine is disabled too). A key carries every
        //    property fq::win_rule_key names, so a disabled twin that differs only by
        //    protocol, ports, program, service or action is never switched on by the
        //    release; a twin differing only in addresses, interfaces or edge traversal
        //    shares the key (README caveat 3). Each key also records, from this same
        //    snapshot, whether its name, direction and profile had exactly one carrier
        //    (on or off) right now: only such a key may be found again by identity at
        //    release (fq::win_rules_to_disable).
        const auto to_disable = fq::win_rules_to_disable(infos);
        const std::string list_key{fq::kWinDisabledRulesKey};
        const auto list_presence = kv_presence(raw_, list_key);
        if (list_presence == fq::KvPresence::unknown)
            return fq::StepResult::fail("storage_unreadable");
        const bool list_exists = list_presence == fq::KvPresence::present;
        std::vector<fq::WinListedRule> stored;
        if (list_exists) {
            const auto parsed = fq::parse_disabled_rules(pc.storage_get(list_key));
            if (!parsed)
                return fq::StepResult::fail("disabled_list_unreadable");
            stored = *parsed;
        }
        const auto merged = fq::win_merge_disabled_list(std::move(stored), to_disable, list_exists);
        if (merged.over_cap)
            return fq::StepResult::fail("too_many_rules");
        if (merged.grew && !pc.storage_set(list_key, fq::serialize_disabled_rules(merged.list)))
            return fq::StepResult::fail("disabled_list_not_persisted");

        // 4. Our rules for this generation: add what is missing FIRST.
        const auto specs = fq::win_rule_specs(next, gen);
        const auto plan = fq::win_update_plan(ours, specs);
        std::vector<std::string> added;
        // Until step 6 completes, EVERY exit (a failure return or an exception)
        // takes this generation's own new rules back out: an update must not leave
        // its looser rules live beside the previous generation's record (an initial
        // apply is removed whole by the driver anyway, and the removal is
        // idempotent). No exit can forget it, there is no call to delete. The
        // destructor swallows everything: a COM call must not throw while unwinding.
        struct UndoAdded {
            INetFwRules& rules;
            const std::vector<std::string>& names;
            bool committed = false;
            ~UndoAdded() {
                if (committed)
                    return;
                try {
                    fq::Deadline cleanup(fq::kVerifyBudget); // its own budget: undo must not be starved
                    (void)remove_rules_by_name(rules, names, cleanup);
                } catch (...) {
                }
            }
        } undo{*rules.get(), added};
        for (const auto& spec : plan.add) {
            if (dl.expired())
                return fq::StepResult::fail("deadline_exceeded");
            const HRESULT ah = add_rule(*rules.get(), spec);
            if (ah != S_OK) // S_FALSE passes SUCCEEDED() but is not "added"
                return fq::StepResult::fail(hr_token("rule_add_failed", ah));
            added.push_back(spec.name);
        }

        // 5. Disable every other enabled rule: an Allow RULE beats a profile
        //    default-block, so leaving them on would leave the host reachable.
        //    A rule the policy store refuses (GPO) is counted and reported.
        std::uint32_t refused = 0;
        if (!for_each_rule(*rules.get(), dl, [&](INetFwRule& r) {
                if (!rule_enabled(r))
                    return true;
                const auto name = rule_name_of(r);
                if (fq::is_our_win_rule(name, rule_group_of(r)))
                    return true;
                if (r.put_Enabled(VARIANT_FALSE) != S_OK)
                    ++refused;
                return true;
            }))
            return enum_fail(dl);
        if (dl.expired())
            return fq::StepResult::fail("deadline_exceeded");

        // 6. Default-block, per profile, inbound and outbound.
        for (const auto profile : kQuarantineProfiles) {
            hr = policy->put_DefaultInboundAction(profile, NET_FW_ACTION_BLOCK);
            if (hr != S_OK)
                return fq::StepResult::fail(hr_token("default_inbound_failed", hr));
            hr = policy->put_DefaultOutboundAction(profile, NET_FW_ACTION_BLOCK);
            if (hr != S_OK)
                return fq::StepResult::fail(hr_token("default_outbound_failed", hr));
        }
        undo.committed = true; // this generation is in force; nothing below can fail the update

        // 7. Remove the stale generation's rules LAST. One that will not go is
        //    not a failed update (this generation is in force) but it IS a live
        //    allowance the record no longer lists -- an Allow rule outranks the
        //    default block -- so it is counted from a fresh read, persisted and
        //    reported PARTIAL, like a rule the policy store refused to disable.
        fq::StepResult ok = fq::StepResult::success();
        std::size_t stale_left = 0;
        if (!plan.remove.empty()) {
            const int failed = remove_rules_by_name(*rules.get(), plan.remove, dl);
            const auto after = collect_our_rule_names(*rules.get(), dl);
            stale_left = after ? fq::win_update_plan(*after, specs).remove.size()
                               : static_cast<std::size_t>(failed);
        }
        os.stale_rules_left = static_cast<std::uint32_t>(stale_left);
        if (stale_left > 0) {
            ok.partial = true;
            ok.notes.push_back(std::format("stale_rules_left={}", stale_left));
        }

        os.rules_not_disabled = refused;
        if (refused > 0) {
            ok.partial = true;
            ok.notes.push_back(std::format("rules_not_disabled={}", refused));
        }
        return ok;
    }

    [[nodiscard]] fq::StepResult remove(fq::OsPayload& os, fq::Deadline& dl) override {
        ComInit com;
        if (!com.ok())
            return fq::StepResult::fail("com_init");
        ComPtr<INetFwPolicy2> policy;
        ComPtr<INetFwRules> rules;
        HRESULT hr = get_fw_policy(policy);
        if (FAILED(hr))
            return fq::StepResult::fail(hr_token("policy2_create", hr));
        hr = policy->get_Rules(rules.put());
        if (FAILED(hr) || !rules)
            return fq::StepResult::fail(hr_token("rules_create", hr));
        yuzu::PluginContext pc{raw_};
        fq::StepResult result = fq::StepResult::success();
        fq::WinReleaseTally tally;

        // Release WIDENS first and removes our rules LAST, so connectivity is never
        // narrower than the quarantine at any point of the release (the reply to
        // this very command travels the control channel our rules keep open).
        // Every loop below checks the operation deadline between rules: a single COM
        // call cannot be cancelled (#1391), so the bound is between calls only.
        // 1. Which of our rules exist (needed to decide the policy fallback below).
        const auto ours_at_start = collect_our_rule_names(*rules.get(), dl);
        if (!ours_at_start)
            return enum_fail(dl);
        // 2. Re-enable what quarantine disabled. The matching is one pure decision
        //    (fq::win_release_plan): the whole rule key first (fq::win_rule_key), so a
        //    rule that was OFF before, or a twin differing only by protocol, ports,
        //    program, service or action, stays off (a twin differing only in addresses,
        //    interfaces or edge traversal shares the key and comes back with it, README
        //    caveat 3). A listed rule someone EDITED during the quarantine carries a
        //    different key; it falls back to name, direction and profile only when the key
        //    was flagged at disable time as the only carrier of them AND exactly one rule in
        //    total carries them now: switched off it is switched on, already on it is
        //    counted (`rules_accounted_enabled`). In every other case it is reported
        //    `rules_unmatched` and nothing is switched on for it (the release still
        //    completes): not flagged at disable (a sibling shared its name, direction and
        //    profile, so a rename or re-profile of the rule would leave that sibling looking
        //    like it), no carrier or more than one now, or the only carrier already claimed
        //    by another listed rule. Every rule is read once and the switched-off ones are
        //    held, so the decision and the re-enable see the same ruleset.
        const std::string list_key{fq::kWinDisabledRulesKey};
        const auto list_presence = kv_presence(raw_, list_key);
        const bool list_exists = list_presence == fq::KvPresence::present;
        if (list_presence == fq::KvPresence::unknown) {
            tally.reenable_unread = true; // cannot tell whether a list exists: not clean
            result.notes.emplace_back("storage_unreadable=1");
        } else if (list_exists) {
            const auto parsed = fq::parse_disabled_rules(pc.storage_get(list_key));
            if (!parsed) {
                result.notes.emplace_back("disabled_list_unreadable=1");
            } else if (!parsed->empty()) {
                std::vector<fq::WinRuleInfo> seen;
                std::deque<ComPtr<INetFwRule>> held; // parallel to `seen`; set for a switched-off rule
                if (!for_each_rule(*rules.get(), dl, [&](INetFwRule& r) {
                        auto info = rule_info_of(r);
                        held.emplace_back();
                        if (!info.enabled) {
                            r.AddRef();
                            *held.back().put() = &r;
                        }
                        seen.push_back(std::move(info));
                        return true;
                    })) {
                    if (dl.expired())
                        return fq::StepResult::fail("deadline_exceeded");
                    tally.reenable_unread = true; // a partial pass decides nothing: retried
                } else {
                    const auto plan = fq::win_release_plan(*parsed, seen);
                    for (const auto i : plan.reenable)
                        if (!held[i] || held[i]->put_Enabled(VARIANT_TRUE) != S_OK)
                            ++tally.not_reenabled;
                    tally.reenabled_by_identity = plan.by_identity;
                    tally.accounted_enabled = plan.accounted_enabled;
                    tally.unmatched = plan.unmatched;
                    // The names are the agent's own record of what the release could not
                    // account for (the reply carries the count only).
                    for (std::size_t n = 0; n < plan.unmatched_keys.size() && n < 8; ++n)
                        spdlog::warn("firewall: release found no unique rule for disabled rule '{}'",
                                     fq::detail::sanitize_text(
                                         fq::win_key_identity(plan.unmatched_keys[n])));
                }
            }
        }

        // 3. Restore the captured profile policy. With no image, fall back to
        //    Windows' own default ONLY if we actually removed our rules: a second
        //    release on an untouched host must not rewrite a hardened policy.
        const std::string prior_key{fq::kWinPriorPolicyKey};
        const auto image_presence = kv_presence(raw_, prior_key);
        const bool image_exists = image_presence == fq::KvPresence::present;
        std::optional<fq::WinPriorPolicy> prior;
        if (image_exists)
            prior = fq::parse_prior_policy(pc.storage_get(prior_key));
        if (image_presence == fq::KvPresence::unknown) {
            // Neither the image nor its absence is known: restoring Windows' default
            // over a hardened policy would be a guess, and so would skipping the restore.
            ++tally.policy_restore_failed;
            result.notes.emplace_back("storage_unreadable=1");
        } else if (prior || !ours_at_start->empty()) {
            for (std::size_t i = 0; i < std::size(kQuarantineProfiles); ++i) {
                if (!restore_default(*policy.get(), i, L"DefaultInboundAction", prior, true) ||
                    !restore_default(*policy.get(), i, L"DefaultOutboundAction", prior, false)) {
                    ++tally.policy_restore_failed;
                    result.notes.emplace_back(
                        std::format("policy_restore_failed={}", fq::kWinProfileLabels[i]));
                }
            }
            if (!prior)
                result.notes.emplace_back("prior_policy_unavailable=1");
        }
        // A default action that is not back (or could not be read) still BLOCKS, and our
        // allowances are the only thing keeping the control channel and DNS open: deleting
        // them now would strand the host block/block with no way back (the repair tick
        // skips a `releasing` record). Stop here with them in place; the record stays
        // `releasing` and the next release or start retries, which is safe because step 2
        // only re-enables listed rules that are still disabled and step 3 is idempotent.
        if (tally.policy_restore_failed > 0)
            return release_incomplete(fq::win_release_decision(tally), result.notes);

        // 4. Our rules, by group, until none is left (Remove(name) takes one rule
        //    per call, and a rule added concurrently by a racing apply must not
        //    survive a release).
        for (int pass = 0; pass < 3; ++pass) {
            const auto ours = collect_our_rule_names(*rules.get(), dl);
            if (!ours)
                return enum_fail(dl);
            if (ours->empty())
                break;
            (void)remove_rules_by_name(*rules.get(), *ours, dl);
            if (dl.expired())
                return fq::StepResult::fail("deadline_exceeded");
        }
        {
            const auto left = collect_our_rule_names(*rules.get(), dl);
            if (!left)
                return enum_fail(dl);
            tally.our_rules_left = !left->empty();
        }

        // 5. Keys go only after a clean release; otherwise the record stays
        //    `releasing` and the next start finishes the job from them. A key that
        //    will not delete is NOT clean either: a surviving restore image or
        //    disabled list would be reused by the next quarantine and its release
        //    would put an old policy back and re-enable rules disabled since.
        auto decision = fq::win_release_decision(tally);
        if (!decision.incomplete) {
            if (list_exists && !pc.storage_delete(list_key))
                tally.images_not_deleted = true;
            if (image_exists && !pc.storage_delete(prior_key))
                tally.images_not_deleted = true;
            decision = fq::win_release_decision(tally);
        }
        if (decision.incomplete)
            return release_incomplete(std::move(decision), result.notes);
        os.rules_not_disabled = 0;
        os.stale_rules_left = 0;
        result.notes.insert(result.notes.end(), decision.notes.begin(), decision.notes.end());
        result.partial = decision.partial;
        return result;
    }

    [[nodiscard]] fq::LegStatus read_status(const fq::OsPayload&, fq::Deadline& dl) override {
        fq::LegStatus st;
        ComInit com;
        ComPtr<INetFwPolicy2> policy;
        ComPtr<INetFwRules> rules;
        if (!com.ok() || FAILED(get_fw_policy(policy)) || FAILED(policy->get_Rules(rules.put())) ||
            !rules)
            return st;
        bool group = false, legacy = false;
        if (!for_each_rule(*rules.get(), dl, [&](INetFwRule& r) {
                const auto name = rule_name_of(r);
                group = group || rule_group_of(r) == fq::kWinGroup;
                legacy = legacy || fq::is_legacy_marker(name);
                return true;
            }))
            return st; // unreadable (or out of time): never a guess
        const auto sw = read_verdict(*policy.get());
        bool all_block = true;
        for (const auto profile : kQuarantineProfiles) {
            NET_FW_ACTION in = NET_FW_ACTION_ALLOW, out = NET_FW_ACTION_ALLOW;
            const HRESULT hi = policy->get_DefaultInboundAction(profile, &in);
            const HRESULT ho = policy->get_DefaultOutboundAction(profile, &out);
            if (hi != S_OK || ho != S_OK)
                return st; // unreadable, never a guess
            all_block = all_block && in == NET_FW_ACTION_BLOCK && out == NET_FW_ACTION_BLOCK;
        }
        if (legacy)
            st.notes.emplace_back("legacy_quarantine_rules_present=1");
        if (!group && all_block)
            st.notes.emplace_back("rules_missing=1"); // block/block with no rules of ours
        // A switched-off profile, an unreadable switch or policy store and a profile Group
        // Policy controls (`gpo_override`: local rules and defaults take no effect, whatever
        // get_Default*Action says, so a policy that arrived mid-quarantine reads
        // not_enforcing here and a re-apply cannot help) all settle the status.
        if (fq::win_switch_status(sw, st))
            return st;
        st.state = (group && all_block) ? fq::OsState::enforcing : fq::OsState::not_enforcing;
        if (st.state == fq::OsState::not_enforcing)
            st.reason = "policy_not_blocking";
        return st;
    }

private:
    /// LocalPolicyModifyState == GP_OVERRIDE: the firewall is controlled by Group
    /// Policy, so a rule or default written here takes no effect. Only a definite S_OK
    /// reading says yes. It describes the CURRENT profile only, so it is the second
    /// signal: read_gpo is the one that sees a profile the host is not on right now.
    [[nodiscard]] static bool policy_overridden(INetFwPolicy2& policy) {
        NET_FW_MODIFY_STATE state = NET_FW_MODIFY_STATE_OK;
        return policy.get_LocalPolicyModifyState(&state) == S_OK &&
               state == NET_FW_MODIFY_STATE_GP_OVERRIDE;
    }

    /// Puts one default-action slot back: deletes the local value when the slot had none
    /// before (ERROR_FILE_NOT_FOUND = already gone), else writes the explicit action.
    [[nodiscard]] static bool restore_default(INetFwPolicy2& policy, std::size_t i, const wchar_t* name,
                                       const std::optional<fq::WinPriorPolicy>& prior,
                                       bool inbound) {
        const auto op = fq::win_release_slot_op(prior, i, inbound);
        if (op == fq::WinSlotOp::delete_local) {
            // The running firewall service holds our block in memory and may not reread a
            // registry delete, so first put the OS default back through the API (inbound
            // block, outbound allow: what "not configured" resolves to), then remove the
            // local value so the store reads not configured again.
            const NET_FW_ACTION os_default = inbound ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW;
            if ((inbound ? policy.put_DefaultInboundAction(kQuarantineProfiles[i], os_default)
                         : policy.put_DefaultOutboundAction(kQuarantineProfiles[i], os_default)) != S_OK)
                return false;
            const LONG rc = RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, kLocalProfileKeys[i], name);
            return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
        }
        const NET_FW_ACTION act =
            op == fq::WinSlotOp::write_allow ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK;
        return (inbound ? policy.put_DefaultInboundAction(kQuarantineProfiles[i], act)
                        : policy.put_DefaultOutboundAction(kQuarantineProfiles[i], act)) == S_OK;
    }

    /// One policy-store DWORD. `readable` is false for any failure but "not there": a
    /// missing key or value (ERROR_FILE_NOT_FOUND) means no policy, anything else (access
    /// denied, a value of the wrong type) is a reading we do not have.
    struct PolicyDword {
        bool readable = false;
        std::optional<std::uint32_t> value;
    };
    [[nodiscard]] static PolicyDword read_policy_dword(const wchar_t* key, const wchar_t* name) {
        DWORD v = 0, size = sizeof(v);
        const LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_DWORD, nullptr, &v, &size);
        if (rc == ERROR_SUCCESS)
            return {true, static_cast<std::uint32_t>(v)};
        return {rc == ERROR_FILE_NOT_FOUND, std::nullopt};
    }

    /// One policy store's verdict on one profile: the three DWORDs the pure rule
    /// (win_gpo_profile_overridden) decides on; nullopt when any of them could not be read.
    [[nodiscard]] static std::optional<bool> read_policy_store(const wchar_t* key) {
        const auto merge = read_policy_dword(key, L"AllowLocalPolicyMerge");
        const auto in = read_policy_dword(key, L"DefaultInboundAction");
        const auto out = read_policy_dword(key, L"DefaultOutboundAction");
        if (!merge.readable || !in.readable || !out.readable)
            return std::nullopt;
        return fq::win_gpo_profile_overridden({merge.value, in.value, out.value});
    }

    /// The policy stores per profile, in kQuarantineProfiles order: Group Policy, and the MDM
    /// store the Firewall CSP writes (the same three values; MDM-managed hosts keep their
    /// policy there, not under Policies). The pure fold (win_policy_stores_overridden) joins
    /// the two. nullopt = a store could not be read; ERROR_FILE_NOT_FOUND on either key is
    /// "no policy there". The MDM path below is UNVERIFIED on a host (taken from the Firewall
    /// CSP's documented storage); gate 4 on kingsley confirms it.
    [[nodiscard]] static fq::WinGpoReading read_gpo() {
        static constexpr const wchar_t* kGroupPolicyKeys[] = {
            L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
            L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile",
            L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"};
        static constexpr const wchar_t* kMdmKeys[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Mdm\\DomainProfile",
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Mdm\\PrivateProfile",
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Mdm\\PublicProfile"};
        static_assert(std::size(kGroupPolicyKeys) == std::size(kQuarantineProfiles));
        static_assert(std::size(kMdmKeys) == std::size(kQuarantineProfiles));
        fq::WinGpoReading r{};
        for (std::size_t i = 0; i < std::size(kGroupPolicyKeys); ++i)
            r[i] = fq::win_policy_stores_overridden(read_policy_store(kGroupPolicyKeys[i]),
                                                    read_policy_store(kMdmKeys[i]));
        return r;
    }

    /// The master switch per profile, through classify_fw_hr: only S_OK is a
    /// reading, so S_FALSE and every error stay nullopt (never a guess).
    [[nodiscard]] static fq::WinSwitchReading read_switch(INetFwPolicy2& policy) {
        fq::WinSwitchReading r{};
        for (std::size_t i = 0; i < std::size(kQuarantineProfiles); ++i) {
            VARIANT_BOOL on = VARIANT_FALSE;
            if (classify_fw_hr(policy.get_FirewallEnabled(kQuarantineProfiles[i], &on)) ==
                FwHrResult::Ok)
                r[i] = on != VARIANT_FALSE;
        }
        return r;
    }

    /// The master switch and the policy override (per profile, plus the COM state)
    /// as ONE verdict: the single pure decision (fq::win_firewall_switch_verdict) that
    /// preflight, apply step 0 and read_status all route through, so the three can never
    /// disagree.
    [[nodiscard]] static fq::WinSwitchVerdict read_verdict(INetFwPolicy2& policy) {
        return fq::win_firewall_switch_verdict(read_switch(policy), read_gpo(), policy_overridden(policy));
    }

    /// `release_incomplete`: what a release that could not finish reports, with the
    /// decision's notes first and the step notes after.
    [[nodiscard]] static fq::StepResult release_incomplete(fq::WinReleaseDecision decision,
                                                           const std::vector<std::string>& step_notes) {
        auto r = fq::StepResult::fail("release_incomplete");
        r.notes = std::move(decision.notes);
        r.notes.insert(r.notes.end(), step_notes.begin(), step_notes.end());
        return r;
    }

    /// The names of the rules that are ours (group or prefix); nullopt when the
    /// enumeration itself failed part-way.
    [[nodiscard]] static std::optional<std::vector<std::string>> collect_our_rule_names(
        INetFwRules& rules, fq::Deadline& dl) {
        std::vector<std::string> out;
        if (!for_each_rule(rules, dl, [&](INetFwRule& r) {
                auto name = rule_name_of(r);
                if (fq::is_our_win_rule(name, rule_group_of(r)))
                    out.push_back(std::move(name));
                return true;
            }))
            return std::nullopt;
        return out;
    }

    /// Removes each named rule from the store; returns how many removals failed.
    [[nodiscard]] static int remove_rules_by_name(INetFwRules& rules,
                                                  const std::vector<std::string>& names,
                                                  fq::Deadline& dl) {
        int failed = 0;
        std::size_t i = 0;
        for (const auto& n : names) {
            if (++i % 64 == 0 && dl.expired()) { // the rest are left, counted as failed
                failed += static_cast<int>(names.size() - i + 1);
                break;
            }
            yuzu::shared::win::BStr b{yuzu::win::to_wide(n)};
            if (!b || rules.Remove(b.get()) != S_OK)
                ++failed;
        }
        return failed;
    }

    [[nodiscard]] static HRESULT add_rule(INetFwRules& rules, const fq::WinRuleSpec& spec) {
        ComPtr<INetFwRule> rule;
        HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                      __uuidof(INetFwRule), reinterpret_cast<void**>(rule.put()));
        if (FAILED(hr) || !rule)
            return FAILED(hr) ? hr : E_POINTER;
        using yuzu::shared::win::BStr;
        BStr name{yuzu::win::to_wide(spec.name)};
        BStr group{yuzu::win::to_wide(fq::kWinGroup)};
        BStr desc{std::wstring{L"Yuzu Firewall quarantine allowance"}};
        if (!name || !group || !desc)
            return E_OUTOFMEMORY;
        if (FAILED(hr = rule->put_Name(name.get())) ||
            FAILED(hr = rule->put_Description(desc.get())) ||
            FAILED(hr = rule->put_Grouping(group.get())) ||
            FAILED(hr = rule->put_Direction(spec.dir == fq::Dir::in ? NET_FW_RULE_DIR_IN
                                                                    : NET_FW_RULE_DIR_OUT)) ||
            FAILED(hr = rule->put_Action(NET_FW_ACTION_ALLOW)) ||
            FAILED(hr = rule->put_Protocol(spec.protocol)))
            return hr;
        // An empty value leaves the property at its default (any).
        auto put_str = [](const std::string& v, auto&& put) -> HRESULT {
            if (v.empty())
                return S_OK;
            BStr b{yuzu::win::to_wide(v)};
            if (!b)
                return E_OUTOFMEMORY;
            return put(b.get());
        };
        if (FAILED(hr = put_str(spec.remote_addrs,
                                [&](BSTR b) { return rule->put_RemoteAddresses(b); })) ||
            FAILED(hr = put_str(spec.local_ports, [&](BSTR b) { return rule->put_LocalPorts(b); })) ||
            FAILED(hr = put_str(spec.remote_ports,
                                [&](BSTR b) { return rule->put_RemotePorts(b); })) ||
            FAILED(hr = put_str(spec.icmp_types,
                                [&](BSTR b) { return rule->put_IcmpTypesAndCodes(b); })) ||
            FAILED(hr = put_str(spec.service_name,
                                [&](BSTR b) { return rule->put_ServiceName(b); })) ||
            FAILED(hr = rule->put_Profiles(NET_FW_PROFILE2_ALL)) ||
            FAILED(hr = rule->put_Enabled(VARIANT_TRUE)))
            return hr;
        return rules.Add(rule.get());
    }

    YuzuPluginContext* raw_;
};

/// The DNS servers of every adapter that is up (GetAdaptersAddresses), the Windows
/// twin of /etc/resolv.conf. The site-local `fec0:0:0:ffff::` placeholders
/// Windows lists when an adapter has no IPv6 DNS are not real resolvers.
[[nodiscard]] std::vector<std::string> host_resolvers() {
    std::vector<std::string> out;
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size);
    }
    if (rc != NO_ERROR)
        return out;
    for (auto* a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp)
            continue;
        for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
            char text[64]{};
            const auto* sa = d->Address.lpSockaddr;
            if (!sa)
                continue;
            if (sa->sa_family == AF_INET) {
                const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
                if (!InetNtopA(AF_INET, const_cast<IN_ADDR*>(&in->sin_addr), text, sizeof(text)))
                    continue;
            } else if (sa->sa_family == AF_INET6) {
                const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
                // fec0:0:0:ffff::N placeholder: the first 8 bytes (fec0:0:0:ffff); a real
                // site-local resolver elsewhere in fec0::/10 is kept.
                static constexpr unsigned char kPlaceholder[8] = {0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff};
                if (std::memcmp(in6->sin6_addr.s6_addr, kPlaceholder, sizeof(kPlaceholder)) == 0)
                    continue;
                if (!InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&in6->sin6_addr), text, sizeof(text)))
                    continue;
            } else {
                continue;
            }
            out.emplace_back(text);
        }
    }
    return out;
}

[[nodiscard]] std::unique_ptr<fq::Leg> make_leg(YuzuPluginContext* raw, fq::BackendKind, bool) {
    return std::make_unique<WinLeg>(raw);
}

#endif // _WIN32

// ── macOS leg (rung 2, sudo pfctl over the pf sub-anchor) ───────────────────
#if defined(__APPLE__)

/// The current boot's identity, `kern.boottime` as "<sec>.<usec>", read in-process
/// (no spawn, so no sudoers line or PATH to trust). pf's enable references reset
/// at reboot, so a token is only meaningful for the boot that issued it.
[[nodiscard]] std::optional<std::string> kern_boot_time() {
    struct timeval tv{};
    size_t len = sizeof(tv);
    if (::sysctlbyname("kern.boottime", &tv, &len, nullptr, 0) != 0 || len != sizeof(tv) ||
        tv.tv_sec <= 0)
        return std::nullopt;
    return std::format("{}.{}", static_cast<long long>(tv.tv_sec), static_cast<long long>(tv.tv_usec));
}

/// macOS has one backend (pf), so the hint and for_apply carry nothing: release
/// and status use the same leg that applied.
[[nodiscard]] std::unique_ptr<fq::Leg> make_leg(YuzuPluginContext* raw, fq::BackendKind, bool) {
    return std::make_unique<fq::PfLeg>(sudo_runner(), temp_file_stage(raw), kern_boot_time);
}

#endif // __APPLE__

// ── Action handlers (all OSes) ──────────────────────────────────────────────

/// One log line per containment state change (info) and per non-OK outcome (warn),
/// `degraded|exception` at error: a boot re-apply that failed, a TTL release that ended
/// partial, an unattended repair and an `uncontained after reboot` host otherwise show
/// nothing until someone polls. The line carries the outcome's notes, so an expiry
/// release reads `firewall: release -> inactive ttl_expired=1`, the only record of it
/// until the server records them. What is logged, and at which level, is
/// fq::log_level (pure, unit-tested); this maps it onto spdlog. The core logs nothing.
void log_outcome(std::string_view action, const fq::Outcome& o) {
    switch (fq::log_level(action, o)) {
    case fq::LogLevel::none:
        return;
    case fq::LogLevel::info:
        spdlog::info("{}", fq::log_line(action, o));
        return;
    case fq::LogLevel::warn:
        spdlog::warn("{}", fq::log_line(action, o));
        return;
    case fq::LogLevel::error:
        spdlog::error("{}", fq::log_line(action, o));
        return;
    }
}

void emit(yuzu::CommandContext& ctx, const fq::Outcome& o, std::string_view action = "containment") {
    log_outcome(action, o);
    for (const auto& row : fq::render_rows(o))
        ctx.write_output(row);
    const auto rk = fq::result_kind(o);
    const auto status = rk.kind == fq::ResultKind::Kind::ok ? YUZU_RESULT_STATUS_OK
                        : rk.kind == fq::ResultKind::Kind::unavailable
                            ? YUZU_RESULT_STATUS_UNAVAILABLE
                            : YUZU_RESULT_STATUS_CONSTRAINED;
    ctx.set_result_status(status,
                          rk.partial ? YUZU_RESULT_COMPLETENESS_PARTIAL
                                     : YUZU_RESULT_COMPLETENESS_FULL,
                          rk.provenance);
}

int emit_refusal(yuzu::CommandContext& ctx, std::string reason, std::string_view action = "containment") {
    const auto o = fq::refused(std::move(reason));
    emit(ctx, o, action);
    return o.rc();
}

int emit_busy(yuzu::CommandContext& ctx) {
    fq::Outcome o;
    o.status = "busy";
    emit(ctx, o, "containment");
    return o.rc();
}

/// The OS leg plus the durable record, built per call. The leg follows the
/// backend the record says applied (a host that gained or lost nft since must
/// still release what it applied); a fresh quarantine picks the best available.
struct Containment {
    YuzuPluginContext* raw;
    KvStateStore store;
    std::unique_ptr<fq::Leg> leg;
    Containment(YuzuPluginContext* raw_, bool for_apply) : raw(raw_), store(raw_) {
        const auto l = store.load();
        leg = make_leg(raw_, l.kind == fq::StateLoad::Kind::ok ? l.state.backend : fq::BackendKind::none,
                       for_apply);
    }
    /// `live_peer`: the verification proves the address the agent's control channel
    /// really uses (`agent.server_peer`, published by agents/core from the stream the
    /// server answered on) instead of scanning the allow set. Agent start passes false:
    /// no Register has happened yet, so no peer is known and the listed scan is the proof.
    [[nodiscard]] fq::Env env(bool live_peer = true) {
        return fq::Env{*leg, store, tcp_probe, epoch_now,
                       live_peer ? fq::parse_live_peer(config_value(raw, "agent.server_peer"))
                                 : std::nullopt};
    }
};

/// The agent's trigger engine, reached through the plugin context. The decision
/// itself (fq::settle_triggers: the time limit's trigger and the repair self-check) is
/// in the core.
class ContextTriggers final : public fq::TriggerRegistry {
public:
    explicit ContextTriggers(YuzuPluginContext* raw) : ctx_{raw} {}
    bool register_trigger(std::string_view id, std::string_view type,
                          std::string_view config_json) override {
        return ctx_.register_trigger(id, type, config_json);
    }
    bool unregister_trigger(std::string_view id) override { return ctx_.unregister_trigger(id); }

private:
    yuzu::PluginContext ctx_;
};

void settle_triggers(fq::Outcome& o, YuzuPluginContext* raw) {
    if (!raw)
        return;
    ContextTriggers triggers{raw};
    KvStateStore store{raw}; // a failed registration is recorded as residue on the record
    fq::settle_triggers(o, triggers, store);
}

/// What a throw out of a containment action answers: `degraded|exception`
/// (CONSTRAINED, PARTIAL, rc 1), never `refused` -- a throw can follow the
/// `applying` record and part of the mutation, and consumers key on the provenance
/// (`firewall:refused` means nothing changed). The stored record, when it loads, is
/// attached so settle_triggers still registers the triggers of an `applying`
/// record. Every step is its own guard: this runs inside the one catch at the plugin
/// seam and must never throw across the ABI.
int emit_exception(yuzu::CommandContext& ctx, YuzuPluginContext* raw) {
    try {
        fq::StateLoad loaded;
        try {
            loaded = KvStateStore{raw}.load();
        } catch (...) {
        }
        auto o = fq::exception_outcome(loaded);
        try {
            settle_triggers(o, raw);
        } catch (...) {
        }
        emit(ctx, o, "containment");
        return o.rc();
    } catch (...) {
        try {
            ctx.write_output("status|degraded|exception");
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "firewall:degraded");
        } catch (...) {
        }
        return 1;
    }
}

/// Linux: the packaged unit (User=yuzu-agent, NoNewPrivileges=true, no sudoers
/// grant) cannot elevate, so a mutating containment action is refused cleanly
/// `privilege_unavailable` before any record or tool call (the decision is
/// fq::linux_privilege_refusal; only the two OS reads are here). Never refused
/// elsewhere.
[[nodiscard]] std::optional<std::string_view> privilege_refusal() {
#if defined(__linux__)
    return fq::linux_privilege_refusal(::geteuid() == 0,
                                       ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
#else
    return std::nullopt;
#endif
}

/// The ONE place the mutation gate is taken. Every mutating action runs through
/// here and answers `busy` when it cannot get in; `quarantine_status` never does.
template <class Body> int gated(yuzu::CommandContext& ctx, Body&& body) {
    auto guard = g_quarantine_gate.try_enter();
    if (!guard)
        return emit_busy(ctx);
    return body();
}

/// The unattended self-check (`firewall.quarantine` with `repair=1`, dispatched by the
/// repair trigger every 60 s). Runs inside the same MutationGate as every mutating
/// action (busy answers, never waits). Reads the record and, at most, re-applies the
/// STORED set of an `active` record the host stopped enforcing (fq::repair); no allow
/// set is built and no other parameter is read.
int do_repair(yuzu::CommandContext& ctx, YuzuPluginContext* raw) {
    if (const auto why = privilege_refusal())
        return emit_refusal(ctx, std::string{*why}, "repair");
    Containment containment(raw, /*for_apply=*/false);
    fq::Outcome o;
    if (!containment.leg) {
        // No firewall tool: nothing of ours is in force unless a record says it is, and
        // a store that cannot answer is still never read as "no record".
        o.notes.emplace_back("repair_tick=1");
        switch (containment.store.load().kind) {
        case fq::StateLoad::Kind::absent:
            o.status = "inactive";
            o.notes.emplace_back("nothing_to_repair=1");
            break;
        case fq::StateLoad::Kind::unreadable:
            o.status = "degraded";
            o.reason = "state_unreadable";
            break;
        case fq::StateLoad::Kind::ok:
            o.status = "degraded";
            o.reason = "os_unreadable";
            break;
        }
    } else {
        auto env = containment.env();
        fq::Deadline dl;
        o = fq::repair(env, dl);
    }
    settle_triggers(o, raw);
    emit(ctx, o, "repair");
    return o.rc();
}

int do_quarantine(yuzu::CommandContext& ctx, yuzu::Params params, YuzuPluginContext* raw) {
    // The repair trigger's dispatch (its config carries `repair=1` and nothing else). The
    // plugin cannot tell that trigger from an operator's dispatch, so a `repair=1` that also
    // names a containment parameter is refused rather than answered as a repair: an operator
    // who meant to contain must not read `inactive nothing_to_repair`. A bare `repair=1`
    // is routed before anything else is read (it never builds an allow set or starts a record).
    if (params.get("repair") == "1") {
        if (params.has("ttl_seconds") || params.has("exceptions") || params.has("probe_target"))
            return emit_refusal(ctx, "repair_with_containment_parameters", "quarantine");
        return do_repair(ctx, raw);
    }
    const auto ttl = fq::parse_ttl_param(params.get("ttl_seconds"));
    if (!ttl)
        return emit_refusal(ctx, ttl.error(), "quarantine");
    const auto exceptions = fq::parse_exceptions_csv(params.get("exceptions"));
    if (!exceptions)
        return emit_refusal(ctx, "exceptions_invalid:" + exceptions.error(), "quarantine");
    // The packaged Linux unit cannot elevate: refuse before any record exists,
    // rather than write `applying` and fail every tool call after it.
    if (const auto why = privilege_refusal())
        return emit_refusal(ctx, std::string{*why}, "quarantine");

    Containment containment(raw, /*for_apply=*/true);
    if (!containment.leg)
        return emit_refusal(ctx, "unsupported_platform");
#ifndef _WIN32
    // The nft and pf legs hand a staged file to a privileged tool: no private
    // directory to stage it in, no apply (and nothing has been touched yet).
    if ((containment.leg->kind() == fq::BackendKind::nft ||
         containment.leg->kind() == fq::BackendKind::pf) &&
        private_staging_dir(raw).empty())
        return emit_refusal(ctx, "staging_unavailable");
#endif

    // The start-resolved set was read ONCE at agent start and the live peer is the
    // address agents/core published from the stream the server answered on (never
    // resolved here: the host being contained must not choose which address survives
    // its own containment, #3429). The live peer leads the set, so a server that moved
    // since start is allowed, and it is what the verification connects to.
    auto allow = fq::build_allow_set(config_value(raw, "agent.server_address_resolved"),
                                     config_value(raw, "agent.server_address"), host_resolvers(),
                                     *exceptions, config_value(raw, "agent.server_peer"));
    if (!allow)
        return emit_refusal(ctx, allow.error());

    fq::ApplyRequest req;
    req.allow = *allow;
    req.probe_target = std::string{params.get("probe_target")};
    req.ttl_seconds = *ttl;
    auto env = containment.env();
    fq::Deadline dl;
    auto o = fq::apply_and_verify(env, req, dl);
    o.notes.insert(o.notes.end(), allow->notes.begin(), allow->notes.end());
    settle_triggers(o, raw);
    emit(ctx, o, "quarantine");
    return o.rc();
}

int do_release(yuzu::CommandContext& ctx, yuzu::Params params, YuzuPluginContext* raw) {
    fq::ReleaseRequest req;
    const auto due = params.get("if_ttl_expired");
    req.if_ttl_expired = due == "1" || due == "true";
    if (const auto why = privilege_refusal())
        return emit_refusal(ctx, std::string{*why}, "release");

    Containment containment(raw, /*for_apply=*/false);
    if (!containment.leg) {
        // No firewall tool and no record of one: nothing of ours can be in force.
        fq::Outcome o;
        if (containment.store.load().kind == fq::StateLoad::Kind::absent) {
            o.status = "inactive";
            o.notes.emplace_back("no_firewall_tool=1");
            emit(ctx, o);
            return 0;
        }
        return emit_refusal(ctx, "unsupported_platform");
    }
    auto env = containment.env();
    fq::Deadline dl;
    auto o = fq::release(env, req, dl);
    settle_triggers(o, raw);
    emit(ctx, o, "release");
    return o.rc();
}

int do_quarantine_allow(yuzu::CommandContext& ctx, yuzu::Params params, YuzuPluginContext* raw) {
    const auto op = params.get("op");
    if (op != "add" && op != "remove")
        return emit_refusal(ctx, "op_invalid");
    const auto exceptions = fq::parse_exceptions_csv(params.get("exceptions"));
    if (!exceptions)
        return emit_refusal(ctx, "exceptions_invalid:" + exceptions.error());
    if (exceptions->empty())
        return emit_refusal(ctx, "exceptions_required");
    if (const auto why = privilege_refusal())
        return emit_refusal(ctx, std::string{*why}, "quarantine_allow");

    Containment containment(raw, /*for_apply=*/true);
    if (!containment.leg) {
        // A record with no tool to read it through is the same answer release and
        // status give; no record at all is "not active".
        return emit_refusal(ctx, containment.store.load().kind == fq::StateLoad::Kind::absent
                                     ? "not_active"
                                     : "unsupported_platform");
    }
    auto env = containment.env();
    fq::Deadline dl;
    auto o = fq::update(env, op == "add", *exceptions, dl);
    emit(ctx, o, "quarantine_allow");
    return o.rc();
}

int do_quarantine_status(yuzu::CommandContext& ctx, YuzuPluginContext* raw,
                         const std::string& init_note) {
    Containment containment(raw, /*for_apply=*/false);
    fq::Outcome o;
    if (!containment.leg) {
        if (containment.store.load().kind == fq::StateLoad::Kind::absent) {
            o.status = "inactive";
            o.notes.emplace_back("no_firewall_tool=1");
        } else {
            o.status = "degraded";
            o.reason = "os_unreadable";
        }
    } else {
        auto env = containment.env();
        fq::Deadline dl;
        o = fq::report_status(env, dl);
    }
    // The start-time note describes a containment that is still in force; once the
    // host is inactive (a release since) it is history, not status.
    if (!init_note.empty() && o.status != "inactive")
        o.notes.push_back("init_recovery=" + init_note);
    emit(ctx, o, "quarantine_status");
    return 0;
}

/// Agent start: complete an interrupted operation, re-apply a stored containment
/// the OS no longer enforces (a reboot), re-register the TTL trigger. Bounded
/// BETWEEN calls by the apply deadline (60 s) plus the verification budget (10 s);
/// a single COM call that never returns is not bounded (#1391); never throws;
/// never rolls back or releases.
[[nodiscard]] std::string recover_containment_at_start(YuzuPluginContext* raw) {
    try {
        KvStateStore probe_store(raw);
        const auto l = probe_store.load();
        if (l.kind == fq::StateLoad::Kind::absent)
            return {};
        Containment containment(raw, /*for_apply=*/true);
        if (!containment.leg)
            return "no_firewall_tool";
        auto env = containment.env(/*live_peer=*/false); // no Register yet: no live peer is known
        fq::Deadline dl;
        auto o = fq::recover_at_init(env, dl);
        settle_triggers(o, raw);
        log_outcome("start recovery", o);
        // `status[:reason][,note...]`: a cause that is only a note (a failed state
        // flush, an unregistered TTL trigger) must survive into init_recovery.
        auto summary = o.reason.empty() ? o.status : o.status + ":" + o.reason;
        for (const auto& n : o.notes)
            summary += "," + n;
        return summary;
    } catch (...) {
        spdlog::error("firewall: start recovery threw; the stored containment was not re-checked");
        return "exception";
    }
}


// ── ABI4 capability declarations (#2204) ────────────────────────────────
//
// Windows: entirely native, zero subprocesses — INetFwPolicy2 COM (rung 1).
// macOS: run_bounded_subprocess argv, no shell (rung 2) — same 3 sites as
// before the migration. Linux: firewalld and nftables are both native rung 1
// (bounded sd-bus / bounded NETLINK_NETFILTER); ufw/iptables are
// run_bounded_subprocess argv (rung 2), the fallback once neither native
// backend is reachable. `state` and `rules` never mutate firewall state. The
// four containment actions below do: Windows over COM (rung 1), Linux over
// `sudo nft -f` / iptables argv (rung 2, with the status read rung 1 -> 2),
// macOS over `sudo pfctl` (rung 2): an own sub-anchor plus a pf enable reference.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "state",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), "
         "else ufw/iptables via run_bounded_subprocess (rung 2)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "socketfilterfw/pfctl via run_bounded_subprocess", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "INetFwPolicy2 COM (per-profile FirewallEnabled)", nullptr},
    },
    {
        /* .action      = */ "rules",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), "
         "else ufw/iptables via run_bounded_subprocess (rung 2)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "pfctl via run_bounded_subprocess", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "INetFwPolicy2 COM (INetFwRules enumeration)", nullptr},
    },
    {
        /* .action      = */ "quarantine",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2,
         "sudo nft -f of an own inet table applied as one transaction (policy-drop chains); "
         "iptables/ip6tables generation chain via run_bounded_subprocess when nft is absent",
         "the packaged systemd unit (NoNewPrivileges, no sudoers) refuses every containment action "
         "privilege_unavailable; needs the installer's sudoers grant on a unit without NoNewPrivileges; "
         "contains the host's own IP traffic and traffic the host routes (L2-bridged guests and "
         "macvlan/ipvlan containers are not contained); a ttl_seconds limit rides the host "
         "wall clock (NTP is blocked while contained) and its expiry release is logged on the "
         "agent only"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2,
         "sudo pfctl: own sub-anchor com.apple/000.yuzu_quarantine loaded with -a -f (the main ruleset "
         "is never loaded), a pf enable reference (-E), one global pf state flush (-F states)",
         "needs Apple's anchor com.apple/* in the main ruleset and no sibling anchor sorting before "
         "000.yuzu_quarantine, else the result is partial or degraded; the state flush cuts every pf "
         "connection once and release does not restore them; a ttl_seconds limit rides the host "
         "wall clock (NTP is blocked while contained) and its expiry release is logged on the "
         "agent only"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "INetFwPolicy2 COM rule group + per-profile default-block; other enabled rules "
         "disabled for the duration",
         "rules the policy store refuses to disable (GPO) leave the result partial; a host where "
         "Group Policy or MDM controls any of the three profiles (a policy-set default action, or "
         "local rules that do not merge; also LocalPolicyModifyState GP_OVERRIDE) is refused "
         "gpo_override:<Profile> and changes nothing (a rule or default written locally takes no "
         "effect there; a policy that sets block/block itself is refused too), and reads "
         "degraded|gpo_override if the policy arrives mid-quarantine; contains "
         "the host's own IP traffic and traffic the host "
         "routes (Hyper-V external-switch guests are not contained); a ttl_seconds limit rides the host "
         "wall clock (NTP is blocked while contained) and its expiry release is logged on the "
         "agent only"},
    },
    {
        /* .action      = */ "release",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "sudo nft delete table / iptables chain removal",
         "the packaged systemd unit (NoNewPrivileges, no sudoers) refuses every containment action "
         "privilege_unavailable; needs the installer's sudoers grant on a unit without NoNewPrivileges"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "sudo pfctl: empty own anchor (-F rules, -F nat), release the enable token (-X)",
         "connections cut by the apply-time state flush are not restored; a token pf no longer "
         "knows is noted, not an error"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "INetFwPolicy2 COM rule-group removal, prior-policy restore, disabled rules re-enabled",
         "a rule edited during the quarantine is re-found by name, direction and profile when that "
         "is unambiguous, else the release completes partial|rules_unmatched (record erased, "
         "nothing of ours left); a rule the policy store will not re-enable is noted "
         "rules_not_reenabled"},
    },
    {
        /* .action      = */ "quarantine_status",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "own nftables table over NETLINK_NETFILTER (rung 1), else sudo nft list table (rung 2); "
         "iptables chain jumps via argv",
         "netlink needs CAP_NET_ADMIN, which the unprivileged agent lacks: the sudo read is "
         "the usual path, and on the packaged systemd unit (NoNewPrivileges, no sudoers) it fails, "
         "so a host with a stored record reads degraded; needs the installer's sudoers grant on a "
         "unit without NoNewPrivileges"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "sudo pfctl reads: info, main-ruleset anchor reference, own anchor rules, sibling anchors "
         "under com.apple, enable references",
         "read-only; a disabled pf, a dangling anchor or an earlier sibling reads degraded"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "INetFwPolicy2 COM rule group presence + per-profile default actions", nullptr},
    },
    {
        /* .action      = */ "quarantine_allow",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2,
         "atomic nft reload / iptables build-then-swap of a new generation",
         "the packaged systemd unit (NoNewPrivileges, no sudoers) refuses every containment action "
         "privilege_unavailable; needs the installer's sudoers grant on a unit without NoNewPrivileges"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2,
         "sudo pfctl: atomic reload of the own sub-anchor (-a -f), then a global pf state flush",
         "each update flushes every pf state once, so connections not covered by an allowance are "
         "cut and not restored"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "INetFwPolicy2 COM: new generation's rules added first, stale ones removed last", nullptr},
    },
};

} // namespace

class FirewallPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "firewall"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Firewall status, rule listing and device containment";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state",      "rules",         "quarantine",
                                     "release",    "quarantine_status", "quarantine_allow",
                                     nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    // The containment record and the Windows restore images live in plugin KV,
    // which only a PluginContext reaches, so the raw handle is cached here (the
    // ABI documents this use; the host owns the context and outlives the plugin).
    // init() runs after the KV store opens and before Register, which is what lets
    // an interrupted operation be finished, and a stored containment re-applied,
    // before the agent connects.
    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        ctx_ = ctx.raw();
        init_note_ = recover_containment_at_start(ctx_);
        return {};
    }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {

        if (action == "state") {
#ifdef _WIN32
            do_state_windows(ctx);
#elif defined(__linux__)
            // Every-backend-unreachable and nftables-C4-dead-end honest-
            // unknown fallbacks live in do_state_linux() itself now (the
            // C4 clamp needs to thread tables_seen through ufw/iptables,
            // which a flat `!a() && !b() && ...` chain can't carry).
            do_state_linux(ctx);
#elif defined(__APPLE__)
            do_state_macos(ctx);
#endif
            return 0;
        }

        if (action == "rules") {
#ifdef _WIN32
            do_rules_windows(ctx);
#elif defined(__linux__)
            do_rules_linux(ctx);
#elif defined(__APPLE__)
            do_rules_macos(ctx);
#endif
            return 0;
        }

        if (action == "quarantine" || action == "release" || action == "quarantine_status" ||
            action == "quarantine_allow") {
            return execute_containment(ctx, action, params);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    // One try/catch at the plugin seam: an exception must never cross the ABI. A
    // throw mid-apply leaves the `applying` record the next start (or `release`)
    // finishes -- the host is never left with unrecorded rules.
    int execute_containment(yuzu::CommandContext& ctx, std::string_view action,
                            yuzu::Params params) {
        try {
            if (action == "quarantine")
                return gated(ctx, [&] { return do_quarantine(ctx, params, ctx_); });
            if (action == "release")
                return gated(ctx, [&] { return do_release(ctx, params, ctx_); });
            if (action == "quarantine_allow")
                return gated(ctx, [&] { return do_quarantine_allow(ctx, params, ctx_); });
            return do_quarantine_status(ctx, ctx_, init_note_); // a read: never gated
        } catch (...) {
            return emit_exception(ctx, ctx_);
        }
    }

    YuzuPluginContext* ctx_ = nullptr;
    std::string init_note_;
};

YUZU_PLUGIN_EXPORT(FirewallPlugin)
