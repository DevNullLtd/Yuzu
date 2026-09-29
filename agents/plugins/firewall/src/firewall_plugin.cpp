/**
 * firewall_plugin.cpp — Firewall status and rules plugin for Yuzu
 *
 * Actions:
 *   "state" — Return firewall state per profile/backend.
 *   "rules" — List firewall rules (summary).
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

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <format>
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

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

#if defined(__linux__)
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
    // tar_netqual_nstat.cpp's nstat socket open: every early return below
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

// ── ABI4 capability declarations (#2204) ────────────────────────────────
//
// Windows: entirely native, zero subprocesses — INetFwPolicy2 COM (rung 1).
// macOS: run_bounded_subprocess argv, no shell (rung 2) — same 3 sites as
// before the migration. Linux: firewalld and nftables are both native rung 1
// (bounded sd-bus / bounded NETLINK_NETFILTER); ufw/iptables are
// run_bounded_subprocess argv (rung 2), the fallback once neither native
// backend is reachable. Neither action mutates firewall state — this plugin
// exposes status/listing only.
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
};

} // namespace

class FirewallPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "firewall"; }
    std::string_view version() const noexcept override { return "0.6.0"; }
    std::string_view description() const noexcept override {
        return "Firewall status and rule listing";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state", "rules", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

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

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(FirewallPlugin)
