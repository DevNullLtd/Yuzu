/**
 * rdp_control_plugin.cpp — Remote Desktop (RDP) control plugin for Yuzu
 *
 * Actions:
 *   "set_state" — Enable or disable Remote Desktop (param: state=enable|disable).
 *   "status"    — Report current RDP posture (registry + firewall + service).
 *
 * Enable flips three switches; disable reverts the first two:
 *   1. HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
 *      (REG_DWORD: 0 = allow, 1 = deny)
 *   2. The "Remote Desktop" firewall rule group, addressed by its
 *      locale-independent indirect string "@FirewallAPI.dll,-28752" via
 *      INetFwPolicy2 (no netsh shell-out, no localized group names)
 *   3. TermService — started on enable, left running on disable (the
 *      registry + firewall gates block new connections)
 *
 * Error semantics: no rollback. Every step reports its own status row and
 * `overall|ok` only when all attempted steps succeeded. Callers (the
 * ServiceNow change-window job) must treat anything other than overall|ok
 * as "state not confirmed" and retry — especially on the disable path,
 * which is the security-relevant direction.
 *
 * Windows-only. Reports rdp_control|unsupported|... on Linux/macOS (no
 * equivalent surface there — see the macOS parity notes for the flagged
 * product decision).
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <mutex>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <netfw.h>
#include <oleauto.h> // SysAllocString / SysFreeString

#include <win_com.hpp> // shared yuzu::shared::win ComInit / ComPtr<T> / BStr
#endif

namespace {

// Strip pipe/newline/CR from a value echoed back into the pipe-delimited
// protocol so a hostile action string cannot inject synthetic fields or rows.
// Platform-agnostic; used by the unknown-action error paths on every platform.
std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    }
    return out;
}

#ifdef _WIN32

constexpr const wchar_t* kTerminalServerKey = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
constexpr const wchar_t* kDenyValueName = L"fDenyTSConnections";
// Locale-independent indirect string for the built-in "Remote Desktop"
// firewall rule group (resolved by Windows from FirewallAPI.dll).
constexpr const wchar_t* kRdpFirewallGroup = L"@FirewallAPI.dll,-28752";

// Mirrored in tests/unit/test_new_plugins.cpp (validation-mirror pattern —
// keep the two copies in sync). Kept inside #ifdef _WIN32 because its only
// caller (do_set_state) is Windows-only; on Linux/macOS it would be an
// uncalled static function and trip -Wunused-function under warning_level=3.
bool is_valid_rdp_state(std::string_view state) {
    return state == "enable" || state == "disable";
}

using yuzu::shared::win::BStr;
using yuzu::shared::win::ComInit;
using yuzu::shared::win::ComPtr;

/// RAII owner for SC_HANDLE (service control manager / service handles).
class ScHandle {
public:
    explicit ScHandle(SC_HANDLE h) : h_(h) {}
    ~ScHandle() {
        if (h_) CloseServiceHandle(h_);
    }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    SC_HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    SC_HANDLE h_;
};

/// RAII owner for an HKEY (RegCloseKey on scope exit). `put()` yields the
/// out-param for RegCreateKeyExW/RegOpenKeyExW.
class RegKey {
public:
    RegKey() = default;
    ~RegKey() {
        if (h_) RegCloseKey(h_);
    }
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    PHKEY put() { return &h_; }
    HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    HKEY h_ = nullptr;
};

/// Write fDenyTSConnections. Returns ERROR_SUCCESS or the Win32 error.
LONG set_deny_ts_connections(DWORD deny) {
    RegKey key;
    // OPEN (do not create) the Terminal Server key — it always exists on Windows;
    // a security gate must fail rather than fabricate the key if it is absent.
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kTerminalServerKey, 0, KEY_SET_VALUE, key.put());
    if (rc != ERROR_SUCCESS) return rc;
    return RegSetValueExW(key.get(), kDenyValueName, 0, REG_DWORD,
                          reinterpret_cast<const BYTE*>(&deny), sizeof(deny));
}

/// Read fDenyTSConnections. Returns ERROR_SUCCESS or the Win32 error.
LONG get_deny_ts_connections(DWORD& deny) {
    DWORD size = sizeof(deny);
    return RegGetValueW(HKEY_LOCAL_MACHINE, kTerminalServerKey, kDenyValueName, RRF_RT_REG_DWORD,
                        nullptr, &deny, &size);
}

/// Acquire INetFwPolicy2 into an owning ComPtr (only inside a live ComInit).
HRESULT get_fw_policy(ComPtr<INetFwPolicy2>& policy) {
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwPolicy2), reinterpret_cast<void**>(policy.put()));
}

/// Enable/disable the Remote Desktop rule group across all profiles.
HRESULT set_rdp_firewall_group(bool enable) {
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) return hr;
    BStr group{kRdpFirewallGroup};
    if (!group) return E_OUTOFMEMORY;
    return policy->EnableRuleGroup(NET_FW_PROFILE2_ALL, group.get(),
                                   enable ? VARIANT_TRUE : VARIANT_FALSE);
}

/// Query whether the Remote Desktop rule group is enabled (all profiles).
HRESULT get_rdp_firewall_group(bool& enabled) {
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) return hr;
    BStr group{kRdpFirewallGroup};
    if (!group) return E_OUTOFMEMORY;
    VARIANT_BOOL on = VARIANT_FALSE;
    hr = policy->IsRuleGroupEnabled(NET_FW_PROFILE2_ALL, group.get(), &on);
    enabled = (on != VARIANT_FALSE);
    return hr;
}

// Classify an INetFwPolicy2 EnableRuleGroup/IsRuleGroupEnabled HRESULT.
// CRITICAL: these return S_FALSE — which PASSES SUCCEEDED() — when the rule
// group does NOT exist (e.g. a hardened image without the built-in Remote
// Desktop group). Treating that as success is a fail-safe inversion: an
// enable becomes a silent no-op reported "ok", and a status read reports the
// gate "disabled/confirmed" when it was actually unreadable. So S_OK alone is
// success; S_FALSE is "group not found" (gate UNKNOWN, never confirmed); any
// other HRESULT is an error. Pure + mirrored in test_new_plugins.cpp.
enum class FwResult { Ok, GroupNotFound, Error };
FwResult classify_fw_hr(HRESULT hr) {
    if (hr == S_OK) return FwResult::Ok;
    if (hr == S_FALSE) return FwResult::GroupNotFound;
    return FwResult::Error;
}

/// Query TermService state. Returns ERROR_SUCCESS or the Win32 error.
LONG get_term_service_state(DWORD& state) {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return static_cast<LONG>(GetLastError());
    ScHandle svc{OpenServiceW(scm.get(), L"TermService", SERVICE_QUERY_STATUS)};
    if (!svc) return static_cast<LONG>(GetLastError());
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
        return static_cast<LONG>(GetLastError());
    }
    state = ssp.dwCurrentState;
    return ERROR_SUCCESS;
}

/// Start TermService and wait (bounded) until it is actually SERVICE_RUNNING.
/// StartServiceW returns once the service's main thread is created — normally at
/// SERVICE_START_PENDING — so a dispatched start is NOT a confirmed running
/// service (and may still fail initialisation). Returns ERROR_SUCCESS only on a
/// confirmed RUNNING state; ERROR_SERVICE_REQUEST_TIMEOUT if still pending after
/// the deadline; ERROR_SERVICE_NOT_ACTIVE if it left the pending/running set; or
/// the Win32 error.
LONG start_term_service() {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return static_cast<LONG>(GetLastError());
    ScHandle svc{
        OpenServiceW(scm.get(), L"TermService", SERVICE_START | SERVICE_QUERY_STATUS)};
    if (!svc) return static_cast<LONG>(GetLastError());

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        const LONG err = static_cast<LONG>(GetLastError());
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
            return err;
    }
    // Poll to a confirmed RUNNING state (bounded ~10s).
    constexpr int kMaxWaitMs = 10000;
    constexpr int kPollMs = 250;
    for (int waited = 0; waited <= kMaxWaitMs; waited += kPollMs) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed))
            return static_cast<LONG>(GetLastError());
        if (ssp.dwCurrentState == SERVICE_RUNNING)
            return ERROR_SUCCESS;
        if (ssp.dwCurrentState != SERVICE_START_PENDING)
            return ERROR_SERVICE_NOT_ACTIVE; // stopped/paused unexpectedly
        Sleep(kPollMs);
    }
    return ERROR_SERVICE_REQUEST_TIMEOUT;
}

const char* service_state_name(DWORD state) {
    switch (state) {
        case SERVICE_RUNNING:          return "running";
        case SERVICE_START_PENDING:    return "start_pending";
        case SERVICE_STOPPED:          return "stopped";
        case SERVICE_STOP_PENDING:     return "stop_pending";
        case SERVICE_PAUSED:           return "paused";
        case SERVICE_PAUSE_PENDING:    return "pause_pending";
        case SERVICE_CONTINUE_PENDING: return "continue_pending";
        default:                       return "unknown";
    }
}

// Pure RDP verdict derivation, taking only the three gate outcomes as bools so
// it is unit-testable cross-platform (mirrored in test_new_plugins.cpp). Returns
// "on" only when every gate is READABLE and OPEN; "unknown" when any gate could
// not be read (never report "off" on missing data — a security-critical "is
// remote access open?" check must distinguish "confirmed closed" from "couldn't
// tell"); "off" when all gates are readable but at least one is closed.
// Kept inside #ifdef _WIN32 (its only caller, do_status, is Windows-only) to
// avoid -Wunused-function on Linux/macOS.
const char* derive_rdp_verdict(bool deny_known, bool deny_allows, bool fw_known,
                               bool fw_enabled, bool svc_known, bool svc_running) {
    if (!deny_known || !fw_known || !svc_known)
        return "unknown";
    return (deny_allows && fw_enabled && svc_running) ? "on" : "off";
}
#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows-only, entirely native: the registry (RegSetValueExW/
// RegGetValueW), the Windows Firewall via INetFwPolicy2 COM, and the
// Service Control Manager (StartServiceW/QueryServiceStatusEx) — zero
// subprocesses (rung 1). Linux/macOS have no implementation at all: both
// actions on both platforms return the honest "rdp_control|unsupported|..."
// sentinel without attempting anything (there is no macOS/Linux equivalent
// surface this plugin targets — see the file header comment).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "set_state",
        /* .linux_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Win32 registry + INetFwPolicy2 COM + SCM", nullptr},
    },
    {
        /* .action      = */ "status",
        /* .linux_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "Win32 registry + INetFwPolicy2 COM + SCM", nullptr},
    },
};

} // namespace

class RdpControlPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "rdp_control"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Remote Desktop control — enable/disable RDP (registry + firewall + TermService)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"set_state", "status", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext&) override { return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        (void)params;
        // Validate against the full known action set FIRST, independent of
        // platform support, so a misspelled/unknown action is never silently
        // recorded as terminal SUCCESS.
        if (action != "set_state" && action != "status") {
            ctx.write_output(std::format("error|unknown action: {}", sanitize_field(action)));
            return 1;
        }

#if defined(__APPLE__)
        // macOS-specific honest sentinel (points at the real macOS alternative).
        ctx.write_output("rdp_control|unsupported|Windows Remote Desktop has no macOS equivalent; use Screen Sharing / com.apple.screensharing");
#else
        // Linux/other: platform-neutral honest sentinel — do NOT name macOS
        // tools (Screen Sharing / com.apple.screensharing) on a Linux agent.
        ctx.write_output("rdp_control|unsupported|Windows Remote Desktop is not available on this platform");
#endif
        // set_state is a STATE-CHANGING security-control action (enable/
        // disable remote access). On non-Windows it never touches anything,
        // so reporting rc=0 (terminal SUCCESS) would be a false success for
        // an RDP posture change that did not happen (BR-03) -- exactly the
        // kind of false "security control changed" report a ServiceNow
        // change-window caller must not receive. "status" is a read-only
        // action honestly reporting "unsupported" and may keep rc=0.
        return (action == "set_state") ? 1 : 0;
#else
        if (action == "set_state") return do_set_state(ctx, params);
        if (action == "status")    return do_status(ctx);
        ctx.write_output(std::format("error|unknown action: {}", sanitize_field(action)));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_set_state(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto state = params.get("state");
        if (!is_valid_rdp_state(state)) {
            ctx.write_output("error|invalid state (use enable or disable)");
            return 1;
        }
        // Serialize the multi-step transition (registry -> firewall -> service):
        // a retry-enable racing a window-close disable on the same agent must not
        // interleave so a stale enable's registry write lands last and leaves RDP
        // reachable after the disable reported overall|ok. Defence-in-depth; the
        // wire-level per-device guarantee is a platform follow-up.
        static std::mutex set_state_mu;
        std::lock_guard<std::mutex> set_state_lock(set_state_mu);

        const bool enable = (state == "enable");
        bool all_ok = true;

        // 1. Registry — fDenyTSConnections (0 = allow, 1 = deny).
        if (LONG rc = set_deny_ts_connections(enable ? 0 : 1); rc == ERROR_SUCCESS) {
            ctx.write_output("reg_status|ok");
        } else {
            // ERROR_ACCESS_DENIED (5) here means the agent is not elevated.
            ctx.write_output(std::format("reg_status|error:{}", rc));
            all_ok = false;
        }

        // 2. Firewall — the Remote Desktop rule group, all profiles. S_FALSE
        //    (group absent) passes SUCCEEDED but is a silent no-op — classify it
        //    as group_not_found and fail the step, never report ok (H2).
        {
            ComInit com;
            if (!com.ok()) {
                ctx.write_output("firewall_status|error:com_init");
                all_ok = false;
            } else {
                HRESULT hr = set_rdp_firewall_group(enable);
                switch (classify_fw_hr(hr)) {
                    case FwResult::Ok:
                        ctx.write_output("firewall_status|ok");
                        break;
                    case FwResult::GroupNotFound:
                        ctx.write_output("firewall_status|error:group_not_found");
                        all_ok = false;
                        break;
                    case FwResult::Error:
                        ctx.write_output(std::format("firewall_status|error:0x{:08x}",
                                                     static_cast<uint32_t>(hr)));
                        all_ok = false;
                        break;
                }
            }
        }

        // 3. Service — ensure TermService is RUNNING on enable (start + poll); on
        //    disable the registry + firewall gates block new connections, so the
        //    service is deliberately left alone (and enforce-stopping security-
        //    adjacent services is the pattern the Guardian denylist exists to
        //    prevent).
        if (enable) {
            LONG rc = start_term_service();
            if (rc == ERROR_SUCCESS) {
                ctx.write_output("service_status|running");
            } else {
                ctx.write_output(std::format("service_status|error:{}", rc));
                all_ok = false;
            }
        } else {
            ctx.write_output("service_status|untouched");
        }

        ctx.write_output(std::format("overall|{}", all_ok ? "ok" : "error"));
        return all_ok ? 0 : 1;
    }

    int do_status(yuzu::CommandContext& ctx) {
        bool all_known = true;

        DWORD deny = 1;
        bool deny_known = false;
        if (LONG rc = get_deny_ts_connections(deny); rc == ERROR_SUCCESS) {
            deny_known = true;
            ctx.write_output(std::format("deny_ts_connections|{}", deny));
        } else {
            ctx.write_output(std::format("deny_ts_connections|error:{}", rc));
            all_known = false;
        }

        bool fw_enabled = false;
        bool fw_known = false;
        {
            ComInit com;
            HRESULT hr = S_OK;
            if (!com.ok()) {
                ctx.write_output("firewall_group|error:com_init");
                all_known = false;
            } else if (hr = get_rdp_firewall_group(fw_enabled); classify_fw_hr(hr) == FwResult::Ok) {
                fw_known = true;
                ctx.write_output(
                    std::format("firewall_group|{}", fw_enabled ? "enabled" : "disabled"));
            } else if (classify_fw_hr(hr) == FwResult::GroupNotFound) {
                // Group absent: the gate is UNREADABLE, not "confirmed disabled".
                // Leave fw_known=false so the verdict derives "unknown", never
                // "off" (H2 — preserves the fail-safe contract).
                ctx.write_output("firewall_group|group_not_found");
                all_known = false;
            } else {
                ctx.write_output(
                    std::format("firewall_group|error:0x{:08x}", static_cast<uint32_t>(hr)));
                all_known = false;
            }
        }

        DWORD svc_state = 0;
        bool svc_known = false;
        if (LONG rc = get_term_service_state(svc_state); rc == ERROR_SUCCESS) {
            svc_known = true;
            ctx.write_output(std::format("term_service|{}", service_state_name(svc_state)));
        } else {
            ctx.write_output(std::format("term_service|error:{}", rc));
            all_known = false;
        }

        // Derived verdict. "on" only when every gate is readable and open;
        // "unknown" when any gate could not be read (a caller filtering on the
        // rdp row alone must not read a failed read as "off"/safe); "off" when
        // all gates are readable but at least one is closed. The non-zero exit
        // code also flags any unreadable gate for callers keying on status.
        const char* verdict = derive_rdp_verdict(deny_known, deny == 0, fw_known, fw_enabled,
                                                 svc_known, svc_state == SERVICE_RUNNING);
        ctx.write_output(std::format("rdp|{}", verdict));
        return all_known ? 0 : 1;
    }
#endif
};

YUZU_PLUGIN_EXPORT(RdpControlPlugin)
