/**
 * sccm_plugin.cpp — SCCM/ConfigMgr client info plugin for Yuzu (Windows-only)
 *
 * Actions:
 *   "client_version" — Check if SCCM client is installed and report version.
 *   "site"           — Get SCCM site assignment info.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   installed|true/false
 *   version|X.Y.Z
 *   site_code|ABC
 *   management_point|hostname
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (BR-07)

#include "sccm_parsers.hpp" // pure select_authority_subkey/interpret_sms_invoke helpers

#include <format>
#include <optional>
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

#include <objbase.h> // CoInitializeEx / CoCreateInstance / CLSIDFromProgID
#include <oleauto.h> // IDispatch / DISPPARAMS / VARIANT / VariantInit / VariantClear

#include <win_com.hpp>        // shared yuzu::shared::win::ComInit/ComPtr
#include <win_reg_handle.hpp> // shared yuzu::win::RegKey (PR1.7)
#include <win_sc_handle.hpp>  // shared yuzu::win::ScHandle (#1822)
#include <win_str.hpp>        // shared yuzu::win wide<->UTF-8 helpers (#1681)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

namespace {

#ifdef _WIN32

// ── native acquisition helpers (ADR-3002 rung 1 — no subprocess) ───────────
//
// Everything below replaces the retired `sc query ccmexec` text parse and
// the two PowerShell `Microsoft.SMS.Client` ComObject shell-outs with
// in-process Win32/COM calls. See docs/agent-spawn-sink-manifest.md — 0
// spawn sites remain in this plugin.

std::string read_registry_string(HKEY root, const char* subkey, const char* value) {
    // Reg*W for UTF-8-correct values (#1662 / #1682); the SCCM version string is
    // ASCII today, converted for consistency with the sibling inventory plugins.
    // Widen the names BEFORE opening so the only operation between open and
    // RegCloseKey is the non-allocating RegQueryValueExW; the allocating
    // reg_sz_to_utf8 runs AFTER the handle is closed, so a std::bad_alloc cannot
    // leak the HKEY (#1682 Gate-4 R1).
    const std::wstring wsubkey = yuzu::win::to_wide(subkey);
    const std::wstring wvalue = yuzu::win::to_wide(value);
    HKEY hkey{};
    if (RegOpenKeyExW(root, wsubkey.c_str(), 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return {};
    }
    wchar_t buf[512]{};
    DWORD size = sizeof(buf); // size in BYTES; buf written as bytes, read back through
    DWORD type = 0;           // its declared wchar_t lvalue (LPBYTE is alignment-1)
    const LONG rc = RegQueryValueExW(hkey, wvalue.c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hkey); // closed before the allocating convert -- no leak window
    if (rc == ERROR_SUCCESS && type == REG_SZ && size >= sizeof(wchar_t)) {
        return yuzu::win::reg_sz_to_utf8(buf, size);
    }
    return {};
}

// ── pure decision logic ─────────────────────────────────────────────────────
//
// classify_service_status below is Windows-typed (DWORD, SERVICE_RUNNING/
// SERVICE_STOPPED), so it stays inside this #ifdef block rather than
// hoisted to a shared *_parsers.hpp: its only caller is Windows-only, so an
// uncalled copy on macOS/Linux would trip -Wunused-function at
// warning_level=3 (same reasoning as rdp_control_plugin.cpp's
// is_valid_rdp_state). It is Mirrored — kept in sync, not shared — in
// tests/unit/test_sccm_parsers.cpp using plain types, the same pattern
// rdp_control_plugin.cpp's classify_fw_hr uses with test_new_plugins.cpp.
// select_authority_subkey/interpret_sms_invoke have no such Windows-type
// dependency, so they live in sccm_parsers.hpp instead (below) and are
// genuinely shared with the test file, not mirrored.

// service_status|<value> classifier for the client_version action's native
// SCM query, replacing the retired `sc query ccmexec` text parse. Preserves
// the same four outcomes that parse produced (running/stopped/exists/
// not_found) and adds an honest 'unavailable' for failure modes a
// garbled/empty `sc query` blob used to silently fold into not_found: the
// SCM connect itself failing, and an OpenServiceW failure that ISN'T "the
// service doesn't exist" (e.g. access denied on a hardened host).
enum class SvcOpenResult { scm_unavailable, not_found, open_failed, opened };

std::string_view classify_service_status(SvcOpenResult open_result, bool query_ok, DWORD state) {
    switch (open_result) {
    case SvcOpenResult::scm_unavailable:
    case SvcOpenResult::open_failed:
        return "unavailable";
    case SvcOpenResult::not_found:
        return "not_found";
    case SvcOpenResult::opened:
        break;
    }
    if (!query_ok)
        return "unavailable";
    if (state == SERVICE_RUNNING)
        return "running";
    if (state == SERVICE_STOPPED)
        return "stopped";
    return "exists"; // any other live state (pending/paused) -- matches the
                      // old text parse's fallback when the service name
                      // appeared but neither RUNNING nor STOPPED did
}

// select_authority_subkey / interpret_sms_invoke (+ SmsInvokeOutcome /
// SmsInvokeResult) now live in sccm_parsers.hpp -- both are portable-typed
// with no Windows dependency, so unlike classify_service_status above they
// are extracted rather than mirrored, and test_sccm_parsers.cpp includes
// this same header instead of keeping its own copy in sync by hand.
using yuzu::sccm::interpret_sms_invoke;
using yuzu::sccm::select_authority_subkey;
using yuzu::sccm::SmsInvokeOutcome;
using yuzu::sccm::SmsInvokeResult;

// ── SCM query (client_version's service_status field) ──────────────────────

// Enumerates the subkey names directly under
// HKLM\SOFTWARE\Microsoft\CCM\Authority\ (each one is normally "SMS:<site>").
// Returns an empty vector if the Authority key itself doesn't exist -- no
// distinct error is surfaced; select_authority_subkey treats "found
// nothing" and "key absent" identically, both mean "not available this way".
std::vector<std::string> enumerate_authority_subkeys() {
    using yuzu::win::RegKey;
    const std::wstring wsubkey = yuzu::win::to_wide("SOFTWARE\\Microsoft\\CCM\\Authority");
    RegKey key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wsubkey.c_str(), 0, KEY_READ, key.put()) !=
        ERROR_SUCCESS) {
        return {};
    }
    std::vector<std::string> names;
    for (DWORD index = 0;; ++index) {
        wchar_t name[256];
        DWORD name_len = 256; // capacity in WCHARs, not bytes (RegEnumKeyExW contract)
        const LONG rc = RegEnumKeyExW(key.get(), index, name, &name_len, nullptr, nullptr,
                                      nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS)
            break; // stop rather than skip/loop on an unexpected error (e.g.
                    // ERROR_MORE_DATA on a pathological >255-char name) --
                    // an honest partial enumeration, never a silent retry
        names.push_back(yuzu::win::from_wide(name, static_cast<int>(name_len)));
    }
    return names;
}

// Native SCM query for the CcmExec service (replaces the retired
// `sc query ccmexec 2>nul` text parse). See classify_service_status for the
// outcome mapping.
std::string_view query_ccmexec_service_status() {
    // yuzu::win::ScHandle (win_sc_handle.hpp) is default-construct + reset(),
    // NOT a converting constructor from SC_HANDLE -- that ctor only exists on
    // rdp_control_plugin.cpp's own LOCAL copy of this class, not the shared one.
    using yuzu::win::ScHandle;
    ScHandle scm;
    scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm)
        return classify_service_status(SvcOpenResult::scm_unavailable, false, 0);

    ScHandle svc;
    svc.reset(OpenServiceW(scm.get(), L"ccmexec", SERVICE_QUERY_STATUS));
    if (!svc) {
        const DWORD err = GetLastError();
        return classify_service_status(err == ERROR_SERVICE_DOES_NOT_EXIST
                                            ? SvcOpenResult::not_found
                                            : SvcOpenResult::open_failed,
                                        false, 0);
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
        return classify_service_status(SvcOpenResult::opened, false, 0);
    }
    return classify_service_status(SvcOpenResult::opened, true, ssp.dwCurrentState);
}

// ── Microsoft.SMS.Client late-bound COM (site's site_code/management_point
//    fallbacks) ────────────────────────────────────────────────────────────

// ComInit/ComPtr come from the shared agents/shared/win_com.hpp
// (yuzu::shared::win) rather than a local clone -- it also tolerates
// RPC_E_CHANGED_MODE (COM already initialised in a different apartment by an
// earlier plugin on the same pool thread), which this file's earlier local
// copy did not.
using yuzu::shared::win::ComInit;
using yuzu::shared::win::ComPtr;

// RAII for the VARIANT Invoke() writes its result into (clone of
// licensing_wmi.cpp's VariantGuard shape). VariantInit in the ctor is
// load-bearing: the dtor VariantClears unconditionally, so the VARIANT must
// be a valid VT_EMPTY even on an Invoke() that fails and never writes it.
struct VariantGuard {
    VARIANT v;
    VariantGuard() { VariantInit(&v); }
    ~VariantGuard() { VariantClear(&v); }
    VariantGuard(const VariantGuard&) = delete;
    VariantGuard& operator=(const VariantGuard&) = delete;
};

// GetIDsOfNames/Invoke's "reserved" riid param, documented as "must be
// IID_NULL" -- a zero GUID, byte-identical to the SDK's IID_NULL constant.
// Defined locally rather than linking uuid.lib for one symbol.
constexpr IID kIidNull{};

// Attempts one late-bound Microsoft.SMS.Client method call with no
// arguments (GetAssignedSite / GetCurrentManagementPoint), returning the
// interpreted result via interpret_sms_invoke -- the single place that
// decides whether the round trip counts as a success. Every failure mode
// (CLSIDFromProgID -- the SCCM client isn't installed, the EXPECTED case on
// any non-managed host including this dev machine and the-rig;
// CoCreateInstance; GetIDsOfNames; Invoke) funnels through the same
// `failed` outcome.
//
// VERIFICATION GAP: the success path (a live SCCM client actually
// answering) rests on code review + the mocked unit test of
// interpret_sms_invoke only -- it has never been exercised against a real
// SCCM client, and none is available on this dev machine or on the-rig. The
// not-installed path (CLSIDFromProgID failing) IS genuinely exercised by
// this reasoning on any such host and is the path this implementation is
// most confident in.
SmsInvokeResult call_sms_client_method(const wchar_t* method) {
    CLSID clsid;
    if (FAILED(CLSIDFromProgID(L"Microsoft.SMS.Client", &clsid)))
        return interpret_sms_invoke(false, false, {});

    ComPtr<IDispatch> disp;
    if (FAILED(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDispatch),
                                reinterpret_cast<void**>(disp.put()))) ||
        !disp) {
        return interpret_sms_invoke(false, false, {});
    }

    LPOLESTR name = const_cast<LPOLESTR>(method);
    DISPID dispid;
    if (FAILED(disp->GetIDsOfNames(kIidNull, &name, 1, LOCALE_USER_DEFAULT, &dispid)))
        return interpret_sms_invoke(false, false, {});

    DISPPARAMS params{};
    VariantGuard result;
    if (FAILED(disp->Invoke(dispid, kIidNull, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params,
                            &result.v, nullptr, nullptr))) {
        return interpret_sms_invoke(false, false, {});
    }

    const bool is_bstr = (result.v.vt == VT_BSTR);
    return interpret_sms_invoke(true, is_bstr,
                                is_bstr ? yuzu::win::from_wide(result.v.bstrVal) : std::string{});
}

#endif // _WIN32

// ── client_version action ──────────────────────────────────────────────────

int do_client_version(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // Check registry for SCCM client version
    auto version = read_registry_string(
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SMS\\Mobile Client", "ProductVersion");

    if (!version.empty()) {
        ctx.write_output("installed|true");
        ctx.write_output(std::format("version|{}", version));
    } else {
        ctx.write_output("installed|false");
        ctx.write_output("version|-");
    }

    // Also check if CcmExec service exists — native SCM query (rung 1)
    // replaces the retired `sc query ccmexec` text parse.
    ctx.write_output(std::format("service_status|{}", query_ccmexec_service_status()));

#elif defined(__APPLE__)
    // macOS-specific honest sentinel (points at the real macOS alternative).
    ctx.write_output("sccm|unsupported|Windows SCCM/ConfigMgr client has no macOS equivalent; use Jamf/MDM for macOS device management");
#else
    // Linux/other: platform-neutral honest sentinel — do NOT name macOS
    // tools on a Linux agent. Preserves the pre-batch Linux output shape.
    ctx.write_output("installed|false");
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── site action ────────────────────────────────────────────────────────────

int do_site(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // Try registry first
    auto site_code = read_registry_string(
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SMS\\Mobile Client", "AssignedSiteCode");

    if (site_code.empty()) {
        // Try alternate location
        site_code = read_registry_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCM",
                                         "AssignedSiteCode");
    }

    // COM is only needed past this point (the SMS Client fallback for
    // site_code just below, and possibly for management_point further
    // down) -- lazily initialised so a machine whose registry already
    // answers both fields never pays for a COM apartment init/uninit.
    // do_client_version's SCM/registry path never touches COM at all.
    std::optional<ComInit> com_init;
    auto sms_client_call = [&](const wchar_t* method) -> SmsInvokeResult {
        if (!com_init)
            com_init.emplace();
        if (!com_init->ok())
            return SmsInvokeResult{SmsInvokeOutcome::failed, {}};
        return call_sms_client_method(method);
    };

    if (!site_code.empty()) {
        ctx.write_output(std::format("site_code|{}", yuzu::util::safe_output_field(site_code)));
    } else {
        // Native late-bound COM (rung 1) replaces the retired PowerShell
        // `(New-Object -ComObject Microsoft.SMS.Client).GetAssignedSite()`.
        auto r = sms_client_call(L"GetAssignedSite");
        if (r.outcome == SmsInvokeOutcome::ok) {
            // Store it, not just print it -- the authority-subkey selection
            // below needs the real site code, not the still-empty registry
            // lookup's value (was silently discarded, so selection always
            // fell back to whichever SMS:* subkey enumerated first).
            site_code = std::move(r.value);
            ctx.write_output(std::format("site_code|{}", yuzu::util::safe_output_field(site_code)));
        } else {
            ctx.write_output("site_code|not_configured");
        }
    }

    // Get management point
    auto mp = read_registry_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCM", "Authority");
    if (mp.empty()) {
        // Genuinely enumerate HKLM\SOFTWARE\Microsoft\CCM\Authority\'s
        // subkeys and pick the real "SMS:<sitecode>" one -- the previous
        // fallback matched a literal (never-substituted) "SMS:{}" subkey
        // name and so was permanently dead. See select_authority_subkey.
        const auto subkeys = enumerate_authority_subkeys();
        if (const auto picked = select_authority_subkey(subkeys, site_code)) {
            mp = read_registry_string(
                HKEY_LOCAL_MACHINE,
                ("SOFTWARE\\Microsoft\\CCM\\Authority\\" + *picked).c_str(),
                "CurrentManagementPoint");
        }
    }
    if (mp.empty()) {
        // Native late-bound COM (rung 1) replaces the retired PowerShell
        // `(New-Object -ComObject Microsoft.SMS.Client).GetCurrentManagementPoint()`.
        auto r = sms_client_call(L"GetCurrentManagementPoint");
        if (r.outcome == SmsInvokeOutcome::ok)
            mp = r.value;
    }
    if (!mp.empty()) {
        ctx.write_output(std::format("management_point|{}", yuzu::util::safe_output_field(mp)));
    } else {
        ctx.write_output("management_point|unknown");
    }

#elif defined(__APPLE__)
    // macOS-specific honest sentinel (points at the real macOS alternative).
    ctx.write_output("sccm|unsupported|Windows SCCM/ConfigMgr client has no macOS equivalent; use Jamf/MDM for macOS device management");
#else
    // Linux/other: platform-neutral honest sentinel — do NOT name macOS
    // tools on a Linux agent. Preserves the pre-batch Linux output shape.
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: registry reads plus native SCM (client_version) / native
// late-bound COM IDispatch (site) -- all in-process, zero subprocesses, all
// rung 1 (ADR-3002). This plugin migrated off its three raw popen spawn
// sites (`sc query`, two PowerShell ComObject calls) — see
// docs/agent-spawn-sink-manifest.md.
// macos/linux: no SCCM/ConfigMgr equivalent -- the code returns an explicit
// honest sentinel on both ("no macOS equivalent" / "platform not
// supported"), never a fabricated result.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"client_version",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "registry+scm", nullptr}},
    {"site",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "registry+com_dispatch", nullptr}},
};

} // namespace

class SccmPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "sccm"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports SCCM/ConfigMgr client status, version, and site assignment";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"client_version", "site", nullptr};
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
        if (action == "client_version")
            return do_client_version(ctx);
        if (action == "site")
            return do_site(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SccmPlugin)
