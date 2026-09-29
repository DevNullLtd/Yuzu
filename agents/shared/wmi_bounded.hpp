// wmi_bounded.hpp -- shared bounded WMI query/method-call helpers.
//
// Hoisted from agents/plugins/license_scan/src/licensing_wmi.{hpp,cpp}
// (roadmap C-8) -- that header's own comment said it was "shaped for
// extraction... ZERO plugin-specific dependencies", anticipating this move.
//
// hardware_plugin.cpp's former file-private WmiQuery and the wmi plugin
// both had an unbounded `enumerator->Next(WBEM_INFINITE, ...)` call site.
// #3368 migrated the wmi plugin onto this helper; #3404 migrated
// hardware_plugin.cpp onto it separately. This helper exists to stop
// that unbounded-Next pattern propagating.
// NEVER call Next(WBEM_INFINITE, ...); always bound both the per-Next wait
// and the overall enumeration under BoundedQueryOptions.
//
// All-inline, header-only (matching agents/shared/win_str.hpp's pattern) --
// originally shipped as a paired wmi_bounded.{hpp,cpp}, which put a compiled
// translation unit in agents/shared/ (header-only-leaves-ONLY violation,
// docs/cpp-conventions.md). Folded into one header so every plugin that
// includes it compiles its own private inline copy, same build-isolation
// rationale as win_com.hpp / win_str.hpp: no exported symbol crosses the
// plugin ABI boundary.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere.

#ifndef YUZU_SHARED_WMI_BOUNDED_HPP
#define YUZU_SHARED_WMI_BOUNDED_HPP

#ifdef _WIN32

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <comdef.h>
#include <wbemidl.h>

#include <win_com.hpp> // shared yuzu::shared::win ComInit / ComPtr<T> / BStr
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <utility>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace yuzu::shared::wmi {

struct BoundedQueryOptions {
    uint32_t next_timeout_ms = 10000;          // per-Next() wait bound (each retry)
    size_t row_cap = 512;                      // stop and mark truncated past this many rows
    uint64_t enumeration_deadline_ms = 60000;  // whole-enumeration bound across all retries
};

/// One result row: non-system property name -> stringified value
/// (VT_NULL / VT_EMPTY properties are omitted).
using WmiRow = std::map<std::string, std::string>;

struct BoundedQueryResult {
    std::vector<WmiRow> rows;
    bool truncated = false;  // row_cap reached — enumeration did NOT complete
    // Stable error token when the call failed; absent on success. Never a
    // silent empty result on failure — see the token list below.
    //   com_init_failed | wbem_locator_failed | wmi_connect_failed_<hr> |
    //   wmi_query_failed_<hr> | wmi_next_timeout | wmi_deadline_exceeded |
    //   wmi_next_failed_<hr>
    std::optional<std::string> error;
    // Rows read successfully BEFORE the failure that set `error` (the rows themselves are cleared
    // on failure); 0 for a failure before the first row and for a result with no error. The
    // wmi_next_failed_<hr> token carries no iteration index, so this is how a caller tells a
    // failure at the FIRST Next() (where a missing class surfaces) from one after data came back.
    size_t rows_before_error = 0;
};

// Named error-token constants — the single source of truth both production
// call sites and tests reference, so a token string can never drift between
// what's actually emitted and what a test pins (governance Gate 3
// quality-engineer: the prior "stable tokens" test constructed its own
// literal array, disconnected from these call sites, so a production string
// edit here wouldn't have failed it).
namespace error_tokens {
inline constexpr const char* kComInitFailed = "com_init_failed";
inline constexpr const char* kWbemLocatorFailed = "wbem_locator_failed";
inline constexpr const char* kWmiConnectFailedPrefix = "wmi_connect_failed_";
inline constexpr const char* kWmiProxyBlanketFailedPrefix = "wmi_proxy_blanket_failed_";
inline constexpr const char* kWmiQueryFailedPrefix = "wmi_query_failed_";
inline constexpr const char* kWmiQueryFailedNoInSignature = "wmi_query_failed_no_in_signature";
inline constexpr const char* kWmiDeadlineExceeded = "wmi_deadline_exceeded";
inline constexpr const char* kWmiNextFailedPrefix = "wmi_next_failed_";
inline constexpr const char* kWmiPutParamFailedPrefix = "wmi_put_param_failed_";
} // namespace error_tokens

namespace detail {

inline std::string hr_hex(HRESULT hr) {
    static constexpr char hexc[] = "0123456789abcdef";
    std::string out = "0x";
    for (int shift = 28; shift >= 0; shift -= 4)
        out += hexc[(static_cast<unsigned long>(hr) >> shift) & 0xF];
    return out;
}

// Clamp a per-call WMI wait to whatever remains of the overall enumeration
// deadline, so a single Next()/GetResultObject() call can never push total
// elapsed time past opts.enumeration_deadline_ms by more than a scheduling
// sliver. Pure arithmetic, no COM dependency, so it's independently
// unit-testable without a live provider (the bug this fixes: passing
// next_timeout_ms unclamped let a call begun with little budget left block
// for the FULL next_timeout_ms, overrunning the documented deadline by up to
// one full per-call timeout).
inline long clamp_call_timeout_ms(uint32_t next_timeout_ms, uint64_t enumeration_deadline_ms,
                                  uint64_t elapsed_ms) {
    const uint64_t remaining_ms =
        elapsed_ms >= enumeration_deadline_ms ? 0 : enumeration_deadline_ms - elapsed_ms;
    const uint64_t clamped = remaining_ms < next_timeout_ms ? remaining_ms : next_timeout_ms;
    return static_cast<long>(clamped);
}

// RAII for the BSTR + VARIANT that IWbemClassObject::Next hands back — own
// the resource, free it on EVERY exit (a per-property allocation can throw
// mid-row via WmiRow::emplace).
struct BstrGuard {
    BSTR b = nullptr;
    BstrGuard() = default;
    ~BstrGuard() {
        if (b) SysFreeString(b);
    }
    BstrGuard(const BstrGuard&) = delete;
    BstrGuard& operator=(const BstrGuard&) = delete;
};

// VariantInit in the ctor is load-bearing: the destructor VariantClears
// unconditionally, so the VARIANT must be a valid VT_EMPTY even on a Next()
// call that fails and never writes it.
struct VariantGuard {
    VARIANT v;
    VariantGuard() { VariantInit(&v); }
    ~VariantGuard() { VariantClear(&v); }
    VariantGuard(const VariantGuard&) = delete;
    VariantGuard& operator=(const VariantGuard&) = delete;
};

inline std::string variant_to_string(const VARIANT& v) {
    switch (v.vt) {
    case VT_BSTR:
        return yuzu::win::from_wide(v.bstrVal);
    case VT_I4:
        return std::to_string(v.lVal);
    case VT_UI4:
        return std::to_string(v.ulVal);
    case VT_I2:
        return std::to_string(v.iVal);
    case VT_UI1:
        return std::to_string(static_cast<unsigned>(v.bVal));
    case VT_BOOL:
        return v.boolVal ? "true" : "false";
    case VT_R8:
        return std::to_string(v.dblVal);
    default:
        return {}; // VT_NULL / VT_EMPTY / exotic types: omitted by caller
    }
}

// Read every non-system property of `obj` into a WmiRow. Shared by the
// query row loop and exec_object_method's out-params extraction.
inline void extract_row(IWbemClassObject* obj, WmiRow& row) {
    obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
    while (true) {
        BstrGuard prop_name;
        VariantGuard prop_val;
        if (obj->Next(0, &prop_name.b, &prop_val.v, nullptr, nullptr) != WBEM_S_NO_ERROR)
            break;
        std::string value = variant_to_string(prop_val.v);
        if (!value.empty())
            row.emplace(yuzu::win::from_wide(prop_name.b), std::move(value));
    }
    obj->EndEnumeration();
}

// Bounded connect shared by both public entry points: ComInit + locator +
// ConnectServer(WBEM_FLAG_CONNECT_USE_MAX_WAIT — the WMI-sanctioned connect
// bound; ConnectServer has no millisecond knob) + CoSetProxyBlanket.
// `com` and `services` are out-params the caller keeps alive for the rest of
// its call; returns an empty string on success or a stable error token.
inline std::string connect_bounded(const std::wstring& wmi_namespace,
                                   yuzu::shared::win::ComInit& com,
                                   yuzu::shared::win::ComPtr<IWbemServices>& services) {
    if (!com.ok())
        return error_tokens::kComInitFailed;

    yuzu::shared::win::ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(locator.put()));
    if (FAILED(hr) || !locator)
        return error_tokens::kWbemLocatorFailed;

    hr = locator->ConnectServer(_bstr_t(wmi_namespace.c_str()), nullptr, nullptr, nullptr,
                                WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, services.put());
    if (FAILED(hr) || !services)
        return error_tokens::kWmiConnectFailedPrefix + hr_hex(hr);

    hr = CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr))
        return error_tokens::kWmiProxyBlanketFailedPrefix + hr_hex(hr);
    return {};
}

} // namespace detail

/// Run a WQL SELECT against `wmi_namespace` with bounded connect + bounded
/// semisynchronous enumeration. Never blocks unbounded: a wedged provider
/// surfaces as `error_tokens::kWmiDeadlineExceeded` after the configured
/// bounds instead of hanging the agent.
inline BoundedQueryResult run_bounded_wmi_query(const std::wstring& wmi_namespace,
                                                const std::wstring& wql,
                                                const BoundedQueryOptions& opts = {}) {
    using namespace detail;
    using yuzu::shared::win::ComInit;
    using yuzu::shared::win::ComPtr;

    BoundedQueryResult result;

    ComInit com;
    ComPtr<IWbemServices> services;
    if (std::string err = connect_bounded(wmi_namespace, com, services); !err.empty()) {
        result.error = std::move(err);
        return result;
    }

    // Semisynchronous enumeration (FORWARD_ONLY | RETURN_IMMEDIATELY) is what
    // makes the per-Next timeout real — a synchronous enumerator ignores it.
    ComPtr<IEnumWbemClassObject> enumerator;
    HRESULT hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql.c_str()),
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                                     enumerator.put());
    if (FAILED(hr) || !enumerator) {
        result.error = error_tokens::kWmiQueryFailedPrefix + hr_hex(hr);
        return result;
    }

    const ULONGLONG start_ticks = GetTickCount64();
    while (true) {
        if (result.rows.size() >= opts.row_cap) {
            // Row cap: stop reading. The enumeration did NOT complete, so the
            // caller must not treat this as a structurally-successful probe —
            // rows are returned for diagnostics.
            result.truncated = true;
            break;
        }
        // Whole-enumeration deadline, checked UNCONDITIONALLY at the top of
        // every iteration.
        const ULONGLONG elapsed = GetTickCount64() - start_ticks;
        if (elapsed >= opts.enumeration_deadline_ms) {
            result.error = error_tokens::kWmiDeadlineExceeded;
            result.rows_before_error = result.rows.size();
            result.rows.clear();
            return result;
        }
        // The per-call wait handed to Next() is clamped to whatever remains
        // of the overall deadline — never the raw next_timeout_ms — so a
        // single call can't itself carry total elapsed time past the
        // deadline (the bug this replaces: an unclamped next_timeout_ms
        // could overrun the deadline by up to one full per-call timeout).
        const long call_timeout_ms = clamp_call_timeout_ms(opts.next_timeout_ms,
                                                            opts.enumeration_deadline_ms, elapsed);
        IWbemClassObject* raw_obj = nullptr;
        ULONG count = 0;
        hr = enumerator->Next(call_timeout_ms, 1, &raw_obj, &count);
        if (hr == WBEM_S_FALSE && count == 0)
            break; // enumeration complete
        if (hr == WBEM_S_TIMEDOUT) {
            // Semisynchronous Next: WBEM_S_TIMEDOUT means "no object ready
            // yet — still working", not "wedged". The call itself was capped
            // to the remaining budget, so the top-of-loop deadline check on
            // the next iteration is what actually terminates a wedged
            // provider — retry unconditionally here.
            continue;
        }
        if (FAILED(hr) || count == 0 || !raw_obj) {
            result.error = error_tokens::kWmiNextFailedPrefix + hr_hex(hr);
            result.rows_before_error = result.rows.size();
            result.rows.clear();
            return result;
        }
        ComPtr<IWbemClassObject> obj;
        *obj.put() = raw_obj; // adopt ownership from Next()

        WmiRow row;
        extract_row(obj.get(), row);
        result.rows.push_back(std::move(row));
    }

    return result;
}

/// Call a WMI instance METHOD (not a property read) via ExecMethod, using
/// the same bounded-connect + semisynchronous-timeout shape as
/// run_bounded_wmi_query (IWbemCallResult::GetResultObject(timeout) on the
/// async ExecMethod path). `in_params` are set as BSTR (VT_BSTR) input
/// parameters on the method's in-signature instance. On success, `rows`
/// holds exactly one row: the method's out-parameters (including any
/// `ReturnValue`), stringified the same way as a query row.
///
/// No production caller today (governance-reviewed, dormant infrastructure).
/// This helper performs NO namespace/method/object_path allowlisting itself
/// -- unlike wmi_plugin.cpp's do_query/do_get_instance, which validate
/// `namespace` against a hardcoded allowlist and `wql` against a SELECT-only
/// gate before ever reaching run_bounded_wmi_query. Whoever wires the FIRST
/// caller of this function MUST add an equivalent floor (allowlist the
/// namespace and the set of callable methods) before accepting
/// `wmi_namespace`/`method`/`in_params` from any action parameter or other
/// untrusted input -- do not assume this helper enforces that for you.
inline BoundedQueryResult exec_object_method(const std::wstring& wmi_namespace,
                                             const std::wstring& object_path,
                                             const std::wstring& method,
                                             const std::map<std::wstring, std::wstring>& in_params,
                                             const BoundedQueryOptions& opts = {}) {
    using namespace detail;
    using yuzu::shared::win::ComInit;
    using yuzu::shared::win::ComPtr;

    BoundedQueryResult result;

    ComInit com;
    ComPtr<IWbemServices> services;
    if (std::string err = connect_bounded(wmi_namespace, com, services); !err.empty()) {
        result.error = std::move(err);
        return result;
    }

    // Build the in-params instance (if the method takes any) by cloning the
    // method's in-signature and Put()-ing each caller-supplied value as
    // VT_BSTR. A method with no in-signature (no parameters) skips this.
    ComPtr<IWbemClassObject> class_obj;
    ComPtr<IWbemClassObject> in_signature;
    ComPtr<IWbemClassObject> in_params_instance;
    HRESULT hr = services->GetObject(_bstr_t(object_path.c_str()), 0, nullptr, class_obj.put(), nullptr);
    if (FAILED(hr) || !class_obj) {
        result.error = error_tokens::kWmiQueryFailedPrefix + hr_hex(hr);
        return result;
    }
    hr = class_obj->GetMethod(method.c_str(), 0, in_signature.put(), nullptr);
    if (FAILED(hr) && !in_params.empty()) {
        // The caller supplied parameters but we couldn't get the in-signature
        // to set them on — proceeding would silently call the method with
        // none of the caller's inputs. (A method with no in-signature can
        // legitimately fail GetMethod depending on provider; that's only
        // safe to treat as "nothing to set" when the caller supplied no
        // parameters either — the branch below.)
        result.error = error_tokens::kWmiQueryFailedPrefix + hr_hex(hr);
        return result;
    }
    if (SUCCEEDED(hr) && in_signature) {
        hr = in_signature->SpawnInstance(0, in_params_instance.put());
        if (FAILED(hr) || !in_params_instance) {
            result.error = error_tokens::kWmiQueryFailedPrefix + hr_hex(hr);
            return result;
        }
        for (const auto& [name, value] : in_params) {
            VariantGuard var;
            var.v.vt = VT_BSTR;
            var.v.bstrVal = SysAllocString(value.c_str());
            hr = in_params_instance->Put(name.c_str(), 0, &var.v, 0);
            if (FAILED(hr)) {
                result.error = error_tokens::kWmiPutParamFailedPrefix + hr_hex(hr);
                return result;
            }
        }
    } else if (!in_params.empty()) {
        // GetMethod succeeded but reported no in-signature, yet the caller
        // supplied parameters — the method doesn't take the parameters the
        // caller thinks it does.
        result.error = error_tokens::kWmiQueryFailedNoInSignature;
        return result;
    }

    // Semisynchronous ExecMethod: WBEM_FLAG_RETURN_IMMEDIATELY + a non-null
    // ppCallResult (and a null ppOutParams) puts the call in async mode, so
    // IWbemCallResult::GetResultObject(timeout) can be bounded the same way
    // enumerator->Next() is above.
    ComPtr<IWbemCallResult> call_result;
    hr = services->ExecMethod(_bstr_t(object_path.c_str()), _bstr_t(method.c_str()),
                              WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                              in_params_instance ? in_params_instance.get() : nullptr, nullptr,
                              call_result.put());
    if (FAILED(hr) || !call_result) {
        result.error = error_tokens::kWmiQueryFailedPrefix + hr_hex(hr);
        return result;
    }

    const ULONGLONG start_ticks = GetTickCount64();
    while (true) {
        const ULONGLONG elapsed = GetTickCount64() - start_ticks;
        if (elapsed >= opts.enumeration_deadline_ms) {
            result.error = error_tokens::kWmiDeadlineExceeded;
            return result;
        }
        const long call_timeout_ms = clamp_call_timeout_ms(opts.next_timeout_ms,
                                                            opts.enumeration_deadline_ms, elapsed);
        ComPtr<IWbemClassObject> out_params;
        hr = call_result->GetResultObject(call_timeout_ms, out_params.put());
        if (hr == WBEM_S_TIMEDOUT) {
            // Capped call, same reasoning as run_bounded_wmi_query above —
            // the top-of-loop deadline check terminates a wedged call.
            continue;
        }
        if (FAILED(hr) || !out_params) {
            result.error = error_tokens::kWmiNextFailedPrefix + hr_hex(hr);
            return result;
        }
        WmiRow row;
        extract_row(out_params.get(), row);
        result.rows.push_back(std::move(row));
        break;
    }

    return result;
}

} // namespace yuzu::shared::wmi

#endif // _WIN32

#endif // YUZU_SHARED_WMI_BOUNDED_HPP
