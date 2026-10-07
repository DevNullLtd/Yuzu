// test_wmi_bounded.cpp -- unit coverage for the shared bounded WMI helper
// (agents/shared/wmi_bounded.hpp, all-inline/header-only), hoisted from
// license_scan's licensing_wmi.{hpp,cpp} (roadmap C-8).
//
// Windows-only: the helper is #ifdef _WIN32 end to end (COM/WMI has no
// cross-platform equivalent). On other platforms this compiles to an empty
// translation unit, so the file is listed unconditionally in tests/meson.build
// (the platform-gated-body / listed-unconditionally convention test_win_str_utils.cpp
// and friends use) rather than guarded with a meson host_machine conditional.
//
// Two tiers:
//   - platform-independent-in-spirit: struct defaults, the documented
//     error-token set, WmiRow map semantics -- construct-only, no COM/WMI
//     calls, so these never flake regardless of host WMI provider state.
//   - Windows-gated compile/smoke: real run_bounded_wmi_query /
//     exec_object_method calls against deterministic, fast failure paths
//     (bad namespace, bad WQL, bad object path) plus one real successful
//     query against a class every Windows host has (Win32_OperatingSystem),
//     bounded tightly so a wedged CI runner fails fast rather than hanging
//     the suite.

#ifdef _WIN32

#include <wmi_bounded.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

using yuzu::shared::wmi::BoundedQueryOptions;
using yuzu::shared::wmi::BoundedQueryResult;
using yuzu::shared::wmi::WmiRow;
using yuzu::shared::wmi::detail::clamp_call_timeout_ms;
using yuzu::shared::wmi::detail::commit_row;
using yuzu::shared::wmi::detail::extract_row;
using yuzu::shared::wmi::detail::fail_enumeration;
using yuzu::shared::wmi::detail::hr_hex;
using yuzu::shared::wmi::exec_object_method;
using yuzu::shared::wmi::run_bounded_wmi_query;
namespace error_tokens = yuzu::shared::wmi::error_tokens;

namespace {

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

// ── platform-independent-in-spirit: no COM/WMI call, construct-only ────────

TEST_CASE("BoundedQueryOptions has the documented C-8 defaults") {
    BoundedQueryOptions opts;
    REQUIRE(opts.next_timeout_ms == 10000);
    REQUIRE(opts.row_cap == 512);
    REQUIRE(opts.enumeration_deadline_ms == 60000);
}

TEST_CASE("BoundedQueryResult default-constructs to an unset, non-truncated result") {
    BoundedQueryResult result;
    REQUIRE(result.rows.empty());
    REQUIRE_FALSE(result.truncated);
    REQUIRE_FALSE(result.error.has_value());
    REQUIRE(result.rows_before_error == 0); // no error, so no rows lost to one
}

TEST_CASE("WmiRow supports the map operations callers rely on (row_get-style lookup)") {
    WmiRow row;
    row.emplace("Name", "Windows 11 Enterprise");
    row.emplace("LicenseStatus", "1");

    REQUIRE(row.find("Name") != row.end());
    REQUIRE(row.at("Name") == "Windows 11 Enterprise");
    // A missing key must miss cleanly (the row_get pattern every caller uses
    // relies on this: `it == row.end() ? std::string{} : it->second`).
    REQUIRE(row.find("PartialProductKey") == row.end());
}

TEST_CASE("Bounded WMI error tokens are stable") {
    // Governance Gate 3 (quality-engineer) finding: this test previously
    // constructed its OWN literal string array, disconnected from
    // wmi_bounded.hpp's actual return sites -- a production token edit could
    // drift silently and this test would still pass. It now asserts against
    // yuzu::shared::wmi::error_tokens' named constants directly, the same
    // symbols every production return site in wmi_bounded.hpp uses, so a
    // rename/edit there is a compile-time rename here too, and the only way
    // this test's literal values can go stale is if they's genuinely renamed
    // in lockstep -- which downstream callers (licensing_win.cpp's
    // row_cap_exceeded, wmi plugin's error| passthrough) that pattern-match
    // on these prefixes need to know about anyway.
    REQUIRE(std::string(error_tokens::kComInitFailed) == "com_init_failed");
    REQUIRE(std::string(error_tokens::kWbemLocatorFailed) == "wbem_locator_failed");
    REQUIRE(std::string(error_tokens::kWmiConnectFailedPrefix) == "wmi_connect_failed_");
    REQUIRE(std::string(error_tokens::kWmiProxyBlanketFailedPrefix) ==
            "wmi_proxy_blanket_failed_");
    REQUIRE(std::string(error_tokens::kWmiQueryFailedPrefix) == "wmi_query_failed_");
    REQUIRE(std::string(error_tokens::kWmiQueryFailedNoInSignature) ==
            "wmi_query_failed_no_in_signature");
    REQUIRE(std::string(error_tokens::kWmiDeadlineExceeded) == "wmi_deadline_exceeded");
    REQUIRE(std::string(error_tokens::kWmiNextFailedPrefix) == "wmi_next_failed_");
    REQUIRE(std::string(error_tokens::kWmiPutParamFailedPrefix) == "wmi_put_param_failed_");
    REQUIRE(std::string(error_tokens::kWmiPropertyEnumFailedPrefix) ==
            "wmi_property_enum_failed_");
}

TEST_CASE("fail_enumeration clears the partial rows, records how many there were, and sets the "
          "token") {
    // The one helper every row-clearing exit of run_bounded_wmi_query goes through (deadline,
    // Next() failure, property-enumeration failure): the stage-aware classifier needs
    // rows_before_error to tell a missing class (fails at the FIRST Next) from a fault after data.
    BoundedQueryResult r;
    r.rows.push_back(WmiRow{{"k", "a"}});
    r.rows.push_back(WmiRow{{"k", "b"}});
    fail_enumeration(r, error_tokens::kWmiPropertyEnumFailedPrefix + hr_hex(static_cast<HRESULT>(WBEM_E_FAILED)));
    REQUIRE(r.rows_before_error == 2);
    REQUIRE(r.rows.empty());
    REQUIRE(r.error.has_value());
    REQUIRE(*r.error == "wmi_property_enum_failed_0x80041001");

    BoundedQueryResult none; // failure before the first row
    fail_enumeration(none, error_tokens::kWmiDeadlineExceeded);
    REQUIRE(none.rows_before_error == 0);
    REQUIRE(none.rows.empty());
    REQUIRE(*none.error == "wmi_deadline_exceeded");
}

namespace {

// WBEM_E_* are enumerators (wbemcli.h); HRESULT is the type extract_row traffics in.
constexpr HRESULT kInvalidOperation = static_cast<HRESULT>(WBEM_E_INVALID_OPERATION);
constexpr HRESULT kFailed = static_cast<HRESULT>(WBEM_E_FAILED);

// Duck-typed stand-in for IWbemClassObject: exactly the three members extract_row calls, over a
// scripted list of (name, VARIANT) and two injectable HRESULTs. Counters record the calls so the
// tests can pin that EndEnumeration() runs only when BeginEnumeration() succeeded.
struct FakeWbemObject {
    std::vector<std::pair<std::wstring, VARIANT>> props;
    HRESULT begin_hr = S_OK;
    HRESULT end_hr = static_cast<HRESULT>(WBEM_S_NO_MORE_DATA); // what Next() returns when exhausted
    size_t next_index = 0;
    int end_calls = 0;

    FakeWbemObject() = default;
    FakeWbemObject(const FakeWbemObject&) = delete;
    FakeWbemObject& operator=(const FakeWbemObject&) = delete;
    ~FakeWbemObject() {
        for (auto& p : props)
            VariantClear(&p.second);
    }

    void add_i4(const wchar_t* name, long v) {
        VARIANT var;
        VariantInit(&var);
        var.vt = VT_I4;
        var.lVal = v;
        props.emplace_back(name, var);
    }
    void add_null(const wchar_t* name) {
        VARIANT var;
        VariantInit(&var);
        var.vt = VT_NULL;
        props.emplace_back(name, var);
    }

    HRESULT BeginEnumeration(long) { return begin_hr; }
    HRESULT Next(long, BSTR* name, VARIANT* val, CIMTYPE*, long*) {
        if (next_index >= props.size())
            return end_hr;
        const auto& p = props[next_index++];
        *name = SysAllocString(p.first.c_str());
        VariantCopy(val, &p.second);
        return S_OK;
    }
    HRESULT EndEnumeration() {
        ++end_calls;
        return S_OK;
    }
};

} // namespace

TEST_CASE("extract_row returns BeginEnumeration's FAILED HRESULT and does not end an enumeration "
          "it never began") {
    FakeWbemObject obj;
    obj.add_i4(L"Count", 7); // never reached
    obj.begin_hr = kInvalidOperation;
    WmiRow row;
    REQUIRE(extract_row(&obj, row) == kInvalidOperation);
    REQUIRE(row.empty());
    REQUIRE(obj.end_calls == 0);
}

TEST_CASE("extract_row returns Next's FAILED HRESULT after ending the enumeration; the caller "
          "fails the query") {
    FakeWbemObject obj;
    obj.add_i4(L"Count", 7);
    obj.end_hr = kFailed; // Next() faults after the one property
    WmiRow row;
    REQUIRE(extract_row(&obj, row) == kFailed);
    REQUIRE(row == WmiRow{{"Count", "7"}}); // the property read before the fault
    REQUIRE(obj.end_calls == 1);
}

TEST_CASE("an undocumented success code from Next() is returned as-is and fails the query, never "
          "collapsed to S_OK") {
    // Pins `hr == WBEM_S_NO_MORE_DATA ? S_OK : hr` in extract_row and `hr != S_OK` in commit_row:
    // the old `FAILED(hr) ? hr : S_OK` collapse turns WBEM_S_FALSE into a clean (false-clean) row.
    constexpr HRESULT kUndocumentedSuccess = static_cast<HRESULT>(WBEM_S_FALSE);
    FakeWbemObject obj;
    obj.add_i4(L"Count", 7);
    obj.end_hr = kUndocumentedSuccess;
    WmiRow row;
    REQUIRE(extract_row(&obj, row) == kUndocumentedSuccess);
    REQUIRE(row == WmiRow{{"Count", "7"}});
    REQUIRE(obj.end_calls == 1);

    BoundedQueryResult r;
    FakeWbemObject good;
    good.add_i4(L"Count", 6);
    REQUIRE(commit_row(&good, r));
    FakeWbemObject obj2;
    obj2.add_i4(L"Count", 7);
    obj2.end_hr = kUndocumentedSuccess;
    REQUIRE_FALSE(commit_row(&obj2, r));
    REQUIRE(r.error.has_value());
    REQUIRE(*r.error == "wmi_property_enum_failed_0x00000001");
    REQUIRE(r.rows.empty());
    REQUIRE(r.rows_before_error == 1);
}

TEST_CASE("extract_row on a clean run returns S_OK with every non-null property") {
    FakeWbemObject obj;
    obj.add_i4(L"Count", 7);
    obj.add_null(L"Nothing"); // VT_NULL is omitted, not a failure
    obj.add_i4(L"Other", -3);
    WmiRow row;
    REQUIRE(extract_row(&obj, row) == S_OK);
    REQUIRE(row == WmiRow{{"Count", "7"}, {"Other", "-3"}});
    REQUIRE(obj.end_calls == 1);
}

TEST_CASE("commit_row appends a clean row; a FAILED extract_row fails the query with the "
          "property-enum token and records the rows read so far") {
    // commit_row is the one place both row loops (run_bounded_wmi_query, exec_object_method) turn
    // a FAILED extract_row into a failed query: removing its FAILED check, or the
    // fail_enumeration call, fails this test.
    BoundedQueryResult r;
    FakeWbemObject good;
    good.add_i4(L"Count", 7);
    REQUIRE(commit_row(&good, r));
    REQUIRE_FALSE(r.error.has_value());
    REQUIRE(r.rows.size() == 1);
    REQUIRE(r.rows.front() == WmiRow{{"Count", "7"}});

    FakeWbemObject bad;
    bad.add_i4(L"Count", 8);
    bad.end_hr = kFailed; // Next() faults after the one property
    REQUIRE_FALSE(commit_row(&bad, r));
    REQUIRE(r.error.has_value());
    REQUIRE(*r.error == "wmi_property_enum_failed_0x80041001");
    REQUIRE(r.rows.empty());           // failed, so no partial data
    REQUIRE(r.rows_before_error == 1); // the one row appended before the fault
}

TEST_CASE("clamp_call_timeout_ms bounds the per-call wait to what remains of the "
          "overall deadline") {
    // Regression pin for the deadline-clamp fix (gate-1 remediation): before
    // the fix, run_bounded_wmi_query/exec_object_method passed
    // opts.next_timeout_ms UNCLAMPED to Next()/GetResultObject() on every
    // iteration, so a call begun with little budget left could still block
    // for the full next_timeout_ms -- overrunning the documented
    // whole-enumeration deadline by up to one full per-call timeout. This is
    // pure arithmetic (no COM/live-provider dependency), so the exact
    // boundary math is testable directly and deterministically rather than
    // via a hard-to-reproduce live timing race.

    // Plenty of budget left: the per-call wait is the requested timeout,
    // untouched.
    REQUIRE(clamp_call_timeout_ms(/*next_timeout_ms=*/10000,
                                  /*enumeration_deadline_ms=*/60000,
                                  /*elapsed_ms=*/0) == 10000);

    // Less budget left than the requested per-call timeout: clamp to what
    // remains -- this is the exact case the original bug got wrong (it would
    // have returned the full 10000 here instead of 1000).
    REQUIRE(clamp_call_timeout_ms(/*next_timeout_ms=*/10000,
                                  /*enumeration_deadline_ms=*/60000,
                                  /*elapsed_ms=*/59000) == 1000);

    // Deadline already exceeded: no budget left, clamp to zero (an
    // immediate, non-blocking poll) rather than a negative/wrapped value.
    REQUIRE(clamp_call_timeout_ms(/*next_timeout_ms=*/10000,
                                  /*enumeration_deadline_ms=*/60000,
                                  /*elapsed_ms=*/60000) == 0);
    REQUIRE(clamp_call_timeout_ms(/*next_timeout_ms=*/10000,
                                  /*enumeration_deadline_ms=*/60000,
                                  /*elapsed_ms=*/99999) == 0);

    // Requested timeout smaller than the remaining budget: pass it through
    // unchanged (no need to clamp when there's more than enough time left).
    REQUIRE(clamp_call_timeout_ms(/*next_timeout_ms=*/500,
                                  /*enumeration_deadline_ms=*/60000,
                                  /*elapsed_ms=*/1000) == 500);
}

// ── Windows-gated compile/smoke: real calls, deterministic fast paths ──────

TEST_CASE("run_bounded_wmi_query fails fast with wmi_connect_failed_ on a bad namespace") {
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result =
        run_bounded_wmi_query(L"root\\yuzu_test_nonexistent_namespace", L"SELECT * FROM Win32_BIOS", opts);
    REQUIRE(result.error.has_value());
    REQUIRE(starts_with(*result.error, error_tokens::kWmiConnectFailedPrefix));
    REQUIRE(result.rows.empty());
}

TEST_CASE("run_bounded_wmi_query fails fast on malformed WQL") {
    // Semisynchronous ExecQuery (WBEM_FLAG_RETURN_IMMEDIATELY) defers WQL
    // parsing: it does not itself fail on bad syntax -- the provider only
    // rejects it once the caller starts pulling results, so the error can
    // legitimately surface at either ExecQuery() ("wmi_query_failed_") or the
    // first Next() ("wmi_next_failed_"). Verified against real WMI: this
    // specific malformed string fails at Next(), not ExecQuery(). Either is
    // a correct instance of the fail-with-reason contract; what must always
    // hold is that malformed WQL never produces a silent empty success.
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result = run_bounded_wmi_query(L"root\\cimv2", L"THIS IS NOT WQL", opts);
    REQUIRE(result.error.has_value());
    REQUIRE((starts_with(*result.error, error_tokens::kWmiQueryFailedPrefix) ||
             starts_with(*result.error, error_tokens::kWmiNextFailedPrefix)));
    REQUIRE(result.rows.empty());
}

TEST_CASE("run_bounded_wmi_query succeeds against a universally-present class") {
    // Win32_OperatingSystem is a single-instance, locally-served class on
    // every Windows host (no remote/slow provider like SoftwareLicensingProduct
    // ever needs), so this is a fast, deterministic real end-to-end smoke path.
    BoundedQueryOptions opts;
    opts.next_timeout_ms = 5000;
    opts.row_cap = 4;
    opts.enumeration_deadline_ms = 10000;
    const auto result = run_bounded_wmi_query(L"root\\cimv2", L"SELECT Name FROM Win32_OperatingSystem", opts);
    REQUIRE_FALSE(result.error.has_value());
    REQUIRE(result.rows.size() == 1);
    REQUIRE(result.rows.front().find("Name") != result.rows.front().end());
}

TEST_CASE("exec_object_method fails fast with an error on a nonexistent object path") {
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result = exec_object_method(L"root\\cimv2",
                                           L"Win32_Process.Handle=\"999999999\"", L"NoSuchMethod",
                                           {}, opts);
    REQUIRE(result.error.has_value());
    REQUIRE(result.rows.empty());
}

TEST_CASE("exec_object_method succeeds against a safe, always-available instance method "
          "(gate-1 remediation)") {
    // Every prior exec_object_method test only exercised a failure path (the
    // success path was introduced by this branch with zero test coverage --
    // a real functional gap, not just a style nit). Win32_Process.GetOwner is
    // read-only and side-effect-free; the test's OWN process is guaranteed to
    // exist, so calling it against our own PID is a deterministic, safe way
    // to exercise a real success round trip (input parameter isn't needed for
    // GetOwner, but the out-parameter/ReturnValue extraction path is real).
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto pid = GetCurrentProcessId();
    const std::wstring object_path = L"Win32_Process.Handle=\"" + std::to_wstring(pid) + L"\"";
    const auto result = exec_object_method(L"root\\cimv2", object_path, L"GetOwner", {}, opts);
    REQUIRE_FALSE(result.error.has_value());
    REQUIRE(result.rows.size() == 1);
    REQUIRE(result.rows.front().find("User") != result.rows.front().end());
}

TEST_CASE("run_bounded_wmi_query sets truncated when row_cap is reached before "
          "enumeration completes (gate-1 remediation)") {
    // Win32_Process always has multiple running instances (at minimum this
    // test's own process plus System), so row_cap=1 against it deterministically
    // exercises the truncation path without depending on host-specific state
    // beyond "more than one process is running" -- true on every real host.
    BoundedQueryOptions opts;
    opts.next_timeout_ms = 5000;
    opts.row_cap = 1;
    opts.enumeration_deadline_ms = 10000;
    const auto result =
        run_bounded_wmi_query(L"root\\cimv2", L"SELECT ProcessId FROM Win32_Process", opts);
    REQUIRE_FALSE(result.error.has_value());
    REQUIRE(result.truncated);
    REQUIRE(result.rows.size() == 1);
}

#endif // _WIN32
