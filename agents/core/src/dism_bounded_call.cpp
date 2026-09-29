// dism_bounded_call.cpp -- process-global, bounded DISM API access for the
// windows_optional_features plugin (adversarial review C1 fix, Wave 9
// PR9.2). See dism_bounded_call.hpp for why this lives in agent-core
// rather than in the plugin that consumes it (detached-thread lifetime vs
// plugin FreeLibrary/dlclose -- same reason passwd_lookup.cpp does, #3406).

#include <yuzu/agent/dism_bounded_call.hpp>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared)

#ifndef _WIN32

namespace yuzu::agent::dism {

// No DISM on non-Windows. These exist so the TU compiles in the shared
// agent-core build; the plugin's own #elif __APPLE__ / #else legs report
// the honest "unsupported" sentinel without ever reaching this file.
bool api_available() noexcept { return false; }
yuzu::wof::DismSlot::Acquire try_acquire_slot() noexcept {
    return yuzu::wof::DismSlot::Acquire::busy;
}
bool slot_in_flight() noexcept { return false; }
BoundedOutcome run_list_bounded(const std::optional<std::unordered_set<yuzu::wof::FeatureState>>&) {
    return {};
}
BoundedOutcome run_info_bounded(const std::string&) { return {}; }

} // namespace yuzu::agent::dism

#else // _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <format>
#include <string_view>

#include "win_str.hpp" // yuzu::win::to_wide / from_wide (agents/shared)

// ── DISM API surface, declared locally -- no <dismapi.h>, no DismApi.lib ──
//
// dismapi.h/DismApi.lib are Windows-ADK-only (P92-1 proved it absent from
// the base SDK on the-rig and every self-hosted Windows CI runner). The
// enums/structs/function-pointer types below are the local declarations
// this file binds DismApi.dll's exports against at runtime; the
// __has_include cross-check further below proves them layout-identical to
// the real header wherever it happens to be present at compile time.
//
// File-scope (not nested in yuzu::agent::dism) since it is used only from
// this one translation unit -- unchanged from its original home in
// windows_optional_features_plugin.cpp (Wave 9 PR9.2, pre-C1-fix).
namespace dism_native {

enum class LogLevel : int { Errors = 0 };
enum class PackageIdentifier : int { None = 0 };

// DismPackageFeatureState (mingw dismapi.h:95-105 / ADK header, agreed
// byte-for-byte per the-rig-dism-findings.md's layout cross-check).
enum class FeatureState : int {
    NotPresent = 0,
    UninstallPending = 1,
    Staged = 2,
    Removed = 3,
    Installed = 4,
    InstallPending = 5,
    Superseded = 6,
    PartiallyInstalled = 7,
};

// DismRestartType.
enum class RestartType : int { No = 0, Possible = 1, Required = 2 };

using Session = UINT;

// DISM_ONLINE_IMAGE.
constexpr wchar_t kOnlineImage[] = L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";

// dismapi.h wraps these in #pragma pack(push, 1) (ADK header lines
// 201-375; mingw header lines 150-319 agree) -- a naturally-aligned local
// declaration would read garbage from features[1] onward. Measured
// byte-for-byte on the-rig: sizeof(Feature)=12, sizeof(FeatureInfo)=44,
// sizeof(String)=8 (x64, the only Windows target this project builds).
#pragma pack(push, 1)
struct String {
    PCWSTR Value;
};
struct CustomProperty {
    PCWSTR Name;
    PCWSTR Value;
    PCWSTR Path;
};
struct Feature {
    PCWSTR FeatureName;
    FeatureState State;
};
struct FeatureInfo {
    PCWSTR FeatureName;
    FeatureState State;
    PCWSTR DisplayName;
    PCWSTR Description;
    RestartType RestartRequired;
    CustomProperty* Custom;
    UINT CustomCount;
};
#pragma pack(pop)

static_assert(sizeof(Feature) == 12, "DismFeature is pack(1) on x64 -- see the-rig-dism-findings.md");
static_assert(sizeof(FeatureInfo) == 44,
             "DismFeatureInfo is pack(1) on x64 -- see the-rig-dism-findings.md");
static_assert(sizeof(String) == 8, "DismString is pack(1) on x64 -- see the-rig-dism-findings.md");

// Function-pointer types for exactly the eight exports this plugin resolves
// (signatures per the-rig-dism-findings.md / mingw dismapi.h:323-346). No
// other DismXxx export is ever GetProcAddress'd -- grep-provable, and the
// only surface a future enable/disable/add/commit call could use.
using DismInitializeFn = HRESULT(WINAPI*)(LogLevel, PCWSTR, PCWSTR);
using DismShutdownFn = HRESULT(WINAPI*)();
using DismOpenSessionFn = HRESULT(WINAPI*)(PCWSTR, PCWSTR, PCWSTR, Session*);
using DismCloseSessionFn = HRESULT(WINAPI*)(Session);
using DismGetFeaturesFn = HRESULT(WINAPI*)(Session, PCWSTR, PackageIdentifier, Feature**, UINT*);
using DismGetFeatureInfoFn =
    HRESULT(WINAPI*)(Session, PCWSTR, PCWSTR, PackageIdentifier, FeatureInfo**);
using DismGetLastErrorMessageFn = HRESULT(WINAPI*)(String**);
using DismDeleteFn = HRESULT(WINAPI*)(void*);

struct Api {
    DismInitializeFn Initialize = nullptr;
    DismShutdownFn Shutdown = nullptr;
    DismOpenSessionFn OpenSession = nullptr;
    DismCloseSessionFn CloseSession = nullptr;
    DismGetFeaturesFn GetFeatures = nullptr;
    DismGetFeatureInfoFn GetFeatureInfo = nullptr;
    DismGetLastErrorMessageFn GetLastErrorMessage = nullptr;
    DismDeleteFn Delete = nullptr;

    [[nodiscard]] bool complete() const noexcept {
        return Initialize && Shutdown && OpenSession && CloseSession && GetFeatures &&
               GetFeatureInfo && GetLastErrorMessage && Delete;
    }
};

/// Resolved once, for the process's lifetime (function-local static --
/// std::call_once is not needed, statics with dynamic init are themselves
/// thread-safe since C++11). LOAD_LIBRARY_SEARCH_SYSTEM32 pins resolution
/// to %SystemRoot%\System32: DismApi.dll is not a KnownDLL, so a bare
/// LoadLibraryW would resolve through the normal search order and is
/// hijackable by a same-named DLL earlier on PATH or in the current
/// directory. NEVER FreeLibrary'd: an abandoned/timed-out DISM worker may
/// still be executing inside the DLL when the caller gives up on it (the
/// slot protocol below), and unloading the module out from under a live
/// call would fault the process rather than just leaking a handle. Living
/// in agent-core (never unloaded) rather than the plugin closes the
/// analogous risk for the WORKER's own code -- see dism_bounded_call.hpp.
[[nodiscard]] inline const Api& api() noexcept {
    static const Api resolved = [] {
        Api a;
        HMODULE m = ::LoadLibraryExW(L"DismApi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!m)
            return a;
        a.Initialize = reinterpret_cast<DismInitializeFn>(::GetProcAddress(m, "DismInitialize"));
        a.Shutdown = reinterpret_cast<DismShutdownFn>(::GetProcAddress(m, "DismShutdown"));
        a.OpenSession = reinterpret_cast<DismOpenSessionFn>(::GetProcAddress(m, "DismOpenSession"));
        a.CloseSession =
            reinterpret_cast<DismCloseSessionFn>(::GetProcAddress(m, "DismCloseSession"));
        a.GetFeatures = reinterpret_cast<DismGetFeaturesFn>(::GetProcAddress(m, "DismGetFeatures"));
        a.GetFeatureInfo =
            reinterpret_cast<DismGetFeatureInfoFn>(::GetProcAddress(m, "DismGetFeatureInfo"));
        a.GetLastErrorMessage = reinterpret_cast<DismGetLastErrorMessageFn>(
            ::GetProcAddress(m, "DismGetLastErrorMessage"));
        a.Delete = reinterpret_cast<DismDeleteFn>(::GetProcAddress(m, "DismDelete"));
        return a;
    }();
    return resolved;
}

// The one DISMAPI_E_* value this plugin branches on by name (value per
// the-rig-dism-findings.md / mingw dismapi.h:359-375) -- every other
// failing HRESULT is reported generically via its stage. E_ACCESSDENIED
// itself comes from <winerror.h> via <windows.h>.
constexpr HRESULT kDismUnknownFeature = 0x800F080C; // DISMAPI_E_UNKNOWN_FEATURE

} // namespace dism_native

// Layout cross-check against the real header, wherever it happens to be
// present at compile time (mingw on the dev Mac; the ADK on the-rig; absent
// entirely on a contract-locked CI runner, where this whole block compiles
// out). Proves the local declarations above are not just size-correct in
// isolation but field-offset-identical to the header this DLL was actually
// built against.
//
// offsetof(Feature, ...) checks added (governance Gate 3 cpp-expert SHOULD,
// Wave 9 PR9.2 C1-fix round): the original block anchored FeatureInfo's
// tail fields by offset but only checked Feature/String by sizeof, which a
// hypothetical vendor field reorder could pass while silently reading the
// wrong bytes out of Feature::State. mingw's real dismapi.h independently
// confirmed FeatureName-then-State, matching the local declaration.
#if defined(__has_include)
#if __has_include(<dismapi.h>)
#include <dismapi.h> // after <windows.h>; mingw on the dev Mac, ADK on the-rig
static_assert(sizeof(dism_native::Feature) == sizeof(::DismFeature));
static_assert(offsetof(dism_native::Feature, FeatureName) == offsetof(::DismFeature, FeatureName));
static_assert(offsetof(dism_native::Feature, State) == offsetof(::DismFeature, State));
static_assert(sizeof(dism_native::FeatureInfo) == sizeof(::DismFeatureInfo));
static_assert(offsetof(dism_native::FeatureInfo, CustomCount) ==
             offsetof(::DismFeatureInfo, CustomPropertyCount));
static_assert(offsetof(dism_native::FeatureInfo, RestartRequired) ==
             offsetof(::DismFeatureInfo, RestartRequired));
static_assert(static_cast<int>(dism_native::FeatureState::PartiallyInstalled) ==
             DismStatePartiallyInstalled);
#pragma message("dism_bounded_call: dismapi.h layout cross-check compiled")
#endif
#endif

namespace yuzu::agent::dism {

namespace {

// Single owner of the busy/abandoned/timed-out slot (peer H2). Every DISM
// call in this process runs through it -- see try_acquire_slot()'s
// three-way result and DismSlot's own doc comment in
// agents/shared/windows_optional_features_parsers.hpp. Process-global,
// agent-core-resident (never unloaded) so a worker that outlives the
// plugin's own bounded shutdown quiesce can still safely call release().
yuzu::wof::DismSlot g_dism_slot;

// Constructed FIRST inside the bounded lambda, so it is destroyed LAST (C++
// destroys locals in reverse construction order) -- after DismSessionGuard
// has already run DismCloseSession/DismShutdown. release() therefore always
// runs on the WORKER thread, only after DISM teardown has actually
// completed, never before. That worker thread runs entirely inside THIS
// translation unit's compiled code (agent-core, never unloaded) even when
// abandoned past the caller's bounded wait -- the property this whole file
// exists to provide.
struct SlotRelease {
    ~SlotRelease() { g_dism_slot.release(); }
};

/// File-private RAII: DismInitialize -> DismOpenSession(DISM_ONLINE_IMAGE)
/// in the constructor, DismCloseSession (if opened) then DismShutdown (if
/// initialized) in the destructor -- every early return inside the bounded
/// lambda releases through this guard. Constructed only after api().
/// complete() is true (checked by the caller before this guard exists).
struct DismSessionGuard {
    bool initialized = false;
    bool opened = false;
    dism_native::Session session = 0;
    HRESULT first_failure = S_OK;
    std::string_view failed_stage;

    explicit DismSessionGuard(const dism_native::Api& api_table) noexcept : api_{api_table} {
        // DISM reference-counts Initialize/Shutdown pairs: a second
        // Initialize returns S_FALSE (not a hard error) per the-rig's
        // measured error-path capture, so FAILED() alone is the right test
        // -- S_OK and S_FALSE both mean the API is usable.
        HRESULT hr = api_.Initialize(dism_native::LogLevel::Errors, nullptr, nullptr);
        if (FAILED(hr)) {
            first_failure = hr;
            failed_stage = "initialize";
            return;
        }
        initialized = true;

        hr = api_.OpenSession(dism_native::kOnlineImage, nullptr, nullptr, &session);
        if (FAILED(hr)) {
            first_failure = hr;
            failed_stage = "open_session";
            return;
        }
        opened = true;
    }

    DismSessionGuard(const DismSessionGuard&) = delete;
    DismSessionGuard& operator=(const DismSessionGuard&) = delete;

    ~DismSessionGuard() {
        if (opened)
            api_.CloseSession(session);
        if (initialized)
            api_.Shutdown();
    }

private:
    const dism_native::Api& api_;
};

/// RAII owner for a DISM-allocated buffer freed via Api::Delete
/// (DismDelete) -- adopts the pointer IMMEDIATELY so a throwing conversion
/// or formatting step between the DISM call and the (formerly trailing,
/// manual) delete cannot leak it (docs/cpp-conventions.md's resource-
/// ownership rule: adopt raw resources into RAII immediately, cover every
/// early return/unwind path). Precedent: windows_updates_plugin.cpp's
/// BStrGuard for a BSTR out-parameter.
template <typename T>
class DismResultGuard {
public:
    DismResultGuard(T* ptr, const dism_native::Api& api) noexcept : ptr_{ptr}, api_{&api} {}
    DismResultGuard(const DismResultGuard&) = delete;
    DismResultGuard& operator=(const DismResultGuard&) = delete;
    ~DismResultGuard() {
        if (ptr_)
            api_->Delete(ptr_);
    }
    [[nodiscard]] T* get() const noexcept { return ptr_; }
    T* operator->() const noexcept { return ptr_; }

private:
    T* ptr_;
    const dism_native::Api* api_;
};

std::string dism_last_error_text(const dism_native::Api& api_table) {
    dism_native::String* raw_msg = nullptr;
    if (FAILED(api_table.GetLastErrorMessage(&raw_msg)) || !raw_msg || !raw_msg->Value)
        return {};
    const DismResultGuard<dism_native::String> msg{raw_msg, api_table};
    return yuzu::win::from_wide(msg->Value);
}

std::string format_hr_reason(HRESULT hr, const dism_native::Api& api_table) {
    std::string reason = std::format("hr=0x{:08X}", static_cast<unsigned long>(hr));
    if (auto text = dism_last_error_text(api_table); !text.empty()) {
        reason += ' ';
        reason += text;
    }
    return reason;
}

/// Runs the whole init->enumerate->shutdown sequence for `list`. Executed
/// entirely inside ONE bounded_call_ex lambda by run_list_bounded() below --
/// this function IS that lambda's body, factored out for readability.
Outcome run_dism_list(const std::optional<std::unordered_set<yuzu::wof::FeatureState>>& filter) {
    try {
        SlotRelease slot_release; // constructed FIRST -- destroyed LAST
        const auto& api_table = dism_native::api();
        DismSessionGuard guard(api_table); // constructed SECOND -- destroyed FIRST
        if (!guard.opened) {
            const auto reason = format_hr_reason(guard.first_failure, api_table);
            if (guard.first_failure == E_ACCESSDENIED)
                return {Outcome::Kind::AccessDenied, {}, reason};
            return {guard.failed_stage == "initialize" ? Outcome::Kind::InitializeFailed
                                                        : Outcome::Kind::OpenSessionFailed,
                    {},
                    reason};
        }

        dism_native::Feature* features = nullptr;
        UINT count = 0;
        const HRESULT hr =
            api_table.GetFeatures(guard.session, nullptr, dism_native::PackageIdentifier::None, &features, &count);
        if (FAILED(hr)) {
            const auto reason = format_hr_reason(hr, api_table);
            if (hr == E_ACCESSDENIED)
                return {Outcome::Kind::AccessDenied, {}, reason};
            return {Outcome::Kind::GetFeaturesFailed, {}, reason};
        }

        // Adopted immediately (docs/cpp-conventions.md resource-ownership
        // rule): from_wide() below can throw, and a trailing manual
        // Delete() would then never run.
        const DismResultGuard<dism_native::Feature> features_guard{features, api_table};

        std::vector<std::string> rows;
        rows.reserve(count);
        for (UINT i = 0; i < count; ++i) {
            const auto state = yuzu::wof::state_from_dism(static_cast<int>(features[i].State));
            if (filter && !filter->contains(state))
                continue;
            std::string name =
                features[i].FeatureName ? yuzu::win::from_wide(features[i].FeatureName) : std::string{};
            rows.push_back(yuzu::wof::format_feature_row(name, state, yuzu::wof::pending_restart(state)));
        }
        return {Outcome::Kind::Ok, std::move(rows), {}};
    } catch (...) {
        return {Outcome::Kind::Exception, {}, "unhandled exception inside the bounded DISM call"};
    }
}

/// Same shape as run_dism_list() for `info`: init->OpenSession->
/// GetFeatureInfo->shutdown, entirely inside one bounded lambda. `name` is
/// already validated (validate_feature_name) by the caller.
Outcome run_dism_info(const std::string& name) {
    try {
        SlotRelease slot_release; // constructed FIRST -- destroyed LAST
        const auto& api_table = dism_native::api();
        DismSessionGuard guard(api_table); // constructed SECOND -- destroyed FIRST
        if (!guard.opened) {
            const auto reason = format_hr_reason(guard.first_failure, api_table);
            if (guard.first_failure == E_ACCESSDENIED)
                return {Outcome::Kind::AccessDenied, {}, reason};
            return {guard.failed_stage == "initialize" ? Outcome::Kind::InitializeFailed
                                                        : Outcome::Kind::OpenSessionFailed,
                    {},
                    reason};
        }

        const std::wstring wide_name = yuzu::win::to_wide(name);
        dism_native::FeatureInfo* info = nullptr;
        const HRESULT hr = api_table.GetFeatureInfo(guard.session, wide_name.c_str(), nullptr,
                                                     dism_native::PackageIdentifier::None, &info);
        if (FAILED(hr)) {
            const auto reason = format_hr_reason(hr, api_table);
            if (hr == dism_native::kDismUnknownFeature)
                return {Outcome::Kind::FeatureNotFound, {}, reason};
            if (hr == E_ACCESSDENIED)
                return {Outcome::Kind::AccessDenied, {}, reason};
            return {Outcome::Kind::GetFeatureInfoFailed, {}, reason};
        }

        // Adopted immediately, same reason as run_dism_list()'s
        // features_guard above -- from_wide()/format below can throw.
        const DismResultGuard<dism_native::FeatureInfo> info_guard{info, api_table};

        const auto state = yuzu::wof::state_from_dism(static_cast<int>(info->State));
        std::string display_name =
            info->DisplayName ? yuzu::win::from_wide(info->DisplayName) : std::string{};
        std::string description =
            info->Description ? yuzu::win::from_wide(info->Description) : std::string{};
        std::string row = yuzu::wof::format_feature_info_row(
            name, display_name, state, static_cast<int>(info->RestartRequired), description);
        return {Outcome::Kind::Ok, {std::move(row)}, {}};
    } catch (...) {
        return {Outcome::Kind::Exception, {}, "unhandled exception inside the bounded DISM call"};
    }
}

} // namespace

bool api_available() noexcept { return dism_native::api().complete(); }

yuzu::wof::DismSlot::Acquire try_acquire_slot() noexcept { return g_dism_slot.try_acquire(); }

bool slot_in_flight() noexcept { return g_dism_slot.in_flight(); }

/// SLOT PROTOCOL (peer H2, resolved): try_acquire_slot() runs BEFORE the
/// bounded call, on the DISPATCHING thread (the plugin calls it directly).
/// On `acquired`, the whole DISM sequence runs inside ONE bounded_call_ex
/// here -- Completed reports the Outcome; TimedOut CAS'es the slot
/// Busy->TimedOut (a no-op if the worker already released it -- see
/// DismSlot::mark_timed_out()'s own doc comment in
/// agents/shared/windows_optional_features_parsers.hpp); Rejected means
/// fn() never ran at all, so THIS function performs the ONE caller-side
/// release the protocol allows.
BoundedOutcome run_list_bounded(const std::optional<std::unordered_set<yuzu::wof::FeatureState>>& filter) {
    auto bounded = yuzu::shared::bounded_call_ex(kTimeout, [filter]() { return run_dism_list(filter); });
    if (bounded.status == yuzu::shared::BoundedCallStatus::TimedOut) {
        g_dism_slot.mark_timed_out(); // DISPATCHING thread; CAS Busy->TimedOut only
        return {BoundedStatus::TimedOut, {}};
    }
    if (bounded.status == yuzu::shared::BoundedCallStatus::Rejected) {
        // fn() never ran -- no worker owns the slot. The ONE caller-side
        // release this protocol allows (see DismSlot's own doc comment).
        g_dism_slot.release();
        return {BoundedStatus::Rejected, {}};
    }
    return {BoundedStatus::Completed, std::move(*bounded.value)};
}

BoundedOutcome run_info_bounded(const std::string& name) {
    auto bounded = yuzu::shared::bounded_call_ex(kTimeout, [name]() { return run_dism_info(name); });
    if (bounded.status == yuzu::shared::BoundedCallStatus::TimedOut) {
        g_dism_slot.mark_timed_out(); // DISPATCHING thread; CAS Busy->TimedOut only
        return {BoundedStatus::TimedOut, {}};
    }
    if (bounded.status == yuzu::shared::BoundedCallStatus::Rejected) {
        g_dism_slot.release();
        return {BoundedStatus::Rejected, {}};
    }
    return {BoundedStatus::Completed, std::move(*bounded.value)};
}

} // namespace yuzu::agent::dism

#endif // _WIN32
