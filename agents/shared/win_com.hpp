// win_com.hpp -- shared Windows COM RAII helpers (ComInit / ComPtr<T> / BStr).
//
// Hoisted from agents/plugins/rdp_control/src/rdp_control_plugin.cpp (the
// best-shaped in-tree copy) so every plugin that touches COM/WMI shares one
// definition instead of re-deriving it. ComInit's RPC_E_CHANGED_MODE
// tolerance is preserved verbatim from that origin, including its rationale
// comment below.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere. Header-only: every plugin is its own shared object and still
// compiles its own inline copy, so there is no exported symbol to interpose
// across the plugin ABI boundary (same reasoning as agents/shared/win_str.hpp).

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <oleauto.h> // SysAllocString / SysFreeString

#include <string>

namespace yuzu::shared::win {

/// RAII COM apartment init/uninit.
class ComInit {
public:
    ComInit() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() {
        if (SUCCEEDED(hr_)) CoUninitialize();
    }
    // Non-copyable: a copy would duplicate hr_ and both destructors would call
    // CoUninitialize (unbalanced).
    ComInit(const ComInit&) = delete;
    ComInit& operator=(const ComInit&) = delete;
    // RPC_E_CHANGED_MODE means COM was already initialised on this thread in a
    // different apartment (e.g. an STA from a prior plugin on the pool thread).
    // That is usable — in-proc COM works regardless of apartment — so treat it as
    // ok. The dtor still only CoUninitialize()s when WE initialised (SUCCEEDED),
    // which excludes RPC_E_CHANGED_MODE, so the ref count stays balanced.
    bool ok() const { return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE; }

private:
    HRESULT hr_;
};

/// RAII owner for a COM interface pointer (Release on scope exit/reset).
/// `put()` yields the out-param for CoCreateInstance / QueryInterface-style
/// calls, releasing any existing pointer first so a reused ComPtr never leaks.
template <class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    /// Releases any existing pointer, then returns the address of the (now
    /// null) member for an out-param call such as CoCreateInstance.
    T** put() {
        reset();
        return &p_;
    }
    T* get() const { return p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }

    void reset() {
        if (p_) {
            p_->Release();
            p_ = nullptr;
        }
    }

private:
    T* p_ = nullptr;
};

/// RAII owner for a BSTR (SysFreeString on scope exit).
class BStr {
public:
    BStr() = default;
    explicit BStr(const wchar_t* s) : b_(SysAllocString(s)) {}
    explicit BStr(const std::wstring& s) : b_(SysAllocStringLen(s.data(), static_cast<UINT>(s.size()))) {}
    ~BStr() {
        if (b_) SysFreeString(b_);
    }
    BStr(const BStr&) = delete;
    BStr& operator=(const BStr&) = delete;
    BSTR get() const { return b_; }
    explicit operator bool() const { return b_ != nullptr; }

private:
    BSTR b_ = nullptr;
};

} // namespace yuzu::shared::win

#endif // _WIN32
