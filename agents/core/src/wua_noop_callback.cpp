/**
 * wua_noop_callback.cpp -- see wua_noop_callback.hpp for the contract.
 */

#ifdef _WIN32

#include <yuzu/agent/wua_noop_callback.hpp>

namespace yuzu::agent {

namespace {

// Deliberately trivial COM refcounting: this instance has process lifetime
// by construction (a function-local static in
// wua_noop_search_completed_callback() below), so AddRef()/Release() have
// nothing real to track and must never destroy it -- returning a fixed
// positive count on both is the correct, minimal implementation, not a
// shortcut.
class WuaNoopSearchCompletedCallback final : public ISearchCompletedCallback {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv)
            return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ISearchCompletedCallback)) {
            *ppv = static_cast<ISearchCompletedCallback*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return 1; }
    STDMETHODIMP_(ULONG) Release() override { return 1; }

    STDMETHODIMP Invoke(ISearchJob* /*searchJob*/,
                        ISearchCompletedCallbackArgs* /*callbackArgs*/) override {
        return S_OK;
    }
};

} // namespace

ISearchCompletedCallback* wua_noop_search_completed_callback() {
    static WuaNoopSearchCompletedCallback instance;
    return &instance;
}

} // namespace yuzu::agent

#endif // _WIN32
