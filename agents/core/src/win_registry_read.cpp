// win_registry_read.cpp -- bounded HKEY_LOCAL_MACHINE reads: the Win32 calls. The decisions are
// in win_registry_walk.hpp; yuzu/agent/win_registry_read.hpp says why this lives in agent-core.

#include <yuzu/agent/win_registry_read.hpp>

#include "win_bounded_run.hpp"
#include "win_registry_walk.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "win_reg_handle.hpp" // yuzu::win::RegKey (agents/shared)
#include "win_str.hpp"        // yuzu::win::to_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_registry_slot = detail::new_slot();

#ifdef _WIN32

static_assert(detail::kErrorInvalidData == ERROR_INVALID_DATA &&
              detail::kErrorInvalidParameter == ERROR_INVALID_PARAMETER &&
              detail::kErrorMoreData == ERROR_MORE_DATA &&
              detail::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(detail::kKeyRead == KEY_READ && detail::kKeyWow64Key64 == KEY_WOW64_64KEY &&
              detail::kKeyWow64Key32 == KEY_WOW64_32KEY);

/// The Ops of detail::walk_registry (see win_registry_walk.hpp).
struct HklmOps {
    yuzu::win::RegKey base;
    yuzu::win::RegKey child;
    HKEY current = nullptr; ///< borrowed from base or child; what query_value reads

    std::uint32_t open_base(const std::string& subkey, std::uint32_t access) {
        const LSTATUS rc = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, yuzu::win::to_wide(subkey).c_str(),
                                           0, access, base.put());
        current = base.get();
        return static_cast<std::uint32_t>(rc);
    }
    std::uint32_t child_name(std::uint32_t index, std::u16string& name) {
        wchar_t buf[256]; // a key name is at most 255 characters
        DWORD length = 256;
        const LSTATUS rc =
            ::RegEnumKeyExW(base.get(), index, buf, &length, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_SUCCESS)
            name.assign(buf, buf + length);
        return static_cast<std::uint32_t>(rc);
    }
    std::uint32_t open_child(const std::u16string& name, std::uint32_t access) {
        const std::wstring wide(name.begin(), name.end());
        const LSTATUS rc = ::RegOpenKeyExW(base.get(), wide.c_str(), 0, access, child.put());
        current = child.get();
        return static_cast<std::uint32_t>(rc);
    }
    std::uint32_t query_value(const std::string& name, std::uint32_t& type, std::uint8_t* data,
                              std::uint32_t& size) {
        DWORD value_type = 0;
        DWORD length = size;
        const LSTATUS rc = ::RegQueryValueExW(current, yuzu::win::to_wide(name).c_str(), nullptr,
                                              &value_type, data, &length);
        type = value_type;
        size = length;
        return static_cast<std::uint32_t>(rc);
    }
};

RegRead read_raw(const RegRequest& request) {
    HklmOps ops;
    return detail::walk_registry(request, ops);
}

#else

RegRead read_raw(const RegRequest&) {
    RegRead out;
    out.win_error = 120; // ERROR_CALL_NOT_IMPLEMENTED: no registry on this OS
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

RegRead read_hklm_values(const RegRequest& request, std::chrono::milliseconds deadline) {
    // The worker owns a copy of the request: it can outlive this call.
    return detail::run_bounded_read<RegRead>(g_registry_slot, deadline, "registry_read",
                                             [owned = request] { return read_raw(owned); });
}

RegRead read_hklm_values_for_test(std::chrono::milliseconds deadline,
                                  const std::function<RegRead()>& reader) {
    return detail::run_bounded_read<RegRead>(g_registry_slot, deadline, "registry_read", reader);
}

} // namespace yuzu::agent::win
