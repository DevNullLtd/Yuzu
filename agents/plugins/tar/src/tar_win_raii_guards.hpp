#pragma once

// Shared RAII owners for the TAR plugin's Win32 handle-like resources
// (SC_HANDLE, HANDLE, LPVOID, PMIB_IPNET_TABLE2). Previously each collector
// file (tar_service_collector.cpp, tar_mapdrive_collector.cpp,
// tar_arp_collector.cpp) hand-rolled its own near-identical guard struct,
// each calling its real WinAPI closer directly from the destructor -- safe
// in production, but untestable without a live Win32 resource. Consolidated
// here with an INJECTABLE closer (CLAUDE.md's "inject the boundary" test
// convention, applied to RAII guards rather than command runners): a
// production call site gets the real WinAPI call via each alias's default
// argument, unchanged from the old bespoke-struct construction syntax; a
// unit test can substitute a stub closer to verify release-once/null-safety
// without touching a real OS resource.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// This exact sequence (winsock2.h, ws2tcpip.h, windows.h, iphlpapi.h,
// netioapi.h, lm.h, winsvc.h) matches tar_arp_collector.cpp's own working
// include block. ws2tcpip.h is load-bearing: without it, PMIB_IPNET_TABLE2
// fails to resolve even with iphlpapi.h + netioapi.h both included -- MSVC
// error C2065 (found the hard way: an earlier version of this header
// omitted it and failed to compile in the two collector files that don't
// otherwise pull in networking headers themselves).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iphlpapi.h> // GetIpNetTable2 declaration
#include <netioapi.h> // PMIB_IPNET_TABLE2 / MIB_IPNET_ROW2 / FreeMibTable
#include <lm.h>       // NetApiBufferFree
#include <winsvc.h>   // SC_HANDLE / CloseServiceHandle

namespace yuzu::tar::win_raii {

template <typename Handle>
class ScopedWinHandle {
public:
    using Closer = void (*)(Handle);

    explicit ScopedWinHandle(Handle h, Closer closer, Handle null_value = Handle{}) noexcept
        : h_(h), closer_(closer), null_(null_value) {}
    ~ScopedWinHandle() {
        if (h_ != null_ && closer_ != nullptr)
            closer_(h_);
    }
    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;

    Handle get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != null_; }

private:
    Handle h_;
    Closer closer_;
    Handle null_;
};

inline void close_sc_handle(SC_HANDLE h) { CloseServiceHandle(h); }
inline void close_wnet_enum(HANDLE h) { WNetCloseEnum(h); }
inline void free_net_api_buf(LPVOID p) { NetApiBufferFree(p); }
inline void free_mib_table(PMIB_IPNET_TABLE2 t) { FreeMibTable(t); }

// Named wrappers preserve each call site's existing construction syntax
// (e.g. `ScHandleGuard scm(OpenSCManagerW(...));`) via the defaulted real
// closer -- only a test passes the second (closer) argument explicitly.
struct ScHandleGuard : ScopedWinHandle<SC_HANDLE> {
    explicit ScHandleGuard(SC_HANDLE h, Closer closer = close_sc_handle) noexcept
        : ScopedWinHandle(h, closer) {}
};

struct WNetEnumGuard : ScopedWinHandle<HANDLE> {
    explicit WNetEnumGuard(HANDLE h, Closer closer = close_wnet_enum) noexcept
        : ScopedWinHandle(h, closer) {}
};

struct NetApiBufGuard : ScopedWinHandle<LPVOID> {
    explicit NetApiBufGuard(LPVOID p, Closer closer = free_net_api_buf) noexcept
        : ScopedWinHandle(p, closer) {}
};

struct MibTableGuard : ScopedWinHandle<PMIB_IPNET_TABLE2> {
    explicit MibTableGuard(PMIB_IPNET_TABLE2 t, Closer closer = free_mib_table) noexcept
        : ScopedWinHandle(t, closer) {}
};

} // namespace yuzu::tar::win_raii

#endif // _WIN32
