/**
 * shares_win.cpp -- Windows leg: the LIVE shares the Server service publishes, through
 * NetShareEnum (netapi32). Names, paths, kind and flags only -- never ACLs (level 502) and
 * never the free-text remark.
 *
 * This file is the OS SHELL. Every decision (the level-2 -> level-1 fallback, the typed
 * service-stopped arm, the row/byte budget, paging termination) is the portable
 * `list_windows` in shares_legs.hpp, unit-tested over canned pages; the shell owns only the
 * NetShareEnum call, the resume handle (reset when the level changes, per WinPageFn's contract)
 * and the one-page conversion.
 *
 * Bounded before materialised: the shell asks for at most 64 KiB per call (kWinPageBytes),
 * never MAX_PREFERRED_LENGTH. That is a request, not a guarantee: the page the service actually
 * returns bounds what is held. One page is converted per call and freed by NetApiBuf on return
 * (including on a throw), so retained memory at any instant is the page the service returned
 * plus the budget-bounded rows. Paging has not been exercised on a host with more than one
 * page of shares (README caveat 3).
 */
#include "shares_legs.hpp"

#if defined(_WIN32)

#include <windows.h>

#include <lm.h> // NetShareEnum / NetApiBufferFree / SHARE_INFO_1 / SHARE_INFO_2

#include <win_str.hpp>

#include <cstdint>
#include <type_traits>

namespace yuzu::shares {

namespace {

// The portable decision code names these as plain numbers; pin them to the SDK here so a
// header that disagrees fails the Windows build instead of misclassifying at runtime.
static_assert(kStypeMask == static_cast<std::uint32_t>(STYPE_MASK));
static_assert(kStypeSpecial == static_cast<std::uint32_t>(STYPE_SPECIAL));
static_assert(kStypeTemporary == static_cast<std::uint32_t>(STYPE_TEMPORARY));
static_assert(kWinAccessDenied == static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
static_assert(kWinMoreData == static_cast<std::uint32_t>(ERROR_MORE_DATA));
static_assert(kNerrServerNotStarted == static_cast<std::uint32_t>(NERR_ServerNotStarted));
static_assert(kRpcServerUnavailable == static_cast<std::uint32_t>(RPC_S_SERVER_UNAVAILABLE));
static_assert(kRpcUnknownIf == static_cast<std::uint32_t>(RPC_S_UNKNOWN_IF));

/// Owns one NetShareEnum out-buffer. Duplicated from TAR's guard on purpose (tar_win_raii_guards.hpp
/// is a TAR-internal header); one buffer at a time, freed on every exit, never transferred.
struct NetApiBuf {
    LPBYTE p = nullptr;
    NetApiBuf() = default;
    NetApiBuf(const NetApiBuf&) = delete;
    NetApiBuf& operator=(const NetApiBuf&) = delete;
    ~NetApiBuf() {
        if (p != nullptr)
            NetApiBufferFree(p);
    }
};

/// The size asked for per call (prefmaxlen is a request). Well above the largest SHARE_INFO_2
/// entry under the LAN Manager limits (NNLEN, MAXCOMMENTSZ, MAX_PATH), so a page normally holds
/// many entries; a page that holds none is reported by list_windows as no_progress, never spun
/// on.
constexpr DWORD kWinPageBytes = 64 * 1024;

/// One NetShareEnum call at the level `Info` names (SHARE_INFO_1 or SHARE_INFO_2). `path` is
/// null for level 1 (no path in SHARE_INFO_1). `resume` is the API's resume handle: NetShareEnum
/// advances it on ERROR_MORE_DATA.
template <class Info>
WinPage one_page(DWORD& resume, LPWSTR Info::*name, LPWSTR Info::*path, DWORD Info::*type) {
    static_assert(std::is_same_v<Info, SHARE_INFO_1> || std::is_same_v<Info, SHARE_INFO_2>);
    constexpr DWORD level = std::is_same_v<Info, SHARE_INFO_2> ? 2 : 1;
    NetApiBuf buf;
    DWORD read = 0;
    DWORD total = 0;
    const NET_API_STATUS status =
        NetShareEnum(nullptr, level, &buf.p, kWinPageBytes, &read, &total, &resume);
    WinPage page;
    page.status = static_cast<std::uint32_t>(status);
    page.total = static_cast<std::uint32_t>(total);
    if ((status == NERR_Success || status == ERROR_MORE_DATA) && buf.p != nullptr) {
        // buf.p is an array of `read` Info entries (aligned by NetApiBufferAllocate) that stays
        // valid until ~NetApiBuf; the strings the entries point at live in the same buffer.
        const auto* entries = reinterpret_cast<const Info*>(buf.p);
        page.shares.reserve(read);
        for (DWORD i = 0; i < read; ++i) {
            WinShareRec rec;
            rec.name = yuzu::win::from_wide(entries[i].*name);
            if (path != nullptr)
                rec.path = yuzu::win::from_wide(entries[i].*path);
            rec.type = static_cast<std::uint32_t>(entries[i].*type);
            page.shares.push_back(std::move(rec));
        }
    }
    return page;
}

} // namespace

int run_windows(yuzu::CommandContext& ctx) {
    DWORD resume = 0;
    int last_level = 0;
    // The resume handle belongs to one level's enumeration; a level change starts over.
    const WinPageFn pager = [&](int level) {
        if (level != last_level) {
            resume = 0;
            last_level = level;
        }
        if (level == 2)
            return one_page<SHARE_INFO_2>(resume, &SHARE_INFO_2::shi2_netname,
                                          &SHARE_INFO_2::shi2_path, &SHARE_INFO_2::shi2_type);
        return one_page<SHARE_INFO_1>(resume, &SHARE_INFO_1::shi1_netname, nullptr,
                                      &SHARE_INFO_1::shi1_type);
    };
    report_list(ctx, list_windows(pager));
    return 0;
}

} // namespace yuzu::shares

#endif // defined(_WIN32)
