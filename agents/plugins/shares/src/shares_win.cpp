/**
 * shares_win.cpp -- Windows leg: the LIVE shares the Server service publishes, through
 * NetShareEnum (netapi32). Names, paths, kind and flags only -- never ACLs (level 502) and
 * never the free-text remark.
 *
 * This file is the OS SHELL. Every decision (the level-2 -> level-1 fallback, the typed
 * service-stopped arm, the row/byte budget, paging termination, an unanswered read) is the
 * portable `list_windows` in shares_legs.hpp, unit-tested over canned pages; the shell owns only
 * the resume handle (reset when the level changes, per WinPageFn's contract) and the copy of
 * agent-core's page into a WinPage.
 *
 * The call itself is agent-core's, bounded per page (yuzu/agent/win_share_enum.hpp): do not call
 * NetShareEnum from this plugin, which can be unloaded under a worker running its code. Paging
 * has not been exercised on a host with more than one page of shares (README caveat 3).
 */
#include "shares_legs.hpp"

#if defined(_WIN32)

#include <windows.h>

#include <lm.h> // STYPE_* / NERR_ServerNotStarted, for the static_asserts below

#include <yuzu/agent/win_share_enum.hpp>

#include <cstdint>
#include <utility>

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

} // namespace

int run_windows(yuzu::CommandContext& ctx) {
    std::uint32_t resume = 0;
    int last_level = 0;
    // The resume handle belongs to one level's enumeration; a level change starts over.
    const WinPageFn pager = [&](int level) {
        if (level != last_level) {
            resume = 0;
            last_level = level;
        }
        auto read =
            yuzu::agent::win::read_share_page(level, resume, yuzu::agent::win::kShareEnumDeadline);
        resume = read.resume;
        WinPage page;
        page.status = read.nerr;
        page.total = read.total;
        page.unanswered = yuzu::agent::bounded_cause(read.status);
        page.shares.reserve(read.shares.size());
        for (auto& s : read.shares)
            page.shares.push_back({std::move(s.name), std::move(s.path), s.type});
        return page;
    };
    report_list(ctx, list_windows(pager));
    return 0;
}

} // namespace yuzu::shares

#endif // defined(_WIN32)
