/**
 * echo_netconn_win.cpp — Windows reader for the `netconn` source (ADR-0020).
 *
 * EvtQuery over the OS-RETAINED NetworkProfile / NCSI / WLAN-AutoConfig
 * operational channels: the OS was logging these transitions before Echo — or
 * the agent — existed on the box, so the first backfill is genuinely
 * retrospective. Rendering + RAII shapes mirror dex_observer.cpp's event-log
 * engine; all field extraction is delegated to the pure allow-list parser in
 * echo_netconn.hpp (raw XML never leaves this TU).
 *
 * Failure posture: PER-CHANNEL isolation. A missing channel (no Wi-Fi service,
 * Server SKU) or an ACL-denied read logs one rate-limited warn and contributes
 * zero rows — never an error, never a throw across the plugin ABI.
 */

#include "echo_netconn.hpp"

#ifdef _WIN32

#include <spdlog/spdlog.h>

#include <atomic>
#include <cstddef>
#include <iterator> // std::size (kChannels / g_nc_query_warned bounds)

// clang-format off
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
// clang-format on

#pragma comment(lib, "wevtapi.lib") // EvtQuery / EvtNext / EvtRender / EvtClose

namespace yuzu::echo {

namespace {

// EVT_HANDLE must be closed with EvtClose, not CloseHandle — a local
// single-owner guard (guard_win_handle.hpp is core-internal; this mirrors the
// dex_observer specialisation without reaching across module boundaries).
struct EvtGuard {
    EVT_HANDLE h{nullptr};
    explicit EvtGuard(EVT_HANDLE handle) : h{handle} {}
    ~EvtGuard() {
        if (h)
            ::EvtClose(h);
    }
    EvtGuard(const EvtGuard&) = delete;
    EvtGuard& operator=(const EvtGuard&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

// Render one event to UTF-8 XML (size-then-fill, same as dex_observer).
std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0)
        return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return yuzu::win::from_wide(buf.c_str());
}

struct ChannelSpec {
    const wchar_t* path;
    const char* tag;         // the parser's trusted channel token
    const wchar_t* id_filter; // XPath EventID clause
};

constexpr ChannelSpec kChannels[] = {
    {L"Microsoft-Windows-NetworkProfile/Operational", "networkprofile",
     L"(EventID=10000 or EventID=10001)"},
    {L"Microsoft-Windows-NCSI/Operational", "ncsi", L"(EventID=4042)"},
    {L"Microsoft-Windows-WLAN-AutoConfig/Operational", "wlan",
     L"(EventID=8001 or EventID=8002 or EventID=8003)"},
};

// One-shot warn latch per channel: a missing channel (no WLAN service on a
// Server SKU) or an ACL-denied read is a permanent topology fact, and the slow
// leg retries every 300s forever — without this, each failing channel would log
// a warn per tick indefinitely (the agent has no /metrics; logs are the only
// surface, so unbounded log growth is the failure mode). Warn once per channel
// per process, matching the ESTATS ACCESS_DENIED latch philosophy.
std::atomic<bool> g_nc_query_warned[std::size(kChannels)] = {};

void read_channel(const ChannelSpec& ch, std::size_t ch_index, std::int64_t from_ts,
                  std::int64_t before_ts,
                  std::size_t cap, std::vector<NetConnRow>& out) {
    // Kernel-side filter: catalogued IDs inside [from, before). The same window
    // is re-checked on the parsed row — the XPath is an optimisation, the code
    // check is the contract (and covers a zero-parse fallback ts).
    const std::wstring query = std::wstring(L"*[System[") + ch.id_filter +
                               L" and TimeCreated[@SystemTime>='" +
                               yuzu::win::to_wide(format_event_systemtime(from_ts)) +
                               L"' and @SystemTime<'" +
                               yuzu::win::to_wide(format_event_systemtime(before_ts)) + L"']]]";

    // NEWEST-first: when a window holds more than `cap` events (a Wi-Fi flap
    // storm on a GPO-enlarged channel, or a large first-run window), the ones we
    // keep must be the most RECENT — the storm the operator is trying to
    // diagnose — not the oldest quiet period. The high-water mark still advances
    // to the window's upper bound, so the dropped OLDEST tail is not re-read;
    // that is the documented "upper bound on intent, not a promise of depth"
    // (echo_netconn.hpp) and matches ADR-0020's newest-first recovery.
    EvtGuard q{::EvtQuery(nullptr, ch.path, query.c_str(),
                          EvtQueryChannelPath | EvtQueryReverseDirection)};
    if (!q) {
        const DWORD err = ::GetLastError();
        // Missing channel (no WLAN service / Server SKU) is expected topology,
        // ACL-denial is expected under a hardened baseline: fewer rows, not an
        // error. Warn only the FIRST time per channel — the slow leg retries
        // this failing channel every tick for the process lifetime, so an
        // un-latched warn would grow the log without bound.
        if (ch_index < std::size(g_nc_query_warned) &&
            !g_nc_query_warned[ch_index].exchange(true))
            spdlog::warn("Echo netconn: EvtQuery {} failed ({}) — channel skipped "
                         "(silenced for the rest of this session)",
                         ch.tag, err);
        return;
    }

    std::size_t taken = 0;
    while (taken < cap) {
        EVT_HANDLE raw[64]{};
        DWORD got = 0;
        if (!::EvtNext(q.h, static_cast<DWORD>(std::size(raw)), raw, INFINITE, 0, &got))
            break; // ERROR_NO_MORE_ITEMS or a hard error — either way, done
        for (DWORD i = 0; i < got; ++i) {
            EvtGuard ev{raw[i]};
            if (taken >= cap)
                continue; // keep closing remaining handles
            const std::string xml = render_event_xml(ev.h);
            if (xml.empty())
                continue;
            auto row = parse_netconn_event_xml(ch.tag, xml);
            if (!row || row->ts < from_ts || row->ts >= before_ts)
                continue;
            out.push_back(std::move(*row));
            ++taken;
        }
    }
    if (taken >= cap)
        spdlog::warn("Echo netconn: {} backfill hit the per-channel cap ({}) — kept the "
                     "newest {} events; older events in the window were skipped",
                     ch.tag, cap, cap);
}

} // namespace

std::vector<NetConnRow> backfill_netconn_events(std::int64_t from_ts, std::int64_t before_ts,
                                                std::size_t cap) {
    std::vector<NetConnRow> out;
    if (before_ts <= from_ts || cap == 0)
        return out;
    for (std::size_t i = 0; i < std::size(kChannels); ++i)
        read_channel(kChannels[i], i, from_ts, before_ts, cap, out);
    return out;
}

} // namespace yuzu::echo

#else // !_WIN32

namespace yuzu::echo {

// Linux (journald) / macOS (oslog) readers are kPlanned — see the netconn
// schema source.
std::vector<NetConnRow> backfill_netconn_events(std::int64_t, std::int64_t, std::size_t) {
    return {};
}

} // namespace yuzu::echo

#endif
