/**
 * users_plugin.cpp — User accounts plugin for Yuzu
 *
 * Actions:
 *   "logged_on"       — Lists currently logged-on users.
 *   "sessions"        — Lists active interactive sessions.
 *   "local_users"     — Enumerates local user accounts.
 *   "local_admins"    — Lists members of the local Administrators group.
 *   "group_members"   — Lists members of a specified local group.
 *   "primary_user"    — Identifies the primary user (most frequent login).
 *   "session_history" — Shows historical login/logout session records.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (BR-07)

#ifndef _WIN32
#include <chrono>
#include <spdlog/spdlog.h>
#include <yuzu/agent/runner_status.hpp> // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (K-7/CDX-07, ADR-3002 rung 2)
#endif

#if defined(__APPLE__)
#include "users_macos_last.hpp" // pure `last -y` parsers (qe-M1)
#endif

#include <format>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <ctime>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <utmp.h>
#endif

#if defined(__APPLE__)
#include <ctime>
#include <macos_console_user.hpp>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <iterator> // std::size (EvtNext batch array bound)
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <winevt.h>     // EvtQuery / EvtNext / EvtRender / EvtClose
#include <lm.h>
#include <wtsapi32.h>
#include <user_profile_model.hpp> // yuzu::profiles::profile_name_from_path (PR1.7)
#include <win_profiles.hpp>       // yuzu::win::enumerate_profile_records (PR1.7)
#include "users_win_events.hpp"   // pure Security-channel XML parsers (Wave-2 WP-A)
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#endif

namespace {

// ── input validation ──────────────────────────────────────────────────────

/// Validate that a string contains only safe characters for use in shell commands.
/// Allows: [a-zA-Z0-9._-] — rejects anything with shell metacharacters.
bool is_safe_identifier(std::string_view s) {
    if (s.empty())
        return false;
    // Reject a leading '-' or '.' (sec-L1): the value is interpolated as a bare
    // token into `last -y -1 {user}` / `dscl` argument lists, and an option-like
    // account name (`-foo`) would otherwise be misread as a flag by `last`
    // (argument injection — no command injection, the allowlist below still
    // blocks every shell metacharacter, but wrong/empty output). Mirrors the
    // certificates plugin's is_valid_username first-character rule.
    if (s.front() == '-' || s.front() == '.')
        return false;
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

// ── subprocess helper (POSIX) ────────────────────────────────────────────

#ifndef _WIN32
// Per-call wall-clock bound for the local account tools (dscl/last/lastlog/
// who/w). Generous enough never to fire in practice, short enough that a
// wedged tool cannot pin the instruction worker indefinitely. Read-only
// tools stay within the plan's binding runner-idiom ceiling (5-10s).
constexpr std::chrono::seconds kUsersCmdDeadline{10};

/// Outcome of run_tool(): the captured output PLUS the raw runner result, so
/// a caller can forward the latter through the ABI4 result seam
/// (yuzu::agent::forward_runner_failure) itself instead of this helper
/// deciding that on the caller's behalf.
struct ToolOutcome {
    std::string output;
    yuzu::agent::SubprocessResult res;
};

/// Direct-argv replacement for the old shell-string hop that ran every
/// command through a shell interpreter (ADR-3002 rung 2): the same bounded,
/// fork-lock-covered runner, but exec'd straight to argv[0] with no shell in
/// between — no shell-quoting/injection surface, and a `2>/dev/null` suffix
/// the old shell string carried is simply this call's default
/// merge_stderr=false (child stderr -> /dev/null, the runner's documented
/// equivalent). Strips trailing CR/LF from `output` exactly as the old
/// helper did. `max_lines` (0 = unlimited) maps to what used to be a
/// `| head -N` pipe — NOT a `| tail -N`, which a caller still needs to
/// replicate in-process (max_lines caps the FIRST N lines).
///
/// Never touches ctx — every ACTION entry point forwards `res` itself via
/// a local `status_forwarded` guard, so a per-user/per-call loop reports
/// only the FIRST non-exit failure (later calls must not overwrite an
/// earlier UNAVAILABLE with a later CONSTRAINED — sdk/include/yuzu/plugin.h:
/// 287-288).
ToolOutcome run_tool(std::vector<std::string> argv, std::size_t max_lines = 0) {
    if (argv.empty() || argv.front().empty()) {
        // A probe_tool_path miss (empty argv[0]) or a programmer error
        // (empty argv): report the same shape run_bounded_subprocess uses
        // for its own runtime-reject (tool_ran=false, termination_reason=
        // spawn_error — both already SubprocessResult's default member
        // values) without ever attempting an OS call.
        return ToolOutcome{std::string{}, yuzu::agent::SubprocessResult{}};
    }

    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kUsersCmdDeadline,
                                             .max_lines = max_lines,
                                             .stop_after_max_lines = max_lines != 0});
    // A cut-short tool returns empty/partial output that parses as "no users /
    // unknown last-logon" — a silent false-negative. Warn so an operator can
    // distinguish a degraded scan from a genuinely empty result (sre-M1).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("users: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, argv.front());
    }
    std::string output = res.output;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    return ToolOutcome{std::move(output), std::move(res)};
}
#endif // !_WIN32

#ifdef _WIN32
// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

// Format a Windows FILETIME as "YYYY-MM-DD HH:MM:SS" or "Never" if zero
std::string format_filetime(DWORD low, DWORD high) {
    if (low == 0 && high == 0)
        return "Never";
    FILETIME ft;
    ft.dwLowDateTime = low;
    ft.dwHighDateTime = high;
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", st.wYear, st.wMonth, st.wDay,
                       st.wHour, st.wMinute, st.wSecond);
}

// ── Security-channel event log reader (wevtapi) ─────────────────────────

// EVT_HANDLE must be closed with EvtClose, not CloseHandle — a local
// single-owner guard, same shape as tar_netconn_win.cpp's EvtGuard.
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

// Render one event to UTF-8 XML (size-then-fill, same as tar_netconn_win.cpp).
std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0)
        return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return from_wide(buf.c_str());
}

// ADR-3002 rung-1 bounded-broker-call requirement: EvtNext is a daemon-
// mediated call (the Event Log service) that offers a bounded wait mode, so
// INFINITE is not an option here -- a wedged/heavily-contended service would
// otherwise pin the instruction worker forever, with no runner deadline to
// catch it (unlike the POSIX rung-2 argv sites, which run under
// kUsersCmdDeadline). 10s matches that same ceiling.
constexpr DWORD kEvtNextTimeoutMs = 10'000;

// Distinguishes WHY a Security-channel query failed, so the caller can give
// an operator an honest message and set the correct ABI4 result status
// instead of a single hardcoded "requires elevated privileges" that also
// fires for a missing/uninstalled channel or a mid-query timeout against a
// wedged (not stopped) Event Log service — three different operational
// facts that a governance chaos-injector pass found collapsed to one,
// possibly-misleading, message (I4: guidance that conceals the real state).
enum class EvtQueryOutcome { kOk, kAccessDenied, kChannelNotFound, kTimeout, kOtherError };

struct EvtQueryFailureInfo {
    const char* message;
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    const char* provenance;
};

inline EvtQueryFailureInfo describe_evt_query_failure(EvtQueryOutcome outcome) {
    switch (outcome) {
    case EvtQueryOutcome::kAccessDenied:
        return {"Cannot access Security event log (requires elevated privileges)",
               YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
               "users_win_events:access_denied"};
    case EvtQueryOutcome::kChannelNotFound:
        return {"Security event log channel not found or unavailable",
               YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
               "users_win_events:channel_not_found"};
    case EvtQueryOutcome::kTimeout:
        return {"Security event log query timed out (service may be degraded)",
               YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
               "users_win_events:evt_next_timeout"};
    case EvtQueryOutcome::kOk:
    case EvtQueryOutcome::kOtherError:
    default:
        return {"Security event log query failed", YUZU_RESULT_STATUS_UNAVAILABLE,
               YUZU_RESULT_COMPLETENESS_PARTIAL, "users_win_events:evt_query_failed"};
    }
}

// Queries the Security channel with `xpath`, newest-first, rendering up to
// `cap` events to XML and folding each through
// yuzu::users_win::parse_logon_events into `out`. Returns a non-kOk outcome
// when EvtQuery itself failed (missing/ACL-denied channel) OR when EvtNext
// failed with anything other than ERROR_NO_MORE_ITEMS (a genuine I/O/access
// error mid-query, including a timeout against a wedged service, must not be
// reported as a clean, if partial, success) — either way the caller owns the
// fallback/error path. A successful, fully-exhausted query still returns
// kOk with `out` possibly empty (a real, distinct fact from "couldn't query
// at all"). Every EVT_HANDLE — including EvtNext batch handles seen after
// the cap is hit — is owned by an EvtGuard.
EvtQueryOutcome query_logon_events(const wchar_t* xpath, std::size_t cap,
                                   std::vector<yuzu::users_win::LogonEvent>& out) {
    EvtGuard q{::EvtQuery(nullptr, L"Security", xpath,
                          EvtQueryChannelPath | EvtQueryReverseDirection)};
    if (!q) {
        switch (::GetLastError()) {
        case ERROR_ACCESS_DENIED:
            return EvtQueryOutcome::kAccessDenied;
        case ERROR_EVT_CHANNEL_NOT_FOUND:
        case ERROR_FILE_NOT_FOUND:
            return EvtQueryOutcome::kChannelNotFound;
        default:
            return EvtQueryOutcome::kOtherError;
        }
    }

    std::size_t taken = 0;
    while (taken < cap) {
        EVT_HANDLE raw[64]{};
        DWORD got = 0;
        if (!::EvtNext(q.h, static_cast<DWORD>(std::size(raw)), raw, kEvtNextTimeoutMs, 0,
                       &got)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_NO_MORE_ITEMS) {
                // A genuine I/O/access error (incl. ERROR_TIMEOUT), not clean
                // exhaustion -- distinguish a mid-query timeout from every
                // other failure so it doesn't read as "access denied".
                return err == ERROR_TIMEOUT ? EvtQueryOutcome::kTimeout
                                            : EvtQueryOutcome::kOtherError;
            }
            break; // ERROR_NO_MORE_ITEMS — legitimately exhausted, done
        }
        for (DWORD i = 0; i < got; ++i) {
            EvtGuard ev{raw[i]};
            if (taken >= cap)
                continue; // keep closing remaining handles in this batch
            const std::string xml = render_event_xml(ev.h);
            if (xml.empty())
                continue;
            for (auto& parsed : yuzu::users_win::parse_logon_events(xml)) {
                out.push_back(std::move(parsed));
                if (++taken >= cap)
                    break;
            }
        }
    }
    return EvtQueryOutcome::kOk;
}
#endif // _WIN32

// ── logged_on action ──────────────────────────────────────────────────────

int do_logged_on(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Read utmp for logged-on users
    setutent();
    struct utmp* entry;
    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type == USER_PROCESS) {
            std::string user(entry->ut_user);
            std::string host(entry->ut_host);
            std::string line(entry->ut_line);
            // Determine logon type from tty name
            std::string logon_type = "console";
            if (line.starts_with("pts/"))
                logon_type = "remote";
            std::string session_id = line;
            ctx.write_output(std::format("user|{}|{}|{}|{}", user, host.empty() ? "local" : host,
                                         logon_type, session_id));
        }
    }
    endutent();

#elif defined(__APPLE__)
    bool status_forwarded = false;
    auto who_path = yuzu::agent::probe_tool_path({"/usr/bin/who", "/bin/who"});
    // sink: users/do_logged_on#1 — `who` enumerates logged-on sessions; macOS
    // exposes no native enumeration API for this (unlike Linux's utmp above).
    auto who_res = run_tool({who_path});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, who_res.res);
    auto& who_out = who_res.output;
    if (!who_out.empty()) {
        std::istringstream ss(who_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: username  tty  date time (host)
            std::istringstream ls(line);
            std::string user, tty;
            ls >> user >> tty;
            std::string logon_type = "console";
            if (tty.starts_with("ttys"))
                logon_type = "remote";
            // Extract host if present (in parentheses at end)
            std::string domain = "local";
            auto paren = line.rfind('(');
            if (paren != std::string::npos) {
                auto end = line.rfind(')');
                if (end != std::string::npos && end > paren) {
                    domain = line.substr(paren + 1, end - paren - 1);
                }
            }
            ctx.write_output(std::format("user|{}|{}|{}|{}", user, domain, logon_type, tty));
        }
    }

#elif defined(_WIN32)
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (sessions[i].State != WTSActive && sessions[i].State != WTSDisconnected)
                continue;

            LPWSTR user_buf = nullptr;
            DWORD user_len = 0;
            LPWSTR domain_buf = nullptr;
            DWORD domain_len = 0;

            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSUserName, &user_buf, &user_len);
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSDomainName, &domain_buf, &domain_len);

            auto user = from_wide(user_buf);
            auto domain = from_wide(domain_buf);

            if (user_buf)
                WTSFreeMemory(user_buf);
            if (domain_buf)
                WTSFreeMemory(domain_buf);

            if (user.empty())
                continue;

            std::string logon_type = "console";
            auto session_name = from_wide(sessions[i].pWinStationName);
            if (session_name.find("RDP") != std::string::npos ||
                session_name.find("rdp") != std::string::npos) {
                logon_type = "RDP";
            }

            ctx.write_output(std::format("user|{}|{}|{}|{}", user,
                                         domain.empty() ? "local" : domain, logon_type,
                                         sessions[i].SessionId));
        }
        WTSFreeMemory(sessions);
    }
#endif
    return 0;
}

// ── sessions action ───────────────────────────────────────────────────────

int do_sessions(yuzu::CommandContext& ctx) {
#ifdef __linux__
    bool status_forwarded = false;
    auto w_path = yuzu::agent::probe_tool_path({"/usr/bin/w", "/bin/w"});
    // sink: users/do_sessions#1 — `w` reports per-session idle/from-host
    // info; no single syscall/proc read gives the same view (utmp alone
    // lacks idle time).
    auto w_res = run_tool({w_path, "-h"});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, w_res.res);
    auto& w_out = w_res.output;
    if (!w_out.empty()) {
        std::istringstream ss(w_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Fields: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
            std::istringstream ls(line);
            std::string user, tty, from, login, idle;
            ls >> user >> tty >> from >> login >> idle;
            std::string state = "Active";
            // Parse idle time to seconds (format: "1:23" or "1.00s" or "1days")
            std::string idle_seconds = idle;
            ctx.write_output(std::format("session|{}|{}|{}|{}|{}", tty, user, state,
                                         from.empty() ? "-" : from, idle));
        }
    }

#elif defined(__APPLE__)
    bool status_forwarded = false;
    auto w_path = yuzu::agent::probe_tool_path({"/usr/bin/w", "/bin/w"});
    // sink: users/do_sessions#2 — `w` reports per-session idle/from-host
    // info; no equivalent native macOS API is wired in this plugin.
    auto w_res = run_tool({w_path, "-h"});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, w_res.res);
    auto& w_out = w_res.output;
    if (!w_out.empty()) {
        std::istringstream ss(w_out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string user, tty, from, login, idle;
            ls >> user >> tty >> from >> login >> idle;
            ctx.write_output(std::format("session|{}|{}|Active|{}|{}", tty, user,
                                         from.empty() ? "-" : from, idle));
        }
    }

#elif defined(_WIN32)
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            LPWSTR user_buf = nullptr;
            DWORD user_len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSUserName, &user_buf, &user_len);
            auto user = from_wide(user_buf);
            if (user_buf)
                WTSFreeMemory(user_buf);

            if (user.empty())
                continue;

            const char* state = "unknown";
            switch (sessions[i].State) {
            case WTSActive:
                state = "Active";
                break;
            case WTSConnected:
                state = "Connected";
                break;
            case WTSDisconnected:
                state = "Disconnected";
                break;
            case WTSIdle:
                state = "Idle";
                break;
            case WTSListen:
                state = "Listen";
                break;
            default:
                state = "Other";
                break;
            }

            // Get client name for RDP sessions
            LPWSTR client_buf = nullptr;
            DWORD client_len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSClientName, &client_buf, &client_len);
            auto client = from_wide(client_buf);
            if (client_buf)
                WTSFreeMemory(client_buf);

            // Get idle time
            WTSINFOEXW* info_buf = nullptr;
            DWORD info_len = 0;
            long long idle_secs = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                            WTSSessionInfo, reinterpret_cast<LPWSTR*>(&info_buf),
                                            &info_len) &&
                info_buf) {
                // IdleTime is a LARGE_INTEGER representing 100-nanosecond intervals
                // But WTSINFOEXA has different layout; use CurrentTime - LastInputTime
                // For simplicity, report 0 for active sessions
                WTSFreeMemory(info_buf);
            }

            ctx.write_output(std::format("session|{}|{}|{}|{}|{}", sessions[i].SessionId, user,
                                         state, client.empty() ? "-" : client, idle_secs));
        }
        WTSFreeMemory(sessions);
    }
#endif
    return 0;
}

#if defined(__APPLE__)
// The `last -y` timestamp/weekday parsers live in users_macos_last.hpp so they
// are independently unit-testable without a subprocess (qe-M1); bring them into
// scope here unqualified to keep the call sites below unchanged.
using yuzu::users_macos::is_weekday;
using yuzu::users_macos::parse_last_timestamp;
#endif // __APPLE__

// ── local_users action ────────────────────────────────────────────────────

int do_local_users(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream passwd("/etc/passwd");
    if (!passwd) {
        ctx.write_output("local_user|error|false|Never|Cannot read /etc/passwd");
        return 1;
    }
    bool status_forwarded = false;
    auto lastlog_path = yuzu::agent::probe_tool_path({"/usr/bin/lastlog", "/bin/lastlog"});
    std::string line;
    while (std::getline(passwd, line)) {
        // Format: username:x:uid:gid:description:home:shell
        std::istringstream ls(line);
        std::string user, x, uid_s, gid_s, desc, home, shell;
        std::getline(ls, user, ':');
        std::getline(ls, x, ':');
        std::getline(ls, uid_s, ':');
        std::getline(ls, gid_s, ':');
        std::getline(ls, desc, ':');
        std::getline(ls, home, ':');
        std::getline(ls, shell, ':');

        int uid = 0;
        try {
            uid = std::stoi(uid_s);
        } catch (...) {}

        // Skip system accounts (uid < 1000, except root)
        if (uid != 0 && uid < 1000)
            continue;
        // Skip nologin/false shell accounts
        bool enabled = true;
        if (shell.find("nologin") != std::string::npos ||
            shell.find("/false") != std::string::npos) {
            enabled = false;
        }

        // Try to get last login from lastlog. `user` comes from /etc/passwd
        // (local-trust), but guard argv construction with the same allowlist
        // the operator-facing paths use — a hostile local account name must
        // not be able to reach the lastlog argv as an unexpected flag/token.
        std::string last_logon = "unknown";
        std::string lastlog_out;
        if (is_safe_identifier(user)) {
            // sink: users/do_local_users#1 — `lastlog` reports per-account
            // last-login time; no /var/log/lastlog reader is wired in this
            // plugin. `| tail -1` is replicated below, in-process: max_lines
            // caps the FIRST N lines, which would invert `tail`'s "last
            // line" selection.
            auto res = run_tool({lastlog_path, "-u", user});
            if (!status_forwarded)
                status_forwarded = yuzu::agent::forward_runner_failure(ctx, res.res);
            std::istringstream ll_ss(res.output);
            std::string ll_line;
            while (std::getline(ll_ss, ll_line)) {
                if (!ll_line.empty())
                    lastlog_out = ll_line;
            }
        }
        if (!lastlog_out.empty() && lastlog_out.find("Never") != std::string::npos) {
            last_logon = "Never";
        } else if (!lastlog_out.empty()) {
            // Extract the date portion (after Username and Port columns)
            auto from_pos = lastlog_out.find("**");
            if (from_pos == std::string::npos) {
                // Try to extract date after the port field
                last_logon = lastlog_out;
            }
        }

        ctx.write_output(std::format("local_user|{}|{}|{}|{}", user, enabled ? "true" : "false",
                                     last_logon, desc.empty() ? "-" : desc));
    }

#elif defined(__APPLE__)
    // M7: macOS dscl output format assumption.
    // `dscl . -list /Users UniqueID` outputs lines of "username  UID" separated
    // by whitespace. `dscl . -read /Users/<name> <key>` outputs "Key: Value"
    // on a single line (or "Key:\n Value" for multi-line values like RealName).
    // Tested and verified on macOS 14 (Sonoma). If Apple changes the dscl
    // output format in a future macOS release, this parsing will need updating.
    bool status_forwarded = false;
    // sink: users/do_local_users#2 — `dscl . -list /Users UniqueID`
    // enumerates local accounts; Directory Services exposes no lighter-weight
    // C API this plugin already links against.
    auto dscl_res = run_tool({"/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, dscl_res.res);
    auto& dscl_out = dscl_res.output;
    // Queried once per call, not per user: the console/GUI-login user via the
    // shared helper (agents/shared/macos_console_user.hpp). nullopt (no
    // SystemConfiguration, or nobody at the console) means every row below
    // honestly reports is_console_user="unknown" rather than guessing false.
    auto console_login_user = yuzu::macos::console_user();
    auto last_path = yuzu::agent::probe_tool_path({"/usr/bin/last", "/bin/last"});
    if (!dscl_out.empty()) {
        std::istringstream ss(dscl_out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string user, uid_s;
            ls >> user >> uid_s;
            int uid = 0;
            try {
                uid = std::stoi(uid_s);
            } catch (...) {}
            // Skip system accounts
            if (uid < 500 && user != "root")
                continue;
            if (user.starts_with("_"))
                continue;

            // Validate username before using it in an argv element. A bare
            // `continue` here would silently drop the account from output
            // entirely -- an admin-privileged actor could rename an account
            // to a name outside is_safe_identifier's charset specifically to
            // blind this enumeration, with the tool reporting a clean,
            // complete-looking result (governance chaos-injector finding,
            // I3/HIGH). Emit a degraded row instead: the account stays
            // visible, and no further dscl/last call ever reaches the
            // unsafe name as an argv element. Matches the Linux branch
            // above, which already degrades (last_logon stays "unknown")
            // rather than dropping the row on the same condition.
            if (!is_safe_identifier(user)) {
                // `user` failed the argv-safety check precisely because it
                // contains a character outside the allowed charset -- it is
                // exactly the value most likely to carry a literal '|' or an
                // embedded CR/LF, the same row/column-injection class the
                // `desc` field below is already escaped against (K-11/CDX-10).
                ctx.write_output(std::format("local_user|{}|unknown|unknown|-|unknown",
                                             yuzu::util::safe_output_field(user)));
                continue;
            }

            // Check if account is enabled
            // sink: users/do_local_users#3 — `dscl . -read UserShell` reads
            // one account's login shell.
            auto shell_res = run_tool(
                {"/usr/bin/dscl", ".", "-read", std::format("/Users/{}", user), "UserShell"});
            if (!status_forwarded)
                status_forwarded = yuzu::agent::forward_runner_failure(ctx, shell_res.res);
            auto& shell = shell_res.output;
            // Extract second field (the shell path) without piping to awk
            bool enabled = true;
            {
                auto sp = shell.find(' ');
                if (sp != std::string::npos) {
                    auto shell_path = shell.substr(sp + 1);
                    while (!shell_path.empty() && shell_path.front() == ' ')
                        shell_path.erase(shell_path.begin());
                    enabled = shell_path.find("false") == std::string::npos &&
                              shell_path.find("nologin") == std::string::npos;
                }
            }

            // sink: users/do_local_users#4 — `dscl . -read RealName` reads
            // one account's display name.
            auto desc_res = run_tool(
                {"/usr/bin/dscl", ".", "-read", std::format("/Users/{}", user), "RealName"});
            if (!status_forwarded)
                status_forwarded = yuzu::agent::forward_runner_failure(ctx, desc_res.res);
            auto& desc_raw = desc_res.output;
            // Extract real name: skip first line ("RealName:"), trim leading space
            std::string desc;
            {
                auto nl = desc_raw.find('\n');
                if (nl != std::string::npos) {
                    desc = desc_raw.substr(nl + 1);
                    while (!desc.empty() && desc.front() == ' ')
                        desc.erase(desc.begin());
                } else {
                    // Single-line: strip "RealName: " prefix
                    auto colon2 = desc_raw.find(':');
                    if (colon2 != std::string::npos) {
                        desc = desc_raw.substr(colon2 + 1);
                        while (!desc.empty() && desc.front() == ' ')
                            desc.erase(desc.begin());
                    }
                }
            }

            // last_logon: parse `last -y -1 <user>` for this user's most
            // recent login record (the plugin already uses plain `last` for
            // primary_user above). `-y` forces an explicit year in the
            // output so parse_last_timestamp never has to guess one, and
            // `LC_ALL=C` pins the weekday/month names and the "wtmp begins"
            // boilerplate to a locale this parser understands. `user` was
            // already validated by is_safe_identifier above before any
            // subprocess use. Default is "unknown": a command failure,
            // empty output, or unrecognized output leaves it there rather
            // than fabricating "Never" for an indeterminate result. "Never"
            // is only assigned once the boilerplate line confirms `last`
            // actually ran and completed its (empty) search for this user.
            std::string last_logon = "unknown";
            {
                // sink: users/do_local_users#5 — `last -y -1 <user>` reads
                // one account's most recent login record. Spawned via
                // `/usr/bin/env LC_ALL=C <last> ...` rather than a shell:
                // SubprocessOptions has no env field, and LC_ALL=C is
                // LOAD-BEARING (is_weekday/parse_last_timestamp above match
                // only English day/month names) — /usr/bin/env is a plain
                // exec wrapper, not an interpreter, so this stays rung 2
                // with no shell involved.
                auto last_res =
                    run_tool({"/usr/bin/env", "LC_ALL=C", last_path, "-y", "-1", user});
                if (!status_forwarded)
                    status_forwarded = yuzu::agent::forward_runner_failure(ctx, last_res.res);
                auto& last_out = last_res.output;
                bool saw_record = false;
                std::istringstream last_ss(last_out);
                std::string last_line;
                while (std::getline(last_ss, last_line)) {
                    if (last_line.empty())
                        continue;
                    std::istringstream ls2(last_line);
                    std::string first;
                    ls2 >> first;
                    // Boilerplate lines (e.g. "wtmp begins ...") don't start
                    // with the username; `last -1 <user>` already filters to
                    // this user, so a first-token match is the real record.
                    if (first != user)
                        continue;
                    saw_record = true;
                    std::vector<std::string> tokens;
                    std::string tok;
                    while (ls2 >> tok)
                        tokens.push_back(tok);
                    for (size_t i = 0; i + 4 < tokens.size(); ++i) {
                        if (is_weekday(tokens[i])) {
                            auto parsed = parse_last_timestamp(tokens[i + 1], tokens[i + 2],
                                                               tokens[i + 3], tokens[i + 4]);
                            if (!parsed.empty()) {
                                last_logon = parsed;
                                break;
                            }
                        }
                    }
                    break;
                }
                if (!saw_record && last_out.find("wtmp begins") != std::string::npos)
                    last_logon = "Never";
            }

            // console_state is tri-state, not a bool: console_login_user is
            // std::nullopt whenever detection is unavailable (no
            // SystemConfiguration, or the API call failed), and that must
            // stay distinguishable from a confirmed "not the console user"
            // -- collapsing it to false would misreport an unknown state as
            // a definite negative, including for the real console user.
            std::string console_state = "unknown";
            if (console_login_user)
                console_state = *console_login_user == user ? "true" : "false";

            // NOTE arity extension: local_user gained a 6th field
            // (is_console_user) here to surface the GUI-login signal
            // honestly; other platforms keep the original 5-field
            // local_user|username|enabled|last_logon|description form. The
            // field is tri-state ("true"/"false"/"unknown"), not boolean.
            // safe_output_field on desc: a directory RealName can carry an
            // embedded CR/LF (multi-valued/malformed) or a literal '|', either
            // of which would inject an extra output row or shift columns
            // (K-11/CDX-10). Matches the certificates/event_logs row-safety
            // discipline on the same branch.
            ctx.write_output(std::format("local_user|{}|{}|{}|{}|{}", user,
                                         enabled ? "true" : "false", last_logon,
                                         desc.empty() ? "-" : yuzu::util::safe_output_field(desc),
                                         console_state));
        }
    }

#elif defined(_WIN32)
    LPUSER_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD resume = 0;
    NET_API_STATUS status;

    do {
        status = NetUserEnum(nullptr, 2, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE*>(&buf),
                             MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume);

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entries_read; ++i) {
                auto& u = buf[i];
                auto name = from_wide(u.usri2_name);
                bool enabled = !(u.usri2_flags & UF_ACCOUNTDISABLE);
                auto comment = from_wide(u.usri2_comment);

                // Format last logon
                std::string last_logon = "Never";
                if (u.usri2_last_logon != 0) {
                    time_t t = static_cast<time_t>(u.usri2_last_logon);
                    struct tm tm_buf {};
                    localtime_s(&tm_buf, &t);
                    char time_str[64]{};
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
                    last_logon = time_str;
                }

                ctx.write_output(std::format("local_user|{}|{}|{}|{}", name,
                                             enabled ? "true" : "false", last_logon,
                                             comment.empty() ? "-" : comment));
            }
            NetApiBufferFree(buf);
            buf = nullptr;
        }
    } while (status == ERROR_MORE_DATA);
#endif
    return 0;
}

// ── local_admins action ───────────────────────────────────────────────────

int do_local_admins(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Check sudo and wheel groups
    for (const char* group_name : {"sudo", "wheel"}) {
        struct group* grp = getgrnam(group_name);
        if (!grp)
            continue;
        for (char** member = grp->gr_mem; *member; ++member) {
            ctx.write_output(std::format("admin|{}|user|{}", *member, group_name));
        }
    }
    // Also check root (uid 0) in /etc/passwd
    struct passwd* pw = getpwuid(0);
    if (pw) {
        ctx.write_output(std::format("admin|{}|user|root", pw->pw_name));
    }

#elif defined(__APPLE__)
    bool status_forwarded = false;
    // sink: users/do_local_admins#1 — `dscl . -read /Groups/admin
    // GroupMembership` reads the local admin group's membership.
    auto admin_res =
        run_tool({"/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, admin_res.res);
    auto& admin_out = admin_res.output;
    if (!admin_out.empty()) {
        // Format: GroupMembership: user1 user2 user3
        auto colon = admin_out.find(':');
        if (colon != std::string::npos) {
            auto members = admin_out.substr(colon + 1);
            std::istringstream ss(members);
            std::string member;
            while (ss >> member) {
                ctx.write_output(std::format("admin|{}|user|admin", member));
            }
        }
    } else if (status_forwarded) {
        // A runner failure (dscl timeout/spawn_error) must not read
        // identically to "queried cleanly, zero admins" -- the caller's
        // result_status already carries the failure (forward_runner_failure
        // above), but the text output alone was previously indistinguishable
        // from a genuinely admin-free host (Gate 4 unhappy-path finding).
        ctx.write_output("admin|error|query failed");
    }

#elif defined(_WIN32)
    LPLOCALGROUP_MEMBERS_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD_PTR resume = 0;

    NET_API_STATUS status =
        NetLocalGroupGetMembers(nullptr, L"Administrators", 2, reinterpret_cast<LPBYTE*>(&buf),
                                MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume);

    if (status == NERR_Success) {
        for (DWORD i = 0; i < entries_read; ++i) {
            auto& m = buf[i];
            auto name = from_wide(m.lgrmi2_domainandname);

            const char* type_str = "unknown";
            switch (m.lgrmi2_sidusage) {
            case SidTypeUser:
                type_str = "user";
                break;
            case SidTypeGroup:
                type_str = "group";
                break;
            case SidTypeWellKnownGroup:
                type_str = "well_known_group";
                break;
            case SidTypeAlias:
                type_str = "alias";
                break;
            default:
                break;
            }

            // Split domain\name
            std::string domain = "local";
            std::string member_name = name;
            auto backslash = name.find('\\');
            if (backslash != std::string::npos) {
                domain = name.substr(0, backslash);
                member_name = name.substr(backslash + 1);
            }

            ctx.write_output(std::format("admin|{}|{}|{}", member_name, type_str, domain));
        }
        NetApiBufferFree(buf);
    }
#endif
    return 0;
}

// ── group_members action ──────────────────────────────────────────────────

int do_group_members(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto group_name = params.get("group");
    if (group_name.empty()) {
        ctx.write_output("group_member|error|Missing required parameter: group");
        return 1;
    }

    // Validate group_name to prevent command injection on platforms that use shell commands
    if (!is_safe_identifier(group_name)) {
        ctx.write_output(std::format("group_member|error|Invalid group name: {}", group_name));
        return 1;
    }

#ifdef __linux__
    struct group* grp = getgrnam(std::string(group_name).c_str());
    if (!grp) {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    }
    for (char** member = grp->gr_mem; *member; ++member) {
        ctx.write_output(std::format("group_member|{}|{}|user", *member, group_name));
    }

    // Also check if any user has this as their primary group (GID match)
    std::ifstream passwd("/etc/passwd");
    if (passwd) {
        std::string line;
        while (std::getline(passwd, line)) {
            std::istringstream ls(line);
            std::string user, x, uid_s, gid_s;
            std::getline(ls, user, ':');
            std::getline(ls, x, ':');
            std::getline(ls, uid_s, ':');
            std::getline(ls, gid_s, ':');
            int gid = 0;
            try {
                gid = std::stoi(gid_s);
            } catch (...) {}
            if (gid == static_cast<int>(grp->gr_gid)) {
                // Check if already listed as explicit member
                bool already_listed = false;
                for (char** member = grp->gr_mem; *member; ++member) {
                    if (user == *member) {
                        already_listed = true;
                        break;
                    }
                }
                if (!already_listed) {
                    ctx.write_output(
                        std::format("group_member|{}|{}|primary_group", user, group_name));
                }
            }
        }
    }

#elif defined(__APPLE__)
    bool status_forwarded = false;
    // sink: users/do_group_members#1 — `dscl . -read /Groups/<name>
    // GroupMembership` reads an arbitrary local group's membership by name
    // (group_name is validated by is_safe_identifier above, and is now a
    // literal argv element, not a shell token).
    auto dscl_res = run_tool(
        {"/usr/bin/dscl", ".", "-read", std::format("/Groups/{}", group_name), "GroupMembership"});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, dscl_res.res);
    auto& dscl_out = dscl_res.output;
    if (!dscl_out.empty()) {
        auto colon = dscl_out.find(':');
        if (colon != std::string::npos) {
            auto members_str = dscl_out.substr(colon + 1);
            std::istringstream ss(members_str);
            std::string member;
            while (ss >> member) {
                ctx.write_output(std::format("group_member|{}|{}|user", member, group_name));
            }
        }
    } else if (status_forwarded) {
        // A runner failure (dscl timeout/spawn_error) is a different fact
        // than "queried cleanly, group doesn't exist" -- the Windows branch
        // below already distinguishes NERR_GroupNotFound from a generic
        // query failure; this branch previously asserted "Group not found"
        // regardless of cause (Gate 4 unhappy-path finding).
        ctx.write_output(std::format("group_member|error|Query failed for group: {}", group_name));
        return 1;
    } else {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    }

#elif defined(_WIN32)
    // Convert group name to wide string
    std::wstring wgroup(group_name.begin(), group_name.end());

    LPLOCALGROUP_MEMBERS_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD_PTR resume = 0;

    NET_API_STATUS status =
        NetLocalGroupGetMembers(nullptr, wgroup.c_str(), 2, reinterpret_cast<LPBYTE*>(&buf),
                                MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume);

    if (status == NERR_Success || status == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entries_read; ++i) {
            auto& m = buf[i];
            auto name = from_wide(m.lgrmi2_domainandname);

            const char* type_str = "unknown";
            switch (m.lgrmi2_sidusage) {
            case SidTypeUser:
                type_str = "user";
                break;
            case SidTypeGroup:
                type_str = "group";
                break;
            case SidTypeWellKnownGroup:
                type_str = "well_known_group";
                break;
            case SidTypeAlias:
                type_str = "alias";
                break;
            default:
                break;
            }

            // Split domain\name
            std::string member_name = name;
            auto backslash = name.find('\\');
            if (backslash != std::string::npos) {
                member_name = name.substr(backslash + 1);
            }

            ctx.write_output(
                std::format("group_member|{}|{}|{}", member_name, group_name, type_str));
        }
        NetApiBufferFree(buf);
    } else if (status == NERR_GroupNotFound || status == ERROR_NO_SUCH_ALIAS) {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    } else {
        ctx.write_output(std::format("group_member|error|Failed to query group: {}", group_name));
        return 1;
    }
#endif
    return 0;
}

// ── primary_user action ──────────────────────────────────────────────────

int do_primary_user(yuzu::CommandContext& ctx) {
#ifdef __linux__
    bool status_forwarded = false;
    auto last_path = yuzu::agent::probe_tool_path({"/usr/bin/last", "/bin/last"});
    // sink: users/do_primary_user#1 — `last -F` enumerates login history to
    // derive the most-frequent interactive user; capped in-process via
    // max_lines/stop_after_max_lines (was `| head -200`).
    auto last_res = run_tool({last_path, "-F"}, 200);
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, last_res.res);
    auto& last_out = last_res.output;
    if (!last_out.empty()) {
        std::map<std::string, int> login_counts;
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("reboot") || line.starts_with("wtmp"))
                continue;
            std::istringstream ls(line);
            std::string user;
            ls >> user;
            if (user.empty() || user == "reboot" || user == "wtmp")
                continue;
            login_counts[user]++;
        }

        // Find the user with most logins
        std::string primary;
        int max_count = 0;
        for (const auto& [user, count] : login_counts) {
            if (count > max_count) {
                max_count = count;
                primary = user;
            }
        }

        if (!primary.empty()) {
            ctx.write_output(std::format("primary_user|{}|{}|last", primary, max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no login records");
        }
    } else {
        ctx.write_output("primary_user|unknown|0|last command failed");
    }

#elif defined(__APPLE__)
    // macOS: use 'last' command similarly
    bool status_forwarded = false;
    auto last_path = yuzu::agent::probe_tool_path({"/usr/bin/last", "/bin/last"});
    // sink: users/do_primary_user#2 — `last` enumerates login history to
    // derive the most-frequent interactive user; capped in-process via
    // max_lines/stop_after_max_lines (was `| head -200`).
    auto last_res = run_tool({last_path}, 200);
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, last_res.res);
    auto& last_out = last_res.output;
    if (!last_out.empty()) {
        std::map<std::string, int> login_counts;
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("reboot") || line.starts_with("wtmp") ||
                line.starts_with("shutdown"))
                continue;
            std::istringstream ls(line);
            std::string user;
            ls >> user;
            if (user.empty() || user == "reboot" || user == "wtmp" || user == "shutdown")
                continue;
            login_counts[user]++;
        }

        std::string primary;
        int max_count = 0;
        for (const auto& [user, count] : login_counts) {
            if (count > max_count) {
                max_count = count;
                primary = user;
            }
        }

        if (!primary.empty()) {
            ctx.write_output(std::format("primary_user|{}|{}|last", primary, max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no login records");
        }
    } else {
        ctx.write_output("primary_user|unknown|0|last command failed");
    }

#elif defined(_WIN32)
    // Windows: read the Security Event Log natively via wevtapi (EvtQuery/
    // EvtRender), newest-first, capped at 200 events — no wevtutil shell-out.
    std::vector<yuzu::users_win::LogonEvent> events;
    const auto evt_outcome = query_logon_events(L"*[System[EventID=4624]]", 200, events);
    if (evt_outcome == EvtQueryOutcome::kOk) {
        auto [primary, max_count] = yuzu::users_win::primary_user_from_events(events);
        if (!primary.empty()) {
            // primary originates from decoded Security-channel event XML --
            // see session_history_rows' identical safe_output_field rationale.
            ctx.write_output(std::format("primary_user|{}|{}|event_log_4624",
                                         yuzu::util::safe_output_field(primary), max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no logon events found");
        }
    } else {
        // Fallback: enumerate ProfileList via the shared Win32 shell
        // (agents/shared/win_profiles.hpp) — no registry shell-out. Same
        // "last profile path under \Users\ wins" selection as before, just
        // driven by RegEnumKeyExW/RegQueryValueExW instead of parsing
        // `reg query /s` text.
        bool ok = false;
        auto records = yuzu::win::enumerate_profile_records(ok);
        std::string last_user;
        for (const auto& rec : records) {
            if (rec.profile_image_path.find("\\Users\\") == std::string::npos)
                continue;
            auto name = yuzu::profiles::profile_name_from_path(rec.profile_image_path);
            if (!name.empty())
                last_user = name;
        }
        if (!ok) {
            // Both the event-log path and the ProfileList fallback failed --
            // surface the more specific event-log failure reason/status
            // rather than a bare "cannot query" (the same message-conflation
            // gap fixed for session_history below).
            const auto info = describe_evt_query_failure(evt_outcome);
            ctx.set_result_status(info.status, info.completeness, info.provenance);
            ctx.write_output(std::format("primary_user|unknown|0|cannot query event log or "
                                         "registry ({})",
                                         info.message));
        } else if (!last_user.empty()) {
            ctx.write_output(std::format("primary_user|{}|0|profile_list", last_user));
        } else {
            ctx.write_output("primary_user|unknown|0|no profiles found");
        }
    }
#endif
    return 0;
}

// ── session_history action ───────────────────────────────────────────────

int do_session_history(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto count_param = params.get("count", "50");
    int count = 50;
    try {
        count = std::stoi(std::string(count_param));
        if (count < 1 || count > 500)
            count = 50;
    } catch (...) {
        count = 50;
    }

#ifdef __linux__
    bool status_forwarded = false;
    auto last_path = yuzu::agent::probe_tool_path({"/usr/bin/last", "/bin/last"});
    // sink: users/do_session_history#1 — `last -F -n <count>` reads recent
    // login/logout records; `-n <count>` already bounds the tool's own
    // output, so no max_lines cap is needed here.
    auto last_res = run_tool({last_path, "-F", "-n", std::to_string(count)});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, last_res.res);
    auto& last_out = last_res.output;
    if (!last_out.empty()) {
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("wtmp"))
                continue;
            // Parse 'last' output: USER TTY HOST LOGIN_TIME - LOGOUT_TIME (DURATION)
            std::istringstream ls(line);
            std::string user, tty, source;
            ls >> user >> tty >> source;
            if (user.empty() || user == "wtmp")
                continue;

            // The rest of the line contains timestamps and duration
            std::string rest;
            std::getline(ls, rest);
            auto start = rest.find_first_not_of(" \t");
            if (start != std::string::npos)
                rest = rest.substr(start);

            // Determine if still logged in
            std::string status = "completed";
            if (rest.find("still logged in") != std::string::npos)
                status = "active";
            else if (rest.find("crash") != std::string::npos)
                status = "crash";

            std::string logon_type = "console";
            if (tty.starts_with("pts/"))
                logon_type = "remote";
            else if (user == "reboot")
                logon_type = "system";

            ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", user, tty, source,
                                         logon_type, status, rest.empty() ? "-" : rest));
        }
    } else {
        ctx.write_output("session_history|error|last command failed");
    }

#elif defined(__APPLE__)
    bool status_forwarded = false;
    auto last_path = yuzu::agent::probe_tool_path({"/usr/bin/last", "/bin/last"});
    // sink: users/do_session_history#2 — `last -n <count>` reads recent
    // login/logout records; `-n <count>` already bounds the tool's own
    // output, so no max_lines cap is needed here.
    auto last_res = run_tool({last_path, "-n", std::to_string(count)});
    if (!status_forwarded)
        status_forwarded = yuzu::agent::forward_runner_failure(ctx, last_res.res);
    auto& last_out = last_res.output;
    if (!last_out.empty()) {
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("wtmp"))
                continue;
            std::istringstream ls(line);
            std::string user, tty, source;
            ls >> user >> tty >> source;
            if (user.empty() || user == "wtmp")
                continue;

            std::string rest;
            std::getline(ls, rest);
            auto start = rest.find_first_not_of(" \t");
            if (start != std::string::npos)
                rest = rest.substr(start);

            std::string status = "completed";
            if (rest.find("still logged in") != std::string::npos)
                status = "active";
            else if (rest.find("crash") != std::string::npos)
                status = "crash";

            std::string logon_type = "console";
            if (tty.starts_with("ttys"))
                logon_type = "remote";
            else if (user == "reboot" || user == "shutdown")
                logon_type = "system";

            ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", user, tty, source,
                                         logon_type, status, rest.empty() ? "-" : rest));
        }
    } else {
        ctx.write_output("session_history|error|last command failed");
    }

#elif defined(_WIN32)
    // Windows: read the Security Event Log natively via wevtapi for both
    // logon (4624) and logoff (4634) events, newest-first, capped at the
    // operator's `count` — no wevtutil shell-out. The field-by-field
    // projection (logon-type name map, IpAddress-as-source, the '-'
    // sentinels, ...) lives entirely in
    // yuzu::users_win::session_history_rows, shared with the pure-parser
    // unit tests.
    std::vector<yuzu::users_win::LogonEvent> events;
    const auto evt_outcome = query_logon_events(L"*[System[(EventID=4624 or EventID=4634)]]",
                                                static_cast<std::size_t>(count), events);
    if (evt_outcome == EvtQueryOutcome::kOk) {
        for (const auto& row : yuzu::users_win::session_history_rows(events))
            ctx.write_output(row);
    } else {
        // Access-denied / channel-missing / EvtNext-timeout are distinct
        // operational facts (a chaos-injector governance pass found them
        // collapsed into one hardcoded "requires elevated privileges"
        // message, which misleads an operator when the real cause is a
        // stopped/degraded service rather than a permissions gap) --
        // describe_evt_query_failure() picks the honest message + ABI4
        // status for whichever one actually occurred.
        const auto info = describe_evt_query_failure(evt_outcome);
        ctx.set_result_status(info.status, info.completeness, info.provenance);
        ctx.write_output(std::format("session_history|error|{}", info.message));
    }
#endif
    return 0;
}

// ABI4 capability declarations (#2204).
//
// Windows: every action reads a native Win32 surface — WTSEnumerateSessionsW/
// NetUserEnum/NetLocalGroupGetMembers for the session/account actions, and
// (as of this migration) EvtQuery/EvtRender against the Security channel for
// "primary_user"/"session_history", with a native ProfileList registry
// enumeration (agents/shared/win_profiles.hpp) as "primary_user"'s
// no-login-count fallback when the Security channel is unreadable. No
// action shells out on Windows; there is no `_popen`/`reg query`/`wevtutil`
// left in this plugin.
//
// Linux/macOS: "local_admins" and "group_members" read native libc group/
// passwd surfaces (getgrnam/getpwuid) on Linux only — rung 1. Every other
// action, and both of those on macOS, goes through run_tool() —
// yuzu::agent::run_bounded_subprocess() called on a fixed argv (an absolute,
// possibly distro-probed tool path plus literal arguments) — never a shell.
// This is ADR-3002 rung 2: no shell hop, no shell-quoting surface,
// replacing the previous governed-shell (rung 3) exception. "local_users" on
// Linux/macOS mixes a native read (passwd/dscl enumeration) with a
// per-account run_tool() call for the last-logon field, so the action as a
// whole is rung 2 there too.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "logged_on",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "utmp (setutent/getutent)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'who'", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WTSEnumerateSessionsW + WTSQuerySessionInformationW",
         nullptr},
    },
    {
        /* .action      = */ "sessions",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'w -h'", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'w -h'", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WTSEnumerateSessionsW + WTSQuerySessionInformationW",
         nullptr},
    },
    {
        /* .action      = */ "local_users",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "/etc/passwd read + runner argv 'lastlog -u <user>' per account", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "runner argv 'dscl . -list/-read UserShell/RealName' + 'last -y -1 <user>' per "
         "account",
         nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "NetUserEnum", nullptr},
    },
    {
        /* .action      = */ "local_admins",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getgrnam(sudo/wheel) + getpwuid(0)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "runner argv 'dscl . -read /Groups/admin GroupMembership'", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "NetLocalGroupGetMembers", nullptr},
    },
    {
        /* .action      = */ "group_members",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getgrnam + /etc/passwd primary-group scan", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "runner argv 'dscl . -read /Groups/<name> GroupMembership'", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "NetLocalGroupGetMembers", nullptr},
    },
    {
        /* .action      = */ "primary_user",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'last -F' (max_lines=200 cap)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'last' (max_lines=200 cap)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "wevtapi (EvtQuery/EvtRender, Security 4624)",
         "falls back to a native ProfileList registry enumeration (no login count) when "
         "the Security channel is inaccessible"},
    },
    {
        /* .action      = */ "session_history",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'last -F -n <count>'", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'last -n <count>'", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "wevtapi (EvtQuery/EvtRender, Security 4624/4634)",
         "requires an elevated token to read the Security channel; reports an error "
         "otherwise"},
    },
};

} // namespace

class UsersPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "users"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports logged-on users, sessions, local accounts, admin group members, "
               "group membership, primary user, and session history";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"logged_on",       "sessions",      "local_users",
                                     "local_admins",    "group_members", "primary_user",
                                     "session_history", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "logged_on")
            return do_logged_on(ctx);
        if (action == "sessions")
            return do_sessions(ctx);
        if (action == "local_users")
            return do_local_users(ctx);
        if (action == "local_admins")
            return do_local_admins(ctx);
        if (action == "group_members")
            return do_group_members(ctx, params);
        if (action == "primary_user")
            return do_primary_user(ctx);
        if (action == "session_history")
            return do_session_history(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(UsersPlugin)
